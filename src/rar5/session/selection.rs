// Copyright (C) 2026 xbmc4lyfe
// SPDX-License-Identifier: RPL-1.5
//
// Unless explicitly acquired and licensed from Licensor under another license,
// the contents of this file are subject to the Reciprocal Public License
// ("RPL") Version 1.5, or subsequent versions as allowed by the RPL, and You
// may not copy or use this file in either source code or executable form,
// except in compliance with the terms and conditions of the RPL.
//
// All software distributed under the RPL is provided strictly on an "AS IS"
// basis, WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR
// HEREBY DISCLAIMS ALL SUCH WARRANTIES, INCLUDING WITHOUT LIMITATION, ANY
// WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, QUIET
// ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing
// rights and limitations under the RPL.

use crate::batch::{self, PositionReadError, read_at_detailed};
use crate::blake2sp::Blake2sp;
use crate::error::{RarInternal, RarPolicyReason};
use crate::extract::{
    EntryContext, Pending, RarEntryIdentity, RarEntryOutcome, RarMatchState, RarOutcome, RarOutput, RarVerification,
};
use crate::rar5::unpack::{Sink, Unpacker, window_for_detailed};

use super::*;
use crate::rar5::RarFormat;
use crate::rar5::unpack::rar4::{Rar4DecodeError, Rar4Decoder};

#[cfg(unix)]
pub(super) mod control;
#[cfg(unix)]
mod extraction;
#[cfg(unix)]
pub use control::*;
mod printing;
pub use printing::RarPrintOptions;

const WINDOW_MAX: u64 = 256 << 20;
const CHUNK: usize = 64 << 10;
type DecodedOutput<'a> = &'a mut dyn FnMut(&[u8]) -> RarResult<()>;

pub(super) struct SessionToken {
    pub(super) _private: u8,
}

/// A selection made against one session's logical member ordinals.
pub struct RarSelection {
    token: Arc<SessionToken>,
    bits: Vec<u64>,
    matched: u64,
    /// extraction writes the selected older file revisions ([`RarSelection::with_versions`])
    versions: bool,
}

impl RarSelection {
    /// Extracts the selected older file revisions (RAR 5.0 version records, `rar -ver`) too, as UnRAR's `x -ver`
    /// does: each under its [`RarMember::display_name`], the name with `;` and its version number appended
    /// (`notes.txt;2`), or as `[VER]/2/notes.txt` with [`crate::extract::VersionNaming::SevenZipDir`] in the run's
    /// [`crate::extract::Options::version_naming`]. Without it [`RarSession::extract_selected`] and `extract_selected_controlled` skip them
    /// ([`RarSkipReason::OlderVersion`]) even when selected. Testing always checks them.
    pub fn with_versions(mut self) -> Self {
        self.versions = true;
        self
    }

    /// Whether [`RarSelection::with_versions`] was asked for.
    pub fn takes_versions(&self) -> bool {
        self.versions
    }
}

/// Cumulative packed and decoded work, and the maximum decoder window.
#[derive(Clone, Copy, Debug)]
pub struct RarDecodeLimits {
    pub packed_bytes: u64,
    pub decoded_bytes: u64,
    pub window_bytes: u64,
}

impl Default for RarDecodeLimits {
    fn default() -> Self {
        Self { packed_bytes: 8 << 30, decoded_bytes: 8 << 30, window_bytes: WINDOW_MAX }
    }
}

impl RarSession {
    /// Evaluate each logical member in archive order and record the matches.
    #[allow(clippy::result_large_err, reason = "reuse the typed RAR error with partial counts")]
    pub fn select(&self, mut include: impl FnMut(RarMember<'_>) -> bool) -> Result<RarSelection, RarRunError> {
        let result = (|| {
            check_cancel(&self.options.cancel)?;
            let words = self.model.members.len().div_ceil(64);
            let capacity = self.options.limits.capacity_for(&self.usage);
            let check_capacity = |words| {
                limit(add(self.usage.capacity, vector_bytes::<u64>(words)?)?, capacity, RarResource::CatalogueCapacity)
            };
            check_capacity(words)?;
            let mut bits = Vec::new();
            bits.try_reserve_exact(words).map_err(|_| allocation())?;
            check_capacity(bits.capacity())?;
            bits.resize(words, 0);
            let mut matched = 0;
            for (index, member) in self.entries().enumerate() {
                check_cancel(&self.options.cancel)?;
                if include(member) {
                    bits[index / 64] |= 1 << (index % 64);
                    matched = add(matched, 1)?;
                }
            }
            check_cancel(&self.options.cancel)?;
            Ok(RarSelection { token: Arc::clone(&self.token), bits, matched, versions: false })
        })();
        result.map_err(|fault: RarFault| run_error(self.summary(0), None, Arc::from(fault.failure)))
    }

    /// Verify selected members and the solid predecessors they require.
    /// Events refer to logical catalogue ordinals and run on the caller's thread.
    #[allow(clippy::result_large_err, reason = "reuse the typed RAR error with partial counts")]
    pub fn test_selected(
        &mut self,
        selection: &RarSelection,
        limits: RarDecodeLimits,
        on_entry: impl FnMut(&RarEntryOutcome),
    ) -> Result<RarRunSummary, RarRunError> {
        self.execute_selected(
            selection,
            limits,
            |run, session, index| {
                if session.model.members[index].header.is_rar4_symlink() {
                    // a symbolic link's target is its data: kept for the outcome
                    return extraction::rar4_link_text(run, session, index)
                        .map_err(|stop| match stop {
                            SelectedStop::Native(failure) => failure,
                            _ => unreachable!("testing has no control stops"),
                        })
                        .map(|decoded| {
                            decoded.map_or_else(
                                |outcome| outcome,
                                |(_, bytes, checks)| RarOutcome::Verified { bytes, checks, output: RarOutput::Tested },
                            )
                        });
                }
                run.test(session, index, None)
            },
            on_entry,
        )
    }

    #[allow(clippy::result_large_err, reason = "reuse the typed RAR error with partial counts")]
    fn execute_selected(
        &mut self,
        selection: &RarSelection,
        limits: RarDecodeLimits,
        mut member: impl FnMut(&mut SelectedRun, &mut RarSession, usize) -> Result<RarOutcome, Arc<RarFailure>>,
        mut on_entry: impl FnMut(&RarEntryOutcome),
    ) -> Result<RarRunSummary, RarRunError> {
        let mut driver = LegacyDriver { member: &mut member, on_entry: &mut on_entry };
        self.execute_driver(selection, limits, &mut driver).map_err(|error| match error {
            DriverError::Native(error) => error,
            DriverError::Owned { .. } => unreachable!("legacy driver has no owned control stops"),
        })
    }

    #[allow(
        clippy::result_large_err,
        reason = "owned control stops preserve allocation refusal and partial summary without boxing"
    )]
    fn execute_driver(
        &mut self,
        selection: &RarSelection,
        limits: RarDecodeLimits,
        driver: &mut impl SelectedDriver,
    ) -> Result<RarRunSummary, DriverError> {
        if !Arc::ptr_eq(&self.token, &selection.token) {
            return Err(DriverError::Native(run_error(self.summary(0), None, Arc::new(RarFailure::ForeignSelection))));
        }
        let mut summary = self.summary(selection.matched);
        self.check_run_sources(&mut summary).map_err(DriverError::Native)?;
        if selection.matched == 0 {
            return Ok(summary);
        }
        driver.prepare(self).map_err(|cause| DriverError::Owned {
            partial: std::mem::take(&mut summary),
            entry: None,
            cause,
        })?;
        let mut run = SelectedRun::new(limits).map_err(|fault| {
            DriverError::Native(run_error(std::mem::take(&mut summary), None, Arc::from(fault.failure)))
        })?;
        run.versions = selection.versions;
        (run.threads, run.parallel_min) = (self.options.threads, self.options.parallel_min);
        for (word, mut bits) in selection.bits.iter().copied().enumerate() {
            while bits != 0 {
                let index = word * 64 + bits.trailing_zeros() as usize;
                bits &= bits - 1;
                let entry = driver.identity(self, index).map_err(|cause| DriverError::Owned {
                    partial: std::mem::take(&mut summary),
                    entry: None,
                    cause,
                })?;
                let method = self.model.members[index].header.method;
                run.link = None;
                let result = driver.member(&mut run, self, index, &entry);
                // a member makes at most one rename; it goes out with the member's own outcome too
                let renamed = run.renames.last().cloned();
                summary.renames.append(&mut run.renames);
                let (outcome, terminal) = match result {
                    Ok(outcome) => (outcome, None),
                    Err(SelectedStop::Native(failure)) => (RarOutcome::Failed(Arc::clone(&failure)), Some(failure)),
                    Err(cause) => return Err(DriverError::Owned { partial: summary, entry: Some(entry), cause }),
                };
                if let Err(fault) = count_outcome(&mut summary, &outcome) {
                    return Err(DriverError::Native(run_error(summary, Some(entry), Arc::from(fault.failure))));
                }
                let link = run.link.take();
                let unverified_bytes = run.unverified.take();
                let event = RarEntryOutcome { entry, method, outcome, renamed, link, unverified_bytes };
                let callback = driver.entry(&event, self);
                if let Some(failure) = terminal {
                    return Err(DriverError::Native(run_error(summary, Some(event.entry), failure)));
                }
                if let Err(cause) = callback {
                    return Err(match cause {
                        SelectedStop::Native(failure) => {
                            DriverError::Native(run_error(summary, Some(event.entry), failure))
                        }
                        cause => DriverError::Owned { partial: summary, entry: Some(event.entry), cause },
                    });
                }
            }
        }
        Ok(summary)
    }

    fn summary(&self, matched: u64) -> RarRunSummary {
        RarRunSummary {
            encountered: self.usage.entries,
            matched,
            volumes: self.usage.volumes,
            match_state: if matched == 0 { RarMatchState::NoMatch } else { RarMatchState::Matched },
            ..RarRunSummary::default()
        }
    }

    #[allow(clippy::result_large_err, reason = "reuse the typed RAR error with partial counts")]
    fn check_run_sources(&mut self, summary: &mut RarRunSummary) -> Result<(), RarRunError> {
        if let Err(fault) = check_cancel(&self.options.cancel) {
            return Err(run_error(std::mem::take(summary), None, Arc::from(fault.failure)));
        }
        for index in 0..self.volumes.len() {
            if let Err(failure) = self.check_volume(index) {
                return Err(run_error(std::mem::take(summary), None, failure));
            }
        }
        Ok(())
    }

    fn check_volume(&mut self, index: usize) -> Result<(), Arc<RarFailure>> {
        if let Some(failure) = &self.invalid_binding {
            return Err(Arc::clone(failure));
        }
        let volume = &self.volumes[index];
        if let Err(fault) = volume.stamp.check(&volume.file, &volume.path) {
            let failure = Arc::from(fault.failure);
            self.invalid_binding = Some(Arc::clone(&failure));
            return Err(failure);
        }
        Ok(())
    }
}

enum SelectedStop {
    Native(Arc<RarFailure>),
    #[cfg(unix)]
    Control(control::RarExtractControlError),
    #[cfg(unix)]
    Decision(control::RarDecisionError),
}
impl From<Arc<RarFailure>> for SelectedStop {
    fn from(failure: Arc<RarFailure>) -> Self {
        Self::Native(failure)
    }
}
#[cfg(unix)]
impl From<control::RarExtractControlError> for SelectedStop {
    fn from(cause: control::RarExtractControlError) -> Self {
        Self::Control(cause)
    }
}
enum DriverError {
    Native(RarRunError),
    Owned { partial: RarRunSummary, entry: Option<RarEntryIdentity>, cause: SelectedStop },
}
trait SelectedDriver {
    fn prepare(&mut self, _session: &RarSession) -> Result<(), SelectedStop> {
        Ok(())
    }
    fn identity(&mut self, session: &RarSession, index: usize) -> Result<RarEntryIdentity, SelectedStop> {
        Ok(RarEntryIdentity {
            index: Some(index as u64),
            order: index as u64,
            name: session.model.members[index].header.name.clone(),
        })
    }
    fn member(
        &mut self,
        run: &mut SelectedRun,
        session: &mut RarSession,
        index: usize,
        entry: &RarEntryIdentity,
    ) -> Result<RarOutcome, SelectedStop>;
    fn entry(&mut self, event: &RarEntryOutcome, session: &mut RarSession) -> Result<(), SelectedStop>;
}
struct LegacyDriver<'a, M, E> {
    member: &'a mut M,
    on_entry: &'a mut E,
}
impl<M, E> SelectedDriver for LegacyDriver<'_, M, E>
where
    M: FnMut(&mut SelectedRun, &mut RarSession, usize) -> Result<RarOutcome, Arc<RarFailure>>,
    E: FnMut(&RarEntryOutcome),
{
    fn member(
        &mut self,
        run: &mut SelectedRun,
        session: &mut RarSession,
        index: usize,
        _: &RarEntryIdentity,
    ) -> Result<RarOutcome, SelectedStop> {
        (self.member)(run, session, index).map_err(SelectedStop::Native)
    }
    fn entry(&mut self, event: &RarEntryOutcome, _: &mut RarSession) -> Result<(), SelectedStop> {
        (self.on_entry)(event);
        Ok(())
    }
}

/// Selected runs choose members with their own selection, never with `Options::select`.
fn member_filter_refused(session: &RarSession) -> RarRunError {
    run_error(session.summary(0), None, Arc::new(RarFailure::Unsupported(RarUnsupported::MemberFilter)))
}

/// A member's name as a path relative to the destination, as a test run checks links against it: `name;N` for an
/// older revision when the selection includes them, as extracting names it.
fn tested_name(header: &FileHeader, versions: bool) -> Option<PathBuf> {
    let name = header.output_name_as(versions.then_some(crate::extract::VersionNaming::Semicolon))?;
    crate::path::sanitize_with(&name, !header.is_unix(), false).ok()
}

fn run_error(partial: RarRunSummary, entry: Option<RarEntryIdentity>, failure: Arc<RarFailure>) -> RarRunError {
    RarRunError { partial, entry, failure, partial_member_bytes: 0 }
}

fn count_outcome(summary: &mut RarRunSummary, outcome: &RarOutcome) -> RarResult<()> {
    match outcome {
        RarOutcome::Verified { bytes, .. } => {
            let files = add(summary.files, 1)?;
            summary.bytes = add(summary.bytes, *bytes)?;
            summary.files = files;
        }
        RarOutcome::Directory => summary.dirs = add(summary.dirs, 1)?,
        RarOutcome::Skipped(_) => summary.skipped = add(summary.skipped, 1)?,
        RarOutcome::Failed(_) => summary.failed = add(summary.failed, 1)?,
    }
    Ok(())
}

struct SelectedRun {
    /// Renames the member being extracted made, moved to the run's summary after it.
    renames: Vec<crate::extract::RenamedOutput>,
    /// The decoded target of the RAR 4.x symbolic link being extracted or tested, reported with its outcome.
    link: Option<Redirection>,
    /// the rename attempts this run has left
    rename_budget: crate::extract::RenameBudget,
    limits: RarDecodeLimits,
    packed: u64,
    decoded: u64,
    chain: Option<usize>,
    next: usize,
    failed: Option<(usize, Arc<RarFailure>)>,
    decoder: Option<Unpacker>,
    /// [`crate::extract::Options::threads`] and [`crate::extract::Options::parallel_min`] for the RAR 5.0 decoder,
    /// from [`RarSessionOptions`] or, extracting, the extraction's options
    threads: Option<usize>,
    parallel_min: Option<u64>,
    /// the RAR4 decoder, kept between the members of a solid stream
    rar4: Option<Rar4Decoder>,
    /// RAR 3.x keys already derived for the session's password, by salt
    rar4_keys: crate::crypto::Rar4KeyCache,
    /// the members this run found whole, by name: the files a tested hard link or file copy may take
    tested: crate::extract::link::Extracted,
    /// the selection includes older file revisions: they are named `name;N` ([`RarSelection::with_versions`])
    versions: bool,
    history_volumes: VolumeSet,
    buffer: Vec<u8>,
    decrypted: Vec<u8>,
    /// [`crate::extract::UnsupportedFilters::WriteUnfiltered`], set by extraction: a RAR 3.x/4.x member using a VM
    /// filter zipfast doesn't run is written unfiltered and fails with [`unfiltered_written`]
    write_unfiltered: bool,
    /// [`crate::extract::UnverifiedOutput::Emit`], set by extraction (with `keep_broken`) and printing: a member cut
    /// off by a missing volume is decoded from the volumes there, its bytes handed to the output, and still fails
    emit_unverified: bool,
    /// the bytes of a failed member printed anyway ([`RarEntryOutcome::unverified_bytes`]), set by printing
    unverified: Option<u64>,
}

/// A catalogue issue that is a member cut off by a missing volume: under
/// [`crate::extract::UnverifiedOutput::Emit`] what the present volumes hold is decoded before it fails.
pub(super) fn cut_off(failure: &RarFailure) -> bool {
    matches!(
        failure,
        RarFailure::MissingVolume { .. }
            | RarFailure::Integrity { reason: RarIntegrityReason::MissingSplitContinuation, .. }
    )
}

/// The failure of a member written unfiltered ([`crate::extract::UnsupportedFilters::WriteUnfiltered`]): its data
/// decoded in full, so a solid stream's history goes on from it.
pub(super) fn unfiltered_written(failure: &RarFailure) -> bool {
    matches!(failure, RarFailure::Unsupported(RarUnsupported::FilterWrittenUnfiltered))
}

impl SelectedRun {
    fn new(limits: RarDecodeLimits) -> RarResult<Self> {
        let mut buffer = Vec::new();
        buffer.try_reserve_exact(CHUNK).map_err(|_| allocation())?;
        buffer.resize(CHUNK, 0);
        let mut decrypted = Vec::new();
        decrypted.try_reserve_exact(CHUNK + 15).map_err(|_| allocation())?;
        Ok(Self {
            renames: Vec::new(),
            link: None,
            rename_budget: Default::default(),
            limits,
            packed: 0,
            decoded: 0,
            chain: None,
            next: 0,
            failed: None,
            decoder: None,
            threads: None,
            parallel_min: None,
            rar4: None,
            rar4_keys: Default::default(),
            tested: Default::default(),
            versions: false,
            history_volumes: [0; VOLUME_WORDS],
            buffer,
            decrypted,
            write_unfiltered: false,
            emit_unverified: false,
            unverified: None,
        })
    }

    fn test(
        &mut self,
        session: &mut RarSession,
        index: usize,
        output: Option<DecodedOutput<'_>>,
    ) -> Result<RarOutcome, Arc<RarFailure>> {
        check_cancel(&session.options.cancel).map_err(|fault| Arc::from(fault.failure))?;
        let member = &session.model.members[index];
        if member.header.is_dir() || member.header.redirection.is_some() {
            let outcome = match (member.issue, &member.header.redirection) {
                (Some(issue), _) => RarOutcome::Failed(Arc::new(copy_catalogue_issue(&session.issues[issue]))),
                (None, Some(link)) => match link_password(session, index, session.options.encrypted_links) {
                    Ok(evidence) => self.test_link(&member.header, link, evidence),
                    Err(failure) => RarOutcome::Failed(Arc::new(failure)),
                },
                (None, None) => RarOutcome::Directory,
            };
            let mut volumes = [0; VOLUME_WORDS];
            mark_volumes(&mut volumes, &session.model.parts[member.parts.clone()]);
            check_volumes(session, &volumes)?;
            return Ok(outcome);
        }
        let compressed = member.header.method != 0;
        if compressed {
            let Some(chain) = member.chain else {
                return Ok(RarOutcome::Failed(history_failure(None)));
            };
            if self.chain != Some(chain) {
                self.chain = Some(chain);
                self.next = chain;
                self.failed = None;
                self.history_volumes.fill(0);
            }
            if let Some(failed) = &self.failed {
                return Ok(RarOutcome::Failed(history_failure(Some(failed))));
            }
            for predecessor in self.next..index {
                if session.model.members[predecessor].chain != Some(chain) {
                    continue;
                }
                if let Err(failure) = self.decode(session, predecessor, true, None) {
                    if is_terminal(&failure) {
                        return Err(failure);
                    }
                    if unfiltered_written(&failure) {
                        continue;
                    }
                    self.decoder = None;
                    self.rar4 = None;
                    self.failed = Some((predecessor, failure));
                    return Ok(RarOutcome::Failed(history_failure(self.failed.as_ref())));
                }
            }
            self.next = index + 1;
        }
        match self.decode(session, index, compressed, output) {
            Ok((bytes, checks)) => {
                let header = &session.model.members[index].header;
                if let Some(rel) = tested_name(header, self.versions) {
                    if header.is_rar4_symlink() { self.tested.replaced(&rel) } else { self.tested.tested(&rel) }
                }
                Ok(RarOutcome::Verified { bytes, checks, output: RarOutput::Tested })
            }
            Err(failure) if is_terminal(&failure) => Err(failure),
            Err(failure) => {
                if compressed && !unfiltered_written(&failure) {
                    self.decoder = None;
                    self.rar4 = None;
                    self.failed = Some((index, Arc::clone(&failure)));
                }
                Ok(RarOutcome::Failed(failure))
            }
        }
    }

    /// A RAR 5.0 redirection, tested: a symbolic link's target must stay inside the destination, and a hard link or
    /// file copy must take a member this run found whole, as extracting checks them ([`crate::extract::link`]).
    fn test_link(&mut self, header: &FileHeader, link: &Redirection, password: RarPasswordEvidence) -> RarOutcome {
        use crate::extract::link::{self, LinkKind};
        let windows = !header.is_unix();
        let Some(kind) = link::from_rar5(link, windows, false, false) else {
            return RarOutcome::Failed(Arc::new(RarFailure::Unsupported(RarUnsupported::Redirection {
                kind: link.kind(),
            })));
        };
        let Some(rel) = tested_name(header, self.versions) else {
            let path = PathBuf::from(&header.name);
            return RarOutcome::Failed(Arc::new(RarFailure::Policy { reason: RarPolicyReason::UnsafePath, path }));
        };
        let refused = match &kind {
            Ok(kind) => link::refusal(&rel, kind, &self.tested).is_some(),
            Err(_) => true,
        };
        if refused {
            let reason = match kind {
                Ok(LinkKind::Symbolic(_)) => RarPolicyReason::LinkTarget,
                _ => RarPolicyReason::HardLinkTarget,
            };
            return RarOutcome::Failed(Arc::new(RarFailure::Policy { reason, path: rel }));
        }
        link::tested(&rel, &kind.expect("refused above"), &mut self.tested);
        let checks = RarVerification { size_checked: false, crc32_checked: false, blake2sp_checked: false, password };
        RarOutcome::Verified { bytes: 0, checks, output: RarOutput::Tested }
    }

    fn decode(
        &mut self,
        session: &mut RarSession,
        index: usize,
        compressed: bool,
        output: Option<DecodedOutput<'_>>,
    ) -> Result<(u64, RarVerification), Arc<RarFailure>> {
        check_cancel(&session.options.cancel).map_err(|fault| Arc::from(fault.failure))?;
        let member = &session.model.members[index];
        let mut used_volumes = if compressed { self.history_volumes } else { [0; VOLUME_WORDS] };
        mark_volumes(&mut used_volumes, &session.model.parts[member.parts.clone()]);
        check_volumes(session, &used_volumes)?;
        let result = self.decode_bound(session, index, output).map_err(Arc::new);
        if result
            .as_ref()
            .is_err_and(|failure| matches!(failure.as_ref(), RarFailure::Output { .. } | RarFailure::PrintSpool { .. }))
        {
            // Record any observed binding loss without replacing the original
            // output failure returned to this run.
            let _ = check_volumes(session, &used_volumes);
            return result;
        }
        #[cfg(test)]
        AFTER_DECODE.with_borrow_mut(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
        check_volumes(session, &used_volumes)?;
        check_cancel(&session.options.cancel).map_err(|fault| Arc::from(fault.failure))?;
        if compressed && result.as_ref().map_or_else(|failure| unfiltered_written(failure), |_| true) {
            self.history_volumes = used_volumes;
        }
        result
    }

    fn decode_bound(
        &mut self,
        session: &RarSession,
        index: usize,
        mut output: Option<DecodedOutput<'_>>,
    ) -> Result<(u64, RarVerification), RarFailure> {
        let member = &session.model.members[index];
        // UnverifiedOutput::Emit: a member cut off by a missing volume is decoded from what is there, then fails
        let cut =
            member.issue.map(|issue| &session.issues[issue]).filter(|issue| self.emit_unverified && cut_off(issue));
        if let Some(issue) = member.issue
            && cut.is_none()
        {
            return Err(copy_catalogue_issue(&session.issues[issue]));
        }
        // Check known totals before key derivation or dictionary allocation.
        // Actual work is still charged at each part and decoded chunk.
        charge(self.packed, member.packed_size, self.limits.packed_bytes, RarResource::SelectedPackedBytes)?;
        if let Some(size) = member.unpacked_size {
            charge(self.decoded, size, self.limits.decoded_bytes, RarResource::SelectedDecodedBytes)?;
        }
        let header = &member.header;
        let parts = &session.model.parts[member.parts.clone()];
        let context = EntryContext {
            entry: RarEntryIdentity { index: Some(index as u64), order: index as u64, name: String::new() },
            method: header.method,
            password: RarPasswordEvidence::NotEncrypted,
            renamed: None,
            link: None,
        };
        let mut pending = Pending::new(header, context);
        if header.encrypted {
            let salt = header.rar4.and_then(|raw| raw.salt);
            // RAR 3.x has no check value, so an empty password is still tried; RAR5 needs a real one.
            let given = if salt.is_some() { session.password_given } else { !session.password.is_empty() };
            if !given {
                return Err(RarFailure::PasswordRequired { scope: pending.context().scope() });
            }
            let password = session.password.as_str();
            if let Some(salt) = salt {
                let keys = self
                    .rar4_keys
                    .keys(password, &salt, Some(&session.options.cancel))
                    .map_err(|_| RarFailure::Canceled)?;
                pending.start_selected_legacy_cipher(keys, header.unpacked_size);
            } else {
                let params = parts[0]
                    .crypt
                    .and_then(Result::ok)
                    .ok_or_else(|| pending.context().integrity(RarIntegrityReason::MalformedEncryptionRecord, false))?;
                let mut keys = session.rar5_keys();
                pending.start_selected_cipher(&mut keys, params, password, member.unpacked_size)?;
            }
        }
        let compressed = header.method != 0;
        let mut rar4 = if compressed && header.format == RarFormat::Rar4 {
            let first = &session.model.parts[member.parts.start];
            let solid = member.has_successor || session.volumes[first.volume].metadata.main.is_solid();
            let mut decoder = self
                .rar4_decoder(session, member, solid)
                .map_err(|error| *error.detailed(pending.context().scope()).failure)?;
            decoder.set_write_unfiltered(self.write_unfiltered);
            if cut.is_some() {
                decoder.track_starts();
            }
            Some(decoder)
        } else {
            None
        };
        if compressed && header.format == RarFormat::Rar5 {
            self.prepare_decoder(session, member, pending.context())?;
            if cut.is_some()
                && let Some(decoder) = self.decoder.as_mut()
            {
                decoder.track_tail();
                // UnRAR's cut at the data's end needs the last symbols of each block, which workers don't note
                decoder.serial_file();
            }
        }
        for (part_index, part) in parts.iter().enumerate() {
            check_cancel(&session.options.cancel).map_err(|fault| *fault.failure)?;
            // the last part there of a member cut off is not its last: it has no checks of its own to pass here
            let final_part = part_index + 1 == parts.len();
            let checked_part = !final_part;
            self.packed =
                charge(self.packed, part.packed_size, self.limits.packed_bytes, RarResource::SelectedPackedBytes)?;
            let volume = &session.volumes[part.volume];
            let mut part_crc = crate::crc32::Hasher::new();
            let mut part_blake = (!final_part && part.checks.blake2sp.is_some()).then(Blake2sp::new);
            let mut left = part.packed_size;
            let mut offset = part.data_offset;
            while left != 0 {
                check_cancel(&session.options.cancel).map_err(|fault| *fault.failure)?;
                let len = left.min(CHUNK as u64) as usize;
                let chunk = &mut self.buffer[..len];
                read_at_detailed(&volume.file, chunk, offset).map_err(|error| match error {
                    PositionReadError::Eof => RarFailure::Input {
                        operation: IoOperation::Read,
                        path: Some(volume.path.clone()),
                        offset: Some(offset),
                        source: io::Error::from(io::ErrorKind::UnexpectedEof),
                    },
                    PositionReadError::Io { offset, source } => RarFailure::Input {
                        operation: IoOperation::Read,
                        path: Some(volume.path.clone()),
                        offset: Some(offset),
                        source,
                    },
                })?;
                if checked_part {
                    part_crc.update(chunk);
                    if let Some(hash) = &mut part_blake {
                        hash.update(chunk);
                    }
                }
                let mut blocks = None;
                let plaintext = if let Some(cipher) = pending.selected_cipher() {
                    cipher.decrypt_selected(chunk, &mut self.decrypted);
                    blocks = cipher.take_blocks();
                    self.decrypted.as_slice()
                } else {
                    chunk
                };
                let mut sink = SelectedSink {
                    pending: &mut pending,
                    decoded: &mut self.decoded,
                    limit: self.limits.decoded_bytes,
                    cancel: &session.options.cancel,
                    failure: None,
                    output: &mut output,
                };
                let decoder = self.decoder.as_mut().filter(|_| compressed && header.format == RarFormat::Rar5);
                if let Some(decoder) = rar4.as_mut() {
                    let result = decoder.feed(plaintext, &mut sink).map(|_| ());
                    if let Err(failure) = sink.finish_rar4(result) {
                        let held = Held { pending: &mut pending, decoded: &mut self.decoded, output: &mut output };
                        return Err(held.salvage(
                            failure,
                            self.emit_unverified,
                            Some(decoder),
                            None,
                            &self.limits,
                            session,
                        ));
                    }
                } else {
                    match decoder {
                        Some(decoder) => {
                            let result = match &mut blocks {
                                Some(blocks) => blocks.feed(plaintext, decoder, &mut sink),
                                None => decoder.feed(plaintext, &mut sink),
                            };
                            if let Err(failure) = sink.finish(result, decoder.take_size_failure()) {
                                let held =
                                    Held { pending: &mut pending, decoded: &mut self.decoded, output: &mut output };
                                let emit = self.emit_unverified;
                                return Err(held.salvage(failure, emit, None, Some(decoder), &self.limits, session));
                            }
                        }
                        None => {
                            let result = sink.put(plaintext);
                            sink.finish(result, None)?;
                        }
                    }
                }
                if let Some(cipher) = pending.selected_cipher() {
                    cipher.put_blocks(blocks);
                }
                left -= len as u64;
                offset += len as u64;
            }
            if checked_part && let Err(failure) = verify_part(&pending, part.checks, part_crc, part_blake) {
                // a part failing its own checksum: what was decoded goes out as on any failure of the member's data
                let held = Held { pending: &mut pending, decoded: &mut self.decoded, output: &mut output };
                let rar5 = self.decoder.as_mut().filter(|_| compressed && header.format == RarFormat::Rar5);
                return Err(held.salvage(failure, self.emit_unverified, rar4.as_mut(), rar5, &self.limits, session));
            }
        }
        if let Some(issue) = cut {
            // what the decoder holds of the volumes there goes out, as UnRAR 7.30 `p` and `x -kb` write it
            let mut sink = SelectedSink {
                pending: &mut pending,
                decoded: &mut self.decoded,
                limit: self.limits.decoded_bytes,
                cancel: &session.options.cancel,
                failure: None,
                output: &mut output,
            };
            if let Some(decoder) = rar4.as_mut() {
                let result = decoder.flush_decoded(&mut sink);
                sink.finish_rar4(result)?;
            } else if let Some(decoder) = self.decoder.as_mut().filter(|_| compressed) {
                let result = decoder.flush_cut(&mut sink);
                sink.finish(result, None)?;
            }
            return Err(copy_catalogue_issue(issue));
        }
        let context = pending.context().clone();
        if let Some(cipher) = pending.selected_cipher() {
            cipher.finish_selected(&context)?;
        }
        if let Some(decoder) = rar4.as_mut() {
            let mut sink = SelectedSink {
                pending: &mut pending,
                decoded: &mut self.decoded,
                limit: self.limits.decoded_bytes,
                cancel: &session.options.cancel,
                failure: None,
                output: &mut output,
            };
            let result = decoder.finish_logical(&mut sink).map(|_| ());
            if let Err(failure) = sink.finish_rar4(result) {
                let held = Held { pending: &mut pending, decoded: &mut self.decoded, output: &mut output };
                return Err(held.salvage(failure, self.emit_unverified, Some(decoder), None, &self.limits, session));
            }
        }
        if let Some(decoder) = self.decoder.as_mut().filter(|_| compressed && header.format == RarFormat::Rar5) {
            let mut sink = SelectedSink {
                pending: &mut pending,
                decoded: &mut self.decoded,
                limit: self.limits.decoded_bytes,
                cancel: &session.options.cancel,
                failure: None,
                output: &mut output,
            };
            let result = decoder.finish(&mut sink);
            if let Err(failure) = sink.finish(result, decoder.take_size_failure()) {
                let held = Held { pending: &mut pending, decoded: &mut self.decoded, output: &mut output };
                return Err(held.salvage(failure, self.emit_unverified, None, Some(decoder), &self.limits, session));
            }
        }
        let unfiltered = rar4.as_mut().is_some_and(Rar4Decoder::take_unfiltered);
        if let Some(decoder) = rar4.filter(Rar4Decoder::has_boundary) {
            // the next member of the solid stream goes on from here
            self.rar4 = Some(decoder);
        }
        if unfiltered {
            // written in full, unchecked: its checksum can't match data a filter was meant to change
            return Err(RarFailure::Unsupported(RarUnsupported::FilterWrittenUnfiltered));
        }
        let final_checks = parts.last().expect("catalogue members have a part").checks;
        let checks = pending.verify_selected(
            member.unpacked_size,
            final_checks.crc32,
            final_checks.blake2sp,
            final_checks.keyed,
        )?;
        Ok((pending.verified_size(), checks))
    }

    /// The RAR4 decoder for a member: the solid stream's, going on to it, or a new one.
    fn rar4_decoder(
        &mut self,
        session: &RarSession,
        member: &Member,
        solid: bool,
    ) -> Result<Rar4Decoder, Rar4DecodeError> {
        let header = &member.header;
        let raw = header.rar4.ok_or(Rar4DecodeError::Binding)?;
        if header.solid {
            let mut decoder = self.rar4.take().ok_or(Rar4DecodeError::State)?;
            decoder.next_solid_member(crate::rar5::unpack::rar4::CoreFrame {
                ordinal: 0,
                packed: member.packed_size,
                unpacked: header.unpacked_size,
                unpack_version: raw.unpack_version,
                method: raw.method,
                dictionary: header.dictionary,
            })?;
            return Ok(decoder);
        }
        self.rar4 = None;
        let mut decoder = Rar4Decoder::new(
            header.dictionary,
            member.packed_size,
            header.unpacked_size,
            self.limits.window_bytes.min(WINDOW_MAX),
            session.options.cancel.clone(),
        )?;
        decoder.set_version(raw.unpack_version)?;
        decoder.set_memory_limit(self.limits.window_bytes.min(WINDOW_MAX));
        if solid {
            decoder.track_boundary();
        }
        Ok(decoder)
    }

    fn prepare_decoder(
        &mut self,
        session: &RarSession,
        member: &Member,
        context: &EntryContext,
    ) -> Result<(), RarFailure> {
        let header = &member.header;
        if header.solid {
            let decoder = self.decoder.as_mut().expect("solid predecessors decoded");
            if header.dictionary > decoder.reach() {
                return Err(RarFailure::Limit {
                    resource: RarResource::DictionarySize,
                    requested: Some(header.dictionary),
                    allowed: Some(decoder.reach()),
                });
            }
            decoder.next_file(member.unpacked_size);
            return Ok(());
        }
        let first = &session.model.parts[member.parts.start];
        let solid = member.has_successor || session.volumes[first.volume].metadata.main.is_solid();
        let window = window_for_detailed(header.dictionary, member.unpacked_size, solid)
            .map_err(|error| *error.detailed(context.scope()).failure)?;
        let allowed = self.limits.window_bytes.min(WINDOW_MAX);
        if window.size > allowed {
            return Err(RarFailure::Limit {
                resource: RarResource::DictionarySize,
                requested: Some(window.size),
                allowed: Some(allowed),
            });
        }
        if let Some(decoder) = self.decoder.as_mut().filter(|decoder| decoder.fits(window)) {
            decoder.restart(window, member.unpacked_size);
        } else {
            self.decoder = None;
            let mut decoder =
                Unpacker::new_detailed(window).map_err(|error| *error.detailed(context.scope()).failure)?;
            crate::rar5::member::apply_threads(&mut decoder, self.threads, self.parallel_min);
            decoder.reset(member.unpacked_size);
            self.decoder = Some(decoder);
        }
        Ok(())
    }
}

const VOLUME_WORDS: usize = (MAX_VOLUMES as usize).div_ceil(64);
type VolumeSet = [u64; VOLUME_WORDS];

fn mark_volumes(words: &mut VolumeSet, parts: &[Part]) {
    for part in parts {
        words[part.volume / 64] |= 1 << (part.volume % 64);
    }
}

/// The volumes a selected member's published bytes depend on: its own parts, plus the solid history behind a
/// compressed RAR 5.0 member (what the run decoded before it). Publication checks exactly these.
fn member_volumes(run: &SelectedRun, session: &RarSession, index: usize) -> VolumeSet {
    let member = &session.model.members[index];
    // a compressed member depends on its solid history (RAR 5.0 and 4.x alike)
    let mut words = if member.header.method != 0 { run.history_volumes } else { [0; VOLUME_WORDS] };
    mark_volumes(&mut words, &session.model.parts[member.parts.clone()]);
    words
}

fn check_volumes(session: &mut RarSession, words: &VolumeSet) -> Result<(), Arc<RarFailure>> {
    for (word, mut bits) in words.iter().copied().enumerate() {
        while bits != 0 {
            let index = word * 64 + bits.trailing_zeros() as usize;
            bits &= bits - 1;
            session.check_volume(index)?;
        }
    }
    Ok(())
}

fn charge(current: u64, count: u64, allowed: u64, resource: RarResource) -> Result<u64, RarFailure> {
    let requested = current.checked_add(count);
    match requested {
        Some(value) if value <= allowed => Ok(value),
        _ => Err(RarFailure::Limit { resource, requested, allowed: Some(allowed) }),
    }
}

fn copy_catalogue_issue(failure: &RarFailure) -> RarFailure {
    match failure {
        RarFailure::Integrity { scope, reason, password } => {
            RarFailure::Integrity { scope: scope.clone(), reason: reason.clone(), password: *password }
        }
        RarFailure::Unsupported(reason) => RarFailure::Unsupported(reason.clone()),
        RarFailure::MissingVolume { path } => RarFailure::MissingVolume { path: path.clone() },
        RarFailure::Limit { resource, requested, allowed } => {
            RarFailure::Limit { resource: resource.clone(), requested: *requested, allowed: *allowed }
        }
        _ => RarFailure::Internal(RarInternal::Invariant("unexpected retained catalogue issue")),
    }
}

/// An encrypted RAR 5.0 redirection is placed or passed only on a password its check value verifies
/// ([`crate::extract::link::rar5_password`]): its target is in the clear, so nothing else would stop it. Unless
/// `links` is [`crate::extract::EncryptedLinks::PlaceUnverified`], which lets one be placed whatever the password.
pub(super) fn link_password(
    session: &RarSession,
    index: usize,
    links: crate::extract::EncryptedLinks,
) -> Result<RarPasswordEvidence, RarFailure> {
    let header = &session.model.members[index].header;
    let scope = RarScope::Member { index: Some(index as u64) };
    crate::extract::link::rar5_link_password(&mut session.rar5_keys(), header, Some(&session.password), scope, links)
}

fn is_terminal(failure: &RarFailure) -> bool {
    matches!(
        failure,
        RarFailure::Input { .. }
            | RarFailure::Output { .. }
            | RarFailure::PrintSpool { .. }
            | RarFailure::SourceChanged { .. }
            | RarFailure::Canceled
            | RarFailure::Internal(_)
            | RarFailure::Limit {
                resource: RarResource::Counter
                    | RarResource::CatalogueAllocation
                    | RarResource::SelectedPackedBytes
                    | RarResource::SelectedDecodedBytes
                    | RarResource::PrintMemberSpoolBytes
                    | RarResource::PrintLiveSpoolBytes
                    | RarResource::PrintIoAttempts
                    | RarResource::ExtractControlCapacity
                    | RarResource::ExtractControlWork
                    | RarResource::ExtractControlAllocation
                    | RarResource::ExtractDecisionCalls
                    | RarResource::ExtractControlIoAttempts
                    | RarResource::ExtractControlHandles,
                ..
            }
    )
}

fn history_failure(failed: Option<&(usize, Arc<RarFailure>)>) -> Arc<RarFailure> {
    Arc::new(RarFailure::SolidHistoryUnavailable {
        predecessor: failed.map(|(index, _)| *index as u64),
        cause: failed.map(|(_, failure)| Arc::clone(failure)),
    })
}

fn verify_part(
    pending: &Pending,
    checks: RarChecks,
    crc: crate::crc32::Hasher,
    blake: Option<Blake2sp>,
) -> Result<(), RarFailure> {
    super::super::member::verify_packed(pending.context(), checks, crc, blake, pending.hash_key(checks.keyed))
}

/// What a failing member's decoded bytes go to: [`Held::salvage`].
struct Held<'a, 'out> {
    pending: &'a mut Pending,
    decoded: &'a mut u64,
    output: &'a mut Option<DecodedOutput<'out>>,
}

impl Held<'_, '_> {
    /// [`crate::extract::UnverifiedOutput::Emit`]: a member failing on its data hands over what its decoder still
    /// buffers, so printing gets every byte decoded before the failure. The member's own failure is returned, or a
    /// terminal one handing the bytes over met (an output or spool failure, a limit, cancellation).
    fn salvage(
        self,
        failure: RarFailure,
        emit: bool,
        rar4: Option<&mut Rar4Decoder>,
        rar5: Option<&mut Unpacker>,
        limits: &RarDecodeLimits,
        session: &RarSession,
    ) -> RarFailure {
        if !emit || is_terminal(&failure) {
            return failure;
        }
        let mut sink = SelectedSink {
            pending: self.pending,
            decoded: self.decoded,
            limit: limits.decoded_bytes,
            cancel: &session.options.cancel,
            failure: None,
            output: self.output,
        };
        let flushed = match (rar4, rar5) {
            (Some(decoder), _) => {
                let result = decoder.flush_decoded(&mut sink);
                sink.finish_rar4(result)
            }
            (None, Some(decoder)) => {
                let result = decoder.flush_now(&mut sink);
                sink.finish(result, None)
            }
            (None, None) => Ok(()),
        };
        match flushed {
            Err(stop) if is_terminal(&stop) => stop,
            _ => failure,
        }
    }
}

struct SelectedSink<'a, 'out> {
    pending: &'a mut Pending,
    decoded: &'a mut u64,
    limit: u64,
    cancel: &'a Cancellation,
    failure: Option<RarFailure>,
    output: &'a mut Option<DecodedOutput<'out>>,
}

impl SelectedSink<'_, '_> {
    fn finish_rar4(self, result: Result<(), Rar4DecodeError>) -> Result<(), RarFailure> {
        if let Some(failure) = self.failure {
            return Err(failure);
        }
        result.map_err(|error| *error.detailed(self.pending.context().scope()).failure)
    }

    fn finish(self, result: crate::Result<()>, size: Option<(u64, u64)>) -> Result<(), RarFailure> {
        if let Some(failure) = self.failure {
            return Err(failure);
        }
        result.map_err(|error| {
            let ctx = self.pending.context();
            *batch::decoder_failure_with_size(error, ctx.scope(), ctx.password, size).failure
        })
    }

    fn take(&mut self, bytes: &[u8]) -> Result<(), RarFailure> {
        check_cancel(self.cancel).map_err(|fault| *fault.failure)?;
        self.pending
            .take_with(bytes, |chunk| {
                *self.decoded =
                    charge(*self.decoded, chunk.len() as u64, self.limit, RarResource::SelectedDecodedBytes)
                        .map_err(|failure| RarFault::new(failure, Error::Corrupt("selected RAR decoded work limit")))?;
                if let Some(output) = &mut self.output {
                    output(chunk)?;
                }
                Ok(())
            })
            .map_err(|fault| *fault.failure)
    }
}

impl Sink for SelectedSink<'_, '_> {
    fn put(&mut self, bytes: &[u8]) -> crate::Result<()> {
        if self.failure.is_none() {
            self.failure = self.take(bytes).err();
        }
        if self.failure.is_some() { Err(Error::Corrupt("selected RAR sink stopped")) } else { Ok(()) }
    }

    fn wants_crc(&self) -> bool {
        self.pending.wants_crc()
    }

    fn crc(&mut self, crc: u32) {
        self.pending.crc(crc);
    }
}

#[cfg(test)]
thread_local! {
    static AFTER_DECODE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn verifies_using_held_descriptors_and_rechecks_sources_after_decode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive.rar");
        let replacement = dir.path().join("replacement");
        let main = [0xc5, 0x1a, 0x33, 0x32, 3, 1, 0, 0];
        let end = [0x19, 0xb2, 0x3a, 0x35, 3, 5, 0, 0];
        let body = [2, 2, 1, 0, 1, 0, 0, 1, 1, b'a'];
        let mut framed = vec![body.len() as u8];
        framed.extend(body);
        let crc = crate::crc32::hash(&framed).to_le_bytes();
        let bytes = [super::super::super::SIGNATURE.as_slice(), &main, &crc, &framed, b"x", &end].concat();
        fs::write(&path, &bytes).unwrap();
        fs::write(&replacement, &bytes).unwrap();
        OPENED.set(0);
        super::super::super::reader::VOLUME_OPENS.set(0);
        let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
        let selection = session.select(|_| true).unwrap();
        let summary = session.test_selected(&selection, RarDecodeLimits::default(), |_| {}).unwrap();
        assert_eq!(summary.bytes, 1);
        assert_eq!(OPENED.get(), 1);
        assert_eq!(super::super::super::reader::VOLUME_OPENS.get(), 0);

        let target = path.clone();
        AFTER_DECODE.with_borrow_mut(|hook| {
            *hook = Some(Box::new(move || fs::rename(replacement, target).unwrap()));
        });
        let result = session
            .test_selected(&selection, RarDecodeLimits::default(), |event| {
                assert!(matches!(event.outcome, RarOutcome::Failed(_)));
            })
            .unwrap_err();
        assert_eq!(result.partial.files, 0);
        assert!(matches!(result.failure.as_ref(), RarFailure::SourceChanged { path: actual } if actual == &path));
        assert!(Arc::ptr_eq(session.invalid_binding.as_ref().unwrap(), &result.failure));
    }
    #[test]
    fn rar4_source_rebound_after_decode_precedes_verified_print() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive.rar");
        let replacement = dir.path().join("replacement");
        let bytes = crate::rar5::unpack::rar4::fixed_fixture();
        fs::write(&path, &bytes).unwrap();
        fs::write(&replacement, &bytes).unwrap();
        let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
        let all = session.select(|_| true).unwrap();
        let target = path.clone();
        AFTER_DECODE.with_borrow_mut(|hook| *hook = Some(Box::new(move || fs::rename(replacement, target).unwrap())));
        let mut stdout = Vec::new();
        let failure = session.print_selected(&all, &mut stdout, &RarPrintOptions::default(), |_| {}).unwrap_err();
        assert!(matches!(failure.failure.as_ref(), RarFailure::SourceChanged { .. }));
        assert_eq!(failure.partial.files, 0);
        assert!(stdout.is_empty());
    }
}
