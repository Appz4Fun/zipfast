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

use std::fmt;
use std::sync::Arc;

use crate::error::{Error, RarFailure, RarFault, RarIntegrityReason, RarPasswordEvidence, RarScope};

use super::{Mode, RenamedOutput, Summary};

/// One completion reported by a RAR bulk run.
#[derive(Debug)]
#[non_exhaustive]
pub struct RarEntryOutcome {
    pub entry: RarEntryIdentity,
    /// Raw compression method bits from this member's initial header.
    pub method: u8,
    pub outcome: RarOutcome,
    /// The rename [`super::Overwrite::RenameNew`] or [`super::Overwrite::RenameExisting`] made for this member, if
    /// any, delivered with the member's own outcome so a caller can report it as it happens (UnRAR's
    /// `Extracting  (1).bashrc  OK`). It is the same record that is added to [`RarRunSummary::renames`]. It can come
    /// with a failure: an existing file or folder moved aside by `RenameExisting` stays moved when writing the member
    /// then fails.
    ///
    /// This field was added after the rename modes; the struct is `#[non_exhaustive]`, so callers outside the crate
    /// could never build or exhaustively destructure it, and the addition doesn't break them.
    pub renamed: Option<RenamedOutput>,
    /// A RAR 4.x symbolic link's target, once its data was decoded and verified: stored, compressed or encrypted
    /// alike, since the target is the member's data (as [`crate::rar5::Redirection::UnixSymlink`], bytes that
    /// aren't UTF-8 replaced). It comes with the outcome even when the link was then refused. It is filled by
    /// [`crate::rar5::session::RarSession`] extraction (plain and controlled) and testing, and by the legacy and
    /// typed runs when extracting; a legacy or typed test run doesn't keep the data. A RAR 5.0 redirection's target
    /// is in its header, so it is in the listing ([`crate::extract::Entry::link`]) and not repeated here.
    ///
    /// **Untrusted.** These are the archive's bytes, unchecked: they can be absolute, climb out with `..`, and hold
    /// control characters, newlines or terminal escape sequences, so escape them before printing them to a terminal
    /// or a log. Only the first 4096 bytes are kept, so a longer target comes cut off there (and such a link is never
    /// placed).
    pub link: Option<crate::rar5::Redirection>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct RarEntryIdentity {
    /// Zero-based listing index, absent for a continuation without its initial header.
    pub index: Option<u64>,
    /// Zero-based reporting order, including orphan continuations.
    pub order: u64,
    /// Stored member name, before output path policy.
    pub name: String,
}

#[derive(Debug)]
#[non_exhaustive]
pub enum RarOutcome {
    /// Complete framing and all available final checks passed.
    Verified {
        bytes: u64,
        checks: RarVerification,
        output: RarOutput,
    },
    Directory,
    Skipped(RarSkipReason),
    Failed(Arc<RarFailure>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RarSkipReason {
    ExistingTarget,
    OlderVersion(u64),
    MissingStart,
    /// [`crate::extract::MemberFilter::on_start`] declined it.
    Declined,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RarOutput {
    Tested,
    /// Output was finished and published. No durability guarantee is implied.
    Written,
    /// All verified member bytes were accepted and the caller writer was flushed.
    Printed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct RarVerification {
    pub size_checked: bool,
    pub crc32_checked: bool,
    pub blake2sp_checked: bool,
    pub password: RarPasswordEvidence,
}

#[derive(Debug, Default)]
#[non_exhaustive]
pub struct RarRunSummary {
    /// Members with an initial header, whether or not [`super::Options::select`] took them.
    pub encountered: u64,
    /// Members [`super::Options::select`] took: all of `encountered` without a filter.
    pub matched: u64,
    pub files: u64,
    pub dirs: u64,
    pub bytes: u64,
    pub skipped: u64,
    pub failed: u64,
    /// Successfully opened volumes, including those opened before a terminal failure.
    pub volumes: u64,
    pub match_state: RarMatchState,
    /// Members renamed by [`super::Overwrite::RenameNew`] or [`super::Overwrite::RenameExisting`], in the order the
    /// names were claimed. A terminal error's `partial` keeps the renames made before it, including an existing file
    /// moved aside for a member that then failed.
    pub renames: Vec<RenamedOutput>,
    /// Headers read past under [`super::Options::damaged_input`] (at most 4096 kept): non-empty means the headers
    /// are damaged ([`super::Summary::damaged_headers`]).
    pub damaged_headers: Vec<super::HeaderDamage>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum RarMatchState {
    #[default]
    NoMatch,
    Matched,
}

/// Terminal failure, with the completions reported before the run returned.
#[derive(Debug)]
#[non_exhaustive]
pub struct RarRunError {
    pub partial: RarRunSummary,
    pub entry: Option<RarEntryIdentity>,
    pub failure: Arc<RarFailure>,
    /// Bytes accepted by a print writer for the failed member. These are
    /// separate from completed member bytes in `partial.bytes`.
    pub partial_member_bytes: u64,
}

impl fmt::Display for RarRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(entry) = &self.entry {
            write!(f, "{}: ", entry.name)?;
        }
        self.failure.fmt(f)
    }
}

impl std::error::Error for RarRunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.failure.as_ref())
    }
}

#[derive(Clone)]
pub(crate) struct EntryContext {
    pub(crate) entry: RarEntryIdentity,
    pub(crate) method: u8,
    pub(crate) password: RarPasswordEvidence,
    /// the rename a rename mode made for this member, reported with its outcome
    pub(crate) renamed: Option<RenamedOutput>,
    /// a RAR 4.x symbolic link's decoded target, reported with its outcome
    pub(crate) link: Option<crate::rar5::Redirection>,
}

impl EntryContext {
    pub(crate) fn scope(&self) -> RarScope {
        RarScope::Member { index: self.entry.index }
    }

    pub(crate) fn integrity(&self, reason: RarIntegrityReason, plaintext_dependent: bool) -> RarFailure {
        RarFailure::integrity(self.scope(), reason, self.password, plaintext_dependent)
    }

    pub(crate) fn event(&self, outcome: RarOutcome) -> RarEntryOutcome {
        RarEntryOutcome {
            entry: self.entry.clone(),
            method: self.method,
            outcome,
            renamed: self.renamed.clone(),
            link: self.link.clone(),
        }
    }

    pub(crate) fn checks(&self, size_checked: bool, crc32_checked: bool, blake2sp_checked: bool) -> RarVerification {
        RarVerification { size_checked, crc32_checked, blake2sp_checked, password: self.password }
    }
}

pub(crate) type RunResult<T> = Result<T, RunFault>;

#[derive(Debug)]
pub(crate) enum RunFault {
    Fault(RarFault),
    Reported { entry: RarEntryIdentity, failure: Arc<RarFailure> },
}

impl From<RarFault> for RunFault {
    fn from(fault: RarFault) -> Self {
        Self::Fault(fault)
    }
}

impl RunFault {
    pub(super) fn into_legacy(self) -> Error {
        match self {
            Self::Fault(fault) => fault.into_legacy(),
            Self::Reported { .. } => unreachable!("only typed runs report terminal events"),
        }
    }

    pub(super) fn into_public(self, partial: RarRunSummary) -> RarRunError {
        let (entry, failure) = match self {
            Self::Fault(fault) => (None, Arc::from(fault.failure)),
            Self::Reported { entry, failure } => (Some(entry), failure),
        };
        RarRunError { partial, entry, failure, partial_member_bytes: 0 }
    }
}

pub(super) enum Reports<'a> {
    Legacy {
        summary: Summary,
        callback: &'a mut dyn super::LegacyReport,
        /// listing indexes handed out so far, as a typed run counts them
        encountered: u64,
        /// the listing index of each reported member not finished yet, by its reporting order
        ordinals: std::collections::HashMap<u64, u64>,
    },
    Typed {
        summary: RarRunSummary,
        callback: &'a mut dyn FnMut(&RarEntryOutcome),
    },
}

impl<'a> Reports<'a> {
    pub(super) fn legacy(callback: &'a mut dyn super::LegacyReport) -> Self {
        Self::Legacy { summary: Summary::default(), callback, encountered: 0, ordinals: Default::default() }
    }

    /// Records a rename made for the member reported at `order`, as soon as it is made.
    pub(super) fn renamed_at(&mut self, order: u64, renamed: RenamedOutput) {
        match self {
            Self::Legacy { summary, callback, ordinals, .. } => {
                match ordinals.get(&order) {
                    Some(&ordinal) => callback.renamed_member(ordinal, &renamed),
                    None => callback.renamed(&renamed),
                }
                summary.renames.push(renamed);
            }
            Self::Typed { summary, .. } => summary.renames.push(renamed),
        }
    }

    /// Headers a salvaging run read past, as it met them: kept in the summary, and told as a diagnostic line.
    pub(super) fn damaged(&mut self, damage: Vec<super::HeaderDamage>) {
        match self {
            Self::Legacy { summary, callback, .. } => {
                for d in &damage {
                    callback.line(&d.to_string());
                }
                super::keep_damage(&mut summary.damaged_headers, damage);
            }
            Self::Typed { summary, .. } => super::keep_damage(&mut summary.damaged_headers, damage),
        }
    }

    /// The live member event of a legacy run, for its observer.
    fn member(&mut self, ctx: &EntryContext, member: impl FnOnce(u64, &str) -> super::LegacyMember<'_>) {
        if let Self::Legacy { callback, ordinals, .. } = self
            && let Some(ordinal) = ordinals.remove(&ctx.entry.order)
        {
            callback.member(member(ordinal, &ctx.entry.name));
        }
    }

    pub(super) fn typed(&self) -> bool {
        matches!(self, Self::Typed { .. })
    }

    pub(super) fn encounter(
        &mut self,
        normal: bool,
        order: &mut u64,
        name: String,
        method: u8,
    ) -> RunResult<EntryContext> {
        let position = *order;
        add(order, 1)?;
        let index = match self {
            Self::Typed { summary, .. } if normal => {
                let index = summary.encountered;
                add(&mut summary.encountered, 1)?;
                add(&mut summary.matched, 1)?;
                summary.match_state = RarMatchState::Matched;
                Some(index)
            }
            Self::Legacy { summary, encountered, ordinals, .. } if normal => {
                add(&mut summary.matched, 1)?;
                ordinals.insert(position, *encountered);
                add(encountered, 1)?;
                None
            }
            _ => None,
        };
        let entry = RarEntryIdentity { index, order: position, name };
        Ok(EntryContext { entry, method, password: RarPasswordEvidence::NotEncrypted, renamed: None, link: None })
    }

    /// A member the run's filter didn't take: it keeps its listing index, so later members' indexes still match a
    /// listing, but takes no reporting order and isn't matched.
    pub(super) fn unselected(&mut self, order: u64, name: String, method: u8) -> RunResult<EntryContext> {
        let index = match self {
            Self::Typed { summary, .. } => {
                let index = summary.encountered;
                add(&mut summary.encountered, 1)?;
                Some(index)
            }
            Self::Legacy { encountered, .. } => {
                add(encountered, 1)?;
                None
            }
        };
        let entry = RarEntryIdentity { index, order, name };
        Ok(EntryContext { entry, method, password: RarPasswordEvidence::NotEncrypted, renamed: None, link: None })
    }

    pub(super) fn volume(&mut self) -> RunResult<()> {
        match self {
            Self::Legacy { summary, .. } => add(&mut summary.volumes, 1),
            Self::Typed { summary, .. } => add(&mut summary.volumes, 1),
        }
    }

    pub(super) fn verified(
        &mut self,
        ctx: &EntryContext,
        bytes: u64,
        checks: RarVerification,
        mode: Mode,
    ) -> RunResult<()> {
        match self {
            Self::Legacy { summary, .. } => {
                complete_file(&mut summary.files, &mut summary.bytes, bytes)?;
                self.member(ctx, |ordinal, name| super::LegacyMember::Succeeded { ordinal, name, bytes });
                Ok(())
            }
            Self::Typed { summary, callback } => {
                complete_file(&mut summary.files, &mut summary.bytes, bytes)?;
                let output = match mode {
                    Mode::Test => RarOutput::Tested,
                    Mode::Extract => RarOutput::Written,
                };
                callback(&ctx.event(RarOutcome::Verified { bytes, checks, output }));
                Ok(())
            }
        }
    }

    pub(super) fn directory(&mut self, ctx: &EntryContext) -> RunResult<()> {
        match self {
            Self::Legacy { summary, .. } => {
                add(&mut summary.dirs, 1)?;
                self.member(ctx, |ordinal, name| super::LegacyMember::Succeeded { ordinal, name, bytes: 0 });
                Ok(())
            }
            Self::Typed { summary, callback } => {
                add(&mut summary.dirs, 1)?;
                callback(&ctx.event(RarOutcome::Directory));
                Ok(())
            }
        }
    }

    pub(super) fn skipped(&mut self, ctx: &EntryContext, reason: RarSkipReason) -> RunResult<()> {
        match self {
            Self::Legacy { summary, callback, .. } => {
                match reason {
                    RarSkipReason::ExistingTarget => callback.line(&format!("{}: exists, skipped", ctx.entry.name)),
                    RarSkipReason::Declined => callback.line(&format!("{}: declined, skipped", ctx.entry.name)),
                    RarSkipReason::OlderVersion(v) => {
                        callback.line(&format!("{}: older version {v}, skipped", ctx.entry.name))
                    }
                    RarSkipReason::MissingStart => {}
                }
                add(&mut summary.skipped, 1)?;
                self.member(ctx, |ordinal, name| super::LegacyMember::Skipped { ordinal, name });
                Ok(())
            }
            Self::Typed { summary, callback } => {
                add(&mut summary.skipped, 1)?;
                callback(&ctx.event(RarOutcome::Skipped(reason)));
                Ok(())
            }
        }
    }

    pub(super) fn failed(
        &mut self,
        ctx: &EntryContext,
        failure: Arc<RarFailure>,
        legacy: impl fmt::Display,
    ) -> RunResult<()> {
        match self {
            Self::Legacy { summary, callback, .. } => {
                let why = legacy.to_string();
                let line = format!("{}: {why}", ctx.entry.name);
                callback.line(&line);
                summary.errors.push(line);
                self.member(ctx, |ordinal, name| super::LegacyMember::Failed {
                    ordinal,
                    name,
                    error: Error::Io(std::io::Error::other(why)),
                });
                Ok(())
            }
            Self::Typed { summary, callback } => {
                add(&mut summary.failed, 1)?;
                callback(&ctx.event(RarOutcome::Failed(failure)));
                Ok(())
            }
        }
    }

    pub(super) fn terminal(&mut self, ctx: &EntryContext, fault: RarFault) -> RunFault {
        if !self.typed() {
            return fault.into();
        }
        let failure: Arc<RarFailure> = Arc::from(fault.failure);
        match self.failed(ctx, Arc::clone(&failure), "") {
            Ok(()) => RunFault::Reported { entry: ctx.entry.clone(), failure },
            Err(limit) => limit,
        }
    }
}

fn complete_file(files: &mut u64, bytes: &mut u64, size: u64) -> RunResult<()> {
    let files_after = files.checked_add(1).ok_or_else(RarFault::counter_limit)?;
    let bytes_after = bytes.checked_add(size).ok_or_else(RarFault::counter_limit)?;
    *files = files_after;
    *bytes = bytes_after;
    Ok(())
}

fn add(counter: &mut u64, value: u64) -> RunResult<()> {
    *counter = counter.checked_add(value).ok_or_else(RarFault::counter_limit)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_reporter_releases_failures_and_does_not_format_legacy_messages() {
        struct LegacyMessage;
        impl fmt::Display for LegacyMessage {
            fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
                panic!("typed reporter formatted a legacy message");
            }
        }

        let mut seen = 0;
        let mut callback = |event: &RarEntryOutcome| {
            assert_eq!(event.entry.order, seen);
            seen += 1;
        };
        let mut reports = Reports::Typed { summary: RarRunSummary::default(), callback: &mut callback };
        let mut order = 0;
        for _ in 0..1300 {
            let ctx = reports.encounter(true, &mut order, "file".into(), 0).unwrap();
            let failure = Arc::new(ctx.integrity(RarIntegrityReason::TruncatedData, false));
            let weak = Arc::downgrade(&failure);
            reports.failed(&ctx, failure, LegacyMessage).unwrap();
            assert!(weak.upgrade().is_none());
        }
        let Reports::Typed { summary, .. } = reports else { unreachable!() };
        assert_eq!((summary.failed, seen), (1300, 1300));
    }

    #[test]
    fn typed_counts_reject_overflow_without_emitting_or_counting_the_entry() {
        let mut callback = |_: &RarEntryOutcome| panic!("overflow emitted a completion");
        let mut reports = Reports::Typed {
            summary: RarRunSummary { files: 42, bytes: u64::MAX, ..RarRunSummary::default() },
            callback: &mut callback,
        };
        let mut order = 0;
        let ctx = reports.encounter(true, &mut order, "file".into(), 0).unwrap();
        let error = reports.verified(&ctx, 1, ctx.checks(true, false, false), Mode::Test).unwrap_err();
        let RunFault::Fault(fault) = error else { panic!("overflow was attached to an event") };
        assert!(matches!(
            fault.failure.as_ref(),
            RarFailure::Limit { resource: crate::error::RarResource::Counter, .. }
        ));
        let Reports::Typed { summary, .. } = reports else { unreachable!() };
        assert_eq!((summary.files, summary.bytes), (42, u64::MAX));
    }
}
