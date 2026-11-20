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

//! Independently owned anchored persistent output.
#![allow(clippy::result_large_err, reason = "typed public errors preserve contextual and committed-anchor receipts")]
#![doc = include_str!("../../docs/persistent-partials.md")]
mod anchor;
mod cipher;
mod journal;
mod ledger;
mod limits;
mod native;
mod state;
pub(crate) use state::member_crypt;
mod types;
mod verify;
use crate::progressive::{Lease, OutputOperation, Resource, SessionControl};
use crate::rar5::source::SourceStamp;
use anchor::AnchorBinding;
pub(crate) use cipher::MemberKeys;
use journal::Bundle;
pub(crate) use limits::PartialBudget;
pub use limits::{PartialLimits, PartialResource};
use limits::{Reservation, limit};
use native::PersistentNative;
pub(crate) use native::{GenesisPath, PartialExclusions, PartialProtectedPath, create_directory};
pub(crate) use state::CipherBlock;
pub use state::PartialState;
use state::{CommittedState, MutationCommit, MutationIntent, Snapshot};
use std::{
    ops::Range,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
pub use types::*;
mod writer;
pub use writer::FillWriter;

#[derive(Clone)]
pub struct PartialFile {
    core: Arc<PartialCore>,
}
pub(crate) struct PartialCore {
    native: PersistentNative,
    budget: PartialBudget,
    anchors: AnchorBinding,
    control: SessionControl,
    read_chunk: usize,
    busy: AtomicBool,
    data: Mutex<Option<CoreData>>,
    /// Keys of an encrypted member, in memory only.
    keys: Option<MemberKeys>,
    /// Whether the keys are known to be the member's: they came from the extraction, passed the archive's password
    /// check value, or decrypted a block of original output correctly. Until then `fill_packed` writes nothing.
    keys_proven: AtomicBool,
    _lease: Reservation,
}
pub(crate) struct PreparedCreate {
    spec: CreateSpec,
    budget: PartialBudget,
    lease: Reservation,
    _event: Reservation,
    anchors: AnchorBinding,
    control: SessionControl,
    read_chunk: u64,
    initial: Snapshot,
    pages: Vec<(state::PageKind, Vec<u8>)>,
    native: native::PreparedNative,
    ready_bytes: Option<usize>,
    keys: Option<MemberKeys>,
}
/// Absolute output and state bundle paths of `member` at `relative` under the roots, as its genesis named them.
pub(crate) fn member_paths(
    output_root: &std::path::Path,
    state_root: &std::path::Path,
    relative: &std::path::Path,
    member: &MemberKey,
) -> PartialResult<(std::path::PathBuf, std::path::PathBuf)> {
    native::validate_relative(relative)?;
    let root = std::path::absolute(output_root).map_err(|e| io_error(OutputOperation::Metadata, e))?;
    let state = std::path::absolute(state_root).map_err(|e| io_error(OutputOperation::Metadata, e))?;
    Ok((root.join(relative), state.join(native::bundle_name(member))))
}
/// What a session needs to adopt a member a previous session created.
pub(crate) struct AdoptSpec {
    pub member: MemberKey,
    pub anchor: StateAnchor,
    pub output_root: std::path::PathBuf,
    pub state_root: std::path::PathBuf,
    pub protection: crate::progressive::ProtectionDeclaration,
    /// The member keys of an encrypted member, from the session's own derivation.
    pub keys: Option<MemberKeys>,
}
/// Hash state of an adopted member's known output before its resume point; `None` where that output has holes.
pub(crate) struct PrefixHashes {
    pub member: Option<(crate::crc32::Hasher, Option<crate::blake2sp::Blake2sp>)>,
    pub part: Option<(crate::crc32::Hasher, Option<crate::blake2sp::Blake2sp>)>,
}
pub(crate) struct PartialEventLease {
    _reservation: Reservation,
}
struct CoreData {
    bundle: Bundle,
    snapshot: Snapshot,
    state: PartialState,
    stamp: SourceStamp,
    uncertain: Option<Uncertain>,
    pending_compaction: Option<journal::PreparedCompaction>,
    verification: Option<verify::Verification>,
    // Part CRC results still valid for the known leaves of the given revision,
    // kept across transactions that do not change known leaves.
    part_results: Option<(u64, Vec<PartCheck>, Lease)>,
    reopened: bool,
    /// An open group commit: its intent is anchored, and `snapshot` already holds the output written since, which
    /// the next commit makes durable.
    group: Option<Group>,
}
/// A group of writes committed together. While it is open, `CoreData::state` is the anchored intent (the state
/// before the group, conservatively), and `CoreData::snapshot` runs ahead of it with every grouped write: their
/// leaves, `produced`, and evidence the extraction appended. Output past the commit is never claimed durably before
/// the output sync that precedes the commit.
struct Group {
    intent: PartialState,
    bytes: u64,
    opened: std::time::Instant,
}
struct Transaction {
    intent: PartialState,
    commit: PartialState,
    valid: Snapshot,
    commit_known: Vec<state::KnownLeaf>,
    // Transaction-scoped copies (state, known vectors, encoded pages).
    _lease: Lease,
}
struct Uncertain {
    expected: PartialState,
    intent: PartialState,
    commit: Option<PartialState>,
    candidate_known: Option<Vec<state::KnownLeaf>>,
}
struct Operation<'a> {
    core: &'a PartialCore,
    data: Option<CoreData>,
}
impl Drop for Operation<'_> {
    fn drop(&mut self) {
        let data = self.data.take();
        *self.core.data.lock().unwrap() = data;
        self.core.busy.store(false, Ordering::Release);
    }
}
impl std::ops::Deref for Operation<'_> {
    type Target = CoreData;
    fn deref(&self) -> &CoreData {
        self.data.as_ref().unwrap()
    }
}
impl std::ops::DerefMut for Operation<'_> {
    fn deref_mut(&mut self) -> &mut CoreData {
        self.data.as_mut().unwrap()
    }
}
/// File and directory syncs issued by persistent partial output in this process (output, journal, pages and
/// bundle directories; not the caller's anchor store). For benchmarks and diagnostics.
static SYNCS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
#[doc(hidden)]
pub fn durable_sync_count() -> u64 {
    SYNCS.load(Ordering::Relaxed)
}
fn sync_file(file: &std::fs::File) -> std::io::Result<()> {
    SYNCS.fetch_add(1, Ordering::Relaxed);
    file.sync_all()
}
fn canceled(control: &SessionControl) -> PartialResult<()> {
    if control.is_canceled() { Err(err(PartialErrorKind::Canceled)) } else { Ok(()) }
}
fn stamp(native: &PersistentNative) -> PartialResult<SourceStamp> {
    SourceStamp::from_metadata(native.output.file.metadata().map_err(|e| io_error(OutputOperation::Metadata, e))?)
        .map_err(|e| io_error(OutputOperation::Metadata, e))
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FillMode {
    /// Bytes the extraction produced from the archive, written once in order.
    Original,
    /// Caller bytes from another copy of the content; may only land in holes.
    Alt,
    /// Archive bytes supplied later (a twin post or a par2 repair); fill holes and replace differing alt bytes.
    Packed,
}
type Ranges = Vec<Range<u64>>;
#[derive(Default)]
struct Written {
    applied: Vec<Range<u64>>,
    corrected: Vec<Range<u64>>,
}
fn write_output(file: &std::fs::File, offset: u64, bytes: &[u8]) -> std::io::Result<usize> {
    #[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
    {
        tests::state::fault_write(file, offset, bytes)
    }
    #[cfg(not(all(test, any(target_os = "linux", target_os = "macos"))))]
    {
        crate::output::range::write_at(file, offset, bytes)
    }
}
fn rehash_known(
    native: &PersistentNative,
    budget: &PartialBudget,
    control: &SessionControl,
    chunk: usize,
    snapshot: &mut Snapshot,
) -> PartialResult<()> {
    if chunk == 0 && !snapshot.known.is_empty() {
        return Err(err(PartialErrorKind::InvalidOptions));
    }
    let before = stamp(native)?;
    let max_leaf = snapshot.known.iter().map(|leaf| leaf.range.end - leaf.range.start).max().unwrap_or(0) as usize;
    let mut buffer = budget.vector(chunk.min(max_leaf))?;
    buffer.resize(chunk.min(max_leaf), 0);
    for leaf in &mut snapshot.known {
        let mut at = leaf.range.start;
        let mut hasher = crate::crc32::Hasher::new();
        while at < leaf.range.end {
            canceled(control)?;
            let n = (leaf.range.end - at).min(buffer.len() as u64) as usize;
            budget.usage.charge(Resource::VerifyBytes, n as u64)?;
            budget.usage.charge(Resource::VerifyWorkBytes, n as u64)?;
            let count = crate::output::range::read_at(&native.output.file, at, &mut buffer[..n])
                .map_err(|e| io_error(OutputOperation::Read, e))?;
            if count == 0 {
                return Err(err(PartialErrorKind::OutputChanged));
            }
            hasher.update(&buffer[..count]);
            at += count as u64;
        }
        if hasher.clone().finalize() != leaf.crc {
            return Err(err(PartialErrorKind::OutputChanged));
        }
        leaf.hasher = hasher;
    }
    native.check(snapshot.head.size)?;
    if stamp(native)? != before {
        return Err(err(PartialErrorKind::OutputChanged));
    }
    Ok(())
}

impl PartialCore {
    fn operation(&self) -> PartialResult<Operation<'_>> {
        if self.busy.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            return Err(err(PartialErrorKind::Busy));
        }
        let data = self.data.lock().unwrap().take();
        Ok(Operation { core: self, data })
    }
    fn check(&self, data: &CoreData) -> PartialResult<()> {
        canceled(&self.control)?;
        self.native.check(data.snapshot.head.size)?;
        if stamp(&self.native)? != data.stamp {
            return Err(err(PartialErrorKind::OutputChanged));
        }
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn create(spec: CreateSpec, checks: MemberChecks, options: CoreOptions) -> PartialResult<Arc<Self>> {
        Self::prepare_create(spec, checks, options)?.complete()
    }
    pub(crate) fn prepare_create(
        spec: CreateSpec,
        checks: MemberChecks,
        options: CoreOptions,
    ) -> PartialResult<PreparedCreate> {
        native::platform()?;
        options.limits.validate()?;
        canceled(&options.control)?;
        if checks.size != spec.size || options.read_chunk == 0 {
            return Err(err(PartialErrorKind::InvalidOptions));
        }
        // The member's memory charges go back to the session when its core (or a failed genesis) is gone.
        let budget = PartialBudget::new(options.limits, options.usage.scoped(), options.exclusions)?;
        let lease = budget.reserve(PartialResource::OpenPartials, 1)?;
        let _event = budget.reserve(PartialResource::Events, 1)?;
        budget.usage.charge(Resource::NameBytes, spec.name.len() as u64)?;
        budget.usage.output_extent(spec.size)?;
        let crypt = state::validate_evidence(&spec.name, spec.size, &spec.evidence, &budget)?;
        native::validate_relative(&spec.relative_output)?;
        match std::fs::symlink_metadata(spec.output_root.join(&spec.relative_output)) {
            Ok(_) => return Err(err(PartialErrorKind::AlreadyExists)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(io_error(OutputOperation::Metadata, e)),
        }
        // Reserve the entire genesis transaction before creating named files.
        let initial_head = CommittedState {
            member: spec.member.clone(),
            sequence: 0,
            revision: 0,
            relative_output: spec.relative_output.clone(),
            size: spec.size,
            produced: 0,
            member_finished: false,
            tail: None,
            checks: checks.clone(),
            binding: native::NativeBinding {
                root: crate::progressive::native::Identity(0, 0),
                parent: crate::progressive::native::Identity(0, 0),
                output: crate::progressive::native::Identity(0, 0),
                bundle: crate::progressive::native::Identity(0, 0),
            },
            pages: Vec::new(),
            metadata: spec.evidence.metadata,
            cursor: None,
        };
        let mut initial = Snapshot {
            head: initial_head,
            name: spec.name.clone(),
            evidence: spec.evidence.clone(),
            known: Vec::new(),
            holes: Vec::new(),
            crypt,
            cipher: Vec::new(),
        };
        // The genesis pages stay with the prepared core until it is created.
        let (pages, encoded) = state::encode_pages(&initial, &budget)?;
        encoded.keep();
        initial.head.pages = pages
            .iter()
            .map(|(kind, bytes)| state::PageRef {
                kind: *kind,
                digest: crate::crypto::sha256(bytes),
                len: bytes.len() as u32,
            })
            .collect();
        let size_probe = state::encode_record(1, 0, None, &initial.head, &budget.limits)?;
        let descriptors = spec.relative_output.components().count().checked_add(6).ok_or_else(malformed)?;
        let mut requests = budget.vector(descriptors + pages.len() * 2 + 4)?;
        for _ in 0..descriptors {
            requests.push((PartialResource::OpenFiles, 1));
        }
        for (_, bytes) in &pages {
            requests.push((PartialResource::StatePages, 1));
            requests.push((PartialResource::LedgerBytes, bytes.len() as u64));
        }
        for _ in 0..2 {
            requests.push((PartialResource::JournalRecords, 1));
            requests.push((PartialResource::JournalBytes, size_probe.wire.len() as u64));
        }
        budget.prepay(&requests)?;
        budget.prepare_genesis(pages.len(), Bundle::genesis_metadata(pages.len())?);
        let anchors = AnchorBinding::new(spec.member.clone(), options.anchors);
        if let Some(latest) = anchors.current()? {
            return Err(err(PartialErrorKind::StateStale { latest }));
        }
        canceled(&options.control)?;
        let native = native::PreparedNative::new(&spec, &budget)?;
        Ok(PreparedCreate {
            spec,
            budget,
            lease,
            _event,
            anchors,
            control: options.control,
            read_chunk: options.read_chunk,
            initial,
            pages,
            native,
            ready_bytes: None,
            keys: None,
        })
    }
    fn reconcile(&self, data: &mut CoreData) -> PartialResult<()> {
        let ack = self.anchors.current_ack()?.ok_or_else(|| err(PartialErrorKind::AnchorConflict))?;
        let result = (|| {
            self.check(data)?;
            if let Some(uncertain) = &data.uncertain {
                let candidate = if ack.matches(uncertain.expected.anchor()) {
                    &uncertain.expected
                } else if ack.matches(uncertain.intent.anchor()) {
                    &uncertain.intent
                } else if uncertain.commit.as_ref().is_some_and(|state| ack.matches(state.anchor())) {
                    uncertain.commit.as_ref().unwrap()
                } else {
                    return Err(err(PartialErrorKind::StateStale { latest: ack.anchor().clone() }));
                };
                self.budget.metadata(candidate.wire.len() as u64)?;
                let candidate = candidate.clone();
                let reusable = if ack.matches(uncertain.expected.anchor()) {
                    &data.snapshot.known
                } else {
                    uncertain.candidate_known.as_ref().unwrap_or(&data.snapshot.known)
                };
                let mut snapshot = data.bundle.snapshot_reusing(&candidate, reusable)?;
                rehash_known(&self.native, &self.budget, &self.control, self.read_chunk, &mut snapshot).map_err(
                    |mut e| {
                        e.committed = Some(ack.anchor().clone());
                        e
                    },
                )?;
                data.state = candidate;
                data.snapshot = snapshot;
                data.uncertain = None;
                if let Some(prepared) = data.pending_compaction.take()
                    && ack.matches(prepared.state.anchor())
                {
                    data.bundle.complete_compaction(prepared, &ack).map_err(|mut e| {
                        e.committed = Some(ack.anchor().clone());
                        e
                    })?;
                }
            } else if !ack.matches(data.state.anchor()) {
                return Err(err(PartialErrorKind::StateStale { latest: ack.anchor().clone() }));
            }
            data.bundle.acknowledge(data.state.anchor(), &ack)?;
            Ok(())
        })();
        result.map_err(|mut error: PartialError| {
            error.committed = Some(ack.anchor().clone());
            error
        })
    }
    /// A working copy of `snapshot`. Its charge lasts as long as the returned
    /// lease: a copy either replaces the retained snapshot or is dropped, and
    /// retained growth (known leaves, holes, evidence) is charged where it is made.
    fn clone_snapshot(&self, snapshot: &Snapshot) -> PartialResult<(Snapshot, Lease)> {
        let bytes = std::mem::size_of::<Snapshot>()
            + snapshot.name.len()
            + snapshot.head.relative_output.as_os_str().len()
            + snapshot.known.len() * std::mem::size_of::<state::KnownLeaf>()
            + snapshot
                .evidence
                .headers
                .iter()
                .map(|h| h.bytes.len() + std::mem::size_of::<HeaderWitness>())
                .sum::<usize>()
            + snapshot.evidence.parts.len() * std::mem::size_of::<PlainPart>()
            + snapshot
                .evidence
                .admissions
                .iter()
                .map(|a| std::mem::size_of::<SourceAdmission>() + a.expected.len())
                .sum::<usize>()
            + snapshot.head.pages.len() * std::mem::size_of::<state::PageRef>()
            + snapshot.cipher.len() * std::mem::size_of::<state::CipherBlock>()
            + snapshot
                .holes
                .iter()
                .map(|h| std::mem::size_of::<HoleReport>() + h.packed.len() * std::mem::size_of::<PackedSpan>())
                .sum::<usize>();
        let lease = self.budget.metadata_lease(bytes as u64)?;
        Ok((snapshot.clone(), lease))
    }
    /// Where this member's output is.
    pub(crate) fn output_path(&self) -> &std::path::Path {
        &self.native.output_path
    }
    pub(crate) fn validate_current(&self) -> PartialResult<()> {
        let data = self.operation()?;
        self.check(&data)
    }
    /// Writes output the extraction produced at `produced`. With grouping (the default) the write joins the open
    /// group, opening one first, and the group commits once it holds `group_commit_bytes` or has been open for
    /// `group_commit_interval`.
    pub(crate) fn write_original(&self, offset: u64, bytes: &[u8]) -> PartialResult<()> {
        let mut op = self.operation()?;
        self.check(&op)?;
        if self.grouping() {
            if op.group.is_none() {
                self.reconcile(&mut op)?;
            }
            if offset == op.snapshot.head.produced {
                return self.group_write(&mut op, offset, bytes, FillMode::Original).map(|_| ());
            }
        }
        self.flush_group(&mut op)?;
        self.reconcile(&mut op)?;
        self.write_data(&mut op, offset, bytes, FillMode::Original).map(|_| ())
    }
    /// Plaintext fill of a [`FillWriter`]: grouped like extraction writes. Returns the ranges written and whether
    /// every grouped write is committed now (no group remains open).
    pub(crate) fn fill_grouped(&self, offset: u64, bytes: &[u8]) -> PartialResult<(Vec<Range<u64>>, bool)> {
        let mut op = self.operation()?;
        self.check(&op)?;
        if !self.grouping() {
            self.reconcile(&mut op)?;
            self.budget.metadata(op.state.wire.len() as u64 + std::mem::size_of::<Range<u64>>() as u64)?;
            return Ok((self.write_data(&mut op, offset, bytes, FillMode::Alt)?.applied, true));
        }
        if op.group.is_none() {
            self.reconcile(&mut op)?;
        }
        let applied = self.group_write(&mut op, offset, bytes, FillMode::Alt)?;
        Ok((applied, op.group.is_none()))
    }
    /// Commits any open group and returns the resulting fill result with nothing applied.
    pub(crate) fn commit_fills(&self) -> PartialResult<FillResult> {
        let mut op = self.operation()?;
        self.check(&op)?;
        self.flush_group(&mut op)?;
        self.reconcile(&mut op)?;
        self.fill_result(&mut op, Vec::new())
    }
    /// Commits any open group now, resolves an uncertain commit from the store, and returns the end of the known
    /// output from `from` (at most `to`) in the committed state: how far a fill starting at `from` is durable.
    pub(crate) fn commit_group(&self, from: u64, to: u64) -> PartialResult<u64> {
        let mut op = self.operation()?;
        self.check(&op)?;
        self.flush_group(&mut op)?;
        if op.uncertain.is_some() {
            self.reconcile(&mut op)?;
        }
        let known = &op.snapshot.known;
        let mut at = from;
        for leaf in &known[known.partition_point(|leaf| leaf.range.end <= from)..] {
            if leaf.range.start > at || at >= to {
                break;
            }
            at = leaf.range.end;
        }
        Ok(at.min(to).max(from))
    }
    /// Commits the open group if it has been open for `group_commit_interval`; the session calls this before it
    /// waits for a provider, so a stalled download does not keep written output uncommitted. A handle busy in
    /// another operation is left alone.
    pub(crate) fn commit_due(&self) -> PartialResult<()> {
        let Ok(mut op) = self.operation() else { return Ok(()) };
        if op.group.as_ref().is_some_and(|g| g.opened.elapsed() >= self.budget.limits.group_commit_interval) {
            self.check(&op)?;
            self.flush_group(&mut op)?;
        }
        Ok(())
    }
    pub(crate) fn fill_plain(&self, offset: u64, bytes: &[u8]) -> PartialResult<FillResult> {
        let mut op = self.operation()?;
        self.check(&op)?;
        self.flush_group(&mut op)?;
        self.reconcile(&mut op)?;
        self.budget.metadata(op.state.wire.len() as u64 + std::mem::size_of::<Range<u64>>() as u64)?;
        let applied = self.write_data(&mut op, offset, bytes, FillMode::Alt)?.applied;
        self.fill_result(&mut op, applied)
    }
    /// Maps archive bytes of `volume` starting at `offset` to this member's produced output and writes them with
    /// archive authority: holes are filled, bytes from the original extraction must match, and alt bytes that
    /// differ are rewritten and reported. Packed bytes outside this member's produced output are returned unused.
    /// An encrypted member's ciphertext is decrypted first; blocks whose previous ciphertext block is unknown are
    /// reported in `undecryptable`, and ciphertext a remaining hole still needs is kept durably.
    pub(crate) fn fill_packed(&self, volume: u32, offset: u64, bytes: &[u8]) -> PartialResult<PackedFillResult> {
        self.budget.limits.check(PartialResource::FillBytes, bytes.len() as u64)?;
        let end = offset.checked_add(bytes.len() as u64).ok_or_else(malformed)?;
        let mut op = self.operation()?;
        self.check(&op)?;
        self.flush_group(&mut op)?;
        self.reconcile(&mut op)?;
        self.budget.metadata(op.state.wire.len() as u64 + std::mem::size_of::<Range<u64>>() as u64)?;
        let keys = match (&op.snapshot.crypt, &self.keys) {
            (None, _) => None,
            (Some(_), Some(keys)) => Some(keys),
            (Some(_), None) => return Err(err(PartialErrorKind::PasswordRequired)),
        };
        let limit = cipher::stream_produced(&op.snapshot);
        let parts = op.snapshot.evidence.parts.len();
        // (packed bytes, ciphertext stream offset); the stream is the output for a plain member.
        let mut segments: Vec<(Range<u64>, u64)> = self.budget.vector(parts)?;
        for (part, stream) in cipher::parts_with_stream(&op.snapshot).filter(|(p, _)| p.packed.volume == volume) {
            let start = offset.max(part.packed.range.start);
            let stop = end.min(part.packed.range.end);
            if start >= stop {
                continue;
            }
            let at = stream + (start - part.packed.range.start);
            let at_end = (at + (stop - start)).min(limit);
            if at < at_end {
                segments.push((start..start + (at_end - at), at));
            }
        }
        let mut unmapped = self.budget.vector(segments.len() + 1)?;
        let mut at = offset;
        for (packed, _) in &segments {
            if at < packed.start {
                unmapped.push(PackedSpan { volume, range: at..packed.start });
            }
            at = packed.end;
        }
        if at < end {
            unmapped.push(PackedSpan { volume, range: at..end });
        }
        let mut applied = Vec::new();
        let mut corrected = Vec::new();
        let mut undecryptable = Vec::new();
        let mut kept = Vec::new();
        let progress = |op: &CoreData,
                        applied: Vec<Range<u64>>,
                        corrected: Vec<Range<u64>>,
                        undecryptable: Vec<Range<u64>>,
                        unmapped: Vec<PackedSpan>,
                        mut error: PartialError| {
            if let Some(step) = error.packed_progress.take() {
                let mut corrected = corrected;
                corrected.extend(step.corrected);
                if !applied.is_empty() || !corrected.is_empty() {
                    error.packed_progress = Some(Box::new(PackedFillResult {
                        revision: op.snapshot.head.revision,
                        applied,
                        corrected,
                        unmapped,
                        undecryptable,
                        state: op.state.clone(),
                        part_checks: Vec::new(),
                        needs_verification: true,
                    }));
                }
            } else if !applied.is_empty() || !corrected.is_empty() {
                error.packed_progress = Some(Box::new(PackedFillResult {
                    revision: op.snapshot.head.revision,
                    applied,
                    corrected,
                    unmapped,
                    undecryptable,
                    state: op.state.clone(),
                    part_checks: Vec::new(),
                    needs_verification: true,
                }));
            }
            error
        };
        let mut decryptions = self.budget.vector(segments.len())?;
        for (packed, stream) in &segments {
            let slice = &bytes[(packed.start - offset) as usize..(packed.end - offset) as usize];
            decryptions.push(match keys {
                Some(keys) => Some(cipher::decrypt(&self.budget, &op.snapshot, keys, *stream, slice)?),
                None => None,
            });
        }
        if keys.is_some() && !self.keys_proven.load(Ordering::Acquire) {
            self.prove_keys(&op, &decryptions)?;
        }
        for ((packed, stream), decrypted) in segments.into_iter().zip(decryptions) {
            let slice = &bytes[(packed.start - offset) as usize..(packed.end - offset) as usize];
            let writes: Vec<(u64, &[u8])> = match &decrypted {
                Some(d) => {
                    undecryptable.extend(d.undecryptable.iter().cloned());
                    d.runs.iter().map(|(out, range)| (*out, &d.plain[range.clone()])).collect()
                }
                None => vec![(stream, slice)],
            };
            for (out, plain) in writes {
                match self.write_data(&mut op, out, plain, FillMode::Packed) {
                    Ok(written) => {
                        applied.extend(written.applied);
                        corrected.extend(written.corrected);
                    }
                    Err(error) => return Err(progress(&op, applied, corrected, undecryptable, unmapped, error)),
                }
            }
            if decrypted.is_some() {
                kept.extend(cipher::keep(&self.budget, &op.snapshot, stream, slice)?);
            }
        }
        if !kept.is_empty()
            && let Err(error) = self.keep_cipher(&mut op, &kept)
        {
            return Err(progress(&op, applied, corrected, undecryptable, unmapped, error));
        }
        let fill = match self.fill_result(&mut op, applied.clone()) {
            Ok(fill) => fill,
            Err(error) => return Err(progress(&op, applied, corrected, undecryptable, unmapped, error)),
        };
        Ok(PackedFillResult {
            revision: fill.revision,
            applied: fill.applied,
            corrected,
            unmapped,
            undecryptable,
            state: fill.state,
            part_checks: fill.part_checks,
            needs_verification: fill.needs_verification,
        })
    }
    /// Proves keys that passed no password check value before `fill_packed` writes with them: a decrypted block
    /// whose whole output the original extraction wrote must match it (one block per original leaf is tried, so an
    /// original block that is itself wrong does not refute the keys). A wrong password matches none
    /// (`WrongPassword`); a fill with no such block that would write unresolved output is `PasswordUnverified`.
    fn prove_keys(&self, op: &CoreData, decryptions: &[Option<cipher::Decrypted>]) -> PartialResult<()> {
        let snapshot = &op.snapshot;
        let size = snapshot.head.size;
        let mut writes = false;
        let mut refuted = false;
        for decrypted in decryptions.iter().flatten() {
            for (out, plain) in &decrypted.runs {
                let run = *out..*out + (plain.end - plain.start) as u64;
                writes |= cipher::unresolved(snapshot, run.clone(), true);
                let first = snapshot.known.partition_point(|leaf| leaf.range.end <= run.start);
                for leaf in &snapshot.known[first..] {
                    self.budget.usage.charge(Resource::SourceBookkeeping, 1)?;
                    if leaf.range.start >= run.end {
                        break;
                    }
                    if leaf.provenance != state::Provenance::Original {
                        continue;
                    }
                    // The first whole block of the run inside this leaf; the last block ends at the size.
                    let start = cipher::ceil_block(leaf.range.start.max(run.start));
                    let end = start.saturating_add(16).min(size);
                    if start >= end || end > leaf.range.end.min(run.end) {
                        continue;
                    }
                    let expected = &decrypted.plain
                        [plain.start + (start - run.start) as usize..plain.start + (end - run.start) as usize];
                    let mut actual = [0u8; 16];
                    let actual = &mut actual[..expected.len()];
                    self.budget.usage.charge(Resource::VerifyBytes, actual.len() as u64)?;
                    let count = crate::output::range::read_at(&self.native.output.file, start, actual)
                        .map_err(|e| io_error(OutputOperation::Read, e))?;
                    if count != actual.len() || actual != expected {
                        refuted = true;
                        continue;
                    }
                    self.keys_proven.store(true, Ordering::Release);
                    return Ok(());
                }
            }
        }
        if refuted {
            Err(err(PartialErrorKind::WrongPassword))
        } else if writes {
            Err(err(PartialErrorKind::PasswordUnverified))
        } else {
            Ok(())
        }
    }
    /// Durably keeps ciphertext blocks a remaining hole needs to decrypt later archive bytes.
    fn keep_cipher(&self, op: &mut CoreData, blocks: &[state::CipherBlock]) -> PartialResult<()> {
        let (mut intent, mut valid, _snapshots) = self.next_snapshots(op)?;
        cipher::merge(&self.budget, &mut valid.cipher, blocks)?;
        cipher::prune(&self.budget, &mut valid)?;
        if valid.cipher == op.snapshot.cipher {
            return Ok(());
        }
        // A copy of the kept list for the intent, charged while the transaction runs; `merge` already charged the
        // blocks added.
        let _copy =
            self.budget.metadata_lease((valid.cipher.len() * std::mem::size_of::<state::CipherBlock>()) as u64)?;
        intent.cipher = valid.cipher.clone();
        op.verification = None;
        let transaction = self.begin_transaction(op, intent, valid, Vec::new())?;
        self.finish_transaction(op, transaction)
    }
    /// Packed ranges of `volume` within `range` whose output is still unknown or came from an alt; output the
    /// original extraction wrote is skipped, so a refill reads only what it can change. For an encrypted member
    /// each range covers whole ciphertext blocks plus the block before, which CBC needs to decrypt the first. While
    /// the keys are unproven it starts one block earlier still, so the block before decrypts to output the original
    /// extraction wrote and proves them.
    pub(crate) fn refill_targets(&self, volume: u32, range: &Range<u64>) -> PartialResult<Vec<Range<u64>>> {
        let mut op = self.operation()?;
        self.check(&op)?;
        self.flush_group(&mut op)?;
        if op.uncertain.is_some() {
            // After an uncertain group commit the snapshot is not conservative: rebuild it from the store.
            self.reconcile(&mut op)?;
        }
        let snapshot = &op.snapshot;
        let produced = snapshot.head.produced;
        let mut targets: Vec<Range<u64>> = Vec::new();
        if snapshot.crypt.is_some() {
            let runs = cipher::unresolved_runs(&self.budget, snapshot)?;
            let total = cipher::stream_total(snapshot);
            let back = if self.keys.is_some() && !self.keys_proven.load(Ordering::Acquire) { 32 } else { 16 };
            for (part, stream) in cipher::parts_with_stream(snapshot).filter(|(p, _)| p.packed.volume == volume) {
                let start = range.start.max(part.packed.range.start);
                let stop = range.end.min(part.packed.range.end);
                if start >= stop {
                    continue;
                }
                let lo = stream + (start - part.packed.range.start);
                let hi = stream + (stop - part.packed.range.start);
                for run in &runs {
                    self.budget.usage.charge(Resource::SourceBookkeeping, 1)?;
                    let need_end = if run.end >= snapshot.head.size { total } else { cipher::ceil_block(run.end) };
                    let need = cipher::floor_block(run.start).saturating_sub(back).max(lo)..need_end.min(hi);
                    if need.start >= need.end {
                        continue;
                    }
                    let p = start + (need.start - lo)..start + (need.end - lo);
                    match targets.last_mut() {
                        Some(last) if last.end >= p.start => last.end = last.end.max(p.end),
                        _ => {
                            self.budget.usage.check(Resource::HoleIntervals, targets.len() as u64 + 1)?;
                            targets.push(p);
                        }
                    }
                }
            }
            return Ok(targets);
        }
        for part in snapshot.evidence.parts.iter().filter(|p| p.packed.volume == volume) {
            let start = range.start.max(part.packed.range.start);
            let stop = range.end.min(part.packed.range.end);
            if start >= stop {
                continue;
            }
            let out = part.out.start + (start - part.packed.range.start);
            let out_end = (out + (stop - start)).min(produced);
            let mut at = out;
            let mut push = |a: u64, b: u64| {
                if a < b {
                    let p = start + (a - out)..start + (b - out);
                    match targets.last_mut() {
                        Some(last) if last.end == p.start => last.end = p.end,
                        _ => targets.push(p),
                    }
                }
            };
            for leaf in &snapshot.known {
                if leaf.range.end <= at || leaf.range.start >= out_end {
                    continue;
                }
                push(at, leaf.range.start.max(at));
                let stop = leaf.range.end.min(out_end);
                if leaf.provenance == state::Provenance::Alt {
                    push(leaf.range.start.max(at), stop);
                }
                at = stop;
            }
            push(at, out_end);
        }
        self.budget.usage.check(Resource::HoleIntervals, targets.len() as u64)?;
        Ok(targets)
    }
    fn fill_result(&self, op: &mut CoreData, applied: Vec<Range<u64>>) -> PartialResult<FillResult> {
        let mut part_checks = self.budget.vector(op.snapshot.evidence.parts.len())?;
        if op.verification.as_ref().is_none_or(|v| v.revision != op.snapshot.head.revision) {
            let previous = self.part_results(op);
            op.verification =
                Some(verify::Verification::after(previous, &[], &op.snapshot, &self.budget, self.hash_key()).map_err(
                    |mut e| {
                        e.committed = Some(op.state.anchor.clone());
                        e
                    },
                )?);
        }
        let verification = op.verification.as_ref().unwrap();
        part_checks.extend_from_slice(&verification.parts);
        let needs_verification = verification.needs_verification();
        Ok(FillResult {
            revision: op.snapshot.head.revision,
            applied,
            state: op.state.clone(),
            part_checks,
            needs_verification,
        })
    }
    fn write_data(&self, op: &mut CoreData, offset: u64, bytes: &[u8], mode: FillMode) -> PartialResult<Written> {
        let alternate = mode != FillMode::Original;
        self.budget.limits.check(PartialResource::FillBytes, bytes.len() as u64)?;
        let end = offset.checked_add(bytes.len() as u64).ok_or_else(malformed)?;
        if end > op.snapshot.head.size {
            return Err(err(PartialErrorKind::InvalidOptions));
        }
        if bytes.is_empty() {
            return Ok(Written::default());
        }
        if self.read_chunk == 0 {
            return Err(err(PartialErrorKind::InvalidOptions));
        }
        if op.snapshot.writable_end().is_none_or(|limit| end > limit) {
            return Err(err(PartialErrorKind::BindingMismatch(BindingField::Source)));
        }
        if !alternate && op.snapshot.head.tail.is_some() {
            return Err(err(PartialErrorKind::TailAbandoned));
        }
        if !alternate && offset > op.snapshot.head.produced {
            return Err(err(PartialErrorKind::IncompleteOutput));
        }
        if alternate && end > op.snapshot.head.produced {
            return Err(err(PartialErrorKind::IncompleteOutput));
        }
        let range = offset..end;
        // Packed bytes carry archive authority: alt leaves that differ are collected here and rewritten below.
        let (corrected, confirmed) = self.compare_known(op, offset, bytes, mode)?;
        let mut base = Vec::new();
        let mut _base_lease = None;
        if !corrected.is_empty() {
            let (mut scratch, _scratch) = self.clone_snapshot(&op.snapshot)?;
            for bad in &corrected {
                let (known, lease) = self.invalidate(&scratch, bad)?;
                scratch.known = known;
                _base_lease = Some(lease);
            }
            base = scratch.known;
        }
        let plan = if corrected.is_empty() {
            ledger::Ledger { known: &mut op.snapshot.known, size: op.snapshot.head.size, budget: &self.budget }
                .plan_fill(range.clone())?
        } else {
            ledger::Ledger { known: &mut base, size: op.snapshot.head.size, budget: &self.budget }
                .plan_fill(range.clone())?
        };
        if mode == FillMode::Alt {
            for range in &plan.unknown {
                let mut at = range.start;
                while at < range.end {
                    let mut next = at;
                    for report in &op.snapshot.holes {
                        self.budget.usage.charge(Resource::SourceBookkeeping, 1)?;
                        if report.out.start <= at && report.out.end > next {
                            next = report.out.end;
                        }
                    }
                    if next == at {
                        return Err(err(PartialErrorKind::IncompleteOutput));
                    }
                    at = next.min(range.end);
                }
            }
        }
        self.check(op)?;
        if plan.unknown.is_empty() && confirmed.is_empty() {
            return Ok(Written { applied: Vec::new(), corrected });
        }
        if !alternate && offset < op.snapshot.head.produced {
            return Err(err(PartialErrorKind::OverlapMismatch { range }));
        }
        let total: u64 = plan.unknown.iter().map(|r| r.end - r.start).sum();
        self.budget.usage.charge(Resource::OutputWriteBytes, total)?;
        let mut count = 0usize;
        for range in &plan.unknown {
            let mut at = range.start;
            while at < range.end {
                let boundary = op.snapshot.part_end(at).ok_or_else(malformed)?;
                at = range.end.min(boundary).min(at.saturating_add(65_536 - at % 65_536));
                count += 1;
            }
        }
        self.budget.limits.check(
            PartialResource::CrcLeaves,
            op.snapshot.known.len().checked_add(count).ok_or_else(malformed)? as u64,
        )?;
        let mut leaves = self.budget.vector(count)?;
        for range in &plan.unknown {
            let mut at = range.start;
            while at < range.end {
                let boundary = op.snapshot.part_end(at).ok_or_else(malformed)?;
                let stop = range.end.min(boundary).min(at.saturating_add(65_536 - at % 65_536));
                self.budget.usage.charge(Resource::VerifyWorkBytes, stop - at)?;
                let mut hasher = crate::crc32::Hasher::new();
                hasher.update(&bytes[(at - offset) as usize..(stop - offset) as usize]);
                leaves.push(state::KnownLeaf {
                    range: at..stop,
                    crc: hasher.clone().finalize(),
                    hasher,
                    provenance: if mode == FillMode::Alt {
                        state::Provenance::Alt
                    } else {
                        state::Provenance::Original
                    },
                    _lease: Arc::new(self.budget.reserve(PartialResource::CrcLeaves, 1)?),
                });
                at = stop;
            }
        }
        let (mut intent, mut commit, _snapshots) = self.next_snapshots(op)?;
        if !alternate {
            commit.head.produced = commit.head.produced.max(end);
        }
        if !corrected.is_empty() {
            // Until the rewrite commits, the differing alt bytes are known bad: a crash leaves them as holes.
            intent.known = base.clone();
            commit.known = base;
            let revision = intent.head.revision;
            // The intent is what a crash reopens, so its holes must fit the same limit reopening enforces.
            self.budget.usage.check(
                Resource::HoleIntervals,
                intent.holes.len().checked_add(corrected.len()).ok_or_else(malformed)? as u64,
            )?;
            for bad in &corrected {
                let report = self.report_for(&intent, revision, bad.clone(), HoleCause::DeclaredBad)?;
                intent.holes.push(report.clone());
                commit.holes.push(report);
            }
        }
        // Both lists are sorted by start; walk them together.
        let mut next = confirmed.iter().peekable();
        for leaf in commit.known.iter_mut() {
            while next.peek().is_some_and(|c| c.start < leaf.range.start) {
                next.next();
            }
            if next.peek().is_some_and(|c| **c == leaf.range) {
                leaf.provenance = state::Provenance::Original;
                next.next();
            }
        }
        ledger::Ledger { known: &mut commit.known, size: commit.head.size, budget: &self.budget }
            .commit_fill(&plan, &leaves)?;
        ledger::Ledger { known: &mut commit.known, size: commit.head.size, budget: &self.budget }.check_intervals()?;
        // Retain only still-unknown observed spans, including exact packed mappings.
        commit.holes = self.remaining_reports(&mut commit)?;
        if commit.crypt.is_some() {
            cipher::prune(&self.budget, &mut commit)?;
        }
        self.budget.metadata((plan.unknown.len() * std::mem::size_of::<Range<u64>>()) as u64)?;
        // Only the written and corrected ranges changed bytes; confirmation and
        // hole bookkeeping leave every leaf CRC as it was.
        let previous = self.part_results(op);
        let (mut changed, changed_lease) = self.budget.leased_vector(plan.unknown.len() + corrected.len())?;
        changed.extend(plan.unknown.iter().chain(&corrected).cloned());
        let verification = verify::Verification::after(previous, &changed, &commit, &self.budget, self.hash_key())?;
        drop((changed, changed_lease));
        // Once the intent is durable: the differing alt ranges are holes now, written or not. Report them on
        // failure so the caller still learns that alt was wrong.
        let progress = |op: &CoreData, mut error: PartialError| {
            if !corrected.is_empty() && error.packed_progress.is_none() {
                error.packed_progress = Some(Box::new(PackedFillResult {
                    revision: op.snapshot.head.revision,
                    applied: Vec::new(),
                    corrected: corrected.clone(),
                    unmapped: Vec::new(),
                    undecryptable: Vec::new(),
                    state: op.state.clone(),
                    part_checks: Vec::new(),
                    needs_verification: true,
                }));
            }
            error
        };
        let intent_revision = intent.head.revision;
        let transaction = match self.begin_transaction(op, intent, commit, plan.unknown.clone()) {
            Ok(transaction) => transaction,
            // The intent was acknowledged (or its CAS is uncertain) before the error: the alt ranges may be holes.
            Err(error) if op.snapshot.head.revision == intent_revision || op.uncertain.is_some() => {
                return Err(progress(op, error));
            }
            Err(error) => return Err(error),
        };
        let mut completed = 0usize;
        let write = (|| {
            for range in &plan.unknown {
                let mut at = range.start;
                while at < range.end {
                    canceled(&self.control)?;
                    self.native.check(op.snapshot.head.size)?;
                    let stop = range.end.min(at + self.read_chunk as u64);
                    let n = write_output(
                        &self.native.output.file,
                        at,
                        &bytes[(at - offset) as usize..(stop - offset) as usize],
                    )
                    .map_err(|e| io_error(OutputOperation::Write, e))?;
                    if n == 0 {
                        return Err(io_error(OutputOperation::Write, std::io::ErrorKind::WriteZero.into()));
                    }
                    completed += n;
                    at += n as u64;
                    #[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
                    tests::state::checkpoint("write");
                }
            }
            Ok(())
        })();
        let refresh = (|| {
            #[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
            tests::state::fault_post_write_stamp().map_err(|e| io_error(OutputOperation::Metadata, e))?;
            op.stamp = stamp(&self.native)?;
            Ok(())
        })();
        // A secondary stamp failure must not replace the write failure or its progress.
        if let Err(mut error) = write.and(refresh) {
            error.committed = Some(transaction.intent.anchor.clone());
            error.output =
                Some(crate::progressive::OutputRange { offset, attempted: total, completed: completed as u64 });
            return Err(progress(op, error));
        }
        if let Err(error) = self.finish_transaction(op, transaction) {
            return Err(progress(op, error));
        }
        op.verification = Some(verification);
        Ok(Written { applied: plan.unknown, corrected })
    }
    fn grouping(&self) -> bool {
        self.budget.limits.group_commit_bytes > 0
    }
    /// Writes `bytes` at `offset` inside a group: an original write at `produced`, or an alt write that may only
    /// land in holes. Validation and overlap checks are those of `write_data`. The group's intent is anchored
    /// before the first byte reaches output; leaves join the in-memory snapshot, and nothing else is durable until
    /// the group commits. Work per write is proportional to the bytes written, not to the ledger.
    fn group_write(
        &self,
        op: &mut CoreData,
        offset: u64,
        bytes: &[u8],
        mode: FillMode,
    ) -> PartialResult<Vec<Range<u64>>> {
        debug_assert!(matches!(mode, FillMode::Original | FillMode::Alt));
        self.budget.limits.check(PartialResource::FillBytes, bytes.len() as u64)?;
        let end = offset.checked_add(bytes.len() as u64).ok_or_else(malformed)?;
        if end > op.snapshot.head.size || self.read_chunk == 0 {
            return Err(err(PartialErrorKind::InvalidOptions));
        }
        if bytes.is_empty() {
            return Ok(Vec::new());
        }
        if op.snapshot.writable_end().is_none_or(|limit| end > limit) {
            return Err(err(PartialErrorKind::BindingMismatch(BindingField::Source)));
        }
        match mode {
            FillMode::Original if op.snapshot.head.tail.is_some() => {
                return Err(err(PartialErrorKind::TailAbandoned));
            }
            FillMode::Original if offset != op.snapshot.head.produced => {
                return Err(err(PartialErrorKind::IncompleteOutput));
            }
            FillMode::Alt if end > op.snapshot.head.produced => return Err(err(PartialErrorKind::IncompleteOutput)),
            _ => {}
        }
        let range = offset..end;
        // Alt bytes over known output must match it (packed corrections never group).
        self.compare_known(op, offset, bytes, mode)?;
        let plan = ledger::Ledger { known: &mut op.snapshot.known, size: op.snapshot.head.size, budget: &self.budget }
            .plan_fill(range.clone())?;
        if mode == FillMode::Alt {
            // Holes reported before the group still cover these ranges: grouped writes only make holes smaller,
            // and the reports are trimmed when the group commits.
            for range in &plan.unknown {
                let mut at = range.start;
                while at < range.end {
                    let mut next = at;
                    for report in &op.snapshot.holes {
                        self.budget.usage.charge(Resource::SourceBookkeeping, 1)?;
                        if report.out.start <= at && report.out.end > next {
                            next = report.out.end;
                        }
                    }
                    if next == at {
                        return Err(err(PartialErrorKind::IncompleteOutput));
                    }
                    at = next.min(range.end);
                }
            }
        }
        if plan.unknown.is_empty() {
            return Ok(Vec::new());
        }
        let total: u64 = plan.unknown.iter().map(|r| r.end - r.start).sum();
        self.budget.usage.charge(Resource::OutputWriteBytes, total)?;
        let snapshot = &op.snapshot;
        let part_end = |at: u64| -> PartialResult<u64> { snapshot.part_end(at).ok_or_else(malformed) };
        let mut count = 0usize;
        for range in &plan.unknown {
            let mut at = range.start;
            while at < range.end {
                at = range.end.min(part_end(at)?).min(at.saturating_add(65_536 - at % 65_536));
                count += 1;
            }
        }
        self.budget.limits.check(
            PartialResource::CrcLeaves,
            op.snapshot.known.len().checked_add(count).ok_or_else(malformed)? as u64,
        )?;
        // Transient: the leaves are cloned into the snapshot below, where they are charged.
        let (mut leaves, _leaves) = self.budget.leased_vector(count)?;
        for range in &plan.unknown {
            let mut at = range.start;
            while at < range.end {
                let stop = range.end.min(part_end(at)?).min(at.saturating_add(65_536 - at % 65_536));
                self.budget.usage.charge(Resource::VerifyWorkBytes, stop - at)?;
                let mut hasher = crate::crc32::Hasher::new();
                hasher.update(&bytes[(at - offset) as usize..(stop - offset) as usize]);
                leaves.push(state::KnownLeaf {
                    range: at..stop,
                    crc: hasher.clone().finalize(),
                    hasher,
                    provenance: if mode == FillMode::Alt {
                        state::Provenance::Alt
                    } else {
                        state::Provenance::Original
                    },
                    _lease: Arc::new(self.budget.reserve(PartialResource::CrcLeaves, 1)?),
                });
                at = stop;
            }
        }
        self.budget.metadata(std::mem::size_of_val(leaves.as_slice()) as u64)?;
        op.snapshot.known.try_reserve(leaves.len()).map_err(|_| malformed())?;
        if op.group.is_none() {
            self.begin_group(op)?;
        }
        let intent = op.group.as_ref().unwrap().intent.anchor.clone();
        let mut completed = 0usize;
        let write = (|| {
            for range in &plan.unknown {
                let mut at = range.start;
                while at < range.end {
                    canceled(&self.control)?;
                    self.native.check(op.snapshot.head.size)?;
                    let stop = range.end.min(at + self.read_chunk as u64);
                    let n = write_output(
                        &self.native.output.file,
                        at,
                        &bytes[(at - offset) as usize..(stop - offset) as usize],
                    )
                    .map_err(|e| io_error(OutputOperation::Write, e))?;
                    if n == 0 {
                        return Err(io_error(OutputOperation::Write, std::io::ErrorKind::WriteZero.into()));
                    }
                    completed += n;
                    at += n as u64;
                    #[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
                    tests::state::checkpoint("write");
                }
            }
            Ok(())
        })();
        let refresh = (|| {
            #[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
            tests::state::fault_post_write_stamp().map_err(|e| io_error(OutputOperation::Metadata, e))?;
            op.stamp = stamp(&self.native)?;
            Ok(())
        })();
        // The group stays open: output written before this call is still committed by the next commit, and the
        // bytes of this call stay unknown.
        if let Err(mut error) = write.and(refresh) {
            error.committed = Some(intent);
            error.output =
                Some(crate::progressive::OutputRange { offset, attempted: total, completed: completed as u64 });
            return Err(error);
        }
        // Insert the leaves in order: one splice per unknown range (an original write appends).
        let known = &mut op.snapshot.known;
        let mut pending = leaves.as_slice();
        while let Some(first) = pending.first() {
            let at = known.partition_point(|leaf| leaf.range.start < first.range.start);
            let next = known.get(at).map_or(u64::MAX, |leaf| leaf.range.start);
            let run = pending.partition_point(|leaf| leaf.range.start < next);
            known.splice(at..at, pending[..run].iter().cloned());
            pending = &pending[run..];
        }
        if mode == FillMode::Original {
            op.snapshot.head.produced = end;
        }
        // Part results and verification are keyed by revision, which a group does not advance.
        op.verification = None;
        op.part_results = None;
        let group = op.group.as_mut().unwrap();
        group.bytes = group.bytes.saturating_add(total);
        if group.bytes >= self.budget.limits.group_commit_bytes
            || group.opened.elapsed() >= self.budget.limits.group_commit_interval
        {
            self.flush_group(op)?;
        }
        Ok(plan.unknown)
    }
    /// Anchors the intent of a new group: the committed head with the next sequence and revision. The ledger is
    /// unchanged (grouped writes only add output the committed state calls unknown), so only the record is written.
    fn begin_group(&self, op: &mut CoreData) -> PartialResult<()> {
        let next_head = |op: &CoreData| -> PartialResult<state::CommittedState> {
            let mut head = op.snapshot.head.clone();
            head.sequence = head.sequence.checked_add(1).ok_or_else(malformed)?;
            head.revision = head.revision.checked_add(1).ok_or_else(malformed)?;
            Ok(head)
        };
        let prior_sequence = op.state.anchor().sequence();
        let result = (|| {
            let mut head = next_head(op)?;
            let probe = state::encode_record(2, head.revision, Some(op.state.anchor()), &head, &self.budget.limits)?;
            let files = [(format!("r-{}", native::hex(probe.anchor().digest())), probe.wire, false)];
            if op.bundle.needs_compaction(&op.snapshot.head, &files)? {
                self.compact_locked(op)?;
                head = next_head(op)?;
            }
            self.check(op)?;
            let expected = op.state.clone();
            let intent = op.bundle.group_intent(expected.anchor(), &head)?;
            #[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
            tests::state::checkpoint("intent-sync");
            op.uncertain = Some(Uncertain {
                expected: expected.clone(),
                intent: intent.clone(),
                commit: None,
                candidate_known: None,
            });
            let ack = self.anchors.advance(Some(expected.anchor()), intent.anchor()).map_err(|mut e| {
                e.committed = Some(expected.anchor.clone());
                e
            })?;
            op.bundle.acknowledge(intent.anchor(), &ack)?;
            op.state = intent.clone();
            op.snapshot.head = head;
            op.uncertain = None;
            op.group = Some(Group { intent: intent.clone(), bytes: 0, opened: std::time::Instant::now() });
            #[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
            tests::state::checkpoint("intent-cas");
            self.check(op).map_err(|mut e| {
                e.committed = Some(intent.anchor.clone());
                e
            })
        })();
        result.map_err(|mut error: PartialError| {
            if error.committed.is_none() && op.state.anchor().sequence() != prior_sequence {
                error.committed = Some(op.state.anchor().clone());
            }
            error
        })
    }
    /// Commits the open group, if any: trims holes and kept ciphertext to what is still unknown, writes the changed
    /// ledger pages, syncs the output, then appends and anchors the commit record. A failure before the anchor CAS
    /// keeps the group open (the next operation tries again); an uncertain CAS leaves recovery to `reconcile`,
    /// which rebuilds the snapshot from whichever state the store holds.
    fn flush_group(&self, op: &mut CoreData) -> PartialResult<()> {
        let Some(group) = &op.group else { return Ok(()) };
        let mut intent = group.intent.clone();
        let result = (|| {
            self.check(op)?;
            if !op.snapshot.holes.is_empty() {
                let holes = self.remaining_reports(&mut op.snapshot)?;
                op.snapshot.holes = holes;
            }
            if op.snapshot.crypt.is_some() {
                cipher::prune(&self.budget, &mut op.snapshot)?;
            }
            ledger::Ledger { known: &mut op.snapshot.known, size: op.snapshot.head.size, budget: &self.budget }
                .check_intervals()?;
            let mut lease = Lease::empty(&self.budget.usage, Resource::MetadataBytes);
            let (refs, mut files) = op.bundle.encode_refs(&op.snapshot, &mut lease)?;
            let commit_head = |intent: &PartialState, op: &CoreData| -> PartialResult<state::CommittedState> {
                let mut head = op.snapshot.head.clone();
                head.sequence = intent.anchor().sequence().checked_add(1).ok_or_else(malformed)?;
                head.pages = refs.clone();
                Ok(head)
            };
            let mut head = commit_head(&intent, op)?;
            let mut commit = state::encode_record(3, head.revision, Some(intent.anchor()), &head, &self.budget.limits)?;
            files.push((format!("r-{}", native::hex(commit.anchor().digest())), commit.wire.clone(), false));
            if op.bundle.needs_compaction(&op.snapshot.head, &files)? {
                // The compaction state re-anchors the intent's content (its head still names the intent's pages);
                // the group then commits on top of it.
                self.compact_locked(op)?;
                intent = op.state.clone();
                op.group.as_mut().unwrap().intent = intent.clone();
                head = commit_head(&intent, op)?;
                commit = state::encode_record(3, head.revision, Some(intent.anchor()), &head, &self.budget.limits)?;
                files.pop();
                files.push((format!("r-{}", native::hex(commit.anchor().digest())), commit.wire.clone(), false));
            }
            op.bundle.reserve_files(&files)?;
            op.bundle.write_pages(&files)?;
            #[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
            tests::state::fault_sync().map_err(|e| io_error(OutputOperation::Flush, e))?;
            self.native.sync()?;
            #[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
            tests::state::checkpoint("output-sync");
            self.check(op)?;
            op.bundle.append_record(&commit)?;
            #[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
            tests::state::checkpoint("commit-sync");
            op.uncertain = Some(Uncertain {
                expected: intent.clone(),
                intent: intent.clone(),
                commit: Some(commit.clone()),
                candidate_known: None,
            });
            op.group = None;
            let ack = self.anchors.advance(Some(intent.anchor()), commit.anchor())?;
            op.bundle.acknowledge(commit.anchor(), &ack)?;
            op.state = commit.clone();
            op.snapshot.head = head;
            op.uncertain = None;
            #[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
            tests::state::checkpoint("commit-cas");
            self.check(op).map_err(|mut e| {
                e.committed = Some(commit.anchor.clone());
                e
            })
        })();
        result.map_err(|mut e| {
            if op.uncertain.is_some() {
                // `reconcile` rebuilds from the store; the in-memory group is no longer authoritative.
                op.group = None;
            }
            if e.committed.is_none() {
                e.committed = Some(op.state.anchor.clone());
            }
            e
        })
    }
    /// Compares `bytes` with every known leaf they overlap. A difference is an error, except that packed fills
    /// return the differing alt leaf ranges (clipped to the fill) so they can be rewritten.
    fn compare_known(
        &self,
        op: &CoreData,
        offset: u64,
        bytes: &[u8],
        mode: FillMode,
    ) -> PartialResult<(Ranges, Ranges)> {
        let end = offset + bytes.len() as u64;
        let mut corrected: Vec<Range<u64>> = Vec::new();
        let mut confirmed: Vec<Range<u64>> = Vec::new();
        let first = op.snapshot.known.partition_point(|leaf| leaf.range.end <= offset);
        if op.snapshot.known.get(first).is_none_or(|leaf| leaf.range.start >= end) {
            return Ok((corrected, confirmed));
        }
        // Scratch freed on return; read_chunk already caps its size.
        let (mut compare, _compare) = self.budget.leased_vector(bytes.len().min(self.read_chunk))?;
        compare.resize(bytes.len().min(self.read_chunk), 0);
        for leaf in op.snapshot.known[first..].iter().take_while(|leaf| leaf.range.start < end) {
            let start = offset.max(leaf.range.start);
            let stop = end.min(leaf.range.end);
            if start >= stop {
                continue;
            }
            let mut at = start;
            let mut differs = false;
            while at < stop {
                canceled(&self.control)?;
                let n = (stop - at).min(compare.len() as u64) as usize;
                self.budget.usage.charge(Resource::VerifyBytes, n as u64)?;
                self.budget.usage.charge(Resource::VerifyWorkBytes, n as u64)?;
                let count = crate::output::range::read_at(&self.native.output.file, at, &mut compare[..n])
                    .map_err(|e| io_error(OutputOperation::Read, e))?;
                let i = (at - offset) as usize;
                if count == 0 || compare[..count] != bytes[i..i + count] {
                    if mode == FillMode::Packed && leaf.provenance == state::Provenance::Alt && count != 0 {
                        match corrected.last_mut() {
                            Some(last) if last.end == start => last.end = stop,
                            _ => {
                                self.budget.usage.check(Resource::HoleIntervals, corrected.len() as u64 + 1)?;
                                corrected.push(start..stop);
                            }
                        }
                        differs = true;
                        break;
                    }
                    return Err(err(PartialErrorKind::OverlapMismatch { range: start..stop }));
                }
                at += count as u64;
            }
            // An alt leaf wholly confirmed by archive bytes is archive output from now on; refills skip it.
            if mode == FillMode::Packed
                && !differs
                && leaf.provenance == state::Provenance::Alt
                && start == leaf.range.start
                && stop == leaf.range.end
            {
                confirmed.push(leaf.range.clone());
            }
        }
        Ok((corrected, confirmed))
    }
    fn report_for(
        &self,
        snapshot: &Snapshot,
        revision: u64,
        out: Range<u64>,
        cause: HoleCause,
    ) -> PartialResult<HoleReport> {
        let packed = cipher::packed_spans(&self.budget, snapshot, &out)?;
        self.budget.metadata(std::mem::size_of::<HoleReport>() as u64)?;
        Ok(HoleReport {
            id: revision,
            revision,
            member: snapshot.head.member.clone(),
            name: snapshot.name.clone(),
            out,
            packed,
            cause,
        })
    }
    fn begin_transaction(
        &self,
        data: &mut CoreData,
        mut intent: Snapshot,
        mut valid: Snapshot,
        affected: Vec<Range<u64>>,
    ) -> PartialResult<Transaction> {
        let prior_sequence = data.state.anchor().sequence();
        let result = (|| {
            // These copies live until the transaction finishes (or, on failure,
            // until the uncertain record is resolved); charge them that long.
            let mut lease = self.budget.metadata_lease(data.state.wire.len() as u64)?;
            let mut expected = data.state.clone();
            let (mut intent_known, known) = self.budget.leased_vector(intent.known.len())?;
            lease.absorb(known);
            intent_known.extend_from_slice(&intent.known);
            let (mut commit_known, known) = self.budget.leased_vector(valid.known.len())?;
            lease.absorb(known);
            commit_known.extend_from_slice(&valid.known);
            let (mut intent_state, mut commit_state, mut files, mut pages) =
                data.bundle.prepare_mutation(expected.anchor(), &mut intent, &mut valid)?;
            if data.bundle.needs_compaction(&data.snapshot.head, &files)? {
                self.compact_locked(data)?;
                expected = data.state.clone();
                intent.head.sequence = data.snapshot.head.sequence.checked_add(1).ok_or_else(malformed)?;
                valid.head.sequence = intent.head.sequence.checked_add(1).ok_or_else(malformed)?;
                (intent_state, commit_state, files, pages) =
                    data.bundle.prepare_mutation(expected.anchor(), &mut intent, &mut valid)?;
            }
            lease.absorb(pages);
            data.bundle.reserve_files(&files)?;
            data.bundle.write_pages(&files)?;
            self.check(data)?;
            let record = MutationIntent {
                transaction: intent.head.revision,
                parent: Some(expected.anchor.clone()),
                conservative: intent.head.clone(),
                affected,
            };
            let anchor = data.bundle.append_intent(&record)?;
            #[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
            tests::state::checkpoint("intent-sync");
            data.uncertain = Some(Uncertain {
                expected: expected.clone(),
                intent: intent_state.clone(),
                commit: None,
                candidate_known: Some(intent_known),
            });
            let ack = self.anchors.advance(Some(expected.anchor()), &anchor).map_err(|mut e| {
                e.committed = Some(expected.anchor.clone());
                e
            })?;
            data.bundle.acknowledge(&anchor, &ack)?;
            data.state = intent_state.clone();
            data.snapshot = intent;
            data.uncertain = None;
            #[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
            tests::state::checkpoint("intent-cas");
            self.check(data).map_err(|mut e| {
                e.committed = Some(anchor);
                e
            })?;
            Ok(Transaction { intent: intent_state, commit: commit_state, valid, commit_known, _lease: lease })
        })();
        result.map_err(|mut error: PartialError| {
            if error.committed.is_none() && data.state.anchor().sequence() != prior_sequence {
                error.committed = Some(data.state.anchor().clone());
            }
            error
        })
    }
    fn finish_transaction(&self, data: &mut CoreData, transaction: Transaction) -> PartialResult<()> {
        let intent_anchor = transaction.intent.anchor.clone();
        let finish = (|| {
            #[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
            tests::state::fault_sync().map_err(|e| io_error(OutputOperation::Flush, e))?;
            self.native.sync()?;
            #[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
            tests::state::checkpoint("output-sync");
            self.check(data)?;
            let record = MutationCommit {
                transaction: transaction.valid.head.revision,
                parent: intent_anchor.clone(),
                valid: transaction.valid.head.clone(),
            };
            let final_anchor = data.bundle.append_commit(&record)?;
            #[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
            tests::state::checkpoint("commit-sync");
            data.uncertain = Some(Uncertain {
                expected: transaction.intent.clone(),
                intent: transaction.intent,
                commit: Some(transaction.commit.clone()),
                candidate_known: Some(transaction.commit_known),
            });
            let ack = self.anchors.advance(Some(&intent_anchor), &final_anchor)?;
            data.bundle.acknowledge(&final_anchor, &ack)?;
            data.state = transaction.commit;
            data.snapshot = transaction.valid;
            data.uncertain = None;
            #[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
            tests::state::checkpoint("commit-cas");
            self.check(data).map_err(|mut e| {
                e.committed = Some(final_anchor);
                e
            })
        })();
        finish.map_err(|mut e| {
            if e.committed.is_none() {
                e.committed = Some(intent_anchor);
            }
            e
        })
    }
    /// Intent and commit copies for one transaction; keep the lease until it finishes. If the transaction fails, the
    /// copies kept in `uncertain` for reconciliation are uncharged until it runs (one transaction's worth, bounded).
    fn next_snapshots(&self, data: &CoreData) -> PartialResult<(Snapshot, Snapshot, Lease)> {
        let (mut intent, mut lease) = self.clone_snapshot(&data.snapshot)?;
        intent.head.sequence = intent.head.sequence.checked_add(1).ok_or_else(malformed)?;
        intent.head.revision = intent.head.revision.checked_add(1).ok_or_else(malformed)?;
        let (mut valid, copy) = self.clone_snapshot(&intent)?;
        lease.absorb(copy);
        valid.head.sequence = valid.head.sequence.checked_add(1).ok_or_else(malformed)?;
        Ok((intent, valid, lease))
    }
    pub(crate) fn hash_key(&self) -> Option<&[u8; 32]> {
        self.keys.as_ref().map(|keys| &keys.hash)
    }
    /// Builds the report of the next revision for observed output `out`, with its exact packed spans.
    pub(crate) fn hole_report(&self, out: Range<u64>, cause: HoleCause) -> PartialResult<HoleReport> {
        let data = self.operation()?;
        self.check(&data)?;
        let revision = data.snapshot.head.revision.checked_add(1).ok_or_else(malformed)?;
        self.report_for(&data.snapshot, revision, out, cause)
    }
    #[cfg(test)]
    pub(crate) fn record_hole(&self, report: HoleReport) -> PartialResult<()> {
        self.record_hole_with(report, &[])
    }
    /// Records a hole and keeps the ciphertext `blocks` next to it (encrypted members) in the same transaction.
    pub(crate) fn record_hole_with(&self, report: HoleReport, blocks: &[state::CipherBlock]) -> PartialResult<()> {
        self.record_hole_inner(report, blocks, &[])
    }
    /// Records a hole, keeps `blocks`, and drops every kept block overlapping a `damaged` stream range, all in one
    /// transaction.
    fn record_hole_inner(
        &self,
        report: HoleReport,
        blocks: &[state::CipherBlock],
        damaged: &[Range<u64>],
    ) -> PartialResult<()> {
        let mut data = self.operation()?;
        self.check(&data)?;
        self.flush_group(&mut data)?;
        self.reconcile(&mut data)?;
        if report.member != data.snapshot.head.member
            || report.name != data.snapshot.name
            || !matches!(report.cause, HoleCause::Missing | HoleCause::DeclaredBad | HoleCause::CipherNeighbour)
            || (report.cause == HoleCause::CipherNeighbour && data.snapshot.crypt.is_none())
            || (!blocks.is_empty() && data.snapshot.crypt.is_none())
            || report.out.start >= report.out.end
            || report.out.end > data.snapshot.head.size
            || report.revision != data.snapshot.head.revision.checked_add(1).ok_or_else(malformed)?
        {
            return Err(err(PartialErrorKind::BindingMismatch(BindingField::Member)));
        }
        // The packed spans must be exactly those of the output range (block-widened for encrypted members).
        if report.packed != cipher::packed_spans(&self.budget, &data.snapshot, &report.out)?
            || data.snapshot.holes.iter().any(|h| h.id == report.id)
        {
            return Err(malformed());
        }
        let (mut intent, mut valid, _snapshots) = self.next_snapshots(&data)?;
        if report.out.start > data.snapshot.head.produced
            || (report.out.end > data.snapshot.head.produced && report.out.start != data.snapshot.head.produced)
        {
            return Err(err(PartialErrorKind::IncompleteOutput));
        }
        // Every copy below replaces a vector the snapshot already holds, so it is charged only while this
        // transaction runs: a hole costs what the state keeps for it, not a copy of the whole member's index.
        let (known, mut lease) = self.invalidate(&data.snapshot, &report.out)?;
        intent.known = known;
        lease
            .absorb(self.budget.metadata_lease((intent.known.len() * std::mem::size_of::<state::KnownLeaf>()) as u64)?);
        valid.known = intent.known.clone();
        valid.head.produced = valid.head.produced.max(report.out.end);
        intent.head.produced = valid.head.produced;
        ledger::Ledger { known: &mut intent.known, size: intent.head.size, budget: &self.budget }.check_intervals()?;
        let affected = report.out.clone();
        // A source answers at most one read buffer per Hole, so one unread range arrives as many holes in a row.
        // A hole that continues the last recorded one (same cause, next output, packed bytes running on in the
        // same volume) extends that record, so a contiguous range keeps one record whatever its length. The
        // event delivered for this hole is unchanged.
        let continues = valid.holes.last().is_some_and(|last| {
            last.cause == report.cause
                && last.out.end == report.out.start
                && match (last.packed.last(), report.packed.first()) {
                    (Some(a), Some(b)) => a.volume == b.volume && a.range.end == b.range.start,
                    _ => false,
                }
        });
        if continues {
            let last = valid.holes.last_mut().expect("checked above");
            self.budget.metadata(((report.packed.len() - 1) * std::mem::size_of::<PackedSpan>()) as u64)?;
            last.packed.try_reserve_exact(report.packed.len() - 1).map_err(|_| malformed())?;
            last.out.end = report.out.end;
            let mut spans = report.packed.into_iter();
            let first = spans.next().expect("checked above");
            last.packed.last_mut().expect("checked above").range.end = first.range.end;
            last.packed.extend(spans);
        } else {
            self.budget.usage.check(
                Resource::HoleIntervals,
                data.snapshot.holes.len().checked_add(1).ok_or_else(malformed)? as u64,
            )?;
            self.budget.metadata(
                (std::mem::size_of::<HoleReport>() + report.packed.len() * std::mem::size_of::<PackedSpan>()) as u64,
            )?;
            valid.holes.try_reserve_exact(1).map_err(|_| malformed())?;
            valid.holes.push(report);
        }
        lease.absorb(
            self.budget.metadata_lease(
                valid
                    .holes
                    .iter()
                    .map(|h| std::mem::size_of::<HoleReport>() + h.packed.len() * std::mem::size_of::<PackedSpan>())
                    .sum::<usize>() as u64,
            )?,
        );
        intent.holes = valid.holes.clone();
        if !blocks.is_empty() {
            cipher::merge(&self.budget, &mut valid.cipher, blocks)?;
        }
        let forgot = cipher::forget(&self.budget, &mut valid.cipher, damaged)?;
        if !blocks.is_empty() || forgot {
            // A copy of the kept list for the intent; `merge` already charged the blocks this hole added.
            lease.absorb(
                self.budget.metadata_lease((valid.cipher.len() * std::mem::size_of::<state::CipherBlock>()) as u64)?,
            );
            intent.cipher = valid.cipher.clone();
        }
        let transaction = self.begin_transaction(&mut data, intent, valid, vec![affected])?;
        self.finish_transaction(&mut data, transaction)
    }
    /// Whether any proven part of this member lies in `range` of `volume`. Checked without taking the
    /// operation or touching the output, so unrelated members never fail a declaration; a member busy in another
    /// operation answers true and is then tried for real.
    /// Packed ranges of every part recorded so far, for a session that releases this core.
    pub(crate) fn packed_parts(&self) -> Vec<PackedSpan> {
        self.data
            .lock()
            .unwrap()
            .as_ref()
            .map_or_else(Vec::new, |data| data.snapshot.evidence.parts.iter().map(|part| part.packed.clone()).collect())
    }
    pub(crate) fn touches(&self, volume: u32, range: &Range<u64>) -> bool {
        self.data.lock().unwrap().as_ref().is_none_or(|data| {
            data.snapshot.evidence.parts.iter().any(|part| {
                part.packed.volume == volume
                    && part.packed.range.start < range.end
                    && range.start < part.packed.range.end
            })
        })
    }
    /// Maps damage declared on archive bytes of `volume` to this member's already written output. Each run of
    /// output that was still known becomes a durable `DeclaredBad` hole. Also returns the packed sub-ranges whose
    /// output this member has produced, known or not, so callers can tell mapped from unmapped damage. For an
    /// encrypted member the damaged ciphertext blocks are `DeclaredBad` and the block after them, which CBC
    /// decrypts with the damaged block, becomes a `CipherNeighbour` hole. Kept ciphertext blocks overlapping the
    /// damage are dropped in the transaction of the first new hole (or alone when there is none), so a later
    /// `fill_packed` never decrypts with them.
    pub(crate) fn declare_damage(
        &self,
        volume: u32,
        range: &Range<u64>,
    ) -> PartialResult<(Vec<HoleReport>, Vec<Range<u64>>)> {
        if range.start >= range.end {
            return Err(err(PartialErrorKind::InvalidOptions));
        }
        let (runs, mapped, damaged, forget) = {
            let mut data = self.operation()?;
            self.check(&data)?;
            self.flush_group(&mut data)?;
            self.reconcile(&mut data)?;
            let snapshot = &data.snapshot;
            let produced = snapshot.head.produced;
            let limit = cipher::stream_produced(snapshot);
            let encrypted = snapshot.crypt.is_some();
            let mut runs: Vec<(Range<u64>, HoleCause)> = self.budget.vector(snapshot.known.len() + 2)?;
            let mut mapped = self.budget.vector(snapshot.evidence.parts.len())?;
            let mut damaged = self.budget.vector(if encrypted { snapshot.evidence.parts.len() } else { 0 })?;
            for (part, stream) in cipher::parts_with_stream(snapshot).filter(|(p, _)| p.packed.volume == volume) {
                let start = range.start.max(part.packed.range.start);
                let end = range.end.min(part.packed.range.end);
                if start >= end {
                    continue;
                }
                let at = stream + (start - part.packed.range.start);
                let at_end = stream + (end - part.packed.range.start);
                if encrypted {
                    damaged.push(at..at_end);
                }
                if at >= at_end.min(limit) {
                    continue;
                }
                mapped.push(start..start + (at_end.min(limit) - at));
                let bad = if encrypted { cipher::floor_block(at)..cipher::ceil_block(at_end) } else { at..at_end };
                let neighbour = if encrypted { bad.end..bad.end.saturating_add(16) } else { bad.end..bad.end };
                for (out, cause) in [(bad, HoleCause::DeclaredBad), (neighbour, HoleCause::CipherNeighbour)] {
                    let out = out.start.min(produced)..out.end.min(produced);
                    for leaf in &snapshot.known {
                        let a = leaf.range.start.max(out.start);
                        let b = leaf.range.end.min(out.end);
                        if a >= b {
                            continue;
                        }
                        match runs.last_mut() {
                            Some((run, kind)) if run.end == a && *kind == cause => run.end = b,
                            _ => {
                                if runs.len() == runs.capacity() {
                                    return Err(err(PartialErrorKind::Limit {
                                        resource: PartialResource::CrcLeaves,
                                        limit: runs.capacity() as u64,
                                        attempted: runs.len() as u64 + 1,
                                    }));
                                }
                                runs.push((a..b, cause.clone()));
                            }
                        }
                    }
                }
            }
            let forget = damaged.iter().any(|range| {
                snapshot.cipher.iter().any(|block| block.offset < range.end && range.start < block.offset + 16)
            });
            (runs, mapped, damaged, forget)
        };
        let mut reports = self.budget.vector(runs.len())?;
        for (index, (out, cause)) in runs.into_iter().enumerate() {
            let report = self.hole_report(out, cause)?;
            self.record_hole_inner(report.clone(), &[], if index == 0 { &damaged } else { &[] })?;
            reports.push(report);
        }
        if reports.is_empty() && forget {
            self.forget_cipher(&damaged)?;
        }
        Ok((reports, mapped))
    }
    /// Durably drops kept ciphertext blocks overlapping `damaged` stream ranges when no hole records it.
    fn forget_cipher(&self, damaged: &[Range<u64>]) -> PartialResult<()> {
        let mut op = self.operation()?;
        self.check(&op)?;
        self.flush_group(&mut op)?;
        self.reconcile(&mut op)?;
        let (mut intent, mut valid, _snapshots) = self.next_snapshots(&op)?;
        if !cipher::forget(&self.budget, &mut valid.cipher, damaged)? {
            return Ok(());
        }
        intent.cipher = valid.cipher.clone();
        op.verification = None;
        let transaction = self.begin_transaction(&mut op, intent, valid, Vec::new())?;
        self.finish_transaction(&mut op, transaction)
    }
    // Called only after the canonical MemberMachine has finished: successfully, or, for a member resumed after a
    // restart, with check mismatches it left to verification (which then reports Bad or PartBad). The acknowledged
    // commit, not complete output coverage, grants finalization; it never grants Verdict::Ok by itself.
    pub(crate) fn finish_member(&self) -> PartialResult<()> {
        let mut data = self.operation()?;
        self.check(&data)?;
        self.flush_group(&mut data)?;
        self.reconcile(&mut data)?;
        if data.snapshot.head.member_finished {
            return Ok(());
        }
        if data.snapshot.head.produced != data.snapshot.head.size
            || data
                .snapshot
                .evidence
                .parts
                .last()
                .is_none_or(|part| !part.final_part || part.out.end != data.snapshot.head.size)
        {
            return Err(err(PartialErrorKind::IncompleteOutput));
        }
        let (intent, mut valid, _snapshots) = self.next_snapshots(&data)?;
        valid.head.member_finished = true;
        let carried = self.part_results(&mut data);
        let transaction = self.begin_transaction(&mut data, intent, valid, Vec::new())?;
        self.finish_transaction(&mut data, transaction)?;
        self.keep_part_results(&mut data, carried)
    }
    /// Ends the member at its committed `produced`: `[produced, size)` becomes one `TailAbandoned` hole that
    /// plaintext fills may write, and the member counts as finished, with the archive's checks when the extraction
    /// had read them and the caller's `supplied` checks otherwise. One transaction: a crash leaves either the
    /// state before or the abandoned one.
    pub(crate) fn abandon_tail(&self, supplied: Option<MemberChecks>) -> PartialResult<HoleReport> {
        let mut data = self.operation()?;
        self.check(&data)?;
        self.flush_group(&mut data)?;
        self.reconcile(&mut data)?;
        let head = &data.snapshot.head;
        if supplied.as_ref().is_some_and(|c| c.size != head.size || (c.crc32.is_none() && c.blake2sp.is_none())) {
            return Err(err(PartialErrorKind::InvalidOptions));
        }
        if let Some(previous) = head.tail {
            // Abandoning again is idempotent when it changes nothing: the same supplied checks, or none (or ones
            // that agree) when the archive's were kept.
            let same = match previous {
                TailChecks::Supplied => supplied.as_ref() == Some(&head.checks),
                _ => supplied.as_ref().is_none_or(|c| {
                    c.crc32.is_none_or(|v| head.checks.crc32.is_none_or(|h| h == v))
                        && c.blake2sp.is_none_or(|v| head.checks.blake2sp.is_none_or(|h| h == v))
                }),
            };
            if !same {
                return Err(err(PartialErrorKind::TailAbandoned));
            }
            let found = data.snapshot.holes.iter().find(|h| h.cause == HoleCause::TailAbandoned).cloned();
            return match found {
                Some(report) => Ok(report),
                None => {
                    let size = head.size;
                    self.report_for(&data.snapshot, head.revision, size..size, HoleCause::TailAbandoned)
                }
            };
        }
        let archive = head.checks.crc32.is_some() || head.checks.blake2sp.is_some();
        // Checks the archive gave win. Supplied ones must agree with them where both are plain values.
        let keyed = data.snapshot.crypt.is_some_and(|crypt| crypt.tweaked_crc);
        let differs = |a: Option<&[u8]>, b: Option<&[u8]>| a.zip(b).is_some_and(|(a, b)| a != b);
        if archive
            && !keyed
            && let Some(supplied) = &supplied
            && (differs(
                supplied.crc32.map(u32::to_le_bytes).as_ref().map(|b| &b[..]),
                head.checks.crc32.map(u32::to_le_bytes).as_ref().map(|b| &b[..]),
            ) || differs(supplied.blake2sp.as_ref().map(|b| &b[..]), head.checks.blake2sp.as_ref().map(|b| &b[..])))
        {
            return Err(err(PartialErrorKind::BindingMismatch(BindingField::Member)));
        }
        let tail = if archive {
            TailChecks::Archive
        } else if supplied.is_some() {
            TailChecks::Supplied
        } else {
            // Nothing could ever verify the member.
            return Err(err(PartialErrorKind::InvalidOptions));
        };
        let produced = head.produced;
        let size = head.size;
        if head.member_finished {
            // The extraction already ran to the end: there is no tail to abandon.
            return Err(err(PartialErrorKind::InvalidOptions));
        }
        let (intent, mut valid, _snapshots) = self.next_snapshots(&data)?;
        let revision = valid.head.revision;
        valid.head.produced = size;
        valid.head.member_finished = true;
        valid.head.tail = Some(tail);
        if tail == TailChecks::Supplied {
            valid.head.checks = supplied.unwrap();
        }
        let report = self.report_for(&valid, revision, produced..size, HoleCause::TailAbandoned)?;
        if produced < size {
            self.budget
                .usage
                .check(Resource::HoleIntervals, valid.holes.len().checked_add(1).ok_or_else(malformed)? as u64)?;
            self.budget.metadata(
                (std::mem::size_of::<HoleReport>() + report.packed.len() * std::mem::size_of::<PackedSpan>()) as u64,
            )?;
            valid.holes.try_reserve_exact(1).map_err(|_| malformed())?;
            valid.holes.push(report.clone());
        }
        // The intent claims no output: a crash before the commit reopens the state before the abandon.
        let transaction = self.begin_transaction(&mut data, intent, valid, Vec::new())?;
        self.finish_transaction(&mut data, transaction)?;
        Ok(report)
    }
    /// Appends parts, admissions and header witnesses. While a group is open the evidence joins it: it describes
    /// output the group writes, and the group commit makes both durable together.
    pub(crate) fn extend_evidence(&self, update: EvidenceUpdate) -> PartialResult<()> {
        let mut data = self.operation()?;
        self.check(&data)?;
        // Once the tail is abandoned, parts a resumed session walks past are not recorded: the tail belongs to
        // the caller's fill.
        if data.snapshot.head.tail.is_some() {
            return Ok(());
        }
        if data.group.is_some() {
            let evidence = &data.snapshot.evidence;
            // A working copy, charged while it lives; growth is charged where `apply_evidence` makes it.
            let _copy = self.budget.metadata_lease(
                (std::mem::size_of::<PlainPart>() * evidence.parts.len()
                    + evidence
                        .admissions
                        .iter()
                        .map(|a| std::mem::size_of::<SourceAdmission>() + a.expected.len())
                        .sum::<usize>()
                    + evidence
                        .headers
                        .iter()
                        .map(|h| std::mem::size_of::<HeaderWitness>() + h.bytes.len())
                        .sum::<usize>()) as u64,
            )?;
            let mut evidence = evidence.clone();
            let mut checks = data.snapshot.head.checks.clone();
            self.apply_evidence(update, &mut evidence, &mut checks)?;
            if state::validate_evidence(&data.snapshot.name, data.snapshot.head.size, &evidence, &self.budget)?
                != data.snapshot.crypt
            {
                return Err(err(PartialErrorKind::BindingMismatch(BindingField::Member)));
            }
            data.snapshot.evidence = evidence;
            data.snapshot.head.checks = checks;
            data.verification = None;
            data.part_results = None;
            return Ok(());
        }
        self.reconcile(&mut data)?;
        let (intent, mut valid, _snapshots) = self.next_snapshots(&data)?;
        self.apply_evidence(update, &mut valid.evidence, &mut valid.head.checks)?;
        if state::validate_evidence(&valid.name, valid.head.size, &valid.evidence, &self.budget)? != valid.crypt {
            return Err(err(PartialErrorKind::BindingMismatch(BindingField::Member)));
        }
        // Evidence only appends parts and witnesses: every known leaf, and so
        // every existing part's CRC result, is unchanged by this transaction.
        let carried = self.part_results(&mut data);
        let transaction = self.begin_transaction(&mut data, intent, valid, Vec::new())?;
        self.finish_transaction(&mut data, transaction)?;
        self.keep_part_results(&mut data, carried)
    }
    fn apply_evidence(
        &self,
        update: EvidenceUpdate,
        evidence: &mut InitialEvidence,
        member_checks: &mut MemberChecks,
    ) -> PartialResult<()> {
        for part in update.parts {
            if let Some(old) = evidence.parts.iter().find(|old| old.ordinal == part.ordinal) {
                if old != &part {
                    return Err(err(PartialErrorKind::BindingMismatch(BindingField::Member)));
                }
                continue;
            }
            if part.ordinal != evidence.parts.len() as u64 || evidence.parts.last().is_some_and(|last| last.final_part)
            {
                return Err(malformed());
            }
            self.budget.usage.check(Resource::Parts, evidence.parts.len() as u64 + 1)?;
            self.budget.metadata(std::mem::size_of::<PlainPart>() as u64)?;
            evidence.parts.try_reserve_exact(1).map_err(|_| malformed())?;
            evidence.parts.push(part);
        }
        for admission in update.admissions {
            if let Some(old) = evidence.admissions.iter().find(|old| old.volume == admission.volume) {
                if old != &admission {
                    return Err(err(PartialErrorKind::BindingMismatch(BindingField::Source)));
                }
                continue;
            }
            self.budget.metadata((std::mem::size_of::<SourceAdmission>() + admission.expected.len()) as u64)?;
            evidence.admissions.try_reserve_exact(1).map_err(|_| malformed())?;
            evidence.admissions.push(admission);
        }
        for header in update.headers {
            if let Some(old) =
                evidence.headers.iter().find(|old| old.volume == header.volume && old.packed == header.packed)
            {
                if old != &header {
                    return Err(err(PartialErrorKind::BindingMismatch(BindingField::Source)));
                }
                continue;
            }
            if evidence.headers.iter().any(|old| {
                old.volume == header.volume
                    && old.packed.start < header.packed.end
                    && header.packed.start < old.packed.end
            }) {
                return Err(malformed());
            }
            self.budget.metadata((std::mem::size_of::<HeaderWitness>() + header.bytes.len()) as u64)?;
            evidence.headers.try_reserve_exact(1).map_err(|_| malformed())?;
            evidence.headers.push(header);
        }
        if let Some(checks) = update.checks {
            let old = &*member_checks;
            if checks.size != old.size
                || old.crc32.is_some_and(|crc| checks.crc32 != Some(crc))
                || old.blake2sp.is_some_and(|hash| checks.blake2sp != Some(hash))
            {
                return Err(err(PartialErrorKind::BindingMismatch(BindingField::Member)));
            }
            *member_checks = checks;
        }
        Ok(())
    }
    /// Keeps part results across a committed transaction that left every known leaf as it was.
    fn keep_part_results(&self, data: &mut CoreData, parts: Vec<PartCheck>) -> PartialResult<()> {
        let lease = self.budget.metadata_lease((parts.capacity() * std::mem::size_of::<PartCheck>()) as u64)?;
        data.part_results = Some((data.snapshot.head.revision, parts, lease));
        Ok(())
    }
    /// Part CRC results valid for the current known leaves, if any are kept.
    fn part_results(&self, data: &mut CoreData) -> Vec<PartCheck> {
        let revision = data.snapshot.head.revision;
        let carried = data.part_results.take().filter(|(at, ..)| *at == revision).map(|(_, parts, _)| parts);
        match data.verification.take() {
            Some(v) if v.revision == revision => v.parts,
            _ => carried.unwrap_or_default(),
        }
    }
    pub(crate) fn compact(&self) -> PartialResult<()> {
        let mut op = self.operation()?;
        self.check(&op)?;
        self.flush_group(&mut op)?;
        self.reconcile(&mut op)?;
        self.compact_locked(&mut op)
    }
    fn compact_locked(&self, op: &mut CoreData) -> PartialResult<()> {
        // Inside a group the snapshot runs ahead of the anchored intent (its `produced`, checks and leaves cover
        // output that is neither synced nor committed), so the compaction re-anchors the intent's own head and
        // the in-memory snapshot keeps running ahead. Outside a group the snapshot is the committed state.
        if op.group.is_some() {
            let (_, _, _, mut head) = state::decode_record(&op.state.wire, &self.budget.limits)?;
            head.sequence = head.sequence.checked_add(1).ok_or_else(malformed)?;
            return self.compact_head(op, head, None);
        }
        let (mut snapshot, lease) = self.clone_snapshot(&op.snapshot)?;
        snapshot.head.sequence = snapshot.head.sequence.checked_add(1).ok_or_else(malformed)?;
        let head = snapshot.head.clone();
        self.compact_head(op, head, Some((snapshot, lease)))
    }
    /// Anchors a compaction record of `head` and retires what it no longer names. `snapshot` replaces the
    /// in-memory snapshot when given; otherwise only the snapshot's sequence follows the new anchor.
    fn compact_head(
        &self,
        op: &mut CoreData,
        head: state::CommittedState,
        snapshot: Option<(Snapshot, Lease)>,
    ) -> PartialResult<()> {
        let prepared = op.bundle.prepare_compaction(&head)?;
        let next = prepared.state.clone();
        let previous = op.state.clone();
        op.uncertain =
            Some(Uncertain { expected: previous.clone(), intent: next.clone(), commit: None, candidate_known: None });
        op.pending_compaction = Some(prepared);
        let ack = self.anchors.advance(Some(previous.anchor()), next.anchor()).map_err(|mut e| {
            e.committed = Some(previous.anchor.clone());
            e
        })?;
        op.state = next.clone();
        match snapshot {
            Some((snapshot, _lease)) => op.snapshot = snapshot,
            None => op.snapshot.head.sequence = head.sequence,
        }
        op.uncertain = None;
        self.check(op).map_err(|mut e| {
            e.committed = Some(next.anchor.clone());
            e
        })?;
        let prepared = op.pending_compaction.take().unwrap();
        op.bundle.complete_compaction(prepared, &ack).map_err(|mut e| {
            e.committed = Some(next.anchor.clone());
            e
        })
    }
    /// The committed state; an open group is committed first, so the state covers every write so far.
    pub(crate) fn state(&self) -> PartialResult<PartialState> {
        let mut op = self.operation()?;
        self.check(&op)?;
        self.flush_group(&mut op)?;
        self.budget.metadata(op.state.wire.len() as u64)?;
        Ok(op.state.clone())
    }
    fn remaining(&self) -> PartialResult<Vec<Range<u64>>> {
        let mut op = self.operation()?;
        self.check(&op)?;
        self.flush_group(&mut op)?;
        if op.uncertain.is_some() {
            // After an uncertain group commit the snapshot is not conservative: rebuild it from the store.
            self.reconcile(&mut op)?;
        }
        let size = op.snapshot.head.size;
        ledger::Ledger { known: &mut op.snapshot.known, size, budget: &self.budget }.remaining()
    }
}
impl PartialCore {
    /// Rebinds the member of `spec` under `budget` and rehashes its known output. `keys` are the member keys when
    /// the caller already holds them (a session adopting a member); otherwise they are derived from the context
    /// password, if any.
    fn reopen(
        spec: ReopenSpec,
        budget: PartialBudget,
        read_chunk: usize,
        keys: Option<MemberKeys>,
    ) -> PartialResult<Arc<Self>> {
        let state = &spec.state;
        let context = &spec.context;
        let anchors = AnchorBinding::new(context.expected_member.clone(), context.anchors.clone());
        let current = anchors.current()?.ok_or_else(|| err(PartialErrorKind::AnchorConflict))?;
        if &current != state.anchor() {
            return Err(err(PartialErrorKind::StateStale { latest: current }));
        }
        if current != context.expected_anchor {
            return Err(err(PartialErrorKind::BindingMismatch(BindingField::Anchor)));
        }
        canceled(&context.control)?;
        let lease = budget.reserve(PartialResource::OpenPartials, 1)?;
        let loaded = PartialState::load_budgeted(&context.state_root, &current, &budget)?;
        if loaded.wire != state.wire {
            return Err(err(PartialErrorKind::BindingMismatch(BindingField::Anchor)));
        }
        let mut bundle = Bundle::open(&spec, &current, &budget)?;
        let mut snapshot = bundle.snapshot(state)?;
        let keys = match (keys, &snapshot.crypt, &context.password) {
            (Some(keys), Some(_), _) => Some(keys),
            (None, Some(params), Some(password)) if snapshot.evidence.format == crate::rar5::RarFormat::Rar4 => {
                let salt = params.salt[..8].try_into().expect("8-byte RAR4 salt");
                Some(MemberKeys::derive_rar4(password, &salt, &budget, &context.control)?)
            }
            (None, Some(params), Some(password)) => {
                Some(MemberKeys::derive(password, params, &budget, &context.control)?)
            }
            _ => None,
        };
        // Derivation refuses a password that fails the check value, so with one the keys are proven. Keys handed
        // over by a session passed the same check when the session derived them.
        let keys_proven = snapshot.crypt.as_ref().is_some_and(|params| params.check.is_some());
        let native = PersistentNative::reopen(&spec, &budget)?;
        let before = stamp(&native)?;
        rehash_known(&native, &budget, &context.control, read_chunk, &mut snapshot)?;
        native.check(snapshot.head.size)?;
        if stamp(&native)? != before {
            return Err(err(PartialErrorKind::OutputChanged));
        }
        let ack = anchors.confirm_current(&current)?;
        bundle.acknowledge(&current, &ack)?;
        canceled(&context.control)?;
        native.check(snapshot.head.size)?;
        if stamp(&native)? != before {
            return Err(err(PartialErrorKind::OutputChanged));
        }
        Ok(Arc::new(PartialCore {
            native,
            budget,
            anchors,
            control: spec.context.control,
            read_chunk,
            busy: AtomicBool::new(false),
            data: Mutex::new(Some(CoreData {
                bundle,
                snapshot,
                state: spec.state,
                stamp: before,
                uncertain: None,
                pending_compaction: None,
                verification: None,
                part_results: None,
                reopened: true,
                group: None,
            })),
            keys,
            keys_proven: AtomicBool::new(keys_proven),
            _lease: lease,
        }))
    }
    /// Adopts the member a previous session created under `member`, whose trusted anchor is `anchor`: loads that
    /// state, rebinds the output and bundle (the native identities must be the recorded ones), and rehashes the
    /// known output, all under the session's budget and exclusions. Nothing is written.
    pub(crate) fn adopt(
        spec: AdoptSpec,
        options: CoreOptions,
    ) -> PartialResult<(Arc<Self>, PartialState, PartialEventLease)> {
        native::platform()?;
        options.limits.validate()?;
        canceled(&options.control)?;
        if options.read_chunk == 0 {
            return Err(err(PartialErrorKind::InvalidOptions));
        }
        let budget = PartialBudget::new(options.limits.clone(), options.usage.scoped(), options.exclusions)?;
        let event = budget.reserve(PartialResource::Events, 1)?;
        let state = PartialState::load_budgeted(&spec.state_root, &spec.anchor, &budget)?;
        if state.member() != &spec.member {
            return Err(err(PartialErrorKind::BindingMismatch(BindingField::Member)));
        }
        let context = PartialOpenContext {
            output_root: spec.output_root,
            state_root: spec.state_root,
            expected_member: spec.member,
            expected_anchor: spec.anchor,
            protection: spec.protection,
            limits: options.limits,
            progressive_limits: crate::progressive::ProgressiveLimits::default(),
            anchors: options.anchors,
            control: options.control,
            password: None,
        };
        let read_chunk = options.read_chunk.min(1_048_576) as usize;
        let core = Self::reopen(ReopenSpec { state: state.clone(), context }, budget, read_chunk, spec.keys)?;
        core.budget.metadata(state.wire.len() as u64)?;
        Ok((core, state, PartialEventLease { _reservation: event }))
    }
    /// The committed resume point of an adopted member: its durable `produced`, whether its canonical finish is
    /// committed, and its size.
    pub(crate) fn resume_point(&self) -> PartialResult<(u64, bool, u64)> {
        let op = self.operation()?;
        self.check(&op)?;
        let head = &op.snapshot.head;
        Ok((head.produced, head.member_finished, head.size))
    }
    /// Refuses adoption unless the recorded member has this output path, name and size.
    pub(crate) fn check_adopted(&self, relative: &std::path::Path, name: &[u8], size: u64) -> PartialResult<()> {
        let op = self.operation()?;
        let snapshot = &op.snapshot;
        if snapshot.head.relative_output != relative || &*snapshot.name != name || snapshot.head.size != size {
            return Err(err(PartialErrorKind::BindingMismatch(BindingField::Member)));
        }
        Ok(())
    }
    /// Whether part `part` (with its header witness) is already recorded. A recorded part, or a witness at the same
    /// archive position, that differs is a `BindingMismatch`: the archive is not the one the member came from.
    pub(crate) fn recorded_part(&self, part: &PlainPart, witness: &HeaderWitness) -> PartialResult<bool> {
        let op = self.operation()?;
        let evidence = &op.snapshot.evidence;
        let old = evidence.headers.iter().find(|old| old.volume == witness.volume && old.packed == witness.packed);
        if old.is_some_and(|old| old != witness) {
            return Err(err(PartialErrorKind::BindingMismatch(BindingField::Source)));
        }
        match evidence.parts.iter().find(|old| old.ordinal == part.ordinal) {
            Some(recorded) if recorded == part && old.is_some() => Ok(true),
            Some(_) => Err(err(PartialErrorKind::BindingMismatch(BindingField::Source))),
            None => Ok(false),
        }
    }
    /// Hash state of the known output an adopted member resumes after, rebuilt from the output itself: the member
    /// CRC32 of `0..at` (combined from the leaves the reopen rehash verified), its BLAKE2sp when `member_blake`
    /// (read back), and the CRC32 and, when `part_blake`, BLAKE2sp of `part.start..at` (read back). A hash whose
    /// range is not wholly known is `None`: those bytes are holes, so that check cannot be judged while streaming.
    pub(crate) fn prefix_hashes(
        &self,
        at: u64,
        part_start: u64,
        member_blake: bool,
        part_blake: bool,
    ) -> PartialResult<PrefixHashes> {
        let op = self.operation()?;
        self.check(&op)?;
        let snapshot = &op.snapshot;
        if at != snapshot.head.produced || part_start > at {
            return Err(malformed());
        }
        let part = part_start..at;
        // Only output the extraction produced counts. A hole filled with alt bytes was never judged by a streaming
        // check, and a wrong fill there must reach `poll_verify` as `Bad` or `PartBad`, as it does without a
        // restart, rather than fail the resumed stream: a range with alt output, or overlapping a recorded hole,
        // is not usable. Archive bytes a `fill_packed` wrote are recorded as original and cannot be told apart,
        // so a resumed member's streaming checks never fail the session either (`MemberMachine::resume_stored`).
        let covered = |range: &Range<u64>| {
            if snapshot.holes.iter().any(|hole| hole.out.start < range.end && range.start < hole.out.end) {
                return false;
            }
            let mut next = range.start;
            for leaf in &snapshot.known[snapshot.known.partition_point(|leaf| leaf.range.end <= range.start)..] {
                if next >= range.end || leaf.range.start > next {
                    break;
                }
                if leaf.provenance != state::Provenance::Original {
                    return false;
                }
                next = leaf.range.end;
            }
            next >= range.end
        };
        let member_known = covered(&(0..at));
        let part_known = covered(&part);
        let mut member_crc = None;
        if member_known {
            let mut combined = crate::crc32::Hasher::new();
            for leaf in snapshot.known.iter().take_while(|leaf| leaf.range.end <= at) {
                self.budget.usage.charge(Resource::VerifyWorkBytes, leaf.range.end - leaf.range.start)?;
                combined.combine(&leaf.hasher);
            }
            member_crc = Some(combined);
        }
        let mut member_hash = (member_known && member_blake).then(crate::blake2sp::Blake2sp::new);
        let mut part_crc = part_known.then(crate::crc32::Hasher::new);
        let mut part_hash = (part_known && part_blake).then(crate::blake2sp::Blake2sp::new);
        let from = if member_hash.is_some() { 0 } else { part.start };
        if (member_hash.is_some() || part_crc.is_some()) && from < at {
            if member_hash.is_some() || part_hash.is_some() {
                self.budget.metadata(4096)?;
            }
            let mut buffer = self.budget.vector(self.read_chunk.min((at - from) as usize))?;
            buffer.resize(self.read_chunk.min((at - from) as usize), 0);
            let mut pos = from;
            while pos < at {
                canceled(&self.control)?;
                let n = (at - pos).min(buffer.len() as u64) as usize;
                self.budget.usage.charge(Resource::VerifyBytes, n as u64)?;
                self.budget.usage.charge(Resource::VerifyWorkBytes, n as u64)?;
                let count = crate::output::range::read_at(&self.native.output.file, pos, &mut buffer[..n])
                    .map_err(|e| io_error(OutputOperation::Read, e))?;
                if count == 0 {
                    return Err(err(PartialErrorKind::OutputChanged));
                }
                let bytes = &buffer[..count];
                if let Some(hash) = &mut member_hash {
                    hash.update(bytes);
                }
                if pos + count as u64 > part.start {
                    let skip = part.start.saturating_sub(pos) as usize;
                    if let Some(crc) = &mut part_crc {
                        crc.update(&bytes[skip..]);
                    }
                    if let Some(hash) = &mut part_hash {
                        hash.update(&bytes[skip..]);
                    }
                }
                pos += count as u64;
            }
            self.check(&op)?;
        }
        Ok(PrefixHashes {
            member: member_crc.map(|crc| (crc, member_hash)),
            part: part_crc.map(|crc| (crc, part_hash)),
        })
    }
}
impl Drop for PartialCore {
    /// The last owner gone: commit an open group if that still works, so output written since its intent is not
    /// re-extracted needlessly. A failure leaves the anchored state as it is, exactly as a crash would.
    /// Skipped while the thread is panicking: the commit syncs files and calls the caller's anchor store, and a
    /// second panic during unwinding would abort the process. The anchored state then stays as after a crash.
    /// Then the member's exclusions are retired.
    fn drop(&mut self) {
        if std::thread::panicking() {
            return;
        }
        let data = self.data.get_mut().ok().and_then(Option::take);
        if let Some(mut data) = data
            && data.group.is_some()
        {
            let _ = self.flush_group(&mut data);
        }
        // Nothing of this member is written any more: its exclusions go (their charges with the budget).
        self.budget.exclusions.retire_member(&self.native.output_path, &self.native.bundle.path);
    }
}
impl PartialFile {
    /// Adopts the existing durable owner without creating another native capability.
    pub(crate) fn from_core(core: Arc<PartialCore>) -> Self {
        Self { core }
    }
    /// Synchronously rebinds and rehashes known output in bounded local chunks.
    /// Work is O(known output); no source provider is called.
    pub fn open(state: PartialState, context: PartialOpenContext) -> PartialResult<Self> {
        native::platform()?;
        context.limits.validate()?;
        canceled(&context.control)?;
        if state.member() != &context.expected_member {
            return Err(err(PartialErrorKind::BindingMismatch(BindingField::Member)));
        }
        let read_chunk = context.progressive_limits.read_chunk.min(1_048_576) as usize;
        let usage = crate::progressive::Usage::new(context.progressive_limits.clone());
        let exclusions = Arc::new(PartialExclusions::new(usage.clone()));
        let budget = PartialBudget::new(context.limits.clone(), usage, exclusions)?;
        PartialCore::reopen(ReopenSpec { state, context }, budget, read_chunk, None).map(|core| Self { core })
    }
    /// Fills observed holes after comparing every known overlap. Matching known bytes are unchanged.
    pub fn fill(&mut self, offset: u64, bytes: &[u8]) -> PartialResult<FillResult> {
        self.core.fill_plain(offset, bytes)
    }
    /// Fills from raw archive bytes of `volume` starting at packed `offset`, for example a byte-identical twin post
    /// or a par2-repaired slice of the volume. The bytes may be larger than the holes they cover and may span
    /// headers or other members: only bytes that map to this member's produced output are used, and the rest are
    /// returned in [`PackedFillResult::unmapped`]. Overlapped bytes from the original extraction must match. Alt
    /// bytes (from [`fill`](Self::fill)) that differ are overwritten, because archive bytes win, and reported in
    /// [`PackedFillResult::corrected`] so the caller can stop trusting that alt. At most
    /// `PartialLimits::fill_bytes` bytes per call.
    pub fn fill_packed(&mut self, volume: u32, offset: u64, bytes: &[u8]) -> PartialResult<PackedFillResult> {
        self.core.fill_packed(volume, offset, bytes)
    }
    /// Re-reads `range` of the archive volume `volume` from `reader` (positioned anywhere; it is sought) after the
    /// volume was repaired in place, and fills this member's output from it as [`fill_packed`](Self::fill_packed)
    /// does. Only packed bytes whose output is still a hole or came from an alt are read, so the cost follows the
    /// damaged ranges, not the volume size. Bytes the original extraction wrote are not re-read or compared.
    pub fn refill_from_packed<R: std::io::Read + std::io::Seek>(
        &mut self,
        volume: u32,
        range: Range<u64>,
        reader: &mut R,
    ) -> PartialResult<PackedFillResult> {
        if range.start > range.end {
            return Err(err(PartialErrorKind::InvalidOptions));
        }
        let chunk = self.core.budget.limits.value(PartialResource::FillBytes).min(usize::MAX as u64) as usize;
        if chunk == 0 {
            return Err(err(PartialErrorKind::InvalidOptions));
        }
        let targets = self.core.refill_targets(volume, &range)?;
        let mut buffer = self.core.budget.vector(chunk)?;
        let mut total: Option<PackedFillResult> = None;
        fn merge(total: &mut Option<PackedFillResult>, step: PackedFillResult) {
            *total = Some(match total.take() {
                None => step,
                Some(mut sum) => {
                    sum.applied.extend(step.applied);
                    sum.corrected.extend(step.corrected);
                    sum.unmapped.extend(step.unmapped);
                    sum.revision = step.revision;
                    sum.state = step.state;
                    sum.part_checks = step.part_checks;
                    sum.needs_verification = step.needs_verification;
                    sum
                }
            });
        }
        for target in targets {
            let mut at = target.start;
            while at < target.end {
                let n = (target.end - at).min(chunk as u64) as usize;
                buffer.resize(n, 0);
                let step = canceled(&self.core.control)
                    .and_then(|()| {
                        reader
                            .seek(std::io::SeekFrom::Start(at))
                            .and_then(|_| reader.read_exact(&mut buffer[..n]))
                            .map_err(|cause| {
                                let mut error = err(PartialErrorKind::PackedRead(cause));
                                error.volume = Some(volume);
                                error.packed_offset = Some(at);
                                error
                            })
                    })
                    .and_then(|()| self.core.fill_packed(volume, at, &buffer[..n]));
                match step {
                    Ok(step) => merge(&mut total, step),
                    Err(mut error) => {
                        if let Some(progress) = error.packed_progress.take() {
                            merge(&mut total, *progress);
                        }
                        error.packed_progress = total.map(Box::new);
                        return Err(error);
                    }
                }
                at += n as u64;
            }
        }
        match total {
            Some(total) => Ok(total),
            None => self.core.fill_packed(volume, range.start, &[]),
        }
    }
    /// The absolute path of the output file this partial writes to: the output root (made absolute when the
    /// session opened it) joined with [`relative_output_path`](Self::relative_output_path). Its parents were
    /// opened without following symbolic links and the file is held by native identity, so the path names this
    /// member's output while the handle lives, unless something outside the session renames it.
    pub fn output_path(&self) -> &std::path::Path {
        self.core.output_path()
    }
    /// The output path relative to the output root: sanitized, with only normal components, so it never escapes
    /// the root.
    pub fn relative_output_path(&self) -> PartialResult<&std::path::Path> {
        self.core.native.relative_output()
    }
    /// Ends this member at its committed `produced` without reading anything more, for a takeover by another copy
    /// of the release: `[produced, size)` becomes one `TailAbandoned` hole that plaintext fills (`fill`,
    /// `fill_writer`, `fill_from`) may write, and the member counts as finished, so `poll_verify` reaches
    /// `Verdict::Ok` once every byte is known and the checks pass. The output file and its inode stay the same.
    ///
    /// The checks come from the archive when the extraction read them (the final part's header); `supplied` must
    /// then agree with them where it can be compared (an encrypted RAR5 member's keyed checks cannot be). Otherwise
    /// `supplied` is required (`size` must equal the member's, and it must carry a CRC-32 or BLAKE2sp) and
    /// verification compares the output with it as plaintext, never keyed with the password. See
    /// [`TailChecks`] for what `Verdict::Ok` claims either way, and [`PartialFile::tail_checks`].
    ///
    /// Durable in one transaction: a crash leaves the state before or the abandoned one, and a reopened handle (or
    /// a resumed session, which then treats the member as finished and walks past its later parts) sees the
    /// abandoned state. Commit or drop the session's extraction of this member first: a session still extracting it
    /// fails with [`PartialErrorKind::TailAbandoned`] on its next write. Abandoning again with the same checks
    /// returns the same report; with other checks it is `TailAbandoned`. A member whose extraction already
    /// finished has no tail (`InvalidOptions`).
    ///
    /// Encrypted members: the tail is filled with plaintext, so no ciphertext, IV or key is needed for it, and the
    /// hole's packed spans list only the archive bytes this copy is known to hold. `fill_packed` can still fill
    /// holes in the produced prefix.
    pub fn abandon_tail(&mut self, supplied: Option<MemberChecks>) -> PartialResult<HoleReport> {
        self.core.abandon_tail(supplied)
    }
    /// Where the checks of a member whose tail was abandoned come from; `None` while it was not.
    pub fn tail_checks(&self) -> PartialResult<Option<TailChecks>> {
        let data = self.core.operation()?;
        self.core.check(&data)?;
        Ok(data.snapshot.head.tail)
    }
    pub fn remaining(&self) -> PartialResult<Vec<Range<u64>>> {
        self.core.remaining()
    }
    /// Declares archive bytes of `volume` bad after they were extracted, for example when an article's CRC
    /// fails late. Output this member produced from those bytes becomes `DeclaredBad` holes again (returned,
    /// one report per newly invalidated run) and must be filled before the member verifies. Bytes that map to
    /// no output of this member, or that were already holes, are ignored.
    pub fn declare_hole(&mut self, volume: u32, range: Range<u64>) -> PartialResult<Vec<HoleReport>> {
        self.core.declare_damage(volume, &range).map(|(reports, _)| reports)
    }
    pub fn state(&self) -> PartialResult<PartialState> {
        self.core.state()
    }
    pub fn close(self) -> PartialResult<PartialState> {
        self.core.state()
    }
}
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    mod ledger;
    mod native;
    #[path = "../../../tests/common/mod.rs"]
    mod rar_fixture;
    mod serde;
    pub(super) mod state;
    mod verify;
}

impl PartialOptions {
    pub(crate) fn validate_session(&self) -> PartialResult<()> {
        native::platform()?;
        self.limits.validate()?;
        canceled(&self.control)?;
        if self.limits.events == 0 || self.state_dir.as_os_str().is_empty() {
            return Err(err(PartialErrorKind::InvalidOptions));
        }
        Ok(())
    }
}

impl PreparedCreate {
    /// Hands the extraction's member keys to the core, in memory only.
    pub(crate) fn set_keys(&mut self, keys: MemberKeys) {
        self.keys = Some(keys);
    }
    pub(crate) fn reserve_ready_state(&mut self) -> PartialResult<()> {
        if self.ready_bytes.is_none() {
            // Native identities and parent digests occupy fixed-width fields.
            let bytes = state::encode_record(3, 0, None, &self.initial.head, &self.budget.limits)?.wire.len();
            self.budget.usage.charge(Resource::MetadataBytes, bytes as u64)?;
            self.ready_bytes = Some(bytes);
        }
        Ok(())
    }
    pub(crate) fn prepare_parents(
        &self,
        check: impl FnMut(native::GenesisPath<'_>) -> PartialResult<()>,
    ) -> PartialResult<native::PreparedParents> {
        native::prepare_parents(&self.spec, &self.budget, &self.control, self.native.paths(), check)
    }
    #[cfg(test)]
    pub(crate) fn complete(self) -> PartialResult<Arc<PartialCore>> {
        self.complete_inner().map(|(core, _, _)| core)
    }
    pub(crate) fn complete_ready(self) -> PartialResult<(Arc<PartialCore>, PartialState, PartialEventLease)> {
        if self.ready_bytes.is_none() {
            return Err(err(PartialErrorKind::InvalidOptions));
        }
        let (core, state, lease) = self.complete_inner()?;
        Ok((core, state.ok_or_else(malformed)?, lease))
    }
    fn complete_inner(self) -> PartialResult<(Arc<PartialCore>, Option<PartialState>, PartialEventLease)> {
        let Self {
            spec,
            budget,
            lease,
            _event,
            anchors,
            control,
            read_chunk,
            initial,
            pages,
            native: prepared_native,
            ready_bytes,
            keys,
        } = self;
        budget.admit_genesis_bookkeeping()?;
        let native = PersistentNative::create(&spec, &budget, prepared_native)?;
        let location = PartialLocation { output: native.output_path.clone(), state_bundle: native.bundle.path.clone() };
        let mut committed = None;
        let result = (|| {
            let mut bundle = Bundle::create(&spec, &budget)?;
            let mut snapshot = initial;
            snapshot.head.binding = native.binding.clone();
            bundle.persist_pages(&mut snapshot, pages)?;
            let intent = MutationIntent {
                transaction: 0,
                parent: None,
                conservative: snapshot.head.clone(),
                affected: std::iter::once(0..spec.size).collect(),
            };
            let intent_anchor = bundle.append_intent(&intent)?;
            // The bundle and output directory entries must be durable before the store can hold an anchor
            // naming them; otherwise a crash leaves an anchor whose state can never be reopened or recreated.
            native.sync()?;
            native.sync_parents()?;
            let ack = anchors.advance(None, &intent_anchor)?;
            bundle.acknowledge(&intent_anchor, &ack)?;
            committed = Some(intent_anchor.clone());
            canceled(&control)?;
            native.check(0)?;
            native.output.file.set_len(spec.size).map_err(|e| io_error(OutputOperation::Write, e))?;
            native.sync()?;
            native.sync_parents()?;
            native.check(spec.size)?;
            snapshot.head.sequence = 1;
            let commit = MutationCommit { transaction: 0, parent: intent_anchor.clone(), valid: snapshot.head.clone() };
            let final_anchor = bundle.append_commit(&commit)?;
            let ack = anchors.advance(Some(&intent_anchor), &final_anchor)?;
            bundle.acknowledge(&final_anchor, &ack)?;
            committed = Some(final_anchor.clone());
            let state = state::encode_record(3, 0, Some(&intent_anchor), &snapshot.head, &budget.limits)?;
            native.check(spec.size)?;
            canceled(&control)?;
            let stamp = stamp(&native)?;
            Ok(CoreData {
                bundle,
                snapshot,
                state,
                stamp,
                uncertain: None,
                pending_compaction: None,
                verification: None,
                part_results: None,
                reopened: false,
                group: None,
            })
        })()
        .map_err(|mut error: PartialError| {
            error.committed = committed;
            error.location = Some(location);
            error
        })?;
        budget.finish_genesis();
        let ready = ready_bytes.map(|bytes| {
            debug_assert_eq!(bytes, result.state.wire.len());
            result.state.clone()
        });
        Ok((
            Arc::new(PartialCore {
                native,
                budget,
                anchors,
                control,
                read_chunk: read_chunk.min(1_048_576) as usize,
                busy: AtomicBool::new(false),
                data: Mutex::new(Some(result)),
                keys,
                // Keys handed over by the extraction produced the original output.
                keys_proven: AtomicBool::new(true),
                _lease: lease,
            }),
            ready,
            PartialEventLease { _reservation: _event },
        ))
    }
}
