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
mod types;
mod verify;
use crate::progressive::{OutputOperation, Resource, SessionControl};
use crate::rar5::source::SourceStamp;
use anchor::AnchorBinding;
pub(crate) use cipher::MemberKeys;
use journal::Bundle;
pub(crate) use limits::PartialBudget;
pub use limits::{PartialLimits, PartialResource};
use limits::{Reservation, limit};
use native::PersistentNative;
pub(crate) use native::{PartialExclusions, PartialProtectedPath};
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
    reopened: bool,
}
struct Transaction {
    intent: PartialState,
    commit: PartialState,
    valid: Snapshot,
    commit_known: Vec<state::KnownLeaf>,
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
        let budget = PartialBudget::new(options.limits, options.usage, options.exclusions)?;
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
        let pages = state::encode_pages(&initial, &budget)?;
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
    fn clone_snapshot(&self, snapshot: &Snapshot) -> PartialResult<Snapshot> {
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
        self.budget.metadata(bytes as u64)?;
        Ok(snapshot.clone())
    }
    pub(crate) fn validate_current(&self) -> PartialResult<()> {
        let data = self.operation()?;
        self.check(&data)
    }
    pub(crate) fn write_original(&self, offset: u64, bytes: &[u8]) -> PartialResult<()> {
        let mut op = self.operation()?;
        self.check(&op)?;
        self.reconcile(&mut op)?;
        self.write_data(&mut op, offset, bytes, FillMode::Original).map(|_| ())
    }
    pub(crate) fn fill_plain(&self, offset: u64, bytes: &[u8]) -> PartialResult<FillResult> {
        let mut op = self.operation()?;
        self.check(&op)?;
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
        for (packed, stream) in segments {
            let slice = &bytes[(packed.start - offset) as usize..(packed.end - offset) as usize];
            let decrypted = match keys {
                Some(keys) => Some(cipher::decrypt(&self.budget, &op.snapshot, keys, stream, slice)?),
                None => None,
            };
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
    /// Durably keeps ciphertext blocks a remaining hole needs to decrypt later archive bytes.
    fn keep_cipher(&self, op: &mut CoreData, blocks: &[state::CipherBlock]) -> PartialResult<()> {
        let (mut intent, mut valid) = self.next_snapshots(op)?;
        cipher::merge(&self.budget, &mut valid.cipher, blocks)?;
        cipher::prune(&self.budget, &mut valid)?;
        if valid.cipher == op.snapshot.cipher {
            return Ok(());
        }
        self.budget.metadata((valid.cipher.len() * std::mem::size_of::<state::CipherBlock>()) as u64)?;
        intent.cipher = valid.cipher.clone();
        op.verification = None;
        let transaction = self.begin_transaction(op, intent, valid, Vec::new())?;
        self.finish_transaction(op, transaction)
    }
    /// Packed ranges of `volume` within `range` whose output is still unknown or came from an alt; output the
    /// original extraction wrote is skipped, so a refill reads only what it can change. For an encrypted member
    /// each range covers whole ciphertext blocks plus the block before, which CBC needs to decrypt the first.
    pub(crate) fn refill_targets(&self, volume: u32, range: &Range<u64>) -> PartialResult<Vec<Range<u64>>> {
        let op = self.operation()?;
        self.check(&op)?;
        let snapshot = &op.snapshot;
        let produced = snapshot.head.produced;
        let mut targets: Vec<Range<u64>> = Vec::new();
        if snapshot.crypt.is_some() {
            let runs = cipher::unresolved_runs(&self.budget, snapshot)?;
            let total = cipher::stream_total(snapshot);
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
                    let need = cipher::floor_block(run.start).saturating_sub(16).max(lo)..need_end.min(hi);
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
            op.verification = None;
            op.verification =
                Some(verify::Verification::new(&op.snapshot, &self.budget, self.hash_key()).map_err(|mut e| {
                    e.committed = Some(op.state.anchor.clone());
                    e
                })?);
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
        if op.snapshot.evidence.parts.last().is_none_or(|part| end > part.out.end) {
            return Err(err(PartialErrorKind::BindingMismatch(BindingField::Source)));
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
        if !corrected.is_empty() {
            let mut scratch = self.clone_snapshot(&op.snapshot)?;
            for bad in &corrected {
                scratch.known = self.invalidate(&scratch, bad)?;
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
                let boundary =
                    op.snapshot.evidence.parts.iter().find(|p| p.out.end > at).ok_or_else(malformed)?.out.end;
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
                let boundary =
                    op.snapshot.evidence.parts.iter().find(|p| p.out.end > at).ok_or_else(malformed)?.out.end;
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
        let (mut intent, mut commit) = self.next_snapshots(op)?;
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
        ledger::Ledger { known: &mut commit.known, size: commit.head.size, budget: &self.budget }.remaining()?;
        // Retain only still-unknown observed spans, including exact packed mappings.
        commit.holes = self.remaining_reports(&mut commit)?;
        if commit.crypt.is_some() {
            cipher::prune(&self.budget, &mut commit)?;
        }
        self.budget.metadata((plan.unknown.len() * std::mem::size_of::<Range<u64>>()) as u64)?;
        op.verification = None;
        let verification = verify::Verification::new(&commit, &self.budget, self.hash_key())?;
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
        let mut compare = self.budget.vector(bytes.len().min(self.read_chunk))?;
        compare.resize(bytes.len().min(self.read_chunk), 0);
        for leaf in &op.snapshot.known {
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
            self.budget.metadata(data.state.wire.len() as u64)?;
            let mut expected = data.state.clone();
            let mut intent_known = self.budget.vector(intent.known.len())?;
            intent_known.extend_from_slice(&intent.known);
            let mut commit_known = self.budget.vector(valid.known.len())?;
            commit_known.extend_from_slice(&valid.known);
            let (mut intent_state, mut commit_state, mut files) =
                data.bundle.prepare_mutation(expected.anchor(), &mut intent, &mut valid)?;
            if data.bundle.needs_compaction(&data.snapshot.head, &files)? {
                self.compact_locked(data)?;
                expected = data.state.clone();
                intent.head.sequence = data.snapshot.head.sequence.checked_add(1).ok_or_else(malformed)?;
                valid.head.sequence = intent.head.sequence.checked_add(1).ok_or_else(malformed)?;
                (intent_state, commit_state, files) =
                    data.bundle.prepare_mutation(expected.anchor(), &mut intent, &mut valid)?;
            }
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
            Ok(Transaction { intent: intent_state, commit: commit_state, valid, commit_known })
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
    fn next_snapshots(&self, data: &CoreData) -> PartialResult<(Snapshot, Snapshot)> {
        let mut intent = self.clone_snapshot(&data.snapshot)?;
        intent.head.sequence = intent.head.sequence.checked_add(1).ok_or_else(malformed)?;
        intent.head.revision = intent.head.revision.checked_add(1).ok_or_else(malformed)?;
        let mut valid = self.clone_snapshot(&intent)?;
        valid.head.sequence = valid.head.sequence.checked_add(1).ok_or_else(malformed)?;
        Ok((intent, valid))
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
    pub(crate) fn record_hole(&self, report: HoleReport) -> PartialResult<()> {
        self.record_hole_with(report, &[])
    }
    /// Records a hole and keeps the ciphertext `blocks` next to it (encrypted members) in the same transaction.
    pub(crate) fn record_hole_with(&self, report: HoleReport, blocks: &[state::CipherBlock]) -> PartialResult<()> {
        let mut data = self.operation()?;
        self.check(&data)?;
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
        self.budget
            .usage
            .check(Resource::HoleIntervals, data.snapshot.holes.len().checked_add(1).ok_or_else(malformed)? as u64)?;
        // The packed spans must be exactly those of the output range (block-widened for encrypted members).
        if report.packed != cipher::packed_spans(&self.budget, &data.snapshot, &report.out)?
            || data.snapshot.holes.iter().any(|h| h.id == report.id)
        {
            return Err(malformed());
        }
        let (mut intent, mut valid) = self.next_snapshots(&data)?;
        if report.out.start > data.snapshot.head.produced
            || (report.out.end > data.snapshot.head.produced && report.out.start != data.snapshot.head.produced)
        {
            return Err(err(PartialErrorKind::IncompleteOutput));
        }
        intent.known = self.invalidate(&data.snapshot, &report.out)?;
        self.budget.metadata((intent.known.len() * std::mem::size_of::<state::KnownLeaf>()) as u64)?;
        valid.known = intent.known.clone();
        valid.head.produced = valid.head.produced.max(report.out.end);
        intent.head.produced = valid.head.produced;
        ledger::Ledger { known: &mut intent.known, size: intent.head.size, budget: &self.budget }.remaining()?;
        self.budget.metadata(
            (std::mem::size_of::<HoleReport>() + report.packed.len() * std::mem::size_of::<PackedSpan>()) as u64,
        )?;
        valid.holes.try_reserve_exact(1).map_err(|_| malformed())?;
        let affected = report.out.clone();
        valid.holes.push(report);
        self.budget.metadata(
            valid
                .holes
                .iter()
                .map(|h| std::mem::size_of::<HoleReport>() + h.packed.len() * std::mem::size_of::<PackedSpan>())
                .sum::<usize>() as u64,
        )?;
        intent.holes = valid.holes.clone();
        if !blocks.is_empty() {
            cipher::merge(&self.budget, &mut valid.cipher, blocks)?;
            self.budget.metadata((valid.cipher.len() * std::mem::size_of::<state::CipherBlock>()) as u64)?;
            intent.cipher = valid.cipher.clone();
        }
        let transaction = self.begin_transaction(&mut data, intent, valid, vec![affected])?;
        self.finish_transaction(&mut data, transaction)
    }
    /// Whether any proven part of this member lies in `range` of `volume`. Checked without taking the
    /// operation or touching the output, so unrelated members never fail a declaration; a member busy in another
    /// operation answers true and is then tried for real.
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
    /// decrypts with the damaged block, becomes a `CipherNeighbour` hole.
    pub(crate) fn declare_damage(
        &self,
        volume: u32,
        range: &Range<u64>,
    ) -> PartialResult<(Vec<HoleReport>, Vec<Range<u64>>)> {
        if range.start >= range.end {
            return Err(err(PartialErrorKind::InvalidOptions));
        }
        let (runs, mapped) = {
            let mut data = self.operation()?;
            self.check(&data)?;
            self.reconcile(&mut data)?;
            let snapshot = &data.snapshot;
            let produced = snapshot.head.produced;
            let limit = cipher::stream_produced(snapshot);
            let encrypted = snapshot.crypt.is_some();
            let mut runs: Vec<(Range<u64>, HoleCause)> = self.budget.vector(snapshot.known.len() + 2)?;
            let mut mapped = self.budget.vector(snapshot.evidence.parts.len())?;
            for (part, stream) in cipher::parts_with_stream(snapshot).filter(|(p, _)| p.packed.volume == volume) {
                let start = range.start.max(part.packed.range.start);
                let end = range.end.min(part.packed.range.end);
                if start >= end {
                    continue;
                }
                let at = stream + (start - part.packed.range.start);
                let at_end = stream + (end - part.packed.range.start);
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
            (runs, mapped)
        };
        let mut reports = self.budget.vector(runs.len())?;
        for (out, cause) in runs {
            let report = self.hole_report(out, cause)?;
            self.record_hole(report.clone())?;
            reports.push(report);
        }
        Ok((reports, mapped))
    }
    // Called only after the canonical MemberMachine has successfully finished.
    // The acknowledged commit, not complete output coverage, grants finalization.
    pub(crate) fn finish_member(&self) -> PartialResult<()> {
        let mut data = self.operation()?;
        self.check(&data)?;
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
        let (intent, mut valid) = self.next_snapshots(&data)?;
        valid.head.member_finished = true;
        let transaction = self.begin_transaction(&mut data, intent, valid, Vec::new())?;
        self.finish_transaction(&mut data, transaction)
    }
    pub(crate) fn extend_evidence(&self, update: EvidenceUpdate) -> PartialResult<()> {
        let mut data = self.operation()?;
        self.check(&data)?;
        self.reconcile(&mut data)?;
        let (intent, mut valid) = self.next_snapshots(&data)?;
        for part in update.parts {
            if let Some(old) = valid.evidence.parts.iter().find(|old| old.ordinal == part.ordinal) {
                if old != &part {
                    return Err(err(PartialErrorKind::BindingMismatch(BindingField::Member)));
                }
                continue;
            }
            if part.ordinal != valid.evidence.parts.len() as u64
                || valid.evidence.parts.last().is_some_and(|last| last.final_part)
            {
                return Err(malformed());
            }
            self.budget.usage.check(Resource::Parts, valid.evidence.parts.len() as u64 + 1)?;
            self.budget.metadata(std::mem::size_of::<PlainPart>() as u64)?;
            valid.evidence.parts.try_reserve_exact(1).map_err(|_| malformed())?;
            valid.evidence.parts.push(part);
        }
        for admission in update.admissions {
            if let Some(old) = valid.evidence.admissions.iter().find(|old| old.volume == admission.volume) {
                if old != &admission {
                    return Err(err(PartialErrorKind::BindingMismatch(BindingField::Source)));
                }
                continue;
            }
            self.budget.metadata((std::mem::size_of::<SourceAdmission>() + admission.expected.len()) as u64)?;
            valid.evidence.admissions.try_reserve_exact(1).map_err(|_| malformed())?;
            valid.evidence.admissions.push(admission);
        }
        for header in update.headers {
            if let Some(old) =
                valid.evidence.headers.iter().find(|old| old.volume == header.volume && old.packed == header.packed)
            {
                if old != &header {
                    return Err(err(PartialErrorKind::BindingMismatch(BindingField::Source)));
                }
                continue;
            }
            if valid.evidence.headers.iter().any(|old| {
                old.volume == header.volume
                    && old.packed.start < header.packed.end
                    && header.packed.start < old.packed.end
            }) {
                return Err(malformed());
            }
            self.budget.metadata((std::mem::size_of::<HeaderWitness>() + header.bytes.len()) as u64)?;
            valid.evidence.headers.try_reserve_exact(1).map_err(|_| malformed())?;
            valid.evidence.headers.push(header);
        }
        if let Some(checks) = update.checks {
            let old = &valid.head.checks;
            if checks.size != old.size
                || old.crc32.is_some_and(|crc| checks.crc32 != Some(crc))
                || old.blake2sp.is_some_and(|hash| checks.blake2sp != Some(hash))
            {
                return Err(err(PartialErrorKind::BindingMismatch(BindingField::Member)));
            }
            valid.head.checks = checks;
        }
        if state::validate_evidence(&valid.name, valid.head.size, &valid.evidence, &self.budget)? != valid.crypt {
            return Err(err(PartialErrorKind::BindingMismatch(BindingField::Member)));
        }
        let transaction = self.begin_transaction(&mut data, intent, valid, Vec::new())?;
        self.finish_transaction(&mut data, transaction)
    }
    pub(crate) fn compact(&self) -> PartialResult<()> {
        let mut op = self.operation()?;
        self.check(&op)?;
        self.reconcile(&mut op)?;
        self.compact_locked(&mut op)
    }
    fn compact_locked(&self, op: &mut CoreData) -> PartialResult<()> {
        let mut snapshot = self.clone_snapshot(&op.snapshot)?;
        snapshot.head.sequence = snapshot.head.sequence.checked_add(1).ok_or_else(malformed)?;
        let prepared = op.bundle.prepare_compaction(&snapshot.head)?;
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
        op.snapshot = snapshot;
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
    pub(crate) fn state(&self) -> PartialResult<PartialState> {
        let op = self.operation()?;
        self.check(&op)?;
        self.budget.metadata(op.state.wire.len() as u64)?;
        Ok(op.state.clone())
    }
    fn remaining(&self) -> PartialResult<Vec<Range<u64>>> {
        let mut op = self.operation()?;
        self.check(&op)?;
        let size = op.snapshot.head.size;
        ledger::Ledger { known: &mut op.snapshot.known, size, budget: &self.budget }.remaining()
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
        let spec = ReopenSpec { state, context };
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
        let read_chunk = context.progressive_limits.read_chunk.min(1_048_576) as usize;
        let usage = crate::progressive::Usage::new(context.progressive_limits.clone());
        let exclusions = Arc::new(PartialExclusions::new(usage.clone()));
        let budget = PartialBudget::new(context.limits.clone(), usage, exclusions)?;
        let lease = budget.reserve(PartialResource::OpenPartials, 1)?;
        let loaded = PartialState::load_budgeted(&context.state_root, &current, &budget)?;
        if loaded.wire != state.wire {
            return Err(err(PartialErrorKind::BindingMismatch(BindingField::Anchor)));
        }
        let mut bundle = Bundle::open(&spec, &current, &budget)?;
        let mut snapshot = bundle.snapshot(state)?;
        let keys = match (&snapshot.crypt, &context.password) {
            (Some(params), Some(password)) => Some(MemberKeys::derive(password, params, &budget, &context.control)?),
            _ => None,
        };
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
        Ok(Self {
            core: Arc::new(PartialCore {
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
                    reopened: true,
                })),
                keys,
                _lease: lease,
            }),
        })
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
        check: impl FnMut(&std::path::Path) -> PartialResult<()>,
    ) -> PartialResult<native::PreparedParents> {
        native::prepare_parents(&self.spec, &self.budget, &self.control, check)
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
                reopened: false,
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
                _lease: lease,
            }),
            ready,
            PartialEventLease { _reservation: _event },
        ))
    }
}
