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

use super::*;
use crate::progressive::ChecksumAlgorithm;
use std::task::{Context, Poll};

pub(super) struct Verification {
    pub revision: u64,
    pub parts: Vec<PartCheck>,
    member_crc: CheckResult,
    member_blake: CheckResult,
    active: Option<Readback>,
    readback: Option<VerifyPath>,
    /// Hash key for an encrypted member whose RAR5 checks are keyed (tweaked) with it.
    key: Option<[u8; 32]>,
    /// The member checks are keyed but this handle has no password.
    password_required: bool,
    _lease: Reservation,
    _metadata: crate::progressive::Lease,
}
// BLAKE2sp holds eight fixed lanes and a 512-byte round. Reserve a conservative
// 4096 bytes for those internal allocations before constructing the existing hasher.
const BLAKE_STORAGE: u64 = 4096;
/// BLAKE2sp hashes of the output's checked ranges, fed by every write as it lands (RustyGet: verify without reading
/// the output back). BLAKE2sp cannot combine pieces as CRC-32 leaves do, so each checked range (a part's, the
/// member's) has one run that follows the writes continuing it from its start: a write past the run is caught up by
/// a read-back from the run's end when verified, and a write inside what the run hashed (a correction) drops it.
/// A run that reaches its range's end keeps only the digest. In memory only: a reopened handle reads back as before.
#[derive(Default)]
pub(super) struct BlakeFrontier {
    pub(super) runs: Vec<BlakeRun>,
    /// The checked ranges, sorted by start, and what they were built from (parts appended, size, member check,
    /// encryption): rebuilt only when that changes, not for every write.
    ranges: Vec<Range<u64>>,
    built: Option<(usize, u64, bool, bool)>,
}
pub(super) struct BlakeRun {
    pub(super) range: Range<u64>,
    /// End of the bytes hashed, from `range.start`.
    pub(super) at: u64,
    /// The hash so far, or the digest once `at` reached `range.end`.
    pub(super) hash: Result<[u8; 32], crate::blake2sp::Blake2sp>,
    /// The budget an unfinished hash holds (`BLAKE_STORAGE`, as a read-back's), let go once it is a digest.
    lease: Option<Reservation>,
}
impl BlakeFrontier {
    /// Brings the checked ranges up to date with `snapshot` (cheap when nothing changed); true when there are any.
    pub(super) fn refresh(&mut self, snapshot: &Snapshot) -> bool {
        let key = (
            snapshot.evidence.parts.len(),
            snapshot.head.size,
            snapshot.head.checks.blake2sp.is_some(),
            snapshot.crypt.is_some(),
        );
        if self.built != Some(key) {
            self.ranges = Self::ranges(snapshot);
            self.built = Some(key);
        }
        !self.ranges.is_empty()
    }

    /// The checked ranges of `snapshot` that have a BLAKE2sp check on plaintext, without repeats.
    pub(super) fn ranges(snapshot: &Snapshot) -> Vec<Range<u64>> {
        let mut ranges = Vec::new();
        if snapshot.crypt.is_none() {
            for part in snapshot.evidence.parts.iter().filter(|p| p.blake2sp.is_some()) {
                ranges.push(if part.final_part { 0..snapshot.head.size } else { part.out.clone() });
            }
        }
        if snapshot.head.checks.blake2sp.is_some() {
            ranges.push(0..snapshot.head.size);
        }
        ranges.sort_by_key(|r| (r.start, r.end));
        ranges.dedup();
        ranges
    }
    /// Follows a write for the ranges [`Self::refresh`] built.
    pub(super) fn feed_checked(&mut self, offset: u64, bytes: &[u8], budget: &PartialBudget) {
        let ranges = std::mem::take(&mut self.ranges);
        self.feed(&ranges, offset, bytes, budget);
        self.ranges = ranges;
    }

    /// Follows a write of `bytes` at output `offset` that landed on disk, for the checked `ranges`. A hash is
    /// begun only if `budget` grants it `BLAKE_STORAGE`; without it that range is read back when verified.
    pub(super) fn feed(&mut self, ranges: &[Range<u64>], offset: u64, bytes: &[u8], budget: &PartialBudget) {
        let end = offset.saturating_add(bytes.len() as u64);
        // ranges are sorted by start: only those starting before the write's end can meet it
        let upto = ranges.partition_point(|r| r.start < end);
        for range in &ranges[..upto] {
            let (from, to) = (offset.max(range.start), end.min(range.end));
            if from >= to {
                continue;
            }
            let piece = &bytes[(from - offset) as usize..(to - offset) as usize];
            let slot = self.runs.iter().position(|run| run.range == *range);
            match slot.map(|i| (i, self.runs[i].at)) {
                // Continues the run.
                Some((i, at)) if from == at => {
                    let run = &mut self.runs[i];
                    if let Err(hash) = &mut run.hash {
                        hash.update(piece);
                        run.at = to;
                        if to == range.end {
                            run.hash = Ok(hash.clone().finish());
                            run.lease = None;
                        }
                    }
                }
                // Past the run: read back when verified.
                Some((_, at)) if from > at => {}
                // Inside what the run hashed: dropped, unless the write begins the range again.
                Some((i, _)) => {
                    self.runs.swap_remove(i);
                    if from == range.start {
                        self.begin(range, piece, budget);
                    }
                }
                None if from == range.start => self.begin(range, piece, budget),
                None => {}
            }
        }
    }
    fn begin(&mut self, range: &Range<u64>, piece: &[u8], budget: &PartialBudget) {
        let at = range.start + piece.len() as u64;
        // The hasher and the run's slot are charged as a read-back's hasher is; refused, the range is read back.
        let lease = if at == range.end {
            None
        } else {
            match budget.reserve(PartialResource::LedgerBytes, BLAKE_STORAGE) {
                Ok(lease) => Some(lease),
                Err(_) => return,
            }
        };
        if self.runs.try_reserve(1).is_err() {
            return;
        }
        let mut hash = crate::blake2sp::Blake2sp::new();
        hash.update(piece);
        let hash = if at == range.end { Ok(hash.finish()) } else { Err(hash) };
        self.runs.push(BlakeRun { range: range.clone(), at, hash, lease });
    }
    pub(super) fn run(&self, range: &Range<u64>) -> Option<&BlakeRun> {
        self.runs.iter().find(|run| run.range == *range)
    }
}
struct Readback {
    range: Range<u64>,
    /// Where the read-back began: the range's start, or a [`BlakeFrontier`]'s end.
    from: u64,
    at: u64,
    hash: crate::blake2sp::Blake2sp,
    buffer: Vec<u8>,
    _lease: Reservation,
}
fn complete(snapshot: &Snapshot, range: &Range<u64>) -> bool {
    let mut at = range.start;
    let first = snapshot.known.partition_point(|leaf| leaf.range.end <= at);
    for leaf in &snapshot.known[first..] {
        if leaf.range.end <= at {
            continue;
        }
        if leaf.range.start > at {
            break;
        }
        at = leaf.range.end;
        if at >= range.end {
            return true;
        }
    }
    at >= range.end
}
/// Work charged to `VerifyWorkBytes` for combining one known leaf's CRC into a range check. A combine does not
/// read the leaf's bytes again (they were hashed once, when written), so it is charged at most this much rather
/// than the leaf's length. A leaf shorter than this is charged its length. Part results are kept for parts a
/// write did not touch, so a refill combines only the leaves of the parts it changes.
pub(super) const CRC_COMBINE_WORK: u64 = 64;
fn crc(
    snapshot: &Snapshot,
    range: &Range<u64>,
    expected: Option<u32>,
    key: Option<&[u8; 32]>,
    budget: &PartialBudget,
) -> PartialResult<CheckResult> {
    let Some(expected) = expected else { return Ok(CheckResult::Missing) };
    if !complete(snapshot, range) {
        return Ok(CheckResult::Pending);
    }
    let mut combined = crate::crc32::Hasher::new();
    let first = snapshot.known.partition_point(|leaf| leaf.range.end <= range.start);
    for leaf in snapshot.known[first..].iter().take_while(|leaf| leaf.range.start < range.end) {
        if leaf.range.start < range.start || leaf.range.end > range.end {
            return Err(malformed());
        }
        budget.usage.charge(Resource::VerifyWorkBytes, (leaf.range.end - leaf.range.start).min(CRC_COMBINE_WORK))?;
        combined.combine(&leaf.hasher);
    }
    let raw = combined.finalize();
    let crc = key.map_or(raw, |key| crate::crypto::rar5_tweak_crc32(raw, key));
    Ok(if crc == expected { CheckResult::Passed } else { CheckResult::Failed })
}
impl Verification {
    /// Fresh checks, reusing nothing.
    #[cfg(test)]
    pub fn new(snapshot: &Snapshot, budget: &PartialBudget, hash_key: Option<&[u8; 32]>) -> PartialResult<Self> {
        Self::after(Vec::new(), &[], snapshot, budget, hash_key)
    }
    /// The checks of `snapshot`, after a write that changed only output `changed`
    /// (empty when `previous` already matches these known leaves). A part
    /// CRC result in `previous` (computed for the known leaves before the
    /// write) whose range lies outside every changed range still holds: it
    /// depends only on the known leaves inside its range. Each write then
    /// re-combines only the parts it touched, instead of every part.
    ///
    /// Encrypted parts carry checks over their ciphertext, keyed with the password: they never check plaintext
    /// output, so they report `Missing`. Keyed member checks need `hash_key`; without it they stay unevaluated and
    /// verification reports [`PartialErrorKind::PasswordRequired`] once nothing else is missing.
    pub fn after(
        previous: Vec<PartCheck>,
        changed: &[Range<u64>],
        snapshot: &Snapshot,
        budget: &PartialBudget,
        hash_key: Option<&[u8; 32]>,
    ) -> PartialResult<Self> {
        // Checks the caller supplied for an abandoned tail are plain, whatever the archive keys.
        let keyed = (snapshot.crypt.is_some_and(|crypt| crypt.tweaked_crc)
            || snapshot.evidence.direct.as_ref().is_some_and(|d| d.keyed.is_some()))
            && snapshot.head.tail != Some(TailChecks::Supplied);
        let password_required = keyed
            && hash_key.is_none()
            && (snapshot.head.checks.crc32.is_some() || snapshot.head.checks.blake2sp.is_some());
        let key = hash_key.filter(|_| keyed).copied();
        let encrypted = snapshot.crypt.is_some();
        budget.usage.check(Resource::Parts, snapshot.evidence.parts.len() as u64)?;
        let bytes = std::mem::size_of::<Self>()
            .checked_add(
                snapshot.evidence.parts.len().checked_mul(std::mem::size_of::<PartCheck>()).ok_or_else(malformed)?,
            )
            .ok_or_else(malformed)?;
        let lease = budget.reserve(PartialResource::LedgerBytes, bytes as u64)?;
        // A verification is replaced after every write; charge it while it lives.
        let mut metadata = budget.metadata_lease(std::mem::size_of::<Self>() as u64)?;
        let (mut parts, vector) = budget.leased_vector(snapshot.evidence.parts.len())?;
        metadata.absorb(vector);
        for (i, part) in snapshot.evidence.parts.iter().enumerate() {
            let range = if part.final_part { 0..snapshot.head.size } else { part.out.clone() };
            budget.usage.charge(Resource::SourceBookkeeping, 1 + changed.len() as u64)?;
            let kept = previous
                .get(i)
                .filter(|old| {
                    old.part == part.ordinal
                        && old.volume == part.packed.volume
                        && old.range == range
                        && changed.iter().all(|c| c.end <= range.start || c.start >= range.end)
                })
                .map(|old| old.crc32.clone());
            parts.push(PartCheck {
                volume: part.packed.volume,
                part: part.ordinal,
                crc32: if encrypted {
                    CheckResult::Missing
                } else if let Some(kept) = kept {
                    kept
                } else {
                    crc(snapshot, &range, part.crc32, None, budget)?
                },
                blake2sp: if part.blake2sp.is_some() && !encrypted {
                    CheckResult::Pending
                } else {
                    CheckResult::Missing
                },
                range,
            });
        }
        // An unkeyed final part spanning the whole member with the member's
        // expected CRC is the same check; reuse its result instead of combining
        // every leaf a second time.
        let whole = 0..snapshot.head.size;
        // Only a part check that actually ran can stand in for the member check: encrypted parts are never
        // checked on plaintext (their result is Missing), so they must not short-circuit the member CRC.
        let same = parts.iter().zip(&snapshot.evidence.parts).find(|(check, part)| {
            part.final_part
                && key.is_none()
                && snapshot.crypt.is_none()
                && matches!(check.crc32, CheckResult::Passed | CheckResult::Failed)
                && check.range == whole
                && part.crc32 == snapshot.head.checks.crc32
        });
        let member_crc = if password_required {
            CheckResult::Missing
        } else if let Some((check, _)) = same {
            check.crc32.clone()
        } else {
            crc(snapshot, &whole, snapshot.head.checks.crc32, key.as_ref(), budget)?
        };
        Ok(Self {
            active: None,
            readback: None,
            revision: snapshot.head.revision,
            parts,
            member_crc,
            member_blake: if snapshot.head.checks.blake2sp.is_some() && !password_required {
                CheckResult::Pending
            } else {
                CheckResult::Missing
            },
            key,
            password_required,
            _lease: lease,
            _metadata: metadata,
        })
    }
    #[cfg(test)]
    pub(super) fn member_crc(&self) -> &CheckResult {
        &self.member_crc
    }
    pub fn needs_verification(&self) -> bool {
        self.password_required
            || self.parts.iter().any(|p| p.crc32 == CheckResult::Pending || p.blake2sp == CheckResult::Pending)
            || self.member_crc == CheckResult::Pending
            || self.member_blake == CheckResult::Pending
    }
    fn read_one(&mut self, core: &PartialCore, snapshot: &Snapshot, frontier: &BlakeFrontier) -> PartialResult<bool> {
        if self.active.is_none() {
            let range = self
                .parts
                .iter()
                .find(|p| p.blake2sp == CheckResult::Pending && complete(snapshot, &p.range))
                .map(|p| p.range.clone())
                .or_else(|| {
                    (self.member_blake == CheckResult::Pending && complete(snapshot, &(0..snapshot.head.size)))
                        .then_some(0..snapshot.head.size)
                });
            let Some(range) = range else { return Ok(false) };
            if core.read_chunk == 0 && !range.is_empty() {
                return Err(err(PartialErrorKind::InvalidOptions));
            }
            // A range whose run hashed it as it was written needs no read-back; a run that stopped short is
            // continued from its end, so only the bytes past it are read.
            let (from, hash) = match frontier.run(&range).map(|run| (run.at, &run.hash)) {
                Some((_, Ok(digest))) => {
                    let digest = *digest;
                    self.settle(&range, digest, snapshot);
                    return Ok(self.more(snapshot));
                }
                Some((at, Err(hash))) => (at, hash.clone()),
                None => (range.start, crate::blake2sp::Blake2sp::new()),
            };
            let n = (range.end - from).min(core.read_chunk as u64) as usize;
            let lease = core.budget.reserve(PartialResource::LedgerBytes, BLAKE_STORAGE + n as u64)?;
            core.budget.metadata(BLAKE_STORAGE)?;
            let mut buffer = core.budget.vector(n)?;
            buffer.resize(n, 0);
            self.active = Some(Readback { at: from, from, range, hash, buffer, _lease: lease });
        }
        let active = self.active.as_mut().unwrap();
        if active.at < active.range.end {
            canceled(&core.control)?;
            let n = (active.range.end - active.at).min(active.buffer.len() as u64) as usize;
            core.budget.usage.charge(Resource::VerifyBytes, n as u64)?;
            core.budget.usage.charge(Resource::VerifyWorkBytes, n as u64)?;
            let count = crate::output::range::read_at(&core.native.output.file, active.at, &mut active.buffer[..n])
                .map_err(|e| io_error(OutputOperation::Read, e))?;
            if count == 0 {
                return Err(err(PartialErrorKind::OutputChanged));
            }
            active.hash.update(&active.buffer[..count]);
            active.at += count as u64;
            if self.readback != Some(VerifyPath::WholeReadback) {
                self.readback = Some(if active.from == 0 && active.range == (0..snapshot.head.size) {
                    VerifyPath::WholeReadback
                } else {
                    VerifyPath::TargetedReadback
                });
            }
        }
        if active.at == active.range.end {
            let active = self.active.take().unwrap();
            self.settle(&active.range, active.hash.finish(), snapshot);
        }
        Ok(self.more(snapshot))
    }
    /// Records the BLAKE2sp `hash` of output `range` against every check over that range.
    fn settle(&mut self, range: &Range<u64>, hash: [u8; 32], snapshot: &Snapshot) {
        for (checks, part) in self.parts.iter_mut().zip(&snapshot.evidence.parts) {
            if checks.range == *range
                && let Some(expected) = part.blake2sp
            {
                checks.blake2sp = if hash == expected { CheckResult::Passed } else { CheckResult::Failed };
            }
        }
        if *range == (0..snapshot.head.size)
            && let Some(expected) = snapshot.head.checks.blake2sp
        {
            let hash = self.key.as_ref().map_or(hash, |key| crate::crypto::rar5_tweak_blake2sp(&hash, key));
            self.member_blake = if hash == expected { CheckResult::Passed } else { CheckResult::Failed };
        }
    }
    /// Whether a BLAKE2sp check can still make progress now.
    fn more(&self, snapshot: &Snapshot) -> bool {
        self.active.is_some()
            || self.parts.iter().any(|p| p.blake2sp == CheckResult::Pending && complete(snapshot, &p.range))
            || (self.member_blake == CheckResult::Pending && complete(snapshot, &(0..snapshot.head.size)))
    }
    fn bad(&self, snapshot: &Snapshot) -> Option<Verdict> {
        for (part, checks) in snapshot.evidence.parts.iter().zip(&self.parts) {
            for (result, which) in
                [(&checks.crc32, ChecksumAlgorithm::Crc32), (&checks.blake2sp, ChecksumAlgorithm::Blake2sp)]
            {
                if *result == CheckResult::Failed {
                    return Some(if part.final_part {
                        Verdict::Bad { revision: self.revision, which }
                    } else {
                        Verdict::PartBad { revision: self.revision, volume: checks.volume, part: checks.part, which }
                    });
                }
            }
        }
        for (result, which) in
            [(&self.member_crc, ChecksumAlgorithm::Crc32), (&self.member_blake, ChecksumAlgorithm::Blake2sp)]
        {
            if *result == CheckResult::Failed {
                return Some(Verdict::Bad { revision: self.revision, which });
            }
        }
        None
    }
}
impl PartialCore {
    fn verify_now(&self) -> PartialResult<Poll<Verdict>> {
        let mut op = self.operation()?;
        self.check(&op)?;
        self.flush_group(&mut op)?;
        self.reconcile(&mut op)?;
        if op.verification.as_ref().is_none_or(|v| v.revision != op.snapshot.head.revision) {
            let previous = self.part_results(&mut op);
            op.verification = Some(Verification::after(previous, &[], &op.snapshot, &self.budget, self.hash_key())?);
        }
        if let Some(bad) = op.verification.as_ref().unwrap().bad(&op.snapshot) {
            return Ok(Poll::Ready(bad));
        }
        let data = op.data.as_mut().unwrap();
        let pending = data.verification.as_mut().unwrap().read_one(self, &data.snapshot, &data.blake)?;
        self.check(&op)?;
        if pending {
            return Ok(Poll::Pending);
        }
        let verification = op.verification.as_ref().unwrap();
        if let Some(bad) = verification.bad(&op.snapshot) {
            return Ok(Poll::Ready(bad));
        }
        let mut parts = self.budget.vector(verification.parts.len())?;
        parts.extend_from_slice(&verification.parts);
        let missing_checks = op.snapshot.head.checks.crc32.is_none() && op.snapshot.head.checks.blake2sp.is_none();
        let password_required = verification.password_required;
        let pending = verification.needs_verification() && !password_required;
        let revision = verification.revision;
        let readback = verification.readback;
        let size = op.snapshot.head.size;
        let holes = ledger::Ledger { known: &mut op.snapshot.known, size, budget: &self.budget }.remaining()?;
        self.check(&op)?;
        // A direct member has no extraction to finish: its checks came from the map, and every byte written once
        // is all it needs.
        let finished = op.snapshot.head.member_finished || op.snapshot.evidence.direct.is_some();
        if password_required && finished && holes.is_empty() && !pending {
            return Err(err(PartialErrorKind::PasswordRequired));
        }
        if !finished || !holes.is_empty() || missing_checks || pending || password_required {
            Ok(Poll::Ready(Verdict::Incomplete { revision, holes, parts, missing_checks }))
        } else {
            // The operation token excludes mutation; callbacks have completed and
            // this stamp was checked for the same revision immediately above.
            self.native.written();
            let result = crate::extract::finish_file_checked(&self.native.output.file, &op.snapshot.evidence.metadata);
            let attribute = |result: Option<std::io::Result<()>>| match result {
                None => AttributeResult::NotRequested,
                Some(Ok(())) => AttributeResult::Applied,
                Some(Err(error)) => AttributeResult::Failed(error),
            };
            let metadata =
                MetadataResult { modified: attribute(result.modified), permissions: attribute(result.permissions) };
            (|| {
                op.stamp = stamp(&self.native)?;
                self.check(&op)
            })()
            .map_err(|mut error| {
                error.committed = Some(op.state.anchor().clone());
                error
            })?;
            Ok(Poll::Ready(Verdict::Ok {
                revision,
                parts,
                path: readback.unwrap_or(if op.reopened {
                    VerifyPath::ReopenRehash
                } else {
                    VerifyPath::ExtentCombine
                }),
                metadata,
            }))
        }
    }
}
impl PartialFile {
    /// Verifies the current revision using retained CRC hashers and bounded local BLAKE readback.
    /// Eligible parts finish even while other output remains missing; no source provider is called.
    pub fn poll_verify(&mut self, cx: &mut Context<'_>) -> Poll<PartialResult<Verdict>> {
        match self.core.verify_now() {
            Ok(Poll::Ready(v)) => Poll::Ready(Ok(v)),
            Err(e) => Poll::Ready(Err(e)),
            Ok(Poll::Pending) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
}
