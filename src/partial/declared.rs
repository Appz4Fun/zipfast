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

//! Refilling a `DeclaredBad` hole of a plain member from only the ranges a repair rewrote
//! ([`super::PartialFile::refill_declared_from_packed`]). The output under such a hole is kept as the extraction
//! wrote it (`Snapshot::kept`), so the repaired ranges are read from the volume, the rest is taken from the kept
//! leaves' CRC-32s, and each touched part's own check decides whether the whole hole is right.

use super::*;
use state::KnownLeaf;

/// Merges sorted-or-not ranges into a sorted, disjoint list (adjacent ranges joined).
fn merge(ranges: &mut Vec<Range<u64>>) {
    ranges.sort_by_key(|r| r.start);
    let mut out: Vec<Range<u64>> = Vec::with_capacity(ranges.len());
    for range in ranges.drain(..) {
        match out.last_mut() {
            Some(last) if range.start <= last.end => last.end = last.end.max(range.end),
            _ => out.push(range),
        }
    }
    *ranges = out;
}
/// Calls `f` with each piece of `range` and whether `cover` (sorted, disjoint) covers it, in order.
fn split(cover: &[Range<u64>], range: Range<u64>, mut f: impl FnMut(Range<u64>, bool)) {
    let first = cover.partition_point(|c| c.end <= range.start);
    let mut at = range.start;
    for c in cover[first..].iter().take_while(|c| c.start < range.end) {
        if at < c.start {
            f(at..c.start, false);
        }
        let end = c.end.min(range.end);
        if at.max(c.start) < end {
            f(at.max(c.start)..end, true);
        }
        at = at.max(end);
    }
    if at < range.end {
        f(at..range.end, false);
    }
}
fn unprovable() -> PartialError {
    err(PartialErrorKind::DeclaredRefill(DeclaredRefillFailure::Unprovable))
}

/// What a declared refill reads, rewrites and lets a check decide, worked out before anything changes.
struct DeclaredPlan {
    /// Output ranges read from the volume and written: the repaired ranges and hole output with no kept leaf, minus
    /// known output. Sorted, disjoint.
    read: Vec<Range<u64>>,
    /// The ranges the touched parts' checks cover (the whole member for a final part): their kept leaves become
    /// known if the checks pass. Sorted, disjoint.
    checks: Vec<Range<u64>>,
    /// Indices of the parts the hole touches.
    targets: Vec<usize>,
    /// (packed range, output offset of its start) of the hole on this volume.
    segments: Vec<(Range<u64>, u64)>,
    unmapped: Vec<PackedSpan>,
}
impl DeclaredPlan {
    /// The packed offset of output `out` and the output end of its segment.
    fn packed_at(&self, out: u64) -> Option<(u64, u64)> {
        self.segments.iter().find_map(|(packed, start)| {
            let end = start + (packed.end - packed.start);
            (*start <= out && out < end).then(|| (packed.start + (out - start), end))
        })
    }
}

impl PartialCore {
    /// Works out a declared refill of `hole` on `volume` with `repaired` (packed ranges inside it) for `snapshot`, or
    /// says why it cannot decide without reading more ([`DeclaredRefillFailure::Unprovable`]).
    fn declared_plan(
        &self,
        snapshot: &Snapshot,
        volume: u32,
        hole: &Range<u64>,
        repaired: &[Range<u64>],
    ) -> PartialResult<DeclaredPlan> {
        if snapshot.crypt.is_some() || snapshot.evidence.direct.is_some() {
            return Err(unprovable());
        }
        let produced = snapshot.head.produced;
        let parts = &snapshot.evidence.parts;
        let mut segments = self.budget.vector(parts.len())?;
        let mut targets = self.budget.vector(parts.len())?;
        for (index, part) in parts.iter().enumerate().filter(|(_, p)| p.packed.volume == volume) {
            let start = hole.start.max(part.packed.range.start);
            let stop = hole.end.min(part.packed.range.end);
            if start >= stop {
                continue;
            }
            // Plain parts map packed bytes one to one onto output.
            let out = part.out.start.checked_add(start - part.packed.range.start).ok_or_else(malformed)?;
            let out_end = out.saturating_add(stop - start).min(part.out.end).min(produced);
            if out < out_end {
                segments.push((start..start + (out_end - out), out));
                targets.push(index);
            }
        }
        if segments.is_empty() {
            return Err(unprovable());
        }
        let mut unmapped = self.budget.vector(segments.len() + 1)?;
        let mut at = hole.start;
        for (packed, _) in &segments {
            if at < packed.start {
                unmapped.push(PackedSpan { volume, range: at..packed.start });
            }
            at = packed.end;
        }
        if at < hole.end {
            unmapped.push(PackedSpan { volume, range: at..hole.end });
        }
        // The repaired ranges as output; bytes that map to no output (headers, padding) need no reading.
        let mut repaired_out = self.budget.vector(repaired.len().saturating_mul(segments.len()))?;
        for range in repaired {
            for (packed, out) in &segments {
                let start = range.start.max(packed.start);
                let stop = range.end.min(packed.end);
                if start < stop {
                    repaired_out.push(out + (start - packed.start)..out + (stop - packed.start));
                }
            }
        }
        merge(&mut repaired_out);
        let (mut known, _known_lease) = self.budget.leased_vector(snapshot.known.len())?;
        known.extend(snapshot.known.iter().map(|leaf| leaf.range.clone()));
        let (mut kept, _kept_lease) = self.budget.leased_vector(snapshot.kept.len())?;
        kept.extend(snapshot.kept.iter().map(|leaf| leaf.range.clone()));
        let mut read: Vec<Range<u64>> = Vec::new();
        let mut failure: Option<PartialError> = None;
        let mut push = |read: &mut Vec<Range<u64>>, range: Range<u64>| {
            if failure.is_some() {
                return;
            }
            if let Err(e) = self.budget.usage.charge(Resource::SourceBookkeeping, 1) {
                failure = Some(e.into());
                return;
            }
            match read.last_mut() {
                Some(last) if last.end == range.start => last.end = range.end,
                _ => {
                    if let Err(e) = self.budget.usage.check(Resource::HoleIntervals, read.len() as u64 + 1) {
                        failure = Some(e.into());
                    } else if read.try_reserve(1).is_err() {
                        failure = Some(malformed());
                    } else {
                        read.push(range);
                    }
                }
            }
        };
        for (packed, out) in &segments {
            let output = *out..out + (packed.end - packed.start);
            split(&known, output, |unknown, is_known| {
                if is_known {
                    return;
                }
                split(&repaired_out, unknown, |piece, is_repaired| {
                    if is_repaired {
                        push(&mut read, piece);
                    } else {
                        split(&kept, piece, |rest, is_kept| {
                            if !is_kept {
                                push(&mut read, rest);
                            }
                        });
                    }
                });
            });
        }
        if let Some(failure) = failure {
            return Err(failure);
        }
        // Every touched part needs a check that decides from leaf CRCs (or a local BLAKE2sp of a non-final part),
        // and all output it covers must be known, kept or read.
        let mut checks: Vec<Range<u64>> = Vec::new();
        checks.try_reserve_exact(targets.len()).map_err(|_| malformed())?;
        let mut cover: Vec<Range<u64>> = Vec::new();
        cover.try_reserve_exact(kept.len() + read.len()).map_err(|_| malformed())?;
        cover.extend(kept.iter().cloned().chain(read.iter().cloned()));
        merge(&mut cover);
        for &index in &targets {
            let part = &parts[index];
            if part.crc32.is_none() && (part.final_part || part.blake2sp.is_none()) {
                return Err(unprovable());
            }
            let range = if part.final_part { 0..snapshot.head.size } else { part.out.clone() };
            let mut complete = true;
            split(&known, range.clone(), |unknown, is_known| {
                if !is_known {
                    split(&cover, unknown, |_, covered| complete &= covered);
                }
            });
            if !complete {
                return Err(unprovable());
            }
            checks.push(range);
        }
        merge(&mut checks);
        Ok(DeclaredPlan { read, checks, targets, segments, unmapped })
    }
    /// `kept` with every leaf that `read` (sorted, disjoint) cuts replaced by its pieces outside `read`, each hashed
    /// again from the output.
    fn kept_outside(&self, kept: &[KnownLeaf], read: &[Range<u64>]) -> PartialResult<Vec<KnownLeaf>> {
        let mut out: Vec<KnownLeaf> = Vec::new();
        out.try_reserve_exact(kept.len().saturating_add(read.len())).map_err(|_| malformed())?;
        for leaf in kept {
            let first = read.partition_point(|r| r.end <= leaf.range.start);
            if !read.get(first).is_some_and(|r| r.start < leaf.range.end) {
                out.push(leaf.clone());
                continue;
            }
            let mut pieces: Vec<Range<u64>> = Vec::new();
            split(read, leaf.range.clone(), |piece, is_read| {
                if !is_read {
                    pieces.push(piece);
                }
            });
            for (index, piece) in pieces.into_iter().enumerate() {
                let lease = if index == 0 {
                    leaf._lease.clone()
                } else {
                    Arc::new(self.budget.reserve(PartialResource::CrcLeaves, 1)?)
                };
                out.try_reserve(1).map_err(|_| malformed())?;
                out.push(self.fragment(leaf, piece, lease)?);
            }
        }
        Ok(out)
    }
    /// BLAKE2sp of output `range`, read back in local chunks.
    fn local_blake(&self, range: &Range<u64>, buffer: &mut [u8]) -> PartialResult<[u8; 32]> {
        let mut hash = crate::blake2sp::Blake2sp::new();
        let mut at = range.start;
        while at < range.end {
            canceled(&self.control)?;
            let n = (range.end - at).min(buffer.len() as u64) as usize;
            self.budget.usage.charge(Resource::VerifyBytes, n as u64)?;
            self.budget.usage.charge(Resource::VerifyWorkBytes, n as u64)?;
            let read = crate::output::range::read_at(&self.native.output.file, at, &mut buffer[..n])
                .map_err(|e| io_error(OutputOperation::Read, e))?;
            if read == 0 {
                return Err(err(PartialErrorKind::OutputChanged));
            }
            hash.update(&buffer[..read]);
            at += read as u64;
        }
        Ok(hash.finish())
    }
    /// Commits `intent`/`valid` from [`Self::next_snapshots`] as one transaction.
    fn commit_snapshots(&self, op: &mut CoreData, intent: Snapshot, valid: Snapshot) -> PartialResult<()> {
        let transaction = self.begin_transaction(op, intent, valid, Vec::new())?;
        self.finish_transaction(op, transaction)
    }
    pub(crate) fn refill_declared<R: std::io::Read + std::io::Seek>(
        &self,
        volume: u32,
        hole: &Range<u64>,
        repaired: &[Range<u64>],
        reader: &mut R,
    ) -> PartialResult<PackedFillResult> {
        if hole.start >= hole.end
            || repaired.iter().any(|r| r.start >= r.end || r.start < hole.start || r.end > hole.end)
        {
            return Err(err(PartialErrorKind::InvalidOptions));
        }
        self.budget.usage.check(Resource::HoleIntervals, repaired.len() as u64)?;
        let chunk = self.budget.limits.value(PartialResource::FillBytes).min(self.read_chunk.max(1) as u64) as usize;
        if chunk == 0 {
            return Err(err(PartialErrorKind::InvalidOptions));
        }
        let mut op = self.operation()?;
        self.check(&op)?;
        self.flush_group(&mut op)?;
        self.reconcile(&mut op)?;
        let _result_lease =
            self.budget.metadata_lease(op.state.wire.len() as u64 + std::mem::size_of::<Range<u64>>() as u64)?;
        let plan = self.declared_plan(&op.snapshot, volume, hole, repaired)?;
        let mut count = 0usize;
        for range in &plan.read {
            let mut at = range.start;
            while at < range.end {
                let boundary = op.snapshot.part_end(at).ok_or_else(malformed)?;
                at = range.end.min(boundary).min(at.saturating_add(65_536 - at % 65_536));
                count += 1;
            }
        }
        // Kept leaves the read ranges cut keep their pieces outside them (two at most per read range).
        count = count.checked_add(plan.read.len().saturating_mul(2)).ok_or_else(malformed)?;
        self.budget.limits.check(
            PartialResource::CrcLeaves,
            (op.snapshot.known.len() + op.snapshot.kept.len()).checked_add(count).ok_or_else(malformed)? as u64,
        )?;
        let total: u64 = plan.read.iter().map(|r| r.end - r.start).sum();
        self.budget.usage.charge(Resource::OutputWriteBytes, total)?;
        let (mut buffer, _buffer_lease) = self.budget.leased_vector::<u8>(chunk)?;
        buffer.resize(chunk, 0);
        let (mut leaves, _leaves_lease) = self.budget.leased_vector::<KnownLeaf>(count)?;

        // First the kept leaves under the bytes this call rewrites are cut down to their pieces outside them (hashed
        // from the output, which has not changed yet), durably, before any byte changes; the hole stays. The bytes
        // rewritten are then unknown output nothing vouches for, so a crash from here on leaves the hole as it was,
        // with the read ranges no longer kept (a retry reads exactly those again).
        if op.snapshot.kept.iter().any(|leaf| {
            let first = plan.read.partition_point(|r| r.end <= leaf.range.start);
            plan.read.get(first).is_some_and(|r| r.start < leaf.range.end)
        }) {
            let kept = self.kept_outside(&op.snapshot.kept, &plan.read)?;
            let (mut intent, mut valid, _snapshots) = self.next_snapshots(&op)?;
            intent.kept = kept.clone();
            valid.kept = kept;
            self.commit_snapshots(&mut op, intent, valid)?;
        }
        #[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
        tests::state::checkpoint("declared-dropped");

        // Writes the read ranges from the volume, hashing each new leaf as it goes.
        let mut blake = std::mem::take(&mut op.blake);
        let hashing = blake.refresh(&op.snapshot);
        let write = (|| -> PartialResult<()> {
            for range in &plan.read {
                let mut at = range.start;
                while at < range.end {
                    let boundary = op.snapshot.part_end(at).ok_or_else(malformed)?;
                    let stop = range.end.min(boundary).min(at.saturating_add(65_536 - at % 65_536));
                    let mut hasher = crate::crc32::Hasher::new();
                    let mut pos = at;
                    while pos < stop {
                        canceled(&self.control)?;
                        let (packed, segment_end) = plan.packed_at(pos).ok_or_else(malformed)?;
                        let n = (stop.min(segment_end) - pos).min(buffer.len() as u64) as usize;
                        reader
                            .seek(std::io::SeekFrom::Start(packed))
                            .and_then(|_| reader.read_exact(&mut buffer[..n]))
                            .map_err(|cause| {
                                let mut error = err(PartialErrorKind::PackedRead(cause));
                                error.volume = Some(volume);
                                error.packed_offset = Some(packed);
                                error
                            })?;
                        self.native.check(op.snapshot.head.size)?;
                        self.native.written();
                        let mut done = 0;
                        while done < n {
                            let w = write_output(&self.native.output.file, pos + done as u64, &buffer[done..n])
                                .map_err(|e| io_error(OutputOperation::Write, e))?;
                            if w == 0 {
                                return Err(io_error(OutputOperation::Write, std::io::ErrorKind::WriteZero.into()));
                            }
                            done += w;
                        }
                        if hashing {
                            blake.feed_checked(pos, &buffer[..n], &self.budget);
                        }
                        #[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
                        tests::state::checkpoint("write");
                        self.budget.usage.charge(Resource::VerifyWorkBytes, n as u64)?;
                        hasher.update(&buffer[..n]);
                        pos += n as u64;
                    }
                    leaves.push(KnownLeaf {
                        range: at..stop,
                        crc: hasher.clone().finalize(),
                        hasher,
                        provenance: state::Provenance::Original,
                        _lease: Arc::new(self.budget.reserve(PartialResource::CrcLeaves, 1)?),
                    });
                    at = stop;
                }
            }
            Ok(())
        })();
        op.blake = blake;
        let refresh = (|| {
            op.stamp = stamp(&self.native)?;
            Ok(())
        })();
        if let Err(mut error) = write.and(refresh) {
            error.committed = Some(op.state.anchor.clone());
            return Err(error);
        }

        // The state if the checks pass: the kept leaves inside the checked ranges and the rebuilt leaves become
        // known output, and the hole closes as far as they reach.
        let (intent, valid, _snapshots) = self.next_snapshots(&op)?;
        let (mut passed, _passed_lease) = self.clone_snapshot(&valid)?;
        let mut restored: Vec<KnownLeaf> = Vec::new();
        restored.try_reserve_exact(passed.kept.len() + leaves.len()).map_err(|_| malformed())?;
        let mut rest = Vec::new();
        rest.try_reserve_exact(passed.kept.len()).map_err(|_| malformed())?;
        for leaf in passed.kept.drain(..) {
            let first = plan.checks.partition_point(|c| c.end <= leaf.range.start);
            if plan.checks.get(first).is_some_and(|c| c.start <= leaf.range.start && leaf.range.end <= c.end) {
                restored.push(leaf);
            } else {
                rest.push(leaf);
            }
        }
        passed.kept = rest;
        restored.extend(leaves.iter().cloned());
        restored.sort_by_key(|leaf| leaf.range.start);
        let mut applied: Vec<Range<u64>> = Vec::new();
        applied.try_reserve_exact(restored.len()).map_err(|_| malformed())?;
        applied.extend(restored.iter().map(|leaf| leaf.range.clone()));
        merge(&mut applied);
        self.budget.metadata((restored.len() * std::mem::size_of::<KnownLeaf>()) as u64)?;
        passed.known.try_reserve_exact(restored.len()).map_err(|_| malformed())?;
        passed.known.extend(restored);
        passed.known.sort_by_key(|leaf| leaf.range.start);
        if passed.known.windows(2).any(|w| w[0].range.end > w[1].range.start) {
            return Err(malformed());
        }
        ledger::Ledger { known: &mut passed.known, size: passed.head.size, budget: &self.budget }.check_intervals()?;
        passed.holes = self.remaining_reports(&mut passed)?;
        let verification = verify::Verification::after(Vec::new(), &[], &passed, &self.budget, self.hash_key())?;
        let mut failed = Vec::new();
        for &index in &plan.targets {
            let part = &passed.evidence.parts[index];
            let check = verification.parts.get(index).ok_or_else(malformed)?;
            let ok = match &check.crc32 {
                CheckResult::Passed => true,
                CheckResult::Missing if !part.final_part => match part.blake2sp {
                    Some(expected) => self.local_blake(&part.out, &mut buffer)? == expected,
                    None => false,
                },
                _ => false,
            };
            if !ok {
                failed.try_reserve(1).map_err(|_| malformed())?;
                failed.push(part.ordinal);
            }
        }
        drop(verification);
        if failed.is_empty() {
            self.commit_snapshots(&mut op, intent, passed)?;
            op.verification = None;
            let fill = self.fill_result(&mut op, applied)?;
            return Ok(PackedFillResult {
                revision: fill.revision,
                applied: fill.applied,
                corrected: Vec::new(),
                unmapped: plan.unmapped,
                undecryptable: Vec::new(),
                state: fill.state,
                part_checks: fill.part_checks,
                needs_verification: fill.needs_verification,
            });
        }
        drop(passed);
        // The checks failed: the hole stays, and the bytes written (repaired archive bytes) are kept in place of the
        // ones they replaced, so a later call with more ranges reads only those.
        let mut valid = valid;
        self.budget.metadata((leaves.len() * std::mem::size_of::<KnownLeaf>()) as u64)?;
        valid.kept.try_reserve_exact(leaves.len()).map_err(|_| malformed())?;
        valid.kept.extend(leaves.iter().cloned());
        valid.kept.sort_by_key(|leaf| leaf.range.start);
        state::prune_kept(&mut valid, &[]);
        self.commit_snapshots(&mut op, intent, valid)?;
        op.verification = None;
        let mut error = err(PartialErrorKind::DeclaredRefill(DeclaredRefillFailure::CheckFailed { parts: failed }));
        error.committed = Some(op.state.anchor.clone());
        Err(error)
    }
}
