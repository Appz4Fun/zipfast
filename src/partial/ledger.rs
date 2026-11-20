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
use state::KnownLeaf;

pub(super) struct Ledger<'a> {
    pub known: &'a mut Vec<KnownLeaf>,
    pub size: u64,
    pub budget: &'a PartialBudget,
}
pub(super) struct FillPlan {
    pub unknown: Vec<Range<u64>>,
}
/// Calls `f` with each piece of `range` that no leaf of `known` (sorted, disjoint) covers, in order.
fn for_each_unknown(known: &[KnownLeaf], range: Range<u64>, mut f: impl FnMut(Range<u64>)) {
    let first = known.partition_point(|leaf| leaf.range.end <= range.start);
    let mut at = range.start;
    for leaf in known[first..].iter().take_while(|leaf| leaf.range.start < range.end) {
        if leaf.range.end <= at {
            continue;
        }
        if at < leaf.range.start {
            f(at..leaf.range.start);
        }
        at = at.max(leaf.range.end.min(range.end));
    }
    if at < range.end {
        f(at..range.end);
    }
}

impl Ledger<'_> {
    pub fn plan_fill(&self, range: Range<u64>) -> PartialResult<FillPlan> {
        // Leaves are sorted and disjoint: start at the first one ending after the range start.
        let first = self.known.partition_point(|leaf| leaf.range.end <= range.start);
        let overlapping = || self.known[first..].iter().take_while(|leaf| leaf.range.start < range.end);
        let mut count = 0;
        let mut at = range.start;
        for leaf in overlapping() {
            if leaf.range.end <= at {
                continue;
            }
            if at < leaf.range.start {
                count += 1;
            }
            at = at.max(leaf.range.end.min(range.end));
        }
        if at < range.end {
            count += 1;
        }
        self.budget.usage.check(Resource::HoleIntervals, count as u64)?;
        let mut unknown = self.budget.vector(count)?;
        at = range.start;
        for leaf in overlapping() {
            if leaf.range.end <= at {
                continue;
            }
            if at < leaf.range.start {
                unknown.push(at..leaf.range.start);
            }
            at = at.max(leaf.range.end.min(range.end));
        }
        if at < range.end {
            unknown.push(at..range.end);
        }
        Ok(FillPlan { unknown })
    }
    pub fn commit_fill(&mut self, plan: &FillPlan, leaves: &[KnownLeaf]) -> PartialResult<()> {
        let mut index = 0;
        for range in &plan.unknown {
            let mut at = range.start;
            while at < range.end {
                let leaf = leaves.get(index).ok_or_else(malformed)?;
                if leaf.range.start != at || leaf.range.end > range.end || leaf.range.is_empty() {
                    return Err(malformed());
                }
                at = leaf.range.end;
                index += 1;
            }
        }
        if index != leaves.len() {
            return Err(malformed());
        }
        self.budget.metadata(std::mem::size_of_val(leaves) as u64)?;
        self.known.try_reserve_exact(leaves.len()).map_err(|_| malformed())?;
        self.known.extend_from_slice(leaves);
        self.known.sort_by_key(|leaf| leaf.range.start);
        Ok(())
    }
    pub fn remaining(&self) -> PartialResult<Vec<Range<u64>>> {
        Ok(self.plan_fill(0..self.size)?.unknown)
    }
    /// Checks the member's unknown ranges against `ProgressiveLimits::hole_intervals`, as [`Self::remaining`]
    /// does, without building the list.
    pub fn check_intervals(&self) -> PartialResult<()> {
        let mut count = 0u64;
        for_each_unknown(self.known, 0..self.size, |_| count += 1);
        self.budget.usage.check(Resource::HoleIntervals, count)?;
        Ok(())
    }
}

// Physical rereads rebuild fragment hashers; CRC values are never split algebraically.
impl PartialCore {
    pub(super) fn fragment(
        &self,
        leaf: &KnownLeaf,
        range: Range<u64>,
        lease: Arc<Reservation>,
    ) -> PartialResult<KnownLeaf> {
        let len = self.read_chunk.min((range.end - range.start) as usize);
        let mut buffer = self.budget.vector(len)?;
        buffer.resize(len, 0);
        let mut hasher = crate::crc32::Hasher::new();
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
            hasher.update(&buffer[..read]);
            at += read as u64;
        }
        Ok(KnownLeaf { range, crc: hasher.clone().finalize(), hasher, provenance: leaf.provenance, _lease: lease })
    }
    /// The recorded holes trimmed to what is still unknown: each report split into the unknown pieces of its
    /// output, with their packed spans. The result replaces `snapshot.holes`, so only growth past the old list is
    /// charged for good (a fill splitting a hole); the copy built alongside the old list is a lease for this call.
    pub(super) fn remaining_reports(&self, snapshot: &mut Snapshot) -> PartialResult<Vec<HoleReport>> {
        let report_bytes = |spans: usize| std::mem::size_of::<HoleReport>() + spans * std::mem::size_of::<PackedSpan>();
        let known = &snapshot.known;
        let (mut count, mut bytes) = (0usize, 0usize);
        for report in &snapshot.holes {
            for_each_unknown(known, report.out.clone(), |out| {
                count += 1;
                bytes += report_bytes(super::cipher::packed_span_count(snapshot, &out));
            });
        }
        self.budget.usage.check(Resource::HoleIntervals, count as u64)?;
        let old: usize = snapshot.holes.iter().map(|h| report_bytes(h.packed.len())).sum();
        if bytes > old {
            self.budget.metadata((bytes - old) as u64)?;
        }
        let _copy = self.budget.metadata_lease(bytes as u64)?;
        let mut reports = Vec::new();
        reports.try_reserve_exact(count).map_err(|_| malformed())?;
        for report in &snapshot.holes {
            let mut failed = false;
            for_each_unknown(known, report.out.clone(), |out| {
                let mut packed = Vec::new();
                if packed.try_reserve_exact(super::cipher::packed_span_count(snapshot, &out)).is_err() {
                    failed = true;
                    return;
                }
                super::cipher::push_packed_spans(snapshot, &out, &mut packed);
                reports.push(HoleReport {
                    id: report.id,
                    revision: report.revision,
                    member: report.member.clone(),
                    name: report.name.clone(),
                    out,
                    packed,
                    cause: report.cause.clone(),
                });
            });
            if failed {
                return Err(malformed());
            }
        }
        Ok(reports)
    }
    /// The known leaves of `snapshot` with `range` cut out. The new vector's charge lasts as long as the returned
    /// lease: it replaces the snapshot's vector, so hold the lease while both exist.
    pub(super) fn invalidate(
        &self,
        snapshot: &Snapshot,
        range: &Range<u64>,
    ) -> PartialResult<(Vec<KnownLeaf>, crate::progressive::Lease)> {
        let count = snapshot
            .known
            .iter()
            .map(|l| {
                if l.range.end <= range.start || l.range.start >= range.end {
                    1
                } else {
                    usize::from(l.range.start < range.start) + usize::from(l.range.end > range.end)
                }
            })
            .sum::<usize>();
        self.budget.limits.check(PartialResource::CrcLeaves, count as u64)?;
        let (mut known, vector_lease) = self.budget.leased_vector(count)?;
        for leaf in &snapshot.known {
            if leaf.range.end <= range.start || leaf.range.start >= range.end {
                known.push(leaf.clone());
                continue;
            }
            let left = leaf.range.start < range.start;
            if left {
                known.push(self.fragment(leaf, leaf.range.start..range.start, leaf._lease.clone())?);
            }
            if leaf.range.end > range.end {
                let lease = if left {
                    Arc::new(self.budget.reserve(PartialResource::CrcLeaves, 1)?)
                } else {
                    leaf._lease.clone()
                };
                known.push(self.fragment(leaf, range.end..leaf.range.end, lease)?);
            }
        }
        Ok((known, vector_lease))
    }
}
