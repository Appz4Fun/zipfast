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

pub(super) struct OriginalSource {
    pub(super) source: Box<dyn RangeSource>,
    pub(super) index: u32,
    pub(super) live: SourceInfo,
    pub(super) holes: Vec<(u64, u64)>,
    pub(super) backing_count: usize,
}
pub(super) struct RetainedOriginals {
    pub(super) slots: Vec<OriginalSource>,
    pub(super) high_water: Option<u32>,
    // The allocation identity is stable when SourceDriver moves. Task 2 binds leases to it.
    _identity: Arc<()>,
    _lease_counter: u64,
}
impl OriginalSource {
    /// First interval whose end is >= offset (coalescing) or > offset (fill).
    /// Search steps are charged individually before each comparison.
    pub(super) fn hole_bound(&self, offset: u64, touching: bool, usage: &mut Usage) -> ProgressiveResult<usize> {
        let (mut low, mut high) = (0, self.holes.len());
        while low < high {
            usage.charge(Resource::SourceBookkeeping, 1)?;
            let mid = low + (high - low) / 2;
            let end = self.holes[mid].1;
            if end < offset || (!touching && end == offset) {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        Ok(low)
    }
    pub(super) fn remember_hole(&mut self, offset: u64, end: u64, usage: &mut Usage) -> ProgressiveResult<()> {
        let start = self.hole_bound(offset, true, usage)?;
        let mut after = start;
        let mut range = (offset, end);
        while after < self.holes.len() {
            usage.charge(Resource::SourceBookkeeping, 1)?;
            let (a, b) = self.holes[after];
            if a > range.1 {
                break;
            }
            range.0 = range.0.min(a);
            range.1 = range.1.max(b);
            after += 1;
        }
        if start == after {
            // Admit all bulk movement before allocating/mutating. Capacity grows
            // geometrically; possible allocator copying is charged separately.
            usage.charge(Resource::SourceBookkeeping, (self.holes.len() - start) as u64)?;
            reserve_records(&mut self.holes, usage)?;
            self.holes.insert(start, range);
        } else {
            let removed = after - start;
            // At most one shift of the tail, plus all replaced/removed slots.
            usage.charge(Resource::SourceBookkeeping, (removed + self.holes.len() - after) as u64)?;
            self.holes[start] = range;
            self.holes.drain(start + 1..after);
        }
        Ok(())
    }
    pub(super) fn check_info(&mut self, usage: &mut Usage) -> ProgressiveResult<()> {
        usage.charge(Resource::SourceRequests, 1)?;
        let new = self.source.info();
        let old = self.live;
        if new.id != old.id
            || new.generation != old.generation
            || new.length.value() != old.length.value()
            || matches!((old.length, new.length), (SourceLength::Final(_), SourceLength::Advertised(_)))
        {
            return Err(changed());
        }
        if new.extent > new.length.value() || new.extent < old.extent {
            return Err(contract());
        }
        self.live = new;
        Ok(())
    }
}
impl SourceDriver {
    // H2 will call this internal entrypoint; legacy construction remains unchanged.
    #[allow(dead_code)]
    pub(crate) fn new_retained(
        provider: Box<dyn VolumeSource>,
        first: OsString,
        limits: ProgressiveLimits,
        control: SessionControl,
    ) -> ProgressiveResult<Self> {
        let mut driver = Self::new(provider, first, limits, control)?;
        driver.usage.charge(Resource::MetadataBytes, (2 * std::mem::size_of::<usize>()) as u64)?;
        driver.retained =
            Some(RetainedOriginals { slots: Vec::new(), high_water: None, _identity: Arc::new(()), _lease_counter: 0 });
        Ok(driver)
    }
    pub(super) fn backing_count(&self) -> usize {
        self.original.as_ref().map_or(0, |original| original.backing_count)
    }
    pub(super) fn retained_backing_count(&self) -> ProgressiveResult<usize> {
        let Some(retained) = &self.retained else {
            return Ok(0);
        };
        self.usage.charge(Resource::SourceBookkeeping, retained.slots.len() as u64)?;
        Ok(retained.slots.iter().map(|original| original.backing_count).sum())
    }
    pub(super) fn original_count(&self) -> usize {
        self.retained.as_ref().map_or(0, |retained| retained.slots.len()) + usize::from(self.original.is_some())
    }
    pub(super) fn check_original_capacity(&self) -> ProgressiveResult<()> {
        if self.retained.is_some() {
            self.usage.check(Resource::VolumeHandles, (self.original_count() + self.replacements.len() + 1) as u64)?;
        }
        Ok(())
    }
    pub(super) fn select_retained(&mut self, request: VolumeRequest) -> ProgressiveResult<()> {
        if self.parked || self.failed || self.original.is_none() {
            return Err(contract());
        }
        let retained = self.retained.as_mut().unwrap();
        self.usage.charge(Resource::SourceBookkeeping, self.admitted.len() as u64)?;
        let admitted = self.admitted.iter().find(|(index, _, _, _)| *index == request.index);
        if let Some((_, _, name, _)) = admitted {
            self.usage.charge(Resource::SourceBookkeeping, name.len().max(request.expected.len()) as u64)?;
            if *name != request.expected {
                return Err(contract());
            }
        } else if retained.high_water.and_then(|i| i.checked_add(1)) != Some(request.index) {
            return Err(contract());
        }
        self.usage.charge(Resource::NameBytes, request.expected.len() as u64)?;
        self.usage.charge(Resource::MetadataBytes, request.expected.capacity() as u64)?;
        // Bound insertion/removal shifts and both index searches before ownership changes.
        // reserve_records separately admits any allocator copy of the old slots.
        self.usage.charge(Resource::SourceBookkeeping, (retained.slots.len() * 5 + 4) as u64)?;
        // Prepare both movement capacity and the fresh selected-request gate before moving owners.
        reserve_records(&mut retained.slots, &mut self.usage)?;
        self.usage.charge(
            Resource::MetadataBytes,
            (std::mem::size_of::<WakeGate>() + 2 * std::mem::size_of::<usize>()) as u64,
        )?;
        let wake = Arc::new(WakeGate::default());
        let old = self.original.take().unwrap();
        let position = retained.slots.partition_point(|source| source.index < old.index);
        retained.slots.insert(position, old);
        self.original = retained
            .slots
            .iter()
            .position(|source| source.index == request.index)
            .map(|position| retained.slots.remove(position));
        self.reopened = self.original.is_some();
        self.wake.disarm();
        self.wake = wake;
        self.retry_admitted = false;
        self.request = request;
        self.cursor = CheckedCursor::new(0);
        Ok(())
    }
}
