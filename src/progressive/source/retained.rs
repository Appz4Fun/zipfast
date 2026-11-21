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
    pub(super) lease: Option<Weak<LeaseEpoch>>,
}
pub(super) struct RetainedOriginals {
    pub(super) slots: Vec<OriginalSource>,
    pub(super) high_water: Option<u32>,
    // The allocation identity is stable when SourceDriver moves. Task 2 binds leases to it.
    pub(super) owner: CancelOwner,
    pub(super) lease_counter: u64,
    pub(super) selected_cancel: Option<CancelRegistration>,
    pub(super) selected_fresh: bool,
    pub(super) selected_len: Option<usize>,
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
        self.observe_info(new)
    }
    pub(super) fn observe_info(&mut self, new: SourceInfo) -> ProgressiveResult<()> {
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
    // The opt-in persistent session retains original sources; legacy construction remains unchanged.
    #[cfg_attr(
        not(feature = "persistent-partials"),
        allow(dead_code, reason = "used by the opt-in persistent session")
    )]
    pub(crate) fn new_retained(
        provider: Box<dyn VolumeSource>,
        first: OsString,
        limits: ProgressiveLimits,
        control: SessionControl,
    ) -> ProgressiveResult<Self> {
        let max_operations = limits.volume_handles.min(4096);
        let mut driver = Self::new(provider, first, limits, control)?;
        driver.control.enable_retained_cancel(&mut driver.usage)?;
        driver.usage.charge(Resource::MetadataBytes, (2 * std::mem::size_of::<usize>()) as u64)?;
        driver.retained = Some(RetainedOriginals {
            slots: Vec::new(),
            high_water: None,
            owner: CancelOwner { identity: Arc::new(()), max_operations },
            lease_counter: 0,
            selected_cancel: None,
            selected_fresh: false,
            selected_len: None,
        });
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
        if self.control.is_canceled() {
            return Err(canceled());
        }
        if self.original.as_mut().is_some_and(|s| s.leased()) {
            return Err(invalid_capability());
        }
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
        retained.selected_cancel = None;
        retained.selected_fresh = false;
        retained.selected_len = None;
        self.wake.disarm();
        self.wake = wake;
        self.retry_admitted = false;
        self.request = request;
        self.cursor = CheckedCursor::new(0);
        Ok(())
    }
}

pub(super) struct LeaseEpoch {
    retired: AtomicBool,
    number: u64,
}
#[allow(dead_code, reason = "H3/H4 consume retained discovery and refill entrypoints")]
#[derive(Clone, Copy)]
pub(crate) enum OriginalReadPurpose {
    Discovery,
    Refill,
}
#[derive(Clone, Copy)]
enum ReadState {
    Active,
    Parked { offset: u64, requested_len: usize },
    Retired,
    Failed,
    Canceled,
}
#[allow(dead_code, reason = "H3/H4 consume retained discovery and refill entrypoints")]
pub(crate) struct OriginalRead {
    #[cfg(feature = "persistent-partials")]
    pending_partial_read: Option<PendingPartialRead>,
    owner: Arc<()>,
    volume: u32,
    identity: SourceInfo,
    epoch: Arc<LeaseEpoch>,
    pub(super) cursor: CheckedCursor,
    gate: Arc<WakeGate>,
    registration: Option<CancelRegistration>,
    state: ReadState,
    purpose: OriginalReadPurpose,
    fresh: bool,
}
impl OriginalRead {
    fn close(&mut self, state: ReadState) {
        self.state = state;
        self.epoch.retired.store(true, Ordering::Release);
        self.gate.disarm();
        self.registration = None;
    }
}
impl Drop for OriginalRead {
    fn drop(&mut self) {
        self.close(ReadState::Retired);
    }
}
impl OriginalSource {
    pub(super) fn leased(&mut self) -> bool {
        if self.lease.as_ref().and_then(Weak::upgrade).is_some_and(|epoch| !epoch.retired.load(Ordering::Acquire)) {
            true
        } else {
            self.lease = None;
            false
        }
    }
}
fn new_gate(usage: &mut Usage) -> ProgressiveResult<Arc<WakeGate>> {
    usage
        .charge(Resource::MetadataBytes, (std::mem::size_of::<WakeGate>() + 2 * std::mem::size_of::<usize>()) as u64)?;
    Ok(Arc::new(WakeGate::default()))
}
impl SourceDriver {
    pub(super) fn prepare_selected(&mut self, cx: &mut Context<'_>, len: usize) -> ProgressiveResult<()> {
        let retained = self.retained.as_mut().unwrap();
        if retained.selected_fresh {
            let gate = new_gate(&mut self.usage)?;
            self.wake.disarm();
            self.wake = gate;
            retained.selected_fresh = false;
        }
        self.wake.register(cx.waker());
        if self.control.is_canceled() {
            self.wake.notify_canceled();
            return Err(canceled());
        }
        if retained.selected_cancel.is_none() {
            retained.selected_cancel =
                Some(self.control.register_retained_cancel(&retained.owner, &self.wake, &mut self.usage)?);
        }
        if self.control.is_canceled() {
            return Err(canceled());
        }
        retained.selected_len = Some(len);
        Ok(())
    }
    pub(super) fn finish_selected_request(&mut self) {
        let retained = self.retained.as_mut().unwrap();
        retained.selected_cancel = None;
        retained.selected_fresh = true;
        retained.selected_len = None;
        self.wake.disarm();
    }
    fn original_mut(&mut self, volume: u32) -> ProgressiveResult<&mut OriginalSource> {
        original_parts(&mut self.original, &mut self.retained, &mut self.usage, volume)
    }
    #[allow(dead_code, reason = "H3/H4 consume retained discovery and refill entrypoints")]
    pub(crate) fn begin_original_read(
        &mut self,
        volume: u32,
        offset: u64,
        purpose: OriginalReadPurpose,
    ) -> ProgressiveResult<OriginalRead> {
        if self.control.is_canceled() {
            return Err(canceled());
        }
        if self.failed {
            return Err(contract());
        }
        let retained = self.retained.as_ref().ok_or_else(invalid_capability)?;
        let owner = retained.owner.identity.clone();
        // A parked selected request already owns this lane.
        if self.request.index == volume && (self.parked || retained.selected_cancel.is_some()) {
            return Err(invalid_capability());
        }
        let number = retained.lease_counter.checked_add(1).ok_or_else(invalid_capability)?;
        let mut usage = self.usage.clone();
        let source = self.original_mut(volume)?;
        if source.leased() {
            return Err(invalid_capability());
        }
        if offset > source.live.length.value() {
            return Err(contract());
        }
        let identity = source.live;
        usage.charge(
            Resource::MetadataBytes,
            (std::mem::size_of::<LeaseEpoch>() + 2 * std::mem::size_of::<usize>()) as u64,
        )?;
        let gate = new_gate(&mut usage)?;
        let epoch = Arc::new(LeaseEpoch { retired: AtomicBool::new(false), number });
        source.lease = Some(Arc::downgrade(&epoch));
        self.retained.as_mut().unwrap().lease_counter = number;
        Ok(OriginalRead {
            #[cfg(feature = "persistent-partials")]
            pending_partial_read: None,
            owner,
            volume,
            identity,
            epoch,
            cursor: CheckedCursor::new(offset),
            gate,
            registration: None,
            state: ReadState::Active,
            purpose,
            fresh: false,
        })
    }
    fn check_read(&mut self, read: &OriginalRead) -> ProgressiveResult<()> {
        let retained = self.retained.as_ref().ok_or_else(invalid_capability)?;
        if !Arc::ptr_eq(&retained.owner.identity, &read.owner) || read.epoch.retired.load(Ordering::Acquire) {
            return Err(invalid_capability());
        }
        let source = self.original_mut(read.volume)?;
        let epoch = source.lease.as_ref().and_then(Weak::upgrade).ok_or_else(invalid_capability)?;
        if !Arc::ptr_eq(&epoch, &read.epoch)
            || epoch.number != read.epoch.number
            || source.live.id != read.identity.id
            || source.live.generation != read.identity.generation
        {
            return Err(invalid_capability());
        }
        Ok(())
    }
    #[allow(dead_code, reason = "H3/H4 consume retained discovery and refill entrypoints")]
    pub(crate) fn retire_original_read(&mut self, read: &mut OriginalRead) -> ProgressiveResult<()> {
        // Retirement stays terminal even when cancellation is already latched.
        if !self.retained.as_ref().is_some_and(|retained| Arc::ptr_eq(&retained.owner.identity, &read.owner)) {
            return Err(if self.control.is_canceled() { canceled() } else { invalid_capability() });
        }
        let result = self.check_read(read);
        read.close(ReadState::Retired);
        if self.control.is_canceled() {
            return Err(canceled());
        }
        result
    }
    #[allow(dead_code, reason = "H3/H4 consume retained discovery and refill entrypoints")]
    pub(crate) fn poll_original_read(
        &mut self,
        read: &mut OriginalRead,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<ProgressiveResult<SourceStep>> {
        if self.control.is_canceled() {
            if self.retained.as_ref().is_some_and(|retained| Arc::ptr_eq(&retained.owner.identity, &read.owner)) {
                read.close(ReadState::Canceled);
            }
            return Poll::Ready(Err(canceled()));
        }
        if let Err(e) = self.check_read(read) {
            if !matches!(e.kind, FailureKind::InvalidCapability) {
                self.failed = true;
                self.finish_selected_request();
                read.close(ReadState::Failed);
            }
            return Poll::Ready(Err(e));
        }
        if self.failed {
            read.close(ReadState::Failed);
            return Poll::Ready(Err(contract()));
        }
        if let ReadState::Parked { offset, requested_len } = read.state
            && (offset != read.cursor.offset() || requested_len != buf.len())
        {
            return Poll::Ready(Err(invalid_capability()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(SourceStep::Filled { offset: read.cursor.offset(), count: 0 }));
        }
        let result = self.poll_original_inner(read, cx, buf);
        match result {
            Ok(Poll::Pending) => {
                read.state = ReadState::Parked { offset: read.cursor.offset(), requested_len: buf.len() };
                Poll::Pending
            }
            Ok(Poll::Ready(step)) => {
                read.state = ReadState::Active;
                read.registration = None;
                read.gate.disarm();
                read.fresh = true;
                Poll::Ready(Ok(step))
            }
            Err(e) => {
                self.failed = true;
                self.wake.disarm();
                self.finish_selected_request();
                read.close(if self.control.is_canceled() { ReadState::Canceled } else { ReadState::Failed });
                Poll::Ready(Err(e))
            }
        }
    }
    fn poll_original_inner(
        &mut self,
        read: &mut OriginalRead,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> ProgressiveResult<Poll<SourceStep>> {
        if read.fresh {
            let gate = new_gate(&mut self.usage)?;
            read.gate.disarm();
            read.gate = gate;
            read.fresh = false;
        }
        read.gate.register(cx.waker());
        if self.control.is_canceled() {
            read.gate.notify_canceled();
            return Err(canceled());
        }
        if read.registration.is_none() {
            read.registration = Some(self.control.register_retained_cancel(
                &self.retained.as_ref().unwrap().owner,
                &read.gate,
                &mut self.usage,
            )?);
        }
        if self.control.is_canceled() {
            return Err(canceled());
        }
        let ready = read.gate.consume_ready(|wakes| self.usage.charge(Resource::ProviderWakes, wakes))?;
        if matches!(read.state, ReadState::Parked { .. }) && !ready {
            return Ok(Poll::Pending);
        }
        let external = self.other_lane_handles()? + self.backing_count();
        self.native.refresh_step(&self.protection, &mut self.usage, external)?;
        if self.control.is_canceled() {
            return Err(canceled());
        }
        let mut usage = self.usage.clone();
        let control = self.control.clone();
        #[cfg(feature = "persistent-partials")]
        let exclusions = self.partial_exclusions.clone();
        let source = original_parts(&mut self.original, &mut self.retained, &mut self.usage, read.volume)?;
        let mut parked = false;
        let mut retry_admitted = false;
        poll_available(
            source,
            RangeOperation {
                cursor: &mut read.cursor,
                gate: &read.gate,
                parked: &mut parked,
                retry_admitted: &mut retry_admitted,
                control: &control,
                usage: &mut usage,
                verify: matches!(read.purpose, OriginalReadPurpose::Refill),
                hole_max: 0,
                #[cfg(feature = "persistent-partials")]
                exclusions: exclusions.as_deref(),
                #[cfg(feature = "persistent-partials")]
                pending: &mut read.pending_partial_read,
                #[cfg(feature = "persistent-partials")]
                native: exclusions.as_ref().map(|_| (&mut self.native, &self.protection, external)),
            },
            buf,
        )
    }
}

fn original_parts<'a>(
    original: &'a mut Option<OriginalSource>,
    retained: &'a mut Option<RetainedOriginals>,
    usage: &mut Usage,
    volume: u32,
) -> ProgressiveResult<&'a mut OriginalSource> {
    if original.as_ref().is_some_and(|s| s.index == volume) {
        return Ok(original.as_mut().unwrap());
    }
    let retained = retained.as_mut().ok_or_else(invalid_capability)?;
    usage.charge(Resource::SourceBookkeeping, retained.slots.len() as u64)?;
    retained.slots.iter_mut().find(|s| s.index == volume).ok_or_else(invalid_capability)
}
