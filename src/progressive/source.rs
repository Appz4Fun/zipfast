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

//! Serialized, owned providers. Committed bytes and holes must remain immutable
//! within a generation. Arbitrary providers are a cooperative trust boundary.
use super::limits::Usage;
use super::{FailureKind, ProgressiveFailure, ProgressiveLimits, ProgressiveResult, Resource};
use crate::extract::Cancellation;
use std::{
    ffi::OsString,
    fs::File,
    path::PathBuf,
    sync::{Arc, Mutex},
    task::{Context, Poll, Wake, Waker},
};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SourceId(pub u128);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Both variants promise the same exact logical EOF; neither implies contiguous availability.
pub enum SourceLength {
    Advertised(u64),
    Final(u64),
}
impl SourceLength {
    pub fn value(self) -> u64 {
        match self {
            Self::Advertised(n) | Self::Final(n) => n,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// `extent` is an observed addressable span, never a contiguous downloaded prefix.
pub struct SourceInfo {
    pub id: SourceId,
    pub generation: u64,
    pub extent: u64,
    pub length: SourceLength,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VolumeRequest {
    pub index: u32,
    pub expected: OsString,
}
pub enum VolumeAnswer {
    Ready(Box<dyn RangeSource>),
    Wait,
    Missing,
    Abort,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Filled commits only the reported nonempty prefix; Hole is permanent within
/// this generation. Mixed statuses must be split across separate calls.
pub enum RangeRead {
    Filled { count: usize },
    NotYet,
    Hole { len: u64 },
}
/// Called for every volume, including index zero. Wait parks until the supplied
/// waker fires; waking before returning Wait is supported. Calls are serialized.
pub trait VolumeSource: Send + 'static {
    fn volume(&mut self, request: &VolumeRequest, cx: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer>;
    /// A declaration of structure only; this does not grant publication authority.
    fn protection(&mut self) -> ProgressiveResult<ProtectionDeclaration> {
        Ok(ProtectionDeclaration::Opaque)
    }
}
/// The caller owns availability and immutability leases. After NotYet, wake the
/// supplied waker when another read attempt is warranted; extra task polls do
/// not retry a parked provider. Empty reads are resolved without a callback.
pub trait RangeSource: Send + std::any::Any + 'static {
    fn info(&self) -> SourceInfo;
    fn read_at(&mut self, offset: u64, buf: &mut [u8], cx: &mut Context<'_>) -> ProgressiveResult<RangeRead>;
    fn backing_files(&self) -> &[File];
}
/// Existing handles are shared without duplicating descriptors. Native identity
/// and alias checks are deliberately the responsibility of publication guards.
#[derive(Clone, Debug)]
pub struct ProtectedPath {
    pub path: PathBuf,
    pub file: Option<Arc<File>>,
}
#[derive(Clone, Debug)]
pub enum VolumeBacking {
    Native(Vec<ProtectedPath>),
    NonFile,
}
#[derive(Clone, Debug)]
pub struct ProtectedVolume {
    pub index: u32,
    pub name: OsString,
    pub backing: VolumeBacking,
}
#[derive(Clone, Debug, Default)]
pub struct ProtectionInventory {
    pub volumes: Vec<ProtectedVolume>,
    pub auxiliary_paths: Vec<ProtectedPath>,
}
#[derive(Clone, Debug)]
pub enum ProtectionDeclaration {
    Opaque,
    Complete { epoch: u64, inventory: ProtectionInventory },
}

/// Cloneable cancellation handle; no runtime, worker thread or blocking wait.
#[derive(Clone, Default)]
pub struct SessionControl {
    token: Cancellation,
    wake: Arc<WakeGate>,
}
impl SessionControl {
    pub fn cancel(&self) {
        self.token.cancel();
        self.wake.notify(false);
    }
    pub(crate) fn register(&self, waker: &Waker) {
        self.wake.register(waker);
    }
    pub fn is_canceled(&self) -> bool {
        self.token.is_canceled()
    }
}
#[derive(Default)]
struct WakeState {
    task: Option<Waker>,
    armed: bool,
    ready: bool,
    wakes: u64,
}
#[derive(Default)]
pub(crate) struct WakeGate(Mutex<WakeState>);
impl WakeGate {
    fn register(&self, waker: &Waker) {
        // RawWaker clone/drop hooks may call back into cancellation. Only
        // ownership transfer belongs under the mutex, never caller code.
        let incoming = waker.clone();
        let previous = {
            let mut state = self.0.lock().unwrap();
            state.task.replace(incoming)
        };
        drop(previous);
    }
    fn arm(&self) {
        let mut s = self.0.lock().unwrap();
        s.armed = true;
        s.ready = false;
    }
    fn disarm(&self) {
        let mut s = self.0.lock().unwrap();
        s.armed = false;
        s.ready = false;
    }
    /// Snapshot retry authority and its exact wake count in one transition.
    /// Admission runs outside the lock, before the caller may use readiness.
    /// Later wakes stay latched/countable for the next consumption.
    fn consume_ready(&self, admit: impl FnOnce(u64) -> ProgressiveResult<()>) -> ProgressiveResult<bool> {
        let (ready, wakes) = {
            let mut state = self.0.lock().unwrap();
            (std::mem::take(&mut state.ready), std::mem::take(&mut state.wakes))
        };
        admit(wakes)?;
        Ok(ready)
    }
    fn notify(&self, provider: bool) {
        let task = {
            let mut s = self.0.lock().unwrap();
            if provider {
                s.wakes = s.wakes.saturating_add(1);
            }
            if s.armed {
                s.ready = true;
            }
            s.task.take()
        };
        if let Some(task) = task {
            task.wake();
        }
    }
}
impl Wake for WakeGate {
    fn wake(self: Arc<Self>) {
        self.notify(true);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.notify(true);
    }
}
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum SourceStep {
    VolumeOpened { index: u32, id: SourceId },
    Filled { offset: u64, count: usize },
    Hole { offset: u64, len: u64 },
    EndOfVolume,
}
#[derive(Default)]
pub(crate) struct CheckedCursor(u64);
impl CheckedCursor {
    fn new(offset: u64) -> Self {
        Self(offset)
    }
    fn offset(&self) -> u64 {
        self.0
    }
    fn advance(&mut self, count: u64) -> ProgressiveResult<()> {
        self.0 = self.0.checked_add(count).ok_or_else(contract)?;
        Ok(())
    }
}
fn contract() -> ProgressiveFailure {
    ProgressiveFailure::new(FailureKind::SourceContract)
}
fn changed() -> ProgressiveFailure {
    ProgressiveFailure::new(FailureKind::SourceChanged)
}

pub(crate) struct SourceDriver {
    provider: Box<dyn VolumeSource>,
    request: VolumeRequest,
    source: Option<Box<dyn RangeSource>>,
    info: Option<SourceInfo>,
    cursor: CheckedCursor,
    control: SessionControl,
    usage: Usage,
    parked: bool,
    failed: bool,
    admitted: Vec<(u32, SourceId, OsString, SourceInfo)>,
    protection: ProtectionDeclaration,
    native: super::output::native::NativeProtection,
    holes: Vec<(u64, u64)>,
    sealed_memory: bool,
    wake: Arc<WakeGate>,
    replacements: Vec<(u32, SourceDriver)>,
    replacement_native: bool,
    backing_count: usize,
    external_handles: usize,
}
impl SourceDriver {
    pub(crate) fn new(
        provider: Box<dyn VolumeSource>,
        first: OsString,
        limits: ProgressiveLimits,
        control: SessionControl,
    ) -> ProgressiveResult<Self> {
        Self::with_usage(provider, first, Usage::new(limits), control)
    }
    fn with_usage(
        provider: Box<dyn VolumeSource>,
        first: OsString,
        usage: Usage,
        control: SessionControl,
    ) -> ProgressiveResult<Self> {
        usage.charge(Resource::NameBytes, first.capacity() as u64)?;
        usage.charge(Resource::MetadataBytes, first.capacity() as u64)?;
        let native = super::output::native::NativeProtection::new(&usage)?;
        Ok(Self {
            provider,
            request: VolumeRequest { index: 0, expected: first },
            source: None,
            info: None,
            cursor: CheckedCursor::new(0),
            control,
            usage,
            parked: false,
            failed: false,
            admitted: Vec::new(),
            protection: ProtectionDeclaration::Opaque,
            native,
            holes: Vec::new(),
            sealed_memory: false,
            wake: Arc::new(WakeGate::default()),
            replacements: Vec::new(),
            replacement_native: false,
            backing_count: 0,
            external_handles: 0,
        })
    }
    // This constructor consumes the private owning backend; no caller-supplied
    // trait object or completeness declaration can mint memory authority.
    pub(crate) fn sealed_memory(
        provider: super::session::memory::SealedMemory,
        first: OsString,
        limits: ProgressiveLimits,
        control: SessionControl,
    ) -> ProgressiveResult<Self> {
        let metadata = provider.metadata_bytes;
        let names = provider.name_bytes;
        let input = provider.source_bytes;
        let mut driver = Self::new(Box::new(provider), first, limits, control)?;
        driver.usage.charge(Resource::MetadataBytes, metadata)?;
        driver.usage.charge(Resource::NameBytes, names)?;
        driver.usage.check(Resource::SourceBytes, input)?;
        driver.sealed_memory = true;
        Ok(driver)
    }
    pub(crate) fn validate_current(&mut self) -> ProgressiveResult<()> {
        if self.control.is_canceled() {
            return Err(ProgressiveFailure::new(FailureKind::Canceled));
        }
        if self.failed {
            return Err(contract());
        }
        if self.info.is_some() {
            self.check_info()?;
        }
        let external = self.other_lane_handles()? + self.backing_count;
        self.native.refresh(&self.protection, &mut self.usage, external)?;
        if self.control.is_canceled() {
            return Err(ProgressiveFailure::new(FailureKind::Canceled));
        }
        Ok(())
    }
    pub(crate) fn shared_usage(&self) -> Usage {
        self.usage.clone()
    }
    pub(crate) fn publication_check(
        &mut self,
        target: &std::path::Path,
        identity: Option<super::output::native::Identity>,
    ) -> ProgressiveResult<bool> {
        if self.failed {
            return Err(contract());
        }
        if self.control.is_canceled() {
            return Err(ProgressiveFailure::new(FailureKind::Canceled));
        }
        let result = (|| {
            self.validate_current()?;
            self.refresh_protection()?;
            self.validate_current()?;
            self.native.check_target(target, identity, &mut self.usage)?;
            let mut replacement_authority = true;
            for (_, lane) in &mut self.replacements {
                lane.validate_current()?;
                lane.native.check_target(target, identity, &mut self.usage)?;
                replacement_authority &= lane.replacement_native;
            }
            Ok(replacement_authority
                && (self.sealed_memory
                    || (matches!(self.protection, ProtectionDeclaration::Complete { .. })
                        && self.native.resolved_for_publication(&self.usage)?)))
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    pub(crate) fn cancel(&self) {
        self.control.cancel();
    }
    pub(crate) fn seek(&mut self, offset: u64) -> ProgressiveResult<()> {
        if self.parked || self.failed || self.info.is_none() || offset > self.info.unwrap().length.value() {
            return Err(contract());
        }
        self.cursor = CheckedCursor::new(offset);
        Ok(())
    }
    pub(crate) fn select_volume(&mut self, request: VolumeRequest) -> ProgressiveResult<()> {
        if self.parked
            || self.failed
            || self.source.is_none()
            || self.request.index.checked_add(1) != Some(request.index)
        {
            return Err(contract());
        }
        self.usage.charge(Resource::NameBytes, request.expected.as_encoded_bytes().len() as u64)?;
        self.usage.charge(Resource::MetadataBytes, request.expected.capacity() as u64)?;
        self.request = request;
        self.source = None;
        self.backing_count = 0;
        self.info = None;
        self.cursor = CheckedCursor::new(0);
        self.holes.clear();
        Ok(())
    }
    pub(crate) fn poll_step(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<ProgressiveResult<SourceStep>> {
        self.poll_step_counted(cx, buf, false)
    }
    fn poll_step_counted(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
        verify: bool,
    ) -> Poll<ProgressiveResult<SourceStep>> {
        self.control.register(cx.waker());
        self.wake.register(cx.waker());
        let result = self.poll_inner(buf, verify);
        match result {
            Err(mut e) => {
                self.failed = true;
                self.wake.disarm();
                e.context.volume_index = Some(self.request.index);
                if e.context.expected.is_none() {
                    e.context.expected = Some(std::mem::take(&mut self.request.expected));
                }
                if e.context.packed_offset.is_none() {
                    e.context.packed_offset = Some(self.cursor.offset());
                }
                Poll::Ready(Err(e))
            }
            Ok(p) => p,
        }
    }
    fn poll_inner(&mut self, buf: &mut [u8], verify: bool) -> ProgressiveResult<Poll<ProgressiveResult<SourceStep>>> {
        if self.control.is_canceled() {
            return Err(ProgressiveFailure::new(FailureKind::Canceled));
        }
        if self.failed {
            return Err(contract());
        }
        if buf.is_empty() {
            return Ok(Poll::Ready(Ok(SourceStep::Filled { offset: self.cursor.offset(), count: 0 })));
        }
        let ready = self.wake.consume_ready(|wakes| self.usage.charge(Resource::ProviderWakes, wakes))?;
        if self.parked && !ready {
            return Ok(Poll::Pending);
        }
        self.parked = false;
        if self.source.is_none() {
            self.refresh_protection()?;
            self.usage.charge(Resource::SourceRequests, 1)?;
            self.wake.arm();
            let w = Waker::from(self.wake.clone());
            let mut cx = Context::from_waker(&w);
            let answer = self.provider.volume(&self.request, &mut cx)?;
            if self.control.is_canceled() {
                return Err(ProgressiveFailure::new(FailureKind::Canceled));
            }
            match answer {
                VolumeAnswer::Wait => {
                    self.parked = true;
                    return Ok(Poll::Pending);
                }
                VolumeAnswer::Missing => return Err(ProgressiveFailure::new(FailureKind::MissingVolume)),
                VolumeAnswer::Abort => return Err(ProgressiveFailure::new(FailureKind::Canceled)),
                VolumeAnswer::Ready(source) => {
                    self.wake.disarm();
                    let info = self.admit_source(source)?;
                    return Ok(Poll::Ready(Ok(SourceStep::VolumeOpened { index: self.request.index, id: info.id })));
                }
            }
        }
        let offset = self.cursor.offset();
        let length = self.info.unwrap().length.value();
        if offset == length {
            return Ok(Poll::Ready(Ok(SourceStep::EndOfVolume)));
        }
        self.check_info()?;
        let count = (length - offset).min(buf.len() as u64);
        self.usage.check(Resource::ReadChunk, count)?;
        self.usage.charge(Resource::SourceRequests, 1)?;
        self.wake.arm();
        let w = Waker::from(self.wake.clone());
        let mut cx = Context::from_waker(&w);
        if verify {
            self.usage.charge(Resource::VerifyBytes, count)?;
        }
        let answer = self.source.as_mut().unwrap().read_at(offset, &mut buf[..count as usize], &mut cx)?;
        self.check_info()?;
        if self.control.is_canceled() {
            return Err(ProgressiveFailure::new(FailureKind::Canceled));
        }
        let step = match answer {
            RangeRead::NotYet => {
                self.parked = true;
                return Ok(Poll::Pending);
            }
            RangeRead::Filled { count: n } => {
                if n == 0 || n as u64 > count {
                    return Err(contract());
                }
                let end = offset.checked_add(n as u64).ok_or_else(contract)?;
                if end > self.info.unwrap().extent {
                    return Err(contract());
                }
                let next = self.hole_bound(offset, false)?;
                if let Some(&(start, _)) = self.holes.get(next) {
                    self.usage.charge(Resource::SourceBookkeeping, 1)?;
                    if start < end {
                        return Err(changed());
                    }
                }
                self.usage.charge(Resource::SourceBytes, n as u64)?;
                self.cursor.advance(n as u64)?;
                SourceStep::Filled { offset, count: n }
            }
            RangeRead::Hole { len } => {
                if len == 0 || len > count {
                    return Err(contract());
                }
                let end = offset.checked_add(len).ok_or_else(contract)?;
                self.usage.charge(Resource::SourceBytes, len)?;
                self.remember_hole(offset, end)?;
                self.cursor.advance(len)?;
                SourceStep::Hole { offset, len }
            }
        };
        self.wake.disarm();
        Ok(Poll::Ready(Ok(step)))
    }
    fn admit_source(&mut self, source: Box<dyn RangeSource>) -> ProgressiveResult<SourceInfo> {
        self.usage.charge(Resource::SourceRequests, 1)?;
        let info = source.info();
        if info.extent > info.length.value() {
            return Err(contract());
        }
        if let ProtectionDeclaration::Complete { inventory, .. } = &self.protection {
            check_name_coverage(inventory, self.request.index, &self.request.expected, &mut self.usage)?;
        }
        let (position, duplicate) = self.admission_position(info.id)?;
        if duplicate {
            return Err(contract());
        }
        self.usage.charge(Resource::SourceRequests, 1)?;
        let backing = source.backing_files();
        let external = self.other_lane_handles()?;
        self.usage.check(Resource::VolumeHandles, (external + self.native.handle_count() + backing.len()) as u64)?;
        self.native.refresh(&self.protection, &mut self.usage, external + backing.len())?;
        self.native.admit(self.request.index, backing, &self.protection, &mut self.usage, external)?;
        self.backing_count = backing.len();
        // Only the concrete library adapter carries its original immutable stamp.
        // Custom providers retain the cooperative progressive identity contract.
        if let Some(immutable) = (&*source as &dyn std::any::Any).downcast_ref::<ImmutableFileSource>() {
            self.native.remember_immutable(&immutable.file, &immutable.path, immutable.stamp, &self.usage)?;
        }
        self.usage.charge(Resource::MetadataBytes, self.request.expected.capacity() as u64)?;
        self.usage.charge(Resource::NameBytes, self.request.expected.capacity() as u64)?;
        self.usage.charge(Resource::SourceBookkeeping, (self.admitted.len() - position) as u64)?;
        reserve_records(&mut self.admitted, &mut self.usage)?;
        self.admitted.insert(position, (self.request.index, info.id, self.request.expected.clone(), info));
        self.replacement_native = (&*source as &dyn std::any::Any).is::<ImmutableFileSource>();
        self.source = Some(source);
        self.info = Some(info);
        Ok(info)
    }
    fn other_lane_handles(&self) -> ProgressiveResult<usize> {
        self.usage.charge(Resource::SourceBookkeeping, self.replacements.len() as u64)?;
        Ok(self.external_handles
            + self.replacements.iter().map(|(_, lane)| lane.native.handle_count() + lane.backing_count).sum::<usize>())
    }
    pub(crate) fn observed_info(&self, index: u32) -> Option<SourceInfo> {
        self.admitted.iter().find(|(i, _, _, _)| *i == index).map(|(_, _, _, v)| *v)
    }
    pub(crate) fn supply_replacement(&mut self, index: u32, source: Box<dyn RangeSource>) -> ProgressiveResult<()> {
        self.validate_current()?;
        self.usage.charge(Resource::SourceBookkeeping, self.admitted.len() as u64)?;
        self.usage.check(Resource::VolumeHandles, self.replacements.len() as u64 + 2)?;
        let original = self.observed_info(index).ok_or_else(contract)?;
        self.usage.charge(Resource::SourceRequests, 1)?;
        let info = source.info();
        if info.length.value() != original.length.value() {
            return Err(changed());
        }
        self.usage.charge(Resource::SourceBookkeeping, self.replacements.len() as u64 + 1)?;
        if self.replacements.iter().any(|(i, s)| *i != index && s.info.is_some_and(|v| v.id == info.id)) {
            return Err(contract());
        }
        self.usage.charge(Resource::SourceBookkeeping, self.admitted.len() as u64)?;
        let name = self.admitted.iter().find(|(i, _, _, _)| *i == index).map(|(_, _, n, _)| n).ok_or_else(contract)?;
        self.usage.charge(Resource::MetadataBytes, name.capacity() as u64)?;
        let first = name.clone();
        let mut lane = Self::with_usage(Box::new(NoVolumes), first, self.usage.clone(), self.control.clone())?;
        lane.request.index = index;
        self.usage.charge(Resource::SourceBookkeeping, self.replacements.len() as u64 * 2)?;
        let held = self.native.handle_count() + self.backing_count;
        let replacements =
            self.replacements.iter().map(|(_, s)| s.native.handle_count() + s.backing_count).sum::<usize>();
        lane.external_handles = held + replacements;
        let admitted = lane.admit_source(source)?;
        if admitted.id != info.id
            || admitted.generation != info.generation
            || admitted.length.value() != info.length.value()
        {
            return Err(changed());
        }
        lane.validate_current()?;
        if self.control.is_canceled() {
            return Err(ProgressiveFailure::new(FailureKind::Canceled));
        }
        if let Some((_, old)) = self.replacements.iter_mut().find(|(i, _)| *i == index) {
            *old = lane;
        } else {
            reserve_records(&mut self.replacements, &mut self.usage)?;
            self.replacements.push((index, lane));
        }
        Ok(())
    }
    pub(crate) fn has_replacement(&self, index: u32) -> ProgressiveResult<bool> {
        self.usage.charge(Resource::SourceBookkeeping, self.replacements.len() as u64)?;
        Ok(self.replacements.iter().any(|(i, _)| *i == index))
    }
    /// Admit a whole verification retry before any caller callback. Readiness
    /// consumption and wake accounting use the same latch as range reads.
    pub(crate) fn replacement_retry_ready(&mut self, cx: &mut Context<'_>) -> ProgressiveResult<bool> {
        for (_, lane) in &mut self.replacements {
            if lane.parked {
                lane.wake.register(cx.waker());
                if self.control.is_canceled() {
                    return Err(ProgressiveFailure::new(FailureKind::Canceled));
                }
                if !lane.wake.consume_ready(|wakes| self.usage.charge(Resource::ProviderWakes, wakes))? {
                    return Ok(false);
                }
                lane.parked = false;
            }
        }
        Ok(true)
    }
    pub(crate) fn poll_replacement(
        &mut self,
        index: u32,
        offset: u64,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<ProgressiveResult<SourceStep>> {
        if let Err(e) = self.usage.charge(Resource::SourceBookkeeping, self.replacements.len() as u64) {
            return Poll::Ready(Err(e));
        }
        let Some((_, lane)) = self.replacements.iter_mut().find(|(i, _)| *i == index) else {
            return Poll::Ready(Err(contract()));
        };
        if lane.cursor.offset() != offset
            && let Err(e) = lane.seek(offset)
        {
            return Poll::Ready(Err(e));
        }
        // Attempted verification reads include callbacks returning NotYet/errors.
        // Do not debit a parked no-wake poll which makes no source call.
        lane.poll_step_counted(cx, buf, true)
    }
    /// Abandon only an explicit verification request. Keep its source identity,
    /// permanent-hole ledger and native guards; old request wakers cannot authorize
    /// a later job because the new lane owns a fresh latch.
    pub(crate) fn abort_replacement_reads(&mut self) -> ProgressiveResult<()> {
        self.usage.charge(Resource::SourceBookkeeping, self.replacements.len() as u64)?;
        let count = self.replacements.iter().filter(|(_, lane)| lane.parked).count();
        self.usage.charge(
            Resource::MetadataBytes,
            (count * (std::mem::size_of::<WakeGate>() + 2 * std::mem::size_of::<usize>())) as u64,
        )?;
        for (_, lane) in &mut self.replacements {
            if lane.parked {
                lane.parked = false;
                lane.wake = Arc::new(WakeGate::default());
            }
        }
        Ok(())
    }
    pub(crate) fn validate_replacements(&mut self) -> ProgressiveResult<()> {
        for (_, lane) in &mut self.replacements {
            lane.validate_current()?;
        }
        Ok(())
    }
    fn admission_position(&mut self, id: SourceId) -> ProgressiveResult<(usize, bool)> {
        let (mut low, mut high) = (0, self.admitted.len());
        while low < high {
            self.usage.charge(Resource::SourceBookkeeping, 1)?;
            let mid = low + (high - low) / 2;
            match self.admitted[mid].1.0.cmp(&id.0) {
                std::cmp::Ordering::Less => low = mid + 1,
                std::cmp::Ordering::Greater => high = mid,
                std::cmp::Ordering::Equal => return Ok((mid, true)),
            }
        }
        Ok((low, false))
    }
    /// First interval whose end is >= offset (coalescing) or > offset (fill).
    /// Search steps are charged individually before each comparison.
    fn hole_bound(&mut self, offset: u64, touching: bool) -> ProgressiveResult<usize> {
        let (mut low, mut high) = (0, self.holes.len());
        while low < high {
            self.usage.charge(Resource::SourceBookkeeping, 1)?;
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
    fn remember_hole(&mut self, offset: u64, end: u64) -> ProgressiveResult<()> {
        let start = self.hole_bound(offset, true)?;
        let mut after = start;
        let mut range = (offset, end);
        while after < self.holes.len() {
            self.usage.charge(Resource::SourceBookkeeping, 1)?;
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
            self.usage.charge(Resource::SourceBookkeeping, (self.holes.len() - start) as u64)?;
            reserve_records(&mut self.holes, &mut self.usage)?;
            self.holes.insert(start, range);
        } else {
            let removed = after - start;
            // At most one shift of the tail, plus all replaced/removed slots.
            self.usage.charge(Resource::SourceBookkeeping, (removed + self.holes.len() - after) as u64)?;
            self.holes[start] = range;
            self.holes.drain(start + 1..after);
        }
        Ok(())
    }
    fn check_info(&mut self) -> ProgressiveResult<()> {
        self.usage.charge(Resource::SourceRequests, 1)?;
        let new = self.source.as_ref().unwrap().info();
        let old = self.info.unwrap();
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
        self.info = Some(new);
        Ok(())
    }
    fn refresh_protection(&mut self) -> ProgressiveResult<()> {
        self.usage.charge(Resource::SourceRequests, 1)?;
        if self.control.is_canceled() {
            return Err(ProgressiveFailure::new(FailureKind::Canceled));
        }
        let mut next = self.provider.protection()?;
        if self.control.is_canceled() {
            return Err(ProgressiveFailure::new(FailureKind::Canceled));
        }
        if let ProtectionDeclaration::Complete { inventory, .. } = &mut next {
            validate_inventory(inventory, &mut self.usage)?;
            canonicalize_inventory(inventory, &mut self.usage)?;
        }
        match (&self.protection, &next) {
            (
                ProtectionDeclaration::Complete { epoch: a, inventory: x },
                ProtectionDeclaration::Complete { epoch: b, inventory: y },
            ) if a == b && same_inventory(x, y, &mut self.usage)? => {}
            (ProtectionDeclaration::Complete { .. }, _) => return Err(changed()),
            _ => {}
        }
        self.check_inventory_admitted(&next)?;
        let external = self.other_lane_handles()? + self.backing_count;
        self.native.refresh(&next, &mut self.usage, external)?;
        self.protection = next;
        Ok(())
    }
    fn check_inventory_admitted(&mut self, candidate: &ProtectionDeclaration) -> ProgressiveResult<()> {
        if let ProtectionDeclaration::Complete { inventory, .. } = candidate {
            for (index, _, name, _) in &self.admitted {
                check_name_coverage(inventory, *index, name, &mut self.usage)?;
            }
        }
        Ok(())
    }
}
struct NoVolumes;
impl VolumeSource for NoVolumes {
    fn volume(&mut self, _: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
        Err(contract())
    }
}
fn check_name_coverage(
    inventory: &ProtectionInventory,
    index: u32,
    name: &std::ffi::OsStr,
    usage: &mut Usage,
) -> ProgressiveResult<()> {
    let (mut low, mut high) = (0, inventory.volumes.len());
    while low < high {
        usage.charge(Resource::SourceBookkeeping, 1)?;
        let mid = low + (high - low) / 2;
        if inventory.volumes[mid].index < index {
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    usage.charge(Resource::SourceBookkeeping, 1)?;
    let Some(volume) = inventory.volumes.get(low) else {
        return Err(contract());
    };
    usage.charge(
        Resource::SourceBookkeeping,
        1 + name.as_encoded_bytes().len() as u64 + volume.name.as_encoded_bytes().len() as u64,
    )?;
    if volume.index != index || volume.name != name {
        return Err(contract());
    }
    Ok(())
}
/// Precharge possible allocation copying and exact requested capacity growth.
/// Any allocator-provided extra capacity is also charged before retention.
fn reserve_records<T>(records: &mut Vec<T>, usage: &mut Usage) -> ProgressiveResult<()> {
    if records.len() < records.capacity() {
        return Ok(());
    }
    let old = records.capacity();
    let target = old.saturating_mul(2).max(1);
    let bytes = (target - old).checked_mul(std::mem::size_of::<T>()).ok_or_else(contract)?;
    usage.charge(Resource::SourceBookkeeping, records.len() as u64)?;
    usage.charge(Resource::MetadataBytes, bytes as u64)?;
    records.try_reserve_exact(target - records.len()).map_err(|_| contract())?;
    if records.capacity() > target {
        let extra = (records.capacity() - target).checked_mul(std::mem::size_of::<T>()).ok_or_else(contract)?;
        usage.charge(Resource::MetadataBytes, extra as u64)?;
    }
    Ok(())
}
/// In-place heapsort permits fallible per-comparison accounting. It never
/// allocates and performs O(n log n) comparisons/moves, even on hostile keys.
fn budget_sort<T, F>(items: &mut [T], usage: &mut Usage, compare: F) -> ProgressiveResult<()>
where
    F: Fn(&T, &T, &mut Usage) -> ProgressiveResult<std::cmp::Ordering>,
{
    fn sift<T, F>(items: &mut [T], usage: &mut Usage, root: usize, end: usize, compare: &F) -> ProgressiveResult<()>
    where
        F: Fn(&T, &T, &mut Usage) -> ProgressiveResult<std::cmp::Ordering>,
    {
        let mut root = root;
        while let Some(left) = root.checked_mul(2).and_then(|n| n.checked_add(1)).filter(|&n| n < end) {
            let mut child = left;
            if left + 1 < end && compare(&items[left], &items[left + 1], usage)?.is_lt() {
                child = left + 1;
            }
            if !compare(&items[root], &items[child], usage)?.is_lt() {
                break;
            }
            usage.charge(Resource::SourceBookkeeping, 2)?;
            items.swap(root, child);
            root = child;
        }
        Ok(())
    }
    for root in (0..items.len() / 2).rev() {
        sift(items, usage, root, items.len(), &compare)?;
    }
    for end in (1..items.len()).rev() {
        usage.charge(Resource::SourceBookkeeping, 2)?;
        items.swap(0, end);
        sift(items, usage, 0, end, &compare)?;
    }
    Ok(())
}
fn path_compare(a: &std::path::Path, b: &std::path::Path, usage: &mut Usage) -> ProgressiveResult<std::cmp::Ordering> {
    usage.charge(
        Resource::SourceBookkeeping,
        1 + a.as_os_str().as_encoded_bytes().len() as u64 + b.as_os_str().as_encoded_bytes().len() as u64,
    )?;
    Ok(a.cmp(b))
}
fn canonicalize_inventory(i: &mut ProtectionInventory, usage: &mut Usage) -> ProgressiveResult<()> {
    budget_sort(&mut i.volumes, usage, |a, b, u| {
        u.charge(Resource::SourceBookkeeping, 1)?;
        Ok(a.index.cmp(&b.index))
    })?;
    budget_sort(&mut i.auxiliary_paths, usage, |a, b, u| path_compare(&a.path, &b.path, u))?;
    for v in &mut i.volumes {
        usage.charge(Resource::SourceBookkeeping, 1)?;
        if let VolumeBacking::Native(paths) = &mut v.backing {
            budget_sort(paths, usage, |a, b, u| path_compare(&a.path, &b.path, u))?;
        }
    }
    Ok(())
}
fn same_path(a: &ProtectedPath, b: &ProtectedPath, usage: &mut Usage) -> ProgressiveResult<bool> {
    if !path_compare(&a.path, &b.path, usage)?.is_eq() {
        return Ok(false);
    }
    usage.charge(Resource::SourceBookkeeping, 1)?;
    Ok(match (&a.file, &b.file) {
        (None, _) => true,
        (Some(x), Some(y)) => Arc::ptr_eq(x, y),
        _ => false,
    })
}
fn same_inventory(a: &ProtectionInventory, b: &ProtectionInventory, usage: &mut Usage) -> ProgressiveResult<bool> {
    usage.charge(Resource::SourceBookkeeping, 2)?;
    if a.volumes.len() != b.volumes.len() || a.auxiliary_paths.len() != b.auxiliary_paths.len() {
        return Ok(false);
    }
    for (x, y) in a.auxiliary_paths.iter().zip(&b.auxiliary_paths) {
        if !same_path(x, y, usage)? {
            return Ok(false);
        }
    }
    for (x, y) in a.volumes.iter().zip(&b.volumes) {
        usage.charge(
            Resource::SourceBookkeeping,
            3 + x.name.as_encoded_bytes().len() as u64 + y.name.as_encoded_bytes().len() as u64,
        )?;
        if x.index != y.index || x.name != y.name {
            return Ok(false);
        }
        match (&x.backing, &y.backing) {
            (VolumeBacking::NonFile, VolumeBacking::NonFile) => {}
            (VolumeBacking::Native(x), VolumeBacking::Native(y)) => {
                usage.charge(Resource::SourceBookkeeping, 1)?;
                if x.len() != y.len() {
                    return Ok(false);
                }
                for (a, b) in x.iter().zip(y) {
                    if !same_path(a, b, usage)? {
                        return Ok(false);
                    }
                }
            }
            _ => return Ok(false),
        }
    }
    Ok(true)
}
fn validate_inventory(i: &ProtectionInventory, usage: &mut Usage) -> ProgressiveResult<()> {
    if i.volumes.is_empty() {
        return Err(contract());
    }
    usage.check(Resource::Entries, i.volumes.len() as u64)?;
    let mut paths = 0u64;
    let mut bytes = 0u64;
    let mut handles = 0u64;
    let mut names = 0u64;
    let size = |count: usize, unit: usize| -> ProgressiveResult<u64> {
        (count as u64).checked_mul(unit as u64).ok_or_else(contract)
    };
    let mut metadata = size(i.volumes.capacity(), std::mem::size_of::<ProtectedVolume>())?
        .checked_add(size(i.auxiliary_paths.capacity(), std::mem::size_of::<ProtectedPath>())?)
        .ok_or_else(contract)?;
    usage.check(Resource::MetadataBytes, metadata)?;
    for v in &i.volumes {
        usage.charge(Resource::SourceBookkeeping, 3)?;
        if v.name.is_empty() {
            return Err(contract());
        }
        names = names.checked_add(v.name.capacity() as u64).ok_or_else(contract)?;
        usage.check(Resource::NameBytes, names)?;
        if let VolumeBacking::Native(p) = &v.backing {
            if p.is_empty() {
                return Err(contract());
            }
            metadata =
                metadata.checked_add(size(p.capacity(), std::mem::size_of::<ProtectedPath>())?).ok_or_else(contract)?;
        }
        usage.check(Resource::MetadataBytes, metadata.checked_add(names).ok_or_else(contract)?)?;
    }
    let all = || {
        i.auxiliary_paths.iter().chain(i.volumes.iter().flat_map(|v| match &v.backing {
            VolumeBacking::Native(p) => p.as_slice(),
            VolumeBacking::NonFile => &[],
        }))
    };
    for p in all() {
        usage.charge(Resource::SourceBookkeeping, 3)?;
        if p.path.as_os_str().is_empty() {
            return Err(contract());
        }
        paths = paths.checked_add(1).ok_or_else(contract)?;
        bytes = bytes.checked_add(p.path.capacity() as u64).ok_or_else(contract)?;
        handles += u64::from(p.file.is_some());
        usage.check(Resource::ProtectionPaths, paths)?;
        usage.check(Resource::ProtectionPathBytes, bytes)?;
        usage.check(Resource::VolumeHandles, handles)?;
    }
    usage.check(Resource::ProtectionPaths, paths)?;
    usage.check(Resource::ProtectionPathBytes, bytes)?;
    usage.check(Resource::VolumeHandles, handles)?;
    usage.charge(Resource::NameBytes, names)?;
    metadata = metadata.checked_add(bytes).and_then(|n| n.checked_add(names)).ok_or_else(contract)?;
    // Temporary borrowed-key indexes below also need reservation before allocation.
    let scratch = size(i.volumes.len(), std::mem::size_of::<u32>())?
        .checked_add(size(paths as usize, std::mem::size_of::<&std::path::Path>())?)
        .ok_or_else(contract)?;
    usage.charge(Resource::MetadataBytes, metadata.checked_add(scratch).ok_or_else(contract)?)?;
    let mut indices = Vec::new();
    indices.try_reserve_exact(i.volumes.len()).map_err(|_| contract())?;
    usage.charge(Resource::SourceBookkeeping, i.volumes.len() as u64)?;
    indices.extend(i.volumes.iter().map(|v| v.index));
    budget_sort(&mut indices, usage, |a, b, u| {
        u.charge(Resource::SourceBookkeeping, 1)?;
        Ok(a.cmp(b))
    })?;
    for pair in indices.windows(2) {
        usage.charge(Resource::SourceBookkeeping, 1)?;
        if pair[0] == pair[1] {
            return Err(contract());
        }
    }
    let mut native = Vec::new();
    native.try_reserve_exact(paths as usize).map_err(|_| contract())?;
    usage.charge(Resource::SourceBookkeeping, paths)?;
    native.extend(all().map(|p| p.path.as_path()));
    budget_sort(&mut native, usage, |a, b, u| path_compare(a, b, u))?;
    for pair in native.windows(2) {
        if path_compare(pair[0], pair[1], usage)?.is_eq() {
            return Err(contract());
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests;

/// A complete, immutable native file. Growth and metadata/content replacement are changes.
pub struct ImmutableFileSource {
    file: File,
    path: PathBuf,
    stamp: crate::rar5::source::SourceStamp,
    info: SourceInfo,
}
impl ImmutableFileSource {
    pub fn open(path: &std::path::Path) -> ProgressiveResult<Self> {
        use super::InputOperation;
        let path = std::path::absolute(path)
            .map_err(|cause| ProgressiveFailure::new(FailureKind::Input { operation: InputOperation::Open, cause }))?;
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
        }
        let file = options
            .open(&path)
            .map_err(|cause| ProgressiveFailure::new(FailureKind::Input { operation: InputOperation::Open, cause }))?;
        let stamp = crate::rar5::source::SourceStamp::capture(&file, &path).map_err(immutable_error)?;
        let info = SourceInfo {
            id: SourceId(((stamp.device as u128) << 64) | stamp.inode as u128),
            generation: 0,
            extent: stamp.len,
            length: SourceLength::Final(stamp.len),
        };
        Ok(Self { file, path, stamp, info })
    }
}
impl RangeSource for ImmutableFileSource {
    fn info(&self) -> SourceInfo {
        self.info
    }
    fn backing_files(&self) -> &[File] {
        std::slice::from_ref(&self.file)
    }
    fn read_at(&mut self, offset: u64, buf: &mut [u8], _cx: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
        self.stamp.check(&self.file, &self.path).map_err(immutable_error)?;
        if offset > self.stamp.len {
            return Err(contract());
        }
        let n = (self.stamp.len - offset).min(buf.len() as u64) as usize;
        #[cfg(unix)]
        let result = {
            use std::os::unix::fs::FileExt;
            self.file.read_at(&mut buf[..n], offset)
        };
        #[cfg(not(unix))]
        let result: std::io::Result<usize> = Err(std::io::ErrorKind::Unsupported.into());
        let count = result.map_err(|cause| {
            let mut e = ProgressiveFailure::new(FailureKind::Input { operation: super::InputOperation::Read, cause });
            e.context.packed_offset = Some(offset);
            e
        })?;
        self.stamp.check(&self.file, &self.path).map_err(immutable_error)?;
        if count == 0 && n != 0 {
            return Err(ProgressiveFailure::new(FailureKind::Truncated));
        }
        Ok(RangeRead::Filled { count })
    }
}
pub(super) fn immutable_error(fault: crate::error::RarFault) -> ProgressiveFailure {
    match *fault.failure {
        crate::error::RarFailure::Input { source, .. } => {
            ProgressiveFailure::new(FailureKind::Input { operation: super::InputOperation::Metadata, cause: source })
        }
        _ => changed(),
    }
}
