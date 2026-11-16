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
    sync::{
        Arc, Mutex, OnceLock, Weak,
        atomic::{AtomicBool, Ordering},
    },
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
    ///
    /// Once Complete, a declaration is frozen: the same epoch and inventory for the session's life, unless
    /// `extends_protection` opts in to growth.
    fn protection(&mut self) -> ProgressiveResult<ProtectionDeclaration> {
        Ok(ProtectionDeclaration::Opaque)
    }
    /// Opts in to a growing Complete declaration; read once, when a persistent session starts. Ordinary sessions
    /// ignore it.
    ///
    /// When true, a persistent session (`ProgressiveSession::new_partial`, feature `persistent-partials`) also
    /// accepts a Complete declaration with a higher epoch that only appends volumes and auxiliary paths, every
    /// earlier entry (index, name and backing) unchanged. When it requests an index the current declaration does
    /// not name, answer Wait and wake the request's waker once a larger declaration names it. A Ready answer for
    /// an undeclared index is held unread until a later declaration names it; wake that request's waker then too.
    /// A provider that opts in and never declares the index leaves the session waiting.
    fn extends_protection(&self) -> bool {
        false
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
    wake: Arc<ControlWake>,
}
impl SessionControl {
    pub(crate) fn cancellation_token(&self) -> Cancellation {
        self.token.clone()
    }
    pub fn cancel(&self) {
        self.token.cancel();
        if let Some(hub) = self.wake.retained.get() {
            hub.cancel();
        }
        self.wake.legacy.notify(false);
    }
    pub(crate) fn register(&self, waker: &Waker) {
        self.wake.legacy.register(waker);
    }
    pub fn is_canceled(&self) -> bool {
        self.token.is_canceled()
    }
}
#[derive(Default)]
struct ControlWake {
    legacy: WakeGate,
    retained: OnceLock<Arc<CancelFanout>>,
}
struct CancelFanout {
    canceled: AtomicBool,
    slots: Mutex<Vec<Weak<CancelSlot>>>,
}
struct CancelOwner {
    identity: Arc<()>,
    max_operations: u64,
}
struct CancelSlot {
    owner: Arc<()>,
    gate: Weak<WakeGate>,
    retired: AtomicBool,
}
struct CancelRegistration(Arc<CancelSlot>);
impl CancelRegistration {
    fn retire(&mut self) {
        self.0.retired.store(true, Ordering::Release);
    }
}
impl Drop for CancelRegistration {
    fn drop(&mut self) {
        self.retire();
    }
}
impl CancelFanout {
    fn cancel(&self) {
        let slots = {
            let mut slots = self.slots.lock().unwrap();
            if self.canceled.swap(true, Ordering::AcqRel) {
                return;
            }
            std::mem::take(&mut *slots)
        };
        // The detached precharged list is bounded. No callback runs under its mutex.
        for slot in slots {
            if let Some(slot) = slot.upgrade()
                && !slot.retired.load(Ordering::Acquire)
                && let Some(gate) = slot.gate.upgrade()
            {
                gate.notify_canceled();
            }
        }
    }
}
impl SessionControl {
    fn enable_retained_cancel(&self, usage: &mut Usage) -> ProgressiveResult<()> {
        if self.wake.retained.get().is_none() {
            usage.charge(
                Resource::MetadataBytes,
                (std::mem::size_of::<CancelFanout>() + 2 * std::mem::size_of::<usize>()) as u64,
            )?;
            let _ = self.wake.retained.set(Arc::new(CancelFanout {
                canceled: AtomicBool::new(self.is_canceled()),
                slots: Mutex::new(Vec::new()),
            }));
        }
        // Covers installation racing cancellation before OnceLock became visible.
        if self.is_canceled() {
            self.wake.retained.get().unwrap().cancel();
        }
        Ok(())
    }
    fn register_retained_cancel(
        &self,
        owner: &CancelOwner,
        gate: &Arc<WakeGate>,
        usage: &mut Usage,
    ) -> ProgressiveResult<CancelRegistration> {
        let hub = self.wake.retained.get().ok_or_else(invalid_capability)?;
        let mut slots = hub.slots.lock().unwrap();
        if self.is_canceled() || hub.canceled.load(Ordering::Acquire) {
            drop(slots);
            gate.notify_canceled();
            return Err(canceled());
        }
        // One bounded scan, compaction movement and one future cancellation visit.
        usage.charge(Resource::SourceBookkeeping, (slots.len() * 3 + 1) as u64)?;
        slots.retain(|row| row.upgrade().is_some_and(|slot| !slot.retired.load(Ordering::Acquire)));
        let own = slots
            .iter()
            .filter(|row| row.upgrade().is_some_and(|slot| Arc::ptr_eq(&slot.owner, &owner.identity)))
            .count() as u64;
        let (limit, attempted) =
            if own >= owner.max_operations { (owner.max_operations, own + 1) } else { (4096, slots.len() as u64 + 1) };
        if attempted > limit {
            return Err(ProgressiveFailure::new(FailureKind::Limit {
                resource: Resource::VolumeHandles,
                limit,
                attempted,
            }));
        }
        usage.charge(
            Resource::MetadataBytes,
            (std::mem::size_of::<CancelSlot>() + 2 * std::mem::size_of::<usize>()) as u64,
        )?;
        reserve_records(&mut slots, usage)?;
        let slot = Arc::new(CancelSlot {
            owner: owner.identity.clone(),
            gate: Arc::downgrade(gate),
            retired: AtomicBool::new(false),
        });
        slots.push(Arc::downgrade(&slot));
        drop(slots);
        // Cancellation may have drained and notified before registration returned.
        if self.is_canceled() {
            gate.notify_canceled();
            return Err(canceled());
        }
        Ok(CancelRegistration(slot))
    }
}
fn canceled() -> ProgressiveFailure {
    ProgressiveFailure::new(FailureKind::Canceled)
}
fn invalid_capability() -> ProgressiveFailure {
    ProgressiveFailure::new(FailureKind::InvalidCapability)
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
    fn notify_canceled(&self) {
        let task = self.0.lock().unwrap().task.take();
        if let Some(task) = task {
            task.wake();
        }
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

mod retained;
#[allow(unused_imports, reason = "H3/H4 consume retained discovery and refill entrypoints")]
pub(crate) use retained::{OriginalRead, OriginalReadPurpose};
use retained::{OriginalSource, RetainedOriginals};

struct RangeOperation<'a> {
    cursor: &'a mut CheckedCursor,
    gate: &'a Arc<WakeGate>,
    parked: &'a mut bool,
    retry_admitted: &'a mut bool,
    control: &'a SessionControl,
    usage: &'a mut Usage,
    verify: bool,
    #[cfg(feature = "persistent-partials")]
    exclusions: Option<&'a crate::partial::PartialExclusions>,
    #[cfg(feature = "persistent-partials")]
    pending: &'a mut Option<PendingPartialRead>,
    #[cfg(feature = "persistent-partials")]
    native: Option<(&'a mut super::output::native::NativeProtection, &'a ProtectionDeclaration, usize)>,
}
#[cfg(feature = "persistent-partials")]
enum Overlay {
    Hole(SourceStep),
    Limit(usize),
}
#[cfg(feature = "persistent-partials")]
struct PendingPartialRead {
    offset: u64,
    requested: u64,
    answer: RangeRead,
    bytes: Vec<u8>,
}
#[cfg(feature = "persistent-partials")]
fn partial_read_stable(original: &mut OriginalSource, op: &mut RangeOperation<'_>) -> ProgressiveResult<bool> {
    let Some(exclusions) = op.exclusions else { return Ok(true) };
    for _ in 0..2 {
        op.usage.charge(Resource::SourceRequests, 1)?;
        let files = original.source.backing_files();
        if op.control.is_canceled() {
            return Err(canceled());
        }
        // info is the final source callback. Validate native facts after it,
        // then accept this identity before any answer/cursor/byte mutation.
        op.usage.charge(Resource::SourceRequests, 1)?;
        let info = original.source.info();
        if op.control.is_canceled() {
            return Err(canceled());
        }
        if let Some((native, declaration, external)) = &mut op.native {
            native.refresh_step(declaration, op.usage, *external)?;
        }
        let stable = exclusions.check_input_revision(&[], files)?.is_some();
        original.observe_info(info)?;
        if stable {
            return Ok(true);
        }
    }
    Ok(false)
}
fn poll_available(
    original: &mut OriginalSource,
    op: RangeOperation<'_>,
    buf: &mut [u8],
) -> ProgressiveResult<Poll<SourceStep>> {
    #[cfg(feature = "persistent-partials")]
    let mut op = op;
    let offset = op.cursor.offset();
    #[cfg(feature = "persistent-partials")]
    if let Some(pending) = op.pending.as_ref() {
        if pending.offset != offset || pending.bytes.len() > buf.len() {
            return Err(contract());
        }
        original.check_info(op.usage)?;
        if op.control.is_canceled() {
            return Err(canceled());
        }
        if !partial_read_stable(original, &mut op)? {
            op.gate.notify(false);
            return Ok(Poll::Pending);
        }
        let pending = op.pending.take().unwrap();
        buf[..pending.bytes.len()].copy_from_slice(&pending.bytes);
        return accept_available(original, op, pending.offset, pending.requested, pending.answer);
    }
    let length = original.live.length.value();
    if offset == length {
        return Ok(Poll::Ready(SourceStep::EndOfVolume));
    }
    let checked = original.check_info(op.usage);
    if op.control.is_canceled() {
        return Err(canceled());
    }
    checked?;
    #[cfg(feature = "persistent-partials")]
    if !partial_read_stable(original, &mut op)? {
        op.gate.notify(false);
        return Ok(Poll::Pending);
    }
    let count = (length - offset).min(buf.len() as u64);
    op.usage.check(Resource::ReadChunk, count)?;
    op.usage.charge(Resource::SourceRequests, 1)?;
    op.gate.arm();
    let w = Waker::from(op.gate.clone());
    let mut cx = Context::from_waker(&w);
    if op.verify {
        op.usage.charge(Resource::VerifyBytes, count)?;
    }
    *op.retry_admitted = false;
    let answer = original.source.read_at(offset, &mut buf[..count as usize], &mut cx);
    if op.control.is_canceled() {
        return Err(canceled());
    }
    let answer = answer?;
    let checked = original.check_info(op.usage);
    if op.control.is_canceled() {
        return Err(canceled());
    }
    checked?;
    #[cfg(feature = "persistent-partials")]
    if !matches!(answer, RangeRead::NotYet) && !partial_read_stable(original, &mut op)? {
        let n = match answer {
            RangeRead::Filled { count: n } if n > 0 && n <= count as usize => n,
            RangeRead::Hole { len } if len > 0 && len <= count => 0,
            _ => return Err(contract()),
        };
        op.usage.charge(Resource::MetadataBytes, n as u64)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(n).map_err(|_| contract())?;
        bytes.extend_from_slice(&buf[..n]);
        *op.pending = Some(PendingPartialRead { offset, requested: count, answer, bytes });
        op.gate.notify(false);
        return Ok(Poll::Pending);
    }
    accept_available(original, op, offset, count, answer)
}
fn accept_available(
    original: &mut OriginalSource,
    op: RangeOperation<'_>,
    offset: u64,
    count: u64,
    answer: RangeRead,
) -> ProgressiveResult<Poll<SourceStep>> {
    let step = match answer {
        RangeRead::NotYet => {
            *op.parked = true;
            return Ok(Poll::Pending);
        }
        RangeRead::Filled { count: n } => {
            if n == 0 || n as u64 > count {
                return Err(contract());
            }
            let end = offset.checked_add(n as u64).ok_or_else(contract)?;
            if end > original.live.extent {
                return Err(contract());
            }
            let next = original.hole_bound(offset, false, op.usage)?;
            if let Some(&(start, _)) = original.holes.get(next) {
                op.usage.charge(Resource::SourceBookkeeping, 1)?;
                if start < end {
                    return Err(changed());
                }
            }
            op.usage.charge(Resource::SourceBytes, n as u64)?;
            op.cursor.advance(n as u64)?;
            SourceStep::Filled { offset, count: n }
        }
        RangeRead::Hole { len } => {
            if len == 0 || len > count {
                return Err(contract());
            }
            let end = offset.checked_add(len).ok_or_else(contract)?;
            op.usage.charge(Resource::SourceBytes, len)?;
            original.remember_hole(offset, end, op.usage)?;
            op.cursor.advance(len)?;
            SourceStep::Hole { offset, len }
        }
    };
    op.gate.disarm();
    Ok(Poll::Ready(step))
}
pub(crate) struct SourceDriver {
    #[cfg(feature = "persistent-partials")]
    partial_exclusions: Option<Arc<crate::partial::PartialExclusions>>,
    /// Whether the provider opted in to a growing declaration (`VolumeSource::extends_protection`).
    #[cfg(feature = "persistent-partials")]
    extends: bool,
    #[cfg(feature = "persistent-partials")]
    pending_partial_read: Option<PendingPartialRead>,
    /// Caller-declared damage on archive bytes not yet read, sorted and disjoint per volume. Reads answer
    /// these ranges as holes without consulting the provider.
    #[cfg(feature = "persistent-partials")]
    declared: Vec<(u32, std::ops::Range<u64>)>,
    /// A source the provider answered Ready for before its Complete declaration named the requested index.
    /// It is held unread, and unadmitted, until a later declaration names it (persistent sessions only).
    #[cfg(feature = "persistent-partials")]
    undeclared: Option<Box<dyn RangeSource>>,
    /// Exclusion registry revision against which every path and handle of the current declaration was last found
    /// clear of persistent outputs, bundles and locks. Reset whenever the declaration is replaced.
    #[cfg(feature = "persistent-partials")]
    inputs_checked: Option<u64>,
    /// Rotating position (volumes, then auxiliary paths) of the next redeclared entries compared in full.
    sample_next: usize,
    provider: Box<dyn VolumeSource>,
    request: VolumeRequest,
    original: Option<OriginalSource>,
    retained: Option<RetainedOriginals>,
    reopened: bool,
    // Empty reusable interval capacity only; live source facts stay in OriginalSource.
    legacy_holes: Vec<(u64, u64)>,
    cursor: CheckedCursor,
    control: SessionControl,
    usage: Usage,
    parked: bool,
    // Readiness admitted by verification, but its source callback has not run.
    retry_admitted: bool,
    failed: bool,
    admitted: Vec<(u32, SourceId, OsString, SourceInfo)>,
    protection: ProtectionDeclaration,
    native: super::output::native::NativeProtection,
    sealed_memory: bool,
    wake: Arc<WakeGate>,
    replacements: Vec<(u32, SourceDriver)>,
    replacement_native: bool,
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
            #[cfg(feature = "persistent-partials")]
            partial_exclusions: None,
            #[cfg(feature = "persistent-partials")]
            extends: false,
            #[cfg(feature = "persistent-partials")]
            pending_partial_read: None,
            #[cfg(feature = "persistent-partials")]
            declared: Vec::new(),
            #[cfg(feature = "persistent-partials")]
            undeclared: None,
            #[cfg(feature = "persistent-partials")]
            inputs_checked: None,
            sample_next: 0,
            provider,
            request: VolumeRequest { index: 0, expected: first },
            original: None,
            retained: None,
            reopened: false,
            legacy_holes: Vec::new(),
            cursor: CheckedCursor::new(0),
            control,
            usage,
            parked: false,
            retry_admitted: false,
            failed: false,
            admitted: Vec::new(),
            protection: ProtectionDeclaration::Opaque,
            native,
            sealed_memory: false,
            wake: Arc::new(WakeGate::default()),
            replacements: Vec::new(),
            replacement_native: false,
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
    /// Full validation for authority points: volume and member boundaries,
    /// publication and replacement admission re-observe every protected path.
    pub(crate) fn validate_current(&mut self) -> ProgressiveResult<()> {
        self.validate(false)
    }
    /// Per-step validation after a header or data step. It checks the same
    /// source facts, but bounds the Complete protection recheck to a rotating
    /// slice (see `NativeProtection::refresh_step`), so cumulative bookkeeping
    /// grows with steps rather than with steps times the inventory size.
    pub(crate) fn validate_step(&mut self) -> ProgressiveResult<()> {
        self.validate(true)
    }
    fn validate(&mut self, step: bool) -> ProgressiveResult<()> {
        if self.control.is_canceled() {
            return Err(ProgressiveFailure::new(FailureKind::Canceled));
        }
        if self.failed {
            return Err(contract());
        }
        if self.original.is_some() {
            let checked = self.check_info();
            if self.control.is_canceled() {
                return Err(canceled());
            }
            checked?;
        }
        let external = self.other_lane_handles()? + self.backing_count();
        if step {
            self.native.refresh_step(&self.protection, &mut self.usage, external)?;
        } else {
            self.native.refresh(&self.protection, &mut self.usage, external)?;
        }
        if self.control.is_canceled() {
            return Err(ProgressiveFailure::new(FailureKind::Canceled));
        }
        #[cfg(feature = "persistent-partials")]
        self.check_partial_inputs()?;
        Ok(())
    }
    #[cfg(feature = "persistent-partials")]
    pub(crate) fn require_partial_catalogue(&mut self) -> ProgressiveResult<()> {
        self.refresh_protection(true)?;
        if !matches!(self.protection, ProtectionDeclaration::Complete { .. }) {
            return Err(ProgressiveFailure::new(FailureKind::Partial(Box::new(crate::partial::PartialError::new(
                crate::partial::PartialErrorKind::InvalidOptions,
            )))));
        }
        self.validate_current()
    }
    #[cfg(feature = "persistent-partials")]
    pub(crate) fn install_partial_exclusions(
        &mut self,
        exclusions: Arc<crate::partial::PartialExclusions>,
    ) -> ProgressiveResult<()> {
        self.partial_exclusions = Some(exclusions);
        self.extends = self.provider.extends_protection();
        self.check_partial_inputs()
    }
    #[cfg(feature = "persistent-partials")]
    fn check_partial_inputs(&mut self) -> ProgressiveResult<()> {
        let Some(exclusions) = self.partial_exclusions.clone() else { return Ok(()) };
        // The declared paths and handles only need comparing again when the declaration or the exclusion registry
        // changed (every registry change bumps its revision); comparing all V of them against every exclusion on
        // every step cost O(V * exclusions) path and descriptor syscalls per step. The registry's directory
        // identities are still re-observed on every call.
        if self.inputs_checked.is_none() || self.inputs_checked != Some(exclusions.revision()) {
            self.inputs_checked = None;
            let before = exclusions.revision();
            self.check_inventory_inputs(&self.protection)?;
            if exclusions.revision() == before {
                self.inputs_checked = Some(before);
            }
        } else if self.original.is_none() {
            exclusions.check_input(&[], &[])?;
        }
        if let Some(original) = &self.original {
            self.usage.charge(Resource::SourceRequests, 1)?;
            let files = original.source.backing_files();
            if self.control.is_canceled() {
                return Err(canceled());
            }
            exclusions.check_input(&[], files)?;
        }
        Ok(())
    }
    /// Refuses a declaration naming a path or handle that is a persistent output, state bundle or lock.
    #[cfg(feature = "persistent-partials")]
    fn check_inventory_inputs(&self, declaration: &ProtectionDeclaration) -> ProgressiveResult<()> {
        let Some(exclusions) = &self.partial_exclusions else { return Ok(()) };
        if let ProtectionDeclaration::Complete { inventory, .. } = declaration {
            for path in inventory
                .volumes
                .iter()
                .flat_map(|volume| match &volume.backing {
                    VolumeBacking::Native(paths) => paths.as_slice(),
                    VolumeBacking::NonFile => &[],
                })
                .chain(inventory.auxiliary_paths.iter())
            {
                exclusions.check_input(
                    std::slice::from_ref(&path.path),
                    path.file.as_ref().map_or(&[], |file| std::slice::from_ref(file.as_ref())),
                )?;
            }
        }
        Ok(())
    }
    #[cfg(feature = "persistent-partials")]
    pub(crate) fn partial_catalogue(&mut self) -> ProgressiveResult<ProtectionDeclaration> {
        self.require_partial_catalogue()?;
        if let ProtectionDeclaration::Complete { inventory, .. } = &self.protection {
            let bytes = inventory
                .volumes
                .iter()
                .map(|v| {
                    std::mem::size_of::<ProtectedVolume>()
                        + v.name.len()
                        + match &v.backing {
                            VolumeBacking::NonFile => 0,
                            VolumeBacking::Native(p) => p
                                .iter()
                                .map(|p| std::mem::size_of::<ProtectedPath>() + p.path.as_os_str().len())
                                .sum::<usize>(),
                        }
                })
                .sum::<usize>()
                + inventory
                    .auxiliary_paths
                    .iter()
                    .map(|p| std::mem::size_of::<ProtectedPath>() + p.path.as_os_str().len())
                    .sum::<usize>();
            self.usage.charge(Resource::MetadataBytes, bytes as u64)?;
        }
        Ok(self.protection.clone())
    }
    #[cfg(feature = "persistent-partials")]
    pub(crate) fn check_partial_target(&mut self, path: &std::path::Path) -> ProgressiveResult<()> {
        self.require_partial_catalogue()?;
        self.native.check_partial_target(path, &mut self.usage)?;
        self.validate_current()
    }
    /// Refuses a state bundle at `path` holding, or being, a path the current declaration names.
    #[cfg(feature = "persistent-partials")]
    pub(crate) fn check_partial_subtree(&mut self, path: &std::path::Path) -> ProgressiveResult<()> {
        self.require_partial_catalogue()?;
        self.native.check_partial_subtree(path, &mut self.usage)?;
        self.validate_current()
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
            self.refresh_protection(true)?;
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
        #[cfg(feature = "persistent-partials")]
        if self.pending_partial_read.is_some() {
            return Err(contract());
        }
        if self.parked
            || self.failed
            || self.original.is_none()
            || offset > self.original.as_ref().unwrap().live.length.value()
        {
            return Err(contract());
        }
        self.cursor = CheckedCursor::new(offset);
        Ok(())
    }
    pub(crate) fn select_volume(&mut self, request: VolumeRequest) -> ProgressiveResult<()> {
        #[cfg(feature = "persistent-partials")]
        if self.pending_partial_read.is_some() {
            return Err(contract());
        }
        if self.retained.is_some() {
            return self.select_retained(request);
        }
        if self.parked
            || self.failed
            || self.original.is_none()
            || self.request.index.checked_add(1) != Some(request.index)
        {
            return Err(contract());
        }
        self.usage.charge(Resource::NameBytes, request.expected.as_encoded_bytes().len() as u64)?;
        self.usage.charge(Resource::MetadataBytes, request.expected.capacity() as u64)?;
        self.request = request;
        let mut original = self.original.take().unwrap();
        self.legacy_holes = std::mem::take(&mut original.holes);
        self.legacy_holes.clear();
        drop(original);
        self.cursor = CheckedCursor::new(0);
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
        if self.retained.is_some() && self.control.is_canceled() {
            self.finish_selected_request();
            return Poll::Ready(Err(canceled()));
        }
        if self.retained.is_some() && self.original.as_mut().is_some_and(|s| s.leased()) {
            return Poll::Ready(Err(invalid_capability()));
        }
        if let Some(retained) = &self.retained {
            if self.parked && retained.selected_len != Some(buf.len()) {
                return Poll::Ready(Err(invalid_capability()));
            }
            if !self.failed && buf.is_empty() {
                return Poll::Ready(Ok(SourceStep::Filled { offset: self.cursor.offset(), count: 0 }));
            }
        }
        let result = (|| {
            if self.retained.is_some() && self.failed {
                return Err(contract());
            }
            if self.retained.is_some() {
                self.prepare_selected(cx, buf.len())?;
            } else {
                self.control.register(cx.waker());
                self.wake.register(cx.waker());
            }
            self.poll_inner(buf, verify)
        })();
        if self.retained.is_some() && !matches!(result, Ok(Poll::Pending)) {
            self.finish_selected_request();
        }
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
        if self.original.is_none() {
            self.check_original_capacity()?;
            self.refresh_protection(false)?;
            #[cfg(feature = "persistent-partials")]
            if let Some(source) = self.undeclared.take() {
                // Woken after a Ready for a volume the declaration did not name yet: admit it once it does.
                if self.awaits_declaration(self.request.index)? {
                    self.undeclared = Some(source);
                    self.parked = true;
                    return Ok(Poll::Pending);
                }
                self.wake.disarm();
                let info = self.admit_source(source)?;
                return Ok(Poll::Ready(Ok(SourceStep::VolumeOpened { index: self.request.index, id: info.id })));
            }
            self.usage.charge(Resource::SourceRequests, 1)?;
            self.wake.arm();
            let w = Waker::from(self.wake.clone());
            let mut cx = Context::from_waker(&w);
            let answer = self.provider.volume(&self.request, &mut cx);
            if self.control.is_canceled() {
                return Err(ProgressiveFailure::new(FailureKind::Canceled));
            }
            match answer? {
                VolumeAnswer::Wait => {
                    self.parked = true;
                    return Ok(Poll::Pending);
                }
                VolumeAnswer::Missing => return Err(ProgressiveFailure::new(FailureKind::MissingVolume)),
                VolumeAnswer::Abort => return Err(ProgressiveFailure::new(FailureKind::Canceled)),
                VolumeAnswer::Ready(source) => {
                    #[cfg(feature = "persistent-partials")]
                    if self.awaits_declaration(self.request.index)? {
                        // The provider may have declared the volume while answering.
                        self.refresh_protection(false)?;
                        if self.awaits_declaration(self.request.index)? {
                            // Hold it unread and wait, still armed, for the provider to wake this request once
                            // a larger declaration names it.
                            self.undeclared = Some(source);
                            self.parked = true;
                            return Ok(Poll::Pending);
                        }
                    }
                    self.wake.disarm();
                    let info = self.admit_source(source)?;
                    return Ok(Poll::Ready(Ok(SourceStep::VolumeOpened { index: self.request.index, id: info.id })));
                }
            }
        }
        if self.reopened {
            let checked = self.check_info();
            if self.control.is_canceled() {
                return Err(canceled());
            }
            checked?;
            let external = self.other_lane_handles()? + self.backing_count();
            self.native.refresh(&self.protection, &mut self.usage, external)?;
            if self.control.is_canceled() {
                return Err(ProgressiveFailure::new(FailureKind::Canceled));
            }
            self.reopened = false;
            return Ok(Poll::Ready(Ok(SourceStep::VolumeOpened {
                index: self.request.index,
                id: self.original.as_ref().unwrap().live.id,
            })));
        }
        if self.retained.is_some() {
            let external = self.other_lane_handles()? + self.backing_count();
            self.native.refresh_step(&self.protection, &mut self.usage, external)?;
            if self.control.is_canceled() {
                return Err(canceled());
            }
        }
        #[cfg(feature = "persistent-partials")]
        let buf = if verify || self.pending_partial_read.is_some() {
            buf
        } else {
            match self.declared_overlay(buf.len())? {
                Overlay::Hole(step) => return Ok(Poll::Ready(Ok(step))),
                Overlay::Limit(n) => &mut buf[..n],
            }
        };
        #[cfg(feature = "persistent-partials")]
        let partial_external =
            if self.partial_exclusions.is_some() { self.other_lane_handles()? + self.backing_count() } else { 0 };
        poll_available(
            self.original.as_mut().unwrap(),
            RangeOperation {
                cursor: &mut self.cursor,
                gate: &self.wake,
                parked: &mut self.parked,
                retry_admitted: &mut self.retry_admitted,
                control: &self.control,
                usage: &mut self.usage,
                verify,
                #[cfg(feature = "persistent-partials")]
                exclusions: self.partial_exclusions.as_deref(),
                #[cfg(feature = "persistent-partials")]
                pending: &mut self.pending_partial_read,
                #[cfg(feature = "persistent-partials")]
                native: self
                    .partial_exclusions
                    .as_ref()
                    .map(|_| (&mut self.native, &self.protection, partial_external)),
            },
            buf,
        )
        .map(|p| p.map(Ok))
    }

    fn admit_source(&mut self, source: Box<dyn RangeSource>) -> ProgressiveResult<SourceInfo> {
        self.usage.charge(Resource::SourceRequests, 1)?;
        let info = source.info();
        if self.control.is_canceled() {
            return Err(canceled());
        }
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
        if self.control.is_canceled() {
            return Err(canceled());
        }
        #[cfg(feature = "persistent-partials")]
        if let Some(exclusions) = &self.partial_exclusions {
            exclusions.check_input(&[], backing)?;
        }
        let external = self.other_lane_handles()?;
        self.usage.check(Resource::VolumeHandles, (external + self.native.handle_count() + backing.len()) as u64)?;
        self.native.refresh_admission(
            &self.protection,
            self.request.index,
            &mut self.usage,
            external + backing.len(),
        )?;
        self.native.admit(self.request.index, backing, &self.protection, &mut self.usage, external)?;
        let backing_count = backing.len();
        // Only the concrete library adapter carries its original immutable stamp.
        // Custom providers retain the cooperative progressive identity contract.
        if let Some(immutable) = (&*source as &dyn std::any::Any).downcast_ref::<ImmutableFileSource>() {
            self.native.remember_immutable(
                &immutable.file,
                &immutable.path,
                immutable.stamp,
                Some((self.request.index, &self.protection)),
                &self.usage,
            )?;
        }
        self.usage.charge(Resource::MetadataBytes, self.request.expected.capacity() as u64)?;
        self.usage.charge(Resource::NameBytes, self.request.expected.capacity() as u64)?;
        self.usage.charge(Resource::SourceBookkeeping, (self.admitted.len() - position) as u64)?;
        reserve_records(&mut self.admitted, &mut self.usage)?;
        self.admitted.insert(position, (self.request.index, info.id, self.request.expected.clone(), info));
        self.replacement_native = (&*source as &dyn std::any::Any).is::<ImmutableFileSource>();
        self.original = Some(OriginalSource {
            source,
            index: self.request.index,
            live: info,
            holes: std::mem::take(&mut self.legacy_holes),
            backing_count,
            lease: None,
        });
        if let Some(retained) = &mut self.retained {
            retained.high_water = Some(self.request.index);
        }
        Ok(info)
    }
    fn other_lane_handles(&self) -> ProgressiveResult<usize> {
        self.usage.charge(Resource::SourceBookkeeping, self.replacements.len() as u64)?;
        Ok(self.external_handles
            + self.retained_backing_count()?
            + self
                .replacements
                .iter()
                .map(|(_, lane)| lane.native.handle_count() + lane.backing_count())
                .sum::<usize>())
    }
    /// Answers a read at the cursor that starts inside declared damage as a hole, or limits it to end where
    /// declared damage begins.
    #[cfg(feature = "persistent-partials")]
    fn declared_overlay(&mut self, len: usize) -> ProgressiveResult<Overlay> {
        let volume = self.request.index;
        let offset = self.cursor.offset();
        let original = self.original.as_mut().unwrap();
        let length = original.live.length.value();
        if offset >= length {
            // End of volume (or a truncated one) is reported by the ordinary read path.
            return Ok(Overlay::Limit(len));
        }
        let end = offset.saturating_add(len as u64).min(length);
        // Ranges are sorted and disjoint and reads only move forward, so ranges behind the cursor are dropped
        // and only the first remaining one can matter.
        let stale = self.declared.iter().take_while(|(v, r)| *v < volume || (*v == volume && r.end <= offset)).count();
        self.declared.drain(..stale);
        if let Some((_, range)) = self.declared.first().filter(|(v, _)| *v == volume) {
            self.usage.charge(Resource::SourceBookkeeping, 1)?;
            if range.start <= offset && offset < range.end {
                let hole = range.end.min(end) - offset;
                self.usage.charge(Resource::SourceBytes, hole)?;
                original.remember_hole(offset, offset + hole, &mut self.usage)?;
                self.cursor.advance(hole)?;
                self.wake.disarm();
                return Ok(Overlay::Hole(SourceStep::Hole { offset, len: hole }));
            }
            if offset < range.start && range.start < end {
                return Ok(Overlay::Limit((range.start - offset) as usize));
            }
        }
        Ok(Overlay::Limit(len))
    }
    /// Records damage on bytes of `volume` the driver has not read yet. Ranges are merged and bounded by the
    /// hole-interval limit.
    #[cfg(feature = "persistent-partials")]
    pub(crate) fn declare_future(&mut self, volume: u32, range: std::ops::Range<u64>) -> ProgressiveResult<()> {
        let (index, cursor) = self.position();
        if range.is_empty() || volume < index || (volume == index && range.start < cursor) {
            return Err(contract());
        }
        if let Some(pending) = &self.pending_partial_read
            && volume == index
            && range.start < pending.offset.saturating_add(pending.requested)
        {
            return Err(ProgressiveFailure::new(FailureKind::Partial(Box::new(crate::partial::PartialError::new(
                crate::partial::PartialErrorKind::Busy,
            )))));
        }
        let declared_start = range.start;
        let mut merged = range;
        let mut kept = Vec::new();
        kept.try_reserve_exact(self.declared.len() + 1).map_err(|_| contract())?;
        for (v, r) in self.declared.drain(..) {
            if v == volume && r.start <= merged.end && merged.start <= r.end {
                merged = merged.start.min(r.start)..merged.end.max(r.end);
            } else {
                kept.push((v, r));
            }
        }
        self.usage.check(Resource::HoleIntervals, kept.len() as u64 + 1)?;
        kept.push((volume, merged));
        kept.sort_by_key(|(v, r)| (*v, r.start));
        self.declared = kept;
        let parked_end =
            self.retained.as_ref().and_then(|r| r.selected_len).map(|len| cursor.saturating_add(len as u64));
        if self.parked
            && self.original.is_some()
            && volume == index
            && parked_end.is_none_or(|end| declared_start < end)
        {
            // A read parked on the provider may be waiting for exactly these bytes; let it retry through the
            // overlay instead of waiting for a provider wake that may never come.
            self.wake.notify(false);
        }
        Ok(())
    }
    /// Whether every byte of `range` on `volume` is caller-declared damage.
    #[cfg(feature = "persistent-partials")]
    pub(crate) fn declared_covers(&self, volume: u32, range: &std::ops::Range<u64>) -> bool {
        self.declared.iter().any(|(v, r)| *v == volume && r.start <= range.start && range.end <= r.end)
    }
    /// The volume being read (or about to be opened) and the packed offset of the next read within it.
    #[cfg(feature = "persistent-partials")]
    pub(crate) fn position(&self) -> (u32, u64) {
        (self.request.index, if self.original.is_some() { self.cursor.offset() } else { 0 })
    }
    pub(crate) fn observed_info(&self, index: u32) -> Option<SourceInfo> {
        self.admitted.iter().find(|(i, _, _, _)| *i == index).map(|(_, _, _, v)| *v)
    }
    pub(crate) fn supply_replacement(&mut self, index: u32, source: Box<dyn RangeSource>) -> ProgressiveResult<()> {
        self.validate_current()?;
        self.usage.charge(Resource::SourceBookkeeping, self.admitted.len() as u64)?;
        if self.retained.is_some() {
            self.usage.check(Resource::VolumeHandles, (self.original_count() + self.replacements.len() + 1) as u64)?;
        } else {
            self.usage.check(Resource::VolumeHandles, self.replacements.len() as u64 + 2)?;
        }
        let original = self.observed_info(index).ok_or_else(contract)?;
        self.usage.charge(Resource::SourceRequests, 1)?;
        let info = source.info();
        if self.control.is_canceled() {
            return Err(canceled());
        }
        if info.length.value() != original.length.value() {
            return Err(changed());
        }
        self.usage.charge(Resource::SourceBookkeeping, self.replacements.len() as u64 + 1)?;
        if self
            .replacements
            .iter()
            .any(|(i, s)| *i != index && s.original.as_ref().is_some_and(|v| v.live.id == info.id))
        {
            return Err(contract());
        }
        self.usage.charge(Resource::SourceBookkeeping, self.admitted.len() as u64)?;
        let name = self.admitted.iter().find(|(i, _, _, _)| *i == index).map(|(_, _, n, _)| n).ok_or_else(contract)?;
        self.usage.charge(Resource::MetadataBytes, name.capacity() as u64)?;
        let first = name.clone();
        let mut lane = Self::with_usage(Box::new(NoVolumes), first, self.usage.clone(), self.control.clone())?;
        lane.request.index = index;
        #[cfg(feature = "persistent-partials")]
        {
            lane.partial_exclusions = self.partial_exclusions.clone();
        }
        self.usage.charge(Resource::SourceBookkeeping, self.replacements.len() as u64 * 2)?;
        let held = self.native.handle_count() + self.backing_count() + self.retained_backing_count()?;
        let replacements =
            self.replacements.iter().map(|(_, s)| s.native.handle_count() + s.backing_count()).sum::<usize>();
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
        if self.control.is_canceled() {
            return Err(ProgressiveFailure::new(FailureKind::Canceled));
        }
        for (_, lane) in &mut self.replacements {
            if lane.failed {
                return Err(contract());
            }
            if lane.parked {
                lane.wake.register(cx.waker());
                if self.control.is_canceled() {
                    return Err(ProgressiveFailure::new(FailureKind::Canceled));
                }
                if !lane.wake.consume_ready(|wakes| self.usage.charge(Resource::ProviderWakes, wakes))? {
                    return Ok(false);
                }
                lane.parked = false;
                lane.retry_admitted = true;
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
        let admitted = self.usage.charge(Resource::SourceBookkeeping, self.replacements.len() as u64).and_then(|_| {
            let count = self.replacements.iter().filter(|(_, lane)| lane.parked || lane.retry_admitted).count();
            self.usage.charge(
                Resource::MetadataBytes,
                (count * (std::mem::size_of::<WakeGate>() + 2 * std::mem::size_of::<usize>())) as u64,
            )
        });
        if let Err(error) = admitted {
            // A failed retirement cannot leave its old request usable by a later
            // job. Close only those lanes; no unbudgeted latch is allocated.
            for (_, lane) in &mut self.replacements {
                if lane.parked || lane.retry_admitted {
                    lane.failed = true;
                }
            }
            return Err(error);
        }
        for (_, lane) in &mut self.replacements {
            if lane.parked || lane.retry_admitted {
                lane.parked = false;
                lane.retry_admitted = false;
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
    fn check_info(&mut self) -> ProgressiveResult<()> {
        self.original.as_mut().unwrap().check_info(&mut self.usage)
    }
    /// Asks the provider for its declaration and checks it against the one the session enforces. `full` compares
    /// a repeated declaration entry by entry (authority points: publication, member creation and its target
    /// checks); otherwise (volume admission) a repeat is judged on a bounded sample, see `sample_redeclaration`.
    fn refresh_protection(&mut self, full: bool) -> ProgressiveResult<()> {
        self.usage.charge(Resource::SourceRequests, 1)?;
        if self.control.is_canceled() {
            return Err(ProgressiveFailure::new(FailureKind::Canceled));
        }
        let next = self.provider.protection();
        if self.control.is_canceled() {
            return Err(ProgressiveFailure::new(FailureKind::Canceled));
        }
        let mut next = next?;
        if !full && self.sample_redeclaration(&next)? {
            // The provider repeated the declaration the session already validated and enforces. Nothing is
            // adopted from it, so only the bounded step recheck runs.
            let external = self.other_lane_handles()? + self.backing_count();
            self.native.refresh_step(&self.protection, &mut self.usage, external)?;
            #[cfg(feature = "persistent-partials")]
            self.check_partial_inputs()?;
            return Ok(());
        }
        // A redeclaration that matches the current Complete inventory position by
        // position is already canonical and duplicate-free, so only its shape and
        // retained sizes are rechecked; the sorts run for a first or reordered one.
        let mut known = false;
        if let ProtectionDeclaration::Complete { epoch: b, inventory } = &mut next {
            validate_inventory_shape(inventory, &mut self.usage)?;
            if let ProtectionDeclaration::Complete { epoch: a, inventory: x } = &self.protection {
                known = a == b && same_inventory(x, inventory, &mut self.usage)?;
            }
            if !known {
                validate_inventory_unique(inventory, &mut self.usage)?;
                canonicalize_inventory(inventory, &mut self.usage)?;
            }
        }
        if let (
            true,
            ProtectionDeclaration::Complete { inventory: x, .. },
            ProtectionDeclaration::Complete { inventory: y, .. },
        ) = (known, &self.protection, &next)
            && !adds_handles(x, y, &mut self.usage)?
        {
            // Nothing new was declared. The retained declaration already covers
            // every admitted name, and every caller re-proves all bindings with a
            // full refresh before it relies on them (admission after the provider
            // callback, or the full validation around a publication check).
            let external = self.other_lane_handles()? + self.backing_count();
            self.native.refresh_step(&self.protection, &mut self.usage, external)?;
            #[cfg(feature = "persistent-partials")]
            self.check_partial_inputs()?;
            return Ok(());
        }
        let extension = match (&self.protection, &next) {
            (ProtectionDeclaration::Complete { .. }, ProtectionDeclaration::Complete { .. }) if known => false,
            (
                ProtectionDeclaration::Complete { epoch: a, inventory: x },
                ProtectionDeclaration::Complete { epoch: b, inventory: y },
            ) if a == b && same_inventory(x, y, &mut self.usage)? => false,
            // Only a persistent session checks every declared path against every output it creates, so only it
            // may learn of volumes later. An extension needs a higher epoch and leaves every entry unchanged.
            (
                ProtectionDeclaration::Complete { epoch: a, inventory: x },
                ProtectionDeclaration::Complete { epoch: b, inventory: y },
            ) if self.extendable() && b > a && extends_inventory(x, y, &mut self.usage)? => true,
            (ProtectionDeclaration::Complete { .. }, _) => return Err(changed()),
            _ => false,
        };
        self.check_inventory_admitted(&next)?;
        #[cfg(feature = "persistent-partials")]
        if extension {
            // Appended paths must not name an output, bundle or lock created under an earlier epoch, by any
            // spelling: the check canonicalises, as member creation does.
            self.check_inventory_inputs(&next)?;
            if let (Some(exclusions), ProtectionDeclaration::Complete { inventory, .. }) =
                (&self.partial_exclusions, &next)
            {
                exclusions.check_declared(
                    inventory
                        .volumes
                        .iter()
                        .flat_map(|volume| match &volume.backing {
                            VolumeBacking::Native(paths) => paths.as_slice(),
                            VolumeBacking::NonFile => &[],
                        })
                        .chain(inventory.auxiliary_paths.iter())
                        .map(|path| path.path.as_path()),
                )?;
            }
        }
        let external = self.other_lane_handles()? + self.backing_count();
        if extension
            && let (
                ProtectionDeclaration::Complete { inventory: old, .. },
                ProtectionDeclaration::Complete { inventory: new, .. },
            ) = (&self.protection, &next)
        {
            self.native.extend(old, new, &mut self.usage, external)?;
            // The bindings now hold the appended paths; anything failing before the declaration is committed
            // leaves them disagreeing with it, so the driver is failed rather than left half extended.
            let committed = (|| {
                self.native.refresh(&next, &mut self.usage, external)?;
                self.protection = next;
                #[cfg(feature = "persistent-partials")]
                {
                    self.inputs_checked = None;
                }
                #[cfg(feature = "persistent-partials")]
                self.check_partial_inputs()?;
                Ok(())
            })();
            if committed.is_err() {
                self.failed = true;
            }
            return committed;
        }
        self.native.refresh(&next, &mut self.usage, external)?;
        self.protection = next;
        #[cfg(feature = "persistent-partials")]
        {
            self.inputs_checked = None;
        }
        #[cfg(feature = "persistent-partials")]
        self.check_partial_inputs()?;
        Ok(())
    }
    /// Whether `next` repeats the current Complete declaration, judged on a bounded sample.
    ///
    /// The provider is asked for its declaration at every volume admission (and at member creation in persistent
    /// sessions), and it answers with a fresh value, so proving the whole answer equal costs O(V * P) per query
    /// and O(V^2 * P) per session. Instead a repeat with the same epoch and the same counts is compared in full
    /// only for the volume being requested and for `SAMPLE` more entries in rotation, so every entry is compared
    /// again every V / `SAMPLE` queries. Any difference in the sample, including a newly supplied handle, falls
    /// through to the full comparison below, which adopts the handle or refuses the change with `SourceChanged`;
    /// so does any change of epoch or count, and with it every extension.
    ///
    /// This is safe because a matching repeat is never adopted: the session keeps enforcing the declaration it
    /// validated in full, whatever the unsampled entries of the repeat say. A same-epoch change to an entry is
    /// still refused when that volume is requested (its entry is always compared), when the rotation reaches it,
    /// and at the latest at the next authority point (publication, persistent member creation and its target
    /// checks), which compares the whole declaration. Only volume admission samples. A handle supplied late for
    /// an entry is likewise adopted when a request, the rotation or an authority point reaches it.
    fn sample_redeclaration(&mut self, next: &ProtectionDeclaration) -> ProgressiveResult<bool> {
        const SAMPLE: usize = 8;
        let (
            ProtectionDeclaration::Complete { epoch: a, inventory: x },
            ProtectionDeclaration::Complete { epoch: b, inventory: y },
        ) = (&self.protection, next)
        else {
            return Ok(false);
        };
        self.usage.charge(Resource::SourceBookkeeping, 3)?;
        if a != b || x.volumes.len() != y.volumes.len() || x.auxiliary_paths.len() != y.auxiliary_paths.len() {
            return Ok(false);
        }
        let total = x.volumes.len() + x.auxiliary_paths.len();
        if total <= SAMPLE + 1 {
            // Small inventories are compared whole by the full path; it is no dearer than the sample.
            return Ok(false);
        }
        self.usage.charge(Resource::SourceBookkeeping, 1 + x.volumes.len().max(1).ilog2() as u64)?;
        let requested = x.volumes.binary_search_by_key(&self.request.index, |v| v.index).ok();
        let start = self.sample_next % total;
        self.sample_next = (start + SAMPLE) % total;
        for i in requested.into_iter().chain((start..start + SAMPLE).map(|i| i % total)) {
            let same = if i < x.volumes.len() {
                same_volume(&x.volumes[i], &y.volumes[i], &mut self.usage)?
                    && !volume_adds_handles(&x.volumes[i], &y.volumes[i], &mut self.usage)?
            } else {
                let (p, q) = (&x.auxiliary_paths[i - x.volumes.len()], &y.auxiliary_paths[i - x.volumes.len()]);
                same_path(p, q, &mut self.usage)? && !(p.file.is_none() && q.file.is_some())
            };
            if !same {
                return Ok(false);
            }
        }
        Ok(true)
    }
    /// The epoch of the current Complete declaration.
    #[cfg(feature = "persistent-partials")]
    pub(crate) fn protection_epoch(&self) -> Option<u64> {
        match &self.protection {
            ProtectionDeclaration::Complete { epoch, .. } => Some(*epoch),
            _ => None,
        }
    }
    /// Whether a Complete declaration may grow: persistent sessions only, whose exclusions refuse any declared
    /// path that names an output, bundle or lock, and only when the provider opted in.
    fn extendable(&self) -> bool {
        #[cfg(feature = "persistent-partials")]
        {
            self.partial_exclusions.is_some() && self.extends
        }
        #[cfg(not(feature = "persistent-partials"))]
        {
            false
        }
    }
    /// Whether the current declaration leaves `index` undeclared, so a persistent session waits for a larger one.
    #[cfg(feature = "persistent-partials")]
    fn awaits_declaration(&mut self, index: u32) -> ProgressiveResult<bool> {
        if !self.extendable() {
            return Ok(false);
        }
        let ProtectionDeclaration::Complete { inventory, .. } = &self.protection else { return Ok(false) };
        self.usage.charge(Resource::SourceBookkeeping, 1 + inventory.volumes.len().max(1).ilog2() as u64)?;
        Ok(inventory.volumes.binary_search_by_key(&index, |v| v.index).is_err())
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
/// Whether `b` declares a handle for a path that `a` declared without one.
/// Both inventories must already compare equal position by position.
fn adds_handles(a: &ProtectionInventory, b: &ProtectionInventory, usage: &mut Usage) -> ProgressiveResult<bool> {
    usage.charge(Resource::SourceBookkeeping, (a.volumes.len() + a.auxiliary_paths.len()) as u64)?;
    for (x, y) in a.auxiliary_paths.iter().zip(&b.auxiliary_paths) {
        if x.file.is_none() && y.file.is_some() {
            return Ok(true);
        }
    }
    for (x, y) in a.volumes.iter().zip(&b.volumes) {
        if let (VolumeBacking::Native(x), VolumeBacking::Native(y)) = (&x.backing, &y.backing) {
            usage.charge(Resource::SourceBookkeeping, x.len() as u64)?;
            if x.iter().zip(y).any(|(x, y)| x.file.is_none() && y.file.is_some()) {
                return Ok(true);
            }
        }
    }
    Ok(false)
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
        if !same_volume(x, y, usage)? {
            return Ok(false);
        }
    }
    Ok(true)
}
/// Whether two declared volumes have the same index, name and backing (a handle absent in `x` may be present in
/// `y`; see [`volume_adds_handles`]).
fn same_volume(x: &ProtectedVolume, y: &ProtectedVolume, usage: &mut Usage) -> ProgressiveResult<bool> {
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
    Ok(true)
}
/// Whether `y` declares a handle for a path of `x` declared without one; both must compare equal.
fn volume_adds_handles(x: &ProtectedVolume, y: &ProtectedVolume, usage: &mut Usage) -> ProgressiveResult<bool> {
    if let (VolumeBacking::Native(x), VolumeBacking::Native(y)) = (&x.backing, &y.backing) {
        usage.charge(Resource::SourceBookkeeping, x.len() as u64)?;
        return Ok(x.iter().zip(y).any(|(x, y)| x.file.is_none() && y.file.is_some()));
    }
    Ok(false)
}
/// Whether canonical `b` keeps every volume of canonical `a` (index, name and backing) and every auxiliary path,
/// adding only new indices and paths.
fn extends_inventory(a: &ProtectionInventory, b: &ProtectionInventory, usage: &mut Usage) -> ProgressiveResult<bool> {
    usage.charge(Resource::SourceBookkeeping, 2)?;
    if a.volumes.len() > b.volumes.len() || a.auxiliary_paths.len() > b.auxiliary_paths.len() {
        return Ok(false);
    }
    // Both are sorted by index; every old index must appear in order with the same entry.
    let mut later = b.volumes.iter();
    for x in &a.volumes {
        let y = loop {
            usage.charge(Resource::SourceBookkeeping, 1)?;
            match later.next() {
                Some(y) if y.index < x.index => continue,
                Some(y) if y.index == x.index => break y,
                _ => return Ok(false),
            }
        };
        usage.charge(
            Resource::SourceBookkeeping,
            2 + x.name.as_encoded_bytes().len() as u64 + y.name.as_encoded_bytes().len() as u64,
        )?;
        if x.name != y.name {
            return Ok(false);
        }
        match (&x.backing, &y.backing) {
            (VolumeBacking::NonFile, VolumeBacking::NonFile) => {}
            (VolumeBacking::Native(p), VolumeBacking::Native(q)) => {
                usage.charge(Resource::SourceBookkeeping, 1)?;
                if p.len() != q.len() {
                    return Ok(false);
                }
                for (p, q) in p.iter().zip(q) {
                    if !same_path(p, q, usage)? {
                        return Ok(false);
                    }
                }
            }
            _ => return Ok(false),
        }
    }
    // Auxiliary paths are sorted and unique; every old path must appear in order, unchanged.
    let mut later = b.auxiliary_paths.iter();
    for x in &a.auxiliary_paths {
        let y = loop {
            let Some(y) = later.next() else { return Ok(false) };
            match path_compare(&y.path, &x.path, usage)? {
                std::cmp::Ordering::Less => continue,
                std::cmp::Ordering::Equal => break y,
                std::cmp::Ordering::Greater => return Ok(false),
            }
        };
        if !same_path(x, y, usage)? {
            return Ok(false);
        }
    }
    Ok(true)
}
#[cfg(test)]
fn validate_inventory(i: &ProtectionInventory, usage: &mut Usage) -> ProgressiveResult<()> {
    validate_inventory_shape(i, usage)?;
    validate_inventory_unique(i, usage)
}
/// Linear checks and retained-size charges for one declared inventory.
fn validate_inventory_shape(i: &ProtectionInventory, usage: &mut Usage) -> ProgressiveResult<()> {
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
    usage.charge(Resource::MetadataBytes, metadata)
}
/// Duplicate volume indexes and native paths, found by sorting borrowed keys.
fn validate_inventory_unique(i: &ProtectionInventory, usage: &mut Usage) -> ProgressiveResult<()> {
    let all = || {
        i.auxiliary_paths.iter().chain(i.volumes.iter().flat_map(|v| match &v.backing {
            VolumeBacking::Native(p) => p.as_slice(),
            VolumeBacking::NonFile => &[],
        }))
    };
    let paths = all().count() as u64;
    // Temporary borrowed-key indexes below also need reservation before allocation.
    let scratch = (i.volumes.len() as u64)
        .checked_mul(std::mem::size_of::<u32>() as u64)
        .and_then(|n| n.checked_add(paths.checked_mul(std::mem::size_of::<&std::path::Path>() as u64)?))
        .ok_or_else(contract)?;
    usage.charge(Resource::MetadataBytes, scratch)?;
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
mod retained_tests;
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

#[cfg(all(test, feature = "persistent-partials"))]
mod partial_callback_tests {
    use super::*;
    use std::sync::atomic::AtomicU64;
    struct ChangingSource {
        generation: AtomicU64,
        armed: AtomicBool,
        reads: Arc<AtomicU64>,
    }
    impl RangeSource for ChangingSource {
        fn info(&self) -> SourceInfo {
            SourceInfo {
                id: SourceId(1),
                generation: self.generation.load(Ordering::SeqCst),
                extent: 4,
                length: SourceLength::Final(4),
            }
        }
        fn backing_files(&self) -> &[File] {
            if self.armed.swap(false, Ordering::SeqCst) {
                self.generation.fetch_add(1, Ordering::SeqCst);
            }
            &[]
        }
        fn read_at(&mut self, _: u64, buf: &mut [u8], _: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            buf.copy_from_slice(b"data");
            self.armed.store(true, Ordering::SeqCst);
            Ok(RangeRead::Filled { count: 4 })
        }
    }
    fn unchanged_acceptance(pending_answer: bool) {
        let mut usage = Usage::new(ProgressiveLimits { source_bytes: 4, ..Default::default() });
        let exclusions = crate::partial::PartialExclusions::new(usage.clone());
        let reads = Arc::new(AtomicU64::new(0));
        let source = Box::new(ChangingSource {
            generation: AtomicU64::new(0),
            armed: AtomicBool::new(pending_answer),
            reads: reads.clone(),
        });
        let mut original =
            OriginalSource { live: source.info(), source, index: 0, holes: Vec::new(), backing_count: 0, lease: None };
        let mut cursor = CheckedCursor::new(0);
        let gate = Arc::new(WakeGate::default());
        let mut parked = false;
        let mut retry = false;
        let control = SessionControl::default();
        let mut pending = pending_answer.then(|| PendingPartialRead {
            offset: 0,
            requested: 4,
            answer: RangeRead::Filled { count: 4 },
            bytes: b"data".to_vec(),
        });
        let mut buf = [0; 4];
        let result = poll_available(
            &mut original,
            RangeOperation {
                cursor: &mut cursor,
                gate: &gate,
                parked: &mut parked,
                retry_admitted: &mut retry,
                control: &control,
                usage: &mut usage,
                verify: false,
                exclusions: Some(&exclusions),
                pending: &mut pending,
                native: None,
            },
            &mut buf,
        );
        assert_eq!(cursor.offset(), 0, "changed source advanced accepted cursor");
        usage.charge(Resource::SourceBytes, 4).expect("changed source charged accepted bytes");
        assert!(matches!(result, Err(ProgressiveFailure { kind: FailureKind::SourceChanged, .. })));
        assert_eq!(reads.load(Ordering::SeqCst), u64::from(!pending_answer));
        if pending_answer {
            assert!(pending.is_some());
            assert_eq!(buf, [0; 4]);
        }
    }
    #[test]
    fn post_backing_change_does_not_accept_fresh_answer() {
        unchanged_acceptance(false);
    }
    #[test]
    fn post_backing_change_does_not_accept_retained_pending_answer() {
        unchanged_acceptance(true);
    }
}
