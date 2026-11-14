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
use crate::progressive::InputOperation;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::task::{Wake, Waker};

#[derive(Default)]
struct Signal(AtomicUsize);
impl Wake for Signal {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
#[derive(Clone)]
struct State {
    info: SourceInfo,
    calls: Arc<AtomicUsize>,
    pending: Arc<Mutex<Option<Waker>>>,
    answers: Arc<Mutex<std::collections::VecDeque<Answer>>>,
}
#[derive(Clone, Copy)]
enum Answer {
    Wait(bool),
    Fill(usize),
    Hole(u64),
    ReadError,
}
impl State {
    fn new(answers: &[Answer]) -> Self {
        Self {
            info: SourceInfo { id: SourceId(1), generation: 0, extent: 8, length: SourceLength::Advertised(8) },
            calls: Arc::new(AtomicUsize::new(0)),
            pending: Arc::new(Mutex::new(None)),
            answers: Arc::new(Mutex::new(answers.iter().copied().collect())),
        }
    }
    fn wake(&self) {
        self.pending.lock().unwrap().as_ref().unwrap().wake_by_ref();
    }
}
struct Provider(State);
impl VolumeSource for Provider {
    fn volume(&mut self, _: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
        Ok(VolumeAnswer::Ready(Box::new(self.0.clone())))
    }
}
impl RangeSource for State {
    fn info(&self) -> SourceInfo {
        self.info
    }
    fn backing_files(&self) -> &[std::fs::File] {
        &[]
    }
    fn read_at(&mut self, _: u64, buf: &mut [u8], cx: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self.answers.lock().unwrap().pop_front().unwrap_or(Answer::Fill(1)) {
            Answer::Wait(now) => {
                *self.pending.lock().unwrap() = Some(cx.waker().clone());
                if now {
                    cx.waker().wake_by_ref();
                }
                Ok(RangeRead::NotYet)
            }
            Answer::Fill(count) => {
                buf.fill(7);
                Ok(RangeRead::Filled { count })
            }
            Answer::Hole(len) => Ok(RangeRead::Hole { len }),
            Answer::ReadError => Err(ProgressiveFailure::new(FailureKind::Input {
                operation: InputOperation::Read,
                cause: std::io::Error::from_raw_os_error(5),
            })),
        }
    }
}
fn driver(state: State, limits: ProgressiveLimits) -> SourceDriver {
    SourceDriver::new(Box::new(Provider(state)), "a.rar".into(), limits, SessionControl::default()).unwrap()
}
fn poll(d: &mut SourceDriver, w: &Waker, buf: &mut [u8]) -> Poll<ProgressiveResult<SourceStep>> {
    d.poll_step(&mut Context::from_waker(w), buf)
}
fn opened(d: &mut SourceDriver, w: &Waker) {
    assert!(matches!(poll(d, w, &mut [0; 4]), Poll::Ready(Ok(SourceStep::VolumeOpened { index: 0, .. }))));
}
#[test]
fn wait_first_and_lost_wake() {
    for immediate in [false, true] {
        let state = State::new(&[Answer::Wait(immediate), Answer::Fill(2)]);
        let mut d = driver(state.clone(), ProgressiveLimits::default());
        let a = Arc::new(Signal::default());
        let wa = Waker::from(a.clone());
        opened(&mut d, &wa);
        assert!(poll(&mut d, &wa, &mut [0; 4]).is_pending());
        let b = Arc::new(Signal::default());
        let wb = Waker::from(b.clone());
        if !immediate {
            assert!(poll(&mut d, &wb, &mut [0; 4]).is_pending());
            state.wake();
            assert_eq!(b.0.load(Ordering::SeqCst), 1);
        }
        assert!(matches!(poll(&mut d, &wb, &mut [0; 4]), Poll::Ready(Ok(SourceStep::Filled { offset: 0, count: 2 }))));
        assert_eq!(state.calls.load(Ordering::SeqCst), 2);
    }
}
#[test]
fn park_without_wake_does_not_retry() {
    let state = State::new(&[Answer::Wait(false)]);
    let mut d = driver(state.clone(), ProgressiveLimits::default());
    let w = Waker::from(Arc::new(Signal::default()));
    opened(&mut d, &w);
    for _ in 0..10_001 {
        assert!(poll(&mut d, &w, &mut [0; 4]).is_pending());
    }
    assert_eq!(state.calls.load(Ordering::SeqCst), 1);
}
#[test]
fn short_fill_advances_exactly() {
    let state = State::new(&[Answer::Fill(2), Answer::Hole(1), Answer::Fill(1)]);
    let mut d = driver(state.clone(), ProgressiveLimits::default());
    let w = Waker::from(Arc::new(Signal::default()));
    opened(&mut d, &w);
    for (offset, count) in [(0, 2), (3, 1)] {
        assert!(
            matches!(poll(&mut d,&w,&mut [0;4]),Poll::Ready(Ok(SourceStep::Filled {offset:o,count:c})) if o==offset && c==count)
        );
        if offset == 0 {
            assert!(matches!(poll(&mut d, &w, &mut [0; 4]), Poll::Ready(Ok(SourceStep::Hole { offset: 2, len: 1 }))));
        }
    }
    assert!(matches!(poll(&mut d, &w, &mut []), Poll::Ready(Ok(SourceStep::Filled { offset: 4, count: 0 }))));
    assert_eq!(state.calls.load(Ordering::SeqCst), 3);
    d.seek(8).unwrap();
    assert!(matches!(poll(&mut d, &w, &mut [0; 4]), Poll::Ready(Ok(SourceStep::EndOfVolume))));
}
#[test]
fn invalid_source_answers() {
    for a in [Answer::Fill(0), Answer::Fill(5), Answer::Hole(0), Answer::Hole(5)] {
        let mut d = driver(State::new(&[a]), ProgressiveLimits::default());
        let w = Waker::from(Arc::new(Signal::default()));
        opened(&mut d, &w);
        assert!(matches!(
            poll(&mut d, &w, &mut [0; 4]),
            Poll::Ready(Err(ProgressiveFailure { kind: FailureKind::SourceContract, .. }))
        ));
    }
    let mut c = CheckedCursor::new(u64::MAX);
    assert!(matches!(c.advance(1).unwrap_err().kind, FailureKind::SourceContract));
    assert_eq!(c.offset(), u64::MAX);
}
#[test]
fn cancel_wakes_parked() {
    let state = State::new(&[Answer::Wait(false)]);
    let control = SessionControl::default();
    let mut d = SourceDriver::new(
        Box::new(Provider(state.clone())),
        "a.rar".into(),
        ProgressiveLimits::default(),
        control.clone(),
    )
    .unwrap();
    let a = Arc::new(Signal::default());
    let w = Waker::from(a.clone());
    opened(&mut d, &w);
    assert!(poll(&mut d, &w, &mut [0; 4]).is_pending());
    control.cancel();
    assert!(a.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(
        poll(&mut d, &w, &mut [0; 4]),
        Poll::Ready(Err(ProgressiveFailure { kind: FailureKind::Canceled, .. }))
    ));
    assert_eq!(state.calls.load(Ordering::SeqCst), 1);
}
#[test]
fn limits_charge_attempts() {
    let state = State::new(&[Answer::Wait(false), Answer::Fill(1)]);
    let limits = ProgressiveLimits { source_requests: 7, ..ProgressiveLimits::default() };
    let mut d = driver(state.clone(), limits);
    let w = Waker::from(Arc::new(Signal::default()));
    opened(&mut d, &w);
    assert!(poll(&mut d, &w, &mut [0; 4]).is_pending());
    state.wake();
    assert!(matches!(
        poll(&mut d, &w, &mut [0; 4]),
        Poll::Ready(Err(ProgressiveFailure {
            kind: FailureKind::Limit { resource: Resource::SourceRequests, .. },
            ..
        }))
    ));
    assert_eq!(state.calls.load(Ordering::SeqCst), 1);
}

#[derive(Clone)]
struct MutableSource {
    info: Arc<Mutex<SourceInfo>>,
    calls: Arc<AtomicUsize>,
}
impl RangeSource for MutableSource {
    fn info(&self) -> SourceInfo {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.info.lock().unwrap()
    }
    fn read_at(&mut self, _: u64, buf: &mut [u8], _: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
        Ok(RangeRead::Filled { count: buf.len() })
    }
    fn backing_files(&self) -> &[std::fs::File] {
        &[]
    }
}
struct MutableProvider(MutableSource);
impl VolumeSource for MutableProvider {
    fn volume(&mut self, _: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
        Ok(VolumeAnswer::Ready(Box::new(self.0.clone())))
    }
}
fn mutable_driver(info: SourceInfo) -> (SourceDriver, Arc<Mutex<SourceInfo>>, Arc<AtomicUsize>) {
    let info = Arc::new(Mutex::new(info));
    let calls = Arc::new(AtomicUsize::new(0));
    let source = MutableSource { info: info.clone(), calls: calls.clone() };
    (
        SourceDriver::new(
            Box::new(MutableProvider(source)),
            "a.rar".into(),
            ProgressiveLimits::default(),
            SessionControl::default(),
        )
        .unwrap(),
        info,
        calls,
    )
}
#[test]
fn changing_info_and_exact_eof() {
    let initial = State::new(&[]).info;
    let w = Waker::from(Arc::new(Signal::default()));
    for (new, changed_kind) in [
        (SourceInfo { extent: 9, ..initial }, false),
        (SourceInfo { extent: 7, ..initial }, false),
        (SourceInfo { length: SourceLength::Final(9), ..initial }, true),
        (SourceInfo { id: SourceId(9), ..initial }, true),
        (SourceInfo { generation: 1, ..initial }, true),
    ] {
        let (mut d, info, _) = mutable_driver(initial);
        opened(&mut d, &w);
        *info.lock().unwrap() = new;
        let Poll::Ready(Err(e)) = poll(&mut d, &w, &mut [0; 4]) else { panic!("invalid metadata accepted") };
        if changed_kind {
            assert!(matches!(e.kind, FailureKind::SourceChanged));
        } else {
            assert!(matches!(e.kind, FailureKind::SourceContract));
        }
    }
    for length in [SourceLength::Advertised(8), SourceLength::Final(8)] {
        let (mut d, _, calls) = mutable_driver(SourceInfo { length, ..initial });
        opened(&mut d, &w);
        d.seek(8).unwrap();
        let before = calls.load(Ordering::SeqCst);
        assert!(matches!(poll(&mut d, &w, &mut [0; 4]), Poll::Ready(Ok(SourceStep::EndOfVolume))));
        assert_eq!(calls.load(Ordering::SeqCst), before);
    }
    let (mut d, info, _) = mutable_driver(initial);
    opened(&mut d, &w);
    info.lock().unwrap().length = SourceLength::Final(8);
    assert!(matches!(poll(&mut d, &w, &mut [0; 4]), Poll::Ready(Ok(SourceStep::Filled { count: 4, .. }))));
    info.lock().unwrap().length = SourceLength::Advertised(8);
    assert!(matches!(
        poll(&mut d, &w, &mut [0; 4]),
        Poll::Ready(Err(ProgressiveFailure { kind: FailureKind::SourceChanged, .. }))
    ));
    let (mut d, _, _) = mutable_driver(SourceInfo { extent: 9, ..initial });
    assert!(matches!(
        poll(&mut d, &w, &mut [0; 4]),
        Poll::Ready(Err(ProgressiveFailure { kind: FailureKind::SourceContract, .. }))
    ));
}
#[test]
fn holes_are_permanent_and_volume_indices_unique() {
    let w = Waker::from(Arc::new(Signal::default()));
    let mut d = driver(State::new(&[Answer::Hole(2), Answer::Fill(1)]), ProgressiveLimits::default());
    opened(&mut d, &w);
    assert!(matches!(poll(&mut d, &w, &mut [0; 4]), Poll::Ready(Ok(SourceStep::Hole { len: 2, .. }))));
    d.seek(1).unwrap();
    assert!(matches!(
        poll(&mut d, &w, &mut [0; 4]),
        Poll::Ready(Err(ProgressiveFailure { kind: FailureKind::SourceChanged, .. }))
    ));
    let mut d = driver(State::new(&[]), ProgressiveLimits::default());
    opened(&mut d, &w);
    assert!(d.select_volume(VolumeRequest { index: 2, expected: "bad".into() }).is_err());
    d.select_volume(VolumeRequest { index: 1, expected: "a.r00".into() }).unwrap();
    assert!(matches!(
        poll(&mut d, &w, &mut [0; 4]),
        Poll::Ready(Err(ProgressiveFailure { kind: FailureKind::SourceContract, .. }))
    ));
    let mut d = driver(State::new(&[Answer::Wait(false)]), ProgressiveLimits::default());
    opened(&mut d, &w);
    assert!(poll(&mut d, &w, &mut [0; 4]).is_pending());
    assert!(d.seek(0).is_err());
    assert!(d.select_volume(VolumeRequest { index: 1, expected: "a.r00".into() }).is_err());
}
struct ErrorProvider;
impl VolumeSource for ErrorProvider {
    fn volume(&mut self, _: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
        unreachable!()
    }
    fn protection(&mut self) -> ProgressiveResult<ProtectionDeclaration> {
        Err(ProgressiveFailure::new(FailureKind::Input {
            operation: InputOperation::Metadata,
            cause: std::io::Error::from_raw_os_error(13),
        }))
    }
}
#[test]
fn input_errors_keep_cause_operation_and_context() {
    let w = Waker::from(Arc::new(Signal::default()));
    let mut d = driver(State::new(&[Answer::ReadError]), ProgressiveLimits::default());
    opened(&mut d, &w);
    d.seek(2).unwrap();
    let Poll::Ready(Err(e)) = poll(&mut d, &w, &mut [0; 4]) else { panic!() };
    assert_eq!(e.context.packed_offset, Some(2));
    assert_eq!(e.context.volume_index, Some(0));
    assert_eq!(e.context.expected, Some("a.rar".into()));
    assert!(std::error::Error::source(&e).is_some());
    assert!(
        matches!(e.kind,FailureKind::Input {operation:InputOperation::Read,cause} if cause.raw_os_error()==Some(5))
    );
    let mut d = SourceDriver::new(
        Box::new(ErrorProvider),
        "a.rar".into(),
        ProgressiveLimits::default(),
        SessionControl::default(),
    )
    .unwrap();
    let Poll::Ready(Err(e)) = poll(&mut d, &w, &mut [0; 4]) else { panic!() };
    assert_eq!(e.context.volume_index, Some(0));
    assert!(
        matches!(e.kind,FailureKind::Input {operation:InputOperation::Metadata,cause} if cause.raw_os_error()==Some(13))
    );
}
struct WaitingVolumes {
    calls: Arc<AtomicUsize>,
    wake: Arc<Mutex<Option<Waker>>>,
    immediate: bool,
}
impl VolumeSource for WaitingVolumes {
    fn volume(&mut self, r: &VolumeRequest, cx: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
        assert_eq!(r.index, 0);
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            *self.wake.lock().unwrap() = Some(cx.waker().clone());
            if self.immediate {
                cx.waker().wake_by_ref();
            }
            Ok(VolumeAnswer::Wait)
        } else {
            Ok(VolumeAnswer::Ready(Box::new(State::new(&[]))))
        }
    }
}
#[test]
fn volume_wait_obeys_same_gate() {
    for immediate in [false, true] {
        let calls = Arc::new(AtomicUsize::new(0));
        let wake = Arc::new(Mutex::new(None));
        let mut d = SourceDriver::new(
            Box::new(WaitingVolumes { calls: calls.clone(), wake: wake.clone(), immediate }),
            "a.rar".into(),
            ProgressiveLimits::default(),
            SessionControl::default(),
        )
        .unwrap();
        let w = Waker::from(Arc::new(Signal::default()));
        assert!(poll(&mut d, &w, &mut [0; 4]).is_pending());
        if !immediate {
            for _ in 0..10_000 {
                assert!(poll(&mut d, &w, &mut [0; 4]).is_pending());
            }
            wake.lock().unwrap().as_ref().unwrap().wake_by_ref();
        }
        opened(&mut d, &w);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
#[test]
fn wake_and_byte_limits_are_separate() {
    let state = State::new(&[Answer::Wait(false)]);
    let mut d = driver(state.clone(), ProgressiveLimits { provider_wakes: 1, ..ProgressiveLimits::default() });
    let w = Waker::from(Arc::new(Signal::default()));
    opened(&mut d, &w);
    assert!(poll(&mut d, &w, &mut [0; 4]).is_pending());
    state.wake();
    state.wake();
    assert!(matches!(
        poll(&mut d, &w, &mut [0; 4]),
        Poll::Ready(Err(ProgressiveFailure {
            kind: FailureKind::Limit { resource: Resource::ProviderWakes, limit: 1, attempted: 2 },
            ..
        }))
    ));
    assert_eq!(state.calls.load(Ordering::SeqCst), 1);
    let state = State::new(&[Answer::Fill(2)]);
    let mut d = driver(state.clone(), ProgressiveLimits { source_bytes: 1, ..ProgressiveLimits::default() });
    opened(&mut d, &w);
    assert!(matches!(
        poll(&mut d, &w, &mut [0; 4]),
        Poll::Ready(Err(ProgressiveFailure { kind: FailureKind::Limit { resource: Resource::SourceBytes, .. }, .. }))
    ));
    assert_eq!(d.cursor.offset(), 0);
    let state = State::new(&[]);
    let mut d = driver(state.clone(), ProgressiveLimits { read_chunk: 3, ..ProgressiveLimits::default() });
    opened(&mut d, &w);
    assert!(matches!(
        poll(&mut d, &w, &mut [0; 4]),
        Poll::Ready(Err(ProgressiveFailure { kind: FailureKind::Limit { resource: Resource::ReadChunk, .. }, .. }))
    ));
    assert_eq!(state.calls.load(Ordering::SeqCst), 0);
}

struct DeclaredProvider {
    declaration: ProtectionDeclaration,
    state: State,
}
impl VolumeSource for DeclaredProvider {
    fn volume(&mut self, _: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
        Ok(VolumeAnswer::Ready(Box::new(self.state.clone())))
    }
    fn protection(&mut self) -> ProgressiveResult<ProtectionDeclaration> {
        Ok(self.declaration.clone())
    }
}
fn inventory() -> ProtectionInventory {
    ProtectionInventory {
        volumes: vec![ProtectedVolume { index: 0, name: "a.rar".into(), backing: VolumeBacking::NonFile }],
        auxiliary_paths: vec![ProtectedPath { path: "future.r00".into(), file: None }],
    }
}
#[test]
fn protection_structural_limits_and_snapshot() {
    let mut usage = Usage::new(ProgressiveLimits::default());
    assert!(validate_inventory(&ProtectionInventory::default(), &mut usage).is_err());
    let mut i = inventory();
    i.volumes.push(i.volumes[0].clone());
    assert!(validate_inventory(&i, &mut usage).is_err());
    let mut i = inventory();
    i.auxiliary_paths.push(i.auxiliary_paths[0].clone());
    assert!(validate_inventory(&i, &mut usage).is_err());
    let a = inventory();
    let mut b = a.clone();
    assert!(same_inventory(&a, &b, &mut usage).unwrap());
    b.auxiliary_paths[0].path = "different".into();
    assert!(!same_inventory(&a, &b, &mut usage).unwrap());
    let mut i = inventory();
    i.auxiliary_paths[0].path = std::path::PathBuf::with_capacity(1024);
    i.auxiliary_paths[0].path.push("x");
    let mut usage = Usage::new(ProgressiveLimits { metadata_bytes: 512, ..ProgressiveLimits::default() });
    assert!(matches!(
        validate_inventory(&i, &mut usage).unwrap_err().kind,
        FailureKind::Limit { resource: Resource::MetadataBytes, .. }
    ));
    let mut i = inventory();
    i.auxiliary_paths = Vec::with_capacity(4097);
    i.auxiliary_paths.push(ProtectedPath { path: "x".into(), file: None });
    let mut usage = Usage::new(ProgressiveLimits { metadata_bytes: 512, ..ProgressiveLimits::default() });
    assert!(matches!(
        validate_inventory(&i, &mut usage).unwrap_err().kind,
        FailureKind::Limit { resource: Resource::MetadataBytes, .. }
    ));
    let w = Waker::from(Arc::new(Signal::default()));
    let provider = DeclaredProvider {
        declaration: ProtectionDeclaration::Complete { epoch: 1, inventory: inventory() },
        state: State::new(&[]),
    };
    let mut d =
        SourceDriver::new(Box::new(provider), "a.rar".into(), ProgressiveLimits::default(), SessionControl::default())
            .unwrap();
    opened(&mut d, &w);
    d.select_volume(VolumeRequest { index: 1, expected: "a.r00".into() }).unwrap();
    assert!(matches!(
        poll(&mut d, &w, &mut [0; 4]),
        Poll::Ready(Err(ProgressiveFailure { kind: FailureKind::SourceContract, .. }))
    ));
}
#[test]
fn zero_read_never_calls_providers() {
    let state = State::new(&[]);
    let mut d = driver(state.clone(), ProgressiveLimits { source_requests: 0, ..ProgressiveLimits::default() });
    let w = Waker::from(Arc::new(Signal::default()));
    assert!(matches!(poll(&mut d, &w, &mut []), Poll::Ready(Ok(SourceStep::Filled { offset: 0, count: 0 }))));
    assert_eq!(state.calls.load(Ordering::SeqCst), 0);
}
#[test]
fn adjacent_holes_use_one_interval() {
    let mut d = driver(
        State::new(&[Answer::Hole(1), Answer::Hole(1)]),
        ProgressiveLimits { hole_intervals: 0, ..ProgressiveLimits::default() },
    );
    let w = Waker::from(Arc::new(Signal::default()));
    opened(&mut d, &w);
    for offset in [0, 1] {
        assert!(matches!(poll(&mut d,&w,&mut [0;4]),Poll::Ready(Ok(SourceStep::Hole {offset:o,len:1})) if o==offset));
    }
    assert_eq!(d.holes, [(0, 2)]);
}

#[test]
fn usage_overflow_and_hard_ceilings() {
    let limits = ProgressiveLimits {
        volume_handles: u64::MAX,
        protection_paths: u64::MAX,
        protection_path_bytes: u64::MAX,
        kdf_exponent: u64::MAX,
        source_bytes: u64::MAX,
        ..ProgressiveLimits::default()
    };
    let mut usage = Usage::new(limits);
    for (resource, cap) in [
        (Resource::VolumeHandles, 4096),
        (Resource::ProtectionPaths, 4096),
        (Resource::ProtectionPathBytes, 1 << 20),
        (Resource::KdfExponent, 20),
    ] {
        assert!(usage.check(resource, cap).is_ok());
        assert!(matches!(usage.check(resource,cap+1).unwrap_err().kind,FailureKind::Limit {limit,..} if limit==cap));
    }
    usage.charge(Resource::SourceBytes, u64::MAX).unwrap();
    assert!(matches!(
        usage.charge(Resource::SourceBytes, 1).unwrap_err().kind,
        FailureKind::Limit { resource: Resource::SourceBytes, attempted: u64::MAX, .. }
    ));
}
#[test]
fn typed_evidence_widths_and_layout() {
    use crate::progressive::{ChecksumValue, FailureContext, MemberId};
    for (value, len) in [
        (ChecksumValue::Crc32([0; 4]), 4),
        (ChecksumValue::Blake2sp([0; 32]), 32),
        (ChecksumValue::Sha1([0; 20]), 20),
        (ChecksumValue::Sha256([0; 32]), 32),
    ] {
        assert_eq!(value.as_bytes().len(), len);
    }
    let checksum = FailureKind::ChecksumMismatch {
        algorithm: crate::progressive::ChecksumAlgorithm::Crc32,
        scope: crate::progressive::ChecksumScope::Member,
        expected: Box::new(ChecksumValue::Crc32([0; 4])),
        actual: Box::new(ChecksumValue::Crc32([1; 4])),
    };
    assert!(
        matches!(checksum, FailureKind::ChecksumMismatch {expected,actual,..} if expected.as_bytes()==[0;4] && actual.as_bytes()==[1;4])
    );
    fn assert_send<T: Send>() {}
    assert_send::<SourceDriver>();
    assert_send::<SessionControl>();
    println!(
        "layout bytes: MemberId={} FailureContext={} FailureKind={} ProgressiveFailure={} ChecksumValue={}",
        std::mem::size_of::<MemberId>(),
        std::mem::size_of::<FailureContext>(),
        std::mem::size_of::<FailureKind>(),
        std::mem::size_of::<ProgressiveFailure>(),
        std::mem::size_of::<ChecksumValue>()
    );
}
#[test]
fn missing_abort_and_declared_tail_are_distinct() {
    struct Terminal(bool);
    impl VolumeSource for Terminal {
        fn volume(&mut self, _: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
            Ok(if self.0 { VolumeAnswer::Abort } else { VolumeAnswer::Missing })
        }
    }
    let w = Waker::from(Arc::new(Signal::default()));
    for abort in [false, true] {
        let mut d = SourceDriver::new(
            Box::new(Terminal(abort)),
            "a.rar".into(),
            ProgressiveLimits::default(),
            SessionControl::default(),
        )
        .unwrap();
        let Poll::Ready(Err(e)) = poll(&mut d, &w, &mut [0; 4]) else { panic!() };
        assert_eq!(e.context.volume_index, Some(0));
        if abort {
            assert!(matches!(e.kind, FailureKind::Canceled))
        } else {
            assert!(matches!(e.kind, FailureKind::MissingVolume))
        }
    }
    for length in [SourceLength::Advertised(8), SourceLength::Final(8)] {
        for answer in [Answer::Fill(0), Answer::Fill(2), Answer::Hole(2)] {
            let mut state = State::new(&[answer]);
            state.info.length = length;
            let mut d = driver(state, ProgressiveLimits::default());
            opened(&mut d, &w);
            d.seek(7).unwrap();
            assert!(matches!(
                poll(&mut d, &w, &mut [0; 4]),
                Poll::Ready(Err(ProgressiveFailure { kind: FailureKind::SourceContract, .. }))
            ));
        }
    }
}
#[test]
fn thread_wake_retries_and_cancel_method_wakes() {
    let state = State::new(&[Answer::Wait(false), Answer::Fill(1)]);
    let mut d = driver(state.clone(), ProgressiveLimits::default());
    let signal = Arc::new(Signal::default());
    let w = Waker::from(signal.clone());
    opened(&mut d, &w);
    assert!(poll(&mut d, &w, &mut [0; 4]).is_pending());
    std::thread::spawn(move || state.wake()).join().unwrap();
    assert_eq!(signal.0.load(Ordering::SeqCst), 1);
    assert!(matches!(poll(&mut d, &w, &mut [0; 4]), Poll::Ready(Ok(SourceStep::Filled { count: 1, .. }))));
    d.cancel();
    assert!(matches!(
        poll(&mut d, &w, &mut [0; 4]),
        Poll::Ready(Err(ProgressiveFailure { kind: FailureKind::Canceled, .. }))
    ));
}

struct OneSource(Option<Box<dyn RangeSource>>);
impl VolumeSource for OneSource {
    fn volume(&mut self, _: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
        Ok(VolumeAnswer::Ready(self.0.take().unwrap()))
    }
}
struct ChangingRead {
    info: SourceInfo,
}
impl RangeSource for ChangingRead {
    fn info(&self) -> SourceInfo {
        self.info
    }
    fn backing_files(&self) -> &[std::fs::File] {
        &[]
    }
    fn read_at(&mut self, _: u64, buf: &mut [u8], _: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
        self.info.generation += 1;
        Ok(RangeRead::Filled { count: buf.len() })
    }
}
#[test]
fn metadata_is_rechecked_after_read_before_advance() {
    let source = ChangingRead { info: State::new(&[]).info };
    let mut d = SourceDriver::new(
        Box::new(OneSource(Some(Box::new(source)))),
        "a.rar".into(),
        ProgressiveLimits::default(),
        SessionControl::default(),
    )
    .unwrap();
    let w = Waker::from(Arc::new(Signal::default()));
    opened(&mut d, &w);
    assert!(matches!(
        poll(&mut d, &w, &mut [0; 4]),
        Poll::Ready(Err(ProgressiveFailure { kind: FailureKind::SourceChanged, .. }))
    ));
    assert_eq!(d.cursor.offset(), 0);
}

struct EvolvingVolumes {
    declarations: std::collections::VecDeque<ProtectionDeclaration>,
    requests: Arc<Mutex<Vec<VolumeRequest>>>,
}
impl VolumeSource for EvolvingVolumes {
    fn protection(&mut self) -> ProgressiveResult<ProtectionDeclaration> {
        Ok(if self.declarations.len() > 1 {
            self.declarations.pop_front().unwrap()
        } else {
            self.declarations.front().unwrap().clone()
        })
    }
    fn volume(&mut self, r: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
        self.requests.lock().unwrap().push(r.clone());
        let mut state = State::new(&[Answer::Fill(1)]);
        state.info.id = SourceId(u128::from(r.index) + 1);
        Ok(VolumeAnswer::Ready(Box::new(state)))
    }
}
fn two_volume_inventory() -> ProtectionInventory {
    let mut i = inventory();
    i.volumes.push(ProtectedVolume { index: 1, name: "a.r00".into(), backing: VolumeBacking::NonFile });
    i
}
#[test]
fn protection_freeze_upgrade_and_successful_selection() {
    let w = Waker::from(Arc::new(Signal::default()));
    let complete = || ProtectionDeclaration::Complete { epoch: 1, inventory: two_volume_inventory() };
    let mut changed_path = two_volume_inventory();
    changed_path.auxiliary_paths[0].path = "different".into();
    let mut reordered = two_volume_inventory();
    reordered.volumes.reverse();
    for (next, allowed) in [
        (ProtectionDeclaration::Opaque, false),
        (ProtectionDeclaration::Complete { epoch: 2, inventory: two_volume_inventory() }, false),
        (ProtectionDeclaration::Complete { epoch: 1, inventory: changed_path }, false),
        (ProtectionDeclaration::Complete { epoch: 1, inventory: reordered }, true),
    ] {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let p = EvolvingVolumes { declarations: [complete(), next].into(), requests: requests.clone() };
        let mut d =
            SourceDriver::new(Box::new(p), "a.rar".into(), ProgressiveLimits::default(), SessionControl::default())
                .unwrap();
        opened(&mut d, &w);
        assert!(matches!(poll(&mut d, &w, &mut [0; 4]), Poll::Ready(Ok(SourceStep::Filled { offset: 0, count: 1 }))));
        d.select_volume(VolumeRequest { index: 1, expected: "a.r00".into() }).unwrap();
        if allowed {
            assert!(matches!(
                poll(&mut d, &w, &mut [0; 4]),
                Poll::Ready(Ok(SourceStep::VolumeOpened { index: 1, id: SourceId(2) }))
            ));
            assert!(matches!(
                poll(&mut d, &w, &mut [0; 4]),
                Poll::Ready(Ok(SourceStep::Filled { offset: 0, count: 1 }))
            ));
            assert_eq!(requests.lock().unwrap().len(), 2);
        } else {
            assert!(matches!(
                poll(&mut d, &w, &mut [0; 4]),
                Poll::Ready(Err(ProgressiveFailure { kind: FailureKind::SourceChanged, .. }))
            ));
            assert_eq!(requests.lock().unwrap().len(), 1);
        }
    }
    for include_prior in [false, true] {
        let mut i = two_volume_inventory();
        if !include_prior {
            i.volumes.remove(0);
        }
        let p = EvolvingVolumes {
            declarations: [ProtectionDeclaration::Opaque, ProtectionDeclaration::Complete { epoch: 1, inventory: i }]
                .into(),
            requests: Arc::new(Mutex::new(Vec::new())),
        };
        let mut d =
            SourceDriver::new(Box::new(p), "a.rar".into(), ProgressiveLimits::default(), SessionControl::default())
                .unwrap();
        opened(&mut d, &w);
        d.select_volume(VolumeRequest { index: 1, expected: "a.r00".into() }).unwrap();
        if include_prior {
            assert!(matches!(
                poll(&mut d, &w, &mut [0; 4]),
                Poll::Ready(Ok(SourceStep::VolumeOpened { index: 1, .. }))
            ));
        } else {
            assert!(matches!(
                poll(&mut d, &w, &mut [0; 4]),
                Poll::Ready(Err(ProgressiveFailure { kind: FailureKind::SourceContract, .. }))
            ));
        }
    }
}

#[test]
fn source_bookkeeping_exact_under_and_overflow() {
    let w = Waker::from(Arc::new(Signal::default()));
    // First insertion has zero work. A descending second insertion charges one
    // binary-search comparison, one merge-boundary comparison, one shifted slot,
    // and one possible allocator-copy slot when growing capacity from one to two.
    for (limit, pass) in [(4, true), (3, false)] {
        let mut d = driver(
            State::new(&[Answer::Hole(1), Answer::Hole(1)]),
            ProgressiveLimits { source_bookkeeping: limit, hole_intervals: 0, ..ProgressiveLimits::default() },
        );
        opened(&mut d, &w);
        d.seek(6).unwrap();
        assert!(matches!(poll(&mut d, &w, &mut [0; 4]), Poll::Ready(Ok(SourceStep::Hole { offset: 6, len: 1 }))));
        d.seek(4).unwrap();
        let result = poll(&mut d, &w, &mut [0; 4]);
        if pass {
            assert!(matches!(result, Poll::Ready(Ok(SourceStep::Hole { offset: 4, len: 1 }))));
            assert_eq!(d.holes, [(4, 5), (6, 7)]);
            assert_eq!(d.cursor.offset(), 5);
        } else {
            assert!(matches!(
                result,
                Poll::Ready(Err(ProgressiveFailure {
                    kind: FailureKind::Limit { resource: Resource::SourceBookkeeping, limit: 3, attempted: 4 },
                    ..
                }))
            ));
            assert_eq!(d.holes, [(6, 7)]);
            assert_eq!(d.cursor.offset(), 4);
        }
    }
    let mut usage = Usage::new(ProgressiveLimits { source_bookkeeping: u64::MAX, ..ProgressiveLimits::default() });
    usage.charge(Resource::SourceBookkeeping, u64::MAX).unwrap();
    assert!(matches!(
        usage.charge(Resource::SourceBookkeeping, 1).unwrap_err().kind,
        FailureKind::Limit { resource: Resource::SourceBookkeeping, attempted: u64::MAX, .. }
    ));
}
struct ManyHoles;
impl RangeSource for ManyHoles {
    fn info(&self) -> SourceInfo {
        SourceInfo { id: SourceId(1), generation: 0, extent: 131074, length: SourceLength::Final(131074) }
    }
    fn backing_files(&self) -> &[std::fs::File] {
        &[]
    }
    fn read_at(&mut self, _: u64, _: &mut [u8], _: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
        Ok(RangeRead::Hole { len: 1 })
    }
}
#[test]
fn source_history_has_no_hidden_per_volume_member_quota() {
    let mut d = SourceDriver::new(
        Box::new(OneSource(Some(Box::new(ManyHoles)))),
        "a.rar".into(),
        ProgressiveLimits { hole_intervals: 0, ..ProgressiveLimits::default() },
        SessionControl::default(),
    )
    .unwrap();
    let w = Waker::from(Arc::new(Signal::default()));
    opened(&mut d, &w);
    for n in 0..65_537 {
        d.seek(2 * n).unwrap();
        assert!(matches!(poll(&mut d,&w,&mut [0;1]),Poll::Ready(Ok(SourceStep::Hole {offset,len:1})) if offset==2*n));
    }
    assert_eq!(d.holes.len(), 65_537);
}

#[test]
fn id_and_coverage_bookkeeping_exact_under_preserves_state() {
    let w = Waker::from(Arc::new(Signal::default()));
    for (limit, pass) in [(2, true), (1, false)] {
        let p = EvolvingVolumes {
            declarations: [ProtectionDeclaration::Opaque].into(),
            requests: Arc::new(Mutex::new(Vec::new())),
        };
        let mut d = SourceDriver::new(
            Box::new(p),
            "a.rar".into(),
            ProgressiveLimits { source_bookkeeping: limit, ..ProgressiveLimits::default() },
            SessionControl::default(),
        )
        .unwrap();
        opened(&mut d, &w);
        d.select_volume(VolumeRequest { index: 1, expected: "a.r00".into() }).unwrap();
        let result = poll(&mut d, &w, &mut [0; 4]);
        if pass {
            assert!(matches!(result, Poll::Ready(Ok(SourceStep::VolumeOpened { index: 1, .. }))));
            assert_eq!(d.admitted.len(), 2);
        } else {
            assert!(matches!(
                result,
                Poll::Ready(Err(ProgressiveFailure {
                    kind: FailureKind::Limit { resource: Resource::SourceBookkeeping, limit: 1, attempted: 2 },
                    ..
                }))
            ));
            assert_eq!(d.admitted.len(), 1);
            assert_eq!(d.admitted[0].1, SourceId(1));
            assert!(d.source.is_none());
        }
        assert_eq!(d.cursor.offset(), 0);
    }
    for (limit, pass) in [(14, true), (13, false)] {
        let mut d = driver(State::new(&[]), ProgressiveLimits::default());
        opened(&mut d, &w);
        // Exercise the real coverage primitive with a fresh accounting scope in the
        // test; production never resets Usage across volume changes.
        d.protection = ProtectionDeclaration::Complete { epoch: 1, inventory: two_volume_inventory() };
        d.usage = Usage::new(ProgressiveLimits { source_bookkeeping: limit, ..ProgressiveLimits::default() });
        let candidate = d.protection.clone();
        let result = d.check_inventory_admitted(&candidate);
        assert_eq!(result.is_ok(), pass);
        if !pass {
            assert!(matches!(
                result.unwrap_err().kind,
                FailureKind::Limit { resource: Resource::SourceBookkeeping, limit: 13, attempted: 14 }
            ));
        }
        assert_eq!(d.admitted.len(), 1);
        assert_eq!(d.cursor.offset(), 0);
    }
}
#[test]
fn fallible_metadata_sort_orders_adversarial_input_and_bounds_work() {
    let mut items: Vec<u32> = (0..4096).rev().collect();
    let mut usage = Usage::new(ProgressiveLimits::default());
    let compare = |a: &u32, b: &u32, u: &mut Usage| {
        u.charge(Resource::SourceBookkeeping, 1)?;
        Ok(a.cmp(b))
    };
    budget_sort(&mut items, &mut usage, compare).unwrap();
    assert!(items.iter().copied().eq(0..4096));
    let mut items = [2, 1];
    let mut usage = Usage::new(ProgressiveLimits { source_bookkeeping: 0, ..ProgressiveLimits::default() });
    assert!(matches!(
        budget_sort(&mut items, &mut usage, compare).unwrap_err().kind,
        FailureKind::Limit { resource: Resource::SourceBookkeeping, .. }
    ));
    assert_eq!(items, [2, 1]);
}
