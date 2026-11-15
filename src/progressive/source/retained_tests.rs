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
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct Probe {
    live: Arc<Mutex<SourceInfo>>,
    drops: Arc<AtomicUsize>,
    offsets: Arc<Mutex<Vec<u64>>>,
    hole: Arc<AtomicBool>,
}
impl Drop for Probe {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}
impl RangeSource for Probe {
    fn info(&self) -> SourceInfo {
        *self.live.lock().unwrap()
    }
    fn backing_files(&self) -> &[File] {
        &[]
    }
    fn read_at(&mut self, offset: u64, buf: &mut [u8], _: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
        self.offsets.lock().unwrap().push(offset);
        if self.hole.load(Ordering::SeqCst) {
            Ok(RangeRead::Hole { len: 1 })
        } else {
            buf[0] = 7;
            Ok(RangeRead::Filled { count: 1 })
        }
    }
}
struct Volumes {
    sources: Vec<Option<Box<dyn RangeSource>>>,
    requests: Arc<Mutex<Vec<u32>>>,
}
impl VolumeSource for Volumes {
    fn volume(&mut self, request: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
        self.requests.lock().unwrap().push(request.index);
        Ok(VolumeAnswer::Ready(self.sources[request.index as usize].take().unwrap()))
    }
}
fn probe(id: u128) -> Probe {
    Probe {
        live: Arc::new(Mutex::new(SourceInfo {
            id: SourceId(id),
            generation: 0,
            extent: 8,
            length: SourceLength::Advertised(8),
        })),
        drops: Arc::new(AtomicUsize::new(0)),
        offsets: Arc::new(Mutex::new(vec![])),
        hole: Arc::new(AtomicBool::new(false)),
    }
}
fn setup(retained: bool, limit: u64, sources: Vec<Box<dyn RangeSource>>) -> (SourceDriver, Arc<Mutex<Vec<u32>>>) {
    let requests = Arc::new(Mutex::new(vec![]));
    let provider = Box::new(Volumes { sources: sources.into_iter().map(Some).collect(), requests: requests.clone() });
    let limits = ProgressiveLimits {
        volume_handles: limit,
        source_requests: if retained { 1_000_000 } else { 11 },
        ..Default::default()
    };
    let d = if retained {
        SourceDriver::new_retained(provider, "v0".into(), limits, SessionControl::default())
    } else {
        SourceDriver::new(provider, "v0".into(), limits, SessionControl::default())
    }
    .unwrap();
    (d, requests)
}
fn poll(d: &mut SourceDriver) -> Poll<ProgressiveResult<SourceStep>> {
    d.poll_step(&mut Context::from_waker(Waker::noop()), &mut [0; 8])
}
fn open(d: &mut SourceDriver, index: u32) {
    assert!(matches!(poll(d), Poll::Ready(Ok(SourceStep::VolumeOpened {index:i,..})) if i==index));
}
fn select(d: &mut SourceDriver, index: u32) {
    d.select_volume(VolumeRequest { index, expected: format!("v{index}").into() }).unwrap();
}
fn limit3(result: ProgressiveResult<()>) {
    assert!(matches!(
        result.unwrap_err().kind,
        FailureKind::Limit { resource: Resource::VolumeHandles, limit: 2, attempted: 3 }
    ));
}

// Catches dropping/reopening an original, losing its holes, or using selected cursor as high-water.
#[test]
fn retained_revisit_keeps_owner_and_high_water() {
    let a = probe(10);
    a.hole.store(true, Ordering::SeqCst);
    let hole = a.hole.clone();
    let drops = a.drops.clone();
    let offsets = a.offsets.clone();
    let b = probe(11);
    let bdrop = b.drops.clone();
    let c = probe(12);
    let cdrop = c.drops.clone();
    let (mut d, requests) = setup(true, 64, vec![Box::new(a), Box::new(b), Box::new(c)]);
    open(&mut d, 0);
    assert!(matches!(poll(&mut d), Poll::Ready(Ok(SourceStep::Hole { offset: 0, len: 1 }))));
    select(&mut d, 1);
    open(&mut d, 1);
    assert!(d.select_volume(VolumeRequest { index: 0, expected: "wrong".into() }).is_err());
    select(&mut d, 0);
    assert!(matches!(
        d.poll_step(&mut Context::from_waker(Waker::noop()), &mut []),
        Poll::Ready(Ok(SourceStep::Filled { count: 0, .. }))
    ));
    open(&mut d, 0);
    assert!(matches!(poll(&mut d), Poll::Ready(Ok(SourceStep::Hole { offset: 0, len: 1 }))));
    assert_eq!(*offsets.lock().unwrap(), [0, 0]);
    select(&mut d, 2);
    open(&mut d, 2);
    assert_eq!(*requests.lock().unwrap(), [0, 1, 2]);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert_eq!(bdrop.load(Ordering::SeqCst), 0);
    assert_eq!(cdrop.load(Ordering::SeqCst), 0);
    select(&mut d, 0);
    open(&mut d, 0);
    hole.store(false, Ordering::SeqCst);
    assert!(matches!(poll(&mut d), Poll::Ready(Err(ProgressiveFailure { kind: FailureKind::SourceChanged, .. }))));
    assert_eq!(*requests.lock().unwrap(), [0, 1, 2]);
    drop(d);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(bdrop.load(Ordering::SeqCst), 1);
    assert_eq!(cdrop.load(Ordering::SeqCst), 1);
}
// Catches rewriting immutable admission snapshots with live source facts.
#[test]
fn retained_live_info_does_not_rewrite_admission() {
    let a = probe(10);
    let live = a.live.clone();
    live.lock().unwrap().extent = 2;
    let (mut d, _) = setup(true, 64, vec![Box::new(a)]);
    open(&mut d, 0);
    {
        let mut i = live.lock().unwrap();
        i.extent = 8;
        i.length = SourceLength::Final(8);
    }
    assert!(matches!(poll(&mut d), Poll::Ready(Ok(SourceStep::Filled { .. }))));
    assert_eq!(
        d.observed_info(0),
        Some(SourceInfo { id: SourceId(10), generation: 0, extent: 2, length: SourceLength::Advertised(8) })
    );
}
// Catches treating non-file objects as free, or omitting live replacement objects.
#[test]
fn retained_nonfile_and_replacement_object_limit() {
    let (mut d, requests) = setup(true, 2, vec![Box::new(probe(10)), Box::new(probe(11)), Box::new(probe(12))]);
    open(&mut d, 0);
    select(&mut d, 1);
    open(&mut d, 1);
    select(&mut d, 2);
    assert!(matches!(
        poll(&mut d),
        Poll::Ready(Err(ProgressiveFailure {
            kind: FailureKind::Limit { resource: Resource::VolumeHandles, limit: 2, attempted: 3 },
            ..
        }))
    ));
    assert_eq!(*requests.lock().unwrap(), [0, 1]);
    let (mut d, requests) = setup(true, 2, vec![Box::new(probe(10)), Box::new(probe(11))]);
    open(&mut d, 0);
    d.supply_replacement(0, Box::new(probe(12))).unwrap();
    limit3(d.supply_replacement(0, Box::new(probe(11))));
    select(&mut d, 1);
    assert!(matches!(poll(&mut d), Poll::Ready(Err(_))));
    assert_eq!(*requests.lock().unwrap(), [0]);
}
// Catches cloning a native guard before accounting all retained backing descriptors.
#[test]
fn retained_native_counts_before_clone() {
    let dir = tempfile::tempdir().unwrap();
    let mut sources: Vec<Box<dyn RangeSource>> = vec![];
    for name in ["a", "b", "c"] {
        let path = dir.path().join(name);
        std::fs::write(&path, b"12345678").unwrap();
        sources.push(Box::new(ImmutableFileSource::open(&path).unwrap()));
    }
    let (mut d, _) = setup(true, 4, sources);
    open(&mut d, 0);
    select(&mut d, 1);
    open(&mut d, 1);
    assert_eq!(d.native.handle_count(), 2);
    assert_eq!(d.native.handle_count() + d.backing_count() + d.retained_backing_count().unwrap(), 4);
    let mut lease = d.begin_original_read(0, 2, OriginalReadPurpose::Discovery).unwrap();
    assert!(matches!(
        lease_poll(&mut d, &mut lease, Waker::noop(), &mut [0; 2]),
        Poll::Ready(Ok(SourceStep::Filled { offset: 2, count: 2 }))
    ));
    assert_eq!(d.original_count(), 2);
    assert_eq!(d.native.handle_count() + d.backing_count() + d.retained_backing_count().unwrap(), 4);
    eprintln!("retained native peak: objects=2 backing=2 guards=2 descriptors=4; lease adds zero sources/descriptors");
    select(&mut d, 2);
    assert!(matches!(
        poll(&mut d),
        Poll::Ready(Err(ProgressiveFailure {
            kind: FailureKind::Limit { resource: Resource::VolumeHandles, limit: 4, attempted: 5 },
            ..
        }))
    ));
    assert_eq!(d.native.handle_count(), 2);
}
// Catches leaking a rejected duplicate or reacquiring it after a terminal failure.
#[test]
fn retained_rejected_candidate_drops_once() {
    let a = probe(10);
    let old = a.drops.clone();
    let b = probe(10);
    let rejected = b.drops.clone();
    let (mut d, requests) = setup(true, 64, vec![Box::new(a), Box::new(b)]);
    open(&mut d, 0);
    select(&mut d, 1);
    assert!(matches!(poll(&mut d), Poll::Ready(Err(_))));
    assert!(matches!(poll(&mut d), Poll::Ready(Err(_))));
    assert_eq!(*requests.lock().unwrap(), [0, 1]);
    assert_eq!(rejected.load(Ordering::SeqCst), 1);
    assert_eq!(old.load(Ordering::SeqCst), 0);
    drop(d);
    assert_eq!(old.load(Ordering::SeqCst), 1);
    assert_eq!(rejected.load(Ordering::SeqCst), 1);
}
// Catches a legacy retention branch or extra provider/info/read accounting.
#[test]
fn legacy_selection_still_drops_and_matches_counters() {
    let a = probe(10);
    let drops = a.drops.clone();
    let (mut d, requests) = setup(false, 64, vec![Box::new(a), Box::new(probe(11))]);
    open(&mut d, 0);
    select(&mut d, 1);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    open(&mut d, 1);
    assert_eq!(*requests.lock().unwrap(), [0, 1]);
    assert!(matches!(poll(&mut d), Poll::Ready(Ok(SourceStep::Filled { offset: 0, count: 1 }))));
    assert!(matches!(
        d.shared_usage().charge(Resource::SourceRequests, 1).unwrap_err().kind,
        FailureKind::Limit { resource: Resource::SourceRequests, limit: 11, attempted: 12 }
    ));
}

// Catches freeing legacy interval capacity and introducing another allocation/debit.
#[test]
fn legacy_selection_reuses_empty_interval_capacity() {
    let a = probe(10);
    a.hole.store(true, Ordering::SeqCst);
    let b = probe(11);
    b.hole.store(true, Ordering::SeqCst);
    let (mut d, _) = setup(false, 64, vec![Box::new(a), Box::new(b)]);
    // This scenario focuses allocation debits rather than the request-boundary test above.
    d.usage = Usage::new(ProgressiveLimits::default());
    open(&mut d, 0);
    assert!(matches!(poll(&mut d), Poll::Ready(Ok(SourceStep::Hole { .. }))));
    select(&mut d, 1);
    open(&mut d, 1);
    d.usage = Usage::new(ProgressiveLimits { metadata_bytes: 0, ..Default::default() });
    assert!(matches!(poll(&mut d), Poll::Ready(Ok(SourceStep::Hole { offset: 0, len: 1 }))));
}

// Catches moving owners or replacing the gate before selection allocation admission.
#[test]
fn retained_selection_gate_failure_preserves_ownership() {
    let a = probe(10);
    let adrop = a.drops.clone();
    let b = probe(11);
    let bdrop = b.drops.clone();
    let (mut d, requests) = setup(true, 64, vec![Box::new(a), Box::new(b)]);
    open(&mut d, 0);
    select(&mut d, 1);
    open(&mut d, 1);
    select(&mut d, 0);
    open(&mut d, 0);
    let gate = d.wake.clone();
    d.usage = Usage::new(ProgressiveLimits { metadata_bytes: 2, ..Default::default() });
    assert!(matches!(
        d.select_volume(VolumeRequest { index: 1, expected: "v1".into() }).unwrap_err().kind,
        FailureKind::Limit { resource: Resource::MetadataBytes, .. }
    ));
    assert!(Arc::ptr_eq(&gate, &d.wake));
    assert_eq!(d.request.index, 0);
    assert!(!d.failed);
    assert_eq!(adrop.load(Ordering::SeqCst), 0);
    assert_eq!(bdrop.load(Ordering::SeqCst), 0);
    assert_eq!(d.cursor.offset(), 0);
    assert_eq!(d.original.as_ref().unwrap().live.id, SourceId(10));
    assert_eq!(*requests.lock().unwrap(), [0, 1]);
    // Task2 fresh range/cancellation admission is separate from failed selection.
    d.usage = Usage::new(ProgressiveLimits::default());
    assert!(matches!(poll(&mut d), Poll::Ready(Ok(SourceStep::Filled { offset: 0, count: 1 }))));
    assert_eq!(*requests.lock().unwrap(), [0, 1]);
    drop(d);
    assert_eq!(adrop.load(Ordering::SeqCst), 1);
    assert_eq!(bdrop.load(Ordering::SeqCst), 1);
}

#[derive(Clone)]
struct LeaseProbe {
    info: Arc<Mutex<SourceInfo>>,
    calls: Arc<AtomicUsize>,
    wakes: Arc<Mutex<Vec<Waker>>>,
    answers: Arc<Mutex<std::collections::VecDeque<LeaseAnswer>>>,
    cancel: Option<SessionControl>,
}
#[derive(Clone, Copy)]
enum LeaseAnswer {
    Wait(bool),
    Fill(usize),
    Hole(u64),
    Change,
    Cancel,
    Error,
}
impl LeaseProbe {
    fn new(id: u128, answers: &[LeaseAnswer]) -> Self {
        Self {
            info: Arc::new(Mutex::new(SourceInfo {
                id: SourceId(id),
                generation: 0,
                extent: 8,
                length: SourceLength::Final(8),
            })),
            calls: Arc::new(AtomicUsize::new(0)),
            wakes: Arc::new(Mutex::new(vec![])),
            answers: Arc::new(Mutex::new(answers.iter().copied().collect())),
            cancel: None,
        }
    }
    fn wake(&self, n: usize) {
        let w = self.wakes.lock().unwrap()[n].clone();
        w.wake();
    }
}
impl RangeSource for LeaseProbe {
    fn info(&self) -> SourceInfo {
        *self.info.lock().unwrap()
    }
    fn backing_files(&self) -> &[File] {
        &[]
    }
    fn read_at(&mut self, offset: u64, buf: &mut [u8], cx: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let answer = self.answers.lock().unwrap().pop_front().unwrap_or(LeaseAnswer::Fill(1));
        match answer {
            LeaseAnswer::Wait(now) => {
                self.wakes.lock().unwrap().push(cx.waker().clone());
                if now {
                    cx.waker().wake_by_ref();
                }
                Ok(RangeRead::NotYet)
            }
            LeaseAnswer::Hole(len) => Ok(RangeRead::Hole { len }),
            LeaseAnswer::Change => {
                self.info.lock().unwrap().generation += 1;
                Ok(RangeRead::Filled { count: 1 })
            }
            LeaseAnswer::Cancel => {
                self.cancel.as_ref().unwrap().cancel();
                Ok(RangeRead::Filled { count: 1 })
            }
            LeaseAnswer::Error => Err(contract()),
            LeaseAnswer::Fill(count) => {
                for (i, b) in buf.iter_mut().enumerate() {
                    *b = (offset + i as u64) as u8;
                }
                Ok(RangeRead::Filled { count })
            }
        }
    }
}
fn lease_poll(
    d: &mut SourceDriver,
    r: &mut OriginalRead,
    w: &Waker,
    buf: &mut [u8],
) -> Poll<ProgressiveResult<SourceStep>> {
    d.poll_original_read(r, &mut Context::from_waker(w), buf)
}
fn invalid<T>(r: ProgressiveResult<T>) {
    assert!(matches!(r, Err(ProgressiveFailure { kind: FailureKind::InvalidCapability, .. })));
}
#[derive(Default)]
struct TaskCount(AtomicUsize);
impl Wake for TaskCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

// Catches sharing the extraction cursor or reopening a retained original.
#[test]
fn retained_read_has_independent_cursor_and_no_reacquisition() {
    let a = LeaseProbe::new(200, &[LeaseAnswer::Fill(2)]);
    let (mut d, requests) = setup(true, 64, vec![Box::new(a.clone()), Box::new(probe(201))]);
    open(&mut d, 0);
    select(&mut d, 1);
    open(&mut d, 1);
    d.seek(3).unwrap();
    let mut r = d.begin_original_read(0, 2, OriginalReadPurpose::Discovery).unwrap();
    let mut buf = [0; 2];
    assert_eq!(
        lease_poll(&mut d, &mut r, Waker::noop(), &mut buf).map(|r| r.unwrap()),
        Poll::Ready(SourceStep::Filled { offset: 2, count: 2 })
    );
    assert_eq!(buf, [2, 3]);
    assert_eq!(d.cursor.offset(), 3);
    assert_eq!(*requests.lock().unwrap(), [0, 1]);
    assert_eq!(a.calls.load(Ordering::SeqCst), 1);
}
// Catches treating a lane conflict as source corruption or invoking its callback.
#[test]
fn retained_lease_same_lane_conflicts_without_poison() {
    let a = LeaseProbe::new(202, &[]);
    let (mut d, _) = setup(true, 64, vec![Box::new(a.clone())]);
    open(&mut d, 0);
    let mut r = d.begin_original_read(0, 0, OriginalReadPurpose::Discovery).unwrap();
    invalid(d.begin_original_read(0, 0, OriginalReadPurpose::Refill));
    invalid(d.select_volume(VolumeRequest { index: 1, expected: "v1".into() }));
    assert!(matches!(poll(&mut d), Poll::Ready(Err(ProgressiveFailure { kind: FailureKind::InvalidCapability, .. }))));
    assert!(!d.failed);
    assert_eq!(a.calls.load(Ordering::SeqCst), 0);
    d.retire_original_read(&mut r).unwrap();
    assert!(poll(&mut d).is_ready());
}
// Catches retrying without this exact request's wake, including pre-return wake loss.
#[test]
fn retained_parked_read_needs_its_own_wake() {
    for now in [false, true] {
        let a = LeaseProbe::new(203, &[LeaseAnswer::Wait(now), LeaseAnswer::Fill(2)]);
        let (mut d, _) = setup(true, 64, vec![Box::new(a.clone())]);
        open(&mut d, 0);
        let mut r = d.begin_original_read(0, 0, OriginalReadPurpose::Discovery).unwrap();
        assert!(lease_poll(&mut d, &mut r, Waker::noop(), &mut [0; 8]).is_pending());
        if !now {
            for _ in 0..10 {
                assert!(lease_poll(&mut d, &mut r, Waker::noop(), &mut [0; 8]).is_pending());
            }
            assert_eq!(a.calls.load(Ordering::SeqCst), 1);
            a.wake(0);
        }
        assert!(matches!(
            lease_poll(&mut d, &mut r, Waker::noop(), &mut [0; 8]),
            Poll::Ready(Ok(SourceStep::Filled { offset: 0, count: 2 }))
        ));
        assert_eq!(a.calls.load(Ordering::SeqCst), 2);
    }
}
// Catches reusing a completed or retired gate on the next lease/request/selection.
#[test]
fn retained_stale_wake_cannot_authorize_new_request() {
    let a = LeaseProbe::new(
        204,
        &[
            LeaseAnswer::Wait(false),
            LeaseAnswer::Fill(1),
            LeaseAnswer::Wait(false),
            LeaseAnswer::Fill(1),
            LeaseAnswer::Wait(false),
        ],
    );
    let (mut d, _) = setup(true, 64, vec![Box::new(a.clone())]);
    open(&mut d, 0);
    let mut r = d.begin_original_read(0, 0, OriginalReadPurpose::Discovery).unwrap();
    assert!(lease_poll(&mut d, &mut r, Waker::noop(), &mut [0; 4]).is_pending());
    a.wake(0);
    assert!(lease_poll(&mut d, &mut r, Waker::noop(), &mut [0; 4]).is_ready());
    assert!(lease_poll(&mut d, &mut r, Waker::noop(), &mut [0; 4]).is_pending());
    a.wake(0);
    assert!(lease_poll(&mut d, &mut r, Waker::noop(), &mut [0; 4]).is_pending());
    assert_eq!(a.calls.load(Ordering::SeqCst), 3);
    d.retire_original_read(&mut r).unwrap();
    let mut r = d.begin_original_read(0, 2, OriginalReadPurpose::Discovery).unwrap();
    assert!(lease_poll(&mut d, &mut r, Waker::noop(), &mut [0; 4]).is_ready());
    assert!(lease_poll(&mut d, &mut r, Waker::noop(), &mut [0; 4]).is_pending());
    a.wake(1);
    assert!(lease_poll(&mut d, &mut r, Waker::noop(), &mut [0; 4]).is_pending());
    assert_eq!(a.calls.load(Ordering::SeqCst), 5);
}
// Catches tokens owning/dropping the source or terminal retirement requiring allocation.
#[test]
fn retained_drop_and_retire_leave_owner_valid() {
    let a = probe(205);
    let drops = a.drops.clone();
    let (mut d, _) = setup(true, 64, vec![Box::new(a)]);
    open(&mut d, 0);
    let mut r = d.begin_original_read(0, 8, OriginalReadPurpose::Discovery).unwrap();
    assert!(matches!(lease_poll(&mut d, &mut r, Waker::noop(), &mut [0; 1]), Poll::Ready(Ok(SourceStep::EndOfVolume))));
    d.retire_original_read(&mut r).unwrap();
    invalid(d.retire_original_read(&mut r));
    let r = d.begin_original_read(0, 0, OriginalReadPurpose::Discovery).unwrap();
    drop(r);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    let r = d.begin_original_read(0, 0, OriginalReadPurpose::Discovery).unwrap();
    drop(d);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    drop(r);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}
// Catches committing callback bytes after cancellation/change, and forgetting permanent holes.
#[test]
fn retained_read_mutation_and_cancel_poison_before_advance() {
    for answer in [LeaseAnswer::Change, LeaseAnswer::Cancel] {
        let control = SessionControl::default();
        let mut a = LeaseProbe::new(206, &[answer]);
        a.cancel = Some(control.clone());
        let (mut d, _) = setup(true, 64, vec![Box::new(a.clone())]);
        d.control = control;
        d.control.enable_retained_cancel(&mut d.usage).unwrap();
        open(&mut d, 0);
        let mut r = d.begin_original_read(0, 2, OriginalReadPurpose::Refill).unwrap();
        assert!(matches!(lease_poll(&mut d, &mut r, Waker::noop(), &mut [0; 2]), Poll::Ready(Err(_))));
        assert_eq!(d.cursor.offset(), 0);
        assert_eq!(r.cursor.offset(), 2);
        assert!(d.failed);
        assert!(lease_poll(&mut d, &mut r, Waker::noop(), &mut [0; 2]).is_ready());
        assert_eq!(a.calls.load(Ordering::SeqCst), 1);
    }
    let a = LeaseProbe::new(207, &[LeaseAnswer::Hole(3), LeaseAnswer::Fill(1)]);
    let (mut d, _) = setup(true, 64, vec![Box::new(a)]);
    open(&mut d, 0);
    let mut r = d.begin_original_read(0, 0, OriginalReadPurpose::Discovery).unwrap();
    assert!(matches!(
        lease_poll(&mut d, &mut r, Waker::noop(), &mut [0; 8]),
        Poll::Ready(Ok(SourceStep::Hole { len: 3, .. }))
    ));
    drop(r);
    let mut r = d.begin_original_read(0, 0, OriginalReadPurpose::Discovery).unwrap();
    assert!(matches!(
        lease_poll(&mut d, &mut r, Waker::noop(), &mut [0; 8]),
        Poll::Ready(Err(ProgressiveFailure { kind: FailureKind::SourceChanged, .. }))
    ));
}
// Catches wraparound reactivation and old token resurrection on failed admission.
#[test]
fn retained_epoch_limit_failure_never_reactivates() {
    let (mut d, _) = setup(true, 64, vec![Box::new(probe(208))]);
    open(&mut d, 0);
    let mut r = d.begin_original_read(0, 0, OriginalReadPurpose::Discovery).unwrap();
    d.retire_original_read(&mut r).unwrap();
    d.retained.as_mut().unwrap().lease_counter = u64::MAX;
    assert!(d.begin_original_read(0, 0, OriginalReadPurpose::Discovery).is_err());
    assert!(matches!(lease_poll(&mut d, &mut r, Waker::noop(), &mut [0; 1]), Poll::Ready(Err(_))));
}
// Catches double-counting leases as source objects and stale native/replacement capacity.
#[test]
fn retained_replacement_guard_regressions() {
    eprintln!(
        "layout: SourceDriver={} replacement_record={} ControlWake={} WakeGate={} OriginalSource={} OriginalRead={}",
        std::mem::size_of::<SourceDriver>(),
        std::mem::size_of::<(u32, SourceDriver)>(),
        std::mem::size_of::<ControlWake>(),
        std::mem::size_of::<WakeGate>(),
        std::mem::size_of::<OriginalSource>(),
        std::mem::size_of::<OriginalRead>()
    );
    let (mut d, _) = setup(true, 2, vec![Box::new(probe(209))]);
    open(&mut d, 0);
    let r = d.begin_original_read(0, 0, OriginalReadPurpose::Discovery).unwrap();
    d.supply_replacement(0, Box::new(probe(210))).unwrap();
    assert_eq!(d.original_count(), 1);
    limit3(d.supply_replacement(0, Box::new(probe(211))));
    drop(r);
}
// Catches missing shared hub for clones predating retained construction and retired wake leaks.
#[test]
fn retained_cancel_wakes_all_live_operations() {
    for selected_range in [false, true] {
        cancel_fanout_case(selected_range);
    }
}
fn cancel_fanout_case(selected_range: bool) {
    let control = SessionControl::default();
    let before = control.clone();
    let mut probes = vec![];
    for i in 0..4 {
        probes.push(LeaseProbe::new(220 + i, &[LeaseAnswer::Wait(false)]));
    }
    struct WaitingVolumes {
        v: Vec<LeaseProbe>,
    }
    impl VolumeSource for WaitingVolumes {
        fn volume(&mut self, r: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
            if r.index == 4 {
                Ok(VolumeAnswer::Wait)
            } else {
                Ok(VolumeAnswer::Ready(Box::new(self.v[r.index as usize].clone())))
            }
        }
    }
    let mut d = SourceDriver::new_retained(
        Box::new(WaitingVolumes { v: probes.clone() }),
        "v0".into(),
        ProgressiveLimits::default(),
        control,
    )
    .unwrap();
    open(&mut d, 0);
    for i in 1..4 {
        select(&mut d, i);
        open(&mut d, i);
    }
    if !selected_range {
        select(&mut d, 4);
    }
    let mut a = d.begin_original_read(0, 0, OriginalReadPurpose::Discovery).unwrap();
    let mut b = d.begin_original_read(1, 0, OriginalReadPurpose::Discovery).unwrap();
    let mut retired = d.begin_original_read(2, 0, OriginalReadPurpose::Discovery).unwrap();
    let counters: Vec<_> = (0..4).map(|_| Arc::new(TaskCount::default())).collect();
    let w: Vec<_> = counters.iter().map(|n| Waker::from(n.clone())).collect();
    assert!(lease_poll(&mut d, &mut a, &w[0], &mut [0; 8]).is_pending());
    assert!(lease_poll(&mut d, &mut b, &w[1], &mut [0; 8]).is_pending());
    assert!(lease_poll(&mut d, &mut retired, &w[3], &mut [0; 8]).is_pending());
    d.retire_original_read(&mut retired).unwrap();
    assert!(d.poll_step(&mut Context::from_waker(&w[2]), &mut [0; 8]).is_pending());
    before.cancel();
    before.cancel();
    for (i, n) in counters.iter().enumerate() {
        assert_eq!(n.0.load(Ordering::SeqCst), usize::from(i != 3));
    }
    for r in [&mut a, &mut b, &mut retired] {
        assert!(matches!(
            lease_poll(&mut d, r, Waker::noop(), &mut [0; 8]),
            Poll::Ready(Err(ProgressiveFailure { kind: FailureKind::Canceled, .. }))
        ));
    }
    assert!(matches!(poll(&mut d), Poll::Ready(Err(ProgressiveFailure { kind: FailureKind::Canceled, .. }))));
    assert!(!d.wake.0.lock().unwrap().ready);
    assert_eq!(d.wake.0.lock().unwrap().wakes, 0);
}
// Catches registry count leaks when weak/retired rows remain and missing per-owner cap.
#[test]
fn retained_cancel_registration_race_and_capacity() {
    let c = SessionControl::default();
    let mut u = Usage::new(ProgressiveLimits::default());
    c.enable_retained_cancel(&mut u).unwrap();
    let owner = CancelOwner { identity: Arc::new(()), max_operations: 1 };
    let gate = Arc::new(WakeGate::default());
    let mut r = c.register_retained_cancel(&owner, &gate, &mut u).unwrap();
    assert!(c.register_retained_cancel(&owner, &gate, &mut u).is_err());
    r.retire();
    let r = c.register_retained_cancel(&owner, &gate, &mut u).unwrap();
    drop(r);
    assert!(c.register_retained_cancel(&owner, &gate, &mut u).is_ok());
}
// Catches requested-length SourceBytes or debit of un-woken polls; exact quotas prove counts.
#[test]
fn retained_accepted_and_attempted_byte_accounting() {
    for purpose in [OriginalReadPurpose::Discovery, OriginalReadPurpose::Refill] {
        let a = LeaseProbe::new(230, &[LeaseAnswer::Wait(false), LeaseAnswer::Fill(2)]);
        let limits = ProgressiveLimits { source_bytes: 2, verify_bytes: 16, ..Default::default() };
        let mut d = SourceDriver::new_retained(
            Box::new(Volumes { sources: vec![Some(Box::new(a.clone()))], requests: Arc::new(Mutex::new(vec![])) }),
            "v0".into(),
            limits,
            SessionControl::default(),
        )
        .unwrap();
        open(&mut d, 0);
        let mut r = d.begin_original_read(0, 0, purpose).unwrap();
        assert!(lease_poll(&mut d, &mut r, Waker::noop(), &mut [0; 8]).is_pending());
        for _ in 0..10 {
            assert!(lease_poll(&mut d, &mut r, Waker::noop(), &mut [0; 8]).is_pending());
        }
        a.wake(0);
        assert!(matches!(
            lease_poll(&mut d, &mut r, Waker::noop(), &mut [0; 8]),
            Poll::Ready(Ok(SourceStep::Filled { count: 2, .. }))
        ));
        assert_eq!(a.calls.load(Ordering::SeqCst), 2);
        assert!(d.usage.charge(Resource::SourceBytes, 1).is_err());
        if matches!(purpose, OriginalReadPurpose::Discovery) {
            d.usage.charge(Resource::VerifyBytes, 16).unwrap();
        }
        assert!(d.usage.charge(Resource::VerifyBytes, 1).is_err());
    }
}
// Actual reentrant callbacks are added below; removing lock-free gate wake must deadlock this child.
#[test]
fn retained_callbacks_and_drops_are_lock_free() {
    if !super::tests::in_bounded_wake_child(
        "progressive::source::retained_tests::retained_callbacks_and_drops_are_lock_free",
        "ZIPFAST_RETAINED_CALLBACK_CHILD",
    ) {
        return;
    }
    struct Reenter(SessionControl);
    impl Wake for Reenter {
        fn wake(self: Arc<Self>) {
            self.0.cancel();
        }
    }
    impl Drop for Reenter {
        fn drop(&mut self) {
            self.0.cancel();
        }
    }
    let a = LeaseProbe::new(231, &[LeaseAnswer::Wait(false)]);
    let (mut d, _) = setup(true, 64, vec![Box::new(a)]);
    open(&mut d, 0);
    let mut r = d.begin_original_read(0, 0, OriginalReadPurpose::Discovery).unwrap();
    let w = Waker::from(Arc::new(Reenter(d.control.clone())));
    assert!(lease_poll(&mut d, &mut r, &w, &mut [0; 8]).is_pending());
    drop(w);
    d.control.cancel();
    assert!(d.control.is_canceled());
}

// Catches admitting callback work after a quota failure and incorrect accepted/attempted charges.
#[test]
fn retained_byte_accounting_matrix_and_boundaries() {
    for purpose in [OriginalReadPurpose::Discovery, OriginalReadPurpose::Refill] {
        for answer in [LeaseAnswer::Error, LeaseAnswer::Change, LeaseAnswer::Cancel, LeaseAnswer::Hole(3)] {
            let control = SessionControl::default();
            let mut a = LeaseProbe::new(240, &[answer]);
            a.cancel = Some(control.clone());
            let limits = ProgressiveLimits { source_bytes: 100, verify_bytes: 100, ..Default::default() };
            let mut d = SourceDriver::new_retained(
                Box::new(Volumes { sources: vec![Some(Box::new(a.clone()))], requests: Arc::new(Mutex::new(vec![])) }),
                "v0".into(),
                limits,
                control,
            )
            .unwrap();
            open(&mut d, 0);
            let mut r = d.begin_original_read(0, 0, purpose).unwrap();
            let result = lease_poll(&mut d, &mut r, Waker::noop(), &mut [0; 8]);
            let accepted = if matches!(answer, LeaseAnswer::Hole(_)) {
                assert!(matches!(result, Poll::Ready(Ok(SourceStep::Hole { offset: 0, len: 3 }))));
                3
            } else {
                assert!(matches!(result, Poll::Ready(Err(_))));
                0
            };
            d.usage.charge(Resource::SourceBytes, 100 - accepted).unwrap();
            assert!(d.usage.charge(Resource::SourceBytes, 1).is_err());
            let attempted = if matches!(purpose, OriginalReadPurpose::Refill) { 8 } else { 0 };
            d.usage.charge(Resource::VerifyBytes, 100 - attempted).unwrap();
            assert!(d.usage.charge(Resource::VerifyBytes, 1).is_err());
            assert_eq!(a.calls.load(Ordering::SeqCst), 1);
        }
    }
    for (source_limit, verify_limit, want_calls) in [(1, 100, 1), (2, 7, 0), (2, 15, 1)] {
        let answers = if verify_limit == 15 {
            vec![LeaseAnswer::Wait(false), LeaseAnswer::Fill(2)]
        } else {
            vec![LeaseAnswer::Fill(2)]
        };
        let a = LeaseProbe::new(241, &answers);
        let mut d = SourceDriver::new_retained(
            Box::new(Volumes { sources: vec![Some(Box::new(a.clone()))], requests: Arc::new(Mutex::new(vec![])) }),
            "v0".into(),
            ProgressiveLimits { source_bytes: source_limit, verify_bytes: verify_limit, ..Default::default() },
            SessionControl::default(),
        )
        .unwrap();
        open(&mut d, 0);
        let mut r = d.begin_original_read(0, 0, OriginalReadPurpose::Refill).unwrap();
        let mut result = lease_poll(&mut d, &mut r, Waker::noop(), &mut [0; 8]);
        if verify_limit == 15 {
            assert!(result.is_pending());
            a.wake(0);
            result = lease_poll(&mut d, &mut r, Waker::noop(), &mut [0; 8]);
        }
        assert!(matches!(result, Poll::Ready(Err(ProgressiveFailure { kind: FailureKind::Limit { .. }, .. }))));
        assert_eq!(a.calls.load(Ordering::SeqCst), want_calls);
        assert_eq!(r.cursor.offset(), 0);
    }
}
// Catches routing default/selected/replacement reads around the same accepted-byte seam.
#[test]
fn retained_selected_and_replacement_byte_accounting() {
    for mode in 0..3 {
        let a = LeaseProbe::new(242, &[LeaseAnswer::Wait(false), LeaseAnswer::Fill(2)]);
        let limits = ProgressiveLimits { source_bytes: 2, verify_bytes: 16, ..Default::default() };
        let mut d = if mode == 0 {
            SourceDriver::new(
                Box::new(Volumes { sources: vec![Some(Box::new(a.clone()))], requests: Arc::new(Mutex::new(vec![])) }),
                "v0".into(),
                limits,
                SessionControl::default(),
            )
            .unwrap()
        } else {
            SourceDriver::new_retained(
                Box::new(Volumes {
                    sources: vec![Some(Box::new(if mode == 2 { LeaseProbe::new(243, &[]) } else { a.clone() }))],
                    requests: Arc::new(Mutex::new(vec![])),
                }),
                "v0".into(),
                limits,
                SessionControl::default(),
            )
            .unwrap()
        };
        open(&mut d, 0);
        if mode == 2 {
            d.supply_replacement(0, Box::new(a.clone())).unwrap();
        }
        let run = |d: &mut SourceDriver| {
            if mode == 2 {
                d.poll_replacement(0, 0, &mut Context::from_waker(Waker::noop()), &mut [0; 8])
            } else {
                poll(d)
            }
        };
        assert!(run(&mut d).is_pending());
        for _ in 0..10 {
            assert!(run(&mut d).is_pending());
        }
        assert_eq!(a.calls.load(Ordering::SeqCst), 1);
        a.wake(0);
        assert!(matches!(run(&mut d), Poll::Ready(Ok(SourceStep::Filled { count: 2, .. }))));
        assert!(d.usage.charge(Resource::SourceBytes, 1).is_err());
        if mode != 2 {
            d.usage.charge(Resource::VerifyBytes, 16).unwrap();
        }
        assert!(d.usage.charge(Resource::VerifyBytes, 1).is_err());
    }
}
// Catches orphaning a refreshed task if its RawWaker clone cancels during registration.
#[test]
fn retained_raw_waker_registration_race_is_bounded() {
    if !super::tests::in_bounded_wake_child(
        "progressive::source::retained_tests::retained_raw_waker_registration_race_is_bounded",
        "ZIPFAST_RETAINED_RAW_CHILD",
    ) {
        return;
    }
    struct Hooks {
        control: SessionControl,
        count: AtomicUsize,
        clone_cancel: AtomicBool,
        other: Mutex<SourceDriver>,
        enter_other: AtomicBool,
    }
    impl Hooks {
        fn enter(&self) {
            self.control.cancel();
            if self.enter_other.swap(false, Ordering::SeqCst) {
                let mut other = self.other.lock().unwrap();
                assert!(matches!(poll(&mut other), Poll::Ready(Ok(_))));
                other.control.cancel();
            }
        }
    }
    // Each raw pointer owns one Arc strong reference. Borrowing hooks restore that
    // reference with into_raw; clone creates one more, wake/drop consume one.
    // Hooks own a different driver behind a mutex, never an alias of the polled driver.
    unsafe fn clone_raw(p: *const ()) -> std::task::RawWaker {
        let a = unsafe { Arc::<Hooks>::from_raw(p.cast()) };
        let b = a.clone();
        if a.clone_cancel.swap(false, Ordering::SeqCst) {
            a.enter();
        }
        let _ = Arc::into_raw(a);
        std::task::RawWaker::new(Arc::into_raw(b).cast(), &VTABLE)
    }
    unsafe fn wake_raw(p: *const ()) {
        let a = unsafe { Arc::<Hooks>::from_raw(p.cast()) };
        a.count.fetch_add(1, Ordering::SeqCst);
        a.enter();
    }
    unsafe fn wake_ref_raw(p: *const ()) {
        let a = unsafe { Arc::<Hooks>::from_raw(p.cast()) };
        a.count.fetch_add(1, Ordering::SeqCst);
        a.enter();
        let _ = Arc::into_raw(a);
    }
    unsafe fn drop_raw(p: *const ()) {
        let a = unsafe { Arc::<Hooks>::from_raw(p.cast()) };
        a.enter();
    }
    static VTABLE: std::task::RawWakerVTable =
        std::task::RawWakerVTable::new(clone_raw, wake_raw, wake_ref_raw, drop_raw);
    for refresh in [false, true] {
        let a = LeaseProbe::new(244, &[LeaseAnswer::Wait(false)]);
        let (mut d, _) = setup(true, 64, vec![Box::new(a.clone())]);
        open(&mut d, 0);
        let mut r = d.begin_original_read(0, 0, OriginalReadPurpose::Discovery).unwrap();
        if refresh {
            assert!(lease_poll(&mut d, &mut r, Waker::noop(), &mut [0; 8]).is_pending());
        }
        let (other, _) = setup(true, 64, vec![Box::new(probe(256))]);
        let hooks = Arc::new(Hooks {
            control: d.control.clone(),
            count: AtomicUsize::new(0),
            clone_cancel: AtomicBool::new(true),
            other: Mutex::new(other),
            enter_other: AtomicBool::new(true),
        });
        let w = unsafe { Waker::from_raw(std::task::RawWaker::new(Arc::into_raw(hooks.clone()).cast(), &VTABLE)) };
        assert!(matches!(
            lease_poll(&mut d, &mut r, &w, &mut [0; 8]),
            Poll::Ready(Err(ProgressiveFailure { kind: FailureKind::Canceled, .. }))
        ));
        assert_eq!(hooks.count.load(Ordering::SeqCst), 1);
        assert_eq!(a.calls.load(Ordering::SeqCst), usize::from(refresh));
    }
}
// Catches treating the hub ceiling as only a per-owner ceiling or charging unreclaimed rows.
#[test]
fn retained_hub_hard_capacity_and_reclamation() {
    let c = SessionControl::default();
    let mut u = Usage::new(ProgressiveLimits::default());
    c.enable_retained_cancel(&mut u).unwrap();
    let gate = Arc::new(WakeGate::default());
    let mut registrations = vec![];
    for _ in 0..4096 {
        let owner = CancelOwner { identity: Arc::new(()), max_operations: 1 };
        registrations.push(c.register_retained_cancel(&owner, &gate, &mut u).unwrap());
    }
    let owner = CancelOwner { identity: Arc::new(()), max_operations: 1 };
    assert!(matches!(
        c.register_retained_cancel(&owner, &gate, &mut u),
        Err(ProgressiveFailure {
            kind: FailureKind::Limit { resource: Resource::VolumeHandles, limit: 4096, attempted: 4097 },
            ..
        })
    ));
    registrations[0].retire();
    let r = c.register_retained_cancel(&owner, &gate, &mut u).unwrap();
    drop(r);
    assert!(c.register_retained_cancel(&owner, &gate, &mut u).is_ok());
}
// Catches structural errors poisoning another owner, invalid empty/EOF callbacks, and epoch allocation resurrection.
#[test]
fn retained_invalid_empty_and_allocation_failure() {
    let a = LeaseProbe::new(245, &[LeaseAnswer::Fill(2)]);
    let (mut d, _) = setup(true, 64, vec![Box::new(a.clone())]);
    open(&mut d, 0);
    invalid(d.begin_original_read(1, 0, OriginalReadPurpose::Discovery));
    assert!(matches!(
        d.begin_original_read(0, 9, OriginalReadPurpose::Discovery),
        Err(ProgressiveFailure { kind: FailureKind::SourceContract, .. })
    ));
    let mut r = d.begin_original_read(0, 0, OriginalReadPurpose::Discovery).unwrap();
    assert!(matches!(
        lease_poll(&mut d, &mut r, Waker::noop(), &mut []),
        Poll::Ready(Ok(SourceStep::Filled { offset: 0, count: 0 }))
    ));
    assert_eq!(a.calls.load(Ordering::SeqCst), 0);
    let (mut other, _) = setup(true, 64, vec![Box::new(probe(246))]);
    open(&mut other, 0);
    assert!(matches!(
        lease_poll(&mut other, &mut r, Waker::noop(), &mut [0; 8]),
        Poll::Ready(Err(ProgressiveFailure { kind: FailureKind::InvalidCapability, .. }))
    ));
    assert!(!other.failed);
    assert!(lease_poll(&mut d, &mut r, Waker::noop(), &mut [0; 8]).is_ready());
    d.usage = Usage::new(ProgressiveLimits { metadata_bytes: 0, ..Default::default() });
    assert!(matches!(lease_poll(&mut d, &mut r, Waker::noop(), &mut [0; 8]), Poll::Ready(Err(_))));
    assert_eq!(r.cursor.offset(), 2);
    assert!(d.failed);
    assert_eq!(a.calls.load(Ordering::SeqCst), 1);
}

// Catches callbacks after a source boundary cancels and user Drop under a registry lock.
#[test]
fn retained_source_callback_reentrancy_is_bounded() {
    if !super::tests::in_bounded_wake_child(
        "progressive::source::retained_tests::retained_source_callback_reentrancy_is_bounded",
        "ZIPFAST_RETAINED_SOURCE_CHILD",
    ) {
        return;
    }
    #[derive(Clone, Copy, PartialEq)]
    enum Boundary {
        Info,
        Backing,
        Read,
        Drop,
    }
    struct ReentrantSource {
        boundary: Boundary,
        control: SessionControl,
        other: Arc<Mutex<SourceDriver>>,
        visits: Arc<Mutex<Vec<&'static str>>>,
        drops: Arc<AtomicUsize>,
        armed: Arc<AtomicBool>,
    }
    impl ReentrantSource {
        fn enter(&self, boundary: Boundary, name: &'static str) {
            self.visits.lock().unwrap().push(name);
            if boundary == self.boundary && self.armed.load(Ordering::SeqCst) {
                self.control.cancel();
                let mut other = self.other.lock().unwrap();
                assert!(matches!(poll(&mut other), Poll::Ready(Ok(_))));
                other.control.cancel();
            }
        }
    }
    impl RangeSource for ReentrantSource {
        fn info(&self) -> SourceInfo {
            self.enter(Boundary::Info, "info");
            SourceInfo { id: SourceId(250), generation: 0, extent: 8, length: SourceLength::Final(8) }
        }
        fn backing_files(&self) -> &[File] {
            self.enter(Boundary::Backing, "backing");
            &[]
        }
        fn read_at(&mut self, _: u64, _: &mut [u8], _: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
            self.enter(Boundary::Read, "read");
            Ok(RangeRead::Filled { count: 1 })
        }
    }
    impl Drop for ReentrantSource {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
            self.enter(Boundary::Drop, "drop");
        }
    }
    for boundary in [Boundary::Info, Boundary::Backing, Boundary::Read, Boundary::Drop] {
        let control = SessionControl::default();
        let (other, _) = setup(true, 64, vec![Box::new(probe(251))]);
        let other = Arc::new(Mutex::new(other));
        let visits = Arc::new(Mutex::new(vec![]));
        let drops = Arc::new(AtomicUsize::new(0));
        let armed = Arc::new(AtomicBool::new(boundary != Boundary::Read));
        let source = ReentrantSource {
            boundary,
            control: control.clone(),
            other: other.clone(),
            visits: visits.clone(),
            drops: drops.clone(),
            armed: armed.clone(),
        };
        let mut d = SourceDriver::new_retained(
            Box::new(Volumes { sources: vec![Some(Box::new(source))], requests: Arc::new(Mutex::new(vec![])) }),
            "v0".into(),
            ProgressiveLimits::default(),
            control.clone(),
        )
        .unwrap();
        if matches!(boundary, Boundary::Info | Boundary::Backing) {
            assert!(matches!(poll(&mut d), Poll::Ready(Err(ProgressiveFailure { kind: FailureKind::Canceled, .. }))));
            assert!(!visits.lock().unwrap().contains(&"read"));
            if boundary == Boundary::Info {
                assert!(!visits.lock().unwrap().contains(&"backing"));
            }
        } else {
            open(&mut d, 0);
            if boundary == Boundary::Read {
                armed.store(true, Ordering::SeqCst);
                let mut r = d.begin_original_read(0, 0, OriginalReadPurpose::Discovery).unwrap();
                assert!(matches!(
                    lease_poll(&mut d, &mut r, Waker::noop(), &mut [0; 8]),
                    Poll::Ready(Err(ProgressiveFailure { kind: FailureKind::Canceled, .. }))
                ));
                assert_eq!(r.cursor.offset(), 0);
            }
        }
        // Only the selected boundary fires once; dropping an admitted source uses an already canceled other driver.
        armed.store(boundary == Boundary::Drop, Ordering::SeqCst);
        drop(d);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(control.is_canceled());
        assert!(other.lock().unwrap().control.is_canceled());
    }
}
// Catches reusing an old selected range/provider gate and cross-lane stale authority.
#[test]
fn retained_selected_epochs_isolate_stale_wakes() {
    let a = LeaseProbe::new(252, &[LeaseAnswer::Wait(false), LeaseAnswer::Fill(1), LeaseAnswer::Wait(false)]);
    let b = LeaseProbe::new(253, &[LeaseAnswer::Wait(false)]);
    let (mut d, _) = setup(true, 64, vec![Box::new(a.clone()), Box::new(b.clone())]);
    open(&mut d, 0);
    assert!(poll(&mut d).is_pending());
    a.wake(0);
    assert!(matches!(poll(&mut d), Poll::Ready(Ok(SourceStep::Filled { offset: 0, count: 1 }))));
    assert!(poll(&mut d).is_pending());
    a.wake(0);
    assert!(poll(&mut d).is_pending());
    assert_eq!(a.calls.load(Ordering::SeqCst), 3);
    d.control.cancel();
    assert!(matches!(poll(&mut d), Poll::Ready(Err(ProgressiveFailure { kind: FailureKind::Canceled, .. }))));
    let a = LeaseProbe::new(254, &[LeaseAnswer::Wait(false)]);
    let (mut d, _) = setup(true, 64, vec![Box::new(a.clone()), Box::new(b.clone())]);
    open(&mut d, 0);
    let mut r = d.begin_original_read(0, 0, OriginalReadPurpose::Discovery).unwrap();
    assert!(lease_poll(&mut d, &mut r, Waker::noop(), &mut [0; 8]).is_pending());
    d.retire_original_read(&mut r).unwrap();
    select(&mut d, 1);
    open(&mut d, 1);
    assert!(poll(&mut d).is_pending());
    a.wake(0);
    assert!(poll(&mut d).is_pending());
    assert_eq!(b.calls.load(Ordering::SeqCst), 1);
    d.supply_replacement(0, Box::new(LeaseProbe::new(255, &[LeaseAnswer::Wait(false)]))).unwrap();
    assert!(d.poll_replacement(0, 0, &mut Context::from_waker(Waker::noop()), &mut [0; 8]).is_pending());
    a.wake(0);
    assert!(d.poll_replacement(0, 0, &mut Context::from_waker(Waker::noop()), &mut [0; 8]).is_pending());
}
// Catches acquisition readiness leaking into the selected range epoch or next selected volume.
#[test]
fn retained_provider_epoch_does_not_authorize_ranges() {
    struct GateVolumes {
        sources: Vec<Option<LeaseProbe>>,
        wakes: Arc<Mutex<Vec<Waker>>>,
        attempts: Vec<usize>,
    }
    impl VolumeSource for GateVolumes {
        fn volume(&mut self, r: &VolumeRequest, cx: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
            let i = r.index as usize;
            self.attempts[i] += 1;
            self.wakes.lock().unwrap().push(cx.waker().clone());
            if self.attempts[i] == 1 {
                Ok(VolumeAnswer::Wait)
            } else {
                Ok(VolumeAnswer::Ready(Box::new(self.sources[i].take().unwrap())))
            }
        }
    }
    let a = LeaseProbe::new(257, &[LeaseAnswer::Wait(false), LeaseAnswer::Fill(1)]);
    let wakes = Arc::new(Mutex::new(vec![]));
    let mut d = SourceDriver::new_retained(
        Box::new(GateVolumes {
            sources: vec![Some(a.clone()), Some(LeaseProbe::new(258, &[]))],
            wakes: wakes.clone(),
            attempts: vec![0, 0],
        }),
        "v0".into(),
        ProgressiveLimits::default(),
        SessionControl::default(),
    )
    .unwrap();
    assert!(poll(&mut d).is_pending());
    let old = wakes.lock().unwrap()[0].clone();
    old.wake_by_ref();
    open(&mut d, 0);
    assert!(poll(&mut d).is_pending());
    old.wake_by_ref();
    assert!(poll(&mut d).is_pending());
    assert_eq!(a.calls.load(Ordering::SeqCst), 1);
    a.wake(0);
    assert!(poll(&mut d).is_ready());
    select(&mut d, 1);
    assert!(poll(&mut d).is_pending());
    old.wake_by_ref();
    assert!(poll(&mut d).is_pending());
    assert_eq!(wakes.lock().unwrap().len(), 3);
}
// Catches ready bits overriding sticky cancellation, and cancellation fabricating provider wakes.
#[test]
fn retained_cancellation_preserves_provider_counters_and_wins_readiness() {
    let a = LeaseProbe::new(259, &[LeaseAnswer::Wait(false), LeaseAnswer::Fill(1)]);
    let (mut d, _) = setup(true, 64, vec![Box::new(a.clone())]);
    open(&mut d, 0);
    let mut r = d.begin_original_read(0, 0, OriginalReadPurpose::Discovery).unwrap();
    assert!(lease_poll(&mut d, &mut r, Waker::noop(), &mut [0; 8]).is_pending());
    a.wake(0);
    let old = a.wakes.lock().unwrap()[0].clone();
    d.control.cancel();
    assert!(matches!(
        lease_poll(&mut d, &mut r, Waker::noop(), &mut [0; 8]),
        Poll::Ready(Err(ProgressiveFailure { kind: FailureKind::Canceled, .. }))
    ));
    assert_eq!(a.calls.load(Ordering::SeqCst), 1);
    old.wake();
    assert_eq!(r.cursor.offset(), 0);
    let c = SessionControl::default();
    let mut u = Usage::new(ProgressiveLimits::default());
    c.enable_retained_cancel(&mut u).unwrap();
    let gate = Arc::new(WakeGate::default());
    let owner = CancelOwner { identity: Arc::new(()), max_operations: 1 };
    let _r = c.register_retained_cancel(&owner, &gate, &mut u).unwrap();
    gate.arm();
    gate.notify(true);
    let before = {
        let state = gate.0.lock().unwrap();
        (state.ready, state.wakes)
    };
    c.cancel();
    let state = gate.0.lock().unwrap();
    assert_eq!(before, (true, 1));
    assert_eq!((state.ready, state.wakes), before);
}
// Catches a foreign driver retiring a live token, and unpoisoned pre-read bookkeeping exhaustion.
#[test]
fn retained_foreign_retirement_and_lookup_budget_failure() {
    let (mut d, _) = setup(true, 64, vec![Box::new(probe(260)), Box::new(probe(261))]);
    open(&mut d, 0);
    select(&mut d, 1);
    open(&mut d, 1);
    let mut r = d.begin_original_read(0, 0, OriginalReadPurpose::Discovery).unwrap();
    let (mut other, _) = setup(true, 64, vec![Box::new(probe(262))]);
    open(&mut other, 0);
    invalid(other.retire_original_read(&mut r));
    assert!(matches!(
        lease_poll(&mut d, &mut r, Waker::noop(), &mut [0; 8]),
        Poll::Ready(Ok(SourceStep::Filled { offset: 0, count: 1 }))
    ));
    d.usage = Usage::new(ProgressiveLimits { source_bookkeeping: 0, ..Default::default() });
    assert!(matches!(
        lease_poll(&mut d, &mut r, Waker::noop(), &mut [0; 8]),
        Poll::Ready(Err(ProgressiveFailure {
            kind: FailureKind::Limit { resource: Resource::SourceBookkeeping, .. },
            ..
        }))
    ));
    assert!(d.failed);
}
// Catches returning a provider error ahead of cancellation latched by the same callback.
#[test]
fn retained_provider_cancel_has_priority_over_callback_error() {
    struct CancelVolumes {
        control: SessionControl,
        protection: bool,
        calls: Arc<AtomicUsize>,
    }
    impl VolumeSource for CancelVolumes {
        fn protection(&mut self) -> ProgressiveResult<ProtectionDeclaration> {
            if self.protection {
                self.control.cancel();
                Err(contract())
            } else {
                Ok(ProtectionDeclaration::Opaque)
            }
        }
        fn volume(&mut self, _: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.control.cancel();
            Err(contract())
        }
    }
    for protection in [false, true] {
        let control = SessionControl::default();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut d = SourceDriver::new_retained(
            Box::new(CancelVolumes { control: control.clone(), protection, calls: calls.clone() }),
            "v0".into(),
            ProgressiveLimits::default(),
            control,
        )
        .unwrap();
        assert!(matches!(poll(&mut d), Poll::Ready(Err(ProgressiveFailure { kind: FailureKind::Canceled, .. }))));
        assert_eq!(calls.load(Ordering::SeqCst), usize::from(!protection));
    }
}

// Catches a revisited source's changed-info error masking callback cancellation.
#[test]
fn retained_revisit_info_cancel_precedes_changed_info() {
    struct CancelInfo {
        source: LeaseProbe,
        armed: Arc<AtomicBool>,
        control: SessionControl,
    }
    impl RangeSource for CancelInfo {
        fn info(&self) -> SourceInfo {
            let mut info = self.source.info();
            if self.armed.load(Ordering::SeqCst) {
                self.control.cancel();
                info.generation += 1;
            }
            info
        }
        fn backing_files(&self) -> &[File] {
            self.source.backing_files()
        }
        fn read_at(&mut self, offset: u64, buf: &mut [u8], cx: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
            self.source.read_at(offset, buf, cx)
        }
    }
    let control = SessionControl::default();
    let armed = Arc::new(AtomicBool::new(false));
    let source = LeaseProbe::new(270, &[]);
    let requests = Arc::new(Mutex::new(vec![]));
    let provider = Volumes {
        sources: vec![
            Some(Box::new(CancelInfo { source: source.clone(), armed: armed.clone(), control: control.clone() })),
            Some(Box::new(probe(271))),
        ],
        requests: requests.clone(),
    };
    let mut d =
        SourceDriver::new_retained(Box::new(provider), "v0".into(), ProgressiveLimits::default(), control.clone())
            .unwrap();
    open(&mut d, 0);
    select(&mut d, 1);
    open(&mut d, 1);
    select(&mut d, 0);
    armed.store(true, Ordering::SeqCst);
    assert!(matches!(poll(&mut d), Poll::Ready(Err(ProgressiveFailure { kind: FailureKind::Canceled, .. }))));
    assert!(control.is_canceled());
    assert_eq!(source.calls.load(Ordering::SeqCst), 0);
    assert_eq!(d.cursor.offset(), 0);
    assert!(d.reopened); // No successful VolumeOpened notice was emitted.
    assert!(d.failed);
    assert_eq!(*requests.lock().unwrap(), [0, 1]);
}

// Catches current-original validation masking cancellation before replacement admission.
#[test]
fn retained_replacement_current_info_cancel_precedes_changed_info() {
    struct CancelCurrent {
        source: Probe,
        armed: Arc<AtomicBool>,
        control: SessionControl,
    }
    impl RangeSource for CancelCurrent {
        fn info(&self) -> SourceInfo {
            let mut info = self.source.info();
            if self.armed.load(Ordering::SeqCst) {
                self.control.cancel();
                info.generation += 1;
            }
            info
        }
        fn backing_files(&self) -> &[File] {
            self.source.backing_files()
        }
        fn read_at(&mut self, offset: u64, buf: &mut [u8], cx: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
            self.source.read_at(offset, buf, cx)
        }
    }
    let control = SessionControl::default();
    let armed = Arc::new(AtomicBool::new(false));
    let original = probe(280);
    let original_drops = original.drops.clone();
    let original_reads = original.offsets.clone();
    let provider = Volumes {
        sources: vec![Some(Box::new(CancelCurrent {
            source: original,
            armed: armed.clone(),
            control: control.clone(),
        }))],
        requests: Arc::new(Mutex::new(vec![])),
    };
    let mut d =
        SourceDriver::new_retained(Box::new(provider), "v0".into(), ProgressiveLimits::default(), control.clone())
            .unwrap();
    open(&mut d, 0);
    let candidate = probe(281);
    let candidate_drops = candidate.drops.clone();
    armed.store(true, Ordering::SeqCst);
    assert!(matches!(
        d.supply_replacement(0, Box::new(candidate)),
        Err(ProgressiveFailure { kind: FailureKind::Canceled, .. })
    ));
    assert!(control.is_canceled());
    assert!(d.replacements.is_empty());
    assert_eq!(d.original.as_ref().unwrap().live.id, SourceId(280));
    assert_eq!(d.original_count(), 1);
    assert_eq!(d.cursor.offset(), 0);
    assert!(original_reads.lock().unwrap().is_empty());
    assert_eq!(original_drops.load(Ordering::SeqCst), 0);
    assert_eq!(candidate_drops.load(Ordering::SeqCst), 1);
    drop(d);
    assert_eq!(original_drops.load(Ordering::SeqCst), 1);
}

// Catches a second candidate info callback after cancellation, or changed-length masking it.
#[test]
fn retained_replacement_candidate_info_cancel_stops_admission() {
    struct CancelCandidate {
        control: SessionControl,
        length: u64,
        info_calls: Arc<AtomicUsize>,
        backing_calls: Arc<AtomicUsize>,
        read_calls: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
    }
    impl RangeSource for CancelCandidate {
        fn info(&self) -> SourceInfo {
            self.info_calls.fetch_add(1, Ordering::SeqCst);
            self.control.cancel();
            SourceInfo { id: SourceId(283), generation: 0, extent: 8, length: SourceLength::Final(self.length) }
        }
        fn backing_files(&self) -> &[File] {
            self.backing_calls.fetch_add(1, Ordering::SeqCst);
            &[]
        }
        fn read_at(&mut self, _: u64, _: &mut [u8], _: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
            self.read_calls.fetch_add(1, Ordering::SeqCst);
            Ok(RangeRead::Filled { count: 1 })
        }
    }
    impl Drop for CancelCandidate {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }
    for length in [8, 9] {
        let original = probe(282);
        let original_drops = original.drops.clone();
        let original_reads = original.offsets.clone();
        let (mut d, requests) = setup(true, 64, vec![Box::new(original)]);
        open(&mut d, 0);
        let info_calls = Arc::new(AtomicUsize::new(0));
        let backing_calls = Arc::new(AtomicUsize::new(0));
        let read_calls = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let candidate = CancelCandidate {
            control: d.control.clone(),
            length,
            info_calls: info_calls.clone(),
            backing_calls: backing_calls.clone(),
            read_calls: read_calls.clone(),
            drops: drops.clone(),
        };
        let result = d.supply_replacement(0, Box::new(candidate));
        // Check the valid-length duplicate-call failure independently of error priority.
        assert_eq!(info_calls.load(Ordering::SeqCst), 1, "candidate length {length}");
        assert!(
            matches!(result, Err(ProgressiveFailure { kind: FailureKind::Canceled, .. })),
            "candidate length {length}"
        );
        assert_eq!(backing_calls.load(Ordering::SeqCst), 0);
        assert_eq!(read_calls.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(d.replacements.is_empty());
        assert_eq!(d.original.as_ref().unwrap().live.id, SourceId(282));
        assert_eq!(d.original_count(), 1);
        assert_eq!(d.cursor.offset(), 0);
        assert_eq!(*requests.lock().unwrap(), [0]);
        assert!(original_reads.lock().unwrap().is_empty());
        assert_eq!(original_drops.load(Ordering::SeqCst), 0);
        drop(d);
        assert_eq!(original_drops.load(Ordering::SeqCst), 1);
    }
}
