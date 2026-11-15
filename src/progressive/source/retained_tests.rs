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
    assert!(matches!(poll(&mut d), Poll::Ready(Ok(SourceStep::Filled { offset: 0, count: 1 }))));
    assert_eq!(*requests.lock().unwrap(), [0, 1]);
    drop(d);
    assert_eq!(adrop.load(Ordering::SeqCst), 1);
    assert_eq!(bdrop.load(Ordering::SeqCst), 1);
}
