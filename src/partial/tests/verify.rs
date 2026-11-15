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

use super::ledger::Fixture;
use crate::partial::*;
use crate::progressive::{ChecksumAlgorithm, ProgressiveLimits};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};
#[derive(Default)]
struct WakeCheck {
    calls: AtomicUsize,
    file: Mutex<Option<PartialFile>>,
}
impl Wake for WakeCheck {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(f) = self.file.lock().unwrap().as_ref() {
            f.remaining().expect("waker outside owner operation");
        }
    }
}
fn drive(file: &mut PartialFile) -> Verdict {
    let wake = Arc::new(WakeCheck::default());
    *wake.file.lock().unwrap() = Some(file.clone());
    let waker = Waker::from(wake.clone());
    let mut cx = Context::from_waker(&waker);
    for _ in 0..30_000 {
        match file.poll_verify(&mut cx) {
            Poll::Ready(value) => return value.unwrap(),
            Poll::Pending => assert!(wake.calls.load(Ordering::SeqCst) > 0),
        }
    }
    panic!("bounded local work never completed")
}
#[test]
fn missing_hash_is_not_ok() {
    let f = Fixture::new(33, false, false, false);
    let mut file = f.create();
    f.hole(&file, 0..33);
    f.finish_missing_member(&file);
    file.fill(0, &f.data).unwrap();
    assert!(matches!(drive(&mut file),Verdict::Incomplete {holes,missing_checks:true,..} if holes.is_empty()));
}
#[test]
fn crc_verdict_distinguishes_part_and_member_scope() {
    for bad in [5, 32] {
        let f = Fixture::new(33, true, true, false);
        let mut file = f.create();
        f.hole(&file, 0..33);
        f.finish_missing_member(&file);
        let mut data = f.data.clone();
        data[bad] ^= 1;
        let mut borrowed = file.clone();
        let filled = file.fill(0, &data).unwrap();
        assert!(matches!(borrowed.fill(0, &f.data).unwrap_err().kind, PartialErrorKind::OverlapMismatch { .. }));
        match (bad, drive(&mut borrowed)) {
            (5, Verdict::PartBad { volume: 0, part: 0, which: ChecksumAlgorithm::Crc32, revision })
            | (32, Verdict::Bad { which: ChecksumAlgorithm::Crc32, revision }) => {
                assert_eq!(revision, filled.revision);
            }
            other => panic!("wrong scope: {other:?}"),
        }
    }
}
#[test]
fn blake_verification_uses_readback() {
    let f = Fixture::new(65_537, true, false, true);
    let limits = ProgressiveLimits { read_chunk: 4096, verify_bytes: 65_554, ..ProgressiveLimits::default() };
    let mut file = f.create_with(PartialLimits::default(), limits).unwrap();
    f.hole(&file, 0..65_537);
    f.finish_missing_member(&file);
    file.fill(0, &f.data).unwrap();
    let Verdict::Ok { path, parts, metadata, .. } = drive(&mut file) else { panic!("complete BLAKE must verify") };
    assert_eq!(path, VerifyPath::WholeReadback);
    assert!(parts.iter().all(|p| p.blake2sp == CheckResult::Passed));
    assert!(matches!(metadata.modified, AttributeResult::Applied));
    assert!(file.core.budget.usage.charge(crate::progressive::Resource::VerifyBytes, 1).is_err());
}
fn deferred(reopen: bool) {
    let f = Fixture::new(33, true, false, true);
    let file = f.create();
    f.hole(&file, 0..33);
    f.finish_missing_member(&file);
    file.core.fill_plain(0, &f.data[..17]).unwrap();
    let mut handle = if reopen {
        let state = file.close().unwrap();
        PartialFile::open(state, f.context()).unwrap()
    } else {
        let handle = file.clone();
        drop(file);
        handle
    };
    let Verdict::Incomplete { revision, holes, parts, missing_checks: false } = drive(&mut handle) else {
        panic!("partial BLAKE snapshot")
    };
    assert_eq!(holes, vec![17..33]);
    assert_eq!((parts[0].volume, parts[0].part, parts[0].range.clone()), (0, 0, 0..17));
    assert_eq!(parts[0].blake2sp, CheckResult::Passed);
    assert_eq!(parts[0].crc32, CheckResult::Missing);
    assert_eq!(parts[1].blake2sp, CheckResult::Pending);
    let filled = handle.fill(17, &f.data[17..]).unwrap();
    assert!(filled.revision > revision);
    assert_eq!(filled.part_checks[0].blake2sp, CheckResult::Pending);
    assert!(matches!(drive(&mut handle), Verdict::Ok { .. }));
}
#[test]
fn standalone_incomplete_exposes_deferred_part_success() {
    deferred(false);
}
#[test]
fn reopened_incomplete_exposes_deferred_part_success() {
    deferred(true);
}
#[test]
fn changed_revision_invalidates_verify() {
    let f = Fixture::new(33, true, false, true);
    let limits = ProgressiveLimits { read_chunk: 3, ..ProgressiveLimits::default() };
    let mut file = f.create_with(PartialLimits::default(), limits).unwrap();
    f.hole(&file, 0..33);
    f.finish_missing_member(&file);
    file.fill(0, &f.data[..17]).unwrap();
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    assert!(file.poll_verify(&mut cx).is_pending());
    let filled = file.fill(17, &f.data[17..]).unwrap();
    assert!(filled.part_checks.iter().all(|p| p.blake2sp == CheckResult::Pending));
    assert!(matches!(drive(&mut file),Verdict::Ok {revision,..} if revision==filled.revision));
}
#[test]
fn reopen_never_trusts_serialized_crc() {
    use std::os::unix::fs::FileExt;
    let f = Fixture::new(33, true, true, false);
    let file = f.create();
    file.core.write_original(0, &f.data).unwrap();
    let state = file.close().unwrap();
    std::fs::OpenOptions::new().write(true).open(f.output()).unwrap().write_at(b"x", 4).unwrap();
    assert!(PartialFile::open(state, f.context()).is_err());
}

fn used(usage: &crate::progressive::Usage, resource: crate::progressive::Resource, limit: u64) -> u64 {
    let error = usage.charge(resource, limit).unwrap_err();
    match error.kind {
        crate::progressive::FailureKind::Limit { attempted, .. } => attempted - limit,
        _ => panic!("typed budget"),
    }
}
#[test]
fn part_snapshots_are_revision_bound_and_bounded() {
    use crate::progressive::Resource;
    for incomplete in [false, true] {
        let f = Fixture::new(33, true, true, false);
        let mut file = f.create();
        f.hole(&file, 0..33);
        f.finish_missing_member(&file);
        file.fill(0, if incomplete { &f.data[..17] } else { &f.data }).unwrap();
        let cap = ProgressiveLimits::default().metadata_bytes;
        let before = used(&file.core.budget.usage, Resource::MetadataBytes, cap);
        let first = drive(&mut file);
        let after = used(&file.core.budget.usage, Resource::MetadataBytes, cap);
        let second = drive(&mut file);
        let repeated = used(&file.core.budget.usage, Resource::MetadataBytes, cap);
        assert_eq!(after - before, repeated - after);
        assert_eq!(
            after - before,
            (2 * std::mem::size_of::<PartCheck>()
                + if incomplete { std::mem::size_of::<std::ops::Range<u64>>() } else { 0 }) as u64
        );
        assert_eq!(std::mem::discriminant(&first), std::mem::discriminant(&second));
        for exact in [false, true] {
            let f = Fixture::new(33, true, true, false);
            let progressive =
                ProgressiveLimits { metadata_bytes: after - u64::from(!exact), ..ProgressiveLimits::default() };
            let mut file = f.create_with(PartialLimits::default(), progressive).unwrap();
            f.hole(&file, 0..33);
            f.finish_missing_member(&file);
            file.fill(0, if incomplete { &f.data[..17] } else { &f.data }).unwrap();
            let waker = Waker::noop();
            let mut cx = Context::from_waker(waker);
            let Poll::Ready(result) = file.poll_verify(&mut cx) else { panic!("CRC is immediate") };
            if exact {
                result.unwrap();
            } else {
                assert!(
                    matches!(result.unwrap_err().kind,PartialErrorKind::Progressive(f) if matches!(f.kind,crate::progressive::FailureKind::Limit {resource:Resource::MetadataBytes,..}))
                );
            }
        }
    }
}
#[test]
fn blake_readback_cap_is_exact_and_chunk_bounded() {
    for exact in [false, true] {
        let f = Fixture::new(33, true, false, true);
        let progressive = ProgressiveLimits {
            verify_bytes: if exact { 50 } else { 49 },
            read_chunk: 7,
            ..ProgressiveLimits::default()
        };
        let mut file = f.create_with(PartialLimits::default(), progressive).unwrap();
        f.hole(&file, 0..33);
        f.finish_missing_member(&file);
        file.fill(0, &f.data).unwrap();
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut polls = 0;
        loop {
            polls += 1;
            match file.poll_verify(&mut cx) {
                Poll::Pending => {}
                Poll::Ready(result) => {
                    if exact {
                        assert!(matches!(result.unwrap(), Verdict::Ok { .. }));
                    } else {
                        assert!(matches!(result.unwrap_err().kind, PartialErrorKind::Progressive(_)));
                    }
                    break;
                }
            }
        }
        assert_eq!(polls, 8);
    }
}

#[test]
fn crc_combine_and_targeted_readback_report_actual_work() {
    use crate::progressive::Resource;
    for targeted in [false, true] {
        let f = Fixture::with_hashes(33, true, true, targeted, true);
        let mut file = f.create();
        f.hole(&file, 0..33);
        f.finish_missing_member(&file);
        file.fill(0, &f.data).unwrap();
        let Verdict::Ok { path, parts, .. } = drive(&mut file) else { panic!("verified") };
        assert_eq!(path, if targeted { VerifyPath::TargetedReadback } else { VerifyPath::ExtentCombine });
        assert_eq!(parts[1].blake2sp, CheckResult::Missing);
        let cap = ProgressiveLimits::default().verify_work_bytes;
        assert_eq!(used(&file.core.budget.usage, Resource::VerifyWorkBytes, cap), 116 + if targeted { 17 } else { 0 });
        if targeted {
            assert_eq!(
                used(&file.core.budget.usage, Resource::VerifyBytes, ProgressiveLimits::default().verify_bytes),
                17
            );
        } else {
            file.core.budget.usage.charge(Resource::VerifyBytes, ProgressiveLimits::default().verify_bytes).unwrap();
        }
    }
}
#[test]
fn blake_verdict_preserves_part_and_member_identity() {
    for bad in [5, 32] {
        let f = Fixture::new(33, true, false, true);
        let mut file = f.create();
        f.hole(&file, 0..33);
        f.finish_missing_member(&file);
        let mut data = f.data.clone();
        data[bad] ^= 1;
        let mut borrowed = file.clone();
        let filled = file.fill(0, &data).unwrap();
        assert!(matches!(borrowed.fill(0, &f.data).unwrap_err().kind, PartialErrorKind::OverlapMismatch { .. }));
        match (bad, drive(&mut borrowed)) {
            (5, Verdict::PartBad { volume: 0, part: 0, which: ChecksumAlgorithm::Blake2sp, revision })
            | (32, Verdict::Bad { which: ChecksumAlgorithm::Blake2sp, revision }) => {
                assert_eq!(revision, filled.revision);
            }
            other => panic!("wrong BLAKE scope: {other:?}"),
        }
    }
}
#[test]
fn retained_part_storage_counts_against_ledger_bytes() {
    let f = Fixture::new(33, true, true, false);
    let file = f.create();
    let cap = PartialLimits::default().ledger_bytes;
    let base = match file.core.budget.reserve(PartialResource::LedgerBytes, cap) {
        Err(PartialError { kind: PartialErrorKind::Limit { attempted, .. }, .. }) => attempted - cap,
        _ => panic!("live pages must count"),
    };
    let needed = std::mem::size_of::<crate::partial::verify::Verification>() as u64
        + 2 * std::mem::size_of::<PartCheck>() as u64;
    for exact in [false, true] {
        let f = Fixture::new(33, true, true, false);
        let limits = PartialLimits { ledger_bytes: base + needed - u64::from(!exact), ..PartialLimits::default() };
        let file = f.create_with(limits, ProgressiveLimits::default()).unwrap();
        let op = file.core.operation().unwrap();
        let result = crate::partial::verify::Verification::new(&op.snapshot, &file.core.budget, None);
        if exact {
            let _held = result.unwrap();
            assert!(file.core.budget.reserve(PartialResource::LedgerBytes, 1).is_err());
        } else {
            assert!(matches!(
                result,
                Err(PartialError { kind: PartialErrorKind::Limit { resource: PartialResource::LedgerBytes, .. }, .. })
            ));
        }
    }
}
