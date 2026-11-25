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
/// Output written in order is hashed as it lands: verifying its BLAKE2sp reads nothing back (RustyGet: the check at
/// download end no longer re-reads the member).
#[test]
fn blake_of_output_written_in_order_verifies_without_readback() {
    use crate::progressive::Resource;
    let f = Fixture::new(65_537, true, false, true);
    let limits = ProgressiveLimits { read_chunk: 4096, ..ProgressiveLimits::default() };
    let mut file = f.create_with(PartialLimits::default(), limits).unwrap();
    f.hole(&file, 0..65_537);
    f.finish_missing_member(&file);
    for (at, piece) in f.data.chunks(10_000).enumerate() {
        file.fill(at as u64 * 10_000, piece).unwrap();
    }
    let Verdict::Ok { path, parts, metadata, .. } = drive(&mut file) else { panic!("complete BLAKE must verify") };
    assert_eq!(path, VerifyPath::ExtentCombine);
    assert!(parts.iter().all(|p| p.blake2sp == CheckResult::Passed));
    assert!(matches!(metadata.modified, AttributeResult::Applied));
    // The whole read-back budget is still there: nothing was read.
    let cap = ProgressiveLimits::default().verify_bytes;
    assert!(file.core.budget.usage.charge(Resource::VerifyBytes, cap).is_ok(), "no output was read back");
}
/// Output written out of order: the hash follows the prefix up to the first byte written ahead of it, and only the
/// bytes past that point are read back.
#[test]
fn blake_reads_back_only_past_the_in_order_prefix() {
    use crate::progressive::Resource;
    let f = Fixture::new(65_537, true, false, true);
    let limits = ProgressiveLimits { read_chunk: 4096, ..ProgressiveLimits::default() };
    let mut file = f.create_with(PartialLimits::default(), limits).unwrap();
    f.hole(&file, 0..65_537);
    f.finish_missing_member(&file);
    // The tail lands first (a later article), then the head fills up to it.
    file.fill(40_000, &f.data[40_000..]).unwrap();
    file.fill(0, &f.data[..40_000]).unwrap();
    let Verdict::Ok { path, parts, .. } = drive(&mut file) else { panic!("complete BLAKE must verify") };
    assert_eq!(path, VerifyPath::TargetedReadback);
    assert!(parts.iter().all(|p| p.blake2sp == CheckResult::Passed));
    let read = used(&file.core.budget.usage, Resource::VerifyBytes, ProgressiveLimits::default().verify_bytes);
    assert_eq!(read, 65_537 - 40_000);
}
/// Wrong bytes written in order fail the BLAKE2sp check just as a read-back would.
#[test]
fn blake_frontier_still_fails_wrong_bytes() {
    let f = Fixture::new(4_000, false, false, true);
    let mut file = f.create();
    f.hole(&file, 0..4_000);
    f.finish_missing_member(&file);
    let mut data = f.data.clone();
    data[3_999] ^= 1;
    file.fill(0, &data).unwrap();
    assert!(matches!(drive(&mut file), Verdict::Bad { which: ChecksumAlgorithm::Blake2sp, .. }));
}
#[test]
fn blake_frontier_follows_each_checked_range_in_order() {
    use crate::partial::verify::BlakeFrontier;
    let data: Vec<u8> = (0..1000u32).map(|i| (i * 7) as u8).collect();
    let digest = |bytes: &[u8]| {
        let mut h = crate::blake2sp::Blake2sp::new();
        h.update(bytes);
        h.finish()
    };
    let state = |f: &BlakeFrontier, r: std::ops::Range<u64>| {
        f.run(&r).map(|run| (run.at, run.hash.as_ref().map(|d| *d).unwrap_or_else(|h| h.clone().finish())))
    };
    // A part check over 0..400, another over 400..1000, and the member check over 0..1000.
    let ranges = [0..400, 0..1000, 400..1000];
    let fixture = Fixture::new(64, false, false, true);
    let file = fixture.create();
    let budget = &file.core.budget;
    let mut f = BlakeFrontier::default();
    f.feed(&ranges, 100, &data[100..200], budget); // ahead of every start: nothing
    assert!(f.runs.is_empty());
    f.feed(&ranges, 0, &data[..100], budget);
    f.feed(&ranges, 600, &data[600..700], budget); // ahead: ignored
    f.feed(&ranges, 100, &data[100..500], budget); // crosses a part boundary: finishes 0..400, begins 400..1000
    assert_eq!(state(&f, 0..400), Some((400, digest(&data[..400]))));
    assert!(f.run(&(0..400)).unwrap().hash.is_ok(), "a finished run keeps only its digest");
    assert_eq!(state(&f, 0..1000), Some((500, digest(&data[..500]))));
    assert_eq!(state(&f, 400..1000), Some((500, digest(&data[400..500]))));
    f.feed(&ranges, 450, &data[450..460], budget); // a correction inside 400..1000 and 0..1000
    assert!(f.run(&(400..1000)).is_none() && f.run(&(0..1000)).is_none());
    assert!(f.run(&(0..400)).is_some(), "a range the correction does not touch keeps its digest");
    f.feed(&ranges, 0, &data[..10], budget); // a write at the start begins 0..400 and 0..1000 again
    assert_eq!(state(&f, 0..400), Some((10, digest(&data[..10]))));
    assert_eq!(state(&f, 0..1000), Some((10, digest(&data[..10]))));
}
/// A hash is begun only when the budget grants it; refused, the range is simply read back when verified.
#[test]
fn blake_frontier_runs_are_charged_to_the_partial_budget() {
    use crate::partial::verify::BlakeFrontier;
    let fixture = Fixture::new(64, false, false, true);
    let file = fixture.create();
    let budget = &file.core.budget;
    let mut hogs = Vec::new();
    while let Ok(lease) = budget.reserve(PartialResource::LedgerBytes, 4096) {
        hogs.push(lease);
    }
    let mut f = BlakeFrontier::default();
    f.feed(std::slice::from_ref(&(0..100)), 0, &[1; 10], budget);
    assert!(f.runs.is_empty(), "no budget, no hash");
    // A range finished in one write needs no hasher held, so it costs nothing.
    f.feed(std::slice::from_ref(&(0..10)), 0, &[1; 10], budget);
    assert!(f.run(&(0..10)).is_some_and(|run| run.hash.is_ok()));
    drop(hogs);
    f.feed(std::slice::from_ref(&(0..100)), 0, &[1; 10], budget);
    assert!(f.run(&(0..100)).is_some());
}
/// Emulates a reopened handle: no hash was kept while writing, so BLAKE2sp checks read the output back.
fn forget_blake(file: &PartialFile) {
    file.core.operation().unwrap().blake = Default::default();
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
    forget_blake(&file);
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
            // Scratch charges are leased and released, so setup may peak above
            // its net usage; tighten the budget only for the verification step.
            let f = Fixture::new(33, true, true, false);
            let mut file = f.create_with(PartialLimits::default(), ProgressiveLimits::default()).unwrap();
            f.hole(&file, 0..33);
            f.finish_missing_member(&file);
            file.fill(0, if incomplete { &f.data[..17] } else { &f.data }).unwrap();
            let start = used(&file.core.budget.usage, Resource::MetadataBytes, cap);
            assert_eq!(start, before);
            file.core.budget.usage.set_limit_for_test(Resource::MetadataBytes, after - u64::from(!exact));
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
        forget_blake(&file);
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
        forget_blake(&file);
        let Verdict::Ok { path, parts, .. } = drive(&mut file) else { panic!("verified") };
        assert_eq!(path, if targeted { VerifyPath::TargetedReadback } else { VerifyPath::ExtentCombine });
        assert_eq!(parts[1].blake2sp, CheckResult::Missing);
        let cap = ProgressiveLimits::default().verify_work_bytes;
        // 33 hashed into leaves, 17 for part 0, 33 for the final part; the member CRC reuses the final part.
        assert_eq!(used(&file.core.budget.usage, Resource::VerifyWorkBytes, cap), 83 + if targeted { 17 } else { 0 });
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
#[test]
fn per_write_scratch_is_released_and_part_checks_are_reused() {
    // Every original write commits a transaction. Its scratch (compare buffer,
    // state and ledger copies, encoded pages, journal names and exclusions)
    // must be released, and part CRCs combined once, or a long member runs out
    // of MetadataBytes, ProtectionPathBytes or VerifyWorkBytes.
    use crate::progressive::Resource;
    const CHUNK: usize = 4096;
    let f = Fixture::new(168 * CHUNK, true, true, false);
    let file = f.create();
    let usage = &file.core.budget.usage;
    let defaults = ProgressiveLimits::default();
    let snapshot = |usage: &crate::progressive::Usage| {
        [
            used(usage, Resource::MetadataBytes, defaults.metadata_bytes),
            used(usage, Resource::ProtectionPathBytes, defaults.protection_path_bytes),
            used(usage, Resource::VerifyWorkBytes, defaults.verify_work_bytes),
        ]
    };
    let mut at = 0;
    for _ in 0..8 {
        file.core.write_original(at as u64, &f.data[at..at + CHUNK]).unwrap();
        at += CHUNK;
    }
    let early = snapshot(usage);
    while at < f.data.len() {
        file.core.write_original(at as u64, &f.data[at..at + CHUNK]).unwrap();
        at += CHUNK;
    }
    let late = snapshot(usage);
    let writes = (f.data.len() / CHUNK - 8) as u64;
    // What stays is the ledger (one leaf per 64 KiB) plus journal files and
    // their exclusions until the next compaction: bounded, unlike the old
    // charges of at least one compare buffer per write.
    assert!(writes * CHUNK as u64 > 600 << 10);
    assert!(late[0] - early[0] < 256 << 10, "MetadataBytes grew {} over {writes} writes", late[0] - early[0]);
    // Journal files come and go with compaction; their exclusions go with them.
    assert!(late[1] - early[1] < 128 << 10, "ProtectionPathBytes grew {}", late[1] - early[1]);
    // Hash each byte into a leaf, combine part 0 once and the final part once.
    assert!(late[2] <= 3 * f.data.len() as u64, "VerifyWorkBytes {}", late[2]);
}

// Catches the member CRC being taken from a final-part check that never ran (encrypted parts are not checked
// on plaintext), which let corrupt output of an encrypted member without tweaked CRCs verify.
#[test]
fn encrypted_member_crc_is_not_taken_from_an_unrun_part_check() {
    let f = Fixture::new(33, false, true, false);
    let mut file = f.create();
    f.hole(&file, 0..33);
    f.finish_missing_member(&file);
    let mut data = f.data.clone();
    data[20] ^= 1;
    file.fill(0, &data).unwrap();
    let op = file.core.operation().unwrap();
    let (mut snapshot, _lease) = file.core.clone_snapshot(&op.snapshot).unwrap();
    drop(op);
    snapshot.crypt = Some(crate::crypto::Rar5CryptParams {
        kdf_count: 1,
        salt: [0; 16],
        iv: [0; 16],
        check: None,
        tweaked_crc: false,
    });
    let checks = crate::partial::verify::Verification::new(&snapshot, &file.core.budget, None).unwrap();
    assert_eq!(checks.member_crc(), &CheckResult::Failed);
}
