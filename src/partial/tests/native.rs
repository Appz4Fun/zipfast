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

use super::state::Fixture;
use crate::partial::*;
use crate::progressive::*;
use std::fs;

// Catches resize-on-reopen and silently adopting a changed output identity.
#[test]
fn reopen_rejects_short_long_and_hardlinked_output_without_changes() {
    for len in [15, 17] {
        let f = Fixture::new();
        let state = f.create().unwrap().close().unwrap();
        fs::OpenOptions::new().write(true).open(f.output()).unwrap().set_len(len).unwrap();
        assert!(matches!(f.open(state).err().unwrap().kind, PartialErrorKind::OutputChanged));
        assert_eq!(fs::metadata(f.output()).unwrap().len(), len);
    }
    let f = Fixture::new();
    let state = f.create().unwrap().close().unwrap();
    fs::hard_link(f.output(), f.dir.path().join("alias")).unwrap();
    assert!(matches!(f.open(state).err().unwrap().kind, PartialErrorKind::UnsafePath));
    assert_eq!(fs::read(f.output()).unwrap(), vec![0; 16]);
}
// Catches following symlink outputs/parents or accepting a replaced held root.
#[test]
fn no_follow_and_parent_swap_preserve_existing_bytes() {
    use std::os::unix::fs::symlink;
    let f = Fixture::new();
    let victim = f.dir.path().join("victim");
    fs::write(&victim, b"do not modify").unwrap();
    symlink(&victim, f.output()).unwrap();
    assert!(f.create().is_err());
    assert_eq!(fs::read(&victim).unwrap(), b"do not modify");
    let f = Fixture::new();
    let file = f.create().unwrap();
    fs::rename(f.dir.path().join("out"), f.dir.path().join("old-out")).unwrap();
    fs::create_dir(f.dir.path().join("out")).unwrap();
    fs::write(f.output(), b"replacement").unwrap();
    assert!(file.core.write_original(0, b"abcd").is_err());
    assert_eq!(fs::read(f.output()).unwrap(), b"replacement");
    assert_eq!(fs::read(f.dir.path().join("old-out/member.bin")).unwrap(), vec![0; 16]);
}
// Catches late partial-specific admission after named file effects.
#[test]
fn creation_fd_page_record_caps_are_reserved_before_effects() {
    for (fd, pages, records, resource) in [
        (6, 3, 2, PartialResource::OpenFiles),
        (7, 2, 2, PartialResource::StatePages),
        (7, 3, 1, PartialResource::JournalRecords),
    ] {
        let f = Fixture::new();
        let mut limits = PartialLimits::default();
        limits.open_files = fd;
        limits.state_pages = pages;
        limits.journal_records = records;
        let error = f.create_with(limits, ProgressiveLimits::default(), SessionControl::default()).err().unwrap();
        assert!(matches!(error.kind,PartialErrorKind::Limit {resource:r,..} if r==resource), "{error:?}");
        assert!(!f.output().exists(), "budget failure must precede named output creation");
        assert_eq!(fs::read_dir(f.dir.path().join("state")).unwrap().count(), 0);
    }
    let f = Fixture::new();
    let mut limits = PartialLimits::default();
    limits.open_files = 7;
    limits.state_pages = 3;
    limits.journal_records = 2;
    let file = f.create_with(limits, ProgressiveLimits::default(), SessionControl::default()).unwrap();
    assert_eq!(file.remaining().unwrap(), vec![0..16]);
}
// Catches losing exact retained Usage resource/error data at the partial boundary.
#[test]
fn legacy_work_limits_remain_typed_and_precede_output_writes() {
    let f = Fixture::new();
    let progressive = ProgressiveLimits { metadata_bytes: 0, ..Default::default() };
    let error = f.create_with(PartialLimits::default(), progressive, SessionControl::default()).err().unwrap();
    assert!(
        matches!(error.kind,PartialErrorKind::Progressive(ref e) if matches!(e.kind,FailureKind::Limit {resource:Resource::MetadataBytes,limit:0,..})),
        "{error:?}"
    );
    assert!(!f.output().exists());
    let f = Fixture::new();
    let progressive = ProgressiveLimits { output_write_bytes: 3, ..Default::default() };
    let file = f.create_with(PartialLimits::default(), progressive, SessionControl::default()).unwrap();
    let error = file.core.write_original(0, b"abcd").unwrap_err();
    assert!(
        matches!(error.kind,PartialErrorKind::Progressive(ref e) if matches!(e.kind,FailureKind::Limit {resource:Resource::OutputWriteBytes,limit:3,attempted:4})),
        "{error:?}"
    );
    assert_eq!(fs::read(f.output()).unwrap(), vec![0; 16]);
    let f = Fixture::new();
    let file = f.create().unwrap();
    file.core.write_original(0, b"abcd").unwrap();
    let state = file.close().unwrap();
    let mut context = f.context();
    context.progressive_limits.verify_bytes = 0;
    let error = PartialFile::open(state, context).err().unwrap();
    assert!(
        matches!(error.kind,PartialErrorKind::Progressive(ref e) if matches!(e.kind,FailureKind::Limit {resource:Resource::VerifyBytes,limit:0,..})),
        "{error:?}"
    );
    assert_eq!(&fs::read(f.output()).unwrap()[..4], b"abcd");
}
// Catches ignoring cancellation at local-open admission or converting zero chunk to one.
#[test]
fn open_rehash_is_bounded_and_cancelable() {
    let f = Fixture::new();
    let file = f.create().unwrap();
    file.core.write_original(0, b"abcd").unwrap();
    let state = file.close().unwrap();
    let mut context = f.context();
    context.control.cancel();
    assert!(matches!(PartialFile::open(state.clone(), context).err().unwrap().kind, PartialErrorKind::Canceled));
    context = f.context();
    context.progressive_limits.read_chunk = 0;
    assert!(matches!(PartialFile::open(state.clone(), context).err().unwrap().kind, PartialErrorKind::InvalidOptions));
    context = f.context();
    context.progressive_limits.read_chunk = 1;
    context.progressive_limits.verify_bytes = 4;
    let opened = PartialFile::open(state, context).unwrap();
    assert_eq!(opened.remaining().unwrap(), vec![4..16]);
}

// Catches slicing attacker-controlled UTF-8 directory names at an invalid boundary.
#[test]
fn malformed_bundle_names_return_errors_without_panicking() {
    let f = Fixture::new();
    let state = f.create().unwrap().close().unwrap();
    let bundle = f.dir.path().join("state").join(crate::partial::native::bundle_name(&f.member));
    fs::write(bundle.join(format!("€{}", "a".repeat(63))), b"untrusted").unwrap();
    assert!(matches!(f.open(state).err().unwrap().kind, PartialErrorKind::StateMalformed));
    assert_eq!(fs::read(f.output()).unwrap(), vec![0; 16]);
}
// Catches accepting fabricated metadata that contradicts the canonical header witness.
#[test]
fn creation_metadata_must_match_witness_before_effects() {
    let f = Fixture::new();
    let mut spec = f.spec();
    spec.evidence.metadata.mtime = Some(0);
    assert!(
        PartialCore::create(
            spec,
            MemberChecks { size: 16, crc32: Some(crc32fast::hash(b"abcdefghijklmnop")), blake2sp: None },
            f.options(PartialLimits::default(), ProgressiveLimits::default(), SessionControl::default())
        )
        .is_err()
    );
    assert!(!f.output().exists());
}
// Catches silent clamping of each hard ceiling and omitted zero-capacity admission.
#[test]
fn all_partial_hard_caps_reject_one_over_without_names() {
    for index in 0..10 {
        let f = Fixture::new();
        let mut limits = PartialLimits::default();
        match index {
            0 => limits.state_wire_bytes = 65_537,
            1 => limits.state_pages = 129,
            2 => limits.ledger_bytes = 67_108_865,
            3 => limits.journal_bytes = 67_108_865,
            4 => limits.journal_records = 65_537,
            5 => limits.crc_leaves = 1_048_577,
            6 => limits.open_files = 4097,
            7 => limits.open_partials = 4097,
            8 => limits.events = 65,
            9 => limits.fill_bytes = 1_048_577,
            _ => unreachable!(),
        }
        assert!(matches!(
            f.create_with(limits, ProgressiveLimits::default(), SessionControl::default()).err().unwrap().kind,
            PartialErrorKind::Limit { .. }
        ));
        assert!(!f.output().exists());
    }
    for events in [false, true] {
        let f = Fixture::new();
        let mut limits = PartialLimits::default();
        if events {
            limits.events = 0
        } else {
            limits.open_partials = 0
        };
        assert!(f.create_with(limits, ProgressiveLimits::default(), SessionControl::default()).is_err());
        assert!(!f.output().exists());
    }
}
// Catches an off-by-one wire, ledger-byte or journal-byte reservation.
#[test]
fn exact_wire_ledger_and_journal_bytes_are_admitted() {
    let baseline = Fixture::new();
    let state = baseline.create().unwrap().close().unwrap();
    let wire = state.wire.len() as u64;
    let bundle = baseline.dir.path().join("state").join(crate::partial::native::bundle_name(&baseline.member));
    let ledger = fs::read_dir(bundle)
        .unwrap()
        .map(|e| e.unwrap())
        .filter(|e| e.file_name().to_str().unwrap().starts_with("p-"))
        .map(|e| e.metadata().unwrap().len())
        .sum::<u64>();
    let mut limits = PartialLimits::default();
    limits.state_wire_bytes = wire as u32;
    assert!(PartialState::load(&baseline.dir.path().join("state"), state.anchor(), &limits).is_ok());
    limits.state_wire_bytes -= 1;
    assert!(PartialState::load(&baseline.dir.path().join("state"), state.anchor(), &limits).is_err());
    for short in [false, true] {
        let f = Fixture::new();
        let limits =
            PartialLimits { ledger_bytes: ledger - u64::from(short), journal_bytes: wire * 2, ..Default::default() };
        let result = f.create_with(limits, ProgressiveLimits::default(), SessionControl::default());
        assert_eq!(result.is_err(), short);
        if short {
            assert!(!f.output().exists());
        }
    }
    let f = Fixture::new();
    let limits = PartialLimits { ledger_bytes: ledger, journal_bytes: wire * 2 - 1, ..Default::default() };
    assert!(f.create_with(limits, ProgressiveLimits::default(), SessionControl::default()).is_err());
    assert!(!f.output().exists());
}

// Catches charging unknown-output geometry to the known CRC leaf capacity.
#[test]
fn zero_crc_leaf_capacity_still_reopens_unknown_output() {
    let f = Fixture::new();
    let limits = PartialLimits { crc_leaves: 0, ..Default::default() };
    let state = f
        .create_with(limits.clone(), ProgressiveLimits::default(), SessionControl::default())
        .unwrap()
        .close()
        .unwrap();
    let mut context = f.context();
    context.limits = limits;
    let file = PartialFile::open(state, context).unwrap();
    assert_eq!(file.remaining().unwrap(), vec![0..16]);
    assert!(matches!(
        file.core.write_original(0, b"a").unwrap_err().kind,
        PartialErrorKind::Limit { resource: PartialResource::CrcLeaves, .. }
    ));
    assert_eq!(fs::read(f.output()).unwrap(), vec![0; 16]);
}
#[test]
fn each_native_lock_independently_excludes_reopen() {
    use std::os::fd::AsRawFd;
    for bundle_lock in [false, true] {
        let f = Fixture::new();
        let state = f.create().unwrap().close().unwrap();
        let path = if bundle_lock {
            f.dir.path().join("state").join(crate::partial::native::bundle_name(&f.member)).join("lock")
        } else {
            f.output()
        };
        let held = fs::OpenOptions::new().read(true).write(true).open(path).unwrap();
        // Tests take the same nonblocking native lock through an independent open.
        assert_eq!(unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }, 0);
        assert!(matches!(f.open(state.clone()).err().unwrap().kind, PartialErrorKind::Busy));
        drop(held);
        assert_eq!(f.open(state).unwrap().remaining().unwrap(), vec![0..16]);
    }
}

// A failed creation must identify the bundle it already created, without removing it.
#[test]
fn creation_failure_reports_retained_bundle_location() {
    let f = Fixture::new();
    let mut progressive = ProgressiveLimits::default();
    progressive.protection_paths = 2;
    let error = f.create_with(PartialLimits::default(), progressive, SessionControl::default()).err().unwrap();
    let location = error.location.expect("created bundle must be reported");
    assert!(location.state_bundle.is_dir());
    assert_eq!(location.output, f.output());
    assert!(!f.output().exists());
    assert_eq!(fs::read_dir(&location.state_bundle).unwrap().count(), 0);
}
