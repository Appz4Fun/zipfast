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

//! Stored recovery through the public progressive session.
mod common;
use common::{FileSpec, archive};
use std::{
    ffi::OsString,
    fs::File,
    ops::Range,
    task::{Context, Poll, Waker},
};
use zipfast::progressive::*;
fn one(range: Range<u64>) -> Vec<Range<u64>> {
    std::iter::once(range).collect()
}
struct Bytes {
    data: Vec<u8>,
    holes: Vec<Range<u64>>,
}
impl RangeSource for Bytes {
    fn info(&self) -> SourceInfo {
        SourceInfo {
            id: SourceId(1),
            generation: 0,
            extent: self.data.len() as u64,
            length: SourceLength::Final(self.data.len() as u64),
        }
    }
    fn backing_files(&self) -> &[File] {
        &[]
    }
    fn read_at(&mut self, at: u64, buf: &mut [u8], _: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
        let mut end = (at + buf.len() as u64).min(self.data.len() as u64);
        for h in &self.holes {
            if h.start <= at && at < h.end {
                return Ok(RangeRead::Hole { len: (h.end - at).min(buf.len() as u64) });
            }
            if h.start > at {
                end = end.min(h.start);
            }
        }
        let n = (end - at) as usize;
        buf[..n].copy_from_slice(&self.data[at as usize..end as usize]);
        Ok(RangeRead::Filled { count: n })
    }
}
struct Provider(Option<Bytes>);
impl VolumeSource for Provider {
    fn volume(&mut self, _: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
        Ok(VolumeAnswer::Ready(Box::new(self.0.take().unwrap())))
    }
}
fn options(dest: &std::path::Path) -> ProgressiveOptions {
    let mut o = ProgressiveOptions::new(
        zipfast::extract::Options {
            mode: zipfast::extract::Mode::Extract,
            dest: dest.to_owned(),
            overwrite: zipfast::extract::Overwrite::Always,
            flatten: false,
            threads: Some(1),
            protected_paths: Default::default(),
            parallel_min: None,
            select: None,
            windows_safe_names: false,
            special_entries: Default::default(),
            fallback_mtime: None,
            compressed_tar: Default::default(),
            version_naming: Default::default(),
            preexisting_links: Default::default(),
            refused_link_placeholder: false,
            restart_from_first_volume: false,
            replace_placed_links: false,
            keep_broken: false,
            attempt_continued_members: false,
            encrypted_links: Default::default(),
            damaged_input: Default::default(),
            unsupported_filters: Default::default(),
            unverified_output: Default::default(),
            salvage_truncated_zip: false,
            seven_zip_strict: false,
            unix_modes: Default::default(),
            backslashes: Default::default(),
            hard_link_targets: Default::default(),
        },
        OsString::from("a.rar"),
    );
    o.hole_policy = HolePolicy::PartialStored { fill: HoleFill::Sparse };
    o
}
#[test]
fn plain_store_continues_through_interior_hole() {
    let dir = tempfile::tempdir().unwrap();
    let plain = b"0123456789abcdefghijklmnopqrstuv";
    let data = archive(&[FileSpec::new("inner", plain)]);
    let start = data.windows(plain.len()).position(|b| b == plain).unwrap() as u64;
    let mut s = ProgressiveSession::new(
        Box::new(Provider(Some(Bytes { data, holes: one(start + 3..start + 7) }))),
        options(dir.path()),
    )
    .unwrap();
    let mut valid = 0;
    for _ in 0..1000 {
        match s.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Pending => {}
            Poll::Ready(Ok(Some(ProgressiveEvent::BytesWritten { valid_bytes, .. }))) => valid += valid_bytes,
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished {
                outcome: MemberOutcome::Partial(mut a), ..
            }))) => {
                assert_eq!(a.holes(), &[OutputHole { offset: 3, len: 4 }]);
                assert_eq!(a.size(), Some(plain.len() as u64));
                assert_eq!(valid, plain.len() as u64 - 4);
                let mut b = [0u8; 32];
                assert_eq!(a.read_at(7, &mut b).unwrap(), ArtifactRead::Filled { count: 25 });
                assert_eq!(&b[..25], &plain[7..]);
                assert!(!dir.path().join("inner").exists());
                return;
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { .. }))) => panic!("expected Partial"),
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) => {
                panic!("terminated: {failure}")
            }
            Poll::Ready(Err(e)) => panic!("{e}"),
            Poll::Ready(Ok(None)) => panic!("no artifact"),
            _ => {}
        }
    }
    panic!("did not finish");
}

fn artifact(s: &mut ProgressiveSession) -> Artifact {
    for _ in 0..100000 {
        match s.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Pending => {}
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished {
                outcome: MemberOutcome::Partial(a) | MemberOutcome::Provisional(a),
                ..
            }))) => return a,
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) | Poll::Ready(Err(failure)) => {
                panic!("{failure}")
            }
            Poll::Ready(Ok(None)) => panic!("no artifact"),
            _ => {}
        }
    }
    panic!("no progress")
}
fn verify(s: &mut ProgressiveSession, a: &mut Artifact) -> ProgressiveResult<Verification> {
    for _ in 0..100000 {
        match s.poll_verify(a, &mut Context::from_waker(Waker::noop())) {
            Poll::Pending => {}
            Poll::Ready(r) => return r,
        }
    }
    panic!("verify did not finish")
}
fn plain_session(
    dest: &std::path::Path,
    plain: &[u8],
    holes: Vec<Range<u64>>,
    no_crc: bool,
    fill: HoleFill,
) -> ProgressiveSession {
    let mut spec = FileSpec::new("inner", plain);
    spec.no_crc = no_crc;
    let data = archive(&[spec]);
    let start = data.windows(plain.len()).position(|b| b == plain).unwrap() as u64;
    let mut opts = options(dest);
    opts.hole_policy = HolePolicy::PartialStored { fill };
    ProgressiveSession::new(
        Box::new(Provider(Some(Bytes {
            data,
            holes: holes.into_iter().map(|h| start + h.start..start + h.end).collect(),
        }))),
        opts,
    )
    .unwrap()
}
#[test]
fn plain_leading_trailing_adjacent_sparse_zero_patch_verify() {
    let plain = b"0123456789abcdefghijklmnopqrstuv";
    for fill in [HoleFill::Sparse, HoleFill::Zero] {
        let dir = tempfile::tempdir().unwrap();
        let mut s = plain_session(dir.path(), plain, vec![0..3, 3..7, 25..32], false, fill);
        let mut a = artifact(&mut s);
        assert_eq!(a.holes(), &[OutputHole { offset: 0, len: 7 }, OutputHole { offset: 25, len: 7 }]);
        assert!(matches!(verify(&mut s, &mut a).unwrap_err().kind, FailureKind::IncompleteOutput));
        s.patch(&mut a, 1, &plain[1..6]).unwrap();
        assert_eq!(
            a.holes(),
            &[OutputHole { offset: 0, len: 1 }, OutputHole { offset: 6, len: 1 }, OutputHole { offset: 25, len: 7 }]
        );
        s.patch(&mut a, 0, &plain[..1]).unwrap();
        s.patch(&mut a, 6, &plain[6..7]).unwrap();
        s.patch(&mut a, 25, &plain[25..]).unwrap();
        let v = verify(&mut s, &mut a).unwrap();
        assert_eq!(v.level(), VerificationLevel::Strict);
        assert_eq!(v.packed(), PackedEvidence::Passed);
        assert_eq!(a.publication(), ArtifactPublication::Unpublished);
        let mut got = [0; 32];
        assert_eq!(a.read_at(0, &mut got).unwrap(), ArtifactRead::Filled { count: 32 });
        assert_eq!(&got, plain);
        assert!(!dir.path().join("inner").exists());
    }
}
#[test]
fn wrong_patch_fails_whole_checksum() {
    let dir = tempfile::tempdir().unwrap();
    let plain = b"0123456789abcdefghijklmnopqrstuv";
    let mut s = plain_session(dir.path(), plain, one(3..7), false, HoleFill::Sparse);
    let mut a = artifact(&mut s);
    s.patch(&mut a, 3, b"bad!").unwrap();
    assert!(verify(&mut s, &mut a).is_err());
    assert!(s.set_expected_inner(&a, ExpectedInner::Crc32 { digest: 0, label: "caller".into() }).is_err());
    assert!(s.patch(&mut a, 3, &plain[3..7]).is_err());
    assert_eq!(a.publication(), ArtifactPublication::Unpublished);
}
#[test]
fn no_checksum_never_auto_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let plain = b"0123456789abcdefghijklmnopqrstuv";
    let mut s = plain_session(dir.path(), plain, one(3..7), true, HoleFill::Sparse);
    let mut a = artifact(&mut s);
    s.patch(&mut a, 3, &plain[3..7]).unwrap();
    let v = verify(&mut s, &mut a).unwrap();
    assert_eq!(v.level(), VerificationLevel::Unverified);
    assert_eq!(v.checksum(), None);
    assert_eq!(a.evidence(), ArtifactEvidence::Provisional);
    s.set_expected_inner(&a, ExpectedInner::Crc32 { digest: crc32fast::hash(plain), label: "donor manifest".into() })
        .unwrap();
    let v = verify(&mut s, &mut a).unwrap();
    assert_eq!(v.origin(), &EvidenceOrigin::Caller { label: "donor manifest".into() });
    s.set_expected_inner(&a, ExpectedInner::Crc32 { digest: 1, label: "replacement expectation".into() }).unwrap();
    assert_eq!(a.evidence(), ArtifactEvidence::Provisional);
    assert!(verify(&mut s, &mut a).is_err());
}
#[test]
fn capability_rejects_foreign_empty_overflow_valid_and_repeated_patch() {
    let dir = tempfile::tempdir().unwrap();
    let plain = b"0123456789abcdefghijklmnopqrstuv";
    let mut s = plain_session(dir.path(), plain, one(3..7), false, HoleFill::Sparse);
    let mut a = artifact(&mut s);
    let mut other = plain_session(dir.path(), plain, one(3..7), false, HoleFill::Sparse);
    for (offset, bytes) in [(0, &b"x"[..]), (3, &b""[..]), (u64::MAX, &b"x"[..]), (6, &b"xx"[..])] {
        assert!(matches!(s.patch(&mut a, offset, bytes).unwrap_err().kind, FailureKind::InvalidCapability));
    }
    assert!(matches!(other.patch(&mut a, 3, b"3456").unwrap_err().kind, FailureKind::InvalidCapability));
    s.patch(&mut a, 3, &plain[3..7]).unwrap();
    assert!(s.patch(&mut a, 3, &plain[3..7]).is_err());
    s.control().cancel();
    assert!(matches!(verify(&mut s, &mut a).unwrap_err().kind, FailureKind::Canceled));
    drop(s);
    let mut b = [0; 4];
    a.read_at(3, &mut b).unwrap();
    assert_eq!(&b, b"3456");
    a.discard().unwrap();
}
fn encrypted(plain: &[u8]) -> (Vec<u8>, u64) {
    let salt = [3; 16];
    let iv = [9; 16];
    let (key, _) = zipfast::crypto::derive_rar5_key_and_hash_key("pw", 1, &salt, None).unwrap();
    let mut padded = plain.to_vec();
    padded.resize((plain.len() + 15) & !15, 0);
    let ciphertext = zipfast::crypto::encrypt_cbc(&key, &iv, &padded).unwrap();
    let mut spec = FileSpec::new("inner", &ciphertext);
    spec.size = Some(plain.len() as u64);
    spec.extra = vec![36, 1, 0, 0, 1];
    spec.extra.extend(salt);
    spec.extra.extend(iv);
    let bytes = common::archive_with(&[(spec, crc32fast::hash(plain))], false);
    let start = bytes.windows(ciphertext.len()).position(|b| b == ciphertext).unwrap() as u64;
    (bytes, start)
}
fn small_bookkeeping_budget_case(cipher: bool) {
    let plain: Vec<u8> = (0..65_536).map(|i| (i % 251) as u8).collect();
    let dir = tempfile::tempdir().unwrap();
    let (data, start) = if cipher {
        encrypted(&plain)
    } else {
        let data = archive(&[FileSpec::new("inner", &plain)]);
        let start = data.windows(plain.len()).position(|b| b == plain).unwrap() as u64;
        (data, start)
    };
    let mut opts = options(dir.path());
    opts.limits.read_chunk = 4096;
    opts.limits.packed_work_per_poll = 4096;
    opts.limits.source_bookkeeping = 8192;
    if cipher {
        opts.set_password(Some("pw".into())).unwrap();
    }
    let mut session =
        ProgressiveSession::new(Box::new(Provider(Some(Bytes { data, holes: one(start + 16..start + 32) }))), opts)
            .unwrap();
    let mut valid = 0;
    for _ in 0..1000 {
        match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Ok(Some(ProgressiveEvent::BytesWritten { valid_bytes, .. }))) => valid += valid_bytes,
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished {
                outcome: MemberOutcome::Partial(mut artifact),
                ..
            }))) => {
                let end = if cipher { 48 } else { 32 };
                assert_eq!(artifact.size(), Some(65_536));
                assert_eq!(artifact.holes(), &[OutputHole { offset: 16, len: end - 16 }]);
                assert_eq!(valid, 65_536 - (end - 16));
                let mut got = [0; 4096];
                for (start, end) in [(0, 16), (end, 65_536)] {
                    let mut at = start;
                    while at < end {
                        let ArtifactRead::Filled { count } =
                            artifact.read_at(at, &mut got[..((end - at) as usize).min(4096)]).unwrap()
                        else {
                            panic!("readable extent became a hole");
                        };
                        assert!(count > 0);
                        assert_eq!(&got[..count], &plain[at as usize..at as usize + count]);
                        at += count as u64;
                    }
                }
                assert!(!dir.path().join("inner").exists());
                return;
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) | Poll::Ready(Err(failure)) => {
                panic!("{failure:?}")
            }
            Poll::Ready(Ok(None)) => panic!("no Partial artifact"),
            _ => {}
        }
    }
    panic!("did not finish");
}
#[test]
fn encrypted_stored_runs_fit_small_bookkeeping_budget() {
    small_bookkeeping_budget_case(true);
}
#[test]
fn plain_stored_runs_fit_small_bookkeeping_budget() {
    small_bookkeeping_budget_case(false);
}
#[test]
fn encrypted_stored_cancel_while_data_waits_does_not_flush_or_retry() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    struct Paused {
        bytes: Bytes,
        start: u64,
        attempts: Arc<AtomicUsize>,
    }
    impl RangeSource for Paused {
        fn info(&self) -> SourceInfo {
            self.bytes.info()
        }
        fn backing_files(&self) -> &[File] {
            &[]
        }
        fn read_at(&mut self, at: u64, buf: &mut [u8], cx: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
            if at >= self.start {
                self.attempts.fetch_add(1, Ordering::SeqCst);
                return Ok(RangeRead::NotYet);
            }
            let n = buf.len().min((self.start - at) as usize);
            self.bytes.read_at(at, &mut buf[..n], cx)
        }
    }
    struct PausedProvider(Option<Paused>);
    impl VolumeSource for PausedProvider {
        fn volume(&mut self, _: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
            Ok(VolumeAnswer::Ready(Box::new(self.0.take().unwrap())))
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let (data, start) = encrypted(&[42; 4096]);
    let attempts = Arc::new(AtomicUsize::new(0));
    let mut opts = options(dir.path());
    opts.set_password(Some("pw".into())).unwrap();
    opts.artifact_aftermath = ArtifactAftermath::RetainProvisional;
    let mut session = ProgressiveSession::new(
        Box::new(PausedProvider(Some(Paused {
            bytes: Bytes { data, holes: vec![] },
            start,
            attempts: attempts.clone(),
        }))),
        opts,
    )
    .unwrap();
    for _ in 0..100 {
        let event = session.poll_event(&mut Context::from_waker(Waker::noop()));
        if attempts.load(Ordering::SeqCst) == 1 {
            assert!(event.is_pending());
            break;
        }
        assert!(!matches!(event, Poll::Ready(Err(_))));
    }
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    for _ in 0..3 {
        assert!(session.poll_event(&mut Context::from_waker(Waker::noop())).is_pending());
    }
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    session.control().cancel();
    let Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, artifact, cleanup_failure }))) =
        session.poll_event(&mut Context::from_waker(Waker::noop()))
    else {
        panic!("cancel must terminate parked extraction")
    };
    assert!(matches!(failure.kind, FailureKind::Canceled));
    assert_eq!(failure.context.inner_offset, Some(0));
    assert!(cleanup_failure.is_none());
    let mut artifact = artifact.unwrap();
    assert_eq!(artifact.produced_extent(), 0);
    assert_eq!(artifact.read_at(0, &mut [0; 1]).unwrap(), ArtifactRead::End);
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    assert!(!dir.path().join("inner").exists());
    artifact.discard().unwrap();
}
#[test]
fn cbc_one_byte_and_full_block_taint_same_following_block_and_replay() {
    let plain: Vec<u8> = (0..79).collect();
    for missing in [17..18, 16..32, 0..1, 63..65, 79..80] {
        let dir = tempfile::tempdir().unwrap();
        let (data, start) = encrypted(&plain);
        let mut opts = options(dir.path());
        opts.set_password(Some("pw".into())).unwrap();
        opts.recovery_publication = RecoveryPublication::VerifiedInner;
        let mut s = ProgressiveSession::new(
            Box::new(Provider(Some(Bytes {
                data: data.clone(),
                holes: one(start + missing.start..start + missing.end),
            }))),
            opts,
        )
        .unwrap();
        let mut a = artifact(&mut s);
        let first = missing.start / 16 * 16;
        let end = (missing.end.div_ceil(16) * 16 + 16).min(plain.len() as u64);
        assert_eq!(a.holes(), &[OutputHole { offset: first, len: end - first }]);
        let mut got = [0u8; 128];
        if first > 0 {
            let ArtifactRead::Filled { count } = a.read_at(0, &mut got).unwrap() else { panic!() };
            assert_eq!(&got[..count], &plain[..first as usize]);
        }
        if end < plain.len() as u64 {
            let ArtifactRead::Filled { count } = a.read_at(end, &mut got).unwrap() else { panic!() };
            assert_eq!(&got[..count], &plain[end as usize..]);
        }
        s.patch(&mut a, first, &plain[first as usize..end as usize]).unwrap();
        let v = verify(&mut s, &mut a).unwrap();
        assert_eq!(v.level(), VerificationLevel::InnerOnly);
        assert_eq!(v.packed(), PackedEvidence::Missing);
        assert_eq!(v.authentication(), AuthenticationEvidence::CbcChecksOnly);
        assert!(matches!(s.publish_recovered(&mut a).unwrap_err().kind, FailureKind::PublicationAuthorityRequired));
        s.supply_verification_source(0, Box::new(Bytes { data, holes: vec![] })).unwrap();
        let v = verify(&mut s, &mut a).unwrap();
        assert_eq!(v.level(), VerificationLevel::Strict);
        assert_eq!(v.packed(), PackedEvidence::Passed);
        assert_eq!(v.replacement_revision(), Some(1));
        assert_eq!(a.publication(), ArtifactPublication::Unpublished);
    }
}

struct Indexed(Bytes, u128);
impl RangeSource for Indexed {
    fn info(&self) -> SourceInfo {
        SourceInfo { id: SourceId(self.1), ..self.0.info() }
    }
    fn backing_files(&self) -> &[File] {
        &[]
    }
    fn read_at(&mut self, at: u64, b: &mut [u8], cx: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
        self.0.read_at(at, b, cx)
    }
}
struct Multi(Vec<Option<Bytes>>);
impl VolumeSource for Multi {
    fn volume(&mut self, r: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
        Ok(VolumeAnswer::Ready(Box::new(Indexed(self.0[r.index as usize].take().unwrap(), r.index as u128 + 1))))
    }
}
#[test]
fn patch_plain_store_strict_verifies_all_parts() {
    let plain: Vec<u8> = (0..101).collect();
    let dir = tempfile::tempdir().unwrap();
    let spec = FileSpec::new("inner", &plain);
    let data = common::volumes(&spec, 23);
    let mut inputs = Vec::new();
    let mut logical = 0;
    for volume in &data {
        let part = &plain[logical..(logical + 23).min(plain.len())];
        let start = volume.windows(part.len()).position(|b| b == part).unwrap() as u64;
        inputs.push(Some(Bytes { data: volume.clone(), holes: one(start..start + part.len() as u64) }));
        logical += part.len();
    }
    let mut opts = options(dir.path());
    opts.first_name = "a.part01.rar".into();
    let mut s = ProgressiveSession::new(Box::new(Multi(inputs)), opts).unwrap();
    let mut a = artifact(&mut s);
    assert_eq!(a.holes(), &[OutputHole { offset: 0, len: 101 }]);
    s.patch(&mut a, 0, &plain).unwrap();
    assert_eq!(verify(&mut s, &mut a).unwrap().packed(), PackedEvidence::Passed);
}
#[test]
fn strict_waits_for_original_packed_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let plain: Vec<u8> = (0..79).collect();
    let salt = [3; 16];
    let iv = [9; 16];
    let (key, _) = zipfast::crypto::derive_rar5_key_and_hash_key("pw", 1, &salt, None).unwrap();
    let mut padded = plain.clone();
    padded.resize(80, 0);
    let cipher = zipfast::crypto::encrypt_cbc(&key, &iv, &padded).unwrap();
    let mut spec = FileSpec::new("inner", &cipher);
    spec.size = Some(79);
    spec.extra = vec![36, 1, 0, 0, 1];
    spec.extra.extend(salt);
    spec.extra.extend(iv);
    let mut first = common::SIG.to_vec();
    first.extend(common::main_block(true, None));
    first.extend(common::file_block(&spec, &cipher[..23], crc32fast::hash(&cipher[..23]), false, true));
    first.extend(common::end_block(true));
    let mut second = common::SIG.to_vec();
    second.extend(common::main_block(true, Some(1)));
    second.extend(common::file_block(&spec, &cipher[23..], crc32fast::hash(&plain), true, false));
    second.extend(common::end_block(false));
    let start = first.windows(23).position(|b| b == &cipher[..23]).unwrap() as u64;
    let mut opts = options(dir.path());
    opts.first_name = "a.part01.rar".into();
    opts.set_password(Some("pw".into())).unwrap();
    let mut s = ProgressiveSession::new(
        Box::new(Multi(vec![
            Some(Bytes { data: first.clone(), holes: one(start + 17..start + 18) }),
            Some(Bytes { data: second.clone(), holes: vec![] }),
        ])),
        opts,
    )
    .unwrap();
    let mut a = artifact(&mut s);
    assert_eq!(a.holes(), &[OutputHole { offset: 16, len: 32 }]);
    s.patch(&mut a, 16, &plain[16..48]).unwrap();
    s.supply_verification_source(0, Box::new(Indexed(Bytes { data: first, holes: vec![] }, 10))).unwrap();
    assert_eq!(verify(&mut s, &mut a).unwrap().level(), VerificationLevel::InnerOnly);
    s.supply_verification_source(1, Box::new(Indexed(Bytes { data: second, holes: vec![] }, 11))).unwrap();
    assert_eq!(a.evidence(), ArtifactEvidence::Provisional);
    let v = verify(&mut s, &mut a).unwrap();
    assert_eq!(v.level(), VerificationLevel::Strict);
    assert_eq!(v.replacement_revision(), Some(2));
}
struct NativeBytes {
    bytes: Bytes,
    file: File,
}
impl RangeSource for NativeBytes {
    fn info(&self) -> SourceInfo {
        self.bytes.info()
    }
    fn backing_files(&self) -> &[File] {
        std::slice::from_ref(&self.file)
    }
    fn read_at(&mut self, at: u64, b: &mut [u8], cx: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
        self.bytes.read_at(at, b, cx)
    }
}
struct NativeProvider {
    source: Option<NativeBytes>,
    declaration: ProtectionDeclaration,
}
impl VolumeSource for NativeProvider {
    fn volume(&mut self, _: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
        Ok(VolumeAnswer::Ready(Box::new(self.source.take().unwrap())))
    }
    fn protection(&mut self) -> ProgressiveResult<ProtectionDeclaration> {
        Ok(self.declaration.clone())
    }
}
fn native_session(dir: &std::path::Path, data: Vec<u8>, holes: Vec<Range<u64>>, encrypted: bool) -> ProgressiveSession {
    native_session_with(dir, data, holes, encrypted, Default::default())
}
fn native_session_with(
    dir: &std::path::Path,
    data: Vec<u8>,
    holes: Vec<Range<u64>>,
    encrypted: bool,
    damaged: zipfast::extract::DamagedInput,
) -> ProgressiveSession {
    let path = dir.join("source.rar");
    std::fs::write(&path, &data).unwrap();
    let file = File::open(&path).unwrap();
    let declaration = ProtectionDeclaration::Complete {
        epoch: 0,
        inventory: ProtectionInventory {
            volumes: vec![ProtectedVolume {
                index: 0,
                name: "a.rar".into(),
                backing: VolumeBacking::Native(vec![ProtectedPath {
                    path,
                    file: Some(std::sync::Arc::new(file.try_clone().unwrap())),
                }]),
            }],
            auxiliary_paths: vec![],
        },
    };
    let mut opts = options(&dir.join("out"));
    opts.extract.damaged_input = damaged;
    opts.recovery_publication = RecoveryPublication::VerifiedInner;
    if encrypted {
        opts.set_password(Some("pw".into())).unwrap();
    }
    ProgressiveSession::new(
        Box::new(NativeProvider { source: Some(NativeBytes { bytes: Bytes { data, holes }, file }), declaration }),
        opts,
    )
    .unwrap()
}
#[test]
fn recovered_inner_keeps_missing_cipher_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let plain: Vec<u8> = (0..79).collect();
    let (data, start) = encrypted(&plain);
    let mut s = native_session(dir.path(), data, one(start + 17..start + 18), true);
    let mut a = artifact(&mut s);
    s.patch(&mut a, 16, &plain[16..48]).unwrap();
    let v = verify(&mut s, &mut a).unwrap();
    assert_eq!(v.level(), VerificationLevel::InnerOnly);
    s.publish_recovered(&mut a).unwrap();
    assert_eq!(a.publication(), ArtifactPublication::RecoveredInner);
    assert!(
        matches!(a.evidence(),ArtifactEvidence::Verified(v) if v.packed()==PackedEvidence::Missing && v.authentication()==AuthenticationEvidence::CbcChecksOnly)
    );
    assert_eq!(std::fs::read(dir.path().join("out/inner")).unwrap(), plain);
    assert!(matches!(a.read_at(0, &mut [0]).unwrap_err().kind, FailureKind::InvalidCapability));
    assert!(s.patch(&mut a, 0, b"x").is_err());
    assert!(verify(&mut s, &mut a).is_err());
    assert!(a.discard().is_err());
    drop(a);
    assert!(dir.path().join("out/inner").exists());
}
/// A member read past damaged headers (`damaged_input`: a main header failing its checksum under `Salvage`, garbage
/// before the member searched past under `Resync`) still verifies Strict from a replacement holding the same bytes:
/// the replay reads the damaged headers as extraction did.
#[test]
fn strict_replacement_replays_headers_read_past_as_damage() {
    let plain: Vec<u8> = (0..79).collect();
    let (data, start) = encrypted(&plain);
    let member = common::SIG.len() + common::main_block(false, None).len();
    let mut main_crc = data.clone();
    main_crc[common::SIG.len()] ^= 0x5a;
    let mut garbage = data[..member].to_vec();
    garbage.extend([0; 5]);
    garbage.extend(&data[member..]);
    for (what, data, start, damaged) in [
        ("main crc", main_crc, start, zipfast::extract::DamagedInput::Salvage),
        ("resync", garbage, start + 5, zipfast::extract::DamagedInput::Resync),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut s = native_session_with(dir.path(), data.clone(), one(start + 17..start + 18), true, damaged);
        let mut a = artifact(&mut s);
        s.patch(&mut a, 16, &plain[16..48]).unwrap();
        let replacement = dir.path().join("replacement.rar");
        std::fs::write(&replacement, &data).unwrap();
        s.supply_verification_source(0, Box::new(ImmutableFileSource::open(&replacement).unwrap())).unwrap();
        let v = verify(&mut s, &mut a).unwrap_or_else(|e| panic!("{what}: {e}"));
        assert_eq!(v.level(), VerificationLevel::Strict, "{what}");
        assert_eq!(std::fs::read(dir.path().join("out/inner")).unwrap(), plain, "{what}");
    }
}
#[test]
fn strict_native_replacement_publishes_and_custom_replacement_cannot() {
    for native in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let plain: Vec<u8> = (0..79).collect();
        let (data, start) = encrypted(&plain);
        let mut s = native_session(dir.path(), data.clone(), one(start + 17..start + 18), true);
        let mut a = artifact(&mut s);
        s.patch(&mut a, 16, &plain[16..48]).unwrap();
        if native {
            let replacement = dir.path().join("replacement.rar");
            std::fs::write(&replacement, &data).unwrap();
            s.supply_verification_source(0, Box::new(ImmutableFileSource::open(&replacement).unwrap())).unwrap();
        } else {
            s.supply_verification_source(0, Box::new(Bytes { data, holes: vec![] })).unwrap();
        }
        let v = verify(&mut s, &mut a).unwrap();
        assert_eq!(v.level(), VerificationLevel::Strict);
        assert_eq!(
            a.publication(),
            if native { ArtifactPublication::Strict } else { ArtifactPublication::Unpublished }
        );
        assert_eq!(dir.path().join("out/inner").exists(), native);
        if native {
            assert!(a.read_at(0, &mut [0]).is_err());
            assert_eq!(std::fs::read(dir.path().join("out/inner")).unwrap(), plain);
        }
    }
}

#[derive(Default)]
struct Gate {
    calls: usize,
    allow: bool,
    waker: Option<Waker>,
}
struct Waiting {
    bytes: Bytes,
    gate: std::sync::Arc<std::sync::Mutex<Gate>>,
}
impl RangeSource for Waiting {
    fn info(&self) -> SourceInfo {
        self.bytes.info()
    }
    fn backing_files(&self) -> &[File] {
        &[]
    }
    fn read_at(&mut self, at: u64, b: &mut [u8], cx: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
        let mut gate = self.gate.lock().unwrap();
        gate.calls += 1;
        if !gate.allow {
            gate.waker = Some(cx.waker().clone());
            return Ok(RangeRead::NotYet);
        }
        gate.allow = false;
        drop(gate);
        let n = b.len().min(3);
        self.bytes.read_at(at, &mut b[..n], cx)
    }
}
#[test]
fn replacement_wait_is_independent_and_conflicts_preserve_job() {
    let dir = tempfile::tempdir().unwrap();
    let plain: Vec<u8> = (0..79).collect();
    let (data, start) = encrypted(&plain);
    let mut opts = options(dir.path());
    opts.set_password(Some("pw".into())).unwrap();
    opts.limits.read_chunk = 7;
    let mut s = ProgressiveSession::new(
        Box::new(Provider(Some(Bytes { data: data.clone(), holes: one(start + 17..start + 18) }))),
        opts,
    )
    .unwrap();
    let mut a = artifact(&mut s);
    // Patch chunks obey the same configured bound.
    for at in (16..48).step_by(7) {
        s.patch(&mut a, at as u64, &plain[at..(at + 7).min(48)]).unwrap();
    }
    let gate = std::sync::Arc::new(std::sync::Mutex::new(Gate::default()));
    s.supply_verification_source(0, Box::new(Waiting { bytes: Bytes { data, holes: vec![] }, gate: gate.clone() }))
        .unwrap();
    for _ in 0..100 {
        assert!(s.poll_verify(&mut a, &mut Context::from_waker(Waker::noop())).is_pending());
        if gate.lock().unwrap().waker.is_some() {
            break;
        }
    }
    let calls = gate.lock().unwrap().calls;
    assert!(calls > 0);
    for _ in 0..3 {
        assert!(s.poll_verify(&mut a, &mut Context::from_waker(Waker::noop())).is_pending());
        assert!(matches!(
            s.poll_event(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(ProgressiveFailure { kind: FailureKind::InvalidCapability, .. }))
        ));
    }
    assert_eq!(gate.lock().unwrap().calls, calls);
    for _ in 0..10000 {
        let waker = {
            let mut g = gate.lock().unwrap();
            g.allow = true;
            g.waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
        if let Poll::Ready(result) = s.poll_verify(&mut a, &mut Context::from_waker(Waker::noop())) {
            assert_eq!(result.unwrap().level(), VerificationLevel::Strict);
            return;
        }
    }
    panic!("replacement did not resume");
}
#[test]
fn strict_replacement_rejects_changed_wire_and_changed_plaintext() {
    let plain: Vec<u8> = (0..79).collect();
    for header in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (data, start) = encrypted(&plain);
        let mut opts = options(dir.path());
        opts.set_password(Some("pw".into())).unwrap();
        let mut s = ProgressiveSession::new(
            Box::new(Provider(Some(Bytes { data: data.clone(), holes: one(start + 17..start + 18) }))),
            opts,
        )
        .unwrap();
        let mut a = artifact(&mut s);
        s.patch(&mut a, 16, &plain[16..48]).unwrap();
        let mut changed = data;
        if header {
            changed[0] ^= 1;
        } else {
            changed[start as usize + 60] ^= 1;
        }
        s.supply_verification_source(0, Box::new(Bytes { data: changed, holes: vec![] })).unwrap();
        assert!(verify(&mut s, &mut a).is_err());
        assert_eq!(a.publication(), ArtifactPublication::Unpublished);
    }
}
#[test]
fn patch_split_capacity_and_verification_work_are_real_limits() {
    let plain = b"0123456789abcdefghijklmnopqrstuv";
    let data = archive(&[FileSpec::new("inner", plain)]);
    let start = data.windows(plain.len()).position(|b| b == plain).unwrap() as u64;
    for work in [0, 32] {
        let dir = tempfile::tempdir().unwrap();
        let mut opts = options(dir.path());
        opts.limits.hole_intervals = 1;
        opts.limits.verify_work_bytes = work;
        let mut s = ProgressiveSession::new(
            Box::new(Provider(Some(Bytes { data: data.clone(), holes: one(start + 3..start + 7) }))),
            opts,
        )
        .unwrap();
        let mut a = artifact(&mut s);
        assert!(matches!(
            s.patch(&mut a, 4, b"4").unwrap_err().kind,
            FailureKind::Limit { resource: Resource::HoleIntervals, .. }
        ));
        assert_eq!(a.holes(), &[OutputHole { offset: 3, len: 4 }]);
        s.patch(&mut a, 3, &plain[3..7]).unwrap();
        let result = verify(&mut s, &mut a);
        if work == 0 {
            assert!(matches!(result.unwrap_err().kind, FailureKind::Limit { resource: Resource::VerifyWorkBytes, .. }));
        } else {
            assert_eq!(result.unwrap().level(), VerificationLevel::Strict);
            assert!(matches!(
                verify(&mut s, &mut a).unwrap_err().kind,
                FailureKind::Limit { resource: Resource::VerifyWorkBytes, .. }
            ));
        }
    }
}

#[test]
fn failed_declared_check_is_not_missing() {
    let plain = b"0123456789abcdefghijklmnopqrstuv";
    let dir = tempfile::tempdir().unwrap();
    let mut spec = FileSpec::new("inner", plain);
    spec.extra = common::blake_record([0; 32]);
    let data = archive(&[spec]);
    let start = data.windows(plain.len()).position(|b| b == plain).unwrap() as u64;
    let mut s = ProgressiveSession::new(
        Box::new(Provider(Some(Bytes { data, holes: one(start + 3..start + 7) }))),
        options(dir.path()),
    )
    .unwrap();
    let mut a = artifact(&mut s);
    s.patch(&mut a, 3, &plain[3..7]).unwrap();
    s.set_expected_inner(
        &a,
        ExpectedInner::Crc32 { digest: crc32fast::hash(plain), label: "correct raw digest".into() },
    )
    .unwrap();
    assert!(matches!(verify(&mut s, &mut a).unwrap_err().kind, FailureKind::Rar(_)));
    assert!(
        s.set_expected_inner(
            &a,
            ExpectedInner::Blake2sp { digest: common::blake(plain), label: "cannot override archive".into() }
        )
        .is_err()
    );
    assert_eq!(a.publication(), ArtifactPublication::Unpublished);
}
#[test]
fn caller_digest_has_provenance_and_bounded_label_on_complete_no_checksum() {
    let plain = b"0123456789abcdefghijklmnopqrstuv";
    let dir = tempfile::tempdir().unwrap();
    let mut s = plain_session(dir.path(), plain, vec![], true, HoleFill::Sparse);
    let mut a = artifact(&mut s);
    assert!(matches!(
        s.set_expected_inner(&a, ExpectedInner::Crc32 { digest: 0, label: "x".repeat(1025).into() }).unwrap_err().kind,
        FailureKind::Limit { .. }
    ));
    s.set_expected_inner(
        &a,
        ExpectedInner::Blake2sp { digest: common::blake(plain), label: "external checksum".into() },
    )
    .unwrap();
    let v = verify(&mut s, &mut a).unwrap();
    assert_eq!(v.origin(), &EvidenceOrigin::Caller { label: "external checksum".into() });
    assert_eq!(v.crc32_verdict(), CheckVerdict::Missing);
    assert_eq!(v.blake2sp_verdict(), CheckVerdict::Missing);
}
#[test]
fn header_holes_fail_and_compressed_holes_stop_at_committed_prefix() {
    for compressed in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let plain = b"0123456789abcdefghijklmnopqrstuv";
        let mut spec = FileSpec::new("inner", plain);
        if compressed {
            spec.method = 1;
        }
        let data = archive(&[spec]);
        let start = if compressed { data.windows(plain.len()).position(|b| b == plain).unwrap() as u64 } else { 0 };
        let mut opts = options(dir.path());
        opts.artifact_aftermath = ArtifactAftermath::RetainProvisional;
        let mut s =
            ProgressiveSession::new(Box::new(Provider(Some(Bytes { data, holes: one(start..start + 1) }))), opts)
                .unwrap();
        loop {
            match s.poll_event(&mut Context::from_waker(Waker::noop())) {
                Poll::Ready(Err(e)) => {
                    assert!(!compressed);
                    assert!(matches!(e.kind, FailureKind::HeaderHole));
                    break;
                }
                Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished {
                    outcome: MemberOutcome::Stopped { inner_offset, restart, failure, artifact: Some(a) },
                    ..
                }))) => {
                    assert!(compressed);
                    assert_eq!(inner_offset, 0);
                    assert_eq!(a.produced_extent(), 0);
                    assert_eq!(restart, RestartAvailability::None);
                    assert!(matches!(failure.kind, FailureKind::DataHole));
                    break;
                }
                Poll::Pending | Poll::Ready(Ok(Some(_))) => {}
                _ => panic!("missing typed failure"),
            }
        }
        assert!(!dir.path().join("inner").exists());
    }
}
#[test]
fn overlapping_cbc_taint_is_coalesced() {
    let plain: Vec<u8> = (0..79).collect();
    let dir = tempfile::tempdir().unwrap();
    let (data, start) = encrypted(&plain);
    let mut opts = options(dir.path());
    opts.set_password(Some("pw".into())).unwrap();
    let mut s = ProgressiveSession::new(
        Box::new(Provider(Some(Bytes { data, holes: vec![start + 17..start + 18, start + 30..start + 33] }))),
        opts,
    )
    .unwrap();
    let a = artifact(&mut s);
    assert_eq!(a.holes(), &[OutputHole { offset: 16, len: 48 }]);
}

#[test]
#[ignore = "root-authorized one tiny stored fixture export for pinned independent native parity"]
fn export_stored_recovery_oracle_fixture() {
    use std::io::Write;
    let directory =
        std::path::PathBuf::from(std::env::var_os("ZIPFAST_STORED_ORACLE_EXPORT").expect("new export directory"));
    std::fs::create_dir(&directory).unwrap();
    let plain: Vec<u8> = (0..79).collect();
    let (data, _) = encrypted(&plain);
    for (name, bytes) in [("stored.rar", data.as_slice()), ("expected.bin", plain.as_slice())] {
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(directory.join(name)).unwrap();
        file.write_all(bytes).unwrap();
    }
}

#[test]
fn unknown_encrypted_hole_and_misaligned_tail_fail_without_guessing_geometry() {
    let plain: Vec<u8> = (0..79).collect();
    let salt = [3; 16];
    let iv = [9; 16];
    let (key, _) = zipfast::crypto::derive_rar5_key_and_hash_key("pw", 1, &salt, None).unwrap();
    let mut padded = plain.clone();
    padded.resize(80, 0);
    let ciphertext = zipfast::crypto::encrypt_cbc(&key, &iv, &padded).unwrap();
    for unknown in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let packed = if unknown { &ciphertext[..] } else { &ciphertext[..79] };
        let mut spec = FileSpec::new("inner", packed);
        spec.size = Some(79);
        spec.size_unknown = unknown;
        spec.extra = vec![36, 1, 0, 0, 1];
        spec.extra.extend(salt);
        spec.extra.extend(iv);
        let data = common::archive_with(&[(spec, crc32fast::hash(&plain))], false);
        let start = data.windows(packed.len()).position(|b| b == packed).unwrap() as u64;
        let mut opts = options(dir.path());
        opts.artifact_aftermath = ArtifactAftermath::RetainProvisional;
        opts.set_password(Some("pw".into())).unwrap();
        let mut s =
            ProgressiveSession::new(Box::new(Provider(Some(Bytes { data, holes: one(start + 17..start + 18) }))), opts)
                .unwrap();
        loop {
            match s.poll_event(&mut Context::from_waker(Waker::noop())) {
                Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished {
                    outcome: MemberOutcome::Stopped { failure, inner_offset, .. },
                    ..
                }))) => {
                    assert!(unknown);
                    assert!(matches!(failure.kind, FailureKind::DataHole));
                    assert_eq!(inner_offset, 16);
                    break;
                }
                Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) => {
                    assert!(!unknown);
                    assert!(matches!(failure.kind, FailureKind::Rar(_)));
                    break;
                }
                Poll::Pending | Poll::Ready(Ok(Some(_))) => {}
                other => {
                    assert!(!matches!(other, Poll::Ready(Ok(None))));
                    panic!("expected bounded geometry failure");
                }
            }
        }
        assert!(!dir.path().join("inner").exists());
    }
}
#[test]
fn keyed_archive_checksum_and_raw_caller_digest_are_both_checked() {
    let dir = tempfile::tempdir().unwrap();
    let plain: Vec<u8> = (0..79).collect();
    let salt = [3; 16];
    let iv = [9; 16];
    let (key, hash_key) = zipfast::crypto::derive_rar5_key_and_hash_key("pw", 1, &salt, None).unwrap();
    let mut padded = plain.clone();
    padded.resize(80, 0);
    let ciphertext = zipfast::crypto::encrypt_cbc(&key, &iv, &padded).unwrap();
    let mut spec = FileSpec::new("inner", &ciphertext);
    spec.size = Some(79);
    spec.extra = vec![36, 1, 0, 2, 1];
    spec.extra.extend(salt);
    spec.extra.extend(iv);
    let data =
        common::archive_with(&[(spec, zipfast::crypto::rar5_tweak_crc32(crc32fast::hash(&plain), &hash_key))], false);
    let start = data.windows(ciphertext.len()).position(|b| b == ciphertext).unwrap() as u64;
    let mut opts = options(dir.path());
    opts.set_password(Some("pw".into())).unwrap();
    let mut s =
        ProgressiveSession::new(Box::new(Provider(Some(Bytes { data, holes: one(start + 17..start + 18) }))), opts)
            .unwrap();
    let mut a = artifact(&mut s);
    s.patch(&mut a, 16, &plain[16..48]).unwrap();
    s.set_expected_inner(
        &a,
        ExpectedInner::Crc32 { digest: crc32fast::hash(&plain), label: "raw plaintext crc".into() },
    )
    .unwrap();
    assert_eq!(verify(&mut s, &mut a).unwrap().level(), VerificationLevel::InnerOnly);
}
#[test]
fn new_member_is_a_real_independent_iv_boundary() {
    let dir = tempfile::tempdir().unwrap();
    let plain: Vec<u8> = (0..64).collect();
    let salt = [3; 16];
    let iv = [9; 16];
    let (key, _) = zipfast::crypto::derive_rar5_key_and_hash_key("pw", 1, &salt, None).unwrap();
    let ciphertext = zipfast::crypto::encrypt_cbc(&key, &iv, &plain).unwrap();
    let make = |name| {
        let mut spec = FileSpec::new(name, &ciphertext);
        spec.size = Some(64);
        spec.extra = vec![36, 1, 0, 0, 1];
        spec.extra.extend(salt);
        spec.extra.extend(iv);
        spec
    };
    let data = common::archive_with(
        &[(make("first"), crc32fast::hash(&plain)), (make("second"), crc32fast::hash(&plain))],
        false,
    );
    let start = data.windows(ciphertext.len()).position(|b| b == ciphertext).unwrap() as u64;
    let mut opts = options(dir.path());
    opts.set_password(Some("pw".into())).unwrap();
    let mut s =
        ProgressiveSession::new(Box::new(Provider(Some(Bytes { data, holes: one(start + 63..start + 64) }))), opts)
            .unwrap();
    let first = artifact(&mut s);
    assert_eq!(first.holes(), &[OutputHole { offset: 48, len: 16 }]);
    let mut second = artifact(&mut s);
    assert!(second.holes().is_empty());
    let mut bytes = [0; 64];
    second.read_at(0, &mut bytes).unwrap();
    assert_eq!(bytes.as_slice(), plain);
    assert!(matches!(second.evidence(),ArtifactEvidence::Verified(v) if v.level()==VerificationLevel::Strict));
}

#[test]
#[ignore = "requires root's one pinned independent stored-CBC gold receipt and private output"]
fn independent_stored_gold_hole_recovery() {
    let dir = std::path::PathBuf::from(
        std::env::var_os("ZIPFAST_STORED_ORACLE_GOLD").expect("private independent stored gold"),
    );
    let gold = std::fs::read(dir.join("native/inner")).unwrap();
    assert_eq!(gold.len(), 79);
    let data = std::fs::read(dir.join("stored.rar")).unwrap();
    let (generated, start) = encrypted(&gold);
    assert_eq!(data, generated);
    for loss in [17..18, 16..32, 0..1, 79..80] {
        let out = tempfile::tempdir().unwrap();
        let mut opts = options(out.path());
        opts.set_password(Some("pw".into())).unwrap();
        let mut s = ProgressiveSession::new(
            Box::new(Provider(Some(Bytes { data: data.clone(), holes: one(start + loss.start..start + loss.end) }))),
            opts,
        )
        .unwrap();
        let mut a = artifact(&mut s);
        let mut at = 0;
        let mut b = [0; 128];
        while at < 79 {
            match a.read_at(at, &mut b).unwrap() {
                ArtifactRead::Filled { count } => {
                    assert_eq!(&b[..count], &gold[at as usize..at as usize + count]);
                    at += count as u64;
                }
                ArtifactRead::Hole { len } => at += len,
                ArtifactRead::End => panic!("early end"),
            }
        }
        for h in a.holes().to_vec() {
            s.patch(&mut a, h.offset, &gold[h.offset as usize..(h.offset + h.len) as usize]).unwrap();
        }
        let v = verify(&mut s, &mut a).unwrap();
        assert_eq!(v.level(), VerificationLevel::InnerOnly);
        assert_eq!(v.packed(), PackedEvidence::Missing);
        let ArtifactRead::Filled { count } = a.read_at(0, &mut b).unwrap() else { panic!() };
        assert_eq!(&b[..count], gold);
    }
}

#[test]
fn cancellation_wakes_a_parked_replacement_without_retrying_provider() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    struct Signal(AtomicUsize);
    impl std::task::Wake for Signal {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let plain: Vec<u8> = (0..79).collect();
    let (data, start) = encrypted(&plain);
    let mut opts = options(dir.path());
    opts.set_password(Some("pw".into())).unwrap();
    let mut s = ProgressiveSession::new(
        Box::new(Provider(Some(Bytes { data: data.clone(), holes: one(start + 17..start + 18) }))),
        opts,
    )
    .unwrap();
    let mut a = artifact(&mut s);
    s.patch(&mut a, 16, &plain[16..48]).unwrap();
    let gate = Arc::new(std::sync::Mutex::new(Gate::default()));
    s.supply_verification_source(0, Box::new(Waiting { bytes: Bytes { data, holes: vec![] }, gate: gate.clone() }))
        .unwrap();
    let signal = Arc::new(Signal(AtomicUsize::new(0)));
    let waker = Waker::from(signal.clone());
    loop {
        assert!(s.poll_verify(&mut a, &mut Context::from_waker(&waker)).is_pending());
        if gate.lock().unwrap().waker.is_some() {
            break;
        }
    }
    let calls = gate.lock().unwrap().calls;
    let wakes = signal.0.load(Ordering::SeqCst);
    s.control().cancel();
    assert!(signal.0.load(Ordering::SeqCst) > wakes);
    assert!(matches!(
        s.poll_verify(&mut a, &mut Context::from_waker(&waker)),
        Poll::Ready(Err(ProgressiveFailure { kind: FailureKind::Canceled, .. }))
    ));
    assert_eq!(gate.lock().unwrap().calls, calls);
    let mut b = [0; 79];
    a.read_at(0, &mut b).unwrap();
    assert_eq!(b.as_slice(), plain);
}
#[test]
fn immutable_replacement_change_and_target_alias_are_rejected() {
    let plain: Vec<u8> = (0..79).collect();
    for alias in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (data, start) = encrypted(&plain);
        let mut s = native_session(dir.path(), data.clone(), one(start + 17..start + 18), true);
        let mut a = artifact(&mut s);
        s.patch(&mut a, 16, &plain[16..48]).unwrap();
        let path = if alias { dir.path().join("out/inner") } else { dir.path().join("replacement.rar") };
        std::fs::write(&path, &data).unwrap();
        s.supply_verification_source(0, Box::new(ImmutableFileSource::open(&path).unwrap())).unwrap();
        if !alias {
            let mut changed = data.clone();
            changed[start as usize + 60] ^= 1;
            std::fs::write(&path, changed).unwrap();
        }
        assert!(verify(&mut s, &mut a).is_err());
        assert_eq!(a.publication(), ArtifactPublication::Unpublished);
        if alias {
            assert_eq!(std::fs::read(path).unwrap(), data);
        }
    }
}
#[test]
fn excessive_full_padding_block_is_malformed_even_with_missing_data() {
    let dir = tempfile::tempdir().unwrap();
    let plain: Vec<u8> = (0..79).collect();
    let salt = [3; 16];
    let iv = [9; 16];
    let (key, _) = zipfast::crypto::derive_rar5_key_and_hash_key("pw", 1, &salt, None).unwrap();
    let mut padded = plain.clone();
    padded.resize(96, 0);
    let cipher = zipfast::crypto::encrypt_cbc(&key, &iv, &padded).unwrap();
    let mut spec = FileSpec::new("inner", &cipher);
    spec.size = Some(79);
    spec.extra = vec![36, 1, 0, 0, 1];
    spec.extra.extend(salt);
    spec.extra.extend(iv);
    let data = common::archive_with(&[(spec, crc32fast::hash(&plain))], false);
    let start = data.windows(cipher.len()).position(|b| b == cipher).unwrap() as u64;
    let mut opts = options(dir.path());
    opts.set_password(Some("pw".into())).unwrap();
    let mut s =
        ProgressiveSession::new(Box::new(Provider(Some(Bytes { data, holes: one(start + 17..start + 18) }))), opts)
            .unwrap();
    loop {
        match s.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Pending
            | Poll::Ready(Ok(Some(
                ProgressiveEvent::VolumeOpened { .. }
                | ProgressiveEvent::MemberStarted { .. }
                | ProgressiveEvent::BytesWritten { .. },
            ))) => {}
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) => {
                assert!(matches!(failure.kind, FailureKind::Rar(_)));
                break;
            }
            _ => panic!("padding must fail"),
        }
    }
    assert!(!dir.path().join("inner").exists());
}

#[test]
fn r1_parked_verification_has_no_callbacks_or_request_debits_until_wake() {
    counted_parked_verification(false);
}
#[test]
fn r2_aborted_admitted_retry_retires_old_request_waker() {
    counted_parked_verification(true);
}
fn counted_parked_verification(abort_admitted: bool) {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    type Counts = Arc<Mutex<[usize; 5]>>;
    struct Counted {
        source: Box<dyn RangeSource>,
        counts: Counts,
    }
    impl RangeSource for Counted {
        fn info(&self) -> SourceInfo {
            self.counts.lock().unwrap()[0] += 1;
            self.source.info()
        }
        fn backing_files(&self) -> &[File] {
            self.counts.lock().unwrap()[1] += 1;
            self.source.backing_files()
        }
        fn read_at(&mut self, at: u64, b: &mut [u8], cx: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
            self.counts.lock().unwrap()[2] += 1;
            self.source.read_at(at, b, cx)
        }
    }
    struct CountedProvider {
        source: Option<Counted>,
        counts: Counts,
    }
    impl VolumeSource for CountedProvider {
        fn volume(&mut self, _: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
            self.counts.lock().unwrap()[3] += 1;
            Ok(VolumeAnswer::Ready(Box::new(self.source.take().unwrap())))
        }
        fn protection(&mut self) -> ProgressiveResult<ProtectionDeclaration> {
            self.counts.lock().unwrap()[4] += 1;
            Ok(ProtectionDeclaration::Opaque)
        }
    }
    #[derive(Default)]
    struct Task(AtomicUsize);
    impl std::task::Wake for Task {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let plain: Vec<u8> = (0..79).collect();
    let (data, start) = encrypted(&plain);
    let original = Arc::new(Mutex::new([0; 5]));
    let replacement = Arc::new(Mutex::new([0; 5]));
    let mut opts = options(dir.path());
    opts.set_password(Some("pw".into())).unwrap();
    opts.limits.source_requests = 2000;
    opts.limits.provider_wakes = if abort_admitted { 2 } else { 1 };
    let mut s = ProgressiveSession::new(
        Box::new(CountedProvider {
            source: Some(Counted {
                source: Box::new(Bytes { data: data.clone(), holes: one(start + 17..start + 18) }),
                counts: original.clone(),
            }),
            counts: original.clone(),
        }),
        opts,
    )
    .unwrap();
    let mut a = artifact(&mut s);
    s.patch(&mut a, 16, &plain[16..48]).unwrap();
    let gate = Arc::new(Mutex::new(Gate::default()));
    s.supply_verification_source(
        0,
        Box::new(Counted {
            source: Box::new(Waiting { bytes: Bytes { data, holes: vec![] }, gate: gate.clone() }),
            counts: replacement.clone(),
        }),
    )
    .unwrap();
    for _ in 0..100 {
        assert!(s.poll_verify(&mut a, &mut Context::from_waker(Waker::noop())).is_pending());
        if gate.lock().unwrap().waker.is_some() {
            break;
        }
    }
    assert!(gate.lock().unwrap().waker.is_some());
    let stale_request = if abort_admitted {
        let old_request = gate.lock().unwrap().waker.take().unwrap();
        let reads_before = replacement.lock().unwrap()[2];
        // Change only the real stage's full stamp; correct plaintext stays identical.
        let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap().map(|e| e.unwrap().path()).collect();
        assert_eq!(entries.len(), 1);
        let file = std::fs::OpenOptions::new().write(true).open(&entries[0]).unwrap();
        let before = file.metadata().unwrap().modified().unwrap();
        file.set_times(std::fs::FileTimes::new().set_modified(before + std::time::Duration::from_secs(2))).unwrap();
        assert_ne!(file.metadata().unwrap().modified().unwrap(), before);
        assert_eq!(std::fs::read(&entries[0]).unwrap(), plain);
        old_request.wake_by_ref();
        assert!(matches!(
            s.poll_verify(&mut a, &mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(ProgressiveFailure { kind: FailureKind::InvalidCapability, .. }))
        ));
        assert_eq!(replacement.lock().unwrap()[2], reads_before, "stamp rejection precedes the admitted read");
        assert_eq!(a.evidence(), ArtifactEvidence::Provisional);
        for _ in 0..100 {
            assert!(s.poll_verify(&mut a, &mut Context::from_waker(Waker::noop())).is_pending());
            if gate.lock().unwrap().waker.is_some() {
                break;
            }
        }
        assert!(gate.lock().unwrap().waker.is_some(), "fresh attempt registered its own NotYet request");
        assert_eq!(replacement.lock().unwrap()[2], reads_before + 1);
        Some(old_request)
    } else {
        None
    };
    let original_before = *original.lock().unwrap();
    let replacement_before = *replacement.lock().unwrap();
    let old = Arc::new(Task::default());
    let latest = Arc::new(Task::default());
    let old_waker = Waker::from(old.clone());
    let latest_waker = Waker::from(latest.clone());
    // An aborted request's notification cannot authorize this new request.
    if let Some(stale) = &stale_request {
        stale.wake_by_ref();
    }
    // More no-wake polls than the entire request budget: no source debit is allowed.
    for _ in 0..2500 {
        assert!(s.poll_verify(&mut a, &mut Context::from_waker(&old_waker)).is_pending());
        assert_eq!(*original.lock().unwrap(), original_before);
        assert_eq!(*replacement.lock().unwrap(), replacement_before);
    }
    assert!(s.poll_verify(&mut a, &mut Context::from_waker(&latest_waker)).is_pending());
    let wake = {
        let mut gate = gate.lock().unwrap();
        gate.allow = true;
        gate.waker.take().unwrap()
    };
    wake.wake();
    assert_eq!(old.0.load(Ordering::SeqCst), 0);
    assert!(latest.0.load(Ordering::SeqCst) > 0);
    assert!(s.poll_verify(&mut a, &mut Context::from_waker(&latest_waker)).is_pending());
    assert!(original.lock().unwrap()[0] > original_before[0], "admitted work revalidates original");
    assert!(replacement.lock().unwrap()[2] > replacement_before[2], "provider resumed after wake");
    for _ in 0..100 {
        assert!(s.poll_verify(&mut a, &mut Context::from_waker(&latest_waker)).is_pending());
        if gate.lock().unwrap().waker.is_some() {
            break;
        }
    }
    let original_before = *original.lock().unwrap();
    let replacement_before = *replacement.lock().unwrap();
    let wakes = latest.0.load(Ordering::SeqCst);
    s.control().cancel();
    assert!(latest.0.load(Ordering::SeqCst) > wakes);
    assert!(matches!(
        s.poll_verify(&mut a, &mut Context::from_waker(&latest_waker)),
        Poll::Ready(Err(ProgressiveFailure { kind: FailureKind::Canceled, .. }))
    ));
    assert_eq!(*original.lock().unwrap(), original_before);
    assert_eq!(*replacement.lock().unwrap(), replacement_before);
}

#[test]
fn r1_caller_checksum_mismatch_permanently_blocks_expectation_correction() {
    let dir = tempfile::tempdir().unwrap();
    let data = archive(&[FileSpec::new("inner", b"correct")]);
    let mut s =
        ProgressiveSession::new(Box::new(Provider(Some(Bytes { data, holes: vec![] }))), options(dir.path())).unwrap();
    let mut a = artifact(&mut s);
    s.set_expected_inner(&a, ExpectedInner::Crc32 { digest: 0, label: "mistaken metadata".into() }).unwrap();
    assert!(matches!(verify(&mut s, &mut a).unwrap_err().kind, FailureKind::ChecksumMismatch { .. }));
    assert!(matches!(
        s.set_expected_inner(
            &a,
            ExpectedInner::Crc32 { digest: crc32fast::hash(b"correct"), label: "corrected metadata".into() }
        )
        .unwrap_err()
        .kind,
        FailureKind::IncompleteOutput
    ));
    assert!(matches!(verify(&mut s, &mut a).unwrap_err().kind, FailureKind::IncompleteOutput));
    assert_eq!(a.evidence(), ArtifactEvidence::Provisional);
    assert_eq!(a.publication(), ArtifactPublication::Unpublished);
    assert!(!dir.path().join("inner").exists());
}
// Catches verify re-reading the whole member after a patch: parts that passed their part CRC are combined.
#[test]
fn patch_verify_reads_back_only_damaged_and_final_parts() {
    let plain: Vec<u8> = (0..101u32).map(|i| (i * 7 + 3) as u8).collect();
    for wrong in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let spec = FileSpec::new("inner", &plain);
        let data = common::volumes(&spec, 23);
        let mut inputs = Vec::new();
        let mut logical = 0;
        for (index, volume) in data.iter().enumerate() {
            let part = &plain[logical..(logical + 23).min(plain.len())];
            let start = volume.windows(part.len()).position(|b| b == part).unwrap() as u64;
            // Only the third volume (output 46..69) loses bytes.
            let holes = if index == 2 { one(start + 5..start + 15) } else { vec![] };
            inputs.push(Some(Bytes { data: volume.clone(), holes }));
            logical += part.len();
        }
        let mut opts = options(dir.path());
        opts.first_name = "a.part01.rar".into();
        let mut s = ProgressiveSession::new(Box::new(Multi(inputs)), opts).unwrap();
        let mut a = artifact(&mut s);
        assert_eq!(a.holes(), &[OutputHole { offset: 51, len: 10 }]);
        let mut patch = plain[51..61].to_vec();
        if wrong {
            patch[3] ^= 1;
        }
        s.patch(&mut a, 51, &patch).unwrap();
        if wrong {
            assert!(verify(&mut s, &mut a).is_err());
            continue;
        }
        let v = verify(&mut s, &mut a).unwrap();
        assert_eq!(v.level(), VerificationLevel::Strict);
        assert_eq!(v.packed(), PackedEvidence::Passed);
        // Part 2 (23 bytes) holds the patch; the final part (9 bytes) has no part CRC of its own.
        assert_eq!(v.read_back(), 23 + 9);
        let mut got = vec![0; 101];
        assert_eq!(a.read_at(0, &mut got).unwrap(), ArtifactRead::Filled { count: 101 });
        assert_eq!(got, plain);
    }
}
// Catches combining part CRCs over a stage that something other than the library changed after extraction.
#[test]
fn outside_write_to_a_proven_part_forces_a_full_readback() {
    let plain: Vec<u8> = (0..101u32).map(|i| (i * 7 + 3) as u8).collect();
    for when in ["extracting", "before patch", "after patch"] {
        let dir = tempfile::tempdir().unwrap();
        let spec = FileSpec::new("inner", &plain);
        let data = common::volumes(&spec, 23);
        let mut inputs = Vec::new();
        let mut logical = 0;
        for (index, volume) in data.iter().enumerate() {
            let part = &plain[logical..(logical + 23).min(plain.len())];
            let start = volume.windows(part.len()).position(|b| b == part).unwrap() as u64;
            let holes = if index == 2 { one(start + 5..start + 15) } else { vec![] };
            inputs.push(Some(Bytes { data: volume.clone(), holes }));
            logical += part.len();
        }
        let mut opts = options(dir.path());
        opts.first_name = "a.part01.rar".into();
        let mut s = ProgressiveSession::new(Box::new(Multi(inputs)), opts).unwrap();
        let stage = |dir: &std::path::Path| {
            std::fs::read_dir(dir)
                .unwrap()
                .map(|e| e.unwrap().path())
                .find(|p| p.file_name().unwrap().to_string_lossy().starts_with(".zipfast-progressive"))
                .expect("stage file")
        };
        let tamper = |dir: &std::path::Path| {
            use std::os::unix::fs::FileExt;
            std::thread::sleep(std::time::Duration::from_millis(5));
            std::fs::OpenOptions::new().write(true).open(stage(dir)).unwrap().write_at(&[0xff], 2).unwrap();
        };
        let mut a = None;
        let mut tampered = false;
        for _ in 0..100000 {
            match s.poll_event(&mut Context::from_waker(Waker::noop())) {
                Poll::Ready(Ok(Some(ProgressiveEvent::BytesWritten { .. }))) if when == "extracting" && !tampered => {
                    tamper(dir.path());
                    tampered = true;
                }
                Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished {
                    outcome: MemberOutcome::Partial(artifact),
                    ..
                }))) => {
                    a = Some(artifact);
                    break;
                }
                Poll::Ready(Err(e)) => panic!("{e}"),
                Poll::Ready(Ok(None)) => panic!("no artifact"),
                _ => {}
            }
        }
        let mut a = a.expect("partial artifact");
        assert!(when != "extracting" || tampered);
        if when == "before patch" {
            tamper(dir.path());
        }
        s.patch(&mut a, 51, &plain[51..61]).unwrap();
        if when == "after patch" {
            tamper(dir.path());
        }
        assert!(verify(&mut s, &mut a).is_err(), "a changed proven part must fail verification");
    }
}

/// An `ImmutableFileSource` that reports one range of its volume as a hole.
struct HoledFile {
    inner: ImmutableFileSource,
    hole: Option<Range<u64>>,
}
impl RangeSource for HoledFile {
    fn info(&self) -> SourceInfo {
        self.inner.info()
    }
    fn backing_files(&self) -> &[File] {
        self.inner.backing_files()
    }
    fn read_at(&mut self, at: u64, b: &mut [u8], cx: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
        let mut len = b.len();
        if let Some(h) = &self.hole {
            if h.start <= at && at < h.end {
                return Ok(RangeRead::Hole { len: (h.end - at).min(len as u64) });
            }
            if at < h.start {
                len = len.min((h.start - at) as usize);
            }
        }
        self.inner.read_at(at, &mut b[..len], cx)
    }
}
struct HoledSet {
    paths: Vec<std::path::PathBuf>,
    handles: Vec<std::sync::Arc<File>>,
    hole: (u32, Range<u64>),
}
impl VolumeSource for HoledSet {
    fn volume(&mut self, r: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
        Ok(match self.paths.get(r.index as usize) {
            Some(p) => VolumeAnswer::Ready(Box::new(HoledFile {
                inner: ImmutableFileSource::open(p)?,
                hole: (r.index == self.hole.0).then(|| self.hole.1.clone()),
            })),
            None => VolumeAnswer::Missing,
        })
    }
    fn protection(&mut self) -> ProgressiveResult<ProtectionDeclaration> {
        Ok(ProtectionDeclaration::Complete {
            epoch: 1,
            inventory: ProtectionInventory {
                volumes: self
                    .paths
                    .iter()
                    .enumerate()
                    .map(|(i, p)| ProtectedVolume {
                        index: i as u32,
                        name: p.file_name().unwrap().into(),
                        backing: VolumeBacking::Native(vec![ProtectedPath {
                            path: p.clone(),
                            file: Some(self.handles[i].clone()),
                        }]),
                    })
                    .collect(),
                auxiliary_paths: vec![],
            },
        })
    }
}
#[test]
fn complete_set_of_200_volumes_with_200_replacement_lanes_fits_bookkeeping() {
    // SourceBookkeeping is cumulative. Before #116/#121 every step rechecked the whole Complete inventory and every
    // admission re-sorted it, so a set this size ran out of the default 64 MiB a fifth of the way in. Strict
    // replacement evidence then adds one lane per member part, and every poll_verify used to run the full
    // inventory recheck too: over 16 MiB at 200 volumes and over the default 64 MiB at 300. The whole run,
    // extraction, 200 lane admissions, verification and publication, now fits in 16 MiB (300 volumes need about
    // 9 MiB of it). 200 keeps the descriptors held, about three per volume, under common 1024 limits. Tiny volumes keep this fast; the
    // cost is per volume, not per byte.
    const VOLUMES: usize = 200;
    const PART: usize = 32;
    let dir = tempfile::tempdir().unwrap();
    let plain: Vec<u8> = (0..VOLUMES * PART - 5).map(|i| (i * 7 % 251) as u8).collect();
    let salt = [3; 16];
    let iv = [9; 16];
    let (key, _) = zipfast::crypto::derive_rar5_key_and_hash_key("pw", 1, &salt, None).unwrap();
    let mut padded = plain.clone();
    padded.resize((plain.len() + 15) & !15, 0);
    let cipher = zipfast::crypto::encrypt_cbc(&key, &iv, &padded).unwrap();
    let mut spec = FileSpec::new("inner", &cipher);
    spec.size = Some(plain.len() as u64);
    spec.extra = vec![36, 1, 0, 0, 1];
    spec.extra.extend(salt);
    spec.extra.extend(iv);
    let input = dir.path().join("in");
    let replacements = dir.path().join("repaired");
    std::fs::create_dir_all(&input).unwrap();
    std::fs::create_dir_all(&replacements).unwrap();
    let parts: Vec<&[u8]> = cipher.chunks(PART).collect();
    assert_eq!(parts.len(), VOLUMES);
    let damaged = (VOLUMES / 2) as u32;
    let mut hole = 0..0;
    let mut paths = Vec::new();
    for (i, part) in parts.iter().enumerate() {
        let last = i + 1 == VOLUMES;
        let mut v = common::SIG.to_vec();
        v.extend(common::main_block(true, (i > 0).then_some(i as u64)));
        let crc = if last { crc32fast::hash(&plain) } else { crc32fast::hash(part) };
        v.extend(common::file_block(&spec, part, crc, i > 0, !last));
        v.extend(common::end_block(!last));
        if i as u32 == damaged {
            let start = v.windows(part.len()).position(|b| b == *part).unwrap() as u64;
            hole = start + 1..start + 2;
        }
        let name = format!("a.part{:03}.rar", i + 1);
        std::fs::write(input.join(&name), &v).unwrap();
        std::fs::write(replacements.join(&name), &v).unwrap();
        paths.push(input.join(name));
    }
    let handles = paths.iter().map(|p| std::sync::Arc::new(File::open(p).unwrap())).collect();
    let mut opts = options(&dir.path().join("out"));
    opts.first_name = "a.part001.rar".into();
    opts.limits.volume_handles = 4 * VOLUMES as u64 + 16;
    opts.limits.source_bookkeeping = 16 << 20;
    opts.set_password(Some("pw".into())).unwrap();
    let mut s =
        ProgressiveSession::new(Box::new(HoledSet { paths: paths.clone(), handles, hole: (damaged, hole) }), opts)
            .unwrap();
    let mut a = artifact(&mut s);
    let holes = a.holes().to_vec();
    assert!(!holes.is_empty());
    for h in holes {
        s.patch(&mut a, h.offset, &plain[h.offset as usize..(h.offset + h.len) as usize]).unwrap();
    }
    let required: Vec<u32> = a.required_verification_volumes().collect();
    assert_eq!(required.len(), VOLUMES);
    for index in required {
        let path = replacements.join(paths[index as usize].file_name().unwrap());
        s.supply_verification_source(index, Box::new(ImmutableFileSource::open(&path).unwrap())).unwrap();
    }
    let v = verify(&mut s, &mut a).unwrap();
    assert_eq!(v.level(), VerificationLevel::Strict);
    assert_eq!(a.publication(), ArtifactPublication::Strict);
    assert_eq!(std::fs::read(dir.path().join("out/inner")).unwrap(), plain);
}
