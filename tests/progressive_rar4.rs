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

#![cfg(unix)]
use std::{
    ffi::OsString,
    task::{Context, Poll, Waker},
};
use zipfast::{crc32::hash, progressive::*};
fn block(kind: u8, flags: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0, 0, kind];
    bytes.extend(flags.to_le_bytes());
    bytes.extend(((body.len() + 7) as u16).to_le_bytes());
    bytes.extend(body);
    let crc = hash(&bytes[2..]) as u16;
    bytes[..2].copy_from_slice(&crc.to_le_bytes());
    bytes
}

fn member(name: &[u8], data: &[u8], flags: u16, method: u8) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend((data.len() as u32).to_le_bytes());
    body.extend((data.len() as u32).to_le_bytes());
    body.push(3);
    body.extend(hash(data).to_le_bytes());
    body.extend(0x50221884u32.to_le_bytes());
    body.extend([20, method]);
    body.extend((name.len() as u16).to_le_bytes());
    body.extend(0o100644u32.to_le_bytes());
    body.extend(name);
    let mut bytes = block(0x74, flags | 0x8000, &body);
    bytes.extend(data);
    bytes
}

fn archive(files: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = b"Rar!\x1a\x07\0".to_vec();
    bytes.extend(block(0x73, 0, &[0; 6]));
    for file in files {
        bytes.extend(file);
    }
    bytes.extend(block(0x7b, 0x4000, &[]));
    bytes
}

fn options(dir: &std::path::Path) -> ProgressiveOptions {
    ProgressiveOptions::new(
        zipfast::extract::Options {
            mode: zipfast::extract::Mode::Extract,
            dest: dir.to_owned(),
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
        },
        OsString::from("a.rar"),
    )
}
#[test]
fn plain_stored_public_session_publishes_checked_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let gold = b"original RAR4 stored plaintext";
    let bytes = archive(&[member(b"one", gold, 0, 0x30)]);
    let mut session =
        ProgressiveSession::from_sealed_memory(vec![("a.rar".into(), bytes.into_boxed_slice())], options(dir.path()))
            .unwrap();
    let mut verified = 0;
    for _ in 0..1000 {
        match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Err(e)) => panic!("unexpected failure: {e:?}"),
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) => {
                panic!("terminated: {failure:?}")
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { outcome: MemberOutcome::Verified(_), .. }))) => {
                verified += 1
            }
            Poll::Ready(Ok(None)) => {
                assert_eq!(verified, 1);
                assert_eq!(std::fs::read(dir.path().join("one")).unwrap(), gold);
                return;
            }
            _ => {}
        }
    }
    panic!("session did not finish")
}

use std::{
    fs::File,
    ops::Range,
    sync::{Arc, Mutex},
};
#[derive(Default)]
struct Gate {
    ready: bool,
    wake: Option<Waker>,
    calls: usize,
    generation: u64,
}
struct Bytes {
    data: Vec<u8>,
    holes: Vec<Range<u64>>,
    id: u128,
    chunk: usize,
    wait: bool,
    gate: Arc<Mutex<Gate>>,
}
impl RangeSource for Bytes {
    fn info(&self) -> SourceInfo {
        SourceInfo {
            id: SourceId(self.id),
            generation: self.gate.lock().unwrap().generation,
            extent: self.data.len() as u64,
            length: SourceLength::Final(self.data.len() as u64),
        }
    }
    fn backing_files(&self) -> &[File] {
        &[]
    }
    fn read_at(&mut self, at: u64, buf: &mut [u8], cx: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
        let mut g = self.gate.lock().unwrap();
        g.calls += 1;
        if self.wait && !g.ready {
            g.wake = Some(cx.waker().clone());
            return Ok(RangeRead::NotYet);
        }
        g.ready = false;
        let mut end = (at + buf.len().min(self.chunk) as u64).min(self.data.len() as u64);
        for h in &self.holes {
            if h.start <= at && at < h.end {
                return Ok(RangeRead::Hole { len: (h.end - at).min(buf.len() as u64) });
            }
            if h.start > at {
                end = end.min(h.start)
            }
        }
        let n = (end - at) as usize;
        buf[..n].copy_from_slice(&self.data[at as usize..end as usize]);
        Ok(RangeRead::Filled { count: n })
    }
}
struct Provider {
    parts: Vec<Option<Bytes>>,
    wait: bool,
    gate: Arc<Mutex<Gate>>,
}
impl VolumeSource for Provider {
    fn volume(&mut self, r: &VolumeRequest, cx: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
        let mut g = self.gate.lock().unwrap();
        g.calls += 1;
        if self.wait && !g.ready {
            g.wake = Some(cx.waker().clone());
            return Ok(VolumeAnswer::Wait);
        }
        g.ready = false;
        Ok(self
            .parts
            .get_mut(r.index as usize)
            .and_then(Option::take)
            .map_or(VolumeAnswer::Missing, |b| VolumeAnswer::Ready(Box::new(b))))
    }
}
fn custom(
    data: Vec<Vec<u8>>,
    holes: Vec<Vec<Range<u64>>>,
    opts: ProgressiveOptions,
    wait: bool,
    chunk: usize,
) -> (ProgressiveSession, Arc<Mutex<Gate>>) {
    let gate = Arc::new(Mutex::new(Gate::default()));
    let parts = data
        .into_iter()
        .zip(holes)
        .enumerate()
        .map(|(i, (data, holes))| Some(Bytes { data, holes, id: i as u128 + 1, chunk, wait, gate: gate.clone() }))
        .collect();
    (ProgressiveSession::new(Box::new(Provider { parts, wait, gate: gate.clone() }), opts).unwrap(), gate)
}
fn step(s: &mut ProgressiveSession) -> Poll<ProgressiveResult<Option<ProgressiveEvent>>> {
    s.poll_event(&mut Context::from_waker(Waker::noop()))
}
fn wake(s: &mut ProgressiveSession, g: &Arc<Mutex<Gate>>) {
    if g.lock().unwrap().wake.is_none() {
        return;
    }
    let before = g.lock().unwrap().calls;
    for _ in 0..5 {
        assert!(step(s).is_pending());
        assert_eq!(g.lock().unwrap().calls, before)
    }
    let w = {
        let mut g = g.lock().unwrap();
        g.ready = true;
        g.wake.take().unwrap()
    };
    w.wake();
}
fn collect(s: &mut ProgressiveSession, g: &Arc<Mutex<Gate>>) -> ProgressiveResult<(Vec<Artifact>, Vec<u32>)> {
    let mut artifacts = Vec::new();
    let mut volumes = Vec::new();
    for _ in 0..2000000 {
        match step(s) {
            Poll::Pending => wake(s, g),
            Poll::Ready(Err(e)) => return Err(e),
            Poll::Ready(Ok(None)) => return Ok((artifacts, volumes)),
            Poll::Ready(Ok(Some(ProgressiveEvent::VolumeOpened { index, .. }))) => volumes.push(index),
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished {
                outcome: MemberOutcome::Provisional(a) | MemberOutcome::Partial(a),
                ..
            }))) => artifacts.push(a),
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) => return Err(failure),
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished {
                outcome: MemberOutcome::Stopped { failure, .. },
                ..
            }))) => return Err(failure),
            _ => {}
        }
    }
    panic!("finite poll bound")
}
fn read_all(a: &mut Artifact) -> Vec<u8> {
    let mut result = Vec::new();
    let mut buf = [0; 1024];
    loop {
        match a.read_at(result.len() as u64, &mut buf).unwrap() {
            ArtifactRead::Filled { count } => result.extend_from_slice(&buf[..count]),
            ArtifactRead::End => return result,
            _ => panic!("hole"),
        }
    }
}
fn fix_crc(b: &mut [u8], start: usize) {
    let n = u16::from_le_bytes([b[start + 5], b[start + 6]]) as usize;
    let crc = hash(&b[start + 2..start + n]) as u16;
    b[start..start + 2].copy_from_slice(&crc.to_le_bytes());
}
fn split(gold: &[u8], chunk: usize) -> Vec<Vec<u8>> {
    let count = gold.len().div_ceil(chunk);
    gold.chunks(chunk)
        .enumerate()
        .map(|(i, payload)| {
            let flags = u16::from(i > 0) | (u16::from(i + 1 < count) * 2);
            let mut file = member(b"one", payload, flags, 0x30);
            file[11..15].copy_from_slice(&(gold.len() as u32).to_le_bytes());
            file[16..20].copy_from_slice(&hash(if i + 1 == count { gold } else { payload }).to_le_bytes());
            fix_crc(&mut file, 0);
            let mut wire = b"Rar!\x1a\x07\0".to_vec();
            wire.extend(block(0x73, 0x11 | if i == 0 { 0x100 } else { 0 }, &[0; 6]));
            wire.extend(file);
            wire.extend(block(0x7b, 0x4000 | u16::from(i + 1 < count), &[]));
            wire
        })
        .collect()
}
#[test]
fn split_stored_waits_inside_every_header_and_part_byte() {
    let gold = b"plain split member retains all state across volume boundaries";
    for chunk in 1..=16 {
        let dir = tempfile::tempdir().unwrap();
        let mut opts = options(dir.path());
        opts.first_name = "a.part01.rar".into();
        let parts = split(gold, 17);
        let n = parts.len();
        let (mut s, g) = custom(parts, vec![vec![]; n], opts, true, chunk);
        let (mut a, volumes) = collect(&mut s, &g).unwrap();
        assert_eq!(volumes, (0..n as u32).collect::<Vec<_>>());
        assert_eq!(a.len(), 1);
        assert_eq!(read_all(&mut a[0]), gold);
        let ArtifactEvidence::Verified(v) = a[0].evidence() else { panic!("no verified evidence") };
        assert_eq!(v.level(), VerificationLevel::Strict);
        assert_eq!(v.packed(), PackedEvidence::Passed);
        assert_eq!(a[0].publication(), ArtifactPublication::Unpublished);
    }
}
fn verify(s: &mut ProgressiveSession, a: &mut Artifact) -> ProgressiveResult<Verification> {
    for _ in 0..100000 {
        if let Poll::Ready(r) = s.poll_verify(a, &mut Context::from_waker(Waker::noop())) {
            return r;
        }
    }
    panic!("verify poll bound")
}
#[test]
fn split_stored_holes_patch_and_full_readback_and_sticky_wrong_patch() {
    let gold = b"0123456789abcdefghijklmnopqrstuvwxyzABCD";
    for wrong in [false, true] {
        for fill in [HoleFill::Sparse, HoleFill::Zero] {
            let dir = tempfile::tempdir().unwrap();
            let parts = split(gold, 20);
            let mut opts = options(dir.path());
            opts.first_name = "a.part01.rar".into();
            opts.hole_policy = HolePolicy::PartialStored { fill };
            let data_at = 20 + u16::from_le_bytes([parts[0][25], parts[0][26]]) as u64;
            let holes = vec![vec![data_at + 18..data_at + 20], vec![data_at..data_at + 3]];
            let (mut s, g) = custom(parts, holes, opts, false, 5);
            let (mut a, _) = collect(&mut s, &g).unwrap();
            assert_eq!(a.len(), 1);
            assert_eq!(a[0].holes(), &[OutputHole { offset: 18, len: 5 }]);
            assert!(verify(&mut s, &mut a[0]).is_err());
            s.patch(&mut a[0], 18, if wrong { b"wrong" } else { &gold[18..23] }).unwrap();
            if wrong {
                assert!(verify(&mut s, &mut a[0]).is_err());
                assert!(
                    s.set_expected_inner(
                        &a[0],
                        ExpectedInner::Crc32 { digest: hash(gold), label: "attempt to erase failure".into() }
                    )
                    .is_err()
                );
                assert!(s.patch(&mut a[0], 18, &gold[18..23]).is_err());
            } else {
                let v = verify(&mut s, &mut a[0]).unwrap();
                assert_eq!(v.level(), VerificationLevel::Strict);
                assert_eq!(v.packed(), PackedEvidence::Passed);
                assert_eq!(read_all(&mut a[0]), gold);
            }
            assert_eq!(a[0].publication(), ArtifactPublication::Unpublished);
            assert!(!dir.path().join("one").exists());
        }
    }
}

fn fails(data: Vec<Vec<u8>>, opts: ProgressiveOptions) -> ProgressiveFailure {
    let n = data.len();
    let (mut session, gate) = custom(data, vec![vec![]; n], opts, false, 7);
    match collect(&mut session, &gate) {
        Err(e) => e,
        Ok(_) => panic!("unexpected successful archive"),
    }
}
mod common;
#[test]
fn volume_set_format_cannot_change_after_a_complete_member() {
    let dir = tempfile::tempdir().unwrap();
    let mut first = split(b"first", 20).remove(0);
    let end = first.len() - 7;
    first[end + 3..end + 5].copy_from_slice(&0x4001u16.to_le_bytes());
    fix_crc(&mut first, end);
    let mut second = common::volumes(&common::FileSpec::new("two", b"second"), 3).remove(0);
    // This is a valid RAR5 first volume, not a RAR4 continuation.
    let mut opts = options(dir.path());
    opts.first_name = "a.part01.rar".into();
    let error = fails(vec![first, std::mem::take(&mut second)], opts);
    assert!(matches!(error.kind, FailureKind::Malformed("volume archive format changed")), "{error:?}");
}
#[test]
fn unsupported_rar4_features_do_not_enter_rar5_decoder() {
    // versions 15, 20, 26 and 29 decode; RAR 1.3 (10) and anything past 2.9 don't
    // (an old file revision, flag 0x800, now decodes under its stored name; RAR 2.0 encryption is still refused)
    for (flags, version, method) in [(0, 29, 0x36), (0, 10, 0x30), (0, 36, 0x31), (4, 29, 0x30), (4, 20, 0x30)] {
        let dir = tempfile::tempdir().unwrap();
        let mut file = member(b"one", b"payload", flags, method);
        file[24] = version;
        fix_crc(&mut file, 0);
        let mut opts = options(dir.path());
        opts.limits.decoder_window = 0;
        let error = fails(vec![archive(&[file])], opts);
        assert!(
            matches!(error.kind,FailureKind::Rar(ref e) if matches!(e.as_ref(),zipfast::error::RarFailure::Unsupported(_))),
            "{error:?}"
        );
        assert!(!dir.path().join("one").exists());
    }
}
#[test]
fn malformed_continuations_and_checks_cannot_complete() {
    let gold = b"0123456789abcdefghijklmnopqrstuvwxyzABCD";
    for mutation in 0..6 {
        let dir = tempfile::tempdir().unwrap();
        let mut parts = split(gold, 20);
        match mutation {
            0 => parts[1][20 + 24] = 29,
            1 => parts[1][20 + 3] ^= 0x20,
            2 => parts[1][20 + 11] ^= 1,
            3 => parts[1][20 + 32] = b'x',
            4 => parts[0][20 + 35] ^= 1,
            _ => parts[1][20 + 16] ^= 1,
        }
        if mutation != 4 {
            fix_crc(&mut parts[1], 20)
        }
        let mut opts = options(dir.path());
        opts.first_name = "a.part01.rar".into();
        let error = fails(parts, opts);
        assert!(
            matches!(
                error.kind,
                FailureKind::Malformed(_) | FailureKind::ChecksumMismatch { .. } | FailureKind::Rar(_)
            ),
            "{error:?}"
        );
        assert!(!dir.path().join("one").exists());
    }
}
#[test]
fn source_change_and_cancel_are_checked_while_rar4_is_parked() {
    for (cancel, encrypted) in [(false, false), (true, false), (false, true), (true, true)] {
        let dir = tempfile::tempdir().unwrap();
        let data = if encrypted {
            aes_stored(b"payload", true, &[16]).remove(0)
        } else {
            archive(&[member(b"one", b"payload", 0, 0x30)])
        };
        let mut opts = options(dir.path());
        opts.set_password(Some("pw".into())).unwrap();
        let (mut s, g) = custom(vec![data], vec![vec![]], opts, true, 1);
        for _ in 0..1000 {
            match step(&mut s) {
                Poll::Pending => wake(&mut s, &g),
                Poll::Ready(Ok(Some(ProgressiveEvent::MemberStarted { .. }))) => break,
                Poll::Ready(Err(e)) => panic!("{e:?}"),
                _ => {}
            }
        }
        assert!(step(&mut s).is_pending());
        if cancel {
            s.control().cancel()
        } else {
            g.lock().unwrap().generation = 1;
            wake(&mut s, &g)
        }
        let error = match collect(&mut s, &g) {
            Err(e) => e,
            _ => panic!("source change/cancel accepted"),
        };
        assert!(
            if cancel {
                matches!(error.kind, FailureKind::Canceled)
            } else {
                matches!(error.kind, FailureKind::SourceChanged)
            },
            "{error:?}"
        );
        assert!(!dir.path().join("one").exists());
    }
}
#[test]
fn header_holes_truncation_crc_and_resource_limits_fail_boundedly() {
    let data = archive(&[member(b"one", b"payload", 0, 0x30)]);
    for cut in 0..55 {
        let dir = tempfile::tempdir().unwrap();
        let error = fails(vec![data[..cut].to_vec()], options(dir.path()));
        assert!(matches!(error.kind, FailureKind::Truncated | FailureKind::Rar(_)), "cut={cut}: {error:?}");
    }
    for mutation in 0..4 {
        let dir = tempfile::tempdir().unwrap();
        let mut wire = data.clone();
        match mutation {
            0 => wire[20] ^= 1,
            1 => {
                wire[25..27].copy_from_slice(&6u16.to_le_bytes());
            }
            2 => {
                wire[23] |= 8;
                fix_crc(&mut wire, 20)
            }
            _ => {
                wire[10] |= 0x80;
                fix_crc(&mut wire, 7)
            }
        }
        let _ = fails(vec![wire], options(dir.path()));
        assert!(!dir.path().join("one").exists());
    }
    for (limit, resource) in [(0, Resource::HeaderBlocks), (1, Resource::NameBytes), (2, Resource::HeaderAllocation)] {
        let dir = tempfile::tempdir().unwrap();
        let mut opts = options(dir.path());
        match limit {
            0 => opts.limits.header_blocks = 1,
            1 => opts.limits.name_bytes = 25,
            _ => opts.limits.header_allocation = 80,
        }
        let error = fails(vec![data.clone()], opts);
        assert!(matches!(error.kind,FailureKind::Limit{resource:r,..} if r==resource), "{error:?}");
    }
    let dir = tempfile::tempdir().unwrap();
    let (mut s, g) = custom(vec![data], vec![vec![24..26]], options(dir.path()), false, 7);
    let e = match collect(&mut s, &g) {
        Err(e) => e,
        _ => panic!("header hole accepted"),
    };
    assert!(matches!(e.kind, FailureKind::HeaderHole));
}
#[test]
#[ignore = "private RARLAB fixtures remain outside redistributable tests"]
fn private_native_stored_and_split_match_recorded_gold() {
    let root = std::path::PathBuf::from(std::env::var_os("ZIPFAST_RAR4_NATIVE_FIXTURES").expect("fixture directory"));
    for split_case in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let mut opts = options(dir.path());
        let data = if split_case {
            opts.first_name = "split.part1.rar".into();
            (1..=3).map(|n| std::fs::read(root.join(format!("fixtures/split.part{n}.rar"))).unwrap()).collect()
        } else {
            vec![std::fs::read(root.join("fixtures/stored.rar")).unwrap()]
        };
        let n = data.len();
        let (mut s, g) = custom(data, vec![vec![]; n], opts, true, 13);
        let (mut artifacts, opened) = collect(&mut s, &g).unwrap();
        assert_eq!(opened.len(), n);
        let names = if split_case { vec!["split.bin"] } else { vec!["a.txt", "b.txt"] };
        assert_eq!(artifacts.len(), names.len());
        for (a, name) in artifacts.iter_mut().zip(names) {
            assert_eq!(read_all(a), std::fs::read(root.join("payloads").join(name)).unwrap());
            assert!(matches!(a.evidence(), ArtifactEvidence::Verified(_)));
        }
    }
}

#[test]
fn encoded_unicode_name_and_empty_member_survive_incremental_framing() {
    let raw = b"xx\0\0\xa0\x3d\xd8\0\xde";
    let dir = tempfile::tempdir().unwrap();
    let wire = archive(&[member(raw, b"", 0x200, 0x30)]);
    let (mut s, g) = custom(vec![wire], vec![vec![]], options(dir.path()), true, 1);
    let mut seen = false;
    let mut finished = false;
    for _ in 0..10000 {
        match step(&mut s) {
            Poll::Pending => wake(&mut s, &g),
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberStarted { name, size, .. }))) => {
                assert_eq!(name.as_slice(), raw);
                assert_eq!(size, Some(0));
                seen = true;
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished {
                outcome: MemberOutcome::Provisional(mut a),
                ..
            }))) => {
                assert!(read_all(&mut a).is_empty());
                assert!(matches!(a.evidence(), ArtifactEvidence::Verified(_)));
                finished = true;
            }
            Poll::Ready(Ok(None)) => {
                assert!(seen && finished);
                return;
            }
            Poll::Ready(Err(e)) => panic!("{e:?}"),
            _ => {}
        }
    }
    panic!("empty member did not finish")
}

#[test]
fn directory_crc_cannot_bypass_rar4_verification() {
    let dir = tempfile::tempdir().unwrap();
    let mut file = member(b"directory", b"", 0xe0, 0x30);
    file[28..32].copy_from_slice(&0o040755u32.to_le_bytes());
    file[16..20].copy_from_slice(&1u32.to_le_bytes());
    fix_crc(&mut file, 0);
    let error = fails(vec![archive(&[file])], options(dir.path()));
    assert!(matches!(error.kind, FailureKind::Rar(_)), "{error:?}");
    assert!(!dir.path().join("directory").exists());
}

// First-party fixture follows the independently observed modern Stored geometry.
fn aes_stored(gold: &[u8], headers: bool, cuts: &[usize]) -> Vec<Vec<u8>> {
    aes_stored_mode(gold, headers, true, cuts)
}
fn aes_stored_mode(gold: &[u8], headers: bool, data_encrypted: bool, cuts: &[usize]) -> Vec<Vec<u8>> {
    let salt = [1, 2, 3, 4, 5, 6, 7, 8];
    let (key, iv) = zipfast::crypto::derive_rar4_key_iv("pw", &salt);
    let mut padded = gold.to_vec();
    padded.resize(gold.len().next_multiple_of(16), 0xa5);
    let cipher = if data_encrypted { zipfast::crypto::encrypt_cbc(&key, &iv, &padded).unwrap() } else { gold.to_vec() };
    let enc_header = |mut bytes: Vec<u8>| {
        if !headers {
            return bytes;
        }
        bytes.resize(bytes.len().next_multiple_of(16), 0x5a);
        let mut wire = salt.to_vec();
        wire.extend(zipfast::crypto::encrypt_cbc(&key, &iv, &bytes).unwrap());
        wire
    };
    let mut at = 0;
    cuts.iter()
        .enumerate()
        .map(|(i, &len)| {
            let payload = &cipher[at..at + len];
            at += len;
            let flags = 0x8000
                | if data_encrypted { 0x404 } else { 0 }
                | u16::from(i > 0)
                | (u16::from(i + 1 < cuts.len()) * 2);
            let mut body = Vec::new();
            body.extend((len as u32).to_le_bytes());
            body.extend((gold.len() as u32).to_le_bytes());
            body.push(3);
            body.extend(hash(if i + 1 == cuts.len() { gold } else { payload }).to_le_bytes());
            body.extend(0x50221884u32.to_le_bytes());
            body.extend([29, 0x30]);
            body.extend(3u16.to_le_bytes());
            body.extend(0o100644u32.to_le_bytes());
            body.extend(b"one");
            if data_encrypted {
                body.extend(salt);
            }
            let mut wire = b"Rar!\x1a\x07\0".to_vec();
            wire.extend(block(0x73, 1 | if headers { 0x80 } else { 0 }, &[0; 6]));
            wire.extend(enc_header(block(0x74, flags, &body)));
            wire.extend(payload);
            wire.extend(enc_header(block(0x7b, 0x4000 | u16::from(i + 1 < cuts.len()), &[])));
            wire
        })
        .collect()
}

#[test]
fn aes_stored_continuous_split_and_independent_headers() {
    let gold = b"continuous CBC across two unaligned boundaries with arbitrary trailing padding";
    for headers in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let mut opts = options(dir.path());
        opts.set_password(Some("pw".into())).unwrap();
        opts.first_name = "a.part01.rar".into();
        let bytes = aes_stored(gold, headers, &[29, 31, 20]);
        let (mut session, gate) = custom(bytes, vec![vec![]; 3], opts, true, 7);
        let (mut artifacts, volumes) = collect(&mut session, &gate).unwrap();
        assert_eq!(volumes, [0, 1, 2]);
        assert_eq!(read_all(&mut artifacts[0]), gold);
    }
}

#[test]
fn aes_stored_password_damage_salt_and_cipher_tail_boundaries() {
    let gold = b"continuous CBC across two unaligned boundaries with arbitrary trailing padding";
    for headers in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let wire = aes_stored(gold, headers, &[80]);
        let error = fails(wire.clone(), options(dir.path()));
        assert!(matches!(error.kind, FailureKind::PasswordRequired), "{error:?}");
        let mut opts = options(dir.path());
        opts.set_password(Some("wrong password".into())).unwrap();
        let error = fails(wire.clone(), opts);
        assert!(
            matches!(error.kind, FailureKind::Rar(ref r) if matches!(**r, zipfast::error::RarFailure::EncryptedIntegrity { .. })),
            "{error:?}"
        );
        for header_damage in [false, true] {
            let mut damaged = wire.clone();
            let at = if header_damage {
                30
            } else if headers {
                100
            } else {
                70
            };
            damaged[0][at] ^= 1;
            let mut opts = options(dir.path());
            opts.set_password(Some("pw".into())).unwrap();
            assert!(!matches!(fails(damaged, opts).kind, FailureKind::PasswordRequired));
        }
    }
    // A changed per-part salt is not a CBC reset signal in the admitted family.
    let mut wire = aes_stored(gold, false, &[29, 31, 20]);
    wire[1][20 + 35] ^= 1;
    fix_crc(&mut wire[1], 20);
    let dir = tempfile::tempdir().unwrap();
    let mut opts = options(dir.path());
    opts.first_name = "a.part01.rar".into();
    opts.set_password(Some("pw".into())).unwrap();
    let error = fails(wire, opts);
    assert!(
        matches!(error.kind, FailureKind::Rar(ref r) if matches!(**r, zipfast::error::RarFailure::Unsupported(_))),
        "{error:?}"
    );
}

#[test]
fn aes_stored_hole_taint_crosses_parts_and_replacement_replays_headers() {
    let gold = b"continuous CBC across two unaligned boundaries with arbitrary trailing padding";
    for headers in [false, true] {
        for fill in [HoleFill::Sparse, HoleFill::Zero] {
            let wire = aes_stored(gold, headers, &[29, 31, 20]);
            let data_at = if headers { 76 } else { 63 };
            let dir = tempfile::tempdir().unwrap();
            let mut opts = options(dir.path());
            opts.set_password(Some("pw".into())).unwrap();
            opts.first_name = "a.part01.rar".into();
            opts.hole_policy = HolePolicy::PartialStored { fill };
            let (mut session, gate) =
                custom(wire.clone(), vec![vec![data_at + 28..data_at + 29], vec![], vec![]], opts, true, 11);
            let (mut artifacts, _) = collect(&mut session, &gate).unwrap();
            let a = &mut artifacts[0];
            assert_eq!(a.holes(), &[OutputHole { offset: 16, len: 32 }]);
            session.patch(a, 16, &gold[16..48]).unwrap();
            let v = verify(&mut session, a).unwrap();
            assert_eq!(v.level(), VerificationLevel::InnerOnly);
            for (i, bytes) in wire.into_iter().enumerate() {
                session
                    .supply_verification_source(
                        i as u32,
                        Box::new(Bytes {
                            data: bytes,
                            holes: vec![],
                            id: 100 + i as u128,
                            chunk: 7,
                            wait: false,
                            gate: Arc::new(Mutex::new(Gate::default())),
                        }),
                    )
                    .unwrap();
            }
            let v = verify(&mut session, a).unwrap();
            assert_eq!(v.level(), VerificationLevel::Strict);
            assert_eq!(v.authentication(), AuthenticationEvidence::CbcChecksOnly);
            assert_eq!(read_all(a), gold);
            assert_eq!(a.publication(), ArtifactPublication::Unpublished);
        }
    }
}

#[test]
fn encrypted_headers_allow_plain_stored_and_new_members_reset_data_cipher() {
    for data_encrypted in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let gold = b"new member CBC IV";
        let len = if data_encrypted { gold.len().next_multiple_of(16) } else { gold.len() };
        let mut wire = aes_stored_mode(gold, true, data_encrypted, &[len]).remove(0);
        // Remove independent encrypted end, append a second member and its end.
        wire.truncate(wire.len() - 24);
        let second = aes_stored_mode(gold, true, data_encrypted, &[len]).remove(0);
        wire.extend_from_slice(&second[20..]);
        let mut opts = options(dir.path());
        opts.set_password(Some("pw".into())).unwrap();
        let (mut s, g) = custom(vec![wire], vec![vec![]], opts, true, 1);
        let (mut artifacts, _) = collect(&mut s, &g).unwrap();
        assert_eq!(artifacts.len(), 2);
        for artifact in &mut artifacts {
            assert_eq!(read_all(artifact), gold);
        }
    }
}

#[test]
fn aes_stored_header_holes_and_kdf_limits_are_typed() {
    let gold = b"continuous CBC across two unaligned boundaries with arbitrary trailing padding";
    let wire = aes_stored(gold, true, &[80]);
    for hole in [20..21, 27..28, 28..29, 75..76] {
        let dir = tempfile::tempdir().unwrap();
        let mut opts = options(dir.path());
        opts.set_password(Some("pw".into())).unwrap();
        opts.hole_policy = HolePolicy::PartialStored { fill: HoleFill::Sparse };
        let (mut session, gate) = custom(wire.clone(), vec![vec![hole]], opts, false, 7);
        let err = collect(&mut session, &gate).err().unwrap();
        assert!(matches!(err.kind, FailureKind::HeaderHole), "{err:?}");
    }
    for (encoded, session_limit) in [(3, 1 << 26), (8192, 100)] {
        let dir = tempfile::tempdir().unwrap();
        let mut opts = options(dir.path());
        opts.set_password(Some("pw".into())).unwrap();
        opts.limits.password_encoded_bytes = encoded;
        opts.limits.kdf_session_blocks = session_limit;
        let err = fails(wire.clone(), opts);
        assert!(
            matches!(
                err.kind,
                FailureKind::Limit { resource: Resource::PasswordEncodedBytes | Resource::KdfSessionBlocks, .. }
            ),
            "{err:?}"
        );
    }
    let dir = tempfile::tempdir().unwrap();
    let mut unknown = b"Rar!\x1a\x07\0".to_vec();
    unknown.extend(block(0x73, 0x280, &[0; 7]));
    let err = fails(vec![unknown], options(dir.path()));
    assert!(matches!(err.kind, FailureKind::Rar(ref r) if matches!(**r, zipfast::error::RarFailure::Unsupported(_))));
}

#[test]
#[ignore = "private native fixture; explicit final-source replay only"]
fn private_native_aes_stored_matches_recorded_gold() {
    let root = std::path::PathBuf::from(std::env::var_os("ZIPFAST_RAR4_AES_NATIVE").expect("private fixture root"));
    let parts = (1..=3)
        .map(|i| std::fs::read(root.join(format!("generated/split-aes-store.part{i}.rar"))).unwrap())
        .collect::<Vec<_>>();
    let gold = std::fs::read(root.join("native/split.bin")).unwrap();
    assert_eq!(gold.len(), 155000);
    for chunk in [1, 17, 4096] {
        let dir = tempfile::tempdir().unwrap();
        let mut opts = options(dir.path());
        opts.first_name = "split-aes-store.part1.rar".into();
        opts.set_password(Some("zipfast-test-only".into())).unwrap();
        let (mut session, gate) = custom(parts.clone(), vec![vec![]; 3], opts, true, chunk);
        let (mut artifacts, volumes) = collect(&mut session, &gate).unwrap();
        assert_eq!(volumes, [0, 1, 2]);
        assert_eq!(read_all(&mut artifacts[0]), gold);
        let ArtifactEvidence::Verified(v) = artifacts[0].evidence() else { panic!("no native gold verification") };
        assert_eq!(v.level(), VerificationLevel::Strict);
        assert_eq!(v.authentication(), AuthenticationEvidence::CbcChecksOnly);
    }
}

#[test]
fn aes_stored_tail_padding_and_total_alignment_are_checked() {
    let gold = b"continuous CBC across two unaligned boundaries with arbitrary trailing padding";
    for mutation in 0..4 {
        let mut wire = aes_stored(gold, false, &[80]).remove(0);
        match mutation {
            0 => {
                // Short total cipher, with coherent physical packed length.
                wire.remove(63 + 79);
                wire[27..31].copy_from_slice(&79u32.to_le_bytes());
            }
            1 => {
                // More than 15 trailing plaintext bytes cannot be padding.
                wire[31..35].copy_from_slice(&60u32.to_le_bytes());
            }
            2 => {
                // Declared output exceeds available decrypted bytes.
                wire[31..35].copy_from_slice(&81u32.to_le_bytes());
            }
            _ => {
                wire.truncate(63 + 60);
            }
        }
        fix_crc(&mut wire, 20);
        let dir = tempfile::tempdir().unwrap();
        let mut opts = options(dir.path());
        opts.set_password(Some("pw".into())).unwrap();
        let _ = fails(vec![wire], opts);
        assert!(!dir.path().join("one").exists());
    }
}

#[test]
fn aes_stored_wrong_patch_keeps_failed_checks_sticky() {
    let gold = b"continuous CBC across two unaligned boundaries with arbitrary trailing padding";
    let dir = tempfile::tempdir().unwrap();
    let wire = aes_stored(gold, true, &[80]);
    let mut opts = options(dir.path());
    opts.set_password(Some("pw".into())).unwrap();
    opts.hole_policy = HolePolicy::PartialStored { fill: HoleFill::Sparse };
    let (mut s, g) = custom(wire, vec![vec![76..77]], opts, true, 7);
    let (mut artifacts, _) = collect(&mut s, &g).unwrap();
    let a = &mut artifacts[0];
    assert_eq!(a.holes(), &[OutputHole { offset: 0, len: 32 }]);
    s.patch(a, 0, &[b'x'; 32]).unwrap();
    assert!(verify(&mut s, a).is_err());
    assert!(s.patch(a, 0, &gold[..32]).is_err());
    assert!(
        s.set_expected_inner(
            a,
            ExpectedInner::Crc32 { digest: hash(gold), label: "cannot erase failed archive check".into() }
        )
        .is_err()
    );
    assert_eq!(a.publication(), ArtifactPublication::Unpublished);
}

fn r1_metadata_record(directory: bool, encrypted: bool, salted: bool, version: u8) -> Vec<u8> {
    let flags = if directory { 0xe0 } else { 0 } | if encrypted { 4 } else { 0 } | if salted { 0x400 } else { 0 };
    let mut file = member(b"entry", b"", flags, 0x30);
    file[24] = version;
    if directory {
        file[28..32].copy_from_slice(&0o040755u32.to_le_bytes());
    }
    if salted {
        file.extend([1; 8]);
        let size = file.len() as u16;
        file[5..7].copy_from_slice(&size.to_le_bytes());
    }
    fix_crc(&mut file, 0);
    archive(&[file])
}

fn r1_observe(bytes: Vec<u8>, opts: ProgressiveOptions) -> (Vec<MemberOutcome>, Option<ProgressiveFailure>) {
    let mut session =
        ProgressiveSession::from_sealed_memory(vec![("a.rar".into(), bytes.into_boxed_slice())], opts).unwrap();
    let mut outcomes = Vec::new();
    for _ in 0..1000 {
        match step(&mut session) {
            Poll::Ready(Err(e)) => return (outcomes, Some(e)),
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) => {
                return (outcomes, Some(failure));
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished {
                outcome: MemberOutcome::Stopped { failure, .. },
                ..
            }))) => return (outcomes, Some(failure)),
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { outcome, .. }))) => outcomes.push(outcome),
            Poll::Ready(Ok(None)) => return (outcomes, None),
            _ => {}
        }
    }
    panic!("finite metadata admission poll bound")
}

#[test]
fn r1_unsupported_crypto_is_refused_before_directory_and_skip_dispositions() {
    let mut bypasses = Vec::new();
    for mode in [zipfast::extract::Mode::Extract, zipfast::extract::Mode::Test] {
        for password in [None, Some("pw".to_owned())] {
            for (directory, salted, version) in
                [(true, false, 29), (true, true, 29), (false, false, 29), (false, true, 20)]
            {
                let dir = tempfile::tempdir().unwrap();
                let target = dir.path().join("entry");
                if !directory {
                    std::fs::write(&target, b"keep existing target").unwrap();
                }
                let mut opts = options(dir.path());
                opts.extract.mode = mode;
                opts.extract.overwrite = zipfast::extract::Overwrite::Skip;
                opts.limits.kdf_session_blocks = 0;
                opts.set_password(password.clone()).unwrap();
                let (outcomes, failure) = r1_observe(r1_metadata_record(directory, true, salted, version), opts);
                let refused = failure.as_ref().is_some_and(|e| matches!(&e.kind, FailureKind::Rar(r) if matches!(**r, zipfast::error::RarFailure::Unsupported(_))));
                let untouched = if directory {
                    !target.exists()
                } else {
                    std::fs::read(&target).unwrap() == b"keep existing target"
                };
                if !refused || !outcomes.is_empty() || !untouched {
                    let outcomes = outcomes
                        .iter()
                        .map(|o| match o {
                            MemberOutcome::Directory { created, .. } => format!("Directory(created={created})"),
                            MemberOutcome::Skipped(_) => "Skipped".to_owned(),
                            _ => "other outcome".to_owned(),
                        })
                        .collect::<Vec<_>>();
                    bypasses.push(format!("mode={mode:?} password={} directory={directory} salted={salted} version={version}: outcomes={outcomes:?}, failure={failure:?}, target_exists={}", password.is_some(), target.exists()));
                } else {
                    let failure = failure.unwrap();
                    assert_eq!(failure.context.volume_index, Some(0));
                    assert_eq!(failure.context.expected.as_deref(), Some(std::ffi::OsStr::new("a.rar")));
                    assert!(failure.context.packed_offset.is_some());
                }
            }
        }
    }
    assert!(bypasses.is_empty(), "admission bypasses:\n{}", bypasses.join("\n"));
}

#[test]
fn r1_plain_directories_and_admitted_regular_aes_keep_existing_dispositions() {
    for mode in [zipfast::extract::Mode::Extract, zipfast::extract::Mode::Test] {
        let dir = tempfile::tempdir().unwrap();
        let mut opts = options(dir.path());
        opts.extract.mode = mode;
        let (outcomes, failure) = r1_observe(r1_metadata_record(true, false, false, 29), opts);
        assert!(failure.is_none(), "{failure:?}");
        let extract = mode == zipfast::extract::Mode::Extract;
        assert!(matches!(outcomes.as_slice(), [MemberOutcome::Directory { created, .. }] if *created == extract));
        assert_eq!(dir.path().join("entry").is_dir(), extract);
        let mut opts = options(dir.path());
        opts.extract.mode = mode;
        opts.set_password(Some("pw".into())).unwrap();
        let (outcomes, failure) = r1_observe(aes_stored(b"admitted", false, &[16]).remove(0), opts);
        assert!(failure.is_none(), "{failure:?}");
        assert!(if extract {
            matches!(outcomes.as_slice(), [MemberOutcome::Verified(_)])
        } else {
            matches!(outcomes.as_slice(), [MemberOutcome::Tested(_)])
        });
        if extract {
            assert_eq!(std::fs::read(dir.path().join("one")).unwrap(), b"admitted");
        } else {
            assert!(!dir.path().join("one").exists());
        }
    }
    for password in [None, Some("pw".to_owned())] {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("entry"), b"keep existing target").unwrap();
        let mut opts = options(dir.path());
        opts.extract.overwrite = zipfast::extract::Overwrite::Skip;
        opts.limits.kdf_session_blocks = 0;
        opts.set_password(password).unwrap();
        let (outcomes, failure) = r1_observe(r1_metadata_record(false, true, true, 29), opts);
        assert!(failure.is_none(), "{failure:?}");
        assert!(matches!(outcomes.as_slice(), [MemberOutcome::Skipped(_)]));
        assert_eq!(std::fs::read(dir.path().join("entry")).unwrap(), b"keep existing target");
    }
}

#[test]
fn a_session_refuses_the_whole_archive_member_filter_before_anything() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = archive(&[member(b"one", b"data", 0, 0x30)]);
    let mut opts = options(dir.path());
    opts.extract.select = Some(zipfast::extract::MemberFilter::new(|_| true));
    let refused = ProgressiveSession::from_sealed_memory(vec![("a.rar".into(), bytes.into_boxed_slice())], opts);
    assert!(matches!(refused.err().unwrap().kind, FailureKind::InvalidCapability));
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}
