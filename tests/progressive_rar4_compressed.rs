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

//! Progressive independent LZ using retained independently validated fixed bytes.
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

fn member(name: &[u8], packed: &[u8], expected: &[u8], version: u8, method: u8, flags: u16) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend((packed.len() as u32).to_le_bytes());
    body.extend((expected.len() as u32).to_le_bytes());
    body.push(3);
    body.extend(hash(expected).to_le_bytes());
    body.extend(0x50221884u32.to_le_bytes());
    body.extend([version, method]);
    body.extend((name.len() as u16).to_le_bytes());
    body.extend(0o100644u32.to_le_bytes());
    body.extend(name);
    let mut bytes = block(0x74, flags | 0x8000, &body);
    bytes.extend(packed);
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
        },
        OsString::from("a.rar"),
    )
}

fn poll(s: &mut ProgressiveSession) -> Poll<ProgressiveResult<Option<ProgressiveEvent>>> {
    s.poll_event(&mut Context::from_waker(Waker::noop()))
}
#[test]
fn independent_lz_test_and_extract() {
    let vectors: &[(&[u8], &[u8])] = &[
        (&[], b""),
        (include_bytes!("fixtures/rar4-lz/literal-a.packed"), b"A"),
        (include_bytes!("fixtures/rar4-lz/table-reuse-delta.packed"), b"AA"),
        (include_bytes!("fixtures/rar4-lz/initial-delta-zero-baseline.packed"), b"A"),
    ];
    for &(packed, gold) in vectors {
        for method in 0x31..=0x35 {
            for test in [false, true] {
                for chunk in [1, 7, 64] {
                    let dir = tempfile::tempdir().unwrap();
                    let mut opts = options(dir.path());
                    opts.limits.read_chunk = chunk;
                    if test {
                        opts.extract.mode = zipfast::extract::Mode::Test;
                    }
                    let data = archive(&[member(b"one", packed, gold, 29, method, 0)]);
                    let mut s =
                        ProgressiveSession::from_sealed_memory(vec![("a.rar".into(), data.into_boxed_slice())], opts)
                            .unwrap();
                    let mut checked = 0;
                    let mut ended = false;
                    for _ in 0..10000 {
                        match poll(&mut s) {
                            Poll::Ready(Err(e)) => panic!("unexpected failure {e:?}"),
                            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) => {
                                panic!("terminated {failure:?}")
                            }
                            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { outcome, .. }))) => match outcome {
                                MemberOutcome::Verified(v) => {
                                    assert_eq!(v.inner_size(), gold.len() as u64);
                                    checked += 1;
                                }
                                MemberOutcome::Tested(v) => {
                                    assert_eq!(v.inner_size(), gold.len() as u64);
                                    assert_eq!(v.crc32_verdict(), CheckVerdict::Passed);
                                    checked += 1;
                                }
                                MemberOutcome::Stopped { failure, .. } => panic!("stopped {failure:?}"),
                                _ => panic!("unexpected outcome"),
                            },
                            Poll::Ready(Ok(None)) => {
                                ended = true;
                                break;
                            }
                            _ => {}
                        }
                    }
                    assert!(ended);
                    assert_eq!(checked, 1);
                    if !test {
                        assert_eq!(std::fs::read(dir.path().join("one")).unwrap(), gold);
                    }
                }
            }
        }
    }
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

fn drive(s: &mut ProgressiveSession, gate: Option<&Arc<Mutex<Gate>>>) -> ProgressiveResult<Vec<Artifact>> {
    let mut artifacts = Vec::new();
    for _ in 0..1000000 {
        match poll(s) {
            Poll::Pending => {
                if let Some(g) = gate {
                    wake(s, g);
                }
            }
            Poll::Ready(Err(e)) => return Err(e),
            Poll::Ready(Ok(None)) => return Ok(artifacts),
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) => return Err(failure),
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { outcome, .. }))) => match outcome {
                MemberOutcome::Provisional(a) => artifacts.push(a),
                MemberOutcome::Stopped { failure, .. } => return Err(failure),
                MemberOutcome::Partial(_) => panic!("compressed data became partial Stored"),
                _ => {}
            },
            _ => {}
        }
    }
    panic!("finite poll bound")
}
fn fixed() -> Vec<u8> {
    archive(&[member(b"one", include_bytes!("fixtures/rar4-lz/new-match-repeat-last.packed"), b"AAAAAAA", 29, 0x33, 0)])
}
fn fix_header(data: &mut [u8], start: usize) {
    let len = u16::from_le_bytes([data[start + 5], data[start + 6]]) as usize;
    let crc = hash(&data[start + 2..start + len]) as u16;
    data[start..start + 2].copy_from_slice(&crc.to_le_bytes());
}
#[test]
fn waits_at_header_table_token_and_end_cuts_preserve_bytes() {
    for chunk in [1, 2, 7, 17, 4096] {
        let dir = tempfile::tempdir().unwrap();
        let mut opts = options(dir.path());
        opts.limits.read_chunk = chunk as u64;
        let (mut s, g) = custom(vec![fixed()], vec![vec![]], opts, true, chunk);
        let mut artifacts = drive(&mut s, Some(&g)).unwrap();
        assert_eq!(artifacts.len(), 1);
        let mut bytes = [0; 7];
        let mut at = 0;
        while at < bytes.len() {
            let end = (at + chunk).min(bytes.len());
            let ArtifactRead::Filled { count } = artifacts[0].read_at(at as u64, &mut bytes[at..end]).unwrap() else {
                panic!("missing output")
            };
            at += count;
        }
        assert_eq!(&bytes, b"AAAAAAA");
        assert!(!dir.path().join("one").exists());
    }
}
#[test]
fn dictionary_and_output_limits_refuse_before_success() {
    for (flags, window) in [(0u16, 65536u64), (0xc0, 4194304)] {
        for budget in [window - 1, window] {
            let dir = tempfile::tempdir().unwrap();
            let mut opts = options(dir.path());
            opts.limits.decoder_window = budget;
            let data = archive(&[member(
                b"one",
                include_bytes!("fixtures/rar4-lz/new-match-repeat-last.packed"),
                b"AAAAAAA",
                29,
                0x33,
                flags,
            )]);
            let mut s =
                ProgressiveSession::from_sealed_memory(vec![("a.rar".into(), data.into_boxed_slice())], opts).unwrap();
            let r = drive(&mut s, None);
            if budget < window {
                assert!(matches!(
                    r.err().expect("expected failure").kind,
                    FailureKind::Limit { resource: Resource::DecoderWindow, .. }
                ));
                assert!(!dir.path().join("one").exists());
            } else {
                r.unwrap();
                assert_eq!(std::fs::read(dir.path().join("one")).unwrap(), b"AAAAAAA");
            }
        }
    }
    for test in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let mut opts = options(dir.path());
        opts.limits.logical_output_bytes = 6;
        if test {
            opts.extract.mode = zipfast::extract::Mode::Test;
        }
        let mut s =
            ProgressiveSession::from_sealed_memory(vec![("a.rar".into(), fixed().into_boxed_slice())], opts).unwrap();
        assert!(matches!(
            drive(&mut s, None).err().expect("expected failure").kind,
            FailureKind::Limit { resource: Resource::LogicalOutputBytes, .. }
        ));
        assert!(!dir.path().join("one").exists());
    }
}
#[test]
fn unsupported_geometry_precedes_skip_test_directory_and_key_work() {
    // Split and solid members decode now (tests/rar4_split_solid.rs).
    // Versions 15, 20, 26 and 29 decode; 10 and 36 don't.
    for (flags, version, unknown) in [(4, 29, false), (0xe4, 29, false), (0, 10, false), (0, 36, false), (0, 29, true)]
    {
        for mode in 0..3 {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join("one"), b"old").unwrap();
            let mut opts = options(dir.path());
            if mode == 1 {
                opts.extract.mode = zipfast::extract::Mode::Test;
            }
            if mode == 2 {
                opts.extract.overwrite = zipfast::extract::Overwrite::Skip;
            }
            opts.limits.kdf_session_blocks = 0;
            let mut file =
                member(b"one", include_bytes!("fixtures/rar4-lz/literal-a.packed"), b"A", version, 0x33, flags);
            if unknown {
                file[11..15].copy_from_slice(&u32::MAX.to_le_bytes());
                fix_header(&mut file, 0);
            }
            let data = archive(&[file]);
            let mut s =
                ProgressiveSession::from_sealed_memory(vec![("a.rar".into(), data.into_boxed_slice())], opts).unwrap();
            let e = drive(&mut s, None).err().expect("expected failure");
            assert!(
                matches!(e.kind,FailureKind::Rar(ref f) if matches!(f.as_ref(),zipfast::error::RarFailure::Unsupported(_))),
                "{e:?}"
            );
            assert_eq!(std::fs::read(dir.path().join("one")).unwrap(), b"old");
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        }
    }
}
#[test]
fn truncated_corrupt_and_unsupported_payloads_never_publish() {
    for case in 0..6 {
        let dir = tempfile::tempdir().unwrap();
        let mut data = fixed();
        match case {
            0 => {
                data.truncate(56);
            }
            1 => {
                data[36] ^= 1;
                fix_header(&mut data, 20);
            }
            2 => {
                data[31..35].copy_from_slice(&8u32.to_le_bytes());
                fix_header(&mut data, 20);
            }
            3 => {
                data[55] = 0xff;
            }
            4 => {
                data =
                    archive(&[member(b"one", include_bytes!("fixtures/rar4-lz/ppm-marker.packed"), b"A", 29, 0x33, 0)]);
            }
            _ => {
                data = archive(&[member(b"one", &[0x3f, 0xff, 0xc0], b"A", 29, 0x33, 0)]);
            }
        }
        let mut s = ProgressiveSession::from_sealed_memory(
            vec![("a.rar".into(), data.into_boxed_slice())],
            options(dir.path()),
        )
        .unwrap();
        let e = drive(&mut s, None).err().expect("malformed data cannot succeed");
        assert!(
            match (&e.kind, case) {
                (FailureKind::Truncated, 0) => true,
                // a PPM block header the data cuts off is corrupt too
                (FailureKind::Rar(f), 1..=5) => matches!(f.as_ref(), zipfast::error::RarFailure::Integrity { .. }),
                _ => false,
            },
            "case{case}: {e:?}"
        );
        assert!(!dir.path().join("one").exists());
    }
}
#[test]
fn source_generation_change_and_cancel_after_start_cannot_verify() {
    for cancel in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (mut s, g) = custom(vec![fixed()], vec![vec![]], options(dir.path()), false, 1);
        let mut started = false;
        for _ in 0..1000 {
            match poll(&mut s) {
                Poll::Ready(Ok(Some(ProgressiveEvent::MemberStarted { .. }))) => {
                    started = true;
                    break;
                }
                Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) => {
                    panic!("terminated before MemberStarted: {failure:?}")
                }
                Poll::Ready(Err(e)) => panic!("failed before MemberStarted: {e:?}"),
                Poll::Ready(Ok(None)) => panic!("EOF before MemberStarted"),
                _ => {}
            }
        }
        assert!(started, "MemberStarted not observed within 1000 setup polls");
        if cancel {
            s.control().cancel();
        } else {
            g.lock().unwrap().generation += 1;
        }
        let e = drive(&mut s, Some(&g)).err().expect("expected failure");
        assert!(if cancel {
            matches!(e.kind, FailureKind::Canceled)
        } else {
            matches!(e.kind, FailureKind::SourceChanged)
        });
        assert!(!dir.path().join("one").exists());
    }
    let dir = tempfile::tempdir().unwrap();
    let mut s =
        ProgressiveSession::from_sealed_memory(vec![("a.rar".into(), fixed().into_boxed_slice())], options(dir.path()))
            .unwrap();
    s.control().cancel();
    assert!(matches!(drive(&mut s, None).err().expect("expected failure").kind, FailureKind::Canceled));
}
#[test]
fn compressed_hole_stops_without_recovery_or_restart() {
    let dir = tempfile::tempdir().unwrap();
    let mut opts = options(dir.path());
    opts.hole_policy = HolePolicy::PartialStored { fill: HoleFill::Sparse };
    let (mut s, g) = custom(vec![fixed()], vec![vec![55..56]], opts, true, 1);
    for _ in 0..10000 {
        match poll(&mut s) {
            Poll::Pending => wake(&mut s, &g),
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished {
                outcome: MemberOutcome::Stopped { failure, restart, inner_offset, .. },
                ..
            }))) => {
                assert!(matches!(failure.kind, FailureKind::DataHole));
                assert_eq!(restart, RestartAvailability::None);
                assert_eq!(inner_offset, 0);
                assert!(!dir.path().join("one").exists());
                return;
            }
            Poll::Ready(Err(e)) => panic!("{e:?}"),
            _ => {}
        }
    }
    panic!("no stopped outcome")
}
#[test]
fn independent_members_in_forward_volume_set_decode_without_history() {
    let dir = tempfile::tempdir().unwrap();
    let mut parts = Vec::new();
    for (i, name) in [b"one".as_slice(), b"two".as_slice()].iter().enumerate() {
        let mut data = b"Rar!\x1a\x07\0".to_vec();
        data.extend(block(0x73, 0x11 | if i == 0 { 0x100 } else { 0 }, &[0; 6]));
        data.extend(member(name, include_bytes!("fixtures/rar4-lz/literal-a.packed"), b"A", 29, 0x31, 0));
        data.extend(block(0x7b, 0x4000 | if i == 0 { 1 } else { 0 }, &[]));
        parts.push(data);
    }
    let mut opts = options(dir.path());
    opts.first_name = "a.part1.rar".into();
    let (mut s, g) = custom(parts, vec![vec![], vec![]], opts, true, 7);
    let a = drive(&mut s, Some(&g)).unwrap();
    assert_eq!(a.len(), 2);
}

fn official_gold() -> Vec<u8> {
    let mut gold = b"RAR4 bounded LZ control.\n".repeat(8000);
    gold.extend((0u8..=255).cycle().take(256 * 400));
    gold
}
#[test]
fn official_lz_methods_wrap_dictionary_and_publish_known_gold() {
    let gold = official_gold();
    for (index, packed) in [
        include_bytes!("fixtures/rar4-lz/official-lz-m1.packed").as_slice(),
        include_bytes!("fixtures/rar4-lz/official-lz-m2.packed"),
        include_bytes!("fixtures/rar4-lz/official-lz-m3.packed"),
        include_bytes!("fixtures/rar4-lz/official-lz-m4.packed"),
        include_bytes!("fixtures/rar4-lz/official-lz-m5.packed"),
    ]
    .iter()
    .enumerate()
    {
        let dir = tempfile::tempdir().unwrap();
        let data = archive(&[member(b"one", packed, &gold, 29, 0x31 + index as u8, 0)]);
        let mut opts = options(dir.path());
        opts.limits.read_chunk = 17;
        let mut s =
            ProgressiveSession::from_sealed_memory(vec![("a.rar".into(), data.into_boxed_slice())], opts).unwrap();
        drive(&mut s, None).unwrap();
        assert_eq!(std::fs::read(dir.path().join("one")).unwrap(), gold);
    }
}
#[test]
fn compressed_hole_keeps_actual_prefix_but_cannot_restart() {
    let packed = include_bytes!("fixtures/rar4-lz/official-lz-m3.packed");
    let gold = official_gold();
    let dir = tempfile::tempdir().unwrap();
    let data = archive(&[member(b"one", packed, &gold, 29, 0x33, 0)]);
    let mut opts = options(dir.path());
    opts.artifact_aftermath = ArtifactAftermath::RetainProvisional;
    opts.hole_policy = HolePolicy::PartialStored { fill: HoleFill::Zero };
    let hole = (55 + packed.len() - 2) as u64;
    let (mut s, g) = custom(vec![data], vec![vec![hole..hole + 1]], opts, true, 17);
    for _ in 0..100000 {
        match poll(&mut s) {
            Poll::Pending => wake(&mut s, &g),
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished {
                outcome: MemberOutcome::Stopped { failure, restart, inner_offset, artifact },
                ..
            }))) => {
                assert!(matches!(failure.kind, FailureKind::DataHole));
                assert_eq!(restart, RestartAvailability::None);
                assert!(inner_offset > 0);
                assert!(inner_offset <= gold.len() as u64);
                let mut a = artifact.expect("retained actual output");
                let mut read = vec![0; inner_offset as usize];
                let mut at = 0;
                while at < read.len() {
                    let ArtifactRead::Filled { count } = a.read_at(at as u64, &mut read[at..]).unwrap() else {
                        panic!("invalid prefix")
                    };
                    at += count;
                }
                assert_eq!(read, gold[..inner_offset as usize]);
                assert!(!dir.path().join("one").exists());
                return;
            }
            Poll::Ready(Err(e)) => panic!("{e:?}"),
            _ => {}
        }
    }
    panic!("no stopped outcome")
}
#[test]
fn encrypted_headers_remain_an_explicit_refusal_and_a_solid_archive_decodes() {
    for encrypted in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let mut opts = options(dir.path());
        let packed = include_bytes!("fixtures/rar4-lz/literal-a.packed");
        let mut f = member(b"one", packed, b"A", 29, 0x33, 0);
        let end = block(0x7b, 0x4000, &[]);
        let mut data = b"Rar!\x1a\x07\0".to_vec();
        data.extend(block(0x73, if encrypted { 0x80 } else { 8 }, &[0; 6]));
        if encrypted {
            opts.set_password(Some("pw".to_owned())).unwrap();
            let salt = [1, 2, 3, 4, 5, 6, 7, 8];
            let (key, iv) = zipfast::crypto::derive_rar4_key_iv("pw", &salt);
            let payload = f.split_off(55 - 20);
            for (header, after) in [(f, payload), (end, vec![])] {
                let mut h = header;
                h.resize(h.len().next_multiple_of(16), 0x5a);
                data.extend(salt);
                data.extend(zipfast::crypto::encrypt_cbc(&key, &iv, &h).unwrap());
                data.extend(after);
            }
        } else {
            data.extend(f);
            data.extend(end);
        }
        let mut s =
            ProgressiveSession::from_sealed_memory(vec![("a.rar".into(), data.into_boxed_slice())], opts).unwrap();
        if !encrypted {
            // a solid archive's first member starts the stream
            drive(&mut s, None).unwrap();
            assert_eq!(std::fs::read(dir.path().join("one")).unwrap(), b"A");
            continue;
        }
        let e = drive(&mut s, None).err().expect("unsupported");
        assert!(
            matches!(e.kind,FailureKind::Rar(ref f) if matches!(f.as_ref(),zipfast::error::RarFailure::Unsupported(_))),
            "{e:?}"
        );
        assert!(!dir.path().join("one").exists());
    }
}
