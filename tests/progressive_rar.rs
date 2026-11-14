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

//! Public adapter parity for the shared progressive framing and physical model.
mod common;
use common::{FileSpec, archive, volumes};
use zipfast::rar5::{
    reader::{Block, Volume},
    session::{RarSession, RarSessionOptions},
};

#[test]
fn file_volume_and_catalogue_keep_public_names_offsets_and_checks() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("a.rar");
    let payload = b"shared physical framing";
    let bytes = archive(&[FileSpec::new("unicode-Ω", payload)]);
    std::fs::write(&path, &bytes).unwrap();
    let mut volume = Volume::open(&path).unwrap();
    assert_eq!(volume.file().metadata().unwrap().len(), bytes.len() as u64);
    let Some(Block::File(header)) = volume.next_block().unwrap() else { panic!("file") };
    let session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    let member = session.entries().next().unwrap();
    let part = member.parts().next().unwrap();
    assert_eq!(member.raw_name(), "unicode-Ω".as_bytes());
    assert_eq!(member.name(), header.name);
    assert_eq!(part.data_offset(), header.data_at);
    assert_eq!(part.packed_size(), header.packed_size);
    assert_eq!(part.checks().crc32, header.crc32);
}

#[test]
fn physical_model_keeps_one_name_and_part_order_across_volumes() {
    let temp = tempfile::tempdir().unwrap();
    let data = b"a logical member across physical volumes";
    let pieces = volumes(&FileSpec::new("one", data), 9);
    for (i, bytes) in pieces.iter().enumerate() {
        std::fs::write(temp.path().join(format!("a.part{:02}.rar", i + 1)), bytes).unwrap();
    }
    let session = RarSession::open(&temp.path().join("a.part01.rar"), None, RarSessionOptions::default()).unwrap();
    let members = session.entries().collect::<Vec<_>>();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].raw_name(), b"one");
    assert!(members[0].is_complete());
    assert_eq!(members[0].parts().map(|p| p.volume()).collect::<Vec<_>>(), (0..pieces.len()).collect::<Vec<_>>());
    assert_eq!(members[0].packed_size(), data.len() as u64);
}

use std::{
    ffi::OsString,
    fs::File,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};
use zipfast::progressive::*;

#[derive(Default)]
struct Availability {
    wake: Option<Waker>,
    allow: bool,
    calls: usize,
}
struct Bytes {
    data: Vec<u8>,
    id: u128,
    gate: Arc<Mutex<Availability>>,
    waits: bool,
    chunk: usize,
}
impl RangeSource for Bytes {
    fn info(&self) -> SourceInfo {
        SourceInfo {
            id: SourceId(self.id),
            generation: 0,
            extent: self.data.len() as u64,
            length: SourceLength::Final(self.data.len() as u64),
        }
    }
    fn backing_files(&self) -> &[File] {
        &[]
    }
    fn read_at(&mut self, at: u64, buf: &mut [u8], cx: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
        let mut gate = self.gate.lock().unwrap();
        gate.calls += 1;
        if self.waits && !gate.allow {
            gate.wake = Some(cx.waker().clone());
            return Ok(RangeRead::NotYet);
        }
        gate.allow = false;
        let n = buf.len().min(self.chunk).min(self.data.len() - at as usize);
        buf[..n].copy_from_slice(&self.data[at as usize..at as usize + n]);
        Ok(RangeRead::Filled { count: n })
    }
}
struct Provider {
    data: Vec<Option<Vec<u8>>>,
    gate: Arc<Mutex<Availability>>,
    volume_waits: bool,
    read_waits: bool,
    chunk: usize,
}
impl VolumeSource for Provider {
    fn volume(&mut self, r: &VolumeRequest, cx: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
        let mut gate = self.gate.lock().unwrap();
        gate.calls += 1;
        if self.volume_waits && !gate.allow {
            gate.wake = Some(cx.waker().clone());
            return Ok(VolumeAnswer::Wait);
        }
        gate.allow = false;
        Ok(match self.data.get_mut(r.index as usize).and_then(Option::take) {
            Some(data) => VolumeAnswer::Ready(Box::new(Bytes {
                data,
                id: u128::from(r.index) + 1,
                gate: self.gate.clone(),
                waits: self.read_waits,
                chunk: self.chunk,
            })),
            None => VolumeAnswer::Missing,
        })
    }
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
        },
        OsString::from("a.part01.rar"),
    )
}
fn session(
    data: Vec<Vec<u8>>,
    options: ProgressiveOptions,
    volume_waits: bool,
    read_waits: bool,
    chunk: usize,
) -> (ProgressiveSession, Arc<Mutex<Availability>>) {
    let gate = Arc::new(Mutex::new(Availability::default()));
    let provider =
        Provider { data: data.into_iter().map(Some).collect(), gate: gate.clone(), volume_waits, read_waits, chunk };
    (ProgressiveSession::new(Box::new(provider), options).unwrap(), gate)
}
fn poll(s: &mut ProgressiveSession) -> Poll<ProgressiveResult<Option<ProgressiveEvent>>> {
    s.poll_event(&mut Context::from_waker(Waker::noop()))
}
fn resume(gate: &Arc<Mutex<Availability>>) {
    let w = {
        let mut g = gate.lock().unwrap();
        g.allow = true;
        g.wake.take().unwrap()
    };
    w.wake();
}
fn read_all(a: &mut Artifact) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0; 1024];
    loop {
        match a.read_at(out.len() as u64, &mut buf).unwrap() {
            ArtifactRead::Filled { count } => out.extend_from_slice(&buf[..count]),
            ArtifactRead::End => break,
            _ => panic!("unexpected hole"),
        }
    }
    out
}
fn collect(s: &mut ProgressiveSession, gate: &Arc<Mutex<Availability>>) -> (Vec<Artifact>, Vec<u32>, usize) {
    let mut artifacts = Vec::new();
    let mut opened = Vec::new();
    let mut starts = 0;
    for _ in 0..2_000_000 {
        match poll(s) {
            Poll::Pending => {
                let calls = gate.lock().unwrap().calls;
                assert!(poll(s).is_pending());
                assert_eq!(gate.lock().unwrap().calls, calls);
                resume(gate);
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::VolumeOpened { index, .. }))) => opened.push(index),
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberStarted { .. }))) => starts += 1,
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished {
                outcome: MemberOutcome::Provisional(a), ..
            }))) => artifacts.push(a),
            Poll::Ready(Ok(Some(ProgressiveEvent::BytesWritten { .. }))) => {}
            Poll::Ready(Ok(None)) => return (artifacts, opened, starts),
            Poll::Ready(Err(e)) => panic!("{e:?}"),
            _ => panic!("unexpected event"),
        }
    }
    panic!("event bound")
}
#[test]
fn wait_between_all_rar5_volumes() {
    let tmp = tempfile::tempdir().unwrap();
    let data = b"one member over many volume boundaries";
    let (mut s, g) = session(volumes(&FileSpec::new("one", data), 7), options(tmp.path()), true, false, 3);
    let (mut artifacts, opened, starts) = collect(&mut s, &g);
    assert_eq!(starts, 1);
    assert_eq!(opened, (0..opened.len() as u32).collect::<Vec<_>>());
    assert_eq!(artifacts.len(), 1);
    assert_eq!(read_all(&mut artifacts[0]), data);
    assert!(matches!(artifacts[0].evidence(), ArtifactEvidence::Verified(_)));
}
#[test]
fn wait_inside_header_and_member() {
    let tmp = tempfile::tempdir().unwrap();
    let data = b"each byte parks once";
    let (mut s, g) = session(vec![archive(&[FileSpec::new("one", data)])], options(tmp.path()), true, true, 1);
    let (mut artifacts, opened, starts) = collect(&mut s, &g);
    assert_eq!(opened, vec![0]);
    assert_eq!(starts, 1);
    assert_eq!(read_all(&mut artifacts[0]), data);
}
#[test]
fn missing_and_abort_first_volume() {
    struct Answer(bool);
    impl VolumeSource for Answer {
        fn volume(&mut self, _: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
            Ok(if self.0 { VolumeAnswer::Missing } else { VolumeAnswer::Abort })
        }
    }
    let tmp = tempfile::tempdir().unwrap();
    for missing in [true, false] {
        let mut s = ProgressiveSession::new(Box::new(Answer(missing)), options(tmp.path())).unwrap();
        let Poll::Ready(Err(e)) = poll(&mut s) else { panic!("pre-stage error") };
        assert_eq!(e.context.volume_index, Some(0));
        assert_eq!(e.context.packed_offset, Some(0));
        assert!(matches!((missing, e.kind), (true, FailureKind::MissingVolume) | (false, FailureKind::Canceled)));
        assert!(matches!(poll(&mut s), Poll::Ready(Ok(None))));
    }
}
#[test]
fn verified_opaque_artifact_public_read() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut s, g) =
        session(vec![archive(&[FileSpec::new("one", b"afterlife")])], options(tmp.path()), false, false, 100);
    let (mut a, _, _) = collect(&mut s, &g);
    drop(s);
    assert!(!tmp.path().join("one").exists());
    assert_eq!(read_all(&mut a[0]), b"afterlife");
    a[0].discard().unwrap();
    assert!(a[0].read_at(0, &mut [0; 1]).is_err());
    assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
}
#[test]
fn events_are_exactly_once() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut s, g) = session(
        vec![archive(&[FileSpec::new("one", b"first"), FileSpec::new("two", b"second")])],
        options(tmp.path()),
        false,
        false,
        2,
    );
    let (a, v, n) = collect(&mut s, &g);
    assert_eq!((a.len(), v.len(), n), (2, 1, 2));
    for _ in 0..5 {
        assert!(matches!(poll(&mut s), Poll::Ready(Ok(None))));
    }
}
#[test]
fn canceled_artifact_public_read() {
    let tmp = tempfile::tempdir().unwrap();
    let mut o = options(tmp.path());
    o.artifact_aftermath = ArtifactAftermath::RetainProvisional;
    let (mut s, _) = session(vec![archive(&[FileSpec::new("one", b"cancel this member")])], o, false, false, 2);
    loop {
        if matches!(poll(&mut s), Poll::Ready(Ok(Some(ProgressiveEvent::BytesWritten { .. })))) {
            break;
        }
    }
    s.control().cancel();
    let Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated {
        failure,
        artifact: Some(mut a),
        cleanup_failure: None,
    }))) = poll(&mut s)
    else {
        panic!("terminal artifact")
    };
    assert!(matches!(failure.kind, FailureKind::Canceled));
    assert_eq!(read_all(&mut a), b"ca");
    assert!(matches!(poll(&mut s), Poll::Ready(Ok(None))));
    drop(s);
    assert_eq!(read_all(&mut a), b"ca");
    a.discard().unwrap();
}
#[test]
fn terminal_after_member_event() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut s, g) = session(vec![archive(&[FileSpec::new("one", b"one")])], options(tmp.path()), false, false, 100);
    let (a, _, _) = collect(&mut s, &g);
    s.control().cancel();
    assert!(matches!(poll(&mut s), Poll::Ready(Ok(None))));
    assert_eq!(a.len(), 1);
}

#[test]
#[ignore = "requires six private RAR5 fixtures and pinned complete/UnRAR gold"]
fn real_encrypted_wait_and_notyet_match_both_golds() {
    let fixtures = std::path::PathBuf::from(std::env::var_os("ZIPFAST_PRIVATE_RAR5_DIR").expect("fixtures"));
    let gold = std::path::PathBuf::from(std::env::var_os("ZIPFAST_PRIVATE_RAR5_GOLD").expect("gold"));
    for set in ["encnam", "encdata"] {
        let data = (1..=3)
            .map(|i| std::fs::read(fixtures.join(format!("testfile5{set}.part{i:02}.rar"))).unwrap())
            .collect::<Vec<_>>();
        let expected = std::fs::read(gold.join(format!("{set}-unrar/testfile5{set}.dat"))).unwrap();
        assert_eq!(expected, std::fs::read(gold.join(format!("{set}-zipfast/testfile5{set}.dat"))).unwrap());
        assert_eq!(expected.len(), 68161);
        for chunk in [1, 7, 16, 4096] {
            let tmp = tempfile::tempdir().unwrap();
            let mut o = options(tmp.path());
            o.first_name = format!("testfile5{set}.part01.rar").into();
            o.set_password(Some("123".into())).unwrap();
            let (mut s, g) = session(data.clone(), o, true, true, chunk);
            let (mut a, opened, starts) = collect(&mut s, &g);
            assert_eq!(opened, vec![0, 1, 2]);
            assert_eq!(starts, 1);
            assert_eq!(a.len(), 1);
            assert_eq!(read_all(&mut a[0]), expected);
            let ArtifactEvidence::Verified(v) = a[0].evidence() else { panic!("verified evidence") };
            assert_eq!(v.level(), VerificationLevel::Strict);
            assert_eq!(v.authentication(), AuthenticationEvidence::CbcChecksOnly);
            assert_eq!(v.packed(), PackedEvidence::Passed);
            assert_eq!(v.size_verdict(), CheckVerdict::Passed);
        }
    }
}
#[test]
fn capacity_release_precedes_more_input_in_long_session() {
    let tmp = tempfile::tempdir().unwrap();
    let specs = (0..35).map(|_| FileSpec::new("repeated", b"one")).collect::<Vec<_>>();
    let (mut s, g) = session(vec![archive(&specs)], options(tmp.path()), false, false, 1024);
    let mut retained = Vec::new();
    let mut finished = 0;
    let mut capacity = 0;
    loop {
        match poll(&mut s) {
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished {
                outcome: MemberOutcome::Provisional(a), ..
            }))) => {
                retained.push(a);
                finished += 1;
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::CapacityNeeded { retained: n }))) => {
                assert_eq!(n, 16);
                capacity += 1;
                let calls = g.lock().unwrap().calls;
                for _ in 0..3 {
                    assert!(poll(&mut s).is_pending());
                }
                assert_eq!(g.lock().unwrap().calls, calls);
                retained.remove(0).discard().unwrap();
            }
            Poll::Ready(Ok(None)) => break,
            Poll::Ready(Ok(Some(_))) => {}
            _ => panic!("unexpected capacity poll"),
        }
    }
    assert_eq!(finished, 35);
    assert_eq!(capacity, 19);
    drop(s);
    drop(retained);
    assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
}
#[test]
fn cancel_each_transition() {
    // Discover every observable transition, including all later volumes and
    // member finalization, rather than assuming a fixed early-poll count.
    let trace_dir = tempfile::tempdir().unwrap();
    let input = volumes(&FileSpec::new("one", b"many boundaries"), 4);
    let (mut trace, gate) = session(input.clone(), options(trace_dir.path()), true, true, 2);
    let mut transitions = 0;
    loop {
        match poll(&mut trace) {
            Poll::Pending => {
                resume(&gate);
                transitions += 1;
            }
            Poll::Ready(Ok(Some(_))) => transitions += 1,
            Poll::Ready(Ok(None)) => break,
            _ => panic!("baseline transition trace"),
        }
    }
    assert!(transitions > 30);
    for threshold in 0..=transitions {
        for aftermath in [ArtifactAftermath::Remove, ArtifactAftermath::RetainProvisional] {
            let tmp = tempfile::tempdir().unwrap();
            let mut o = options(tmp.path());
            o.artifact_aftermath = aftermath;
            let (mut s, g) = session(input.clone(), o, true, true, 2);
            let mut ever_staged = false;
            let mut active = false;
            for _ in 0..threshold {
                match poll(&mut s) {
                    Poll::Pending => resume(&g),
                    Poll::Ready(Ok(Some(ProgressiveEvent::MemberStarted { .. }))) => {
                        ever_staged = true;
                        active = true;
                    }
                    Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { .. }))) => active = false,
                    Poll::Ready(Ok(Some(_))) => {}
                    _ => panic!("transition {threshold}"),
                }
            }
            s.control().cancel();
            match poll(&mut s) {
                Poll::Ready(Err(e)) if !ever_staged => assert!(matches!(e.kind, FailureKind::Canceled)),
                Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated {
                    failure,
                    artifact,
                    cleanup_failure: None,
                }))) if ever_staged => {
                    assert!(matches!(failure.kind, FailureKind::Canceled));
                    assert_eq!(artifact.is_some(), active && aftermath == ArtifactAftermath::RetainProvisional);
                    drop(artifact);
                }
                _ => panic!("cancel result at transition {threshold}"),
            }
            for _ in 0..3 {
                assert!(matches!(poll(&mut s), Poll::Ready(Ok(None))));
            }
            drop(s);
            assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
        }
    }
}

#[test]
fn sealed_memory_publishes_but_no_checksum_stays_provisional() {
    let tmp = tempfile::tempdir().unwrap();
    let mut absent = FileSpec::new("unchecked", b"unchecked");
    absent.no_crc = true;
    let mut s = ProgressiveSession::from_sealed_memory(
        vec![("a.part01.rar".into(), archive(&[FileSpec::new("one", b"verified"), absent]).into_boxed_slice())],
        options(tmp.path()),
    )
    .unwrap();
    let mut verified = 0;
    let mut provisional = 0;
    loop {
        match poll(&mut s) {
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { outcome: MemberOutcome::Verified(v), .. }))) => {
                assert_eq!(v.level(), VerificationLevel::Strict);
                verified += 1
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished {
                outcome: MemberOutcome::Provisional(a), ..
            }))) => {
                assert_eq!(a.evidence(), &ArtifactEvidence::Provisional);
                provisional += 1
            }
            Poll::Ready(Ok(None)) => break,
            Poll::Ready(Ok(Some(_))) => {}
            Poll::Ready(Err(e)) => panic!("{e:?}"),
            _ => panic!("sealed wait"),
        }
    }
    assert_eq!((verified, provisional), (1, 1));
    assert_eq!(std::fs::read(tmp.path().join("one")).unwrap(), b"verified");
    assert!(!tmp.path().join("unchecked").exists());
}
#[test]
fn sink_failure_retires_machine_and_retains_committed_prefix() {
    let tmp = tempfile::tempdir().unwrap();
    let mut o = options(tmp.path());
    o.artifact_aftermath = ArtifactAftermath::RetainProvisional;
    o.limits.output_write_bytes = 4;
    let (mut s, _) = session(vec![archive(&[FileSpec::new("one", b"more than budget")])], o, false, false, 2);
    loop {
        match poll(&mut s) {
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated {
                failure,
                artifact: Some(mut a),
                cleanup_failure: None,
            }))) => {
                assert!(matches!(failure.kind, FailureKind::Limit { resource: Resource::OutputWriteBytes, .. }));
                assert_eq!(read_all(&mut a), b"more");
                break;
            }
            Poll::Ready(Ok(Some(_))) => {}
            _ => panic!("sink terminal"),
        }
    }
    for _ in 0..3 {
        assert!(matches!(poll(&mut s), Poll::Ready(Ok(None))));
    }
}
#[test]
fn final_checksum_failure_retires_machine() {
    let tmp = tempfile::tempdir().unwrap();
    let mut o = options(tmp.path());
    o.artifact_aftermath = ArtifactAftermath::RetainProvisional;
    let data = common::archive_with(&[(FileSpec::new("one", b"wrong digest"), 0)], false);
    let (mut s, _) = session(vec![data], o, false, false, 1024);
    loop {
        match poll(&mut s) {
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { artifact: Some(mut a), .. }))) => {
                assert_eq!(read_all(&mut a), b"wrong digest");
                assert_eq!(a.evidence(), &ArtifactEvidence::Provisional);
                break;
            }
            Poll::Ready(Ok(Some(_))) => {}
            _ => panic!("checksum terminal"),
        }
    }
    for _ in 0..3 {
        assert!(matches!(poll(&mut s), Poll::Ready(Ok(None))));
    }
}

struct NativeSet {
    paths: Vec<std::path::PathBuf>,
    handles: Vec<Arc<File>>,
}
impl NativeSet {
    fn new(paths: Vec<std::path::PathBuf>) -> Self {
        let handles = paths.iter().map(|p| Arc::new(File::open(p).unwrap())).collect();
        Self { paths, handles }
    }
}
impl VolumeSource for NativeSet {
    fn volume(&mut self, r: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
        Ok(match self.paths.get(r.index as usize) {
            Some(p) => VolumeAnswer::Ready(Box::new(ImmutableFileSource::open(p)?)),
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
fn early_member_cannot_replace_unopened_volume() {
    let tmp = tempfile::tempdir().unwrap();
    let first = tmp.path().join("a.part01.rar");
    let second = tmp.path().join("a.part02.rar");
    let spec = FileSpec::new("a.part02.rar", b"would replace input");
    let mut bytes = common::SIG.to_vec();
    bytes.extend(common::main_block(true, None));
    bytes.extend(common::file_block(&spec, spec.data, crc32fast::hash(spec.data), false, false));
    bytes.extend(common::end_block(true));
    let mut last = common::SIG.to_vec();
    last.extend(common::main_block(true, Some(1)));
    last.extend(common::end_block(false));
    std::fs::write(&first, &bytes).unwrap();
    std::fs::write(&second, &last).unwrap();
    let mut s =
        ProgressiveSession::new(Box::new(NativeSet::new(vec![first.clone(), second.clone()])), options(tmp.path()))
            .unwrap();
    loop {
        match poll(&mut s) {
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) => {
                assert!(matches!(failure.kind, FailureKind::UnsafePath), "{failure:?}");
                break;
            }
            Poll::Ready(Ok(Some(_))) => {}
            _ => panic!("alias should terminate"),
        }
    }
    assert_eq!(std::fs::read(first).unwrap(), bytes);
    assert_eq!(std::fs::read(second).unwrap(), last);
}
#[test]
fn stopped_prefix_public_read() {
    struct HoleBytes {
        bytes: Vec<u8>,
        hole: u64,
    }
    impl RangeSource for HoleBytes {
        fn info(&self) -> SourceInfo {
            SourceInfo {
                id: SourceId(1),
                generation: 0,
                extent: self.bytes.len() as u64,
                length: SourceLength::Final(self.bytes.len() as u64),
            }
        }
        fn backing_files(&self) -> &[File] {
            &[]
        }
        fn read_at(&mut self, at: u64, buf: &mut [u8], _: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
            if at == self.hole {
                return Ok(RangeRead::Hole { len: 1 });
            }
            let count = buf.len().min(2).min(self.bytes.len() - at as usize).min(if at < self.hole {
                (self.hole - at) as usize
            } else {
                usize::MAX
            });
            buf[..count].copy_from_slice(&self.bytes[at as usize..at as usize + count]);
            Ok(RangeRead::Filled { count })
        }
    }
    struct HoleProvider(Option<HoleBytes>);
    impl VolumeSource for HoleProvider {
        fn volume(&mut self, _: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
            Ok(VolumeAnswer::Ready(Box::new(self.0.take().unwrap())))
        }
    }
    let tmp = tempfile::tempdir().unwrap();
    let bytes = archive(&[FileSpec::new("one", b"prefix suffix"), FileSpec::new("two", b"independent")]);
    let hole = bytes.windows(13).position(|w| w == b"prefix suffix").unwrap() as u64 + 6;
    let mut o = options(tmp.path());
    o.artifact_aftermath = ArtifactAftermath::RetainProvisional;
    let mut s = ProgressiveSession::new(Box::new(HoleProvider(Some(HoleBytes { bytes, hole }))), o).unwrap();
    let mut stopped = None;
    let mut finished = 0;
    loop {
        match poll(&mut s) {
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished {
                outcome: MemberOutcome::Stopped { inner_offset, artifact: Some(a), failure, .. },
                ..
            }))) => {
                assert_eq!(inner_offset, 6);
                assert!(matches!(failure.kind, FailureKind::DataHole));
                stopped = Some(a)
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished {
                outcome: MemberOutcome::Provisional(mut a),
                ..
            }))) => {
                assert_eq!(read_all(&mut a), b"independent");
                finished += 1
            }
            Poll::Ready(Ok(None)) => break,
            Poll::Ready(Ok(Some(_))) => {}
            Poll::Ready(Err(e)) => panic!("{e:?}"),
            _ => panic!("stop result"),
        }
    }
    drop(s);
    assert_eq!(finished, 1);
    assert_eq!(read_all(&mut stopped.unwrap()), b"prefix");
}
#[test]
fn cancel_after_member_event_reports_terminal_without_losing_artifact() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut s, _) = session(
        vec![archive(&[FileSpec::new("one", b"kept"), FileSpec::new("two", b"later")])],
        options(tmp.path()),
        false,
        false,
        100,
    );
    let mut a = loop {
        if let Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished {
            outcome: MemberOutcome::Provisional(a), ..
        }))) = poll(&mut s)
        {
            break a;
        }
    };
    s.control().cancel();
    assert!(matches!(poll(&mut s), Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { artifact: None, .. })))));
    assert!(matches!(poll(&mut s), Poll::Ready(Ok(None))));
    assert_eq!(read_all(&mut a), b"kept");
}
#[test]
fn bytes_events_include_decoder_finish_output() {
    let tmp = tempfile::tempdir().unwrap();
    let ops = [zipfast::rar5::testenc::Op::Lit(b'x'), zipfast::rar5::testenc::Op::Lit(b'y')];
    let (packed, expected) = common::packed("one", &ops);
    let mut f = FileSpec::new("one", &packed);
    f.method = 1;
    f.size = Some(expected.len() as u64);
    let (mut s, _) = session(
        vec![common::archive_with(&[(f, crc32fast::hash(&expected))], false)],
        options(tmp.path()),
        false,
        false,
        1024,
    );
    let mut written = 0;
    loop {
        match poll(&mut s) {
            Poll::Ready(Ok(Some(ProgressiveEvent::BytesWritten { valid_bytes, .. }))) => written += valid_bytes,
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished {
                outcome: MemberOutcome::Provisional(mut a),
                ..
            }))) => {
                assert_eq!(read_all(&mut a), expected)
            }
            Poll::Ready(Ok(None)) => break,
            Poll::Ready(Ok(Some(_))) => {}
            Poll::Ready(Err(e)) => panic!("{e:?}"),
            _ => panic!("compressed"),
        }
    }
    assert_eq!(written, expected.len() as u64);
}

#[test]
fn test_mode_rejected_before_provider_or_output_effects() {
    let tmp = tempfile::tempdir().unwrap();
    let mut o = options(&tmp.path().join("not-created"));
    o.extract.mode = zipfast::extract::Mode::Test;
    struct NoCallbacks;
    impl VolumeSource for NoCallbacks {
        fn volume(&mut self, _: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
            panic!("provider not allowed")
        }
    }
    let Err(e) = ProgressiveSession::new(Box::new(NoCallbacks), o) else { panic!("test mode unsupported") };
    assert!(matches!(e.kind, FailureKind::UnsupportedMethod));
    assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
}
#[test]
fn overwrite_skip_collision_preserves_target_bytes() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("one"), b"keep").unwrap();
    let mut o = options(tmp.path());
    o.extract.overwrite = zipfast::extract::Overwrite::Skip;
    let mut s = ProgressiveSession::from_sealed_memory(
        vec![("a.part01.rar".into(), archive(&[FileSpec::new("one", b"new")]).into_boxed_slice())],
        o,
    )
    .unwrap();
    loop {
        match poll(&mut s) {
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) => {
                assert!(
                    matches!(failure.kind,FailureKind::Output {cause,..} if cause.kind()==std::io::ErrorKind::AlreadyExists)
                );
                break;
            }
            Poll::Ready(Ok(Some(_))) => {}
            _ => panic!("collision"),
        }
    }
    assert_eq!(std::fs::read(tmp.path().join("one")).unwrap(), b"keep");
}
#[test]
fn zero_capacity_is_a_limit_not_an_unwakeable_park() {
    let tmp = tempfile::tempdir().unwrap();
    let mut o = options(tmp.path());
    o.limits.retained_artifacts = 0;
    let provider = Provider { data: vec![], gate: Arc::default(), volume_waits: false, read_waits: false, chunk: 1 };
    let Err(e) = ProgressiveSession::new(Box::new(provider), o) else { panic!("capacity limit") };
    assert!(matches!(e.kind, FailureKind::Limit { resource: Resource::RetainedArtifacts, limit: 0, attempted: 1 }));
}
struct NativeWait {
    inner: NativeSet,
    gate: Arc<Mutex<Availability>>,
}
impl VolumeSource for NativeWait {
    fn volume(&mut self, r: &VolumeRequest, cx: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
        if r.index > 0 {
            let mut gate = self.gate.lock().unwrap();
            gate.calls += 1;
            if !gate.allow {
                gate.wake = Some(cx.waker().clone());
                return Ok(VolumeAnswer::Wait);
            }
            gate.allow = false;
        }
        self.inner.volume(r, cx)
    }
    fn protection(&mut self) -> ProgressiveResult<ProtectionDeclaration> {
        self.inner.protection()
    }
}
#[test]
fn input_and_output_replacement_while_parked_preserves_every_file() {
    for replace_input in [true, false] {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("one");
        let pieces = volumes(&FileSpec::new("one", b"original bytes"), 7);
        let paths = pieces
            .iter()
            .enumerate()
            .map(|(i, bytes)| {
                let path = tmp.path().join(format!("a.part{:02}.rar", i + 1));
                std::fs::write(&path, bytes).unwrap();
                path
            })
            .collect::<Vec<_>>();
        let input = paths[0].clone();
        std::fs::write(&target, b"old output").unwrap();
        let gate = Arc::new(Mutex::new(Availability::default()));
        let mut s = ProgressiveSession::new(
            Box::new(NativeWait { inner: NativeSet::new(paths), gate: gate.clone() }),
            options(tmp.path()),
        )
        .unwrap();
        loop {
            match poll(&mut s) {
                Poll::Pending => break,
                Poll::Ready(Ok(Some(_))) => {}
                _ => panic!("must park on second volume"),
            }
        }
        assert!(poll(&mut s).is_pending());
        let replaced = if replace_input { &input } else { &target };
        let backup = tmp.path().join("original");
        std::fs::rename(replaced, &backup).unwrap();
        std::fs::write(replaced, b"replacement").unwrap();
        resume(&gate);
        loop {
            match poll(&mut s) {
                Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { .. }))) => break,
                Poll::Ready(Ok(Some(_))) => {}
                Poll::Pending => resume(&gate),
                _ => panic!("replacement terminal"),
            }
        }
        assert_eq!(std::fs::read(replaced).unwrap(), b"replacement");
        assert_eq!(std::fs::read(backup).unwrap(), if replace_input { pieces[0].as_slice() } else { b"old output" });
    }
}
#[test]
fn work_yield_has_one_self_wake_and_no_provider_retry_gate() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Wake;
    struct Counter(AtomicUsize);
    impl Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let tmp = tempfile::tempdir().unwrap();
    let mut bytes = vec![0; 1 << 20];
    bytes.extend(archive(&[FileSpec::new("one", b"after sfx")]));
    let mut o = options(tmp.path());
    o.limits.source_requests = 16_000_000;
    let (mut s, _) = session(vec![bytes], o, false, false, 1 << 20);
    let counter = Arc::new(Counter(AtomicUsize::new(0)));
    let w = Waker::from(counter.clone());
    let mut cx = Context::from_waker(&w);
    assert!(matches!(s.poll_event(&mut cx), Poll::Ready(Ok(Some(ProgressiveEvent::VolumeOpened { .. })))));
    assert!(s.poll_event(&mut cx).is_pending());
    assert_eq!(counter.0.load(Ordering::SeqCst), 1);
    assert!(matches!(s.poll_event(&mut cx), Poll::Ready(Ok(Some(ProgressiveEvent::MemberStarted { .. })))));
}
#[test]
fn missing_later_volume_moves_prefix_into_terminal_event() {
    let tmp = tempfile::tempdir().unwrap();
    let mut o = options(tmp.path());
    o.artifact_aftermath = ArtifactAftermath::RetainProvisional;
    let mut pieces = volumes(&FileSpec::new("one", b"missing continuation"), 7);
    pieces.truncate(1);
    let (mut s, _) = session(pieces, o, false, false, 2);
    loop {
        match poll(&mut s) {
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated {
                failure,
                artifact: Some(mut a),
                cleanup_failure: None,
            }))) => {
                assert!(matches!(failure.kind, FailureKind::MissingVolume));
                assert_eq!(failure.context.volume_index, Some(1));
                assert_eq!(failure.context.packed_offset, Some(0));
                assert_eq!(read_all(&mut a), b"missing");
                break;
            }
            Poll::Ready(Ok(Some(_))) => {}
            _ => panic!("missing continuation"),
        }
    }
    assert!(matches!(poll(&mut s), Poll::Ready(Ok(None))));
}
#[test]
fn cancellation_cleanup_failure_keeps_artifact_and_rebound_name() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut s, _) = session(vec![archive(&[FileSpec::new("one", b"bytes")])], options(tmp.path()), false, false, 2);
    loop {
        if matches!(poll(&mut s), Poll::Ready(Ok(Some(ProgressiveEvent::BytesWritten { .. })))) {
            break;
        }
    }
    let stage = std::fs::read_dir(tmp.path()).unwrap().next().unwrap().unwrap().path();
    std::fs::rename(&stage, tmp.path().join("held-stage")).unwrap();
    std::fs::write(&stage, b"unrelated replacement").unwrap();
    s.control().cancel();
    let Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated {
        failure,
        artifact: Some(a),
        cleanup_failure: Some(cleanup),
    }))) = poll(&mut s)
    else {
        panic!("retained cleanup failure")
    };
    assert!(matches!(failure.kind, FailureKind::Canceled));
    assert!(matches!(cleanup.kind, FailureKind::Output { operation: OutputOperation::Remove, .. }));
    drop(a);
    drop(s);
    assert_eq!(std::fs::read(stage).unwrap(), b"unrelated replacement");
}
#[test]
fn sealed_memory_admission_is_bounded_before_output_creation() {
    let tmp = tempfile::tempdir().unwrap();
    let mut o = options(&tmp.path().join("not-created"));
    o.limits.metadata_bytes = 8;
    let Err(e) =
        ProgressiveSession::from_sealed_memory(vec![("a.part01.rar".into(), vec![0; 1024].into_boxed_slice())], o)
    else {
        panic!("memory budget")
    };
    assert!(matches!(e.kind, FailureKind::Limit { resource: Resource::MetadataBytes, .. }));
    assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
}
#[test]
fn custom_complete_nonfile_declaration_cannot_publish() {
    struct Claimed(Provider);
    impl VolumeSource for Claimed {
        fn volume(&mut self, r: &VolumeRequest, cx: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
            self.0.volume(r, cx)
        }
        fn protection(&mut self) -> ProgressiveResult<ProtectionDeclaration> {
            Ok(ProtectionDeclaration::Complete {
                epoch: 1,
                inventory: ProtectionInventory {
                    volumes: vec![ProtectedVolume {
                        index: 0,
                        name: "a.part01.rar".into(),
                        backing: VolumeBacking::NonFile,
                    }],
                    auxiliary_paths: vec![],
                },
            })
        }
    }
    let tmp = tempfile::tempdir().unwrap();
    let provider = Provider {
        data: vec![Some(archive(&[FileSpec::new("one", b"checked")]))],
        gate: Arc::default(),
        volume_waits: false,
        read_waits: false,
        chunk: 4096,
    };
    let mut s = ProgressiveSession::new(Box::new(Claimed(provider)), options(tmp.path())).unwrap();
    loop {
        match poll(&mut s) {
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished {
                outcome: MemberOutcome::Provisional(mut a),
                ..
            }))) => {
                assert_eq!(read_all(&mut a), b"checked");
                assert!(matches!(a.evidence(),ArtifactEvidence::Verified(v) if v.level()==VerificationLevel::Strict));
                break;
            }
            Poll::Ready(Ok(Some(_))) => {}
            _ => panic!("opaque proof"),
        }
    }
    assert!(!tmp.path().join("one").exists());
}
#[test]
fn member_event_shares_raw_name_owner_and_session_ids_are_unique() {
    let tmp = tempfile::tempdir().unwrap();
    let mut ids = Vec::new();
    for _ in 0..2 {
        let (mut s, _) =
            session(vec![archive(&[FileSpec::new("shared-name", b"bytes")])], options(tmp.path()), false, false, 100);
        loop {
            if let Poll::Ready(Ok(Some(ProgressiveEvent::MemberStarted { member, name, .. }))) = poll(&mut s) {
                assert_eq!(name.as_slice(), b"shared-name");
                assert_eq!(Arc::strong_count(&name), 2);
                ids.push(member);
                break;
            }
        }
    }
    assert_ne!(ids[0], ids[1]);
    assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
}
#[test]
fn wake_during_volume_return_resumes_once_through_public_session() {
    struct Racing {
        wake: bool,
        calls: Arc<Mutex<usize>>,
    }
    impl VolumeSource for Racing {
        fn volume(&mut self, _: &VolumeRequest, cx: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
            *self.calls.lock().unwrap() += 1;
            if !self.wake {
                self.wake = true;
                cx.waker().wake_by_ref();
                return Ok(VolumeAnswer::Wait);
            }
            Ok(VolumeAnswer::Ready(Box::new(Bytes {
                data: archive(&[]),
                id: 1,
                gate: Arc::default(),
                waits: false,
                chunk: 1024,
            })))
        }
    }
    let tmp = tempfile::tempdir().unwrap();
    let calls = Arc::new(Mutex::new(0));
    let mut s =
        ProgressiveSession::new(Box::new(Racing { wake: false, calls: calls.clone() }), options(tmp.path())).unwrap();
    assert!(poll(&mut s).is_pending());
    assert_eq!(*calls.lock().unwrap(), 1);
    assert!(matches!(poll(&mut s), Poll::Ready(Ok(Some(ProgressiveEvent::VolumeOpened { .. })))));
    assert_eq!(*calls.lock().unwrap(), 2);
    assert!(matches!(poll(&mut s), Poll::Ready(Ok(None))));
    assert_eq!(*calls.lock().unwrap(), 2);
}
#[test]
fn malformed_continuation_and_part_limits_do_not_publish() {
    let tmp = tempfile::tempdir().unwrap();
    for corrupt in [false, true] {
        let data = b"split bytes";
        let mut pieces = volumes(&FileSpec::new("one", data), 6);
        let mut o = options(tmp.path());
        o.artifact_aftermath = ArtifactAftermath::RetainProvisional;
        if corrupt {
            let second = &mut pieces[1];
            let bad = common::main_block(true, Some(9));
            let good = common::main_block(true, Some(1));
            second.splice(common::SIG.len()..common::SIG.len() + good.len(), bad);
        } else {
            o.limits.parts = 1;
        }
        let (mut s, _) = session(pieces, o, false, false, 100);
        loop {
            match poll(&mut s) {
                Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated {
                    failure, artifact: Some(mut a), ..
                }))) => {
                    assert!(matches!(
                        failure.kind,
                        FailureKind::Malformed(_) | FailureKind::Limit { resource: Resource::Parts, .. }
                    ));
                    assert_eq!(read_all(&mut a), &data[..6]);
                    break;
                }
                Poll::Ready(Ok(Some(_))) => {}
                _ => panic!("continuation failure"),
            }
        }
        assert!(!tmp.path().join("one").exists());
    }
}

#[test]
fn decoder_finish_sink_failure_is_terminal_and_never_retried() {
    let tmp = tempfile::tempdir().unwrap();
    let ops = [zipfast::rar5::testenc::Op::Lit(b'x'), zipfast::rar5::testenc::Op::Lit(b'y')];
    let (packed, expected) = common::packed("one", &ops);
    let mut spec = FileSpec::new("one", &packed);
    spec.method = 1;
    spec.size = Some(expected.len() as u64);
    let mut o = options(tmp.path());
    o.limits.output_write_bytes = 1;
    o.limits.read_chunk = 1;
    o.artifact_aftermath = ArtifactAftermath::RetainProvisional;
    let (mut s, _) =
        session(vec![common::archive_with(&[(spec, crc32fast::hash(&expected))], false)], o, false, false, 1);
    let mut artifact = loop {
        match poll(&mut s) {
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, artifact: Some(a), .. }))) => {
                assert!(matches!(failure.kind, FailureKind::Limit { resource: Resource::OutputWriteBytes, .. }));
                break a;
            }
            Poll::Ready(Ok(Some(_))) => {}
            _ => panic!("finalizer failure"),
        }
    };
    let mut byte = [0];
    assert_eq!(artifact.read_at(0, &mut byte).unwrap(), ArtifactRead::Filled { count: 1 });
    assert_eq!(byte, [b'x']);
    for _ in 0..3 {
        assert!(matches!(poll(&mut s), Poll::Ready(Ok(None))));
        assert_eq!(artifact.produced_extent(), 1);
    }
}

#[test]
fn invalid_continuation_crypt_metadata_is_not_ignored() {
    let tmp = tempfile::tempdir().unwrap();
    let salt = [3; 16];
    let iv = [9; 16];
    let (key, _) = zipfast::crypto::derive_rar5_key_and_hash_key("pw", 1, &salt, None).unwrap();
    let mut padded = b"plain".to_vec();
    padded.resize(16, 0);
    let ciphertext = zipfast::crypto::encrypt_cbc(&key, &iv, &padded).unwrap();
    let mut spec = FileSpec::new("one", &ciphertext);
    spec.size = Some(5);
    spec.extra = vec![36, 1, 0, 0, 1]; // size, crypt record, version, flags, exponent
    spec.extra.extend(salt);
    spec.extra.extend(iv);
    let mut first = common::SIG.to_vec();
    first.extend(common::main_block(true, None));
    first.extend(common::file_block(&spec, &ciphertext[..8], crc32fast::hash(&ciphertext[..8]), false, true));
    first.extend(common::end_block(true));
    spec.extra = vec![2, 1, 9]; // unsupported member encryption record version
    let mut second = common::SIG.to_vec();
    second.extend(common::main_block(true, Some(1)));
    second.extend(common::file_block(&spec, &ciphertext[8..], crc32fast::hash(b"plain"), true, false));
    second.extend(common::end_block(false));
    let mut o = options(tmp.path());
    o.set_password(Some("pw".into())).unwrap();
    o.artifact_aftermath = ArtifactAftermath::RetainProvisional;
    let (mut s, _) = session(vec![first, second], o, false, false, 7);
    loop {
        match poll(&mut s) {
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, artifact: Some(a), .. }))) => {
                assert!(matches!(failure.kind, FailureKind::Rar(_)));
                assert_eq!(a.produced_extent(), 0);
                break;
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { .. }))) => {
                panic!("invalid crypt metadata was accepted")
            }
            Poll::Ready(Ok(Some(_))) => {}
            _ => panic!("crypt continuation failure"),
        }
    }
}
#[test]
fn changed_volume_header_encryption_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let salt = [4; 16];
    let iv = [8; 16];
    let (key, _) = zipfast::crypto::derive_rar5_key_and_hash_key("pw", 1, &salt, None).unwrap();
    let mut first = common::SIG.to_vec();
    first.extend(common::main_block(true, None));
    first.extend(common::end_block(true));
    let mut second = common::SIG.to_vec();
    let mut fields = vec![0, 0, 1];
    fields.extend(salt);
    second.extend(common::block(4, 0, &fields, &[], &[], false));
    for mut header in [common::main_block(true, Some(1)), common::end_block(false)] {
        header.resize(header.len().next_multiple_of(16), 0);
        second.extend(iv);
        second.extend(zipfast::crypto::encrypt_cbc(&key, &iv, &header).unwrap());
    }
    let mut o = options(tmp.path());
    o.set_password(Some("pw".into())).unwrap();
    let (mut s, _) = session(vec![first, second], o, false, false, 3);
    loop {
        match poll(&mut s) {
            Poll::Ready(Err(e)) => {
                assert!(matches!(e.kind, FailureKind::Malformed("volume header encryption changed")));
                break;
            }
            Poll::Ready(Ok(Some(_))) => {}
            _ => panic!("changed encryption was accepted"),
        }
    }
}

fn size_transition_volumes(data: &[u8], initial_size: Option<u64>, final_size: Option<u64>) -> Vec<Vec<u8>> {
    let split = data.len() / 2;
    let mut spec = FileSpec::new("transition", data);
    spec.size_unknown = initial_size.is_none();
    spec.size = initial_size;
    let mut first = common::SIG.to_vec();
    first.extend(common::main_block(true, Some(0)));
    first.extend(common::file_block(&spec, &data[..split], crc32fast::hash(&data[..split]), false, true));
    first.extend(common::end_block(true));
    spec.size_unknown = final_size.is_none();
    spec.size = final_size;
    let mut second = common::SIG.to_vec();
    second.extend(common::main_block(true, Some(1)));
    second.extend(common::file_block(&spec, &data[split..], crc32fast::hash(data), true, false));
    let successor = FileSpec::new("successor", b"independent successor");
    second.extend(common::file_block(&successor, successor.data, crc32fast::hash(successor.data), false, false));
    second.extend(common::end_block(false));
    vec![first, second]
}
fn size_transition_session(bytes: Vec<Vec<u8>>, options: ProgressiveOptions, sealed: bool) -> ProgressiveSession {
    if sealed {
        ProgressiveSession::from_sealed_memory(
            bytes
                .into_iter()
                .enumerate()
                .map(|(i, b)| (format!("a.part{:02}.rar", i + 1).into(), b.into_boxed_slice()))
                .collect(),
            options,
        )
        .unwrap()
    } else {
        session(bytes, options, false, false, 3).0
    }
}
#[test]
fn size_transition_unknown_first_known_final_completes_and_runs_successor() {
    for size in [0, 1, 7, 16, 17] {
        let data = vec![b'x'; size];
        for sealed in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            let mut s = size_transition_session(
                size_transition_volumes(&data, None, Some(size as u64)),
                options(tmp.path()),
                sealed,
            );
            let mut started = Vec::new();
            let mut finished = Vec::new();
            let mut opened = Vec::new();
            let mut artifacts = Vec::new();
            loop {
                match poll(&mut s) {
                    Poll::Ready(Ok(Some(ProgressiveEvent::VolumeOpened { index, .. }))) => opened.push(index),
                    Poll::Ready(Ok(Some(ProgressiveEvent::MemberStarted { member, size: declared, .. }))) => {
                        if started.is_empty() {
                            assert_eq!(declared, None);
                        }
                        started.push(member);
                    }
                    Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { member, outcome }))) => {
                        let expected = if finished.is_empty() { data.as_slice() } else { b"independent successor" };
                        match outcome {
                            MemberOutcome::Verified(v) if sealed => {
                                assert_eq!(v.level(), VerificationLevel::Strict);
                                assert_eq!(v.size_verdict(), CheckVerdict::Passed);
                                assert_eq!(v.inner_size(), expected.len() as u64);
                            }
                            MemberOutcome::Provisional(mut a) if !sealed => {
                                assert_eq!(a.size(), Some(expected.len() as u64));
                                assert_eq!(a.produced_extent(), expected.len() as u64);
                                assert!(
                                    matches!(a.evidence(), ArtifactEvidence::Verified(v) if v.level()==VerificationLevel::Strict && v.size_verdict()==CheckVerdict::Passed)
                                );
                                assert_eq!(read_all(&mut a), expected);
                                artifacts.push(a);
                            }
                            _ => panic!("size promotion completion outcome"),
                        }
                        finished.push(member);
                    }
                    Poll::Ready(Ok(Some(ProgressiveEvent::BytesWritten { .. }))) => {}
                    Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) => {
                        panic!("valid size promotion terminated: {failure:?}")
                    }
                    Poll::Ready(Err(failure)) => panic!("valid size promotion failed: {failure:?}"),
                    Poll::Ready(Ok(None)) => break,
                    _ => panic!("size promotion poll"),
                }
            }
            assert_eq!(opened, [0, 1]);
            assert_eq!(started.len(), 2);
            assert_eq!(finished, started);
            for _ in 0..3 {
                assert!(matches!(poll(&mut s), Poll::Ready(Ok(None))));
            }
            drop(s);
            if sealed {
                assert_eq!(std::fs::read(tmp.path().join("transition")).unwrap(), data);
                assert_eq!(std::fs::read(tmp.path().join("successor")).unwrap(), b"independent successor");
            } else {
                assert!(!tmp.path().join("transition").exists());
                assert!(!tmp.path().join("successor").exists());
                assert_eq!(read_all(&mut artifacts[0]), data);
                for a in &mut artifacts {
                    a.discard().unwrap();
                }
                assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
            }
        }
    }
}
#[test]
fn size_transition_mismatches_preserve_targets_and_terminal_artifacts() {
    let data = b"payload";
    for initial in [None, Some(data.len() as u64)] {
        for final_size in [data.len() as u64 - 1, data.len() as u64 + 1] {
            for sealed in [false, true] {
                for aftermath in [ArtifactAftermath::Remove, ArtifactAftermath::RetainProvisional] {
                    let tmp = tempfile::tempdir().unwrap();
                    std::fs::write(tmp.path().join("transition"), b"prior target").unwrap();
                    std::fs::write(tmp.path().join("successor"), b"prior successor").unwrap();
                    let mut o = options(tmp.path());
                    o.artifact_aftermath = aftermath;
                    let mut s =
                        size_transition_session(size_transition_volumes(data, initial, Some(final_size)), o, sealed);
                    let mut started = 0;
                    let mut retained = loop {
                        match poll(&mut s) {
                            Poll::Ready(Ok(Some(ProgressiveEvent::MemberStarted { .. }))) => started += 1,
                            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated {
                                failure,
                                artifact,
                                cleanup_failure,
                            }))) => {
                                assert!(cleanup_failure.is_none());
                                assert!(matches!(failure.kind, FailureKind::Rar(_) | FailureKind::Malformed(_)));
                                assert_eq!(artifact.is_some(), aftermath == ArtifactAftermath::RetainProvisional);
                                break artifact;
                            }
                            Poll::Ready(Ok(Some(
                                ProgressiveEvent::VolumeOpened { .. } | ProgressiveEvent::BytesWritten { .. },
                            ))) => {}
                            _ => panic!("size mismatch must terminate once before a completion/successor"),
                        }
                    };
                    assert_eq!(started, 1);
                    for _ in 0..3 {
                        assert!(matches!(poll(&mut s), Poll::Ready(Ok(None))));
                    }
                    drop(s);
                    if let Some(a) = &mut retained {
                        assert_eq!(a.size(), initial);
                        assert_eq!(a.evidence(), &ArtifactEvidence::Provisional);
                        assert_eq!(
                            read_all(a),
                            if initial.is_some() { &data[..data.len() / 2] } else { data.as_slice() }
                        );
                        a.discard().unwrap();
                    }
                    assert_eq!(std::fs::read(tmp.path().join("transition")).unwrap(), b"prior target");
                    assert_eq!(std::fs::read(tmp.path().join("successor")).unwrap(), b"prior successor");
                    assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 2);
                }
            }
        }
    }
}
#[test]
fn size_transition_always_unknown_stays_provisional_and_runs_successor() {
    let data = b"unknown geometry";
    for sealed in [false, true] {
        let tmp = tempfile::tempdir().unwrap();
        let mut s = size_transition_session(size_transition_volumes(data, None, None), options(tmp.path()), sealed);
        let mut completions = 0;
        let mut first_artifact = None;
        loop {
            match poll(&mut s) {
                Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { outcome, .. }))) => {
                    if completions == 0 {
                        let MemberOutcome::Provisional(mut a) = outcome else { panic!("unknown size is provisional") };
                        assert_eq!(a.size(), None);
                        assert_eq!(a.evidence(), &ArtifactEvidence::Provisional);
                        assert_eq!(read_all(&mut a), data);
                        first_artifact = Some(a);
                    } else {
                        match outcome {
                            MemberOutcome::Verified(v) if sealed => assert_eq!(v.level(), VerificationLevel::Strict),
                            MemberOutcome::Provisional(mut a) if !sealed => {
                                assert!(
                                    matches!(a.evidence(), ArtifactEvidence::Verified(v) if v.level()==VerificationLevel::Strict)
                                );
                                assert_eq!(read_all(&mut a), b"independent successor");
                                a.discard().unwrap();
                            }
                            _ => panic!("independent successor"),
                        }
                    }
                    completions += 1;
                }
                Poll::Ready(Ok(Some(
                    ProgressiveEvent::VolumeOpened { .. }
                    | ProgressiveEvent::MemberStarted { .. }
                    | ProgressiveEvent::BytesWritten { .. },
                ))) => {}
                Poll::Ready(Ok(None)) => break,
                _ => panic!("unknown size continuation"),
            }
        }
        assert_eq!(completions, 2);
        for _ in 0..3 {
            assert!(matches!(poll(&mut s), Poll::Ready(Ok(None))));
        }
        drop(s);
        let mut a = first_artifact.unwrap();
        assert_eq!(read_all(&mut a), data);
        a.discard().unwrap();
        assert!(!tmp.path().join("transition").exists());
        assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), usize::from(sealed));
    }
}
