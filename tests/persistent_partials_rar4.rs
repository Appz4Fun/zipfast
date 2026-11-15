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

//! Persistent partial files for plain RAR4 stored members (method 0x30), single and split across volumes.
#![cfg(all(feature = "persistent-partials", any(target_os = "linux", target_os = "macos")))]
#[path = "common/partial_state.rs"]
mod partial_state;
use std::{
    ffi::OsString,
    fs::{self, File},
    ops::Range,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};
use zipfast::crc32::hash;
use zipfast::partial::*;
use zipfast::progressive::*;

fn block(kind: u8, flags: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0, 0, kind];
    bytes.extend(flags.to_le_bytes());
    bytes.extend(((body.len() + 7) as u16).to_le_bytes());
    bytes.extend(body);
    let crc = hash(&bytes[2..]) as u16;
    bytes[..2].copy_from_slice(&crc.to_le_bytes());
    bytes
}
/// A RAR4 file header (version 20) for `name`: `packed` bytes of payload follow it, `unpacked` is the member size
/// and `crc` the header CRC field (the part's data CRC in a non-final part, the member CRC in the final one).
fn file_header(name: &[u8], packed: usize, unpacked: usize, crc: u32, flags: u16, version: u8, method: u8) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend((packed as u32).to_le_bytes());
    body.extend((unpacked as u32).to_le_bytes());
    body.push(3);
    body.extend(crc.to_le_bytes());
    body.extend(0x50221884u32.to_le_bytes());
    body.extend([version, method]);
    body.extend((name.len() as u16).to_le_bytes());
    body.extend(0o100644u32.to_le_bytes());
    body.extend(name);
    block(0x74, flags | 0x8000, &body)
}
const SIG: &[u8] = b"Rar!\x1a\x07\0";

#[derive(Clone, Copy)]
enum Naming {
    /// set.rar, set.r00, set.r01, ...
    Old,
    /// set.part01.rar, set.part02.rar, ...
    Parts,
}
impl Naming {
    fn name(self, index: u32) -> OsString {
        match (self, index) {
            (Naming::Old, 0) => "set.rar".into(),
            (Naming::Old, n) => format!("set.r{:02}", n - 1).into(),
            (Naming::Parts, n) => format!("set.part{:02}.rar", n + 1).into(),
        }
    }
}

struct Source {
    index: u32,
    bytes: Vec<u8>,
    holes: Vec<Range<u64>>,
}
impl RangeSource for Source {
    fn info(&self) -> SourceInfo {
        SourceInfo {
            id: SourceId(self.index as u128 + 1),
            generation: 0,
            extent: self.bytes.len() as u64,
            length: SourceLength::Final(self.bytes.len() as u64),
        }
    }
    fn backing_files(&self) -> &[File] {
        &[]
    }
    fn read_at(&mut self, at: u64, buf: &mut [u8], _: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
        let mut end = (at + buf.len() as u64).min(self.bytes.len() as u64);
        for hole in &self.holes {
            if hole.start <= at && at < hole.end {
                return Ok(RangeRead::Hole { len: (hole.end - at).min(buf.len() as u64) });
            }
            if hole.start > at {
                end = end.min(hole.start);
            }
        }
        let n = (end - at) as usize;
        buf[..n].copy_from_slice(&self.bytes[at as usize..end as usize]);
        Ok(RangeRead::Filled { count: n })
    }
}
struct Provider {
    naming: Naming,
    volumes: Vec<Option<Source>>,
    protection: ProtectionDeclaration,
}
impl VolumeSource for Provider {
    fn protection(&mut self) -> ProgressiveResult<ProtectionDeclaration> {
        Ok(self.protection.clone())
    }
    fn volume(&mut self, request: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
        assert_eq!(request.expected, self.naming.name(request.index));
        match self.volumes.get_mut(request.index as usize).and_then(Option::take) {
            Some(source) => Ok(VolumeAnswer::Ready(Box::new(source))),
            None => Ok(VolumeAnswer::Missing),
        }
    }
}
#[derive(Default)]
struct Anchors(Mutex<Vec<StateAnchor>>);
impl StateAnchorStore for Anchors {
    fn current(&self, member: &MemberKey) -> PartialResult<Option<StateAnchor>> {
        Ok(self.0.lock().unwrap().iter().find(|a| a.member() == member).cloned())
    }
    fn compare_exchange(
        &self,
        member: &MemberKey,
        expected: Option<&StateAnchor>,
        next: &StateAnchor,
    ) -> PartialResult<()> {
        let mut anchors = self.0.lock().unwrap();
        let index = anchors.iter().position(|a| a.member() == member);
        if index.map(|i| &anchors[i]) != expected {
            return Err(PartialError::new(PartialErrorKind::AnchorConflict));
        }
        match index {
            Some(index) => anchors[index] = next.clone(),
            None => anchors.push(next.clone()),
        }
        Ok(())
    }
}

/// A RAR4 volume set built in memory, with the archive bytes the source answers as holes.
struct Set {
    naming: Naming,
    /// Bytes of every volume file.
    volumes: Vec<Vec<u8>>,
    /// Packed payload range of each part, per volume (one member part per volume for split sets).
    payloads: Vec<Range<u64>>,
    holes: Vec<Vec<Range<u64>>>,
}
impl Set {
    /// One member, `gold`, split across volumes at `cuts` (output offsets).
    fn split(naming: Naming, gold: &[u8], cuts: &[usize]) -> Self {
        let mut bounds = vec![0];
        bounds.extend_from_slice(cuts);
        bounds.push(gold.len());
        let count = bounds.len() - 1;
        let mut volumes = Vec::new();
        let mut payloads = Vec::new();
        for i in 0..count {
            let payload = &gold[bounds[i]..bounds[i + 1]];
            let last = i + 1 == count;
            let flags = u16::from(i > 0) | (u16::from(!last) * 2);
            let crc = hash(if last { gold } else { payload });
            let mut wire = SIG.to_vec();
            let main = 0x01 | if matches!(naming, Naming::Parts) { 0x10 } else { 0 } | if i == 0 { 0x100 } else { 0 };
            wire.extend(block(0x73, main, &[0; 6]));
            wire.extend(file_header(b"big.bin", payload.len(), gold.len(), crc, flags, 20, 0x30));
            payloads.push(wire.len() as u64..(wire.len() + payload.len()) as u64);
            wire.extend(payload);
            wire.extend(block(0x7b, 0x4000 | u16::from(!last), &[]));
            volumes.push(wire);
        }
        Self { naming, holes: vec![Vec::new(); count], volumes, payloads }
    }
    /// One unsplit volume holding each `(name, data)` member in order.
    fn single(members: &[(&[u8], &[u8])]) -> Self {
        let mut wire = SIG.to_vec();
        wire.extend(block(0x73, 0, &[0; 6]));
        let mut payloads = Vec::new();
        for (name, data) in members {
            wire.extend(file_header(name, data.len(), data.len(), hash(data), 0, 20, 0x30));
            payloads.push(wire.len() as u64..(wire.len() + data.len()) as u64);
            wire.extend(*data);
        }
        wire.extend(block(0x7b, 0x4000, &[]));
        Self { naming: Naming::Old, volumes: vec![wire], payloads, holes: vec![Vec::new()] }
    }
    /// Makes the source answer archive bytes `packed` of `volume` as a hole.
    fn hole(&mut self, volume: usize, packed: Range<u64>) {
        self.holes[volume].push(packed);
    }
    fn protection(&self) -> ProtectionDeclaration {
        ProtectionDeclaration::Complete {
            epoch: 1,
            inventory: ProtectionInventory {
                volumes: (0..self.volumes.len() as u32)
                    .map(|index| ProtectedVolume {
                        index,
                        name: self.naming.name(index),
                        backing: VolumeBacking::NonFile,
                    })
                    .collect(),
                auxiliary_paths: Vec::new(),
            },
        }
    }
    fn provider(&self) -> Provider {
        Provider {
            naming: self.naming,
            volumes: self
                .volumes
                .iter()
                .zip(&self.holes)
                .enumerate()
                .map(|(index, (bytes, holes))| {
                    Some(Source { index: index as u32, bytes: bytes.clone(), holes: holes.clone() })
                })
                .collect(),
            protection: self.protection(),
        }
    }
}

struct Run {
    dir: tempfile::TempDir,
    session: ProgressiveSession,
    holes: Vec<HoleReport>,
    parts: Vec<(u64, u32)>,
    files: Vec<(MemberKey, PartialFile)>,
    outcomes: Vec<MemberOutcome>,
    anchors: Arc<Anchors>,
    protection: ProtectionDeclaration,
}
impl Run {
    fn out(&self) -> PathBuf {
        self.dir.path().join("out")
    }
    fn state(&self) -> PathBuf {
        self.dir.path().join("state")
    }
}
fn options(dest: &Path, first: OsString) -> ProgressiveOptions {
    let mut options = ProgressiveOptions::new(
        zipfast::extract::Options {
            mode: zipfast::extract::Mode::Extract,
            dest: dest.into(),
            overwrite: zipfast::extract::Overwrite::Always,
            flatten: false,
            threads: Some(1),
            protected_paths: Default::default(),
            parallel_min: None,
            select: None,
        },
        first,
    );
    options.hole_policy = HolePolicy::PartialStored { fill: HoleFill::Sparse };
    options
}
fn partial_options(state: &Path, anchors: Arc<Anchors>) -> PartialOptions {
    PartialOptions {
        binding: ArchiveBinding { job: [1; 16], archive: [2; 32] },
        naming: PartialNaming::ArchivePath,
        state_dir: state.into(),
        limits: PartialLimits::default(),
        anchors,
        control: SessionControl::default(),
    }
}
fn extract(set: &Set) -> Run {
    let dir = tempfile::tempdir().unwrap();
    let anchors = Arc::new(Anchors::default());
    let mut session = ProgressiveSession::new_partial(
        Box::new(set.provider()),
        options(&dir.path().join("out"), set.naming.name(0)),
        partial_options(&dir.path().join("state"), anchors.clone()),
    )
    .unwrap();
    let mut holes = Vec::new();
    let mut parts = Vec::new();
    let mut files = Vec::new();
    let mut outcomes = Vec::new();
    for _ in 0..100_000 {
        match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Ok(Some(ProgressiveEvent::PartialReady { member, .. }))) => {
                files.push((member.clone(), session.partial_file(&member).unwrap()))
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::Hole(report)))) => holes.push(report),
            Poll::Ready(Ok(Some(ProgressiveEvent::PartVerified { check, .. }))) => {
                assert_eq!(check.crc32, CheckResult::Passed);
                parts.push((check.part, check.volume));
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { outcome, .. }))) => outcomes.push(outcome),
            Poll::Ready(Ok(None)) => {
                let protection = set.protection();
                return Run { dir, session, holes, parts, files, outcomes, anchors, protection };
            }
            Poll::Ready(Err(e)) => panic!("{e:?}"),
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) => panic!("{failure:?}"),
            _ => {}
        }
    }
    panic!("session did not finish")
}
fn verify(file: &mut PartialFile) -> Verdict {
    for _ in 0..10000 {
        if let Poll::Ready(result) = file.poll_verify(&mut Context::from_waker(Waker::noop())) {
            return result.unwrap();
        }
    }
    panic!("local verification failed to complete")
}
/// (output, packed spans as (volume, range), cause) of one hole report.
type Report = (Range<u64>, Vec<(u32, Range<u64>)>, HoleCause);
fn reports(holes: &[HoleReport]) -> Vec<Report> {
    holes
        .iter()
        .map(|h| (h.out.clone(), h.packed.iter().map(|s| (s.volume, s.range.clone())).collect(), h.cause.clone()))
        .collect()
}
#[allow(clippy::result_large_err, reason = "the public partial error type")]
fn reopen(run: Run, index: usize) -> PartialResult<(tempfile::TempDir, PartialFile)> {
    let Run { dir, session, mut files, anchors, protection, .. } = run;
    drop(session);
    let (key, file) = files.remove(index);
    drop(files);
    let state = partial_state::roundtrip(&file.close().unwrap());
    let expected_anchor = anchors.current(&key).unwrap().unwrap();
    let file = PartialFile::open(
        state,
        PartialOpenContext {
            output_root: dir.path().join("out"),
            state_root: dir.path().join("state"),
            expected_member: key,
            expected_anchor,
            protection,
            limits: PartialLimits::default(),
            progressive_limits: ProgressiveLimits::default(),
            anchors,
            control: SessionControl::default(),
            password: None,
        },
    )?;
    Ok((dir, file))
}

fn gold(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 37 + 11) % 251) as u8).collect()
}
/// Four volumes of 1000 bytes; the hole is output 800..1300, straddling the boundary of volumes 0 and 1.
fn straddling(naming: Naming) -> (Vec<u8>, Set) {
    let gold = gold(4000);
    let mut set = Set::split(naming, &gold, &[1000, 2000, 3000]);
    let (p0, p1) = (set.payloads[0].clone(), set.payloads[1].clone());
    set.hole(0, p0.start + 800..p0.end);
    set.hole(1, p1.start..p1.start + 300);
    (gold, set)
}

#[test]
fn split_hole_straddling_a_volume_boundary_is_reported_per_volume_and_alt_fill_verifies() {
    for naming in [Naming::Old, Naming::Parts] {
        let (gold, set) = straddling(naming);
        let mut run = extract(&set);
        let (p0, p1) = (set.payloads[0].clone(), set.payloads[1].clone());
        assert_eq!(
            reports(&run.holes),
            vec![
                (800..1000, vec![(0, p0.start + 800..p0.end)], HoleCause::Missing),
                (1000..1300, vec![(1, p1.start..p1.start + 300)], HoleCause::Missing),
            ]
        );
        assert!(run.holes.iter().all(|h| &*h.name == b"big.bin"));
        // The clean non-final part is checked against its volume header CRC while extraction runs.
        assert_eq!(run.parts, vec![(2, 2)]);
        assert_eq!(run.outcomes.len(), 1);
        assert!(matches!(run.outcomes[0], MemberOutcome::PersistentPartial { .. }));
        let file = &mut run.files[0].1;
        assert_eq!(file.remaining().unwrap(), vec![800..1300]);
        let Verdict::Incomplete { parts, .. } = verify(file) else { panic!("holes remain") };
        assert_eq!(
            parts.iter().map(|p| (p.volume, p.crc32.clone())).collect::<Vec<_>>(),
            [(0, CheckResult::Pending), (1, CheckResult::Pending), (2, CheckResult::Passed), (3, CheckResult::Pending),]
        );
        let filled = file.fill(800, &gold[800..1300]).unwrap();
        assert_eq!(filled.applied, vec![800..1300]);
        assert!(matches!(verify(file), Verdict::Ok { .. }));
        assert_eq!(fs::read(run.out().join("big.bin")).unwrap(), gold);
    }
}

#[test]
fn one_wrong_byte_is_pinned_to_its_volume_by_the_part_crc() {
    let (gold, set) = straddling(Naming::Old);
    let mut run = extract(&set);
    let file = &mut run.files[0].1;
    let mut wrong = gold[800..1300].to_vec();
    wrong[1100 - 800] ^= 1;
    file.fill(800, &wrong).unwrap();
    let verdict = verify(file);
    assert!(
        matches!(verdict, Verdict::PartBad { volume: 1, part: 1, which: ChecksumAlgorithm::Crc32, .. }),
        "{verdict:?}"
    );
    // Archive bytes win over the wrong alt bytes and report them.
    let fixed = file.fill_packed(1, 0, &set.volumes[1]).unwrap();
    assert_eq!(fixed.corrected, vec![1000..1300]);
    assert!(matches!(verify(file), Verdict::Ok { .. }));
    assert_eq!(fs::read(run.out().join("big.bin")).unwrap(), gold);

    // A wrong byte in the final part is judged by the member CRC, which names no volume.
    let gold = self::gold(3000);
    let mut set = Set::split(Naming::Old, &gold, &[1000, 2000]);
    let p2 = set.payloads[2].clone();
    set.hole(2, p2.start + 100..p2.start + 200);
    let mut run = extract(&set);
    let file = &mut run.files[0].1;
    let mut wrong = gold[2100..2200].to_vec();
    wrong[5] ^= 0x80;
    file.fill(2100, &wrong).unwrap();
    assert!(matches!(verify(file), Verdict::Bad { which: ChecksumAlgorithm::Crc32, .. }));
}

#[test]
fn reopen_then_fill_then_verify() {
    let (gold, set) = straddling(Naming::Parts);
    let run = extract(&set);
    let key = run.files[0].0.clone();
    assert_ne!(run.holes[0].member.identity(), &[0; 32]);
    let (dir, mut file) = reopen(run, 0).unwrap();
    assert_eq!(file.remaining().unwrap(), vec![800..1300]);
    file.fill(800, &gold[800..1300]).unwrap();
    assert!(matches!(verify(&mut file), Verdict::Ok { .. }));
    assert_eq!(fs::read(dir.path().join("out/big.bin")).unwrap(), gold);
    assert_eq!(file.close().unwrap().member(), &key);
}

#[test]
fn fill_packed_with_whole_volumes_fills_only_the_holes_and_verifies() {
    let (gold, set) = straddling(Naming::Old);
    let mut run = extract(&set);
    let file = &mut run.files[0].1;
    let p0 = set.payloads[0].clone();
    let first = file.fill_packed(0, 0, &set.volumes[0]).unwrap();
    assert_eq!(first.applied, vec![800..1000]);
    assert!(first.corrected.is_empty());
    let unmapped: Vec<_> = first.unmapped.iter().map(|s| (s.volume, s.range.clone())).collect();
    assert_eq!(unmapped, vec![(0, 0..p0.start), (0, p0.end..set.volumes[0].len() as u64)]);
    assert_eq!(file.remaining().unwrap(), vec![1000..1300]);
    let second = file.fill_packed(1, 0, &set.volumes[1]).unwrap();
    assert_eq!(second.applied, vec![1000..1300]);
    assert!(file.remaining().unwrap().is_empty());
    // Volumes without holes change nothing.
    for volume in [2, 3] {
        let none = file.fill_packed(volume, 0, &set.volumes[volume as usize]).unwrap();
        assert!(none.applied.is_empty() && none.corrected.is_empty());
    }
    assert!(matches!(verify(file), Verdict::Ok { .. }));
    assert_eq!(fs::read(run.out().join("big.bin")).unwrap(), gold);
}

#[test]
fn declared_damage_and_refill_from_a_repaired_volume() {
    let (gold, set) = straddling(Naming::Old);
    let mut run = extract(&set);
    let p2 = set.payloads[2].clone();
    // Ten header bytes before the payload map to no output.
    let receipt = run.session.declare_hole(2, p2.start - 10..p2.start + 40).unwrap();
    assert_eq!(reports(&receipt.holes), vec![(2000..2040, vec![(2, p2.start..p2.start + 40)], HoleCause::DeclaredBad)]);
    assert_eq!(
        receipt.unmapped.iter().map(|s| (s.volume, s.range.clone())).collect::<Vec<_>>(),
        [(2, p2.start - 10..p2.start)]
    );
    let file = &mut run.files[0].1;
    assert_eq!(file.remaining().unwrap(), vec![800..1300, 2000..2040]);
    struct Counting(std::io::Cursor<Vec<u8>>, u64);
    impl std::io::Read for Counting {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.0.read(buf)?;
            self.1 += n as u64;
            Ok(n)
        }
    }
    impl std::io::Seek for Counting {
        fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
            self.0.seek(pos)
        }
    }
    let mut reader = Counting(std::io::Cursor::new(set.volumes[2].clone()), 0);
    let refilled = file.refill_from_packed(2, 0..set.volumes[2].len() as u64, &mut reader).unwrap();
    assert_eq!(reader.1, 40, "refill reads only the damaged bytes");
    assert_eq!(refilled.applied, vec![2000..2040]);
    for volume in [0, 1] {
        let mut reader = Counting(std::io::Cursor::new(set.volumes[volume].clone()), 0);
        file.refill_from_packed(volume as u32, 0..set.volumes[volume].len() as u64, &mut reader).unwrap();
    }
    assert!(file.remaining().unwrap().is_empty());
    assert!(matches!(verify(file), Verdict::Ok { .. }));
    assert_eq!(fs::read(run.out().join("big.bin")).unwrap(), gold);
}

#[test]
fn two_member_set_only_the_damaged_member_is_partial() {
    let (a, b) = (gold(1500), gold(900).into_iter().rev().collect::<Vec<_>>());
    let mut set = Set::single(&[(b"a.bin", &a), (b"b.bin", &b)]);
    let pa = set.payloads[0].clone();
    set.hole(0, pa.start + 100..pa.start + 400);
    let mut run = extract(&set);
    assert_eq!(reports(&run.holes), vec![(100..400, vec![(0, pa.start + 100..pa.start + 400)], HoleCause::Missing)]);
    assert_eq!(run.outcomes.len(), 2);
    assert!(matches!(run.outcomes[0], MemberOutcome::PersistentPartial { .. }));
    assert!(matches!(run.outcomes[1], MemberOutcome::PersistentComplete { verdict: Verdict::Ok { .. }, .. }));
    assert_eq!(fs::read(run.out().join("b.bin")).unwrap(), b);
    assert!(matches!(verify(&mut run.files[1].1), Verdict::Ok { .. }));
    // RAR4 members get their own identity domain; members of one set never share a key.
    assert_ne!(run.files[0].0, run.files[1].0);
    let file = &mut run.files[0].1;
    file.fill(100, &a[100..400]).unwrap();
    assert!(matches!(verify(file), Verdict::Ok { .. }));
    assert_eq!(fs::read(run.out().join("a.bin")).unwrap(), a);
    assert!(run.state().exists());
}

#[test]
fn reopened_state_keeps_its_format() {
    // A RAR4 state reopens and reparses its RAR4 header witnesses; the state roundtrips through serde unchanged.
    let gold = gold(700);
    let mut set = Set::single(&[(b"one.bin", &gold)]);
    let p = set.payloads[0].clone();
    set.hole(0, p.start..p.start + 1);
    let run = extract(&set);
    let (dir, mut file) = reopen(run, 0).unwrap();
    assert_eq!(file.remaining().unwrap(), vec![0..1]);
    let state = file.state().unwrap();
    assert_eq!(partial_state::roundtrip(&state).anchor(), state.anchor());
    file.fill(0, &gold[..1]).unwrap();
    assert!(matches!(verify(&mut file), Verdict::Ok { .. }));
    assert_eq!(fs::read(dir.path().join("out/one.bin")).unwrap(), gold);
}

fn refused(volume: Vec<u8>) -> PartialErrorKind {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out");
    let state = dir.path().join("state");
    let set = Set { naming: Naming::Old, volumes: vec![volume], payloads: Vec::new(), holes: vec![Vec::new()] };
    let mut session = ProgressiveSession::new_partial(
        Box::new(set.provider()),
        options(&dest, set.naming.name(0)),
        partial_options(&state, Arc::new(Anchors::default())),
    )
    .unwrap();
    let error = loop {
        match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Err(e)) => break e,
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberStarted { .. } | ProgressiveEvent::PartialReady { .. }))) => {
                panic!("unsupported member created output")
            }
            Poll::Ready(Ok(None)) => panic!("unsupported archive accepted"),
            _ => {}
        }
    };
    assert!(!dest.exists(), "refusal precedes output effects");
    assert!(!state.exists(), "refusal precedes state effects");
    let FailureKind::Partial(error) = error.kind else { panic!("not a typed partial refusal: {error:?}") };
    error.kind
}

#[test]
fn encrypted_compressed_and_header_encrypted_rar4_are_refused_before_effects() {
    let data = b"some member data";
    let archive = |header: Vec<u8>, payload: &[u8], main: u16| {
        let mut wire = SIG.to_vec();
        wire.extend(block(0x73, main, &[0; 6]));
        wire.extend(header);
        wire.extend(payload);
        wire.extend(block(0x7b, 0x4000, &[]));
        wire
    };
    // Compressed (method 0x33, version 29).
    let packed = [0u8; 8];
    let compressed = archive(file_header(b"c.bin", packed.len(), data.len(), hash(data), 0, 29, 0x33), &packed, 0);
    assert!(matches!(refused(compressed), PartialErrorKind::UnsupportedMethod));
    // Encrypted stored, with and without a salt.
    for (flags, salt) in [(0x04u16, false), (0x404, true)] {
        let mut header = file_header(b"e.bin", 16, data.len(), hash(data), flags, 29, 0x30);
        if salt {
            let mut body = header[7..].to_vec();
            body.extend([7u8; 8]);
            header = block(0x74, flags | 0x8000, &body);
        }
        assert!(matches!(refused(archive(header, &[0; 16], 0)), PartialErrorKind::UnsupportedMethod));
    }
    // Header encryption (-hp): refused at the main header, before any encrypted header is read.
    let mut hp = SIG.to_vec();
    hp.extend(block(0x73, 0x80, &[0; 6]));
    hp.extend([0u8; 64]);
    assert!(matches!(refused(hp), PartialErrorKind::UnsupportedMethod));
    // All-ones RAR4 size means unknown.
    let unknown = archive(file_header(b"u.bin", data.len(), u32::MAX as usize, hash(data), 0, 20, 0x30), data, 0);
    assert!(matches!(refused(unknown), PartialErrorKind::UnknownMemberSize));
}
