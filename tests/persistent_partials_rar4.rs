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
    reads: Arc<Mutex<Vec<(u32, u64)>>>,
    /// Answers every other read `NotYet`, as a volume still downloading does.
    slow: bool,
    /// Answers each hole whole, from the read offset to its end, rather than capped at the buffer.
    long_holes: bool,
    ticks: usize,
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
    fn read_at(&mut self, at: u64, buf: &mut [u8], cx: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
        self.ticks += 1;
        if self.slow && self.ticks % 2 == 1 {
            // The next bytes arrive at once: wake the session to read again.
            cx.waker().wake_by_ref();
            return Ok(RangeRead::NotYet);
        }
        self.reads.lock().unwrap().push((self.index, at));
        let mut end = (at + buf.len() as u64).min(self.bytes.len() as u64);
        for hole in &self.holes {
            if hole.start <= at && at < hole.end {
                let len = if self.long_holes { hole.end - at } else { (hole.end - at).min(buf.len() as u64) };
                return Ok(RangeRead::Hole { len });
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
    slow: bool,
    ticks: usize,
}
impl VolumeSource for Provider {
    fn protection(&mut self) -> ProgressiveResult<ProtectionDeclaration> {
        Ok(self.protection.clone())
    }
    fn volume(&mut self, request: &VolumeRequest, cx: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
        assert_eq!(request.expected, self.naming.name(request.index));
        self.ticks += 1;
        if self.slow && self.ticks % 2 == 1 {
            cx.waker().wake_by_ref();
            return Ok(VolumeAnswer::Wait);
        }
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
    /// (volume, offset) of every source read.
    reads: Arc<Mutex<Vec<(u32, u64)>>>,
    /// Whether the provider and its sources answer as a set still downloading.
    slow: bool,
    /// Whether sources answer each hole whole (see [`Source::long_holes`]).
    long_holes: bool,
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
        Self {
            naming,
            holes: vec![Vec::new(); count],
            volumes,
            payloads,
            reads: Arc::default(),
            slow: false,
            long_holes: false,
        }
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
        Self {
            naming: Naming::Old,
            volumes: vec![wire],
            payloads,
            holes: vec![Vec::new()],
            reads: Arc::default(),
            slow: false,
            long_holes: false,
        }
    }
    /// One RAR4 stored member, `gold`, AES-encrypted with `password` (plain headers, salt present), its ciphertext
    /// split across volumes at the part lengths `cuts`.
    fn aes_split(naming: Naming, gold: &[u8], cuts: &[usize], password: &str) -> Self {
        const SALT: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        let (key, iv) = zipfast::crypto::derive_rar4_key_iv(password, &SALT);
        let mut padded = gold.to_vec();
        padded.resize(gold.len().next_multiple_of(16), 0xa5);
        let cipher = zipfast::crypto::encrypt_cbc(&key, &iv, &padded).unwrap();
        assert_eq!(cuts.iter().sum::<usize>(), cipher.len());
        let (mut volumes, mut payloads, mut at) = (Vec::new(), Vec::new(), 0);
        for (i, &len) in cuts.iter().enumerate() {
            let payload = &cipher[at..at + len];
            at += len;
            let last = i + 1 == cuts.len();
            let flags = 0x404 | u16::from(i > 0) | (u16::from(!last) * 2);
            let crc = hash(if last { gold } else { payload });
            let mut body = file_header(b"movie.mkv", len, gold.len(), crc, flags, 29, 0x30)[7..].to_vec();
            body.extend(SALT);
            let mut wire = SIG.to_vec();
            let main = 0x01 | if matches!(naming, Naming::Parts) { 0x10 } else { 0 } | if i == 0 { 0x100 } else { 0 };
            wire.extend(block(0x73, main, &[0; 6]));
            wire.extend(block(0x74, flags | 0x8000, &body));
            payloads.push(wire.len() as u64..(wire.len() + len) as u64);
            wire.extend(payload);
            wire.extend(block(0x7b, 0x4000 | u16::from(!last), &[]));
            volumes.push(wire);
        }
        Self {
            naming,
            holes: vec![Vec::new(); cuts.len()],
            volumes,
            payloads,
            reads: Arc::default(),
            slow: false,
            long_holes: false,
        }
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
                    Some(Source {
                        index: index as u32,
                        bytes: bytes.clone(),
                        holes: holes.clone(),
                        reads: self.reads.clone(),
                        slow: self.slow,
                        long_holes: self.long_holes,
                        ticks: 0,
                    })
                })
                .collect(),
            protection: self.protection(),
            slow: self.slow,
            ticks: 0,
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
fn a_part_failing_its_header_crc_becomes_a_declared_hole_and_the_member_finishes() {
    // A wrong byte in part 2 (output 2000..3000), from an article whose transport check passed: the part's header
    // CRC fails. The part's output becomes a DeclaredBad hole instead of ending the session, and refilling it from
    // the repaired volume reads that part and nothing else.
    for naming in [Naming::Old, Naming::Parts] {
        let gold = gold(4000);
        let mut set = Set::split(naming, &gold, &[1000, 2000, 3000]);
        let p2 = set.payloads[2].clone();
        let good = set.volumes[2].clone();
        set.volumes[2][p2.start as usize + 500] ^= 0x40;
        let mut run = extract(&set);
        assert_eq!(reports(&run.holes), vec![(2000..3000, vec![(2, p2.clone())], HoleCause::DeclaredBad)]);
        // The clean non-final parts are checked as before; the bad one is not reported verified.
        assert_eq!(run.parts, vec![(0, 0), (1, 1)]);
        assert_eq!(run.outcomes.len(), 1);
        assert!(matches!(run.outcomes[0], MemberOutcome::PersistentPartial { .. }));
        // Every volume is read forward: no source read goes back to an offset already passed.
        let reads = set.reads.lock().unwrap().clone();
        for volume in 0..set.volumes.len() as u32 {
            let offsets: Vec<u64> = reads.iter().filter(|r| r.0 == volume).map(|r| r.1).collect();
            assert!(offsets.windows(2).all(|w| w[0] < w[1]), "volume {volume} read again: {offsets:?}");
        }
        let file = &mut run.files[0].1;
        assert_eq!(file.remaining().unwrap(), vec![2000..3000]);
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
        let mut reader = Counting(std::io::Cursor::new(good.clone()), 0);
        file.refill_from_packed(2, 0..good.len() as u64, &mut reader).unwrap();
        assert_eq!(reader.1, 1000, "refill reads only the declared part");
        assert!(matches!(verify(file), Verdict::Ok { .. }));
        assert_eq!(fs::read(run.out().join("big.bin")).unwrap(), gold);
    }
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

/// The refusal of the one member of `volume`, after a session that created nothing.
fn refused_member(volume: Vec<u8>) -> RefusalReason {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out");
    let state = dir.path().join("state");
    let set = Set {
        naming: Naming::Old,
        volumes: vec![volume],
        payloads: Vec::new(),
        holes: vec![Vec::new()],
        reads: Arc::default(),
        slow: false,
        long_holes: false,
    };
    let mut session = ProgressiveSession::new_partial(
        Box::new(set.provider()),
        options(&dest, set.naming.name(0)),
        partial_options(&state, Arc::new(Anchors::default())),
    )
    .unwrap();
    let mut reasons = Vec::new();
    loop {
        match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Err(e)) => panic!("{e:?}"),
            Poll::Ready(Ok(Some(ProgressiveEvent::PartialReady { .. }))) => panic!("refused member created output"),
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished {
                outcome: MemberOutcome::Refused { reason },
                ..
            }))) => reasons.push(reason),
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { .. }))) => panic!("member not refused"),
            Poll::Ready(Ok(None)) => break,
            _ => {}
        }
    }
    assert!(!dest.exists(), "refusal precedes output effects");
    assert!(!state.exists(), "refusal precedes state effects");
    assert_eq!(reasons.len(), 1);
    reasons[0]
}
fn refused(volume: Vec<u8>) -> PartialErrorKind {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out");
    let state = dir.path().join("state");
    let set = Set {
        naming: Naming::Old,
        volumes: vec![volume],
        payloads: Vec::new(),
        holes: vec![Vec::new()],
        reads: Arc::default(),
        slow: false,
        long_holes: false,
    };
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
fn encrypted_compressed_and_unknown_size_rar4_members_are_refused_and_header_encryption_ends_the_session() {
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
    assert_eq!(refused_member(compressed), RefusalReason::Compressed { method: 3 });
    // A solid stream's members are compressed members too, though other sessions now decode them.
    let solid = archive(file_header(b"s.bin", packed.len(), data.len(), hash(data), 0x10, 29, 0x33), &packed, 0x08);
    assert_eq!(refused_member(solid), RefusalReason::Compressed { method: 3 });
    // Encrypted stored without a salt (an AES member with one is admitted: see the RAR4 AES tests below), and
    // with an older cipher.
    for version in [29, 20] {
        let header = file_header(b"e.bin", 16, data.len(), hash(data), 0x04, version, 0x30);
        assert_eq!(refused_member(archive(header, &[0; 16], 0)), RefusalReason::Encrypted);
    }
    // Header encryption (-hp): refused at the main header, before any encrypted header is read.
    let mut hp = SIG.to_vec();
    hp.extend(block(0x73, 0x80, &[0; 6]));
    hp.extend([0u8; 64]);
    assert!(matches!(refused(hp), PartialErrorKind::UnsupportedMethod));
    // All-ones RAR4 size means unknown.
    let unknown = archive(file_header(b"u.bin", data.len(), u32::MAX as usize, hash(data), 0, 20, 0x30), data, 0);
    assert_eq!(refused_member(unknown), RefusalReason::UnknownSize);
}

/// Drops `value` as a crash leaves it: an open group is not committed. (Drop skips that commit while unwinding.)
fn crash<T>(value: T) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _held = value;
        std::panic::resume_unwind(Box::new("simulated crash"));
    }));
}
/// A session over `set` under `dir` with 300-byte reads, committing every write.
fn session(set: &Set, dir: &Path, anchors: &Arc<Anchors>) -> ProgressiveSession {
    session_with(set, dir, anchors, None)
}
fn session_with(set: &Set, dir: &Path, anchors: &Arc<Anchors>, password: Option<&str>) -> ProgressiveSession {
    let mut opts = options(&dir.join("out"), set.naming.name(0));
    opts.set_password(password.map(String::from)).unwrap();
    opts.limits.read_chunk = 300;
    let mut partial = partial_options(&dir.join("state"), anchors.clone());
    partial.limits.group_commit_bytes = 0;
    ProgressiveSession::new_partial(Box::new(set.provider()), opts, partial).unwrap()
}
#[derive(Default)]
struct Seen {
    events: usize,
    written: u64,
    files: Vec<(MemberKey, PartialFile)>,
    adopted: Vec<(MemberKey, u64, bool)>,
    outcomes: Vec<MemberOutcome>,
}
/// Polls until the session ends (true) or `stop` events were delivered (false).
fn run(session: &mut ProgressiveSession, seen: &mut Seen, stop: Option<usize>) -> bool {
    for _ in 0..1_000_000 {
        if stop.is_some_and(|stop| seen.events >= stop) {
            return false;
        }
        let event = match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Pending => continue,
            Poll::Ready(Ok(None)) => return true,
            Poll::Ready(Ok(Some(event))) => event,
            Poll::Ready(Err(e)) => panic!("{e:?}"),
        };
        seen.events += 1;
        match event {
            ProgressiveEvent::PartialReady { member, .. } => {
                seen.written = 0;
                seen.files.push((member.clone(), session.partial_file(&member).unwrap()));
            }
            ProgressiveEvent::PartialAdopted { member, produced, finished, .. } => {
                seen.written = produced;
                seen.files.push((member.clone(), session.partial_file(&member).unwrap()));
                seen.adopted.push((member, produced, finished));
            }
            ProgressiveEvent::BytesWritten { logical_end, .. } => seen.written = logical_end,
            ProgressiveEvent::MemberFinished { outcome, .. } => seen.outcomes.push(outcome),
            ProgressiveEvent::SessionTerminated { failure, .. } => panic!("{failure:?}"),
            _ => {}
        }
    }
    panic!("session did not finish")
}

/// (output name, expected bytes) of each member of a set.
type Members<'a> = Vec<(&'a str, &'a [u8])>;
#[test]
fn restart_resumes_split_and_multi_member_sets_at_every_crash_point() {
    let gold = gold(4000);
    let (x, y) = (gold[..1500].to_vec(), gold[1500..].to_vec());
    let sets: [(Set, Members<'_>); 2] = [
        (Set::split(Naming::Parts, &gold, &[1000, 2000, 3000]), vec![("big.bin", &gold)]),
        (Set::single(&[(b"x.bin", &x), (b"y.bin", &y)]), vec![("x.bin", &x), ("y.bin", &y)]),
    ];
    for (set, members) in &sets {
        let total = {
            let dir = tempfile::tempdir().unwrap();
            let mut seen = Seen::default();
            assert!(run(&mut session(set, dir.path(), &Arc::default()), &mut seen, None));
            seen.events
        };
        for crash_at in 1..total {
            let dir = tempfile::tempdir().unwrap();
            let anchors = Arc::new(Anchors::default());
            let mut first = session(set, dir.path(), &anchors);
            let mut before = Seen::default();
            assert!(!run(&mut first, &mut before, Some(crash_at)));
            let finished = before.outcomes.len();
            let written = before.written;
            let created: Vec<MemberKey> = before.files.iter().map(|(key, _)| key.clone()).collect();
            crash((first, std::mem::take(&mut before.files)));
            set.reads.lock().unwrap().clear();
            let mut second = session(set, dir.path(), &anchors);
            let mut after = Seen::default();
            assert!(run(&mut second, &mut after, None), "crash at {crash_at}");
            assert_eq!(after.outcomes.len(), members.len());
            for outcome in &after.outcomes {
                assert!(matches!(outcome, MemberOutcome::PersistentComplete { verdict: Verdict::Ok { .. }, .. }));
            }
            for (name, data) in members {
                assert_eq!(fs::read(dir.path().join("out").join(name)).unwrap(), *data, "crash at {crash_at}");
            }
            for (index, (key, produced, done)) in after.adopted.iter().enumerate() {
                if index < finished {
                    assert!(*done, "crash at {crash_at}");
                } else if !created.contains(key) {
                    // Its genesis preceded a `PartialReady` the crash kept from being delivered.
                    assert_eq!((*produced, *done), (0, false), "crash at {crash_at}");
                } else {
                    assert_eq!(*produced, written, "crash at {crash_at}");
                }
                // Output offset of every payload read of this member: none for a finished member, and none
                // below the resume point otherwise.
                let ordinal = key.ordinal() as usize;
                for &(volume, at) in set.reads.lock().unwrap().iter() {
                    let (payload, out) = if set.volumes.len() > 1 {
                        (&set.payloads[volume as usize], volume as u64 * 1000)
                    } else {
                        (&set.payloads[ordinal], 0)
                    };
                    if payload.contains(&at) {
                        assert!(!*done && out + (at - payload.start) >= *produced, "crash at {crash_at}");
                    }
                }
            }
        }
    }
}

fn describe(outcome: &MemberOutcome) -> &'static str {
    match outcome {
        MemberOutcome::PersistentComplete { verdict: Verdict::Ok { .. }, .. } => "complete, verified",
        MemberOutcome::PersistentComplete { .. } => "complete, not verified",
        MemberOutcome::PersistentPartial { .. } => "partial",
        MemberOutcome::Refused { .. } => "refused",
        _ => "other",
    }
}
/// RustyGet's case: a 5-volume RAR4 set whose one stored member is AES-encrypted (plain headers, salt present),
/// 60,000 bytes of ciphertext per volume. The persistent session admits it and publishes the decrypted member with
/// a verified CRC, whether the set is still downloading or already complete.
#[test]
fn rar4_aes_stored_member_publishes_its_output_downloading_and_complete() {
    let gold = gold(250_000);
    for slow in [true, false] {
        for naming in [Naming::Parts, Naming::Old] {
            let mut set = Set::aes_split(naming, &gold, &[60_000, 60_000, 60_000, 60_000, 10_000], "pw");
            set.slow = slow;
            let dir = tempfile::tempdir().unwrap();
            let mut seen = Seen::default();
            // Default reads and group commits: a commit per 300-byte read is slow on a set this size.
            let mut opts = options(&dir.path().join("out"), set.naming.name(0));
            opts.set_password(Some("pw".into())).unwrap();
            let partial = partial_options(&dir.path().join("state"), Arc::default());
            let mut session = ProgressiveSession::new_partial(Box::new(set.provider()), opts, partial).unwrap();
            assert!(run(&mut session, &mut seen, None));
            assert_eq!(seen.outcomes.len(), 1, "slow {slow}");
            // `Verdict::Ok` is the member CRC-32 over the decrypted output, checked against the header's.
            assert!(
                matches!(&seen.outcomes[0], MemberOutcome::PersistentComplete { verdict: Verdict::Ok { .. }, .. }),
                "{}",
                describe(&seen.outcomes[0])
            );
            assert_eq!(fs::read(dir.path().join("out").join("movie.mkv")).unwrap(), gold, "slow {slow}");
        }
    }
}

/// A wrong or missing password for a RAR4 AES member fails typed, and nothing is published.
#[test]
fn rar4_aes_stored_member_without_its_password_publishes_nothing() {
    let gold = gold(4000);
    let set = Set::aes_split(Naming::Parts, &gold, &[1008, 1008, 1008, 976], "pw");
    for password in [None, Some("wrong")] {
        let dir = tempfile::tempdir().unwrap();
        let mut session = session_with(&set, dir.path(), &Arc::default(), password);
        let mut failed = false;
        for _ in 0..1_000_000 {
            match session.poll_event(&mut Context::from_waker(Waker::noop())) {
                Poll::Pending => continue,
                Poll::Ready(Ok(None)) => break,
                Poll::Ready(Err(_)) | Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { .. }))) => {
                    failed = true;
                    break;
                }
                Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { outcome, .. }))) => {
                    assert!(
                        !matches!(outcome, MemberOutcome::PersistentComplete { verdict: Verdict::Ok { .. }, .. }),
                        "{password:?}"
                    );
                }
                _ => {}
            }
        }
        assert!(failed, "{password:?}");
        assert!(fs::read(dir.path().join("out").join("movie.mkv")).ok().is_none_or(|bytes| bytes != gold));
    }
}

/// A RAR4 AES member resumes after a restart at every crash point, and every byte lands decrypted.
#[test]
fn restart_resumes_a_rar4_aes_stored_member_at_every_crash_point() {
    let gold = gold(4000);
    let set = Set::aes_split(Naming::Parts, &gold, &[1008, 1008, 1008, 976], "pw");
    let pw = Some("pw");
    let total = {
        let dir = tempfile::tempdir().unwrap();
        let mut seen = Seen::default();
        assert!(run(&mut session_with(&set, dir.path(), &Arc::default(), pw), &mut seen, None));
        seen.events
    };
    for crash_at in 1..total {
        let dir = tempfile::tempdir().unwrap();
        let anchors = Arc::new(Anchors::default());
        let mut first = session_with(&set, dir.path(), &anchors, pw);
        let mut before = Seen::default();
        assert!(!run(&mut first, &mut before, Some(crash_at)));
        crash((first, std::mem::take(&mut before.files)));
        let mut second = session_with(&set, dir.path(), &anchors, pw);
        let mut after = Seen::default();
        assert!(run(&mut second, &mut after, None), "crash at {crash_at}");
        assert_eq!(after.outcomes.len(), 1, "crash at {crash_at}");
        assert!(
            matches!(&after.outcomes[0], MemberOutcome::PersistentComplete { verdict: Verdict::Ok { .. }, .. }),
            "crash at {crash_at}: {}",
            describe(&after.outcomes[0])
        );
        for (_, produced, _) in &after.adopted {
            assert_eq!(produced % 16, 0, "crash at {crash_at}");
        }
        assert_eq!(fs::read(dir.path().join("out").join("movie.mkv")).unwrap(), gold, "crash at {crash_at}");
    }
}

/// RustyGet M6e: after a restart, the source answers every hole whole (as RustyGet's `HoledVolume` does inside
/// member data), and a hole now covers bytes the first session read. The resume of an AES member reads the 16-byte
/// ciphertext block before its next byte without a long-hole allowance; when that block lies inside the hole, the
/// source still answers to the hole's end. A persistent session trims such an answer to the read (the block becomes
/// unknown) instead of failing the run as a source contract violation.
#[test]
fn restart_of_an_aes_member_trims_a_long_hole_answer_to_its_resume_read() {
    let gold = gold(8000);
    let intact = Set::aes_split(Naming::Parts, &gold, &[2000, 2000, 2000, 2000], "pw");
    let mut holed = Set::aes_split(Naming::Parts, &gold, &[2000, 2000, 2000, 2000], "pw");
    for v in 0..holed.payloads.len() {
        let p = holed.payloads[v].clone();
        holed.hole(v, p.start + 32..p.end - 32);
    }
    holed.long_holes = true;
    let pw = Some("pw");
    let total = {
        let dir = tempfile::tempdir().unwrap();
        let mut seen = Seen::default();
        assert!(run(&mut session_with(&intact, dir.path(), &Arc::default(), pw), &mut seen, None));
        seen.events
    };
    for crash_at in 1..total {
        let dir = tempfile::tempdir().unwrap();
        let anchors = Arc::new(Anchors::default());
        let mut first = session_with(&intact, dir.path(), &anchors, pw);
        let mut before = Seen::default();
        assert!(!run(&mut first, &mut before, Some(crash_at)));
        crash((first, std::mem::take(&mut before.files)));
        let mut second = session_with(&holed, dir.path(), &anchors, pw);
        let mut after = Seen::default();
        // `run` panics on a SessionTerminated failure such as SourceContract.
        assert!(run(&mut second, &mut after, None), "crash at {crash_at}");
        assert_eq!(after.outcomes.len(), 1, "crash at {crash_at}");
    }
}

/// A wrong password on the persistent RAR4 AES route: RAR 3.x AES has no check value, so the member decrypts to
/// garbage and the session fails on its final CRC-32. No member finishes, so nothing is published: the in-place
/// partial output holds no decrypted bytes and is never reported complete.
#[test]
fn rar4_aes_stored_member_with_a_wrong_password_fails_its_crc_and_publishes_nothing() {
    let gold = gold(4000);
    let set = Set::aes_split(Naming::Parts, &gold, &[1008, 1008, 1008, 976], "pw");
    let dir = tempfile::tempdir().unwrap();
    let mut session = session_with(&set, dir.path(), &Arc::default(), Some("wrong"));
    let mut outcomes = Vec::new();
    let failure = loop {
        match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Pending => continue,
            Poll::Ready(Err(failure)) => break failure,
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) => break failure,
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { outcome, .. }))) => outcomes.push(outcome),
            Poll::Ready(Ok(None)) => panic!("a wrong password must fail the session"),
            _ => {}
        }
    };
    let FailureKind::Rar(rar) = &failure.kind else { panic!("not a RAR integrity failure: {failure:?}") };
    let detail = format!("{rar:?}");
    assert!(
        detail.contains("EncryptedIntegrity") && detail.contains("crc32: true"),
        "the member CRC-32 must fail: {detail}"
    );
    assert!(outcomes.is_empty(), "no member may finish: {:?}", outcomes.iter().map(describe).collect::<Vec<_>>());
    let out = dir.path().join("out").join("movie.mkv");
    assert!(fs::read(&out).ok().is_none_or(|bytes| bytes != gold));
}

/// A session over 200 members: each member's core is released once it finished and its handle was taken, so
/// neither the state page budget nor the descriptors held (`open_files`) grow with the number of members.
#[test]
fn a_session_with_200_members_releases_finished_members() {
    let data: Vec<(Vec<u8>, Vec<u8>)> = (0..200).map(|i| (format!("m{i:03}.bin").into_bytes(), gold(64 + i))).collect();
    let members: Vec<(&[u8], &[u8])> = data.iter().map(|(n, d)| (n.as_slice(), d.as_slice())).collect();
    let set = Set::single(&members);
    let dir = tempfile::tempdir().unwrap();
    let mut session = ProgressiveSession::new_partial(
        Box::new(set.provider()),
        options(&dir.path().join("out"), set.naming.name(0)),
        {
            // Caps that hold two members at a time: 200 pass only if each finished member's pages, descriptors
            // and lease come back.
            let mut partial = partial_options(&dir.path().join("state"), Arc::default());
            partial.limits.state_pages = 8;
            partial.limits.open_files = 14;
            partial.limits.open_partials = 2;
            partial
        },
    )
    .unwrap();
    let mut held: Option<(MemberKey, PartialFile)> = None;
    let mut released: Vec<MemberKey> = Vec::new();
    let mut finished = 0;
    // (protection path bytes, metadata bytes) charged to the session after the 10th member.
    let mut after_ten = None;
    loop {
        match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Pending => continue,
            Poll::Ready(Ok(Some(ProgressiveEvent::PartialReady { member, .. }))) => {
                held = Some((member.clone(), session.partial_file(&member).unwrap()));
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { outcome, .. }))) => {
                assert!(matches!(outcome, MemberOutcome::PersistentComplete { verdict: Verdict::Ok { .. }, .. }));
                let (key, file) = held.take().unwrap();
                // While a handle lives, the session hands out more; once the last is dropped the core is gone.
                let again = session.partial_file(&key).unwrap();
                drop((file, again));
                released.push(key);
                finished += 1;
                let used = |resource| session.resource_usage(resource).used;
                if finished == 10 {
                    after_ten = Some((used(Resource::ProtectionPathBytes), used(Resource::MetadataBytes)));
                }
            }
            Poll::Ready(Ok(None)) => break,
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) => panic!("{failure:?}"),
            Poll::Ready(Err(e)) => panic!("{e:?}"),
            _ => {}
        }
    }
    assert_eq!(finished, 200);
    // A released member's memory charges come back: protection paths are flat, and metadata grows only by the
    // progressive walk's own per-member bookkeeping (names, parts, frames: under 4 KB a member, as in any
    // session), not by the ~22 KB a member's core charges.
    let (paths, metadata) = after_ten.unwrap();
    assert_eq!(session.resource_usage(Resource::ProtectionPathBytes).used, paths);
    let growth = session.resource_usage(Resource::MetadataBytes).used - metadata;
    assert!(growth < 190 * 4096, "metadata grew {growth} bytes over 190 members");
    // The caps above bound the descriptors and pages held at any time (a process-wide descriptor count is not
    // used: tests running in parallel open their own).
    let Err(error) = session.partial_file(&released[0]) else { panic!("a released member has no core left") };
    assert!(matches!(error.kind, PartialErrorKind::BindingMismatch(BindingField::Member)), "{error:?}");
    for (name, bytes) in &data {
        assert_eq!(fs::read(dir.path().join("out").join(std::str::from_utf8(name).unwrap())).unwrap(), *bytes);
    }
}

/// Damage declared on a released member's bytes is reported under `released`, never as harmless `unmapped`
/// bytes, and the member can then be reopened and the damage declared there.
#[test]
fn damage_on_a_released_member_is_reported_as_released() {
    let (x, y) = (gold(1500), gold(900));
    let set = Set::single(&[(b"x.bin", &x), (b"y.bin", &y)]);
    let dir = tempfile::tempdir().unwrap();
    let anchors = Arc::new(Anchors::default());
    let mut session = ProgressiveSession::new_partial(
        Box::new(set.provider()),
        options(&dir.path().join("out"), set.naming.name(0)),
        partial_options(&dir.path().join("state"), anchors.clone()),
    )
    .unwrap();
    let mut first: Option<(MemberKey, PartialFile)> = None;
    let mut released = None;
    loop {
        match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Pending => continue,
            Poll::Ready(Ok(Some(ProgressiveEvent::PartialReady { member, .. }))) if first.is_none() => {
                first = Some((member.clone(), session.partial_file(&member).unwrap()));
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { .. }))) if released.is_none() => {
                // Closing the only handle releases the member; keep its state to reopen it.
                let (key, file) = first.take().unwrap();
                released = Some((key, file.close().unwrap()));
            }
            Poll::Ready(Ok(None)) => break,
            Poll::Ready(Err(e)) => panic!("{e:?}"),
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) => panic!("{failure:?}"),
            _ => {}
        }
    }
    let (key, state) = released.unwrap();
    let payload = set.payloads[0].clone();
    let damaged = payload.start + 100..payload.start + 200;
    let receipt = session.declare_hole(0, damaged.clone()).unwrap();
    assert!(receipt.holes.is_empty());
    assert!(receipt.unmapped.is_empty(), "{:?}", receipt.unmapped);
    assert_eq!(receipt.released.len(), 1);
    assert_eq!(receipt.released[0].0, key);
    assert_eq!((receipt.released[0].1.volume, receipt.released[0].1.range.clone()), (0, damaged.clone()));
    // Header bytes stay unmapped.
    let header = session.declare_hole(0, 0..8).unwrap();
    assert!(header.released.is_empty() && !header.unmapped.is_empty());
    drop(session);
    let expected_anchor = anchors.current(&key).unwrap().unwrap();
    let mut file = PartialFile::open(
        partial_state::roundtrip(&state),
        PartialOpenContext {
            output_root: dir.path().join("out"),
            state_root: dir.path().join("state"),
            expected_member: key,
            expected_anchor,
            protection: set.protection(),
            limits: PartialLimits::default(),
            progressive_limits: ProgressiveLimits::default(),
            anchors,
            control: SessionControl::default(),
            password: None,
        },
    )
    .unwrap();
    let holes = file.declare_hole(0, damaged).unwrap();
    assert_eq!(holes.iter().map(|h| h.out.clone()).collect::<Vec<_>>(), vec![100..200]);
}

/// Stores 0 as the file header CRC of `volume`'s part, as a caller that rebuilt the volume before knowing its packed
/// bytes does, and re-seals the header's own CRC.
fn zero_part_crc(set: &mut Set, volume: usize) {
    // signature (7) + main header (13): the file header starts at 20; its CRC field follows the 7-byte block
    // header, packed and unpacked sizes and the host byte.
    let start = SIG.len() + 13;
    let wire = &mut set.volumes[volume];
    assert_eq!(wire[start + 2], 0x74);
    let size = u16::from_le_bytes([wire[start + 5], wire[start + 6]]) as usize;
    wire[start + 16..start + 20].copy_from_slice(&0u32.to_le_bytes());
    let crc = hash(&wire[start + 2..start + size]) as u16;
    wire[start..start + 2].copy_from_slice(&crc.to_le_bytes());
}

/// Every event of a persistent session over `set`, ending with the error that stopped it, if any.
fn events_with(set: &Set, unknown_part_crc: bool) -> (Run, Option<String>) {
    let dir = tempfile::tempdir().unwrap();
    let anchors = Arc::new(Anchors::default());
    let mut options = options(&dir.path().join("out"), set.naming.name(0));
    options.rar4_unknown_part_crc = unknown_part_crc;
    let mut session = ProgressiveSession::new_partial(
        Box::new(set.provider()),
        options,
        partial_options(&dir.path().join("state"), anchors.clone()),
    )
    .unwrap();
    let (mut holes, mut parts, mut files, mut outcomes) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let mut failure = None;
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
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure: f, .. }))) => {
                failure = Some(format!("{f:?}"));
            }
            Poll::Ready(Err(e)) => {
                failure = Some(format!("{e:?}"));
                break;
            }
            Poll::Ready(Ok(None)) => break,
            _ => {}
        }
    }
    let protection = set.protection();
    (Run { dir, session, holes, parts, files, outcomes, anchors, protection }, failure)
}

/// Three volumes of 1000 bytes; the middle part stores 0 for its CRC and output 1100..1400 is a hole in it.
fn unknown_middle_crc() -> (Vec<u8>, Set) {
    let gold = gold(3000);
    let mut set = Set::split(Naming::Old, &gold, &[1000, 2000]);
    zero_part_crc(&mut set, 1);
    let p1 = set.payloads[1].clone();
    set.hole(1, p1.start + 100..p1.start + 400);
    (gold, set)
}

fn described(outcomes: &[MemberOutcome]) -> Vec<&'static str> {
    outcomes.iter().map(describe).collect()
}

fn refill_volume(file: &mut PartialFile, set: &Set, volume: usize) -> PackedFillResult {
    let mut reader = std::io::Cursor::new(set.volumes[volume].clone());
    file.refill_from_packed(volume as u32, 0..set.volumes[volume].len() as u64, &mut reader).unwrap()
}

#[test]
fn an_opted_in_middle_part_with_an_unknown_crc_extracts_with_holes_and_verifies_after_refill() {
    let (gold, set) = unknown_middle_crc();
    let (mut run, failure) = events_with(&set, true);
    assert_eq!(failure, None);
    let p1 = set.payloads[1].clone();
    assert_eq!(reports(&run.holes), vec![(1100..1400, vec![(1, p1.start + 100..p1.start + 400)], HoleCause::Missing)]);
    // The first part is checked as it is produced; the middle part has no check to run.
    assert_eq!(run.parts, vec![(0, 0)]);
    assert!(matches!(run.outcomes[..], [MemberOutcome::PersistentPartial { .. }]), "{:?}", described(&run.outcomes));
    let file = &mut run.files[0].1;
    let Verdict::Incomplete { parts, .. } = verify(file) else { panic!("holes remain") };
    assert_eq!(
        parts.iter().map(|p| (p.volume, p.crc32.clone())).collect::<Vec<_>>(),
        [(0, CheckResult::Passed), (1, CheckResult::Missing), (2, CheckResult::Pending)]
    );
    let refilled = refill_volume(file, &set, 1);
    assert_eq!(refilled.applied, vec![1100..1400]);
    assert!(file.remaining().unwrap().is_empty());
    assert!(matches!(verify(file), Verdict::Ok { .. }), "the member CRC in the final part verifies the whole file");
    assert_eq!(fs::read(run.out().join("big.bin")).unwrap(), gold);
}

#[test]
fn an_unknown_part_crc_survives_reopening_the_state() {
    let (gold, set) = unknown_middle_crc();
    let (run, failure) = events_with(&set, true);
    assert_eq!(failure, None);
    let (dir, mut file) = reopen(run, 0).unwrap();
    refill_volume(&mut file, &set, 1);
    assert!(matches!(verify(&mut file), Verdict::Ok { .. }));
    assert_eq!(fs::read(dir.path().join("out").join("big.bin")).unwrap(), gold);
}

#[test]
fn an_opted_in_part_still_fails_its_member_check_when_the_bytes_are_wrong() {
    let (gold, set) = unknown_middle_crc();
    let (mut run, _) = events_with(&set, true);
    let file = &mut run.files[0].1;
    let mut wrong = gold[1100..1400].to_vec();
    wrong[7] ^= 1;
    file.fill(1100, &wrong).unwrap();
    assert!(matches!(verify(file), Verdict::Bad { which: ChecksumAlgorithm::Crc32, .. }), "member CRC catches it");
}

#[test]
fn without_opting_in_a_zero_part_crc_is_a_part_crc_mismatch() {
    let gold = gold(3000);
    let mut set = Set::split(Naming::Old, &gold, &[1000, 2000]);
    zero_part_crc(&mut set, 1);
    let (mut run, failure) = events_with(&set, false);
    // The default is unchanged: the part CRC is checked. A part failing it is damage the session places on that
    // part (a DeclaredBad hole over its output), and the member finishes with it.
    assert_eq!(failure, None);
    let p1 = set.payloads[1].clone();
    assert_eq!(reports(&run.holes), vec![(1000..2000, vec![(1, p1)], HoleCause::DeclaredBad)]);
    assert_eq!(described(&run.outcomes), ["partial"]);
    // Its bytes are right, so a refill from the volume writes them back, and the stored 0 still fails the part.
    let file = &mut run.files[0].1;
    refill_volume(file, &set, 1);
    assert!(file.remaining().unwrap().is_empty());
    assert!(matches!(verify(file), Verdict::PartBad { volume: 1, .. }));
}

#[test]
fn opting_in_never_skips_the_member_check_in_the_final_part() {
    let gold = gold(3000);
    let mut set = Set::split(Naming::Old, &gold, &[1000, 2000]);
    zero_part_crc(&mut set, 2);
    let (mut run, failure) = events_with(&set, true);
    // The final part's CRC is the member check, and it fails. Both parts before it passed their own CRCs, so the
    // session places the damage on the final part (a DeclaredBad hole) instead of ending.
    assert_eq!(failure, None);
    assert_eq!(run.parts, vec![(0, 0), (1, 1)]);
    let p2 = set.payloads[2].clone();
    assert_eq!(reports(&run.holes), vec![(2000..3000, vec![(2, p2)], HoleCause::DeclaredBad)]);
    assert_eq!(described(&run.outcomes), ["partial"]);
    let file = &mut run.files[0].1;
    refill_volume(file, &set, 2);
    assert!(matches!(verify(file), Verdict::Bad { which: ChecksumAlgorithm::Crc32, .. }), "member CRC still judged");
}

/// [`session`] with [`ProgressiveOptions::rar4_unknown_part_crc`] set.
fn session_unknown_part_crc(set: &Set, dir: &Path, anchors: &Arc<Anchors>) -> ProgressiveSession {
    let mut opts = options(&dir.join("out"), set.naming.name(0));
    opts.rar4_unknown_part_crc = true;
    opts.limits.read_chunk = 300;
    let mut partial = partial_options(&dir.join("state"), anchors.clone());
    partial.limits.group_commit_bytes = 0;
    ProgressiveSession::new_partial(Box::new(set.provider()), opts, partial).unwrap()
}

#[test]
fn a_restarted_session_that_keeps_the_option_resumes_at_every_crash_point() {
    for holes in [false, true] {
        let gold = gold(3000);
        let mut set = Set::split(Naming::Old, &gold, &[1000, 2000]);
        zero_part_crc(&mut set, 1);
        if holes {
            let p1 = set.payloads[1].clone();
            set.hole(1, p1.start + 100..p1.start + 400);
        }
        let total = {
            let dir = tempfile::tempdir().unwrap();
            let mut seen = Seen::default();
            assert!(run(&mut session_unknown_part_crc(&set, dir.path(), &Arc::default()), &mut seen, None));
            seen.events
        };
        for crash_at in 1..total {
            let dir = tempfile::tempdir().unwrap();
            let anchors = Arc::new(Anchors::default());
            let mut first = session_unknown_part_crc(&set, dir.path(), &anchors);
            let mut before = Seen::default();
            assert!(!run(&mut first, &mut before, Some(crash_at)));
            crash((first, std::mem::take(&mut before.files)));
            let mut second = session_unknown_part_crc(&set, dir.path(), &anchors);
            let mut after = Seen::default();
            assert!(run(&mut second, &mut after, None), "crash at {crash_at}, holes {holes}");
            let outcomes = described(&after.outcomes);
            if holes {
                assert_eq!(outcomes, ["partial"], "crash at {crash_at}");
            } else {
                assert_eq!(outcomes, ["complete, verified"], "crash at {crash_at}");
                assert_eq!(fs::read(dir.path().join("out").join("big.bin")).unwrap(), gold, "crash at {crash_at}");
            }
        }
    }
}

/// RustyGet's case: the whole data area of a large middle volume is answered as holes, one read buffer per Hole.
/// Each hole used to be charged a copy of the member's whole known-output index, so the session ran out of
/// MetadataBytes; now the session finishes within the default limits, the stored holes collapse to one range, and
/// a refill from the repaired volume verifies.
#[test]
fn a_volume_answered_entirely_as_holes_stays_within_default_limits_and_refills() {
    const MIB: usize = 1 << 20;
    // 16 MiB of output before the holes: the old per-hole charge grew with it.
    let gold = gold(127 * MIB);
    let mut set = Set::split(Naming::Old, &gold, &[16 * MIB, 126 * MIB]);
    let p1 = set.payloads[1].clone();
    set.hole(1, p1.clone());
    let dir = tempfile::tempdir().unwrap();
    let anchors = Arc::new(Anchors::default());
    let mut session = ProgressiveSession::new_partial(
        Box::new(set.provider()),
        options(&dir.path().join("out"), set.naming.name(0)),
        partial_options(&dir.path().join("state"), anchors.clone()),
    )
    .unwrap();
    let (mut holes, mut files, mut at_tenth) = (0usize, Vec::new(), 0);
    let mut last = 0;
    loop {
        match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Ok(Some(ProgressiveEvent::PartialReady { member, .. }))) => {
                files.push(session.partial_file(&member).unwrap())
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::Hole(_)))) => {
                holes += 1;
                last = session.resource_usage(Resource::MetadataBytes).used;
                if holes == 10 {
                    at_tenth = last;
                }
            }
            Poll::Ready(Ok(None)) => break,
            Poll::Ready(Err(e)) => panic!("{e:?}"),
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) => panic!("{failure:?}"),
            _ => {}
        }
    }
    // One Hole per read buffer, so the 110 MiB range arrives as about 110 holes.
    assert!(holes >= 100, "{holes} holes");
    // Each hole used to cost a copy of the member's known-output index, more with every MiB already produced;
    // now a hole adds a small, fixed amount of bookkeeping.
    let per_hole = (last - at_tenth) / (holes as u64 - 10);
    assert!(per_hole < 8 << 10, "{per_hole} metadata bytes per hole");
    let metadata = session.resource_usage(Resource::MetadataBytes);
    assert!(metadata.used < metadata.limit / 16, "{metadata:?}");
    let file = &mut files[0];
    assert_eq!(file.remaining().unwrap(), vec![16 * MIB as u64..126 * MIB as u64]);
    let mut reader = std::io::Cursor::new(set.volumes[1].clone());
    file.refill_from_packed(1, 0..set.volumes[1].len() as u64, &mut reader).unwrap();
    assert!(file.remaining().unwrap().is_empty());
    assert!(matches!(verify(file), Verdict::Ok { .. }));
    assert_eq!(fs::read(dir.path().join("out").join("big.bin")).unwrap(), gold);
}

/// Holes scattered through an encrypted member keep the ciphertext block before each one (CBC needs it later), so
/// each hole also updates the kept-block list. Recording one must still cost the same however many came before:
/// the list's copy for each transaction used to be charged for good, so the cost of a hole grew with the number of
/// earlier holes until the session ran out of MetadataBytes.
#[test]
fn scattered_holes_in_an_encrypted_member_cost_the_same_however_many_came_before() {
    const RANGES: u64 = 150;
    let gold = gold(RANGES as usize * 2048);
    let mut set = Set::aes_split(Naming::Old, &gold, &[gold.len()], "secret");
    let p0 = set.payloads[0].clone();
    for i in 0..RANGES {
        // 40 bytes, not on a 16-byte block boundary, like a missing article.
        let start = p0.start + i * 2048 + 5;
        set.hole(0, start..start + 40);
    }
    let dir = tempfile::tempdir().unwrap();
    let anchors = Arc::new(Anchors::default());
    let mut session = session_with(&set, dir.path(), &anchors, Some("secret"));
    let mut costs = Vec::new();
    let mut last = session.resource_usage(Resource::MetadataBytes).used as i64;
    loop {
        match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Ok(Some(ProgressiveEvent::Hole(_)))) => {
                let now = session.resource_usage(Resource::MetadataBytes).used as i64;
                costs.push(now - last);
                last = now;
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::BytesWritten { .. }))) => {
                last = session.resource_usage(Resource::MetadataBytes).used as i64;
            }
            Poll::Ready(Ok(None)) => break,
            Poll::Ready(Err(e)) => panic!("{e:?}"),
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) => panic!("{failure:?}"),
            _ => {}
        }
    }
    assert!(costs.len() as u64 >= RANGES, "{} hole events", costs.len());
    let window = 30;
    let early = costs[10..10 + window].iter().sum::<i64>() / window as i64;
    let late = costs[costs.len() - window..].iter().sum::<i64>() / window as i64;
    assert!(late <= early + 512, "a hole cost {early} bytes early and {late} late, after {} holes", costs.len());
}

/// RustyGet patches holes inline: on each `Hole` event it refills that range with `refill_from_packed` while the
/// session goes on. Each refill re-judges the part checks it may complete. Part results used to be dropped by
/// every streaming write, and each leaf combine charged at the leaf's length, so every patch re-combined (and was
/// charged for) every complete part before it. Now untouched parts keep their results: a patch costs about its
/// own bytes, and later patches, with more verified output behind them, cost no more than early ones.
#[test]
fn an_inline_patch_costs_verify_work_for_its_own_bytes_only() {
    const MIB: usize = 1 << 20;
    const VOLUMES: usize = 12;
    let gold = gold(VOLUMES * 4 * MIB);
    let cuts: Vec<usize> = (1..VOLUMES).map(|v| v * 4 * MIB).collect();
    let mut set = Set::split(Naming::Old, &gold, &cuts);
    // A 256 KiB hole in every volume from the third on: each patch comes after one more complete part.
    for v in 2..VOLUMES {
        let p = set.payloads[v].clone();
        set.hole(v, p.start + MIB as u64..p.start + MIB as u64 + 256 * 1024);
    }
    let dir = tempfile::tempdir().unwrap();
    let anchors = Arc::new(Anchors::default());
    let mut session = ProgressiveSession::new_partial(
        Box::new(set.provider()),
        options(&dir.path().join("out"), set.naming.name(0)),
        partial_options(&dir.path().join("state"), anchors.clone()),
    )
    .unwrap();
    let (mut files, mut costs) = (Vec::new(), Vec::new());
    loop {
        match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Ok(Some(ProgressiveEvent::PartialReady { member, .. }))) => {
                files.push(session.partial_file(&member).unwrap())
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::Hole(report)))) => {
                let before = session.resource_usage(Resource::VerifyWorkBytes).used;
                let span = report.packed[0].clone();
                let mut reader = std::io::Cursor::new(set.volumes[span.volume as usize].clone());
                files[0].refill_from_packed(span.volume, span.range.clone(), &mut reader).unwrap();
                let cost = session.resource_usage(Resource::VerifyWorkBytes).used - before;
                let patched = span.range.end - span.range.start;
                // The patched bytes are hashed (and compared) once; nothing scales with the member.
                assert!(cost <= 2 * patched + 16 * 1024, "a {patched}-byte patch cost {cost} bytes of verify work");
                costs.push(cost);
            }
            Poll::Ready(Ok(None)) => break,
            Poll::Ready(Err(e)) => panic!("{e:?}"),
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) => panic!("{failure:?}"),
            _ => {}
        }
    }
    assert!(costs.len() >= VOLUMES - 2, "{} patches", costs.len());
    let (first, last) = (costs[0], *costs.last().unwrap());
    assert!(last <= first + 1024, "the first patch cost {first} and the last {last} after more verified output");
    let file = &mut files[0];
    assert!(file.remaining().unwrap().is_empty());
    assert!(matches!(verify(file), Verdict::Ok { .. }));
    assert_eq!(fs::read(dir.path().join("out").join("big.bin")).unwrap(), gold);
}

/// RustyGet's inline patching: three dead middle volumes are answered entirely as holes, one read buffer per
/// Hole, and once a volume's holes are all reported each hole range is refilled with its own `refill_from_packed`
/// call while the session keeps extracting. Output grows between the refills. With `password` the member is RAR4
/// AES, so every refill also decrypts.
fn inline_refills_of_dead_volumes(volumes: usize, volume_mib: usize, password: Option<&str>) {
    const MIB: usize = 1 << 20;
    let gold = gold(volumes * volume_mib * MIB);
    let mut set = match password {
        None => {
            let cuts: Vec<usize> = (1..volumes).map(|v| v * volume_mib * MIB).collect();
            Set::split(Naming::Old, &gold, &cuts)
        }
        Some(password) => Set::aes_split(Naming::Old, &gold, &vec![volume_mib * MIB; volumes], password),
    };
    let dead = [volumes * 7 / 23, volumes * 13 / 23, volumes * 14 / 23];
    for &d in &dead {
        let p = set.payloads[d].clone();
        set.hole(d, p);
    }
    let dir = tempfile::tempdir().unwrap();
    let anchors = Arc::new(Anchors::default());
    let mut opts = options(&dir.path().join("out"), set.naming.name(0));
    opts.set_password(password.map(String::from)).unwrap();
    let mut session = ProgressiveSession::new_partial(
        Box::new(set.provider()),
        opts,
        partial_options(&dir.path().join("state"), anchors.clone()),
    )
    .unwrap();
    let used = |s: &ProgressiveSession| s.resource_usage(Resource::MetadataBytes).used as i64;
    let mut files: Vec<PartialFile> = Vec::new();
    // Hole spans reported per volume not yet refilled, and the bytes reported per volume.
    let mut pending: Vec<Vec<PackedSpan>> = vec![Vec::new(); volumes];
    let mut seen = vec![0u64; volumes];
    let mut costs = Vec::new();
    let mut refill = |files: &mut Vec<PartialFile>, session: &ProgressiveSession, spans: Vec<PackedSpan>| {
        for span in spans {
            let before = used(session);
            let mut reader = std::io::Cursor::new(set.volumes[span.volume as usize].as_slice());
            files[0].refill_from_packed(span.volume, span.range.clone(), &mut reader).unwrap();
            costs.push(used(session) - before);
        }
    };
    loop {
        let event = session.poll_event(&mut Context::from_waker(Waker::noop()));
        // A volume is patched once all its holes are reported; an encrypted member's neighbour-block report can
        // come later, and is patched on the next poll.
        for v in 0..volumes {
            // An encrypted member also reports the next volume's first block (its previous block is in this
            // volume): wait for it, so the refill keeps the ciphertext block it needs.
            let neighbour = password.is_none() || v + 1 == volumes || seen[v + 1] > 0;
            if !pending[v].is_empty() && neighbour && seen[v] >= set.payloads[v].end - set.payloads[v].start {
                let spans = std::mem::take(&mut pending[v]);
                refill(&mut files, &session, spans);
            }
        }
        match event {
            Poll::Ready(Ok(Some(ProgressiveEvent::PartialReady { member, .. }))) => {
                files.push(session.partial_file(&member).unwrap())
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::Hole(report)))) => {
                for span in &report.packed {
                    let v = span.volume as usize;
                    seen[v] += span.range.end - span.range.start;
                    pending[v].push(span.clone());
                }
            }
            Poll::Ready(Ok(None)) => break,
            Poll::Ready(Err(e)) => panic!("{e:?}"),
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) => panic!("{failure:?}"),
            _ => {}
        }
    }
    for spans in std::mem::take(&mut pending) {
        refill(&mut files, &session, spans);
    }
    drop(refill);
    assert!(costs.len() >= 3 * volume_mib, "{} refills: one per hole, a hole per read buffer", costs.len());
    // A refill of a hole range costs metadata for the bytes it adds to the known index (a few KiB per MiB), not a
    // read or decryption buffer, nor anything that grows with the member, its holes or earlier refills.
    let mean = |c: &[i64]| c.iter().sum::<i64>() / c.len() as i64;
    let per_call = mean(&costs);
    assert!(per_call < 12 << 10, "a 1 MiB refill cost {per_call} metadata bytes");
    // Refills that found nothing left to fill cost nothing; compare the ones that filled.
    let filled: Vec<i64> = costs.iter().copied().filter(|&c| c > 0).collect();
    let (early, late) = (mean(&filled[..8]), mean(&filled[filled.len() - 8..]));
    assert!(late <= early + 2048, "refills cost {early} metadata bytes early and {late} late");
    let metadata = session.resource_usage(Resource::MetadataBytes);
    assert!(metadata.used < metadata.limit / 4, "{metadata:?}");
    let file = &mut files[0];
    assert!(file.remaining().unwrap().is_empty());
    assert!(matches!(verify(file), Verdict::Ok { .. }));
    let name = if password.is_some() { "movie.mkv" } else { "big.bin" };
    assert_eq!(fs::read(dir.path().join("out").join(name)).unwrap(), gold);
}

#[test]
fn dead_volumes_refilled_inline_one_hole_at_a_time_cost_metadata_for_their_bytes_only() {
    inline_refills_of_dead_volumes(23, 8, None);
}

#[test]
fn encrypted_dead_volumes_refilled_inline_one_hole_at_a_time_cost_metadata_for_their_bytes_only() {
    inline_refills_of_dead_volumes(23, 8, Some("secret"));
}

/// [`inline_refills_of_dead_volumes`] at RustyGet's scale: about 2 GB in 23 volumes of 88 MiB, 264 holes and
/// refills, plain and encrypted. Slow and about 9 GB of memory; run with `cargo test --release -- --ignored`.
#[test]
#[ignore]
fn dead_volumes_refilled_inline_at_full_scale_stay_within_default_limits() {
    inline_refills_of_dead_volumes(23, 88, None);
    inline_refills_of_dead_volumes(23, 88, Some("secret"));
}

/// Runs a three-volume set whose middle volume's whole data area is one hole and returns the `Hole` events, the
/// session's final MetadataBytes, the member state's sequence (one per durable transaction), the member's handle and
/// the session's directory.
fn dead_middle_volume(
    set: &Set,
    password: Option<&str>,
) -> (Vec<HoleReport>, u64, u64, PartialFile, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let mut opts = options(&dir.path().join("out"), set.naming.name(0));
    opts.set_password(password.map(String::from)).unwrap();
    let mut session = ProgressiveSession::new_partial(
        Box::new(set.provider()),
        opts,
        partial_options(&dir.path().join("state"), Arc::default()),
    )
    .unwrap();
    let (mut holes, mut files) = (Vec::new(), Vec::new());
    loop {
        match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Ok(Some(ProgressiveEvent::PartialReady { member, .. }))) => {
                files.push(session.partial_file(&member).unwrap())
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::Hole(report)))) => holes.push(report),
            Poll::Ready(Ok(None)) => break,
            Poll::Ready(Err(e)) => panic!("{e:?}"),
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) => panic!("{failure:?}"),
            _ => {}
        }
    }
    let used = session.resource_usage(Resource::MetadataBytes).used;
    let file = files.pop().unwrap();
    let sequence = file.state().unwrap().anchor().sequence();
    (holes, used, sequence, file, dir)
}

/// RustyGet's dead volume, answered once: the source answers the middle volume's whole data area (92 MiB) with one
/// `RangeRead::Hole`, longer than any read buffer. The session records it as one hole and one event, without the
/// per-event journal bookkeeping of one answer per buffer, and refilling it in pieces verifies.
#[test]
fn a_dead_volume_answered_with_one_hole_is_one_record_and_one_event_and_refills_in_pieces() {
    const MIB: usize = 1 << 20;
    for password in [None, Some("secret")] {
        let gold = gold(110 * MIB);
        let mut set = match password {
            None => Set::split(Naming::Old, &gold, &[8 * MIB, 100 * MIB]),
            Some(p) => Set::aes_split(Naming::Old, &gold, &[8 * MIB, 92 * MIB, 10 * MIB], p),
        };
        let p1 = set.payloads[1].clone();
        set.hole(1, p1.clone());
        let (buffered, buffered_used, buffered_sequence, _, _) = dead_middle_volume(&set, password);
        set.long_holes = true;
        let (holes, used, sequence, mut file, dir) = dead_middle_volume(&set, password);
        // One event for the dead volume's range (an encrypted member also reports the next volume's first block,
        // whose previous ciphertext block is in the dead volume).
        let dead: Vec<_> = holes.iter().filter(|h| h.packed.iter().any(|s| s.volume == 1)).collect();
        assert_eq!(dead.len(), 1, "{password:?}: {holes:?}");
        assert_eq!(dead[0].packed, vec![PackedSpan { volume: 1, range: p1.clone() }], "{password:?}");
        assert!(holes.len() <= 2, "{password:?}: {holes:?}");
        assert!(buffered.len() >= 92, "{password:?}: {} events one buffer per Hole", buffered.len());
        // One buffer per Hole commits a transaction per event; one answer commits once.
        assert!(
            sequence + 80 < buffered_sequence,
            "{password:?}: {sequence} transactions, {buffered_sequence} buffered"
        );
        assert!(used < buffered_used, "{password:?}: {used} metadata bytes, {buffered_used} buffered");
        // One unknown output range: the next volume's first block, if reported, adjoins the dead range.
        assert_eq!(file.remaining().unwrap().len(), 1, "{password:?}");
        // Refill the dead volume in 7 MiB pieces, then whatever the next volume's first block still needs.
        let volume = set.volumes[1].clone();
        let mut at = 0;
        while at < volume.len() as u64 {
            let end = (at + 7 * MIB as u64).min(volume.len() as u64);
            file.refill_from_packed(1, at..end, &mut std::io::Cursor::new(volume.as_slice())).unwrap();
            at = end;
        }
        for hole in holes.iter().filter(|h| h.packed.iter().all(|s| s.volume != 1)) {
            let span = &hole.packed[0];
            let bytes = set.volumes[span.volume as usize].as_slice();
            file.refill_from_packed(span.volume, span.range.clone(), &mut std::io::Cursor::new(bytes)).unwrap();
        }
        assert!(file.remaining().unwrap().is_empty(), "{password:?}");
        assert!(matches!(verify(&mut file), Verdict::Ok { .. }), "{password:?}");
        let name = if password.is_some() { "movie.mkv" } else { "big.bin" };
        assert_eq!(fs::read(dir.path().join("out").join(name)).unwrap(), gold, "{password:?}");
    }
}

/// A `Hole` longer than the buffer is accepted only by a persistent session reading member data: an ordinary
/// session still fails it as a source contract violation.
#[test]
fn an_ordinary_session_still_refuses_a_hole_longer_than_its_buffer() {
    let gold = gold(3 << 20);
    let mut set = Set::split(Naming::Old, &gold, &[1 << 20, 2 << 20]);
    set.long_holes = true;
    let p1 = set.payloads[1].clone();
    set.hole(1, p1);
    let dir = tempfile::tempdir().unwrap();
    let mut opts = options(&dir.path().join("out"), set.naming.name(0));
    opts.limits.read_chunk = 4096;
    let mut session = ProgressiveSession::new(Box::new(set.provider()), opts).unwrap();
    let failure = loop {
        match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) => break format!("{failure:?}"),
            Poll::Ready(Err(e)) => break format!("{e:?}"),
            Poll::Ready(Ok(None)) => panic!("finished"),
            _ => {}
        }
    };
    assert!(failure.contains("SourceContract"), "{failure}");
}

/// A long `Hole` inside the volume is trimmed to the part, but one that runs past the volume's end is still a
/// source contract violation.
#[test]
fn a_persistent_session_refuses_a_hole_past_the_end_of_the_volume() {
    let gold = gold(3 << 20);
    let mut set = Set::split(Naming::Old, &gold, &[1 << 20, 2 << 20]);
    set.long_holes = true;
    let p1 = set.payloads[1].clone();
    let end = set.volumes[1].len() as u64 + 100;
    set.hole(1, p1.start..end);
    let (run, failure) = events_with(&set, false);
    let failure = failure.expect("the long hole is refused");
    assert!(failure.contains("SourceContract"), "{failure}");
    assert!(run.holes.is_empty(), "{:?}", run.holes);
}
