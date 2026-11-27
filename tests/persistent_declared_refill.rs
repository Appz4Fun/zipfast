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

//! `PartialFile::refill_declared_from_packed`: a stored plain RAR5 part whose own CRC fails becomes a `DeclaredBad`
//! hole of the whole part; after the volume is repaired in place, refilling only the repaired slice closes it when
//! the part's check passes over the kept and repaired bytes (RustyGet request N3).
#![cfg(all(feature = "persistent-partials", any(target_os = "linux", target_os = "macos")))]
mod common;
use std::{
    ffi::OsString,
    fs::File,
    ops::Range,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
};
use zipfast::partial::*;
use zipfast::progressive::*;

/// Bytes per part: several 64 KiB leaves, the last one short.
const PART: usize = 200_000;
const PARTS: usize = 3;

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
    volumes: Vec<Option<Source>>,
    protection: ProtectionDeclaration,
}
impl VolumeSource for Provider {
    fn protection(&mut self) -> ProgressiveResult<ProtectionDeclaration> {
        Ok(self.protection.clone())
    }
    fn volume(&mut self, request: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
        Ok(VolumeAnswer::Ready(Box::new(self.volumes[request.index as usize].take().expect("one acquisition"))))
    }
}
fn volume_name(index: u32) -> OsString {
    format!("set.part{:02}.rar", index + 1).into()
}

/// One stored RAR5 member split over three volumes, one part each.
struct Fixture {
    data: Vec<u8>,
    /// The volumes as the repair leaves them (good bytes).
    good: Vec<Vec<u8>>,
    /// The volumes as downloaded (the damage applied).
    served: Vec<Vec<u8>>,
    /// Each volume's payload (the part's data) range.
    payloads: Vec<Range<u64>>,
    /// Ranges of each served volume the source answers as holes (missing articles).
    holes: Vec<Vec<Range<u64>>>,
}
impl Fixture {
    fn new() -> Self {
        let mut x = 0x1234_5678u32;
        let data: Vec<u8> = (0..PART * PARTS)
            .map(|_| {
                x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (x >> 24) as u8
            })
            .collect();
        let mut good = Vec::new();
        let mut payloads = Vec::new();
        for index in 0..PARTS {
            let out = index * PART..(index + 1) * PART;
            let spec = common::FileSpec::new("big.bin", &data);
            let last = index == PARTS - 1;
            let scope = if last { data.as_slice() } else { &data[out.clone()] };
            let file = common::file_block(&spec, &data[out.clone()], crc32fast::hash(scope), index != 0, !last);
            let mut bytes = common::SIG.to_vec();
            bytes.extend(common::main_block(true, Some(index as u64)));
            let start = bytes.len() + file.len() - PART;
            payloads.push(start as u64..(start + PART) as u64);
            bytes.extend(file);
            bytes.extend(common::end_block(!last));
            good.push(bytes);
        }
        let served = good.clone();
        Self { data, good, served, payloads, holes: vec![Vec::new(); PARTS] }
    }
    /// Flips a byte at `offset` of part `part`'s data in the served volume.
    fn damage(&mut self, part: usize, offset: usize) {
        self.served[part][self.payloads[part].start as usize + offset] ^= 0x5A;
    }
    fn provider(&self) -> Provider {
        let protection = ProtectionDeclaration::Complete {
            epoch: 1,
            inventory: ProtectionInventory {
                volumes: (0..PARTS as u32)
                    .map(|index| ProtectedVolume { index, name: volume_name(index), backing: VolumeBacking::NonFile })
                    .collect(),
                auxiliary_paths: Vec::new(),
            },
        };
        let volumes = (0..PARTS)
            .map(|i| Some(Source { index: i as u32, bytes: self.served[i].clone(), holes: self.holes[i].clone() }))
            .collect();
        Provider { volumes, protection }
    }
    /// Packed range of part `part`'s data bytes `range`.
    fn packed(&self, part: usize, range: Range<usize>) -> Range<u64> {
        let start = self.payloads[part].start;
        start + range.start as u64..start + range.end as u64
    }
}

fn options(dest: &Path) -> ProgressiveOptions {
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
        volume_name(0),
    );
    options.hole_policy = HolePolicy::PartialStored { fill: HoleFill::Sparse };
    options
}

/// An anchor store that can fail one later compare-exchange: before applying it, or after (an uncertain commit).
#[derive(Default)]
struct Anchors {
    anchors: Mutex<Vec<StateAnchor>>,
    calls: AtomicUsize,
    /// Fail the call with this number (counted from 1 by `calls`); 0 never.
    fail_at: AtomicUsize,
    apply_then_fail: std::sync::atomic::AtomicBool,
}
impl StateAnchorStore for Anchors {
    fn current(&self, member: &MemberKey) -> PartialResult<Option<StateAnchor>> {
        Ok(self.anchors.lock().unwrap().iter().find(|a| a.member() == member).cloned())
    }
    fn compare_exchange(
        &self,
        member: &MemberKey,
        expected: Option<&StateAnchor>,
        next: &StateAnchor,
    ) -> PartialResult<()> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        let fail = call == self.fail_at.load(Ordering::SeqCst);
        if fail && !self.apply_then_fail.load(Ordering::SeqCst) {
            return Err(PartialError::new(PartialErrorKind::AnchorCommitUncertain));
        }
        let mut anchors = self.anchors.lock().unwrap();
        let index = anchors.iter().position(|a| a.member() == member);
        if index.map(|i| &anchors[i]) != expected {
            return Err(PartialError::new(PartialErrorKind::AnchorConflict));
        }
        match index {
            Some(index) => anchors[index] = next.clone(),
            None => anchors.push(next.clone()),
        }
        if fail {
            return Err(PartialError::new(PartialErrorKind::AnchorCommitUncertain));
        }
        Ok(())
    }
}

/// A `Read + Seek` over volume bytes that records every byte range read.
struct CountingVolume {
    inner: std::io::Cursor<Vec<u8>>,
    reads: Vec<Range<u64>>,
    /// Fail with an I/O error once this many bytes were read.
    fail_after: Option<u64>,
}
impl CountingVolume {
    fn new(bytes: Vec<u8>) -> Self {
        Self { inner: std::io::Cursor::new(bytes), reads: Vec::new(), fail_after: None }
    }
    fn total(&self) -> u64 {
        self.reads.iter().map(|r| r.end - r.start).sum()
    }
}
impl std::io::Read for CountingVolume {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.fail_after.is_some_and(|limit| self.total() >= limit) {
            return Err(std::io::Error::other("injected volume read failure"));
        }
        let at = self.inner.position();
        let n = self.inner.read(buf)?;
        self.reads.push(at..at + n as u64);
        Ok(n)
    }
}
impl std::io::Seek for CountingVolume {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(pos)
    }
}

struct Run {
    _dir: tempfile::TempDir,
    dest: std::path::PathBuf,
    state_root: std::path::PathBuf,
    anchors: Arc<Anchors>,
    protection: ProtectionDeclaration,
    key: MemberKey,
    file: Option<PartialFile>,
    holes: Vec<HoleReport>,
}
/// Extracts the fixture with a persistent session to its end.
fn run(fixture: &Fixture) -> Run {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out");
    let state_root = dir.path().join("state");
    let anchors = Arc::new(Anchors::default());
    let partial = PartialOptions {
        binding: ArchiveBinding { job: [1; 16], archive: [2; 32] },
        naming: PartialNaming::ArchivePath,
        state_dir: state_root.clone(),
        limits: PartialLimits::default(),
        anchors: anchors.clone(),
        control: SessionControl::default(),
    };
    let provider = fixture.provider();
    let protection = provider.protection.clone();
    let mut session = ProgressiveSession::new_partial(Box::new(provider), options(&dest), partial).unwrap();
    let (mut holes, mut file) = (Vec::new(), None);
    for _ in 0..1_000_000 {
        match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Ok(Some(ProgressiveEvent::PartialReady { member, .. }))) => {
                file = Some((member.clone(), session.partial_file(&member).unwrap()))
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::Hole(report)))) => holes.push(report),
            Poll::Ready(Ok(None)) => {
                drop(session);
                let (key, file) = file.expect("one member");
                return Run { _dir: dir, dest, state_root, anchors, protection, key, file: Some(file), holes };
            }
            Poll::Ready(Err(e)) => panic!("{e:?}"),
            _ => {}
        }
    }
    panic!("session did not finish")
}
impl Run {
    /// Reopens the member from the state the anchor store holds, as a restarted process would.
    fn reopen(&mut self) {
        drop(self.file.take());
        let anchor = self.anchors.current(&self.key).unwrap().unwrap();
        let state = PartialState::load(&self.state_root, &anchor, &PartialLimits::default()).unwrap();
        self.file = Some(PartialFile::open(state, self.context(anchor)).unwrap());
    }
    fn file(&mut self) -> &mut PartialFile {
        self.file.as_mut().unwrap()
    }
    fn context(&self, expected_anchor: StateAnchor) -> PartialOpenContext {
        PartialOpenContext {
            output_root: self.dest.clone(),
            state_root: self.state_root.clone(),
            expected_member: self.key.clone(),
            expected_anchor,
            protection: self.protection.clone(),
            limits: PartialLimits::default(),
            progressive_limits: ProgressiveLimits::default(),
            anchors: self.anchors.clone(),
            control: SessionControl::default(),
            password: None,
        }
    }
    fn output(&self) -> Vec<u8> {
        std::fs::read(self.dest.join("big.bin")).unwrap()
    }
}

fn verify(file: &mut PartialFile) -> Verdict {
    for _ in 0..100_000 {
        if let Poll::Ready(result) = file.poll_verify(&mut Context::from_waker(Waker::noop())) {
            return result.unwrap();
        }
    }
    panic!("local verification failed to complete")
}
fn declared(run: &Run) -> (u32, Range<u64>) {
    let declared: Vec<_> = run.holes.iter().filter(|h| h.cause == HoleCause::DeclaredBad).collect();
    assert_eq!(declared.len(), 1, "one declared hole: {:?}", run.holes);
    assert_eq!(declared[0].packed.len(), 1);
    (declared[0].packed[0].volume, declared[0].packed[0].range.clone())
}
fn check_failed(error: &PartialError) -> Option<&[u64]> {
    match &error.kind {
        PartialErrorKind::DeclaredRefill(DeclaredRefillFailure::CheckFailed { parts }) => Some(parts),
        _ => None,
    }
}

/// Offset of the wrong byte in part 0, and the repaired slice around it (crossing 64 KiB leaf boundaries on both
/// sides, so the leaves it cuts keep their pieces outside it).
const BAD: usize = 100_000;
const SLICE: Range<usize> = 70_000..140_000;

#[test]
fn a_repaired_slice_closes_a_declared_part_reading_only_the_slice() {
    for reopen_first in [false, true] {
        let mut fixture = Fixture::new();
        fixture.damage(0, BAD);
        let mut run = run(&fixture);
        let (volume, hole) = declared(&run);
        assert_eq!((volume, hole.clone()), (0, fixture.payloads[0].clone()));
        assert_eq!(run.file().remaining().unwrap(), vec![0..PART as u64]);
        // The output under the hole is kept as the extraction wrote it.
        assert_eq!(run.output()[..PART], fixture.served[0][fixture.payloads[0].start as usize..][..PART]);
        if reopen_first {
            run.reopen();
        }
        let repaired = fixture.packed(0, SLICE);
        let mut reader = CountingVolume::new(fixture.good[0].clone());
        let result = run.file().refill_declared_from_packed(volume, hole, std::slice::from_ref(&repaired), &mut reader);
        let result = result.unwrap();
        assert_eq!(reader.total(), (SLICE.end - SLICE.start) as u64, "{reopen_first}");
        assert!(reader.reads.iter().all(|r| repaired.start <= r.start && r.end <= repaired.end));
        assert_eq!(result.applied, vec![0..PART as u64]);
        assert!(result.unmapped.is_empty());
        assert!(run.file().remaining().unwrap().is_empty());
        assert!(matches!(verify(run.file()), Verdict::Ok { .. }));
        assert_eq!(run.output(), fixture.data);
    }
}

#[test]
fn a_wrong_repair_keeps_the_hole_and_another_range_or_the_full_refill_closes_it() {
    for fallback in [false, true] {
        let mut fixture = Fixture::new();
        fixture.damage(0, BAD);
        let mut run = run(&fixture);
        let (volume, hole) = declared(&run);
        // A slice that misses the wrong byte: the part's CRC still fails, the hole stays.
        let wrong = fixture.packed(0, 150_000..190_000);
        let mut reader = CountingVolume::new(fixture.good[0].clone());
        let error = run
            .file()
            .refill_declared_from_packed(volume, hole.clone(), std::slice::from_ref(&wrong), &mut reader)
            .unwrap_err();
        assert_eq!(check_failed(&error), Some(&[0u64][..]), "{error:?}");
        assert_eq!(reader.total(), 40_000);
        assert_eq!(run.file().remaining().unwrap(), vec![0..PART as u64]);
        assert!(!matches!(verify(run.file()), Verdict::Ok { .. }));
        if fallback {
            // RustyGet's fallback: the whole hole from the repaired volume.
            run.file().refill_from_packed(volume, hole, &mut reader).unwrap();
        } else {
            // The right slice: only it is read (the first slice's bytes are kept now).
            let before = reader.total();
            let right = fixture.packed(0, 90_000..110_000);
            run.file().refill_declared_from_packed(volume, hole, std::slice::from_ref(&right), &mut reader).unwrap();
            assert_eq!(reader.total() - before, 20_000);
        }
        assert!(run.file().remaining().unwrap().is_empty());
        assert!(matches!(verify(run.file()), Verdict::Ok { .. }));
        assert_eq!(run.output(), fixture.data);
    }
}

#[test]
fn a_restart_at_any_point_of_a_refill_leaves_the_hole_or_closes_it() {
    // Each anchor compare-exchange of the refill fails in turn (before or after it applies, as a crash around it
    // would), then the member is reopened from what the anchor store holds; also a volume read that fails midway.
    let mut cases: Vec<(usize, bool, Option<u64>)> = Vec::new();
    for at in 1..=6 {
        cases.push((at, false, None));
        cases.push((at, true, None));
    }
    cases.push((0, false, Some(30_000)));
    for (fail_at, apply_then_fail, fail_after) in cases {
        let label = format!("{fail_at} {apply_then_fail} {fail_after:?}");
        let mut fixture = Fixture::new();
        fixture.damage(0, BAD);
        let mut run = run(&fixture);
        let (volume, hole) = declared(&run);
        let repaired = fixture.packed(0, SLICE);
        run.anchors.calls.store(0, Ordering::SeqCst);
        run.anchors.fail_at.store(fail_at, Ordering::SeqCst);
        run.anchors.apply_then_fail.store(apply_then_fail, Ordering::SeqCst);
        let mut reader = CountingVolume::new(fixture.good[0].clone());
        reader.fail_after = fail_after;
        let first =
            run.file().refill_declared_from_packed(volume, hole.clone(), std::slice::from_ref(&repaired), &mut reader);
        run.anchors.fail_at.store(0, Ordering::SeqCst);
        run.reopen();
        let remaining = run.file().remaining().unwrap();
        if remaining.is_empty() {
            // Closed: only by the commit that records the rebuilt leaves, so the output is right.
            assert!(first.is_ok() || apply_then_fail, "{label}: {first:?}");
        } else {
            assert_eq!(remaining, vec![0..PART as u64], "{label}");
            // A retry reads exactly the slice again: the kept leaves outside it survived the restart.
            let mut reader = CountingVolume::new(fixture.good[0].clone());
            run.file().refill_declared_from_packed(volume, hole, std::slice::from_ref(&repaired), &mut reader).unwrap();
            assert_eq!(reader.total(), (SLICE.end - SLICE.start) as u64, "{label}");
        }
        assert!(matches!(verify(run.file()), Verdict::Ok { .. }), "{label}");
        assert_eq!(run.output(), fixture.data, "{label}");
    }
}

#[test]
fn a_declared_final_part_refills_from_its_slice_by_the_member_crc() {
    let mut fixture = Fixture::new();
    fixture.damage(2, 50_000);
    let mut run = run(&fixture);
    let (volume, hole) = declared(&run);
    assert_eq!((volume, hole.clone()), (2, fixture.payloads[2].clone()));
    let repaired = fixture.packed(2, 40_000..60_000);
    let mut reader = CountingVolume::new(fixture.good[2].clone());
    run.file().refill_declared_from_packed(volume, hole, std::slice::from_ref(&repaired), &mut reader).unwrap();
    assert_eq!(reader.total(), 20_000);
    assert!(matches!(verify(run.file()), Verdict::Ok { .. }));
    assert_eq!(run.output(), fixture.data);
}

#[test]
fn a_refill_the_checks_cannot_decide_reads_nothing() {
    // Part 0 is declared; part 1 has a missing article, so its check cannot decide a range of it.
    let mut fixture = Fixture::new();
    fixture.damage(0, BAD);
    fixture.holes[1] = vec![fixture.packed(1, 10_000..20_000)];
    let mut run = run(&fixture);
    let (volume, hole) = declared(&run);
    let unprovable = |error: PartialError| {
        assert!(matches!(error.kind, PartialErrorKind::DeclaredRefill(DeclaredRefillFailure::Unprovable)), "{error:?}")
    };
    let mut reader = CountingVolume::new(fixture.good[1].clone());
    let range = fixture.packed(1, 100_000..150_000);
    unprovable(
        run.file()
            .refill_declared_from_packed(1, range.clone(), std::slice::from_ref(&range), &mut reader)
            .unwrap_err(),
    );
    // Bytes that map to no output (the volume's headers).
    unprovable(run.file().refill_declared_from_packed(1, 0..20, &[], &mut reader).unwrap_err());
    assert_eq!(reader.total(), 0);
    // Repaired ranges must lie inside the hole.
    let outside = hole.end..hole.end + 10;
    let error = run
        .file()
        .refill_declared_from_packed(volume, hole.clone(), std::slice::from_ref(&outside), &mut reader)
        .unwrap_err();
    assert!(matches!(error.kind, PartialErrorKind::InvalidOptions), "{error:?}");
    // Part 0 still refills from its slice.
    let repaired = fixture.packed(0, SLICE);
    let mut reader = CountingVolume::new(fixture.good[0].clone());
    run.file().refill_declared_from_packed(volume, hole, std::slice::from_ref(&repaired), &mut reader).unwrap();
    assert_eq!(reader.total(), (SLICE.end - SLICE.start) as u64);
    assert_eq!(run.file().remaining().unwrap(), vec![PART as u64 + 10_000..PART as u64 + 20_000]);
}

#[test]
fn a_write_over_kept_output_is_never_trusted_by_a_later_declared_refill() {
    // After the declaration, bytes inside the hole are written by another path: wrong alt bytes, wrong packed bytes
    // (a bad twin), or the right alt bytes. The kept CRC of what was there before must not vouch for them.
    for (case, right) in [("fill", false), ("fill_packed", false), ("fill", true)] {
        let label = format!("{case} right={right}");
        let mut fixture = Fixture::new();
        fixture.damage(0, BAD);
        let mut run = run(&fixture);
        let (volume, hole) = declared(&run);
        let at = 180_000usize;
        let mut bytes = fixture.data[at..at + 1000].to_vec();
        if !right {
            bytes[500] ^= 0xFF;
        }
        match case {
            "fill" => {
                run.file().fill(at as u64, &bytes).unwrap();
            }
            _ => {
                run.file().fill_packed(volume, fixture.packed(0, at..at + 1000).start, &bytes).unwrap();
            }
        }
        let repaired = fixture.packed(0, SLICE);
        let mut reader = CountingVolume::new(fixture.good[0].clone());
        let result =
            run.file().refill_declared_from_packed(volume, hole.clone(), std::slice::from_ref(&repaired), &mut reader);
        if right {
            result.unwrap();
            // The write dropped the whole kept leaf it landed in (131072..196608): the rest of that leaf outside the
            // slice and the alt bytes is read as well.
            let leaf = 131_072..196_608;
            let extra = (leaf.end - SLICE.end) - 1000;
            assert_eq!(reader.total(), (SLICE.end - SLICE.start + extra) as u64, "{label}");
            assert!(matches!(verify(run.file()), Verdict::Ok { .. }), "{label}");
            assert_eq!(run.output(), fixture.data, "{label}");
        } else {
            let error = result.unwrap_err();
            assert_eq!(check_failed(&error), Some(&[0u64][..]), "{label}: {error:?}");
            assert!(!run.file().remaining().unwrap().is_empty(), "{label}");
        }
    }
}

#[test]
fn a_kept_leaf_whose_bytes_changed_while_closed_is_read_again() {
    let mut fixture = Fixture::new();
    fixture.damage(0, BAD);
    let mut run = run(&fixture);
    let (volume, hole) = declared(&run);
    drop(run.file.take());
    // A byte under a kept leaf outside the slice changes while no handle is open.
    let path = run.dest.join("big.bin");
    let mut output = std::fs::read(&path).unwrap();
    output[10_000] ^= 0xFF;
    std::fs::write(&path, &output).unwrap();
    let anchor = run.anchors.current(&run.key).unwrap().unwrap();
    let state = PartialState::load(&run.state_root, &anchor, &PartialLimits::default()).unwrap();
    match PartialFile::open(state, run.context(anchor)) {
        // The reopen refuses a changed output outright, or drops that kept leaf and the refill reads it again.
        Err(error) => assert!(matches!(error.kind, PartialErrorKind::OutputChanged), "{error:?}"),
        Ok(file) => {
            run.file = Some(file);
            let repaired = fixture.packed(0, SLICE);
            let mut reader = CountingVolume::new(fixture.good[0].clone());
            run.file().refill_declared_from_packed(volume, hole, std::slice::from_ref(&repaired), &mut reader).unwrap();
            assert_eq!(reader.total(), (SLICE.end - SLICE.start) as u64 + 65_536);
            assert!(matches!(verify(run.file()), Verdict::Ok { .. }));
            assert_eq!(run.output(), fixture.data);
        }
    }
}
