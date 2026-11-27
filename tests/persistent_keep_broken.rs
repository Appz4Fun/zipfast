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

//! `Options::keep_broken` and `Options::unverified_output` in a persistent-partial session
//! (`ProgressiveSession::new_partial`, `docs/persistent-partials.md`, "Damaged members: keep_broken and
//! unverified output"): a member failing its checksum is kept and judged `Bad` while the session goes on, and a
//! member cut off by a missing volume or a truncated set is reported `PersistentUnverified`, with its unknown
//! ranges, before the session's failure. Defaults unchanged; a restart resumes as before.

#![cfg(all(feature = "persistent-partials", any(target_os = "linux", target_os = "macos")))]

mod common;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use common::{FileSpec, SIG, end_block, file_block, main_block};
use zipfast::crc32::hash;
use zipfast::extract::{self, Mode, Overwrite, UnverifiedOutput};
use zipfast::partial::*;
use zipfast::progressive::*;

fn extract_options(dest: &Path, keep_broken: bool, unverified: UnverifiedOutput) -> extract::Options {
    extract::Options {
        mode: Mode::Extract,
        dest: dest.to_path_buf(),
        overwrite: Overwrite::Always,
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
        keep_broken,
        attempt_continued_members: false,
        damaged_input: Default::default(),
        unverified_output: unverified,
        unsupported_filters: Default::default(),
        encrypted_links: Default::default(),
        salvage_truncated_zip: false,
        unix_modes: Default::default(),
        backslashes: Default::default(),
        hard_link_targets: Default::default(),
    }
}

/// The three opt-in settings a test compares: neither flag, `keep_broken` alone, both.
const OFF: (bool, UnverifiedOutput) = (false, UnverifiedOutput::Withhold);
const KEEP: (bool, UnverifiedOutput) = (true, UnverifiedOutput::Withhold);
const EMIT: (bool, UnverifiedOutput) = (true, UnverifiedOutput::Emit);

/// `len` bytes no window of which repeats elsewhere in practice (a xorshift stream).
fn data(len: usize, seed: u8) -> Vec<u8> {
    let mut x = 0x9e37_79b9_7f4a_7c15u64 ^ u64::from(seed);
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

fn rar4_block(kind: u8, flags: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0, 0, kind];
    bytes.extend(flags.to_le_bytes());
    bytes.extend(((body.len() + 7) as u16).to_le_bytes());
    bytes.extend(body);
    let crc = hash(&bytes[2..]) as u16;
    bytes[..2].copy_from_slice(&crc.to_le_bytes());
    bytes
}

/// A RAR 4.x archive of `files` stored, each with the CRC of its data.
fn rar4(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = b"Rar!\x1a\x07\0".to_vec();
    out.extend(rar4_block(0x73, 0, &[0; 6]));
    for (name, data) in files {
        let mut body = Vec::new();
        body.extend((data.len() as u32).to_le_bytes());
        body.extend((data.len() as u32).to_le_bytes());
        body.push(3);
        body.extend(hash(data).to_le_bytes());
        body.extend(0x50221884u32.to_le_bytes());
        body.extend([20, 0x30]);
        body.extend((name.len() as u16).to_le_bytes());
        body.extend(0o100644u32.to_le_bytes());
        body.extend(name.as_bytes());
        out.extend(rar4_block(0x74, 0x8000, &body));
        out.extend(*data);
    }
    out.extend(rar4_block(0x7b, 0x4000, &[]));
    out
}

/// Flips one byte of `data` inside `archive` (its first occurrence), so the member fails its checksum.
fn hit(archive: &mut [u8], data: &[u8], at: usize) {
    let start = archive.windows(data.len()).position(|w| w == data).unwrap();
    archive[start + at] ^= 0x5a;
}

/// A volume read whole, with a final length.
struct Source {
    index: u32,
    data: Vec<u8>,
}
impl RangeSource for Source {
    fn info(&self) -> SourceInfo {
        SourceInfo {
            id: SourceId(self.index as u128 + 1),
            generation: 0,
            extent: self.data.len() as u64,
            length: SourceLength::Final(self.data.len() as u64),
        }
    }
    fn backing_files(&self) -> &[fs::File] {
        &[]
    }
    fn read_at(&mut self, at: u64, buf: &mut [u8], _: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
        let len = self.data.len() as u64;
        if at >= len {
            return Ok(RangeRead::Filled { count: 0 });
        }
        let n = (len - at).min(buf.len() as u64) as usize;
        buf[..n].copy_from_slice(&self.data[at as usize..at as usize + n]);
        Ok(RangeRead::Filled { count: n })
    }
}
/// Every volume named in a Complete declaration; a `None` volume answers `Missing`.
struct Provider {
    names: Vec<OsString>,
    volumes: Vec<Option<Source>>,
}
impl VolumeSource for Provider {
    fn protection(&mut self) -> ProgressiveResult<ProtectionDeclaration> {
        Ok(ProtectionDeclaration::Complete {
            epoch: 1,
            inventory: ProtectionInventory {
                volumes: self
                    .names
                    .iter()
                    .enumerate()
                    .map(|(index, name)| ProtectedVolume {
                        index: index as u32,
                        name: name.clone(),
                        backing: VolumeBacking::NonFile,
                    })
                    .collect(),
                auxiliary_paths: Vec::new(),
            },
        })
    }
    fn volume(&mut self, request: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
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

/// The roots and anchor store a set's sessions share, run after run.
struct Job {
    _dir: tempfile::TempDir,
    out: PathBuf,
    state: PathBuf,
    anchors: Arc<Anchors>,
}
impl Job {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        let state = dir.path().join("state");
        fs::create_dir(&out).unwrap();
        Self { _dir: dir, out, state, anchors: Arc::new(Anchors::default()) }
    }
    fn read(&self, name: &str) -> Vec<u8> {
        fs::read(self.out.join(name)).unwrap()
    }
}

/// What one session made of a set.
#[derive(Debug, Default)]
struct Report {
    /// The failure the session ended with, `None` when it ran to its end.
    failure: Option<String>,
    /// Each member's outcome, by name: "Ok", a `Verdict` other than `Ok`, "partial", or "unverified".
    outcomes: BTreeMap<String, String>,
    /// The `missing` ranges of each `PersistentUnverified` member.
    missing: BTreeMap<String, Vec<Range<u64>>>,
    /// Members adopted from an earlier session, with whether they were finished.
    adopted: Vec<(String, bool)>,
    /// Every event, in order, by kind (and member name).
    events: Vec<String>,
    /// Whether any event came after the session's failure was returned (it must not).
    after_failure: bool,
}

/// Runs a persistent session over `volumes` (a `None` volume is missing) to its end.
fn run(job: &Job, volumes: &[(&str, Option<Vec<u8>>)], (keep_broken, unverified): (bool, UnverifiedOutput)) -> Report {
    let mut options =
        ProgressiveOptions::new(extract_options(&job.out, keep_broken, unverified), OsString::from(volumes[0].0));
    options.hole_policy = HolePolicy::PartialStored { fill: HoleFill::Sparse };
    let provider = Provider {
        names: volumes.iter().map(|(name, _)| OsString::from(*name)).collect(),
        volumes: volumes
            .iter()
            .enumerate()
            .map(|(index, (_, bytes))| bytes.clone().map(|data| Source { index: index as u32, data }))
            .collect(),
    };
    let partial = PartialOptions {
        binding: ArchiveBinding { job: [1; 16], archive: [2; 32] },
        naming: PartialNaming::ArchivePath,
        state_dir: job.state.clone(),
        limits: PartialLimits::default(),
        anchors: job.anchors.clone(),
        control: SessionControl::default(),
    };
    let mut session = ProgressiveSession::new_partial(Box::new(provider), options, partial).unwrap();
    let mut report = Report::default();
    let mut names: std::collections::HashMap<MemberId, String> = Default::default();
    let mut current = String::new();
    let mut cx = Context::from_waker(Waker::noop());
    let started = Instant::now();
    loop {
        assert!(started.elapsed() < Duration::from_secs(60), "the session never ended");
        let event = match session.poll_event(&mut cx) {
            Poll::Pending => continue,
            Poll::Ready(Ok(None)) => break,
            Poll::Ready(Err(failure)) => {
                report.failure = Some(format!("{:?}", failure.kind));
                break;
            }
            Poll::Ready(Ok(Some(event))) => event,
        };
        match event {
            ProgressiveEvent::MemberStarted { member, name, .. } => {
                current = String::from_utf8_lossy(&name).into_owned();
                names.insert(member, current.clone());
                report.events.push(format!("started {current}"));
            }
            ProgressiveEvent::PartialAdopted { finished, .. } => report.adopted.push((current.clone(), finished)),
            ProgressiveEvent::Hole(hole) => report.events.push(format!("hole {current} {:?}", hole.out)),
            ProgressiveEvent::BytesWritten { .. } => {
                if report.events.last().is_none_or(|e| *e != format!("written {current}")) {
                    report.events.push(format!("written {current}"));
                }
            }
            ProgressiveEvent::MemberFinished { member, outcome } => {
                let name = names[&member].clone();
                let label = match outcome {
                    MemberOutcome::PersistentComplete { verdict: Verdict::Ok { .. }, .. } => "Ok".to_string(),
                    MemberOutcome::PersistentComplete { verdict, .. } => format!("{verdict:?}"),
                    MemberOutcome::PersistentPartial { .. } => "partial".to_string(),
                    MemberOutcome::PersistentUnverified { member: key, state, expected, missing } => {
                        assert_eq!(state.anchor(), &job.anchors.current(&key).unwrap().unwrap());
                        assert_eq!(expected.size, fs::metadata(job.out.join(&name)).unwrap().len());
                        // The handle is there as for any member, and says the same.
                        assert_eq!(session.partial_file(&key).unwrap().remaining().unwrap(), missing);
                        report.missing.insert(name.clone(), missing);
                        "unverified".to_string()
                    }
                    _ => "other".to_string(),
                };
                report.events.push(format!("finished {name} {label}"));
                report.outcomes.insert(name, label);
            }
            _ => {}
        }
    }
    // Once the failure is returned, the session is over.
    for _ in 0..3 {
        report.after_failure |= !matches!(session.poll_event(&mut cx), Poll::Ready(Ok(None)));
    }
    report
}

fn bad_crc(label: &str) -> bool {
    label.starts_with("Bad") && label.contains("Crc32")
}

/// A member in one part failing its CRC ends the session by default, before the members after it. With
/// `keep_broken` the member is kept as written, judged `Bad` (no metadata applied), and the session goes on; a
/// restart reports it the same way without reading it again. RAR 5.0 and RAR 4.x.
#[test]
fn a_member_failing_its_checksum_is_kept_and_the_session_goes_on() {
    let a = data(5000, 1);
    let b = data(3000, 7);
    for format in ["rar5", "rar4"] {
        let mut archive = if format == "rar5" {
            common::archive(&[FileSpec::new("a.bin", &a), FileSpec::new("b.bin", &b)])
        } else {
            rar4(&[("a.bin", &a), ("b.bin", &b)])
        };
        hit(&mut archive, &a, 1234);
        let mut damaged = a.clone();
        damaged[1234] ^= 0x5a;
        let volumes = [("a.rar", Some(archive))];

        let job = Job::new();
        let off = run(&job, &volumes, OFF);
        assert!(off.failure.as_deref().is_some_and(|f| f.contains("FinalChecks")), "{format}: {off:?}");
        assert!(off.outcomes.is_empty(), "{format}: {off:?}");
        assert!(!job.out.join("b.bin").exists(), "{format}: the session ended before b.bin");

        for setting in [KEEP, EMIT] {
            let job = Job::new();
            let kept = run(&job, &volumes, setting);
            assert_eq!(kept.failure, None, "{format}: {kept:?}");
            assert!(bad_crc(&kept.outcomes["a.bin"]), "{format}: {kept:?}");
            assert_eq!(kept.outcomes["b.bin"], "Ok", "{format}: {kept:?}");
            assert_eq!(job.read("a.bin"), damaged, "{format}: every byte written is kept");
            assert_eq!(job.read("b.bin"), b);
            assert!(!kept.after_failure);
            // Unverified output gets no archive metadata (mtime 1_700_000_000 for RAR 5.0).
            let mtime = fs::metadata(job.out.join("a.bin")).unwrap().modified().unwrap();
            let archive_time = std::time::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
            assert_ne!(mtime, archive_time, "{format}: metadata applied to a Bad member");

            // A restart adopts both members finished and reports them as they stand, reading nothing again; with
            // or without the option, since the member's finish is committed.
            for again in [setting, OFF] {
                let restarted = run(&job, &volumes, again);
                assert_eq!(restarted.failure, None, "{format}: {restarted:?}");
                assert_eq!(restarted.adopted, [("a.bin".to_string(), true), ("b.bin".to_string(), true)]);
                assert!(bad_crc(&restarted.outcomes["a.bin"]), "{format}: {restarted:?}");
                assert_eq!(restarted.outcomes["b.bin"], "Ok");
                assert_eq!(job.read("a.bin"), damaged);
            }
        }
    }
}

/// One stored member split over three volumes of `chunk` data bytes each, and a member after it in the last.
fn split_set(a: &[u8], chunk: usize) -> Vec<(&'static str, Option<Vec<u8>>)> {
    let mut volumes = common::volumes(&FileSpec::new("a.bin", a), chunk);
    assert_eq!(volumes.len(), 3);
    // b.bin follows a.bin in the last volume, before its end header.
    let b = data(700, 9);
    let last = volumes.last_mut().unwrap();
    let end = end_block(false);
    last.truncate(last.len() - end.len());
    last.extend(file_block(&FileSpec::new("b.bin", &b), &b, hash(&b), false, false));
    last.extend(end);
    ["set.part1.rar", "set.part2.rar", "set.part3.rar"].into_iter().zip(volumes.into_iter().map(Some)).collect()
}

/// A member cut off by a missing volume: by default (and with `keep_broken` alone) the session ends with
/// `MissingVolume` and reports nothing for it. With `keep_broken` and `Emit` its `MemberFinished` comes first,
/// `PersistentUnverified`, the bytes before the cut kept and the rest listed missing; then the failure. A restart
/// with the volume still missing reports the same; one with the volume there finishes the member `Ok`.
#[test]
fn a_member_cut_off_by_a_missing_volume_is_reported_unverified() {
    let chunk = 4000;
    let a = data(3 * chunk - 500, 3);
    let whole = split_set(&a, chunk);
    let mut cut = whole.clone();
    cut[1].1 = None;

    for setting in [OFF, KEEP] {
        let job = Job::new();
        let report = run(&job, &cut, setting);
        assert_eq!(report.failure.as_deref(), Some("MissingVolume"), "{report:?}");
        assert!(report.outcomes.is_empty(), "{report:?}");
        assert!(!report.after_failure);
        assert_eq!(&job.read("a.bin")[..chunk], &a[..chunk], "the bytes before the cut are on disk as ever");
    }

    let job = Job::new();
    let report = run(&job, &cut, EMIT);
    assert_eq!(report.failure.as_deref(), Some("MissingVolume"), "{report:?}");
    assert_eq!(report.outcomes.len(), 1, "{report:?}");
    assert_eq!(report.outcomes["a.bin"], "unverified");
    assert_eq!(report.missing["a.bin"], vec![chunk as u64..a.len() as u64]);
    assert_eq!(report.events.last().unwrap(), "finished a.bin unverified");
    assert!(!report.after_failure, "the failure ends the session: {report:?}");
    let kept = job.read("a.bin");
    assert_eq!(kept.len(), a.len());
    assert_eq!(&kept[..chunk], &a[..chunk]);
    assert!(!job.out.join("b.bin").exists());

    // Restart, the volume still missing: the member is adopted unfinished, resumed, and cut off again.
    let again = run(&job, &cut, EMIT);
    assert_eq!(again.adopted, [("a.bin".to_string(), false)]);
    assert_eq!(again.failure.as_deref(), Some("MissingVolume"));
    assert_eq!(again.missing["a.bin"], vec![chunk as u64..a.len() as u64]);

    // Restart with the volume there (a repair, a late download): the member resumes and verifies.
    let repaired = run(&job, &whole, EMIT);
    assert_eq!(repaired.failure, None, "{repaired:?}");
    assert_eq!(repaired.adopted, [("a.bin".to_string(), false)]);
    assert_eq!(repaired.outcomes["a.bin"], "Ok");
    assert_eq!(repaired.outcomes["b.bin"], "Ok");
    assert_eq!(job.read("a.bin"), a);
}

/// A set cut short inside a member: a later volume whose final length ends inside the member's part (its data,
/// or its header). By default (and with `keep_broken` alone) the session ends as before and reports nothing for the
/// member; with `keep_broken` and `Emit` it ends `Truncated` after reporting the member `PersistentUnverified`, the
/// bytes of the parts before the cut kept. The whole set later finishes the member `Ok`.
#[test]
fn a_member_cut_short_by_a_truncated_set_is_reported_unverified() {
    let chunk = 4000;
    let a = data(3 * chunk - 500, 5);
    // (volume cut, its new length from the end or the start, the output known before the cut)
    for (volume, cut_data) in [(1, true), (2, true), (2, false)] {
        let whole = split_set(&a, chunk);
        let mut cut = whole.clone();
        let bytes = cut[volume].1.as_mut().unwrap();
        if cut_data {
            // inside the part's data
            let at = bytes.windows(64).position(|w| w == &a[volume * chunk..volume * chunk + 64]).unwrap();
            bytes.truncate(at + 100);
        } else {
            // inside the part's header
            bytes.truncate(SIG.len() + 12);
        }
        let known = (volume * chunk) as u64;
        let case = format!("volume {volume}, cut in {}", if cut_data { "data" } else { "header" });

        for setting in [OFF, KEEP] {
            let job = Job::new();
            let report = run(&job, &cut, setting);
            assert!(report.failure.is_some(), "{case}: {report:?}");
            assert!(report.outcomes.is_empty(), "{case}: {report:?}");
        }
        let job = Job::new();
        let report = run(&job, &cut, EMIT);
        assert_eq!(report.failure.as_deref(), Some("Truncated"), "{case}: {report:?}");
        assert_eq!(report.outcomes.len(), 1, "{case}: {report:?}");
        assert_eq!(report.outcomes["a.bin"], "unverified", "{case}: {report:?}");
        assert_eq!(report.missing["a.bin"], vec![known..a.len() as u64], "{case}");
        assert_eq!(&job.read("a.bin")[..known as usize], &a[..known as usize], "{case}");
        assert!(!report.after_failure);

        let repaired = run(&job, &whole, EMIT);
        assert_eq!(repaired.failure, None, "{case}: {repaired:?}");
        assert_eq!(repaired.adopted, [("a.bin".to_string(), false)], "{case}");
        assert_eq!(repaired.outcomes["a.bin"], "Ok", "{case}");
        assert_eq!(job.read("a.bin"), a);
    }
}

/// A volume whose final length ends inside the first part of a member: the member can't be created, under every
/// setting, so nothing is written and nothing is reported (the earlier members stand as they finished).
#[test]
fn a_member_whose_first_part_is_cut_is_not_created() {
    let a = data(2000, 2);
    let b = data(5000, 6);
    let archive = common::archive(&[FileSpec::new("a.bin", &a), FileSpec::new("b.bin", &b)]);
    let at = archive.windows(64).position(|w| w == &b[..64]).unwrap();
    let volumes = [("a.rar", Some(archive[..at + 1000].to_vec()))];
    for setting in [OFF, KEEP, EMIT] {
        let job = Job::new();
        let report = run(&job, &volumes, setting);
        assert!(report.failure.is_some(), "{report:?}");
        assert_eq!(report.outcomes.len(), 1, "{report:?}");
        assert_eq!(report.outcomes["a.bin"], "Ok");
        assert!(!job.out.join("b.bin").exists());
    }
}

/// A set cut between two members ends with the same failure under every setting, and nothing is reported
/// unverified: the member before the cut finished `Ok`, and no member was cut off.
#[test]
fn a_cut_between_members_reports_nothing_unverified() {
    let a = data(2000, 2);
    let mut first = SIG.to_vec();
    first.extend(main_block(true, None));
    first.extend(file_block(&FileSpec::new("a.bin", &a), &a, hash(&a), false, false));
    first.extend(end_block(true));
    let volumes = [("set.part1.rar", Some(first)), ("set.part2.rar", None)];
    for setting in [OFF, KEEP, EMIT] {
        let job = Job::new();
        let report = run(&job, &volumes, setting);
        assert_eq!(report.failure.as_deref(), Some("MissingVolume"), "{report:?}");
        assert_eq!(report.outcomes.len(), 1);
        assert_eq!(report.outcomes["a.bin"], "Ok");
        assert!(report.missing.is_empty());
    }
}
