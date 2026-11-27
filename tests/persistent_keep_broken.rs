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
        seven_zip_strict: false,
        rar4_raw_names: false,
        folder_times: Default::default(),
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
fn run(job: &Job, volumes: &[(&str, Option<Vec<u8>>)], setting: (bool, UnverifiedOutput)) -> Report {
    run_with(job, volumes, setting, None)
}
/// [`run`] with the password of an encrypted set.
fn run_with(
    job: &Job,
    volumes: &[(&str, Option<Vec<u8>>)],
    (keep_broken, unverified): (bool, UnverifiedOutput),
    password: Option<&str>,
) -> Report {
    let mut options =
        ProgressiveOptions::new(extract_options(&job.out, keep_broken, unverified), OsString::from(volumes[0].0));
    options.set_password(password.map(str::to_string)).unwrap();
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

fn mtime(job: &Job, name: &str) -> std::time::SystemTime {
    fs::metadata(job.out.join(name)).unwrap().modified().unwrap()
}
fn mode(job: &Job, name: &str) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(job.out.join(name)).unwrap().permissions().mode() & 0o7777
}
const ARCHIVE_TIME: Duration = Duration::from_secs(1_700_000_000);

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
            // The kept member gets the archive's metadata, as the whole-archive runners give a kept broken file: the
            // same modified time as b.bin (verified Ok), mode 0644 from the RAR 5.0 header.
            assert_eq!(mtime(&job, "a.bin"), mtime(&job, "b.bin"), "{format}: metadata of a kept Bad member");
            if format == "rar5" {
                assert_eq!(mtime(&job, "a.bin"), std::time::UNIX_EPOCH + ARCHIVE_TIME);
                assert_eq!(mode(&job, "a.bin"), 0o644);
            }

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
            // `Truncated` under every setting (until #330's follow-up a part cut in its data was
            // `Partial(StateMalformed)` by default)
            assert_eq!(report.failure.as_deref(), Some("Truncated"), "{case}: {report:?}");
            assert!(report.outcomes.is_empty(), "{case}: {report:?}");
            assert_eq!(&job.read("a.bin")[..known as usize], &a[..known as usize], "{case}");
        }
        let job = Job::new();
        let report = run(&job, &cut, EMIT);
        assert_eq!(report.failure.as_deref(), Some("Truncated"), "{case}: {report:?}");
        assert_eq!(report.outcomes.len(), 1, "{case}: {report:?}");
        assert_eq!(report.outcomes["a.bin"], "unverified", "{case}: {report:?}");
        assert_eq!(report.missing["a.bin"], vec![known..a.len() as u64], "{case}");
        assert_eq!(&job.read("a.bin")[..known as usize], &a[..known as usize], "{case}");
        assert!(!report.after_failure);
        // kept with the archive's metadata, as the whole-archive runners keep a cut-off file
        assert_eq!(mtime(&job, "a.bin"), std::time::UNIX_EPOCH + ARCHIVE_TIME, "{case}");

        let repaired = run(&job, &whole, EMIT);
        assert_eq!(repaired.failure, None, "{case}: {repaired:?}");
        assert_eq!(repaired.adopted, [("a.bin".to_string(), false)], "{case}");
        assert_eq!(repaired.outcomes["a.bin"], "Ok", "{case}");
        assert_eq!(job.read("a.bin"), a);
    }
}

/// A volume whose final length ends inside the first part of a member. By default (and with `keep_broken` alone)
/// the session ends `Truncated` before creating the member, so nothing is written for it (until #330's follow-up
/// this was `Partial(StateMalformed)`). With `keep_broken` and `Emit` the member is created with its part recorded
/// cut short, the bytes the volume has are extracted, and it is reported `PersistentUnverified` before the
/// `Truncated` failure, the rest listed missing. A restart with the volume still cut adopts it and reports the
/// same; one with the whole volume finishes it `Ok`. RAR 5.0 and RAR 4.x.
#[test]
fn a_member_whose_first_part_is_cut_is_reported_unverified() {
    let a = data(2000, 2);
    let b = data(5000, 6);
    for format in ["rar5", "rar4"] {
        let archive = if format == "rar5" {
            common::archive(&[FileSpec::new("a.bin", &a), FileSpec::new("b.bin", &b)])
        } else {
            rar4(&[("a.bin", &a), ("b.bin", &b)])
        };
        let at = archive.windows(64).position(|w| w == &b[..64]).unwrap();
        let whole = [("a.rar", Some(archive.clone()))];
        let cut = [("a.rar", Some(archive[..at + 1000].to_vec()))];
        for setting in [OFF, KEEP] {
            let job = Job::new();
            let report = run(&job, &cut, setting);
            assert_eq!(report.failure.as_deref(), Some("Truncated"), "{format}: {report:?}");
            assert_eq!(report.outcomes.len(), 1, "{format}: {report:?}");
            assert_eq!(report.outcomes["a.bin"], "Ok");
            assert!(!job.out.join("b.bin").exists(), "{format}");
            assert!(!report.after_failure);
        }

        let job = Job::new();
        let report = run(&job, &cut, EMIT);
        assert_eq!(report.failure.as_deref(), Some("Truncated"), "{format}: {report:?}");
        assert_eq!(report.outcomes["a.bin"], "Ok", "{format}: {report:?}");
        assert_eq!(report.outcomes["b.bin"], "unverified", "{format}: {report:?}");
        assert_eq!(report.missing["b.bin"], vec![1000..b.len() as u64], "{format}");
        assert_eq!(report.events.last().unwrap(), "finished b.bin unverified", "{format}");
        assert!(!report.after_failure, "{format}: the failure ends the session");
        let kept = job.read("b.bin");
        assert_eq!(kept.len(), b.len(), "{format}");
        assert_eq!(&kept[..1000], &b[..1000], "{format}");
        assert_eq!(mtime(&job, "b.bin"), mtime(&job, "a.bin"), "{format}: kept with the archive's metadata");

        // The state written for it reopens on its own, the cut part included.
        let held = load_held(&job.state, &job.out, &HeldOptions::default()).unwrap();
        assert!(held.skipped.is_empty(), "{format}: {:?}", held.skipped);
        let b_held = held.held.iter().find(|h| h.name.as_ref() == b"b.bin").unwrap();
        assert_eq!(b_held.good, vec![0..1000], "{format}");
        assert!(!b_held.finished, "{format}");

        // Restart, the volume still cut: adopted unfinished, resumed, cut off again (under every setting it ends
        // `Truncated`; only the opt-in reports it).
        for (setting, reported) in [(OFF, false), (EMIT, true)] {
            let again = run(&job, &cut, setting);
            assert_eq!(again.failure.as_deref(), Some("Truncated"), "{format}: {again:?}");
            assert_eq!(again.adopted, [("a.bin".to_string(), true), ("b.bin".to_string(), false)], "{format}");
            assert_eq!(again.missing.contains_key("b.bin"), reported, "{format}: {again:?}");
            if reported {
                assert_eq!(again.missing["b.bin"], vec![1000..b.len() as u64], "{format}");
            }
        }

        // Restart with the whole volume (a repair, a late download): the member resumes and verifies.
        let repaired = run(&job, &whole, EMIT);
        assert_eq!(repaired.failure, None, "{format}: {repaired:?}");
        assert_eq!(repaired.adopted, [("a.bin".to_string(), true), ("b.bin".to_string(), false)], "{format}");
        assert_eq!(repaired.outcomes["b.bin"], "Ok", "{format}");
        assert_eq!(job.read("b.bin"), b, "{format}");
        // and a later session adopts it finished
        let later = run(&job, &whole, OFF);
        assert_eq!(later.failure, None, "{format}: {later:?}");
        assert_eq!(later.outcomes["b.bin"], "Ok", "{format}");
    }
}

/// The first part of a member split over three volumes, cut inside the first volume: reported unverified with the
/// rest of the member missing; with the set repaired, the restart continues into the later volumes and verifies.
#[test]
fn a_split_member_cut_in_its_first_volume_resumes_into_the_later_ones() {
    let chunk = 4000;
    let a = data(3 * chunk - 500, 11);
    let whole = split_set(&a, chunk);
    let mut cut = whole.clone();
    let first = cut[0].1.as_mut().unwrap();
    let at = first.windows(64).position(|w| w == &a[..64]).unwrap();
    first.truncate(at + 1500);
    // only the first volume is offered: the cut ends the walk there
    let cut = &cut[..1];

    let job = Job::new();
    let off = run(&job, cut, OFF);
    assert_eq!(off.failure.as_deref(), Some("Truncated"), "{off:?}");
    assert!(!job.out.join("a.bin").exists());

    let report = run(&job, cut, EMIT);
    assert_eq!(report.failure.as_deref(), Some("Truncated"), "{report:?}");
    assert_eq!(report.outcomes["a.bin"], "unverified");
    assert_eq!(report.missing["a.bin"], vec![1500..a.len() as u64]);
    assert_eq!(&job.read("a.bin")[..1500], &a[..1500]);

    let repaired = run(&job, &whole, OFF);
    assert_eq!(repaired.failure, None, "{repaired:?}");
    assert_eq!(repaired.adopted, [("a.bin".to_string(), false)]);
    assert_eq!(repaired.outcomes["a.bin"], "Ok");
    assert_eq!(repaired.outcomes["b.bin"], "Ok");
    assert_eq!(job.read("a.bin"), a);
}

/// An encrypted (AES-256) member whose first part is cut: what the volume holds is decrypted up to the last whole
/// cipher block, reported unverified, resumed on that block boundary after a restart, and verified once the volume
/// is whole.
#[test]
fn an_encrypted_member_whose_first_part_is_cut_resumes_on_a_block_boundary() {
    const SALT: [u8; 16] = [3; 16];
    const IV: [u8; 16] = [9; 16];
    let plain = data(5000, 8);
    let (key, hash_key) = zipfast::crypto::derive_rar5_key_and_hash_key("pw", 1, &SALT, None).unwrap();
    let mut padded = plain.clone();
    padded.resize(plain.len().div_ceil(16) * 16, 0);
    let cipher = zipfast::crypto::encrypt_cbc(&key, &IV, &padded).unwrap();
    let mut extra = vec![36, 1, 0, 2, 1];
    extra.extend(SALT);
    extra.extend(IV);
    let mut spec = FileSpec::new("a.bin", &cipher);
    spec.size = Some(plain.len() as u64);
    spec.extra = extra;
    let crc = zipfast::crypto::rar5_tweak_crc32(hash(&plain), &hash_key);
    let mut archive = SIG.to_vec();
    archive.extend(main_block(false, None));
    archive.extend(file_block(&spec, &cipher, crc, false, false));
    archive.extend(end_block(false));
    let at = archive.windows(64).position(|w| w == &cipher[..64]).unwrap();
    let whole = [("a.rar", Some(archive.clone()))];
    let cut = [("a.rar", Some(archive[..at + 1000].to_vec()))];
    let pw = Some("pw");

    let job = Job::new();
    let off = run_with(&job, &cut, OFF, pw);
    assert_eq!(off.failure.as_deref(), Some("Truncated"), "{off:?}");
    assert!(!job.out.join("a.bin").exists());

    let report = run_with(&job, &cut, EMIT, pw);
    assert_eq!(report.failure.as_deref(), Some("Truncated"), "{report:?}");
    assert_eq!(report.outcomes["a.bin"], "unverified", "{report:?}");
    let known = report.missing["a.bin"][0].start;
    assert_eq!(report.missing["a.bin"], vec![known..plain.len() as u64]);
    assert!(known.is_multiple_of(16) && known <= 1000 && known + 32 >= 1000, "decrypted to a block boundary: {known}");
    assert_eq!(&job.read("a.bin")[..known as usize], &plain[..known as usize]);

    let again = run_with(&job, &cut, EMIT, pw);
    assert_eq!(again.adopted, [("a.bin".to_string(), false)], "{again:?}");
    assert_eq!(again.failure.as_deref(), Some("Truncated"), "{again:?}");
    assert_eq!(again.missing["a.bin"], vec![known..plain.len() as u64]);

    let repaired = run_with(&job, &whole, OFF, pw);
    assert_eq!(repaired.failure, None, "{repaired:?}");
    assert_eq!(repaired.adopted, [("a.bin".to_string(), false)]);
    assert_eq!(repaired.outcomes["a.bin"], "Ok");
    assert_eq!(job.read("a.bin"), plain);
}

/// `keep_broken` sets the archive's permissions on a kept member with the owner's read and write kept, so the
/// output stays resumable and repairable; once it verifies `Ok` the archive's mode is applied exactly.
#[test]
fn a_kept_member_stays_writable_by_its_owner() {
    let a = data(3000, 4);
    let mut spec = FileSpec::new("a.bin", &a);
    spec.unix_mode = Some(0o444);
    let mut archive = common::archive(&[spec]);
    let clean = archive.clone();
    hit(&mut archive, &a, 100);
    let job = Job::new();
    let kept = run(&job, &[("a.rar", Some(archive.clone()))], KEEP);
    assert!(bad_crc(&kept.outcomes["a.bin"]), "{kept:?}");
    assert_eq!(mode(&job, "a.bin"), 0o644, "0444 with the owner's read and write");
    assert_eq!(mtime(&job, "a.bin"), std::time::UNIX_EPOCH + ARCHIVE_TIME);

    // A reopen reads (and could write) it: the handle opens and verification judges it `Bad` again. Kept with the
    // archive's 0444, it could not be opened for writing.
    let anchor = job.anchors.0.lock().unwrap().first().cloned().unwrap();
    let key = anchor.member().clone();
    let state = PartialState::load(&job.state, &anchor, &PartialLimits::default()).unwrap();
    let mut file = PartialFile::open(
        state,
        PartialOpenContext {
            output_root: job.out.clone(),
            state_root: job.state.clone(),
            expected_member: key,
            expected_anchor: anchor,
            protection: ProtectionDeclaration::Complete {
                epoch: 1,
                inventory: ProtectionInventory {
                    volumes: vec![ProtectedVolume { index: 0, name: "a.rar".into(), backing: VolumeBacking::NonFile }],
                    auxiliary_paths: Vec::new(),
                },
            },
            limits: PartialLimits::default(),
            progressive_limits: ProgressiveLimits::default(),
            anchors: job.anchors.clone(),
            control: SessionControl::default(),
            password: None,
        },
    )
    .unwrap();
    let verdict = loop {
        if let Poll::Ready(verdict) = file.poll_verify(&mut Context::from_waker(Waker::noop())) {
            break verdict.unwrap();
        }
    };
    assert!(matches!(verdict, Verdict::Bad { .. }), "{verdict:?}");
    drop(file);

    // Without keep_broken nothing is kept, and a clean member verifying Ok gets the archive's mode exactly.
    let job = Job::new();
    let ok = run(&job, &[("a.rar", Some(clean))], OFF);
    assert_eq!(ok.outcomes["a.bin"], "Ok", "{ok:?}");
    assert_eq!(mode(&job, "a.bin"), 0o444);
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
