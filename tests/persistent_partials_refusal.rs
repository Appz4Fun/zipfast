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

//! Per-member refusal in persistent sessions: refused members are skipped without reading their data, directory
//! entries create their directory, and the session goes on with the next member.
#![cfg(all(feature = "persistent-partials", any(target_os = "linux", target_os = "macos")))]
mod common;
use common::FileSpec;
use std::{
    collections::HashMap,
    ffi::OsString,
    fs::{self, File},
    ops::Range,
    path::Path,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};
use zipfast::partial::*;
use zipfast::progressive::*;

type Reads = Arc<Mutex<Vec<(u32, u64, usize)>>>;
struct Source {
    index: u32,
    bytes: Vec<u8>,
    reads: Reads,
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
        self.reads.lock().unwrap().push((self.index, at, buf.len()));
        let end = (at as usize + buf.len()).min(self.bytes.len());
        buf[..end - at as usize].copy_from_slice(&self.bytes[at as usize..end]);
        Ok(RangeRead::Filled { count: end - at as usize })
    }
}
/// A set of volumes held in memory, with every source read logged.
struct Set {
    names: Vec<OsString>,
    volumes: Vec<Vec<u8>>,
    reads: Reads,
    auxiliary: Vec<std::path::PathBuf>,
}
impl Set {
    fn rar5(volumes: Vec<Vec<u8>>) -> Self {
        let names = (0..volumes.len()).map(|i| format!("set.part{:02}.rar", i + 1).into()).collect();
        Self { names, volumes, reads: Arc::default(), auxiliary: Vec::new() }
    }
    fn rar4(volume: Vec<u8>) -> Self {
        Self { names: vec!["set.rar".into()], volumes: vec![volume], reads: Arc::default(), auxiliary: Vec::new() }
    }
    fn protection(&self) -> ProtectionDeclaration {
        ProtectionDeclaration::Complete {
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
                auxiliary_paths: self
                    .auxiliary
                    .iter()
                    .map(|path| ProtectedPath { path: path.clone(), file: None })
                    .collect(),
            },
        }
    }
    fn provider(&self) -> Provider {
        Provider {
            names: self.names.clone(),
            volumes: self
                .volumes
                .iter()
                .enumerate()
                .map(|(index, bytes)| {
                    Some(Source { index: index as u32, bytes: bytes.clone(), reads: self.reads.clone() })
                })
                .collect(),
            protection: self.protection(),
        }
    }
    /// Every read that touched `range` of `volume`.
    fn reads_in(&self, volume: u32, range: &Range<u64>) -> Vec<(u32, u64, usize)> {
        self.reads
            .lock()
            .unwrap()
            .iter()
            .copied()
            .filter(|&(v, at, len)| v == volume && at < range.end && range.start < at + len as u64)
            .collect()
    }
}
struct Provider {
    names: Vec<OsString>,
    volumes: Vec<Option<Source>>,
    protection: ProtectionDeclaration,
}
impl VolumeSource for Provider {
    fn protection(&mut self) -> ProgressiveResult<ProtectionDeclaration> {
        Ok(self.protection.clone())
    }
    fn volume(&mut self, request: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
        assert_eq!(Some(&request.expected), self.names.get(request.index as usize));
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
fn extract_options(dest: &Path, first: OsString) -> ProgressiveOptions {
    ProgressiveOptions::new(
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
            unix_modes: Default::default(),
            backslashes: Default::default(),
            hard_link_targets: Default::default(),
        },
        first,
    )
}
/// A persistent session over `set` under `dir`, with small reads and every write committed.
fn session(set: &Set, dir: &Path, anchors: &Arc<Anchors>) -> ProgressiveSession {
    session_at(set, &dir.join("out"), &dir.join("state"), anchors)
}
/// A persistent session over `set` with output root `dest` and state root `state`.
fn session_at(set: &Set, dest: &Path, state: &Path, anchors: &Arc<Anchors>) -> ProgressiveSession {
    let mut options = extract_options(dest, set.names[0].clone());
    options.hole_policy = HolePolicy::PartialStored { fill: HoleFill::Sparse };
    options.limits.read_chunk = 256;
    let limits = PartialLimits { group_commit_bytes: 0, ..Default::default() };
    let partial = PartialOptions {
        binding: ArchiveBinding { job: [1; 16], archive: [2; 32] },
        naming: PartialNaming::ArchivePath,
        state_dir: state.into(),
        limits,
        anchors: anchors.clone(),
        control: SessionControl::default(),
    };
    ProgressiveSession::new_partial(Box::new(set.provider()), options, partial).unwrap()
}
#[derive(Default)]
struct Seen {
    events: usize,
    names: HashMap<MemberId, String>,
    /// Name of every member started, in order.
    started: Vec<String>,
    refused: Vec<(String, RefusalReason)>,
    directories: Vec<(String, bool)>,
    /// Members that finished `PersistentComplete` with `Verdict::Ok`.
    complete: Vec<String>,
    files: Vec<(MemberKey, PartialFile)>,
    adopted: Vec<(MemberKey, u64, bool)>,
    holes: usize,
    /// Whether every refusal immediately followed its own `MemberStarted`.
    refused_at_once: bool,
    last: Option<MemberId>,
}
/// Polls until the session ends (true) or `stop` events were delivered (false).
fn run(session: &mut ProgressiveSession, seen: &mut Seen, stop: Option<usize>) -> bool {
    if seen.events == 0 {
        seen.refused_at_once = true;
    }
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
        let previous = seen.last.take();
        match event {
            ProgressiveEvent::MemberStarted { member, name, .. } => {
                let name = String::from_utf8(name.to_vec()).unwrap();
                seen.started.push(name.clone());
                seen.names.insert(member, name);
                seen.last = Some(member);
            }
            ProgressiveEvent::PartialReady { member, .. } => {
                seen.files.push((member.clone(), session.partial_file(&member).unwrap()));
            }
            ProgressiveEvent::PartialAdopted { member, produced, finished, .. } => {
                seen.files.push((member.clone(), session.partial_file(&member).unwrap()));
                seen.adopted.push((member, produced, finished));
            }
            ProgressiveEvent::Hole(_) => seen.holes += 1,
            ProgressiveEvent::MemberFinished { member, outcome } => {
                let name = seen.names[&member].clone();
                match outcome {
                    MemberOutcome::Refused { reason } => {
                        seen.refused_at_once &= previous == Some(member);
                        seen.refused.push((name, reason));
                    }
                    MemberOutcome::Directory { created, .. } => seen.directories.push((name, created)),
                    MemberOutcome::PersistentComplete { verdict: Verdict::Ok { .. }, .. } => seen.complete.push(name),
                    _ => panic!("unexpected outcome for {name}"),
                }
            }
            ProgressiveEvent::SessionTerminated { failure, .. } => panic!("{failure:?}"),
            _ => {}
        }
    }
    panic!("session did not finish")
}
/// The first failure of a session, as its partial error kind.
fn run_failure(session: &mut ProgressiveSession) -> PartialErrorKind {
    match run_failure_kind(session) {
        FailureKind::Partial(error) => error.kind,
        other => panic!("{other:?}"),
    }
}
/// The first failure of a session.
fn run_failure_kind(session: &mut ProgressiveSession) -> FailureKind {
    for _ in 0..1_000_000 {
        match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Err(failure)) | Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) => {
                return failure.kind;
            }
            Poll::Ready(Ok(None)) => panic!("the session finished"),
            _ => {}
        }
    }
    panic!("session did not fail")
}
fn verify(file: &mut PartialFile) -> Verdict {
    for _ in 0..10000 {
        if let Poll::Ready(result) = file.poll_verify(&mut Context::from_waker(Waker::noop())) {
            return result.unwrap();
        }
    }
    panic!("local verification failed to complete")
}
/// Drops `value` as a crash leaves it: an open group is not committed. (Drop skips that commit while unwinding.)
fn crash<T>(value: T) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _held = value;
        std::panic::resume_unwind(Box::new("simulated crash"));
    }));
}
/// Pseudo-random bytes, so no member's data occurs anywhere else in an archive.
fn data(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}
/// Where `needle` (unique) lies in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Range<u64> {
    let start = haystack.windows(needle.len()).position(|w| w == needle).unwrap();
    assert!(haystack[start + 1..].windows(needle.len()).all(|w| w != needle));
    start as u64..(start + needle.len()) as u64
}
fn redirection_record() -> Vec<u8> {
    let mut record = Vec::new();
    common::vint(5, &mut record);
    common::vint(1, &mut record);
    common::vint(0, &mut record);
    common::vint(1, &mut record);
    record.push(b'x');
    let mut extra = Vec::new();
    common::vint(record.len() as u64, &mut extra);
    extra.extend(record);
    extra
}

#[test]
fn compressed_unknown_size_and_link_members_between_stored_members_are_refused_and_skipped() {
    let (a, b, middle) = (data(3000, 1), data(2000, 2), data(1500, 3));
    type Configure = fn(&mut FileSpec<'_>);
    let cases: [(Configure, RefusalReason); 3] = [
        (|s| s.method = 3, RefusalReason::Compressed { method: 3 }),
        (|s| s.size_unknown = true, RefusalReason::UnknownSize),
        (|s| s.extra = redirection_record(), RefusalReason::Redirection),
    ];
    for (configure, reason) in cases {
        let mut refused = FileSpec::new("m.bin", &middle);
        configure(&mut refused);
        let set = Set::rar5(vec![common::archive(&[FileSpec::new("a.bin", &a), refused, FileSpec::new("b.bin", &b)])]);
        let dir = tempfile::tempdir().unwrap();
        let anchors = Arc::new(Anchors::default());
        let mut seen = Seen::default();
        assert!(run(&mut session(&set, dir.path(), &anchors), &mut seen, None));
        assert_eq!(seen.started, ["a.bin", "m.bin", "b.bin"]);
        assert_eq!(seen.refused, [("m.bin".to_string(), reason)]);
        assert!(seen.refused_at_once, "the refusal follows its MemberStarted directly");
        assert_eq!(seen.complete, ["a.bin", "b.bin"]);
        assert_eq!(fs::read(dir.path().join("out/a.bin")).unwrap(), a);
        assert_eq!(fs::read(dir.path().join("out/b.bin")).unwrap(), b);
        // No output, state or anchor for the refused member, and not one byte of its data read.
        assert!(!dir.path().join("out/m.bin").exists());
        assert_eq!(anchors.0.lock().unwrap().len(), 2);
        assert_eq!(fs::read_dir(dir.path().join("state")).unwrap().count(), 2);
        assert!(set.reads_in(0, &find(&set.volumes[0], &middle)).is_empty());
        for (_, file) in &mut seen.files {
            assert!(matches!(verify(file), Verdict::Ok { .. }));
        }
    }
}

#[test]
fn a_set_of_refused_members_only_creates_nothing() {
    let (x, y) = (data(700, 4), data(900, 5));
    let set = Set::rar5(vec![common::archive(&[
        FileSpec { method: 2, ..FileSpec::new("x.bin", &x) },
        FileSpec { size_unknown: true, ..FileSpec::new("y.bin", &y) },
    ])]);
    let dir = tempfile::tempdir().unwrap();
    let mut seen = Seen::default();
    assert!(run(&mut session(&set, dir.path(), &Arc::default()), &mut seen, None));
    assert_eq!(seen.refused.len(), 2);
    assert!(!dir.path().join("out").exists());
    assert!(!dir.path().join("state").exists());
}

#[test]
fn a_refused_member_split_across_volumes_is_skipped_without_reading_its_data() {
    let (a, c, b) = (data(1000, 6), data(6000, 7), data(1200, 8));
    let compressed = FileSpec { method: 3, ..FileSpec::new("c.bin", &c) };
    let cuts = [&c[..2000], &c[2000..4000], &c[4000..]];
    let mut volumes = Vec::new();
    for (index, piece) in cuts.iter().enumerate() {
        let mut wire = common::SIG.to_vec();
        wire.extend(common::main_block(true, (index > 0).then_some(index as u64)));
        if index == 0 {
            wire.extend(common::file_block(&FileSpec::new("a.bin", &a), &a, crc32fast::hash(&a), false, false));
        }
        let crc = crc32fast::hash(if index == 2 { &c } else { piece });
        wire.extend(common::file_block(&compressed, piece, crc, index > 0, index < 2));
        if index == 2 {
            wire.extend(common::file_block(&FileSpec::new("b.bin", &b), &b, crc32fast::hash(&b), false, false));
        }
        wire.extend(common::end_block(index < 2));
        volumes.push(wire);
    }
    let set = Set::rar5(volumes);
    let payloads: Vec<Range<u64>> = cuts.iter().zip(&set.volumes).map(|(piece, wire)| find(wire, piece)).collect();
    let dir = tempfile::tempdir().unwrap();
    let anchors = Arc::new(Anchors::default());
    let mut session = session(&set, dir.path(), &anchors);
    // Damage declared ahead on the refused data is dropped with it, never reported.
    let receipt = session.declare_hole(1, payloads[1].start + 100..payloads[1].start + 300).unwrap();
    assert!(receipt.holes.is_empty() && receipt.pending.len() == 1);
    let mut seen = Seen::default();
    assert!(run(&mut session, &mut seen, None));
    assert_eq!(seen.refused, [("c.bin".to_string(), RefusalReason::Compressed { method: 3 })]);
    assert_eq!(seen.complete, ["a.bin", "b.bin"]);
    assert_eq!(seen.holes, 0);
    assert_eq!(fs::read(dir.path().join("out/b.bin")).unwrap(), b);
    for (volume, payload) in payloads.iter().enumerate() {
        assert!(set.reads_in(volume as u32, payload).is_empty(), "volume {volume}: {:?}", set.reads.lock().unwrap());
    }
    // Volume 1 holds nothing but the refused part: only its headers were read.
    let read: usize = set.reads.lock().unwrap().iter().filter(|r| r.0 == 1).map(|r| r.2).sum();
    assert!(read < 200, "{read} bytes read from volume 1");
    for (_, file) in &mut seen.files {
        assert!(matches!(verify(file), Verdict::Ok { .. }));
    }
}

#[test]
fn directory_entries_create_their_directory_and_get_their_metadata_at_the_end() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let (a, b) = (data(800, 9), data(600, 10));
    let directory =
        |name| FileSpec { dir: true, unix_mode: Some(0o750), mtime: Some(1_600_000_000), ..FileSpec::new(name, b"") };
    let set = Set::rar5(vec![common::archive(&[
        FileSpec::new("a.bin", &a),
        directory("d"),
        FileSpec::new("d/b.bin", &b),
        directory("e/f"),
    ])]);
    let dir = tempfile::tempdir().unwrap();
    let anchors = Arc::new(Anchors::default());
    let mut seen = Seen::default();
    assert!(run(&mut session(&set, dir.path(), &anchors), &mut seen, None));
    assert_eq!(seen.directories, [("d".to_string(), true), ("e/f".to_string(), true)]);
    assert!(seen.refused.is_empty());
    assert_eq!(seen.complete, ["a.bin", "d/b.bin"]);
    assert_eq!(fs::read(dir.path().join("out/d/b.bin")).unwrap(), b);
    for name in ["d", "e/f"] {
        let meta = fs::symlink_metadata(dir.path().join("out").join(name)).unwrap();
        assert!(meta.is_dir());
        assert_eq!(meta.permissions().mode() & 0o777, 0o750, "{name}");
        assert_eq!(meta.mtime(), 1_600_000_000, "{name}");
    }
    // Not a persistent partial: no anchor or bundle for a directory.
    assert_eq!(anchors.0.lock().unwrap().len(), 2);
    // A restart finds the directories and adopts both files.
    drop(seen);
    let mut again = Seen::default();
    assert!(run(&mut session(&set, dir.path(), &anchors), &mut again, None));
    assert_eq!(again.directories, [("d".to_string(), false), ("e/f".to_string(), false)]);
    assert_eq!(again.adopted.len(), 2);
    assert!(again.adopted.iter().all(|(_, produced, finished)| *finished && *produced > 0));
    assert_eq!(again.complete, ["a.bin", "d/b.bin"]);
}

#[test]
fn directory_entries_get_the_path_checks_of_member_creation() {
    let a = data(500, 11);
    let set = |name: &'static str, aux: Option<&Path>| {
        let mut set = Set::rar5(vec![common::archive(&[
            FileSpec::new("a.bin", &a),
            FileSpec { dir: true, unix_mode: Some(0o755), ..FileSpec::new(name, b"") },
        ])]);
        set.auxiliary.extend(aux.map(Path::to_path_buf));
        set
    };
    // A file, or a symbolic link to a directory elsewhere, where the directory or one of its parents goes.
    for (link, name) in [(false, "d"), (true, "d"), (true, "d/e")] {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = dir.path().join("elsewhere");
        fs::create_dir_all(dir.path().join("out")).unwrap();
        fs::create_dir(&elsewhere).unwrap();
        if link {
            std::os::unix::fs::symlink(&elsewhere, dir.path().join("out/d")).unwrap();
        } else {
            fs::write(dir.path().join("out/d"), b"file").unwrap();
        }
        let kind = run_failure(&mut session(&set(name, None), dir.path(), &Arc::default()));
        assert!(matches!(kind, PartialErrorKind::UnsafePath), "{name}: {kind:?}");
        assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0);
    }
    // A path the declaration names.
    let dir = tempfile::tempdir().unwrap();
    let protected = std::path::absolute(dir.path().join("out/d")).unwrap();
    let kind = run_failure(&mut session(&set("d/e", Some(&protected)), dir.path(), &Arc::default()));
    assert!(matches!(&kind, PartialErrorKind::Progressive(e) if matches!(e.kind, FailureKind::UnsafePath)), "{kind:?}");
    assert!(!protected.exists());
}

#[test]
fn restart_with_refused_members_around_adopted_ones_re_reports_them_at_every_crash_point() {
    let (a, b) = (data(2600, 12), data(1800, 13));
    let (c1, c2) = (data(900, 14), data(1100, 15));
    let set = Set::rar5(vec![common::archive(&[
        FileSpec { method: 1, ..FileSpec::new("c1.bin", &c1) },
        FileSpec::new("a.bin", &a),
        FileSpec { method: 4, ..FileSpec::new("c2.bin", &c2) },
        FileSpec::new("b.bin", &b),
    ])]);
    let refused = [
        ("c1.bin".to_string(), RefusalReason::Compressed { method: 1 }),
        ("c2.bin".to_string(), RefusalReason::Compressed { method: 4 }),
    ];
    let skipped = [find(&set.volumes[0], &c1), find(&set.volumes[0], &c2)];
    let total = {
        let dir = tempfile::tempdir().unwrap();
        let mut seen = Seen::default();
        assert!(run(&mut session(&set, dir.path(), &Arc::default()), &mut seen, None));
        assert_eq!(seen.refused, refused);
        seen.events
    };
    for crash_at in 1..total {
        let dir = tempfile::tempdir().unwrap();
        let anchors = Arc::new(Anchors::default());
        let mut first = session(&set, dir.path(), &anchors);
        let mut before = Seen::default();
        assert!(!run(&mut first, &mut before, Some(crash_at)));
        crash((first, std::mem::take(&mut before.files)));
        set.reads.lock().unwrap().clear();
        let mut after = Seen::default();
        assert!(run(&mut session(&set, dir.path(), &anchors), &mut after, None), "crash at {crash_at}");
        assert_eq!(after.refused, refused, "crash at {crash_at}");
        assert_eq!(after.complete, ["a.bin", "b.bin"], "crash at {crash_at}");
        assert_eq!(fs::read(dir.path().join("out/a.bin")).unwrap(), a, "crash at {crash_at}");
        assert_eq!(fs::read(dir.path().join("out/b.bin")).unwrap(), b, "crash at {crash_at}");
        assert!(!dir.path().join("out/c1.bin").exists() && !dir.path().join("out/c2.bin").exists());
        // Every member the first session created is adopted, with the key it had.
        let created = anchors.0.lock().unwrap().len();
        assert!(after.adopted.len() <= created && created <= 2, "crash at {crash_at}");
        assert_eq!(after.files.len(), 2, "crash at {crash_at}");
        for range in &skipped {
            assert!(set.reads_in(0, range).is_empty(), "crash at {crash_at}");
        }
        for (_, file) in &mut after.files {
            assert!(matches!(verify(file), Verdict::Ok { .. }));
        }
    }
}

#[test]
fn solid_compressed_members_are_each_refused_and_an_ordinary_session_extracts_them_afterwards() {
    use zipfast::rar5::testenc::{self, Op};
    let history = b"solid history";
    let first = testenc::block(&history.iter().copied().map(Op::Lit).collect::<Vec<_>>(), true, true);
    let second = testenc::block(&[Op::Match(13, 13)], false, true);
    let stored = data(1000, 16);
    let set = Set::rar5(vec![common::archive_with(
        &[
            (FileSpec { method: 3, size: Some(13), ..FileSpec::new("one", &first) }, crc32fast::hash(history)),
            (FileSpec::new("s.bin", &stored), crc32fast::hash(&stored)),
            (
                FileSpec { method: 3, solid: true, size: Some(13), ..FileSpec::new("two", &second) },
                crc32fast::hash(history),
            ),
        ],
        true,
    )]);
    let dir = tempfile::tempdir().unwrap();
    let mut seen = Seen::default();
    assert!(run(&mut session(&set, dir.path(), &Arc::default()), &mut seen, None));
    assert_eq!(
        seen.refused,
        [
            ("one".to_string(), RefusalReason::Compressed { method: 3 }),
            ("two".to_string(), RefusalReason::Compressed { method: 3 }),
        ]
    );
    // The stored member between them takes nothing from the solid history.
    assert_eq!(seen.complete, ["s.bin"]);
    assert_eq!(fs::read(dir.path().join("out/s.bin")).unwrap(), stored);
    drop(seen);
    // The fallback: an ordinary session over the same set and root, skipping what exists, decodes the solid
    // chain from its first member.
    let mut options = extract_options(&dir.path().join("out"), set.names[0].clone());
    options.extract.overwrite = zipfast::extract::Overwrite::Skip;
    let mut ordinary = ProgressiveSession::new(Box::new(set.provider()), options).unwrap();
    let mut names = HashMap::new();
    let mut outputs = Vec::new();
    loop {
        match ordinary.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberStarted { member, name, .. }))) => {
                names.insert(member, String::from_utf8(name.to_vec()).unwrap());
            }
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { member, outcome }))) => {
                let name = names[&member].clone();
                match outcome {
                    MemberOutcome::Skipped(zipfast::extract::RarSkipReason::ExistingTarget) => {
                        outputs.push((name, None))
                    }
                    MemberOutcome::Provisional(mut artifact) => {
                        let mut bytes = vec![0; 13];
                        assert_eq!(artifact.read_at(0, &mut bytes).unwrap(), ArtifactRead::Filled { count: 13 });
                        outputs.push((name, Some(bytes)));
                    }
                    MemberOutcome::Verified(_) => {
                        outputs.push((name.clone(), Some(fs::read(dir.path().join("out").join(&name)).unwrap())))
                    }
                    _ => panic!("unexpected ordinary outcome for {name}"),
                }
            }
            Poll::Ready(Ok(None)) => break,
            Poll::Ready(Err(e)) => panic!("{e:?}"),
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) => panic!("{failure:?}"),
            _ => {}
        }
    }
    assert_eq!(
        outputs,
        [
            ("one".to_string(), Some(history.to_vec())),
            ("s.bin".to_string(), None),
            ("two".to_string(), Some(history.to_vec())),
        ]
    );
    assert_eq!(fs::read(dir.path().join("out/s.bin")).unwrap(), stored);
}

// RAR4 builders, as in tests/persistent_partials_rar4.rs.
fn rar4_block(kind: u8, flags: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0, 0, kind];
    bytes.extend(flags.to_le_bytes());
    bytes.extend(((body.len() + 7) as u16).to_le_bytes());
    bytes.extend(body);
    let crc = zipfast::crc32::hash(&bytes[2..]) as u16;
    bytes[..2].copy_from_slice(&crc.to_le_bytes());
    bytes
}
fn rar4_file(name: &[u8], payload: &[u8], unpacked: u32, crc: u32, flags: u16, version: u8, method: u8) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend((payload.len() as u32).to_le_bytes());
    body.extend(unpacked.to_le_bytes());
    body.push(3);
    body.extend(crc.to_le_bytes());
    body.extend(0x50221884u32.to_le_bytes());
    body.extend([version, method]);
    body.extend((name.len() as u16).to_le_bytes());
    body.extend(0o100644u32.to_le_bytes());
    body.extend(name);
    let mut wire = rar4_block(0x74, flags | 0x8000, &body);
    wire.extend(payload);
    wire
}

#[test]
fn encrypted_compressed_and_unknown_size_rar4_members_are_refused_and_the_next_stored_member_extracts() {
    let (x, y, middle) = (data(1500, 17), data(1300, 18), data(64, 19));
    let stored =
        |name: &[u8], data: &[u8]| rar4_file(name, data, data.len() as u32, crc32fast::hash(data), 0, 20, 0x30);
    let cases: [(Vec<u8>, RefusalReason); 3] = [
        (rar4_file(b"m.bin", &middle, 60, 0, 0x04, 29, 0x30), RefusalReason::Encrypted),
        (rar4_file(b"m.bin", &middle, 200, 0, 0, 29, 0x33), RefusalReason::Compressed { method: 3 }),
        (rar4_file(b"m.bin", &middle, u32::MAX, 0, 0, 20, 0x30), RefusalReason::UnknownSize),
    ];
    for (member, reason) in cases {
        let mut wire = b"Rar!\x1a\x07\0".to_vec();
        wire.extend(rar4_block(0x73, 0, &[0; 6]));
        wire.extend(stored(b"x.bin", &x));
        wire.extend(member);
        wire.extend(stored(b"y.bin", &y));
        wire.extend(rar4_block(0x7b, 0x4000, &[]));
        let set = Set::rar4(wire);
        let dir = tempfile::tempdir().unwrap();
        let anchors = Arc::new(Anchors::default());
        let mut seen = Seen::default();
        assert!(run(&mut session(&set, dir.path(), &anchors), &mut seen, None));
        assert_eq!(seen.refused, [("m.bin".to_string(), reason)]);
        assert_eq!(seen.complete, ["x.bin", "y.bin"]);
        assert_eq!(fs::read(dir.path().join("out/x.bin")).unwrap(), x);
        assert_eq!(fs::read(dir.path().join("out/y.bin")).unwrap(), y);
        assert!(!dir.path().join("out/m.bin").exists());
        assert_eq!(anchors.0.lock().unwrap().len(), 2);
        assert!(set.reads_in(0, &find(&set.volumes[0], &middle)).is_empty());
    }
}

/// A symbolic link in the middle of a path must never be followed, for a directory entry or for a file member's
/// parents: nothing is created or changed outside the output root.
#[test]
fn a_symlink_in_the_middle_of_the_path_is_refused_for_directory_entries_and_file_members() {
    use std::os::unix::fs::PermissionsExt;
    let f = data(300, 20);
    let directory = |name| FileSpec { dir: true, unix_mode: Some(0o700), ..FileSpec::new(name, b"") };
    let archives = [
        common::archive(&[directory("d/x"), directory("d/x/y")]),
        common::archive(&[FileSpec::new("d/x/f.bin", &f)]),
        common::archive(&[FileSpec::new("d/x/y/f.bin", &f)]),
    ];
    for (case, archive) in archives.into_iter().enumerate() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = dir.path().join("elsewhere");
        fs::create_dir_all(elsewhere.join("x")).unwrap();
        fs::set_permissions(elsewhere.join("x"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::create_dir_all(dir.path().join("out")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, dir.path().join("out/d")).unwrap();
        let set = Set::rar5(vec![archive]);
        let kind = run_failure(&mut session(&set, dir.path(), &Arc::default()));
        assert!(
            matches!(&kind, PartialErrorKind::UnsafePath)
                || matches!(&kind, PartialErrorKind::Progressive(e) if matches!(e.kind, FailureKind::UnsafePath)),
            "case {case}: {kind:?}"
        );
        assert_eq!(fs::read_dir(elsewhere.join("x")).unwrap().count(), 0, "case {case}");
        assert_eq!(fs::metadata(elsewhere.join("x")).unwrap().permissions().mode() & 0o777, 0o755, "case {case}");
    }
}

/// Directory metadata never makes the state root, a declared path or an existing directory unusable.
#[test]
fn directory_metadata_spares_the_state_root_declared_paths_existing_and_output_holding_directories() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let a = data(400, 21);
    let locked =
        |name| FileSpec { dir: true, unix_mode: Some(0o000), mtime: Some(1_500_000_000), ..FileSpec::new(name, b"") };
    // The output root holds the state root; the entry `state` comes first, so this session creates it.
    let dir = tempfile::tempdir().unwrap();
    let mut set = Set::rar5(vec![common::archive(&[
        locked("state"),
        locked("incoming"),
        locked("kept"),
        FileSpec { dir: true, unix_mode: Some(0o500), ..FileSpec::new("held", b"") },
        FileSpec::new("held/a.bin", &a),
    ])]);
    let root = std::path::absolute(dir.path()).unwrap();
    set.auxiliary.push(root.join("incoming/set.part01.rar"));
    fs::create_dir(dir.path().join("kept")).unwrap();
    fs::set_permissions(dir.path().join("kept"), fs::Permissions::from_mode(0o755)).unwrap();
    let anchors = Arc::new(Anchors::default());
    let mut seen = Seen::default();
    assert!(run(&mut session_at(&set, dir.path(), &dir.path().join("state"), &anchors), &mut seen, None));
    assert_eq!(seen.complete, ["held/a.bin"]);
    let mode = |name: &str| fs::metadata(dir.path().join(name)).unwrap().permissions().mode() & 0o777;
    assert_ne!(mode("state"), 0, "the state root keeps its permissions");
    assert_ne!(fs::metadata(dir.path().join("state")).unwrap().mtime(), 1_500_000_000);
    assert_ne!(mode("incoming"), 0, "a directory holding a declared path keeps its permissions");
    assert_eq!(mode("kept"), 0o755, "an existing directory is left as it is");
    assert_eq!(mode("held"), 0o700, "a directory holding an output keeps the owner's access");
    // The member still verifies, and a restart still adopts it.
    for (_, file) in &mut seen.files {
        assert!(matches!(verify(file), Verdict::Ok { .. }));
    }
    drop(seen);
    let mut again = Seen::default();
    assert!(run(&mut session_at(&set, dir.path(), &dir.path().join("state"), &anchors), &mut again, None));
    assert_eq!(again.adopted.len(), 1);
    assert_eq!(again.complete, ["held/a.bin"]);
}

#[test]
fn a_directory_swapped_for_a_symlink_before_the_end_is_output_changed() {
    use std::os::unix::fs::PermissionsExt;
    let a = data(400, 22);
    let set = Set::rar5(vec![common::archive(&[
        FileSpec { dir: true, unix_mode: Some(0o700), ..FileSpec::new("d", b"") },
        FileSpec::new("a.bin", &a),
    ])]);
    let dir = tempfile::tempdir().unwrap();
    let elsewhere = dir.path().join("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    fs::set_permissions(&elsewhere, fs::Permissions::from_mode(0o755)).unwrap();
    let mut session = session(&set, dir.path(), &Arc::default());
    let mut seen = Seen::default();
    while seen.directories.is_empty() {
        let stop = seen.events + 1;
        assert!(!run(&mut session, &mut seen, Some(stop)));
    }
    fs::rename(dir.path().join("out/d"), dir.path().join("moved")).unwrap();
    std::os::unix::fs::symlink(&elsewhere, dir.path().join("out/d")).unwrap();
    let kind = run_failure(&mut session);
    assert!(matches!(kind, PartialErrorKind::OutputChanged), "{kind:?}");
    assert_eq!(fs::metadata(&elsewhere).unwrap().permissions().mode() & 0o777, 0o755);
}

#[test]
fn a_refused_member_running_past_its_volume_end_is_truncated() {
    let (a, c) = (data(400, 23), data(2000, 24));
    let mut wire = common::archive(&[FileSpec::new("a.bin", &a), FileSpec { method: 3, ..FileSpec::new("c.bin", &c) }]);
    let cut = find(&wire, &c).start as usize + 500;
    wire.truncate(cut);
    let set = Set::rar5(vec![wire]);
    let dir = tempfile::tempdir().unwrap();
    let kind = run_failure_kind(&mut session(&set, dir.path(), &Arc::default()));
    assert!(matches!(kind, FailureKind::Truncated), "{kind:?}");
}

#[test]
fn a_refused_rar4_directory_with_an_unsafe_name_is_refused_not_fatal() {
    let x = data(500, 25);
    let mut wire = b"Rar!\x1a\x07\0".to_vec();
    wire.extend(rar4_block(0x73, 0, &[0; 6]));
    // A compressed RAR4 directory entry (directory flags 0xe0) with a name that escapes the root.
    wire.extend(rar4_file(b"../evil", b"", 0, 0, 0xe0, 29, 0x33));
    wire.extend(rar4_file(b"x.bin", &x, x.len() as u32, crc32fast::hash(&x), 0, 20, 0x30));
    wire.extend(rar4_block(0x7b, 0x4000, &[]));
    let set = Set::rar4(wire);
    let dir = tempfile::tempdir().unwrap();
    let mut seen = Seen::default();
    assert!(run(&mut session(&set, dir.path(), &Arc::default()), &mut seen, None));
    assert_eq!(seen.refused, [("../evil".to_string(), RefusalReason::Compressed { method: 3 })]);
    assert_eq!(seen.complete, ["x.bin"]);
    assert!(!dir.path().join("evil").exists());
}

/// RAR usually stores a directory record after its files: the parent this session created for the file is the
/// entry's directory, so it still gets the entry's metadata.
#[test]
fn a_directory_entry_after_its_files_gets_its_metadata() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let f = data(700, 26);
    let set = Set::rar5(vec![common::archive(&[
        FileSpec::new("d/f", &f),
        FileSpec { dir: true, unix_mode: Some(0o750), mtime: Some(1_400_000_000), ..FileSpec::new("d", b"") },
    ])]);
    let dir = tempfile::tempdir().unwrap();
    let mut seen = Seen::default();
    assert!(run(&mut session(&set, dir.path(), &Arc::default()), &mut seen, None));
    assert_eq!(seen.directories, [("d".to_string(), true)]);
    assert_eq!(seen.complete, ["d/f"]);
    let meta = fs::metadata(dir.path().join("out/d")).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o750);
    assert_eq!(meta.mtime(), 1_400_000_000);
    assert_eq!(fs::read(dir.path().join("out/d/f")).unwrap(), f);
    for (_, file) in &mut seen.files {
        assert!(matches!(verify(file), Verdict::Ok { .. }));
    }
}

#[test]
fn a_partial_file_reports_its_output_path() {
    let (a, b) = (data(800, 21), data(600, 22));
    let set = Set::rar5(vec![common::archive(&[FileSpec::new("a.bin", &a), FileSpec::new("d/e/b.bin", &b)])]);
    let dir = tempfile::tempdir().unwrap();
    let anchors = Arc::new(Anchors::default());
    let mut seen = Seen::default();
    assert!(run(&mut session(&set, dir.path(), &anchors), &mut seen, None));
    let root = std::path::absolute(dir.path().join("out")).unwrap();
    let expected = [Path::new("a.bin").to_path_buf(), Path::new("d").join("e").join("b.bin")];
    assert_eq!(seen.files.len(), 2);
    for ((_, file), relative) in seen.files.iter().zip(&expected) {
        assert_eq!(file.relative_output_path().unwrap(), relative.as_path());
        assert_eq!(file.output_path(), root.join(relative));
        assert!(file.output_path().is_absolute());
    }
    assert_eq!(fs::read(seen.files[1].1.output_path()).unwrap(), b);
}
