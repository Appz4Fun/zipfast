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

//! `Options::damaged_input` in a persistent-partial session (`ProgressiveSession::new_partial`): damaged RAR headers
//! read past as the progressive session reads them (`tests/progressive_salvage.rs`), with the same hole rules, and
//! members bound to their header's position so that a restart over the same damaged bytes, or a resume over a
//! header repaired since, finds them again (`docs/persistent-partials.md`, "Damaged headers").

#![cfg(all(feature = "persistent-partials", any(target_os = "linux", target_os = "macos")))]

mod common;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use common::{FileSpec, SIG, end_block, file_block, main_block};
use zipfast::crc32::hash;
use zipfast::extract::{self, DamagedInput, HeaderDamageKind, Mode, Overwrite};
use zipfast::partial::*;
use zipfast::progressive::*;

const A: &[u8] = b"alpha alpha alpha alpha alpha alpha alpha alpha alpha alpha";
const B: &[u8] = b"bravo bravo bravo bravo bravo bravo bravo bravo bravo bravo bravo bravo";
const C: &[u8] = b"charlie charlie charlie charlie charlie charlie charlie charlie charlie charlie";
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rar-salvage");

fn extract_options(dest: &Path, damaged: DamagedInput) -> extract::Options {
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
        keep_broken: false,
        attempt_continued_members: false,
        damaged_input: damaged,
        unverified_output: Default::default(),
        unsupported_filters: Default::default(),
        encrypted_links: Default::default(),
        salvage_truncated_zip: false,
        unix_modes: Default::default(),
        backslashes: Default::default(),
    }
}

/// A RAR 5.0 archive of a.txt, b.txt, c.txt stored, and where each header starts.
fn rar5() -> (Vec<u8>, [usize; 4]) {
    let mut out = SIG.to_vec();
    out.extend(main_block(false, None));
    let mut at = [0; 4];
    for (i, (name, data)) in [("a.txt", A), ("b.txt", B), ("c.txt", C)].into_iter().enumerate() {
        at[i] = out.len();
        out.extend(file_block(&FileSpec::new(name, data), data, hash(data), false, false));
    }
    at[3] = out.len();
    out.extend(end_block(false));
    (out, at)
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

fn rar4_member(name: &[u8], data: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend((data.len() as u32).to_le_bytes());
    body.extend((data.len() as u32).to_le_bytes());
    body.push(3);
    body.extend(hash(data).to_le_bytes());
    body.extend(0x50221884u32.to_le_bytes());
    body.extend([20, 0x30]);
    body.extend((name.len() as u16).to_le_bytes());
    body.extend(0o100644u32.to_le_bytes());
    body.extend(name);
    let mut bytes = rar4_block(0x74, 0x8000, &body);
    bytes.extend(data);
    bytes
}

/// A RAR 4.x archive of a.txt, b.txt, c.txt stored, and where each header starts.
fn rar4() -> (Vec<u8>, [usize; 4]) {
    let mut out = b"Rar!\x1a\x07\0".to_vec();
    out.extend(rar4_block(0x73, 0, &[0; 6]));
    let mut at = [0; 4];
    for (i, (name, data)) in [(&b"a.txt"[..], A), (b"b.txt", B), (b"c.txt", C)].into_iter().enumerate() {
        at[i] = out.len();
        out.extend(rar4_member(name, data));
    }
    at[3] = out.len();
    out.extend(rar4_block(0x7b, 0x4000, &[]));
    (out, at)
}

fn garbage(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 37 + 11) as u8).collect()
}

type Volumes = Vec<(&'static str, Vec<u8>)>;

/// The damaged archives of `tests/progressive_salvage.rs`, each a set of named volumes.
fn cases() -> Vec<(&'static str, Volumes)> {
    let one = |bytes: Vec<u8>| vec![("a.rar", bytes)];
    let mut cases = Vec::new();
    for (format, (bytes, at)) in [("rar5", rar5()), ("rar4", rar4())] {
        let mut crc = bytes.clone();
        crc[at[1]] ^= 0x5a;
        cases.push((if format == "rar5" { "rar5 header crc" } else { "rar4 header crc" }, one(crc)));
        let main = if format == "rar5" { 8 } else { 7 };
        let mut damaged_main = bytes.clone();
        damaged_main[main] ^= 0x5a;
        cases.push((if format == "rar5" { "rar5 main crc" } else { "rar4 main crc" }, one(damaged_main)));
        let mut retyped = bytes.clone();
        retyped[if format == "rar5" { main + 5 } else { main + 2 }] = if format == "rar5" { 6 } else { 0x70 };
        cases.push((if format == "rar5" { "rar5 main type" } else { "rar4 main type" }, one(retyped)));
        let mut junk = bytes[..at[1]].to_vec();
        junk.extend(garbage(300));
        junk.extend(&bytes[at[1]..]);
        cases.push((if format == "rar5" { "rar5 garbage" } else { "rar4 garbage" }, one(junk)));
        let mut zeros = bytes.clone();
        zeros[at[1]..at[1] + 20].fill(0);
        cases.push((if format == "rar5" { "rar5 zeroed header" } else { "rar4 zeroed header" }, one(zeros)));
        cases.push((
            if format == "rar5" { "rar5 cut in header" } else { "rar4 cut in header" },
            one(bytes[..at[1] + 9].to_vec()),
        ));
    }
    let (bytes, at) = rar5();
    let mut renamed = bytes.clone();
    let name = at[1] + bytes[at[1]..].windows(5).position(|w| w == b"b.txt").unwrap();
    renamed[name + 1] = b't';
    cases.push(("rar5 damaged name", one(renamed)));
    cases.push(("rar5 without end", one(bytes[..at[3]].to_vec())));
    // b.txt's type byte hit so that it reads as a second main header, its data passed over
    let mut as_main = bytes.clone();
    as_main[at[1] + 5] = 1;
    cases.push(("rar5 file read as main", one(as_main)));
    let (mut typed, at4) = rar4();
    typed[at4[1] + 2] ^= 0x5a;
    cases.push(("rar4 damaged type", one(typed)));
    for file in [
        "salvage-rar5-dir-crc.rar",
        "salvage-rar5-main-and-dir-crc.rar",
        "list-rar4-cut-in-main.rar",
        "list-rar4-cut-at-main.rar",
        "hdrerr-rar5-no-end.rar",
        "hdrerr-rar4-cut-in-file.rar",
    ] {
        cases.push((file, one(fs::read(Path::new(FIXTURES).join(file)).unwrap())));
    }
    let mut first = SIG.to_vec();
    first.extend(main_block(true, None));
    first.extend(file_block(&FileSpec::new("a.txt", A), A, hash(A), false, false));
    first.extend(garbage(64));
    let mut second = SIG.to_vec();
    second.extend(main_block(true, Some(1)));
    second.extend(file_block(&FileSpec::new("c.txt", C), C, hash(C), false, false));
    second.extend(end_block(false));
    cases.push(("two volumes", vec![("set.part1.rar", first), ("set.part2.rar", second.clone())]));
    let mut ended = SIG.to_vec();
    ended.extend(main_block(true, None));
    ended.extend(file_block(&FileSpec::new("a.txt", A), A, hash(A), false, false));
    ended.extend(end_block(true));
    let mut second_main = second;
    second_main[SIG.len()] ^= 0x5a;
    cases.push(("second main crc", vec![("set.part1.rar", ended), ("set.part2.rar", second_main)]));
    cases
}

/// A volume: whole reads, or a few bytes a call (`NotYet` past `revealed`, as a download); bytes in `gate` of the
/// first volume held back while `open` is false (`NotYet`, or a `Hole` when `hole`).
struct Source {
    index: u32,
    data: Vec<u8>,
    pieces: bool,
    revealed: Arc<AtomicU64>,
    gate: Range<u64>,
    open: Arc<AtomicBool>,
    hole: bool,
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
    fn read_at(&mut self, at: u64, buf: &mut [u8], cx: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
        let shut = !self.open.load(Ordering::SeqCst);
        if shut && self.gate.contains(&at) {
            if self.hole {
                return Ok(RangeRead::Hole { len: (self.gate.end - at).min(buf.len() as u64) });
            }
            cx.waker().wake_by_ref();
            return Ok(RangeRead::NotYet);
        }
        let len = self.data.len() as u64;
        let revealed = if self.pieces { self.revealed.load(Ordering::SeqCst).min(len) } else { len };
        if at >= revealed {
            if at >= len {
                return Ok(RangeRead::Filled { count: 0 });
            }
            cx.waker().wake_by_ref();
            return Ok(RangeRead::NotYet);
        }
        let mut end = revealed.min(at + buf.len() as u64);
        if self.pieces {
            end = end.min(at + 13);
        }
        if shut && self.gate.start > at {
            end = end.min(self.gate.start);
        }
        let n = (end - at) as usize;
        buf[..n].copy_from_slice(&self.data[at as usize..end as usize]);
        Ok(RangeRead::Filled { count: n })
    }
}
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
}

/// One damage record, as compared across routes: (volume index, offset, kind, name, resumed at).
type Damage = (u32, u64, HeaderDamageKind, Option<String>, Option<u64>);

#[derive(Debug, Default)]
struct Outcome {
    /// How the session ended: `None` when it ran to its end (or was stopped), else the failure kind.
    failure: Option<String>,
    /// The failure's volume and packed offset.
    failed_at: (Option<u32>, Option<u64>),
    /// Members finished `PersistentComplete`, by name, with their output's bytes.
    files: BTreeMap<String, Vec<u8>>,
    /// Their verdicts.
    verdicts: BTreeMap<String, String>,
    dirs: Vec<String>,
    /// Members refused or left partial, by name.
    other: Vec<(String, String)>,
    damage: Vec<Damage>,
    /// Members created, and adopted (with the produced committed and whether they were finished).
    created: Vec<(String, MemberKey)>,
    adopted: Vec<(String, MemberKey, u64, bool)>,
    /// An output could not be read back (a damaged header's attributes, applied as its permissions, may deny it).
    unreadable: bool,
    /// Whether the session was dropped early by `stop`.
    stopped: bool,
}

struct Run<'a> {
    job: &'a Job,
    volumes: &'a [(&'a str, Vec<u8>)],
    damaged: DamagedInput,
    pieces: bool,
    gate: Range<u64>,
    hole: bool,
    /// Called on every `Pending`; returns whether to open the gate.
    on_pending: Option<&'a mut dyn FnMut(&Outcome) -> bool>,
    /// Drops the session (a crash or a pause) once the member of this name has had this many `BytesWritten` events
    /// (any member when the name is empty).
    stop: Option<(&'a str, usize)>,
}
impl<'a> Run<'a> {
    fn simple(job: &'a Job, volumes: &'a [(&'a str, Vec<u8>)], damaged: DamagedInput, pieces: bool) -> Self {
        Self { job, volumes, damaged, pieces, gate: 0..0, hole: false, on_pending: None, stop: None }
    }
}

fn persistent(mut run: Run<'_>) -> Outcome {
    let mut options =
        ProgressiveOptions::new(extract_options(&run.job.out, run.damaged), OsString::from(run.volumes[0].0));
    options.hole_policy = HolePolicy::PartialStored { fill: HoleFill::Sparse };
    let revealed = Arc::new(AtomicU64::new(0));
    let open = Arc::new(AtomicBool::new(run.gate.is_empty()));
    let provider = Provider {
        names: run.volumes.iter().map(|(name, _)| OsString::from(*name)).collect(),
        volumes: run
            .volumes
            .iter()
            .enumerate()
            .map(|(index, (_, bytes))| {
                Some(Source {
                    index: index as u32,
                    data: bytes.clone(),
                    pieces: run.pieces,
                    revealed: revealed.clone(),
                    gate: if index == 0 { run.gate.clone() } else { 0..0 },
                    open: open.clone(),
                    hole: run.hole,
                })
            })
            .collect(),
    };
    let partial = PartialOptions {
        binding: ArchiveBinding { job: [1; 16], archive: [2; 32] },
        naming: PartialNaming::ArchivePath,
        state_dir: run.job.state.clone(),
        limits: PartialLimits::default(),
        anchors: run.job.anchors.clone(),
        control: SessionControl::default(),
    };
    let mut out = Outcome::default();
    let mut session = match ProgressiveSession::new_partial(Box::new(provider), options, partial) {
        Ok(session) => session,
        Err(failure) => {
            out.failure = Some(format!("{:?}", failure.kind));
            return out;
        }
    };
    let mut names: std::collections::HashMap<MemberId, String> = Default::default();
    let mut current = String::new();
    let mut written = 0;
    let mut cx = Context::from_waker(Waker::noop());
    let started = Instant::now();
    loop {
        assert!(started.elapsed() < Duration::from_secs(60), "the session never ended");
        let event = match session.poll_event(&mut cx) {
            Poll::Pending => {
                revealed.fetch_add(7, Ordering::SeqCst);
                if run.on_pending.as_mut().is_some_and(|f| f(&out)) {
                    open.store(true, Ordering::SeqCst);
                }
                continue;
            }
            Poll::Ready(Ok(None)) => break,
            Poll::Ready(Err(failure)) => {
                out.failed_at = (failure.context.volume_index, failure.context.packed_offset);
                out.failure = Some(format!("{:?}", failure.kind));
                break;
            }
            Poll::Ready(Ok(Some(event))) => event,
        };
        match event {
            ProgressiveEvent::HeaderDamaged { volume, damage } => {
                assert_eq!(damage.volume, Path::new(run.volumes[volume as usize].0));
                out.damage.push((volume, damage.offset, damage.kind, damage.name.clone(), damage.resumed_at));
            }
            ProgressiveEvent::MemberStarted { member, name, .. } => {
                written = 0;
                current = String::from_utf8_lossy(&name).into_owned();
                names.insert(member, current.clone());
            }
            ProgressiveEvent::PartialReady { member, .. } => out.created.push((current.clone(), member)),
            ProgressiveEvent::PartialAdopted { member, produced, finished, .. } => {
                out.adopted.push((current.clone(), member, produced, finished))
            }
            ProgressiveEvent::BytesWritten { .. } => {
                written += 1;
                if run.stop.is_some_and(|(name, stop)| (name.is_empty() || name == current) && written >= stop) {
                    out.stopped = true;
                    break;
                }
            }
            ProgressiveEvent::MemberFinished { member, outcome } => {
                let name = names[&member].clone();
                match outcome {
                    MemberOutcome::PersistentComplete { verdict, .. } => {
                        let label =
                            if matches!(verdict, Verdict::Ok { .. }) { "Ok".into() } else { format!("{verdict:?}") };
                        out.verdicts.insert(name.clone(), label);
                        let bytes = fs::read(run.job.out.join(&name));
                        out.unreadable |= bytes.is_err();
                        out.files.insert(name.clone(), bytes.unwrap_or_default());
                    }
                    MemberOutcome::Directory { .. } => out.dirs.push(name),
                    MemberOutcome::PersistentPartial { .. } => out.other.push((name, "partial".into())),
                    MemberOutcome::Refused { reason } => out.other.push((name, format!("{reason:?}"))),
                    MemberOutcome::Stopped { failure, .. } => out.other.push((name, format!("{:?}", failure.kind))),
                    _ => out.other.push((name, "other".into())),
                }
            }
            ProgressiveEvent::SessionTerminated { failure, .. } => {
                out.failed_at = (failure.context.volume_index, failure.context.packed_offset);
                out.failure = Some(format!("{:?}", failure.kind));
                break;
            }
            _ => {}
        }
    }
    out.dirs.sort();
    out
}

fn run_simple(job: &Job, volumes: &[(&str, Vec<u8>)], damaged: DamagedInput, pieces: bool) -> Outcome {
    persistent(Run::simple(job, volumes, damaged, pieces))
}

/// What a plain progressive session (`from_sealed_memory`) makes of the same volumes: the members, their bytes, the
/// folders and the damage list; and the members a persistent session refuses (compressed ones), by name.
fn progressive(volumes: &[(&str, Vec<u8>)], damaged: DamagedInput) -> Outcome {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out");
    fs::create_dir(&dest).unwrap();
    let mut options = ProgressiveOptions::new(extract_options(&dest, damaged), OsString::from(volumes[0].0));
    options.artifact_aftermath = ArtifactAftermath::RetainProvisional;
    let mut session = ProgressiveSession::from_sealed_memory(
        volumes.iter().map(|(name, bytes)| (OsString::from(*name), bytes.clone().into_boxed_slice())).collect(),
        options,
    )
    .unwrap();
    let mut out = Outcome::default();
    let mut names: std::collections::HashMap<MemberId, String> = Default::default();
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        match session.poll_event(&mut cx) {
            Poll::Pending => {}
            Poll::Ready(Ok(None)) => break,
            Poll::Ready(Err(failure)) => {
                out.failure = Some(format!("{:?}", failure.kind));
                break;
            }
            Poll::Ready(Ok(Some(event))) => match event {
                ProgressiveEvent::HeaderDamaged { volume, damage } => {
                    out.damage.push((volume, damage.offset, damage.kind, damage.name.clone(), damage.resumed_at));
                }
                ProgressiveEvent::MemberStarted { member, name, .. } => {
                    names.insert(member, String::from_utf8_lossy(&name).into_owned());
                }
                ProgressiveEvent::MemberFinished { member, outcome } => {
                    let name = names[&member].clone();
                    match outcome {
                        MemberOutcome::Verified(_) => {
                            out.files.insert(name.clone(), fs::read(dest.join(&name)).unwrap_or_default());
                        }
                        MemberOutcome::Directory { .. } => out.dirs.push(name),
                        MemberOutcome::Stopped { failure, .. } => out.other.push((name, format!("{:?}", failure.kind))),
                        _ => out.other.push((name, "other".into())),
                    }
                }
                ProgressiveEvent::SessionTerminated { failure, .. } => {
                    out.failure = Some(format!("{:?}", failure.kind));
                    break;
                }
                _ => {}
            },
        }
    }
    out.dirs.sort();
    out
}

/// The default refuses every damaged archive as before: no `HeaderDamaged` event, the session fails at the damage.
#[test]
fn refuse_is_unchanged_in_a_persistent_session() {
    for (case, volumes) in cases() {
        for pieces in [false, true] {
            let job = Job::new();
            let out = run_simple(&job, &volumes, DamagedInput::Refuse, pieces);
            assert!(out.damage.is_empty(), "{case} {pieces}");
            assert!(out.failure.is_some(), "{case} {pieces}: {out:?}");
        }
    }
}

/// A whole archive under `Refuse` keys each member as it always did: its ordinal and a digest of its first header's
/// bytes in the format's domain. So the states and anchors a build before this one wrote are found again.
#[test]
fn whole_headers_keep_their_keys() {
    for (format, (bytes, at)) in [("rar5", rar5()), ("rar4", rar4())] {
        for damaged in [DamagedInput::Refuse, DamagedInput::Salvage, DamagedInput::Resync] {
            let job = Job::new();
            let volumes = [("a.rar", bytes.clone())];
            let out = run_simple(&job, &volumes, damaged, false);
            assert_eq!(out.failure, None, "{format} {damaged:?}");
            assert_eq!(out.created.len(), 3);
            for (i, (name, key)) in out.created.iter().enumerate() {
                let end = if i == 2 { at[3] } else { at[i + 1] };
                let data = [A, B, C][i];
                let header = &bytes[at[i]..end - data.len()];
                let mut identity = if format == "rar5" {
                    b"zipfast/plain-stored/member/v1\0".to_vec()
                } else {
                    b"zipfast/rar4-stored/member/v1\0".to_vec()
                };
                identity.extend_from_slice(header);
                assert_eq!(key.ordinal(), i as u64, "{format} {damaged:?} {name}");
                assert_eq!(key.identity(), &zipfast::crypto::sha256(&identity), "{format} {damaged:?} {name}");
            }
        }
    }
}

/// `Salvage` and `Resync` in a persistent session extract what a progressive session extracts from the same damaged
/// archive under the same choice: the same members and bytes, the same folders and the same `HeaderDamaged` list,
/// read whole or a few bytes at a time. Compressed members, which a persistent session refuses, are refused here.
#[test]
fn salvage_and_resync_extract_what_the_progressive_session_does() {
    for (case, volumes) in cases() {
        for damaged in [DamagedInput::Salvage, DamagedInput::Resync] {
            let expected = progressive(&volumes, damaged);
            assert_eq!(expected.failure, None, "{case} {damaged:?}: {expected:?}");
            assert!(!expected.damage.is_empty(), "{case} {damaged:?}: not damaged");
            for pieces in [false, true] {
                let at = format!("{case} {damaged:?} pieces={pieces}");
                let job = Job::new();
                let out = run_simple(&job, &volumes, damaged, pieces);
                assert_eq!(out.failure, None, "{at}: {out:?}");
                assert_eq!(out.damage, expected.damage, "{at}");
                assert_eq!(out.dirs, expected.dirs, "{at}");
                let refused: Vec<&String> = out.other.iter().map(|(name, _)| name).collect();
                for (name, why) in &out.other {
                    assert!(why.contains("Compressed") || why.contains("Encrypted"), "{at}: {name} {why}");
                }
                let kept: BTreeMap<String, Vec<u8>> = expected
                    .files
                    .iter()
                    .filter(|(name, _)| !refused.contains(name))
                    .map(|(n, b)| (n.clone(), b.clone()))
                    .collect();
                assert_eq!(out.files, kept, "{at}");
            }
        }
    }
}

/// b.txt's header still to come (`NotYet`) is waited for: no damage, and all three members once it arrives. The same
/// header answered as a `Hole` is `HeaderHole`, neither read past nor searched across; and a hole inside the stretch a
/// resync searches stops it with `HeaderHole` too.
#[test]
fn a_header_still_to_come_is_waited_for_and_one_in_a_hole_stops_the_session() {
    for (format, (bytes, at)) in [("rar5", rar5()), ("rar4", rar4())] {
        let gate = at[1] as u64..at[1] as u64 + 12;
        let volumes = [("a.rar", bytes.clone())];
        for damaged in [DamagedInput::Salvage, DamagedInput::Resync] {
            let job = Job::new();
            let mut waits = 0;
            let out = persistent(Run {
                job: &job,
                volumes: &volumes,
                damaged,
                pieces: true,
                gate: gate.clone(),
                hole: false,
                on_pending: Some(&mut |seen| {
                    if waits <= 400 {
                        assert!(seen.damage.is_empty(), "{format} {damaged:?}: {:?}", seen.damage);
                        assert!(!seen.files.contains_key("b.txt"));
                    }
                    waits += 1;
                    waits > 400
                }),
                stop: None,
            });
            assert!(waits > 400, "{format} {damaged:?}: the session did not wait for the header");
            assert_eq!(out.failure, None, "{format} {damaged:?}");
            assert!(out.damage.is_empty(), "{format} {damaged:?}: {:?}", out.damage);
            assert_eq!(out.files.keys().collect::<Vec<_>>(), ["a.txt", "b.txt", "c.txt"], "{format} {damaged:?}");
            assert_eq!(out.files["b.txt"], B);

            let job = Job::new();
            let out = persistent(Run {
                job: &job,
                volumes: &volumes,
                damaged,
                pieces: true,
                gate: gate.clone(),
                hole: true,
                on_pending: None,
                stop: None,
            });
            assert_eq!(out.failure.as_deref(), Some("HeaderHole"), "{format} {damaged:?}");
            assert!(out.damage.is_empty(), "{format} {damaged:?}: {:?}", out.damage);
            assert_eq!(out.files.keys().collect::<Vec<_>>(), ["a.txt"], "{format} {damaged:?}");
        }
    }
    let (bytes, at) = rar5();
    let mut damaged = bytes[..at[1]].to_vec();
    damaged.extend(garbage(300));
    damaged.extend(&bytes[at[1]..]);
    let job = Job::new();
    let out = persistent(Run {
        job: &job,
        volumes: &[("a.rar", damaged)],
        damaged: DamagedInput::Resync,
        pieces: true,
        gate: at[1] as u64 + 200..at[1] as u64 + 260,
        hole: true,
        on_pending: None,
        stop: None,
    });
    assert_eq!(out.failure.as_deref(), Some("HeaderHole"));
    assert!(out.damage.is_empty(), "{:?}", out.damage);
    assert_eq!(out.files.keys().collect::<Vec<_>>(), ["a.txt"]);
}

/// A restart over the same damaged bytes binds to the same members: a second session adopts every member the first
/// one finished, under the same keys, creates nothing, reports the same damage and leaves the same output. And a
/// session dropped part way through (after its first few writes) is resumed by the next to the same result.
#[test]
fn a_restart_over_the_same_damaged_bytes_binds_the_same_members() {
    for (case, volumes) in cases() {
        for damaged in [DamagedInput::Salvage, DamagedInput::Resync] {
            let at = format!("{case} {damaged:?}");
            let job = Job::new();
            let first = run_simple(&job, &volumes, damaged, false);
            assert_eq!(first.failure, None, "{at}: {first:?}");
            let again = run_simple(&job, &volumes, damaged, true);
            assert_eq!(again.failure, None, "{at}: {again:?} first {first:?}");
            assert!(again.created.is_empty(), "{at}: {:?}", again.created);
            let keys = |o: &Outcome| o.adopted.iter().map(|(n, k, ..)| (n.clone(), k.clone())).collect::<Vec<_>>();
            assert_eq!(keys(&again), first.created, "{at}");
            assert!(again.adopted.iter().all(|(.., finished)| *finished), "{at}");
            assert_eq!(again.damage, first.damage, "{at}");
            assert_eq!(again.files, first.files, "{at}");
            assert_eq!(again.dirs, first.dirs, "{at}");

            // dropped after a few writes, a few bytes a call, then resumed
            let job = Job::new();
            let paused = persistent(Run { stop: Some(("", 3)), ..Run::simple(&job, &volumes, damaged, true) });
            let resumed = run_simple(&job, &volumes, damaged, true);
            assert_eq!(resumed.failure, None, "{at}: {resumed:?}");
            assert_eq!(resumed.damage, first.damage, "{at}");
            assert_eq!(resumed.files, first.files, "{at}: paused {paused:?}");
        }
    }
}

/// An archive of a.bin, b.bin and c.bin stored, each long enough to be written in many pieces: its bytes, where each
/// header starts, and the members' data.
fn long(rar4: bool) -> (Vec<u8>, [usize; 4], [Vec<u8>; 3]) {
    let data: [Vec<u8>; 3] = std::array::from_fn(|m| (0..2000).map(|i| ((i * 7 + m * 13) % 251) as u8).collect());
    let mut out = if rar4 { b"Rar!\x1a\x07\0".to_vec() } else { SIG.to_vec() };
    out.extend(if rar4 { rar4_block(0x73, 0, &[0; 6]) } else { main_block(false, None) });
    let mut at = [0; 4];
    for (i, name) in ["a.bin", "b.bin", "c.bin"].into_iter().enumerate() {
        at[i] = out.len();
        if rar4 {
            out.extend(rar4_member(name.as_bytes(), &data[i]));
        } else {
            out.extend(file_block(&FileSpec::new(name, &data[i]), &data[i], hash(&data[i]), false, false));
        }
    }
    at[3] = out.len();
    out.extend(if rar4 { rar4_block(0x7b, 0x4000, &[]) } else { end_block(false) });
    (out, at, data)
}

/// Repaired later: b.bin's header fails its checksum (its CRC field was hit), so a salvaging session reads it as it
/// stands and is dropped part way through b.bin. par2 then repairs the header. The resumed session reads no damage:
/// it finds b.bin's state under its position, sees that the repaired header describes the same member, and resumes
/// it from what the first session committed. Every member ends whole and verified, and a later run adopts them all.
#[test]
fn a_repaired_header_rebinds_to_the_same_member() {
    for rar4 in [false, true] {
        let (bytes, at, data) = long(rar4);
        let mut damaged = bytes.clone();
        damaged[at[1]] ^= 0x5a;
        for choice in [DamagedInput::Salvage, DamagedInput::Resync] {
            let case = format!("rar4={rar4} {choice:?}");
            let job = Job::new();
            let volumes = [("a.rar", damaged.clone())];
            let paused = persistent(Run { stop: Some(("b.bin", 20)), ..Run::simple(&job, &volumes, choice, true) });
            assert!(paused.stopped, "{case}");
            assert_eq!(paused.damage.len(), 1, "{case}");
            assert_eq!(paused.created.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(), ["a.bin", "b.bin"]);
            let salvaged = paused.created[1].1.clone();
            assert_eq!(salvaged.ordinal(), MemberKey::POSITIONAL, "{case}: a damaged header binds by position");

            let repaired = [("a.rar", bytes.clone())];
            let out = run_simple(&job, &repaired, choice, true);
            assert_eq!(out.failure, None, "{case}: {out:?}");
            assert!(out.damage.is_empty());
            assert_eq!(out.adopted.len(), 2, "{case}: {:?}", out.adopted);
            assert_eq!(out.adopted[1].0, "b.bin");
            assert_eq!(out.adopted[1].1, salvaged, "{case}: rebound to the state read from the damaged header");
            assert!(!out.adopted[1].3 && out.adopted[1].2 > 0 && out.adopted[1].2 < 2000, "{:?}", out.adopted[1]);
            assert_eq!(out.created.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(), ["c.bin"]);
            for (i, name) in ["a.bin", "b.bin", "c.bin"].into_iter().enumerate() {
                assert_eq!(out.files[name], data[i], "{case} {name}");
                assert_eq!(out.verdicts[name], "Ok", "{case} {name}");
            }
            let again = run_simple(&job, &repaired, choice, false);
            assert_eq!(again.failure, None);
            assert!(again.created.is_empty() && again.adopted.len() == 3, "{case}: {again:?}");

            // a whole first run: c.bin is created after the damage, by position, and found so once repaired
            let job = Job::new();
            let first = run_simple(&job, &volumes, choice, false);
            assert_eq!(first.created[2].1.ordinal(), MemberKey::POSITIONAL, "{case}");
            let out = run_simple(&job, &repaired, choice, false);
            assert_eq!(out.failure, None, "{case}: {out:?}");
            let keys = |o: &Outcome| o.adopted.iter().map(|(n, k, ..)| (n.clone(), k.clone())).collect::<Vec<_>>();
            assert_eq!(keys(&out), first.created, "{case}");
        }
    }
}

/// A member split over two volumes whose second part's header failed its checksum: salvaged, then repaired, the
/// part is the same part (a run over the repaired volume adopts the member and walks both parts), while a repair
/// that changes the part (its data CRC) is another archive (`BindingMismatch`).
#[test]
fn a_repaired_continuation_header_is_the_same_part() {
    let data: Vec<u8> = (0..2000).map(|i| (i * 11 % 253) as u8).collect();
    let spec = FileSpec::new("split.bin", &data);
    let volume = |index: usize, part: &[u8], crc: u32| {
        let mut bytes = SIG.to_vec();
        bytes.extend(main_block(true, Some(index as u64)));
        let header = bytes.len();
        bytes.extend(file_block(&spec, part, crc, index == 1, index == 0));
        bytes.extend(end_block(index == 0));
        (bytes, header)
    };
    let (first, _) = volume(0, &data[..1000], hash(&data[..1000]));
    let (second, header) = volume(1, &data[1000..], hash(&data));
    let mut damaged = second.clone();
    damaged[header] ^= 0x5a;
    for choice in [DamagedInput::Salvage, DamagedInput::Resync] {
        let job = Job::new();
        let volumes = [("set.part1.rar", first.clone()), ("set.part2.rar", damaged.clone())];
        let out = run_simple(&job, &volumes, choice, false);
        assert_eq!(out.failure, None, "{choice:?}: {out:?}");
        assert_eq!(
            out.damage,
            [(1, header as u64, HeaderDamageKind::ChecksumMismatch, Some("split.bin".into()), None)]
        );
        assert_eq!(out.files["split.bin"], data);
        let repaired = [("set.part1.rar", first.clone()), ("set.part2.rar", second.clone())];
        let out = run_simple(&job, &repaired, choice, true);
        assert_eq!(out.failure, None, "{choice:?}: {out:?}");
        assert!(out.created.is_empty() && out.adopted.len() == 1 && out.adopted[0].3, "{choice:?}: {out:?}");
        assert_eq!(out.files["split.bin"], data);
        // a "repair" that makes the part another one: its header now carries another data CRC
        let (other, _) = volume(1, &data[1000..], hash(&data) ^ 1);
        let out = run_simple(&job, &[("set.part1.rar", first.clone()), ("set.part2.rar", other)], choice, false);
        assert!(out.failure.as_deref().is_some_and(|f| f.contains("BindingMismatch")), "{choice:?}: {out:?}");
    }
}

/// Repaired later into another member: b.txt's name was hit ("bttxt"), so the salvaged member wrote `bttxt`. Once
/// the header is repaired it names b.txt: the state found at that position is another member's, so the session
/// refuses it with `BindingMismatch(Member)`, naming the header's volume and offset, before writing anything for it.
/// The salvaged output is left as it was; nothing is mixed into b.txt.
#[test]
fn a_header_repaired_into_another_member_is_refused() {
    let (bytes, at) = rar5();
    let mut renamed = bytes.clone();
    let name = at[1] + bytes[at[1]..].windows(5).position(|w| w == b"b.txt").unwrap();
    renamed[name + 1] = b't';
    for choice in [DamagedInput::Salvage, DamagedInput::Resync] {
        let job = Job::new();
        let first = run_simple(&job, &[("a.rar", renamed.clone())], choice, false);
        assert_eq!(first.failure, None);
        assert_eq!(first.files["bttxt"], B);
        let out = run_simple(&job, &[("a.rar", bytes.clone())], choice, false);
        assert!(out.failure.as_deref().is_some_and(|f| f.contains("BindingMismatch(Member)")), "{choice:?}: {out:?}");
        assert_eq!(out.failed_at, (Some(0), Some(at[1] as u64)), "{choice:?}");
        assert!(!job.out.join("b.txt").exists(), "nothing was written for b.txt");
        assert_eq!(fs::read(job.out.join("bttxt")).unwrap(), B);
    }
}

/// Repaired later, after a member was hidden: b.txt's header was zeroed, so a `Resync` session searched past it and
/// extracted a.txt and c.txt (c.txt by position: its ordinal is 1 here and 2 in the whole archive). Once repaired,
/// the session creates b.txt, which it has never seen, and finds c.txt under its position.
#[test]
fn a_member_found_again_after_its_ordinal_moved() {
    for (format, (bytes, at)) in [("rar5", rar5()), ("rar4", rar4())] {
        let mut zeros = bytes.clone();
        zeros[at[1]..at[1] + 20].fill(0);
        let job = Job::new();
        let first = run_simple(&job, &[("a.rar", zeros)], DamagedInput::Resync, false);
        assert_eq!(first.failure, None, "{format}");
        assert_eq!(first.files.keys().collect::<Vec<_>>(), ["a.txt", "c.txt"], "{format}");
        let out = run_simple(&job, &[("a.rar", bytes.clone())], DamagedInput::Resync, false);
        assert_eq!(out.failure, None, "{format}: {out:?}");
        assert_eq!(out.created.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(), ["b.txt"], "{format}");
        assert_eq!(out.adopted.iter().map(|(n, ..)| n.as_str()).collect::<Vec<_>>(), ["a.txt", "c.txt"], "{format}");
        assert_eq!(out.files["a.txt"], A);
        assert_eq!(out.files["b.txt"], B);
        assert_eq!(out.files["c.txt"], C);
    }
}

/// A state holding a witness read past as damage reopens with `PartialFile::open` (the witness is parsed again as
/// it stands) and verifies; the state names the witness as salvaged in a section only such states carry.
#[test]
fn a_salvaged_state_reopens() {
    let (mut bytes, at) = rar5();
    bytes[at[1]] ^= 0x5a;
    let job = Job::new();
    let out = run_simple(&job, &[("a.rar", bytes)], DamagedInput::Salvage, false);
    assert_eq!(out.failure, None);
    let (_, key) = out.created.iter().find(|(n, _)| n == "b.txt").unwrap();
    let anchor = job.anchors.current(key).unwrap().unwrap();
    let state = PartialState::load(&job.state, &anchor, &PartialLimits::default()).unwrap();
    let mut file = PartialFile::open(
        state,
        PartialOpenContext {
            output_root: job.out.clone(),
            state_root: job.state.clone(),
            expected_member: key.clone(),
            expected_anchor: anchor.clone(),
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
    assert!(matches!(verdict, Verdict::Ok { .. }), "{verdict:?}");
}

/// Hostile input: every 37th byte of a three-member archive changed, under each salvaging choice, read whole and in
/// pieces, then the same bytes run again over the same roots: nothing panics, every session ends in bounded time,
/// and the restart binds the same members.
#[test]
fn corrupting_every_37th_offset_never_panics_and_restarts_the_same() {
    let started = Instant::now();
    for (bytes, _) in [rar5(), rar4()] {
        for offset in (0..bytes.len()).step_by(37) {
            for value in [0x00, 0xff, bytes[offset] ^ 0x5a] {
                let mut damaged = bytes.clone();
                damaged[offset] = value;
                for choice in [DamagedInput::Salvage, DamagedInput::Resync] {
                    let volumes = [("a.rar", damaged.clone())];
                    let job = Job::new();
                    let first = run_simple(&job, &volumes, choice, offset % 2 == 0);
                    let again = run_simple(&job, &volumes, choice, offset % 2 == 1);
                    // a damaged mode applied to an output can make it unreadable, which no restart gets past
                    if first.failure.is_none() && !first.unreadable {
                        let at = format!("{offset} {value} {choice:?}");
                        assert_eq!(again.failure, None, "{at}: {again:?} first {first:?}");
                        assert!(again.created.is_empty(), "{at}: {again:?}");
                        assert_eq!(again.damage, first.damage, "{at}");
                        assert_eq!(again.files, first.files, "{at}");
                    }
                }
            }
        }
    }
    assert!(started.elapsed() < Duration::from_secs(300), "{:?}", started.elapsed());
}
