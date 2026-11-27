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

//! `Options::damaged_input` in a progressive session (`ProgressiveOptions::extract`): damaged RAR headers read past
//! as the whole-archive runners read them (`tests/rar_salvage.rs`), over sealed memory and over a source that
//! delivers its bytes a few at a time, and reported as `ProgressiveEvent::HeaderDamaged`. A header the source has
//! not delivered yet is waited on, never damage.

#![cfg(unix)]

mod common;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use common::{FileSpec, SIG, end_block, file_block, main_block};
use zipfast::crc32::hash;
use zipfast::extract::{self, DamagedInput, HeaderDamageKind, Mode, Overwrite};
use zipfast::progressive::*;

const A: &[u8] = b"alpha alpha alpha alpha alpha alpha alpha alpha alpha alpha";
const B: &[u8] = b"bravo bravo bravo bravo bravo bravo bravo bravo bravo bravo bravo bravo";
const C: &[u8] = b"charlie charlie charlie charlie charlie charlie charlie charlie charlie charlie";
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rar-salvage");

fn extract_options(dest: &Path, mode: Mode, damaged: DamagedInput) -> extract::Options {
    extract::Options {
        mode,
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
        unsupported_filters: Default::default(),
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

/// How the session gets its bytes.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Route {
    /// `ProgressiveSession::from_sealed_memory`: every volume up front, published as verified.
    Sealed,
    /// A provider that delivers a few bytes a call and `NotYet` past what it has so far, as a download does; its
    /// members end as provisional artifacts.
    Pieces,
}

/// A volume revealed a few bytes at a time: `NotYet` past `revealed`, and bytes in `gate` held back (`NotYet`, or a
/// `Hole` when `hole`) until `open`.
struct Trickle {
    data: Vec<u8>,
    revealed: Arc<AtomicU64>,
    gate: Range<u64>,
    open: Arc<AtomicBool>,
    hole: bool,
}
impl RangeSource for Trickle {
    fn info(&self) -> SourceInfo {
        SourceInfo {
            id: SourceId(self.data.len() as u128 + 1),
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
        let revealed = self.revealed.load(Ordering::SeqCst).min(self.data.len() as u64);
        if at >= revealed {
            cx.waker().wake_by_ref();
            return Ok(RangeRead::NotYet);
        }
        let mut end = revealed.min(at + buf.len() as u64).min(at + 13);
        if shut && self.gate.start > at {
            end = end.min(self.gate.start);
        }
        let n = (end - at) as usize;
        buf[..n].copy_from_slice(&self.data[at as usize..end as usize]);
        Ok(RangeRead::Filled { count: n })
    }
}
struct Provider {
    volumes: Vec<Vec<u8>>,
    revealed: Arc<AtomicU64>,
    gate: Range<u64>,
    open: Arc<AtomicBool>,
    hole: bool,
}
impl VolumeSource for Provider {
    fn volume(&mut self, request: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
        let Some(data) = self.volumes.get(request.index as usize) else { return Ok(VolumeAnswer::Missing) };
        Ok(VolumeAnswer::Ready(Box::new(Trickle {
            data: data.clone(),
            revealed: self.revealed.clone(),
            gate: if request.index == 0 { self.gate.clone() } else { 0..0 },
            open: self.open.clone(),
            hole: self.hole,
        })))
    }
}

/// One damage record, as compared across routes: (volume index, offset, kind, name, resumed at).
type Damage = (u32, u64, HeaderDamageKind, Option<String>, Option<u64>);

#[derive(Debug, Default)]
struct Outcome {
    /// How the session ended: `None` when it ran to its end, else the failure kind.
    failure: Option<String>,
    /// Files written whole, by name.
    files: BTreeMap<String, Vec<u8>>,
    dirs: Vec<String>,
    /// Members that stopped, by name, with why.
    stopped: Vec<(String, String)>,
    damage: Vec<Damage>,
}

/// Knobs for one progressive run.
struct Run<'a> {
    volumes: &'a [(&'a str, Vec<u8>)],
    damaged: DamagedInput,
    route: Route,
    gate: Range<u64>,
    hole: bool,
    /// Called on every `Pending` with the outcome so far; returns whether to open the gate.
    on_pending: &'a mut dyn FnMut(&Outcome) -> bool,
}

fn progressive(run: Run<'_>) -> Outcome {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out");
    fs::create_dir(&dest).unwrap();
    let mut options =
        ProgressiveOptions::new(extract_options(&dest, Mode::Extract, run.damaged), OsString::from(run.volumes[0].0));
    options.artifact_aftermath = ArtifactAftermath::RetainProvisional;
    let revealed = Arc::new(AtomicU64::new(0));
    let open = Arc::new(AtomicBool::new(run.gate.is_empty()));
    let session = match run.route {
        Route::Sealed => ProgressiveSession::from_sealed_memory(
            run.volumes.iter().map(|(name, bytes)| (OsString::from(*name), bytes.clone().into_boxed_slice())).collect(),
            options,
        ),
        Route::Pieces => ProgressiveSession::new(
            Box::new(Provider {
                volumes: run.volumes.iter().map(|(_, bytes)| bytes.clone()).collect(),
                revealed: revealed.clone(),
                gate: run.gate.clone(),
                open: open.clone(),
                hole: run.hole,
            }),
            options,
        ),
    };
    let mut out = Outcome::default();
    let mut session = match session {
        Ok(session) => session,
        Err(failure) => {
            out.failure = Some(format!("{:?}", failure.kind));
            return out;
        }
    };
    let mut names: std::collections::HashMap<MemberId, String> = Default::default();
    let mut cx = Context::from_waker(Waker::noop());
    let started = Instant::now();
    loop {
        assert!(started.elapsed() < Duration::from_secs(60), "the session never ended");
        match session.poll_event(&mut cx) {
            Poll::Pending => {
                revealed.fetch_add(7, Ordering::SeqCst);
                if (run.on_pending)(&out) {
                    open.store(true, Ordering::SeqCst);
                }
            }
            Poll::Ready(Ok(None)) => break,
            Poll::Ready(Err(failure)) => {
                out.failure = Some(format!("{:?}", failure.kind));
                break;
            }
            Poll::Ready(Ok(Some(event))) => match event {
                ProgressiveEvent::HeaderDamaged { volume, damage } => {
                    assert_eq!(damage.volume, Path::new(run.volumes[volume as usize].0));
                    out.damage.push((volume, damage.offset, damage.kind, damage.name.clone(), damage.resumed_at));
                }
                ProgressiveEvent::MemberStarted { member, name, .. } => {
                    names.insert(member, String::from_utf8_lossy(&name).into_owned());
                }
                ProgressiveEvent::MemberFinished { member, outcome } => {
                    let name = names[&member].clone();
                    match outcome {
                        MemberOutcome::Verified(_) => {
                            // a damaged name may be written under another (sanitized) path: then it reads empty
                            out.files.insert(name.clone(), fs::read(dest.join(&name)).unwrap_or_default());
                        }
                        MemberOutcome::Provisional(mut artifact) => {
                            let mut bytes = vec![0; artifact.produced_extent() as usize];
                            let mut at = 0;
                            while at < bytes.len() {
                                match artifact.read_at(at as u64, &mut bytes[at..]).unwrap() {
                                    ArtifactRead::Filled { count } => at += count,
                                    other => panic!("{name}: {other:?}"),
                                }
                            }
                            out.files.insert(name, bytes);
                            artifact.discard().unwrap();
                        }
                        MemberOutcome::Directory { .. } => out.dirs.push(name),
                        MemberOutcome::Stopped { failure, artifact, .. } => {
                            if let Some(mut artifact) = artifact {
                                artifact.discard().unwrap();
                            }
                            out.stopped.push((name, format!("{:?}", failure.kind)));
                        }
                        _ => panic!("{name}: unexpected outcome"),
                    }
                }
                ProgressiveEvent::SessionTerminated { failure, artifact, .. } => {
                    if let Some(mut artifact) = artifact {
                        artifact.discard().unwrap();
                    }
                    out.failure = Some(format!("{:?}", failure.kind));
                    break;
                }
                _ => {}
            },
        }
    }
    out
}

fn run_simple(volumes: &[(&str, Vec<u8>)], damaged: DamagedInput, route: Route) -> Outcome {
    progressive(Run { volumes, damaged, route, gate: 0..0, hole: false, on_pending: &mut |_| false })
}

/// What `extract::run` makes of the same volumes: files and bytes, folders, and the damage list.
fn whole(volumes: &[(&str, Vec<u8>)], damaged: DamagedInput) -> Option<Outcome> {
    let dir = tempfile::tempdir().unwrap();
    for (name, bytes) in volumes {
        fs::write(dir.path().join(name), bytes).unwrap();
    }
    let dest = dir.path().join("out");
    let summary =
        extract::run(&dir.path().join(volumes[0].0), &extract_options(&dest, Mode::Extract, damaged), |_| {}).ok()?;
    let mut out = Outcome::default();
    if dest.exists() {
        for entry in fs::read_dir(&dest).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().into_string().unwrap();
            if entry.file_type().unwrap().is_dir() {
                out.dirs.push(name);
            } else {
                out.files.insert(name, fs::read(entry.path()).unwrap());
            }
        }
    }
    out.dirs.sort();
    for damage in &summary.damaged_headers {
        let name = damage.volume.file_name().unwrap();
        let volume = volumes.iter().position(|(v, _)| name == *v).unwrap() as u32;
        out.damage.push((volume, damage.offset, damage.kind, damage.name.clone(), damage.resumed_at));
    }
    Some(out)
}

/// The damaged archives of `tests/rar_salvage.rs`, each a set of named volumes.
/// Named volumes, in order.
type Volumes = Vec<(&'static str, Vec<u8>)>;

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
    // the second volume's main header fails its checksum: read on as present
    let mut ended = SIG.to_vec();
    ended.extend(main_block(true, None));
    ended.extend(file_block(&FileSpec::new("a.txt", A), A, hash(A), false, false));
    ended.extend(end_block(true));
    let mut second_main = second;
    second_main[SIG.len()] ^= 0x5a;
    cases.push(("second main crc", vec![("set.part1.rar", ended), ("set.part2.rar", second_main)]));
    cases
}

/// The default refuses every damaged archive as before: no `HeaderDamaged` event, the session fails at the damage.
#[test]
fn refuse_fails_at_the_damage_as_before() {
    for (case, volumes) in cases() {
        for route in [Route::Sealed, Route::Pieces] {
            let out = run_simple(&volumes, DamagedInput::Refuse, route);
            assert!(out.damage.is_empty(), "{case} {route:?}");
            assert!(out.failure.is_some(), "{case} {route:?}: {out:?}");
        }
    }
}

/// `Salvage` and `Resync` extract what `extract::run` extracts from the same damaged archive under the same choice:
/// the same members, the same bytes, the same folders and the same damage list, over sealed memory and fed in pieces.
#[test]
fn salvage_and_resync_extract_what_the_whole_archive_runner_does() {
    for (case, volumes) in cases() {
        for damaged in [DamagedInput::Salvage, DamagedInput::Resync] {
            let expected =
                whole(&volumes, damaged).unwrap_or_else(|| panic!("{case} {damaged:?}: extract::run failed"));
            assert!(!expected.damage.is_empty(), "{case} {damaged:?}: not damaged");
            for route in [Route::Sealed, Route::Pieces] {
                let out = run_simple(&volumes, damaged, route);
                let at = format!("{case} {damaged:?} {route:?}");
                assert_eq!(out.failure, None, "{at}: {out:?}");
                assert!(out.stopped.is_empty(), "{at}: {out:?}");
                assert_eq!(out.files, expected.files, "{at}");
                let mut dirs = out.dirs.clone();
                dirs.sort();
                assert_eq!(dirs, expected.dirs, "{at}");
                assert_eq!(out.damage, expected.damage, "{at}");
            }
        }
    }
}

/// b.txt's header is still to come (`NotYet`) while everything around it is there: under `Salvage` and `Resync` the
/// session waits for it, reports nothing, and extracts all three members once it arrives. The same header answered
/// as a `Hole` (lost, maybe to be repaired) is `HeaderHole`, as under `Refuse`: neither read past nor searched across.
#[test]
fn a_header_still_to_come_is_waited_for_and_one_in_a_hole_is_not_damage() {
    for (format, (bytes, at)) in [("rar5", rar5()), ("rar4", rar4())] {
        let gate = at[1] as u64..at[1] as u64 + 12;
        let volumes = [("a.rar", bytes.clone())];
        for damaged in [DamagedInput::Salvage, DamagedInput::Resync] {
            let mut waits = 0;
            let out = progressive(Run {
                volumes: &volumes,
                damaged,
                route: Route::Pieces,
                gate: gate.clone(),
                hole: false,
                on_pending: &mut |seen| {
                    assert!(seen.damage.is_empty(), "{format} {damaged:?}: {:?}", seen.damage);
                    assert!(!seen.files.contains_key("b.txt"));
                    waits += 1;
                    waits > 400
                },
            });
            assert!(waits > 400, "{format} {damaged:?}: the session did not wait for the header");
            assert_eq!(out.failure, None, "{format} {damaged:?}");
            assert!(out.damage.is_empty(), "{format} {damaged:?}: {:?}", out.damage);
            assert_eq!(out.files.keys().collect::<Vec<_>>(), ["a.txt", "b.txt", "c.txt"], "{format} {damaged:?}");
            assert_eq!(out.files["b.txt"], B);
            assert_eq!(out.files["c.txt"], C);

            let out = progressive(Run {
                volumes: &volumes,
                damaged,
                route: Route::Pieces,
                gate: gate.clone(),
                hole: true,
                on_pending: &mut |_| false,
            });
            assert_eq!(out.failure.as_deref(), Some("HeaderHole"), "{format} {damaged:?}");
            assert!(out.damage.is_empty(), "{format} {damaged:?}: {:?}", out.damage);
            assert_eq!(out.files.keys().collect::<Vec<_>>(), ["a.txt"], "{format} {damaged:?}");
        }
    }
}

/// A hole answered inside the stretch a resync searches stops it with `HeaderHole`: the next header may be in it.
#[test]
fn a_resync_never_searches_across_a_hole() {
    let (bytes, at) = rar5();
    let mut damaged = bytes[..at[1]].to_vec();
    damaged.extend(garbage(300));
    damaged.extend(&bytes[at[1]..]);
    let gate = at[1] as u64 + 200..at[1] as u64 + 260;
    let out = progressive(Run {
        volumes: &[("a.rar", damaged)],
        damaged: DamagedInput::Resync,
        route: Route::Pieces,
        gate,
        hole: true,
        on_pending: &mut |_| false,
    });
    assert_eq!(out.failure.as_deref(), Some("HeaderHole"));
    assert!(out.damage.is_empty(), "{:?}", out.damage);
    assert_eq!(out.files.keys().collect::<Vec<_>>(), ["a.txt"]);
}

/// A solid archive whose middle member's header is lost (zeroed and searched past, or read as a service, a main header
/// or a folder whose data is skipped): the member after it must fail as lacking its history, never decode against
/// the history from before the gap. Its header carries no CRC32, so only that rule stands between it and wrong bytes.
#[test]
fn solid_history_after_a_skipped_header_fails_the_next_solid_member() {
    use zipfast::rar5::testenc::{self, Op};
    let ops: [Vec<Op>; 3] = [vec![Op::Lit(b'a'); 100], vec![Op::Lit(b'b'); 100], vec![Op::Match(100, 100)]];
    let mut all = Vec::new();
    let mut plain = Vec::new();
    let mut at = 0;
    for o in &ops {
        all.extend(o.iter().cloned());
        let model = testenc::model(&all);
        plain.push(model[at..].to_vec());
        at = model.len();
    }
    let streams: Vec<Vec<u8>> = ops.iter().map(|o| testenc::block(o, true, true)).collect();
    let names = ["a.bin", "b.bin", "c.bin"];
    let mut bytes = SIG.to_vec();
    bytes.extend(common::main_block_flags(false, None, true));
    let mut offsets = Vec::new();
    for i in 0..3 {
        offsets.push(bytes.len());
        let spec = FileSpec {
            method: 3,
            size: Some(plain[i].len() as u64),
            solid: i > 0,
            no_crc: i == 2,
            ..FileSpec::new(names[i], &streams[i])
        };
        bytes.extend(file_block(&spec, &streams[i], hash(&plain[i]), false, false));
    }
    bytes.extend(end_block(false));
    for route in [Route::Sealed, Route::Pieces] {
        let out = run_simple(&[("a.rar", bytes.clone())], DamagedInput::Resync, route);
        assert_eq!(out.files["c.bin"], plain[2], "intact {route:?}");
    }

    let mut hole = bytes.clone();
    hole[offsets[1]..offsets[1] + 16].fill(0);
    let mut service = bytes.clone();
    service[offsets[1] + 5] = 3;
    let mut main = bytes.clone();
    main[offsets[1] + 5] = 1;
    let mut folder = bytes.clone();
    let flags = {
        let mut at = offsets[1] + 4;
        for _ in 0..4 {
            while bytes[at] & 0x80 != 0 {
                at += 1;
            }
            at += 1;
        }
        at
    };
    assert_eq!(folder[flags], 0x06, "b.bin's file flags (CRC32, mtime)");
    folder[flags] |= 0x01;
    for (what, damaged) in [("hole", hole), ("service", service), ("main", main), ("folder", folder)] {
        for choice in [DamagedInput::Salvage, DamagedInput::Resync] {
            if what == "hole" && choice == DamagedInput::Salvage {
                continue; // the volume ends at the hole: nothing after it is read
            }
            for route in [Route::Sealed, Route::Pieces] {
                let at = format!("{what} {choice:?} {route:?}");
                let out = run_simple(&[("a.rar", damaged.clone())], choice, route);
                assert_eq!(out.failure, None, "{at}: {out:?}");
                assert_eq!(out.files.get("a.bin"), Some(&plain[0]), "{at}");
                assert!(!out.files.contains_key("c.bin"), "{at}: c.bin decoded against stale history");
                assert_eq!(out.stopped.len(), 1, "{at}: {out:?}");
                assert_eq!(out.stopped[0].0, "c.bin", "{at}");
                assert!(out.stopped[0].1.contains("SolidHistoryUnavailable"), "{at}: {:?}", out.stopped);
                assert_eq!(out.damage.len(), 1, "{at}: {:?}", out.damage);
                assert_eq!(out.dirs, if what == "folder" { vec!["b.bin".to_owned()] } else { vec![] }, "{at}");
            }
        }
    }
}

/// Hostile input: every 37th byte of a three-member archive changed, under each salvaging choice and over both
/// routes: nothing panics and every session ends.
#[test]
fn corrupting_every_37th_offset_never_panics() {
    let started = Instant::now();
    for (bytes, _) in [rar5(), rar4()] {
        for offset in (0..bytes.len()).step_by(37) {
            for value in [0x00, 0xff, bytes[offset] ^ 0x5a] {
                let mut damaged = bytes.clone();
                damaged[offset] = value;
                for choice in [DamagedInput::Salvage, DamagedInput::Resync] {
                    for route in [Route::Sealed, Route::Pieces] {
                        let out = run_simple(&[("a.rar", damaged.clone())], choice, route);
                        if out.failure.is_none() && damaged != bytes {
                            // whatever was read past is reported, or the damage was in a member's data
                            assert!(!out.damage.is_empty() || !out.stopped.is_empty() || out.files.len() == 3);
                        }
                    }
                }
            }
        }
    }
    assert!(started.elapsed() < Duration::from_secs(60), "took {:?}", started.elapsed());
}

fn noise(len: usize, mut seed: u64) -> Vec<u8> {
    (0..len)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed as u8
        })
        .collect()
}

/// Megabytes of random bytes, and a stretch packed with headers whose fixed fields look right but whose checksums
/// fail, between a.txt and b.txt: a progressive resync crosses both in bounded, linear work and recovers b.txt and
/// c.txt.
#[test]
fn resync_crosses_random_data_and_false_headers_in_bounded_work() {
    let (bytes, at) = rar5();
    let mut fake = Vec::new();
    for _ in 0..20_000 {
        // a RAR 5.0 end header shape (size 3, type 5) with a wrong CRC32
        fake.extend([0xde, 0xad, 0xbe, 0xef, 3, 5, 0, 0]);
    }
    for (what, filler) in [("noise", noise(4 << 20, 0x9e37_79b9_7f4a_7c15)), ("false headers", fake)] {
        let mut damaged = bytes[..at[1]].to_vec();
        // a header of size 0: unreadable, so the search starts here
        damaged.extend([0; 5]);
        damaged.extend(&filler);
        damaged.extend(&bytes[at[1]..]);
        let started = Instant::now();
        let out = run_simple(&[("a.rar", damaged)], DamagedInput::Resync, Route::Sealed);
        assert!(started.elapsed() < Duration::from_secs(20), "{what}: took {:?}", started.elapsed());
        assert_eq!(out.failure, None, "{what}: {out:?}");
        assert_eq!(out.files.keys().collect::<Vec<_>>(), ["a.txt", "b.txt", "c.txt"], "{what}");
        assert_eq!(out.damage.len(), 1, "{what}: {:?}", out.damage);
        assert_eq!(out.damage[0].4, Some((at[1] + 5 + filler.len()) as u64), "{what}");
    }
}

/// A persistent session refuses a damaged header whatever `damaged_input` says: its journal binds each member to
/// the header bytes it was read from, so salvage there is a follow-up.
#[cfg(feature = "persistent-partials")]
#[test]
fn a_persistent_session_still_refuses_damaged_headers() {
    use std::sync::Mutex;
    use zipfast::partial::*;

    struct Source(Vec<u8>);
    impl RangeSource for Source {
        fn info(&self) -> SourceInfo {
            SourceInfo {
                id: SourceId(1),
                generation: 0,
                extent: self.0.len() as u64,
                length: SourceLength::Final(self.0.len() as u64),
            }
        }
        fn backing_files(&self) -> &[fs::File] {
            &[]
        }
        fn read_at(&mut self, at: u64, buf: &mut [u8], _: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
            let end = (at as usize + buf.len()).min(self.0.len());
            buf[..end - at as usize].copy_from_slice(&self.0[at as usize..end]);
            Ok(RangeRead::Filled { count: end - at as usize })
        }
    }
    struct Set(Option<Vec<u8>>);
    impl VolumeSource for Set {
        fn protection(&mut self) -> ProgressiveResult<ProtectionDeclaration> {
            Ok(ProtectionDeclaration::Complete {
                epoch: 1,
                inventory: ProtectionInventory {
                    volumes: vec![ProtectedVolume { index: 0, name: "a.rar".into(), backing: VolumeBacking::NonFile }],
                    auxiliary_paths: Vec::new(),
                },
            })
        }
        fn volume(&mut self, request: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
            match self.0.take().filter(|_| request.index == 0) {
                Some(bytes) => Ok(VolumeAnswer::Ready(Box::new(Source(bytes)))),
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

    let (mut bytes, at) = rar5();
    bytes[at[1]] ^= 0x5a;
    let dir = tempfile::tempdir().unwrap();
    let mut options = ProgressiveOptions::new(
        extract_options(&dir.path().join("out"), Mode::Extract, DamagedInput::Resync),
        OsString::from("a.rar"),
    );
    options.hole_policy = HolePolicy::PartialStored { fill: HoleFill::Sparse };
    let partial = PartialOptions {
        binding: ArchiveBinding { job: [1; 16], archive: [2; 32] },
        naming: PartialNaming::ArchivePath,
        state_dir: dir.path().join("state"),
        limits: PartialLimits::default(),
        anchors: Arc::new(Anchors::default()),
        control: SessionControl::default(),
    };
    let mut session = ProgressiveSession::new_partial(Box::new(Set(Some(bytes))), options, partial).unwrap();
    let mut failed = false;
    for _ in 0..100_000 {
        match session.poll_event(&mut Context::from_waker(Waker::noop())) {
            Poll::Pending => {}
            Poll::Ready(Ok(None)) => break,
            Poll::Ready(Ok(Some(ProgressiveEvent::HeaderDamaged { .. }))) => panic!("a persistent session salvaged"),
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { .. }))) | Poll::Ready(Err(_)) => {
                failed = true;
                break;
            }
            Poll::Ready(Ok(Some(_))) => {}
        }
    }
    assert!(failed, "the damaged header did not stop the persistent session");
}
