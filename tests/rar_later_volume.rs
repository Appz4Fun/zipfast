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

//! Extracting or testing from a later volume, as UnRAR 7.30 does it (expected data recorded from UnRAR, run once
//! on these same inputs):
//!
//! - every volume before the given one exists back to the first: the run starts over at the first volume and
//!   extracts everything (exit 0);
//! - a volume is missing before it: only what starts in the given and later volumes is extracted; a member that
//!   continues from before is reported "You need to start extraction from a previous volume" (here
//!   `RarSkipReason::MissingStart`, exit 6 when nothing is left to extract or when it is the only trouble).

#![cfg(unix)]

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use common::*;
use zipfast::extract::{Mode, Options, Overwrite, RarOutcome, RarSkipReason, run_rar_with_outcomes};

fn options(dest: &Path, mode: Mode) -> Options {
    Options {
        mode,
        dest: dest.to_owned(),
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
        // These tests check UnRAR's behaviour, which a caller opts into.
        restart_from_first_volume: true,
        replace_placed_links: false,
        keep_broken: false,
        attempt_continued_members: false,
        damaged_input: Default::default(),
        unsupported_filters: Default::default(),
        salvage_truncated_zip: false,
        unix_modes: Default::default(),
        backslashes: Default::default(),
    }
}

fn fixtures(dir: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(dir)
}

/// Copies the named fixture files into a fresh directory.
fn stage(from: &str, names: &[&str]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    for name in names {
        fs::copy(fixtures(from).join(name), dir.path().join(name)).unwrap();
    }
    dir
}

/// File name to length for every file under `dir`.
fn sizes(dir: &Path) -> BTreeMap<String, u64> {
    fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap())
        .map(|e| (e.file_name().to_string_lossy().into_owned(), e.metadata().unwrap().len()))
        .collect()
}

/// Runs from `start` and returns what was extracted, each member's outcome kind in report order, and the volumes
/// opened.
fn run(set: &Path, start: &str, mode: Mode) -> (BTreeMap<String, u64>, Vec<(String, &'static str)>, u64) {
    let out = tempfile::tempdir().unwrap();
    let mut seen = Vec::new();
    let summary = run_rar_with_outcomes(&set.join(start), &options(out.path(), mode), None, |outcome| {
        let kind = match &outcome.outcome {
            RarOutcome::Verified { .. } => "ok",
            RarOutcome::Skipped(RarSkipReason::MissingStart) => "missing-start",
            other => panic!("unexpected outcome {other:?}"),
        };
        seen.push((outcome.entry.name.clone(), kind));
    })
    .unwrap();
    (sizes(out.path()), seen, summary.volumes)
}

fn ok(name: &str) -> (String, &'static str) {
    (name.to_owned(), "ok")
}

const RAR4_FULL: [(&str, u64); 3] = [("file1.txt", 18), ("file2.txt", 17704), ("file3.txt", 18)];

fn want(sizes: &[(&str, u64)]) -> BTreeMap<String, u64> {
    sizes.iter().map(|&(n, s)| (n.to_owned(), s)).collect()
}

#[test]
fn rar4_part2_with_earlier_volumes_restarts_at_the_first() {
    let set = stage("rar4-volumes", &["multi.part1.rar", "multi.part2.rar", "multi.part3.rar"]);
    for mode in [Mode::Extract, Mode::Test] {
        let (tree, seen, volumes) = run(set.path(), "multi.part2.rar", mode);
        if mode == Mode::Extract {
            assert_eq!(tree, want(&RAR4_FULL));
        }
        assert_eq!(seen, [ok("file1.txt"), ok("file2.txt"), ok("file3.txt")]);
        assert_eq!(volumes, 3);
    }
    // from the last volume too
    let (tree, seen, _) = run(set.path(), "multi.part3.rar", Mode::Extract);
    assert_eq!(tree, want(&RAR4_FULL));
    assert_eq!(seen.len(), 3);
}

#[test]
fn rar4_part2_alone_extracts_what_starts_there() {
    // UnRAR: "WARNING: You need to start extraction from a previous volume to unpack file2.txt", file3.txt OK, exit 6
    let set = stage("rar4-volumes", &["multi.part2.rar", "multi.part3.rar"]);
    let (tree, seen, volumes) = run(set.path(), "multi.part2.rar", Mode::Extract);
    assert_eq!(tree, want(&[("file3.txt", 18)]));
    assert_eq!(seen, [("file2.txt".to_owned(), "missing-start"), ok("file3.txt")]);
    assert_eq!(volumes, 2);
}

#[test]
fn rar4_a_missing_middle_volume_means_no_restart() {
    // part1 and part3 only, starting at part3: UnRAR does not go back (part2 is not there)
    let set = stage("rar4-volumes", &["multi.part1.rar", "multi.part3.rar"]);
    let (tree, seen, _) = run(set.path(), "multi.part3.rar", Mode::Extract);
    assert_eq!(tree, want(&[("file3.txt", 18)]));
    assert_eq!(seen, [("file2.txt".to_owned(), "missing-start"), ok("file3.txt")]);
    // part2 and part3 only, starting at part3
    let set = stage("rar4-volumes", &["multi.part2.rar", "multi.part3.rar"]);
    let (tree, _, _) = run(set.path(), "multi.part3.rar", Mode::Extract);
    assert_eq!(tree, want(&[("file3.txt", 18)]));
}

#[test]
fn rar4_old_naming_r00_restarts_at_the_rar() {
    // UnRAR: extracts bigtext_64k.bin from the .rar and the .r00, exit 0
    let both = ["multivol_oldnaming_rar300.rar", "multivol_oldnaming_rar300.r00"];
    let set = stage("rar4-rar300", &both);
    let (tree, seen, volumes) = run(set.path(), "multivol_oldnaming_rar300.r00", Mode::Extract);
    assert_eq!(tree, want(&[("bigtext_64k.bin", 65536)]));
    assert_eq!(seen, [ok("bigtext_64k.bin")]);
    assert_eq!(volumes, 2);
    // without the .rar: UnRAR extracts nothing, "No files to extract", exit 6
    let set = stage("rar4-rar300", &["multivol_oldnaming_rar300.r00"]);
    let (tree, seen, _) = run(set.path(), "multivol_oldnaming_rar300.r00", Mode::Extract);
    assert!(tree.is_empty());
    assert_eq!(seen, [("bigtext_64k.bin".to_owned(), "missing-start")]);
}

#[test]
fn rar4_old_naming_r02_walks_back_through_every_volume() {
    let names: Vec<String> =
        ["rar", "r00", "r01", "r02", "r03"].iter().map(|e| format!("compressed_multivol_prng_rar300.{e}")).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let set = stage("rar4-rar300", &refs);
    let (tree, seen, volumes) = run(set.path(), "compressed_multivol_prng_rar300.r02", Mode::Extract);
    assert_eq!(tree, want(&[("cvolume.bin", 4096)]));
    assert_eq!(seen, [ok("cvolume.bin")]);
    assert_eq!(volumes, 5);
    // the .r00 missing: no restart; UnRAR extracts nothing and exits 6
    let set = stage("rar4-rar300", &[&names[0], &names[2], &names[3], &names[4]]);
    let (tree, seen, _) = run(set.path(), "compressed_multivol_prng_rar300.r02", Mode::Extract);
    assert!(tree.is_empty());
    assert_eq!(seen, [("cvolume.bin".to_owned(), "missing-start")]);
}

/// A RAR 5 member of 3000 bytes cut over three volumes (the same bytes UnRAR was run on).
fn rar5_set(keep: &[usize]) -> tempfile::TempDir {
    let data: Vec<u8> = (0..3000u32).map(|i| (i * 7 % 251) as u8).collect();
    let spec = FileSpec::new("a.bin", &data);
    let dir = tempfile::tempdir().unwrap();
    for (i, volume) in volumes(&spec, 1000).iter().enumerate() {
        if keep.contains(&(i + 1)) {
            fs::write(dir.path().join(format!("set.part{}.rar", i + 1)), volume).unwrap();
        }
    }
    dir
}

#[test]
fn rar5_later_volume_with_earlier_ones_restarts_at_the_first() {
    let set = rar5_set(&[1, 2, 3]);
    for start in ["set.part2.rar", "set.part3.rar"] {
        for mode in [Mode::Extract, Mode::Test] {
            let (tree, seen, volumes) = run(set.path(), start, mode);
            if mode == Mode::Extract {
                assert_eq!(tree, want(&[("a.bin", 3000)]));
            }
            assert_eq!(seen, [ok("a.bin")]);
            assert_eq!(volumes, 3);
        }
    }
}

#[test]
fn rar5_later_volume_without_the_first_extracts_nothing() {
    // UnRAR: "You need to start extraction from a previous volume to unpack a.bin", "No files to extract", exit 6
    let set = rar5_set(&[2, 3]);
    let (tree, seen, _) = run(set.path(), "set.part2.rar", Mode::Extract);
    assert!(tree.is_empty());
    assert_eq!(seen, [("a.bin".to_owned(), "missing-start")]);
    let set = rar5_set(&[3]);
    let (tree, seen, _) = run(set.path(), "set.part3.rar", Mode::Extract);
    assert!(tree.is_empty());
    assert_eq!(seen, [("a.bin".to_owned(), "missing-start")]);
}

#[test]
fn rar5_volume_starting_with_a_new_member_does_not_restart() {
    // UnRAR on part3 of this set (part1, part2 beside it): only z.bin, exit 0, no start-over
    let vol = |number: Option<u64>, body: Vec<u8>, more: bool| {
        let mut out = SIG.to_vec();
        out.extend(main_block(true, number));
        out.extend(body);
        out.extend(end_block(more));
        out
    };
    let (x, z) = (vec![1u8; 100], vec![9u8; 50]);
    let y: Vec<u8> = (0..200u32).map(|i| i as u8).collect();
    let (sx, sy, sz) = (FileSpec::new("x.bin", &x), FileSpec::new("y.bin", &y), FileSpec::new("z.bin", &z));
    let crc = crc32fast::hash;
    let mut one = file_block(&sx, &x, crc(&x), false, false);
    one.extend(file_block(&sy, &y[..100], crc(&y[..100]), false, true));
    let two = file_block(&sy, &y[100..], crc(&y), true, false);
    let three = file_block(&sz, &z, crc(&z), false, false);
    let dir = tempfile::tempdir().unwrap();
    for (name, bytes) in [
        ("s.part1.rar", vol(None, one, true)),
        ("s.part2.rar", vol(Some(1), two, true)),
        ("s.part3.rar", vol(Some(2), three, false)),
    ] {
        fs::write(dir.path().join(name), bytes).unwrap();
    }
    let (tree, seen, volumes) = run(dir.path(), "s.part3.rar", Mode::Extract);
    assert_eq!(tree, want(&[("z.bin", 50)]));
    assert_eq!(seen, [ok("z.bin")]);
    assert_eq!(volumes, 1);
}

/// Y5: a set numbered without padding (part1 .. part10) restarts from part10, whose predecessor is part9.
#[test]
fn rar5_unpadded_set_restarts_from_part10() {
    let data: Vec<u8> = (0..3000u32).map(|i| (i * 7 % 251) as u8).collect();
    let spec = FileSpec::new("a.bin", &data);
    let dir = tempfile::tempdir().unwrap();
    let vols = volumes(&spec, 300);
    assert_eq!(vols.len(), 10);
    for (i, volume) in vols.iter().enumerate() {
        fs::write(dir.path().join(format!("set.part{}.rar", i + 1)), volume).unwrap();
    }
    for mode in [Mode::Extract, Mode::Test] {
        let (tree, seen, volumes) = run(dir.path(), "set.part10.rar", mode);
        if mode == Mode::Extract {
            assert_eq!(tree, want(&[("a.bin", 3000)]));
        }
        assert_eq!(seen, [ok("a.bin")]);
        assert_eq!(volumes, 10);
    }
}

/// Y4: a selection by listing position means the positions the listing of the volume given shows.
#[test]
fn a_selection_by_ordinal_from_a_later_volume_follows_that_volumes_listing() {
    use zipfast::extract::MemberFilter;
    let set = stage("rar4-volumes", &["multi.part1.rar", "multi.part2.rar", "multi.part3.rar"]);
    // part2 lists file3.txt alone (file2.txt continues from part1), so its ordinal 0 is file3.txt
    for mode in [Mode::Extract, Mode::Test] {
        let out = tempfile::tempdir().unwrap();
        let mut opts = options(out.path(), mode);
        opts.select = Some(MemberFilter::new(|m| m.ordinal == 0));
        let mut seen = Vec::new();
        run_rar_with_outcomes(&set.path().join("multi.part2.rar"), &opts, None, |o| seen.push(o.entry.name.clone()))
            .unwrap();
        assert_eq!(seen, ["file3.txt"], "{mode:?}");
        if mode == Mode::Extract {
            assert_eq!(sizes(out.path()), want(&[("file3.txt", 18)]));
        }
    }
}

#[test]
fn by_default_a_run_from_a_later_volume_walks_forward_only_as_7zip_does() {
    // 7-Zip 26.06 `x multi.part2.rar`: file2 (continued from part1) is a Data Error, file3 is extracted, exit 2;
    // it never opens part1.
    let set = stage("rar4-volumes", &["multi.part1.rar", "multi.part2.rar", "multi.part3.rar"]);
    let out = tempfile::tempdir().unwrap();
    let opts = Options { restart_from_first_volume: false, ..options(out.path(), Mode::Extract) };
    let mut seen = Vec::new();
    run_rar_with_outcomes(&set.path().join("multi.part2.rar"), &opts, None, |outcome| {
        seen.push((outcome.entry.name.clone(), matches!(outcome.outcome, RarOutcome::Verified { .. })));
    })
    .unwrap();
    assert_eq!(seen, [("file2.txt".to_owned(), false), ("file3.txt".to_owned(), true)]);
    assert_eq!(sizes(out.path()), want(&[("file3.txt", 18)]));
}

/// Names of the members a session catalogues (a member continued across volumes listed once).
fn session_names(set: &Path, start: &str, restart: bool) -> (Vec<String>, Option<String>) {
    use zipfast::rar5::session::{RarSession, RarSessionOptions};
    let options = RarSessionOptions { restart_from_first_volume: restart, ..RarSessionOptions::default() };
    let session = RarSession::open(&set.join(start), None, options).unwrap();
    let names = session.entries().map(|e| e.name().to_owned()).collect();
    let from = session.restarted_from().map(|p| p.file_name().unwrap().to_string_lossy().into_owned());
    (names, from)
}

#[test]
fn a_session_opened_at_a_later_volume_restarts_at_the_first_when_asked() {
    let set = stage("rar4-volumes", &["multi.part1.rar", "multi.part2.rar", "multi.part3.rar"]);
    let (names, from) = session_names(set.path(), "multi.part2.rar", true);
    assert_eq!(names, ["file1.txt", "file2.txt", "file3.txt"]);
    assert_eq!(from.as_deref(), Some("multi.part1.rar"));
    {
        use zipfast::rar5::session::{RarSession, RarSessionOptions};
        let options = RarSessionOptions { restart_from_first_volume: true, ..RarSessionOptions::default() };
        let session = RarSession::open(&set.path().join("multi.part2.rar"), None, options).unwrap();
        // file1 starts in part1, before the volume named; file2 (continued into part2) starts there too.
        assert_eq!(session.members_before_named(), 2);
        let session =
            RarSession::open(&set.path().join("multi.part3.rar"), None, RarSessionOptions::default()).unwrap();
        assert_eq!(session.members_before_named(), 0);
    }
    // Off (the default): the catalogue starts at the named volume, as before.
    let (names, from) = session_names(set.path(), "multi.part2.rar", false);
    assert!(!names.contains(&"file1.txt".to_owned()), "{names:?}");
    assert!(from.is_none());
    // Old naming: the .r00 goes back to the .rar.
    let set = stage("rar4-rar300", &["multivol_oldnaming_rar300.rar", "multivol_oldnaming_rar300.r00"]);
    let (names, from) = session_names(set.path(), "multivol_oldnaming_rar300.r00", true);
    assert_eq!(names, ["bigtext_64k.bin"]);
    assert_eq!(from.as_deref(), Some("multivol_oldnaming_rar300.rar"));
    // An earlier volume missing: no restart.
    let set = stage("rar4-volumes", &["multi.part2.rar", "multi.part3.rar"]);
    let (_, from) = session_names(set.path(), "multi.part2.rar", true);
    assert!(from.is_none());
    // RAR 5.0, from the last of three volumes.
    let set = rar5_set(&[1, 2, 3]);
    let (names, from) = session_names(set.path(), "set.part3.rar", true);
    assert_eq!(names, ["a.bin"]);
    assert_eq!(from.as_deref(), Some("set.part1.rar"));
}

/// Restart discovery is read under the session's cancellation and budget, and opens volumes without blocking.
#[test]
fn session_restart_discovery_honours_cancellation_budgets_and_fifos() {
    use zipfast::rar5::session::{RarCatalogueLimits, RarSession, RarSessionOptions};
    let set = stage("rar4-volumes", &["multi.part1.rar", "multi.part2.rar", "multi.part3.rar"]);
    let named = set.path().join("multi.part2.rar");
    // Already canceled: nothing is scanned.
    let cancel = zipfast::extract::Cancellation::default();
    cancel.cancel();
    let options = RarSessionOptions { restart_from_first_volume: true, cancel, ..RarSessionOptions::default() };
    let failure = RarSession::open(&named, None, options).err().expect("canceled");
    assert!(format!("{failure:?}").contains("Canceled"), "{failure:?}");
    // A header-block budget too small for the probes is a limit failure, not an unbounded walk.
    let limits = RarCatalogueLimits { header_blocks: 1, ..RarCatalogueLimits::default() };
    let options = RarSessionOptions { restart_from_first_volume: true, limits, ..RarSessionOptions::default() };
    let failure = RarSession::open(&named, None, options).err().expect("limit");
    assert!(format!("{failure:?}").contains("Limit"), "{failure:?}");
    // A FIFO in place of the first volume: the probe neither blocks nor restarts.
    let dir = tempfile::tempdir().unwrap();
    for name in ["multi.part2.rar", "multi.part3.rar"] {
        fs::copy(fixtures("rar4-volumes").join(name), dir.path().join(name)).unwrap();
    }
    let fifo = dir.path().join("multi.part1.rar");
    assert!(std::process::Command::new("mkfifo").arg(&fifo).status().unwrap().success());
    let named = dir.path().join("multi.part2.rar");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let options = RarSessionOptions { restart_from_first_volume: true, ..RarSessionOptions::default() };
        let opened = RarSession::open(&named, None, options).map(|s| s.restarted_from().is_none());
        let _ = tx.send(opened.ok());
    });
    let got = rx.recv_timeout(std::time::Duration::from_secs(20)).expect("RarSession::open must not block on a FIFO");
    assert_eq!(got, Some(true), "no restart through a FIFO");
}

/// Codex review of #286: an output descriptor that aliases an earlier volume the restart probe opens is refused, as
/// for any input the session opens, not taken as "no restart".
#[test]
fn a_restart_probe_refuses_an_output_aliasing_an_earlier_volume() {
    use zipfast::rar5::session::{RarSession, RarSessionOptions};
    let set = stage("rar4-volumes", &["multi.part1.rar", "multi.part2.rar", "multi.part3.rar"]);
    let alias = set.path().join("out.bin");
    fs::hard_link(set.path().join("multi.part1.rar"), &alias).unwrap();
    let output = fs::OpenOptions::new().append(true).open(&alias).unwrap();
    let options = RarSessionOptions { restart_from_first_volume: true, ..RarSessionOptions::default() };
    let failure = RarSession::open_with_output_file(&set.path().join("multi.part2.rar"), None, options, &output)
        .err()
        .expect("an output aliasing part1 is refused");
    assert!(format!("{failure:?}").contains("OutputAliasesInput"), "{failure:?}");
}
