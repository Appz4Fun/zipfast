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
