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

//! `MemberFilter::on_start` sees each member as it starts to be written, with its final path, in order, and can
//! decline it; staged temporaries carry the `.zipfast-` prefix.

#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use zipfast::extract::{self, MemberFilter, Mode, Options, Overwrite, RarOutcome, RarSkipReason, StartDecision};

fn fixture(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(rel)
}

fn options(dest: &Path, overwrite: Overwrite, select: MemberFilter) -> Options {
    Options {
        mode: Mode::Extract,
        dest: dest.into(),
        overwrite,
        flatten: false,
        threads: Some(1),
        protected_paths: Default::default(),
        parallel_min: None,
        select: Some(select),
        windows_safe_names: false,
    }
}

/// A hook that records each path it sees and lets only the first `limit` through.
fn limited(limit: usize) -> (MemberFilter, Arc<Mutex<Vec<PathBuf>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    let filter = MemberFilter::all().on_start(move |m| {
        let mut seen = log.lock().unwrap();
        seen.push(m.path.to_path_buf());
        if seen.len() <= limit { StartDecision::Write } else { StartDecision::Skip }
    });
    (filter, seen)
}

fn files(dir: &Path) -> Vec<String> {
    let mut out: Vec<String> =
        walk(dir).into_iter().map(|p| p.strip_prefix(dir).unwrap().display().to_string()).collect();
    out.sort();
    out
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else {
            out.push(path);
        }
    }
    out
}

/// Each format's whole-archive run asks the hook in order and writes only what it lets through.
#[test]
fn the_hook_counts_and_limits_members_in_order() {
    for (archive, all) in [("rar4-volumes/multi.part1.rar", 3), ("7z-extract/copy.7z", 3)] {
        let tmp = tempfile::tempdir().unwrap();
        let (filter, seen) = limited(2);
        let summary = extract::run(&fixture(archive), &options(tmp.path(), Overwrite::Skip, filter), |_| {}).unwrap();
        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen.len(), all, "{archive}: every member that would be written is offered");
        assert_eq!((summary.files, summary.skipped), (2, all as u64 - 2), "{archive}");
        // in order, and only the ones let through are on disk
        let written: Vec<String> =
            seen[..2].iter().map(|p| p.strip_prefix(tmp.path()).unwrap().display().to_string()).collect();
        assert_eq!(files(tmp.path()), written, "{archive}");
    }
}

/// With a rename mode the hook sees the renamed path; a declined member lets the name it claimed go.
#[test]
fn the_hook_sees_the_final_name_after_a_rename() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("file1.txt"), b"old").unwrap();
    fs::write(tmp.path().join("file2.txt"), b"old").unwrap();
    let (filter, seen) = limited(1);
    let summary = extract::run(
        &fixture("rar4-volumes/multi.part1.rar"),
        &options(tmp.path(), Overwrite::RenameNew(zipfast::extract::RenameStyle::Underscore), filter),
        |_| {},
    )
    .unwrap();
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen[0], tmp.path().join("file1_1.txt"), "{seen:?}");
    assert_eq!(seen[1], tmp.path().join("file2_1.txt"), "{seen:?}");
    assert_eq!(summary.files, 1);
    // file2's declined rename leaves neither a file nor a record
    assert_eq!(files(tmp.path()), ["file1.txt", "file1_1.txt", "file2.txt"]);
    assert_eq!(summary.renames.len(), 1, "{:?}", summary.renames);
    assert_eq!(fs::read(tmp.path().join("file1.txt")).unwrap(), b"old");
}

/// A typed RAR run reports a declined member as skipped, with its own reason.
#[test]
fn a_declined_rar_member_is_a_typed_skip() {
    let tmp = tempfile::tempdir().unwrap();
    let (filter, _) = limited(0);
    let mut skips = Vec::new();
    extract::run_rar_with_outcomes(
        &fixture("rar4-volumes/multi.part1.rar"),
        &options(tmp.path(), Overwrite::Skip, filter),
        None,
        |o| {
            if let RarOutcome::Skipped(reason) = o.outcome {
                skips.push(reason);
            }
        },
    )
    .unwrap();
    assert_eq!(skips, [RarSkipReason::Declined; 3]);
    assert!(files(tmp.path()).is_empty());
}

/// The prefix staged output is created under is public, so a caller can skip a temporary a crash left behind.
#[test]
fn the_staged_prefix_is_public() {
    assert_eq!(zipfast::STAGED_PREFIX, ".zipfast-");
}
