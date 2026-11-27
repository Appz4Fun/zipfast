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

//! `extract::Options::rar4_raw_names` and `extract::Options::folder_times` against `rar4/corrupted.rar` (also
//! Prybar's `seven-list/rar4-rawname.rar`, the same bytes): a solid RAR 1.5 archive whose legacy names hold bytes
//! that aren't UTF-8 and whose stream breaks after its first file, so every later file fails its checksum.
//!
//! Expected values are what UnRAR 7.30 `x -y` and 7-Zip 26.06 `x -y` left on Linux (ext4 in Docker, `TZ=UTC`):
//!
//! - both write the first file under its raw bytes, `test/C\x85:5\xe5\xcbB'` (82 bytes, sha256 60603e05...);
//! - UnRAR sets a folder's time when it reaches the folder's entry and never again: `test/a`, `test/a.a`,
//!   `test/a.a.a`, `test/a.a.a/a.a` and `test/a.a/a.a.a` get a file (written, failed and removed) or a folder
//!   created in them after their entry, and are left at the extraction time; the other folders keep their times;
//! - 7-Zip sets every folder's time at the end, so all keep their archived times.
#![cfg(unix)]

use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use zipfast::extract::{self, FolderTimes, Mode, Options, Overwrite};

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rar4/corrupted.rar");

/// The first file, whose data checks out: its name as stored (raw bytes), and its sha256.
const RAW_NAME: &[u8] = b"test/C\x85:5\xe5\xcbB'";
const PRIVATE_USE_NAME: &str = "test/C\u{E085}:5\u{E0E5}\u{E0CB}B'";
const FIRST_SHA256: &str = "60603e05cb8c64bb9bb2f668c5ce12136a40f58e0dd195a2ac0de90ba43e6c15";
const FIRST_MTIME: u64 = 1_159_441_442;

/// Every folder with the time 7-Zip leaves it (its archived time), and whether UnRAR leaves it at the extraction
/// time instead.
const FOLDERS: &[(&str, u64, bool)] = &[
    ("test", 1_159_441_875, false),
    ("test/a", 1_159_441_863, true),
    ("test/a.a", 1_159_441_874, true),
    ("test/a.a.a", 1_159_441_664, true),
    ("test/a.a.a.a", 1_159_441_653, false),
    ("test/a.a.a.a/a", 1_159_441_653, false),
    ("test/a.a.a.a/a.a", 1_159_441_688, false),
    ("test/a.a.a.a/a.a.a", 1_159_441_653, false),
    ("test/a.a.a.a/a.a.a.a", 1_159_441_620, false),
    ("test/a.a.a/a", 1_159_441_653, false),
    ("test/a.a.a/a.a", 1_159_441_776, true),
    ("test/a.a.a/a.a.a", 1_159_441_620, false),
    ("test/a.a.a/a.a.a.a", 1_159_441_653, false),
    ("test/a.a/a", 1_159_441_653, false),
    ("test/a.a/a.a", 1_159_441_620, false),
    ("test/a.a/a.a.a", 1_159_441_851, true),
    ("test/a.a/a.a.a.a", 1_159_441_696, false),
    ("test/a/a", 1_159_441_620, false),
    ("test/a/a.a", 1_159_441_681, false),
    ("test/a/a.a.a", 1_159_441_653, false),
    ("test/a/a.a.a.a", 1_159_441_653, false),
];

fn options(dest: &Path, threads: usize, raw: bool, folder_times: FolderTimes) -> Options {
    Options {
        mode: Mode::Extract,
        dest: dest.to_path_buf(),
        overwrite: Overwrite::Always,
        flatten: false,
        threads: Some(threads),
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
        rar4_raw_names: raw,
        folder_times,
        unix_modes: Default::default(),
        backslashes: Default::default(),
        hard_link_targets: Default::default(),
    }
}

fn mtime(path: &Path) -> SystemTime {
    fs::symlink_metadata(path).unwrap().modified().unwrap()
}

fn seconds(at: SystemTime) -> u64 {
    at.duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn sha256_hex(data: &[u8]) -> String {
    zipfast::crypto::sha256(data).iter().map(|b| format!("{b:02x}")).collect()
}

/// The files the run left, as raw names, sorted.
#[cfg(unix)]
fn files(dest: &Path) -> Vec<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    fn walk(dir: &Path, root: &Path, out: &mut Vec<Vec<u8>>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if fs::symlink_metadata(&path).unwrap().is_dir() {
                walk(&path, root, out);
            } else {
                out.push(path.strip_prefix(root).unwrap().as_os_str().as_bytes().to_vec());
            }
        }
    }
    let mut out = Vec::new();
    walk(dest, dest, &mut out);
    out.sort();
    out
}

fn run(dest: &Path, threads: usize, raw: bool, folder_times: FolderTimes) -> extract::Summary {
    extract::run(Path::new(FIXTURE), &options(dest, threads, raw, folder_times), |_| {}).unwrap()
}

/// UnRAR 7.30 and 7-Zip 26.06 on Linux: `test/C\x85:5\xe5\xcbB'`, under its raw bytes.
#[test]
#[cfg(target_os = "linux")]
fn a_raw_rar4_name_is_written_under_its_bytes_when_asked() {
    use std::os::unix::ffi::OsStrExt;
    let dir = tempfile::tempdir().unwrap();
    for threads in [1, 4] {
        let out = dir.path().join(format!("raw-{threads}"));
        let summary = run(&out, threads, true, FolderTimes::AtEnd);
        assert!(!summary.errors.is_empty(), "the later files fail their checksums");
        let first = out.join(std::ffi::OsStr::from_bytes(RAW_NAME));
        assert_eq!(sha256_hex(&fs::read(&first).unwrap()), FIRST_SHA256, "{threads}");
        assert_eq!(seconds(mtime(&first)), FIRST_MTIME);
        // as UnRAR leaves it: only that file, and no private-use name or probe left behind
        assert_eq!(files(&out), vec![RAW_NAME.to_vec()], "{threads}");
    }
}

/// A file system that takes only UTF-8 names (APFS refuses the bytes with EILSEQ) keeps the private-use name.
#[test]
#[cfg(target_os = "macos")]
fn a_raw_rar4_name_keeps_its_private_use_name_where_the_bytes_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("raw");
    run(&out, 1, true, FolderTimes::AtEnd);
    let first = out.join(PRIVATE_USE_NAME);
    assert_eq!(sha256_hex(&fs::read(&first).unwrap()), FIRST_SHA256);
    assert_eq!(files(&out), vec![PRIVATE_USE_NAME.as_bytes().to_vec()]);
}

/// The default is unchanged: the private-use name, valid UTF-8 on every file system.
#[test]
#[cfg(unix)]
fn a_raw_rar4_name_keeps_its_private_use_name_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("default");
    run(&out, 1, false, FolderTimes::AtEnd);
    let first = out.join(PRIVATE_USE_NAME);
    assert_eq!(sha256_hex(&fs::read(&first).unwrap()), FIRST_SHA256);
    assert_eq!(files(&out), vec![PRIVATE_USE_NAME.as_bytes().to_vec()]);
}

/// 7-Zip 26.06 (and the default): every folder keeps its archived time.
#[test]
#[cfg(unix)]
fn folder_times_at_end_keep_every_archived_time() {
    let dir = tempfile::tempdir().unwrap();
    for threads in [1, 4] {
        let out = dir.path().join(format!("end-{threads}"));
        run(&out, threads, false, FolderTimes::AtEnd);
        for &(folder, archived, _) in FOLDERS {
            assert_eq!(seconds(mtime(&out.join(folder))), archived, "{threads} {folder}");
        }
    }
}

/// UnRAR 7.30: a folder's time is set at its entry; the five folders that get a file or folder created (a failed
/// file created and removed included) after their entry are left at the extraction time.
#[test]
#[cfg(unix)]
fn folder_times_at_entry_leave_later_changes_as_unrar_does() {
    let dir = tempfile::tempdir().unwrap();
    for (threads, raw) in [(1, false), (4, false), (1, true), (4, true)] {
        let out = dir.path().join(format!("entry-{threads}-{raw}"));
        // file systems keep times coarser than the clock on some hosts
        let started = SystemTime::now() - Duration::from_secs(2);
        run(&out, threads, raw, FolderTimes::AtEntry);
        for &(folder, archived, moved) in FOLDERS {
            let at = mtime(&out.join(folder));
            if moved {
                assert!(at >= started, "{threads} {raw} {folder}: left at the extraction time, not {at:?}");
            } else {
                assert_eq!(seconds(at), archived, "{threads} {raw} {folder}");
            }
        }
    }
}
