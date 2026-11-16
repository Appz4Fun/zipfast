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

//! A raw byte-split ZIP (`.zip.001`, ...) lists, inspects and extracts as the pieces concatenated, as 7-Zip reads it.
use std::fs;
use std::path::{Path, PathBuf};

use zipfast::extract::{self, Inspection, Mode, Options, Overwrite};

fn first() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/zip-bytesplit/bytesplit.zip.001")
}

fn options(dest: &Path, mode: Mode) -> Options {
    Options {
        mode,
        dest: dest.to_path_buf(),
        overwrite: Overwrite::Always,
        flatten: false,
        threads: Some(1),
        protected_paths: Default::default(),
        parallel_min: None,
        select: None,
    }
}

fn names(entries: &[extract::Entry]) -> Vec<(&str, u64)> {
    entries.iter().map(|e| (e.name.as_str(), e.size)).collect()
}

#[test]
fn lists_and_inspects_the_whole_set() {
    let entries = extract::list(&first()).unwrap();
    assert_eq!(names(&entries), [("noise.bin", 3000), ("tiny.txt", 5)]);
    assert_eq!(entries[1].crc32, Some(crc32fast::hash(b"tiny\n")));
    match extract::inspect(&first()).unwrap() {
        Inspection::Other(entries) => assert_eq!(names(&entries), [("noise.bin", 3000), ("tiny.txt", 5)]),
        _ => panic!("a byte-split ZIP inspects as a listing"),
    }
}

#[test]
fn tests_and_extracts_across_pieces() {
    let dir = tempfile::tempdir().unwrap();
    let crc = extract::list(&first()).unwrap()[0].crc32.unwrap();
    let tested = extract::run(&first(), &options(dir.path(), Mode::Test), |_| {}).unwrap();
    assert_eq!((tested.files, tested.volumes, tested.errors.len()), (2, 4, 0), "{:?}", tested.errors);
    let extracted = extract::run(&first(), &options(dir.path(), Mode::Extract), |_| {}).unwrap();
    assert_eq!((extracted.files, extracted.errors.len()), (2, 0), "{:?}", extracted.errors);
    let noise = fs::read(dir.path().join("noise.bin")).unwrap();
    assert_eq!((noise.len(), crc32fast::hash(&noise)), (3000, crc));
    assert_eq!(fs::read(dir.path().join("tiny.txt")).unwrap(), b"tiny\n");
}

#[test]
fn a_lone_first_piece_is_an_ordinary_zip() {
    // Only the first piece: not a set, so the ZIP reader sees a truncated archive.
    let dir = tempfile::tempdir().unwrap();
    let lone = dir.path().join("lone.zip.001");
    fs::copy(first(), &lone).unwrap();
    assert!(extract::list(&lone).is_err());
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn checked_entry_points_route_the_set_through_the_split_layer() {
    use zipfast::extract::{Cancellation, ProjectedInspection};
    match extract::inspect_projected_cancelable(&first(), None, &Cancellation::default()).unwrap() {
        ProjectedInspection::Other(entries) => assert_eq!(names(&entries), [("noise.bin", 3000), ("tiny.txt", 5)]),
        _ => panic!("a byte-split ZIP inspects as a listing"),
    }
}
