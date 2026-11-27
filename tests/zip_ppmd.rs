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

//! ZIP method 98 (PPMd variant I revision 1) as 7-Zip writes it, on the plain and the checked routes.
use std::fs;
use std::path::{Path, PathBuf};

use zipfast::extract::{self, Mode, Options, Overwrite};

const W150_SHA256: &str = "081533bffe507c87cd53f3f342c7c3d5eb11dd193fe3f46fb8fcb80c41db9243";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/zip-ppmd").join(name)
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
        damaged_input: Default::default(),
        unsupported_filters: Default::default(),
        unverified_output: Default::default(),
        salvage_truncated_zip: false,
        unix_modes: Default::default(),
        backslashes: Default::default(),
    }
}

fn hex(d: [u8; 32]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

fn assert_outputs(dest: &Path) {
    assert_eq!(hex(zipfast::crypto::sha256(&fs::read(dest.join("w150.txt")).unwrap())), W150_SHA256);
    assert_eq!(fs::read(dest.join("small.txt")).unwrap(), b"hello ppmd\n".repeat(50));
}

const FIXTURES: [&str; 3] = ["ppmd-o6-restart.zip", "ppmd-o8-cutoff.zip", "ppmd-o16-cutoff.zip"];

#[test]
fn restart_and_cut_off_models_extract_on_the_plain_route() {
    for name in FIXTURES {
        let dir = tempfile::tempdir().unwrap();
        let s = extract::run(&fixture(name), &options(dir.path(), Mode::Extract), |_| {}).unwrap();
        assert!(s.errors.is_empty(), "{name}: {:?}", s.errors);
        assert_outputs(dir.path());
        let t = extract::run(&fixture(name), &options(dir.path(), Mode::Test), |_| {}).unwrap();
        assert_eq!((t.files, t.errors.len()), (2, 0), "{name}");
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn restart_and_cut_off_models_extract_on_the_checked_route() {
    use zipfast::extract::Cancellation;
    for name in FIXTURES {
        let dir = tempfile::tempdir().unwrap();
        let report = zipfast::zip::run_with_policy(
            &fixture(name),
            &options(dir.path(), Mode::Extract),
            None,
            &Cancellation::default(),
            &Default::default(),
            |_: zipfast::zip::ZipRunEvent<'_>| Ok(()),
        )
        .unwrap();
        assert_eq!((report.files(), report.failed()), (2, 0), "{name}");
        assert_outputs(dir.path());
    }
}

#[test]
fn aes_encrypted_ppmd_extracts_with_its_password() {
    let dir = tempfile::tempdir().unwrap();
    let s = extract::run_with_password(
        &fixture("ppmd-aes.zip"),
        &options(dir.path(), Mode::Extract),
        Some("password"),
        |_| {},
    )
    .unwrap();
    assert!(s.errors.is_empty(), "{:?}", s.errors);
    assert_eq!(fs::read(dir.path().join("small.txt")).unwrap(), b"hello ppmd\n".repeat(50));
}

#[test]
fn damaged_ppmd_data_fails_its_member_only() {
    let dir = tempfile::tempdir().unwrap();
    let mut bytes = fs::read(fixture("ppmd-o8-cutoff.zip")).unwrap();
    // flip bytes well inside the first member's data (it follows a 30-byte header and its name)
    for at in [2000usize, 2001, 9000, 30000] {
        bytes[at] ^= 0x5a;
    }
    let archive = dir.path().join("bad.zip");
    fs::write(&archive, bytes).unwrap();
    let s = extract::run(&archive, &options(&dir.path().join("out"), Mode::Test), |_| {}).unwrap();
    assert_eq!((s.files, s.errors.len()), (1, 1), "{:?}", s.errors);
}
