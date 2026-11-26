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

//! Deflate64 (ZIP method 9, 7z coder 040109) through every read path, against archives 7-Zip wrote
//! (`tests/fixtures/deflate64`, see its README).
#![allow(clippy::result_large_err)]
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use zipfast::extract::{self, Cancellation, Mode, Options, Overwrite, SelectedEntry};
use zipfast::zip::{Archive, IntegrityReason, ReadFault, ReadSession, ZipRunEvent};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/deflate64");
const ALL: [&str; 4] = ["far.bin", "runs.bin", "small.txt", "text.txt"];
const SMALL: [&str; 2] = ["small.txt", "text.txt"];
/// Every fixture with its password and members.
const ARCHIVES: [(&str, Option<&str>, &[&str]); 4] = [
    ("d64.zip", None, &ALL),
    ("d64_zipcrypto.zip", Some("password"), &SMALL),
    ("d64_aes.zip", Some("password"), &SMALL),
    ("d64.7z", None, &ALL),
];

fn fixture(name: &str) -> PathBuf {
    Path::new(FIXTURES).join(name)
}

fn expected() -> HashMap<String, (usize, String)> {
    fs::read_to_string(fixture("expected.txt"))
        .unwrap()
        .lines()
        .map(|line| {
            let parts: Vec<&str> = line.split(' ').collect();
            (parts[0].to_owned(), (parts[1].parse().unwrap(), parts[2].to_owned()))
        })
        .collect()
}

fn sha(data: &[u8]) -> String {
    zipfast::crypto::sha256(data).iter().map(|b| format!("{b:02x}")).collect()
}

fn check(archive: &str, name: &str, data: &[u8]) {
    let want = &expected()[name];
    assert_eq!((data.len(), sha(data)), (want.0, want.1.clone()), "{archive}: {name}");
}

fn opts(dest: &Path) -> Options {
    Options {
        mode: Mode::Extract,
        dest: dest.to_path_buf(),
        overwrite: Overwrite::Skip,
        flatten: false,
        threads: None,
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
        unix_modes: Default::default(),
        backslashes: Default::default(),
    }
}

fn check_tree(archive: &str, out: &Path, members: &[&str]) {
    for name in members {
        check(archive, name, &fs::read(out.join(name)).unwrap_or_else(|e| panic!("{archive}: {name}: {e}")));
    }
}

#[test]
fn the_checked_zip_policy_run_extracts_deflate64() {
    for (archive, password, members) in ARCHIVES {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        let mut failed = Vec::new();
        let report = extract::run_with_zip_policy(
            &fixture(archive),
            &opts(&out),
            password,
            &Cancellation::default(),
            &Default::default(),
            |event: ZipRunEvent<'_>| {
                if let ZipRunEvent::MemberFailed { name, error, .. } = event {
                    failed.push(format!("{name}: {error:?}"));
                }
                Ok(())
            },
        )
        .unwrap_or_else(|e| panic!("{archive}: {e:?}"));
        assert!(failed.is_empty(), "{archive}: {failed:?}");
        assert_eq!((report.files(), report.failed()), (members.len() as u64, 0), "{archive}");
        check_tree(archive, &out, members);
    }
}

#[test]
fn extract_run_extracts_and_tests_deflate64() {
    for (archive, password, members) in ARCHIVES {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        let mut lines = Vec::new();
        let summary =
            extract::run_with_password(&fixture(archive), &opts(&out), password, |l| lines.push(l.to_owned()))
                .unwrap_or_else(|e| panic!("{archive}: {e}"));
        assert!(summary.errors.is_empty() && lines.is_empty(), "{archive}: {:?} {lines:?}", summary.errors);
        assert_eq!(summary.files, members.len() as u64, "{archive}");
        check_tree(archive, &out, members);
        let test = Options { mode: Mode::Test, ..opts(&dir.path().join("t")) };
        let tested = extract::run_with_password(&fixture(archive), &test, password, |_| {}).unwrap();
        assert_eq!((tested.files, tested.errors.len()), (members.len() as u64, 0), "{archive}");
    }
    // Without a password the encrypted members are refused, not misread.
    let dir = tempfile::tempdir().unwrap();
    let summary = extract::run(&fixture("d64_aes.zip"), &opts(&dir.path().join("out")), |_| {}).unwrap();
    assert_eq!(summary.errors.len(), 2, "{:?}", summary.errors);
}

/// Index of each member in a ZIP's directory.
fn zip_index(archive: &str) -> Vec<String> {
    Archive::open(&fixture(archive)).unwrap().entries.iter().map(|e| e.name.clone()).collect()
}

#[test]
fn selected_entries_and_the_legacy_archive_read_deflate64() {
    for (archive, password, members) in ARCHIVES.into_iter().filter(|a| a.0.ends_with(".zip")) {
        let names = zip_index(archive);
        assert_eq!(names.len(), members.len());
        let mut legacy = Archive::open(&fixture(archive)).unwrap();
        for (index, name) in names.iter().enumerate() {
            let mut out = Vec::new();
            SelectedEntry::open(&fixture(archive), index, password, 1 << 20)
                .unwrap()
                .read(password, |chunk| {
                    out.extend_from_slice(chunk);
                    Ok(())
                })
                .unwrap_or_else(|e| panic!("{archive}: {name}: {e}"));
            check(archive, name, &out);
            let mut out = Vec::new();
            SelectedEntry::open_cancelable_with_zip_limit(
                &fixture(archive),
                index,
                password,
                1 << 20,
                None,
                Cancellation::default(),
            )
            .unwrap()
            .read(password, |chunk| {
                out.extend_from_slice(chunk);
                Ok(())
            })
            .unwrap_or_else(|e| panic!("{archive}: {name}: {e}"));
            check(archive, name, &out);
            let mut out = Vec::new();
            legacy
                .read_at(index, password, 1 << 20, |chunk| {
                    out.extend_from_slice(chunk);
                    Ok(())
                })
                .unwrap_or_else(|e| panic!("{archive}: {name}: {e}"));
            check(archive, name, &out);
        }
    }
}

#[test]
fn sessions_and_listings_name_the_method() {
    let mut session = ReadSession::open(&fixture("d64.zip")).unwrap();
    let names: Vec<(String, &str, u16)> = session
        .metadata()
        .entries()
        .map(|e| (e.name().to_owned(), e.compression_name(), e.effective_method()))
        .collect();
    assert_eq!(names.len(), 4);
    for (index, (name, method, effective)) in names.iter().enumerate() {
        assert_eq!((*method, *effective), ("Deflate64", 9), "{name}");
        let id = session.metadata().entry_id(index).unwrap();
        let mut out = Vec::new();
        session
            .select(&id, 1 << 20, Cancellation::default())
            .unwrap()
            .read(None, |chunk| {
                out.extend_from_slice(chunk);
                Ok(())
            })
            .unwrap();
        check("d64.zip", name, &out);
    }
    for archive in ["d64.zip", "d64.7z"] {
        let entries = extract::list(&fixture(archive)).unwrap();
        assert_eq!(entries.len(), 4);
        assert!(entries.iter().all(|e| e.method == 9), "{archive}: {:?}", entries.iter().map(|e| e.method));
    }
}

/// `d64.zip` with the CRC of `text.txt` changed in both its local header and its directory record.
fn bad_crc(dir: &Path) -> PathBuf {
    let mut bytes = fs::read(fixture("d64.zip")).unwrap();
    let mut patched = 0;
    for sig in [&b"PK\x03\x04"[..], &b"PK\x01\x02"[..]] {
        let (crc_at, name_at) = if sig[2] == 3 { (14, 30) } else { (16, 46) };
        let mut at = 0;
        while let Some(found) = bytes[at..].windows(4).position(|w| w == sig) {
            let start = at + found;
            if bytes[start + name_at..].starts_with(b"text.txt") {
                bytes[start + crc_at] ^= 0x55;
                patched += 1;
            }
            at = start + 4;
        }
    }
    assert_eq!(patched, 2);
    let path = dir.join("bad.zip");
    fs::write(&path, bytes).unwrap();
    path
}

#[test]
fn a_bad_crc_is_refused_on_every_path() {
    let dir = tempfile::tempdir().unwrap();
    let archive = bad_crc(dir.path());
    let out = dir.path().join("out");
    let mut failed = Vec::new();
    let report = extract::run_with_zip_policy(
        &archive,
        &opts(&out),
        None,
        &Cancellation::default(),
        &Default::default(),
        |event: ZipRunEvent<'_>| {
            if let ZipRunEvent::MemberFailed { name, error, .. } = event {
                let checksum =
                    matches!(error.operation(), Some(ReadFault::Integrity { reason: IntegrityReason::Checksum, .. }));
                failed.push((name.to_owned(), checksum));
            }
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(report.failed(), 1);
    assert_eq!(failed, [("text.txt".to_owned(), true)]);
    assert!(!out.join("text.txt").exists() && out.join("far.bin").exists());

    let out = dir.path().join("legacy");
    let summary = extract::run(&archive, &opts(&out), |_| {}).unwrap();
    assert_eq!(summary.errors.len(), 1, "{:?}", summary.errors);
    assert!(summary.errors[0].contains("text.txt"), "{:?}", summary.errors);
    assert!(!out.join("text.txt").exists());

    let index = zip_index("d64.zip").iter().position(|n| n == "text.txt").unwrap();
    let selected = SelectedEntry::open(&archive, index, None, 1 << 20).unwrap().read(None, |_| Ok(()));
    assert!(selected.is_err());
    let mut legacy = Archive::open(&archive).unwrap();
    assert!(legacy.read_at(index, None, 1 << 20, |_| Ok(())).is_err());
}

#[test]
fn damaged_deflate64_data_is_an_integrity_failure() {
    let dir = tempfile::tempdir().unwrap();
    let mut bytes = fs::read(fixture("d64.zip")).unwrap();
    // far.bin comes first; its stream starts with stored blocks, so break the first block header instead of data.
    let start = 30 + "far.bin".len() + usize::from(u16::from_le_bytes([bytes[28], bytes[29]]));
    bytes[start] |= 0b110; // block type 3
    let archive = dir.path().join("damaged.zip");
    fs::write(&archive, bytes).unwrap();
    let mut failed = Vec::new();
    let report = extract::run_with_zip_policy(
        &archive,
        &opts(&dir.path().join("out")),
        None,
        &Cancellation::default(),
        &Default::default(),
        |event: ZipRunEvent<'_>| {
            if let ZipRunEvent::MemberFailed { error, .. } = event {
                failed.push(matches!(
                    error.operation(),
                    Some(ReadFault::Integrity { reason: IntegrityReason::Decoder, .. })
                ));
            }
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(report.failed(), 1);
    assert_eq!(failed, [true], "a decoder fault");
    let summary = extract::run(&archive, &opts(&dir.path().join("legacy")), |_| {}).unwrap();
    assert_eq!(summary.errors.len(), 1, "{:?}", summary.errors);
}

#[test]
fn a_damaged_7z_deflate64_folder_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let mut bytes = fs::read(fixture("d64.7z")).unwrap();
    // The packed stream follows the 32-byte signature header; break its first block header.
    bytes[32] |= 0b110;
    let archive = dir.path().join("damaged.7z");
    fs::write(&archive, bytes).unwrap();
    let out = dir.path().join("out");
    let result = extract::run(&archive, &opts(&out), |_| {});
    let failed = match &result {
        Ok(summary) => !summary.errors.is_empty(),
        Err(_) => true,
    };
    assert!(failed, "{result:?}");
    assert!(!out.join("far.bin").exists());
}
