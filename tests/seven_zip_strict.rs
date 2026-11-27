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

//! `extract::Options::seven_zip_strict`: the end checks 7-Zip 26.06 makes on a 7z folder decoded to its end, and its
//! comparison of a ZIP member's local header with its central record. Every fixture in
//! `tests/fixtures/seven-zip-strict` (written by its `gen.py` from archives 7-Zip wrote) carries 7-Zip's `t` verdict
//! in its README; each case below checks zipfast against it, and that nothing changes with the option off.
use std::fs;
use std::path::{Path, PathBuf};

use zipfast::extract::{self, Cancellation, FolderDamageKind, MemberFilter, Mode, Options, Overwrite};
use zipfast::sevenzip::{self, SevenZipLimits, SevenZipPrintOptions};
use zipfast::zip::{PublicationState, ReadFault, ZipRunEvent};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/seven-zip-strict").join(name)
}

fn options(mode: Mode, dest: &Path, strict: bool) -> Options {
    Options {
        mode,
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
        encrypted_links: Default::default(),
        damaged_input: Default::default(),
        unsupported_filters: Default::default(),
        unverified_output: Default::default(),
        salvage_truncated_zip: false,
        seven_zip_strict: strict,
        unix_modes: Default::default(),
        backslashes: Default::default(),
        hard_link_targets: Default::default(),
    }
}

fn test_run(name: &str, strict: bool) -> extract::Summary {
    let dir = tempfile::tempdir().unwrap();
    extract::run(&fixture(name), &options(Mode::Test, dir.path(), strict), |_| {})
        .unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// Folder damage 7-Zip reports with every member passing its own check: `#N` and how.
const FOLDER_DAMAGE: &[(&str, u64, FolderDamageKind)] = &[
    ("lzma-code.7z", 0, FolderDamageKind::DataError),
    ("lzma-tail.7z", 0, FolderDamageKind::DataError),
    ("lzma2-tail.7z", 0, FolderDamageKind::DataError),
    ("lzma2-chunk-start.7z", 0, FolderDamageKind::DataError),
    ("ppmd-code.7z", 0, FolderDamageKind::DataError),
    ("ppmd-tail.7z", 0, FolderDamageKind::DataError),
    ("bcj2-call-tail.7z", 0, FolderDamageKind::DataError),
    ("bcj2-rc-code.7z", 0, FolderDamageKind::DataError),
    ("deflate-past-size.7z", 0, FolderDamageKind::DataError),
    ("deflate-tail.7z", 0, FolderDamageKind::DataAfterEnd),
    ("deflate64-tail.7z", 0, FolderDamageKind::DataAfterEnd),
    ("deflate64-copy-last-block-empty.7z", 0, FolderDamageKind::DataError),
    ("bzip2-second-stream.7z", 0, FolderDamageKind::DataAfterEnd),
    ("copy-tail.7z", 0, FolderDamageKind::DataAfterEnd),
    ("two-folders-last-tail.7z", 1, FolderDamageKind::DataError),
];

/// What 7-Zip passes: an LZMA end marker after the data, an LZMA2 stream without its end marker.
const CLEAN: &[&str] = &["lzma.7z", "lzma-eos.7z", "lzma2-no-end-marker.7z", "ppmd.7z", "bcj2.7z"];

#[test]
fn a_folder_that_does_not_end_cleanly_is_damage_and_its_members_pass() {
    for &(name, folder, kind) in FOLDER_DAMAGE {
        let quiet = test_run(name, false);
        assert!(quiet.errors.is_empty() && quiet.folder_damage.is_empty(), "{name} off: {:?}", quiet.errors);
        let strict = test_run(name, true);
        assert_eq!(strict.folder_damage.len(), 1, "{name}: {:?}", strict.errors);
        let damage = &strict.folder_damage[0];
        assert_eq!((damage.folder, damage.kind), (folder, kind), "{name}: {damage:?}");
        // the folder's line is the run's only error: every member passed its own check
        assert_eq!(strict.errors, [damage.to_string()], "{name}");
        assert!(strict.errors[0].starts_with(&format!("#{folder}: ")), "{name}: {:?}", strict.errors);
        assert_eq!(strict.files, quiet.files, "{name}");
    }
}

#[test]
fn what_7zip_passes_stays_clean() {
    for name in CLEAN {
        let summary = test_run(name, true);
        assert!(summary.errors.is_empty() && summary.folder_damage.is_empty(), "{name}: {:?}", summary.errors);
        assert!(summary.files >= 2, "{name}");
    }
}

/// A range coder whose first byte isn't 0, and a BZip2 coder given two streams: 7-Zip fails the members ("Data
/// Error : NAME"), and zipfast with the option does too; without it they decode.
#[test]
fn members_7zip_fails_fail() {
    for (name, failed) in [
        ("bcj2-rc-first-byte.7z", &["a.bin", "b.bin"][..]),
        ("ppmd-first-byte.7z", &["a.txt", "b.txt"][..]),
        ("bzip2-two-streams.7z", &["b.txt"][..]),
    ] {
        let strict = test_run(name, true);
        assert!(strict.folder_damage.is_empty(), "{name}");
        let names: Vec<&str> = strict.errors.iter().map(|e| e.split(':').next().unwrap()).collect();
        assert_eq!(names, failed, "{name}: {:?}", strict.errors);
        if name != "ppmd-first-byte.7z" {
            // zipfast's PPMd decoder refuses that stream whatever the option says
            assert!(test_run(name, false).errors.is_empty(), "{name}");
        }
    }
}

#[test]
fn damaged_folders_still_write_their_members() {
    let dir = tempfile::tempdir().unwrap();
    for name in ["lzma-code.7z", "deflate-tail.7z", "bcj2-call-tail.7z"] {
        let out = dir.path().join(name);
        let summary = extract::run(&fixture(name), &options(Mode::Extract, &out, true), |_| {}).unwrap();
        assert_eq!(summary.folder_damage.len(), 1, "{name}");
        let mut written: Vec<String> =
            fs::read_dir(&out).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        written.sort();
        assert_eq!(written.len() as u64, summary.files, "{name}");
        assert_eq!(summary.files, 2, "{name}");
        for file in written {
            assert!(fs::metadata(out.join(&file)).unwrap().len() > 0, "{name}: {file}");
        }
    }
}

/// 7-Zip checks a folder only once it is decoded to its end: `7z t lzma-code.7z a.txt` passes.
#[test]
fn a_folder_not_decoded_to_its_end_is_not_checked() {
    let dir = tempfile::tempdir().unwrap();
    for (take, damaged) in [("a.txt", false), ("b.txt", true)] {
        let mut opts = options(Mode::Test, dir.path(), true);
        opts.select = Some(MemberFilter::new(move |m| m.name == take));
        let summary = extract::run(&fixture("lzma-code.7z"), &opts, |_| {}).unwrap();
        assert_eq!(summary.folder_damage.is_empty(), !damaged, "{take}: {:?}", summary.errors);
    }
}

#[test]
fn printing_checks_the_folder_too() {
    for strict in [false, true] {
        let mut out = Vec::new();
        let summary = sevenzip::print_selected_with_options(
            &fixture("ppmd-tail.7z"),
            None,
            &mut |_, _| true,
            &mut |_, bytes| {
                out.extend_from_slice(bytes);
                Ok(())
            },
            &Cancellation::default(),
            &SevenZipLimits::default(),
            &SevenZipPrintOptions::new().seven_zip_strict(strict),
        )
        .unwrap();
        assert_eq!(out.len(), 3000, "both members print");
        assert_eq!(summary.folder_damage.len(), usize::from(strict), "{:?}", summary.errors);
    }
}

#[test]
fn the_checked_dispatcher_reports_folder_damage() {
    let dir = tempfile::tempdir().unwrap();
    let mut lines = Vec::new();
    let mut failed = 0;
    let report = extract::run_with_zip_policy(
        &fixture("copy-tail.7z"),
        &options(Mode::Test, dir.path(), true),
        None,
        &Cancellation::default(),
        &Default::default(),
        |event: ZipRunEvent<'_>| {
            match event {
                ZipRunEvent::LegacyDiagnostic { message } => lines.push(message.to_owned()),
                ZipRunEvent::MemberFailed { .. } => failed += 1,
                _ => {}
            }
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(report.folder_damage(), 1);
    assert_eq!(report.failed(), 1, "the folder's line counts as a failure, as 7-Zip exits 2");
    assert_eq!(failed, 0, "no member failed");
    assert!(lines.iter().any(|l| l.starts_with("#0: there are some data after the end")), "{lines:?}");
}

/// Which fields of `f1.txt` differ.
type Fields = fn(&extract::LocalHeaderMismatch) -> bool;

const LOCAL_MISMATCH: &[(&str, Fields)] = &[
    ("local-crc.zip", |m| m.crc32 && !m.size && !m.method),
    ("local-size.zip", |m| m.size && !m.crc32),
    ("local-method.zip", |m| m.method && !m.crc32),
    ("local-descriptor-flag.zip", |m| m.descriptor_flag && !m.crc32 && !m.size),
    ("central-descriptor-flag.zip", |m| m.descriptor_flag && !m.crc32 && !m.size && !m.method),
];

#[test]
fn a_zip_local_header_that_differs_fails_its_member_on_the_legacy_route() {
    for &(name, fields) in LOCAL_MISMATCH {
        assert!(test_run(name, false).errors.is_empty(), "{name}");
        let summary = test_run(name, true);
        assert_eq!(summary.files, 2, "{name}");
        assert_eq!(summary.local_header_mismatches.len(), 1, "{name}");
        let found = &summary.local_header_mismatches[0];
        assert_eq!((found.ordinal, found.name.as_str()), (1, "f1.txt"), "{name}");
        assert!(fields(found), "{name}: {found:?}");
        assert_eq!(summary.errors, [format!("f1.txt: {found}")], "{name}");
    }
    for name in ["local.zip", "local-streamed-crc.zip"] {
        let summary = test_run(name, true);
        assert!(
            summary.errors.is_empty() && summary.local_header_mismatches.is_empty(),
            "{name}: {:?}",
            summary.errors
        );
    }
}

#[test]
fn a_zip_local_header_that_differs_fails_its_member_on_the_checked_route() {
    let dir = tempfile::tempdir().unwrap();
    for &(name, fields) in LOCAL_MISMATCH {
        for strict in [false, true] {
            let mut failures = Vec::new();
            let report = extract::run_with_zip_policy(
                &fixture(name),
                &options(Mode::Test, dir.path(), strict),
                None,
                &Cancellation::default(),
                &Default::default(),
                |event: ZipRunEvent<'_>| {
                    if let ZipRunEvent::MemberFailed { name, error, .. } = event {
                        let found = match error.operation() {
                            Some(ReadFault::LocalHeaderMismatch(found)) => Some((**found).clone()),
                            _ => None,
                        };
                        failures.push((name.to_owned(), found));
                    }
                    Ok(())
                },
            )
            .unwrap();
            if !strict {
                assert!(failures.is_empty() && report.failed() == 0, "{name}: {failures:?}");
                continue;
            }
            assert_eq!((report.files(), report.failed(), report.local_header_mismatches()), (2, 1, 1), "{name}");
            let [(member, Some(found))] = failures.as_slice() else { panic!("{name}: {failures:?}") };
            assert_eq!((member.as_str(), found.ordinal), ("f1.txt", 1), "{name}");
            assert!(fields(found), "{name}: {found:?}");
        }
    }
}

/// 7-Zip compares a link's local header too ("Headers Error : l1").
#[test]
fn a_link_whose_local_header_differs_fails() {
    let summary = test_run("local-link-crc.zip", true);
    assert_eq!(summary.local_header_mismatches.len(), 1);
    let found = &summary.local_header_mismatches[0];
    assert_eq!((found.ordinal, found.name.as_str(), found.crc32), (1, "l1", true));
    assert_eq!(summary.errors, [format!("l1: {found}")]);
    assert!(test_run("local-link-crc.zip", false).errors.is_empty());
    let dir = tempfile::tempdir().unwrap();
    let mut failed = Vec::new();
    let report = extract::run_with_zip_policy(
        &fixture("local-link-crc.zip"),
        &options(Mode::Test, dir.path(), true),
        None,
        &Cancellation::default(),
        &Default::default(),
        |event: ZipRunEvent<'_>| {
            if let ZipRunEvent::MemberFailed { name, error, .. } = event {
                failed.push((name.to_owned(), matches!(error.operation(), Some(ReadFault::LocalHeaderMismatch(_)))));
            }
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(failed, [("l1".to_owned(), true)]);
    assert_eq!(report.local_header_mismatches(), 1);
}

/// 7-Zip `x` leaves the member's file empty: with `keep_broken`, so does zipfast, on both routes.
#[test]
fn keep_broken_leaves_the_member_empty() {
    let dir = tempfile::tempdir().unwrap();
    for checked in [false, true] {
        let out = dir.path().join(if checked { "checked" } else { "legacy" });
        let mut opts = options(Mode::Extract, &out, true);
        opts.keep_broken = true;
        if checked {
            let report = extract::run_with_zip_policy(
                &fixture("local-crc.zip"),
                &opts,
                None,
                &Cancellation::default(),
                &Default::default(),
                |_: ZipRunEvent<'_>| Ok(()),
            )
            .unwrap();
            assert_eq!(report.local_header_mismatches(), 1);
        } else {
            let summary = extract::run(&fixture("local-crc.zip"), &opts, |_| {}).unwrap();
            assert_eq!(summary.local_header_mismatches.len(), 1);
        }
        assert_eq!(fs::metadata(out.join("f1.txt")).unwrap().len(), 0, "checked: {checked}");
        assert_eq!(fs::metadata(out.join("f0.txt")).unwrap().len(), 1200, "checked: {checked}");
    }
}

/// Extracts `name` on the legacy or the checked route: the local header mismatches reported and the files written.
/// On the checked route, each failure must say it was published exactly when `published` says so.
fn extract_route(
    name: &str,
    out: &Path,
    checked: bool,
    keep_broken: bool,
    published: bool,
) -> (Vec<extract::LocalHeaderMismatch>, u64) {
    let mut opts = options(Mode::Extract, out, true);
    opts.keep_broken = keep_broken;
    if !checked {
        let summary = extract::run(&fixture(name), &opts, |_| {}).unwrap();
        let lines: Vec<_> = summary.local_header_mismatches.iter().map(|m| format!("{}: {m}", m.name)).collect();
        assert_eq!(summary.errors, lines, "{name}: one line per mismatch");
        return (summary.local_header_mismatches, summary.files);
    }
    let mut found = Vec::new();
    let report = extract::run_with_zip_policy(
        &fixture(name),
        &opts,
        None,
        &Cancellation::default(),
        &Default::default(),
        |event: ZipRunEvent<'_>| {
            if let ZipRunEvent::MemberFailed { error, .. } = event {
                match error.operation() {
                    Some(ReadFault::LocalHeaderMismatch(m)) => found.push((**m).clone()),
                    other => panic!("{name}: {other:?}"),
                }
                let state = if published { PublicationState::Published } else { PublicationState::NotPublished };
                assert_eq!(error.publication_state(), state, "{name}");
            }
            Ok(())
        },
    )
    .unwrap();
    assert_eq!((report.failed(), report.local_header_mismatches()), (found.len() as u64, found.len() as u64), "{name}");
    (found, report.files())
}

/// 7-Zip 26.06 `x` writes `f1.txt`'s data when only the data descriptor flag differs (either header setting it), and
/// still reports "Headers Error : f1.txt" and exits 2: zipfast writes it whole and fails it, on both routes, without
/// `keep_broken`. A differing CRC-32, size or method still fails it unread.
#[test]
fn only_the_descriptor_flag_differing_still_writes_the_data() {
    let dir = tempfile::tempdir().unwrap();
    let plain = dir.path().join("plain");
    extract::run(&fixture("local.zip"), &options(Mode::Extract, &plain, false), |_| {}).unwrap();
    let f1 = fs::read(plain.join("f1.txt")).unwrap();
    assert_eq!(f1.len(), 1200);
    for name in ["local-descriptor-flag.zip", "central-descriptor-flag.zip", "local-crc.zip"] {
        for checked in [false, true] {
            let out = dir.path().join(format!("{name}-{checked}"));
            let written = name != "local-crc.zip";
            let (found, files) = extract_route(name, &out, checked, false, written);
            let [found] = found.as_slice() else { panic!("{name} checked {checked}: {found:?}") };
            assert_eq!((found.ordinal, found.name.as_str()), (1, "f1.txt"), "{name}");
            assert_eq!(files, 2, "{name} checked {checked}: the failed member isn't counted");
            assert_eq!(fs::read(out.join("f0.txt")).unwrap().len(), 1200);
            if found.fails_unread() {
                assert!(fs::symlink_metadata(out.join("f1.txt")).is_err(), "{name} checked {checked}");
            } else {
                assert!(found.descriptor_flag, "{name}");
                assert_eq!(fs::read(out.join("f1.txt")).unwrap(), f1, "{name} checked {checked}");
            }
        }
    }
}

/// 7-Zip 26.06 `x` places a link whose local header differs only in the data descriptor flag, and reports
/// "Headers Error : l1": zipfast places it and fails it, on both routes.
#[cfg(unix)]
#[test]
fn a_link_differing_only_in_its_descriptor_flag_is_placed_then_fails() {
    let dir = tempfile::tempdir().unwrap();
    for checked in [false, true] {
        let out = dir.path().join(format!("{checked}"));
        let (found, files) = extract_route("local-link-flag.zip", &out, checked, false, true);
        let [found] = found.as_slice() else { panic!("checked {checked}: {found:?}") };
        assert_eq!((found.ordinal, found.name.as_str()), (1, "l1"));
        assert!(found.descriptor_flag && !found.fails_unread(), "{found:?}");
        assert_eq!(files, 2, "checked {checked}");
        assert_eq!(fs::read_link(out.join("l1")).unwrap(), Path::new("f0.txt"), "checked {checked}");
    }
    assert!(test_run("local-link-flag.zip", false).errors.is_empty());
}

/// 7-Zip 26.06 `x` fails a link whose local CRC-32 differs unread and leaves an empty regular file at its path
/// ("Unknown reparse stream : l1", "Headers Error : l1"): with `keep_broken`, so does zipfast, on both routes; without
/// it, nothing is placed, as for a file.
#[cfg(unix)]
#[test]
fn keep_broken_leaves_an_empty_file_for_a_link_failed_unread() {
    let dir = tempfile::tempdir().unwrap();
    for checked in [false, true] {
        for keep_broken in [false, true] {
            let out = dir.path().join(format!("{checked}-{keep_broken}"));
            let (found, files) = extract_route("local-link-crc.zip", &out, checked, keep_broken, keep_broken);
            let [found] = found.as_slice() else { panic!("checked {checked}: {found:?}") };
            assert_eq!((found.name.as_str(), found.crc32), ("l1", true));
            assert_eq!(files, 2, "checked {checked}");
            let l1 = fs::symlink_metadata(out.join("l1"));
            if keep_broken {
                let l1 = l1.unwrap();
                assert!(l1.file_type().is_file() && l1.len() == 0, "checked {checked}: {l1:?}");
            } else {
                assert!(l1.is_err(), "checked {checked}");
            }
            assert_eq!(fs::read(out.join("f2.txt")).unwrap().len(), 500);
        }
    }
}
