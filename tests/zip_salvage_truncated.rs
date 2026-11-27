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

//! `extract::Options::salvage_truncated_zip`: one ZIP file cut short (its central directory and end record gone) is
//! read by walking its local headers, as 7-Zip 26.06 does (prybar: `head -c 30000` of a one-member ZIP lists and
//! extracts what is there, "Unexpected end of archive", exit 2; `7zz x` keeps 29,955 bytes of the cut member). Off by
//! default, the file is refused as not a ZIP archive.

#![cfg(any(target_os = "macos", target_os = "linux"))]

use std::fs;
use std::io::Write;
use std::path::Path;

use flate2::Compression;
use flate2::write::DeflateEncoder;
use zipfast::extract::{self, Cancellation, Mode, Options, Overwrite};
use zipfast::zip::{EncryptedReadOverrides, ReadFault, ZipRunEvent};

const FIRST: &[u8] = b"the first member, stored whole before the cut\n";
const A_LEN: usize = 50_000;

fn options(dest: &Path, salvage: bool, keep: bool) -> Options {
    Options {
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
        keep_broken: keep,
        attempt_continued_members: false,
        encrypted_links: Default::default(),
        damaged_input: Default::default(),
        unsupported_filters: Default::default(),
        unverified_output: Default::default(),
        unix_modes: Default::default(),
        backslashes: Default::default(),
        hard_link_targets: Default::default(),
        salvage_truncated_zip: salvage,
        seven_zip_strict: false,
    }
}

/// 50,000 bytes of text that deflate can't squeeze to nothing: words picked by a small LCG.
fn a_txt() -> Vec<u8> {
    const WORDS: [&str; 12] = [
        "alpha ", "bravo ", "charlie ", "delta ", "echo\n", "foxtrot ", "golf ", "hotel ", "india ", "juliet\n",
        "kilo ", "lima ",
    ];
    let mut out = Vec::with_capacity(A_LEN + 16);
    let mut state = 0x1234_5678u32;
    while out.len() < A_LEN {
        state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        let word = WORDS[(state >> 16) as usize % WORDS.len()];
        out.extend_from_slice(word.as_bytes());
        // a digit now and then keeps the stream from settling into a few codes
        out.push(b'0' + (state >> 8) as u8 % 10);
    }
    out.truncate(A_LEN);
    out
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = flate2::Crc::new();
    crc.update(data);
    crc.sum()
}

/// A ZIP of stored `first.txt` then deflated `a.txt`, and the offset of `a.txt`'s data and its packed length.
fn archive(a: &[u8]) -> (Vec<u8>, usize, usize) {
    let mut deflater = DeflateEncoder::new(Vec::new(), Compression::default());
    deflater.write_all(a).unwrap();
    let packed = deflater.finish().unwrap();
    let members: [(&str, u16, &[u8], &[u8]); 2] = [("first.txt", 0, FIRST, FIRST), ("a.txt", 8, a, &packed)];
    let mut zip = Vec::new();
    let mut central = Vec::new();
    let mut a_data_at = 0;
    for (name, method, plain, stored) in members {
        let at = zip.len() as u32;
        let crc = crc32(plain);
        let fixed = |sig: u32, out: &mut Vec<u8>| {
            out.extend_from_slice(&sig.to_le_bytes());
            out.extend_from_slice(&20u16.to_le_bytes()); // version needed
            out.extend_from_slice(&0u16.to_le_bytes()); // flags
            out.extend_from_slice(&method.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // time
            out.extend_from_slice(&0x5421u16.to_le_bytes()); // date 2022-01-01
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&(stored.len() as u32).to_le_bytes());
            out.extend_from_slice(&(plain.len() as u32).to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // extra length
        };
        fixed(0x0403_4b50, &mut zip);
        zip.extend_from_slice(name.as_bytes());
        if name == "a.txt" {
            a_data_at = zip.len();
        }
        zip.extend_from_slice(stored);
        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&0x031eu16.to_le_bytes()); // made by: Unix
        let mut rest = Vec::new();
        fixed(0, &mut rest);
        central.extend_from_slice(&rest[4..]);
        central.extend_from_slice(&0u16.to_le_bytes()); // comment length
        central.extend_from_slice(&0u16.to_le_bytes()); // disk
        central.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
        central.extend_from_slice(&(0o100644u32 << 16).to_le_bytes());
        central.extend_from_slice(&at.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let central_at = zip.len() as u32;
    zip.extend_from_slice(&central);
    zip.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    zip.extend_from_slice(&[0, 0, 0, 0]);
    zip.extend_from_slice(&2u16.to_le_bytes());
    zip.extend_from_slice(&2u16.to_le_bytes());
    zip.extend_from_slice(&(central.len() as u32).to_le_bytes());
    zip.extend_from_slice(&central_at.to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes());
    (zip, a_data_at, packed.len())
}

/// The archive cut halfway through `a.txt`'s deflated data, written to `dir`.
fn truncated(dir: &Path) -> (std::path::PathBuf, Vec<u8>) {
    let a = a_txt();
    let (zip, data_at, packed) = archive(&a);
    assert!(packed > 4_000, "the deflated member is big enough to cut: {packed}");
    let path = dir.join("cut.zip");
    fs::write(&path, &zip[..data_at + packed / 2]).unwrap();
    (path, a)
}

#[derive(Default, Debug)]
struct Seen {
    succeeded: Vec<String>,
    failed: Vec<(String, String)>,
    legacy_errors: Vec<String>,
    legacy_lines: usize,
}

fn run(path: &Path, opts: &Options) -> (zipfast::zip::ZipReadResult<zipfast::zip::ZipRunReport>, Seen) {
    let mut seen = Seen::default();
    let result = extract::run_with_policy(
        path,
        opts,
        None,
        &Cancellation::default(),
        &EncryptedReadOverrides::default(),
        |event: ZipRunEvent<'_>| {
            match event {
                ZipRunEvent::MemberSucceeded { name, .. } => seen.succeeded.push(name.to_owned()),
                ZipRunEvent::MemberFailed { name, error, .. } => {
                    // a legacy member's failure carries its message
                    let why = match error.operation() {
                        Some(ReadFault::Legacy(legacy)) => legacy.to_string(),
                        _ => format!("{error:?}"),
                    };
                    seen.failed.push((name.to_owned(), why))
                }
                ZipRunEvent::LegacyError { message, .. } => seen.legacy_errors.push(message.to_owned()),
                ZipRunEvent::LegacyDiagnostic { .. } => seen.legacy_lines += 1,
                _ => {}
            }
            Ok(())
        },
    );
    (result, seen)
}

#[test]
fn a_truncated_zip_is_still_refused_with_the_option_off() {
    let dir = tempfile::tempdir().unwrap();
    let (path, _) = truncated(dir.path());
    let out = dir.path().join("out");
    let (result, seen) = run(&path, &options(&out, false, false));
    let error = result.unwrap_err();
    assert!(matches!(error.operation(), Some(ReadFault::CheckedFormat { reason: "not a ZIP archive" })), "{error:?}");
    assert!(seen.succeeded.is_empty() && seen.failed.is_empty(), "{seen:?}");
    assert!(!out.join("first.txt").exists());
    // the legacy runner refuses it too
    assert!(matches!(extract::run(&path, &options(&out, false, false), |_| {}), Err(zipfast::Error::NotAnArchive)));
    // and so does a listing
    assert!(zipfast::zip::list_detailed_with_options(&path, &options(&out, false, false)).is_err());
}

#[test]
fn a_truncated_zip_is_read_from_its_local_headers_with_the_option_on() {
    let dir = tempfile::tempdir().unwrap();
    let (path, _) = truncated(dir.path());
    let out = dir.path().join("out");
    let (result, seen) = run(&path, &options(&out, true, false));
    // the run fails: the cut member, and the archive itself as truncated
    assert!(result.unwrap().failed() > 0, "{seen:?}");
    assert_eq!(seen.succeeded, ["first.txt"], "{seen:?}");
    assert_eq!(seen.failed.len(), 1, "{seen:?}");
    let (name, why) = &seen.failed[0];
    assert_eq!(name, "a.txt");
    assert!(why.contains("truncated") && !why.contains("missing volume"), "{why}");
    assert_eq!(seen.legacy_errors.last().map(String::as_str), Some("archive is truncated"), "{seen:?}");
    assert_eq!(fs::read(out.join("first.txt")).unwrap(), FIRST);
    assert!(!out.join("a.txt").exists(), "the cut member is removed without keep_broken");
}

#[test]
fn the_legacy_runner_salvages_a_truncated_zip_too() {
    let dir = tempfile::tempdir().unwrap();
    let (path, _) = truncated(dir.path());
    let out = dir.path().join("out");
    let summary = extract::run(&path, &options(&out, true, false), |_| {}).unwrap();
    assert_eq!(summary.files, 1);
    assert!(summary.errors.iter().any(|e| e == "a.txt: archive is truncated"), "{:?}", summary.errors);
    assert_eq!(summary.errors.last().map(String::as_str), Some("archive is truncated"));
    assert_eq!(fs::read(out.join("first.txt")).unwrap(), FIRST);
    assert!(!out.join("a.txt").exists());
}

#[test]
fn keep_broken_keeps_the_decoded_prefix_of_the_cut_member() {
    let dir = tempfile::tempdir().unwrap();
    let (path, a) = truncated(dir.path());
    let out = dir.path().join("out");
    let (result, seen) = run(&path, &options(&out, true, true));
    assert!(result.unwrap().failed() > 0, "{seen:?}");
    assert!(seen.failed.len() == 1 && seen.failed[0].1.contains("truncated"), "{seen:?}");
    assert_eq!(fs::read(out.join("first.txt")).unwrap(), FIRST);
    let kept = fs::read(out.join("a.txt")).unwrap();
    assert!(!kept.is_empty() && kept.len() < A_LEN, "{} bytes kept", kept.len());
    assert!(kept[..] == a[..kept.len()], "the kept bytes are a prefix of the original");
}

#[test]
fn listing_a_truncated_zip_with_the_option_on_walks_its_local_headers() {
    let dir = tempfile::tempdir().unwrap();
    let (path, _) = truncated(dir.path());
    let listing = zipfast::zip::list_detailed_with_options(&path, &options(dir.path(), true, false)).unwrap();
    let names: Vec<&str> = listing.entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, ["first.txt", "a.txt"]);
    assert!(listing.truncated && listing.unexpected_end() && listing.missing_volume.is_none());
}

#[test]
fn an_intact_zip_is_read_on_the_checked_route_with_the_option_on() {
    let dir = tempfile::tempdir().unwrap();
    let a = a_txt();
    let (zip, _, _) = archive(&a);
    let path = dir.path().join("whole.zip");
    fs::write(&path, &zip).unwrap();
    let mut files = Vec::new();
    for salvage in [false, true] {
        let out = dir.path().join(format!("{salvage}"));
        let (result, seen) = run(&path, &options(&out, salvage, false));
        assert_eq!(result.unwrap().failed(), 0, "{salvage}: {seen:?}");
        assert_eq!(seen.succeeded, ["first.txt", "a.txt"], "{salvage}");
        // the checked route sends no legacy lines
        assert!(seen.legacy_lines == 0 && seen.legacy_errors.is_empty(), "{salvage}: {seen:?}");
        files.push((fs::read(out.join("first.txt")).unwrap(), fs::read(out.join("a.txt")).unwrap()));
    }
    assert!(files[0] == files[1]);
    assert_eq!(files[1].0, FIRST);
    assert!(files[1].1 == a);
    let listing = zipfast::zip::list_detailed_with_options(&path, &options(dir.path(), true, false)).unwrap();
    assert!(!listing.truncated && !listing.unexpected_end());
}

#[test]
fn a_file_that_is_not_a_zip_is_still_refused_with_the_option_on() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("text.zip");
    fs::write(&path, b"plain text, no local header here\n".repeat(20)).unwrap();
    let out = dir.path().join("out");
    let error = run(&path, &options(&out, true, false)).0.unwrap_err();
    assert!(matches!(error.operation(), Some(ReadFault::CheckedFormat { reason: "not a ZIP archive" })), "{error:?}");
}

#[test]
fn truncation_at_any_offset_never_panics_with_the_option_on() {
    let dir = tempfile::tempdir().unwrap();
    let a = a_txt();
    let (zip, _, _) = archive(&a);
    let path = dir.path().join("cut.zip");
    for cut in (0..=zip.len()).step_by(97).chain([zip.len() - 1, zip.len()]) {
        fs::write(&path, &zip[..cut]).unwrap();
        for keep in [false, true] {
            let out = dir.path().join(format!("out-{keep}"));
            let _ = fs::remove_dir_all(&out);
            let opts = options(&out, true, keep);
            let _ = run(&path, &opts);
            let _ = extract::run(&path, &opts, |_| {});
            let _ = zipfast::zip::list_detailed_with_options(&path, &opts);
        }
    }
}
