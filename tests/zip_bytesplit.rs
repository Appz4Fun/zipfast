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

/// A stored ZIP of `(name, data)` members.
fn stored_zip(members: &[(&str, &[u8])]) -> Vec<u8> {
    let (mut out, mut central) = (Vec::new(), Vec::new());
    for (name, data) in members {
        let at = out.len() as u32;
        let crc = crc32fast::hash(data);
        let common = |sig: &[u8], out: &mut Vec<u8>, central: bool| {
            out.extend(sig);
            if central {
                out.extend(20u16.to_le_bytes());
            }
            out.extend(20u16.to_le_bytes());
            out.extend([0; 2 + 2 + 4]); // flags, method, time and date
            out.extend(crc.to_le_bytes());
            out.extend((data.len() as u32).to_le_bytes());
            out.extend((data.len() as u32).to_le_bytes());
            out.extend((name.len() as u16).to_le_bytes());
            out.extend(0u16.to_le_bytes());
        };
        common(b"PK\x03\x04", &mut out, false);
        out.extend(name.as_bytes());
        out.extend(*data);
        common(b"PK\x01\x02", &mut central, true);
        central.extend([0; 2 + 2 + 2 + 4]); // comment, disk, internal and external attributes
        central.extend(at.to_le_bytes());
        central.extend(name.as_bytes());
    }
    let (cd_at, cd_len, n) = (out.len() as u32, central.len() as u32, members.len() as u16);
    out.extend(central);
    out.extend(b"PK\x05\x06");
    out.extend([0; 4]);
    out.extend(n.to_le_bytes());
    out.extend(n.to_le_bytes());
    out.extend(cd_len.to_le_bytes());
    out.extend(cd_at.to_le_bytes());
    out.extend([0; 2]);
    out
}

#[test]
fn extracting_beside_the_set_never_overwrites_a_piece() {
    let dir = tempfile::tempdir().unwrap();
    let zip = stored_zip(&[("set.zip.002", b"evil two"), ("set.zip.003", b"evil three"), ("ok.txt", b"fine")]);
    let pieces: Vec<_> = zip.chunks(zip.len() / 3 + 1).collect();
    for (i, piece) in pieces.iter().enumerate() {
        fs::write(dir.path().join(format!("set.zip.{:03}", i + 1)), piece).unwrap();
    }
    let first = dir.path().join("set.zip.001");
    let result = extract::run(&first, &options(dir.path(), Mode::Extract), |_| {}).unwrap();
    assert_eq!((result.files, result.errors.len()), (1, 2), "{:?}", result.errors);
    for (i, piece) in pieces.iter().enumerate() {
        assert_eq!(fs::read(dir.path().join(format!("set.zip.{:03}", i + 1))).unwrap(), *piece);
    }
    assert_eq!(fs::read(dir.path().join("ok.txt")).unwrap(), b"fine");
}

#[test]
fn a_missing_middle_piece_lists_and_extracts_what_comes_before_it() {
    let dir = tempfile::tempdir().unwrap();
    let a = vec![b'a'; 700];
    let b = vec![b'b'; 700];
    let c = vec![b'c'; 700];
    let zip = stored_zip(&[("a.txt", &a), ("b.txt", &b), ("c.txt", &c)]);
    for (i, piece) in zip.chunks(1024).enumerate() {
        fs::write(dir.path().join(format!("gap.zip.{:03}", i + 1)), piece).unwrap();
    }
    fs::remove_file(dir.path().join("gap.zip.002")).unwrap();
    let first = dir.path().join("gap.zip.001");
    // Like 7-Zip: the members whose headers come before the gap, the last one cut short.
    assert_eq!(names(&extract::list(&first).unwrap()), [("a.txt", 700), ("b.txt", 700)]);
    let out = dir.path().join("out");
    let result = extract::run(&first, &options(&out, Mode::Extract), |_| {}).unwrap();
    assert_eq!(result.files, 1, "{:?}", result.errors);
    assert_eq!(fs::read(out.join("a.txt")).unwrap(), a);
    assert_eq!(result.errors.len(), 2, "{:?}", result.errors);
    assert!(result.errors[0].starts_with("b.txt: missing volume") && result.errors[0].ends_with("gap.zip.002"));
    assert!(result.errors[1].starts_with("missing volume"), "{:?}", result.errors);
}

#[test]
fn a_listing_cut_short_by_a_missing_piece_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let zip = stored_zip(&[("a.txt", &[b'a'; 700]), ("b.txt", &[b'b'; 700]), ("c.txt", &[b'c'; 700])]);
    for (i, piece) in zip.chunks(1024).enumerate() {
        fs::write(dir.path().join(format!("cut.zip.{:03}", i + 1)), piece).unwrap();
    }
    let whole = extract::list_detailed(&dir.path().join("cut.zip.001"), None).unwrap();
    assert!(!whole.unexpected_end());
    assert_eq!(whole.entries.len(), 3);
    fs::remove_file(dir.path().join("cut.zip.002")).unwrap();
    let cut = extract::list_detailed(&dir.path().join("cut.zip.001"), None).unwrap();
    assert!(cut.unexpected_end());
    assert!(cut.missing_volume.unwrap().ends_with("cut.zip.002"));
    assert_eq!(names(&cut.entries), [("a.txt", 700), ("b.txt", 700)]);
    // A whole single archive has no warning either.
    assert!(!extract::list_detailed(&first(), None).unwrap().unexpected_end());
}

#[test]
fn streamed_members_before_a_gap_are_found_by_their_descriptors() {
    let first = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/zip-bytesplit-streamed/s.zip.001");
    let listing = extract::list_detailed(&first, None).unwrap();
    assert!(listing.unexpected_end());
    let got: Vec<_> = listing.entries.iter().map(|e| (e.name.as_str(), e.size, e.packed)).collect();
    assert_eq!(got, [("a.txt", 800, 26), ("b.txt", 5, 5), ("c.bin", 0, 11832)]);
    let known: Vec<_> = listing.entries.iter().map(|e| (e.known_size(), e.size_unknown)).collect();
    assert_eq!(known, [(Some(800), false), (Some(5), false), (None, true)]);
    // Extraction checks each CRC before publishing: the two whole members come out, c.bin fails on the gap.
    let dir = tempfile::tempdir().unwrap();
    let result = extract::run(&first, &options(dir.path(), Mode::Extract), |_| {}).unwrap();
    assert_eq!(result.files, 2, "{:?}", result.errors);
    assert_eq!(fs::read(dir.path().join("b.txt")).unwrap().len(), 5);
    assert!(result.errors.iter().any(|e| e.starts_with("c.bin: missing volume")), "{:?}", result.errors);
    assert!(!dir.path().join("c.bin").exists());
}

/// A set whose first piece is too short to hold the ZIP signature still routes as a byte-split set on the checked
/// entry points and in inspection, not as a single-file ZIP of the first piece.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn a_first_piece_without_a_signature_still_routes_as_a_set() {
    use zipfast::extract::Cancellation;
    let dir = tempfile::tempdir().unwrap();
    let zip = stored_zip(&[("a.txt", b"one"), ("b.txt", b"two")]);
    fs::write(dir.path().join("short.zip.001"), &zip[..2]).unwrap();
    fs::write(dir.path().join("short.zip.002"), &zip[2..]).unwrap();
    let first = dir.path().join("short.zip.001");
    match extract::inspect(&first).unwrap() {
        Inspection::Other(entries) => assert_eq!(names(&entries), [("a.txt", 3), ("b.txt", 3)]),
        _ => panic!("a byte-split ZIP inspects as a listing"),
    }
    let out = dir.path().join("out");
    let report = extract::run_with_policy(
        &first,
        &options(&out, Mode::Extract),
        None,
        &Cancellation::default(),
        &Default::default(),
        |_: extract::RunEvent<'_>| Ok(()),
    )
    .unwrap();
    assert_eq!(report.files(), 2);
    assert_eq!(fs::read(out.join("b.txt")).unwrap(), b"two");
}

/// The checked entry points report a split set's members one by one with their listing ordinals, and stop once a
/// cancellation is seen: one from the first success stops before the next member, and one from the last member's
/// success still ends the run as canceled rather than as a success.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn checked_runs_report_members_and_honor_cancellation() {
    use zipfast::extract::{Cancellation, RunEvent};
    use zipfast::zip::ReadFault;
    // which member's success cancels the run
    for cancel_at in [None, Some(0), Some(1)] {
        let dir = tempfile::tempdir().unwrap();
        let cancel = Cancellation::default();
        let mut succeeded = Vec::new();
        let result = extract::run_with_policy(
            &first(),
            &options(dir.path(), Mode::Extract),
            None,
            &cancel,
            &Default::default(),
            |event: RunEvent<'_>| {
                if let RunEvent::MemberSucceeded { ordinal, name, .. } = event {
                    succeeded.push((ordinal, name.to_owned()));
                    if cancel_at == Some(ordinal) {
                        cancel.cancel();
                    }
                }
                Ok(())
            },
        );
        let both = [(0, "noise.bin".to_owned()), (1, "tiny.txt".to_owned())];
        match cancel_at {
            None => {
                assert_eq!(result.unwrap().files(), 2);
                assert_eq!(succeeded, both);
            }
            Some(0) => {
                let error = result.unwrap_err();
                assert!(matches!(error.operation(), Some(ReadFault::Cancelled)), "{error:?}");
                assert_eq!(succeeded, [(0, "noise.bin".to_owned())]);
                assert!(!dir.path().join("tiny.txt").exists());
            }
            _ => {
                let error = result.unwrap_err();
                assert!(matches!(error.operation(), Some(ReadFault::Cancelled)), "{error:?}");
                assert_eq!(succeeded, both);
            }
        }
    }
}

/// The 7-Zip fixture with its second piece removed. `7zz l -slt bytesplit.zip.001` (7-Zip 26.06, which reads only
/// the pieces up to the gap) reports `Errors: 1`, "Unexpected end of archive", and lists one member: `noise.bin`,
/// Size = 3000, Packed Size = 3000, CRC = F1915F9E, Method = Store.
#[test]
fn the_7zip_fixture_without_its_second_piece_lists_like_7zip() {
    let dir = tempfile::tempdir().unwrap();
    let src = first().parent().unwrap().to_owned();
    for n in ["001", "003", "004"] {
        fs::copy(src.join(format!("bytesplit.zip.{n}")), dir.path().join(format!("bytesplit.zip.{n}"))).unwrap();
    }
    let listing = extract::list_detailed(&dir.path().join("bytesplit.zip.001"), None).unwrap();
    assert!(listing.unexpected_end());
    assert!(listing.missing_volume.unwrap().ends_with("bytesplit.zip.002"));
    assert_eq!(names(&listing.entries), [("noise.bin", 3000)]);
    assert_eq!(listing.entries[0].crc32, Some(0xF191_5F9E));
}
