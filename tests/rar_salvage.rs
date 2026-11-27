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

//! `Options::damaged_input`: RAR archives with damaged headers, read as UnRAR 7.30 reads them (`Salvage`) or searched
//! past (`Resync`), and refused by default.

#![cfg(unix)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use common::{FileSpec, SIG, end_block, file_block, main_block};
use zipfast::crc32::hash;
use zipfast::extract::{self, DamagedInput, HeaderDamageKind, Mode, Options, Overwrite};
use zipfast::rar5::session::{RarDecodeLimits, RarSession, RarSessionOptions};

const A: &[u8] = b"alpha alpha alpha alpha alpha alpha alpha alpha alpha alpha";
const B: &[u8] = b"bravo bravo bravo bravo bravo bravo bravo bravo bravo bravo bravo bravo";
const C: &[u8] = b"charlie charlie charlie charlie charlie charlie charlie charlie charlie charlie";
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rar-salvage");

fn options(dest: &Path, mode: Mode, damaged: DamagedInput) -> Options {
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
        encrypted_links: Default::default(),
        damaged_input: damaged,
        unsupported_filters: Default::default(),
        salvage_truncated_zip: false,
        unix_modes: Default::default(),
        backslashes: Default::default(),
    }
}

/// A RAR 5.0 archive of a.txt, b.txt, c.txt stored, and where each header starts.
fn rar5() -> (Vec<u8>, [usize; 4]) {
    let mut out = SIG.to_vec();
    out.extend(main_block(false, None));
    let mut at = [0; 4];
    for (i, (name, data)) in [("a.txt", A), ("b.txt", B), ("c.txt", C)].into_iter().enumerate() {
        at[i] = out.len();
        out.extend(file_block(&FileSpec::new(name, data), data, hash(data), false, false));
    }
    at[3] = out.len();
    out.extend(end_block(false));
    (out, at)
}

fn rar4_block(kind: u8, flags: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0, 0, kind];
    bytes.extend(flags.to_le_bytes());
    bytes.extend(((body.len() + 7) as u16).to_le_bytes());
    bytes.extend(body);
    let crc = hash(&bytes[2..]) as u16;
    bytes[..2].copy_from_slice(&crc.to_le_bytes());
    bytes
}

fn rar4_member(name: &[u8], data: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend((data.len() as u32).to_le_bytes());
    body.extend((data.len() as u32).to_le_bytes());
    body.push(3);
    body.extend(hash(data).to_le_bytes());
    body.extend(0x50221884u32.to_le_bytes());
    body.extend([20, 0x30]);
    body.extend((name.len() as u16).to_le_bytes());
    body.extend(0o100644u32.to_le_bytes());
    body.extend(name);
    let mut bytes = rar4_block(0x74, 0x8000, &body);
    bytes.extend(data);
    bytes
}

/// A RAR 4.x archive of a.txt, b.txt, c.txt stored, and where each header starts.
fn rar4() -> (Vec<u8>, [usize; 4]) {
    let mut out = b"Rar!\x1a\x07\0".to_vec();
    out.extend(rar4_block(0x73, 0, &[0; 6]));
    let mut at = [0; 4];
    for (i, (name, data)) in [(&b"a.txt"[..], A), (b"b.txt", B), (b"c.txt", C)].into_iter().enumerate() {
        at[i] = out.len();
        out.extend(rar4_member(name, data));
    }
    at[3] = out.len();
    out.extend(rar4_block(0x7b, 0x4000, &[]));
    (out, at)
}

fn garbage(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 37 + 11) as u8).collect()
}

struct Case {
    _dir: tempfile::TempDir,
    archive: PathBuf,
    out: PathBuf,
}

fn case(bytes: &[u8]) -> Case {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("damaged.rar");
    fs::write(&archive, bytes).unwrap();
    let out = dir.path().join("out");
    Case { archive, out, _dir: dir }
}

fn extract(case: &Case, damaged: DamagedInput) -> zipfast::Result<extract::Summary> {
    extract::run(&case.archive, &options(&case.out, Mode::Extract, damaged), |_| {})
}

fn listed(case: &Case, damaged: DamagedInput) -> zipfast::Result<extract::Listing> {
    extract::list_detailed_with_options(&case.archive, None, &options(&case.out, Mode::Test, damaged))
}

fn names(listing: &extract::Listing) -> Vec<&str> {
    listing.entries.iter().map(|e| e.name.as_str()).collect()
}

fn written(case: &Case) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(&case.out)
        .map(|d| d.map(|e| e.unwrap().file_name().into_string().unwrap()).collect())
        .unwrap_or_default();
    names.sort();
    names
}

fn assert_bytes(case: &Case, name: &str, data: &[u8]) {
    assert_eq!(fs::read(case.out.join(name)).unwrap(), data, "{name}");
}

fn kinds(damage: &[extract::HeaderDamage]) -> Vec<HeaderDamageKind> {
    damage.iter().map(|d| d.kind).collect()
}

/// b.txt's header fails its checksum (its CRC byte changed) but parses: UnRAR 7.30 says "b.txt - the file header is
/// corrupt" and extracts all three; zipfast reads it as it stands and reports the damage.
#[test]
fn salvage_uses_a_rar5_header_whose_checksum_fails() {
    let (mut bytes, at) = rar5();
    bytes[at[1]] ^= 0x5a;
    let case = case(&bytes);
    assert!(extract(&case, DamagedInput::Refuse).is_err(), "Refuse keeps today's error");
    assert!(!case.out.join("c.txt").exists());

    let summary = extract(&case, DamagedInput::Salvage).unwrap();
    assert!(summary.errors.is_empty(), "{:?}", summary.errors);
    assert_bytes(&case, "a.txt", A);
    assert_bytes(&case, "b.txt", B);
    assert_bytes(&case, "c.txt", C);
    assert_eq!(kinds(&summary.damaged_headers), [HeaderDamageKind::ChecksumMismatch]);
    let damage = &summary.damaged_headers[0];
    assert_eq!((damage.offset, damage.name.as_deref(), damage.resumed_at), (at[1] as u64, Some("b.txt"), None));

    assert!(listed(&case, DamagedInput::Refuse).is_err());
    let listing = listed(&case, DamagedInput::Salvage).unwrap();
    assert_eq!(names(&listing), ["a.txt", "b.txt", "c.txt"]);
    assert!(listing.headers_damaged());
    assert!(!listing.unexpected_end());
}

/// A changed byte in the name: the header still parses, and the member is written under the name it now reads,
/// as UnRAR writes `bttxt`.
#[test]
fn salvage_writes_a_damaged_name_as_read() {
    let (mut bytes, at) = rar5();
    let name = at[1] + bytes[at[1]..].windows(5).position(|w| w == b"b.txt").unwrap();
    bytes[name + 1] = b't';
    let case = case(&bytes);
    let summary = extract(&case, DamagedInput::Salvage).unwrap();
    assert_eq!(written(&case), ["a.txt", "bttxt", "c.txt"]);
    assert_bytes(&case, "bttxt", B);
    assert_eq!(summary.damaged_headers[0].name.as_deref(), Some("bttxt"));
}

#[test]
fn salvage_uses_a_rar4_header_whose_checksum_fails() {
    let (mut bytes, at) = rar4();
    bytes[at[1]] ^= 0x5a;
    let case = case(&bytes);
    assert!(extract(&case, DamagedInput::Refuse).is_err());
    let summary = extract(&case, DamagedInput::Salvage).unwrap();
    assert!(summary.errors.is_empty(), "{:?}", summary.errors);
    assert_eq!(written(&case), ["a.txt", "b.txt", "c.txt"]);
    assert_bytes(&case, "c.txt", C);
    assert_eq!(kinds(&summary.damaged_headers), [HeaderDamageKind::ChecksumMismatch]);
    assert_eq!(names(&listed(&case, DamagedInput::Salvage).unwrap()), ["a.txt", "b.txt", "c.txt"]);
}

/// A RAR 4.x header whose type byte changed fails its checksum and names no known block: UnRAR passes it over by its
/// size and extracts the rest.
#[test]
fn salvage_passes_over_a_rar4_block_whose_type_is_damaged() {
    let (mut bytes, at) = rar4();
    bytes[at[1] + 2] ^= 0x5a;
    let case = case(&bytes);
    assert!(extract(&case, DamagedInput::Refuse).is_err());
    let summary = extract(&case, DamagedInput::Salvage).unwrap();
    assert_eq!(written(&case), ["a.txt", "c.txt"]);
    assert_bytes(&case, "c.txt", C);
    assert_eq!(kinds(&summary.damaged_headers), [HeaderDamageKind::ChecksumMismatch]);
    assert_eq!(summary.damaged_headers[0].name, None);
    assert_eq!(names(&listed(&case, DamagedInput::Salvage).unwrap()), ["a.txt", "c.txt"]);
}

/// The main header fails its checksum: UnRAR says "Main archive header is corrupt" and extracts everything.
#[test]
fn salvage_reads_past_a_damaged_main_header() {
    for (mut bytes, main) in [(rar5().0, 8), (rar4().0, 7)] {
        bytes[main] ^= 0x5a;
        let case = case(&bytes);
        assert!(extract(&case, DamagedInput::Refuse).is_err());
        let summary = extract(&case, DamagedInput::Salvage).unwrap();
        assert_eq!(written(&case), ["a.txt", "b.txt", "c.txt"]);
        assert_eq!(kinds(&summary.damaged_headers), [HeaderDamageKind::ChecksumMismatch]);
        assert_eq!(summary.damaged_headers[0].offset, main as u64);
    }
}

/// Garbage between a.txt and b.txt: neither UnRAR 7.30 nor 7-Zip looks past it ("Corrupt header is found",
/// "Headers Error"), so `Salvage` keeps a.txt and passes over the rest of the volume; `Resync` finds b.txt's header
/// and extracts b.txt and c.txt byte-exact.
#[test]
fn garbage_between_blocks_ends_the_volume_under_salvage_and_is_searched_past_under_resync() {
    for (format, (bytes, at)) in [("rar5", rar5()), ("rar4", rar4())] {
        let mut damaged = bytes[..at[1]].to_vec();
        damaged.extend(garbage(300));
        damaged.extend(&bytes[at[1]..]);
        let case = case(&damaged);
        assert!(extract(&case, DamagedInput::Refuse).is_err(), "{format}");
        assert!(listed(&case, DamagedInput::Refuse).is_err(), "{format}");

        // The garbage reads as a RAR 4.x header longer than what is left, which UnRAR 7.30 reports as "Unexpected
        // end of archive" too; as RAR 5.0 it doesn't frame ("Corrupt header is found").
        let kind = if format == "rar4" { HeaderDamageKind::UnexpectedEnd } else { HeaderDamageKind::Unreadable };
        let summary = extract(&case, DamagedInput::Salvage).unwrap();
        assert_eq!(written(&case), ["a.txt"], "{format}");
        assert_eq!(kinds(&summary.damaged_headers), [kind], "{format}");
        assert_eq!(summary.damaged_headers[0].offset, at[1] as u64, "{format}");
        assert_eq!(summary.damaged_headers[0].resumed_at, None, "{format}");
        assert_eq!(names(&listed(&case, DamagedInput::Salvage).unwrap()), ["a.txt"], "{format}");

        fs::remove_dir_all(&case.out).unwrap();
        let summary = extract(&case, DamagedInput::Resync).unwrap();
        assert!(summary.errors.is_empty(), "{format}: {:?}", summary.errors);
        assert_eq!(written(&case), ["a.txt", "b.txt", "c.txt"], "{format}");
        assert_bytes(&case, "a.txt", A);
        assert_bytes(&case, "b.txt", B);
        assert_bytes(&case, "c.txt", C);
        assert_eq!(kinds(&summary.damaged_headers), [kind], "{format}");
        assert_eq!(summary.damaged_headers[0].resumed_at, Some(at[1] as u64 + 300), "{format}");
        let listing = listed(&case, DamagedInput::Resync).unwrap();
        assert_eq!(names(&listing), ["a.txt", "b.txt", "c.txt"], "{format}");
        assert!(listing.headers_damaged());
    }
}

/// A hole of zeros over b.txt's header (a download still waiting for repair): `Resync` recovers c.txt, and b.txt,
/// whose header is gone, is not listed.
#[test]
fn resync_recovers_the_members_after_a_hole() {
    for (format, (mut bytes, at)) in [("rar5", rar5()), ("rar4", rar4())] {
        bytes[at[1]..at[1] + 20].fill(0);
        let case = case(&bytes);
        assert!(extract(&case, DamagedInput::Refuse).is_err(), "{format}");
        let summary = extract(&case, DamagedInput::Resync).unwrap();
        assert_eq!(written(&case), ["a.txt", "c.txt"], "{format}");
        assert_bytes(&case, "c.txt", C);
        assert_eq!(summary.damaged_headers[0].resumed_at, Some(at[2] as u64), "{format}");
    }
}

/// A header cut short by the end of the file: UnRAR and 7-Zip say "Unexpected end of archive"; what came before
/// stands.
#[test]
fn salvage_reports_a_volume_cut_inside_a_header() {
    for (format, (bytes, at)) in [("rar5", rar5()), ("rar4", rar4())] {
        let case = case(&bytes[..at[1] + 9]);
        assert!(extract(&case, DamagedInput::Refuse).is_err(), "{format}");
        let summary = extract(&case, DamagedInput::Salvage).unwrap();
        assert_eq!(written(&case), ["a.txt"], "{format}");
        assert_eq!(kinds(&summary.damaged_headers), [HeaderDamageKind::UnexpectedEnd], "{format}");
        let listing = listed(&case, DamagedInput::Salvage).unwrap();
        assert_eq!(names(&listing), ["a.txt"], "{format}");
        assert!(listing.unexpected_end(), "{format}");
    }
}

/// A RAR 5.0 archive without its end header: 7-Zip says "Unexpected end of archive" where zipfast said nothing.
#[test]
fn salvage_reports_a_rar5_volume_without_its_end_header() {
    let (bytes, at) = rar5();
    let case = case(&bytes[..at[3]]);
    let summary = extract(&case, DamagedInput::Refuse).unwrap();
    assert!(summary.damaged_headers.is_empty());
    let summary = extract(&case, DamagedInput::Salvage).unwrap();
    assert_eq!(written(&case), ["a.txt", "b.txt", "c.txt"]);
    assert_eq!(kinds(&summary.damaged_headers), [HeaderDamageKind::UnexpectedEnd]);
    assert_eq!(summary.damaged_headers[0].offset, at[3] as u64);
}

/// Only a member's data damaged: it fails as before, whatever the choice, and nothing is header damage.
#[test]
fn damaged_data_alone_is_not_header_damage() {
    let (mut bytes, at) = rar5();
    bytes[at[2] - 3] ^= 0x5a;
    let case = case(&bytes);
    for damaged in [DamagedInput::Refuse, DamagedInput::Salvage, DamagedInput::Resync] {
        let summary = extract(&case, damaged).unwrap();
        assert_eq!(summary.errors.len(), 1, "{damaged:?}");
        assert!(summary.damaged_headers.is_empty(), "{damaged:?}");
        assert_eq!(written(&case), ["a.txt", "c.txt"], "{damaged:?}");
    }
}

/// The damage in the first volume of a set passes over the rest of that volume, and the next volume is read.
#[test]
fn salvage_goes_on_into_the_next_volume() {
    let dir = tempfile::tempdir().unwrap();
    let mut first = SIG.to_vec();
    first.extend(main_block(true, None));
    first.extend(file_block(&FileSpec::new("a.txt", A), A, hash(A), false, false));
    first.extend(garbage(64));
    let mut second = SIG.to_vec();
    second.extend(main_block(true, Some(1)));
    second.extend(file_block(&FileSpec::new("c.txt", C), C, hash(C), false, false));
    second.extend(end_block(false));
    fs::write(dir.path().join("set.part1.rar"), &first).unwrap();
    fs::write(dir.path().join("set.part2.rar"), &second).unwrap();
    let out = dir.path().join("out");
    let opts = options(&out, Mode::Extract, DamagedInput::Salvage);
    let summary = extract::run(&dir.path().join("set.part1.rar"), &opts, |_| {}).unwrap();
    assert_eq!(fs::read(out.join("a.txt")).unwrap(), A);
    assert_eq!(fs::read(out.join("c.txt")).unwrap(), C);
    assert_eq!(summary.volumes, 2);
    assert_eq!(kinds(&summary.damaged_headers), [HeaderDamageKind::Unreadable]);
    assert!(summary.damaged_headers[0].volume.ends_with("set.part1.rar"));
}

/// The typed runner reports the damage too.
#[test]
fn typed_runner_reports_damaged_headers() {
    let (mut bytes, at) = rar5();
    bytes[at[1]] ^= 0x5a;
    let case = case(&bytes);
    let opts = options(&case.out, Mode::Test, DamagedInput::Salvage);
    let summary = extract::run_rar_with_outcomes(&case.archive, &opts, None, |_| {}).unwrap();
    assert_eq!((summary.files, summary.failed), (3, 0));
    assert_eq!(kinds(&summary.damaged_headers), [HeaderDamageKind::ChecksumMismatch]);
    let opts = options(&case.out, Mode::Test, DamagedInput::Refuse);
    assert!(extract::run_rar_with_outcomes(&case.archive, &opts, None, |_| {}).is_err());
}

/// `RarSession` (Prybar's UnRAR mode) catalogues past the damage, lists and extracts the members, and says the
/// headers are damaged.
#[test]
fn session_catalogues_lists_and_extracts_past_damaged_headers() {
    let (mut bytes, at) = rar5();
    bytes[at[1]] ^= 0x5a;
    let mut resync = bytes[..at[2]].to_vec();
    resync.extend(garbage(100));
    resync.extend(&bytes[at[2]..]);
    for (damaged, bytes, expected) in [
        (DamagedInput::Salvage, &bytes, vec!["a.txt", "b.txt", "c.txt"]),
        (DamagedInput::Resync, &resync, vec!["a.txt", "b.txt", "c.txt"]),
        (DamagedInput::Salvage, &resync, vec!["a.txt", "b.txt"]),
    ] {
        let case = case(bytes);
        assert!(RarSession::open(&case.archive, None, RarSessionOptions::default()).is_err());
        let mut session =
            RarSession::open(&case.archive, None, RarSessionOptions { damaged_input: damaged, ..Default::default() })
                .unwrap();
        let listed: Vec<&str> = session.entries().map(|m| m.name()).collect();
        assert_eq!(listed, expected, "{damaged:?}");
        assert!(!session.archive().damaged_headers().is_empty());
        assert_eq!(session.archive().damaged_headers()[0].name.as_deref(), Some("b.txt"));
        let selected = session.select(|_| true).unwrap();
        let opts = options(&case.out, Mode::Extract, damaged);
        let summary = session.extract_selected(&selected, &opts, RarDecodeLimits::default(), |_| {}).unwrap();
        assert_eq!((summary.files as usize, summary.failed), (expected.len(), 0), "{damaged:?}");
        assert_bytes(&case, "b.txt", B);
    }
}

#[test]
fn fixture_unrar_salvage_creates_the_folder_whose_header_is_corrupt() {
    for (file, folder, kinds_expected) in [
        ("salvage-rar5-dir-crc.rar", "t", vec![HeaderDamageKind::ChecksumMismatch, HeaderDamageKind::UnexpectedEnd]),
        ("salvage-rar5-main-and-dir-crc.rar", "p", vec![HeaderDamageKind::ChecksumMismatch; 3]),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let archive = Path::new(FIXTURES).join(file);
        let out = dir.path().join("out");
        assert!(extract::run(&archive, &options(&out, Mode::Extract, DamagedInput::Refuse), |_| {}).is_err());
        let summary = extract::run(&archive, &options(&out, Mode::Extract, DamagedInput::Salvage), |_| {}).unwrap();
        assert!(out.join(folder).is_dir(), "{file}");
        assert_eq!(summary.dirs, 1, "{file}");
        assert_eq!(kinds(&summary.damaged_headers), kinds_expected, "{file}");
        let session = RarSession::open(
            &archive,
            None,
            RarSessionOptions { damaged_input: DamagedInput::Salvage, ..Default::default() },
        )
        .unwrap();
        assert_eq!(session.entries().map(|m| m.name().to_owned()).collect::<Vec<_>>(), [folder]);
    }
}

/// UnRAR lists an archive cut inside its RAR 4.x main header as `Details: RAR 1.5`, `0 files`, exit 3; 7-Zip says
/// "Unexpected end of archive" for one cut inside a file header or (RAR 5.0) without its end header.
#[test]
fn fixtures_cut_short_open_empty_with_an_unexpected_end() {
    for (file, format, refused) in [
        ("list-rar4-cut-in-main.rar", zipfast::rar5::RarFormat::Rar4, true),
        ("list-rar4-cut-at-main.rar", zipfast::rar5::RarFormat::Rar4, true),
        ("hdrerr-rar4-cut-in-file.rar", zipfast::rar5::RarFormat::Rar4, true),
        ("hdrerr-rar5-no-end.rar", zipfast::rar5::RarFormat::Rar5, false),
    ] {
        let archive = Path::new(FIXTURES).join(file);
        let dir = tempfile::tempdir().unwrap();
        let refuse = options(dir.path(), Mode::Test, DamagedInput::Refuse);
        assert_eq!(extract::list_detailed_with_options(&archive, None, &refuse).is_err(), refused, "{file}");
        assert_eq!(RarSession::open(&archive, None, RarSessionOptions::default()).is_err(), refused, "{file}");
        let salvage = options(dir.path(), Mode::Test, DamagedInput::Salvage);
        let listing = extract::list_detailed_with_options(&archive, None, &salvage).unwrap();
        assert!(listing.entries.is_empty(), "{file}");
        assert!(listing.unexpected_end() && listing.headers_damaged(), "{file}");
        let session = RarSession::open(
            &archive,
            None,
            RarSessionOptions { damaged_input: DamagedInput::Salvage, ..Default::default() },
        )
        .unwrap();
        assert_eq!(session.archive().format(), format, "{file}");
        assert_eq!(session.entries().len(), 0, "{file}");
        assert_eq!(kinds(session.archive().damaged_headers()), [HeaderDamageKind::UnexpectedEnd], "{file}");
        let summary = extract::run(&archive, &salvage, |_| {}).unwrap();
        assert_eq!(kinds(&summary.damaged_headers), [HeaderDamageKind::UnexpectedEnd], "{file}");
    }
}

/// Hostile input: every 37th byte of a 3-member archive changed, under each salvaging choice and for each route:
/// nothing panics, every run ends, and any damage found is reported.
#[test]
fn corrupting_every_37th_offset_never_panics() {
    let started = Instant::now();
    for (bytes, _) in [rar5(), rar4()] {
        for offset in (0..bytes.len()).step_by(37) {
            for value in [0x00, 0xff, bytes[offset] ^ 0x5a] {
                let mut damaged = bytes.clone();
                damaged[offset] = value;
                let case = case(&damaged);
                for choice in [DamagedInput::Salvage, DamagedInput::Resync] {
                    let _ = extract(&case, choice);
                    let _ = listed(&case, choice);
                    let session_options = RarSessionOptions { damaged_input: choice, ..Default::default() };
                    if let Ok(mut session) = RarSession::open(&case.archive, None, session_options)
                        && let Ok(selected) = session.select(|_| true)
                    {
                        let opts = options(&case.out, Mode::Test, choice);
                        let _ = session.extract_selected(&selected, &opts, RarDecodeLimits::default(), |_| {});
                    }
                }
            }
        }
    }
    assert!(started.elapsed() < Duration::from_secs(120), "{:?}", started.elapsed());
}

/// A resync over a long stretch built to pass every cheap check (a plausible size and header type at every byte)
/// stays bounded: its checksum work is capped by a multiple of what it scans.
#[test]
fn resync_over_adversarial_bytes_stays_linear() {
    let (bytes, at) = rar5();
    let mut damaged = bytes[..at[1]].to_vec();
    // every position reads as a 4-byte CRC, a 2-byte size of 0x3f02 (16130) and type 2
    let pattern = [0x82u8, 0x7e, 0x02, 0x02];
    damaged.extend(pattern.iter().cycle().take(8 << 20));
    damaged.extend(&bytes[at[1]..]);
    let case = case(&damaged);
    let started = Instant::now();
    let summary = extract(&case, DamagedInput::Resync).unwrap();
    assert!(written(&case).starts_with(&["a.txt".to_owned()]));
    assert!(!summary.damaged_headers.is_empty());
    assert!(started.elapsed() < Duration::from_secs(60), "{:?}", started.elapsed());
}

/// Thousands of headers that pass their checksum but don't parse, back to back: every one is a resync and a
/// damage record (kept up to the cap), and the volume-wide work bound keeps the whole walk bounded.
#[test]
fn resync_through_many_false_headers_stays_bounded() {
    let (bytes, at) = rar5();
    let mut damaged = bytes[..at[1]].to_vec();
    let false_header = common::block(2, 0, &[0xff], &[], &[], false);
    for _ in 0..100_000 {
        damaged.extend(&false_header);
    }
    damaged.extend(&bytes[at[1]..]);
    let case = case(&damaged);
    let started = Instant::now();
    let summary = extract(&case, DamagedInput::Resync).unwrap();
    assert_eq!(written(&case), ["a.txt", "b.txt", "c.txt"]);
    assert_bytes(&case, "c.txt", C);
    assert_eq!(summary.damaged_headers.len(), 4096);
    let mut session = RarSession::open(
        &case.archive,
        None,
        RarSessionOptions { damaged_input: DamagedInput::Resync, ..Default::default() },
    )
    .unwrap();
    assert_eq!(session.entries().len(), 3);
    assert_eq!(session.archive().damaged_headers().len(), 4096);
    let selected = session.select(|_| true).unwrap();
    let opts = options(&case.out, Mode::Test, DamagedInput::Resync);
    assert_eq!(session.extract_selected(&selected, &opts, RarDecodeLimits::default(), |_| {}).unwrap().files, 3);
    assert!(started.elapsed() < Duration::from_secs(60), "{:?}", started.elapsed());
}

/// Deterministic noise, like compressed data (xorshift).
fn noise(len: usize, mut seed: u64) -> Vec<u8> {
    (0..len)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed as u8
        })
        .collect()
}

/// The case resync is for: a damaged header followed by megabytes of what looks like compressed data, then intact
/// members. The search must cross it within its work bound and find the next header.
#[test]
fn resync_crosses_megabytes_of_random_data() {
    for (format, (bytes, at)) in [("rar5", rar5()), ("rar4", rar4())] {
        for (len, seed) in [(256 << 10, 1), (4 << 20, 2), (16 << 20, 3)] {
            let mut damaged = bytes[..at[1]].to_vec();
            damaged.extend(noise(len, seed));
            damaged.extend(&bytes[at[1]..]);
            let case = case(&damaged);
            let summary = extract(&case, DamagedInput::Resync).unwrap();
            assert_eq!(written(&case), ["a.txt", "b.txt", "c.txt"], "{format} {len}");
            assert_bytes(&case, "b.txt", B);
            let last = summary.damaged_headers.last().unwrap();
            assert_eq!(last.resumed_at, Some((at[1] + len) as u64), "{format} {len}: {:?}", summary.damaged_headers);
        }
    }
}

/// A catalogue's resync that runs out of the catalogue's read budget gives up on the rest of that volume instead of
/// failing the whole session.
#[test]
fn session_resync_out_of_read_budget_gives_up_instead_of_failing() {
    let (bytes, at) = rar5();
    let mut damaged = bytes[..at[1]].to_vec();
    damaged.extend(vec![0; 2 << 20]);
    damaged.extend(&bytes[at[1]..]);
    let case = case(&damaged);
    let mut options = RarSessionOptions { damaged_input: DamagedInput::Resync, ..Default::default() };
    options.limits.read_bytes = 1 << 20;
    let session = RarSession::open(&case.archive, None, options).unwrap();
    assert_eq!(session.entries().map(|m| m.name().to_owned()).collect::<Vec<_>>(), ["a.txt"]);
    let damage = session.archive().damaged_headers();
    assert_eq!((damage.len(), damage[0].resumed_at), (1, None));
}

/// A damaged RAR 5.0 encryption header is never read as it stands (its salt and KDF parameters would make every
/// later header look like a wrong password): it is an unreadable header, and nothing after it is read.
#[test]
fn a_damaged_encryption_header_is_not_salvaged() {
    let mut fields = Vec::new();
    common::vint(0, &mut fields); // encryption version
    common::vint(0, &mut fields); // flags: no password check
    fields.push(15); // KDF count
    fields.extend([7; 16]); // salt
    let mut bytes = SIG.to_vec();
    bytes.extend(main_block(false, None));
    let crypt = bytes.len();
    bytes.extend(common::block(4, 0, &fields, &[], &[], false));
    bytes.extend(garbage(64));
    bytes[crypt + 10] ^= 0x5a;
    let case = case(&bytes);
    assert!(
        extract::run_with_password(
            &case.archive,
            &options(&case.out, Mode::Test, DamagedInput::Refuse),
            Some("pw"),
            |_| {}
        )
        .is_err()
    );
    let opts = options(&case.out, Mode::Test, DamagedInput::Salvage);
    let summary = extract::run_with_password(&case.archive, &opts, Some("pw"), |_| {}).unwrap();
    assert_eq!(kinds(&summary.damaged_headers), [HeaderDamageKind::Unreadable]);
    assert_eq!(summary.damaged_headers[0].offset, crypt as u64);
}

/// A RAR 4.x header whose damage sets the embedded-comment flag is damage, not an unsupported feature: Salvage ends
/// the volume there and Resync goes on to the next member.
#[test]
fn a_damaged_rar4_comment_flag_is_damage_not_unsupported() {
    let (mut bytes, at) = rar4();
    bytes[at[1] + 3] |= 0x08;
    let case = case(&bytes);
    assert!(extract(&case, DamagedInput::Refuse).is_err());
    let summary = extract(&case, DamagedInput::Salvage).unwrap();
    assert_eq!(written(&case), ["a.txt"]);
    assert_eq!(kinds(&summary.damaged_headers), [HeaderDamageKind::Unreadable]);
    fs::remove_dir_all(&case.out).unwrap();
    let summary = extract(&case, DamagedInput::Resync).unwrap();
    assert_eq!(written(&case), ["a.txt", "c.txt"]);
    assert_eq!(summary.damaged_headers[0].resumed_at, Some(at[2] as u64));
}

/// Canceling a whole-archive run while a resync searches a long damaged stretch fails the run as canceled, never as
/// a success.
#[test]
fn canceling_during_a_resync_cancels_the_run() {
    let (bytes, at) = rar5();
    let mut damaged = bytes[..at[1]].to_vec();
    damaged.extend(noise(8 << 20, 9));
    let case = case(&damaged);
    let cancel = extract::Cancellation::default();
    let opts = options(&case.out, Mode::Extract, DamagedInput::Resync);
    let result = extract::run_with_policy(
        &case.archive,
        &opts,
        None,
        &cancel,
        &Default::default(),
        |event: extract::RunEvent<'_>| {
            if matches!(event, extract::RunEvent::MemberSucceeded { .. }) {
                cancel.cancel();
            }
            Ok(())
        },
    );
    assert!(result.is_err(), "{result:?}");
    let uncanceled = extract::Cancellation::default();
    let report = extract::run_with_policy(
        &case.archive,
        &opts,
        None,
        &uncanceled,
        &Default::default(),
        |_: extract::RunEvent<'_>| Ok(()),
    )
    .unwrap();
    // the stretch where b.txt's header should be is unreadable, and the search finds nothing after it
    assert_eq!(report.damaged_headers(), 1);
}

/// A catalogue charges the damage records it keeps to its retained capacity: every slot of the vector holding them
/// (3000 records sit in 4096 slots) and each record's path.
#[test]
fn session_charges_damage_records_to_its_capacity() {
    let (bytes, at) = rar5();
    let mut damaged = bytes[..at[1]].to_vec();
    let false_header = common::block(2, 0, &[0xff], &[], &[], false);
    for _ in 0..3000 {
        damaged.extend(&false_header);
    }
    damaged.extend(&bytes[at[1]..]);
    let clean = case(&bytes);
    let damaged = case(&damaged);
    let resync = RarSessionOptions { damaged_input: DamagedInput::Resync, ..Default::default() };
    let session = RarSession::open(&damaged.archive, None, resync.clone()).unwrap();
    let baseline = RarSession::open(&clean.archive, None, resync).unwrap();
    let records = session.archive().damaged_headers();
    assert_eq!(records.len(), 3000);
    let paths: u64 = records.iter().map(|d| d.volume.as_os_str().len() as u64).sum();
    let charged = session.usage().capacity - baseline.usage().capacity;
    let slots = 4096 * size_of::<extract::HeaderDamage>() as u64;
    assert!(charged >= slots + paths, "{charged} < {slots} + {paths}");
}

/// A damage record keeps at most 1 KiB of a damaged header's name, whatever the header claims.
#[test]
fn damage_records_keep_at_most_a_kibibyte_of_name() {
    let long = "n".repeat(4000);
    let mut bytes = SIG.to_vec();
    bytes.extend(main_block(false, None));
    let at = bytes.len();
    bytes.extend(file_block(&FileSpec::new(&long, A), A, hash(A), false, false));
    bytes.extend(end_block(false));
    bytes[at] ^= 0x5a;
    let case = case(&bytes);
    let summary = extract::run(&case.archive, &options(&case.out, Mode::Test, DamagedInput::Salvage), |_| {}).unwrap();
    let name = summary.damaged_headers[0].name.as_ref().unwrap();
    assert_eq!(name.len(), 1024);
    assert!(name.capacity() <= 1024, "the record holds {} bytes for its name", name.capacity());
}

/// A solid archive whose middle member's header is lost: the member after the gap continues a history that is no
/// longer whole, so it must fail as such, never decode against the history from before the gap. Its header carries
/// no CRC32 here, so only that rule stands between it and silently wrong bytes.
#[test]
fn a_resync_gap_breaks_the_solid_history() {
    use zipfast::rar5::testenc::{self, Op};
    let ops: [Vec<Op>; 3] = [vec![Op::Lit(b'a'); 100], vec![Op::Lit(b'b'); 100], vec![Op::Match(100, 100)]];
    let mut all = Vec::new();
    let mut plain = Vec::new();
    let mut at = 0;
    for o in &ops {
        all.extend(o.iter().cloned());
        let model = testenc::model(&all);
        plain.push(model[at..].to_vec());
        at = model.len();
    }
    assert_eq!(plain[2], vec![b'b'; 100]);
    let streams: Vec<Vec<u8>> = ops.iter().map(|o| testenc::block(o, true, true)).collect();
    let names = ["a.bin", "b.bin", "c.bin"];
    let mut bytes = SIG.to_vec();
    bytes.extend(common::main_block_flags(false, None, true));
    let mut offsets = Vec::new();
    for i in 0..3 {
        offsets.push(bytes.len());
        let spec = FileSpec {
            method: 3,
            size: Some(plain[i].len() as u64),
            solid: i > 0,
            no_crc: i == 2,
            ..FileSpec::new(names[i], &streams[i])
        };
        bytes.extend(file_block(&spec, &streams[i], hash(&plain[i]), false, false));
    }
    bytes.extend(end_block(false));
    let intact = case(&bytes);
    extract(&intact, DamagedInput::Resync).unwrap();
    assert_eq!(fs::read(intact.out.join("c.bin")).unwrap(), plain[2]);

    // b.bin's header zeroed (a hole, searched past), or its type byte turned from file (2) into service (3) or main
    // (1) so that it parses but its data is skipped: either way c.bin must not decode against a.bin's history alone
    let mut hole = bytes.clone();
    hole[offsets[1]..offsets[1] + 16].fill(0);
    let mut service = bytes.clone();
    assert_eq!(service[offsets[1] + 5], 2, "b.bin's header type");
    service[offsets[1] + 5] = 3;
    let mut main = bytes.clone();
    main[offsets[1] + 5] = 1;
    // or its file flags given the folder bit, so that it reads as a folder whose data is never decoded
    let mut folder = bytes.clone();
    let flags = {
        // CRC32, then the header size, type, header flags and data size, each a one-byte or longer vint
        let mut at = offsets[1] + 4;
        for _ in 0..4 {
            while bytes[at] & 0x80 != 0 {
                at += 1;
            }
            at += 1;
        }
        at
    };
    assert_eq!(folder[flags], 0x06, "b.bin's file flags (CRC32, mtime)");
    folder[flags] |= 0x01;
    let without_b = vec!["a.bin", "c.bin"];
    let cases = [
        ("hole", hole, without_b.clone()),
        ("service", service, without_b.clone()),
        ("main", main, without_b),
        ("folder", folder, vec!["a.bin", "b.bin", "c.bin"]),
    ];
    for (what, damaged, listed) in cases {
        for choice in [DamagedInput::Salvage, DamagedInput::Resync] {
            if what == "hole" && choice == DamagedInput::Salvage {
                continue; // the volume ends at the hole: nothing after it is read
            }
            let case = case(&damaged);
            let summary = extract(&case, choice).unwrap();
            assert_eq!(fs::read(case.out.join("a.bin")).unwrap(), plain[0], "{what} {choice:?}");
            assert!(!case.out.join("c.bin").exists(), "{what} {choice:?}: c.bin decoded against stale history");
            assert_eq!(summary.errors.len(), 1, "{what} {choice:?}: {:?}", summary.errors);

            let options_session = RarSessionOptions { damaged_input: choice, ..Default::default() };
            let mut session = RarSession::open(&case.archive, None, options_session).unwrap();
            let names: Vec<String> = session.entries().map(|m| m.name().to_owned()).collect();
            assert_eq!(names, listed, "{what} {choice:?}");
            let selected = session.select(|_| true).unwrap();
            let out = case.out.join("session");
            let opts = options(&out, Mode::Extract, choice);
            let summary = session.extract_selected(&selected, &opts, RarDecodeLimits::default(), |_| {}).unwrap();
            assert_eq!((summary.files, summary.failed), (1, 1), "{what} {choice:?}");
            assert!(!out.join("c.bin").exists(), "{what} {choice:?}");
        }
    }
}
