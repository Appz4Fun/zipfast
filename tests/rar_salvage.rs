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
        damaged_input: damaged,
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
