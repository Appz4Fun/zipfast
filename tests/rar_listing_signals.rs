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

//! Listing signals and cut members under `Options::damaged_input`, as UnRAR 7.30 and 7-Zip 26.06 list them: a missing
//! volume and a damaged archive comment reported without failing the listing, a member whose data the volume cuts
//! short listed (and decoded from what is there), and a RAR 4.x file header cut short listed as UnRAR lists it. The
//! default (`Refuse`) is unchanged.

#![cfg(unix)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use common::{FileSpec, SIG, end_block, file_block, main_block};
use zipfast::crc32::hash;
use zipfast::error::{RarFailure, RarIntegrityReason};
use zipfast::extract::{self, DamagedInput, HeaderDamageKind, Mode, Options, Overwrite, RarOutcome, UnverifiedOutput};
use zipfast::rar5::HeaderCut;
use zipfast::rar5::session::{RarDecodeLimits, RarPrintOptions, RarSession, RarSessionOptions};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
const A: &[u8] = b"alpha alpha alpha alpha alpha alpha alpha alpha alpha alpha";
const B: &[u8] = b"bravo bravo bravo bravo bravo bravo bravo bravo bravo bravo bravo bravo";

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
        unverified_output: Default::default(),
        salvage_truncated_zip: false,
        unix_modes: Default::default(),
        backslashes: Default::default(),
        hard_link_targets: Default::default(),
        seven_zip_strict: false,
        rar4_raw_names: false,
        folder_times: Default::default(),
    }
}

fn fixture(path: &str) -> Vec<u8> {
    fs::read(Path::new(FIXTURES).join(path)).unwrap()
}

struct Case {
    dir: tempfile::TempDir,
    archive: PathBuf,
    out: PathBuf,
}

/// `bytes` written as `name` in a fresh folder.
fn case_named(name: &str, bytes: &[u8]) -> Case {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join(name);
    fs::write(&archive, bytes).unwrap();
    let out = dir.path().join("out");
    Case { archive, out, dir }
}

fn case(bytes: &[u8]) -> Case {
    case_named("cut.rar", bytes)
}

fn listed(case: &Case, damaged: DamagedInput) -> zipfast::Result<extract::Listing> {
    extract::list_detailed_with_options(&case.archive, None, &options(&case.out, Mode::Test, damaged))
}

fn names(listing: &extract::Listing) -> Vec<&str> {
    listing.entries.iter().map(|e| e.name.as_str()).collect()
}

#[allow(clippy::result_large_err)]
fn session(case: &Case, damaged: DamagedInput) -> Result<RarSession, extract::RarRunError> {
    RarSession::open(&case.archive, None, RarSessionOptions { damaged_input: damaged, ..Default::default() })
}

fn sha256(bytes: &[u8]) -> String {
    zipfast::crypto::sha256(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

fn kinds(damage: &[extract::HeaderDamage]) -> Vec<HeaderDamageKind> {
    damage.iter().map(|d| d.kind).collect()
}

fn written(case: &Case) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(&case.out)
        .map(|d| d.map(|e| e.unwrap().file_name().into_string().unwrap()).collect())
        .unwrap_or_default();
    names.sort();
    names
}

/// A RAR 5.0 archive of a.txt and b.txt stored, and where b.txt's data starts.
fn rar5() -> (Vec<u8>, usize) {
    let mut out = SIG.to_vec();
    out.extend(main_block(false, None));
    out.extend(file_block(&FileSpec::new("a.txt", A), A, hash(A), false, false));
    out.extend(file_block(&FileSpec::new("b.txt", B), B, hash(B), false, false));
    let b_data = out.len() - B.len();
    out.extend(end_block(false));
    (out, b_data)
}

/// The set names a volume that isn't there: `Refuse` fails the listing as before; `Salvage` lists the members up to
/// it, the one split into it with its declared sizes, and names it, as 7-Zip's "ERROR = Missing volume" does. The
/// session already reported it.
#[test]
fn salvage_lists_up_to_a_missing_volume_and_names_it() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("multi.part1.rar"), fixture("rar4-volumes/multi.part1.rar")).unwrap();
    // the third volume is there, the second isn't: the listing stops at the gap, as 7-Zip's does
    fs::write(dir.path().join("multi.part3.rar"), fixture("rar4-volumes/multi.part3.rar")).unwrap();
    let first = dir.path().join("multi.part1.rar");
    let out = dir.path().join("out");
    let refused = extract::list_detailed_with_options(&first, None, &options(&out, Mode::Test, DamagedInput::Refuse));
    assert!(matches!(refused, Err(zipfast::Error::MissingVolume(_))), "{refused:?}");
    assert!(matches!(extract::list_detailed(&first, None), Err(zipfast::Error::MissingVolume(_))));
    for damaged in [DamagedInput::Salvage, DamagedInput::Resync] {
        let listing = extract::list_detailed_with_options(&first, None, &options(&out, Mode::Test, damaged)).unwrap();
        assert_eq!(names(&listing), ["file1.txt", "file2.txt"], "{damaged:?}");
        assert_eq!(listing.entries[1].size, 17704, "{damaged:?}");
        assert!(listing.missing_volume.as_ref().unwrap().ends_with("multi.part2.rar"), "{damaged:?}");
        assert!(listing.unexpected_end() && !listing.headers_damaged(), "{damaged:?}");
    }
    let session = RarSession::open(&first, None, RarSessionOptions::default()).unwrap();
    assert!(session.archive().missing_volume().unwrap().ends_with("multi.part2.rar"));
}

/// commented.rar with its `CMT` comment's data CRC changed and the header's own CRC fixed up: UnRAR 7.30 prints
/// "The archive comment is corrupt" (exit 3) and lists file.txt. `Salvage` lists it and names the volume; `Refuse`
/// lists it as before, saying nothing; the session's `comment` fails.
#[test]
fn salvage_reports_a_rar4_comment_that_fails_its_crc() {
    let good = fixture("rar4/commented.rar");
    // the CMT service header: at 20, its file CRC at +16, its header CRC16 over bytes 2..35 of it
    assert_eq!(good[20 + 2], 0x7a);
    let mut bad = good.clone();
    bad[36] ^= 0x01;
    let crc = (hash(&bad[22..55]) & 0xffff) as u16;
    bad[20..22].copy_from_slice(&crc.to_le_bytes());
    for (bytes, damaged_comment) in [(&good, false), (&bad, true)] {
        let case = case(bytes);
        let refused = listed(&case, DamagedInput::Refuse).unwrap();
        assert_eq!(names(&refused), ["file.txt"]);
        assert!(refused.damaged_comments.is_empty());
        let listing = listed(&case, DamagedInput::Salvage).unwrap();
        assert_eq!(names(&listing), ["file.txt"]);
        assert_eq!(listing.comment_damaged(), damaged_comment);
        assert!(!listing.headers_damaged() && !listing.unexpected_end());
        if damaged_comment {
            assert_eq!(listing.damaged_comments, std::slice::from_ref(&case.archive));
        }
        let session = session(&case, DamagedInput::Refuse).unwrap();
        assert_eq!(session.comment(0).is_err(), damaged_comment);
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_zipfast"))
            .args(["l", "--salvage"])
            .arg(&case.archive)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(if damaged_comment { 1 } else { 0 }), "{stderr}");
        assert_eq!(stderr.contains("comment"), damaged_comment, "{stderr}");
    }
}

/// readme_154_normal.rar (one RAR 1.5 compressed member) cut 1000 bytes in, inside its data: UnRAR and 7-Zip list
/// README.md with its declared sizes; UnRAR decodes what is there and reports a checksum error, removing the file
/// (`-kb` keeps the 1774 bytes decoded). `Salvage` lists it, reports the cut, and the member fails on its own.
#[test]
fn salvage_lists_a_rar4_member_whose_data_is_cut_off() {
    let bytes = fixture("rar4-legacy/readme_154_normal.rar");
    let case = case(&bytes[..1000]);
    assert!(listed(&case, DamagedInput::Refuse).is_err());
    assert!(session(&case, DamagedInput::Refuse).is_err());
    let opts = options(&case.out, Mode::Extract, DamagedInput::Refuse);
    assert!(extract::run(&case.archive, &opts, |_| {}).is_err());

    let listing = listed(&case, DamagedInput::Salvage).unwrap();
    assert_eq!(names(&listing), ["README.md"]);
    assert_eq!((listing.entries[0].size, listing.entries[0].packed), (4198, 2068));
    assert!(listing.unexpected_end());
    let damage = &listing.damaged_headers;
    assert_eq!(damage.len(), 1);
    assert_eq!((damage[0].kind, damage[0].offset), (HeaderDamageKind::UnexpectedEnd, 20));
    assert_eq!(damage[0].name.as_deref(), Some("README.md"));
    assert_eq!(damage[0].cut, Some(HeaderCut::Data { present: 1000 - 61 }));

    let session = session(&case, DamagedInput::Salvage).unwrap();
    let member = session.entries().next().unwrap();
    assert_eq!((member.name(), member.packed_size()), ("README.md", 2068));
    assert_eq!(member.cut(), Some(HeaderCut::Data { present: 939 }));

    let opts = options(&case.out, Mode::Extract, DamagedInput::Salvage);
    let summary = extract::run(&case.archive, &opts, |_| {}).unwrap();
    assert_eq!(summary.errors.len(), 1, "{:?}", summary.errors);
    assert!(written(&case).is_empty());
    assert_eq!(summary.damaged_headers.len(), 1);
    // kept with keep_broken: the 1,774 bytes `unrar x -kb` keeps (and `unrar p` prints), under Withhold and Emit
    // alike, decoded as UnRAR decodes a member cut short
    const UNRAR_KB: &str = "9088570bd395f56c88ab726efae3c7a024309fd449c9e84bf22bf9eee9fe4e29";
    let opts = Options { keep_broken: true, ..options(&case.out, Mode::Extract, DamagedInput::Salvage) };
    let emit = Options { unverified_output: UnverifiedOutput::Emit, ..opts.clone() };
    for opts in [&opts, &emit] {
        let summary = extract::run(&case.archive, opts, |_| {}).unwrap();
        assert_eq!(summary.errors.len(), 1);
        assert_eq!(written(&case), ["README.md"]);
        assert_eq!(sha256(&fs::read(case.out.join("README.md")).unwrap()), UNRAR_KB);
    }

    // a RarSession fails it as truncated (UnRAR: "checksum error", exit 3), in a test and an extraction alike, and
    // keeps the same bytes with keep_broken
    let mut session = self::session(&case, DamagedInput::Salvage).unwrap();
    let selected = session.select(|_| true).unwrap();
    let mut failures = Vec::new();
    session
        .test_selected(&selected, RarDecodeLimits::default(), |event| {
            if let RarOutcome::Failed(failure) = &event.outcome {
                failures.push(failure.clone());
            }
        })
        .unwrap();
    assert!(
        matches!(failures[..], [ref f] if matches!(f.as_ref(), RarFailure::Integrity { reason: RarIntegrityReason::TruncatedData, .. })),
        "{failures:?}"
    );
    let out = case.dir.path().join("session");
    let opts = Options { dest: out.clone(), ..opts };
    let summary = session.extract_selected(&selected, &opts, RarDecodeLimits::default(), |_| {}).unwrap();
    assert_eq!((summary.files, summary.failed), (0, 1));
    assert_eq!(sha256(&fs::read(out.join("README.md")).unwrap()), UNRAR_KB);
}

/// latest_winrar.rar cut 50 bytes into 1.txt's 17 packed bytes... at 70, 8 bytes in: UnRAR 7.30 decodes 1.txt from
/// them, its CRC passes, and it reports it OK (`t` and `x`: "Unexpected end of archive", exit 1). So does `Salvage`,
/// through the runner and a `RarSession` alike: the member's own checks decide, and the archive still ends
/// unexpectedly (its `UnexpectedEnd` record).
#[test]
fn salvage_extracts_a_cut_member_whose_checks_pass_as_unrar_does() {
    let bytes = fixture("rar4/latest_winrar.rar");
    let case = case(&bytes[..70]);
    let opts = options(&case.out, Mode::Extract, DamagedInput::Salvage);
    let summary = extract::run(&case.archive, &opts, |_| {}).unwrap();
    assert!(summary.errors.is_empty(), "{:?}", summary.errors);
    assert_eq!(fs::read(case.out.join("1.txt")).unwrap().len(), 5);
    assert_eq!(summary.damaged_headers[0].cut, Some(HeaderCut::Data { present: 8 }));
    // a RarSession lists it with its declared size, reports the cut, and tests, prints and extracts it as good
    let mut session = session(&case, DamagedInput::Salvage).unwrap();
    assert_eq!(kinds(session.archive().damaged_headers()), [HeaderDamageKind::UnexpectedEnd]);
    let member = session.entries().next().unwrap();
    assert_eq!((member.name(), member.cut()), ("1.txt", Some(HeaderCut::Data { present: 8 })));
    let selected = session.select(|_| true).unwrap();
    let out = case.dir.path().join("session");
    let opts = options(&out, Mode::Extract, DamagedInput::Salvage);
    let summary = session.extract_selected(&selected, &opts, RarDecodeLimits::default(), |_| {}).unwrap();
    assert_eq!((summary.files, summary.failed), (1, 0));
    assert_eq!(fs::read(out.join("1.txt")).unwrap(), fs::read(case.out.join("1.txt")).unwrap());
    let summary = session.test_selected(&selected, RarDecodeLimits::default(), |_| {}).unwrap();
    assert_eq!((summary.files, summary.failed), (1, 0));
    let mut printed = Vec::new();
    let summary = session.print_selected(&selected, &mut printed, &RarPrintOptions::default(), |_| {}).unwrap();
    assert_eq!((summary.files, summary.failed, printed.len()), (1, 0, 5));
    // with no data bytes at all it fails
    let case = self::case(&bytes[..62]);
    let opts = options(&case.out, Mode::Extract, DamagedInput::Salvage);
    let summary = extract::run(&case.archive, &opts, |_| {}).unwrap();
    assert_eq!(summary.errors.len(), 1);
    assert!(written(&case).is_empty());
}

/// latest_winrar.rar cut at every byte of 1.txt's 17 packed bytes (62 to 78): `unrar t` 7.30 reports 1.txt OK from
/// 68 on (six bytes of data there) and a checksum error before ("Unexpected end of archive" either way). The runner and
/// a `RarSession` give the same verdicts, under `Withhold` and `Emit` alike.
#[test]
fn a_cut_member_passes_or_fails_where_unrar_does() {
    let bytes = fixture("rar4/latest_winrar.rar");
    for at in 62..79 {
        let unrar_ok = at >= 68;
        let case = case(&bytes[..at]);
        for unverified in [UnverifiedOutput::Withhold, UnverifiedOutput::Emit] {
            let what = format!("cut at {at} {unverified:?}");
            let opts =
                Options { unverified_output: unverified, ..options(&case.out, Mode::Test, DamagedInput::Salvage) };
            let summary = extract::run(&case.archive, &opts, |_| {}).unwrap();
            assert_eq!(summary.errors.is_empty(), unrar_ok, "{what}: runner {:?}", summary.errors);
            assert_eq!(kinds(&summary.damaged_headers), [HeaderDamageKind::UnexpectedEnd], "{what}");
            let mut session = self::session(&case, DamagedInput::Salvage).unwrap();
            let selected = session.select(|_| true).unwrap();
            let summary = session.test_selected(&selected, RarDecodeLimits::default(), |_| {}).unwrap();
            assert_eq!((summary.files, summary.failed), if unrar_ok { (1, 0) } else { (0, 1) }, "{what}: session");
            let print = RarPrintOptions { unverified_output: unverified, ..RarPrintOptions::default() };
            let summary = session.print_selected(&selected, &mut Vec::new(), &print, |_| {}).unwrap();
            assert_eq!(summary.failed, u64::from(!unrar_ok), "{what}: session print");
        }
    }
}

/// A RAR 5.0 archive cut inside b.txt's data: both tools list a.txt and b.txt. `Salvage` lists both, through the
/// listing and the session, extracts a.txt, and b.txt fails (stored, so too short).
#[test]
fn salvage_lists_a_rar5_member_whose_data_is_cut_off() {
    let (bytes, b_data) = rar5();
    let case = case(&bytes[..b_data + 10]);
    assert!(listed(&case, DamagedInput::Refuse).is_err());
    let listing = listed(&case, DamagedInput::Salvage).unwrap();
    assert_eq!(names(&listing), ["a.txt", "b.txt"]);
    assert_eq!(listing.entries[1].packed, B.len() as u64);
    assert_eq!(listing.damaged_headers.len(), 1, "{:?}", listing.damaged_headers);
    assert_eq!(listing.damaged_headers[0].cut, Some(HeaderCut::Data { present: 10 }));
    assert_eq!(listing.damaged_headers[0].name.as_deref(), Some("b.txt"));

    let opts = options(&case.out, Mode::Extract, DamagedInput::Salvage);
    let summary = extract::run(&case.archive, &opts, |_| {}).unwrap();
    assert_eq!(summary.errors.len(), 1, "{:?}", summary.errors);
    assert_eq!(written(&case), ["a.txt"]);

    let mut session = session(&case, DamagedInput::Salvage).unwrap();
    let listed: Vec<&str> = session.entries().map(|m| m.name()).collect();
    assert_eq!(listed, ["a.txt", "b.txt"]);
    assert_eq!(session.entries().nth(1).unwrap().packed_size(), B.len() as u64);
    let selected = session.select(|_| true).unwrap();
    let out = case.dir.path().join("session");
    let opts = options(&out, Mode::Extract, DamagedInput::Salvage);
    let summary = session.extract_selected(&selected, &opts, RarDecodeLimits::default(), |_| {}).unwrap();
    assert_eq!((summary.files, summary.failed), (1, 1));
    assert_eq!(fs::read(out.join("a.txt")).unwrap(), A);
    assert!(!out.join("b.txt").exists());
}

/// latest_winrar.rar cut inside 1.txt's header: UnRAR 7.30 lists an entry with what of the name is there ("1.t" at
/// 55 bytes, an empty name at 40) and its other fields as read, the rest zeros ("NAME - the file header is corrupt",
/// "Unexpected end of archive", exit 3); 7-Zip lists nothing. `Salvage` lists it as UnRAR does, marked
/// `HeaderCut::Header`, and extracting it fails without writing anything.
#[test]
fn salvage_lists_a_cut_rar4_file_header_as_unrar_does() {
    let bytes = fixture("rar4/latest_winrar.rar");
    for (cut, name) in [(55, "1.t"), (40, ""), (27, "")] {
        let case = case(&bytes[..cut]);
        assert!(listed(&case, DamagedInput::Refuse).is_err(), "{cut}");
        let listing = listed(&case, DamagedInput::Salvage).unwrap();
        assert_eq!(names(&listing), [name], "{cut}");
        assert!(listing.unexpected_end(), "{cut}");
        assert_eq!(listing.damaged_headers.len(), 1, "{cut}: {:?}", listing.damaged_headers);
        let damage = &listing.damaged_headers[0];
        assert_eq!(
            (damage.kind, damage.offset, damage.cut),
            (HeaderDamageKind::UnexpectedEnd, 20, Some(HeaderCut::Header))
        );
        assert_eq!(damage.name.as_deref(), Some(name), "{cut}");

        let session = session(&case, DamagedInput::Salvage).unwrap();
        let member = session.entries().next().unwrap();
        assert_eq!((member.name(), member.cut()), (name, Some(HeaderCut::Header)), "{cut}");
        assert!(member.payload_issue().is_some(), "{cut}");

        let opts = options(&case.out, Mode::Extract, DamagedInput::Salvage);
        let summary = extract::run(&case.archive, &opts, |_| {}).unwrap();
        assert_eq!(summary.errors.len(), 1, "{cut}: {:?}", summary.errors);
        assert!(written(&case).is_empty(), "{cut}");
    }
    // the second header cut short: 1.txt stands, and 2 is listed after it
    let case = self::case(&bytes[..112]);
    let listing = listed(&case, DamagedInput::Salvage).unwrap();
    assert_eq!(names(&listing), ["1.txt", "2"]);
    // fewer than the 7 bytes every header starts with: nothing to list, as UnRAR ("Corrupt header is found")
    let case = self::case(&bytes[..25]);
    let listing = listed(&case, DamagedInput::Salvage).unwrap();
    assert!(listing.entries.is_empty());
    assert!(listing.unexpected_end());
}

/// Hostile input: every cut of a RAR 4.x and a RAR 5.0 archive, listed, catalogued and extracted under each choice,
/// never panics, and `Refuse` lists nothing new.
#[test]
fn every_cut_is_read_without_panicking() {
    let (rar5, _) = rar5();
    for bytes in [fixture("rar4/latest_winrar.rar"), fixture("rar4/commented.rar"), rar5] {
        for cut in 8..bytes.len() {
            let case = case(&bytes[..cut]);
            for damaged in [DamagedInput::Refuse, DamagedInput::Salvage, DamagedInput::Resync] {
                let _ = listed(&case, damaged);
                if let Ok(mut session) = session(&case, damaged)
                    && let Ok(selected) = session.select(|_| true)
                {
                    let out = case.dir.path().join(format!("s{cut}"));
                    let opts = options(&out, Mode::Extract, damaged);
                    let _ = session.extract_selected(&selected, &opts, RarDecodeLimits::default(), |_| {});
                }
                let _ = extract::run(&case.archive, &options(&case.out, Mode::Test, damaged), |_| {});
            }
        }
    }
}

/// multi.part2.rar (its continuation header at 20, 46 bytes, then 4914 data bytes) written cut at `len` beside the
/// whole first and third volumes.
fn cut_second_volume(len: usize) -> Case {
    let case = case_named("multi.part1.rar", &fixture("rar4-volumes/multi.part1.rar"));
    fs::write(case.dir.path().join("multi.part2.rar"), &fixture("rar4-volumes/multi.part2.rar")[..len]).unwrap();
    fs::write(case.dir.path().join("multi.part3.rar"), fixture("rar4-volumes/multi.part3.rar")).unwrap();
    case
}

/// A split member's continuation header cut short in the second volume: `Salvage` finishes the run at every cut
/// inside the header. Once file2.txt's name is whole (61 bytes on) the cut header continues it, and file2.txt fails
/// because the header is cut short; before that the partial name continues nothing.
#[test]
fn salvage_fails_a_split_member_whose_continuation_header_is_cut() {
    for len in 27..66 {
        let case = cut_second_volume(len);
        let opts = options(&case.out, Mode::Extract, DamagedInput::Salvage);
        let summary = extract::run(&case.archive, &opts, |_| {}).unwrap_or_else(|e| panic!("cut at {len}: {e}"));
        if len >= 61 {
            assert_eq!(summary.errors.len(), 1, "cut at {len}: {:?}", summary.errors);
            assert!(summary.errors[0].contains("file2.txt") && summary.errors[0].contains("cut short"), "{len}");
        } else {
            assert!(!summary.errors.is_empty(), "cut at {len}");
        }
        assert!(!case.out.join("file2.txt").exists(), "cut at {len}");
    }
}

/// The second volume cut inside a split member's data: the member is marked cut, but the first volume's own header
/// for it is not.
#[test]
fn salvage_marks_only_the_cut_part_of_a_split_member() {
    let case = cut_second_volume(1000);
    let session = session(&case, DamagedInput::Salvage).unwrap();
    let cut: Vec<_> = session.entries().filter_map(|m| m.cut().map(|cut| (m.name().to_owned(), cut))).collect();
    assert_eq!(cut, [("file2.txt".to_owned(), HeaderCut::Data { present: 1000 - 66 })]);
    let first = session.volume_headers(0).last().unwrap();
    assert_eq!((first.name(), first.cut()), ("file2.txt", None));
    let second = session.volume_headers(1).next().unwrap();
    assert_eq!((second.name(), second.cut()), ("file2.txt", Some(HeaderCut::Data { present: 1000 - 66 })));
}

/// `zipfast l --salvage` / `--resync` on a set missing its second volume shows what was listed, names the missing
/// volume and exits 2, as 7-Zip does; a damaged comment exits 1.
#[test]
fn salvage_cli_reports_a_missing_volume_and_a_damaged_comment() {
    let case = case_named("multi.part1.rar", &fixture("rar4-volumes/multi.part1.rar"));
    for flag in ["--salvage", "--resync"] {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_zipfast"))
            .args(["l", flag])
            .arg(&case.archive)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{flag}: {stderr}");
        assert!(stderr.contains("missing volume") && stderr.contains("multi.part2.rar"), "{flag}: {stderr}");
        assert!(String::from_utf8_lossy(&out.stdout).contains("name"), "{flag}");
    }
}

/// solid_simple_rar300.rar (one.txt, then compressed two.txt's header at 101, 39 bytes) cut at every byte of two.txt's
/// header, extracting only one.txt: the unselected cut header is passed over without reading its data (and the solid
/// stream's history marked lost after it), and the run finishes. A regression guard: the run passes a trailing
/// unselected member over without decoding it either way.
#[test]
fn salvage_passes_over_an_unselected_cut_header_in_a_solid_archive() {
    let bytes = fixture("rar4-rar300/solid_simple_rar300.rar");
    for len in 108..140 {
        let case = case(&bytes[..len]);
        let mut opts = options(&case.out, Mode::Extract, DamagedInput::Salvage);
        opts.select = Some(extract::MemberFilter::new(|m| m.name == "one.txt"));
        let summary = extract::run(&case.archive, &opts, |_| {}).unwrap_or_else(|e| panic!("cut at {len}: {e}"));
        assert!(summary.errors.is_empty(), "cut at {len}: {:?}", summary.errors);
        assert_eq!(written(&case), ["one.txt"], "cut at {len}");
        assert_eq!(summary.damaged_headers.len(), 1, "cut at {len}: {:?}", summary.damaged_headers);
        assert_eq!(summary.damaged_headers[0].cut, Some(HeaderCut::Header), "cut at {len}");
    }
}

/// A RAR 5.0 vint at `at`: its value and the offset after it.
fn vint(bytes: &[u8], mut at: usize) -> (u64, usize) {
    let (mut value, mut shift) = (0u64, 0);
    loop {
        let byte = bytes[at];
        value |= u64::from(byte & 0x7f) << shift;
        at += 1;
        shift += 7;
        if byte & 0x80 == 0 {
            return (value, at);
        }
    }
}

/// `rar5-threads/solid.rar` cut 100 bytes short of `b.txt`'s data end, as `x.part1.rar`, with no end header, so the
/// session goes on to `x.part2.rar` (both marked volumes): the main header, then `c.txt` (solid, its history `b.txt`'s) and the end header.
/// `b.txt`'s header is patched to declare the size and CRC of what UnRAR decodes of it there, so it tests good; `c.txt`
/// then fails as one whose history is lost (nothing goes on from a member decoded past the end), rather than the session
/// going on without a decoder.
#[test]
fn a_solid_member_after_a_cut_one_that_passes_has_no_history() {
    let solid = fixture("rar5-threads/solid.rar");
    let dir = tempfile::tempdir().unwrap();
    let whole = dir.path().join("solid.rar");
    fs::write(&whole, &solid).unwrap();
    let session = RarSession::open(&whole, None, RarSessionOptions::default()).unwrap();
    let headers: Vec<(String, u64, u64)> = session
        .volume_headers(0)
        .map(|h| (h.name().to_owned(), h.data_offset(), h.data_offset() + h.packed_size()))
        .collect();
    // the members, then the quick open record, then the end header
    assert_eq!(headers.iter().map(|h| h.0.as_str()).collect::<Vec<_>>(), ["b.txt", "c.txt", "d.txt", "s.txt", "QO"]);
    let (b_end, c_end, last_end) = (headers[0].2 as usize, headers[1].2 as usize, headers[4].2 as usize);
    // the signature and the main header: its CRC, then its size
    let (size, after) = vint(&solid, 12);
    let main_end = after + size as usize;
    // marked a volume (archive flag 0x0001), so the session looks for the next one where the first ends early
    let mut volume = solid.clone();
    let (_, at) = vint(&volume, after);
    let (header_flags, mut at) = vint(&volume, at);
    if header_flags & 1 != 0 {
        at = vint(&volume, at).1;
    }
    assert_eq!(volume[at] & 0x81, 0, "one-byte archive flags, not yet a volume");
    volume[at] |= 1;
    let main_crc = hash(&volume[12..main_end]);
    volume[8..12].copy_from_slice(&main_crc.to_le_bytes());
    let solid = volume;
    let mut part2 = solid[..main_end].to_vec();
    part2.extend_from_slice(&solid[b_end..c_end]);
    part2.extend_from_slice(&solid[last_end..]);
    fs::write(dir.path().join("x.part2.rar"), &part2).unwrap();

    let first = dir.path().join("x.part1.rar");
    let mut part1 = solid[..b_end - 100].to_vec();
    fs::write(&first, &part1).unwrap();
    let salvage = RarSessionOptions { damaged_input: DamagedInput::Salvage, ..Default::default() };
    let mut session = RarSession::open(&first, None, salvage.clone()).unwrap();
    let selected = session.select(|m| m.name() == "b.txt").unwrap();
    let mut decoded = Vec::new();
    let print = RarPrintOptions { unverified_output: UnverifiedOutput::Emit, ..RarPrintOptions::default() };
    session.print_selected(&selected, &mut decoded, &print, |_| {}).unwrap();
    assert!(!decoded.is_empty());
    // b.txt's header: CRC, size, type, flags, [extra size], [data size], file flags, unpacked size,
    // attributes, [mtime], data CRC
    let header = main_end;
    let (size, fields) = vint(&part1, header + 4);
    let header_end = fields + size as usize;
    let (_, at) = vint(&part1, fields);
    let (flags, mut at) = vint(&part1, at);
    if flags & 1 != 0 {
        at = vint(&part1, at).1;
    }
    if flags & 2 != 0 {
        at = vint(&part1, at).1;
    }
    let (file_flags, unpacked_at) = vint(&part1, at);
    let (_, after_unpacked) = vint(&part1, unpacked_at);
    assert_eq!(file_flags & 0x0004, 0x0004, "b.txt has a data CRC");
    // the decoded length in a vint as wide as the declared size's
    let width = after_unpacked - unpacked_at;
    let len = decoded.len() as u64;
    assert!(len < 1 << (7 * width));
    for (k, byte) in part1[unpacked_at..after_unpacked].iter_mut().enumerate() {
        *byte = (len >> (7 * k)) as u8 & 0x7f | if k + 1 < width { 0x80 } else { 0 };
    }
    let (_, mut crc_at) = vint(&part1, after_unpacked);
    if file_flags & 0x0002 != 0 {
        crc_at += 4;
    }
    part1[crc_at..crc_at + 4].copy_from_slice(&hash(&decoded).to_le_bytes());
    let header_crc = hash(&part1[header + 4..header_end]);
    part1[header..header + 4].copy_from_slice(&header_crc.to_le_bytes());
    fs::write(&first, &part1).unwrap();

    let mut session = RarSession::open(&first, None, salvage.clone()).unwrap();
    let names: Vec<String> = session.entries().map(|m| m.name().to_owned()).collect();
    assert_eq!(names, ["b.txt", "c.txt"]);
    let selected = session.select(|_| true).unwrap();
    let mut outcomes = Vec::new();
    session
        .test_selected(&selected, RarDecodeLimits::default(), |event| {
            outcomes.push(match &event.outcome {
                RarOutcome::Verified { .. } => "verified",
                RarOutcome::Failed(f) if matches!(f.as_ref(), RarFailure::SolidHistoryUnavailable { .. }) => "history",
                _ => "other",
            })
        })
        .unwrap();
    assert_eq!(outcomes, ["verified", "history"]);
    // the runner too
    let out = dir.path().join("out");
    let summary = extract::run(&first, &options(&out, Mode::Test, DamagedInput::Salvage), |_| {}).unwrap();
    assert_eq!(summary.errors.len(), 1, "{:?}", summary.errors);
    assert!(summary.errors[0].contains("c.txt"), "{:?}", summary.errors);
    // c.txt alone: its predecessor decoded first, then the same
    let mut session = RarSession::open(&first, None, salvage).unwrap();
    let selected = session.select(|m| m.name() == "c.txt").unwrap();
    let summary = session.test_selected(&selected, RarDecodeLimits::default(), |_| {}).unwrap();
    assert_eq!((summary.files, summary.failed), (0, 1));
}

/// RAR 4.x's low 16 bits of the CRC32 of a block from its type byte on.
fn rar4_header_crc(block: &mut [u8]) {
    let crc = hash(&block[2..]) as u16;
    block[..2].copy_from_slice(&crc.to_le_bytes());
}

/// [`a_solid_member_after_a_cut_one_that_passes_has_no_history`] for RAR 4.x: `rar4/solid.rar` (`tese.txt`, then
/// `unrardll.txt` solid after it) cut 100 bytes short of `tese.txt`'s data end, as `x.part1.rar`, then `x.part2.rar`
/// holding `unrardll.txt` (both marked volumes, new naming). `tese.txt`'s header declares what UnRAR decodes of it
/// there, so it tests good. `unrardll.txt` selected alone decodes `tese.txt` first, then fails as one whose history is
/// lost, and the run goes on, rather than ending on a decoder it has no stream for.
#[test]
fn a_rar4_solid_member_after_a_cut_one_that_passes_has_no_history() {
    let solid = fixture("rar4/solid.rar");
    // the marker (7 bytes), the main header (13), tese.txt's header (45) and data (448), then unrardll.txt
    let (main, a_header, a_end) = (7usize, 20usize, 513usize);
    assert_eq!(&solid[a_header + 32..a_header + 40], b"tese.txt");
    assert_eq!(&solid[a_end + 32..a_end + 44], b"unrardll.txt");
    assert_eq!(u16::from_le_bytes([solid[a_end + 3], solid[a_end + 4]]) & 0x0010, 0x0010, "unrardll.txt is solid");
    let mut volume = solid.clone();
    // MHD_VOLUME | MHD_NEWNUMBERING beside MHD_SOLID
    volume[main + 3] |= 0x11;
    rar4_header_crc(&mut volume[main..a_header]);
    let dir = tempfile::tempdir().unwrap();
    let mut part2 = volume[..a_header].to_vec();
    part2.extend_from_slice(&volume[a_end..]);
    fs::write(dir.path().join("x.part2.rar"), &part2).unwrap();

    let first = dir.path().join("x.part1.rar");
    let mut part1 = volume[..a_end - 100].to_vec();
    fs::write(&first, &part1).unwrap();
    let salvage = RarSessionOptions { damaged_input: DamagedInput::Salvage, ..Default::default() };
    let mut session = RarSession::open(&first, None, salvage.clone()).unwrap();
    let selected = session.select(|m| m.name() == "tese.txt").unwrap();
    let mut decoded = Vec::new();
    let print = RarPrintOptions { unverified_output: UnverifiedOutput::Emit, ..RarPrintOptions::default() };
    let _ = session.print_selected(&selected, &mut decoded, &print, |_| {});
    assert!(!decoded.is_empty());
    // tese.txt's unpacked size (after the packed size), then its CRC (after the host OS byte)
    let unpacked_at = a_header + 11;
    part1[unpacked_at..unpacked_at + 4].copy_from_slice(&(decoded.len() as u32).to_le_bytes());
    part1[unpacked_at + 5..unpacked_at + 9].copy_from_slice(&hash(&decoded).to_le_bytes());
    rar4_header_crc(&mut part1[a_header..a_end - 448]);
    fs::write(&first, &part1).unwrap();

    let history = |f: &RarFailure| matches!(f, RarFailure::SolidHistoryUnavailable { .. });
    let mut session = RarSession::open(&first, None, salvage.clone()).unwrap();
    let names: Vec<String> = session.entries().map(|m| m.name().to_owned()).collect();
    assert_eq!(names, ["tese.txt", "unrardll.txt"]);
    let selected = session.select(|_| true).unwrap();
    let mut outcomes = Vec::new();
    session
        .test_selected(&selected, RarDecodeLimits::default(), |event| {
            outcomes.push(match &event.outcome {
                RarOutcome::Verified { .. } => "verified",
                RarOutcome::Failed(f) if history(f) => "history",
                _ => "other",
            })
        })
        .unwrap();
    assert_eq!(outcomes, ["verified", "history"]);
    // unrardll.txt alone: its predecessor decoded first, then the same, and the run carries on
    let mut session = RarSession::open(&first, None, salvage).unwrap();
    let selected = session.select(|m| m.name() == "unrardll.txt").unwrap();
    let mut outcomes = Vec::new();
    let summary = session
        .test_selected(&selected, RarDecodeLimits::default(), |event| {
            outcomes.push(matches!(&event.outcome, RarOutcome::Failed(f) if history(f)))
        })
        .unwrap();
    assert_eq!(outcomes, [true]);
    assert_eq!((summary.files, summary.failed), (0, 1));
    // the runner too
    let out = dir.path().join("out");
    let summary = extract::run(&first, &options(&out, Mode::Test, DamagedInput::Salvage), |_| {}).unwrap();
    assert_eq!(summary.errors.len(), 1, "{:?}", summary.errors);
    assert!(summary.errors[0].contains("unrardll.txt"), "{:?}", summary.errors);
}
