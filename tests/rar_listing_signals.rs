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
use zipfast::extract::{self, DamagedInput, HeaderDamageKind, Mode, Options, Overwrite};
use zipfast::rar5::HeaderCut;
use zipfast::rar5::session::{RarDecodeLimits, RarSession, RarSessionOptions};

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
    // kept with keep_broken, as UnRAR -kb keeps what it decoded
    let opts = Options { keep_broken: true, ..options(&case.out, Mode::Extract, DamagedInput::Salvage) };
    let summary = extract::run(&case.archive, &opts, |_| {}).unwrap();
    assert_eq!(summary.errors.len(), 1);
    assert_eq!(written(&case), ["README.md"]);
}

/// latest_winrar.rar cut 50 bytes into 1.txt's 17 packed bytes... at 70, 8 bytes in: UnRAR 7.30 decodes 1.txt from
/// them, its CRC passes, and it reports it OK (with "Unexpected end of archive"). So does `Salvage`: the member's own
/// checks decide.
#[test]
fn salvage_extracts_a_cut_member_whose_checks_pass_as_unrar_does() {
    let bytes = fixture("rar4/latest_winrar.rar");
    let case = case(&bytes[..70]);
    let opts = options(&case.out, Mode::Extract, DamagedInput::Salvage);
    let summary = extract::run(&case.archive, &opts, |_| {}).unwrap();
    assert!(summary.errors.is_empty(), "{:?}", summary.errors);
    assert_eq!(fs::read(case.out.join("1.txt")).unwrap().len(), 5);
    assert_eq!(summary.damaged_headers[0].cut, Some(HeaderCut::Data { present: 8 }));
    // the session decodes it from the bytes there too, not the declared packed size
    let mut session = session(&case, DamagedInput::Salvage).unwrap();
    let selected = session.select(|_| true).unwrap();
    let out = case.dir.path().join("session");
    let opts = options(&out, Mode::Extract, DamagedInput::Salvage);
    let summary = session.extract_selected(&selected, &opts, RarDecodeLimits::default(), |_| {}).unwrap();
    assert_eq!((summary.files, summary.failed), (1, 0));
    assert_eq!(fs::read(out.join("1.txt")).unwrap().len(), 5);
    // with no data bytes at all it fails
    let case = self::case(&bytes[..62]);
    let opts = options(&case.out, Mode::Extract, DamagedInput::Salvage);
    let summary = extract::run(&case.archive, &opts, |_| {}).unwrap();
    assert_eq!(summary.errors.len(), 1);
    assert!(written(&case).is_empty());
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
