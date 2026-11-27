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

//! `extract::Options::unsupported_filters`: a RAR 3.x/4.x member whose data a VM program other than the standard
//! filters filters fails by default, and with `UnsupportedFilters::WriteUnfiltered` is written in full with that
//! program's blocks left as decoded, as 7-Zip 26.06 writes it ("ERROR: Unsupported Method", exit 2). The expected
//! outputs are 7-Zip 26.06's (Linux x86-64, `7z x`), checked by length and CRC-32 (SHA-256 in the comments).

use std::fs;
use std::path::{Path, PathBuf};
use zipfast::error::{RarFailure, RarUnsupported};
use zipfast::extract::{self, Mode, Options, Overwrite, RarOutcome, RarOutput, UnsupportedFilters};
use zipfast::rar5::session::{RarDecodeLimits, RarSession, RarSessionOptions};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
const MEMBER: &str = "itanium_synthetic_bundles.bin";
/// `7z x generic_delta_padding_mutation.rar` writes this member: 1 MiB, SHA-256
/// aff2543ca3d75b1837cf511c36a3e3e9df7719ed2846f479b650ca9e749e76c5 (`7z x -so` streams the same bytes).
const MEMBER_7Z: (usize, u32) = (1 << 20, 0x1b98_b701);

fn fixture() -> PathBuf {
    Path::new(FIXTURES).join("rar4-rar300/generic_delta_padding_mutation.rar")
}

fn options(dest: &Path, mode: Mode, filters: UnsupportedFilters) -> Options {
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
        unsupported_filters: filters,
        unverified_output: Default::default(),
        damaged_input: Default::default(),
        salvage_truncated_zip: false,
        seven_zip_strict: false,
        unix_modes: Default::default(),
        backslashes: Default::default(),
    }
}

/// What became of a member.
#[derive(Debug, PartialEq)]
enum Seen {
    /// verified and written
    Written,
    /// tested and verified
    Tested,
    /// `RarUnsupported::FilterWrittenUnfiltered`
    Unfiltered,
    /// `RarUnsupported::Rar4Feature`: refused as unsupported
    Refused,
    /// another failure
    Failed(String),
    Other(String),
}

fn seen(outcome: &RarOutcome) -> Seen {
    match outcome {
        RarOutcome::Verified { output: RarOutput::Written, .. } => Seen::Written,
        RarOutcome::Verified { output: RarOutput::Tested, .. } => Seen::Tested,
        RarOutcome::Failed(f) if matches!(**f, RarFailure::Unsupported(RarUnsupported::FilterWrittenUnfiltered)) => {
            Seen::Unfiltered
        }
        RarOutcome::Failed(f) if matches!(**f, RarFailure::Unsupported(RarUnsupported::Rar4Feature(_))) => {
            Seen::Refused
        }
        RarOutcome::Failed(f) => Seen::Failed(format!("{f:?}")),
        other => Seen::Other(format!("{other:?}")),
    }
}

fn digest(path: &Path) -> (usize, u32) {
    let data = fs::read(path).unwrap();
    (data.len(), zipfast::crc32::hash(&data))
}

/// The members of a whole-archive run, by name, with their outcomes.
fn run_outcomes(archive: &Path, opts: &Options) -> Vec<(String, Seen)> {
    let names = extract::list(archive).unwrap().into_iter().map(|e| e.name).collect::<Vec<_>>();
    let mut events = Vec::new();
    extract::run_rar_with_outcomes(archive, opts, None, |event| {
        events.push((names[event.entry.order as usize].clone(), seen(&event.outcome)));
    })
    .unwrap();
    events
}

/// The members of a `RarSession` extraction of every member, by name, with their outcomes.
fn session_outcomes(archive: &Path, opts: &Options) -> Vec<(String, Seen)> {
    let mut session = RarSession::open(archive, None, RarSessionOptions::default()).unwrap();
    let names = extract::list(archive).unwrap().into_iter().map(|e| e.name).collect::<Vec<_>>();
    let all = session.select(|_| true).unwrap();
    let mut events = Vec::new();
    session
        .extract_selected(&all, opts, RarDecodeLimits::default(), |event| {
            events.push((names[event.entry.order as usize].clone(), seen(&event.outcome)));
        })
        .unwrap();
    events
}

#[test]
fn by_default_the_member_fails_and_nothing_is_written() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("run");
    let summary = extract::run(&fixture(), &options(&out, Mode::Extract, Default::default()), |_| {}).unwrap();
    assert_eq!(summary.errors.len(), 1, "{:?}", summary.errors);
    assert!(summary.errors[0].contains("unsupported"), "{:?}", summary.errors);
    assert!(!out.join(MEMBER).exists());

    let out = dir.path().join("typed");
    let outcomes = run_outcomes(&fixture(), &options(&out, Mode::Extract, UnsupportedFilters::Fail));
    assert_eq!(outcomes, [(MEMBER.to_string(), Seen::Refused)]);
    assert!(!out.join(MEMBER).exists());

    let out = dir.path().join("session");
    let outcomes = session_outcomes(&fixture(), &options(&out, Mode::Extract, UnsupportedFilters::Fail));
    assert_eq!(outcomes, [(MEMBER.to_string(), Seen::Refused)]);
    assert!(!out.join(MEMBER).exists());
}

#[test]
fn write_unfiltered_writes_what_7zip_writes_and_reports_it() {
    let dir = tempfile::tempdir().unwrap();
    let opts = |out: &Path| options(out, Mode::Extract, UnsupportedFilters::WriteUnfiltered);

    let out = dir.path().join("run");
    let summary = extract::run(&fixture(), &opts(&out), |_| {}).unwrap();
    assert_eq!(summary.errors.len(), 1, "{:?}", summary.errors);
    assert!(summary.errors[0].contains("written unfiltered"), "{:?}", summary.errors);
    assert_eq!(digest(&out.join(MEMBER)), MEMBER_7Z);

    let out = dir.path().join("typed");
    let outcomes = run_outcomes(&fixture(), &opts(&out));
    assert_eq!(outcomes, [(MEMBER.to_string(), Seen::Unfiltered)]);
    assert_eq!(digest(&out.join(MEMBER)), MEMBER_7Z);
    // its time is set as a whole file's is
    let mtime = fs::metadata(out.join(MEMBER)).unwrap().modified().unwrap();
    assert!(mtime < std::time::SystemTime::now() - std::time::Duration::from_secs(3600));

    let out = dir.path().join("session");
    let outcomes = session_outcomes(&fixture(), &opts(&out));
    assert_eq!(outcomes, [(MEMBER.to_string(), Seen::Unfiltered)]);
    assert_eq!(digest(&out.join(MEMBER)), MEMBER_7Z);
}

#[test]
fn a_test_run_reports_the_member_without_writing_it() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("test");
    let outcomes = run_outcomes(&fixture(), &options(&out, Mode::Test, UnsupportedFilters::WriteUnfiltered));
    assert_eq!(outcomes, [(MEMBER.to_string(), Seen::Unfiltered)]);
    assert!(!out.join(MEMBER).exists());
}

/// `solid_e8_filter_member_offset.rar` (solid: `lead.txt`, then `tiny_e8e9.exe` through two filter records), with
/// one record's program changed so it is none of the standard filters (two bits flipped in its body, so its check
/// byte still holds) and a third member, `lead2.txt`, going on from the stream: `lead.txt`'s header renamed and
/// marked solid, and its packed data again. The program bytes end at the bit position the decoder reports after each
/// record: byte 115 less 4 bits and byte 177 less 6 bits of `tiny_e8e9.exe`'s packed data.
fn solid_case(record: usize, flips: &[usize]) -> Vec<u8> {
    let original = fs::read(Path::new(FIXTURES).join("rar4-rar300/solid_e8_filter_member_offset.rar")).unwrap();
    let mut data = original.clone();
    let (fetched, left) = [(115, 4), (177, 6)][record];
    for back in flips {
        let bit = fetched * 8 - left - back;
        data[181 + bit / 8] ^= 0x80 >> (bit % 8);
    }
    // lead.txt's header (20..60) and data (60..136), as lead2.txt, before the end block at 476
    let mut header = original[20..60].to_vec();
    let name_len = u16::from_le_bytes([header[26], header[27]]) as usize;
    header.splice(32..32 + name_len, *b"lead2.txt");
    header[26..28].copy_from_slice(&9u16.to_le_bytes());
    let flags = u16::from_le_bytes([header[3], header[4]]) | 0x10;
    header[3..5].copy_from_slice(&flags.to_le_bytes());
    let size = header.len() as u16;
    header[5..7].copy_from_slice(&size.to_le_bytes());
    let crc = zipfast::crc32::hash(&header[2..]) as u16;
    header[..2].copy_from_slice(&crc.to_le_bytes());
    [&data[..476], &header, &original[60..136], &data[476..]].concat()
}

/// 7-Zip 26.06 on [`solid_case`]: "ERROR: Unsupported Method : tiny_e8e9.exe", exit 2, `lead.txt` and `lead2.txt`
/// whole and `tiny_e8e9.exe` with the changed record's block unfiltered (the other filter still applied):
/// SHA-256 ad8c8905d12e3020c96f1a3480ec07398572481297a1349a271f07b39bccaf34 for the first record changed,
/// 957fbdc7391f2b1d402a4880f48bd437c9907a6a90c77a755de890526ae29880 for the second.
#[test]
fn a_solid_stream_goes_on_past_a_member_written_unfiltered() {
    const LEAD: (usize, u32) = (800, 0x93b3_7d98);
    let dir = tempfile::tempdir().unwrap();
    for (record, exe) in [(0, (5884, 0x507a_ca8a)), (1, (5884, 0x830a_bbaf))] {
        let archive = dir.path().join(format!("solid{record}.rar"));
        fs::write(&archive, solid_case(record, &[8, 16])).unwrap();
        for route in ["typed", "session"] {
            let out = dir.path().join(format!("{route}{record}"));
            let opts = options(&out, Mode::Extract, UnsupportedFilters::WriteUnfiltered);
            let outcomes =
                if route == "typed" { run_outcomes(&archive, &opts) } else { session_outcomes(&archive, &opts) };
            let expected =
                [("lead.txt", Seen::Written), ("tiny_e8e9.exe", Seen::Unfiltered), ("lead2.txt", Seen::Written)];
            assert_eq!(outcomes, expected.map(|(name, seen)| (name.to_string(), seen)), "{route} {record}");
            assert_eq!(digest(&out.join("lead.txt")), LEAD);
            assert_eq!(digest(&out.join("lead2.txt")), LEAD, "{route} {record}: the stream goes on");
            assert_eq!(digest(&out.join("tiny_e8e9.exe")), exe, "{route} {record}");

            // by default the member fails, and the stream with it, as before
            let out = dir.path().join(format!("{route}{record}-fail"));
            let opts = options(&out, Mode::Extract, UnsupportedFilters::Fail);
            let outcomes =
                if route == "typed" { run_outcomes(&archive, &opts) } else { session_outcomes(&archive, &opts) };
            assert_eq!(outcomes[1].1, Seen::Refused, "{route} {record}");
            assert!(matches!(outcomes[2].1, Seen::Failed(_)), "{route} {record}: {outcomes:?}");
            assert!(!out.join("tiny_e8e9.exe").exists() && !out.join("lead2.txt").exists());
        }
    }
}

/// A program whose check byte (the XOR of the rest) doesn't hold is damaged data, which 7-Zip 26.06 reports as
/// "Data Error" (the file empty, `lead2.txt` failing with the stream): never written unfiltered.
#[test]
fn a_program_failing_its_check_byte_is_never_written_unfiltered() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("damaged.rar");
    fs::write(&archive, solid_case(0, &[8])).unwrap();
    for route in ["typed", "session"] {
        let out = dir.path().join(route);
        let opts = options(&out, Mode::Extract, UnsupportedFilters::WriteUnfiltered);
        let outcomes = if route == "typed" { run_outcomes(&archive, &opts) } else { session_outcomes(&archive, &opts) };
        assert!(matches!(outcomes[1].1, Seen::Failed(_)), "{route}: {outcomes:?}");
        assert!(matches!(outcomes[2].1, Seen::Failed(_)), "{route}: {outcomes:?}");
        assert!(!out.join("tiny_e8e9.exe").exists() && !out.join("lead2.txt").exists());
    }
}

/// Codex on #317: a `SelectedEntry` read with `UnverifiedOutput::Emit` goes on past a solid prerequisite written
/// unfiltered (its filters act on its output, never on the history), so a later member reads whole; the member
/// itself reads unfiltered and fails as written so.
#[test]
fn a_selected_read_goes_on_past_a_prerequisite_written_unfiltered() {
    use zipfast::extract::{Cancellation, SelectOptions, SelectedEntry, UnverifiedOutput, UnverifiedWritten};
    const LEAD: (usize, u32) = (800, 0x93b3_7d98);
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("solid.rar");
    fs::write(&archive, solid_case(0, &[8, 16])).unwrap();
    let read = |index: usize| {
        let select = SelectOptions::new().unverified_output(UnverifiedOutput::Emit);
        let entry = SelectedEntry::open_cancelable_with_options(
            &archive,
            index,
            None,
            1 << 20,
            Cancellation::default(),
            select,
        )
        .unwrap();
        let mut got = Vec::new();
        let result = entry.read(None, |chunk| {
            got.extend_from_slice(chunk);
            Ok(())
        });
        (got, result)
    };
    let (lead2, result) = read(2);
    result.expect("lead2.txt reads whole");
    assert_eq!((lead2.len(), zipfast::crc32::hash(&lead2)), LEAD);
    let (exe, result) = read(1);
    let error = result.unwrap_err();
    assert_eq!(UnverifiedWritten::of(&error).map(|s| s.bytes), Some(exe.len() as u64), "{error}");
    assert_eq!((exe.len(), zipfast::crc32::hash(&exe)), (5884, 0x507a_ca8a));
}
