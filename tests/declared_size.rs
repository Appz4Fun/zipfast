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

//! A member whose header declares fewer bytes than its data gives: what `Options::keep_broken` keeps of it and what
//! `UnverifiedOutput::Emit` hands over. UnRAR 7.30 (`x -kb`, `p`) and 7-Zip 26.06 (`x`, `x -so`) all stop at the
//! declared size, for RAR 5.0 and RAR 4.x (stored, LZ, PPMd), 7z (Copy, LZMA, LZMA2) and ZIP (stored, Deflate). The
//! expected bytes are theirs, recorded in `tests/fixtures/declared-size/README.md`.

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use common::FileSpec;
use zipfast::extract::{
    self, Cancellation, Mode, Options, Overwrite, SelectOptions, SelectedEntry, UnverifiedOutput, UnverifiedWritten,
};
use zipfast::rar5::session::{RarDecodeLimits, RarPrintOptions, RarSession, RarSessionOptions};
use zipfast::sevenzip::{self, SevenZipLimits, SevenZipPrintOptions};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/declared-size");

/// One byte, `00`.
const ONE: (usize, &str) = (1, "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d");
/// The first 1,000 bytes of `words.txt`.
const WORDS: (usize, &str) = (1000, "58ae25d10a75cb43c0d645b1880b514b358f98094f4caec7066f55bc015dbdc5");

struct Case {
    archive: &'static str,
    member: &'static str,
    /// what every reference mode writes
    want: (usize, &'static str),
}

const RAR: &[Case] = &[
    Case { archive: "r5-stored.rar", member: "big.bin", want: ONE },
    Case { archive: "r4-stored.rar", member: "big.bin", want: ONE },
    Case { archive: "r5-lz.rar", member: "words.txt", want: WORDS },
    Case {
        archive: "r4-lz.rar",
        member: "tese.txt",
        want: (100, "214bd299a2fc79f8a863416ff0707eb9c655c7ed7240c7e7e3052ffb91efba05"),
    },
    Case {
        archive: "r4-ppmd.rar",
        member: "solid_lorem_a.txt",
        want: (1000, "9c458d03f8c918bb7b3061480b274e269383da10dc4b430593afd305db8c936e"),
    },
];

const SEVEN_ZIP: &[Case] = &[
    Case { archive: "7z-copy.7z", member: "part.txt", want: WORDS },
    Case { archive: "7z-lzma.7z", member: "part.txt", want: WORDS },
    Case { archive: "7z-lzma2.7z", member: "part.txt", want: WORDS },
];

const ZIP: &[Case] = &[
    Case { archive: "zip-stored.zip", member: "big.bin", want: ONE },
    Case { archive: "zip-deflate.zip", member: "words.txt", want: WORDS },
];

fn all() -> impl Iterator<Item = &'static Case> {
    RAR.iter().chain(SEVEN_ZIP).chain(ZIP)
}

fn fixture(name: &str) -> PathBuf {
    Path::new(FIXTURES).join(name)
}

fn sha256(bytes: &[u8]) -> String {
    zipfast::crypto::sha256(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

fn assert_reference(got: &[u8], (len, sha): (usize, &str), what: &str) {
    assert_eq!(got.len(), len, "{what}: length");
    assert_eq!(sha256(got), sha, "{what}: bytes");
}

fn options(dest: &Path, keep: bool, unverified: UnverifiedOutput, threads: usize) -> Options {
    Options {
        mode: Mode::Extract,
        dest: dest.to_path_buf(),
        overwrite: Overwrite::Always,
        flatten: false,
        threads: Some(threads),
        protected_paths: Default::default(),
        // with more than one thread, every compressed block goes to a decode worker
        parallel_min: (threads > 1).then_some(0),
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
        unverified_output: unverified,
        salvage_truncated_zip: false,
        unix_modes: Default::default(),
        backslashes: Default::default(),
    }
}

/// Runs the whole-archive runner over `path` and returns what it left of `member` (None when nothing).
fn run(path: &Path, member: &str, keep: bool, unverified: UnverifiedOutput, threads: usize) -> Option<Vec<u8>> {
    let dir = tempfile::tempdir().unwrap();
    let summary = extract::run(path, &options(dir.path(), keep, unverified, threads), |_| {}).unwrap();
    assert!(!summary.errors.is_empty(), "{}: the member still fails", path.display());
    fs::read(dir.path().join(member)).ok()
}

/// `unrar x -kb` and `7z x`: the kept file stops at the declared size, whichever imitation (`Emit` for UnRAR,
/// `Withhold` for 7-Zip) and on the calling thread or decode workers alike. Without `keep_broken` nothing is left.
#[test]
fn whole_archive_runs_keep_a_member_to_its_declared_size() {
    for case in all() {
        for threads in [1, 4] {
            for unverified in [UnverifiedOutput::Emit, UnverifiedOutput::Withhold] {
                let what = format!("{} {threads} {unverified:?}", case.archive);
                let kept = run(&fixture(case.archive), case.member, true, unverified, threads);
                assert_reference(&kept.unwrap_or_else(|| panic!("{what}: kept")), case.want, &what);
                assert_eq!(run(&fixture(case.archive), case.member, false, unverified, threads), None, "{what}");
            }
        }
    }
}

/// The checked ZIP route (`extract::run_with_policy`) keeps a ZIP member to its declared size too.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn the_checked_zip_route_keeps_a_member_to_its_declared_size() {
    for case in ZIP {
        for keep in [true, false] {
            let what = format!("{} {keep}", case.archive);
            let dir = tempfile::tempdir().unwrap();
            let report = extract::run_with_policy(
                &fixture(case.archive),
                &options(dir.path(), keep, UnverifiedOutput::Withhold, 1),
                None,
                &Cancellation::default(),
                &Default::default(),
                |_: extract::RunEvent<'_>| Ok(()),
            )
            .unwrap();
            assert_eq!(report.failed(), 1, "{what}");
            let kept = fs::read(dir.path().join(case.member)).ok();
            if keep {
                assert_reference(&kept.unwrap_or_else(|| panic!("{what}: kept")), case.want, &what);
            } else {
                assert_eq!(kept, None, "{what}");
            }
        }
    }
}

/// The case Prybar met: a stored RAR 5.0 member declaring 1 byte and carrying 5,000,000 is kept at 1 byte, not at
/// what its data gives.
#[test]
fn a_large_stored_member_is_kept_to_its_declared_size() {
    let data: Vec<u8> = (0..5_000_000u32).map(|i| (i.wrapping_mul(7) ^ (i >> 9)) as u8).collect();
    let mut spec = FileSpec::new("big.bin", &data);
    spec.size = Some(1);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.rar");
    fs::write(&path, common::archive(&[spec])).unwrap();
    for threads in [1, 4] {
        for unverified in [UnverifiedOutput::Emit, UnverifiedOutput::Withhold] {
            let what = format!("{threads} {unverified:?}");
            let kept = run(&path, "big.bin", true, unverified, threads).expect("kept");
            assert_eq!(kept, data[..1], "{what}");
        }
    }
    let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    let all = session.select(|_| true).unwrap();
    let options = RarPrintOptions { unverified_output: UnverifiedOutput::Emit, ..RarPrintOptions::default() };
    let mut output = Vec::new();
    session.print_selected(&all, &mut output, &options, |_| {}).unwrap();
    assert_eq!(output, data[..1], "printed");
}

/// `unrar p`: `RarSession::print_selected` under `Emit` prints the member to its declared size and reports that
/// many bytes unverified; by default it prints nothing of it.
#[test]
fn rar_session_print_stops_at_the_declared_size() {
    for case in RAR {
        for unverified in [UnverifiedOutput::Emit, UnverifiedOutput::Withhold] {
            let what = format!("{} {unverified:?}", case.archive);
            let mut session = RarSession::open(&fixture(case.archive), None, RarSessionOptions::default()).unwrap();
            let all = session.select(|_| true).unwrap();
            let options = RarPrintOptions { unverified_output: unverified, ..RarPrintOptions::default() };
            let mut output = Vec::new();
            let mut unverified_bytes = Vec::new();
            let summary = session
                .print_selected(&all, &mut output, &options, |event| unverified_bytes.push(event.unverified_bytes))
                .unwrap();
            assert_eq!(summary.failed, 1, "{what}");
            if unverified == UnverifiedOutput::Emit {
                assert_reference(&output, case.want, &what);
                assert_eq!(unverified_bytes, [Some(case.want.0 as u64)], "{what}");
            } else {
                assert!(output.is_empty(), "{what}");
                assert_eq!(unverified_bytes, [None], "{what}");
            }
        }
    }
}

/// `unrar x -kb` through `RarSession::extract_selected`: the kept file stops at the declared size.
#[test]
fn rar_session_extraction_keeps_a_member_to_its_declared_size() {
    for case in RAR {
        for threads in [1, 4] {
            let what = format!("{} {threads}", case.archive);
            let dir = tempfile::tempdir().unwrap();
            let mut session = RarSession::open(&fixture(case.archive), None, RarSessionOptions::default()).unwrap();
            let all = session.select(|_| true).unwrap();
            let opts = options(dir.path(), true, UnverifiedOutput::Emit, threads);
            let summary = session.extract_selected(&all, &opts, RarDecodeLimits::default(), |_| {}).unwrap();
            assert_eq!(summary.failed, 1, "{what}");
            let kept = fs::read(dir.path().join(case.member)).unwrap_or_else(|e| panic!("{what}: {e}"));
            assert_reference(&kept, case.want, &what);
        }
    }
}

/// `7z x -so` through `SelectedEntry` under `Emit`: the sink gets the member to its declared size and the read fails
/// with an `UnverifiedWritten` saying that many bytes. By default the read fails without one, as before.
#[test]
fn selected_entry_streams_a_member_to_its_declared_size() {
    for case in all() {
        for unverified in [UnverifiedOutput::Emit, UnverifiedOutput::Withhold] {
            let what = format!("{} {unverified:?}", case.archive);
            let select = SelectOptions::new().unverified_output(unverified);
            let entry = SelectedEntry::open_cancelable_with_options(
                &fixture(case.archive),
                0,
                None,
                1 << 20,
                Cancellation::default(),
                select,
            )
            .unwrap_or_else(|e| panic!("{what}: {e}"));
            let mut got = Vec::new();
            let error = entry
                .read(None, |chunk| {
                    got.extend_from_slice(chunk);
                    Ok(())
                })
                .unwrap_err();
            let sign = UnverifiedWritten::of(&error);
            if unverified == UnverifiedOutput::Emit {
                assert_reference(&got, case.want, &what);
                assert_eq!(sign.map(|s| s.bytes), Some(case.want.0 as u64), "{what}: {error}");
            } else {
                assert!(sign.is_none(), "{what}: {error}");
            }
        }
    }
}

/// `7z x -so` through `sevenzip::print_selected_with_options` under `Emit`.
#[test]
fn seven_zip_print_streams_a_member_to_its_declared_size() {
    for case in SEVEN_ZIP {
        let mut output = Vec::new();
        let summary = sevenzip::print_selected_with_options(
            &fixture(case.archive),
            None,
            &mut |_, _| true,
            &mut |_, bytes| {
                output.extend_from_slice(bytes);
                Ok(())
            },
            &Cancellation::default(),
            &SevenZipLimits::default(),
            &SevenZipPrintOptions::new().unverified_output(UnverifiedOutput::Emit),
        )
        .unwrap();
        assert_reference(&output, case.want, case.archive);
        assert!(!summary.errors.is_empty(), "{}: still failed", case.archive);
    }
}
