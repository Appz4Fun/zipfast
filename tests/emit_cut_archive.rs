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

//! An archive cut short inside a member's data ("Unexpected end of archive"), catalogued under
//! `DamagedInput::Salvage`: with `UnverifiedOutput::Emit`, `RarSession` prints (`unrar p`) and keeps (`unrar x -kb`)
//! the members before the cut and what UnRAR 7.30 decodes of the member cut short, which is reported failed as
//! truncated, and so does the whole-archive runner (`extract::run`, `unrar x -kb`). See
//! `tests/fixtures/emit-cut-archive/README.md`.

use std::fs;
use std::path::{Path, PathBuf};

use zipfast::error::{RarFailure, RarIntegrityReason};
use zipfast::extract::{DamagedInput, Mode, Options, Overwrite, RarOutcome, UnverifiedOutput};
use zipfast::rar5::session::{RarDecodeLimits, RarPrintOptions, RarSession, RarSessionOptions};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn sha256(bytes: &[u8]) -> String {
    zipfast::crypto::sha256(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// An archive, where it is cut, and what `unrar p` prints of the cut archive (length and SHA-256).
struct Cut {
    archive: &'static str,
    at: usize,
    unrar: (usize, &'static str),
}

const fn cut(archive: &'static str, at: usize, len: usize, sha: &'static str) -> Cut {
    Cut { archive, at, unrar: (len, sha) }
}

const PPMD: &str = "rar4-rar300/ppmd_solid_rar300.rar";
const R4_STORED: &str = "emit-cut-archive/r4-stored.rar";
const R5_STORED: &str = "emit-cut-archive/r5-stored.rar";
const R5_LZ: &str = "emit-cut-archive/r5-lz.rar";

const CUTS: &[Cut] = &[
    // RAR 2.9 LZ, solid: the second member is cut short
    cut("rar4/solid.rar", 1518, 3357, "a547aa308e6c44eba5a36ed01d31c88ef52f1969995e5e431ca7fe9a2435c049"),
    cut("rar4/solid.rar", 1530, 3379, "1e606cbc3098b49d2c3c1e6de4b21c3b57cd89eb5badd29ccebcb20fe60d1eb5"),
    cut("rar4/solid.rar", 1545, 3488, "0991c60379ca3468df1fb4e4f8afe75622be577fec9ffa74943d9d525dc3a3b2"),
    cut("rar4/solid.rar", 3036, 10494, "559bb42632a27116c413469e7f69b836e64392fbfac81974f87fda5a8a876ce5"),
    cut("rar4/solid.rar", 4554, 17499, "17dd9eb56b181800dbb4f5398b2bb35413fceca80908642d7b2c3b3c9b97fe1d"),
    // RAR 2.9 PPMd, solid
    cut(PPMD, 5977, 55716, "0721bbace134903d9a786b3fc74a2d5c4fe20ce31d66d0eb13fc5280c58095ef"),
    cut(PPMD, 5985, 55796, "9b0b01e4e6a810876d3d136a5e2a860715ba11372f2192d172f9234a2cf8b172"),
    cut(PPMD, 11955, 116192, "d2ea62452ab70337995d11b004ab3e9c8664ed2a6f16d1d4f8b0302111003b10"),
    cut(PPMD, 17932, 176566, "72fb2f3808636c69e6fa95358e8f74c667708d709befd03371ef43d1ea959681"),
    // RAR 2.0 LZ
    cut("rar4-legacy/BIGLZ.RAR", 1337, 9466, "71ba67ca0c5f1c547a3e4669e030dd920c07059ea5bf2eefb04f6fd92dd2b136"),
    cut("rar4-legacy/BIGLZ.RAR", 2675, 74207, "27308609d986acb27d2df8a8ce080d7af13eb521578a5d79fcd1c183729eb275"),
    cut("rar4-legacy/BIGLZ.RAR", 4013, 144399, "a6561e8a2e2ece668991c7f2fbb2c41900015ff72d4d1e18c8f461ae2b95b9b0"),
    // stored
    cut(R4_STORED, 18019, 17960, "a30930b94adfe93811c4074f7ce2daf1f39743ebec98978ca77b7e59433293cc"),
    cut(R5_STORED, 18015, 17970, "f3ed3905d782815302a69e76e31c66acebb084e37eb01bd17c33157c715b9511"),
    cut(R5_STORED, 36031, 35986, "7847bd188f6a6ea20a3faf8743a3de3b9582a4f81db114c87574afb73318144e"),
    // RAR 5.0 LZ: the first three end inside the first block, short of 1,024 bytes of it
    cut(R5_LZ, 200, 72, "3e4deb303b762b0b4489a6f01fdc9f19351bff7a69287d3d4b17fca59661af08"),
    cut(R5_LZ, 400, 861, "5d57284ca2ff2bab94bc48780d86f9bbe2d915860f8b85fb0683b612d1600914"),
    cut(R5_LZ, 700, 2483, "a471565bf8bda58e93f8811c7eb05990b2c5d15c6cbf34f28aea4069bd9ebdd3"),
    cut(R5_LZ, 10002, 63402, "eed72168af4b8582609bb62a3c27505b4635cf2501f82e9e5cab91ddf726a58b"),
    cut(R5_LZ, 10018, 63501, "3d58f3c8fbcb35944116d624b58687bef0a078dbf75ba5be27629dacf9096727"),
    cut(R5_LZ, 20003, 129516, "42f96607a014771d88b46c60f25170a2d68627c2ad1e091e247b8713f337e380"),
];

/// The first `at` bytes of the archive, in a directory of their own.
fn cut_archive(dir: &Path, case: &Cut) -> PathBuf {
    let bytes = fs::read(Path::new(FIXTURES).join(case.archive)).unwrap();
    let path = dir.join(format!("{}-{}", case.at, Path::new(case.archive).file_name().unwrap().to_string_lossy()));
    fs::write(&path, &bytes[..case.at]).unwrap();
    path
}

fn salvaging() -> RarSessionOptions {
    RarSessionOptions { damaged_input: DamagedInput::Salvage, ..RarSessionOptions::default() }
}

fn truncated(failure: &RarFailure) -> bool {
    matches!(failure, RarFailure::Integrity { reason: RarIntegrityReason::TruncatedData, .. })
}

fn options(dest: &Path, unverified: UnverifiedOutput) -> Options {
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
        keep_broken: true,
        attempt_continued_members: false,
        encrypted_links: Default::default(),
        damaged_input: DamagedInput::Salvage,
        unsupported_filters: Default::default(),
        unverified_output: unverified,
        salvage_truncated_zip: false,
        seven_zip_strict: false,
        unix_modes: Default::default(),
        backslashes: Default::default(),
        hard_link_targets: Default::default(),
    }
}

/// `unrar p`: the members before the cut, then what UnRAR prints of the one cut short, reported failed as truncated
/// with its bytes counted unverified. `Withhold` prints only the members before it. By default the archive doesn't
/// open, as before.
#[test]
fn rar_session_print_prints_what_unrar_prints_of_an_archive_cut_short() {
    let dir = tempfile::tempdir().unwrap();
    for case in CUTS {
        let archive = cut_archive(dir.path(), case);
        assert!(RarSession::open(&archive, None, RarSessionOptions::default()).is_err(), "{}", case.archive);
        let mut whole = (Vec::new(), None);
        for unverified in [UnverifiedOutput::Emit, UnverifiedOutput::Withhold] {
            let what = format!("{}@{} {unverified:?}", case.archive, case.at);
            let mut session = RarSession::open(&archive, None, salvaging()).unwrap();
            let all = session.select(|_| true).unwrap();
            let options = RarPrintOptions { unverified_output: unverified, ..RarPrintOptions::default() };
            let mut output = Vec::new();
            let mut failed = Vec::new();
            session
                .print_selected(&all, &mut output, &options, |event| {
                    if let RarOutcome::Failed(failure) = &event.outcome {
                        failed.push((truncated(failure), event.unverified_bytes));
                    }
                })
                .unwrap();
            let [(truncated, unverified_bytes)] = failed[..] else { panic!("{what}: {failed:?}") };
            assert!(truncated, "{what}");
            if unverified == UnverifiedOutput::Emit {
                assert_eq!(output.len(), case.unrar.0, "{what}: length");
                assert_eq!(sha256(&output), case.unrar.1, "{what}: bytes");
                whole = (output, unverified_bytes);
            } else {
                // the members before it, and the rest went out unverified with Emit
                assert!(whole.0.starts_with(&output), "{what}: the members before it");
                assert_eq!(whole.1, Some((whole.0.len() - output.len()) as u64), "{what}: unverified with Emit");
                assert_eq!(unverified_bytes, None, "{what}");
            }
        }
    }
}

/// `unrar x -kb` through `RarSession::extract_selected` with `keep_broken`: the members' files, in the archive's
/// order, hold what `unrar p` prints. With `Withhold` too: a member an archive cut short ends inside of is always
/// decoded as UnRAR decodes it (its checks decide on those bytes), and `keep_broken` keeps it as written.
#[test]
fn rar_session_extraction_keeps_what_unrar_decodes_of_an_archive_cut_short() {
    let dir = tempfile::tempdir().unwrap();
    for case in CUTS {
        let archive = cut_archive(dir.path(), case);
        for unverified in [UnverifiedOutput::Emit, UnverifiedOutput::Withhold] {
            let what = format!("{}@{} {unverified:?}", case.archive, case.at);
            let out = dir.path().join(format!("out-{}-{unverified:?}", archive.file_name().unwrap().to_string_lossy()));
            fs::create_dir_all(&out).unwrap();
            let mut session = RarSession::open(&archive, None, salvaging()).unwrap();
            let names: Vec<String> = session.entries().map(|member| member.name().to_owned()).collect();
            let all = session.select(|_| true).unwrap();
            let summary =
                session.extract_selected(&all, &options(&out, unverified), RarDecodeLimits::default(), |_| {}).unwrap();
            assert_eq!(summary.failed, 1, "{what}");
            let (cut_short, before) = names.split_last().unwrap();
            let mut kept: Vec<u8> = before.iter().flat_map(|name| fs::read(out.join(name)).unwrap()).collect();
            let last = fs::read(out.join(cut_short));
            kept.extend(last.unwrap_or_else(|e| panic!("{what}: {e}")));
            assert_eq!(kept.len(), case.unrar.0, "{what}: length");
            assert_eq!(sha256(&kept), case.unrar.1, "{what}: bytes");
        }
    }
}

/// The member files `extract::run` leaves in `out`, in the order `names` gives, joined.
fn joined(out: &Path, names: &[String]) -> Vec<u8> {
    names.iter().flat_map(|name| fs::read(out.join(name)).unwrap_or_default()).collect()
}

/// `unrar x -kb` through the whole-archive runner (`extract::run`, `Salvage`, `keep_broken`, `Emit`), on one thread
/// and on several: the member cut short fails, and the files hold what `unrar p` prints, as the session keeps them.
/// `Withhold` keeps the same: the member is decoded as UnRAR decodes it whatever, its checks deciding on that.
#[test]
fn whole_archive_run_keeps_what_unrar_decodes_of_an_archive_cut_short() {
    let dir = tempfile::tempdir().unwrap();
    for case in CUTS {
        let archive = cut_archive(dir.path(), case);
        let names: Vec<String> = RarSession::open(&archive, None, salvaging())
            .unwrap()
            .entries()
            .map(|member| member.name().to_owned())
            .collect();
        for unverified in [UnverifiedOutput::Emit, UnverifiedOutput::Withhold] {
            for threads in [1, 4] {
                let what = format!("{}@{} {unverified:?} threads {threads}", case.archive, case.at);
                let out = dir.path().join(format!("run-{}-{unverified:?}-{threads}", case.at));
                let options = Options { threads: Some(threads), ..options(&out, unverified) };
                let summary = zipfast::extract::run(&archive, &options, |_| {}).unwrap();
                assert_eq!(summary.errors.len(), 1, "{what}: {:?}", summary.errors);
                assert!(summary.errors[0].contains(names.last().unwrap().as_str()), "{what}: {:?}", summary.errors);
                let kept = joined(&out, &names);
                assert_eq!(kept.len(), case.unrar.0, "{what}: length");
                assert_eq!(sha256(&kept), case.unrar.1, "{what}: bytes");
                if threads == 1 {
                    // the session keeps the same
                    let session_out = dir.path().join(format!("session-{}-{threads}", case.at));
                    let mut session = RarSession::open(&archive, None, salvaging()).unwrap();
                    let all = session.select(|_| true).unwrap();
                    session
                        .extract_selected(&all, &options_at(&session_out, &options), Default::default(), |_| {})
                        .unwrap();
                    assert_eq!(joined(&session_out, &names), kept, "{what}: the session keeps the same");
                }
            }
        }
        // without keep_broken the member cut short is removed, as `unrar x` removes it
        let out = dir.path().join(format!("plain-{}", case.at));
        let options = Options { keep_broken: false, ..options(&out, UnverifiedOutput::Emit) };
        let summary = zipfast::extract::run(&archive, &options, |_| {}).unwrap();
        assert_eq!(summary.errors.len(), 1, "{}@{}", case.archive, case.at);
        assert!(!out.join(names.last().unwrap()).exists(), "{}@{}", case.archive, case.at);
    }
}

fn options_at(dest: &Path, options: &Options) -> Options {
    Options { dest: dest.to_path_buf(), ..options.clone() }
}

/// The first volume of `rar5-threads/big` cut 70,000 bytes in, inside `a.txt`, its later volumes there: `unrar x -kb`
/// keeps 930,710 bytes of `a.txt` (what `unrar p` prints of it) and extracts `s.txt` from the last volume; the part of
/// `a.txt` in the second volume continues nothing. So does the runner, under `Emit` and `Withhold` alike.
#[test]
fn whole_archive_run_does_not_continue_a_member_cut_short_from_the_next_volume() {
    let dir = tempfile::tempdir().unwrap();
    let set = Path::new(FIXTURES).join("rar5-threads");
    let first = dir.path().join("big.part01.rar");
    fs::write(&first, &fs::read(set.join("big.part01.rar")).unwrap()[..70_000]).unwrap();
    for later in ["big.part02.rar", "big.part03.rar"] {
        fs::copy(set.join(later), dir.path().join(later)).unwrap();
    }
    for unverified in [UnverifiedOutput::Emit, UnverifiedOutput::Withhold] {
        for threads in [1, 4] {
            let what = format!("{unverified:?} threads {threads}");
            let out = dir.path().join(format!("out-{unverified:?}-{threads}"));
            let options = Options { threads: Some(threads), ..options(&out, unverified) };
            let summary = zipfast::extract::run(&first, &options, |_| {}).unwrap();
            assert!(summary.errors.iter().any(|error| error.contains("a.txt")), "{what}: {:?}", summary.errors);
            assert_eq!(fs::read(out.join("s.txt")).unwrap(), b"small\n", "{what}");
            let a = fs::read(out.join("a.txt")).unwrap();
            let mut printed = a.clone();
            printed.extend_from_slice(b"small\n");
            assert_eq!(a.len(), 930_710, "{what}");
            assert_eq!(sha256(&printed), "41cf0cc0b9c6a62ca032a319c7eb30115240e95775c4bbe4ddf858b628cee6ae", "{what}");
        }
    }
}

/// A first volume cut short inside a member split into the next volume, with the later volumes there: UnRAR 7.30
/// prints what it decodes of `a.txt` up to the cut and goes on to the members of the later volumes (`unrar p`: 930,716
/// bytes, `s.txt` the last 6), and so does the session. The continuation of `a.txt` in the second volume isn't joined
/// to the member cut short (that would give the bytes after a gap as the ones after the cut).
#[test]
fn a_member_cut_short_is_not_continued_from_the_next_volume() {
    let dir = tempfile::tempdir().unwrap();
    let set = Path::new(FIXTURES).join("rar5-threads");
    let first = dir.path().join("big.part01.rar");
    fs::write(&first, &fs::read(set.join("big.part01.rar")).unwrap()[..70_000]).unwrap();
    for later in ["big.part02.rar", "big.part03.rar"] {
        fs::copy(set.join(later), dir.path().join(later)).unwrap();
    }
    let mut session = RarSession::open(&first, None, salvaging()).unwrap();
    let all = session.select(|_| true).unwrap();
    let options = RarPrintOptions { unverified_output: UnverifiedOutput::Emit, ..RarPrintOptions::default() };
    let mut output = Vec::new();
    let mut failures = Vec::new();
    session
        .print_selected(&all, &mut output, &options, |event| {
            if let RarOutcome::Failed(failure) = &event.outcome {
                failures.push(truncated(failure));
            }
        })
        .unwrap();
    assert!(failures.first() == Some(&true), "a.txt fails as truncated: {failures:?}");
    assert_eq!(output.len(), 930_716);
    assert_eq!(sha256(&output), "41cf0cc0b9c6a62ca032a319c7eb30115240e95775c4bbe4ddf858b628cee6ae");
}

/// The second volume of `rar5-threads/big` cut 70,000 bytes in, inside the part of `a.txt` it continues: `unrar x -kb`
/// keeps 2,950,048 bytes of `a.txt` (what `unrar p` prints; its last bytes are where a RAR 5.0 symbol straddling the
/// end decodes differently from zeros). The runner keeps that many, the same bytes on one thread and on several (where
/// the first volume's part goes to the workers before the cut is known), and the same as the session prints.
#[test]
fn whole_archive_run_keeps_what_unrar_decodes_of_a_continuation_cut_short() {
    let dir = tempfile::tempdir().unwrap();
    let set = Path::new(FIXTURES).join("rar5-threads");
    let first = dir.path().join("big.part01.rar");
    fs::copy(set.join("big.part01.rar"), &first).unwrap();
    fs::write(dir.path().join("big.part02.rar"), &fs::read(set.join("big.part02.rar")).unwrap()[..70_000]).unwrap();
    let mut session = RarSession::open(&first, None, salvaging()).unwrap();
    let all = session.select(|_| true).unwrap();
    let print = RarPrintOptions { unverified_output: UnverifiedOutput::Emit, ..RarPrintOptions::default() };
    let mut printed = Vec::new();
    session.print_selected(&all, &mut printed, &print, |_| {}).unwrap();
    assert_eq!(printed.len(), 2_950_048);
    for unverified in [UnverifiedOutput::Emit, UnverifiedOutput::Withhold] {
        for threads in [1, 4] {
            let what = format!("{unverified:?} threads {threads}");
            let out = dir.path().join(format!("out-{unverified:?}-{threads}"));
            let options = Options { threads: Some(threads), parallel_min: Some(1 << 16), ..options(&out, unverified) };
            let summary = zipfast::extract::run(&first, &options, |_| {}).unwrap();
            assert!(summary.errors.iter().any(|error| error.contains("a.txt")), "{what}: {:?}", summary.errors);
            let a = fs::read(out.join("a.txt")).unwrap();
            assert_eq!(a.len(), printed.len(), "{what}");
            assert!(a == printed, "{what}: the bytes the session prints");
        }
    }
}
