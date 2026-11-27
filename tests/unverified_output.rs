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

//! `extract::UnverifiedOutput`: what becomes of the bytes decoded of a member that then fails. `Withhold` (the
//! default) keeps zipfast's behaviour; `Emit` writes, prints or streams them as UnRAR 7.30 (`p`, `x -kb`) and 7-Zip
//! 26.06 (`x -so`) do, and the member is still reported failed. The expected bytes are the reference tools' outputs
//! (length and SHA-256), recorded in `tests/fixtures/unverified-output/README.md`.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use zipfast::error::{RarFailure, RarIntegrityReason};
use zipfast::extract::{
    self, Cancellation, Mode, Options, Overwrite, RarOutcome, SelectOptions, SelectedEntry, UNFILTERED_SELECTED,
    UnverifiedOutput, UnverifiedWritten,
};
use zipfast::rar5::session::{RarDecodeLimits, RarPrintOptions, RarSession, RarSessionOptions};
use zipfast::sevenzip::{self, SevenZipLimits, SevenZipPrintOptions};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn fixture(rel: &str) -> PathBuf {
    Path::new(FIXTURES).join(rel)
}

fn sha256(bytes: &[u8]) -> String {
    zipfast::crypto::sha256(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// What the reference tool wrote: its length and SHA-256.
fn assert_reference(got: &[u8], (len, sha): (usize, &str), what: &str) {
    assert_eq!(got.len(), len, "{what}: length");
    assert_eq!(sha256(got), sha, "{what}: bytes");
}

const EMPTY: (usize, &str) = (0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

fn options(dest: &Path, keep: bool, unverified: UnverifiedOutput, threads: usize) -> Options {
    Options {
        mode: Mode::Extract,
        dest: dest.to_path_buf(),
        overwrite: Overwrite::Always,
        flatten: false,
        threads: Some(threads),
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
        unverified_output: unverified,
        salvage_truncated_zip: false,
        seven_zip_strict: false,
        unix_modes: Default::default(),
        backslashes: Default::default(),
    }
}

/// A first volume whose later volumes are missing, with the member cut off there and what `unrar p` prints of it.
struct Cut {
    volume: &'static str,
    member: &'static str,
    unrar: (usize, &'static str),
}

const CUTS: &[Cut] = &[
    Cut {
        volume: "rar4/multi_broken.part1.rar",
        member: "file2.txt",
        unrar: (6198, "08d189238e140db78fd3efd2fb94281cd9fb697934bc04f1883a314a9d402895"),
    },
    Cut {
        volume: "rar4-rar300/multivol_newnaming_rar300.part01.rar",
        member: "bigtext_64k.bin",
        unrar: (53664, "7a7bc1f048eb734dffbd7ad558e10787f3e479893cbc8fd6bb505482e47af513"),
    },
    Cut {
        volume: "rar4-rar300/compressed_multivol_prng_rar300.rar",
        member: "cvolume.bin",
        unrar: (819, "2f016dfe8aa5423d308ea9f76a009489a782c576d5c1a07c078372b69528f8e3"),
    },
    Cut {
        volume: "unverified-output/r5-partial.part1.rar",
        member: "text.txt",
        unrar: (55043, "11c38a4de906c15f93a2be9e54c2a1a353a74f54bc174ba4cd1b79b5b2d7a06e"),
    },
    Cut {
        volume: "unverified-output/r5-edge.part1.rar",
        member: "text.txt",
        unrar: (51611, "9e56b78c9855adba0d200b971714afe00bd67cd2ed08c26d6d5b753dbd6d2a64"),
    },
];

/// The first volume alone in a directory of its own, so the next one is missing.
fn alone(dir: &Path, rel: &str) -> PathBuf {
    let path = dir.join(Path::new(rel).file_name().unwrap());
    fs::copy(fixture(rel), &path).unwrap();
    path
}

/// `unrar x -kb`: the member a missing volume cuts off keeps every byte UnRAR decodes of it; by default (as 7-Zip `x`)
/// it stays empty for RAR 4.x. Without `keep_broken` it is removed either way, as `unrar x` removes it.
#[test]
fn whole_archive_runs_keep_what_unrar_decodes_of_a_member_cut_off_by_a_missing_volume() {
    let dir = tempfile::tempdir().unwrap();
    for cut in CUTS {
        let volume = alone(dir.path(), cut.volume);
        for threads in [1, 4] {
            for (keep, unverified) in
                [(true, UnverifiedOutput::Emit), (true, UnverifiedOutput::Withhold), (false, UnverifiedOutput::Emit)]
            {
                let what = format!("{} {threads} {keep} {unverified:?}", cut.volume);
                let out = dir.path().join(format!("out-{threads}-{keep}-{unverified:?}-{}", cut.member));
                let summary = extract::run(&volume, &options(&out, keep, unverified, threads), |_| {}).unwrap();
                assert!(
                    summary.errors.iter().any(|e| e.starts_with(cut.member) && e.contains("missing volume")),
                    "{what}: still a failure: {:?}",
                    summary.errors
                );
                let kept = fs::read(out.join(cut.member));
                match (keep, unverified) {
                    (true, UnverifiedOutput::Emit) => assert_reference(&kept.unwrap(), cut.unrar, &what),
                    // as 7-Zip `x` leaves it
                    (true, _) if cut.member == "file2.txt" => assert_reference(&kept.unwrap(), EMPTY, &what),
                    // what was written before the volume was found missing, as before
                    (true, _) => assert!(kept.unwrap().len() < cut.unrar.0, "{what}"),
                    (false, _) => assert!(kept.is_err(), "{what}: removed without keep_broken"),
                }
            }
        }
    }
}

/// `unrar p`: `RarSession::print_selected` prints what UnRAR prints of a member cut off by a missing volume, reports it
/// failed with the missing volume, and says how many bytes went out unverified; by default it prints nothing of it.
#[test]
fn rar_session_print_prints_what_unrar_prints_of_a_member_cut_off() {
    let dir = tempfile::tempdir().unwrap();
    for cut in CUTS {
        let volume = alone(dir.path(), cut.volume);
        for unverified in [UnverifiedOutput::Emit, UnverifiedOutput::Withhold] {
            let what = format!("{} {unverified:?}", cut.volume);
            let mut session = RarSession::open(&volume, None, RarSessionOptions::default()).unwrap();
            let selection = session.select(|member| member.name() == cut.member).unwrap();
            let options = RarPrintOptions { unverified_output: unverified, ..RarPrintOptions::default() };
            let mut output = Vec::new();
            let mut events = Vec::new();
            let summary = session
                .print_selected(&selection, &mut output, &options, |event| {
                    events.push((matches!(event.outcome, RarOutcome::Failed(_)), event.unverified_bytes, {
                        match &event.outcome {
                            RarOutcome::Failed(failure) => Some(Arc::clone(failure)),
                            _ => None,
                        }
                    }))
                })
                .unwrap();
            assert_eq!(summary.failed, 1, "{what}");
            let [(failed, unverified_bytes, failure)] = events.as_slice() else { panic!("{what}: {events:?}") };
            assert!(*failed, "{what}");
            assert!(
                matches!(
                    failure.as_deref(),
                    Some(
                        RarFailure::MissingVolume { .. }
                            | RarFailure::Integrity { reason: RarIntegrityReason::MissingSplitContinuation, .. }
                    )
                ),
                "{what}: {failure:?}"
            );
            if unverified == UnverifiedOutput::Emit {
                assert_reference(&output, cut.unrar, &what);
                assert_eq!(*unverified_bytes, Some(cut.unrar.0 as u64), "{what}");
            } else {
                assert!(output.is_empty(), "{what}");
                assert_eq!(*unverified_bytes, None, "{what}");
            }
        }
    }
}

/// `unrar x -kb` through `RarSession::extract_selected` with `keep_broken`: the cut-off member keeps what UnRAR decodes
/// of it. By default a session doesn't write such a member at all.
#[test]
fn rar_session_extraction_keeps_what_unrar_decodes_of_a_member_cut_off() {
    let dir = tempfile::tempdir().unwrap();
    for cut in CUTS {
        let volume = alone(dir.path(), cut.volume);
        for unverified in [UnverifiedOutput::Emit, UnverifiedOutput::Withhold] {
            let what = format!("{} {unverified:?}", cut.volume);
            let out = dir.path().join(format!("session-{unverified:?}-{}", cut.member));
            fs::create_dir_all(&out).unwrap();
            let mut session = RarSession::open(&volume, None, RarSessionOptions::default()).unwrap();
            let all = session.select(|_| true).unwrap();
            let opts = options(&out, true, unverified, 1);
            let summary = session.extract_selected(&all, &opts, RarDecodeLimits::default(), |_| {}).unwrap();
            assert_eq!(summary.failed, 1, "{what}");
            let kept = fs::read(out.join(cut.member));
            if unverified == UnverifiedOutput::Emit {
                assert_reference(&kept.unwrap_or_else(|e| panic!("{what}: {e}")), cut.unrar, &what);
            } else {
                assert!(kept.is_err(), "{what}: not written, as before");
            }
        }
    }
}

/// A 7z case: the archive, the member printed (all when empty), the password, and what `7z x -so` writes.
struct SevenZipCase {
    archive: &'static str,
    member: &'static str,
    password: Option<&'static str>,
    seven_zip: (usize, &'static str),
}

const SEVEN_ZIP: &[SevenZipCase] = &[
    SevenZipCase {
        archive: "copy_crc.7z",
        member: "a.txt",
        password: None,
        seven_zip: (20484, "9597f3068dd98659e058b9a77ec6ee5750c9994422cba18ecf669432eac9ee35"),
    },
    SevenZipCase {
        archive: "lzma_bad.7z",
        member: "a.txt",
        password: None,
        seven_zip: (1392, "d54f224690763bd462294893354cde7defd70dced0f28fad5b68d414573ce438"),
    },
    SevenZipCase {
        archive: "solid_bad.7z",
        member: "a.txt",
        password: None,
        seven_zip: (3281, "296d3f40da4727405783b6b6c424bddc72809edbb50a0dda5e3f3fe47178f600"),
    },
    SevenZipCase { archive: "solid_bad.7z", member: "b.bin", password: None, seven_zip: EMPTY },
    SevenZipCase {
        archive: "lzma_trunc.7z",
        member: "",
        password: None,
        seven_zip: (13904, "b0e0070e78eea365b14c9e55f06926b29c96892020edb082d8998e1c6b31e793"),
    },
    SevenZipCase { archive: "enc.7z", member: "", password: Some("wrong"), seven_zip: EMPTY },
    SevenZipCase {
        archive: "enc_copy.7z",
        member: "",
        password: Some("wrong"),
        seven_zip: (22484, "b37305f9abe1f03c38ab4a1557ef89535768cbcb88bac7e4a07164dc6d6b0a7d"),
    },
];

fn seven_zip_print(case: &SevenZipCase, unverified: UnverifiedOutput) -> (Vec<u8>, extract::Summary) {
    let mut output = Vec::new();
    let summary = sevenzip::print_selected_with_options(
        &fixture("unverified-output").join(case.archive),
        case.password,
        &mut |_, name| case.member.is_empty() || name == case.member,
        &mut |_, bytes| {
            output.extend_from_slice(bytes);
            Ok(())
        },
        &Cancellation::default(),
        &SevenZipLimits::default(),
        &SevenZipPrintOptions::new().unverified_output(unverified),
    )
    .unwrap();
    (output, summary)
}

/// `7z x -so`: a member failing its CRC prints everything decoded, a data error or a folder cut short the bytes
/// before it, a wrong password what the folder decodes to (nothing for LZMA, garbage for Copy), a member after a
/// broken one in its solid block nothing. Each still fails; by default nothing of them is printed.
#[test]
fn seven_zip_print_streams_failing_members_as_seven_zip_does() {
    for case in SEVEN_ZIP {
        let what = format!("{} {}", case.archive, case.member);
        let (output, summary) = seven_zip_print(case, UnverifiedOutput::Emit);
        assert_reference(&output, case.seven_zip, &what);
        assert!(!summary.errors.is_empty(), "{what}: still failed");
        let printed: u64 = summary.unverified.iter().map(|m| m.bytes).sum();
        assert_eq!(printed, case.seven_zip.0 as u64, "{what}: {:?}", summary.unverified);
        assert!(
            summary.unverified.iter().all(|m| summary.errors.iter().any(|e| e.starts_with(&m.name))),
            "{what}: every unverified member is a failure too"
        );

        let (output, withheld) = seven_zip_print(case, UnverifiedOutput::Withhold);
        assert!(output.is_empty(), "{what}: nothing by default");
        assert_eq!(withheld.errors, summary.errors, "{what}: the same failures");
        assert!(withheld.unverified.is_empty(), "{what}");
    }
}

/// The same through `SelectedEntry` (`SelectOptions::unverified_output`): the sink gets 7-Zip's bytes and the read
/// fails with an `UnverifiedWritten` saying how many.
#[test]
fn selected_entry_streams_a_failing_7z_member_as_seven_zip_does() {
    for case in SEVEN_ZIP.iter().filter(|case| !case.member.is_empty() || case.archive == "lzma_trunc.7z") {
        let what = format!("{} {}", case.archive, case.member);
        let path = fixture("unverified-output").join(case.archive);
        let index = sevenzip::list(&path, case.password)
            .unwrap()
            .iter()
            .position(|entry| case.member.is_empty() || entry.name == case.member)
            .unwrap();
        for unverified in [UnverifiedOutput::Emit, UnverifiedOutput::Withhold] {
            let select = SelectOptions::new().unverified_output(unverified);
            let entry = SelectedEntry::open_cancelable_with_options(
                &path,
                index,
                case.password,
                1 << 20,
                Cancellation::default(),
                select,
            )
            .unwrap();
            let mut got = Vec::new();
            let error = entry
                .read(case.password, |chunk| {
                    got.extend_from_slice(chunk);
                    Ok(())
                })
                .unwrap_err();
            let sign = UnverifiedWritten::of(&error);
            if unverified == UnverifiedOutput::Emit {
                assert_reference(&got, case.seven_zip, &what);
                assert_eq!(sign.map(|s| s.bytes), (case.seven_zip.0 != 0).then_some(case.seven_zip.0 as u64), "{what}");
            } else {
                assert!(got.is_empty(), "{what}");
                assert!(sign.is_none(), "{what}: {error}");
            }
        }
    }
}

/// `7z x -so generic_delta_padding_mutation.rar`: with `Emit`, a `SelectedEntry` decodes the member with the block an
/// unknown VM program filters left unfiltered, as 7-Zip streams it, and fails as written unfiltered; by default it
/// fails as unsupported.
#[test]
fn selected_entry_streams_a_rar_member_with_an_unsupported_filter_unfiltered() {
    let path = fixture("rar4-rar300/generic_delta_padding_mutation.rar");
    let want = (1_048_576, "aff2543ca3d75b1837cf511c36a3e3e9df7719ed2846f479b650ca9e749e76c5");
    for unverified in [UnverifiedOutput::Emit, UnverifiedOutput::Withhold] {
        let select = SelectOptions::new().unverified_output(unverified);
        let entry =
            SelectedEntry::open_cancelable_with_options(&path, 0, None, 4 << 20, Cancellation::default(), select)
                .unwrap();
        let mut got = Vec::new();
        let error = entry
            .read(None, |chunk| {
                got.extend_from_slice(chunk);
                Ok(())
            })
            .unwrap_err();
        let sign = UnverifiedWritten::of(&error);
        if unverified == UnverifiedOutput::Emit {
            assert_reference(&got, want, "Emit");
            let sign = sign.expect("written unverified");
            assert_eq!(sign.bytes, want.0 as u64);
            assert!(
                matches!(&sign.cause, zipfast::Error::Unsupported(what) if what == UNFILTERED_SELECTED),
                "{:?}",
                sign.cause
            );
        } else {
            assert!(got.len() < want.0, "never the whole member");
            assert!(sign.is_none(), "{error}");
        }
    }
}

fn num(out: &mut Vec<u8>, value: u64) {
    let bytes = value.to_le_bytes();
    let extra = (0..=8).find(|&n| n == 8 || value < 1u64 << (7 * (n + 1))).unwrap();
    if extra == 8 {
        out.push(0xFF);
        out.extend_from_slice(&bytes);
        return;
    }
    let first = (0xFFu16 << (8 - extra)) as u8 | (value >> (8 * extra)) as u8;
    out.push(first);
    out.extend_from_slice(&bytes[..extra]);
}

/// One folder holding `files` (name, contents, the CRC stored for it if any) with the folder's own CRC, so a member
/// without a CRC of its own is held back for it: Copy, or 7zAES over the data when `password` is given (the "no
/// hashing" key derivation, power 0x3F: the key is the password). 7-Zip always writes member CRCs, so this is built
/// by hand.
fn folder_with_a_crc(path: &Path, password: Option<&str>, files: &[(&str, &[u8], Option<u32>)]) {
    let plain: Vec<u8> = files.iter().flat_map(|(_, data, _)| data.iter().copied()).collect();
    let iv = [9u8; 16];
    let packed = match password {
        Some(password) => {
            let mut key = [0u8; 32];
            for (slot, byte) in key.iter_mut().zip(password.encode_utf16().flat_map(u16::to_le_bytes)) {
                *slot = byte;
            }
            let mut padded = plain.clone();
            padded.resize(plain.len().next_multiple_of(16), 0);
            zipfast::crypto::encrypt_cbc(&key, &iv, &padded).unwrap()
        }
        None => plain.clone(),
    };
    let mut h = vec![0x01, 0x04, 0x06, 0x00, 0x01, 0x09];
    num(&mut h, packed.len() as u64);
    h.extend([0x00, 0x07, 0x0B, 0x01, 0x00, 0x01]);
    if password.is_some() {
        h.extend([0x24, 0x06, 0xF1, 0x07, 0x01]);
        let mut props = vec![0x7F, 0x0F];
        props.extend(iv);
        num(&mut h, props.len() as u64);
        h.extend(props);
    } else {
        h.extend([0x01, 0x00]);
    }
    h.push(0x0C);
    num(&mut h, plain.len() as u64);
    h.extend([0x0A, 0x01]);
    h.extend(zipfast::crc32::hash(&plain).to_le_bytes());
    h.push(0x00);
    h.extend([0x08, 0x0D]);
    num(&mut h, files.len() as u64);
    h.push(0x09);
    for (_, data, _) in &files[..files.len() - 1] {
        num(&mut h, data.len() as u64);
    }
    h.extend([0x0A, 0x00]);
    let mut bits = vec![0u8; files.len().div_ceil(8)];
    for (i, (_, _, crc)) in files.iter().enumerate() {
        if crc.is_some() {
            bits[i / 8] |= 0x80 >> (i % 8);
        }
    }
    h.extend(bits);
    for (_, _, crc) in files {
        if let Some(crc) = crc {
            h.extend(crc.to_le_bytes());
        }
    }
    h.extend([0x00, 0x00, 0x05]);
    num(&mut h, files.len() as u64);
    let mut names = vec![0u8];
    for (name, _, _) in files {
        names.extend(name.encode_utf16().flat_map(u16::to_le_bytes));
        names.extend([0, 0]);
    }
    h.push(0x11);
    num(&mut h, names.len() as u64);
    h.extend(names);
    h.extend([0x00, 0x00]);
    let mut start = [0u8; 20];
    start[..8].copy_from_slice(&(packed.len() as u64).to_le_bytes());
    start[8..16].copy_from_slice(&(h.len() as u64).to_le_bytes());
    start[16..].copy_from_slice(&zipfast::crc32::hash(&h).to_le_bytes());
    let mut out = vec![b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C, 0, 4];
    out.extend(zipfast::crc32::hash(&start).to_le_bytes());
    out.extend(start);
    out.extend(packed);
    out.extend(h);
    fs::write(path, out).unwrap();
}

/// Codex on #317: a member failing its own CRC behind one held for the folder's CRC prints after it, in archive order.
#[test]
fn seven_zip_print_keeps_archive_order_behind_a_member_held_for_the_folder_crc() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("held.7z");
    let (first, second, third): (&[u8], &[u8], &[u8]) = (b"no crc of its own, ", b"a wrong stored crc, ", b"fine");
    let files = [
        ("first.txt", first, None),
        ("second.txt", second, Some(zipfast::crc32::hash(second) ^ 1)),
        ("third.txt", third, Some(zipfast::crc32::hash(third))),
    ];
    folder_with_a_crc(&path, None, &files);
    let mut output = Vec::new();
    let summary = sevenzip::print_selected_with_options(
        &path,
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
    assert_eq!(output, [first, second, third].concat(), "archive order");
    assert_eq!(summary.errors.len(), 1, "{:?}", summary.errors);
    assert!(summary.errors[0].starts_with("second.txt"), "{:?}", summary.errors);
    let unverified: Vec<_> = summary.unverified.iter().map(|m| (m.index, m.bytes)).collect();
    assert_eq!(unverified, [(1, second.len() as u64)]);
}

/// Codex on #317: a member held for the folder's CRC, printed when a later member shows the wrong password, fails the
/// run when writing it fails.
#[test]
fn seven_zip_print_fails_on_an_output_error_printing_held_members_for_a_wrong_password() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("aes-held.7z");
    let (first, second): (&[u8], &[u8]) = (b"no crc of its own", b"checked by its crc");
    folder_with_a_crc(
        &path,
        Some("right"),
        &[("first.txt", first, None), ("second.txt", second, Some(zipfast::crc32::hash(second)))],
    );
    let result = sevenzip::print_selected_with_options(
        &path,
        Some("wrong"),
        &mut |_, _| true,
        &mut |_, _| Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "closed")),
        &Cancellation::default(),
        &SevenZipLimits::default(),
        &SevenZipPrintOptions::new().unverified_output(UnverifiedOutput::Emit),
    );
    let error = result.expect_err("the output error ends the run");
    assert!(error.to_string().contains("closed"), "{error}");
}

/// Codex on #317: a compressed split member whose first part fails its own packed checksum prints what was decoded
/// of it (the RAR 3.x decoder still buffering it) under `Emit`; nothing by default.
#[test]
fn rar_session_print_hands_over_a_member_whose_part_fails_its_checksum() {
    let dir = tempfile::tempdir().unwrap();
    for part in 1..=3 {
        fs::copy(
            fixture(&format!("rar4-volumes/multi.part{part}.rar")),
            dir.path().join(format!("multi.part{part}.rar")),
        )
        .unwrap();
    }
    let first = dir.path().join("multi.part1.rar");
    let mut bytes = fs::read(&first).unwrap();
    // the last byte of file2.txt's data in this volume, before the end block: the part's CRC fails, nothing else
    let at = bytes.len() - 21;
    bytes[at] ^= 0x01;
    fs::write(&first, bytes).unwrap();
    for unverified in [UnverifiedOutput::Emit, UnverifiedOutput::Withhold] {
        let mut session = RarSession::open(&first, None, RarSessionOptions::default()).unwrap();
        let selection = session.select(|member| member.name() == "file2.txt").unwrap();
        let options = RarPrintOptions { unverified_output: unverified, ..RarPrintOptions::default() };
        let mut output = Vec::new();
        let mut events = Vec::new();
        session
            .print_selected(&selection, &mut output, &options, |event| {
                events.push((
                    match &event.outcome {
                        RarOutcome::Failed(failure) => Some(format!("{failure:?}")),
                        _ => None,
                    },
                    event.unverified_bytes,
                ))
            })
            .unwrap();
        let [(Some(failure), unverified_bytes)] = events.as_slice() else { panic!("{unverified:?}: {events:?}") };
        assert!(failure.contains("Integrity"), "{failure}");
        if unverified == UnverifiedOutput::Emit {
            assert!(!output.is_empty(), "{failure}");
            assert_eq!(*unverified_bytes, Some(output.len() as u64));
        } else {
            assert!(output.is_empty());
            assert_eq!(*unverified_bytes, None);
        }
    }
}
