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

//! Connected public consumers for independently specified fixed RAR4 bit vectors.
//! Provenance and bit-by-bit derivation are in the shared SDD worksheet.
//! This wraps fixed bytes with headers and does not compress arbitrary data.

#![cfg(unix)]

use std::{fs, path::Path};
use zipfast::crc32::hash;
use zipfast::error::{RarFailure, RarIntegrityReason, RarResource, RarUnsupported};
use zipfast::extract::{self, Mode, Options, Overwrite, RarOutcome};
use zipfast::rar5::session::{RarDecodeLimits, RarPrintOptions, RarSession, RarSessionOptions};

fn block(kind: u8, flags: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0, 0, kind];
    bytes.extend(flags.to_le_bytes());
    bytes.extend(((body.len() + 7) as u16).to_le_bytes());
    bytes.extend(body);
    let crc = hash(&bytes[2..]) as u16;
    bytes[..2].copy_from_slice(&crc.to_le_bytes());
    bytes
}

fn member(name: &[u8], packed: &[u8], expected: &[u8], version: u8, method: u8, flags: u16) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend((packed.len() as u32).to_le_bytes());
    body.extend((expected.len() as u32).to_le_bytes());
    body.push(3);
    body.extend(hash(expected).to_le_bytes());
    body.extend(0x50221884u32.to_le_bytes());
    body.extend([version, method]);
    body.extend((name.len() as u16).to_le_bytes());
    body.extend(0o100644u32.to_le_bytes());
    body.extend(name);
    let mut bytes = block(0x74, flags | 0x8000, &body);
    bytes.extend(packed);
    bytes
}
fn archive(files: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = b"Rar!\x1a\x07\0".to_vec();
    bytes.extend(block(0x73, 0, &[0; 6]));
    for file in files {
        bytes.extend(file);
    }
    bytes.extend(block(0x7b, 0x4000, &[]));
    bytes
}
fn fixed_archive(packed: &[u8], expected: &[u8]) -> Vec<u8> {
    archive(&[member(b"vector", packed, expected, 29, 0x33, 0)])
}
fn options(dest: &Path, mode: Mode, threads: usize) -> Options {
    Options {
        mode,
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
        keep_broken: false,
        attempt_continued_members: false,
        encrypted_links: Default::default(),
        damaged_input: Default::default(),
        unsupported_filters: Default::default(),
        unverified_output: Default::default(),
        salvage_truncated_zip: false,
        unix_modes: Default::default(),
        backslashes: Default::default(),
        hard_link_targets: Default::default(),
    }
}

fn verify(packed: &[u8], expected: &[u8]) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fixed.rar");
    std::fs::write(&path, fixed_archive(packed, expected)).unwrap();
    let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    let selection = session.select(|_| true).unwrap();
    let mut events = Vec::new();
    let result = session
        .test_selected(&selection, RarDecodeLimits::default(), |event| events.push(format!("{event:?}")))
        .unwrap();
    assert_eq!((result.files, result.failed), (1, 0), "fixed version-29 LZ vector must verify. Events {events:?}");
    let mut stdout = Vec::new();
    session.print_selected(&selection, &mut stdout, &RarPrintOptions::default(), |_| {}).unwrap();
    assert_eq!(stdout, expected);
    let selected = dir.path().join("selected");
    assert_eq!(
        session
            .extract_selected(&selection, &options(&selected, Mode::Extract, 4), RarDecodeLimits::default(), |_| {})
            .unwrap()
            .files,
        1
    );
    assert_eq!(fs::read(selected.join("vector")).unwrap(), expected);
    let mut legacy = Vec::new();
    extract::SelectedEntry::open(&path, 0, None, 1 << 20)
        .unwrap()
        .read(None, |bytes| {
            legacy.extend_from_slice(bytes);
            Ok(())
        })
        .unwrap();
    assert_eq!(legacy, expected);
    for threads in [1, 4] {
        let dest = dir.path().join(format!("bulk{threads}"));
        let mut checked = 0;
        let result = extract::run_rar_with_outcomes(&path, &options(&dest, Mode::Test, threads), None, |event| {
            if let RarOutcome::Verified { checks, .. } = &event.outcome {
                assert!(checks.size_checked && checks.crc32_checked);
                checked += 1;
            }
        })
        .unwrap();
        assert_eq!((result.files, result.failed, checked), (1, 0, 1));
        assert_eq!(
            extract::run_rar_with_outcomes(&path, &options(&dest, Mode::Extract, threads), None, |_| {}).unwrap().files,
            1
        );
        assert_eq!(fs::read(dest.join("vector")).unwrap(), expected);
    }
}

#[test]
fn literal_a() {
    verify(include_bytes!("fixtures/rar4-lz/literal-a.packed"), b"A");
}

#[test]
fn initial_delta_zero_baseline() {
    verify(include_bytes!("fixtures/rar4-lz/initial-delta-zero-baseline.packed"), b"A");
}

#[test]
fn table_reuse_delta() {
    verify(include_bytes!("fixtures/rar4-lz/table-reuse-delta.packed"), b"AA");
}

#[test]
fn code_length_nibble_zero_run() {
    verify(include_bytes!("fixtures/rar4-lz/code-length-nibble-zero-run.packed"), b"A");
}

#[test]
fn new_match_repeat_last() {
    verify(include_bytes!("fixtures/rar4-lz/new-match-repeat-last.packed"), b"AAAAAAA");
}

#[test]
fn recent_distance_repeat() {
    verify(include_bytes!("fixtures/rar4-lz/recent-distance-repeat.packed"), b"AAAAAA");
}

#[test]
fn short_distance_match() {
    verify(include_bytes!("fixtures/rar4-lz/short-distance-match.packed"), b"AAA");
}

#[test]
fn zero_length_runs() {
    verify(include_bytes!("fixtures/rar4-lz/zero-length-runs.packed"), b"A");
}

#[test]
fn previous_length_runs() {
    verify(include_bytes!("fixtures/rar4-lz/previous-length-runs.packed"), b"AP");
}

fn issue(path: &Path) -> Vec<std::sync::Arc<RarFailure>> {
    let mut session = RarSession::open(path, None, RarSessionOptions::default()).unwrap();
    let all = session.select(|_| true).unwrap();
    let mut failures = Vec::new();
    session
        .test_selected(&all, RarDecodeLimits::default(), |event| {
            if let RarOutcome::Failed(failure) = &event.outcome {
                failures.push(failure.clone());
            }
        })
        .unwrap();
    failures
}

#[test]
fn truncated_ppm_and_filter_records_and_bad_crc_never_publish_and_later_members_reset() {
    let dir = tempfile::tempdir().unwrap();
    let good = include_bytes!("fixtures/rar4-lz/initial-delta-zero-baseline.packed");
    let cases = [
        (include_bytes!("fixtures/rar4-lz/ppm-marker.packed").as_slice(), b"AA".as_slice(), 0),
        (include_bytes!("fixtures/rar4-lz/vm-marker-after-prefix.packed").as_slice(), b"AA".as_slice(), 1),
        (include_bytes!("fixtures/rar4-lz/literal-a.packed").as_slice(), b"B".as_slice(), 2),
    ];
    for (packed, expected, case) in cases {
        let path = dir.path().join(format!("case{case}.rar"));
        fs::write(
            &path,
            archive(&[member(b"bad", packed, expected, 29, 0x33, 0), member(b"good", good, b"A", 29, 0x35, 0)]),
        )
        .unwrap();
        let failures = issue(&path);
        assert_eq!(failures.len(), 1);
        match case {
            // a PPM block header or filter record the data cuts off is corrupt
            0 | 1 => assert!(matches!(failures[0].as_ref(), RarFailure::Integrity { .. }), "{failures:?}"),
            _ => assert!(matches!(
                failures[0].as_ref(),
                RarFailure::Integrity { reason: RarIntegrityReason::FinalChecks { crc32: true, .. }, .. }
            )),
        }
        let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
        let all = session.select(|_| true).unwrap();
        let mut stdout = Vec::new();
        let summary = session.print_selected(&all, &mut stdout, &RarPrintOptions::default(), |_| {}).unwrap();
        assert_eq!((summary.files, summary.failed), (1, 1));
        assert_eq!(stdout, b"A");
        for threads in [1, 4] {
            let dest = dir.path().join(format!("out{case}-{threads}"));
            fs::create_dir(&dest).unwrap();
            fs::write(dest.join("bad"), b"keep").unwrap();
            let summary =
                extract::run_rar_with_outcomes(&path, &options(&dest, Mode::Extract, threads), None, |_| {}).unwrap();
            assert_eq!((summary.files, summary.failed), (1, 1));
            assert_eq!(fs::read(dest.join("bad")).unwrap(), b"keep");
            assert_eq!(fs::read(dest.join("good")).unwrap(), b"A");
            assert_eq!(fs::read_dir(&dest).unwrap().count(), 2);
        }
        let dest = dir.path().join(format!("selected{case}"));
        fs::create_dir(&dest).unwrap();
        fs::write(dest.join("bad"), b"keep").unwrap();
        let summary = session
            .extract_selected(&all, &options(&dest, Mode::Extract, 4), RarDecodeLimits::default(), |_| {})
            .unwrap();
        assert_eq!((summary.files, summary.failed), (1, 1));
        assert_eq!(fs::read(dest.join("bad")).unwrap(), b"keep");
        assert_eq!(fs::read(dest.join("good")).unwrap(), b"A");
        assert_eq!(fs::read_dir(dest).unwrap().count(), 2);
    }
}

#[test]
fn exact_selected_limits_window_and_spool_failures_are_typed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("limits.rar");
    let packed = include_bytes!("fixtures/rar4-lz/literal-a.packed");
    fs::write(&path, fixed_archive(packed, b"A")).unwrap();
    let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    let all = session.select(|_| true).unwrap();
    let exact = RarDecodeLimits { packed_bytes: packed.len() as u64, decoded_bytes: 1, window_bytes: 65536 };
    assert_eq!(session.test_selected(&all, exact, |_| {}).unwrap().files, 1);
    for (limits, resource) in [
        (RarDecodeLimits { packed_bytes: packed.len() as u64 - 1, ..exact }, RarResource::SelectedPackedBytes),
        (RarDecodeLimits { decoded_bytes: 0, ..exact }, RarResource::SelectedDecodedBytes),
    ] {
        let error = session.test_selected(&all, limits, |_| {}).unwrap_err();
        assert!(
            matches!(error.failure.as_ref(),RarFailure::Limit{resource:actual,..} if std::mem::discriminant(actual)==std::mem::discriminant(&resource))
        );
    }
    let mut failures = Vec::new();
    assert_eq!(
        session
            .test_selected(&all, RarDecodeLimits { window_bytes: 65535, ..exact }, |event| {
                if let RarOutcome::Failed(failure) = &event.outcome {
                    failures.push(failure.clone());
                }
            })
            .unwrap()
            .failed,
        1
    );
    assert!(matches!(
        failures[0].as_ref(),
        RarFailure::Limit { resource: RarResource::DictionarySize, requested: Some(65536), allowed: Some(65535) }
    ));
    let mut stdout = Vec::new();
    let opts = RarPrintOptions { decode: exact, member_spool_bytes: 0, ..Default::default() };
    let error = session.print_selected(&all, &mut stdout, &opts, |_| {}).unwrap_err();
    assert!(stdout.is_empty());
    assert!(matches!(error.failure.as_ref(), RarFailure::Limit { resource: RarResource::PrintMemberSpoolBytes, .. }));
}

#[test]
fn old_versions_and_methods_stay_excluded() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("excluded.rar");
    let packed = include_bytes!("fixtures/rar4-lz/literal-a.packed");
    for (version, method, flags, label) in [
        // Versions 15, 20, 26 and 29 decode (tests/rar4_split_solid.rs); RAR 1.3 and anything past 2.9 don't.
        (10, 0x33, 0, "unpack version"),
        (36, 0x33, 0, "unpack version"),
        (29, 0x36, 0, "compression method"),
        // Split, solid and encrypted version 29 members decode (tests/rar4_split_solid.rs); RAR 2.0's cipher doesn't.
        (20, 0x30, 4, "encrypted payload"),
    ] {
        fs::write(&path, archive(&[member(b"excluded", packed, b"A", version, method, flags)])).unwrap();
        let failures = issue(&path);
        assert_eq!(failures.len(), 1);
        assert!(
            matches!(failures[0].as_ref(),RarFailure::Unsupported(RarUnsupported::Rar4Feature(actual)) if *actual==label),
            "{failures:?}"
        );
    }
}

#[test]
fn size_underflow_overflow_and_terminal_slack_follow_exact_contract() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sizes.rar");
    let packed = include_bytes!("fixtures/rar4-lz/literal-a.packed");
    for bytes in [&packed[..packed.len() - 1], packed.as_slice()] {
        verify(bytes, b"A");
    }
    for tail in [0, 255] {
        let mut bytes = packed.to_vec();
        bytes.push(tail);
        verify(&bytes, b"A");
    }
    for (bytes, expected, actual) in [
        (packed.as_slice(), b"AA".as_slice(), 1),
        (include_bytes!("fixtures/rar4-lz/new-match-repeat-last.packed").as_slice(), b"AAA".as_slice(), 4),
    ] {
        fs::write(&path, fixed_archive(bytes, expected)).unwrap();
        let failures = issue(&path);
        assert!(
            matches!(failures[0].as_ref(),RarFailure::Integrity{reason:RarIntegrityReason::DecodedSize{expected:size,actual:got},..} if *size==expected.len() as u64 && *got==actual)
        );
        let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
        let all = session.select(|_| true).unwrap();
        let mut stdout = Vec::new();
        assert_eq!(session.print_selected(&all, &mut stdout, &RarPrintOptions::default(), |_| {}).unwrap().failed, 1);
        assert!(stdout.is_empty());
    }
    verify(&[128], b"");
}

#[test]
fn checked_output_aliases_and_source_changes_keep_typed_precedence() {
    use std::io::{self, Write};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("source.rar");
    let bytes = fixed_archive(include_bytes!("fixtures/rar4-lz/literal-a.packed"), b"A");
    fs::write(&path, &bytes).unwrap();
    let alias = dir.path().join("alias");
    fs::hard_link(&path, &alias).unwrap();
    let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    let all = session.select(|_| true).unwrap();
    let output = fs::OpenOptions::new().append(true).open(&alias).unwrap();
    assert!(matches!(session.check_output_file(&output).unwrap_err().failure.as_ref(), RarFailure::OutputAliasesInput));
    assert_eq!(fs::read(&path).unwrap(), bytes);
    struct BadSink {
        source: std::path::PathBuf,
    }
    impl Write for BadSink {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            let source = fs::OpenOptions::new().append(true).open(&self.source)?;
            source.set_len(0)?;
            Err(io::Error::from_raw_os_error(libc::ENOSPC))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let failure = session
        .print_selected(&all, &mut BadSink { source: path.clone() }, &RarPrintOptions::default(), |_| {})
        .unwrap_err();
    assert!(
        matches!(failure.failure.as_ref(),RarFailure::PrintWriter{source,..} if source.raw_os_error()==Some(libc::ENOSPC))
    );
    let failure = session.test_selected(&all, RarDecodeLimits::default(), |_| {}).unwrap_err();
    assert!(matches!(failure.failure.as_ref(), RarFailure::SourceChanged { .. }));
}

#[test]
fn cancellation_and_protected_archive_destination_are_preserved() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive.rar");
    let packed = include_bytes!("fixtures/rar4-lz/literal-a.packed");
    let bytes = archive(&[member(b"archive.rar", packed, b"A", 29, 0x33, 0)]);
    fs::write(&path, &bytes).unwrap();
    for threads in [1, 4] {
        let result =
            extract::run_rar_with_outcomes(&path, &options(dir.path(), Mode::Extract, threads), None, |_| {}).unwrap();
        assert_eq!((result.files, result.failed), (0, 1));
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }
    let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    let all = session.select(|_| true).unwrap();
    assert_eq!(
        session
            .extract_selected(&all, &options(dir.path(), Mode::Extract, 4), RarDecodeLimits::default(), |_| {})
            .unwrap()
            .failed,
        1
    );
    assert_eq!(fs::read(&path).unwrap(), bytes);
    let cancel = extract::Cancellation::default();
    let mut session =
        RarSession::open(&path, None, RarSessionOptions { cancel: cancel.clone(), ..Default::default() }).unwrap();
    let all = session.select(|_| true).unwrap();
    cancel.cancel();
    assert!(matches!(
        session.test_selected(&all, RarDecodeLimits::default(), |_| {}).unwrap_err().failure.as_ref(),
        RarFailure::Canceled
    ));
}

fn legacy_unsupported(path: &Path, label: &str) {
    let failures = issue(path);
    assert_eq!(failures.len(), 1);
    assert!(matches!(failures[0].as_ref(),
        RarFailure::Unsupported(RarUnsupported::Rar4Feature(actual)) if *actual == label));
    let mut provisional = Vec::new();
    let error = extract::SelectedEntry::open(path, 0, None, 1 << 20)
        .unwrap()
        .read(None, |bytes| {
            provisional.extend_from_slice(bytes);
            Ok(())
        })
        .unwrap_err();
    assert!(provisional.is_empty());
    assert_eq!(error.to_string(), format!("unsupported: {label}"));
    assert!(matches!(error, zipfast::error::Error::Unsupported(actual) if actual == label));
}

#[test]
fn truncated_ppm_legacy_error_is_corrupt() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ppm.rar");
    fs::write(&path, fixed_archive(include_bytes!("fixtures/rar4-lz/ppm-marker.packed"), b"AA")).unwrap();
    let error = extract::SelectedEntry::open(&path, 0, None, 1 << 20).unwrap().read(None, |_| Ok(())).unwrap_err();
    assert!(matches!(error, zipfast::error::Error::Corrupt(_)), "{error:?}");
}

/// A VM program other than the six standard filters would need the VM itself.
#[test]
fn vm_program_other_than_a_standard_filter_is_unsupported() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rar4-rar300/generic_delta_padding_mutation.rar");
    legacy_unsupported(&path, "VM/filter payload");
}

/// A RAR 4.x symbolic link (Unix host, `S_IFLNK`) whose target is this member's data.
fn link_member(name: &[u8], packed: &[u8], target: &[u8], method: u8) -> Vec<u8> {
    let mut bytes = member(name, packed, target, 29, method, 0);
    // the mode is the last four bytes before the name; the header CRC covers it
    let header_len = u16::from_le_bytes([bytes[5], bytes[6]]) as usize;
    let mode = header_len - name.len() - 4;
    bytes[mode..mode + 4].copy_from_slice(&0o120777u32.to_le_bytes());
    let crc = hash(&bytes[2..header_len]) as u16;
    bytes[..2].copy_from_slice(&crc.to_le_bytes());
    bytes
}

/// A compressed RAR 4.x symbolic link's target is its decoded data: it is placed, and reported with the outcome on
/// RarSession extraction and testing and on the typed run, as a stored link's is.
#[test]
fn compressed_and_stored_rar4_links_report_their_decoded_targets() {
    use zipfast::rar5::Redirection;
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("links.rar");
    let packed = include_bytes!("fixtures/rar4-lz/literal-a.packed");
    fs::write(&path, archive(&[link_member(b"packed", packed, b"A", 0x33), link_member(b"stored", b"B", b"B", 0x30)]))
        .unwrap();
    let expected = [Some(Redirection::UnixSymlink("A".into())), Some(Redirection::UnixSymlink("B".into()))];
    let verified = |events: &[(Option<Redirection>, bool)]| {
        assert!(events.iter().all(|(_, ok)| *ok), "{events:?}");
        events.iter().map(|(link, _)| link.clone()).collect::<Vec<_>>()
    };
    let event = |e: &extract::RarEntryOutcome| (e.link.clone(), matches!(e.outcome, RarOutcome::Verified { .. }));
    for mode in [Mode::Extract, Mode::Test] {
        let dest = tmp.path().join(format!("session-{mode:?}"));
        let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
        let all = session.select(|_| true).unwrap();
        let mut events = Vec::new();
        match mode {
            Mode::Extract => {
                session.extract_selected(&all, &options(&dest, mode, 1), RarDecodeLimits::default(), |e| {
                    events.push(event(e))
                })
            }
            _ => session.test_selected(&all, RarDecodeLimits::default(), |e| events.push(event(e))),
        }
        .unwrap();
        assert_eq!(verified(&events), expected, "session {mode:?}");
        if mode == Mode::Extract {
            assert_eq!(fs::read_link(dest.join("packed")).unwrap(), Path::new("A"));
            assert_eq!(fs::read_link(dest.join("stored")).unwrap(), Path::new("B"));
        }
    }
    let dest = tmp.path().join("typed");
    let mut events = Vec::new();
    extract::run_rar_with_outcomes(&path, &options(&dest, Mode::Extract, 1), None, |e| events.push(event(e))).unwrap();
    assert_eq!(verified(&events), expected, "typed");
    assert_eq!(fs::read_link(dest.join("packed")).unwrap(), Path::new("A"));
}

/// Codex on #317: with `RarPrintOptions::unverified_output = Emit`, a member failing on its data prints what its
/// decoder still buffered too (`literal-a` declared as two bytes fails its decoded size with the `A` buffered).
#[test]
fn printing_unverified_hands_over_what_the_decoder_buffered() {
    use zipfast::extract::UnverifiedOutput;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("short.rar");
    let packed = include_bytes!("fixtures/rar4-lz/literal-a.packed");
    fs::write(&path, archive(&[member(b"short", packed, b"AA", 29, 0x33, 0)])).unwrap();
    for unverified in [UnverifiedOutput::Emit, UnverifiedOutput::Withhold] {
        let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
        let all = session.select(|_| true).unwrap();
        let options = RarPrintOptions { unverified_output: unverified, ..RarPrintOptions::default() };
        let mut stdout = Vec::new();
        let mut events = Vec::new();
        let summary = session
            .print_selected(&all, &mut stdout, &options, |event| {
                events.push((matches!(event.outcome, RarOutcome::Failed(_)), event.unverified_bytes))
            })
            .unwrap();
        assert_eq!(summary.failed, 1, "{unverified:?}");
        if unverified == UnverifiedOutput::Emit {
            assert_eq!(stdout, b"A");
            assert_eq!(events, [(true, Some(1))]);
        } else {
            assert!(stdout.is_empty());
            assert_eq!(events, [(true, None)]);
        }
    }
}
