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

//! RAR 4.x archives written by real WinRAR and rar builds (tests/fixtures/rar4, from dariusiii/rarinfo). Expected
//! names and order are `unrar lb`'s.

#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};
use zipfast::crc32::hash;
use zipfast::error::{RarFailure, RarUnsupported};
use zipfast::extract::{self, Mode, Options, Overwrite, RarEntryOutcome};
use zipfast::rar5::RarFormat;
use zipfast::rar5::session::*;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rar4").join(name)
}

fn options(dest: &Path) -> Options {
    Options {
        mode: Mode::Extract,
        dest: dest.into(),
        overwrite: Overwrite::Always,
        flatten: false,
        threads: Some(1),
        protected_paths: Default::default(),
        parallel_min: None,
        select: None,
    }
}

struct Replace;
impl RarExtractObserver for Replace {
    fn overwrite(
        &mut self,
        _: &RarOverwriteConflict<'_>,
        _: RarDiagnostic<'_>,
    ) -> Result<RarOverwriteDecision, RarDecisionError> {
        Ok(RarOverwriteDecision::Replace)
    }
    fn entry(&mut self, _: &RarEntryOutcome, _: RarDiagnostic<'_>) {}
}

/// Extract the members `include` takes through the controlled path; returns (files, dirs, failed).
fn controlled(session: &mut RarSession, dest: &Path, include: impl FnMut(RarMember<'_>) -> bool) -> (u64, u64, u64) {
    controlled_with(session, dest, None, include)
}

/// As `controlled`, with an optional diagnostic file whose target-alias proof projects every selected name.
fn controlled_with(
    session: &mut RarSession,
    dest: &Path,
    diagnostic: Option<fs::File>,
    include: impl FnMut(RarMember<'_>) -> bool,
) -> (u64, u64, u64) {
    let selected = session.select(include).unwrap();
    let diagnosed = diagnostic.is_some();
    let mut control = RarExtractControl::new(diagnostic, RarOverwriteMode::Always, RarExtractControlLimits::default());
    let report = session.extract_selected_controlled(
        &selected,
        &options(dest),
        RarDecodeLimits::default(),
        &mut control,
        &mut Replace,
    );
    if diagnosed {
        assert!(report.diagnostic_failure().is_none(), "{:?}", report.diagnostic_failure());
    }
    let summary = report.finish().outcome.unwrap();
    (summary.files, summary.dirs, summary.failed)
}

fn names(session: &RarSession) -> Vec<&str> {
    session.entries().map(|e| e.name()).collect()
}

fn rar4_unsupported(member: RarMember<'_>) -> Option<&'static str> {
    match member.payload_issue() {
        Some(RarFailure::Unsupported(RarUnsupported::Rar4Feature(feature))) => Some(feature),
        _ => None,
    }
}

#[test]
fn rar4_unicode_name_extracts_through_the_controlled_path() {
    let path = fixture("rar_unicode.rar");
    let name = "file1À۞.txt";
    let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    assert_eq!(names(&session), [name]);
    let entry = session.entries().next().unwrap();
    assert_eq!(entry.format(), RarFormat::Rar4);
    // The raw field keeps the legacy name, its NUL and the encoded Unicode stream.
    assert!(entry.raw_name().starts_with(b"file1\xb7?.txt\0"));
    let crc = entry.final_checks().unwrap().crc32.unwrap();

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("controlled");
    assert_eq!(controlled(&mut session, &out, |_| true), (1, 0, 0));
    let bytes = fs::read(out.join(name)).unwrap();
    assert_eq!(bytes, b"contents of file 1");
    assert_eq!(hash(&bytes), crc);
    assert_eq!(fs::read_dir(&out).unwrap().count(), 1);

    // With a diagnostic file the controlled run first proves no target aliases it, projecting the same name.
    let out = dir.path().join("diagnosed");
    let log = dir.path().join("log");
    let diagnostic = fs::OpenOptions::new().create(true).append(true).open(&log).unwrap();
    assert_eq!(controlled_with(&mut session, &out, Some(diagnostic), |_| true), (1, 0, 0));
    assert_eq!(fs::read(out.join(name)).unwrap(), bytes);

    // The uncontrolled selected path shares the same member executor.
    let out = dir.path().join("selected");
    let all = session.select(|_| true).unwrap();
    let summary = session.extract_selected(&all, &options(&out), RarDecodeLimits::default(), |_| {}).unwrap();
    assert_eq!((summary.files, summary.failed), (1, 0));
    assert_eq!(fs::read(out.join(name)).unwrap(), bytes);

    // And so does whole-archive extraction.
    let out = dir.path().join("bulk");
    let result = extract::run(&path, &options(&out), |_| {}).unwrap();
    assert!(result.errors.is_empty(), "{:?}", result.errors);
    assert_eq!(fs::read(out.join(name)).unwrap(), bytes);
}

#[test]
fn latest_winrar_recovery_record_header_opens_and_lists() {
    // A WinRAR 5 RAR4 archive with a recovery record: a service header named RR whose SubData ("Protect+...")
    // follows the name inside the header.
    let path = fixture("latest_winrar.rar");
    let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    assert_eq!(names(&session), ["1.txt", "2.txt"]);
    assert_eq!(extract::list(&path).unwrap().iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), ["1.txt", "2.txt"]);
    for (index, entry) in session.entries().enumerate() {
        assert_eq!(entry.format(), RarFormat::Rar4);
        assert!(!entry.is_directory());
        assert_eq!(entry.unpacked_size(), Some(5));
        // As UnRAR lists it: the first member starts the solid stream, the second goes on from it.
        assert_eq!(entry.solid(), index == 1);
        assert_eq!(rar4_unsupported(entry), None);
    }
    // 1.txt is a PPMd block; 2.txt goes on from its model.
    let all = session.select(|_| true).unwrap();
    let summary = session.test_selected(&all, RarDecodeLimits::default(), |_| {}).unwrap();
    assert_eq!((summary.files, summary.failed), (2, 0));
}

#[test]
fn unix_symlinks_owner_records_and_special_directory_modes_list_like_unrar() {
    // Made by rar on Unix: symbolic links, a backslash-separated name, a Unix owner service header (UOW, whose owner
    // and group names are SubData) after every member, and directories with mode 000, setuid and sticky bits.
    let path = fixture("dirlink_unix.rar");
    let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    let expected = ["emptydir/link", "file", "link", "emptydir", "nopermdir", "setuiddir", "stickydir"];
    assert_eq!(names(&session), expected);
    assert_eq!(extract::list(&path).unwrap().iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), expected);
    let listed: Vec<_> = session
        .entries()
        .map(|e| (e.name(), e.is_directory(), e.attributes(), e.host_os(), rar4_unsupported(e)))
        .collect();
    assert_eq!(
        listed,
        [
            ("emptydir/link", false, 0o120777, 1, Some("symbolic link")),
            ("file", false, 0o100644, 1, None),
            ("link", false, 0o120777, 1, Some("symbolic link")),
            ("emptydir", true, 0o040755, 1, None),
            ("nopermdir", true, 0o040000, 1, None),
            ("setuiddir", true, 0o044000, 1, None),
            ("stickydir", true, 0o041700, 1, None),
        ]
    );
    // The link targets are the stored payloads; the name keeps its raw backslash.
    let raw: Vec<_> = session.entries().map(|e| e.raw_name().to_vec()).collect();
    assert_eq!(raw[0], b"emptydir\\link");
    assert_eq!(session.entries().map(|e| e.unpacked_size()).collect::<Vec<_>>()[..3], [Some(4), Some(8), Some(8)]);

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    let crc = session.entries().nth(1).unwrap().final_checks().unwrap().crc32.unwrap();
    assert_eq!(controlled(&mut session, &out, |e| e.name() == "file"), (1, 0, 0));
    let bytes = fs::read(out.join("file")).unwrap();
    assert_eq!(bytes.len(), 8);
    assert_eq!(hash(&bytes), crc);

    // Symbolic links keep their typed refusal and create nothing.
    let links = dir.path().join("links");
    assert_eq!(controlled(&mut session, &links, |e| e.name().ends_with("link")), (0, 0, 2));
    assert!(!links.join("link").exists() && !links.join("emptydir").exists());

    let all = session.select(|e| !e.is_directory()).unwrap();
    let summary = session.test_selected(&all, RarDecodeLimits::default(), |_| {}).unwrap();
    assert_eq!((summary.files, summary.failed), (1, 2));
}

fn block(kind: u8, flags: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0, 0, kind];
    bytes.extend(flags.to_le_bytes());
    bytes.extend(((body.len() + 7) as u16).to_le_bytes());
    bytes.extend(body);
    let crc = hash(&bytes[2..]) as u16;
    bytes[..2].copy_from_slice(&crc.to_le_bytes());
    bytes
}

/// A stored file (0x74) or service (0x7a) header, with `trailing` after the name inside the header.
fn header(kind: u8, host: u8, name: &[u8], data: &[u8], mode: u32, trailing: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend((data.len() as u32).to_le_bytes());
    body.extend((data.len() as u32).to_le_bytes());
    body.push(host);
    body.extend(hash(data).to_le_bytes());
    body.extend(0x50221884u32.to_le_bytes());
    body.extend([20, 0x30]);
    body.extend((name.len() as u16).to_le_bytes());
    body.extend(mode.to_le_bytes());
    body.extend(name);
    body.extend(trailing);
    let mut bytes = block(kind, 0x8000, &body);
    bytes.extend(data);
    bytes
}

fn archive(blocks: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = b"Rar!\x1a\x07\0".to_vec();
    bytes.extend(block(0x73, 0, &[0; 6]));
    for block in blocks {
        bytes.extend(block);
    }
    bytes.extend(block(0x7b, 0x4000, &[]));
    bytes
}

#[test]
fn only_service_headers_carry_sub_data_and_their_crc_still_covers_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a.rar");
    let owner = header(0x7a, 3, b"UOW", b"", 0, b"owner\0group");
    let file = header(0x74, 3, b"file", b"payload", 0o100644, &[]);
    fs::write(&path, archive(&[file.clone(), owner.clone()])).unwrap();
    let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    assert_eq!(names(&session), ["file"]);
    let all = session.select(|_| true).unwrap();
    assert_eq!(session.test_selected(&all, RarDecodeLimits::default(), |_| {}).unwrap().files, 1);

    // A flipped SubData byte fails the header CRC.
    let mut corrupt = owner;
    let at = corrupt.len() - 2;
    corrupt[at] ^= 1;
    fs::write(&path, archive(&[file, corrupt])).unwrap();
    let error = RarSession::open(&path, None, RarSessionOptions::default()).err().unwrap();
    assert!(matches!(error.failure.as_ref(), RarFailure::Integrity { .. }), "{error:?}");

    // A file header has no SubData: bytes after its fields stay refused outside map walks.
    fs::write(&path, archive(&[header(0x74, 3, b"file", b"payload", 0o100644, b"extra")])).unwrap();
    let error = RarSession::open(&path, None, RarSessionOptions::default()).err().unwrap();
    assert!(matches!(error.failure.as_ref(), RarFailure::Unsupported(RarUnsupported::Rar4Feature(_))), "{error:?}");
}

#[test]
fn rar4_backslashes_separate_directories_on_every_host_and_stay_sanitized() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a.rar");
    for host in [2, 3] {
        let attributes = if host == 3 { 0o100644 } else { 0x20 };
        fs::write(
            &path,
            archive(&[
                header(0x74, host, b"dir\\sub\\file", b"payload", attributes, &[]),
                header(0x74, host, b"..\\escape", b"x", attributes, &[]),
                header(0x74, host, b"\\root", b"y", attributes, &[]),
            ]),
        )
        .unwrap();
        let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
        assert_eq!(names(&session), ["dir/sub/file", "../escape", "/root"]);
        assert_eq!(session.entries().next().unwrap().raw_name(), b"dir\\sub\\file");
        let out = dir.path().join(format!("out{host}"));
        assert_eq!(controlled(&mut session, &out, |_| true), (1, 0, 2));
        assert_eq!(fs::read(out.join("dir/sub/file")).unwrap(), b"payload");
        assert!(!dir.path().join("escape").exists() && !Path::new("/root/y").exists());
        assert_eq!(fs::read_dir(&out).unwrap().count(), 1);
    }
}
