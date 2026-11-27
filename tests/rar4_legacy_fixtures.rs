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

mod common;

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
        seven_zip_strict: false,
        rar4_raw_names: false,
        folder_times: Default::default(),
        unix_modes: Default::default(),
        backslashes: Default::default(),
        hard_link_targets: Default::default(),
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
            ("emptydir/link", false, 0o120777, 1, None),
            ("file", false, 0o100644, 1, None),
            ("link", false, 0o120777, 1, None),
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

    // Symbolic links are created as UnRAR creates them on Unix: `link -> emptydir`, `emptydir/link -> link`.
    let links = dir.path().join("links");
    assert_eq!(controlled(&mut session, &links, |e| e.name().ends_with("link")), (2, 0, 0));
    assert_eq!(fs::read_link(links.join("link")).unwrap(), Path::new("emptydir"));
    assert_eq!(fs::read_link(links.join("emptydir/link")).unwrap(), Path::new("link"));

    let all = session.select(|e| !e.is_directory()).unwrap();
    let summary = session.test_selected(&all, RarDecodeLimits::default(), |_| {}).unwrap();
    assert_eq!((summary.files, summary.failed), (3, 0));
}

fn link_member(name: &[u8], target: &[u8]) -> Vec<u8> {
    header(0x74, 3, name, target, 0o120777, &[])
}

fn progressive(path: &Path, dest: &Path) -> Result<Vec<String>, zipfast::progressive::ProgressiveFailure> {
    progressive_with(path, options(dest))
}

fn progressive_with(path: &Path, options: Options) -> Result<Vec<String>, zipfast::progressive::ProgressiveFailure> {
    use std::task::{Context, Poll};
    use zipfast::progressive::*;
    let volume = (path.file_name().unwrap().to_owned(), fs::read(path).unwrap().into_boxed_slice());
    let opts = ProgressiveOptions::new(options, path.file_name().unwrap().to_owned());
    let mut session = ProgressiveSession::from_sealed_memory(vec![volume], opts).unwrap();
    let waker = std::task::Waker::noop();
    let mut outcomes = Vec::new();
    loop {
        match session.poll_event(&mut Context::from_waker(waker)) {
            Poll::Pending => std::thread::yield_now(),
            Poll::Ready(Ok(None)) => return Ok(outcomes),
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { outcome, .. }))) => outcomes.push(match outcome {
                MemberOutcome::Verified(_) => "verified".into(),
                MemberOutcome::Directory { .. } => "directory".into(),
                MemberOutcome::Skipped(reason) => format!("skipped {reason:?}"),
                _ => "other".into(),
            }),
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) => return Err(failure),
            Poll::Ready(Ok(Some(_))) => {}
            Poll::Ready(Err(failure)) => return Err(failure),
        }
    }
}

/// `dirlink_unix.rar` through every route: the links UnRAR creates, the file and the directories.
#[test]
fn every_route_creates_the_unix_links_unrar_creates() {
    let path = fixture("dirlink_unix.rar");
    let dir = tempfile::tempdir().unwrap();
    let check = |route: &str, out: &Path| {
        assert_eq!(fs::read_link(out.join("link")).unwrap(), Path::new("emptydir"), "{route}");
        assert_eq!(fs::read_link(out.join("emptydir/link")).unwrap(), Path::new("link"), "{route}");
        assert_eq!(fs::read(out.join("file")).unwrap().len(), 8, "{route}");
        for d in ["emptydir", "nopermdir", "setuiddir", "stickydir"] {
            assert!(fs::symlink_metadata(out.join(d)).unwrap().is_dir(), "{route}: {d}");
        }
    };
    let out = dir.path().join("run");
    let summary = extract::run(&path, &options(&out), |_| {}).unwrap();
    assert!(summary.errors.is_empty(), "{:?}", summary.errors);
    check("run", &out);
    // a second run over the same output leaves the links alone: a link in the way is never written through
    let again = extract::run(&path, &options(&out), |_| {}).unwrap();
    assert_eq!(again.errors.len(), 2, "{:?}", again.errors);
    check("run again", &out);

    let out = dir.path().join("selected");
    let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    let all = session.select(|_| true).unwrap();
    let summary = session.extract_selected(&all, &options(&out), RarDecodeLimits::default(), |_| {}).unwrap();
    assert_eq!((summary.files, summary.failed), (3, 0));
    check("selected", &out);

    let out = dir.path().join("progressive");
    let outcomes = progressive(&path, &out).unwrap();
    assert_eq!(outcomes.iter().filter(|o| *o == "verified").count(), 3, "{outcomes:?}");
    check("progressive", &out);
}

/// A link whose target is absolute or climbs out of the destination is refused on every route, and nothing is
/// created for it; a link that stays inside is created beside it.
#[test]
fn links_leading_out_of_the_destination_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    for (n, target) in
        [&b"/etc/passwd"[..], b"../outside", b"a/../../outside", b"sub/../x", b""].into_iter().enumerate()
    {
        let path = dir.path().join(format!("{n}.rar"));
        fs::write(&path, archive(&[link_member(b"bad", target), link_member(b"good", b"sub/x")])).unwrap();
        let label = String::from_utf8_lossy(target);

        let out = dir.path().join(format!("{n}-run"));
        let mut failures = Vec::new();
        extract::run_rar_with_outcomes(&path, &options(&out), None, |o: &RarEntryOutcome| {
            if let extract::RarOutcome::Failed(failure) = &o.outcome {
                failures.push((o.entry.name.clone(), format!("{failure:?}")));
            }
        })
        .unwrap();
        assert!(
            failures.len() == 1 && failures[0].0 == "bad" && failures[0].1.contains("LinkTarget"),
            "{label}: {failures:?}"
        );
        assert!(fs::symlink_metadata(out.join("bad")).is_err(), "{label}");
        assert_eq!(fs::read_link(out.join("good")).unwrap(), Path::new("sub/x"));

        let out = dir.path().join(format!("{n}-selected"));
        let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
        let all = session.select(|_| true).unwrap();
        let mut failures = Vec::new();
        let summary = session
            .extract_selected(&all, &options(&out), RarDecodeLimits::default(), |o| {
                if let extract::RarOutcome::Failed(failure) = &o.outcome {
                    failures.push(format!("{failure:?}"));
                }
            })
            .unwrap();
        assert_eq!((summary.files, summary.failed), (1, 1), "{label}");
        assert!(failures[0].contains("LinkTarget"), "{label}: {failures:?}");
        assert!(fs::symlink_metadata(out.join("bad")).is_err(), "{label}");
        assert_eq!(fs::read_link(out.join("good")).unwrap(), Path::new("sub/x"));

        // a progressive session stops at an unsafe path, as it does for an unsafe name
        let out = dir.path().join(format!("{n}-progressive"));
        let failure = progressive(&path, &out).unwrap_err();
        assert!(matches!(failure.kind, zipfast::progressive::FailureKind::UnsafePath), "{label}: {failure:?}");
        assert!(fs::symlink_metadata(out.join("bad")).is_err(), "{label}");
    }
}

/// Flattened, a link is checked where it goes: `a/b/esc -> ../../outside` would land as `esc -> ../../outside`, so
/// every route refuses it.
#[test]
fn a_flattened_link_is_checked_where_it_lands() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a.rar");
    fs::write(&path, archive(&[link_member(b"a/b/esc", b"../../outside")])).unwrap();
    let flat = |dest: &Path| Options { flatten: true, ..options(dest) };

    let out = dir.path().join("run");
    let summary = extract::run(&path, &flat(&out), |_| {}).unwrap();
    assert_eq!(summary.errors.len(), 1, "{:?}", summary.errors);
    assert!(fs::symlink_metadata(out.join("esc")).is_err());

    let out = dir.path().join("selected");
    let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    let all = session.select(|_| true).unwrap();
    let summary = session.extract_selected(&all, &flat(&out), RarDecodeLimits::default(), |_| {}).unwrap();
    assert_eq!((summary.files, summary.failed), (0, 1));
    assert!(fs::symlink_metadata(out.join("esc")).is_err());

    let out = dir.path().join("progressive");
    let volume = (path.file_name().unwrap().to_owned(), fs::read(&path).unwrap().into_boxed_slice());
    let opts = zipfast::progressive::ProgressiveOptions::new(flat(&out), path.file_name().unwrap().to_owned());
    let mut session = zipfast::progressive::ProgressiveSession::from_sealed_memory(vec![volume], opts).unwrap();
    let waker = std::task::Waker::noop();
    let failure = loop {
        match session.poll_event(&mut std::task::Context::from_waker(waker)) {
            std::task::Poll::Ready(Err(failure)) => break failure,
            std::task::Poll::Ready(Ok(None)) => panic!("the flattened link was created"),
            _ => {}
        }
    };
    assert!(matches!(failure.kind, zipfast::progressive::FailureKind::UnsafePath), "{failure:?}");
    assert!(fs::symlink_metadata(out.join("esc")).is_err());
}

/// A member below a link the archive created is not written through it.
#[test]
fn a_member_is_never_written_through_a_link_from_the_archive() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a.rar");
    let inside = dir.path().join("out/real");
    fs::create_dir_all(&inside).unwrap();
    fs::write(
        &path,
        archive(&[
            link_member(b"alias", b"real"),
            header(0x74, 3, b"alias/file", b"data", 0o100644, &[]),
            header(0x74, 3, b"after", b"after", 0o100644, &[]),
        ]),
    )
    .unwrap();
    let out = dir.path().join("out");
    // only that member fails in the whole-archive run too: a link among its folders is in the way
    let summary = extract::run(&path, &options(&out), |_| {}).unwrap();
    assert_eq!(summary.errors, ["alias/file: a symlink is in the way"]);
    assert_eq!(fs::read_link(out.join("alias")).unwrap(), Path::new("real"));
    assert!(!inside.join("file").exists());
    assert_eq!(fs::read(out.join("after")).unwrap(), b"after");

    let out = dir.path().join("selected/out");
    fs::create_dir_all(out.join("real")).unwrap();
    let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    let all = session.select(|_| true).unwrap();
    let summary = session.extract_selected(&all, &options(&out), RarDecodeLimits::default(), |_| {}).unwrap();
    assert_eq!((summary.files, summary.failed), (2, 1));
    assert!(!out.join("real/file").exists());
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

fn unrar_reference(name: &str) -> Vec<u8> {
    fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rar4-unrar").join(name)).unwrap()
}

/// `corrupted.rar`: a solid archive whose legacy names hold bytes that aren't UTF-8 and whose stream breaks after
/// its first file. The catalogue opens, lists every name as UnRAR does (`unrar lb`), and testing reports each
/// member as `unrar t` does: the first file and every directory are OK, every later file fails.
#[test]
fn a_damaged_solid_archive_with_unmapped_names_is_catalogued_and_reported_per_member() {
    let path = fixture("corrupted.rar");
    let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    let listing = String::from_utf8(unrar_reference("in_rarinfo_corrupted.rar.lb")).unwrap();
    let unrar: Vec<&str> = listing.lines().take_while(|l| !l.starts_with("status=")).collect();
    assert_eq!(names(&session), unrar);

    // `unrar t`: "<name> - checksum error" for each failed file
    let tested = String::from_utf8(unrar_reference("in_rarinfo_corrupted.rar.t")).unwrap();
    let failed: Vec<&str> =
        tested.lines().filter_map(|l| l.strip_suffix(" - checksum error")).map(str::trim_end).collect();
    assert_eq!(failed.len(), 29);
    let all = session.select(|_| true).unwrap();
    let mut got_failed = Vec::new();
    let mut verified = Vec::new();
    session
        .test_selected(&all, RarDecodeLimits::default(), |o| match &o.outcome {
            extract::RarOutcome::Failed(_) => got_failed.push(o.entry.name.clone()),
            extract::RarOutcome::Verified { .. } => verified.push(o.entry.name.clone()),
            _ => {}
        })
        .unwrap();
    assert_eq!(got_failed, failed);
    assert_eq!(verified, [unrar[0]]);

    // Extraction creates every directory UnRAR creates and goes on past each failure. The one intact file is
    // written under its private-use mapping (UnRAR writes its raw bytes); the rest of the stream is broken.
    let dir = tempfile::tempdir().unwrap();
    let intact = unrar[0].replace('\u{fffe}', "");
    let out = dir.path().join("run");
    let summary = extract::run_rar_with_outcomes(&path, &options(&out), None, |_| {}).unwrap();
    assert_eq!((summary.files, summary.failed), (1, 29));
    let out_selected = dir.path().join("selected");
    let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    let all = session.select(|_| true).unwrap();
    let summary = session.extract_selected(&all, &options(&out_selected), RarDecodeLimits::default(), |_| {}).unwrap();
    assert_eq!((summary.files, summary.failed), (1, 29));
    let unrar_dirs: Vec<&str> =
        unrar.iter().copied().filter(|n| !n.contains('\u{fffe}') && !failed.contains(n)).collect();
    assert_eq!(unrar_dirs.len() as u64, summary.dirs);
    for out in [&out, &out_selected] {
        for name in &unrar_dirs {
            assert!(out.join(name).is_dir(), "{name}");
        }
        let files: Vec<String> = files_under(out).into_iter().map(|(name, _)| name).collect();
        assert_eq!(files, std::slice::from_ref(&intact));
    }
}

fn files_under(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in fs::read_dir(&d).into_iter().flatten().flatten() {
            if entry.file_type().unwrap().is_dir() {
                stack.push(entry.path());
            } else {
                let rel = entry.path().strip_prefix(dir).unwrap().to_string_lossy().into_owned();
                out.push((rel, fs::read(entry.path()).unwrap()));
            }
        }
    }
    out.sort();
    out
}

/// Legacy names holding bytes that aren't UTF-8 (OEM/ANSI, from a Unix or a Windows host) extract under their
/// private-use mapping, one file per distinct raw name, through every route. A name spelling such a private-use
/// character in valid UTF-8 can't collide with them: it is refused.
#[test]
fn raw_legacy_names_extract_one_to_one_on_every_route() {
    let dir = tempfile::tempdir().unwrap();
    for host in [3u8, 2] {
        let path = dir.path().join(format!("raw-{host}.rar"));
        let members = [
            header(0x74, host, b"caf\xe9.txt", b"e-acute", 0o100644, &[]),
            header(0x74, host, b"caf\xe8.txt", b"e-grave", 0o100644, &[]),
            header(0x74, host, b"d\xe9j\xe0\\vu.txt", b"nested", 0o100644, &[]),
            header(0x74, host, "caf\u{e0e9}.txt".as_bytes(), b"impostor", 0o100644, &[]),
        ];
        fs::write(&path, archive(&members)).unwrap();
        let want = vec![
            ("caf\u{e0e8}.txt".to_owned(), b"e-grave".to_vec()),
            ("caf\u{e0e9}.txt".to_owned(), b"e-acute".to_vec()),
            ("d\u{e0e9}j\u{e0e0}/vu.txt".to_owned(), b"nested".to_vec()),
        ];
        let refused = |name: &str, failure: &str| {
            name.contains('\u{e0e9}') && !name.contains('\u{fffe}') && failure.contains("NameEncoding")
        };

        let out = dir.path().join(format!("{host}-run"));
        let mut failures = Vec::new();
        extract::run_rar_with_outcomes(&path, &options(&out), None, |o: &RarEntryOutcome| {
            if let extract::RarOutcome::Failed(f) = &o.outcome {
                failures.push((o.entry.name.clone(), format!("{f:?}")));
            }
        })
        .unwrap();
        assert!(failures.len() == 1 && refused(&failures[0].0, &failures[0].1), "{host}: {failures:?}");
        assert_eq!(files_under(&out), want, "{host}: run");

        let out = dir.path().join(format!("{host}-selected"));
        let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
        let all = session.select(|_| true).unwrap();
        let summary = session.extract_selected(&all, &options(&out), RarDecodeLimits::default(), |_| {}).unwrap();
        assert_eq!((summary.files, summary.failed), (3, 1), "{host}");
        assert_eq!(files_under(&out), want, "{host}: selected");

        let out = dir.path().join(format!("{host}-controlled"));
        assert_eq!(controlled(&mut session, &out, |_| true), (3, 0, 1), "{host}");
        assert_eq!(files_under(&out), want, "{host}: controlled");

        // a progressive session writes the first three, then stops at the name it can't write
        let out = dir.path().join(format!("{host}-progressive"));
        let failure = progressive(&path, &out).unwrap_err();
        assert!(format!("{failure:?}").contains("NameEncoding"), "{host}: {failure:?}");
        assert_eq!(files_under(&out), want, "{host}: progressive");
        // without the impostor it finishes
        let path = dir.path().join(format!("raw-{host}-clean.rar"));
        fs::write(&path, archive(&members[..3])).unwrap();
        let out = dir.path().join(format!("{host}-progressive-clean"));
        assert_eq!(progressive(&path, &out).unwrap(), ["verified"; 3]);
        assert_eq!(files_under(&out), want, "{host}: progressive");
    }
}

/// A name that stores U+FFFE itself would pass for the mark of a mapped name: it is refused, and a name with
/// U+FFFD next to it is written as it is, so the two never meet.
#[test]
fn a_stored_mark_is_refused_and_never_merges_with_a_replacement_character() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("marks.rar");
    let members = [
        header(0x74, 3, "a\u{fffe}".as_bytes(), b"mark", 0o100644, &[]),
        header(0x74, 3, "a\u{fffd}".as_bytes(), b"replacement", 0o100644, &[]),
    ];
    fs::write(&path, archive(&members)).unwrap();
    let out = dir.path().join("out");
    let mut failures = Vec::new();
    extract::run_rar_with_outcomes(&path, &options(&out), None, |o: &RarEntryOutcome| {
        if let extract::RarOutcome::Failed(f) = &o.outcome {
            failures.push(format!("{f:?}"));
        }
    })
    .unwrap();
    assert!(failures.len() == 1 && failures[0].contains("NameEncoding"), "{failures:?}");
    assert_eq!(files_under(&out), [("a\u{fffd}".to_owned(), b"replacement".to_vec())]);
}

/// A folder the run made is never trusted past a rename that moved it aside under another spelling of its name: on
/// APFS `A/B` (or `e` with a combining accent) is `a/b` (or `é`), so the link `A/B -> .` takes the folder's place and
/// `a/b/l -> ../../outside` would sit one folder higher than its name says.
#[test]
fn a_moved_folder_is_never_trusted_under_another_spelling() {
    let tmp = tempfile::tempdir().unwrap();
    for (nfd, upper, lower) in [(false, "A", "a"), (true, "e\u{301}", "\u{e9}")] {
        if !common::folds_names(tmp.path(), nfd) {
            eprintln!("skipped: this file system keeps {upper:?} and {lower:?} apart");
            continue;
        }
        let alias = if nfd { format!("{upper}/b") } else { format!("{upper}/B") };
        let case = tmp.path().join(format!("{nfd}"));
        fs::create_dir_all(case.join("outside")).unwrap();
        let path = case.join("a.rar");
        let blocks = [
            header(0x74, 3, format!("{lower}/b/x").as_bytes(), b"x", 0o100644, &[]),
            link_member(alias.as_bytes(), b"."),
            link_member(format!("{lower}/b/l").as_bytes(), b"../../outside"),
        ];
        fs::write(&path, archive(&blocks)).unwrap();
        for threads in [1, 4] {
            let dest = case.join(format!("out{threads}"));
            let opts = Options {
                overwrite: Overwrite::RenameExisting(zipfast::extract::RenameStyle::Underscore),
                threads: Some(threads),
                ..options(&dest)
            };
            let _ = extract::run(&path, &opts, |_| {});
            assert_eq!(common::links_leading_out(&dest), Vec::<PathBuf>::new(), "nfd={nfd} threads={threads}");
        }
    }
}

/// A link whose target names a member with a raw non-UTF-8 name points at that member where it was written (its
/// name mapped to U+E080..U+E0FF), on every route, rather than at the raw bytes.
#[test]
fn link_targets_are_mapped_like_raw_member_names() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("raw.rar");
    fs::write(&path, archive(&[header(0x74, 3, b"caf\xe9", b"data", 0o100644, &[]), link_member(b"link", b"caf\xe9")]))
        .unwrap();
    let written = "caf\u{E0E9}";
    let check = |route: &str, out: &Path| {
        assert_eq!(fs::read(out.join(written)).unwrap(), b"data", "{route}");
        assert_eq!(fs::read_link(out.join("link")).unwrap(), Path::new(written), "{route}");
        assert_eq!(fs::read(out.join("link")).unwrap(), b"data", "{route}: the link resolves to the member");
    };
    let out = dir.path().join("run");
    let summary = extract::run(&path, &options(&out), |_| {}).unwrap();
    assert!(summary.errors.is_empty(), "{:?}", summary.errors);
    check("run", &out);

    let out = dir.path().join("selected");
    let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    let all = session.select(|_| true).unwrap();
    let summary = session.extract_selected(&all, &options(&out), RarDecodeLimits::default(), |_| {}).unwrap();
    assert_eq!((summary.files, summary.failed), (2, 0));
    check("selected", &out);

    let out = dir.path().join("progressive");
    let outcomes = progressive(&path, &out).unwrap();
    assert_eq!(outcomes.iter().filter(|o| *o == "verified").count(), 2, "{outcomes:?}");
    check("progressive", &out);
}

/// `Options::rar4_raw_names` on a file system that takes the bytes: the member is written under `caf\xe9`, and the
/// link's target names it the same way, so the link still resolves, as UnRAR 7.30 and 7-Zip 26.06 make it on Linux.
#[test]
#[cfg(target_os = "linux")]
fn link_targets_follow_raw_member_names_when_asked() {
    use std::os::unix::ffi::OsStrExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("raw.rar");
    fs::write(&path, archive(&[header(0x74, 3, b"caf\xe9", b"data", 0o100644, &[]), link_member(b"link", b"caf\xe9")]))
        .unwrap();
    let raw = std::ffi::OsStr::from_bytes(b"caf\xe9");
    let out = dir.path().join("run");
    let summary = extract::run(&path, &Options { rar4_raw_names: true, ..options(&out) }, |_| {}).unwrap();
    assert!(summary.errors.is_empty(), "{:?}", summary.errors);
    assert_eq!(fs::read(out.join(raw)).unwrap(), b"data");
    assert_eq!(fs::read_link(out.join("link")).unwrap(), Path::new(raw));
    assert_eq!(fs::read(out.join("link")).unwrap(), b"data", "the link resolves to the member");
}

/// A link already in the destination that leads out (`alias -> ../outside`): an archive link whose target passes
/// through it (`new -> alias/secret`, or `new -> alias`) is refused on every route, while a chain through a link
/// the same run placed is still made.
#[test]
fn link_targets_through_preexisting_links_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("outside")).unwrap();
    for (n, target) in [&b"alias/secret"[..], b"alias", b"./sub/../alias/x"].into_iter().enumerate() {
        let path = dir.path().join(format!("{n}.rar"));
        let blocks = [link_member(b"new", target), link_member(b"mine", b"sub"), link_member(b"chain", b"mine/x")];
        fs::write(&path, archive(&blocks)).unwrap();
        let label = String::from_utf8_lossy(target);
        let prepare = |route: &str| {
            let out = dir.path().join(format!("{n}-{route}"));
            fs::create_dir_all(out.join("sub")).unwrap();
            std::os::unix::fs::symlink("../outside", out.join("alias")).unwrap();
            out
        };
        let check = |route: &str, out: &Path| {
            assert!(fs::symlink_metadata(out.join("new")).is_err(), "{label} {route}");
            assert_eq!(fs::read_link(out.join("chain")).unwrap(), Path::new("mine/x"), "{label} {route}");
        };

        let out = prepare("run");
        let summary = extract::run(&path, &options(&out), |_| {}).unwrap();
        assert_eq!(summary.errors.len(), 1, "{label}: {:?}", summary.errors);
        check("run", &out);

        let out = prepare("selected");
        let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
        let all = session.select(|_| true).unwrap();
        let summary = session.extract_selected(&all, &options(&out), RarDecodeLimits::default(), |_| {}).unwrap();
        assert_eq!((summary.files, summary.failed), (2, 1), "{label}");
        check("selected", &out);

        let out = prepare("progressive");
        let failure = progressive(&path, &out).unwrap_err();
        assert!(matches!(failure.kind, zipfast::progressive::FailureKind::UnsafePath), "{label}: {failure:?}");
        assert!(fs::symlink_metadata(out.join("new")).is_err(), "{label}");
    }
}

/// A link already in the destination that stays inside (`d -> sub`) is followed by default, as UnRAR 7.30 does:
/// `f -> d/file.txt` is made, and so are `l -> d` and `m -> l/file.txt`. Under `PreexistingLinks::Refuse` (7-Zip's
/// rule) `f` and `l` are refused on every route; `m` is then made, with nothing at `l` to pass through.
#[test]
fn preexisting_links_inside_the_destination_follow_the_policy() {
    use zipfast::extract::PreexistingLinks;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a.rar");
    let blocks = [link_member(b"f", b"d/file.txt"), link_member(b"l", b"d"), link_member(b"m", b"l/file.txt")];
    fs::write(&path, archive(&blocks)).unwrap();
    for policy in [PreexistingLinks::FollowInside, PreexistingLinks::Refuse] {
        let follow = policy == PreexistingLinks::FollowInside;
        let prepare = |route: &str| {
            let out = dir.path().join(format!("{policy:?}-{route}"));
            fs::create_dir_all(out.join("sub")).unwrap();
            fs::write(out.join("sub/file.txt"), b"pre").unwrap();
            std::os::unix::fs::symlink("sub", out.join("d")).unwrap();
            (out.clone(), Options { preexisting_links: policy, ..options(&out) })
        };
        let check = |route: &str, out: &Path| {
            assert_eq!(fs::read_link(out.join("m")).unwrap(), Path::new("l/file.txt"), "{policy:?} {route}");
            for name in ["f", "l"] {
                assert_eq!(fs::symlink_metadata(out.join(name)).is_ok(), follow, "{policy:?} {route} {name}");
            }
            if follow {
                assert_eq!(fs::read(out.join("f")).unwrap(), b"pre");
                assert_eq!(fs::read(out.join("m")).unwrap(), b"pre");
            }
        };

        let (out, opts) = prepare("run");
        let summary = extract::run(&path, &opts, |_| {}).unwrap();
        assert_eq!(summary.errors.len(), if follow { 0 } else { 2 }, "{policy:?}: {:?}", summary.errors);
        check("run", &out);

        let (out, opts) = prepare("selected");
        let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
        let all = session.select(|_| true).unwrap();
        let summary = session.extract_selected(&all, &opts, RarDecodeLimits::default(), |_| {}).unwrap();
        assert_eq!(summary.failed, if follow { 0 } else { 2 }, "{policy:?}");
        check("selected", &out);

        let (out, opts) = prepare("progressive");
        let outcome = progressive_with(&path, opts);
        if follow {
            outcome.unwrap();
            check("progressive", &out);
        } else {
            let failure = outcome.unwrap_err();
            assert!(matches!(failure.kind, zipfast::progressive::FailureKind::UnsafePath), "{failure:?}");
            assert!(fs::symlink_metadata(out.join("f")).is_err());
        }
    }
}

/// prybar's P8: `dirlink_unix.rar` flattened (`e -y`) puts two links at `link`. With `replace_placed_links` the second
/// replaces the first, which this run placed, as UnRAR 7.30 does, on the whole-archive, selected and controlled routes;
/// without it the second is refused (7-Zip 26.06) and the first stays.
#[test]
fn a_flattened_second_link_replaces_the_first_only_when_asked() {
    let path = fixture("dirlink_unix.rar");
    let dir = tempfile::tempdir().unwrap();
    for replace in [true, false] {
        let flat = |dest: &Path| Options { flatten: true, replace_placed_links: replace, ..options(dest) };
        // `emptydir/link -> link` lands first at `link`, then `link -> emptydir`
        let want = if replace { "emptydir" } else { "link" };
        let out = dir.path().join(format!("run-{replace}"));
        let summary = extract::run(&path, &flat(&out), |_| {}).unwrap();
        assert_eq!(summary.errors.len(), usize::from(!replace), "run {replace}: {:?}", summary.errors);
        assert_eq!(fs::read_link(out.join("link")).unwrap(), Path::new(want), "run {replace}");

        let out = dir.path().join(format!("selected-{replace}"));
        let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
        let all = session.select(|_| true).unwrap();
        let summary = session.extract_selected(&all, &flat(&out), RarDecodeLimits::default(), |_| {}).unwrap();
        assert_eq!(summary.failed, u64::from(!replace), "selected {replace}: {summary:?}");
        assert_eq!(fs::read_link(out.join("link")).unwrap(), Path::new(want), "selected {replace}");
        assert_eq!(fs::read(out.join("file")).unwrap().len(), 8, "selected {replace}");

        // prybar's UnRAR mode runs the controlled route: the same decision there (-y replaces)
        let out = dir.path().join(format!("controlled-{replace}"));
        let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
        let selected = session.select(|_| true).unwrap();
        let mut control = RarExtractControl::new(None, RarOverwriteMode::Always, RarExtractControlLimits::default());
        let report = session.extract_selected_controlled(
            &selected,
            &flat(&out),
            RarDecodeLimits::default(),
            &mut control,
            &mut Replace,
        );
        let summary = report.finish().outcome.unwrap();
        assert_eq!(summary.failed, u64::from(!replace), "controlled {replace}: {summary:?}");
        assert_eq!(fs::read_link(out.join("link")).unwrap(), Path::new(want), "controlled {replace}");
    }
}

/// Codex on #291: a regular file landing on a link this run placed (`a -> x`, then a file `a`) replaces it through
/// `extract_selected` and `extract_selected_controlled` too, when asked; publication carries the link's identity, so
/// only that link is replaced. Without the option both refuse it.
#[test]
fn a_file_over_a_link_this_run_placed_replaces_it_when_asked() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a.rar");
    let file = header(0x74, 3, b"a", b"data", 0o100644, &[]);
    fs::write(&path, archive(&[link_member(b"a", b"x"), file])).unwrap();
    for replace in [true, false] {
        let opts = |dest: &Path| Options { replace_placed_links: replace, ..options(dest) };
        let out = dir.path().join(format!("selected-{replace}"));
        let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
        let all = session.select(|_| true).unwrap();
        let summary = session.extract_selected(&all, &opts(&out), RarDecodeLimits::default(), |_| {}).unwrap();
        assert_eq!(summary.failed, u64::from(!replace), "{replace}: {summary:?}");
        if replace {
            assert_eq!(fs::read(out.join("a")).unwrap(), b"data");
        } else {
            assert_eq!(fs::read_link(out.join("a")).unwrap(), Path::new("x"));
        }

        let out = dir.path().join(format!("controlled-{replace}"));
        let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
        let selected = session.select(|_| true).unwrap();
        let mut control = RarExtractControl::new(None, RarOverwriteMode::Always, RarExtractControlLimits::default());
        let report = session.extract_selected_controlled(
            &selected,
            &opts(&out),
            RarDecodeLimits::default(),
            &mut control,
            &mut Replace,
        );
        let summary = report.finish().outcome.unwrap();
        assert_eq!(summary.failed, u64::from(!replace), "controlled {replace}: {summary:?}");
        if replace {
            assert_eq!(fs::read(out.join("a")).unwrap(), b"data", "controlled");
        } else {
            assert_eq!(fs::read_link(out.join("a")).unwrap(), Path::new("x"), "controlled");
        }
    }
}
