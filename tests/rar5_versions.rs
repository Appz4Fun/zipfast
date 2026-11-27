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

//! RAR 5.0 older file revisions (`rar -ver`): skipped by default, as UnRAR skips them without `-ver`; listed with
//! their version number; extracted as `name;N` on request, as UnRAR's `x -ver` writes them.

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use common::{FileSpec, archive};
use zipfast::extract::{self, MemberFilter, Mode, Options, Overwrite, RarOutcome, RarSkipReason};
use zipfast::rar5::session::{RarDecodeLimits, RarSession, RarSessionOptions};

/// A version record (extra type 4): flags 0, then the version.
fn version(v: u8) -> Vec<u8> {
    vec![3, 4, 0, v]
}

/// `notes.txt` at revisions 2 and 1 and current, then `zero.txt` with a version record holding 0.
fn archive_path(dir: &Path) -> PathBuf {
    let path = dir.join("versions.rar");
    fs::write(
        &path,
        archive(&[
            FileSpec { extra: version(2), ..FileSpec::new("notes.txt", b"second") },
            FileSpec { extra: version(1), ..FileSpec::new("notes.txt", b"first") },
            FileSpec::new("notes.txt", b"current"),
            FileSpec { extra: version(0), ..FileSpec::new("zero.txt", b"zero") },
        ]),
    )
    .unwrap();
    path
}

fn options(dest: &Path, mode: Mode, select: Option<MemberFilter>) -> Options {
    Options {
        mode,
        dest: dest.to_path_buf(),
        overwrite: Overwrite::Always,
        flatten: false,
        threads: Some(1),
        protected_paths: Default::default(),
        parallel_min: None,
        select,
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
    }
}

/// The files under `dir`, by name, with their contents.
fn files(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            (e.file_name().into_string().unwrap(), fs::read(e.path()).unwrap())
        })
        .collect();
    out.sort();
    out
}

fn named(list: &[(&str, &[u8])]) -> Vec<(String, Vec<u8>)> {
    list.iter().map(|(n, d)| (n.to_string(), d.to_vec())).collect()
}

#[test]
fn listings_carry_the_version_and_unrars_name() {
    let tmp = tempfile::tempdir().unwrap();
    let entries = extract::list(&archive_path(tmp.path())).unwrap();
    let got: Vec<_> = entries.iter().map(|e| (e.name.as_str(), e.version, e.display_name().into_owned())).collect();
    assert_eq!(
        got,
        [
            ("notes.txt", Some(2), "notes.txt;2".to_owned()),
            ("notes.txt", Some(1), "notes.txt;1".to_owned()),
            ("notes.txt", None, "notes.txt".to_owned()),
            // a version of 0 is no version, as UnRAR reads it
            ("zero.txt", None, "zero.txt".to_owned()),
        ]
    );
    let session = RarSession::open(&archive_path(tmp.path()), None, RarSessionOptions::default()).unwrap();
    let members: Vec<_> = session.entries().map(|m| (m.version(), m.display_name().into_owned())).collect();
    assert_eq!(
        members,
        [
            (Some(2), "notes.txt;2".to_owned()),
            (Some(1), "notes.txt;1".to_owned()),
            (None, "notes.txt".to_owned()),
            (None, "zero.txt".to_owned()),
        ]
    );
}

#[test]
fn extraction_skips_revisions_unless_asked_and_then_writes_them_as_name_semicolon_n() {
    let tmp = tempfile::tempdir().unwrap();
    let arc = archive_path(tmp.path());
    // default: the revisions are skipped, the record holding 0 is an ordinary file
    let out = tmp.path().join("default");
    let s = extract::run(&arc, &options(&out, Mode::Extract, None), |_| {}).unwrap();
    assert!(s.errors.is_empty(), "{:?}", s.errors);
    assert_eq!(files(&out), named(&[("notes.txt", b"current"), ("zero.txt", b"zero")]));
    let mut skipped = Vec::new();
    extract::run_rar_with_outcomes(&arc, &options(&tmp.path().join("typed"), Mode::Extract, None), None, |o| {
        if let RarOutcome::Skipped(reason) = o.outcome {
            skipped.push(reason);
        }
    })
    .unwrap();
    assert_eq!(skipped, [RarSkipReason::OlderVersion(2), RarSkipReason::OlderVersion(1)]);
    // with_versions: every revision, under UnRAR's `-ver` names
    let out = tmp.path().join("all");
    let s =
        extract::run(&arc, &options(&out, Mode::Extract, Some(MemberFilter::all().with_versions())), |_| {}).unwrap();
    assert!(s.errors.is_empty(), "{:?}", s.errors);
    assert_eq!(
        files(&out),
        named(&[
            ("notes.txt", b"current"),
            ("notes.txt;1", b"first"),
            ("notes.txt;2", b"second"),
            ("zero.txt", b"zero")
        ])
    );
    // the filter sees each revision's number and picks among them
    let out = tmp.path().join("two");
    let pick = MemberFilter::new(|m| m.version.is_none_or(|v| v == 2)).with_versions();
    extract::run(&arc, &options(&out, Mode::Extract, Some(pick)), |_| {}).unwrap();
    assert_eq!(files(&out), named(&[("notes.txt", b"current"), ("notes.txt;2", b"second"), ("zero.txt", b"zero")]));
    // testing checks every member, as before
    let s = extract::run(&arc, &options(tmp.path(), Mode::Test, None), |_| {}).unwrap();
    assert_eq!((s.files, s.errors.len()), (4, 0));
}

#[test]
fn rar_session_extracts_selected_revisions_on_request() {
    let tmp = tempfile::tempdir().unwrap();
    let arc = archive_path(tmp.path());
    let mut session = RarSession::open(&arc, None, RarSessionOptions::default()).unwrap();
    let all = session.select(|_| true).unwrap();
    let out = tmp.path().join("default");
    let s = session.extract_selected(&all, &options(&out, Mode::Extract, None), RarDecodeLimits::default(), |_| {});
    assert_eq!(s.unwrap().skipped, 2);
    assert_eq!(files(&out), named(&[("notes.txt", b"current"), ("zero.txt", b"zero")]));
    let revisions = session.select(|m| m.version().is_some()).unwrap().with_versions();
    assert!(revisions.takes_versions());
    let out = tmp.path().join("revisions");
    let s = session
        .extract_selected(&revisions, &options(&out, Mode::Extract, None), RarDecodeLimits::default(), |_| {})
        .unwrap();
    assert_eq!((s.files, s.skipped, s.failed), (2, 0, 0));
    assert_eq!(files(&out), named(&[("notes.txt;1", b"first"), ("notes.txt;2", b"second")]));
}

/// A folder kept as an older revision is skipped by a progressive session, which never takes revisions, as every
/// other route skips it by default: no `dir;1` (nor `dir`) is made for it.
#[test]
fn a_progressive_session_skips_a_versioned_folder() {
    use std::task::{Context, Poll};
    use zipfast::progressive::*;
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("folder.rar");
    fs::write(
        &path,
        archive(&[
            FileSpec { dir: true, unix_mode: Some(0o755), extra: version(1), ..FileSpec::new("old", b"") },
            FileSpec { extra: version(1), ..FileSpec::new("notes.txt", b"first") },
            FileSpec::new("notes.txt", b"current"),
        ]),
    )
    .unwrap();
    let out = tmp.path().join("out");
    let volume = (std::ffi::OsString::from("folder.rar"), fs::read(&path).unwrap().into_boxed_slice());
    let opts = ProgressiveOptions::new(options(&out, Mode::Extract, None), "folder.rar".into());
    let mut session = ProgressiveSession::from_sealed_memory(vec![volume], opts).unwrap();
    let mut outcomes = Vec::new();
    loop {
        match session.poll_event(&mut Context::from_waker(std::task::Waker::noop())) {
            Poll::Pending => std::thread::yield_now(),
            Poll::Ready(Ok(None)) => break,
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { outcome, .. }))) => outcomes.push(match outcome {
                MemberOutcome::Verified(_) => "verified".to_owned(),
                MemberOutcome::Directory { .. } => "directory".to_owned(),
                MemberOutcome::Skipped(reason) => format!("skipped {reason:?}"),
                _ => "other".to_owned(),
            }),
            Poll::Ready(Ok(Some(_))) => {}
            Poll::Ready(Err(e)) => panic!("{e:?}"),
        }
    }
    assert_eq!(outcomes, ["skipped OlderVersion(1)", "skipped OlderVersion(1)", "verified"]);
    assert_eq!(files(&out), named(&[("notes.txt", b"current")]));
}

/// Every route names a revision `name;N` exactly when it includes revisions, testing as extracting: a hard link
/// to `notes.txt` after only a revision of it passes a test run that leaves revisions out (where the revision is
/// `notes.txt`) and fails one that takes them (where it is `notes.txt;1`), on the whole-archive run and on
/// `RarSession` alike.
#[test]
fn test_runs_name_revisions_as_extraction_does_on_every_route() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("link.rar");
    let mut redirect = Vec::new();
    for v in [5u64, 4, 0, 9] {
        common::vint(v, &mut redirect);
    }
    redirect.extend(b"notes.txt");
    let mut extra = Vec::new();
    common::vint(redirect.len() as u64, &mut extra);
    extra.extend(redirect);
    fs::write(
        &path,
        archive(&[
            FileSpec { extra: version(1), ..FileSpec::new("notes.txt", b"first") },
            FileSpec { extra, unix_mode: Some(0o120777), ..FileSpec::new("h", b"") },
        ]),
    )
    .unwrap();
    for versions in [false, true] {
        let select = versions.then(|| MemberFilter::all().with_versions());
        let mut failed = Vec::new();
        extract::run_rar_with_outcomes(&path, &options(tmp.path(), Mode::Test, select), None, |o| {
            if let RarOutcome::Failed(_) = o.outcome {
                failed.push(o.entry.order);
            }
        })
        .unwrap();
        let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
        let mut all = session.select(|_| true).unwrap();
        if versions {
            all = all.with_versions();
        }
        let mut session_failed = Vec::new();
        session
            .test_selected(&all, RarDecodeLimits::default(), |o| {
                if let RarOutcome::Failed(_) = o.outcome {
                    session_failed.push(o.entry.order);
                }
            })
            .unwrap();
        let expected: &[u64] = if versions { &[1] } else { &[] };
        assert_eq!((failed.as_slice(), session_failed.as_slice()), (expected, expected), "versions={versions}");
    }
}
