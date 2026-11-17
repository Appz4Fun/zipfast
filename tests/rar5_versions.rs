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
