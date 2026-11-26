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

//! A RAR 5.0 redirection in an archive whose file data is encrypted (`rar a -p`, headers in the clear) keeps its
//! target in the clear, so a wrong password would not stop it being placed. Every route places such a member only
//! when the password is verified for it by its check value, as UnRAR does: a wrong password fails it as a data
//! member's would, no password fails it as password required, and a member with no check value is refused.
#![cfg(unix)]

mod common;

use std::fs;
use std::path::Path;

use common::{FileSpec, archive};
use zipfast::error::RarFailure;
use zipfast::extract::{self, Mode, Options, Overwrite, RarOutcome};

const PASSWORD: &str = "zipfast-test-only";
const SALT: [u8; 16] = [0x53; 16];
const IV: [u8; 16] = [0x49; 16];
const KDF_COUNT: u8 = 4;
/// The check value and its checksum for PASSWORD, SALT and KDF_COUNT (as in tests/rar5_encrypted.rs).
const CHECK: [u8; 12] = [0x17, 0x41, 0x9a, 0xfa, 0xa6, 0x98, 0xfd, 0x50, 0xa8, 0x4b, 0x9b, 0x32];

fn options(dest: &Path, mode: Mode) -> Options {
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
        unsupported_filters: Default::default(),
        salvage_truncated_zip: false,
        unix_modes: Default::default(),
        backslashes: Default::default(),
    }
}

fn record(body: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::new();
    common::vint(body.len() as u64, &mut out);
    out.extend(body);
    out
}

/// A file encryption record (extra type 1), with the password check value or without one.
fn encryption(check: bool) -> Vec<u8> {
    let mut body = vec![1, 0, u8::from(check), KDF_COUNT]; // type, version, flags, exponent
    body.extend(SALT);
    body.extend(IV);
    if check {
        body.extend(CHECK);
    }
    record(body)
}

/// A redirection record (extra type 5): kind, flags, target.
fn redirection(kind: u64, target: &str) -> Vec<u8> {
    let mut body = Vec::new();
    for v in [5, kind, 0, target.len() as u64] {
        common::vint(v, &mut body);
    }
    body.extend(target.as_bytes());
    record(body)
}

/// An encrypted redirection member: its header carries the encryption record, its target is in the clear.
fn link<'a>(name: &'a str, kind: u64, target: &str, check: bool) -> FileSpec<'a> {
    let mut extra = encryption(check);
    extra.extend(redirection(kind, target));
    FileSpec { extra, unix_mode: Some(0o120777), no_crc: true, ..FileSpec::new(name, b"") }
}

/// Unix symlink, Windows symlink and junction members (a junction's target is relative here, so it stays inside),
/// then a plain file, so a refused link fails only itself.
fn write(dir: &Path, check: bool) -> std::path::PathBuf {
    let path = dir.join("links.rar");
    let files = [
        link("unix", 1, "plain", check),
        link("windows", 2, "plain", check),
        link("junction", 3, "plain", check),
        FileSpec::new("plain", b"plain"),
    ];
    fs::write(&path, archive(&files)).unwrap();
    path
}

const LINKS: [&str; 3] = ["unix", "windows", "junction"];

/// What became of each member, by archive position: "ok", "wrong", "required", "unverified" or another failure.
type Outcomes = Vec<String>;

fn classify(outcome: &RarOutcome) -> String {
    match outcome {
        RarOutcome::Failed(failure) => match failure.as_ref() {
            RarFailure::WrongPassword { .. } => "wrong".into(),
            RarFailure::PasswordRequired { .. } => "required".into(),
            RarFailure::EncryptedIntegrity { .. } => "unverified".into(),
            other => format!("{other:?}"),
        },
        _ => "ok".into(),
    }
}

fn expect(links: &str) -> Outcomes {
    vec![links.to_string(), links.to_string(), links.to_string(), "ok".to_string()]
}

fn assert_no_links(dest: &Path) {
    for name in LINKS {
        assert!(fs::symlink_metadata(dest.join(name)).is_err(), "{name} was placed");
    }
}

fn assert_links(dest: &Path) {
    for name in LINKS {
        assert_eq!(fs::read_link(dest.join(name)).unwrap(), Path::new("plain"), "{name}");
    }
}

/// The whole-archive runner, legacy summary and typed outcomes.
fn whole(arc: &Path, dest: &Path, mode: Mode, password: Option<&str>) -> Outcomes {
    let summary = extract::run_with_password(arc, &options(dest, mode), password, |_| {}).unwrap();
    let mut events = Vec::new();
    let typed = dest.with_extension("typed");
    extract::run_rar_with_outcomes(arc, &options(&typed, mode), password, |e| {
        events.push((e.entry.order, classify(&e.outcome)))
    })
    .unwrap();
    events.sort();
    let outcomes: Outcomes = events.into_iter().map(|e| e.1).collect();
    let failed = outcomes.iter().filter(|o| *o != "ok").count();
    assert_eq!(summary.errors.len(), failed, "{:?} {outcomes:?}", summary.errors);
    if mode == Mode::Extract {
        for name in LINKS {
            assert_eq!(
                fs::symlink_metadata(dest.join(name)).is_ok(),
                fs::symlink_metadata(typed.join(name)).is_ok(),
                "{name}: legacy and typed runs disagree"
            );
        }
    }
    outcomes
}

fn session(arc: &Path, dest: &Path, mode: Mode, password: Option<&str>) -> Outcomes {
    use zipfast::rar5::session::{RarDecodeLimits, RarSession, RarSessionOptions};
    let mut session = RarSession::open(arc, password, RarSessionOptions::default()).unwrap();
    let all = session.select(|_| true).unwrap();
    let mut events = Vec::new();
    let mut push = |e: &extract::RarEntryOutcome| events.push((e.entry.order, classify(&e.outcome)));
    match mode {
        Mode::Test => session.test_selected(&all, RarDecodeLimits::default(), &mut push),
        Mode::Extract => session.extract_selected(&all, &options(dest, mode), RarDecodeLimits::default(), &mut push),
    }
    .unwrap();
    events.sort();
    events.into_iter().map(|e| e.1).collect()
}

/// A progressive session over the sealed archive: each member's outcome, or the failure that stopped the session.
fn progressive(arc: &Path, dest: &Path, mode: Mode, password: Option<&str>) -> Result<Outcomes, String> {
    progressive_with(arc, options(dest, mode), password)
}

fn progressive_with(arc: &Path, extract: Options, password: Option<&str>) -> Result<Outcomes, String> {
    use std::task::{Context, Poll};
    use zipfast::progressive::*;
    let volume = (arc.file_name().unwrap().to_owned(), fs::read(arc).unwrap().into_boxed_slice());
    let mut opts = ProgressiveOptions::new(extract, arc.file_name().unwrap().to_owned());
    opts.set_password(password.map(str::to_owned)).unwrap();
    let mut session = ProgressiveSession::from_sealed_memory(vec![volume], opts).unwrap();
    let mut outcomes = Vec::new();
    loop {
        match session.poll_event(&mut Context::from_waker(std::task::Waker::noop())) {
            Poll::Pending => std::thread::yield_now(),
            Poll::Ready(Ok(None)) => return Ok(outcomes),
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { outcome, .. }))) => outcomes.push(match outcome {
                MemberOutcome::Verified(_) | MemberOutcome::Tested(_) => "ok".into(),
                _ => "other".into(),
            }),
            Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { failure, .. }))) => {
                return Err(format!("{:?}", failure.kind));
            }
            Poll::Ready(Ok(Some(_))) => {}
            Poll::Ready(Err(failure)) => return Err(format!("{:?}", failure.kind)),
        }
    }
}

#[test]
fn a_wrong_password_places_no_link_on_the_whole_archive_runner() {
    let tmp = tempfile::tempdir().unwrap();
    let arc = write(tmp.path(), true);
    for mode in [Mode::Test, Mode::Extract] {
        let dest = tmp.path().join(format!("out-{mode:?}"));
        assert_eq!(whole(&arc, &dest, mode, Some("not the password")), expect("wrong"), "{mode:?}");
        assert_no_links(&dest);
    }
}

#[test]
fn the_right_password_places_links_on_the_whole_archive_runner() {
    let tmp = tempfile::tempdir().unwrap();
    let arc = write(tmp.path(), true);
    for mode in [Mode::Test, Mode::Extract] {
        let dest = tmp.path().join(format!("out-{mode:?}"));
        assert_eq!(whole(&arc, &dest, mode, Some(PASSWORD)), expect("ok"), "{mode:?}");
        if mode == Mode::Extract {
            assert_links(&dest);
        }
    }
}

#[test]
fn no_password_is_password_required_on_the_whole_archive_runner() {
    let tmp = tempfile::tempdir().unwrap();
    let arc = write(tmp.path(), true);
    for mode in [Mode::Test, Mode::Extract] {
        let dest = tmp.path().join(format!("out-{mode:?}"));
        assert_eq!(whole(&arc, &dest, mode, None), expect("required"), "{mode:?}");
        assert_no_links(&dest);
    }
}

#[test]
fn a_wrong_password_places_no_link_on_a_rar_session() {
    let tmp = tempfile::tempdir().unwrap();
    let arc = write(tmp.path(), true);
    for mode in [Mode::Test, Mode::Extract] {
        let dest = tmp.path().join(format!("out-{mode:?}"));
        assert_eq!(session(&arc, &dest, mode, Some("not the password")), expect("wrong"), "{mode:?}");
        assert_no_links(&dest);
    }
}

#[test]
fn the_right_password_places_links_on_a_rar_session() {
    let tmp = tempfile::tempdir().unwrap();
    let arc = write(tmp.path(), true);
    for mode in [Mode::Test, Mode::Extract] {
        let dest = tmp.path().join(format!("out-{mode:?}"));
        assert_eq!(session(&arc, &dest, mode, Some(PASSWORD)), expect("ok"), "{mode:?}");
        if mode == Mode::Extract {
            assert_links(&dest);
        }
    }
}

#[test]
fn no_password_is_password_required_on_a_rar_session() {
    let tmp = tempfile::tempdir().unwrap();
    let arc = write(tmp.path(), true);
    for mode in [Mode::Test, Mode::Extract] {
        let dest = tmp.path().join(format!("out-{mode:?}"));
        assert_eq!(session(&arc, &dest, mode, None), expect("required"), "{mode:?}");
        assert_no_links(&dest);
    }
}

#[test]
fn a_wrong_password_places_no_link_on_a_progressive_session() {
    let tmp = tempfile::tempdir().unwrap();
    let arc = write(tmp.path(), true);
    for mode in [Mode::Test, Mode::Extract] {
        let dest = tmp.path().join(format!("out-{mode:?}"));
        let result = progressive(&arc, &dest, mode, Some("not the password"));
        assert_eq!(result, Err("WrongPassword".into()), "{mode:?}");
        assert_no_links(&dest);
    }
}

#[test]
fn the_right_password_places_links_on_a_progressive_session() {
    let tmp = tempfile::tempdir().unwrap();
    let arc = write(tmp.path(), true);
    for mode in [Mode::Test, Mode::Extract] {
        let dest = tmp.path().join(format!("out-{mode:?}"));
        assert_eq!(progressive(&arc, &dest, mode, Some(PASSWORD)), Ok(expect("ok")), "{mode:?}");
        if mode == Mode::Extract {
            assert_links(&dest);
        }
    }
}

#[test]
fn no_password_is_password_required_on_a_progressive_session() {
    let tmp = tempfile::tempdir().unwrap();
    let arc = write(tmp.path(), true);
    for mode in [Mode::Test, Mode::Extract] {
        let dest = tmp.path().join(format!("out-{mode:?}"));
        assert_eq!(progressive(&arc, &dest, mode, None), Err("PasswordRequired".into()), "{mode:?}");
        assert_no_links(&dest);
    }
}

/// With no check value the password can't be verified for a link, which has no data to check it against: it is
/// refused even with the right password.
#[test]
fn a_link_without_a_check_value_is_refused_on_every_route() {
    let tmp = tempfile::tempdir().unwrap();
    let arc = write(tmp.path(), false);
    for mode in [Mode::Test, Mode::Extract] {
        let dest = tmp.path().join(format!("whole-{mode:?}"));
        assert_eq!(whole(&arc, &dest, mode, Some(PASSWORD)), expect("unverified"), "{mode:?}");
        assert_no_links(&dest);
        let dest = tmp.path().join(format!("session-{mode:?}"));
        assert_eq!(session(&arc, &dest, mode, Some(PASSWORD)), expect("unverified"), "{mode:?}");
        assert_no_links(&dest);
        let dest = tmp.path().join(format!("progressive-{mode:?}"));
        let failure = progressive(&arc, &dest, mode, Some(PASSWORD)).unwrap_err();
        assert!(failure.contains("UnverifiableLinkPassword"), "{mode:?}: {failure}");
        assert_no_links(&dest);
    }
}

/// A hard link or file copy whose own header is encrypted is gated the same way, even when the earlier member it
/// takes is a plain file this run extracted.
#[test]
fn encrypted_hard_links_and_copies_are_gated_too() {
    let tmp = tempfile::tempdir().unwrap();
    let arc = tmp.path().join("hard.rar");
    let files = [FileSpec::new("plain", b"plain"), link("hard", 4, "plain", true), link("copy", 5, "plain", true)];
    fs::write(&arc, archive(&files)).unwrap();
    let both = |what: &str| vec!["ok".to_string(), what.to_string(), what.to_string()];
    for (password, expected) in [(Some("not the password"), "wrong"), (None, "required"), (Some(PASSWORD), "ok")] {
        let dest = tmp.path().join(format!("whole-{expected}"));
        assert_eq!(whole(&arc, &dest, Mode::Extract, password), both(expected));
        let dest2 = tmp.path().join(format!("session-{expected}"));
        assert_eq!(session(&arc, &dest2, Mode::Extract, password), both(expected));
        for dest in [dest, dest2] {
            for name in ["hard", "copy"] {
                let placed = fs::symlink_metadata(dest.join(name)).is_ok();
                assert_eq!(placed, expected == "ok", "{name} with {password:?}");
            }
            if expected == "ok" {
                assert_eq!(fs::read(dest.join("copy")).unwrap(), b"plain");
            }
        }
    }
}

/// Codex on #307: an older revision of an encrypted link with no check value is skipped by a progressive session as
/// any older revision is, not refused for its missing check value (which would end the session), so later members
/// still extract.
#[test]
fn an_older_revision_of_an_unverifiable_link_is_skipped_on_a_progressive_session() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("old.rar");
    let mut old = link("old", 1, "plain", false);
    old.extra.extend([3, 4, 0, 1]); // a version record (extra type 4): an older revision
    fs::write(&path, archive(&[old, FileSpec::new("plain", b"plain")])).unwrap();
    let dest = dir.path().join("out");
    let outcomes = progressive(&path, &dest, Mode::Extract, Some(PASSWORD)).expect("the session goes on");
    assert_eq!(outcomes.last().map(String::as_str), Some("ok"), "{outcomes:?}");
    assert_eq!(fs::read(dest.join("plain")).unwrap(), b"plain");
    assert!(fs::symlink_metadata(dest.join("old")).is_err(), "the older revision is not placed");
}

/// Codex on #307: with Overwrite::Skip and an existing target, an encrypted link with no check value is skipped (as
/// any member whose target exists is), not refused for its missing check value, so later members still extract.
#[test]
fn an_unverifiable_link_over_an_existing_target_is_skipped_on_a_progressive_session() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("skip.rar");
    fs::write(&path, archive(&[link("old", 1, "plain", false), FileSpec::new("plain", b"plain")])).unwrap();
    let dest = dir.path().join("out");
    fs::create_dir_all(&dest).unwrap();
    fs::write(dest.join("old"), b"kept").unwrap();
    let extract = Options { overwrite: zipfast::extract::Overwrite::Skip, ..options(&dest, Mode::Extract) };
    let outcomes = progressive_with(&path, extract, Some(PASSWORD)).expect("the session goes on");
    assert_eq!(outcomes.last().map(String::as_str), Some("ok"), "{outcomes:?}");
    assert_eq!(fs::read(dest.join("plain")).unwrap(), b"plain");
    assert_eq!(fs::read(dest.join("old")).unwrap(), b"kept", "the existing target is left alone");
}
