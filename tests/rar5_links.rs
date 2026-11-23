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

//! RAR 5.0 redirections: Unix and Windows symbolic links and junctions placed as symbolic links within the
//! destination, hard links and file copies of files extracted earlier in the run.
#![cfg(unix)]

mod common;

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use common::{FileSpec, SIG, archive, file_block, main_block_flags};
use zipfast::extract::{self, Mode, Options, Overwrite, RenameStyle};
use zipfast::rar5::Redirection;

fn options(dest: &Path, mode: Mode, overwrite: Overwrite, threads: usize) -> Options {
    Options {
        mode,
        dest: dest.to_path_buf(),
        overwrite,
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
    }
}

/// A RAR 5.0 redirection record (extra type 5): kind, flags, target.
fn redirection(kind: u64, target: &str) -> Vec<u8> {
    let mut body = Vec::new();
    for v in [5, kind, 0, target.len() as u64] {
        common::vint(v, &mut body);
    }
    body.extend(target.as_bytes());
    let mut extra = Vec::new();
    common::vint(body.len() as u64, &mut extra);
    extra.extend(body);
    extra
}

fn link<'a>(name: &'a str, kind: u64, target: &str) -> FileSpec<'a> {
    FileSpec { extra: redirection(kind, target), unix_mode: Some(0o120777), ..FileSpec::new(name, b"") }
}

fn dir(name: &str) -> FileSpec<'_> {
    FileSpec { dir: true, unix_mode: Some(0o755), ..FileSpec::new(name, b"") }
}

fn write(dir: &Path, files: &[FileSpec<'_>]) -> std::path::PathBuf {
    let path = dir.join("links.rar");
    fs::write(&path, archive(files)).unwrap();
    path
}

fn ino(path: &Path) -> u64 {
    fs::symlink_metadata(path).unwrap().ino()
}

#[test]
fn every_redirection_kind_extracts_on_one_and_several_threads() {
    for threads in [1, 4] {
        let tmp = tempfile::tempdir().unwrap();
        let arc = write(
            tmp.path(),
            &[
                dir("d"),
                FileSpec::new("d/f", b"data"),
                link("unix", 1, "d/f"),
                link("windows", 2, "d\\f"),
                link("d/up", 1, "../d/f"),
                link("junction", 3, "\\??\\C:\\Windows"),
                link("hard", 4, "d/f"),
                link("copy", 5, "d/f"),
                FileSpec::new("after", b"after"),
            ],
        );
        let dest = tmp.path().join("out");
        let s = extract::run(&arc, &options(&dest, Mode::Extract, Overwrite::Always, threads), |_| {}).unwrap();
        assert_eq!(s.errors.len(), 1, "threads={threads}: only the junction fails: {:?}", s.errors);
        assert!(s.errors[0].contains("junction") && s.errors[0].contains("leads out"), "{:?}", s.errors);
        assert_eq!(fs::read_link(dest.join("unix")).unwrap(), Path::new("d/f"));
        assert_eq!(fs::read_link(dest.join("windows")).unwrap(), Path::new("d/f"));
        assert_eq!(fs::read_link(dest.join("d/up")).unwrap(), Path::new("../d/f"));
        assert!(fs::symlink_metadata(dest.join("junction")).is_err());
        assert_eq!(ino(&dest.join("hard")), ino(&dest.join("d/f")), "threads={threads}");
        assert_eq!(fs::read(dest.join("copy")).unwrap(), b"data");
        assert_ne!(ino(&dest.join("copy")), ino(&dest.join("d/f")));
        assert!(fs::symlink_metadata(dest.join("copy")).unwrap().file_type().is_file());
        assert_eq!(fs::read(dest.join("after")).unwrap(), b"after");
    }
}

#[test]
fn escaping_and_unknown_targets_fail_only_their_member() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = tmp.path().join("outside");
    fs::write(&outside, b"OUTSIDE").unwrap();
    let dest = tmp.path().join("out");
    fs::create_dir(&dest).unwrap();
    // a file that was there before the run is never a hard link's target
    fs::write(dest.join("before"), b"BEFORE").unwrap();
    let arc = write(
        tmp.path(),
        &[
            link("up", 1, "../outside"),
            link("abs", 1, "/etc/passwd"),
            link("mid", 1, "x/../../outside"),
            link("winup", 2, "..\\outside"),
            link("hardup", 4, "../outside"),
            link("hardabs", 4, "/etc/passwd"),
            link("hardbefore", 4, "before"),
            link("hardlater", 4, "later"),
            link("copyup", 5, "../outside"),
            link("copybefore", 5, "before"),
            FileSpec::new("later", b"later"),
        ],
    );
    for mode in [Mode::Test, Mode::Extract] {
        let s = extract::run(&arc, &options(&dest, mode, Overwrite::Always, 1), |_| {}).unwrap();
        assert_eq!(s.errors.len(), 10, "{mode:?}: {:?}", s.errors);
        assert_eq!(s.files, 1, "{mode:?}");
    }
    for name in ["up", "abs", "mid", "winup", "hardup", "hardabs", "hardbefore", "hardlater", "copyup", "copybefore"] {
        assert!(fs::symlink_metadata(dest.join(name)).is_err(), "{name}");
    }
    assert_eq!(fs::read(&outside).unwrap(), b"OUTSIDE");
    assert_eq!(fs::metadata(&outside).unwrap().nlink(), 1);
    assert_eq!(fs::metadata(dest.join("before")).unwrap().nlink(), 1);
}

#[test]
fn rename_new_links_to_where_the_file_landed() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("out");
    fs::create_dir(&dest).unwrap();
    fs::write(dest.join("a.txt"), b"SECRET").unwrap();
    let arc = write(tmp.path(), &[FileSpec::new("a.txt", b"new"), link("h", 4, "a.txt"), link("c", 5, "a.txt")]);
    for threads in [1, 4] {
        let _ = fs::remove_file(dest.join("a_1.txt"));
        let _ = fs::remove_file(dest.join("h"));
        let _ = fs::remove_file(dest.join("c"));
        let opts = options(&dest, Mode::Extract, Overwrite::RenameNew(RenameStyle::Underscore), threads);
        let s = extract::run(&arc, &opts, |_| {}).unwrap();
        assert!(s.errors.is_empty(), "{:?}", s.errors);
        assert_eq!(fs::read(dest.join("a.txt")).unwrap(), b"SECRET");
        assert_eq!(ino(&dest.join("h")), ino(&dest.join("a_1.txt")), "threads={threads}");
        assert_eq!(fs::read(dest.join("c")).unwrap(), b"new");
        assert_eq!(fs::metadata(dest.join("a.txt")).unwrap().nlink(), 1);
    }
}

#[test]
fn rename_existing_never_links_through_a_symlink_that_replaced_a_folder() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = tmp.path().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("f"), b"OUTSIDE").unwrap();
    let dest = tmp.path().join("out");
    fs::create_dir(&dest).unwrap();
    std::os::unix::fs::symlink("../outside", dest.join("ext")).unwrap();
    let arc = write(
        tmp.path(),
        &[dir("d"), FileSpec::new("d/f", b"mine"), link("d", 1, "ext"), link("h", 4, "d/f"), link("c", 5, "d/f")],
    );
    let opts = options(&dest, Mode::Extract, Overwrite::RenameExisting(RenameStyle::Underscore), 1);
    let s = extract::run(&arc, &opts, |_| {}).unwrap();
    assert_eq!(fs::read_link(dest.join("d")).unwrap(), Path::new("ext"));
    assert_eq!(fs::read(dest.join("d_1/f")).unwrap(), b"mine");
    // refused as files no longer recorded, before any device and inode check: the link replaced the folder, so
    // every record under it went (#189)
    let why = "the hard link's target is not a file extracted earlier in this run";
    assert_eq!(s.errors, [format!("h: {why}"), format!("c: {why}")]);
    assert!(fs::symlink_metadata(dest.join("h")).is_err() && fs::symlink_metadata(dest.join("c")).is_err());
    assert_eq!(fs::metadata(outside.join("f")).unwrap().nlink(), 1);
}

#[test]
fn a_changed_target_fails_only_its_member_and_leaves_no_reserved_file() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("out");
    fs::create_dir(&dest).unwrap();
    fs::write(dest.join("h"), b"was here").unwrap();
    // the file member `d` moves the folder holding `d/f` aside: `d/f` is no longer the file extracted
    let arc = write(
        tmp.path(),
        &[
            dir("d"),
            FileSpec::new("d/f", b"mine"),
            FileSpec::new("d", b"file"),
            link("h", 4, "d/f"),
            FileSpec::new("z", b"z"),
        ],
    );
    let opts = options(&dest, Mode::Extract, Overwrite::RenameExisting(RenameStyle::Underscore), 1);
    let s = extract::run(&arc, &opts, |_| {}).unwrap();
    assert_eq!(s.errors.len(), 1, "{:?}", s.errors);
    assert!(s.errors[0].contains("no longer"), "{:?}", s.errors);
    assert_eq!(fs::read(dest.join("z")).unwrap(), b"z");
    assert_eq!(fs::read(dest.join("h_1")).unwrap(), b"was here");
    assert!(fs::symlink_metadata(dest.join("h")).is_err(), "the reserved name is left behind");
}

#[test]
fn a_solid_stream_keeps_its_history_past_a_link() {
    use zipfast::rar5::testenc::{self, Op};
    let tmp = tempfile::tempdir().unwrap();
    let start = testenc::block(&[Op::Lit(b'A'), Op::Lit(b'A'), Op::Lit(b'A')], true, true);
    let dependent = testenc::block(&[Op::Match(3, 3)], true, true);
    let aaa = crc32fast::hash(b"AAA");
    let mut bytes = SIG.to_vec();
    bytes.extend(main_block_flags(false, None, true));
    let files = [
        (FileSpec { method: 3, size: Some(3), ..FileSpec::new("start", &start) }, aaa),
        // a link carrying a method, as WinRAR writes them in a compressed archive
        (FileSpec { method: 3, solid: true, ..link("ln", 1, "start") }, 0),
        (FileSpec { method: 3, size: Some(3), solid: true, ..FileSpec::new("dependent", &dependent) }, aaa),
        (FileSpec { method: 3, solid: true, ..link("hl", 4, "dependent") }, 0),
    ];
    for (spec, crc) in &files {
        bytes.extend(file_block(spec, spec.data, *crc, false, false));
    }
    bytes.extend(common::end_block(false));
    let arc = tmp.path().join("solid.rar");
    fs::write(&arc, bytes).unwrap();
    let dest = tmp.path().join("out");
    let s = extract::run(&arc, &options(&dest, Mode::Extract, Overwrite::Always, 1), |_| {}).unwrap();
    assert!(s.errors.is_empty(), "{:?}", s.errors);
    assert_eq!(fs::read(dest.join("dependent")).unwrap(), b"AAA");
    assert_eq!(fs::read_link(dest.join("ln")).unwrap(), Path::new("start"));
    assert_eq!(ino(&dest.join("hl")), ino(&dest.join("dependent")));
}

#[test]
fn listings_carry_raw_targets() {
    let tmp = tempfile::tempdir().unwrap();
    let arc = write(tmp.path(), &[link("w", 2, "d\\f"), link("h", 4, "d/f"), link("up", 1, "../x")]);
    let entries = extract::list(&arc).unwrap();
    let links: Vec<_> = entries.iter().map(|e| e.link.clone()).collect();
    assert_eq!(
        links,
        [
            Some(Redirection::WindowsSymlink("d\\f".into())),
            Some(Redirection::HardLink("d/f".into())),
            Some(Redirection::UnixSymlink("../x".into())),
        ]
    );
}

/// The archive of every kind, with an escape of each, as (name, whether it fails).
fn mixed(dir: &Path) -> (std::path::PathBuf, Vec<(&'static str, bool)>) {
    let members = [
        ("d", false),
        ("d/f", false),
        ("unix", false),
        ("windows", false),
        ("junction", true),
        ("up", true),
        ("hard", false),
        ("hardup", true),
        ("hardlater", true),
        ("copy", false),
        ("later", false),
    ];
    let arc = write(
        dir,
        &[
            self::dir("d"),
            FileSpec::new("d/f", b"data"),
            link("unix", 1, "d/f"),
            link("windows", 2, "d\\f"),
            link("junction", 3, "\\??\\C:\\Windows"),
            link("up", 1, "../outside"),
            link("hard", 4, "d/f"),
            link("hardup", 4, "../outside"),
            link("hardlater", 4, "later"),
            link("copy", 5, "d/f"),
            FileSpec::new("later", b"later"),
        ],
    );
    (arc, members.to_vec())
}

fn assert_mixed_tree(dest: &Path) {
    assert_eq!(fs::read_link(dest.join("unix")).unwrap(), Path::new("d/f"));
    assert_eq!(fs::read_link(dest.join("windows")).unwrap(), Path::new("d/f"));
    assert_eq!(ino(&dest.join("hard")), ino(&dest.join("d/f")));
    assert_eq!(fs::read(dest.join("copy")).unwrap(), b"data");
    assert_ne!(ino(&dest.join("copy")), ino(&dest.join("d/f")));
    assert_eq!(fs::read(dest.join("later")).unwrap(), b"later");
    for name in ["junction", "up", "hardup", "hardlater"] {
        assert!(fs::symlink_metadata(dest.join(name)).is_err(), "{name}");
    }
}

/// Which members failed, by archive position, from typed outcomes.
fn failed(events: &[(u64, bool, String)]) -> Vec<u64> {
    let mut out: Vec<_> = events.iter().filter(|e| e.1).map(|e| e.0).collect();
    out.sort();
    out
}

/// A typed outcome kept: its position, whether it failed, and how it reads.
fn event(e: &zipfast::extract::RarEntryOutcome) -> (u64, bool, String) {
    (e.entry.order, matches!(e.outcome, zipfast::extract::RarOutcome::Failed(_)), format!("{e:?}"))
}

fn expected_failures(members: &[(&str, bool)]) -> Vec<u64> {
    members.iter().enumerate().filter(|(_, (_, fails))| *fails).map(|(i, _)| i as u64).collect()
}

#[test]
fn the_typed_run_and_rar_session_agree_with_the_legacy_run() {
    use zipfast::rar5::session::{RarDecodeLimits, RarSession, RarSessionOptions};
    let tmp = tempfile::tempdir().unwrap();
    let (arc, members) = mixed(tmp.path());
    let expected = expected_failures(&members);
    for mode in [Mode::Test, Mode::Extract] {
        // typed run
        let dest = tmp.path().join(format!("typed-{mode:?}"));
        let mut events = Vec::new();
        let opts = options(&dest, mode, Overwrite::Always, 1);
        let s = extract::run_rar_with_outcomes(&arc, &opts, None, |e| events.push(event(e))).unwrap();
        assert_eq!(failed(&events), expected, "typed {mode:?}: {events:?}");
        assert_eq!(s.failed, expected.len() as u64);
        if mode == Mode::Extract {
            assert_mixed_tree(&dest);
        }
        // RarSession
        let dest = tmp.path().join(format!("session-{mode:?}"));
        let mut session = RarSession::open(&arc, None, RarSessionOptions::default()).unwrap();
        let all = session.select(|_| true).unwrap();
        let mut events = Vec::new();
        let s = match mode {
            Mode::Test => session.test_selected(&all, RarDecodeLimits::default(), |e| events.push(event(e))),
            Mode::Extract => session.extract_selected(
                &all,
                &options(&dest, mode, Overwrite::Always, 1),
                RarDecodeLimits::default(),
                |e| events.push(event(e)),
            ),
        }
        .unwrap();
        assert_eq!(failed(&events), expected, "session {mode:?}: {events:?}");
        assert_eq!(s.failed, expected.len() as u64);
        if mode == Mode::Extract {
            assert_mixed_tree(&dest);
        }
    }
}

#[test]
fn rar_session_hard_links_follow_renames_and_never_a_replaced_folder() {
    use zipfast::rar5::session::{RarDecodeLimits, RarSession, RarSessionOptions};
    let extract = |arc: &Path, dest: &Path, overwrite| {
        let mut session = RarSession::open(arc, None, RarSessionOptions::default()).unwrap();
        let all = session.select(|_| true).unwrap();
        let mut events = Vec::new();
        let opts = options(dest, Mode::Extract, overwrite, 1);
        session.extract_selected(&all, &opts, RarDecodeLimits::default(), |e| events.push(event(e))).unwrap();
        failed(&events)
    };
    // RenameNew: the hard link takes the file that landed, never the one that was there
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("out");
    fs::create_dir(&dest).unwrap();
    fs::write(dest.join("a.txt"), b"SECRET").unwrap();
    let arc = write(tmp.path(), &[FileSpec::new("a.txt", b"new"), link("h", 4, "a.txt")]);
    assert!(extract(&arc, &dest, Overwrite::RenameNew(RenameStyle::Underscore)).is_empty());
    assert_eq!(fs::read(dest.join("a.txt")).unwrap(), b"SECRET");
    assert_eq!(ino(&dest.join("h")), ino(&dest.join("a_1.txt")));
    // RenameExisting: a symlink that replaced the folder is never followed
    let tmp = tempfile::tempdir().unwrap();
    let outside = tmp.path().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("f"), b"OUTSIDE").unwrap();
    let dest = tmp.path().join("out");
    fs::create_dir(&dest).unwrap();
    std::os::unix::fs::symlink("../outside", dest.join("ext")).unwrap();
    let arc = write(
        tmp.path(),
        &[dir("d"), FileSpec::new("d/f", b"mine"), link("d", 1, "ext"), link("h", 4, "d/f"), FileSpec::new("z", b"z")],
    );
    assert_eq!(extract(&arc, &dest, Overwrite::RenameExisting(RenameStyle::Underscore)), [3]);
    assert_eq!(fs::read_link(dest.join("d")).unwrap(), Path::new("ext"));
    assert_eq!(fs::read(dest.join("z")).unwrap(), b"z");
    assert_eq!(fs::metadata(outside.join("f")).unwrap().nlink(), 1);
}

/// A progressive session over one sealed volume: each member's outcome, or the failure that stopped it.
fn progressive(arc: &Path, dest: &Path, mode: Mode) -> Result<Vec<String>, zipfast::progressive::ProgressiveFailure> {
    use std::task::{Context, Poll};
    use zipfast::progressive::*;
    let volume = (arc.file_name().unwrap().to_owned(), fs::read(arc).unwrap().into_boxed_slice());
    let opts = ProgressiveOptions::new(options(dest, mode, Overwrite::Always, 1), arc.file_name().unwrap().to_owned());
    let mut session = ProgressiveSession::from_sealed_memory(vec![volume], opts).unwrap();
    let mut outcomes = Vec::new();
    loop {
        match session.poll_event(&mut Context::from_waker(std::task::Waker::noop())) {
            Poll::Pending => std::thread::yield_now(),
            Poll::Ready(Ok(None)) => return Ok(outcomes),
            Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { outcome, .. }))) => outcomes.push(match outcome {
                MemberOutcome::Verified(_) => "verified".into(),
                MemberOutcome::Tested(_) => "tested".into(),
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

#[test]
fn a_progressive_session_places_every_kind_and_stops_at_an_escape() {
    let tmp = tempfile::tempdir().unwrap();
    let good = [
        dir("d"),
        FileSpec::new("d/f", b"data"),
        link("unix", 1, "d/f"),
        link("windows", 2, "d\\f"),
        link("hard", 4, "d/f"),
        link("copy", 5, "d/f"),
        FileSpec::new("later", b"later"),
    ];
    let arc = write(tmp.path(), &good);
    for mode in [Mode::Test, Mode::Extract] {
        let dest = tmp.path().join(format!("good-{mode:?}"));
        let outcomes = progressive(&arc, &dest, mode).unwrap();
        let done = if mode == Mode::Test { "tested" } else { "verified" };
        assert_eq!(outcomes.iter().filter(|o| *o == done).count(), 6, "{mode:?}: {outcomes:?}");
        if mode == Mode::Extract {
            assert_eq!(fs::read_link(dest.join("unix")).unwrap(), Path::new("d/f"));
            assert_eq!(fs::read_link(dest.join("windows")).unwrap(), Path::new("d/f"));
            assert_eq!(ino(&dest.join("hard")), ino(&dest.join("d/f")));
            assert_eq!(fs::read(dest.join("copy")).unwrap(), b"data");
            assert_ne!(ino(&dest.join("copy")), ino(&dest.join("d/f")));
        }
    }
    let outside = tmp.path().join("outside");
    fs::write(&outside, b"OUTSIDE").unwrap();
    for (n, bad) in [
        link("bad", 1, "../outside"),
        link("bad", 2, "..\\outside"),
        link("bad", 3, "\\??\\C:\\Windows"),
        link("bad", 4, "../outside"),
        link("bad", 4, "later"),
        link("bad", 5, "before"),
    ]
    .into_iter()
    .enumerate()
    {
        let arc = tmp.path().join(format!("bad{n}.rar"));
        fs::write(&arc, archive(&[FileSpec::new("f", b"f"), bad, FileSpec::new("later", b"later")])).unwrap();
        for mode in [Mode::Test, Mode::Extract] {
            let dest = tmp.path().join(format!("bad{n}-{mode:?}"));
            fs::create_dir(&dest).unwrap();
            fs::write(dest.join("before"), b"BEFORE").unwrap();
            let failure = progressive(&arc, &dest, mode).unwrap_err();
            assert!(matches!(failure.kind, zipfast::progressive::FailureKind::UnsafePath), "{n} {mode:?}: {failure:?}");
            assert!(fs::symlink_metadata(dest.join("bad")).is_err(), "{n} {mode:?}");
        }
    }
    assert_eq!(fs::metadata(&outside).unwrap().nlink(), 1);
}

/// A folder the run made or checked is never trusted past a rename that moved it aside under another spelling of
/// its name: `A/B` (or `e` with a combining accent) is `a/b` (or `é`) on APFS, so the link `A/B -> .` takes the
/// folder's place and `a/b/l -> ../../outside` would then sit one folder higher than its name says.
#[test]
fn a_moved_folder_is_never_trusted_under_another_spelling() {
    let tmp = tempfile::tempdir().unwrap();
    for (nfd, upper, lower) in [(false, "A", "a"), (true, "e\u{301}", "\u{e9}")] {
        if !common::folds_names(tmp.path(), nfd) {
            eprintln!("skipped: this file system keeps {upper:?} and {lower:?} apart");
            continue;
        }
        // the folder `lower/b` under its other spelling
        let alias = if nfd { format!("{upper}/b") } else { format!("{upper}/B") };
        let (dir_ab, file, escape) = (format!("{lower}/b"), format!("{lower}/b/x"), format!("{lower}/b/l"));
        for threads in [1, 4] {
            let case = tmp.path().join(format!("{nfd}-{threads}"));
            fs::create_dir_all(case.join("outside")).unwrap();
            let arc = write(
                &case,
                &[
                    self::dir(lower),
                    self::dir(&dir_ab),
                    FileSpec::new(&file, b"x"),
                    link(&alias, 1, "."),
                    link(&escape, 1, "../../outside"),
                ],
            );
            let dest = case.join("out");
            let opts = options(&dest, Mode::Extract, Overwrite::RenameExisting(RenameStyle::Underscore), threads);
            let _ = extract::run(&arc, &opts, |_| {});
            assert_eq!(
                common::links_leading_out(&dest),
                Vec::<std::path::PathBuf>::new(),
                "nfd={nfd} threads={threads}"
            );
        }
    }
}

/// A symbolic link takes the archived modification time on itself (as `lutimes`), never on what it points to, on
/// the legacy run, the typed run and RarSession, whether it lands where nothing was or replaces a file.
#[test]
fn symbolic_links_take_the_archived_time_without_following() {
    use zipfast::rar5::session::{RarDecodeLimits, RarSession, RarSessionOptions};
    let tmp = tempfile::tempdir().unwrap();
    let file = FileSpec { mtime: Some(1_500_000_000), ..FileSpec::new("f", b"data") };
    let arc = write(tmp.path(), &[file, link("sym", 1, "f"), link("d/sym", 1, "../f")]);
    let check = |dest: &Path, how: &str| {
        for name in ["sym", "d/sym"] {
            let m = fs::symlink_metadata(dest.join(name)).unwrap();
            assert!(m.file_type().is_symlink(), "{how} {name}");
            assert_eq!(m.mtime(), 1_700_000_000, "{how} {name}: the link's own time");
        }
        assert_eq!(fs::metadata(dest.join("f")).unwrap().mtime(), 1_500_000_000, "{how}: the target keeps its own");
    };
    for incumbent in [false, true] {
        let prepare = |name: &str| {
            let dest = tmp.path().join(format!("{name}-{incumbent}"));
            if incumbent {
                fs::create_dir_all(dest.join("d")).unwrap();
                fs::write(dest.join("sym"), b"old").unwrap();
                fs::write(dest.join("d/sym"), b"old").unwrap();
            }
            dest
        };
        let dest = prepare("legacy");
        let s = extract::run(&arc, &options(&dest, Mode::Extract, Overwrite::Always, 1), |_| {}).unwrap();
        assert!(s.errors.is_empty(), "{:?}", s.errors);
        check(&dest, "legacy");
        let dest = prepare("typed");
        extract::run_rar_with_outcomes(&arc, &options(&dest, Mode::Extract, Overwrite::Always, 1), None, |_| {})
            .unwrap();
        check(&dest, "typed");
        let dest = prepare("session");
        let mut session = RarSession::open(&arc, None, RarSessionOptions::default()).unwrap();
        let all = session.select(|_| true).unwrap();
        let opts = options(&dest, Mode::Extract, Overwrite::Always, 1);
        let s = session.extract_selected(&all, &opts, RarDecodeLimits::default(), |_| {}).unwrap();
        assert_eq!(s.failed, 0);
        check(&dest, "session");
    }
}

/// A member under a link placed earlier in the run (a folder link, or one a rename mode swapped in for a moved
/// folder) fails alone: nothing is written or made through the link, the members after it still extract on the
/// legacy and typed runs, and the run counts that one failure.
#[test]
fn a_member_under_a_linked_folder_fails_only_itself() {
    let cases: [(&str, Vec<FileSpec<'_>>, Overwrite, &str); 4] = [
        (
            "file",
            vec![FileSpec::new("a", b"a"), dir("real"), link("ln", 1, "real"), FileSpec::new("ln/evil", b"e")],
            Overwrite::Always,
            "ln/evil",
        ),
        (
            "folder",
            vec![FileSpec::new("a", b"a"), dir("real"), link("ln", 1, "real"), dir("ln/sub")],
            Overwrite::Always,
            "ln/sub",
        ),
        (
            "link",
            vec![FileSpec::new("a", b"a"), dir("real"), link("ln", 1, "real"), link("ln/l", 1, "x")],
            Overwrite::Always,
            "ln/l",
        ),
        (
            "moved",
            vec![dir("real"), FileSpec::new("real/a", b"a"), link("real", 1, "e"), FileSpec::new("real/b", b"b")],
            Overwrite::RenameExisting(RenameStyle::Underscore),
            "real/b",
        ),
    ];
    for (case, mut files, overwrite, refused) in cases {
        files.push(FileSpec::new("z", b"z"));
        for threads in [1, 4] {
            let tmp = tempfile::tempdir().unwrap();
            let arc = write(tmp.path(), &files);
            let dest = tmp.path().join("out");
            fs::create_dir_all(dest.join("e")).unwrap();
            let opts = options(&dest, Mode::Extract, overwrite, threads);
            let s = extract::run(&arc, &opts, |_| {}).unwrap();
            assert_eq!(s.errors, [format!("{refused}: a symlink is in the way")], "{case} threads={threads}");
            assert_eq!(fs::read(dest.join("z")).unwrap(), b"z", "{case} threads={threads}");
            assert_eq!(fs::read_dir(dest.join("e")).unwrap().count(), 0, "{case}: written through the link");
            assert!(fs::read_dir(dest.join("real")).is_ok_and(|d| d.count() == 0), "{case}: written through the link");

            // the typed run reports the same single failure and goes on to `z`
            let tmp = tempfile::tempdir().unwrap();
            let arc = write(tmp.path(), &files);
            let dest = tmp.path().join("out");
            fs::create_dir_all(dest.join("e")).unwrap();
            let mut events = Vec::new();
            let opts = options(&dest, Mode::Extract, overwrite, threads);
            let summary = extract::run_rar_with_outcomes(&arc, &opts, None, |e| events.push(event(e))).unwrap();
            assert_eq!(summary.failed, 1, "{case} threads={threads}: {events:?}");
            assert_eq!(failed(&events), [3], "{case} threads={threads}: {events:?}");
            assert_eq!(fs::read(dest.join("z")).unwrap(), b"z", "{case} threads={threads}");
        }
    }
}

/// In a Windows-made archive a `\` in a RAR 5.0 name is written as `_`; a hard link's or file copy's target names
/// that member the same way, so it finds the file where it was written.
#[test]
fn links_to_a_windows_name_with_a_backslash_find_the_written_file() {
    for threads in [1, 4] {
        let tmp = tempfile::tempdir().unwrap();
        let windows = |spec: FileSpec<'static>| FileSpec { unix_mode: None, ..spec };
        let arc = write(
            tmp.path(),
            &[
                windows(FileSpec::new("d\\x.txt", b"data")),
                windows(link("hard", 4, "d\\x.txt")),
                windows(link("copy", 5, "d\\x.txt")),
            ],
        );
        let dest = tmp.path().join("out");
        let s = extract::run(&arc, &options(&dest, Mode::Extract, Overwrite::Always, threads), |_| {}).unwrap();
        assert!(s.errors.is_empty(), "threads={threads}: {:?}", s.errors);
        assert_eq!(fs::read(dest.join("d_x.txt")).unwrap(), b"data");
        assert_eq!(ino(&dest.join("hard")), ino(&dest.join("d_x.txt")), "threads={threads}");
        assert_eq!(fs::read(dest.join("copy")).unwrap(), b"data");
        assert!(!dest.join("d").exists(), "no folder made from the backslash");
    }
}
