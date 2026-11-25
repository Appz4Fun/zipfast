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

//! `StartDecision::RenameTo`: the start hook renames a member's output inside the run. Hard links and RAR 5.0 file
//! copies naming the member resolve to the renamed file; unsafe or protected names and taken names follow the
//! run's rules.
#![cfg(unix)]

mod common;

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use common::{FileSpec, archive};
use zipfast::extract::{self, MemberFilter, Mode, Options, Overwrite, RenameStyle, StartDecision, Summary};

fn options(dest: &Path, overwrite: Overwrite, select: MemberFilter) -> Options {
    Options {
        mode: Mode::Extract,
        dest: dest.to_path_buf(),
        overwrite,
        flatten: false,
        threads: Some(1),
        protected_paths: Default::default(),
        parallel_min: None,
        select: Some(select),
        windows_safe_names: false,
        special_entries: Default::default(),
        fallback_mtime: None,
        compressed_tar: Default::default(),
        version_naming: Default::default(),
        preexisting_links: Default::default(),
        refused_link_placeholder: false,
        restart_from_first_volume: false,
    }
}

/// A hook that sends the member written at `from` (a path under the destination) to `to`.
fn renaming(dest: &Path, from: &str, to: &str) -> MemberFilter {
    let from = dest.join(from);
    let to = PathBuf::from(to);
    MemberFilter::all()
        .on_start(move |m| if m.path == from { StartDecision::RenameTo(to.clone()) } else { StartDecision::Write })
}

fn tar() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/links/bsdtar.tar")
}

fn run_tar(dest: &Path, overwrite: Overwrite, to: &str) -> Summary {
    extract::run(&tar(), &options(dest, overwrite, renaming(dest, "dir/file.txt", to)), |_| {}).unwrap()
}

#[test]
fn a_tar_hard_link_resolves_to_the_file_the_hook_renamed() {
    let tmp = tempfile::tempdir().unwrap();
    let s = run_tar(tmp.path(), Overwrite::Always, "moved/there.txt");
    assert!(s.errors.is_empty(), "{:?}", s.errors);
    assert!(!tmp.path().join("dir/file.txt").exists());
    assert_eq!(fs::read(tmp.path().join("moved/there.txt")).unwrap(), b"hello\n");
    let (a, b) =
        (fs::metadata(tmp.path().join("moved/there.txt")).unwrap(), fs::metadata(tmp.path().join("hard.txt")).unwrap());
    assert_eq!(a.ino(), b.ino(), "the hard link reaches the renamed file");
}

#[test]
fn a_rar5_file_copy_resolves_to_the_file_the_hook_renamed() {
    for threads in [1, 4] {
        let tmp = tempfile::tempdir().unwrap();
        let mut body = Vec::new();
        for v in [5, 5, 0, 3] {
            common::vint(v, &mut body);
        }
        body.extend(b"d/f");
        let mut extra = Vec::new();
        common::vint(body.len() as u64, &mut extra);
        extra.extend(body);
        let copy = FileSpec { extra, unix_mode: Some(0o120777), ..FileSpec::new("copy", b"") };
        let dir = FileSpec { dir: true, unix_mode: Some(0o755), ..FileSpec::new("d", b"") };
        let arc = tmp.path().join("copy.rar");
        fs::write(&arc, archive(&[dir, FileSpec::new("d/f", b"data"), copy])).unwrap();
        let dest = tmp.path().join("out");
        let mut opts = options(&dest, Overwrite::Always, renaming(&dest, "d/f", "elsewhere/f2"));
        opts.threads = Some(threads);
        let s = extract::run(&arc, &opts, |_| {}).unwrap();
        assert!(s.errors.is_empty(), "threads={threads}: {:?}", s.errors);
        assert!(!dest.join("d/f").exists());
        assert_eq!(fs::read(dest.join("elsewhere/f2")).unwrap(), b"data");
        assert_eq!(fs::read(dest.join("copy")).unwrap(), b"data", "the copy reads the renamed file");
    }
}

#[test]
fn an_escaping_or_unsafe_new_name_fails_only_its_member() {
    for bad in ["../evil.txt", "a/../../evil.txt", "/etc/evil.txt", ""] {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out");
        let s = run_tar(&dest, Overwrite::Always, bad);
        assert!(!s.errors.is_empty(), "{bad:?}");
        assert!(s.errors[0].starts_with("dir/file.txt:"), "{bad:?}: {:?}", s.errors);
        assert!(!dest.join("dir/file.txt").exists(), "{bad:?}: nothing under the old name");
        assert!(!tmp.path().join("evil.txt").exists() && !Path::new("/etc/evil.txt").exists(), "{bad:?}");
        // the run went on: later members that don't depend on it are there
        assert_eq!(fs::read_link(dest.join("ln_dir")).unwrap(), Path::new("dir"), "{bad:?}");
    }
}

#[test]
fn a_new_name_that_is_a_protected_input_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("out");
    fs::create_dir_all(&dest).unwrap();
    let guarded = dest.join("guarded.txt");
    fs::write(&guarded, b"keep").unwrap();
    let mut opts = options(&dest, Overwrite::Always, renaming(&dest, "dir/file.txt", "guarded.txt"));
    opts.protected_paths = [guarded.canonicalize().unwrap()].into_iter().collect();
    let s = extract::run(&tar(), &opts, |_| {}).unwrap();
    assert!(s.errors.iter().any(|e| e.contains("protected")), "{:?}", s.errors);
    assert_eq!(fs::read(&guarded).unwrap(), b"keep");
}

#[test]
fn a_taken_new_name_follows_the_overwrite_mode() {
    let seed = |dest: &Path| {
        fs::create_dir_all(dest).unwrap();
        fs::write(dest.join("taken.txt"), b"old").unwrap();
    };
    // Skip keeps what is there
    let tmp = tempfile::tempdir().unwrap();
    seed(tmp.path());
    let s = run_tar(tmp.path(), Overwrite::Skip, "taken.txt");
    assert_eq!(fs::read(tmp.path().join("taken.txt")).unwrap(), b"old");
    assert!(s.skipped >= 1, "{s:?}");
    // Always replaces it
    let tmp = tempfile::tempdir().unwrap();
    seed(tmp.path());
    run_tar(tmp.path(), Overwrite::Always, "taken.txt");
    assert_eq!(fs::read(tmp.path().join("taken.txt")).unwrap(), b"hello\n");
    // a rename mode picks the next free name, and the hard link follows it
    let tmp = tempfile::tempdir().unwrap();
    seed(tmp.path());
    let s = run_tar(tmp.path(), Overwrite::RenameNew(RenameStyle::Underscore), "taken.txt");
    assert_eq!(fs::read(tmp.path().join("taken.txt")).unwrap(), b"old");
    assert_eq!(fs::read(tmp.path().join("taken_1.txt")).unwrap(), b"hello\n");
    assert_eq!(
        fs::metadata(tmp.path().join("taken_1.txt")).unwrap().ino(),
        fs::metadata(tmp.path().join("hard.txt")).unwrap().ino()
    );
    assert_eq!(s.renames.len(), 1, "{:?}", s.renames);
}

#[test]
fn without_a_rename_the_run_is_unchanged() {
    let tmp = tempfile::tempdir().unwrap();
    let s = extract::run(
        &tar(),
        &options(tmp.path(), Overwrite::Always, MemberFilter::all().on_start(|_| StartDecision::Write)),
        |_| {},
    )
    .unwrap();
    assert!(s.errors.is_empty());
    assert_eq!(fs::read(tmp.path().join("dir/file.txt")).unwrap(), b"hello\n");
}

/// The first member any route offers is renamed, and written only under the new name.
fn first_renamed(archive: &Path, dest: &Path) -> (Summary, PathBuf) {
    let first = std::sync::Arc::new(std::sync::Mutex::new(None::<PathBuf>));
    let seen = first.clone();
    let filter = MemberFilter::all().on_start(move |m| {
        let mut seen = seen.lock().unwrap();
        if seen.is_none() {
            *seen = Some(m.path.to_path_buf());
            StartDecision::RenameTo(PathBuf::from("renamed-by-hook.bin"))
        } else {
            StartDecision::Write
        }
    });
    let s = extract::run(archive, &options(dest, Overwrite::Always, filter), |_| {}).unwrap();
    let first = first.lock().unwrap().clone().unwrap();
    (s, first)
}

#[test]
fn a_sevenzip_member_is_written_under_the_new_name() {
    let tmp = tempfile::tempdir().unwrap();
    let archive = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/7z-extract/copy.7z");
    let (s, first) = first_renamed(&archive, tmp.path());
    assert!(s.errors.is_empty(), "{:?}", s.errors);
    assert!(!first.exists());
    assert!(tmp.path().join("renamed-by-hook.bin").is_file());
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn the_checked_zip_route_fails_the_member_instead_of_renaming() {
    let tmp = tempfile::tempdir().unwrap();
    let archive = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/links/infozip.zip");
    let filter = MemberFilter::all().on_start(|_| StartDecision::RenameTo(PathBuf::from("renamed-by-hook.bin")));
    let report = zipfast::zip::run_with_policy(
        &archive,
        &options(tmp.path(), Overwrite::Always, filter),
        None,
        &extract::Cancellation::default(),
        &Default::default(),
        |_: zipfast::zip::ZipRunEvent<'_>| Ok(()),
    )
    .unwrap();
    assert!(report.failed() >= 1);
    assert!(!tmp.path().join("renamed-by-hook.bin").exists());
    assert!(!tmp.path().join("dir/file.txt").exists());
}

fn rar_ab(tmp: &Path) -> PathBuf {
    let arc = tmp.join("ab.rar");
    fs::write(&arc, archive(&[FileSpec::new("a", b"from a"), FileSpec::new("b", b"from b")])).unwrap();
    arc
}

/// Y1: a member sent to `b` and a later member `b` write the same place, so the second waits for the first.
#[test]
fn a_renamed_member_and_a_later_member_at_its_new_name_are_serialized() {
    for (overwrite, expect) in [(Overwrite::Always, &b"from b"[..]), (Overwrite::Skip, &b"from a"[..])] {
        for _ in 0..20 {
            let tmp = tempfile::tempdir().unwrap();
            let arc = rar_ab(tmp.path());
            let dest = tmp.path().join("out");
            let mut opts = options(&dest, overwrite, renaming(&dest, "a", "b"));
            opts.threads = Some(4);
            let s = extract::run(&arc, &opts, |_| {}).unwrap();
            assert!(s.errors.is_empty(), "{overwrite:?}: {:?}", s.errors);
            assert!(!dest.join("a").exists());
            assert_eq!(fs::read(dest.join("b")).unwrap(), expect, "{overwrite:?}");
        }
    }
}

/// Y2: a new name spelled `a//b` or `a/./b` lands at `a/b`.
#[test]
fn a_new_name_with_empty_or_dot_components_is_normalized() {
    for spelled in ["x//y", "x/./y"] {
        let tmp = tempfile::tempdir().unwrap();
        let arc = rar_ab(tmp.path());
        let dest = tmp.path().join("out");
        let opts = options(&dest, Overwrite::Always, renaming(&dest, "a", spelled));
        let s = extract::run(&arc, &opts, |_| {}).unwrap();
        assert!(s.errors.is_empty(), "{spelled}: {:?}", s.errors);
        assert_eq!(fs::read(dest.join("x/y")).unwrap(), b"from a", "{spelled}");
    }
}

/// Y3: a NUL in a new name is an unsafe path for that member, not a fault that stops the run.
#[test]
fn a_new_name_with_a_nul_fails_only_its_member() {
    let tmp = tempfile::tempdir().unwrap();
    let arc = rar_ab(tmp.path());
    let dest = tmp.path().join("out");
    let opts = options(&dest, Overwrite::Always, renaming(&dest, "a", "bad\0name"));
    let s = extract::run(&arc, &opts, |_| {}).unwrap();
    assert_eq!(s.errors.len(), 1, "{:?}", s.errors);
    assert!(s.errors[0].starts_with("a:"), "{:?}", s.errors);
    assert_eq!(fs::read(dest.join("b")).unwrap(), b"from b", "the run went on");
}

/// Y1, the other order: the renamed member lands on a name an earlier, still pending member writes.
#[test]
fn a_member_renamed_onto_an_earlier_pending_name_waits_for_it() {
    for (overwrite, expect) in [(Overwrite::Always, &b"from a"[..]), (Overwrite::Skip, &b"from b"[..])] {
        for _ in 0..20 {
            let tmp = tempfile::tempdir().unwrap();
            let arc = tmp.path().join("ba.rar");
            fs::write(&arc, archive(&[FileSpec::new("b", b"from b"), FileSpec::new("a", b"from a")])).unwrap();
            let dest = tmp.path().join("out");
            let mut opts = options(&dest, overwrite, renaming(&dest, "a", "b"));
            opts.threads = Some(4);
            let s = extract::run(&arc, &opts, |_| {}).unwrap();
            assert!(s.errors.is_empty(), "{overwrite:?}: {:?}", s.errors);
            assert_eq!(fs::read(dest.join("b")).unwrap(), expect, "{overwrite:?}");
        }
    }
}
