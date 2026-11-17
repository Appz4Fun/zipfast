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

//! Symbolic and hard links from tar, ZIP and 7z: placed only inside the destination, never followed.
#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};

use zipfast::extract::{self, Mode, Options, Overwrite};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/links").join(name)
}

fn options(dest: &Path, mode: Mode, overwrite: Overwrite) -> Options {
    Options {
        mode,
        dest: dest.to_path_buf(),
        overwrite,
        flatten: false,
        threads: Some(1),
        protected_paths: Default::default(),
        parallel_min: None,
        select: None,
        windows_safe_names: false,
    }
}

fn link(path: &Path) -> String {
    fs::read_link(path).unwrap().to_string_lossy().into_owned()
}

/// The tree every real archiver stored: dir/file.txt, ln_file -> dir/file.txt, ln_dir -> dir, chain -> ln_file.
fn assert_tree(dest: &Path) {
    assert_eq!(fs::read(dest.join("dir/file.txt")).unwrap(), b"hello\n");
    assert_eq!(link(&dest.join("ln_file")), "dir/file.txt");
    assert_eq!(link(&dest.join("ln_dir")), "dir");
    assert_eq!(link(&dest.join("chain")), "ln_file");
    assert_eq!(fs::read(dest.join("chain")).unwrap(), b"hello\n");
}

#[test]
fn real_archivers_links_extract_on_every_legacy_route() {
    for name in ["bsdtar.tar", "bsdtar.tgz", "infozip.zip", "ditto.zip", "7z.7z"] {
        let dir = tempfile::tempdir().unwrap();
        let s = extract::run(&fixture(name), &options(dir.path(), Mode::Extract, Overwrite::Always), |_| {}).unwrap();
        assert!(s.errors.is_empty(), "{name}: {:?}", s.errors);
        assert_tree(dir.path());
        // a second run never replaces a link in the way, as for files (#153): those members are refused
        let again = extract::run(&fixture(name), &options(dir.path(), Mode::Extract, Overwrite::Always), |_| {});
        assert!(again.unwrap().errors.iter().all(|e| e.contains("symlink is in the way")), "{name} again");
        assert_tree(dir.path());
        let tested = extract::run(&fixture(name), &options(dir.path(), Mode::Test, Overwrite::Always), |_| {});
        assert!(tested.unwrap().errors.is_empty(), "{name} test");
    }
}

#[test]
fn tar_hard_links_point_at_the_file_extracted_before() {
    use std::os::unix::fs::MetadataExt;
    for name in ["bsdtar.tar", "bsdtar.tgz"] {
        let dir = tempfile::tempdir().unwrap();
        extract::run(&fixture(name), &options(dir.path(), Mode::Extract, Overwrite::Always), |_| {}).unwrap();
        let (a, b) = (
            fs::metadata(dir.path().join("dir/file.txt")).unwrap(),
            fs::metadata(dir.path().join("hard.txt")).unwrap(),
        );
        assert_eq!((a.ino(), b.ino()), (a.ino(), a.ino()), "{name}");
        assert_eq!(fs::read(dir.path().join("hard.txt")).unwrap(), b"hello\n");
    }
}

#[test]
fn a_hard_link_to_a_missing_or_later_member_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    // a file outside the run, named as the missing target, must not be linked either
    fs::write(dir.path().join("nowhere.txt"), b"before the run").unwrap();
    let s = extract::run(&fixture("hard-missing.tar"), &options(dir.path(), Mode::Extract, Overwrite::Always), |_| {})
        .unwrap();
    assert_eq!(s.errors.len(), 1, "{:?}", s.errors);
    assert!(s.errors[0].starts_with("orphan:"), "{:?}", s.errors);
    assert!(!dir.path().join("orphan").exists());
    // `early` names a member that came before it in the archive: allowed
    assert_eq!(fs::read(dir.path().join("early")).unwrap(), b"later\n");
}

#[test]
fn escaping_targets_fail_only_their_member() {
    for name in ["escape.tar", "escape.zip"] {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out");
        let s = extract::run(&fixture(name), &options(&dest, Mode::Extract, Overwrite::Always), |_| {}).unwrap();
        assert_eq!(fs::read(dest.join("ok.txt")).unwrap(), b"ok\n", "{name}");
        for bad in ["up", "abs", "d/sneak"] {
            assert!(fs::symlink_metadata(dest.join(bad)).is_err(), "{name}: {bad}");
        }
        assert!(s.errors.iter().all(|e| e.contains("leads out of the destination")), "{name}: {:?}", s.errors);
        assert!(s.errors.len() >= 2, "{name}: {:?}", s.errors);
    }
}

#[test]
fn a_member_under_a_linked_folder_is_never_written_through_it() {
    for name in ["under-link.tar", "under-link.zip"] {
        let dir = tempfile::tempdir().unwrap();
        let _ = extract::run(&fixture(name), &options(dir.path(), Mode::Extract, Overwrite::Always), |_| {});
        assert_eq!(link(&dir.path().join("ln")), "real", "{name}");
        assert!(!dir.path().join("real/evil.txt").exists(), "{name}: written through the link");
    }
}

#[test]
fn skip_keeps_what_is_there() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("ln_file"), b"mine").unwrap();
    let _ = extract::run(&fixture("bsdtar.tar"), &options(dir.path(), Mode::Extract, Overwrite::Skip), |_| {});
    assert_eq!(fs::read(dir.path().join("ln_file")).unwrap(), b"mine");
    assert!(!fs::symlink_metadata(dir.path().join("ln_file")).unwrap().file_type().is_symlink());
}

#[test]
fn listings_carry_link_targets() {
    use zipfast::rar5::Redirection;
    for name in ["bsdtar.tar", "infozip.zip", "ditto.zip"] {
        let entries = extract::list(&fixture(name)).unwrap();
        let ln = entries.iter().find(|e| e.name == "ln_file").unwrap();
        assert!(matches!(&ln.link, Some(Redirection::UnixSymlink(t)) if t == "dir/file.txt"), "{name}: {:?}", ln.link);
    }
    let entries = extract::list(&fixture("7z.7z")).unwrap();
    assert!(matches!(entries.iter().find(|e| e.name == "ln_file").unwrap().link, Some(Redirection::UnixSymlink(_))));
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn the_checked_zip_route_places_links_too() {
    use zipfast::extract::Cancellation;
    for name in ["infozip.zip", "ditto.zip"] {
        let dir = tempfile::tempdir().unwrap();
        let report = zipfast::zip::run_with_policy(
            &fixture(name),
            &options(dir.path(), Mode::Extract, Overwrite::Always),
            None,
            &Cancellation::default(),
            &Default::default(),
            |_: zipfast::zip::ZipRunEvent<'_>| Ok(()),
        )
        .unwrap();
        assert_eq!(report.failed(), 0, "{name}");
        assert_tree(dir.path());
    }
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out");
    let report = zipfast::zip::run_with_policy(
        &fixture("escape.zip"),
        &options(&dest, Mode::Extract, Overwrite::Always),
        None,
        &Cancellation::default(),
        &Default::default(),
        |_: zipfast::zip::ZipRunEvent<'_>| Ok(()),
    )
    .unwrap();
    assert_eq!(report.failed(), 2);
    assert!(fs::symlink_metadata(dest.join("up")).is_err());
    assert_eq!(fs::read(dest.join("ok.txt")).unwrap(), b"ok\n");
}
