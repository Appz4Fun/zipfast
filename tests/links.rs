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

mod common;

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

/// A ustar archive: (name, kind, data or link target).
fn tar(members: &[(&str, u8, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for &(name, kind, body) in members {
        let mut h = [0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        let size = if kind == b'0' { body.len() } else { 0 };
        let mut octal = |at: usize, width: usize, v: u64| {
            h[at..at + width].copy_from_slice(format!("{v:0w$o}\0", w = width - 1).as_bytes());
        };
        octal(100, 8, if kind == b'5' { 0o755 } else { 0o644 });
        octal(108, 8, 0);
        octal(116, 8, 0);
        octal(124, 12, size as u64);
        octal(136, 12, 1_577_934_245);
        h[156] = kind;
        if kind != b'0' && kind != b'5' {
            h[157..157 + body.len()].copy_from_slice(body);
        }
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        h[148..156].fill(b' ');
        let sum: u64 = h.iter().map(|&b| u64::from(b)).sum();
        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        out.extend(h);
        if kind == b'0' {
            out.extend(body);
            out.resize(out.len().div_ceil(512) * 512, 0);
        }
    }
    out.extend([0u8; 1024]);
    out
}

/// Writes `bytes` as a plain or gzip-compressed tar.
fn write_tar(path: &Path, bytes: Vec<u8>, gz: bool) {
    if gz {
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(&bytes).unwrap();
        fs::write(path, enc.finish().unwrap()).unwrap();
    } else {
        fs::write(path, bytes).unwrap();
    }
}

#[test]
fn rename_new_links_to_where_the_file_landed_not_the_old_file() {
    use std::os::unix::fs::MetadataExt;
    use zipfast::extract::RenameStyle;
    for gz in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join(if gz { "a.tgz" } else { "a.tar" });
        write_tar(&archive, tar(&[("a.txt", b'0', b"new"), ("h", b'1', b"a.txt")]), gz);
        let dest = dir.path().join("out");
        fs::create_dir(&dest).unwrap();
        fs::write(dest.join("a.txt"), b"SECRET").unwrap();
        let opts = options(&dest, Mode::Extract, Overwrite::RenameNew(RenameStyle::Underscore));
        let s = extract::run(&archive, &opts, |_| {}).unwrap();
        assert!(s.errors.is_empty(), "gz={gz}: {:?}", s.errors);
        assert_eq!(fs::read(dest.join("a.txt")).unwrap(), b"SECRET", "gz={gz}");
        assert_eq!(fs::read(dest.join("a_1.txt")).unwrap(), b"new", "gz={gz}");
        assert_eq!(fs::read(dest.join("h")).unwrap(), b"new", "gz={gz}");
        let h = fs::metadata(dest.join("h")).unwrap().ino();
        assert_ne!(h, fs::metadata(dest.join("a.txt")).unwrap().ino(), "gz={gz}");
        assert_eq!(fs::metadata(dest.join("a.txt")).unwrap().nlink(), 1, "gz={gz}");
    }
}

#[test]
fn rename_existing_never_links_through_a_symlink_that_replaced_a_folder() {
    use std::os::unix::fs::MetadataExt;
    use zipfast::extract::RenameStyle;
    for gz in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("f"), b"OUTSIDE").unwrap();
        let dest = dir.path().join("out");
        fs::create_dir(&dest).unwrap();
        std::os::unix::fs::symlink("../outside", dest.join("ext")).unwrap();
        let bytes = tar(&[("d/", b'5', b""), ("d/f", b'0', b"mine"), ("d", b'2', b"ext"), ("h", b'1', b"d/f")]);
        let archive = dir.path().join(if gz { "a.tgz" } else { "a.tar" });
        write_tar(&archive, bytes, gz);
        let opts = options(&dest, Mode::Extract, Overwrite::RenameExisting(RenameStyle::Underscore));
        let s = extract::run(&archive, &opts, |_| {}).unwrap();
        // the attack's setup happened: the folder moved aside and `d` is now the link to `ext`
        assert_eq!(fs::read_link(dest.join("d")).unwrap(), Path::new("ext"), "gz={gz}");
        assert_eq!(fs::read(dest.join("d_1/f")).unwrap(), b"mine", "gz={gz}");
        assert_eq!(s.errors.len(), 1, "gz={gz}: only `h` fails: {:?}", s.errors);
        let outside_ino = fs::metadata(outside.join("f")).unwrap().ino();
        if let Ok(h) = fs::symlink_metadata(dest.join("h")) {
            assert_ne!(h.ino(), outside_ino, "gz={gz}: h shares the outside file");
        }
        assert_eq!(fs::metadata(outside.join("f")).unwrap().nlink(), 1, "gz={gz}");
        assert_eq!(fs::read(outside.join("f")).unwrap(), b"OUTSIDE");
    }
}

#[test]
fn testing_refuses_the_links_extracting_would_refuse() {
    for name in ["escape.tar", "escape.zip"] {
        let dir = tempfile::tempdir().unwrap();
        let s = extract::run(&fixture(name), &options(dir.path(), Mode::Test, Overwrite::Always), |_| {}).unwrap();
        assert!(s.errors.len() >= 2 && s.errors.iter().all(|e| e.contains("leads out")), "{name}: {:?}", s.errors);
    }
    let dir = tempfile::tempdir().unwrap();
    let s = extract::run(&fixture("hard-missing.tar"), &options(dir.path(), Mode::Test, Overwrite::Always), |_| {});
    assert_eq!(s.unwrap().errors.len(), 1);
}

#[test]
fn a_changed_hard_link_target_fails_only_its_member_and_leaves_no_reserved_file() {
    use zipfast::extract::RenameStyle;
    for gz in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out");
        fs::create_dir(&dest).unwrap();
        fs::write(dest.join("h"), b"was here").unwrap();
        // the file member `d` moves the folder holding `d/f` aside: `d/f` is no longer the file extracted
        let bytes = tar(&[
            ("d/", b'5', b""),
            ("d/f", b'0', b"mine"),
            ("d", b'0', b"file"),
            ("h", b'1', b"d/f"),
            ("z", b'0', b"z"),
        ]);
        let archive = dir.path().join(if gz { "a.tgz" } else { "a.tar" });
        write_tar(&archive, bytes, gz);
        let opts = options(&dest, Mode::Extract, Overwrite::RenameExisting(RenameStyle::Underscore));
        let s = extract::run(&archive, &opts, |_| {}).unwrap();
        assert_eq!(s.errors.len(), 1, "gz={gz}: {:?}", s.errors);
        assert!(s.errors[0].contains("no longer"), "gz={gz}: {:?}", s.errors);
        assert_eq!(fs::read(dest.join("z")).unwrap(), b"z", "gz={gz}");
        assert_eq!(fs::read(dest.join("h_1")).unwrap(), b"was here", "gz={gz}");
        assert!(fs::symlink_metadata(dest.join("h")).is_err(), "gz={gz}: the reserved name is left behind");
    }
}

/// A folder is never trusted past a rename that moved it aside under another spelling of its name: on APFS `A/B`
/// (or `e` with a combining accent) is `a/b` (or `é`), so the link `A/B -> .` takes the folder's place and
/// `a/b/l -> ../../outside` would sit one folder higher than its name says.
#[test]
fn a_moved_folder_is_never_trusted_under_another_spelling() {
    use zipfast::extract::RenameStyle;
    let tmp = tempfile::tempdir().unwrap();
    for (nfd, upper, lower) in [(false, "A", "a"), (true, "e\u{301}", "\u{e9}")] {
        if !common::folds_names(tmp.path(), nfd) {
            eprintln!("skipped: this file system keeps {upper:?} and {lower:?} apart");
            continue;
        }
        let alias = if nfd { format!("{upper}/b") } else { format!("{upper}/B") };
        let (dir_a, dir_ab, file, escape) =
            (format!("{lower}/"), format!("{lower}/b/"), format!("{lower}/b/x"), format!("{lower}/b/l"));
        for gz in [false, true] {
            let case = tmp.path().join(format!("{nfd}-{gz}"));
            fs::create_dir_all(case.join("outside")).unwrap();
            let bytes = tar(&[
                (dir_a.as_str(), b'5', b""),
                (dir_ab.as_str(), b'5', b""),
                (file.as_str(), b'0', b"x"),
                (alias.as_str(), b'2', b"."),
                (escape.as_str(), b'2', b"../../outside"),
            ]);
            let archive = case.join(if gz { "a.tgz" } else { "a.tar" });
            write_tar(&archive, bytes, gz);
            let dest = case.join("out");
            let opts = options(&dest, Mode::Extract, Overwrite::RenameExisting(RenameStyle::Underscore));
            let _ = extract::run(&archive, &opts, |_| {});
            assert_eq!(common::links_leading_out(&dest), Vec::<PathBuf>::new(), "nfd={nfd} gz={gz}");
        }
    }
}

/// A symbolic link takes its archived time on itself, not the time it was made.
#[test]
fn symbolic_links_keep_their_archived_time() {
    use std::os::unix::fs::MetadataExt;
    let day_ago = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64 - 86_400;
    for name in ["bsdtar.tar", "bsdtar.tgz", "infozip.zip", "ditto.zip", "7z.7z"] {
        let dir = tempfile::tempdir().unwrap();
        extract::run(&fixture(name), &options(dir.path(), Mode::Extract, Overwrite::Always), |_| {}).unwrap();
        for link in ["ln_file", "ln_dir", "chain"] {
            let m = fs::symlink_metadata(dir.path().join(link)).unwrap();
            assert!(m.file_type().is_symlink());
            assert!(m.mtime() < day_ago, "{name} {link}: {}", m.mtime());
        }
    }
}
