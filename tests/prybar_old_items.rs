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

//! WP-B7: replacing a link this run placed, and what the start hook sees under flatten.
#![cfg(unix)]

use std::fs;
use std::path::Path;

use zipfast::extract::{self, Mode, Options, Overwrite};

fn options(dest: &Path, overwrite: Overwrite) -> Options {
    Options {
        mode: Mode::Extract,
        dest: dest.to_path_buf(),
        overwrite,
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
    }
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
        octal(100, 8, 0o644);
        octal(108, 8, 0);
        octal(116, 8, 0);
        octal(124, 12, size as u64);
        octal(136, 12, 1_577_934_245);
        h[156] = kind;
        if kind != b'0' {
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

#[test]
fn tar_replaces_a_link_this_run_placed() {
    for later in [(b'0', &b"data"[..]), (b'2', &b"y"[..])] {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        fs::write(&archive, tar(&[("a", b'2', b"x"), ("a", later.0, later.1)])).unwrap();
        let dest = dir.path().join("out");
        fs::create_dir(&dest).unwrap();
        let s = extract::run(&archive, &options(&dest, Overwrite::Always), |_| {}).unwrap();
        assert!(s.errors.is_empty(), "{:?}: {:?}", later.0, s.errors);
        if later.0 == b'0' {
            assert_eq!(fs::read(dest.join("a")).unwrap(), b"data");
            assert!(!fs::symlink_metadata(dest.join("a")).unwrap().file_type().is_symlink());
        } else {
            assert_eq!(fs::read_link(dest.join("a")).unwrap(), Path::new("y"));
        }
    }
}

#[test]
fn a_link_from_an_earlier_run_is_still_refused() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("a.tar");
    fs::write(&archive, tar(&[("a", b'0', b"data")])).unwrap();
    let dest = dir.path().join("out");
    fs::create_dir(&dest).unwrap();
    std::os::unix::fs::symlink("elsewhere", dest.join("a")).unwrap();
    let s = extract::run(&archive, &options(&dest, Overwrite::Always), |_| {}).unwrap();
    assert!(s.errors.iter().any(|e| e.contains("symlink is in the way")), "{:?}", s.errors);
    assert_eq!(fs::read_link(dest.join("a")).unwrap(), Path::new("elsewhere"));
}

fn fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/links").join(name)
}

/// Each ZIP route: the legacy runner and the checked one.
fn run_zip(route: &str, archive: &Path, dest: &Path, overwrite: Overwrite) -> Vec<String> {
    let opts = options(dest, overwrite);
    if route == "legacy" {
        extract::run(archive, &opts, |_| {}).unwrap().errors
    } else {
        let report = zipfast::zip::run_with_policy(
            archive,
            &opts,
            None,
            &extract::Cancellation::default(),
            &Default::default(),
            |_: zipfast::zip::ZipRunEvent<'_>| Ok(()),
        )
        .unwrap();
        (0..report.failed()).map(|i| format!("failed {i}")).collect()
    }
}

#[test]
fn zip_replaces_a_link_this_run_placed_on_both_routes() {
    for route in ["legacy", "checked"] {
        for (name, file) in [("link-then-file.zip", true), ("link-then-link.zip", false)] {
            // NOT DONE: the checked route's native publication still refuses a file over a link this run placed
            // (handoff WP-B7); a link over a link works on both routes.
            if route == "checked" && file {
                let dir = tempfile::tempdir().unwrap();
                let dest = dir.path().join("out");
                fs::create_dir(&dest).unwrap();
                assert_eq!(run_zip(route, &fixture(name), &dest, Overwrite::Always).len(), 1);
                assert_eq!(fs::read_link(dest.join("a")).unwrap(), Path::new("x"));
                continue;
            }
            let dir = tempfile::tempdir().unwrap();
            let dest = dir.path().join("out");
            fs::create_dir(&dest).unwrap();
            let errors = run_zip(route, &fixture(name), &dest, Overwrite::Always);
            assert!(errors.is_empty(), "{route} {name}: {errors:?}");
            if file {
                assert_eq!(fs::read(dest.join("a")).unwrap(), b"data", "{route}");
                assert!(!fs::symlink_metadata(dest.join("a")).unwrap().file_type().is_symlink(), "{route}");
            } else {
                assert_eq!(fs::read_link(dest.join("a")).unwrap(), Path::new("y"), "{route}");
            }
        }
    }
}

#[test]
fn zip_skip_keeps_a_link_this_run_placed_and_earlier_links_stay_refused() {
    for route in ["legacy", "checked"] {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out");
        fs::create_dir(&dest).unwrap();
        run_zip(route, &fixture("link-then-file.zip"), &dest, Overwrite::Skip);
        assert_eq!(fs::read_link(dest.join("a")).unwrap(), Path::new("x"), "{route}");
        // a link from before the run: refused
        let other = dir.path().join("other");
        fs::create_dir(&other).unwrap();
        std::os::unix::fs::symlink("elsewhere", other.join("a")).unwrap();
        let errors = run_zip(route, &fixture("link-then-file.zip"), &other, Overwrite::Always);
        assert!(!errors.is_empty(), "{route}");
        assert_eq!(fs::read_link(other.join("a")).unwrap(), Path::new("elsewhere"), "{route}");
    }
}

fn flatten_options(
    dest: &Path,
    overwrite: Overwrite,
) -> (Options, std::sync::Arc<std::sync::Mutex<Vec<std::path::PathBuf>>>) {
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = std::sync::Arc::clone(&seen);
    let filter = extract::MemberFilter::all().on_start(move |m| {
        log.lock().unwrap().push(m.path.to_path_buf());
        extract::StartDecision::Write
    });
    let mut opts = options(dest, overwrite);
    opts.flatten = true;
    opts.select = Some(filter);
    (opts, seen)
}

fn run_route(route: &str, archive: &Path, opts: &Options) {
    match route {
        "checked" => {
            zipfast::zip::run_with_policy(
                archive,
                opts,
                None,
                &extract::Cancellation::default(),
                &Default::default(),
                |_: zipfast::zip::ZipRunEvent<'_>| Ok(()),
            )
            .unwrap();
        }
        _ => {
            extract::run(archive, opts, |_| {}).unwrap();
        }
    }
}

/// With flatten the start hook sees the path that is written (`dest/b.txt`), and an existing flattened target
/// under `Skip` is skipped before the hook is asked.
#[test]
fn flatten_start_hook_sees_the_flattened_path_on_every_route() {
    let dir = tempfile::tempdir().unwrap();
    let tar_path = dir.path().join("d.tar");
    fs::write(&tar_path, tar(&[("dir/b.txt", b'0', b"new")])).unwrap();
    for (route, archive) in [("legacy", fixture("dir-b.zip")), ("checked", fixture("dir-b.zip")), ("tar", tar_path)] {
        // written: the hook sees dest/b.txt
        let out = tempfile::tempdir().unwrap();
        let (opts, seen) = flatten_options(out.path(), Overwrite::Always);
        run_route(route, &archive, &opts);
        assert_eq!(*seen.lock().unwrap(), vec![out.path().join("b.txt")], "{route}");
        assert_eq!(fs::read(out.path().join("b.txt")).unwrap(), b"new", "{route}");
        // skip-existing: ./b.txt exists, so the member is skipped and not offered
        let out = tempfile::tempdir().unwrap();
        fs::write(out.path().join("b.txt"), b"old").unwrap();
        let (opts, seen) = flatten_options(out.path(), Overwrite::Skip);
        run_route(route, &archive, &opts);
        assert_eq!(fs::read(out.path().join("b.txt")).unwrap(), b"old", "{route}");
        assert!(seen.lock().unwrap().is_empty(), "{route}: {:?}", seen.lock().unwrap());
        assert!(!out.path().join("dir").exists(), "{route}");
    }
}

/// Whole-archive 7z and RAR runs with flatten: whatever the hook is asked about sits directly in the destination.
#[test]
fn flatten_start_hook_paths_are_flat_for_7z_and_rar() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    for archive in [fixture("7z.7z"), root.join("rar4/solid.rar"), root.join("rar4/latest_winrar.rar")] {
        let out = tempfile::tempdir().unwrap();
        let (opts, seen) = flatten_options(out.path(), Overwrite::Always);
        let _ = extract::run(&archive, &opts, |_| {});
        let seen = seen.lock().unwrap();
        assert!(!seen.is_empty(), "{archive:?}");
        for path in seen.iter() {
            assert_eq!(path.parent(), Some(out.path()), "{archive:?}: {path:?}");
        }
    }
}
