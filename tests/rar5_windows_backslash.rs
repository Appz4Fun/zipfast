//! A RAR 5.0 name separates folders with `/` only. A `\` in a Windows-made member's name is part of the file name,
//! which Windows cannot hold, so it is written as `_`, as UnRAR 7.30 writes it; a Unix-made name keeps it.

mod common;

use common::{FileSpec, archive};
use zipfast::extract::{self, Mode, Options, Overwrite};

fn extract_to(bytes: &[u8], dir: &std::path::Path) -> Vec<String> {
    let rar = dir.join("a.rar");
    std::fs::write(&rar, bytes).unwrap();
    let out = dir.join("out");
    let options = Options {
        mode: Mode::Extract,
        dest: out.clone(),
        overwrite: Overwrite::Skip,
        flatten: false,
        threads: None,
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
        salvage_truncated_zip: false,
        unix_modes: Default::default(),
        backslashes: Default::default(),
    };
    extract::run_with_password(&rar, &options, None, |_| {}).unwrap();
    let mut names: Vec<String> =
        walk(&out).into_iter().map(|p| p.strip_prefix(&out).unwrap().display().to_string()).collect();
    names.sort();
    names
}

/// A member made on Windows: the test writer marks host OS Windows when the member has no Unix mode.
fn windows<'a>(name: &'a str, data: &'a [u8]) -> FileSpec<'a> {
    let mut spec = FileSpec::new(name, data);
    spec.unix_mode = None;
    spec
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut all = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            all.push(p.clone());
            all.extend(walk(&p));
        } else {
            all.push(p);
        }
    }
    all
}

#[test]
fn a_windows_rar5_name_with_a_backslash_is_written_with_an_underscore() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = archive(&[windows("d\\x.txt", b"payload")]);
    assert_eq!(extract_to(&bytes, dir.path()), ["d_x.txt"]);
    assert_eq!(std::fs::read(dir.path().join("out/d_x.txt")).unwrap(), b"payload");
}

#[test]
fn a_windows_rar5_name_keeps_its_real_folders() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = archive(&[windows("f/g\\h.txt", b"x")]);
    assert_eq!(extract_to(&bytes, dir.path()), ["f", "f/g_h.txt"]);
}

#[cfg(unix)]
#[test]
fn a_unix_rar5_name_keeps_its_backslash() {
    let dir = tempfile::tempdir().unwrap();
    let mut spec = FileSpec::new("d\\x.txt", b"payload");
    spec.unix_mode = Some(0o100644);
    let bytes = archive(&[spec]);
    assert_eq!(extract_to(&bytes, dir.path()), ["d\\x.txt"]);
}
