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

//! The 7-Zip and UnRAR compatibility choices in `extract::Options`, each checked against what 7-Zip 26.06 and UnRAR
//! 7.30 (Linux x86-64) do with the same input:
//!
//! - `special_entries`: `7z x ustar.tar` writes the character device `dev` as an empty regular file (mode 0644, the
//!   member's mtime 2020-01-02 03:04:05 UTC) and exits 0; `7z x -so ustar.tar dev` prints nothing.
//! - `fallback_mtime`: `7z x notime.7z` (no `MTime` property) gives `a.txt`, `d` and `d/b.txt` the archive file's
//!   mtime; `7z x rars-compressed.rar` (DOS date and time 0) does the same, where `unrar x` writes 1979-11-30.
//! - `compressed_tar`: `7z x pax.tgz` writes `pax.tar` (10240 bytes) with the archive's mtime; `.tbz`, `.tbz2`,
//!   `.tar.bz2`, `.txz`, `.tar.xz`, `.tzst` and `.tar.zst` come out as `<stem>.tar`, and a gzip stream with a stored
//!   name and MTIME as that name with that time.
//! - `version_naming`: `7z x` writes RAR 5.0 revisions as `[VER]/N/name` (`[VER]/2/dir/sub/a.txt`), and `7z e` as
//!   the bare file name.
//! - 7z wrong passwords: `7z t -pwrong` says "Data Error in encrypted file. Wrong password?" for the LZMA2 folder of
//!   `aes.7z` and "CRC Failed in encrypted file. Wrong password?" for the Copy folder of `aes_copy.7z`.

#![cfg(any(target_os = "macos", target_os = "linux"))]

mod common;

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use common::{FileSpec, archive};
use zipfast::extract::{
    self, Cancellation, CompressedTar, MemberFilter, Mode, Options, Overwrite, SelectOptions, SelectedEntry,
    SpecialEntries, VersionNaming,
};
use zipfast::sevenzip::{EncryptedFailure, SevenZipError};

fn fixture(dir: &str, name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(dir).join(name)
}

fn options(mode: Mode, dest: &Path) -> Options {
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
        special_entries: SpecialEntries::Refuse,
        fallback_mtime: None,
        compressed_tar: CompressedTar::Members,
        version_naming: VersionNaming::Semicolon,
        preexisting_links: Default::default(),
        refused_link_placeholder: false,
        restart_from_first_volume: false,
        replace_placed_links: false,
        keep_broken: false,
        attempt_continued_members: false,
        damaged_input: Default::default(),
        unsupported_filters: Default::default(),
        salvage_truncated_zip: false,
        unix_modes: Default::default(),
        backslashes: Default::default(),
    }
}

fn mtime(path: &Path) -> SystemTime {
    fs::symlink_metadata(path).unwrap().modified().unwrap()
}

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

/// 2019-09-09 09:09:09 UTC, the time the reference runs gave their archive files.
const ARCHIVE_TIME: u64 = 1_568_020_149;

/// A copy of `source` in `dir` named `name`, with `ARCHIVE_TIME` as its modification time.
fn copy_dated(source: &Path, dir: &Path, name: &str) -> PathBuf {
    let path = dir.join(name);
    fs::copy(source, &path).unwrap();
    fs::File::options().write(true).open(&path).unwrap().set_modified(at(ARCHIVE_TIME)).unwrap();
    path
}

// ---- special_entries ----

#[test]
fn a_tar_device_is_refused_by_default_and_an_empty_file_on_request() {
    let tmp = tempfile::tempdir().unwrap();
    let tar = fixture("tar-meta", "ustar.tar");
    let out = tmp.path().join("refused");
    let summary = extract::run(&tar, &options(Mode::Extract, &out), |_| {}).unwrap();
    assert_eq!(summary.errors, ["dev: devices and pipes are not extracted"]);
    assert!(!out.join("dev").exists());

    let out = tmp.path().join("empty");
    let opts = Options { special_entries: SpecialEntries::EmptyFile, ..options(Mode::Extract, &out) };
    let summary = extract::run(&tar, &opts, |_| {}).unwrap();
    assert!(summary.errors.is_empty(), "{:?}", summary.errors);
    assert_eq!((summary.files, summary.matched), (2, 2));
    let dev = out.join("dev");
    let meta = fs::symlink_metadata(&dev).unwrap();
    assert!(meta.file_type().is_file());
    assert_eq!(meta.len(), 0);
    // 7-Zip: -rw-r--r--, 2020-01-02 03:04:05 UTC, the member's own mode and time
    assert_eq!(mtime(&dev), at(1_577_934_245));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(meta.permissions().mode() & 0o777, 0o644);
    }
    assert_eq!(fs::read(out.join("f.txt")).unwrap().len(), 2);

    // `7z t` passes it too
    let summary = extract::run(&tar, &Options { mode: Mode::Test, ..opts.clone() }, |_| {}).unwrap();
    assert_eq!((summary.files, summary.errors.len()), (2, 0));
}

#[test]
fn a_device_in_a_compressed_tar_follows_the_same_choice() {
    let tmp = tempfile::tempdir().unwrap();
    let tgz = tmp.path().join("ustar.tgz");
    let mut gz = flate2::write::GzEncoder::new(fs::File::create(&tgz).unwrap(), flate2::Compression::default());
    gz.write_all(&fs::read(fixture("tar-meta", "ustar.tar")).unwrap()).unwrap();
    gz.finish().unwrap();
    let out = tmp.path().join("out");
    let summary = extract::run(&tgz, &options(Mode::Extract, &out), |_| {}).unwrap();
    assert_eq!(summary.errors, ["dev: devices and pipes are not extracted"]);
    let opts = Options { special_entries: SpecialEntries::EmptyFile, ..options(Mode::Extract, &out) };
    let summary = extract::run(&tgz, &opts, |_| {}).unwrap();
    assert!(summary.errors.is_empty(), "{:?}", summary.errors);
    assert_eq!(fs::metadata(out.join("dev")).unwrap().len(), 0);
}

#[test]
fn a_selected_tar_device_reads_as_no_bytes_on_request() {
    let tar = fixture("tar-meta", "ustar.tar");
    let refused = SelectedEntry::open(&tar, 1, None, 1 << 20).map(|_| ()).unwrap_err();
    assert!(refused.to_string().contains("not a regular file"), "{refused}");
    let select = SelectOptions::new().special_entries(SpecialEntries::EmptyFile);
    let entry =
        SelectedEntry::open_cancelable_with_options(&tar, 1, None, 1 << 20, Cancellation::default(), select).unwrap();
    assert_eq!(entry.name(), "dev");
    assert_eq!(entry.modified(), Some((1_577_934_245, 0)));
    let mut data = Vec::new();
    entry
        .read(None, |b| {
            data.extend_from_slice(b);
            Ok(())
        })
        .unwrap();
    assert!(data.is_empty());
    // the checked dispatcher takes the same choice
    let entry = SelectedEntry::open_cancelable_with_zip_limit_and_options(
        &tar,
        1,
        None,
        1 << 20,
        None,
        Cancellation::default(),
        SelectOptions::from(&Options {
            special_entries: SpecialEntries::EmptyFile,
            ..options(Mode::Test, "x".as_ref())
        }),
    )
    .unwrap();
    assert_eq!(entry.name(), "dev");
}

// ---- fallback_mtime ----

#[test]
fn a_7z_member_without_a_time_takes_the_fallback() {
    let tmp = tempfile::tempdir().unwrap();
    let archive = copy_dated(&fixture("7z-extract", "notime.7z"), tmp.path(), "notime.7z");
    let entries = extract::list(&archive).unwrap();
    assert_eq!(entries.len(), 3);
    assert!(entries.iter().all(|e| e.mtime.is_none()), "no MTime is listed as none");

    let out = tmp.path().join("fallback");
    let opts = Options { fallback_mtime: Some(mtime(&archive)), ..options(Mode::Extract, &out) };
    let summary = extract::run(&archive, &opts, |_| {}).unwrap();
    assert!(summary.errors.is_empty(), "{:?}", summary.errors);
    // 7-Zip: a.txt, d and d/b.txt all get the archive's 2019-09-09 09:09:09
    for name in ["a.txt", "d", "d/b.txt"] {
        assert_eq!(mtime(&out.join(name)), at(ARCHIVE_TIME), "{name}");
    }
    assert_eq!(fs::read(out.join("d/b.txt")).unwrap(), b"bravo\n");

    // without one, the outputs keep the time they were written at
    let out = tmp.path().join("none");
    let before = SystemTime::now() - Duration::from_secs(60);
    extract::run(&archive, &options(Mode::Extract, &out), |_| {}).unwrap();
    assert!(mtime(&out.join("a.txt")) > before);
}

#[test]
fn a_rar4_member_with_dos_time_zero_takes_the_fallback() {
    let tmp = tempfile::tempdir().unwrap();
    let archive = copy_dated(&fixture("rar4-legacy", "rars-compressed.rar"), tmp.path(), "rars-compressed.rar");
    let entries = extract::list(&archive).unwrap();
    assert_eq!(entries.iter().map(|e| (e.name.as_str(), e.mtime)).collect::<Vec<_>>(), [("payload.txt", None)]);
    let out = tmp.path().join("out");
    let opts = Options { fallback_mtime: Some(mtime(&archive)), ..options(Mode::Extract, &out) };
    let summary = extract::run(&archive, &opts, |_| {}).unwrap();
    assert!(summary.errors.is_empty(), "{:?}", summary.errors);
    assert_eq!(mtime(&out.join("payload.txt")), at(ARCHIVE_TIME));
    // UnRAR's choice is another fallback: the zero DOS date read as 1979-11-30 00:00:00
    let unrar = at(312_768_000);
    let out = tmp.path().join("unrar");
    let solid = fixture("rar4-legacy", "rars-solid.rar");
    let opts = Options { fallback_mtime: Some(unrar), ..options(Mode::Extract, &out) };
    extract::run(&solid, &opts, |_| {}).unwrap();
    for name in ["payload.txt", "second.txt"] {
        assert_eq!(mtime(&out.join(name)), unrar, "{name}");
    }
}

#[test]
fn a_rar5_member_without_a_time_takes_the_fallback_on_every_route() {
    use zipfast::rar5::session::{RarDecodeLimits, RarSession, RarSessionOptions};
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("notime.rar");
    fs::write(
        &path,
        archive(&[FileSpec { mtime: None, ..FileSpec::new("notime.txt", b"nt") }, FileSpec::new("timed.txt", b"t")]),
    )
    .unwrap();
    let fallback = at(1_234_567_890);
    let entries = extract::list(&path).unwrap();
    assert_eq!(entries[0].mtime, None);

    let out = tmp.path().join("run");
    extract::run(&path, &Options { fallback_mtime: Some(fallback), ..options(Mode::Extract, &out) }, |_| {}).unwrap();
    assert_eq!(mtime(&out.join("notime.txt")), fallback);
    assert_eq!(mtime(&out.join("timed.txt")), at(1_700_000_000), "a recorded time is kept");

    let out = tmp.path().join("session");
    let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    let all = session.select(|_| true).unwrap();
    let opts = Options { fallback_mtime: Some(fallback), ..options(Mode::Extract, &out) };
    session.extract_selected(&all, &opts, RarDecodeLimits::default(), |_| {}).unwrap();
    assert_eq!(mtime(&out.join("notime.txt")), fallback);
    assert_eq!(mtime(&out.join("timed.txt")), at(1_700_000_000));
}

// ---- compressed_tar ----

/// The tar inside `pax.tgz`, compressed with every codec 7-Zip names `<stem>.tar`.
fn compressed_tars(dir: &Path) -> Vec<(PathBuf, &'static str)> {
    let tar = fs::read(fixture("tar-meta", "pax.tar")).unwrap();
    let mut out = Vec::new();
    let mut put = |name: &'static str, data: Vec<u8>, becomes: &'static str| {
        let path = dir.join(name);
        fs::write(&path, data).unwrap();
        fs::File::options().write(true).open(&path).unwrap().set_modified(at(ARCHIVE_TIME)).unwrap();
        out.push((path, becomes));
    };
    let bz = {
        let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
        e.write_all(&tar).unwrap();
        e.finish().unwrap()
    };
    let xz = {
        let mut e = liblzma::write::XzEncoder::new(Vec::new(), 6);
        e.write_all(&tar).unwrap();
        e.finish().unwrap()
    };
    let zst = zstd::encode_all(&tar[..], 3).unwrap();
    let gz = {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(&tar).unwrap();
        e.finish().unwrap()
    };
    put("a.tbz", bz.clone(), "a.tar");
    put("a.tbz2", bz.clone(), "a.tar");
    put("b.tar.bz2", bz, "b.tar");
    put("a.txz", xz.clone(), "a.tar");
    put("b.tar.xz", xz, "b.tar");
    put("a.tzst", zst.clone(), "a.tar");
    put("b.tar.zst", zst, "b.tar");
    put("b.tar.gz", gz, "b.tar");
    out
}

#[test]
fn a_compressed_tar_comes_out_whole_as_7zip_writes_it() {
    let tmp = tempfile::tempdir().unwrap();
    let tar = fs::read(fixture("tar-meta", "pax.tar")).unwrap();
    let tgz = copy_dated(&fixture("tar-meta", "pax.tgz"), tmp.path(), "pax.tgz");
    // the default reads the members
    let out = tmp.path().join("members");
    extract::run(&tgz, &options(Mode::Extract, &out), |_| {}).unwrap();
    assert!(out.join("f.txt").is_file());

    let whole = |dest: &Path| Options { compressed_tar: CompressedTar::Whole, ..options(Mode::Extract, dest) };
    let out = tmp.path().join("whole");
    let summary = extract::run(&tgz, &whole(&out), |_| {}).unwrap();
    assert_eq!((summary.files, summary.bytes, summary.errors.len()), (1, 10240, 0));
    // 7-Zip: pax.tar, 10240 bytes, the archive's mtime (the gzip header records none)
    assert_eq!(fs::read_dir(&out).unwrap().count(), 1);
    assert_eq!(fs::read(out.join("pax.tar")).unwrap(), tar);
    assert_eq!(mtime(&out.join("pax.tar")), at(ARCHIVE_TIME));

    for (path, becomes) in compressed_tars(tmp.path()) {
        let out = tmp.path().join(format!("out-{}", path.file_name().unwrap().to_string_lossy()));
        let summary = extract::run(&path, &whole(&out), |_| {}).unwrap();
        assert!(summary.errors.is_empty(), "{path:?}: {:?}", summary.errors);
        assert_eq!(fs::read(out.join(becomes)).unwrap(), tar, "{path:?}");
        assert_eq!(mtime(&out.join(becomes)), at(ARCHIVE_TIME), "{path:?}");
        let listed = zipfast::tar::list_with_options(&path, &whole(&out)).unwrap();
        assert_eq!(listed.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), [becomes], "{path:?}");
    }
}

#[test]
fn a_gzip_header_name_and_time_name_the_whole_tar() {
    let tmp = tempfile::tempdir().unwrap();
    let tar = fs::read(fixture("tar-meta", "pax.tar")).unwrap();
    // gzip -N: the stored name and MTIME, which 7-Zip uses (named.tgz -> inner.tar, 2021-03-04 05:06:07 UTC)
    let path = tmp.path().join("named.tgz");
    let mut e = flate2::GzBuilder::new()
        .filename("inner.tar")
        .mtime(1_614_834_367)
        .write(fs::File::create(&path).unwrap(), flate2::Compression::default());
    e.write_all(&tar).unwrap();
    e.finish().unwrap();
    let out = tmp.path().join("out");
    let opts = Options { compressed_tar: CompressedTar::Whole, ..options(Mode::Extract, &out) };
    extract::run(&path, &opts, |_| {}).unwrap();
    assert_eq!(fs::read(out.join("inner.tar")).unwrap(), tar);
    assert_eq!(mtime(&out.join("inner.tar")), at(1_614_834_367));
    // `7z e` flattens to the same name
    let out = tmp.path().join("flat");
    extract::run(&path, &Options { flatten: true, dest: out.clone(), ..opts }, |_| {}).unwrap();
    assert!(out.join("inner.tar").is_file());
}

#[test]
fn a_selected_compressed_tar_is_one_entry_when_whole() {
    let tar = fs::read(fixture("tar-meta", "pax.tar")).unwrap();
    let tgz = fixture("tar-meta", "pax.tgz");
    let select = SelectOptions::new().compressed_tar(CompressedTar::Whole);
    let read = |entry: SelectedEntry| {
        let mut data = Vec::new();
        entry
            .read(None, |b| {
                data.extend_from_slice(b);
                Ok(())
            })
            .unwrap();
        data
    };
    let entry =
        SelectedEntry::open_cancelable_with_options(&tgz, 0, None, 1 << 20, Cancellation::default(), select).unwrap();
    assert_eq!(entry.name(), "pax.tar");
    assert_eq!(read(entry), tar);
    let past = SelectedEntry::open_cancelable_with_options(&tgz, 1, None, 1 << 20, Cancellation::default(), select);
    assert!(past.is_err());
    let entry = SelectedEntry::open_cancelable_with_zip_limit_and_options(
        &tgz,
        0,
        None,
        1 << 20,
        None,
        Cancellation::default(),
        select,
    )
    .unwrap();
    assert_eq!(read(entry), tar);
    // the default opens the member inside
    let entry = SelectedEntry::open(&tgz, 0, None, 1 << 20).unwrap();
    assert_eq!(entry.name(), "f.txt");
    // a plain tar is members either way
    let entry = SelectedEntry::open_cancelable_with_options(
        &fixture("tar-meta", "pax.tar"),
        0,
        None,
        1 << 20,
        Cancellation::default(),
        select,
    )
    .unwrap();
    assert_eq!(entry.name(), "f.txt");
}

// ---- version_naming ----

fn versions_archive(dir: &Path) -> PathBuf {
    let v = |n: u8| vec![3u8, 4, 0, n];
    let path = dir.join("nested.rar");
    fs::write(
        &path,
        archive(&[
            FileSpec { extra: v(2), ..FileSpec::new("dir/sub/a.txt", b"two") },
            FileSpec::new("dir/sub/a.txt", b"cur"),
            FileSpec { extra: v(1), ..FileSpec::new("b.txt", b"one") },
        ]),
    )
    .unwrap();
    path
}

/// Every file under `dir`, relative, with its contents.
fn tree(dir: &Path) -> Vec<(String, Vec<u8>)> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(root, &path, out);
            } else {
                let rel = path.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
                out.push((rel, fs::read(&path).unwrap()));
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

fn named(list: &[(&str, &[u8])]) -> Vec<(String, Vec<u8>)> {
    list.iter().map(|(n, d)| (n.to_string(), d.to_vec())).collect()
}

#[test]
fn rar5_revisions_are_named_as_7zip_names_them_on_request() {
    let tmp = tempfile::tempdir().unwrap();
    let arc = versions_archive(tmp.path());
    let take = || Some(MemberFilter::all().with_versions());

    let out = tmp.path().join("unrar");
    extract::run(&arc, &Options { select: take(), ..options(Mode::Extract, &out) }, |_| {}).unwrap();
    assert_eq!(tree(&out), named(&[("b.txt;1", b"one"), ("dir/sub/a.txt", b"cur"), ("dir/sub/a.txt;2", b"two")]));

    // 7-Zip 26.06 `x`: [VER]/1/b.txt, [VER]/2/dir/sub/a.txt, dir/sub/a.txt
    let seven = |dest: &Path| Options {
        select: take(),
        version_naming: VersionNaming::SevenZipDir,
        preexisting_links: Default::default(),
        refused_link_placeholder: false,
        restart_from_first_volume: false,
        replace_placed_links: false,
        keep_broken: false,
        attempt_continued_members: false,
        damaged_input: Default::default(),
        unsupported_filters: Default::default(),
        salvage_truncated_zip: false,
        unix_modes: Default::default(),
        backslashes: Default::default(),
        ..options(Mode::Extract, dest)
    };
    let out = tmp.path().join("seven");
    let summary = extract::run(&arc, &seven(&out), |_| {}).unwrap();
    assert_eq!((summary.files, summary.skipped, summary.errors.len()), (3, 0, 0));
    assert_eq!(
        tree(&out),
        named(&[("[VER]/1/b.txt", b"one"), ("[VER]/2/dir/sub/a.txt", b"two"), ("dir/sub/a.txt", b"cur")])
    );
    // `7z e -y`: flattened, the current file written last wins
    let out = tmp.path().join("flat");
    extract::run(&arc, &Options { flatten: true, ..seven(&out) }, |_| {}).unwrap();
    assert_eq!(tree(&out), named(&[("a.txt", b"cur"), ("b.txt", b"one")]));
    // without with_versions the naming changes nothing: revisions are skipped
    let out = tmp.path().join("skipped");
    let summary = extract::run(&arc, &Options { select: None, ..seven(&out) }, |_| {}).unwrap();
    assert_eq!(summary.skipped, 2);
    assert_eq!(tree(&out), named(&[("dir/sub/a.txt", b"cur")]));
    assert_eq!(VersionNaming::SevenZipDir.name("x/y.txt", 4), "[VER]/4/x/y.txt");
    assert_eq!(VersionNaming::Semicolon.name("x/y.txt", 4), "x/y.txt;4");
}

#[test]
fn r5extra_comes_out_as_7zip_writes_it() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("out");
    let opts = Options {
        select: Some(MemberFilter::all().with_versions()),
        version_naming: VersionNaming::SevenZipDir,
        preexisting_links: Default::default(),
        refused_link_placeholder: false,
        restart_from_first_volume: false,
        replace_placed_links: false,
        keep_broken: false,
        attempt_continued_members: false,
        damaged_input: Default::default(),
        unsupported_filters: Default::default(),
        salvage_truncated_zip: false,
        unix_modes: Default::default(),
        backslashes: Default::default(),
        ..options(Mode::Extract, &out)
    };
    extract::run(&fixture("rar5-compat", "r5extra.rar"), &opts, |_| {}).unwrap();
    // `7z x r5extra.rar`: [VER]/3/owned.txt and [VER]/3/timed.txt
    let names: Vec<String> = tree(&out).into_iter().map(|(n, _)| n).collect();
    assert_eq!(names, ["[VER]/3/owned.txt", "[VER]/3/timed.txt"]);
}

#[test]
fn a_rar_session_names_revisions_by_the_options() {
    use zipfast::rar5::session::{RarDecodeLimits, RarSession, RarSessionOptions};
    let tmp = tempfile::tempdir().unwrap();
    let arc = versions_archive(tmp.path());
    let mut session = RarSession::open(&arc, None, RarSessionOptions::default()).unwrap();
    let all = session.select(|_| true).unwrap().with_versions();
    let out = tmp.path().join("out");
    let opts = Options { version_naming: VersionNaming::SevenZipDir, ..options(Mode::Extract, &out) };
    let summary = session.extract_selected(&all, &opts, RarDecodeLimits::default(), |_| {}).unwrap();
    assert_eq!((summary.files, summary.failed), (3, 0));
    assert_eq!(
        tree(&out),
        named(&[("[VER]/1/b.txt", b"one"), ("[VER]/2/dir/sub/a.txt", b"two"), ("dir/sub/a.txt", b"cur")])
    );
}

// ---- 7z wrong passwords ----

#[test]
fn a_7z_wrong_password_says_how_the_member_failed() {
    let tmp = tempfile::tempdir().unwrap();
    for (archive, failure, line) in [
        ("aes.7z", EncryptedFailure::DataError, "data error in encrypted file: wrong password?"),
        ("nonsolid_wrongpw.7z", EncryptedFailure::DataError, "data error in encrypted file: wrong password?"),
        ("solid_wrongpw.7z", EncryptedFailure::DataError, "data error in encrypted file: wrong password?"),
        ("aes_copy.7z", EncryptedFailure::CrcFailed, "CRC failed in encrypted file: wrong password?"),
    ] {
        let out = tmp.path().join(archive);
        let failures = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&failures);
        let summary = zipfast::sevenzip::run(
            &fixture("7z-extract", archive),
            &options(Mode::Test, &out),
            Some("wrong"),
            &Cancellation::default(),
            &Default::default(),
            |_| {},
        )
        .unwrap();
        assert!(!summary.errors.is_empty(), "{archive}");
        assert!(summary.errors.iter().all(|e| e.ends_with(&format!(": {line}"))), "{archive}: {:?}", summary.errors);
        // the typed error the checked route sees for each member
        extract::run_with_zip_policy(
            &fixture("7z-extract", archive),
            &options(Mode::Test, &out),
            Some("wrong"),
            &Cancellation::default(),
            &Default::default(),
            |event: zipfast::zip::ZipRunEvent<'_>| {
                if let zipfast::zip::ZipRunEvent::MemberFailed { error, .. } = event {
                    seen.lock().unwrap().push(match error.operation() {
                        Some(zipfast::zip::ReadFault::PasswordCheckFailed { seven_zip, .. }) => *seven_zip,
                        _ => None,
                    });
                }
                Ok(())
            },
        )
        .unwrap();
        let failures = failures.lock().unwrap();
        assert_eq!(failures.len(), summary.errors.len(), "{archive}");
        assert!(failures.iter().all(|f| *f == Some(failure)), "{archive}: {failures:?}");
    }
    assert_eq!(EncryptedFailure::DataError.seven_zip_message(), "Data Error in encrypted file. Wrong password?");
    assert_eq!(EncryptedFailure::CrcFailed.seven_zip_message(), "CRC Failed in encrypted file. Wrong password?");
}

#[test]
fn a_7z_member_outcome_carries_the_failure() {
    use zipfast::zip::{ReadFault, ZipRunEvent};
    let tmp = tempfile::tempdir().unwrap();
    // the legacy route: SevenZipError::of finds it in the failing run's error for encrypted headers (no member), and
    // each member's line names it
    let error = extract::run_with_password(
        &fixture("7z-extract", "aes_hdr.7z"),
        &options(Mode::Test, tmp.path()),
        Some("wrong"),
        |_| {},
    )
    .unwrap_err();
    assert!(matches!(SevenZipError::of(&error), Some(SevenZipError::WrongPassword { failure: None })));
    let mut kinds = Vec::new();
    extract::run_with_zip_policy(
        &fixture("7z-extract", "mixed_wrongpw.7z"),
        &options(Mode::Extract, &tmp.path().join("mixed")),
        Some("wrong"),
        &Cancellation::default(),
        &Default::default(),
        |event: ZipRunEvent<'_>| {
            match event {
                ZipRunEvent::MemberFailed { name, error, .. } => {
                    let typed = matches!(
                        error.operation(),
                        Some(ReadFault::PasswordCheckFailed { seven_zip: Some(EncryptedFailure::DataError), .. })
                    );
                    kinds.push((name.to_owned(), typed));
                }
                ZipRunEvent::MemberSucceeded { name, .. } => kinds.push((name.to_owned(), false)),
                _ => {}
            }
            Ok(())
        },
    )
    .unwrap();
    // 7-Zip: p.txt extracted, a.txt "Data Error in encrypted file. Wrong password?"
    assert_eq!(kinds, [("p.txt".to_owned(), false), ("a.txt".to_owned(), true)]);
    let mut text = String::new();
    fs::File::open(tmp.path().join("mixed/p.txt")).unwrap().read_to_string(&mut text).unwrap();
    assert!(!text.is_empty());
}

// ---- `unix_modes` and `backslashes`: how 7-Zip 26.06 on Linux writes names and modes ----
//
// `7z x` under umask 022 gives a file stored 0777 mode 0755 and one stored 0666 mode 0644 (under umask 002, 0775 and
// 0664), drops setuid, setgid and sticky from files and folders alike, and gives a folder stored 0500 mode 0700
// (u+rwx first); the same in ZIP, 7z, RAR and tar. It writes `d\x\y.txt`, `a?b.txt` and `..\up.txt` of a ZIP made on
// Windows (host 0) as those single names, as it does for a ZIP made on Unix, and keeps a `\` in 7z and RAR 5.0 names
// whatever system made them.

/// A stored ZIP of `(name, data, mode)` entries: host Unix with the mode, or host MS-DOS (0) without one; a name
/// ending in `/` or `\` is a folder (MS-DOS attribute 0x10 for host 0).
fn stored_zip(entries: &[(&str, &[u8], Option<u32>)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data, mode) in entries {
        let crc = crc32fast::hash(data);
        let at = out.len() as u32;
        let common = |v: &mut Vec<u8>| {
            v.extend(0x0800u16.to_le_bytes());
            v.extend(0u16.to_le_bytes());
            v.extend(0u16.to_le_bytes());
            v.extend(((40u16 << 9) | (1 << 5) | 1).to_le_bytes());
            v.extend(crc.to_le_bytes());
            v.extend((data.len() as u32).to_le_bytes());
            v.extend((data.len() as u32).to_le_bytes());
            v.extend((name.len() as u16).to_le_bytes());
        };
        out.extend(0x0403_4b50u32.to_le_bytes());
        out.extend(20u16.to_le_bytes());
        common(&mut out);
        out.extend(0u16.to_le_bytes());
        out.extend(name.as_bytes());
        out.extend(*data);
        central.extend(0x0201_4b50u32.to_le_bytes());
        central.extend(((if mode.is_some() { 3u16 << 8 } else { 0 }) | 20).to_le_bytes());
        central.extend(20u16.to_le_bytes());
        common(&mut central);
        central.extend([0; 8]);
        let folder = name.ends_with('/') || name.ends_with('\\');
        let external = match mode {
            Some(mode) => (mode << 16) | (u32::from(folder) * 0x10),
            None => u32::from(folder) * 0x10,
        };
        central.extend(external.to_le_bytes());
        central.extend(at.to_le_bytes());
        central.extend(name.as_bytes());
    }
    let cd = out.len() as u32;
    out.extend(&central);
    out.extend(0x0605_4b50u32.to_le_bytes());
    out.extend([0; 4]);
    out.extend((entries.len() as u16).to_le_bytes());
    out.extend((entries.len() as u16).to_le_bytes());
    out.extend((central.len() as u32).to_le_bytes());
    out.extend(cd.to_le_bytes());
    out.extend(0u16.to_le_bytes());
    out
}

/// Every path under `root`, `/`-separated, with `/` after a folder.
fn paths(root: &Path) -> Vec<String> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.strip_prefix(root).unwrap().to_string_lossy().into_owned();
            if fs::symlink_metadata(&path).unwrap().is_dir() {
                out.push(format!("{name}/"));
                walk(root, &path, out);
            } else {
                out.push(name);
            }
        }
    }
    let mut out = Vec::new();
    if root.exists() {
        walk(root, root, &mut out);
    }
    out.sort();
    out
}

fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
}

/// Extracts `archive` through the legacy runner and the checked dispatcher with `options`, each into its own folder.
fn both_routes(archive: &Path, options: &Options, out: &Path) -> [PathBuf; 2] {
    let legacy = out.join("legacy");
    extract::run_with_password(archive, &Options { dest: legacy.clone(), ..options.clone() }, None, |_| {}).unwrap();
    let checked = out.join("checked");
    extract::run_with_zip_policy(
        archive,
        &Options { dest: checked.clone(), ..options.clone() },
        None,
        &Cancellation::default(),
        &Default::default(),
        |_: zipfast::zip::ZipRunEvent<'_>| Ok(()),
    )
    .unwrap();
    [legacy, checked]
}

#[test]
fn literal_backslashes_keep_a_windows_zip_name_whole() {
    let tmp = tempfile::tempdir().unwrap();
    let archive = tmp.path().join("dos.zip");
    let entries: &[(&str, &[u8], Option<u32>)] = &[
        ("d\\x\\y.txt", b"y", None),
        ("a?b.txt", b"q", None),
        ("..\\up.txt", b"u", None),
        ("\\abs.txt", b"a", None),
        ("e/f\\g", b"g", None),
        ("plain\\", b"", None),
    ];
    fs::write(&archive, stored_zip(entries)).unwrap();
    let literal = Options { backslashes: extract::Backslashes::Literal, ..options(Mode::Extract, tmp.path()) };
    for out in both_routes(&archive, &literal, &tmp.path().join("literal")) {
        assert_eq!(
            paths(&out),
            ["..\\up.txt", "\\abs.txt", "a?b.txt", "d\\x\\y.txt", "e/", "e/f\\g", "plain\\/"],
            "{out:?}"
        );
        assert_eq!(fs::read(out.join("d\\x\\y.txt")).unwrap(), b"y");
    }
    // By format: separators, `_` for `?`, and the names that climb out or start at the root refused.
    let by_format = options(Mode::Extract, tmp.path());
    let legacy = tmp.path().join("by-format");
    let _ = extract::run_with_password(&archive, &Options { dest: legacy.clone(), ..by_format }, None, |_| {});
    assert_eq!(paths(&legacy), ["a_b.txt", "d/", "d/x/", "d/x/y.txt", "e/", "e/f/", "e/f/g", "plain/"]);
    assert!(!tmp.path().join("up.txt").exists());
}

#[test]
fn literal_backslashes_keep_a_windows_rar5_name_whole() {
    let tmp = tempfile::tempdir().unwrap();
    let rar = tmp.path().join("win.rar");
    let mut spec = FileSpec::new("t/x\\y", b"payload");
    spec.unix_mode = None;
    fs::write(&rar, archive(&[spec])).unwrap();
    let out = tmp.path().join("out");
    let literal = Options { backslashes: extract::Backslashes::Literal, ..options(Mode::Extract, &out) };
    extract::run_with_password(&rar, &literal, None, |_| {}).unwrap();
    assert_eq!(paths(&out), ["t/", "t/x\\y"]);
    let by_format = tmp.path().join("by-format");
    extract::run_with_password(&rar, &options(Mode::Extract, &by_format), None, |_| {}).unwrap();
    assert_eq!(paths(&by_format), ["t/", "t/x_y"]);
}

#[test]
fn masked_unix_modes_narrow_stored_modes_by_the_umask() {
    let tmp = tempfile::tempdir().unwrap();
    let archive = tmp.path().join("modes.zip");
    let entries: &[(&str, &[u8], Option<u32>)] = &[
        ("d/", b"", Some(0o40500)),
        ("s/", b"", Some(0o41777)),
        ("d/f777", b"a", Some(0o100777)),
        ("d/f666", b"b", Some(0o100666)),
        ("d/f4755", b"c", Some(0o104755)),
        ("d/f640", b"d", Some(0o100640)),
    ];
    fs::write(&archive, stored_zip(entries)).unwrap();
    for (umask, expected) in [
        (0o022, [0o700, 0o755, 0o755, 0o644, 0o755, 0o640]),
        (0o002, [0o700, 0o775, 0o775, 0o664, 0o755, 0o640]),
        (0o077, [0o700, 0o700, 0o700, 0o600, 0o700, 0o600]),
    ] {
        let masked = Options { unix_modes: extract::UnixModes::Masked { umask }, ..options(Mode::Extract, tmp.path()) };
        for out in both_routes(&archive, &masked, &tmp.path().join(format!("{umask:o}"))) {
            let found = ["d", "s", "d/f777", "d/f666", "d/f4755", "d/f640"].map(|name| mode_of(&out.join(name)));
            assert_eq!(found, expected, "umask {umask:o} {out:?}");
        }
    }
    // Stored: the permission bits as stored, without setuid, setgid and sticky.
    for out in both_routes(&archive, &options(Mode::Extract, tmp.path()), &tmp.path().join("stored")) {
        let found = ["d", "s", "d/f777", "d/f666", "d/f4755"].map(|name| mode_of(&out.join(name)));
        assert_eq!(found, [0o500, 0o777, 0o777, 0o666, 0o755], "{out:?}");
    }
}

#[test]
fn masked_unix_modes_apply_to_7z_and_rar_members() {
    let tmp = tempfile::tempdir().unwrap();
    // tree.7z: text/run.sh is stored 0755.
    let out = tmp.path().join("7z");
    let masked = Options { unix_modes: extract::UnixModes::Masked { umask: 0o027 }, ..options(Mode::Extract, &out) };
    extract::run_with_password(&fixture("7z-extract", "tree.7z"), &masked, None, |_| {}).unwrap();
    assert_eq!(mode_of(&out.join("text/run.sh")), 0o750);
    let rar = tmp.path().join("modes.rar");
    let mut spec = FileSpec::new("f", b"x");
    spec.unix_mode = Some(0o100777);
    fs::write(&rar, archive(&[spec])).unwrap();
    let out = tmp.path().join("rar");
    let masked = Options { unix_modes: extract::UnixModes::Masked { umask: 0o002 }, ..options(Mode::Extract, &out) };
    extract::run_with_password(&rar, &masked, None, |_| {}).unwrap();
    assert_eq!(mode_of(&out.join("f")), 0o775);
}

/// Codex on #301: under literal backslashes a folder named `\` or `.\` is a folder of that name, not the destination
/// root (by format both name the root and are passed over).
#[test]
fn literal_backslashes_keep_backslash_named_folders() {
    let tmp = tempfile::tempdir().unwrap();
    let archive = tmp.path().join("dirs.zip");
    let entries: &[(&str, &[u8], Option<u32>)] = &[("\\/", b"", None), (".\\/", b"", None), ("f.txt", b"f", None)];
    fs::write(&archive, stored_zip(entries)).unwrap();
    let literal = Options { backslashes: extract::Backslashes::Literal, ..options(Mode::Extract, tmp.path()) };
    for out in both_routes(&archive, &literal, &tmp.path().join("literal")) {
        assert_eq!(paths(&out), [".\\/", "\\/", "f.txt"], "{out:?}");
    }
    let legacy = tmp.path().join("by-format");
    extract::run_with_password(&archive, &options(Mode::Extract, &legacy), None, |_| {}).unwrap();
    assert_eq!(paths(&legacy), ["f.txt"]);
}

/// Codex on #301: under literal backslashes a Windows-made RAR 5.0 hard link or file copy finds its target by the
/// same literal name the target was written under (never a different `d_x.txt`).
#[test]
fn literal_backslashes_map_rar5_link_targets_as_names() {
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
    let windows = |mut spec: FileSpec<'static>| {
        spec.unix_mode = None;
        spec
    };
    let link = |name: &'static str, kind| {
        windows(FileSpec { extra: redirection(kind, "d\\x.txt"), ..FileSpec::new(name, b"") })
    };
    let tmp = tempfile::tempdir().unwrap();
    let rar = tmp.path().join("links.rar");
    let files = [
        windows(FileSpec::new("d_x.txt", b"decoy")),
        windows(FileSpec::new("d\\x.txt", b"target")),
        link("hard.txt", 4),
        link("copy.txt", 5),
    ];
    fs::write(&rar, archive(&files)).unwrap();
    let out = tmp.path().join("out");
    let literal = Options { backslashes: extract::Backslashes::Literal, ..options(Mode::Extract, &out) };
    let summary = extract::run_with_password(&rar, &literal, None, |_| {}).unwrap();
    assert!(summary.errors.is_empty(), "{:?}", summary.errors);
    assert_eq!(fs::read(out.join("d\\x.txt")).unwrap(), b"target");
    assert_eq!(fs::read(out.join("hard.txt")).unwrap(), b"target");
    assert_eq!(fs::read(out.join("copy.txt")).unwrap(), b"target");
}
