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

//! 7z extraction: every coder against archives 7-Zip wrote (`tests/fixtures/7z-extract`, see its README), and
//! hand-built archives for the cases 7-Zip will not write (unsafe names, bad checksums, oversized folders).
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use zipfast::Error;
use zipfast::extract::{self, Cancellation, MemberFilter, Mode, Options, Overwrite};
use zipfast::sevenzip::{self, SevenZipError, SevenZipLimit, SevenZipLimits};

/// The 7z failure a run returned.
fn seven(result: &Result<extract::Summary, Error>) -> Option<&SevenZipError> {
    result.as_ref().err().and_then(SevenZipError::of)
}

type LimitCase = (&'static str, fn(&mut SevenZipLimits), SevenZipLimit);

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/7z-extract");

fn fixture(name: &str) -> PathBuf {
    Path::new(FIXTURES).join(name)
}

/// Size and SHA-256 of each input file the fixtures were made from.
fn expected() -> HashMap<String, (u64, String)> {
    fs::read_to_string(fixture("expected.txt"))
        .unwrap()
        .lines()
        .map(|line| {
            let mut parts = line.split(' ');
            let name = parts.next().unwrap().to_owned();
            let size = parts.next().unwrap().parse().unwrap();
            (name, (size, parts.next().unwrap().to_owned()))
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn opts(mode: Mode, dest: &Path) -> Options {
    Options {
        mode,
        dest: dest.to_path_buf(),
        overwrite: Overwrite::Skip,
        flatten: false,
        threads: None,
        protected_paths: Default::default(),
        parallel_min: None,
        select: None,
    }
}

/// Extracts `archive` and checks each listed file against the inputs.
fn extracts_to(archive: &str, password: Option<&str>, files: &[&str]) {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    let mut lines = Vec::new();
    let summary = extract::run_with_password(&fixture(archive), &opts(Mode::Extract, &out), password, |l| {
        lines.push(l.to_owned())
    })
    .unwrap_or_else(|e| panic!("{archive}: {e}"));
    assert!(summary.errors.is_empty() && lines.is_empty(), "{archive}: {:?} {lines:?}", summary.errors);
    assert_eq!(summary.files, files.len() as u64, "{archive}");
    let want = expected();
    for file in files {
        let data = fs::read(out.join(file)).unwrap_or_else(|e| panic!("{archive}: {file}: {e}"));
        let (size, sha) = &want[*file];
        assert_eq!(
            (data.len() as u64, hex(&zipfast::crypto::sha256(&data))),
            (*size, sha.clone()),
            "{archive}: {file}"
        );
    }
    // Testing reads the same and writes nothing.
    let tested =
        extract::run_with_password(&fixture(archive), &opts(Mode::Test, &dir.path().join("t")), password, |_| {})
            .unwrap();
    assert_eq!((tested.files, tested.errors.len()), (files.len() as u64, 0), "{archive}");
    assert!(!dir.path().join("t").exists());
}

#[test]
fn every_coder_extracts() {
    extracts_to("copy.7z", None, &["text/a.txt", "text/b.txt", "text/tiny.txt"]);
    extracts_to("lzma.7z", None, &["text/a.txt", "text/b.txt"]);
    extracts_to("lzma2.7z", None, &["text/a.txt", "text/b.txt"]);
    extracts_to("deflate.7z", None, &["text/a.txt", "text/b.txt"]);
    extracts_to("bzip2.7z", None, &["text/a.txt", "text/b.txt"]);
    extracts_to("delta.7z", None, &["delta/samples.raw"]);
    for arch in ["x86", "arm", "armt", "arm64", "ppc", "sparc", "ia64"] {
        extracts_to(&format!("bcj_{arch}.7z"), None, &[&format!("code/{arch}.bin")]);
    }
    extracts_to("bcj2.7z", None, &["code/x86.bin"]);
}

#[test]
fn the_branch_fixtures_use_the_coders_they_are_named_for() {
    use zipfast::map::{CoderKind, MemberMap};
    for (name, kind) in [
        ("bcj_x86.7z", CoderKind::Bcj),
        ("bcj_arm.7z", CoderKind::Arm),
        ("bcj_armt.7z", CoderKind::ArmThumb),
        ("bcj_arm64.7z", CoderKind::Arm64),
        ("bcj_ppc.7z", CoderKind::PowerPc),
        ("bcj_sparc.7z", CoderKind::Sparc),
        ("bcj_ia64.7z", CoderKind::Ia64),
        ("bcj2.7z", CoderKind::Bcj2),
        ("delta.7z", CoderKind::Delta),
        ("deflate.7z", CoderKind::Deflate),
        ("bzip2.7z", CoderKind::Bzip2),
        ("lzma.7z", CoderKind::Lzma),
        ("lzma2.7z", CoderKind::Lzma2),
    ] {
        let bytes = fs::read(fixture(name)).unwrap();
        let map = MemberMap::from_memory(&[&bytes], name, None).unwrap();
        assert!(map.folders[0].coders.iter().any(|c| c.kind == kind), "{name}");
    }
}

#[test]
fn solid_trees_split_sets_and_encryption() {
    extracts_to(
        "solid.7z",
        None,
        &["big/one.txt", "big/two.txt", "text/a.txt", "text/b.txt", "text/run.sh", "text/tiny.txt"],
    );
    extracts_to("tree.7z", None, &["tree/sub/file.txt", "tree/empty.txt", "text/run.sh"]);
    extracts_to("split.7z.001", None, &["noise/noise.bin", "text/tiny.txt"]);
    extracts_to("aes.7z", Some("password"), &["text/a.txt", "text/b.txt"]);
    extracts_to("aes_hdr.7z", Some("password"), &["text/a.txt", "text/b.txt"]);
    extracts_to("aes_copy.7z", Some("password"), &["text/tiny.txt"]);
}

#[test]
fn empty_entries_times_and_modes_are_restored() {
    let dir = tempfile::tempdir().unwrap();
    let summary = extract::run(&fixture("tree.7z"), &opts(Mode::Extract, dir.path()), |_| {}).unwrap();
    assert_eq!((summary.files, summary.dirs), (3, 3));
    assert!(dir.path().join("tree/emptydir").is_dir());
    assert_eq!(fs::metadata(dir.path().join("tree/empty.txt")).unwrap().len(), 0);
    // 2020-01-02 03:04:05 in the generating machine's local time: within a day of that in UTC.
    let mtime = fs::metadata(dir.path().join("tree/sub/file.txt")).unwrap().modified().unwrap();
    let secs = mtime.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    assert!((secs - 1_577_934_245).abs() < 86_400, "{secs}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(dir.path().join("text/run.sh")).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755);
    }
}

#[test]
fn listing_reports_members_in_order() {
    let entries = extract::list(&fixture("tree.7z")).unwrap();
    let names: Vec<_> = entries.iter().map(|e| (e.name.as_str(), e.dir, e.size)).collect();
    assert_eq!(
        names,
        [
            ("tree", true, 0),
            ("tree/emptydir", true, 0),
            ("tree/sub", true, 0),
            ("tree/empty.txt", false, 0),
            ("text/run.sh", false, 18),
            ("tree/sub/file.txt", false, 500),
        ]
    );
    assert_eq!(entries[4].mode.map(|m| m & 0o777), Some(0o755));
    assert!(entries[4].solid && entries[5].crc32.is_some());
    let encrypted = extract::list_with_password(&fixture("aes_hdr.7z"), Some("password")).unwrap();
    assert!(encrypted.iter().all(|e| e.encrypted));
    assert!(matches!(extract::list(&fixture("aes_hdr.7z")), Err(Error::Encrypted)));
}

#[test]
fn passwords_missing_and_wrong_are_typed() {
    let dir = tempfile::tempdir().unwrap();
    for archive in ["aes.7z", "aes_hdr.7z", "aes_copy.7z"] {
        let out = dir.path().join(archive);
        let missing = extract::run(&fixture(archive), &opts(Mode::Extract, &out), |_| {});
        assert!(matches!(missing, Err(Error::Encrypted)), "{archive}: {missing:?}");
        assert_eq!(missing.unwrap_err().to_string(), "encrypted: a password is required, or the one given is wrong");
        let wrong = extract::run_with_password(&fixture(archive), &opts(Mode::Extract, &out), Some("wrong"), |_| {});
        assert!(matches!(seven(&wrong), Some(SevenZipError::WrongPassword)), "{archive}: {wrong:?}");
        assert_eq!(wrong.unwrap_err().to_string(), "7z: wrong password");
        // Nothing was published.
        assert!(fs::read_dir(&out).map_or(true, |d| d.flatten().all(|e| e.path().is_dir())), "{archive}");
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
#[allow(clippy::result_large_err)]
fn the_checked_dispatcher_runs_7z_with_typed_password_faults() {
    use zipfast::zip::{CipherKind, ReadFault, ZipRunEvent};
    let dir = tempfile::tempdir().unwrap();
    let options = opts(Mode::Extract, dir.path());
    let run = |archive: &str, password: Option<&str>, cancel: &Cancellation| {
        extract::run_with_zip_policy(
            &fixture(archive),
            &options,
            password,
            cancel,
            &Default::default(),
            |_: ZipRunEvent<'_>| Ok(()),
        )
    };
    let report = run("lzma2.7z", None, &Cancellation::default()).unwrap();
    assert_eq!((report.files(), report.failed()), (2, 0));
    let error = run("aes.7z", None, &Cancellation::default()).unwrap_err();
    assert!(matches!(error.operation(), Some(ReadFault::PasswordRequired)), "{error:?}");
    let error = run("aes.7z", Some("wrong"), &Cancellation::default()).unwrap_err();
    assert!(matches!(error.operation(), Some(ReadFault::PasswordCheckFailed { cipher: CipherKind::Aes })));
    let canceled = Cancellation::default();
    canceled.cancel();
    let error = run("lzma.7z", None, &canceled).unwrap_err();
    assert!(matches!(error.operation(), Some(ReadFault::Cancelled)), "{error:?}");
    let error = run("ppmd.7z", None, &Cancellation::default()).unwrap_err();
    let Some(ReadFault::Legacy(legacy)) = error.operation() else { panic!("{error:?}") };
    assert!(matches!(SevenZipError::of(legacy), Some(SevenZipError::UnsupportedCoder { id: 0x03_0401 })));
}

#[test]
fn ppmd_is_refused_before_anything_is_written() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    let result = extract::run(&fixture("ppmd.7z"), &opts(Mode::Extract, &out), |_| {});
    assert!(matches!(seven(&result), Some(SevenZipError::UnsupportedCoder { id: 0x03_0401 })), "{result:?}");
    assert!(!out.exists());
}

#[test]
fn a_bad_crc_is_not_published() {
    let dir = tempfile::tempdir().unwrap();
    let mut bytes = fs::read(fixture("copy.7z")).unwrap();
    // copy.7z stores text/a.txt first, right after the signature header.
    bytes[32 + 100] ^= 1;
    let archive = dir.path().join("bad.7z");
    fs::write(&archive, &bytes).unwrap();
    let out = dir.path().join("out");
    let summary = extract::run(&archive, &opts(Mode::Extract, &out), |_| {}).unwrap();
    assert_eq!(summary.files, 2);
    assert_eq!(summary.errors, ["text/a.txt: checksum error in text/a.txt"]);
    assert!(!out.join("text/a.txt").exists());
    assert!(out.join("text/b.txt").exists());
    // No temporary file is left behind.
    assert_eq!(fs::read_dir(out.join("text")).unwrap().count(), 2);
}

#[test]
fn overwrite_skip_and_always() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    fs::create_dir_all(out.join("text")).unwrap();
    fs::write(out.join("text/a.txt"), b"old").unwrap();
    let mut lines = Vec::new();
    let summary = extract::run(&fixture("lzma.7z"), &opts(Mode::Extract, &out), |l| lines.push(l.to_owned())).unwrap();
    assert_eq!((summary.files, summary.skipped), (1, 1));
    assert_eq!(lines, ["text/a.txt: exists, skipped"]);
    assert_eq!(fs::read(out.join("text/a.txt")).unwrap(), b"old");
    let mut always = opts(Mode::Extract, &out);
    always.overwrite = Overwrite::Always;
    let summary = extract::run(&fixture("lzma.7z"), &always, |_| {}).unwrap();
    assert_eq!((summary.files, summary.skipped), (2, 0));
    assert_eq!(fs::read(out.join("text/a.txt")).unwrap().len(), 5999);
}

#[cfg(unix)]
#[test]
fn a_symlink_at_the_target_is_never_written_through() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    fs::create_dir_all(out.join("text")).unwrap();
    let victim = dir.path().join("victim");
    fs::write(&victim, b"keep").unwrap();
    std::os::unix::fs::symlink(&victim, out.join("text/a.txt")).unwrap();
    let mut always = opts(Mode::Extract, &out);
    always.overwrite = Overwrite::Always;
    let summary = extract::run(&fixture("lzma.7z"), &always, |_| {}).unwrap();
    assert_eq!(summary.errors, ["text/a.txt: a symlink is in the way"]);
    assert_eq!(fs::read(&victim).unwrap(), b"keep");
    // A linked folder is refused too.
    let out2 = dir.path().join("out2");
    fs::create_dir_all(&out2).unwrap();
    std::os::unix::fs::symlink(dir.path(), out2.join("text")).unwrap();
    assert!(extract::run(&fixture("lzma.7z"), &opts(Mode::Extract, &out2), |_| {}).is_err());
    assert!(!dir.path().join("a.txt").exists());
}

#[test]
fn a_filter_decodes_through_the_solid_block() {
    let dir = tempfile::tempdir().unwrap();
    let mut options = opts(Mode::Extract, dir.path());
    options.select = Some(MemberFilter::new(|m| m.name == "text/tiny.txt"));
    let summary = extract::run(&fixture("solid.7z"), &options, |_| {}).unwrap();
    assert_eq!((summary.files, summary.matched), (1, 1));
    assert_eq!(fs::read(dir.path().join("text/tiny.txt")).unwrap(), b"hello 7z\n");
    assert!(!dir.path().join("big").exists());
}

#[test]
fn cancellation_mid_folder_publishes_nothing_more() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("big")).unwrap();
    fs::write(dir.path().join("big/one.txt"), b"there").unwrap();
    let cancel = Cancellation::default();
    let limits = SevenZipLimits::default();
    // big/one.txt is the first member of the solid block: skipping it cancels before big/two.txt.
    let result = sevenzip::run(&fixture("solid.7z"), &opts(Mode::Extract, dir.path()), None, &cancel, &limits, |_| {
        cancel.cancel()
    });
    assert!(matches!(seven(&result), Some(SevenZipError::Canceled)), "{result:?}");
    assert_eq!(fs::read_dir(dir.path().join("big")).unwrap().count(), 1, "no temporary file is left");
    // The folder entries come first in the listing; no file went into them.
    assert!(fs::read_dir(dir.path().join("text")).map_or(true, |mut d| d.next().is_none()));
}

#[test]
fn a_missing_volume_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    for n in ["001", "002"] {
        fs::copy(fixture(&format!("split.7z.{n}")), dir.path().join(format!("split.7z.{n}"))).unwrap();
    }
    let result = extract::run(&dir.path().join("split.7z.001"), &opts(Mode::Test, dir.path()), |_| {});
    match result {
        Err(Error::MissingVolume(path)) => assert!(path.ends_with("split.7z.003")),
        other => panic!("{other:?}"),
    }
}

#[test]
fn limits_are_typed() {
    let dir = tempfile::tempdir().unwrap();
    let cases: [LimitCase; 6] = [
        ("copy.7z", |l| l.folder_bytes = 100, SevenZipLimit::FolderBytes),
        ("copy.7z", |l| l.folders = 2, SevenZipLimit::Folders),
        ("copy.7z", |l| l.pack_streams = 2, SevenZipLimit::PackStreams),
        ("copy.7z", |l| l.entries = 2, SevenZipLimit::Entries),
        ("bcj2.7z", |l| l.coders = 3, SevenZipLimit::Coders),
        ("lzma2.7z", |l| l.dictionary_bytes = 4096, SevenZipLimit::DictionaryBytes),
    ];
    for (archive, set, want) in cases {
        let mut limits = SevenZipLimits::default();
        set(&mut limits);
        let result = sevenzip::run(
            &fixture(archive),
            &opts(Mode::Test, dir.path()),
            None,
            &Cancellation::default(),
            &limits,
            |_| {},
        );
        match seven(&result) {
            Some(SevenZipError::Limit { limit, .. }) => assert_eq!(*limit, want, "{archive}"),
            _ => panic!("{archive}: {result:?}"),
        }
    }
}

// ---- Hand-built archives ----

fn num(out: &mut Vec<u8>, value: u64) {
    let bytes = value.to_le_bytes();
    let extra = (0..=8).find(|&n| n == 8 || value < 1u64 << (7 * (n + 1))).unwrap();
    if extra == 8 {
        out.push(0xFF);
        out.extend_from_slice(&bytes);
        return;
    }
    let first = (0xFFu16 << (8 - extra)) as u8 | (value >> (8 * extra)) as u8;
    out.push(first);
    out.extend_from_slice(&bytes[..extra]);
}

/// One Copy folder per group of files (a group of several shares a folder), plain header.
struct Built {
    /// Coders per folder: a chain of this many Copy coders.
    chain: usize,
    /// Property bytes on each coder.
    props: usize,
    /// A folder CRC to store (else the per-file CRCs are stored).
    folder_crc: Option<u32>,
}

impl Default for Built {
    fn default() -> Self {
        Self { chain: 1, props: 0, folder_crc: None }
    }
}

impl Built {
    fn archive(&self, groups: &[Vec<(&str, &[u8])>]) -> Vec<u8> {
        let mut packed = Vec::new();
        let mut h = vec![0x01, 0x04, 0x06, 0x00];
        num(&mut h, groups.len() as u64);
        h.push(0x09);
        for group in groups {
            let data: Vec<u8> = group.iter().flat_map(|(_, d)| d.iter().copied()).collect();
            num(&mut h, data.len() as u64);
            packed.extend_from_slice(&data);
        }
        h.extend([0x00, 0x07, 0x0B]);
        num(&mut h, groups.len() as u64);
        h.push(0x00);
        for _ in groups {
            num(&mut h, self.chain as u64);
            for _ in 0..self.chain {
                if self.props > 0 {
                    h.extend([0x21, 0x00]);
                    num(&mut h, self.props as u64);
                    h.extend(std::iter::repeat_n(0, self.props));
                } else {
                    h.extend([0x01, 0x00]);
                }
            }
            for i in 0..self.chain - 1 {
                num(&mut h, i as u64);
                num(&mut h, i as u64 + 1);
            }
        }
        h.push(0x0C);
        for group in groups {
            let len: usize = group.iter().map(|(_, d)| d.len()).sum();
            for _ in 0..self.chain {
                num(&mut h, len as u64);
            }
        }
        if let Some(crc) = self.folder_crc {
            h.extend([0x0A, 0x01]);
            for _ in groups {
                h.extend(crc.to_le_bytes());
            }
        }
        h.extend([0x00, 0x08, 0x0D]);
        for group in groups {
            num(&mut h, group.len() as u64);
        }
        h.push(0x09);
        for group in groups {
            for (_, data) in &group[..group.len() - 1] {
                num(&mut h, data.len() as u64);
            }
        }
        h.extend([0x0A, 0x01]);
        for (_, data) in groups.iter().flatten() {
            h.extend(crc32fast::hash(data).to_le_bytes());
        }
        h.extend([0x00, 0x00, 0x05]);
        let files: Vec<&str> = groups.iter().flatten().map(|(n, _)| *n).collect();
        num(&mut h, files.len() as u64);
        let mut names = vec![0u8];
        for name in &files {
            names.extend(name.encode_utf16().flat_map(u16::to_le_bytes));
            names.extend([0, 0]);
        }
        h.push(0x11);
        num(&mut h, names.len() as u64);
        h.extend(names);
        h.extend([0x00, 0x00]);
        let mut start = [0u8; 20];
        start[..8].copy_from_slice(&(packed.len() as u64).to_le_bytes());
        start[8..16].copy_from_slice(&(h.len() as u64).to_le_bytes());
        start[16..].copy_from_slice(&crc32fast::hash(&h).to_le_bytes());
        let mut out = vec![b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C, 0, 4];
        out.extend(crc32fast::hash(&start).to_le_bytes());
        out.extend(start);
        out.extend(packed);
        out.extend(h);
        out
    }
}

fn write(dir: &Path, bytes: &[u8]) -> PathBuf {
    let path = dir.join("built.7z");
    fs::write(&path, bytes).unwrap();
    path
}

#[test]
fn the_hand_built_archive_extracts() {
    let dir = tempfile::tempdir().unwrap();
    let archive = write(dir.path(), &Built::default().archive(&[vec![("a.txt", b"one"), ("b/c.txt", b"two")]]));
    let out = dir.path().join("out");
    let summary = extract::run(&archive, &opts(Mode::Extract, &out), |_| {}).unwrap();
    assert_eq!((summary.files, summary.errors.len()), (2, 0));
    assert_eq!(fs::read(out.join("b/c.txt")).unwrap(), b"two");
}

#[test]
fn unsafe_names_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let archive = write(
        dir.path(),
        &Built::default().archive(&[vec![
            ("../evil.txt", b"x"),
            ("/abs.txt", b"y"),
            ("a/../../up.txt", b"z"),
            ("..\\back.txt", b"w"),
            ("ok.txt", b"ok"),
        ]]),
    );
    let out = dir.path().join("deep/out");
    let summary = extract::run(&archive, &opts(Mode::Extract, &out), |_| {}).unwrap();
    assert_eq!(summary.files, 1);
    assert_eq!(summary.errors.len(), 4, "{:?}", summary.errors);
    assert!(summary.errors.iter().all(|e| e.contains("unsafe path refused")));
    assert_eq!(fs::read(out.join("ok.txt")).unwrap(), b"ok");
    for escaped in ["deep/evil.txt", "evil.txt", "up.txt", "deep/up.txt", "deep/back.txt"] {
        assert!(!dir.path().join(escaped).exists(), "{escaped}");
    }
}

#[test]
fn a_bad_folder_crc_holds_back_the_whole_block() {
    let dir = tempfile::tempdir().unwrap();
    let built = Built { folder_crc: Some(0xDEAD_BEEF), ..Built::default() };
    let archive = write(dir.path(), &built.archive(&[vec![("a.txt", b"one"), ("b.txt", b"two")]]));
    let out = dir.path().join("out");
    let summary = extract::run(&archive, &opts(Mode::Extract, &out), |_| {}).unwrap();
    assert_eq!(summary.files, 0);
    assert_eq!(summary.errors.len(), 2, "{:?}", summary.errors);
    assert!(fs::read_dir(&out).unwrap().next().is_none());
    // With the right folder CRC both are published.
    let built = Built { folder_crc: Some(crc32fast::hash(b"onetwo")), ..Built::default() };
    let archive = write(dir.path(), &built.archive(&[vec![("a.txt", b"one"), ("b.txt", b"two")]]));
    let summary = extract::run(&archive, &opts(Mode::Extract, &out), |_| {}).unwrap();
    assert_eq!((summary.files, summary.errors.len()), (2, 0));
}

#[test]
fn default_bounds_on_coders_and_properties() {
    let dir = tempfile::tempdir().unwrap();
    let ok = write(dir.path(), &Built { chain: 32, ..Built::default() }.archive(&[vec![("a.txt", b"chained")]]));
    let summary = extract::run(&ok, &opts(Mode::Extract, &dir.path().join("o")), |_| {}).unwrap();
    assert_eq!(summary.files, 1);
    let cases = [
        (Built { chain: 33, ..Built::default() }, SevenZipLimit::Coders, 33),
        (Built { props: 65, ..Built::default() }, SevenZipLimit::CoderProperties, 65),
    ];
    for (built, want, attempted_want) in cases {
        let archive = write(dir.path(), &built.archive(&[vec![("a.txt", b"x")]]));
        let result = extract::run(&archive, &opts(Mode::Test, dir.path()), |_| {});
        match seven(&result) {
            Some(SevenZipError::Limit { limit, attempted, .. }) => {
                assert_eq!((*limit, *attempted), (want, attempted_want))
            }
            _ => panic!("{result:?}"),
        }
    }
}

#[test]
fn default_bounds_on_folders_and_entries() {
    let dir = tempfile::tempdir().unwrap();
    let data = [0u8; 1];
    let groups: Vec<Vec<(&str, &[u8])>> = (0..4097).map(|_| vec![("f", &data[..])]).collect();
    let archive = write(dir.path(), &Built::default().archive(&groups));
    let result = extract::run(&archive, &opts(Mode::Test, dir.path()), |_| {});
    assert!(
        matches!(seven(&result), Some(SevenZipError::Limit { limit: SevenZipLimit::Folders, attempted: 4097, .. })),
        "{result:?}"
    );
    let group: Vec<(&str, &[u8])> = (0..65537).map(|_| ("f", &data[..0])).collect();
    let archive = write(dir.path(), &Built::default().archive(&[group]));
    let result = extract::run(&archive, &opts(Mode::Test, dir.path()), |_| {});
    assert!(matches!(seven(&result), Some(SevenZipError::Limit { limit: SevenZipLimit::Entries, .. })), "{result:?}");
}

/// Progressive sessions read RAR only: a 7z archive is refused and nothing is written.
#[test]
fn progressive_sessions_refuse_7z() {
    use std::task::{Context, Poll, Waker};
    use zipfast::progressive::*;
    struct Bytes(Vec<u8>);
    impl RangeSource for Bytes {
        fn info(&self) -> SourceInfo {
            let len = self.0.len() as u64;
            SourceInfo { id: SourceId(1), generation: 0, extent: len, length: SourceLength::Final(len) }
        }
        fn backing_files(&self) -> &[fs::File] {
            &[]
        }
        fn read_at(&mut self, at: u64, buf: &mut [u8], _: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
            let at = at as usize;
            let n = buf.len().min(self.0.len().saturating_sub(at));
            buf[..n].copy_from_slice(&self.0[at..at + n]);
            Ok(RangeRead::Filled { count: n })
        }
    }
    struct Provider(Option<Bytes>);
    impl VolumeSource for Provider {
        fn volume(&mut self, _: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
            Ok(self.0.take().map_or(VolumeAnswer::Missing, |b| VolumeAnswer::Ready(Box::new(b))))
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let options = ProgressiveOptions::new(opts(Mode::Extract, dir.path()), "copy.7z".into());
    let provider = Provider(Some(Bytes(fs::read(fixture("copy.7z")).unwrap())));
    let mut refused = false;
    match ProgressiveSession::new(Box::new(provider), options) {
        Err(_) => refused = true,
        Ok(mut session) => {
            for _ in 0..10_000 {
                match session.poll_event(&mut Context::from_waker(Waker::noop())) {
                    Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated { .. }))) | Poll::Ready(Err(_)) => {
                        refused = true;
                        break;
                    }
                    Poll::Ready(Ok(None)) => break,
                    _ => {}
                }
            }
        }
    }
    assert!(refused);
    assert!(fs::read_dir(dir.path()).unwrap().next().is_none());
}

#[test]
fn probe_reports_a_7z_head() {
    use zipfast::probe::{Borrowable, NotBorrowable, Packing, PasswordNeed, Undecided, probe};
    let seven = |packing: Packing| match packing {
        Packing::SevenZip(seven) => seven,
        other => panic!("{other:?}"),
    };
    // A first article: only the signature header.
    let bytes = fs::read(fixture("solid.7z")).unwrap();
    let head = seven(probe(&bytes[..1000], None, None).unwrap());
    assert_eq!((head.version, head.complete, head.archive_len), ((0, 4), false, bytes.len() as u64));
    assert_eq!(head.borrowable, Borrowable::Unknown(Undecided::Truncated));
    // A split set's first volume gives the whole set's length.
    let first = fs::read(fixture("split.7z.001")).unwrap();
    let total: u64 =
        ["001", "002", "003"].iter().map(|n| fs::metadata(fixture(&format!("split.7z.{n}"))).unwrap().len()).sum();
    assert_eq!(seven(probe(&first, None, None).unwrap()).archive_len, total);
    // A head holding the whole archive is listed.
    let whole = seven(probe(&fs::read(fixture("copy.7z")).unwrap(), None, None).unwrap());
    assert_eq!((whole.complete, whole.members), (true, 3));
    assert_eq!(whole.borrowable, Borrowable::Yes);
    let packed = seven(probe(&fs::read(fixture("lzma2.7z")).unwrap(), None, None).unwrap());
    assert_eq!(packed.borrowable, Borrowable::No(NotBorrowable::Compressed));
    let encrypted = fs::read(fixture("aes_copy.7z")).unwrap();
    assert_eq!(
        seven(probe(&encrypted, None, None).unwrap()).borrowable,
        Borrowable::NeedsPassword(PasswordNeed::DataEncrypted)
    );
    assert_eq!(seven(probe(&encrypted, None, Some("password")).unwrap()).borrowable, Borrowable::PasswordUnverified);
    let locked = fs::read(fixture("aes_hdr.7z")).unwrap();
    let packing = seven(probe(&locked, None, None).unwrap());
    assert!(packing.locked);
    assert_eq!(packing.borrowable, Borrowable::NeedsPassword(PasswordNeed::HeaderEncrypted));
    let wrong = seven(probe(&locked, None, Some("nope")).unwrap());
    assert_eq!(wrong.borrowable, Borrowable::NeedsPassword(PasswordNeed::WrongPassword));
    let right = seven(probe(&locked, None, Some("password")).unwrap());
    assert!(right.complete && right.header_encrypted && !right.locked);
}

// ---- Rename modes ----

fn renaming(dest: &Path, overwrite: Overwrite) -> Options {
    let mut options = opts(Mode::Extract, dest);
    options.overwrite = overwrite;
    options
}

#[test]
fn rename_modes_for_an_existing_target() {
    use zipfast::extract::RenameStyle;
    let a = expected()["text/a.txt"].1.clone();
    let sha = |path: &Path| hex(&zipfast::crypto::sha256(&fs::read(path).unwrap()));
    for (overwrite, renamed, new_at_renamed) in [
        (Overwrite::RenameNew(RenameStyle::Underscore), "a_1.txt", true),
        (Overwrite::RenameNew(RenameStyle::Parenthesized), "a(1).txt", true),
        (Overwrite::RenameExisting(RenameStyle::Underscore), "a_1.txt", false),
        (Overwrite::RenameExisting(RenameStyle::Parenthesized), "a(1).txt", false),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let text = dir.path().join("text");
        fs::create_dir_all(&text).unwrap();
        fs::write(text.join("a.txt"), b"old").unwrap();
        let mut lines = Vec::new();
        let summary =
            extract::run(&fixture("lzma.7z"), &renaming(dir.path(), overwrite), |l| lines.push(l.to_owned())).unwrap();
        assert_eq!((summary.files, summary.skipped, summary.errors.len()), (2, 0, 0), "{overwrite:?}");
        let (new, old) = if new_at_renamed {
            (text.join(renamed), text.join("a.txt"))
        } else {
            (text.join("a.txt"), text.join(renamed))
        };
        assert_eq!(sha(&new), a, "{overwrite:?}");
        assert_eq!(fs::read(&old).unwrap(), b"old", "{overwrite:?}");
        assert_eq!(summary.renames.len(), 1);
        let record = &summary.renames[0];
        assert_eq!(record.requested, text.join("a.txt"));
        if new_at_renamed {
            assert_eq!((record.path.clone(), record.existing.clone()), (text.join(renamed), None));
            assert_eq!(
                lines,
                [format!("{}: exists, written as {}", text.join("a.txt").display(), text.join(renamed).display())]
            );
        } else {
            assert_eq!((record.path.clone(), record.existing.clone()), (text.join("a.txt"), Some(text.join(renamed))));
            assert_eq!(
                lines,
                [format!("{}: existing file moved to {}", text.join("a.txt").display(), text.join(renamed).display())]
            );
        }
        // No temporary or reserved file is left behind.
        assert_eq!(fs::read_dir(&text).unwrap().count(), 3, "{overwrite:?}");
    }
}

#[test]
fn rename_modes_for_duplicate_members() {
    use zipfast::extract::RenameStyle;
    let dir = tempfile::tempdir().unwrap();
    let archive = write(dir.path(), &Built::default().archive(&[vec![("d.txt", b"first"), ("d.txt", b"second")]]));
    for (overwrite, at_name, at_renamed) in [
        (Overwrite::RenameNew(RenameStyle::Underscore), &b"first"[..], &b"second"[..]),
        (Overwrite::RenameExisting(RenameStyle::Underscore), b"second", b"first"),
    ] {
        let out = dir.path().join(format!("{overwrite:?}"));
        let summary = extract::run_with_renames(&archive, &renaming(&out, overwrite), None, |_| {}).unwrap();
        assert_eq!((summary.files, summary.renames.len()), (2, 1), "{overwrite:?}");
        assert_eq!(fs::read(out.join("d.txt")).unwrap(), at_name, "{overwrite:?}");
        assert_eq!(fs::read(out.join("d_1.txt")).unwrap(), at_renamed, "{overwrite:?}");
    }
}

#[test]
fn a_terminal_error_after_a_rename_existing_move_keeps_the_rename() {
    use zipfast::extract::RenameStyle;
    let dir = tempfile::tempdir().unwrap();
    let text = dir.path().join("text");
    fs::create_dir_all(&text).unwrap();
    fs::write(text.join("a.txt"), b"old").unwrap();
    let options = renaming(dir.path(), Overwrite::RenameExisting(RenameStyle::Underscore));
    // The move happens when the member starts; the wrong password shows when it decodes.
    let error = extract::run_with_renames(&fixture("aes.7z"), &options, Some("wrong"), |_| {}).unwrap_err();
    assert!(matches!(SevenZipError::of(&error.error), Some(SevenZipError::WrongPassword)), "{error:?}");
    assert_eq!(error.renames.len(), 1);
    assert_eq!(error.renames[0].existing, Some(text.join("a_1.txt")));
    assert_eq!(fs::read(text.join("a_1.txt")).unwrap(), b"old");
    // The reserved name is not left as an empty file.
    assert!(!text.join("a.txt").exists());
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
#[allow(clippy::result_large_err)]
fn the_checked_dispatcher_reports_7z_renames() {
    use zipfast::extract::RenameStyle;
    use zipfast::zip::ZipRunEvent;
    let dir = tempfile::tempdir().unwrap();
    let text = dir.path().join("text");
    fs::create_dir_all(&text).unwrap();
    fs::write(text.join("b.txt"), b"old").unwrap();
    let options = renaming(dir.path(), Overwrite::RenameNew(RenameStyle::Parenthesized));
    let mut renamed = Vec::new();
    let report = extract::run_with_zip_policy(
        &fixture("lzma2.7z"),
        &options,
        None,
        &Cancellation::default(),
        &Default::default(),
        |event: ZipRunEvent<'_>| {
            if let ZipRunEvent::MemberRenamed { renamed: r, .. } = event {
                renamed.push(r.path.clone());
            }
            Ok(())
        },
    )
    .unwrap();
    assert_eq!((report.files(), report.failed()), (2, 0));
    assert_eq!(renamed, [text.join("b(1).txt")]);
    assert_eq!(fs::read(text.join("b.txt")).unwrap(), b"old");
}
