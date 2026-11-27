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

//! cpio archives in every format bsdtar writes, and two converted from them (tests/fixtures/cpio/gen.sh), plain
//! and compressed, through the same entry points as tar; then hostile archives built here.

use std::fs;
use std::path::{Path, PathBuf};

use zipfast::extract::{self, Mode, Options, Overwrite, SelectedEntry};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cpio")
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
        unverified_output: Default::default(),
        salvage_truncated_zip: false,
        seven_zip_strict: false,
        rar4_raw_names: false,
        folder_times: Default::default(),
        unix_modes: Default::default(),
        backslashes: Default::default(),
        hard_link_targets: Default::default(),
    }
}

/// (fixture, whether it holds the fifo, which the binary format can't store)
const ALL: [(&str, bool); 7] = [
    ("newc.cpio", true),
    ("crc.cpio", true),
    ("odc.cpio", true),
    ("bin.cpio", false),
    ("bin-be.cpio", false),
    ("newc.cpio.gz", true),
    ("odc.cpio.xz", true),
];

#[test]
fn every_format_extracts_the_same_tree() {
    for (fixture, fifo) in ALL {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        let s = extract::run(&fixtures().join(fixture), &opts(Mode::Extract, &out), |_| {}).unwrap();
        // d/f, a, b, c, e, e2 and s; the fifo is reported, not made
        assert_eq!((s.files, s.dirs), (7, 1), "{fixture}: {:?}", s.errors);
        assert_eq!(s.errors.len(), usize::from(fifo), "{fixture}: {:?}", s.errors);
        if fifo {
            assert!(s.errors[0].contains("p") && s.errors[0].contains("not extracted"), "{fixture}: {:?}", s.errors);
        }
        assert_eq!(fs::read(out.join("d/f")).unwrap(), b"in a folder\n", "{fixture}");
        for name in ["a", "b", "c"] {
            assert_eq!(fs::read(out.join(name)).unwrap(), b"linked data\n", "{fixture}/{name}");
        }
        for name in ["e", "e2"] {
            assert_eq!(fs::read(out.join(name)).unwrap(), b"", "{fixture}/{name}");
        }
        assert!(!out.join("p").exists(), "{fixture}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let id = |n: &str| {
                let m = fs::symlink_metadata(out.join(n)).unwrap();
                (m.dev(), m.ino())
            };
            assert!(id("a") == id("b") && id("b") == id("c"), "{fixture}: a, b and c are one file");
            assert_eq!(id("e"), id("e2"), "{fixture}: e and e2 are one file");
            assert_eq!(fs::read_link(out.join("s")).unwrap(), Path::new("a"), "{fixture}");
            assert_eq!(fs::metadata(out.join("d/f")).unwrap().mode() & 0o777, 0o644, "{fixture}");
        }
        let mtime = fs::metadata(out.join("d/f")).unwrap().modified().unwrap();
        let since = mtime.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        // 2026-01-02 03:04:05 in whatever zone made the fixtures
        assert!((1_767_276_245 - 14 * 3600..=1_767_323_045 + 12 * 3600).contains(&since), "{fixture}: {since}");
    }
}

#[test]
fn a_test_and_a_listing_agree_with_extraction() {
    for (fixture, fifo) in ALL {
        let path = fixtures().join(fixture);
        let unused = tempfile::tempdir().unwrap();
        let s = extract::run(&path, &opts(Mode::Test, unused.path()), |_| {}).unwrap();
        assert_eq!((s.files, s.dirs, s.errors.len()), (7, 1, usize::from(fifo)), "{fixture}: {:?}", s.errors);
        assert!(fs::read_dir(unused.path()).unwrap().next().is_none());
        let listing = extract::list(&path).unwrap();
        let mut names: Vec<&str> = listing.iter().map(|e| e.name.as_str()).collect();
        names.sort();
        let mut want = vec!["a", "b", "c", "d", "d/f", "e", "e2", "s"];
        if fifo {
            want.push("p");
            want.sort();
        }
        assert_eq!(names, want, "{fixture}");
        let entry = |n: &str| listing.iter().find(|e| e.name == n).unwrap();
        assert!(entry("d").dir, "{fixture}");
        assert!(entry("d").tar.is_none(), "{fixture}: cpio has no tar metadata");
        assert_eq!(entry("d/f").size, 12, "{fixture}");
        // one of a, b and c holds the data; the others link to it
        let holders: Vec<_> = ["a", "b", "c"].into_iter().filter(|n| entry(n).link.is_none()).collect();
        assert_eq!(holders.len(), 1, "{fixture}");
        assert_eq!(entry(holders[0]).size, 12, "{fixture}");
        assert!(entry("s").link.is_some(), "{fixture}");
    }
}

#[test]
fn a_member_read_by_index_comes_out_whole() {
    for (fixture, _) in ALL {
        let path = fixtures().join(fixture);
        let listing = extract::list(&path).unwrap();
        let index = listing.iter().position(|e| e.name == "d/f").unwrap();
        let mut data = Vec::new();
        SelectedEntry::open(&path, index, None, 1 << 20)
            .unwrap()
            .read(None, |c| {
                data.extend_from_slice(c);
                Ok(())
            })
            .unwrap();
        assert_eq!(data, b"in a folder\n", "{fixture}");
    }
}

// --- built here -------------------------------------------------------------------------------------------------

/// One newc member (`070702` with its checksum when `crc`).
fn newc(name: &str, mode: u32, ino: u32, nlink: u32, data: &[u8], crc: bool) -> Vec<u8> {
    let sum = if crc { data.iter().map(|&b| u32::from(b)).fold(0u32, u32::wrapping_add) } else { 0 };
    let fields = [ino, mode, 0, 0, nlink, 1_700_000_000, data.len() as u32, 0, 1, 0, 0, name.len() as u32 + 1, sum];
    let mut out = if crc { b"070702".to_vec() } else { b"070701".to_vec() };
    for f in fields {
        out.extend_from_slice(format!("{f:08X}").as_bytes());
    }
    out.extend_from_slice(name.as_bytes());
    out.push(0);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
    out.extend_from_slice(data);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
    out
}

fn trailer() -> Vec<u8> {
    newc("TRAILER!!!", 0, 0, 1, b"", false)
}

fn file(name: &str, data: &[u8]) -> Vec<u8> {
    newc(name, 0o100644, 0, 1, data, false)
}

fn archive(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut out: Vec<u8> = parts.concat();
    out.extend(trailer());
    out
}

fn gzip(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

/// Runs `bytes` plain and gzipped in both modes; returns each run's summary with what it extracted.
fn runs(bytes: &[u8]) -> Vec<(String, extract::Summary, tempfile::TempDir)> {
    let mut out = Vec::new();
    for (name, data) in [("h.cpio", bytes.to_vec()), ("h.cpio.gz", gzip(bytes))] {
        for mode in [Mode::Extract, Mode::Test] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join(name);
            fs::write(&path, &data).unwrap();
            // an archive too damaged to be recognised fails the run
            let s = extract::run(&path, &opts(mode, &dir.path().join("out")), |_| {}).unwrap_or_else(|e| {
                let mut s = extract::Summary::default();
                s.errors.push(format!("archive: {e}"));
                s
            });
            out.push((format!("{name} {mode:?}"), s, dir));
        }
    }
    out
}

#[test]
fn a_checksum_that_doesnt_add_up_fails() {
    let mut bad = newc("f", 0o100644, 0, 1, b"payload", true);
    // the check field is the last eight hex digits of the header
    bad[102..110].copy_from_slice(b"00000001");
    for (what, s, _) in runs(&archive(&[bad])) {
        assert_eq!(s.files, 0, "{what}");
        assert!(s.errors.iter().any(|e| e.contains("checksum")), "{what}: {:?}", s.errors);
    }
    // and a right one passes
    for (what, s, _) in runs(&archive(&[newc("f", 0o100644, 0, 1, b"payload", true)])) {
        assert!(s.errors.is_empty() && s.files == 1, "{what}: {:?}", s.errors);
    }
}

#[test]
fn names_and_links_that_leave_the_destination_are_refused() {
    let tar = archive(&[
        file("../evil", b"x"),
        file("/abs/evil", b"x"),
        newc("up", 0o120777, 0, 1, b"../../outside", false),
        // a hard link (by inode) whose data comes first under a name that's refused
        newc("../held", 0o100644, 7, 2, b"held", false),
        newc("later", 0o100644, 7, 2, b"", false),
        file("ok", b"fine"),
    ]);
    for (what, s, dir) in runs(&tar) {
        assert!(s.errors.iter().any(|e| e.contains("../evil")), "{what}: {:?}", s.errors);
        assert!(s.errors.iter().any(|e| e.contains("up")), "{what}: {:?}", s.errors);
        assert!(s.errors.iter().any(|e| e.contains("later")), "{what}: {:?}", s.errors);
        assert!(!dir.path().join("evil").exists() && !dir.path().join("held").exists(), "{what}");
        if what.ends_with("Extract") {
            assert_eq!(fs::read(dir.path().join("out/ok")).unwrap(), b"fine", "{what}");
            assert!(!dir.path().join("out/later").exists(), "{what}");
            assert!(fs::read_dir(dir.path().join("out")).unwrap().count() <= 2, "{what}");
        }
    }
}

#[test]
fn damaged_archives_fail() {
    let good = archive(&[file("a", b"alpha"), file("b", b"beta")]);
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("cut in the data", good[..good.len() / 2 + 3].to_vec()),
        ("bad magic after the first member", {
            let mut b = good.clone();
            let second = file("a", b"alpha").len();
            b[second..second + 6].copy_from_slice(b"070799");
            b
        }),
        ("a name length of zero", {
            let mut b = file("a", b"alpha");
            b[94..102].copy_from_slice(b"00000000");
            // in the second member, so the archive is still found to be cpio
            archive(&[file("first", b"1"), b])
        }),
        ("a name without its NUL", {
            let mut b = file("abc", b"alpha");
            b[113] = b'x';
            // in the second member, so the archive is still found to be cpio
            archive(&[file("first", b"1"), b])
        }),
        ("numbers that aren't hex", {
            let mut b = file("a", b"alpha");
            b[54..62].copy_from_slice(b"0000000G");
            // in the second member, so the archive is still found to be cpio
            archive(&[file("first", b"1"), b])
        }),
    ];
    for (why, bytes) in cases {
        for (what, s, _) in runs(&bytes) {
            assert!(!s.errors.is_empty(), "{why}, {what}: no error");
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.cpio");
        fs::write(&path, &bytes).unwrap();
        let listed = extract::list(&path);
        assert!(listed.is_err() || listed.unwrap().len() < 2, "{why}: listed whole");
    }
}

/// Without the trailer, what was read stands, as a tar archive without its end marker does.
#[test]
fn a_missing_trailer_ends_the_archive_where_the_data_does() {
    let bytes = [file("a", b"alpha"), newc("b", 0o100644, 9, 2, b"", false)].concat();
    for (what, s, dir) in runs(&bytes) {
        assert!(s.errors.is_empty() && s.files == 2, "{what}: {:?}", s.errors);
        if what.ends_with("Extract") {
            assert_eq!(fs::read(dir.path().join("out/a")).unwrap(), b"alpha");
            assert_eq!(fs::read(dir.path().join("out/b")).unwrap(), b"");
        }
    }
}

#[test]
fn the_format_is_found_by_its_magic() {
    for (fixture, _) in ALL {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive.bin");
        fs::copy(fixtures().join(fixture), &path).unwrap();
        assert!(extract::list(&path).unwrap().len() >= 8, "{fixture}");
    }
}

/// Many links waiting for data that never comes, and as many files whose data comes with their only other link:
/// each member is handled on its own, so the reading stays linear (it used to rescan every waiting link for each
/// file, quadratic in their number). Counted work, not time: a rescan would show as more links handled than there are waiting.
#[test]
fn many_waiting_links_are_read_in_linear_time() {
    const N: u32 = 50_000;
    let mut parts = Vec::with_capacity(2 * N as usize);
    for i in 0..N {
        // waits for data under an inode no other member has
        parts.push(newc(&format!("w{i}"), 0o100644, 1_000_000 + i, 2, b"", false));
        // carries its own data, its other link never coming
        parts.push(newc(&format!("d{i}"), 0o100644, 10 + i, 2, b"x", false));
    }
    let bytes = archive(&parts);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("many.cpio");
    fs::write(&path, &bytes).unwrap();
    zipfast::work::take(zipfast::work::Work::CpioWaitingLinks);
    let listing = extract::list(&path).unwrap();
    // every waiting link is handled once, at the end (the others' data came with their only other link)
    let handled = zipfast::work::take(zipfast::work::Work::CpioWaitingLinks);
    assert_eq!(handled, u64::from(N), "waiting links handled");
    assert_eq!(listing.len(), 2 * N as usize);
    // the waiting ones come out at the end, in archive order, each an empty file of its own
    assert_eq!(listing[N as usize].name, "w0");
    assert_eq!(listing.last().unwrap().name, format!("w{}", N - 1));
    assert!(listing[N as usize..].iter().all(|e| e.link.is_none() && e.size == 0));
}

/// A file's links waiting for data come out as links to the member that carries it, right after it, and the
/// links of a file that never carries data as an empty file and links to it, in archive order.
#[test]
fn waiting_links_resolve_to_their_own_file_only() {
    let bytes = archive(&[
        newc("a1", 0o100644, 5, 3, b"", false),
        newc("b1", 0o100644, 6, 2, b"", false),
        newc("a2", 0o100644, 5, 3, b"", false),
        newc("a3", 0o100644, 5, 3, b"data", false),
        newc("b2", 0o100644, 6, 2, b"", false),
    ]);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("w.cpio");
    fs::write(&path, &bytes).unwrap();
    let listing = extract::list(&path).unwrap();
    let shown: Vec<(String, Option<String>)> = listing
        .iter()
        .map(|e| {
            let link = e.link.as_ref().map(|l| format!("{l:?}"));
            (e.name.clone(), link)
        })
        .collect();
    let names: Vec<&str> = shown.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, ["a3", "a1", "a2", "b1", "b2"]);
    assert!(shown[0].1.is_none() && shown[3].1.is_none(), "{shown:?}");
    assert!(shown[1].1.as_deref().unwrap().contains("a3") && shown[2].1.as_deref().unwrap().contains("a3"));
    assert!(shown[4].1.as_deref().unwrap().contains("b1"), "{shown:?}");
}

/// A first name longer than the 512 bytes read to tell the format: still found to be cpio, plain and compressed.
#[test]
fn a_long_first_name_is_still_cpio() {
    let long = ["d".repeat(100), "e".repeat(100), "f".repeat(100), "g".repeat(100), "h".repeat(100)].join("/");
    let bytes = archive(&[file(&long, b"deep"), file("b", b"beta")]);
    for (what, s, dir) in runs(&bytes) {
        assert!(s.errors.is_empty() && s.files == 2, "{what}: {:?}", s.errors);
        if what.ends_with("Extract") {
            assert_eq!(fs::read(dir.path().join("out").join(&long)).unwrap(), b"deep", "{what}");
        }
    }
}

/// Inode zero is an identity like any other: an empty name before the one carrying the data links to it.
#[test]
fn links_with_inode_zero_share_their_data() {
    let bytes = archive(&[newc("a", 0o100644, 0, 2, b"", false), newc("b", 0o100644, 0, 2, b"data", false)]);
    for (what, s, dir) in runs(&bytes) {
        assert!(s.errors.is_empty() && s.files == 2, "{what}: {:?}", s.errors);
        if what.ends_with("Extract") {
            assert_eq!(fs::read(dir.path().join("out/a")).unwrap(), b"data", "{what}");
            assert_eq!(fs::read(dir.path().join("out/b")).unwrap(), b"data", "{what}");
        }
    }
}

/// A second name of a file that carries its own copy of the data comes out as a link, but its copy is still held
/// to its checksum.
#[test]
fn a_linked_copy_is_checked_before_it_is_passed_over() {
    let mut bad = newc("b", 0o100644, 5, 2, b"bad", true);
    bad[102..110].copy_from_slice(b"00000001");
    let bytes = archive(&[newc("a", 0o100644, 5, 2, b"good", true), bad]);
    for (what, s, _) in runs(&bytes) {
        assert!(s.errors.iter().any(|e| e.contains("checksum")), "{what}: {:?}", s.errors);
    }
    let good = archive(&[newc("a", 0o100644, 5, 2, b"good", true), newc("b", 0o100644, 5, 2, b"good", true)]);
    for (what, s, _) in runs(&good) {
        assert!(s.errors.is_empty() && s.files == 2, "{what}: {:?}", s.errors);
    }
}

/// Many short names waiting for data that comes under a 60,000-byte name: each becomes a link holding that long
/// name, and those copies count against the hard-link cap before they pile up.
#[test]
fn links_expanded_to_a_long_name_are_bounded() {
    let long = "n".repeat(60_000);
    let mut parts: Vec<Vec<u8>> = (0..2_000).map(|i| newc(&format!("w{i}"), 0o100644, 9, 3, b"", false)).collect();
    parts.push(newc(&long, 0o100644, 9, 3, b"x", false));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("l.cpio");
    fs::write(&path, archive(&parts)).unwrap();
    let err = extract::list(&path).unwrap_err();
    assert!(err.to_string().contains("too many hard links"), "{err}");
    // a few of them are fine
    parts.drain(..1_990);
    fs::write(&path, archive(&parts)).unwrap();
    assert_eq!(extract::list(&path).unwrap().len(), 11);
}
