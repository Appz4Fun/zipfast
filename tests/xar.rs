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

//! xar archives from bsdtar (every compression, SHA-1 and MD5 checksums, stored) and from macOS xar (SHA-256),
//! see tests/fixtures/xar/gen.sh, through the same entry points as tar; then hostile archives built here.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use zipfast::extract::{self, Mode, Options, Overwrite, SelectedEntry};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/xar")
}

const ALL: [&str; 6] =
    ["bsd-gzip-sha1.xar", "bsd-bzip2-md5.xar", "bsd-xz.xar", "bsd-lzma.xar", "bsd-stored.xar", "apple-sha256.xar"];

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
    }
}

fn sha(data: &[u8]) -> String {
    zipfast::crypto::sha256(data).iter().map(|b| format!("{b:02x}")).collect()
}

fn expected() -> BTreeMap<String, String> {
    fs::read_to_string(fixtures().join("expected.sha256"))
        .unwrap()
        .lines()
        .map(|l| {
            let (sum, name) = l.split_once("  ").unwrap();
            (name.to_owned(), sum.to_owned())
        })
        .collect()
}

#[test]
fn every_writer_and_encoding_extracts_the_same_tree() {
    let want = expected();
    for fixture in ALL {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        let s = extract::run(&fixtures().join(fixture), &opts(Mode::Extract, &out), |_| {}).unwrap();
        assert!(s.errors.is_empty(), "{fixture}: {:?}", s.errors);
        // a, b, s, e, d/f, big; and d
        assert_eq!((s.files, s.dirs), (6, 1), "{fixture}");
        for (name, sum) in &want {
            assert_eq!(&sha(&fs::read(out.join(name)).unwrap()), sum, "{fixture}/{name}");
        }
        assert_eq!(fs::read(out.join("b")).unwrap(), b"hello xar\n", "{fixture}");
        assert_eq!(fs::read(out.join("e")).unwrap(), b"", "{fixture}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let id = |n: &str| {
                let m = fs::symlink_metadata(out.join(n)).unwrap();
                (m.dev(), m.ino())
            };
            assert_eq!(id("a"), id("b"), "{fixture}: a hard link");
            assert_eq!(fs::read_link(out.join("s")).unwrap(), Path::new("a"), "{fixture}");
            assert_eq!(fs::metadata(out.join("d/f")).unwrap().mode() & 0o777, 0o644, "{fixture}");
        }
        let since = fs::metadata(out.join("d/f"))
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // 2026-01-02 03:04:05 in whatever zone made the fixtures
        assert!((1_767_276_245 - 14 * 3600..=1_767_323_045 + 12 * 3600).contains(&since), "{fixture}: {since}");
    }
}

#[test]
fn a_test_a_listing_and_a_read_by_index_agree() {
    let want = expected();
    for fixture in ALL {
        let path = fixtures().join(fixture);
        let unused = tempfile::tempdir().unwrap();
        let s = extract::run(&path, &opts(Mode::Test, unused.path()), |_| {}).unwrap();
        assert!(s.errors.is_empty() && s.files == 6, "{fixture}: {:?}", s.errors);
        assert!(fs::read_dir(unused.path()).unwrap().next().is_none());
        let listing = extract::list(&path).unwrap();
        let mut names: Vec<&str> = listing.iter().map(|e| e.name.as_str()).collect();
        names.sort();
        assert_eq!(names, ["a", "b", "big", "d", "d/f", "e", "s"], "{fixture}");
        let index = listing.iter().position(|e| e.name == "big").unwrap();
        assert_eq!(listing[index].size, 100_000, "{fixture}");
        let mut data = Vec::new();
        SelectedEntry::open(&path, index, None, 1 << 20)
            .unwrap()
            .read(None, |c| {
                data.extend_from_slice(c);
                Ok(())
            })
            .unwrap();
        assert_eq!(sha(&data), want["big"], "{fixture}");
        // found by its magic, whatever the name
        let renamed = unused.path().join("archive.bin");
        fs::copy(&path, &renamed).unwrap();
        assert_eq!(extract::list(&renamed).unwrap().len(), 7, "{fixture}");
    }
}

// --- built here -------------------------------------------------------------------------------------------------

fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

/// A xar archive from `toc` and `heap`, with no TOC checksum.
fn xar(toc: &str, heap: &[u8]) -> Vec<u8> {
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(toc.as_bytes()).unwrap();
    let packed = enc.finish().unwrap();
    let mut out = b"xar!".to_vec();
    out.extend_from_slice(&28u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(packed.len() as u64).to_be_bytes());
    out.extend_from_slice(&(toc.len() as u64).to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&packed);
    out.extend_from_slice(heap);
    out
}

/// One stored file's <file> element: `data` at `offset` in the heap, with its SHA-256 (or `sum` in its place).
fn stored(id: u32, name: &str, offset: usize, data: &[u8], sum: Option<&str>) -> String {
    let digest = sum.map_or_else(|| hex(&zipfast::crypto::sha256(data)), str::to_owned);
    format!(
        "<file id=\"{id}\"><name>{name}</name><type>file</type><mode>0644</mode><data><length>{len}</length>\
         <offset>{offset}</offset><size>{len}</size><encoding style=\"application/octet-stream\"/>\
         <extracted-checksum style=\"sha256\">{digest}</extracted-checksum></data></file>",
        len = data.len()
    )
}

fn toc(files: &str) -> String {
    format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?><xar><toc>{files}</toc></xar>")
}

/// Every route fails on `bytes` with `why` somewhere in what it reports.
fn fails(bytes: &[u8], why: &str) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("x.xar");
    fs::write(&path, bytes).unwrap();
    for mode in [Mode::Extract, Mode::Test] {
        let message = match extract::run(&path, &opts(mode, &dir.path().join("out")), |_| {}) {
            Ok(s) => s.errors.join("\n"),
            Err(e) => e.to_string(),
        };
        assert!(message.contains(why), "{mode:?}: wanted {why:?}, got {message:?}");
    }
}

#[test]
fn a_built_archive_reads_back() {
    let heap = b"alphabeta";
    let files = format!("{}{}", stored(1, "a", 0, b"alpha", None), stored(2, "b", 5, b"beta", None));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ok.xar");
    fs::write(&path, xar(&toc(&files), heap)).unwrap();
    let out = dir.path().join("out");
    let s = extract::run(&path, &opts(Mode::Extract, &out), |_| {}).unwrap();
    assert!(s.errors.is_empty() && s.files == 2, "{:?}", s.errors);
    assert_eq!(fs::read(out.join("a")).unwrap(), b"alpha");
    assert_eq!(fs::read(out.join("b")).unwrap(), b"beta");
}

#[test]
fn a_file_that_fails_its_checksum_fails() {
    let files = stored(1, "a", 0, b"alpha", Some(&hex(&[0u8; 32])));
    fails(&xar(&toc(&files), b"alpha"), "checksum");
}

#[test]
fn data_outside_the_archive_or_shorter_than_its_size_fails() {
    fails(&xar(&toc(&stored(1, "a", 1 << 40, b"alpha", None)), b"alpha"), "outside");
    // the size claims more than the heap holds for it
    let short = "<file id=\"1\"><name>a</name><type>file</type><data><length>5</length><offset>0</offset>\
                 <size>9</size><encoding style=\"application/octet-stream\"/></data></file>";
    fails(&xar(&toc(short), b"alpha"), "truncated");
}

#[test]
fn hostile_tables_of_contents_are_refused() {
    // an entity defined in a document type declaration is never expanded
    let doctype = "<?xml version=\"1.0\"?><!DOCTYPE xar [<!ENTITY a \"aaaaaaaaaa\"><!ENTITY b \"&a;&a;&a;&a;\">]>\
                   <xar><toc><file id=\"1\"><name>&b;</name><type>directory</type></file></toc></xar>";
    fails(&xar(doctype, b""), "document type");
    // nesting past the bound
    let mut deep = String::new();
    for i in 0..300 {
        deep.push_str(&format!("<file id=\"{i}\"><name>d</name><type>directory</type>"));
    }
    for _ in 0..300 {
        deep.push_str("</file>");
    }
    fails(&xar(&toc(&deep), b""), "nests too deep");
    // a size field that doesn't match what the TOC decompresses to
    let mut wrong = xar(&toc(&stored(1, "a", 0, b"alpha", None)), b"alpha");
    wrong[16..24].copy_from_slice(&7u64.to_be_bytes());
    fails(&wrong, "wrong size");
    // a TOC claiming more than the bound, refused before anything is decompressed
    let mut huge = xar(&toc(""), b"");
    huge[16..24].copy_from_slice(&(1u64 << 40).to_be_bytes());
    fails(&huge, "impossible");
    // an encoding no reader knows
    let odd = "<file id=\"1\"><name>a</name><type>file</type><data><length>5</length><offset>0</offset><size>5</size>\
               <encoding style=\"application/x-pkzip\"/></data></file>";
    fails(&xar(&toc(odd), b"alpha"), "x-pkzip");
}

#[test]
fn a_toc_checksum_that_doesnt_match_fails() {
    let files = stored(1, "a", 20, b"alpha", None);
    let toc_xml = format!(
        "<?xml version=\"1.0\"?><xar><toc><checksum style=\"sha1\"><offset>0</offset><size>20</size></checksum>{files}\
         </toc></xar>"
    );
    let mut heap = vec![0u8; 20];
    heap.extend_from_slice(b"alpha");
    let mut bytes = xar(&toc_xml, &heap);
    // algorithm 1 is SHA-1; the stored digest (zeros) is wrong
    bytes[24..28].copy_from_slice(&1u32.to_be_bytes());
    fails(&bytes, "table of contents fails its checksum");
}

#[test]
fn names_that_leave_the_destination_are_refused() {
    let files = format!(
        "{}<file id=\"2\"><name>..</name><type>directory</type>{}</file>{}",
        stored(1, "../evil", 0, b"x", None),
        stored(3, "inner", 1, b"x", None),
        stored(4, "ok", 2, b"x", None)
    );
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("t.xar");
    fs::write(&path, xar(&toc(&files), b"xxx")).unwrap();
    let out = dir.path().join("out");
    let s = extract::run(&path, &opts(Mode::Extract, &out), |_| {}).unwrap();
    assert!(s.errors.iter().any(|e| e.contains("../evil")), "{:?}", s.errors);
    assert!(s.errors.iter().any(|e| e.contains("../inner")), "{:?}", s.errors);
    assert_eq!(fs::read(out.join("ok")).unwrap(), b"x");
    assert!(!dir.path().join("evil").exists() && !dir.path().join("inner").exists());
}

/// Bytes flipped all over a real archive: errors or a tree, never a panic or a hang.
#[test]
fn damaged_archives_never_panic() {
    let original = fs::read(fixtures().join("bsd-gzip-sha1.xar")).unwrap();
    let mut x = 0x2545_f491_4f6c_dd1du64;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let dir = tempfile::tempdir().unwrap();
    for round in 0..300 {
        let mut bytes = original.clone();
        for _ in 0..1 + round % 8 {
            // mostly in the header and TOC, where the structure is
            let span = if round % 3 == 0 { bytes.len() } else { 900.min(bytes.len()) };
            let i = (next() % span as u64) as usize;
            bytes[i] ^= (next() as u8) | 1;
        }
        let path = dir.path().join(format!("f{round}.xar"));
        fs::write(&path, &bytes).unwrap();
        let _ = extract::list(&path);
        let _ = extract::run(&path, &opts(Mode::Test, dir.path()), |_| {});
    }
}

/// Files pointing at one heap range would decode the same bytes once each: refused.
#[test]
fn files_sharing_heap_data_are_refused() {
    let files = format!("{}{}", stored(1, "a", 0, b"alpha", None), stored(2, "b", 2, b"pha", None));
    fails(&xar(&toc(&files), b"alpha"), "share heap data");
    let same = format!("{}{}", stored(1, "a", 0, b"alpha", None), stored(2, "b", 0, b"alpha", None));
    fails(&xar(&toc(&same), b"alpha"), "share heap data");
}

fn link(id: u32, name: &str, to: u32) -> String {
    format!("<file id=\"{id}\"><name>{name}</name><type link=\"{to}\">hardlink</type></file>")
}

/// h1 links to h2, which links to t, listed before t: both come out as links to t, after it. A link to an id
/// nobody has, or a loop of links, fails with that link alone.
#[cfg(unix)]
#[test]
fn chains_of_hard_links_resolve_to_the_file() {
    use std::os::unix::fs::MetadataExt;
    let original = "<file id=\"3\"><name>t</name><type link=\"original\">hardlink</type><data><length>5</length>\
                    <offset>0</offset><size>5</size><encoding style=\"application/octet-stream\"/></data></file>";
    let files = format!(
        "{}{}{original}{}{}{}",
        link(1, "h1", 2),
        link(2, "h2", 3),
        link(4, "lost", 99),
        link(5, "x", 6),
        link(6, "y", 5)
    );
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("l.xar");
    fs::write(&path, xar(&toc(&files), b"alpha")).unwrap();
    let out = dir.path().join("out");
    let s = extract::run(&path, &opts(Mode::Extract, &out), |_| {}).unwrap();
    let ino = |n: &str| fs::metadata(out.join(n)).unwrap().ino();
    assert_eq!(fs::read(out.join("h1")).unwrap(), b"alpha", "{:?}", s.errors);
    assert_eq!(ino("h1"), ino("t"));
    assert_eq!(ino("h2"), ino("t"));
    assert_eq!(s.errors.len(), 3, "{:?}", s.errors);
    for name in ["lost", "x", "y"] {
        assert!(s.errors.iter().any(|e| e.starts_with(name)), "{name}: {:?}", s.errors);
    }
    // the listing names the file each link comes to
    let listing = extract::list(&path).unwrap();
    let names: Vec<&str> = listing.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(&names[..3], ["t", "h1", "h2"]);
}

/// SHA-512 extracted checksums are checked too.
#[test]
fn sha512_checksums_are_checked() {
    // SHA-512 of "alpha", from Python's hashlib
    let digest = "ba3ce58667ca9b12b3c0cdcc4da57f9962aeca7065c43a7d9c027332fdb9f0bbcf69004286880fe3d8f3fd8f03ddffd7485fd94c9d3a38618ea10691d8d6a7fa";
    let file = |sum: &str| {
        format!(
            "<file id=\"1\"><name>a</name><type>file</type><data><length>5</length><offset>0</offset><size>5</size>\
             <encoding style=\"application/octet-stream\"/><extracted-checksum style=\"sha512\">{sum}</extracted-checksum>\
             </data></file>"
        )
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ok.xar");
    fs::write(&path, xar(&toc(&file(digest)), b"alpha")).unwrap();
    let s = extract::run(&path, &opts(Mode::Test, dir.path()), |_| {}).unwrap();
    assert!(s.errors.is_empty() && s.files == 1, "{:?}", s.errors);
    let wrong = format!("{}0", &digest[..127]);
    fails(&xar(&toc(&file(&wrong)), b"alpha"), "checksum");
}
