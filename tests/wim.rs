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

//! WIM images as wimlib-imagex writes them (tests/fixtures/wim/gen.sh): stored, XPRESS and LZX, a file with two
//! images, and LZMS and solid files, which are refused. Hostile images built by hand are tested in src/tar/wim.rs.

use std::fs;
use std::path::{Path, PathBuf};

use zipfast::extract::{self, Mode, Options, Overwrite, SelectedEntry};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wim")
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

const READABLE: [&str; 4] = ["none.wim", "xpress.wim", "lzx.wim", "multi.wim"];

fn big_txt() -> Vec<u8> {
    (0..3000).flat_map(|i| format!("line {i} of a text file that spans several 32 KiB chunks\n").into_bytes()).collect()
}

fn e8_bin() -> Vec<u8> {
    (0..20000u32).flat_map(|i| [0xE8, (i % 256) as u8, (i / 256 % 256) as u8, 0, 0, 0x90]).collect()
}

#[test]
fn every_compression_extracts_the_same_tree() {
    let mut random = None;
    for fixture in READABLE {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        let s = extract::run(&fixtures().join(fixture), &opts(Mode::Extract, &out), |_| {}).unwrap();
        // the absolute symbolic link is refused; everything else comes out
        assert_eq!(s.errors.len(), 1, "{fixture}: {:?}", s.errors);
        assert!(s.errors[0].contains("abs-link"), "{fixture}: {:?}", s.errors);
        assert_eq!(fs::read(out.join("hello.txt")).unwrap(), b"hello, wim\n", "{fixture}");
        assert_eq!(fs::read(out.join("dir/hard.txt")).unwrap(), b"hello, wim\n", "{fixture}");
        assert_eq!(fs::read(out.join("empty.txt")).unwrap(), b"", "{fixture}");
        assert_eq!(fs::read(out.join("dir/big.txt")).unwrap(), big_txt(), "{fixture}");
        assert_eq!(fs::read(out.join("dir/sub/copy.txt")).unwrap(), big_txt(), "{fixture}");
        assert_eq!(fs::read(out.join("dir/e8.bin")).unwrap(), e8_bin(), "{fixture}: E8 translation undone");
        assert_eq!(fs::read(out.join("dir/sub/caf\u{e9}.txt")).unwrap(), b"unicode\n", "{fixture}");
        assert!(out.join("empty-dir").is_dir(), "{fixture}");
        assert!(!out.join("two.txt").exists(), "{fixture}: only image 1");
        let r = fs::read(out.join("dir/random.bin")).unwrap();
        assert_eq!(r.len(), 100_000, "{fixture}");
        assert_eq!(random.get_or_insert_with(|| r.clone()), &r, "{fixture}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let id = |n: &str| {
                let m = fs::symlink_metadata(out.join(n)).unwrap();
                (m.dev(), m.ino())
            };
            assert_eq!(id("hello.txt"), id("dir/hard.txt"), "{fixture}: one file");
            assert_eq!(fs::read_link(out.join("dir/rel-link")).unwrap(), Path::new("../hello.txt"), "{fixture}");
            assert!(fs::symlink_metadata(out.join("dir/abs-link")).is_err(), "{fixture}");
        }
        let mtime = fs::metadata(out.join("hello.txt")).unwrap().modified().unwrap();
        let since = mtime.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        assert!((1_790_000_000..1_800_000_000).contains(&since), "{fixture}: {since}");
    }
}

#[test]
fn a_test_and_a_listing_agree_with_extraction() {
    for fixture in READABLE {
        let path = fixtures().join(fixture);
        let unused = tempfile::tempdir().unwrap();
        let s = extract::run(&path, &opts(Mode::Test, unused.path()), |_| {}).unwrap();
        assert!(s.errors.len() <= 1, "{fixture}: {:?}", s.errors);
        assert!(fs::read_dir(unused.path()).unwrap().next().is_none());
        let listing = extract::list(&path).unwrap();
        let names: Vec<&str> = listing.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "dir",
                "dir/abs-link",
                "dir/big.txt",
                "dir/e8.bin",
                "dir/hard.txt",
                "dir/random.bin",
                "dir/rel-link",
                "dir/sub",
                "dir/sub/caf\u{e9}.txt",
                "dir/sub/copy.txt",
                "empty-dir",
                "empty.txt",
                "hello.txt",
            ],
            "{fixture}"
        );
        let entry = |n: &str| listing.iter().find(|e| e.name == n).unwrap();
        assert!(entry("dir").dir && entry("dir/sub").dir, "{fixture}");
        assert_eq!(entry("dir/big.txt").size, 172_890, "{fixture}");
        assert!(entry("dir/rel-link").link.is_some() && entry("hello.txt").link.is_some(), "{fixture}");
        assert!(entry("dir/hard.txt").link.is_none(), "{fixture}");
    }
}

#[test]
fn a_member_read_by_index_comes_out_whole() {
    for fixture in READABLE {
        let path = fixtures().join(fixture);
        let listing = extract::list(&path).unwrap();
        let index = listing.iter().position(|e| e.name == "dir/big.txt").unwrap();
        let mut data = Vec::new();
        SelectedEntry::open(&path, index, None, 1 << 30)
            .unwrap()
            .read(None, |c| {
                data.extend_from_slice(c);
                Ok(())
            })
            .unwrap();
        assert_eq!(data, big_txt(), "{fixture}");
    }
}

#[test]
fn the_header_and_other_images_can_be_read() {
    let info = zipfast::tar::wim_info(&fixtures().join("multi.wim")).unwrap();
    assert_eq!((info.images, info.compression, info.chunk_size), (2, "XPRESS", 32 << 10));
    assert_ne!(info.guid, [0; 16]);
    let lzx = zipfast::tar::wim_info(&fixtures().join("lzx.wim")).unwrap();
    assert_eq!((lzx.images, lzx.compression), (1, "LZX"));
    let two = zipfast::tar::list_wim_image(&fixtures().join("multi.wim"), 2).unwrap();
    assert_eq!(two.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), ["two.txt"]);
    assert!(zipfast::tar::list_wim_image(&fixtures().join("multi.wim"), 3).is_err());
    assert!(zipfast::tar::list_wim_image(&fixtures().join("multi.wim"), 0).is_err());
}

/// Image 2 lists although image 1's metadata is damaged: only the requested image's metadata is read.
#[test]
fn another_image_lists_when_image_1_is_damaged() {
    let mut bytes = fs::read(fixtures().join("multi.wim")).unwrap();
    let le64 = |b: &[u8], at: usize| u64::from_le_bytes(b[at..at + 8].try_into().unwrap());
    // the lookup table (stored as it is) and its first metadata resource, image 1's
    let (table_flags, table_at, table_len) = (bytes[55], le64(&bytes, 56) as usize, le64(&bytes, 64) as usize);
    assert_eq!(table_flags & 0x04, 0, "the lookup table is stored");
    let first_meta = bytes[table_at..table_at + table_len]
        .as_chunks::<50>()
        .0
        .iter()
        .find(|e| e[7] & 0x02 != 0)
        .map(|e| (le64(e, 8) as usize, le64(e, 0) as usize & ((1 << 56) - 1)))
        .unwrap();
    bytes[first_meta.0 + first_meta.1 / 2] ^= 0x55;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("damaged.wim");
    fs::write(&path, &bytes).unwrap();
    assert!(extract::list(&path).is_err(), "image 1 is damaged");
    let two = zipfast::tar::list_wim_image(&path, 2).unwrap();
    assert_eq!(two.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), ["two.txt"]);
}

#[test]
fn lzms_and_solid_files_are_refused_as_unsupported() {
    for fixture in ["lzms.wim", "solid.wim"] {
        let path = fixtures().join(fixture);
        let dir = tempfile::tempdir().unwrap();
        let e = extract::run(&path, &opts(Mode::Extract, &dir.path().join("out")), |_| {}).unwrap_err();
        assert!(matches!(&e, zipfast::error::Error::Unsupported(m) if m.starts_with("WIM LZMS")), "{fixture}: {e}");
        assert!(extract::list(&path).is_err(), "{fixture}");
    }
}

#[test]
fn the_format_is_found_by_its_magic() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("image.bin");
    fs::copy(fixtures().join("lzx.wim"), &path).unwrap();
    assert_eq!(extract::list(&path).unwrap().len(), 13);
}

/// Damage to a file's data fails it, and nothing of it is left behind.
#[test]
fn a_damaged_chunk_fails_its_file() {
    for fixture in ["xpress.wim", "lzx.wim", "none.wim"] {
        let mut bytes = fs::read(fixtures().join(fixture)).unwrap();
        // big.txt's data is the first resource, right after the header
        for b in &mut bytes[208 + 600..208 + 640] {
            *b ^= 0x55;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.wim");
        fs::write(&path, &bytes).unwrap();
        let out = dir.path().join("out");
        let s = extract::run(&path, &opts(Mode::Extract, &out), |_| {}).unwrap();
        assert!(s.errors.iter().any(|e| e.contains("big.txt")), "{fixture}: {:?}", s.errors);
        assert!(!out.join("dir/big.txt").exists(), "{fixture}");
        // the stored file fails its SHA-1; the compressed ones fail sooner, as their chunks decode
        let why = if fixture == "none.wim" { "SHA-1" } else { "damaged" };
        assert!(s.errors.iter().any(|e| e.contains(why)), "{fixture}: {:?}", s.errors);
    }
}

/// Fuzz smoke test: fixtures with bytes changed or cut short list, test and extract without panicking.
#[test]
fn mangled_fixtures_never_panic() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("m.wim");
    let mut seed = 0x0123_4567_89ab_cdefu64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for fixture in ["xpress.wim", "lzx.wim", "multi.wim"] {
        let good = fs::read(fixtures().join(fixture)).unwrap();
        for round in 0..60 {
            let mut bytes = good.clone();
            if round % 10 == 9 {
                bytes.truncate(next() as usize % bytes.len());
            }
            for _ in 0..1 + next() % 8 {
                let len = bytes.len().max(1);
                // aim most changes at the header, the lookup table and the metadata at the end
                let at = match next() % 3 {
                    0 => next() as usize % 208.min(len),
                    1 => len - 1 - next() as usize % 4096.min(len),
                    _ => next() as usize % len,
                };
                if at < bytes.len() {
                    bytes[at] = next() as u8;
                }
            }
            fs::write(&path, &bytes).unwrap();
            let _ = extract::list(&path);
            let _ = extract::run(&path, &opts(Mode::Test, &dir.path().join("t")), |_| {});
        }
    }
}
