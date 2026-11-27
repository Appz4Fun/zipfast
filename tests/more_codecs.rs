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

//! LZ4 (frames, legacy frames, linked blocks, skippable frames), Unix compress (`.Z`, 9 to 16 bits) and
//! LZMA-alone, as lone compressed files and around tar, made by the lz4, compress, xz and bsdtar tools (see
//! tests/fixtures/more-codecs/gen.sh); then damaged and hostile streams built here.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use zipfast::extract::{self, Mode, Options, Overwrite, SelectedEntry};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/more-codecs")
}

fn hex(d: [u8; 32]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha(data: &[u8]) -> String {
    hex(zipfast::crypto::sha256(data))
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
        damaged_input: Default::default(),
        unsupported_filters: Default::default(),
        unverified_output: Default::default(),
        salvage_truncated_zip: false,
        unix_modes: Default::default(),
        backslashes: Default::default(),
    }
}

/// (fixture, the name it comes out under, the original it holds; twice for the stream of two frames)
const LONE: [(&str, &str, &str, usize); 8] = [
    ("data-plain.bin.lz4", "data-plain.bin", "data.bin", 1),
    ("data-legacy.bin.lz4", "data-legacy.bin", "data.bin", 1),
    ("data-linked.bin.lz4", "data-linked.bin", "data.bin", 1),
    ("data-frames.bin.lz4", "data-frames.bin", "data.bin", 2),
    ("data-b9.bin.Z", "data-b9.bin", "data.bin", 1),
    ("data-b12.bin.Z", "data-b12.bin", "data.bin", 1),
    ("dna.bin.Z", "dna.bin", "dna.bin", 1),
    ("data.bin.lzma", "data.bin", "data.bin", 1),
];

fn check_copies(data: &[u8], sum: &str, copies: usize, what: &str) {
    assert!(data.len().is_multiple_of(copies), "{what}");
    for part in data.chunks(data.len() / copies) {
        assert_eq!(sha(part), sum, "{what}");
    }
}

#[test]
fn lone_compressed_files_decode_to_what_was_compressed() {
    let want = expected();
    for (fixture, name, original, copies) in LONE {
        let path = fixtures().join(fixture);
        let dir = tempfile::tempdir().unwrap();
        let s = extract::run(&path, &opts(Mode::Extract, dir.path()), |_| {}).unwrap();
        assert!(s.errors.is_empty(), "{fixture}: {:?}", s.errors);
        assert_eq!(s.files, 1, "{fixture}");
        let out = fs::read(dir.path().join(name)).unwrap();
        check_copies(&out, &want[original], copies, fixture);
        // a test, a listing and a read by index agree
        let t = extract::run(&path, &opts(Mode::Test, dir.path()), |_| {}).unwrap();
        assert!(t.errors.is_empty() && t.bytes == out.len() as u64, "{fixture}: {:?}", t.errors);
        let listing = extract::list(&path).unwrap();
        assert_eq!((listing.len(), listing[0].name.as_str(), listing[0].size), (1, name, out.len() as u64));
        let mut read = Vec::new();
        SelectedEntry::open(&path, 0, None, 1 << 30)
            .unwrap()
            .read(None, |c| {
                read.extend_from_slice(c);
                Ok(())
            })
            .unwrap();
        assert!(read == out, "{fixture}");
    }
}

#[test]
fn compressed_tar_reads_as_tar_does() {
    let want = expected();
    for fixture in ["t.tar.lz4", "t.tar.Z", "t.tar.lzma"] {
        let path = fixtures().join(fixture);
        let dir = tempfile::tempdir().unwrap();
        let s = extract::run(&path, &opts(Mode::Extract, dir.path()), |_| {}).unwrap();
        assert!(s.errors.is_empty(), "{fixture}: {:?}", s.errors);
        assert_eq!(s.files, 2, "{fixture}");
        for name in ["data.bin", "small.txt"] {
            assert_eq!(sha(&fs::read(dir.path().join(name)).unwrap()), want[name], "{fixture}/{name}");
        }
        let names: Vec<String> = extract::list(&path).unwrap().into_iter().map(|e| e.name).collect();
        assert_eq!(names, ["data.bin", "small.txt"], "{fixture}");
        let t = extract::run(&path, &opts(Mode::Test, dir.path()), |_| {}).unwrap();
        assert!(t.errors.is_empty() && t.files == 2, "{fixture}: {:?}", t.errors);
    }
}

/// The format comes from the first bytes, whatever the name says.
#[test]
fn the_magic_decides_not_the_name() {
    let want = expected();
    for (fixture, _, original, copies) in LONE {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob");
        fs::copy(fixtures().join(fixture), &path).unwrap();
        let out = dir.path().join("out");
        let s = extract::run(&path, &opts(Mode::Extract, &out), |_| {}).unwrap();
        assert!(s.errors.is_empty(), "{fixture}: {:?}", s.errors);
        check_copies(&fs::read(out.join("blob.out")).unwrap(), &want[original], copies, fixture);
    }
    for fixture in ["t.tar.lz4", "t.tar.Z", "t.tar.lzma"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive.bin");
        fs::copy(fixtures().join(fixture), &path).unwrap();
        assert_eq!(extract::list(&path).unwrap().len(), 2, "{fixture}");
    }
}

/// Every route fails on `bytes`: extraction and testing report an error, a listing and a read by index fail.
fn fails(bytes: &[u8], what: &str) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("x");
    fs::write(&path, bytes).unwrap();
    for mode in [Mode::Extract, Mode::Test] {
        let out = dir.path().join(format!("out-{mode:?}"));
        if let Ok(s) = extract::run(&path, &opts(mode, &out), |_| {}) {
            assert!(!s.errors.is_empty(), "{what} {mode:?}: no error");
            assert_eq!(s.files, 0, "{what} {mode:?}");
        }
        assert!(!out.join("x.out").exists(), "{what} {mode:?}: a broken stream left output");
    }
    assert!(extract::list(&path).is_err(), "{what}: listed");
    let read = SelectedEntry::open(&path, 0, None, 1 << 30).and_then(|e| e.read(None, |_| Ok(())));
    assert!(read.is_err(), "{what}: read");
}

#[test]
fn a_stream_cut_short_fails() {
    for (fixture, ..) in LONE {
        let bytes = fs::read(fixtures().join(fixture)).unwrap();
        // .Z has no end mark: cut it inside the header instead, and mid-way for the others
        let cut = if fixture.ends_with(".Z") { 2 } else { bytes.len() / 2 };
        fails(&bytes[..cut], fixture);
    }
    for fixture in ["t.tar.lz4", "t.tar.Z", "t.tar.lzma"] {
        let bytes = fs::read(fixtures().join(fixture)).unwrap();
        fails(&bytes[..bytes.len() / 3], fixture);
    }
}

#[test]
fn damaged_lz4_frames_fail() {
    let plain = fs::read(fixtures().join("data-plain.bin.lz4")).unwrap();
    // the header checksum (magic, FLG, BD, HC)
    let mut b = plain.clone();
    b[6] ^= 1;
    fails(&b, "header checksum");
    // reserved bits in BD
    let mut b = plain.clone();
    b[5] |= 0x01;
    fails(&b, "reserved bits");
    // a block bigger than the frame allows
    let mut b = plain.clone();
    b[7..11].copy_from_slice(&0x0100_0000u32.to_le_bytes());
    fails(&b, "oversized block");
    // the content checksum at the very end
    let mut b = plain.clone();
    *b.last_mut().unwrap() ^= 1;
    fails(&b, "content checksum");
    // data in a block
    let mut b = plain.clone();
    let mid = b.len() / 2;
    b[mid] ^= 0x55;
    fails(&b, "a damaged block");
    // what follows a frame has to be another frame
    let mut b = plain.clone();
    b.extend_from_slice(b"junk after the frame");
    fails(&b, "trailing junk");
    // linked blocks carry block checksums
    let mut linked = fs::read(fixtures().join("data-linked.bin.lz4")).unwrap();
    let mid = linked.len() / 2;
    linked[mid] ^= 0x55;
    fails(&linked, "a damaged linked block");
}

#[test]
fn damaged_compress_streams_fail() {
    // 9-bit codes, least significant bit first: a first code past 255
    fails(&[0x1f, 0x9d, 0x90, 0x2c, 0x01], "an invalid first code");
    // 'a', then code 300 when the next free code is 257
    fails(&[0x1f, 0x9d, 0x90, 0x61, 0x58, 0x02], "a code past the table");
    // the reviewer's case: 9-bit codes at most, 264 literals fill the table and the width grows to 10, then
    // code 512, past the table, three times
    let mut codes: Vec<(u32, u32)> = (0..264).map(|i| (i % 256, 9)).collect();
    codes.extend([(512, 10), (512, 10), (512, 10)]);
    let (mut packed, mut acc, mut bits) = (vec![0x1f, 0x9d, 0x09], 0u64, 0u32);
    for (code, width) in codes {
        acc |= u64::from(code) << bits;
        bits += width;
        while bits >= 8 {
            packed.push(acc as u8);
            acc >>= 8;
            bits -= 8;
        }
    }
    packed.push(acc as u8);
    fails(&packed, "a code past a full 9-bit table");
    packed[2] = 0x89;
    fails(&packed, "the same in block mode");
}

#[test]
fn an_lzma_dictionary_past_the_memory_limit_is_refused() {
    // 1.5 GiB of dictionary, against the 256 MiB the decoders may use
    let mut b = vec![0x5d];
    b.extend_from_slice(&(3u32 << 29).to_le_bytes());
    b.extend_from_slice(&u64::MAX.to_le_bytes());
    b.extend_from_slice(&[0u8; 64]);
    fails(&b, "a 1.5 GiB dictionary");
    // a stream with data after its end
    let mut trailing = fs::read(fixtures().join("data.bin.lzma")).unwrap();
    trailing.extend_from_slice(b"trailing junk");
    fails(&trailing, "data after the LZMA stream");
    // and a stream whose data is damaged
    let mut lzma = fs::read(fixtures().join("data.bin.lzma")).unwrap();
    let mid = lzma.len() / 2;
    lzma[mid] ^= 0x55;
    fails(&lzma, "a damaged LZMA stream");
}
