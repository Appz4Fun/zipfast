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

//! Sparse tar members: GNU tar's old format and pax 0.0, 0.1 and 1.0, and bsdtar's pax 1.0 (see
//! tests/fixtures/tar-sparse/gen.sh), extracted, tested, listed and read by index, plain and gzip-compressed; then
//! hostile maps built here.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use flate2::Compression;
use flate2::write::GzEncoder;
use zipfast::extract::{self, Mode, Options, Overwrite, SelectedEntry};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tar-sparse")
}

fn hex(d: [u8; 32]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// name -> (sha256, size) of the files each archive holds
fn expected(gnu: bool) -> BTreeMap<String, (String, Option<u64>)> {
    let dir = fixtures();
    let mut out = BTreeMap::new();
    let sums = if gnu { "expected.sha256" } else { "expected-bsdtar.sha256" };
    for line in fs::read_to_string(dir.join(sums)).unwrap().lines() {
        let (sum, name) = line.split_once("  ").unwrap();
        out.insert(name.to_owned(), (sum.to_owned(), None));
    }
    if gnu {
        for line in fs::read_to_string(dir.join("expected.size")).unwrap().lines() {
            let (size, name) = line.split_once(' ').unwrap();
            out.get_mut(name).unwrap().1 = Some(size.parse().unwrap());
        }
    }
    out
}

const GNU: [&str; 5] = ["gnu-old.tar", "pax-0.0.tar", "pax-0.1.tar", "pax-1.0.tar", "pax-1.0.tgz"];
const BSDTAR: [&str; 2] = ["bsdtar-pax.tar", "bsdtar-pax.tgz"];

fn all() -> impl Iterator<Item = (&'static str, BTreeMap<String, (String, Option<u64>)>)> {
    GNU.into_iter().map(|a| (a, expected(true))).chain(BSDTAR.into_iter().map(|a| (a, expected(false))))
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
    }
}

fn sha_file(path: &Path) -> String {
    hex(zipfast::crypto::sha256(&fs::read(path).unwrap()))
}

#[test]
fn every_writer_and_form_extracts_to_the_files_it_was_made_from() {
    for (archive, want) in all() {
        let dir = tempfile::tempdir().unwrap();
        let s = extract::run(&fixtures().join(archive), &opts(Mode::Extract, dir.path()), |_| {}).unwrap();
        assert!(s.errors.is_empty(), "{archive}: {:?}", s.errors);
        assert_eq!(s.files as usize, want.len(), "{archive}");
        let mut found: Vec<String> =
            fs::read_dir(dir.path()).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        found.sort();
        assert_eq!(found, want.keys().cloned().collect::<Vec<_>>(), "{archive}: GNU.sparse.name is the name");
        for (name, (sum, size)) in &want {
            let path = dir.path().join(name);
            let meta = fs::metadata(&path).unwrap();
            if let Some(size) = size {
                assert_eq!(meta.len(), *size, "{archive}/{name}");
            }
            assert_eq!(&sha_file(&path), sum, "{archive}/{name}");
        }
        assert_eq!(s.bytes, want.keys().map(|n| fs::metadata(dir.path().join(n)).unwrap().len()).sum::<u64>());
    }
}

/// The 96 MiB bsdtar file holds 24 KiB of data: written out, it takes about that much room where holes are kept.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn the_holes_stay_holes_on_disk() {
    use std::os::unix::fs::MetadataExt;
    for archive in BSDTAR {
        let dir = tempfile::tempdir().unwrap();
        let s = extract::run(&fixtures().join(archive), &opts(Mode::Extract, dir.path()), |_| {}).unwrap();
        assert!(s.errors.is_empty(), "{archive}: {:?}", s.errors);
        let meta = fs::metadata(dir.path().join("holes")).unwrap();
        assert_eq!(meta.len(), 4 * (24 << 20) + 12345);
        assert!(meta.blocks() * 512 < 8 << 20, "{archive}: {} bytes allocated", meta.blocks() * 512);
    }
}

#[test]
fn a_test_and_a_listing_count_the_full_size() {
    for (archive, want) in all() {
        let path = fixtures().join(archive);
        let unused = tempfile::tempdir().unwrap();
        let s = extract::run(&path, &opts(Mode::Test, unused.path()), |_| {}).unwrap();
        assert!(s.errors.is_empty(), "{archive}: {:?}", s.errors);
        assert_eq!(s.files as usize, want.len());
        let listing = extract::list(&path).unwrap();
        let names: Vec<&str> = listing.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, want.keys().map(String::as_str).collect::<Vec<_>>(), "{archive}");
        for e in &listing {
            if let Some(size) = want[&e.name].1 {
                assert_eq!(e.size, size, "{archive}/{}", e.name);
            }
            assert!(e.packed < e.size, "{archive}/{}: stored {} of {}", e.name, e.packed, e.size);
        }
        assert_eq!(s.bytes, listing.iter().map(|e| e.size).sum::<u64>(), "{archive}");
        assert!(fs::read_dir(unused.path()).unwrap().next().is_none());
    }
}

#[test]
fn a_member_read_by_index_comes_out_whole_and_counts_its_full_size_against_the_limit() {
    for (archive, want) in all() {
        let path = fixtures().join(archive);
        for (index, (name, (sum, _))) in want.iter().enumerate() {
            let entry = SelectedEntry::open(&path, index, None, 1 << 30).unwrap();
            assert_eq!(entry.name(), name);
            let mut h = zipfast::crypto::Sha256::new();
            let mut n = 0u64;
            entry
                .read(None, |chunk| {
                    h.update(chunk);
                    n += chunk.len() as u64;
                    Ok(())
                })
                .unwrap();
            assert_eq!(&hex(h.finalize()), sum, "{archive}/{name}");
            let size = extract::list(&path).unwrap()[index].size;
            assert_eq!(n, size);
            // more than it stores, less than it makes
            assert!(SelectedEntry::open(&path, index, None, size - 1).is_err(), "{archive}/{name}");
        }
    }
}

// --- hostile maps -----------------------------------------------------------------------------------------------

fn header(name: &[u8], kind: u8, size: u64, gnu: bool) -> [u8; 512] {
    let mut h = [0u8; 512];
    h[..name.len()].copy_from_slice(name);
    let octal = |h: &mut [u8; 512], at: usize, width: usize, v: u64| {
        h[at..at + width].copy_from_slice(format!("{v:0w$o}\0", w = width - 1).as_bytes());
    };
    octal(&mut h, 100, 8, 0o644);
    octal(&mut h, 108, 8, 0);
    octal(&mut h, 116, 8, 0);
    octal(&mut h, 124, 12, size);
    octal(&mut h, 136, 12, 0);
    h[156] = kind;
    h[257..265].copy_from_slice(if gnu { b"ustar  \0" } else { b"ustar\x0000" });
    sum(&mut h);
    h
}

fn sum(h: &mut [u8; 512]) {
    h[148..156].fill(b' ');
    let sum: u64 = h.iter().map(|&b| b as u64).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
}

fn padded(mut v: Vec<u8>) -> Vec<u8> {
    v.resize(v.len().div_ceil(512) * 512, 0);
    v
}

fn records(records: &[(&str, String)]) -> Vec<u8> {
    let mut body = Vec::new();
    for (k, v) in records {
        let tail = format!(" {k}={v}\n");
        let mut n = tail.len() + 1;
        while format!("{n}{tail}").len() != n {
            n += 1;
        }
        body.extend_from_slice(format!("{n}{tail}").as_bytes());
    }
    body
}

/// A pax member with `recs`, stored data `data`, and a plain member after it.
fn pax_member(recs: &[(&str, String)], data: &[u8]) -> Vec<u8> {
    let body = records(recs);
    let mut out = header(b"PaxHeaders/x", b'x', body.len() as u64, false).to_vec();
    out.extend(padded(body));
    out.extend(header(b"GNUSparseFile.1/s", b'0', data.len() as u64, false));
    out.extend(padded(data.to_vec()));
    out.extend(header(b"after.txt", b'0', 5, false));
    out.extend(padded(b"after".to_vec()));
    out.extend([0u8; 1024]);
    out
}

fn v01(map: &str, real: u64, data: &[u8]) -> Vec<u8> {
    pax_member(
        &[
            ("GNU.sparse.major", "0".into()),
            ("GNU.sparse.minor", "1".into()),
            ("GNU.sparse.name", "s".into()),
            ("GNU.sparse.size", real.to_string()),
            ("GNU.sparse.map", map.into()),
        ],
        data,
    )
}

fn v10(map: &[u8], real: u64, data: &[u8]) -> Vec<u8> {
    let mut stored = padded(map.to_vec());
    stored.extend_from_slice(data);
    pax_member(
        &[
            ("GNU.sparse.major", "1".into()),
            ("GNU.sparse.minor", "0".into()),
            ("GNU.sparse.name", "s".into()),
            ("GNU.sparse.realsize", real.to_string()),
        ],
        &stored,
    )
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

/// Every route refuses the archive with `why`, plain and compressed, and writes nothing of the sparse member.
fn refused(tar: &[u8], why: &str) {
    for (name, bytes) in [("h.tar", tar.to_vec()), ("h.tgz", gzip(tar))] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(name);
        fs::write(&path, &bytes).unwrap();
        let out = dir.path().join("out");
        for mode in [Mode::Extract, Mode::Test] {
            let message = match extract::run(&path, &opts(mode, &out), |_| {}) {
                Ok(s) => {
                    assert_eq!(s.files, 0, "{name} {mode:?}: {why}");
                    s.errors.join("\n")
                }
                Err(e) => e.to_string(),
            };
            assert!(message.contains(why), "{name} {mode:?}: wanted {why:?}, got {message:?}");
            assert!(!out.join("s").exists());
        }
        let listed = extract::list(&path).map(|_| ()).unwrap_err().to_string();
        assert!(listed.contains(why), "{name} list: {listed}");
        let selected = SelectedEntry::open(&path, 0, None, 1 << 30).map(|_| ()).unwrap_err().to_string();
        assert!(selected.contains(why), "{name} selected: {selected}");
    }
}

#[test]
fn a_well_formed_map_built_here_reads_back() {
    // data, a hole, data, and a hole to the end
    let tar = v01("0,3,10,2", 20, b"abcde");
    let mut want = b"abc".to_vec();
    want.resize(10, 0);
    want.extend_from_slice(b"de");
    want.resize(20, 0);
    let tar10 = v10(b"2\n0\n3\n10\n2\n", 20, b"abcde");
    for (name, bytes) in
        [("a.tar", tar.clone()), ("a.tgz", gzip(&tar)), ("b.tar", tar10.clone()), ("b.tgz", gzip(&tar10))]
    {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(name);
        fs::write(&path, &bytes).unwrap();
        let out = dir.path().join("out");
        let s = extract::run(&path, &opts(Mode::Extract, &out), |_| {}).unwrap();
        assert!(s.errors.is_empty(), "{name}: {:?}", s.errors);
        assert_eq!(fs::read(out.join("s")).unwrap(), want, "{name}");
        assert_eq!(fs::read(out.join("after.txt")).unwrap(), b"after", "{name}");
    }
}

#[test]
fn a_map_out_of_order_or_overlapping_is_refused() {
    refused(&v01("10,2,0,3", 20, b"abcde"), "out of order or overlap");
    refused(&v01("0,3,2,2", 20, b"abcde"), "out of order or overlap");
    refused(&v10(b"2\n10\n2\n0\n3\n", 20, b"abcde"), "out of order or overlap");
}

#[test]
fn a_map_entry_past_the_real_size_is_refused() {
    refused(&v01("0,3,18,2", 19, b"abcde"), "past the end");
    refused(&v01(&format!("0,3,{},2", u64::MAX - 1), u64::MAX, b"abcde"), "past the end");
}

#[test]
fn a_map_that_does_not_add_up_to_the_stored_data_is_refused() {
    refused(&v01("0,3,10,3", 20, b"abcde"), "don't add up");
    refused(&v01("0,3", 20, b"abcde"), "don't add up");
    refused(&v10(b"1\n0\n6\n", 20, b"abcde"), "don't add up");
}

#[test]
fn a_map_with_too_many_entries_or_bytes_is_refused() {
    // the count alone is enough to refuse it
    refused(&v10(format!("{}\n", 1u64 << 40).as_bytes(), 20, b""), "too many entries");
    // 400,001 lines of 21 bytes: past the 8 MiB the map may take in the data area
    let mut map = b"200000\n".to_vec();
    for _ in 0..400_000 {
        map.extend_from_slice(b"00000000000000000000\n");
    }
    refused(&v10(&map, 20, b""), "too long");
    // an old GNU map whose extension blocks never end
    let mut h = header(b"s", b'S', 0, true);
    h[482] = 1;
    sum(&mut h);
    let mut tar = h.to_vec();
    let mut ext = [0u8; 512];
    ext[504] = 1;
    for _ in 0..20_000 {
        tar.extend_from_slice(&ext);
    }
    tar.extend([0u8; 1024]);
    refused(&tar, "too long");
    // unreadable numbers
    refused(&v01("0,x", 20, b""), "unreadable");
    refused(&v10(b"1\n0\n-3\n", 20, b""), "unreadable");
}

#[test]
fn a_huge_real_size_allocates_nothing_and_counts_against_the_limit() {
    let tar = v01("0,5", 1 << 60, b"abcde");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("huge.tar");
    fs::write(&path, &tar).unwrap();
    let listing = extract::list(&path).unwrap();
    assert_eq!((listing[0].name.as_str(), listing[0].size, listing[0].packed), ("s", 1 << 60, 5));
    let refused = SelectedEntry::open(&path, 0, None, 1 << 30).map(|_| ()).unwrap_err().to_string();
    assert!(refused.contains("byte limit"), "{refused}");
}

#[test]
fn an_old_gnu_member_with_map_extensions_extracts_and_the_member_after_it_is_found() {
    // two pieces in the header, one in an extension block
    let mut h = header(b"s", b'S', 3 * 512, true);
    let entry = |h: &mut [u8], at: usize, offset: u64, len: u64| {
        h[at..at + 12].copy_from_slice(format!("{offset:011o}\0").as_bytes());
        h[at + 12..at + 24].copy_from_slice(format!("{len:011o}\0").as_bytes());
    };
    entry(&mut h, 386, 0, 512);
    entry(&mut h, 410, 4096, 512);
    h[482] = 1;
    h[483..495].copy_from_slice(format!("{:011o}\0", 16384).as_bytes());
    sum(&mut h);
    let mut ext = [0u8; 512];
    entry(&mut ext, 0, 8192, 512);
    let mut tar = h.to_vec();
    tar.extend_from_slice(&ext);
    tar.extend([b'a'; 512]);
    tar.extend([b'b'; 512]);
    tar.extend([b'c'; 512]);
    tar.extend(header(b"after.txt", b'0', 5, false));
    tar.extend(padded(b"after".to_vec()));
    tar.extend([0u8; 1024]);
    let mut want = vec![0u8; 16384];
    want[..512].fill(b'a');
    want[4096..4608].fill(b'b');
    want[8192..8704].fill(b'c');
    for (name, bytes) in [("o.tar", tar.clone()), ("o.tgz", gzip(&tar))] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(name);
        fs::write(&path, &bytes).unwrap();
        let out = dir.path().join("out");
        let s = extract::run(&path, &opts(Mode::Extract, &out), |_| {}).unwrap();
        assert!(s.errors.is_empty(), "{name}: {:?}", s.errors);
        assert_eq!(s.files, 2);
        assert!(fs::read(out.join("s")).unwrap() == want, "{name}");
        assert_eq!(fs::read(out.join("after.txt")).unwrap(), b"after");
        assert_eq!(extract::list(&path).unwrap()[0].size, 16384);
    }
}

/// Every route fails the sparse member alone with `why`, plain and compressed: the member after it still comes out.
fn member_refused(tar: &[u8], why: &str) {
    for (name, bytes) in [("m.tar", tar.to_vec()), ("m.tgz", gzip(tar))] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(name);
        fs::write(&path, &bytes).unwrap();
        for mode in [Mode::Extract, Mode::Test] {
            let out = dir.path().join(format!("out-{mode:?}"));
            let s = extract::run(&path, &opts(mode, &out), |_| {}).unwrap();
            assert_eq!((s.files, s.errors.len()), (1, 1), "{name} {mode:?}: {:?}", s.errors);
            assert!(s.errors[0].contains(why), "{name} {mode:?}: {:?}", s.errors);
            assert!(!out.join("s").exists(), "{name} {mode:?}");
            if mode == Mode::Extract {
                assert_eq!(fs::read(out.join("after.txt")).unwrap(), b"after", "{name}");
            }
        }
        // listed at the size it claims, refused when read
        assert_eq!(extract::list(&path).unwrap().len(), 2);
        let selected = SelectedEntry::open(&path, 0, None, u64::MAX).map(|_| ()).unwrap_err().to_string();
        assert!(selected.contains(why), "{name} selected: {selected}");
        let after = SelectedEntry::open(&path, 1, None, 1 << 30).unwrap();
        assert_eq!(after.name(), "after.txt");
    }
}

const BOMB: &str = "refused as a bomb";

#[test]
fn a_few_kib_claiming_a_tib_is_refused_on_its_own() {
    let data = vec![b'x'; 3000];
    member_refused(&v01("0,3000", 1 << 40, &data), BOMB);
    member_refused(&v10(b"1\n0\n3000\n", 1 << 40, &data), BOMB);
}

#[test]
fn a_real_size_past_what_a_file_can_be_fails_only_its_member() {
    member_refused(&v01("0,5", u64::MAX, b"abcde"), BOMB);
    member_refused(&v01("0,5", 1 << 63, b"abcde"), BOMB);
    member_refused(&v01(&format!("{},5", u64::MAX - 5), u64::MAX, b"abcde"), BOMB);
}

/// Both sides of the cap: 1 GiB from 4 KiB, and 1024 times 2 MiB; one byte more than the latter is a bomb.
#[test]
fn a_high_ratio_file_under_the_cap_extracts() {
    for (stored, real, fill) in [(4096u64, 1u64 << 30, b'k'), (2 << 20, 2 << 30, b'm')] {
        let data = vec![fill; stored as usize];
        let tar = v01(&format!("{},{stored}", real - stored), real, &data);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ok.tar");
        fs::write(&path, &tar).unwrap();
        let out = dir.path().join("out");
        let s = extract::run(&path, &opts(Mode::Extract, &out), |_| {}).unwrap();
        assert!(s.errors.is_empty(), "{real}: {:?}", s.errors);
        assert_eq!(s.files, 2);
        let meta = fs::metadata(out.join("s")).unwrap();
        assert_eq!(meta.len(), real);
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            use std::os::unix::fs::MetadataExt;
            assert!(meta.blocks() * 512 < 64 << 20, "{real}: {} bytes allocated", meta.blocks() * 512);
        }
        use std::io::{Read, Seek, SeekFrom};
        let mut f = fs::File::open(out.join("s")).unwrap();
        f.seek(SeekFrom::Start(real - stored - 1)).unwrap();
        let mut tail = Vec::new();
        f.read_to_end(&mut tail).unwrap();
        assert_eq!(tail.len() as u64, stored + 1);
        assert!(tail[0] == 0 && tail[1..].iter().all(|&b| b == fill), "{real}");
    }
    let data = vec![b'm'; 2 << 20];
    member_refused(&v01(&format!("{},{}", 2 << 20, 2 << 20), (2 << 30) + 1, &data), BOMB);
}

#[test]
fn conflicting_sparse_records_are_refused() {
    let tar = pax_member(
        &[
            ("GNU.sparse.major", "0".into()),
            ("GNU.sparse.minor", "1".into()),
            ("GNU.sparse.name", "s".into()),
            ("GNU.sparse.size", "20".into()),
            ("GNU.sparse.map", "0,5".into()),
            ("GNU.sparse.size", "1099511627776".into()),
        ],
        b"abcde",
    );
    refused(&tar, "records conflict");
    // the same value twice is no conflict
    let tar = pax_member(
        &[
            ("GNU.sparse.name", "s".into()),
            ("GNU.sparse.size", "20".into()),
            ("GNU.sparse.size", "20".into()),
            ("GNU.sparse.map", "0,5".into()),
        ],
        b"abcde",
    );
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("same.tar");
    fs::write(&path, &tar).unwrap();
    assert_eq!(extract::list(&path).unwrap()[0].size, 20);
}

/// One pax 0.1 member named `name`: `data` at the end of a file `real` bytes long.
fn sparse_member(name: &str, real: u64, data: &[u8]) -> Vec<u8> {
    let body = records(&[
        ("GNU.sparse.major", "0".into()),
        ("GNU.sparse.minor", "1".into()),
        ("GNU.sparse.name", name.into()),
        ("GNU.sparse.size", real.to_string()),
        ("GNU.sparse.map", format!("{},{}", real - data.len() as u64, data.len())),
    ]);
    let mut out = header(b"PaxHeaders/x", b'x', body.len() as u64, false).to_vec();
    out.extend(padded(body));
    out.extend(header(format!("GNUSparseFile.1/{name}").as_bytes(), b'0', data.len() as u64, false));
    out.extend(padded(data.to_vec()));
    out
}

fn plain_member(name: &str, data: &[u8]) -> Vec<u8> {
    let mut out = header(name.as_bytes(), b'0', data.len() as u64, false).to_vec();
    out.extend(padded(data.to_vec()));
    out
}

/// Eight members of 1 KiB each claiming 300 MiB, each well under the per-member cap: the run's 1 GiB of holes (plus
/// 1 MiB for each member's KiB) covers three, the other five are refused one by one, and plain members between and
/// after them still come out.
#[test]
fn many_members_under_the_cap_share_one_budget_of_holes() {
    let data = vec![b'd'; 1024];
    let mut tar = Vec::new();
    for i in 0..8 {
        tar.extend(sparse_member(&format!("s{i}"), 300 << 20, &data));
        if i == 5 {
            tar.extend(plain_member("middle.txt", b"middle"));
        }
    }
    tar.extend(plain_member("after.txt", b"after"));
    tar.extend([0u8; 1024]);
    for (name, bytes) in [("b.tar", tar.clone()), ("b.tgz", gzip(&tar))] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(name);
        fs::write(&path, &bytes).unwrap();
        for mode in [Mode::Extract, Mode::Test] {
            let out = dir.path().join(format!("out-{mode:?}"));
            let s = extract::run(&path, &opts(mode, &out), |_| {}).unwrap();
            assert_eq!((s.files, s.errors.len()), (5, 5), "{name} {mode:?}: {:?}", s.errors);
            assert!(s.errors.iter().all(|e| e.contains("together claim")), "{name} {mode:?}: {:?}", s.errors);
            for i in 3..8 {
                assert!(s.errors.iter().any(|e| e.contains(&format!("s{i}"))), "{name} {mode:?}: {:?}", s.errors);
            }
            if mode == Mode::Extract {
                for i in 0..3 {
                    assert_eq!(fs::metadata(out.join(format!("s{i}"))).unwrap().len(), 300 << 20, "{name}");
                }
                for i in 3..8 {
                    assert!(!out.join(format!("s{i}")).exists(), "{name}: s{i}");
                }
                assert_eq!(fs::read(out.join("middle.txt")).unwrap(), b"middle", "{name}");
                assert_eq!(fs::read(out.join("after.txt")).unwrap(), b"after", "{name}");
            }
        }
        // a read by index keeps its own limit, not the run's budget
        let entry = SelectedEntry::open(&path, 8, None, 1 << 30).unwrap(); // middle.txt is index 6
        assert_eq!(entry.name(), "s7");
    }
}

fn link_member(name: &str, kind: u8, target: &str) -> Vec<u8> {
    let mut h = header(name.as_bytes(), kind, 0, false);
    h[157..157 + target.len()].copy_from_slice(target.as_bytes());
    sum(&mut h);
    h.to_vec()
}

/// A sparse member, a hard link and a symbolic link to it, and a hard link to a sparse member refused as a bomb:
/// the links take the sparse file as any other, and the one to the refused member fails, testing as extracting.
#[cfg(unix)]
#[test]
fn links_to_sparse_members_work_and_one_to_a_refused_member_fails() {
    let mut tar = sparse_member("s", 20, b"abcde");
    tar.extend(link_member("hard", b'1', "s"));
    tar.extend(link_member("soft", b'2', "s"));
    tar.extend(sparse_member("bomb", 1 << 40, b"x"));
    tar.extend(link_member("to-bomb", b'1', "bomb"));
    tar.extend(plain_member("after.txt", b"after"));
    tar.extend([0u8; 1024]);
    let mut want = vec![0u8; 15];
    want.extend_from_slice(b"abcde");
    for (name, bytes) in [("l.tar", tar.clone()), ("l.tgz", gzip(&tar))] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(name);
        fs::write(&path, &bytes).unwrap();
        for mode in [Mode::Extract, Mode::Test] {
            let out = dir.path().join(format!("out-{mode:?}"));
            let s = extract::run(&path, &opts(mode, &out), |_| {}).unwrap();
            assert_eq!(s.errors.len(), 2, "{name} {mode:?}: {:?}", s.errors);
            assert!(s.errors.iter().any(|e| e.contains("bomb") && e.contains("refused as a bomb")), "{:?}", s.errors);
            assert!(s.errors.iter().any(|e| e.contains("to-bomb") && e.contains("hard link")), "{:?}", s.errors);
            assert_eq!(s.files, 4, "{name} {mode:?}: s, hard, soft, after.txt");
            if mode == Mode::Extract {
                assert_eq!(fs::read(out.join("s")).unwrap(), want, "{name}");
                assert_eq!(fs::read(out.join("hard")).unwrap(), want, "{name}");
                assert_eq!(fs::read_link(out.join("soft")).unwrap(), Path::new("s"), "{name}");
                assert!(!out.join("bomb").exists() && !out.join("to-bomb").exists(), "{name}");
                assert_eq!(fs::read(out.join("after.txt")).unwrap(), b"after", "{name}");
            }
        }
    }
}
