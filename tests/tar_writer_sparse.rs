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

//! Sparse members against archives GNU tar 1.35 wrote with `--sparse` (tests/fixtures/tar-writer/make-sparse.sh),
//! and a round trip through zipfast's own tar reader that checks the expanded bytes.

use std::path::Path;

use zipfast::extract::{self, Mode, Options, Overwrite};
use zipfast::tar::write::{TarEntry, TarEntryKind as K, TarFormat, TarWriter, TarWriterOptions};

const T: i64 = 1_700_000_000;

struct Sp {
    entry: TarEntry,
    /// the data bytes of the segments, back to back
    data: Vec<u8>,
    /// the whole file as it reads back
    full: Vec<u8>,
}

/// A file of `size` bytes whose segments are `(offset, bytes)`.
fn sparse(name: &[u8], size: u64, pieces: &[(u64, Vec<u8>)]) -> Sp {
    let mut e = TarEntry::new(name, K::Sparse);
    e.mtime = T;
    e.uname = b"root".to_vec();
    e.gname = b"root".to_vec();
    e.size = size;
    let mut data = Vec::new();
    let mut full = vec![0u8; size as usize];
    for (off, bytes) in pieces {
        e.sparse.push((*off, bytes.len() as u64));
        data.extend_from_slice(bytes);
        full[*off as usize..*off as usize + bytes.len()].copy_from_slice(bytes);
    }
    Sp { entry: e, data, full }
}

fn blk(c: u8) -> Vec<u8> {
    vec![c; 4096]
}

/// The files of make-sparse.sh, in its archive order.
fn files() -> Vec<Sp> {
    const M: u64 = 1 << 20;
    let mut v = vec![sparse(b"one-hole", M, &[(0, blk(b'A')), (1_044_480, blk(b'Z'))])];
    let six: Vec<_> = b"ABCDEF".iter().enumerate().map(|(i, &c)| (i as u64 * 163_840, blk(c))).collect();
    v.push(sparse(b"many6", M, &six));
    let thirty: Vec<_> =
        b"abcdefghijklmnopqrstuvwxyzABCD".iter().enumerate().map(|(i, &c)| (i as u64 * 32_768, blk(c))).collect();
    v.push(sparse(b"many30", M, &thirty));
    v.push(sparse(b"hole-end", M, &[(0, blk(b'H'))]));
    v.push(sparse(b"hole-start", M, &[(1_044_480, blk(b'S'))]));
    let mut tail = vec![0u8; 4072];
    tail[3232..3241].copy_from_slice(b"tail-data");
    v.push(sparse(b"partial", 36_840, &[(0, blk(b'P')), (32_768, tail)]));
    v.push(sparse(b"all-hole", M, &[]));
    let mut name = b"sd/".to_vec();
    name.extend(std::iter::repeat_n(b'l', 110));
    let mut long = sparse(&name, 20_480, &[(0, blk(b'L')), (12_288, blk(b'M'))]);
    long.entry.uid = 3_000_000;
    long.entry.gid = 2;
    long.entry.gname = b"bin".to_vec();
    long.entry.uname = Vec::new();
    long.entry.mtime_nanos = 250_000_000;
    v.push(long);
    v
}

fn write(items: &[Sp], format: TarFormat) -> Vec<u8> {
    let o = TarWriterOptions { format, sparse_pid: Some(1), ..TarWriterOptions::default() };
    let mut w = TarWriter::new(Vec::new(), o);
    for i in items {
        w.append(&i.entry, &mut i.data.as_slice()).unwrap();
    }
    w.finish().unwrap()
}

fn assert_same(got: &[u8], want: &[u8], what: &str) {
    if got != want {
        let at = got.iter().zip(want).position(|(a, b)| a != b).unwrap_or(got.len().min(want.len()));
        panic!("{what}: differs at byte {at} (block {}); lengths {} and {}", at / 512, got.len(), want.len());
    }
}

fn reference(name: &str) -> Vec<u8> {
    std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tar-writer").join(name)).unwrap()
}

#[test]
fn gnu_sparse_is_byte_exact() {
    assert_same(&write(&files(), TarFormat::Gnu), &reference("sparse-gnu.tar"), "gnu --sparse");
}

#[test]
fn pax_sparse_1_0_is_byte_exact() {
    // GNU tar 1.35's default `--sparse-version` is 1.0: the same bytes as an explicit 1.0 (make-sparse.sh checks)
    assert_same(&write(&files(), TarFormat::Pax), &reference("sparse-pax10.tar"), "pax --sparse");
}

#[test]
fn each_file_alone_is_byte_exact_in_the_gnu_archive() {
    // the last four blocks of a one-file archive are the end marker and padding: compare member by member by
    // writing each file alone and finding its blocks in the reference
    let want = reference("sparse-gnu.tar");
    for f in files() {
        let one = write(std::slice::from_ref(&f), TarFormat::Gnu);
        let used = one.iter().rposition(|&b| b != 0).unwrap() / 512 + 1;
        let body = &one[..used * 512];
        assert!(
            want.windows(body.len()).step_by(512).any(|w| w == body),
            "{:?}",
            String::from_utf8_lossy(&f.entry.path)
        );
    }
}

fn opts(dest: &Path) -> Options {
    Options {
        mode: Mode::Extract,
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

#[test]
fn round_trips_through_the_tar_reader() {
    let dir = tempfile::tempdir().unwrap();
    for format in [TarFormat::Gnu, TarFormat::Pax] {
        let archive = dir.path().join(format!("{format:?}.tar"));
        std::fs::write(&archive, write(&files(), format)).unwrap();
        let out = dir.path().join(format!("out-{format:?}"));
        std::fs::create_dir(&out).unwrap();
        extract::run(&archive, &opts(&out), |_| {}).unwrap();
        for f in files() {
            let rel = String::from_utf8(f.entry.path.clone()).unwrap();
            let got = std::fs::read(out.join(&rel)).unwrap();
            assert_eq!(got.len(), f.full.len(), "{format:?} {rel}");
            assert!(got == f.full, "{format:?} {rel}: expanded bytes differ");
        }
    }
}

#[test]
fn refuses_what_cannot_be_written() {
    let fresh =
        |f: TarFormat| TarWriter::new(Vec::new(), TarWriterOptions { format: f, ..TarWriterOptions::default() });
    let ok = sparse(b"s", 8192, &[(0, vec![1; 100])]);
    assert!(fresh(TarFormat::Ustar).begin(&ok.entry).is_err());
    for pieces in [vec![(0u64, 0u64)], vec![(100, 50), (120, 10)], vec![(8000, 500)], vec![(10, 5), (0, 5)]] {
        let mut e = ok.entry.clone();
        e.sparse = pieces;
        assert!(fresh(TarFormat::Gnu).begin(&e).is_err());
        assert!(fresh(TarFormat::Pax).begin(&e).is_err());
    }
    // short and long data
    let mut w = fresh(TarFormat::Gnu);
    assert!(w.append(&ok.entry, &mut &[0u8; 10][..]).is_err());
    let mut w = fresh(TarFormat::Gnu);
    w.begin(&ok.entry).unwrap();
    assert!(w.write_data(&[0u8; 101]).is_err());
}

/// Bug group X, X4: GNU tar pads each data segment to whole blocks but counts the stored size unpadded, so a
/// segment before the last one that ends mid-block cannot be laid out; it is refused before any byte is written.
#[test]
fn unaligned_middle_segment_is_refused_before_any_header() {
    for format in [TarFormat::Gnu, TarFormat::Pax] {
        let mut e = sparse(b"s", 8192, &[(0, vec![1; 100]), (4096, vec![2; 100])]).entry;
        e.sparse = vec![(0, 100), (4096, 100)];
        let mut w = TarWriter::new(Vec::new(), TarWriterOptions { format, ..TarWriterOptions::default() });
        assert!(w.begin(&e).is_err(), "{format:?}");
        assert!(w.finish().unwrap().iter().all(|&b| b == 0), "{format:?}: bytes written before the refusal");
        // block-multiple middle segments and an unaligned last one are fine
        e.sparse = vec![(0, 512), (4096, 100)];
        let mut w = TarWriter::new(Vec::new(), TarWriterOptions { format, ..TarWriterOptions::default() });
        w.begin(&e).unwrap();
    }
}
