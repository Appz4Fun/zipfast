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

//! 7z LZMA2 folders decoded on several threads give what one thread gives: every 7z fixture, and hand-built solid
//! folders of independent LZMA2 blocks (as `7z -mmt` writes them) at many thread counts and budgets, damaged ones
//! and canceled runs. See `docs/7z-extract.md`.
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use liblzma::stream::{Action, Filters, LzmaOptions, Status};
use zipfast::extract::{self, Cancellation, MemberFilter, Mode, Options, Overwrite, StartDecision, Summary};
use zipfast::sevenzip::{self, SevenZipError, SevenZipLimits};

fn opts(mode: Mode, dest: &Path, threads: usize) -> Options {
    Options {
        mode,
        dest: dest.to_path_buf(),
        overwrite: Overwrite::Skip,
        flatten: false,
        threads: Some(threads),
        protected_paths: Default::default(),
        parallel_min: None,
        select: None,
        windows_safe_names: false,
        special_entries: zipfast::extract::SpecialEntries::Refuse,
        fallback_mtime: None,
        compressed_tar: zipfast::extract::CompressedTar::Members,
        version_naming: zipfast::extract::VersionNaming::Semicolon,
    }
}

fn limits(threads: usize, memory: Option<u64>) -> SevenZipLimits {
    let mut limits = SevenZipLimits::default();
    limits.decode_threads = Some(threads);
    if let Some(memory) = memory {
        limits.lzma2_parallel_bytes = memory;
    }
    limits
}

/// Each printed member's listing index and bytes.
type Printed = Vec<(u64, Vec<u8>)>;

/// Everything `print_selected` prints of `archive`, member by member, and the summary; or the run's error.
fn print(archive: &Path, password: Option<&str>, limits: &SevenZipLimits) -> Result<(Printed, Summary), String> {
    let mut members: Printed = Vec::new();
    let summary = sevenzip::print_selected_with(
        archive,
        password,
        &mut |_, _| true,
        &mut |ordinal, bytes| {
            match members.last_mut() {
                Some((o, data)) if *o == ordinal => data.extend_from_slice(bytes),
                _ => members.push((ordinal, bytes.to_vec())),
            }
            Ok(())
        },
        &Cancellation::default(),
        limits,
    );
    summary.map(|s| (members, s)).map_err(|e| e.to_string())
}

fn same_print(archive: &Path, password: Option<&str>, threads: usize, memory: Option<u64>) {
    let one = print(archive, password, &limits(1, None));
    let many = print(archive, password, &limits(threads, memory));
    match (&one, &many) {
        (Ok((a, sa)), Ok((b, sb))) => {
            assert!(a == b, "{}: {threads} threads print other bytes", archive.display());
            assert_eq!((&sa.errors, sa.files, sa.bytes), (&sb.errors, sb.files, sb.bytes), "{}", archive.display());
        }
        _ => assert_eq!(one.err(), many.err(), "{}: {threads} threads", archive.display()),
    }
}

fn tested(archive: &Path, password: Option<&str>, threads: usize) -> Result<(Vec<String>, u64, u64), String> {
    let dir = tempfile::tempdir().unwrap();
    extract::run_with_password(archive, &opts(Mode::Test, dir.path(), threads), password, |_| {})
        .map(|s| (s.errors, s.files, s.bytes))
        .map_err(|e| e.to_string())
}

/// Every 7z fixture prints and tests alike on one thread and on several, with each password the fixtures use.
#[test]
fn every_7z_fixture_decodes_alike_on_several_threads() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut archives: Vec<PathBuf> = Vec::new();
    for dir in ["7z-extract", "7z"] {
        for entry in fs::read_dir(root.join(dir)).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if name.ends_with(".7z") || name.ends_with(".7z.001") {
                archives.push(path);
            }
        }
    }
    archives.sort();
    assert!(archives.len() >= 35, "{} fixtures", archives.len());
    for archive in &archives {
        for password in [None, Some("password"), Some("pw")] {
            for threads in [2, 8] {
                same_print(archive, password, threads, None);
            }
            assert_eq!(tested(archive, password, 1), tested(archive, password, 4), "{}", archive.display());
        }
    }
}

/// Deterministic bytes: text-like (they compress) or noise (LZMA2 stores them).
fn bytes(len: usize, seed: u64, text: bool) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let words = ["seven ", "zip ", "block ", "thread ", "dictionary ", "reset ", "chunk ", "member ", "\n"];
    let mut out = Vec::with_capacity(len + 16);
    while out.len() < len {
        if text {
            out.extend_from_slice(words[(next() % words.len() as u64) as usize].as_bytes());
        } else {
            out.extend_from_slice(&next().to_le_bytes());
        }
    }
    out.truncate(len);
    out
}

/// A raw LZMA2 stream of `data` (1 MiB dictionary, the fastest preset), without its end marker.
fn lzma2_block(data: &[u8]) -> Vec<u8> {
    let mut options = LzmaOptions::new_preset(0).unwrap();
    options.dict_size(1 << 20);
    let mut filters = Filters::new();
    filters.lzma2(&options);
    let mut stream = liblzma::stream::Stream::new_raw_encoder(&filters).unwrap();
    let mut out = Vec::with_capacity(data.len() + (data.len() >> 4) + 4096);
    loop {
        if out.capacity() - out.len() < 4096 {
            out.reserve(1 << 20);
        }
        let at = stream.total_in() as usize;
        if stream.process_vec(&data[at..], &mut out, Action::Finish).unwrap() == Status::StreamEnd {
            break;
        }
    }
    assert_eq!(out.pop(), Some(0));
    out
}

/// `plain` as `7z -mmt` writes it: independent LZMA2 blocks of `block` bytes, ending with an end marker.
fn blocks(plain: &[u8], block: usize) -> Vec<u8> {
    let mut packed: Vec<u8> = plain.chunks(block).flat_map(lzma2_block).collect();
    packed.push(0);
    packed
}

fn num(out: &mut Vec<u8>, value: u64) {
    let bytes = value.to_le_bytes();
    let extra = (0..=8).find(|&n| n == 8 || value < 1u64 << (7 * (n + 1))).unwrap();
    if extra == 8 {
        out.push(0xFF);
        out.extend_from_slice(&bytes);
        return;
    }
    out.push((0xFFu16 << (8 - extra)) as u8 | (value >> (8 * extra)) as u8);
    out.extend_from_slice(&bytes[..extra]);
}

/// A 7z archive of one solid LZMA2 folder (dictionary property 16, 1 MiB) holding `files`, each with its CRC, whose
/// packed stream is `packed`.
fn solid_lzma2(files: &[(String, Vec<u8>)], packed: &[u8]) -> Vec<u8> {
    let total: u64 = files.iter().map(|(_, d)| d.len() as u64).sum();
    let mut h = vec![0x01, 0x04, 0x06, 0x00, 0x01, 0x09];
    num(&mut h, packed.len() as u64);
    // one folder: one LZMA2 coder, property byte 16
    h.extend([0x00, 0x07, 0x0B, 0x01, 0x00, 0x01, 0x21, 0x21, 0x01, 16, 0x0C]);
    num(&mut h, total);
    h.push(0x00);
    // substreams: the files' sizes (all but the last) and all their CRCs
    h.extend([0x08, 0x0D]);
    num(&mut h, files.len() as u64);
    h.push(0x09);
    for (_, data) in &files[..files.len() - 1] {
        num(&mut h, data.len() as u64);
    }
    h.extend([0x0A, 0x01]);
    for (_, data) in files {
        h.extend(crc32fast::hash(data).to_le_bytes());
    }
    h.extend([0x00, 0x00]);
    h.push(0x05);
    num(&mut h, files.len() as u64);
    let mut names = vec![0u8];
    for (name, _) in files {
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

/// Files of every shape for one solid folder: small and large, text and noise.
fn members() -> Vec<(String, Vec<u8>)> {
    [(700_000, true), (3 << 20, true), (10, true), (2_200_000, false), (5 << 20, true), (1_100_000, true)]
        .iter()
        .enumerate()
        .map(|(i, &(len, text))| (format!("m{i}.bin"), bytes(len, i as u64 + 1, text)))
        .collect()
}

fn write(dir: &Path, name: &str, archive: &[u8]) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, archive).unwrap();
    path
}

/// A solid folder of many blocks extracts, tests and prints the same bytes at every thread count and budget.
#[test]
fn a_multi_block_folder_decodes_alike_at_every_thread_count() {
    let dir = tempfile::tempdir().unwrap();
    let files = members();
    let plain: Vec<u8> = files.iter().flat_map(|(_, d)| d.iter().copied()).collect();
    // blocks that straddle the members, joined (small), one per piece, and larger than a small budget
    for block in [300_000, 1_500_000, 4 << 20] {
        let archive = write(dir.path(), &format!("b{block}.7z"), &solid_lzma2(&files, &blocks(&plain, block)));
        for threads in [2, 3, 4, 6, 8, 16] {
            for memory in [None, Some(0), Some(8 << 20)] {
                same_print(&archive, None, threads, memory);
            }
        }
        let printed = print(&archive, None, &limits(5, None)).unwrap();
        assert!(printed.1.errors.is_empty(), "{:?}", printed.1.errors);
        let want: Vec<(u64, Vec<u8>)> = files.iter().enumerate().map(|(i, (_, d))| (i as u64, d.clone())).collect();
        assert!(printed.0 == want, "{block}: printed members");
        for threads in [1, 2, 4, 8] {
            let out = dir.path().join(format!("x{block}-{threads}"));
            let summary = extract::run(&archive, &opts(Mode::Extract, &out, threads), |_| {}).unwrap();
            assert!(summary.errors.is_empty(), "{:?}", summary.errors);
            assert_eq!(summary.files, files.len() as u64);
            for (name, data) in &files {
                assert!(fs::read(out.join(name)).unwrap() == *data, "{block}, {threads} threads: {name}");
            }
        }
    }
}

/// Damage in one block fails the member it lands in, as on one thread, and the run ends without hanging.
#[test]
fn a_damaged_block_fails_the_same_member_as_on_one_thread() {
    let dir = tempfile::tempdir().unwrap();
    let files = members();
    let plain: Vec<u8> = files.iter().flat_map(|(_, d)| d.iter().copied()).collect();
    let block = 1_000_000;
    let good = blocks(&plain, block);
    // where each block starts in the packed stream, and which output it decodes
    let mut starts = Vec::new();
    let mut at = 0;
    for piece in plain.chunks(block) {
        starts.push(at);
        at += lzma2_block(piece).len();
    }
    // m4.bin (5 MiB of text) starts after the first four members and covers blocks 7 to 11
    let m4: usize = files[..4].iter().map(|(_, d)| d.len()).sum();
    let middle = (m4 + (5 << 20) / 2) / block;
    let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();
    let mut flipped = good.clone();
    flipped[(starts[middle] + starts[middle + 1]) / 2] ^= 0x5A;
    cases.push(("payload byte", flipped));
    let mut control = good.clone();
    control[starts[middle]] = 0x05;
    cases.push(("control byte", control));
    let mut cut = good[..starts[middle] + 2000].to_vec();
    cut.push(0);
    cases.push(("cut short", cut));
    for (what, packed) in cases {
        let archive = write(dir.path(), "damaged.7z", &solid_lzma2(&files, &packed));
        let one = tested(&archive, None, 1).unwrap();
        assert!(one.0.iter().any(|e| e.starts_with("m4.bin")), "{what}: {:?}", one.0);
        assert!(!one.0.iter().any(|e| ["m0.bin", "m1.bin", "m2.bin", "m3.bin"].iter().any(|m| e.starts_with(m))));
        for threads in [2, 4, 8] {
            let started = Instant::now();
            assert_eq!(tested(&archive, None, threads).unwrap(), one, "{what}: {threads} threads");
            same_print(&archive, None, threads, None);
            same_print(&archive, None, threads, Some(0));
            assert!(started.elapsed() < Duration::from_secs(60), "{what}: {threads} threads");
        }
    }
}

/// A big multi-block folder canceled part way: the run stops with a cancellation, promptly, on any thread count.
#[test]
fn a_canceled_multi_block_folder_stops_promptly() {
    let dir = tempfile::tempdir().unwrap();
    let files: Vec<(String, Vec<u8>)> =
        (0..12).map(|i| (format!("c{i:02}.bin"), bytes(2 << 20, 50 + i, true))).collect();
    let plain: Vec<u8> = files.iter().flat_map(|(_, d)| d.iter().copied()).collect();
    let archive = write(dir.path(), "big.7z", &solid_lzma2(&files, &blocks(&plain, 1 << 20)));
    for threads in [2, 4, 8] {
        // extracting: canceled as the fourth member starts, a quarter into the folder
        let cancel = Cancellation::default();
        let out = dir.path().join(format!("out{threads}"));
        let mut options = opts(Mode::Extract, &out, threads);
        let (hook, starts) = (cancel.clone(), Arc::new(AtomicUsize::new(0)));
        let counted = starts.clone();
        options.select = Some(MemberFilter::all().on_start(move |_| {
            if counted.fetch_add(1, Ordering::Relaxed) == 3 {
                hook.cancel();
            }
            StartDecision::Write
        }));
        let started = Instant::now();
        let error = sevenzip::run(&archive, &options, None, &cancel, &SevenZipLimits::default(), |_| {}).unwrap_err();
        assert!(matches!(SevenZipError::of(&error), Some(SevenZipError::Canceled)), "{threads}: {error}");
        assert!(started.elapsed() < Duration::from_secs(30), "{threads} threads");
        assert_eq!(starts.load(Ordering::Relaxed), 4, "{threads} threads: no member started after the cancel");
        assert!(!out.join("c03.bin").exists() && !out.join("c11.bin").exists(), "{threads} threads");
        // canceled before the folder starts
        let cancel = Cancellation::default();
        cancel.cancel();
        let error = sevenzip::print_selected(
            &archive,
            None,
            |_, _| true,
            &mut std::io::sink(),
            &cancel,
            &limits(threads, None),
        )
        .unwrap_err();
        assert!(matches!(SevenZipError::of(&error), Some(SevenZipError::Canceled)), "{threads}: {error}");
        // canceled from the sink, part way through the folder
        let cancel = Cancellation::default();
        let mut seen = 0usize;
        let error = sevenzip::print_selected_with(
            &archive,
            None,
            &mut |_, _| true,
            &mut |_, bytes| {
                seen += bytes.len();
                cancel.cancel();
                Ok(())
            },
            &cancel,
            &limits(threads, None),
        )
        .unwrap_err();
        assert!(matches!(SevenZipError::of(&error), Some(SevenZipError::Canceled)), "{threads}: {error}");
        assert!(seen < plain.len(), "{threads} threads printed everything");
    }
}
