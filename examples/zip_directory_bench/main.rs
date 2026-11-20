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

//! Opening time and peak allocation for ZIP archives with large central
//! directories, by each reader in the workspace.
//!
//! ```text
//! cargo run --release --example zip_directory_bench -- <work dir> [rounds] [word ...]
//! ```
//!
//! The archives (see `shapes.rs`: 20k and 200k members, short, rich, prefixed
//! and Unicode-named) are written into `<work dir>` once and reused. A `word`
//! keeps only the shapes or readers whose name contains it, such as `200k` or
//! `container`. Each case reports the median and fastest of `rounds` opens
//! (default 5), the size of its central directory, and the peak heap allocation of one open, measured by a
//! counting allocator. The file is read once before timing, so the OS cache is
//! warm. Every reader's result is checked against what the generator wrote
//! before anything is timed.
//!
//! The readers:
//!
//! - `fast`: `zipfast::zip::Archive::open` on the file.
//! - `container`: `zip_container::DirectoryParser` with the Zipfast profile,
//!   fed by positioned reads of the ranges it asks for.
//! - `view-slice`: `zipview::ZipReader::new` on the whole archive in memory;
//!   the archive buffer itself is not counted.
//! - `view-index`: `zipview::ZipIndexOpener` fed by positioned reads.

#[path = "shapes.rs"]
mod shapes;

use std::alloc::{GlobalAlloc, Layout, System};
use std::fs::File;
use std::hint::black_box;
use std::io::BufWriter;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::time::{Duration, Instant};

use shapes::{BENCH_SHAPES, Shape, Written};
use zip_container::{DirectoryParser, Limits, Profile};
use zipfast::zip::Archive;
use zipview::{ZipIndex, ZipIndexOpener, ZipReader};

struct Meter;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grew(bytes: usize) {
    let live = LIVE.fetch_add(bytes, Relaxed) + bytes;
    PEAK.fetch_max(live, Relaxed);
}

// SAFETY: every method forwards to `System` with the caller's layout, and only
// adds bookkeeping that never touches the allocation.
unsafe impl GlobalAlloc for Meter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded unchanged; the caller upholds `alloc`'s contract.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            grew(layout.size());
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded unchanged; the caller upholds `alloc_zeroed`'s contract.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            grew(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarded unchanged; the caller upholds `dealloc`'s contract.
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size(), Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: forwarded unchanged; the caller upholds `realloc`'s contract.
        let moved = unsafe { System.realloc(ptr, layout, new_size) };
        if !moved.is_null() {
            LIVE.fetch_sub(layout.size(), Relaxed);
            grew(new_size);
        }
        moved
    }
}

#[global_allocator]
static METER: Meter = Meter;

/// Heap bytes the call had live at its peak, beyond what was live before it.
fn peak_of<T>(call: impl FnOnce() -> T) -> (T, usize) {
    let base = LIVE.load(Relaxed);
    PEAK.store(base, Relaxed);
    let value = call();
    (value, PEAK.load(Relaxed) - base)
}

#[cfg(unix)]
fn read_at(file: &File, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
    std::os::unix::fs::FileExt::read_exact_at(file, buf, offset)
}

#[cfg(windows)]
fn read_at(file: &File, mut buf: &mut [u8], mut offset: u64) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        let n = file.seek_read(buf, offset)?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        buf = &mut buf[n..];
        offset += n as u64;
    }
    Ok(())
}

/// Writes the shape into `dir` unless a file of the expected length is already there.
fn archive(dir: &Path, shape: &Shape) -> (PathBuf, Written) {
    let path = dir.join(format!("{}.zip", shape.label));
    // Generating into a sink is cheap next to writing, and gives the expectations either way.
    let written = shapes::write(shape, std::io::sink()).expect("sink never fails");
    if std::fs::metadata(&path).ok().map(|m| m.len()) != Some(written.len) {
        let part = dir.join(format!("{}.zip.part", shape.label));
        let file = File::create(&part).expect("create archive");
        shapes::write(shape, BufWriter::new(file)).expect("write archive");
        std::fs::rename(&part, &path).expect("publish archive");
    }
    (path, written)
}

fn open_fast(path: &Path) -> Archive {
    Archive::open(path).expect("zipfast opens the archive")
}

fn open_container(file: &File, len: u64) -> zip_container::Directory {
    let mut parser = DirectoryParser::new(len, Profile::Zipfast, Limits::default()).expect("parser starts");
    let mut buf = Vec::new();
    while let Some(range) = parser.next_read().expect("parser asks for a range") {
        buf.resize(usize::try_from(range.end - range.start).expect("range fits usize"), 0);
        read_at(file, &mut buf, range.start).expect("read range");
        parser.supply(range.start, &buf).expect("parser takes the range");
    }
    parser.finish().expect("parser finishes")
}

fn open_view_index(file: &File, len: u64) -> ZipIndex {
    let mut opener = ZipIndexOpener::new(len);
    let mut buf = Vec::new();
    while let Some(range) = opener.next_read().expect("opener asks for a range") {
        buf.resize(usize::try_from(range.end - range.start).expect("range fits usize"), 0);
        read_at(file, &mut buf, range.start).expect("read range");
        opener.supply(range.start, &buf).expect("opener takes the range");
    }
    opener.finish().expect("opener finishes")
}

/// Checks a reader's names and local offsets against the generator. zipfast
/// names a member by its Unicode Path extra and reports offsets with the prefix
/// added; zipview reports the raw name and the stored offset
/// (docs/zip-parser-parity.md).
fn check<'a>(
    reader: &str,
    shape: &Shape,
    written: &Written,
    entries: impl ExactSizeIterator<Item = (&'a str, u64)>,
    zipfast: bool,
) {
    let physical = zipfast;
    assert_eq!(entries.len(), written.members.len(), "{reader}: member count");
    for (index, ((name, local_at), member)) in entries.zip(&written.members).enumerate() {
        let expected_name = if zipfast { member.name.as_bytes() } else { member.raw_name.as_slice() };
        assert_eq!(name.as_bytes(), expected_name, "{reader}: name of member {index}");
        let expected = member.local_at + if physical { shape.prefix } else { 0 };
        assert_eq!(local_at, expected, "{reader}: local offset of member {index}");
    }
}

fn verify(reader: &str, shape: &Shape, written: &Written, path: &Path, bytes: &[u8]) {
    let file = File::open(path).expect("open archive");
    let len = bytes.len() as u64;
    match reader {
        "fast" => {
            let archive = open_fast(path);
            let entries = archive.entries.iter().map(|e| (e.name.as_str(), e.local_at));
            check(reader, shape, written, entries, true);
            for (entry, member) in archive.entries.iter().zip(&written.members) {
                assert_eq!((entry.crc32, entry.size), (member.crc32, member.payload.len() as u64));
            }
        }
        "container" => {
            let directory = open_container(&file, len);
            assert_eq!(directory.entries.len(), written.members.len(), "container: member count");
            let central =
                written.directory_at + shape.prefix..written.directory_at + shape.prefix + written.directory_len;
            assert_eq!(directory.directory_range, central, "container: directory range");
            for (index, (record, member)) in directory.entries.iter().zip(&written.members).enumerate() {
                assert_eq!(record.raw_name.as_ref(), member.raw_name.as_slice(), "container: name {index}");
                assert_eq!(
                    directory.physical_local_header_offset(index),
                    Some(member.local_at + shape.prefix),
                    "container: offset {index}"
                );
            }
        }
        "view-slice" => {
            let reader_ = ZipReader::new(bytes).expect("zipview reads the archive");
            let entries = reader_.entries().iter().map(|e| (e.name(), e.local_header_offset()));
            check(reader, shape, written, entries, false);
        }
        "view-index" => {
            let index = open_view_index(&file, len);
            let entries = index.entries().iter().map(|e| (e.name(), e.local_header_offset()));
            check(reader, shape, written, entries, false);
        }
        _ => unreachable!(),
    }
}

/// One open by `reader`, returning nothing the optimizer may drop early.
fn open_once(reader: &str, path: &Path, file: &File, bytes: &[u8]) -> usize {
    let len = bytes.len() as u64;
    match reader {
        "fast" => black_box(open_fast(path)).entries.len(),
        "container" => black_box(open_container(file, len)).entries.len(),
        "view-slice" => black_box(ZipReader::new(bytes).expect("zipview reads the archive")).len(),
        "view-index" => black_box(open_view_index(file, len)).len(),
        _ => unreachable!(),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(dir) = args.first().map(PathBuf::from) else {
        eprintln!("usage: zip_directory_bench <work dir> [rounds] [word ...]");
        std::process::exit(2);
    };
    let (rounds, words) = match args.get(1).and_then(|r| r.parse::<usize>().ok()) {
        Some(rounds) => (rounds.max(1), &args[2..]),
        None => (5, &args[1..]),
    };
    std::fs::create_dir_all(&dir).expect("create work dir");
    const READERS: [&str; 4] = ["fast", "container", "view-slice", "view-index"];
    // A word naming part of a reader picks readers; any other word picks shapes.
    let (reader_words, shape_words): (Vec<&String>, Vec<&String>) =
        words.iter().partition(|word| READERS.iter().any(|reader| reader.contains(word.as_str())));
    let keep =
        |words: &[&String], name: &str| words.is_empty() || words.iter().any(|word| name.contains(word.as_str()));
    let readers: Vec<&str> = READERS.into_iter().filter(|reader| keep(&reader_words, reader)).collect();

    println!(
        "{:<20} {:<11} {:>8} {:>8} {:>11} {:>11} {:>9}",
        "shape", "reader", "members", "dir MiB", "median ms", "best ms", "peak MiB"
    );
    for shape in BENCH_SHAPES.iter().filter(|shape| keep(&shape_words, shape.label)) {
        let (path, written) = archive(&dir, shape);
        let bytes = std::fs::read(&path).expect("read archive");
        let file = File::open(&path).expect("open archive");
        for &reader in &readers {
            verify(reader, shape, &written, &path, &bytes);
            let (count, peak) = peak_of(|| open_once(reader, &path, &file, &bytes));
            assert_eq!(count, shape.count);
            let mut times: Vec<Duration> = (0..rounds)
                .map(|_| {
                    let start = Instant::now();
                    black_box(open_once(reader, &path, &file, &bytes));
                    start.elapsed()
                })
                .collect();
            times.sort();
            let ms = |d: Duration| d.as_secs_f64() * 1e3;
            println!(
                "{:<20} {:<11} {:>8} {:>8.2} {:>11.3} {:>11.3} {:>9.2}",
                shape.label,
                reader,
                shape.count,
                written.directory_len as f64 / (1024.0 * 1024.0),
                ms(times[times.len() / 2]),
                ms(times[0]),
                peak as f64 / (1024.0 * 1024.0)
            );
        }
    }
}
