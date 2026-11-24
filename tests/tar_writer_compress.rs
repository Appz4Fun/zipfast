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

//! Compressed tar output: each compressor's stream decompresses (system tool, when installed) to the exact GNU
//! tar bytes of the B1a fixture, and zipfast's own tar reader lists it.

use std::io::Write;
use std::process::{Command, Stdio};

use zipfast::tar::write::{CompressedWriter, Compression};

const TAR: &[u8] = include_bytes!("fixtures/tar-writer/gnu.tar");

fn compress(c: Compression, chunk: usize) -> Vec<u8> {
    let mut w = CompressedWriter::new(Vec::new(), c).unwrap();
    for part in TAR.chunks(chunk) {
        w.write_all(part).unwrap();
    }
    w.finish().unwrap()
}

fn system_decode(tool: &str, args: &[&str], data: &[u8]) -> Option<Vec<u8>> {
    let mut child = Command::new(tool).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().ok()?;
    let mut stdin = child.stdin.take().unwrap();
    let data = data.to_vec();
    let t = std::thread::spawn(move || {
        let _ = stdin.write_all(&data);
    });
    let out = child.wait_with_output().unwrap();
    t.join().unwrap();
    assert!(out.status.success(), "{tool} failed");
    Some(out.stdout)
}

fn check(name: &str, c: Compression, tool: &str, args: &[&str], ext: &str) {
    for chunk in [512, 7, TAR.len()] {
        let z = compress(c, chunk);
        assert!(z.len() < TAR.len() || matches!(c, Compression::Gzip { level: 0 }), "{name} did not compress");
        match system_decode(tool, args, &z) {
            Some(out) => assert!(out == TAR, "{name}: {tool} output differs from the tar"),
            None => eprintln!("{tool} not installed; system check skipped"),
        }
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(format!("t.tar.{ext}"));
        std::fs::write(&p, &z).unwrap();
        let listed = zipfast::tar::list(&p).unwrap();
        assert_eq!(listed.len(), 25, "{name}: own reader");
    }
}

#[test]
fn gzip_round_trips() {
    for level in [0, 1, 6, 9] {
        check("gzip", Compression::Gzip { level }, "gzip", &["-dc"], "gz");
    }
}

#[test]
fn bzip2_round_trips() {
    for level in [1, 9] {
        check("bzip2", Compression::Bzip2 { level }, "bzip2", &["-dc"], "bz2");
    }
}

#[test]
fn xz_round_trips() {
    for level in [0, 6, 9] {
        check("xz", Compression::Xz { level }, "xz", &["-dc"], "xz");
    }
}

#[test]
fn zstd_round_trips() {
    for level in [1, 3, 19] {
        check("zstd", Compression::Zstd { level }, "zstd", &["-dc"], "zst");
    }
}

#[test]
fn none_is_passthrough() {
    assert!(compress(Compression::None, 100) == TAR);
}

#[test]
fn bad_levels_are_refused() {
    for c in [
        Compression::Gzip { level: 10 },
        Compression::Bzip2 { level: 0 },
        Compression::Xz { level: 10 },
        Compression::Zstd { level: 0 },
    ] {
        assert!(CompressedWriter::new(Vec::new(), c).is_err(), "{c:?}");
    }
}

#[test]
fn gzip_header_is_what_gnu_gzip_writes_for_a_pipe() {
    let z = compress(Compression::Gzip { level: 6 }, 4096);
    assert_eq!(&z[..10], &[0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3]);
    let z = compress(Compression::Gzip { level: 9 }, 4096);
    assert_eq!(z[8], 2);
}

#[test]
fn tar_writer_streams_into_compressor() {
    use zipfast::tar::write::{TarEntry, TarEntryKind, TarWriter, TarWriterOptions};
    let sink = CompressedWriter::new(Vec::new(), Compression::Zstd { level: 3 }).unwrap();
    let mut w = TarWriter::new(sink, TarWriterOptions::default());
    let mut e = TarEntry::new(&b"f"[..], TarEntryKind::File);
    e.size = 3;
    w.append(&e, &mut &b"abc"[..]).unwrap();
    let z = w.finish().unwrap().finish().unwrap();
    if let Some(out) = system_decode("zstd", &["-dc"], &z) {
        assert_eq!(out.len(), 10240);
        assert_eq!(&out[512..515], b"abc");
    }
}

#[test]
fn gzip_header_and_trailer_match_gnu_gzip_reference() {
    let refs: [(u32, &[u8]); 3] = [
        (1, include_bytes!("fixtures/tar-writer/gnu.tar.1.gz")),
        (6, include_bytes!("fixtures/tar-writer/gnu.tar.6.gz")),
        (9, include_bytes!("fixtures/tar-writer/gnu.tar.9.gz")),
    ];
    for (level, want) in refs {
        let got = compress(Compression::Gzip { level }, 10240);
        eprintln!("level {level}: ours {} bytes, gzip 1.13 {} bytes, identical {}", got.len(), want.len(), got == want);
        assert_eq!(&got[..10], &want[..10], "level {level}: header");
        assert_eq!(&got[got.len() - 8..], &want[want.len() - 8..], "level {level}: crc and size trailer");
    }
}
