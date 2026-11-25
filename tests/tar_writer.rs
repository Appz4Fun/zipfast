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

//! The tar writer against archives GNU tar 1.35 wrote (tests/fixtures/tar-writer, made by make-reference.sh over
//! the tree rebuilt here from explicit metadata), and a round trip through zipfast's own tar reader.

use zipfast::tar::write::{IdOverride, TarEntry, TarEntryKind as K, TarFormat, TarWriter, TarWriterOptions};

fn rep(c: u8, n: usize) -> Vec<u8> {
    vec![c; n]
}

fn join(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

struct Item {
    entry: TarEntry,
    data: Vec<u8>,
}

fn item(path: &[u8], kind: K, mode: u32, mtime: i64, data: &[u8]) -> Item {
    let mut e = TarEntry::new(path, kind);
    e.mode = mode;
    e.mtime = mtime;
    e.uname = b"root".to_vec();
    e.gname = b"root".to_vec();
    e.size = data.len() as u64;
    Item { entry: e, data: data.to_vec() }
}

fn owned(mut i: Item, uid: u64, gid: u64, uname: &[u8], gname: &[u8]) -> Item {
    i.entry.uid = uid;
    i.entry.gid = gid;
    i.entry.uname = uname.to_vec();
    i.entry.gname = gname.to_vec();
    i
}

fn link(path: &[u8], kind: K, target: &[u8], mode: u32, mtime: i64) -> Item {
    let mut i = item(path, kind, mode, mtime, b"");
    i.entry.link = target.to_vec();
    i
}

const T: i64 = 1_700_000_000;

/// Every member of the full tree, in the archive order of make-reference.sh.
fn tree() -> Vec<Item> {
    let a = rep(b'a', 100);
    let a1 = join(&[&a, b"b"]);
    let c100 = rep(b'c', 100);
    let c60 = rep(b'e', 60);
    let t150 = rep(b't', 150);
    let h110 = rep(b'h', 110);
    let p60 = rep(b'p', 60);
    let q60 = rep(b'q', 60);
    let uni = join(&["uni/\u{fc}n\u{ef}-\u{65e5}\u{672c}.txt".as_bytes()]);
    let short = || owned(item(b"d/short.txt", K::File, 0o644, T, b"hello\n"), 1, 1, b"daemon", b"daemon");
    let deep = join(&[&c100, b"/", &c100, b"/", &c60]);
    let mut v = vec![item(b"d", K::Dir, 0o755, T, b"")];
    v.push(short());
    v.push(owned(link(b"hl", K::HardLink, b"d/short.txt", 0o644, T), 1, 1, b"daemon", b"daemon"));
    v.push(item(&a, K::File, 0o644, T + 123, b"x"));
    v.push(link(&join(&[b"hl-", &h110]), K::HardLink, &a, 0o644, T + 123));
    let mut big = owned(item(&a1, K::File, 0o644, T, b"y"), 3_000_000, 2, b"", b"bin");
    big.entry.mtime_nanos = 500_000_000;
    v.push(big);
    v.push(item(&c100, K::Dir, 0o755, T, b""));
    v.push(item(&join(&[&c100, b"/", &c100]), K::Dir, 0o755, T, b""));
    v.push(item(&deep, K::Dir, 0o755, T, b""));
    v.push(item(&join(&[&deep, b"/file.bin"]), K::File, 0o644, T, b"deep\n"));
    v.push(item(b"uni", K::Dir, 0o755, T, b""));
    v.push(item(&uni, K::File, 0o644, T, b"u\n"));
    v.push(link(b"link", K::Symlink, b"d/short.txt", 0o777, T));
    v.push(link(b"longlink", K::Symlink, &t150, 0o777, T));
    v.push(item(b"empty", K::File, 0o4755, T, b""));
    v.push(item(b"pipe", K::Fifo, 0o644, T, b""));
    let mut null = item(b"null", K::CharDevice, 0o644, T, b"");
    null.entry.dev_major = 1;
    null.entry.dev_minor = 3;
    v.push(null);
    let mut blk = item(b"blk", K::BlockDevice, 0o644, T, b"");
    blk.entry.dev_major = 7;
    v.push(blk);
    v.push(item(b"bigtime", K::File, 0o644, 9_000_000_000, b"big\n"));
    v.push(owned(item(b"bigid", K::File, 0o644, T, b"bigid\n"), 3_000_000, 2, b"", b"bin"));
    let mut frac = item(b"frac", K::File, 0o644, T, b"frac\n");
    frac.entry.mtime_nanos = 123_456_789;
    v.push(frac);
    v.push(item(&p60, K::Dir, 0o755, T, b""));
    v.push(item(&join(&[&p60, b"/", &q60]), K::Dir, 0o755, T, b""));
    v.push(item(&join(&[&p60, b"/", &q60, b"/r.txt"]), K::File, 0o644, T, b"split\n"));
    v.push(link(&join(&[b"both-", &h110]), K::Symlink, &t150, 0o777, T));
    v
}

fn write(items: &[Item], opts: TarWriterOptions) -> Vec<u8> {
    let mut w = TarWriter::new(Vec::new(), opts);
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

fn opts(format: TarFormat) -> TarWriterOptions {
    TarWriterOptions { format, ..TarWriterOptions::default() }
}

#[test]
fn gnu_default_is_byte_exact() {
    let got = write(&tree(), opts(TarFormat::Gnu));
    assert_same(&got, include_bytes!("fixtures/tar-writer/gnu.tar"), "gnu.tar");
}

#[test]
fn gnu_numeric_owner_is_byte_exact() {
    let o = TarWriterOptions { numeric_owner: true, ..opts(TarFormat::Gnu) };
    assert_same(&write(&tree(), o), include_bytes!("fixtures/tar-writer/gnu-numeric.tar"), "gnu-numeric.tar");
}

#[test]
fn gnu_owner_group_mtime_overrides_are_byte_exact() {
    let o = TarWriterOptions {
        owner: Some(IdOverride { id: 1001, name: b"alice".to_vec() }),
        group: Some(IdOverride { id: 50, name: b"staff".to_vec() }),
        mtime: Some(1_600_000_000),
        ..opts(TarFormat::Gnu)
    };
    assert_same(&write(&tree(), o), include_bytes!("fixtures/tar-writer/gnu-override.tar"), "gnu-override.tar");
}

#[test]
fn pax_is_byte_exact() {
    assert_same(&write(&tree(), opts(TarFormat::Pax)), include_bytes!("fixtures/tar-writer/pax.tar"), "pax.tar");
}

#[test]
fn ustar_is_byte_exact() {
    let keep = [
        &b"d"[..],
        b"d/short.txt",
        b"hl",
        b"link",
        b"empty",
        b"pipe",
        b"null",
        b"blk",
        b"frac",
        &rep(b'p', 60),
        &join(&[&rep(b'p', 60), b"/", &rep(b'q', 60), b"/r.txt"]),
    ];
    let items: Vec<Item> = tree().into_iter().filter(|i| keep.contains(&i.entry.path.as_slice())).collect();
    assert_eq!(items.len(), keep.len());
    assert_same(&write(&items, opts(TarFormat::Ustar)), include_bytes!("fixtures/tar-writer/ustar.tar"), "ustar.tar");
}

#[test]
fn ustar_refuses_what_does_not_fit() {
    let mut w = TarWriter::new(Vec::new(), opts(TarFormat::Ustar));
    let long = item(&rep(b'x', 101), K::File, 0o644, T, b"");
    assert!(w.begin(&long.entry).is_err());
    let big = owned(item(b"f", K::File, 0o644, T, b""), 3_000_000, 0, b"", b"");
    assert!(w.begin(&big.entry).is_err());
}

#[test]
fn blocking_factor_pads_to_records() {
    let o = TarWriterOptions { blocking_factor: 1, ..opts(TarFormat::Gnu) };
    let out = write(&[item(b"f", K::File, 0o644, T, b"abc")], o);
    assert_eq!(out.len(), 512 * 4);
    let out = write(&[item(b"f", K::File, 0o644, T, b"abc")], opts(TarFormat::Gnu));
    assert_eq!(out.len(), 10240);
}

#[test]
fn short_data_and_bad_sparse_are_errors() {
    let mut w = TarWriter::new(Vec::new(), opts(TarFormat::Gnu));
    let mut e = TarEntry::new(&b"f"[..], K::File);
    e.size = 10;
    assert!(w.append(&e, &mut &b"abc"[..]).is_err());
    // a sparse member needs a map no wider than its apparent size (an empty one over size 0 is a valid hole)
    let mut w = TarWriter::new(Vec::new(), opts(TarFormat::Gnu));
    let mut e = TarEntry::new(&b"s"[..], K::Sparse);
    e.sparse = vec![(0, 1)];
    assert!(w.begin(&e).is_err());
}

#[test]
fn round_trips_through_the_tar_reader() {
    let dir = tempfile::tempdir().unwrap();
    for format in [TarFormat::Gnu, TarFormat::Pax] {
        let path = dir.path().join("rt.tar");
        std::fs::write(&path, write(&tree(), opts(format))).unwrap();
        let listed = zipfast::tar::list(&path).unwrap();
        let items = tree();
        assert_eq!(listed.len(), items.len(), "{format:?}");
        for (got, want) in listed.iter().zip(&items) {
            let name = String::from_utf8(want.entry.path.clone()).unwrap();
            assert_eq!(got.name.trim_end_matches('/'), name, "{format:?}");
            if want.entry.kind == K::File {
                assert_eq!(got.size, want.data.len() as u64, "{name}");
            }
        }
    }
}

/// Bug group X, X1: a pre-epoch fractional time is written as GNU tar writes it (`mtime=-0.5` for half a second
/// before the epoch, which GNU tar 1.35 produced for `touch -d @-0.5`) and reads back as the same instant.
#[test]
fn negative_fractional_pax_time_is_the_signed_decimal() {
    for (secs, nanos, text) in [
        (-1i64, 500_000_000u32, "mtime=-0.5\n"),
        (-2, 500_000_000, "mtime=-1.5\n"),
        (-1, 250_000_000, "mtime=-0.75\n"),
        (-3, 0, "mtime=-3\n"),
    ] {
        let mut e = TarEntry::new(b"f", K::File);
        e.mtime = secs;
        e.mtime_nanos = nanos;
        e.size = 2;
        let mut w = TarWriter::new(Vec::new(), opts(TarFormat::Pax));
        w.append(&e, &mut &b"hi"[..]).unwrap();
        let tar = w.finish().unwrap();
        let hay = String::from_utf8_lossy(&tar[512..1024]).into_owned();
        assert!(hay.contains(text), "{secs}.{nanos}: {hay:?}");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.tar");
        std::fs::write(&path, &tar).unwrap();
        let out = dir.path().join("out");
        std::fs::create_dir(&out).unwrap();
        let o = zipfast::extract::Options {
            mode: zipfast::extract::Mode::Extract,
            dest: out.clone(),
            overwrite: zipfast::extract::Overwrite::Skip,
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
        };
        zipfast::extract::run(&path, &o, |_| {}).unwrap();
        let m = std::fs::metadata(out.join("f")).unwrap().modified().unwrap();
        let want = if secs < 0 && nanos != 0 {
            std::time::UNIX_EPOCH - std::time::Duration::new((-(secs + 1)) as u64, 1_000_000_000 - nanos)
        } else {
            std::time::UNIX_EPOCH - std::time::Duration::new(secs.unsigned_abs(), 0)
        };
        assert_eq!(m, want, "{secs}.{nanos}");
    }
}

/// Bug group X, X2: an eight-byte base-256 field keeps its high bits next to the marker; what does not fit is refused.
#[test]
fn eight_byte_base256_ids_keep_their_high_bits() {
    let id_field = |uid: u64| -> Result<[u8; 8], zipfast::error::Error> {
        let mut e = TarEntry::new(b"f", K::File);
        e.uid = uid;
        let mut w = TarWriter::new(Vec::new(), opts(TarFormat::Gnu));
        w.begin(&e)?;
        w.write_data(&[])?;
        let tar = w.finish()?;
        Ok(tar[108..116].try_into().unwrap())
    };
    assert_eq!(id_field(1 << 56).unwrap(), [0x81, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(id_field((1 << 62) - 1).unwrap(), [0xbf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    assert!(id_field(1 << 62).is_err());
    assert!(id_field((1 << 63) - 1).is_err());
    assert_eq!(id_field(0x0123_4567_89ab_cdef).unwrap(), [0x81, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
    assert!(id_field(1 << 63).is_err());
    assert!(id_field(u64::MAX).is_err());
}

/// Bug group X, X3: a reader that reports `Interrupted` once does not fail the member.
#[test]
fn append_retries_an_interrupted_reader() {
    struct Flaky(Vec<u8>, bool);
    impl std::io::Read for Flaky {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if !self.1 {
                self.1 = true;
                return Err(std::io::ErrorKind::Interrupted.into());
            }
            let n = buf.len().min(self.0.len());
            buf[..n].copy_from_slice(&self.0[..n]);
            self.0.drain(..n);
            Ok(n)
        }
    }
    let mut e = TarEntry::new(b"f", K::File);
    e.size = 5;
    let mut w = TarWriter::new(Vec::new(), opts(TarFormat::Gnu));
    w.append(&e, &mut Flaky(b"hello".to_vec(), false)).unwrap();
    let tar = w.finish().unwrap();
    assert_eq!(&tar[512..517], b"hello");
}
