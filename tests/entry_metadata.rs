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

//! Listing metadata a 7-Zip or UnRAR style listing needs: which clock an entry's
//! mtime came from, its raw Windows attribute bits, and RAR 4.x volume naming.

mod common;

use std::fs;
use std::io::Write;
use std::path::Path;

use common::{FileSpec, SIG, end_block, file_block, main_block};
use zipfast::crc32::hash;
use zipfast::extract::{self, Entry, MtimeOrigin};
use zipfast::rar5::RarFormat;
use zipfast::rar5::session::{RarSession, RarSessionOptions};

/// 2020-01-02 03:04:06 as MS-DOS date (high half) and time (low half).
const DOS: u32 = (40 << 25) | (1 << 21) | (2 << 16) | (3 << 11) | (4 << 5) | 3;
const DOS_AS_UTC: i64 = 1_577_934_246;
const R: u32 = 0x01;
const H: u32 = 0x02;
const S: u32 = 0x04;
const D: u32 = 0x10;
const A: u32 = 0x20;

fn list(dir: &Path, name: &str, bytes: &[u8]) -> Vec<Entry> {
    let path = dir.join(name);
    fs::write(&path, bytes).unwrap();
    extract::list(&path).unwrap()
}

// ZIP

struct ZipMember<'a> {
    name: &'a str,
    data: &'a [u8],
    host: u8,
    external: u32,
    extra: Vec<u8>,
}

impl<'a> ZipMember<'a> {
    fn new(name: &'a str, data: &'a [u8]) -> Self {
        ZipMember { name, data, host: 0, external: 0, extra: Vec::new() }
    }
}

/// A stored ZIP; each member's extra goes in both its local and central headers.
fn zip(members: &[ZipMember<'_>]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for m in members {
        let offset = out.len() as u32;
        let crc = hash(m.data);
        let common = |out: &mut Vec<u8>| {
            out.extend(0u16.to_le_bytes()); // flags
            out.extend(0u16.to_le_bytes()); // stored
            out.extend((DOS as u16).to_le_bytes());
            out.extend(((DOS >> 16) as u16).to_le_bytes());
            out.extend(crc.to_le_bytes());
            out.extend((m.data.len() as u32).to_le_bytes());
            out.extend((m.data.len() as u32).to_le_bytes());
            out.extend((m.name.len() as u16).to_le_bytes());
            out.extend((m.extra.len() as u16).to_le_bytes());
        };
        out.extend(0x0403_4b50u32.to_le_bytes());
        out.extend(20u16.to_le_bytes());
        common(&mut out);
        out.extend(m.name.as_bytes());
        out.extend(&m.extra);
        out.extend(m.data);

        central.extend(0x0201_4b50u32.to_le_bytes());
        central.extend((u16::from(m.host) << 8 | 20).to_le_bytes());
        central.extend(20u16.to_le_bytes());
        common(&mut central);
        central.extend([0; 6]); // comment length, disk, internal attributes
        central.extend(m.external.to_le_bytes());
        central.extend(offset.to_le_bytes());
        central.extend(m.name.as_bytes());
        central.extend(&m.extra);
    }
    let at = out.len() as u32;
    out.extend(&central);
    out.extend(0x0605_4b50u32.to_le_bytes());
    out.extend([0; 4]);
    out.extend((members.len() as u16).to_le_bytes());
    out.extend((members.len() as u16).to_le_bytes());
    out.extend((central.len() as u32).to_le_bytes());
    out.extend(at.to_le_bytes());
    out.extend([0; 2]);
    out
}

fn ut_extra(mtime: u32) -> Vec<u8> {
    let mut extra = vec![0x55, 0x54, 5, 0, 1];
    extra.extend(mtime.to_le_bytes());
    extra
}

fn ntfs_extra(filetime: u64) -> Vec<u8> {
    let mut extra = vec![0x0a, 0, 32, 0, 0, 0, 0, 0, 1, 0, 24, 0];
    for _ in 0..3 {
        extra.extend(filetime.to_le_bytes());
    }
    extra
}

#[test]
fn zip_mtime_origin_follows_the_field_that_supplied_the_time() {
    let dir = tempfile::tempdir().unwrap();
    let filetime = (1_700_000_000u64 + 11_644_473_600) * 10_000_000 + 5;
    let members = [
        ZipMember::new("dos", b"a"),
        ZipMember { extra: ut_extra(1_600_000_000), ..ZipMember::new("ut", b"b") },
        ZipMember { extra: ntfs_extra(filetime), ..ZipMember::new("ntfs", b"c") },
        // The later of the two time extras wins.
        ZipMember {
            extra: [ntfs_extra(filetime), ut_extra(1_600_000_000)].concat(),
            ..ZipMember::new("ntfs-then-ut", b"d")
        },
    ];
    let entries = list(dir.path(), "times.zip", &zip(&members));
    let times: Vec<_> = entries.iter().map(|e| (e.name.as_str(), e.mtime, e.mtime_origin)).collect();
    assert_eq!(
        times,
        [
            ("dos", Some(zipfast::extract::local_wall_clock_to_utc(DOS_AS_UTC)), Some(MtimeOrigin::LocalWallClock)),
            ("ut", Some(1_600_000_000), Some(MtimeOrigin::Utc)),
            ("ntfs", Some(1_700_000_000), Some(MtimeOrigin::Utc)),
            ("ntfs-then-ut", Some(1_600_000_000), Some(MtimeOrigin::Utc)),
        ]
    );

    // An invalid DOS date and no extra: no time, so no origin.
    let mut bytes = zip(&[ZipMember::new("bad", b"x")]);
    let central = bytes.windows(4).position(|w| w == [0x50, 0x4b, 1, 2]).unwrap();
    bytes[central + 14..central + 16].copy_from_slice(&0u16.to_le_bytes());
    let entry = &list(dir.path(), "bad.zip", &bytes)[0];
    assert_eq!((entry.mtime, entry.mtime_origin), (None, None));
}

#[test]
fn zip_windows_attributes_come_from_dos_hosts_only() {
    let dir = tempfile::tempdir().unwrap();
    let members = [
        ZipMember { host: 0, external: R | H | S | A, ..ZipMember::new("fat", b"a") },
        ZipMember { host: 0, external: D | H, ..ZipMember::new("fatdir/", b"") },
        ZipMember { host: 10, external: 0x8000_0000 | 0x2000 | A, ..ZipMember::new("ntfs", b"b") },
        ZipMember { host: 14, external: R, ..ZipMember::new("vfat", b"c") },
        ZipMember { host: 3, external: (0o100644 << 16) | A, ..ZipMember::new("unix", b"d") },
        ZipMember { host: 19, external: 0o100644 << 16, ..ZipMember::new("osx", b"e") },
    ];
    let entries = list(dir.path(), "attrs.zip", &zip(&members));
    let attrs: Vec<_> = entries.iter().map(|e| (e.name.as_str(), e.attributes, e.mode)).collect();
    assert_eq!(
        attrs,
        [
            ("fat", Some(R | H | S | A), None),
            ("fatdir/", Some(D | H), None),
            ("ntfs", Some(0x2000 | A), None),
            ("vfat", Some(R), None),
            ("unix", None, Some(0o100644)),
            ("osx", None, None),
        ]
    );
    assert!(entries[1].dir);
}

// RAR 5.0

#[test]
fn rar5_times_are_utc_and_windows_hosts_carry_attributes() {
    let dir = tempfile::tempdir().unwrap();
    let windows = FileSpec { unix_mode: None, ..FileSpec::new("windows", b"a") };
    let unix = FileSpec { unix_mode: Some(0o100640), ..FileSpec::new("unix", b"b") };
    let untimed = FileSpec { mtime: None, ..FileSpec::new("untimed", b"c") };
    let entries = list(dir.path(), "meta.rar", &common::archive(&[windows, unix, untimed]));
    let got: Vec<_> = entries.iter().map(|e| (e.name.as_str(), e.mtime_origin, e.attributes, e.mode)).collect();
    assert_eq!(
        got,
        [
            // The builder's Windows host stores FILE_ATTRIBUTE_ARCHIVE.
            ("windows", Some(MtimeOrigin::Utc), Some(A), None),
            ("unix", Some(MtimeOrigin::Utc), None, Some(0o100640)),
            ("untimed", None, None, Some(0o644)),
        ]
    );
    assert_eq!(entries[0].mtime, Some(1_700_000_000));
}

#[test]
fn rar5_volumes_always_use_new_numbering() {
    let dir = tempfile::tempdir().unwrap();
    let data = vec![7u8; 100];
    for (i, volume) in common::volumes(&FileSpec::new("f", &data), 40).iter().enumerate() {
        fs::write(dir.path().join(format!("set.part{}.rar", i + 1)), volume).unwrap();
    }
    let session = RarSession::open(&dir.path().join("set.part1.rar"), None, RarSessionOptions::default()).unwrap();
    assert_eq!(session.volumes().len(), 3);
    for volume in session.volumes() {
        assert_eq!(volume.format(), RarFormat::Rar5);
        assert!(volume.new_numbering());
        assert_eq!(volume.rar4_flags(), None);
    }
    // A lone archive, too.
    let mut single = SIG.to_vec();
    single.extend(main_block(false, None));
    single.extend(file_block(&FileSpec::new("g", b"g"), b"g", hash(b"g"), false, false));
    single.extend(end_block(false));
    let path = dir.path().join("single.rar");
    fs::write(&path, single).unwrap();
    let session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    assert!(session.volumes().next().unwrap().new_numbering());
}

// RAR 4.x

fn r4_block(kind: u8, flags: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0, 0, kind];
    bytes.extend(flags.to_le_bytes());
    bytes.extend(((body.len() + 7) as u16).to_le_bytes());
    bytes.extend(body);
    let crc = hash(&bytes[2..]) as u16;
    bytes[..2].copy_from_slice(&crc.to_le_bytes());
    bytes
}

/// A stored RAR 4.x member. `ext_time` appends an extended-time record for the mtime.
fn r4_member(name: &str, data: &[u8], host: u8, attributes: u32, ext_time: Option<&[u8]>) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend((data.len() as u32).to_le_bytes());
    body.extend((data.len() as u32).to_le_bytes());
    body.push(host);
    body.extend(hash(data).to_le_bytes());
    body.extend(DOS.to_le_bytes());
    body.extend([20, 0x30]);
    body.extend((name.len() as u16).to_le_bytes());
    body.extend(attributes.to_le_bytes());
    body.extend(name.as_bytes());
    let mut flags = 0x8000;
    if let Some(record) = ext_time {
        flags |= 0x1000;
        body.extend(record);
    }
    let mut bytes = r4_block(0x74, flags, &body);
    bytes.extend(data);
    bytes
}

fn r4_archive(main_flags: u16, more: bool, members: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = b"Rar!\x1a\x07\0".to_vec();
    bytes.extend(r4_block(0x73, main_flags, &[0; 6]));
    for member in members {
        bytes.extend(member);
    }
    bytes.extend(r4_block(0x7b, 0x4000 | u16::from(more), &[]));
    bytes
}

#[test]
fn rar4_times_are_local_wall_clock_even_with_extended_time() {
    let dir = tempfile::tempdir().unwrap();
    // mtime present (8), one more second (4), two bytes of 100 ns fraction.
    let ext = [0x00, 0xe2, 0x34, 0x12];
    let members = [r4_member("plain", b"a", 2, A, None), r4_member("precise", b"b", 2, A, Some(&ext))];
    let entries = list(dir.path(), "times.rar", &r4_archive(0, false, &members));
    assert_eq!(entries[0].mtime, Some(zipfast::extract::local_wall_clock_to_utc(DOS_AS_UTC)));
    assert_eq!(entries[0].mtime_origin, Some(MtimeOrigin::LocalWallClock));
    assert_eq!(entries[1].mtime, Some(zipfast::extract::local_wall_clock_to_utc(DOS_AS_UTC) + 1));
    assert_eq!(entries[1].mtime_origin, Some(MtimeOrigin::LocalWallClock));
}

#[test]
fn rar4_windows_hosts_carry_attributes_and_unix_hosts_a_mode() {
    let dir = tempfile::tempdir().unwrap();
    let members = [
        r4_member("msdos", b"a", 0, R | H | S | A, None),
        r4_member("os2", b"b", 1, H, None),
        r4_member("win32", b"c", 2, R | A, None),
        r4_member("unix", b"d", 3, 0o100600, None),
    ];
    let entries = list(dir.path(), "attrs.rar", &r4_archive(0, false, &members));
    let got: Vec<_> = entries.iter().map(|e| (e.name.as_str(), e.attributes, e.mode)).collect();
    assert_eq!(
        got,
        [
            ("msdos", Some(R | H | S | A), None),
            ("os2", Some(H), None),
            ("win32", Some(R | A), None),
            ("unix", None, Some(0o100600)),
        ]
    );
}

#[test]
fn rar4_new_numbering_comes_from_the_main_header() {
    // WinRAR's `NAME.partN.rar` set (MHD_VOLUME | MHD_NEWNUMBERING, plus MHD_FIRSTVOLUME on the first).
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rar4-volumes");
    let session = RarSession::open(&fixtures.join("multi.part1.rar"), None, RarSessionOptions::default()).unwrap();
    let volumes: Vec<_> = session.volumes().collect();
    assert_eq!(volumes.len(), 3);
    for (i, volume) in volumes.iter().enumerate() {
        assert_eq!(volume.format(), RarFormat::Rar4);
        assert!(volume.new_numbering(), "volume {i}");
        // The normalized flags keep only the volume bit; the raw flags keep the rest.
        assert_eq!(volume.flags(), 1);
        assert_eq!(volume.rar4_flags(), Some(if i == 0 { 0x0111 } else { 0x0011 }));
    }

    // An old-style `NAME.rar`, `NAME.r00`, `NAME.r01` set: MHD_VOLUME without MHD_NEWNUMBERING.
    let dir = tempfile::tempdir().unwrap();
    for (i, name) in ["old.rar", "old.r00", "old.r01"].into_iter().enumerate() {
        let member = r4_member(&format!("f{i}"), b"data", 2, A, None);
        let main = 0x0001 | if i == 0 { 0x0100 } else { 0 };
        fs::write(dir.path().join(name), r4_archive(main, i < 2, &[member])).unwrap();
    }
    let session = RarSession::open(&dir.path().join("old.rar"), None, RarSessionOptions::default()).unwrap();
    let volumes: Vec<_> = session.volumes().collect();
    assert_eq!(volumes.len(), 3);
    for (i, volume) in volumes.iter().enumerate() {
        assert!(!volume.new_numbering(), "volume {i}");
        assert_eq!(volume.rar4_flags(), Some(if i == 0 { 0x0101 } else { 0x0001 }));
    }
}

// tar and gzip

fn tar_header(name: &str, size: usize, mtime: u64) -> [u8; 512] {
    let mut h = [0u8; 512];
    h[..name.len()].copy_from_slice(name.as_bytes());
    let mut octal = |at: usize, width: usize, value: u64| {
        h[at..at + width].copy_from_slice(format!("{value:0w$o}\0", w = width - 1).as_bytes());
    };
    octal(100, 8, 0o644);
    octal(108, 8, 0);
    octal(116, 8, 0);
    octal(124, 12, size as u64);
    octal(136, 12, mtime);
    h[156] = b'0';
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h[148..156].fill(b' ');
    let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    h
}

#[test]
fn tar_and_gzip_times_are_utc() {
    let dir = tempfile::tempdir().unwrap();
    let mut tar = tar_header("t", 2, 1_650_000_000).to_vec();
    tar.extend(b"hi");
    tar.resize(1024 + 1024, 0);
    let entry = &list(dir.path(), "a.tar", &tar)[0];
    assert_eq!(
        (entry.mtime, entry.mtime_origin, entry.attributes),
        (Some(1_650_000_000), Some(MtimeOrigin::Utc), None)
    );

    let gzip = |mtime: u32| {
        let mut encoder = flate2::GzBuilder::new().mtime(mtime).write(Vec::new(), flate2::Compression::fast());
        encoder.write_all(b"payload").unwrap();
        encoder.finish().unwrap()
    };
    let entry = &list(dir.path(), "p.gz", &gzip(1_234_567_890))[0];
    assert_eq!(
        (entry.mtime, entry.mtime_origin, entry.attributes),
        (Some(1_234_567_890), Some(MtimeOrigin::Utc), None)
    );
    // MTIME 0 means no time was recorded.
    let entry = &list(dir.path(), "q.gz", &gzip(0))[0];
    assert_eq!((entry.mtime, entry.mtime_origin), (None, None));
}
