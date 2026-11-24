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

//! Tar listing metadata: owner, ids, device numbers, magic and pax records, as 7-Zip's `l -slt` prints them.
use std::path::Path;

use zipfast::extract::{self, Entry};
use zipfast::tar::TarMagic;

fn list(name: &str) -> Vec<Entry> {
    extract::list(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tar-meta").join(name)).unwrap()
}

#[test]
fn pax_members_carry_owner_times_and_records() {
    for archive in ["pax.tar", "pax.tgz"] {
        let entries = list(archive);
        assert_eq!(entries.len(), 1, "{archive}");
        let e = &entries[0];
        assert_eq!((e.atime, e.ctime), (Some((1_614_834_367, 500_000_000)), Some((1_600_000_000, 250_000_000))));
        let t = e.tar.as_deref().unwrap();
        assert_eq!(t.magic, TarMagic::Ustar);
        assert_eq!(t.typeflag, b'0');
        assert_eq!(
            (t.user.as_deref(), t.group.as_deref(), t.uid, t.gid),
            (Some("builder"), Some("staff"), Some(1234), Some(56))
        );
        assert_eq!((t.device_major, t.device_minor), (None, None));
        assert_eq!(t.pax_header_name.as_deref(), Some("././@PaxHeader"));
        let keys: Vec<_> = t.pax_records.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains(&"atime") && keys.contains(&"ctime"), "{keys:?}");
        assert!(t.pax_records.iter().any(|(k, v)| k == "comment" && v == b"hi"));
        assert_eq!(&t.header.as_ref().unwrap()[257..263], b"ustar\0");
    }
}

#[test]
fn gnu_and_ustar_magic_and_devices() {
    let gnu = list("gnu.tar");
    let t = gnu[0].tar.as_deref().unwrap();
    assert_eq!((t.magic, t.user.as_deref(), t.uid), (TarMagic::Gnu, Some("builder"), Some(1234)));
    assert_eq!((t.pax_header_name.as_deref(), t.pax_records.len()), (None, 0));
    assert_eq!((gnu[0].atime, gnu[0].ctime), (None, None));
    let ustar = list("ustar.tar");
    let dev = ustar.iter().find(|e| e.name == "dev").unwrap().tar.as_deref().unwrap();
    assert_eq!(
        (dev.magic, dev.typeflag, dev.device_major, dev.device_minor),
        (TarMagic::Ustar, b'3', Some(4), Some(7))
    );
}

fn block(name: &str, kind: u8, size: u64) -> [u8; 512] {
    let mut h = [0u8; 512];
    h[..name.len()].copy_from_slice(name.as_bytes());
    let mut octal = |at: usize, width: usize, v: u64| {
        h[at..at + width].copy_from_slice(format!("{v:0w$o}\0", w = width - 1).as_bytes());
    };
    octal(100, 8, 0o644);
    octal(108, 8, 0);
    octal(116, 8, 0);
    octal(124, 12, size);
    octal(136, 12, 0);
    h[156] = kind;
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h[148..156].fill(b' ');
    let sum: u64 = h.iter().map(|&b| u64::from(b)).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    h
}

#[test]
fn pax_records_share_one_budget_across_the_listing() {
    use std::io::Write;
    // 80 members, each with a pax record of almost 1 MiB: 80 MiB of records, past the 64 MiB listing budget.
    let value = "v".repeat((1 << 20) - 64);
    let body = format!(" comment={value}\n");
    let mut n = body.len() + 1;
    while format!("{n}{body}").len() != n {
        n += 1;
    }
    let record = format!("{n}{body}");
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    for i in 0..80 {
        enc.write_all(&block("PaxHeader", b'x', record.len() as u64)).unwrap();
        enc.write_all(record.as_bytes()).unwrap();
        enc.write_all(&vec![0; (512 - record.len() % 512) % 512]).unwrap();
        enc.write_all(&block(&format!("f{i}"), b'0', 0)).unwrap();
    }
    enc.write_all(&[0; 1024]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("many.tgz");
    std::fs::write(&path, enc.finish().unwrap()).unwrap();
    let entries = extract::list(&path).unwrap();
    assert_eq!(entries.len(), 80);
    let meta: Vec<_> = entries.iter().map(|e| e.tar.as_deref().unwrap()).collect();
    let kept = meta.iter().filter(|t| !t.pax_records.is_empty()).count();
    assert!((50..64).contains(&kept), "{kept} members kept their records");
    assert!(meta[..kept].iter().all(|t| !t.pax_records_truncated));
    assert!(meta[kept..].iter().all(|t| t.pax_records_truncated && t.pax_records.is_empty()));
}

/// `gpax.tgz` was written by GNU tar 1.35 (`tar --format=pax --owner=builder:1234 --group=staff:56`). 7-Zip 26.06
/// (`7zz l -slt gpax.tar`, the tar inside) lists `f.txt` with: User = builder, Group = staff, User ID = 1234,
/// Group ID = 56, Characteristics = `0 POSIX ASCII PAX atime ctime`, Comment = `./PaxHeaders/f.txt_`, Created and
/// Accessed with nanoseconds, and empty Device Major and Minor.
#[test]
fn a_gnu_tar_pax_tgz_lists_the_owner_and_records_like_its_tar() {
    let tar = list("gpax.tar");
    let tgz = list("gpax.tgz");
    assert_eq!((tar.len(), tgz.len()), (1, 1));
    for e in [&tar[0], &tgz[0]] {
        assert_eq!(e.name, "f.txt");
        assert!(e.atime.is_some_and(|(_, ns)| ns != 0) && e.ctime.is_some_and(|(_, ns)| ns != 0));
        let t = e.tar.as_deref().unwrap();
        assert_eq!(t.magic, TarMagic::Ustar);
        assert_eq!(t.typeflag, b'0');
        assert_eq!(
            (t.user.as_deref(), t.group.as_deref(), t.uid, t.gid),
            (Some("builder"), Some("staff"), Some(1234), Some(56))
        );
        assert_eq!((t.device_major, t.device_minor), (None, None));
        assert_eq!(t.pax_header_name.as_deref(), Some("./PaxHeaders/f.txt"));
        let keys: Vec<_> = t.pax_records.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains(&"atime") && keys.contains(&"ctime"), "{keys:?}");
    }
    assert_eq!(tar[0].tar, tgz[0].tar);
    assert_eq!((tar[0].atime, tar[0].ctime), (tgz[0].atime, tgz[0].ctime));
}
