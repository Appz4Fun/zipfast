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

mod common;
#[allow(dead_code)]
#[path = "common/zip_parity_fixture.rs"]
mod zip_fixture;

use common::*;
use std::{
    cell::{Cell, RefCell},
    fs,
    io::Write,
    path::{Path, PathBuf},
};
use zipfast::extract::{self, Cancellation, SelectedEntry, SelectedReadRole as Role};
use zipfast::rar5::Redirection;
use zipfast::rar5::testenc::{self, Op};
use zipfast::{Error, Result};

// These entrypoint tests catch lost mode projection and changed list ordering/classification.
#[test]
fn rar_listing_modes_preserve_order_directory_link_and_unknown_host() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("metadata.rar");
    let members = [
        FileSpec { unix_mode: Some(0o640), ..FileSpec::new("same", b"abc") },
        FileSpec { dir: true, unix_mode: Some(0o750), ..FileSpec::new("folder", b"") },
        FileSpec { unix_mode: None, ..FileSpec::new("same", b"def") },
        FileSpec { extra: vec![5, 5, 1, 0, 1, b'x'], unix_mode: Some(0o777), ..FileSpec::new("link", b"") },
    ];
    fs::write(&path, archive(&members)).unwrap();
    let listed = extract::list(&path).unwrap();
    assert_eq!(listed.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), ["same", "folder", "same", "link"]);
    assert_eq!(listed.iter().map(|e| e.mode).collect::<Vec<_>>(), [Some(0o640), Some(0o750), None, Some(0o777)]);
    assert_eq!(
        listed.iter().map(|e| (e.size, e.dir, e.mtime)).collect::<Vec<_>>(),
        [
            (3, false, Some(1_700_000_000)),
            (0, true, Some(1_700_000_000)),
            (3, false, Some(1_700_000_000)),
            (0, false, Some(1_700_000_000))
        ]
    );
    assert!(matches!(&listed[3].link, Some(Redirection::UnixSymlink(target)) if target == "x"));
    assert_eq!(SelectedEntry::open(&path, 0, None, 64).unwrap().unix_mode(), Some(0o640));
    assert_eq!(SelectedEntry::open(&path, 2, None, 64).unwrap().unix_mode(), None);
}

fn zip_bytes() -> Vec<u8> {
    use zip_fixture::Member;
    zip_fixture::build(
        &[
            Member { external: 0o100640 << 16, ..Member::stored(b"same", b"abc") },
            Member { external: 0o40750 << 16, ..Member::stored(b"folder/", b"") },
            Member { made_by: 20, external: 0x20, ..Member::stored(b"same", b"def") },
            Member { external: 0o120777 << 16, ..Member::stored(b"link", b"same") },
        ],
        &[0, 1, 2, 3],
        b"",
        b"",
        false,
    )
    .bytes
}

#[test]
fn zip_listing_modes_preserve_order_directory_link_and_unknown_host() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("metadata.zip");
    fs::write(&path, zip_bytes()).unwrap();
    let listed = extract::list(&path).unwrap();
    assert_eq!(listed.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), ["same", "folder/", "same", "link"]);
    assert_eq!(
        listed.iter().map(|e| e.mode).collect::<Vec<_>>(),
        [Some(0o100640), Some(0o40750), None, Some(0o120777)]
    );
    assert_eq!(
        listed.iter().map(|e| (e.size, e.dir)).collect::<Vec<_>>(),
        [(3, false), (0, true), (3, false), (4, false)]
    );
    assert!(matches!(&listed[3].link, Some(Redirection::UnixSymlink(_))));
    assert_eq!(SelectedEntry::open(&path, 0, None, 64).unwrap().unix_mode(), Some(0o100640));
    assert_eq!(SelectedEntry::open(&path, 2, None, 64).unwrap().unix_mode(), None);
}

fn tar_bytes() -> Vec<u8> {
    let mut out = Vec::new();
    for (name, kind, mode, data, link) in [
        ("same", b'0', 0o640, b"abc".as_slice(), ""),
        ("folder/", b'5', 0o750, b"".as_slice(), ""),
        ("link", b'2', 0o777, b"".as_slice(), "same"),
    ] {
        let mut h = [0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        h[100..108].copy_from_slice(format!("{mode:07o}\0").as_bytes());
        h[124..136].copy_from_slice(format!("{:011o}\0", data.len()).as_bytes());
        h[136..148].copy_from_slice(b"14524770400\0");
        h[148..156].fill(b' ');
        h[156] = kind;
        h[157..157 + link.len()].copy_from_slice(link.as_bytes());
        h[257..263].copy_from_slice(b"ustar\0");
        let sum: u64 = h.iter().map(|&b| u64::from(b)).sum();
        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        out.extend(h);
        out.extend(data);
        out.resize(out.len().next_multiple_of(512), 0);
    }
    out.resize(out.len() + 1024, 0);
    out
}

#[test]
fn tar_listing_modes_preserve_order_directory_and_link() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("metadata.tar");
    fs::write(&path, tar_bytes()).unwrap();
    let listed = extract::list(&path).unwrap();
    assert_eq!(listed.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), ["same", "folder/", "link"]);
    assert_eq!(listed.iter().map(|e| e.mode).collect::<Vec<_>>(), [Some(0o640), Some(0o750), Some(0o777)]);
    assert_eq!(listed.iter().map(|e| (e.size, e.dir)).collect::<Vec<_>>(), [(3, false), (0, true), (0, false)]);
    assert!(matches!(&listed[2].link, Some(Redirection::UnixSymlink(target)) if target == "same"));
    assert_eq!(SelectedEntry::open(&path, 0, None, 4096).unwrap().unix_mode(), Some(0o640));
}

fn read(path: &Path, index: usize, observed: bool) -> Result<Vec<u8>> {
    let entry = SelectedEntry::open(path, index, None, 1 << 20)?;
    let mut out = Vec::new();
    let sink = |chunk: &[u8]| {
        out.extend_from_slice(chunk);
        Ok(())
    };
    if observed {
        entry.read_observed(None, sink, |_| Ok(()))?;
    } else {
        entry.read(None, sink)?;
    }
    Ok(out)
}

// A notice must precede the existing payload read, with one actual source and no chunk events.
#[test]
fn zip_tar_and_single_stream_notice_actual_path_before_payload_once() {
    let dir = tempfile::tempdir().unwrap();
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gzip.write_all(b"single").unwrap();
    for (name, bytes, expected, mode) in [
        ("input.zip", zip_bytes(), b"abc".as_slice(), Some(0o100640)),
        ("input.tar", tar_bytes(), b"abc".as_slice(), Some(0o640)),
        ("input.gz", gzip.finish().unwrap(), b"single".as_slice(), None),
    ] {
        let path = dir.path().join(name);
        fs::write(&path, bytes).unwrap();
        assert_eq!(extract::list(&path).unwrap()[0].mode, mode);
        let seen = Cell::new(false);
        let mut notices = 0;
        let mut out = Vec::new();
        SelectedEntry::open(&path, 0, None, 4096)
            .unwrap()
            .read_observed(
                None,
                |chunk| {
                    assert!(seen.get());
                    out.extend_from_slice(chunk);
                    Ok(())
                },
                |notice| {
                    assert_eq!((notice.volume_index, notice.path, notice.role), (0, path.as_path(), Role::Selected));
                    seen.set(true);
                    notices += 1;
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(notices, 1);
        assert_eq!(out, expected);
        assert_eq!(read(&path, 0, false).unwrap(), expected);
    }
}

fn split(dir: &Path) -> (PathBuf, PathBuf, Vec<Vec<u8>>) {
    let first = dir.join("input.part7.rar");
    let second = dir.join("input.part8.rar");
    let parts = volumes(&FileSpec::new("selected", b"abcdef"), 3);
    fs::write(&first, &parts[0]).unwrap();
    fs::write(&second, &parts[1]).unwrap();
    (first, second, parts)
}

#[test]
fn rar_split_notices_use_read_order_paths_before_volume_open_and_payload() {
    let dir = tempfile::tempdir().unwrap();
    let (first, second, parts) = split(dir.path());
    // The selected file ends before this promised unrelated volume: never open it.
    let mut tail = parts[1].clone();
    let end = end_block(false).len();
    tail.truncate(tail.len() - end);
    tail.extend(end_block(true));
    fs::write(&second, &tail).unwrap();
    fs::write(dir.path().join("input.part9.rar"), b"not an archive").unwrap();
    let entry = SelectedEntry::open(&first, 0, None, 64).unwrap();
    // Opening either corrupt placeholder before its notice would fail.
    fs::write(&first, b"placeholder").unwrap();
    fs::write(&second, b"placeholder").unwrap();
    let roles = RefCell::new(Vec::<(u32, PathBuf, Role)>::new());
    let mut out = Vec::new();
    entry
        .read_observed(
            None,
            |chunk| {
                assert_eq!(roles.borrow().last().unwrap().2, Role::Selected);
                out.extend_from_slice(chunk);
                Ok(())
            },
            |n| {
                if n.role == Role::Header {
                    fs::write(n.path, if n.volume_index == 0 { &parts[0] } else { &tail }).unwrap();
                }
                roles.borrow_mut().push((n.volume_index, n.path.to_path_buf(), n.role));
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(out, b"abcdef");
    assert_eq!(
        *roles.borrow(),
        [
            (0, first.clone(), Role::Header),
            (0, first.clone(), Role::Selected),
            (0, first.clone(), Role::Header),
            (1, second, Role::Header),
            (1, dir.path().join("input.part8.rar"), Role::Selected)
        ]
    );
    assert_eq!(read(&first, 0, false).unwrap(), b"abcdef");
}

#[test]
fn rar_solid_prerequisite_notices_follow_existing_decode_chain() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("solid.part1.rar");
    let second = dir.path().join("solid.part2.rar");
    let packed = testenc::tuned_blocks(&[&[Op::Lit(b'a'), Op::Lit(b'b'), Op::Lit(b'c')]], true);
    let following = testenc::tuned_blocks(&[&[Op::Match(3, 3), Op::Lit(b'x')]], true);
    let initial = FileSpec { method: 3, size: Some(3), ..FileSpec::new("initial", &packed) };
    let selected = FileSpec { method: 3, size: Some(4), solid: true, ..FileSpec::new("selected", &following) };
    let unrelated = FileSpec { method: 3, size: Some(99), ..FileSpec::new("unrelated", b"invalid packed bytes") };
    let cut = packed.len() / 2;
    let mut one = SIG.to_vec();
    one.extend(main_block_flags(true, None, true));
    one.extend(file_block(&unrelated, unrelated.data, 0, false, false));
    one.extend(file_block(&initial, &packed[..cut], crc32fast::hash(&packed[..cut]), false, true));
    one.extend(end_block(true));
    let mut two = SIG.to_vec();
    two.extend(main_block_flags(true, Some(1), true));
    two.extend(file_block(&initial, &packed[cut..], crc32fast::hash(b"abc"), true, false));
    two.extend(file_block(&selected, &following, crc32fast::hash(b"abcx"), false, false));
    two.extend(end_block(true));
    fs::write(&first, one).unwrap();
    fs::write(&second, two).unwrap();
    fs::write(dir.path().join("solid.part3.rar"), b"unrelated invalid volume").unwrap();
    let events = RefCell::new(Vec::<(u32, PathBuf, Role)>::new());
    let mut out = Vec::new();
    SelectedEntry::open(&first, 2, None, 1 << 20)
        .unwrap()
        .read_observed(
            None,
            |chunk| {
                assert_eq!(events.borrow().last().unwrap().2, Role::Selected);
                out.extend_from_slice(chunk);
                Ok(())
            },
            |n| {
                events.borrow_mut().push((n.volume_index, n.path.to_path_buf(), n.role));
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(out, b"abcx");
    assert_eq!(
        *events.borrow(),
        [
            (0, first.clone(), Role::Header),
            (0, first.clone(), Role::Prerequisite),
            (0, first.clone(), Role::Header),
            (1, second.clone(), Role::Header),
            (1, second.clone(), Role::Prerequisite),
            (1, second.clone(), Role::Header),
            (1, second, Role::Selected)
        ]
    );
    assert_eq!(read(&first, 2, false).unwrap(), b"abcx");
}

#[test]
fn callback_error_is_unchanged_and_precedes_rar_open_or_payload() {
    let dir = tempfile::tempdir().unwrap();
    let (first, _, _) = split(dir.path());
    for role in [Role::Header, Role::Selected] {
        let entry = SelectedEntry::open(&first, 0, None, 64).unwrap();
        let mut events = Vec::new();
        let error = entry
            .read_observed(
                None,
                |_| panic!("sink after abort"),
                |n| {
                    events.push(n.role);
                    if n.role == role { Err(Error::Corrupt("notice sentinel")) } else { Ok(()) }
                },
            )
            .unwrap_err();
        assert!(matches!(error, Error::Corrupt("notice sentinel")));
        assert_eq!(events.last(), Some(&role));
    }
    let entry = SelectedEntry::open(&first, 0, None, 64).unwrap();
    fs::remove_file(&first).unwrap();
    let error =
        entry.read_observed(None, |_| panic!("sink after abort"), |_| Err(Error::Corrupt("before open"))).unwrap_err();
    assert!(matches!(error, Error::Corrupt("before open")));
}

#[test]
fn callback_abort_and_cancellation_stop_all_formats_before_sink() {
    let dir = tempfile::tempdir().unwrap();
    for (name, bytes) in
        [("a.zip", zip_bytes()), ("a.tar", tar_bytes()), ("a.rar", archive(&[FileSpec::new("a", b"abc")]))]
    {
        let path = dir.path().join(name);
        fs::write(&path, bytes).unwrap();
        for canceled_before in [false, true] {
            let cancel = Cancellation::default();
            let entry = SelectedEntry::open_cancelable(&path, 0, None, 4096, cancel.clone()).unwrap();
            if canceled_before {
                cancel.cancel();
            }
            let mut notices = 0;
            let error = entry
                .read_observed(
                    None,
                    |_| panic!("sink after cancel"),
                    |_| {
                        notices += 1;
                        cancel.cancel();
                        Ok(())
                    },
                )
                .unwrap_err();
            assert!(matches!(error, Error::Io(ref e) if e.kind() == std::io::ErrorKind::ConnectionAborted));
            assert_eq!(notices, usize::from(!canceled_before));
        }
        let error = SelectedEntry::open(&path, 0, None, 4096)
            .unwrap()
            .read_observed(
                None,
                |_| panic!("sink after error"),
                |_| Err(Error::Io(std::io::Error::from_raw_os_error(1234))),
            )
            .unwrap_err();
        assert!(matches!(error, Error::Io(ref e) if e.raw_os_error() == Some(1234)));
    }
}

#[test]
fn observed_and_old_read_keep_checksum_and_limit_failures() {
    let dir = tempfile::tempdir().unwrap();
    let mut rar = SIG.to_vec();
    rar.extend(main_block(false, None));
    rar.extend(file_block(&FileSpec::new("bad", b"abc"), b"abc", 0, false, false));
    rar.extend(end_block(false));
    let zip = zip_fixture::build(
        &[zip_fixture::Member { crc: Some(0), ..zip_fixture::Member::stored(b"bad", b"abc") }],
        &[0],
        b"",
        b"",
        false,
    )
    .bytes;
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(&tar_bytes()).unwrap();
    let mut tar = gz.finish().unwrap();
    let trailer = tar.len() - 8;
    tar[trailer] ^= 1;
    for (name, bytes) in [("bad.rar", rar), ("bad.zip", zip), ("bad.tar.gz", tar)] {
        let path = dir.path().join(name);
        fs::write(&path, bytes).unwrap();
        let old = read(&path, 0, false).unwrap_err();
        let new = read(&path, 0, true).unwrap_err();
        assert_eq!(std::mem::discriminant(&old), std::mem::discriminant(&new));
        assert_eq!(old.to_string(), new.to_string());
        assert!(SelectedEntry::open(&path, 0, None, 2).is_err());
    }
}

// Deleting the unopened continuation after selection proves abort/cancel run before its open.
#[test]
fn rar_later_volume_callback_abort_or_cancel_prevents_open_and_later_sink_writes() {
    let dir = tempfile::tempdir().unwrap();
    for cancel_callback in [false, true] {
        let (first, second, _) = split(dir.path());
        let cancel = Cancellation::default();
        let entry = SelectedEntry::open_cancelable(&first, 0, None, 64, cancel.clone()).unwrap();
        let mut bytes = Vec::new();
        let mut notices = Vec::new();
        let error = entry
            .read_observed(
                None,
                |chunk| {
                    bytes.extend_from_slice(chunk);
                    Ok(())
                },
                |n| {
                    notices.push((n.volume_index, n.role));
                    if n.volume_index == 1 {
                        assert_eq!(n.path, second);
                        assert_eq!(n.role, Role::Header);
                        fs::remove_file(&second).unwrap();
                        if cancel_callback {
                            cancel.cancel();
                        } else {
                            return Err(Error::Corrupt("later volume abort"));
                        }
                    }
                    Ok(())
                },
            )
            .unwrap_err();
        if cancel_callback {
            assert!(matches!(error, Error::Io(ref e) if e.kind() == std::io::ErrorKind::ConnectionAborted));
        } else {
            assert!(matches!(error, Error::Corrupt("later volume abort")));
        }
        assert_eq!(bytes, b"abc");
        assert_eq!(notices, [(0, Role::Header), (0, Role::Selected), (0, Role::Header), (1, Role::Header)]);
    }
}

#[test]
fn observed_rar_preserves_password_and_integrity_errors() {
    use zipfast::crypto::{derive_rar5_key, encrypt_cbc};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("encrypted.rar");
    let key = derive_rar5_key("correct", 1, &[1; 16], None).unwrap();
    let plain = b"encrypted data!!";
    let cipher = encrypt_cbc(&key, &[2; 16], plain).unwrap();
    let mut record = vec![1, 0, 0, 1];
    record.extend([1; 16]);
    record.extend([2; 16]);
    let mut extra = Vec::new();
    vint(record.len() as u64, &mut extra);
    extra.extend(record);
    let spec = FileSpec { extra, ..FileSpec::new("encrypted", &cipher) };
    fs::write(&path, archive_with(&[(spec, crc32fast::hash(plain))], false)).unwrap();
    for password in [None, Some("wrong"), Some("correct")] {
        let mut results = Vec::new();
        for observed in [false, true] {
            let entry = SelectedEntry::open(&path, 0, Some("correct"), 64).unwrap();
            let mut out = Vec::new();
            let sink = |bytes: &[u8]| {
                out.extend_from_slice(bytes);
                Ok(())
            };
            let result =
                if observed { entry.read_observed(password, sink, |_| Ok(())) } else { entry.read(password, sink) };
            if password == Some("correct") {
                result.unwrap();
                assert_eq!(out, plain);
                results.push(None);
            } else {
                let e = result.unwrap_err();
                results.push(Some((std::mem::discriminant(&e), e.to_string(), out)));
            }
        }
        assert_eq!(results[0], results[1]);
    }
}

fn rar4_block(kind: u8, flags: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0, 0, kind];
    bytes.extend(flags.to_le_bytes());
    bytes.extend(((body.len() + 7) as u16).to_le_bytes());
    bytes.extend(body);
    let crc = crc32fast::hash(&bytes[2..]) as u16;
    bytes[..2].copy_from_slice(&crc.to_le_bytes());
    bytes
}

#[test]
fn rar4_unix_and_nonunix_modes_and_read_notices_match_existing_selection() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rar4.rar");
    let mut bytes = b"Rar!\x1a\x07\0".to_vec();
    bytes.extend(rar4_block(0x73, 0, &[0; 6]));
    for (name, host, mode) in [(b"unix".as_slice(), 3u8, 0o100640u32), (b"dos".as_slice(), 2, 0x20)] {
        let mut body = Vec::new();
        body.extend(3u32.to_le_bytes());
        body.extend(3u32.to_le_bytes());
        body.push(host);
        body.extend(crc32fast::hash(b"abc").to_le_bytes());
        body.extend(0x50221884u32.to_le_bytes());
        body.extend([20, 0x30]);
        body.extend((name.len() as u16).to_le_bytes());
        body.extend(mode.to_le_bytes());
        body.extend(name);
        bytes.extend(rar4_block(0x74, 0x8000, &body));
        bytes.extend(b"abc");
    }
    bytes.extend(rar4_block(0x7b, 0x4000, &[]));
    fs::write(&path, bytes).unwrap();
    let listed = extract::list(&path).unwrap();
    assert_eq!(
        listed.iter().map(|e| (e.name.as_str(), e.mode)).collect::<Vec<_>>(),
        [("unix", Some(0o100640)), ("dos", None)]
    );
    for (index, mode) in [(0, Some(0o100640)), (1, None)] {
        let entry = SelectedEntry::open(&path, index, None, 64).unwrap();
        assert_eq!(entry.unix_mode(), mode);
        let mut notices = Vec::new();
        let mut out = Vec::new();
        entry
            .read_observed(
                None,
                |chunk| {
                    out.extend_from_slice(chunk);
                    Ok(())
                },
                |n| {
                    notices.push((n.volume_index, n.path.to_path_buf(), n.role));
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(out, b"abc");
        assert_eq!(notices, [(0, path.clone(), Role::Header), (0, path.clone(), Role::Selected)]);
        assert_eq!(read(&path, index, false).unwrap(), b"abc");
    }
}

#[test]
fn payload_chunks_do_not_repeat_source_notices() {
    let dir = tempfile::tempdir().unwrap();
    let data = vec![b'x'; (2 << 20) + 17];
    let rar = archive(&[FileSpec::new("large", &data)]);
    let zip = zip_fixture::build(&[zip_fixture::Member::stored(b"large", &data)], &[0], b"", b"", false).bytes;
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(&data).unwrap();
    for (name, bytes, expected_roles) in [
        ("chunked.rar", rar, vec![Role::Header, Role::Selected]),
        ("chunked.zip", zip, vec![Role::Selected]),
        ("chunked.gz", gz.finish().unwrap(), vec![Role::Selected]),
    ] {
        let path = dir.path().join(name);
        fs::write(&path, bytes).unwrap();
        let mut roles = Vec::new();
        let mut chunks = 0;
        let mut received = 0;
        SelectedEntry::open(&path, 0, None, data.len() as u64)
            .unwrap()
            .read_observed(
                None,
                |chunk| {
                    assert!(chunk.iter().all(|&b| b == b'x'));
                    chunks += 1;
                    received += chunk.len();
                    Ok(())
                },
                |n: extract::SelectedReadNotice<'_>| {
                    assert_eq!(n.path, path);
                    assert_eq!(n.volume_index, 0);
                    roles.push(n.role);
                    Ok(())
                },
            )
            .unwrap();
        assert!(chunks > 1);
        assert_eq!(received, data.len());
        assert_eq!(roles, expected_roles);
    }
}

#[test]
fn callback_error_keeps_precedence_when_callback_also_cancels() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cancel-and-error.rar");
    fs::write(&path, archive(&[FileSpec::new("a", b"abc")])).unwrap();
    let cancel = Cancellation::default();
    let entry = SelectedEntry::open_cancelable(&path, 0, None, 64, cancel.clone()).unwrap();
    let error = entry
        .read_observed(
            None,
            |_| panic!("sink after cancel and error"),
            |_| {
                cancel.cancel();
                Err(Error::Corrupt("callback error wins"))
            },
        )
        .unwrap_err();
    assert!(matches!(error, Error::Corrupt("callback error wins")));
}
