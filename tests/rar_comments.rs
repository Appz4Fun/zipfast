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

//! Archive comments: compressed RAR 4.x `CMT` service headers and RAR 2.x comments in the main header.

#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};

use zipfast::error::{RarFailure, RarIntegrityReason, RarResource};
use zipfast::rar5::session::{RarSession, RarSessionOptions};

fn fixture(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(path)
}

fn comment_of(path: &Path) -> Result<Option<Vec<u8>>, std::sync::Arc<RarFailure>> {
    RarSession::open(path, None, RarSessionOptions::default()).unwrap().comment(0)
}

#[test]
fn compressed_cmt_service_comments_match_unrar() {
    // UnRAR 7.30 `l` prints these comments; each is a CMT header packed by RAR 2.9 with -m3.
    for (path, text) in [
        ("rar4/commented.rar", &b"This is the comment of the file commented.rar."[..]),
        ("rar4-rar300/with_comment_rar300.rar", b"This is the archive comment.\n"),
        ("rar4-archiver/mac-rr-comment.rar", b"nzbfast RAR4 fixture comment.\n"),
    ] {
        let session = RarSession::open(&fixture(path), None, RarSessionOptions::default()).unwrap();
        let cmt = session.volumes().next().unwrap().comment_header().unwrap();
        let header = session.headers().nth(cmt).unwrap();
        assert_eq!(header.service_name(), Some("CMT"));
        assert_eq!(header.method(), 3, "{path}");
        let comment = session.comment(0).unwrap().unwrap();
        assert_eq!(String::from_utf8_lossy(&comment), String::from_utf8_lossy(text), "{path}");
        assert_eq!(Some(comment.len() as u64), header.unpacked_size());
    }
}

/// The reference listings, when `ZIPFAST_RAR4_CORPUS` names Prybar's corpus: every `Archive comment:` UnRAR prints
/// for an archive the catalogue opens must be what `comment()` returns.
#[test]
fn comments_match_the_unrar_l_corpus() {
    let Some(root) = std::env::var_os("ZIPFAST_RAR4_CORPUS").map(PathBuf::from) else {
        eprintln!("ZIPFAST_RAR4_CORPUS is not set: skipping the UnRAR l comparison");
        return;
    };
    let mut compared = 0;
    for entry in fs::read_dir(root.join("out2")).unwrap() {
        let path = entry.unwrap().path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()).and_then(|n| n.strip_suffix(".l")) else {
            continue;
        };
        let text = fs::read_to_string(&path).unwrap();
        let Some((_, rest)) = text.split_once("Archive comment:\n") else { continue };
        let expected = rest.split("\nArchive: ").next().unwrap().trim_end();
        let archive = root.join(name.strip_prefix("in_").unwrap().replacen('_', "/", 2));
        let archive = if archive.exists() { archive } else { root.join(name.replacen('_', "/", 2)) };
        let Ok(session) = RarSession::open(&archive, None, RarSessionOptions::default()) else { continue };
        let comment = session.comment(0).unwrap().unwrap();
        // UnRAR prints up to the first NUL (RAR 5.0 writes one at the end).
        let shown = comment.split(|&b| b == 0).next().unwrap();
        assert_eq!(String::from_utf8_lossy(shown).trim_end(), expected, "{name}");
        compared += 1;
    }
    eprintln!("compared {compared} comments");
    assert!(compared >= 3);
}

fn r4_head(kind: u8, flags: u16, body: &[u8], crc_len: Option<usize>) -> Vec<u8> {
    let mut bytes = vec![0, 0, kind];
    bytes.extend(flags.to_le_bytes());
    bytes.extend(((body.len() + 7) as u16).to_le_bytes());
    bytes.extend(body);
    let end = crc_len.unwrap_or(bytes.len());
    let crc = crc32fast::hash(&bytes[2..end]) as u16;
    bytes[..2].copy_from_slice(&crc.to_le_bytes());
    bytes
}

/// A RAR 2.x archive with no members whose main header embeds a comment block.
fn rar2_commented(unpacked: u16, version: u8, method: u8, crc: u16, data: &[u8]) -> Vec<u8> {
    let mut comment = unpacked.to_le_bytes().to_vec();
    comment.extend([version, method]);
    comment.extend(crc.to_le_bytes());
    comment.extend(data);
    let block = r4_head(0x75, 0, &comment, Some(13));
    let mut body = vec![0; 6];
    body.extend(block);
    let mut bytes = b"Rar!\x1a\x07\x00".to_vec();
    bytes.extend(r4_head(0x73, 0x0002, &body, Some(13)));
    bytes.extend(r4_head(0x7b, 0x4000, &[], None));
    bytes
}

/// The first member of a RAR 1.5 or 2.0 fixture: packed data, unpacked size, unpack version, method, CRC-32.
fn first_member(path: &str) -> (Vec<u8>, u32, u8, u8, u32) {
    let bytes = fs::read(fixture(path)).unwrap();
    let main = 7 + usize::from(u16::from_le_bytes([bytes[12], bytes[13]]));
    let h = &bytes[main..];
    assert_eq!(h[2], 0x74);
    let size = usize::from(u16::from_le_bytes([h[5], h[6]]));
    let packed = u32::from_le_bytes(h[7..11].try_into().unwrap()) as usize;
    let unpacked = u32::from_le_bytes(h[11..15].try_into().unwrap());
    let crc = u32::from_le_bytes(h[16..20].try_into().unwrap());
    (h[size..size + packed].to_vec(), unpacked, h[24], h[25], crc)
}

#[test]
fn rar2_main_header_comments_stored_and_compressed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("old.rar");
    let text = b"an old comment";
    fs::write(&path, rar2_commented(text.len() as u16, 20, 0x30, crc32fast::hash(text) as u16, text)).unwrap();
    let session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    assert_eq!(session.volumes().next().unwrap().comment_header(), None);
    assert_eq!(session.comment(0).unwrap().as_deref(), Some(&text[..]));
    // The comment header's own CRC covers its fields: a changed unpacked size is caught there (the main header's
    // CRC covers only its first 13 bytes).
    let mut bytes = rar2_commented(text.len() as u16, 20, 0x30, crc32fast::hash(text) as u16, text);
    bytes[20 + 7] ^= 1;
    fs::write(&path, &bytes).unwrap();
    let failure = comment_of(&path).unwrap_err();
    assert!(matches!(&*failure, RarFailure::Integrity { reason: RarIntegrityReason::HeaderCrc, .. }), "{failure:?}");

    // Genuine RAR 1.5 and RAR 2.0 compressed streams, embedded as comments.
    for fixture in ["rar4-legacy/readme_154_normal.rar", "rar4-legacy/AUTOREJ.RAR"] {
        let (packed, unpacked, version, method, crc) = first_member(fixture);
        fs::write(&path, rar2_commented(unpacked as u16, version, method, crc as u16, &packed)).unwrap();
        let comment = comment_of(&path).unwrap().unwrap();
        assert_eq!((comment.len() as u32, crc32fast::hash(&comment)), (unpacked, crc), "{fixture}");
        // A wrong 16-bit CRC is reported.
        fs::write(&path, rar2_commented(unpacked as u16, version, method, !crc as u16, &packed)).unwrap();
        let failure = comment_of(&path).unwrap_err();
        assert!(
            matches!(&*failure, RarFailure::Integrity { reason: RarIntegrityReason::FinalChecks { .. }, .. }),
            "{failure:?}"
        );
    }
}

#[test]
fn crafted_comments_fail_without_panicking() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.rar");
    let (packed, _, version, _, _) = first_member("rar4-legacy/readme_154_normal.rar");
    // Unknown unpack version and method.
    for (version, method) in [(14, 0x33), (36, 0x33), (version, 0x36)] {
        fs::write(&path, rar2_commented(10, version, method, 0, &packed[..10])).unwrap();
        assert!(matches!(&*comment_of(&path).unwrap_err(), RarFailure::Unsupported(_)));
    }
    // A comment block whose declared size passes the main header's end.
    let mut bytes = rar2_commented(5, 20, 0x30, 0, b"hello");
    bytes[7 + 13 + 5..7 + 13 + 7].copy_from_slice(&200u16.to_le_bytes());
    let crc16 = crc32fast::hash(&bytes[7 + 2..7 + 13]) as u16;
    bytes[7..9].copy_from_slice(&crc16.to_le_bytes());
    fs::write(&path, &bytes).unwrap();
    assert!(comment_of(&path).is_err());
    // Corrupted and truncated compressed streams, and wrong declared sizes, for both engines and RAR 2.9.
    let mut state = 0x1234_5678u32;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        state
    };
    for fixture in ["rar4-legacy/readme_154_normal.rar", "rar4-legacy/AUTOREJ.RAR"] {
        let (packed, unpacked, version, method, crc) = first_member(fixture);
        for round in 0..64 {
            let mut data = packed.clone();
            let at = next() as usize % data.len();
            data[at] ^= (next() % 255 + 1) as u8;
            if round % 4 == 0 {
                data.truncate(next() as usize % data.len());
            }
            let size = if round % 8 == 1 { (next() % 0xffff) as u16 } else { unpacked as u16 };
            fs::write(&path, rar2_commented(size, version, method, crc as u16, &data)).unwrap();
            let _ = comment_of(&path);
        }
    }

    // A RAR 2.9 CMT service header with its packed data mutated.
    let original = fs::read(fixture("rar4/commented.rar")).unwrap();
    for _ in 0..64 {
        let mut bytes = original.clone();
        // The CMT header at 0x14 is 0x23 bytes; its 0x2e data bytes follow.
        let at = 0x37 + next() as usize % 0x2e;
        bytes[at] ^= (next() % 255 + 1) as u8;
        fs::write(&path, &bytes).unwrap();
        let result = comment_of(&path);
        assert!(result.is_err(), "a mutated comment must fail its CRC or decoding");
    }
}

#[test]
fn oversized_cmt_comment_is_refused() {
    // Declare a 2 MiB unpacked size on the RAR 2.9 CMT header (bytes 11..15 of the header at 0x14), fixing its CRC.
    let mut bytes = fs::read(fixture("rar4/commented.rar")).unwrap();
    let at = 0x14;
    bytes[at + 11..at + 15].copy_from_slice(&(2u32 << 20).to_le_bytes());
    let size = usize::from(u16::from_le_bytes([bytes[at + 5], bytes[at + 6]]));
    let crc = crc32fast::hash(&bytes[at + 2..at + size]) as u16;
    bytes[at..at + 2].copy_from_slice(&crc.to_le_bytes());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.rar");
    fs::write(&path, &bytes).unwrap();
    let failure = comment_of(&path).unwrap_err();
    assert!(matches!(&*failure, RarFailure::Limit { resource: RarResource::CatalogueReadBytes, .. }), "{failure:?}");
}
