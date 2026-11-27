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

//! Streaming stored members' plaintext from an output offset, from memory and from a waiting volume source.
mod common;

use common::{FileSpec, SIG, end_block, file_block, main_block};
use std::{
    fs::File,
    io::Cursor,
    ops::Range,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};
use zipfast::map::*;
use zipfast::progressive::{
    ChecksumAlgorithm, ProgressiveResult, RangeRead, RangeSource, SourceId, SourceInfo, SourceLength, VolumeAnswer,
    VolumeRequest, VolumeSource,
};

fn refs(volumes: &[Vec<u8>]) -> Vec<&[u8]> {
    volumes.iter().map(Vec::as_slice).collect()
}

fn data(len: usize, seed: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + seed) % 251) as u8).collect()
}

fn extract(volumes: &[Vec<u8>], map: &MemberMap, member: usize, at: u64, pw: Option<&str>) -> Vec<u8> {
    let mut out = Vec::new();
    let done = extract_member_from(&refs(volumes), map, member, at, pw, &mut out)
        .unwrap_or_else(|e| panic!("offset {at}: {e:?}"));
    assert_eq!(done.written, out.len() as u64);
    out
}

fn extract_err(volumes: &[Vec<u8>], map: &MemberMap, member: usize, at: u64, pw: Option<&str>) -> ExtractFromError {
    extract_member_from(&refs(volumes), map, member, at, pw, &mut Vec::new()).unwrap_err()
}

/// Offsets every kind is read from: start, mid-block, block boundaries, around each piece boundary, the last byte
/// and the end.
fn offsets(member: &MapMember) -> Vec<u64> {
    let size = member.unpacked_size.unwrap();
    let mut out = vec![0, 1, 7, 15, 16, 17, 32, 40, size / 2, size - 1, size];
    for piece in &member.pieces[1..] {
        let at = piece.out.as_ref().map_or(piece.stream_offset, |o| o.start);
        out.extend([at.saturating_sub(17), at.saturating_sub(16), at - 1, at, at + 1, at + 16]);
    }
    out.retain(|&o| o <= size);
    out.sort_unstable();
    out.dedup();
    out
}

fn assert_suffixes(volumes: &[Vec<u8>], map: &MemberMap, member: usize, gold: &[u8], pw: Option<&str>) {
    for at in offsets(&map.members[member]) {
        assert_eq!(extract(volumes, map, member, at, pw), &gold[at as usize..], "offset {at}");
    }
}

// ---- Fixtures (shared shapes with tests/member_map.rs) ----

fn rar5_split(gold: &[u8], chunk: usize) -> Vec<Vec<u8>> {
    common::volumes(&FileSpec::new("big.bin", gold), chunk)
}

const SALT: [u8; 16] = [3; 16];
const IV: [u8; 16] = [9; 16];

fn hmac(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut padded = [0u8; 64];
    padded[..key.len()].copy_from_slice(key);
    let mut inner: Vec<u8> = padded.iter().map(|b| b ^ 0x36).collect();
    inner.extend_from_slice(message);
    let mut outer: Vec<u8> = padded.iter().map(|b| b ^ 0x5c).collect();
    outer.extend_from_slice(&zipfast::crypto::sha256(&inner));
    zipfast::crypto::sha256(&outer)
}

fn password_check(password: &str, kdf_count: u8) -> [u8; 8] {
    let mut block = SALT.to_vec();
    block.extend(1u32.to_be_bytes());
    let mut u = hmac(password.as_bytes(), &block);
    let mut sum = u;
    for _ in 1..(1u32 << kdf_count) + 32 {
        u = hmac(password.as_bytes(), &u);
        sum.iter_mut().zip(u).for_each(|(s, b)| *s ^= b);
    }
    let mut folded = [0u8; 8];
    sum.iter().enumerate().for_each(|(i, b)| folded[i % 8] ^= b);
    folded
}

/// One encrypted stored RAR5 member "e.bin" holding `plain`, password "pw", its ciphertext cut at stream offsets
/// `cuts`; part checks are keyed CRCs of the ciphertext, the final one a keyed CRC of the plaintext.
fn rar5_encrypted(plain: &[u8], cuts: &[usize], with_check: bool) -> Vec<Vec<u8>> {
    let size = plain.len();
    let (key, hash_key) = zipfast::crypto::derive_rar5_key_and_hash_key("pw", 1, &SALT, None).unwrap();
    let mut padded = plain.to_vec();
    padded.resize(size.div_ceil(16) * 16, 0);
    let cipher = zipfast::crypto::encrypt_cbc(&key, &IV, &padded).unwrap();
    let check = password_check("pw", 1);
    let mut extra = vec![if with_check { 48 } else { 36 }, 1, 0, if with_check { 3 } else { 2 }, 1];
    extra.extend(SALT);
    extra.extend(IV);
    if with_check {
        extra.extend(check);
        extra.extend(&zipfast::crypto::sha256(&check)[..4]);
    }
    let mut spec = FileSpec::new("e.bin", &cipher);
    spec.size = Some(size as u64);
    spec.extra = extra;
    let bounds: Vec<usize> = std::iter::once(0).chain(cuts.iter().copied()).chain([cipher.len()]).collect();
    bounds
        .windows(2)
        .enumerate()
        .map(|(index, pair)| {
            let part = &cipher[pair[0]..pair[1]];
            let last = pair[1] == cipher.len();
            let crc = zipfast::crypto::rar5_tweak_crc32(crc32fast::hash(if last { plain } else { part }), &hash_key);
            let mut bytes = SIG.to_vec();
            bytes.extend(main_block(true, Some(index as u64)));
            bytes.extend(file_block(&spec, part, crc, index > 0, !last));
            bytes.extend(end_block(!last));
            bytes
        })
        .collect()
}

fn r4_block(kind: u8, flags: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0, 0, kind];
    bytes.extend(flags.to_le_bytes());
    bytes.extend(((body.len() + 7) as u16).to_le_bytes());
    bytes.extend(body);
    let crc = crc32fast::hash(&bytes[2..]) as u16;
    bytes[..2].copy_from_slice(&crc.to_le_bytes());
    bytes
}

fn r4_member(name: &[u8], data: &[u8], flags: u16, method: u8, size: usize, crc: u32, version: u8) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend((data.len() as u32).to_le_bytes());
    body.extend((size as u32).to_le_bytes());
    body.push(3);
    body.extend(crc.to_le_bytes());
    body.extend(0x50221884u32.to_le_bytes());
    body.extend([version, method]);
    body.extend((name.len() as u16).to_le_bytes());
    body.extend(0o100644u32.to_le_bytes());
    body.extend(name);
    let mut bytes = r4_block(0x74, flags | 0x8000, &body);
    bytes.extend(data);
    bytes
}

fn r4_archive(files: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = b"Rar!\x1a\x07\0".to_vec();
    bytes.extend(r4_block(0x73, 0, &[0; 6]));
    for file in files {
        bytes.extend(file);
    }
    bytes.extend(r4_block(0x7b, 0x4000, &[]));
    bytes
}

fn r4_split(gold: &[u8], chunk: usize) -> Vec<Vec<u8>> {
    let count = gold.len().div_ceil(chunk);
    gold.chunks(chunk)
        .enumerate()
        .map(|(i, payload)| {
            let flags = u16::from(i > 0) | (u16::from(i + 1 < count) * 2);
            let crc = crc32fast::hash(if i + 1 == count { gold } else { payload });
            let mut wire = b"Rar!\x1a\x07\0".to_vec();
            wire.extend(r4_block(0x73, 0x11 | if i == 0 { 0x100 } else { 0 }, &[0; 6]));
            wire.extend(r4_member(b"one", payload, flags, 0x30, gold.len(), crc, 29));
            wire.extend(r4_block(0x7b, 0x4000 | u16::from(i + 1 < count), &[]));
            wire
        })
        .collect()
}

const R4_SALT: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

/// RAR4 stored member with AES data (password "pw"), its ciphertext cut into parts of the lengths `cuts`.
fn r4_aes(gold: &[u8], cuts: &[usize]) -> Vec<Vec<u8>> {
    let (key, iv) = zipfast::crypto::derive_rar4_key_iv("pw", &R4_SALT);
    let mut padded = gold.to_vec();
    padded.resize(gold.len().next_multiple_of(16), 0xa5);
    let cipher = zipfast::crypto::encrypt_cbc(&key, &iv, &padded).unwrap();
    assert_eq!(cuts.iter().sum::<usize>(), cipher.len());
    let mut at = 0;
    cuts.iter()
        .enumerate()
        .map(|(i, &len)| {
            let payload = &cipher[at..at + len];
            at += len;
            let flags = 0x8000 | 0x404 | u16::from(i > 0) | (u16::from(i + 1 < cuts.len()) * 2);
            let mut body = Vec::new();
            body.extend((len as u32).to_le_bytes());
            body.extend((gold.len() as u32).to_le_bytes());
            body.push(3);
            body.extend(crc32fast::hash(if i + 1 == cuts.len() { gold } else { payload }).to_le_bytes());
            body.extend(0x50221884u32.to_le_bytes());
            body.extend([29, 0x30]);
            body.extend(3u16.to_le_bytes());
            body.extend(0o100644u32.to_le_bytes());
            body.extend(b"one");
            body.extend(R4_SALT);
            let mut wire = b"Rar!\x1a\x07\0".to_vec();
            wire.extend(r4_block(0x73, 1, &[0; 6]));
            wire.extend(r4_block(0x74, flags, &body));
            wire.extend(payload);
            wire.extend(r4_block(0x7b, 0x4000 | u16::from(i + 1 < cuts.len()), &[]));
            wire
        })
        .collect()
}

struct ZipSpec<'a> {
    name: &'a str,
    payload: Vec<u8>,
    method: u16,
    flags: u16,
    crc: u32,
    size: u32,
}

fn zip(entries: &[ZipSpec<'_>]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for e in entries {
        let local_at = out.len() as u32;
        let common = |sig: u32, out: &mut Vec<u8>| {
            out.extend(sig.to_le_bytes());
            if sig == 0x0201_4b50 {
                out.extend(((3u16 << 8) | 20).to_le_bytes());
            }
            out.extend(20u16.to_le_bytes());
            out.extend(e.flags.to_le_bytes());
            out.extend(e.method.to_le_bytes());
            out.extend(0x6000u16.to_le_bytes());
            out.extend(0x5a21u16.to_le_bytes());
            out.extend(e.crc.to_le_bytes());
            out.extend((e.payload.len() as u32).to_le_bytes());
            out.extend(e.size.to_le_bytes());
            out.extend((e.name.len() as u16).to_le_bytes());
            out.extend(0u16.to_le_bytes());
        };
        common(0x0403_4b50, &mut out);
        out.extend(e.name.as_bytes());
        out.extend(&e.payload);
        common(0x0201_4b50, &mut central);
        central.extend([0; 6]);
        central.extend((0o100644u32 << 16).to_le_bytes());
        central.extend(local_at.to_le_bytes());
        central.extend(e.name.as_bytes());
    }
    let cd_at = out.len() as u32;
    out.extend(&central);
    out.extend(0x0605_4b50u32.to_le_bytes());
    out.extend([0; 4]);
    out.extend((entries.len() as u16).to_le_bytes());
    out.extend((entries.len() as u16).to_le_bytes());
    out.extend((central.len() as u32).to_le_bytes());
    out.extend(cd_at.to_le_bytes());
    out.extend(0u16.to_le_bytes());
    out
}

/// Traditional PKWARE encryption of `plain` under `password`, with the 12-byte header ending in `check`.
fn zipcrypto(password: &str, check: u8, plain: &[u8]) -> Vec<u8> {
    let table: Vec<u32> = (0..256u32)
        .map(|mut c| {
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xedb8_8320 ^ (c >> 1) } else { c >> 1 };
            }
            c
        })
        .collect();
    let crc = |c: u32, b: u8| table[((c ^ u32::from(b)) & 0xff) as usize] ^ (c >> 8);
    let mut keys = [0x1234_5678u32, 0x2345_6789, 0x3456_7890];
    let update = |keys: &mut [u32; 3], b: u8| {
        keys[0] = crc(keys[0], b);
        keys[1] = (keys[1].wrapping_add(keys[0] & 0xff)).wrapping_mul(134_775_813).wrapping_add(1);
        keys[2] = crc(keys[2], (keys[1] >> 24) as u8);
    };
    for &b in password.as_bytes() {
        update(&mut keys, b);
    }
    let mut header: Vec<u8> = (0..11).map(|i| i * 7 + 3).collect();
    header.push(check);
    header
        .iter()
        .chain(plain)
        .map(|&p| {
            let t = (keys[2] | 2) as u16;
            let c = p ^ ((t.wrapping_mul(t ^ 1)) >> 8) as u8;
            update(&mut keys, p);
            c
        })
        .collect()
}

fn winzip_aes(
    plain: &[u8],
    strength: zipfast::zip::write::AesStrength,
    variant: zipfast::zip::write::AesVariant,
) -> Vec<u8> {
    use zipfast::zip::write::*;
    let mut writer = ZipStreamWriter::new(Vec::new(), WriterOptions::default()).unwrap();
    let options = EntryOptions {
        name: EntryName::Utf8("aes.bin"),
        method: Method::Stored,
        modified: DosDateTime::default(),
        extended_mtime: None,
        permissions: Permissions::new(0o644).unwrap(),
        comment: b"",
    };
    let request = WinZipAesRequest::new("pw", strength, variant).unwrap();
    writer
        .add_winzip_aes_file(
            options,
            &mut Cursor::new(plain),
            InputLength::Exact(plain.len() as u64),
            request,
            |salt| {
                salt.iter_mut().enumerate().for_each(|(i, b)| *b = i as u8 + 1);
                Ok(())
            },
        )
        .unwrap();
    writer.finish().unwrap().sink
}

// ---- Suffixes equal the original plaintext ----

#[test]
fn rar5_plain_split_suffixes() {
    let gold = data(10_000, 7);
    let volumes = rar5_split(&gold, 2600);
    let map = MemberMap::from_memory(&refs(&volumes), "big.part1.rar", None).unwrap();
    assert_suffixes(&volumes, &map, 0, &gold, None);
}

#[test]
fn rar5_encrypted_split_suffixes() {
    // 9,999 bytes: one padding byte; cuts are not block aligned.
    let gold = data(9_999, 11);
    let volumes = rar5_encrypted(&gold, &[2600, 5203, 7801], true);
    let map = MemberMap::from_memory(&refs(&volumes), "e.part1.rar", None).unwrap();
    assert_eq!(map.members[0].mapping, OutputMapping::CbcBlocks);
    assert_suffixes(&volumes, &map, 0, &gold, Some("pw"));
    // A size that is a whole number of blocks has no padding.
    let gold = data(4096, 5);
    let volumes = rar5_encrypted(&gold, &[1000, 2048], true);
    let map = MemberMap::from_memory(&refs(&volumes), "e.part1.rar", None).unwrap();
    assert_suffixes(&volumes, &map, 0, &gold, Some("pw"));
}

#[test]
fn rar4_plain_split_suffixes() {
    let gold = data(1300, 9);
    let volumes = r4_split(&gold, 400);
    let map = MemberMap::from_memory(&refs(&volumes), "old.part1.rar", None).unwrap();
    assert_eq!(map.format, MapFormat::Rar4);
    assert_suffixes(&volumes, &map, 0, &gold, None);
}

#[test]
fn rar4_aes_split_suffixes() {
    let gold = data(1000, 13);
    let volumes = r4_aes(&gold, &[333, 400, 275]);
    let map = MemberMap::from_memory(&refs(&volumes), "a.part01.rar", None).unwrap();
    assert_eq!(map.members[0].cipher, Some(CipherParams::Rar4 { salt: R4_SALT }));
    assert_suffixes(&volumes, &map, 0, &gold, Some("pw"));
}

#[test]
fn zip_stored_and_zipcrypto_suffixes() {
    let plain = data(3000, 4);
    let secret = data(500, 6);
    let crc = crc32fast::hash(&secret);
    let bytes = zip(&[
        ZipSpec {
            name: "plain.bin",
            payload: plain.clone(),
            method: 0,
            flags: 0,
            crc: crc32fast::hash(&plain),
            size: 3000,
        },
        ZipSpec {
            name: "zc.bin",
            payload: zipcrypto("pw", (crc >> 24) as u8, &secret),
            method: 0,
            flags: 1,
            crc,
            size: 500,
        },
    ]);
    let volumes = vec![bytes];
    let map = MemberMap::from_memory(&refs(&volumes), "x.zip", None).unwrap();
    assert_suffixes(&volumes, &map, 0, &plain, None);
    assert_eq!(extract(&volumes, &map, 1, 0, Some("pw")), secret);
    assert_eq!(extract(&volumes, &map, 1, 500, Some("pw")), b"");
    assert!(matches!(
        extract_err(&volumes, &map, 1, 1, Some("pw")),
        ExtractFromError::Unsupported(UnsupportedRead::SequentialCipher)
    ));
    assert!(matches!(extract_err(&volumes, &map, 1, 0, Some("wrong!")), ExtractFromError::WrongPassword));
}

#[test]
fn winzip_aes_suffixes_for_every_strength_and_variant() {
    use zipfast::zip::write::{AesStrength, AesVariant};
    let gold = data(5000, 3);
    for strength in [AesStrength::Aes128, AesStrength::Aes192, AesStrength::Aes256] {
        for variant in [AesVariant::Ae1, AesVariant::Ae2] {
            let volumes = vec![winzip_aes(&gold, strength, variant)];
            let map = MemberMap::from_memory(&refs(&volumes), "x.zip", None).unwrap();
            assert!(matches!(map.members[0].mapping, OutputMapping::Counter { .. }));
            assert_suffixes(&volumes, &map, 0, &gold, Some("pw"));
            assert!(matches!(extract_err(&volumes, &map, 0, 100, Some("nope")), ExtractFromError::WrongPassword));
            // From offset 0 the authentication code is checked; past it, it cannot be.
            let mut bad = volumes.clone();
            let piece = map.members[0].pieces[0].clone();
            bad[0][piece.packed.end as usize - 1] ^= 1;
            assert!(matches!(extract_err(&bad, &map, 0, 0, Some("pw")), ExtractFromError::AuthenticationFailed));
            assert_eq!(extract(&bad, &map, 0, 1, Some("pw")), &gold[1..]);
        }
    }
}

// ---- Verification ----

#[test]
fn corrupt_part_is_pinned_to_its_volume() {
    let gold = data(10_000, 7);
    let volumes = rar5_split(&gold, 2600);
    let map = MemberMap::from_memory(&refs(&volumes), "big.part1.rar", None).unwrap();
    let piece = map.members[0].pieces[2].clone();
    let mut bad = volumes.clone();
    bad[2][piece.packed.start as usize + 100] ^= 0x40;
    for at in [0, 3000, 5200] {
        let mut out = Vec::new();
        let error = extract_member_from(&refs(&bad), &map, 0, at, None, &mut out).unwrap_err();
        let ExtractFromError::PartBad { volume, part, which, bad: range, out: reached, released } = error else {
            panic!("offset {at}: {error:?}")
        };
        assert_eq!((volume, part, which), (2, 2, ChecksumAlgorithm::Crc32));
        assert_eq!(range, at.max(5200)..7800);
        // Bytes before the part are delivered and correct; none of the bad part's.
        assert!(!released);
        assert_eq!(reached, at.max(5200));
        assert_eq!(out.len() as u64, reached - at);
        assert_eq!(out[..(5200 - at.min(5200)) as usize], gold[at as usize..5200]);
    }
    // A part read only from its middle cannot be checked; the next one still is.
    assert_eq!(extract(&bad, &map, 0, 5300, None).len(), 4700);
    // From offset 0 the final part's member check covers the last volume too.
    let last = map.members[0].pieces[3].clone();
    let mut bad = volumes.clone();
    bad[3][last.packed.start as usize] ^= 1;
    assert!(matches!(
        extract_err(&bad, &map, 0, 0, None),
        ExtractFromError::MemberBad { which: ChecksumAlgorithm::Crc32 }
    ));
    assert_eq!(extract(&bad, &map, 0, 7801, None), &gold[7801..]);
}

#[test]
fn corrupt_encrypted_parts_fail_their_keyed_ciphertext_checks() {
    let gold = data(9_999, 11);
    let volumes = rar5_encrypted(&gold, &[2600, 5203, 7801], true);
    let map = MemberMap::from_memory(&refs(&volumes), "e.part1.rar", None).unwrap();
    let piece = map.members[0].pieces[1].clone();
    let mut bad = volumes.clone();
    bad[1][piece.packed.start as usize + 7] ^= 1;
    let error = extract_err(&bad, &map, 0, 2584, Some("pw"));
    let ExtractFromError::PartBad { volume: 1, part: 1, which: ChecksumAlgorithm::Crc32, bad: range, .. } = error
    else {
        panic!("{error:?}")
    };
    assert_eq!(range, 2600..5219, "CBC spreads damage one block past the part");

    let gold4 = data(1000, 13);
    let volumes = r4_aes(&gold4, &[333, 400, 275]);
    let map = MemberMap::from_memory(&refs(&volumes), "a.part01.rar", None).unwrap();
    let piece = map.members[0].pieces[1].clone();
    let mut bad = volumes.clone();
    bad[1][piece.packed.start as usize] ^= 1;
    assert!(matches!(extract_err(&bad, &map, 0, 0, Some("pw")), ExtractFromError::PartBad { volume: 1, .. }));
}

#[test]
fn wrong_passwords() {
    let gold = data(3000, 2);
    let volumes = rar5_encrypted(&gold, &[1000], true);
    let map = MemberMap::from_memory(&refs(&volumes), "e.part1.rar", None).unwrap();
    assert!(matches!(extract_err(&volumes, &map, 0, 1234, Some("wrong")), ExtractFromError::WrongPassword));
    assert!(matches!(extract_err(&volumes, &map, 0, 0, None), ExtractFromError::PasswordRequired));
    // Without a check value a wrong password is caught only by keyed checks the read covers: a whole part's, or the
    // member's at offset 0.
    let volumes = rar5_encrypted(&gold, &[1000], false);
    let map = MemberMap::from_memory(&refs(&volumes), "e.part1.rar", None).unwrap();
    assert_eq!(extract(&volumes, &map, 0, 1234, Some("pw")), &gold[1234..]);
    assert!(matches!(extract_err(&volumes, &map, 0, 0, Some("wrong")), ExtractFromError::PartBad { part: 0, .. }));
    let single = rar5_encrypted(&gold, &[], false);
    let single_map = MemberMap::from_memory(&refs(&single), "e.rar", None).unwrap();
    assert!(matches!(
        extract_err(&single, &single_map, 0, 0, Some("wrong")),
        ExtractFromError::MemberBad { which: ChecksumAlgorithm::Crc32 }
    ));
    assert_ne!(extract(&volumes, &map, 0, 1234, Some("wrong")), &gold[1234..]);
    // RAR4 has no check value at all.
    let gold4 = data(1000, 13);
    let volumes = r4_aes(&gold4, &[333, 400, 275]);
    let map = MemberMap::from_memory(&refs(&volumes), "a.part01.rar", None).unwrap();
    assert!(matches!(extract_err(&volumes, &map, 0, 0, Some("wrong")), ExtractFromError::MemberBad { .. }));
    assert_ne!(extract(&volumes, &map, 0, 500, Some("wrong")), &gold4[500..]);
}

// ---- Typed refusals ----

#[test]
fn unsupported_and_invalid_requests_are_typed() {
    let mut packed = FileSpec::new("c.bin", b"compressed stand-in");
    packed.method = 3;
    packed.size = Some(1000);
    let bytes = common::archive(&[packed]);
    let map = MemberMap::from_memory(&[&bytes], "x.rar", None).unwrap();
    let volumes = vec![bytes];
    assert!(matches!(
        extract_err(&volumes, &map, 0, 10, None),
        ExtractFromError::Unsupported(UnsupportedRead::Compressed { id: 3 })
    ));
    assert!(matches!(extract_err(&volumes, &map, 1, 0, None), ExtractFromError::NoSuchMember { index: 1 }));

    let old = r4_archive(&[r4_member(b"old", b"old cipher payload", 0x04, 0x30, 18, 0, 20)]);
    let map = MemberMap::from_memory(&[&old], "old.rar", None).unwrap();
    assert!(matches!(
        extract_err(&[old], &map, 0, 0, Some("pw")),
        ExtractFromError::Unsupported(UnsupportedRead::LegacyRar4Cipher)
    ));

    let deflated =
        zip(&[ZipSpec { name: "d.bin", payload: b"deflate stand-in".to_vec(), method: 8, flags: 0, crc: 1, size: 77 }]);
    let map = MemberMap::from_memory(&[&deflated], "x.zip", None).unwrap();
    assert!(matches!(
        extract_err(&[deflated], &map, 0, 0, None),
        ExtractFromError::Unsupported(UnsupportedRead::Compressed { id: 8 })
    ));

    let gold = data(10_000, 7);
    let volumes = rar5_split(&gold, 2600);
    let map = MemberMap::from_memory(&refs(&volumes), "big.part1.rar", None).unwrap();
    assert!(matches!(
        extract_err(&volumes, &map, 0, 10_001, None),
        ExtractFromError::OffsetPastEnd { offset: 10_001, size: 10_000 }
    ));
    let partial = MemberMap::from_memory(&refs(&volumes[..2]), "big.part1.rar", None).unwrap();
    assert!(matches!(extract_err(&volumes, &partial, 0, 100, None), ExtractFromError::IncompleteMember { out: 5200 }));
    // Volumes the read does not need may be absent.
    let mut sparse = volumes.clone();
    sparse[0].clear();
    sparse[1].clear();
    assert_eq!(extract(&sparse, &map, 0, 5200, None), &gold[5200..]);
}

// ---- A waiting volume source ----

#[derive(Default)]
struct Gate {
    ready: bool,
    wake: Option<Waker>,
    waits: usize,
}

struct Bytes {
    data: Vec<u8>,
    holes: Vec<Range<u64>>,
    chunk: usize,
    gate: Arc<Mutex<Gate>>,
}

impl RangeSource for Bytes {
    fn info(&self) -> SourceInfo {
        SourceInfo {
            id: SourceId(1),
            generation: 0,
            extent: self.data.len() as u64,
            length: SourceLength::Final(self.data.len() as u64),
        }
    }
    fn backing_files(&self) -> &[File] {
        &[]
    }
    fn read_at(&mut self, at: u64, buf: &mut [u8], cx: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
        let mut g = self.gate.lock().unwrap();
        if !g.ready {
            g.waits += 1;
            g.wake = Some(cx.waker().clone());
            return Ok(RangeRead::NotYet);
        }
        g.ready = false;
        let mut end = (at + buf.len().min(self.chunk) as u64).min(self.data.len() as u64);
        for h in &self.holes {
            if h.start <= at && at < h.end {
                return Ok(RangeRead::Hole { len: (h.end - at).min(buf.len() as u64) });
            }
            if h.start > at {
                end = end.min(h.start);
            }
        }
        let n = (end - at) as usize;
        buf[..n].copy_from_slice(&self.data[at as usize..end as usize]);
        Ok(RangeRead::Filled { count: n })
    }
}

struct Provider {
    volumes: Vec<Option<Bytes>>,
    gate: Arc<Mutex<Gate>>,
    asked: Arc<Mutex<Vec<VolumeRequest>>>,
}

impl VolumeSource for Provider {
    fn volume(&mut self, r: &VolumeRequest, cx: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
        let mut g = self.gate.lock().unwrap();
        if !g.ready {
            g.waits += 1;
            g.wake = Some(cx.waker().clone());
            return Ok(VolumeAnswer::Wait);
        }
        g.ready = false;
        self.asked.lock().unwrap().push(r.clone());
        Ok(self
            .volumes
            .get_mut(r.index as usize)
            .and_then(Option::take)
            .map_or(VolumeAnswer::Missing, |b| VolumeAnswer::Ready(Box::new(b))))
    }
}

type Asked = Arc<Mutex<Vec<VolumeRequest>>>;

fn waiting_reader(
    volumes: &[Vec<u8>],
    holes: &[(u32, Range<u64>)],
    map: &MemberMap,
    at: u64,
    options: MapOptions,
) -> (MemberReader, Arc<Mutex<Gate>>, Asked) {
    let gate = Arc::new(Mutex::new(Gate::default()));
    let asked = Arc::new(Mutex::new(Vec::new()));
    let volumes = volumes
        .iter()
        .enumerate()
        .map(|(i, data)| {
            Some(Bytes {
                data: data.clone(),
                holes: holes.iter().filter(|(v, _)| *v == i as u32).map(|(_, r)| r.clone()).collect(),
                chunk: 333,
                gate: gate.clone(),
            })
        })
        .collect();
    let provider = Provider { volumes, gate: gate.clone(), asked: asked.clone() };
    (MemberReader::new(Box::new(provider), map, 0, at, options).unwrap(), gate, asked)
}

/// Reads to the end with `poll_read`, releasing each wait through the waker the provider kept.
fn drive(reader: &mut MemberReader, gate: &Arc<Mutex<Gate>>, out: &mut Vec<u8>) -> Result<(), ExtractFromError> {
    let mut cx = Context::from_waker(Waker::noop());
    let mut buf = [0u8; 1000];
    for _ in 0..1_000_000 {
        match reader.poll_read(&mut cx, &mut buf) {
            Poll::Ready(Ok(0)) => return Ok(()),
            Poll::Ready(Ok(n)) => out.extend_from_slice(&buf[..n]),
            Poll::Ready(Err(e)) => return Err(e),
            Poll::Pending => {
                let waker = {
                    let mut g = gate.lock().unwrap();
                    g.ready = true;
                    g.wake.take().expect("pending only after the provider kept a waker")
                };
                waker.wake();
            }
        }
    }
    panic!("read did not finish")
}

#[test]
fn volume_source_with_waits_matches_memory() {
    let gold = data(9_999, 11);
    let volumes = rar5_encrypted(&gold, &[2600, 5203, 7801], true);
    let map = MemberMap::from_memory(&refs(&volumes), "e.part1.rar", None).unwrap();
    for at in [0, 2601, 5203, 9998] {
        let options = MapOptions::new("e.part1.rar").password(Some("pw"));
        let (mut reader, gate, asked) = waiting_reader(&volumes, &[], &map, at, options);
        assert_eq!((reader.position(), reader.end()), (at, 9_999));
        let mut out = Vec::new();
        drive(&mut reader, &gate, &mut out).unwrap();
        assert_eq!(out, extract(&volumes, &map, 0, at, Some("pw")), "offset {at}");
        assert_eq!(reader.position(), 9_999);
        assert!(gate.lock().unwrap().waits >= 2);
        // Only the volumes the read needs are asked for, by index and by derived name.
        let asked: Vec<_> = asked.lock().unwrap().iter().map(|r| (r.index, r.expected.clone())).collect();
        let start = (at & !15).saturating_sub(16);
        let first = map.members[0]
            .pieces
            .iter()
            .position(|p| start < p.stream_offset + (p.packed.end - p.packed.start))
            .unwrap() as u32;
        let expected: Vec<_> = (first..4).map(|i| (i, format!("e.part{}.rar", i + 1).into())).collect();
        assert_eq!(asked, expected, "offset {at}");
    }
    // poll_write_to gives the same bytes.
    let options = MapOptions::new("e.part1.rar").password(Some("pw"));
    let (mut reader, gate, _) = waiting_reader(&volumes, &[], &map, 4000, options);
    let mut out = Vec::new();
    let mut cx = Context::from_waker(Waker::noop());
    let total = loop {
        match reader.poll_write_to(&mut cx, &mut out) {
            Poll::Ready(result) => break result.unwrap(),
            Poll::Pending => {
                let waker = {
                    let mut g = gate.lock().unwrap();
                    g.ready = true;
                    g.wake.take().unwrap()
                };
                waker.wake();
            }
        }
    };
    assert_eq!(total, 5_999);
    assert_eq!(out, &gold[4000..]);
}

#[test]
fn hole_mid_stream_reports_the_output_reached() {
    let gold = data(10_000, 7);
    let volumes = rar5_split(&gold, 2600);
    let map = MemberMap::from_memory(&refs(&volumes), "big.part1.rar", None).unwrap();
    let piece = map.members[0].pieces[2].clone();
    let hole = piece.packed.start + 1000..piece.packed.start + 1500;
    let (mut reader, gate, _) =
        waiting_reader(&volumes, &[(2, hole.clone())], &map, 3000, MapOptions::new("big.part1.rar"));
    let mut out = Vec::new();
    let error = drive(&mut reader, &gate, &mut out).unwrap_err();
    let ExtractFromError::Hole { out: reached, volume, packed } = error else { panic!("{error:?}") };
    // Part 2 (output 5200..7800) is checked, so its bytes before the hole were held back, never returned.
    assert_eq!((reached, volume, packed), (5200, 2, hole.start));
    assert_eq!(out, &gold[3000..5200]);
    assert_eq!(reader.position(), 5200);
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(reader.poll_read(&mut cx, &mut [0; 4]), Poll::Ready(Err(ExtractFromError::AlreadyFailed))));
    // Switching to another copy from the reported offset completes the member.
    let rest = extract(&volumes, &map, 0, reached, None);
    out.extend(rest);
    assert_eq!(out, &gold[3000..]);
    // The last part has no check of its own, so it streams up to the hole.
    let last = map.members[0].pieces[3].clone();
    let hole = last.packed.start + 1000..last.packed.start + 1500;
    let (mut reader, gate, _) = waiting_reader(&volumes, &[(3, hole)], &map, 3000, MapOptions::new("big.part1.rar"));
    let mut out = Vec::new();
    let error = drive(&mut reader, &gate, &mut out).unwrap_err();
    assert!(matches!(error, ExtractFromError::Hole { out: 8800, volume: 3, .. }), "{error:?}");
    assert_eq!(out, &gold[3000..8800]);

    // An encrypted member: the hole is in the block before the start, so nothing was produced yet.
    let gold = data(9_999, 11);
    let volumes = rar5_encrypted(&gold, &[2600, 5203, 7801], true);
    let map = MemberMap::from_memory(&refs(&volumes), "e.part1.rar", None).unwrap();
    let piece = map.members[0].pieces[1].clone();
    let options = MapOptions::new("e.part1.rar").password(Some("pw"));
    let at = piece.packed.start + (4000 - 16 - 2600);
    let (mut reader, gate, _) = waiting_reader(&volumes, &[(1, at..at + 16)], &map, 4000, options);
    let error = drive(&mut reader, &gate, &mut Vec::new()).unwrap_err();
    assert!(matches!(error, ExtractFromError::Hole { out: 4000, volume: 1, .. }), "{error:?}");

    // A missing volume is typed too.
    let gold = data(10_000, 7);
    let volumes = rar5_split(&gold, 2600);
    let map = MemberMap::from_memory(&refs(&volumes), "big.part1.rar", None).unwrap();
    let (mut reader, gate, _) = waiting_reader(&volumes[..3], &[], &map, 7000, MapOptions::new("big.part1.rar"));
    let mut out = Vec::new();
    let error = drive(&mut reader, &gate, &mut out).unwrap_err();
    assert!(matches!(error, ExtractFromError::MissingVolume { out: 7800, volume: 3 }), "{error:?}");
    assert_eq!(out, &gold[7000..7800]);
}

// ---- Review regressions ----

fn extract_with(
    volumes: &[Vec<u8>],
    map: &MemberMap,
    at: u64,
    options: MapOptions,
) -> (Result<ExtractedFrom, ExtractFromError>, Vec<u8>) {
    let mut out = Vec::new();
    let result = extract_member_from_with(&refs(volumes), map, 0, at, options, &mut out);
    (result, out)
}

// Catches a checked part's earlier chunks being released before its check fails.
#[test]
fn a_checked_part_is_held_back_until_its_check_passes() {
    let gold = data(10_000, 7);
    let volumes = rar5_split(&gold, 2600);
    let map = MemberMap::from_memory(&refs(&volumes), "big.part1.rar", None).unwrap();
    let piece = map.members[0].pieces[2].clone();
    let mut bad = volumes.clone();
    bad[2][piece.packed.start as usize + 100] ^= 0x40;
    let mut options = MapOptions::new("big.part1.rar");
    options.limits.read_chunk = 64;
    let (result, out) = extract_with(&bad, &map, 3000, options.clone());
    let error = result.unwrap_err();
    assert!(
        matches!(error, ExtractFromError::PartBad { out: 5200, released: false, volume: 2, part: 2, ref bad, .. } if *bad == (5200..7800)),
        "{error:?}"
    );
    assert_eq!(out, &gold[3000..5200], "nothing of the bad part reaches the sink");

    // Over a waiting source with poll_read, too.
    let (mut reader, gate, _) = waiting_reader(&bad, &[], &map, 3000, options.clone());
    let mut got = Vec::new();
    assert!(matches!(drive(&mut reader, &gate, &mut got), Err(ExtractFromError::PartBad { out: 5200, .. })));
    assert_eq!(got, &gold[3000..5200]);

    // A good part still streams in full with small reads.
    let (result, out) = extract_with(&volumes, &map, 3000, options.clone());
    assert_eq!(result.unwrap().written, 7000);
    assert_eq!(out, &gold[3000..]);

    // A part larger than the hold cap streams unchecked; the error then says so and points back to its start.
    options.part_hold_bytes = 100;
    let (result, out) = extract_with(&bad, &map, 3000, options);
    let error = result.unwrap_err();
    assert!(matches!(error, ExtractFromError::PartBad { out: 5200, released: true, .. }), "{error:?}");
    assert!(out.len() > 2200, "the unchecked part was released");
    assert_eq!(&out[..2200], &gold[3000..5200]);

    // A wrong RAR 5.0 password without a check value releases nothing either.
    let gold = data(3000, 2);
    let volumes = rar5_encrypted(&gold, &[1000, 2000], false);
    let map = MemberMap::from_memory(&refs(&volumes), "e.part1.rar", None).unwrap();
    let mut options = MapOptions::new("e.part1.rar").password(Some("wrong"));
    options.limits.read_chunk = 64;
    let (result, out) = extract_with(&volumes, &map, 0, options);
    assert!(matches!(result, Err(ExtractFromError::PartBad { out: 0, released: false, part: 0, .. })), "{result:?}");
    assert!(out.is_empty());
}

// Catches an inconsistent public map panicking or reading header bytes as data.
#[test]
fn inconsistent_maps_are_malformed() {
    let gold = data(10_000, 7);
    let volumes = rar5_split(&gold, 2600);
    let good = MemberMap::from_memory(&refs(&volumes), "big.part1.rar", None).unwrap();
    let malformed = |edit: &dyn Fn(&mut MapMember)| {
        let mut map = good.clone();
        edit(&mut map.members[0]);
        let error = extract_err(&volumes, &map, 0, 0, Some("pw"));
        assert!(matches!(error, ExtractFromError::Malformed(_)), "{error:?}");
    };
    // A gap between pieces.
    malformed(&|m| {
        m.pieces[1].packed.start += 10;
        m.pieces[1].stream_offset += 10;
    });
    // Pieces out of order.
    malformed(&|m| m.pieces.swap(1, 2));
    // An inverted packed range.
    malformed(&|m| m.pieces[1].packed = m.pieces[1].packed.end..m.pieces[1].packed.start);
    // Encrypted data mapped as plain.
    malformed(&|m| m.encrypted = true);
    // Plain mapping with cipher parameters, and CBC without them.
    malformed(&|m| m.cipher = Some(CipherParams::Rar4 { salt: [0; 8] }));
    malformed(&|m| {
        m.encrypted = true;
        m.mapping = OutputMapping::CbcBlocks;
    });
    // An output range that is not what the piece carries.
    malformed(&|m| m.pieces[2].out = Some(0..10));
    // An offset overflow.
    malformed(&|m| m.pieces[3].packed = 0..u64::MAX);
}

// Catches a read with an unproven password being indistinguishable from a verified one.
#[test]
fn password_verification_is_reported() {
    let gold = data(1000, 13);
    let volumes = r4_aes(&gold, &[333, 400, 275]);
    let map = MemberMap::from_memory(&refs(&volumes), "a.part01.rar", None).unwrap();
    let run = |volumes: &[Vec<u8>], map: &MemberMap, at, pw| {
        extract_member_from(&refs(volumes), map, 0, at, Some(pw), &mut Vec::new()).unwrap().password_verified
    };
    assert!(!run(&volumes, &map, 500, "pw"));
    assert!(!run(&volumes, &map, 500, "wrong"), "a wrong RAR 4.x password is silent past offset 0");
    assert!(run(&volumes, &map, 0, "pw"), "the member CRC proves it from offset 0");

    let gold = data(3000, 2);
    let checked = rar5_encrypted(&gold, &[1000], true);
    let map = MemberMap::from_memory(&refs(&checked), "e.part1.rar", None).unwrap();
    assert!(run(&checked, &map, 2500, "pw"), "the check value proves it");
    let unchecked = rar5_encrypted(&gold, &[1000], false);
    let map = MemberMap::from_memory(&refs(&unchecked), "e.part1.rar", None).unwrap();
    assert!(!run(&unchecked, &map, 2500, "pw"), "no whole part is covered");
    assert!(!run(&unchecked, &map, 2500, "wrong"));
    assert!(run(&unchecked, &map, 0, "pw"), "a keyed part check proves it");

    let plain = data(5000, 7);
    let split = rar5_split(&plain, 2600);
    let map = MemberMap::from_memory(&refs(&split), "big.part1.rar", None).unwrap();
    assert!(run(&split, &map, 4000, "unused"));

    use zipfast::zip::write::{AesStrength, AesVariant};
    let zip = vec![winzip_aes(&plain, AesStrength::Aes256, AesVariant::Ae2)];
    let map = MemberMap::from_memory(&refs(&zip), "x.zip", None).unwrap();
    assert!(run(&zip, &map, 4000, "pw"));

    // MemberReader reports it as well.
    let map = MemberMap::from_memory(&refs(&unchecked), "e.part1.rar", None).unwrap();
    let options = MapOptions::new("e.part1.rar").password(Some("pw"));
    let (mut reader, gate, _) = waiting_reader(&unchecked, &[], &map, 2500, options);
    drive(&mut reader, &gate, &mut Vec::new()).unwrap();
    assert!(!reader.password_verified());
}

// Catches WinZip AES key derivation escaping the KDF budget.
#[test]
fn winzip_aes_key_derivation_is_charged() {
    use zipfast::zip::write::{AesStrength, AesVariant};
    let zip = vec![winzip_aes(&data(100, 1), AesStrength::Aes256, AesVariant::Ae1)];
    let map = MemberMap::from_memory(&refs(&zip), "x.zip", None).unwrap();
    let mut options = MapOptions::new("x.zip").password(Some("pw"));
    options.limits.kdf_session_blocks = 1000;
    let (result, _) = extract_with(&zip, &map, 10, options);
    assert!(
        matches!(
            result,
            Err(ExtractFromError::Limit { resource: zipfast::progressive::Resource::KdfSessionBlocks, .. })
        ),
        "{result:?}"
    );
}

// Catches a held part that outlives the stream making its bytes vanish from an Ok read.
#[test]
fn pieces_must_fill_the_packed_stream_and_finish_on_a_final_part() {
    let gold = data(10_000, 7);
    let volumes = rar5_split(&gold, 2600);
    let good = MemberMap::from_memory(&refs(&volumes), "big.part1.rar", None).unwrap();
    let malformed = |edit: &dyn Fn(&mut MapMember), at: u64| {
        let mut map = good.clone();
        edit(&mut map.members[0]);
        let mut out = Vec::new();
        let result = extract_member_from(&refs(&volumes), &map, 0, at, None, &mut out);
        assert!(matches!(result, Err(ExtractFromError::Malformed(_))), "offset {at}: {result:?}");
    };
    // The reviewed case: the last piece carries its own check, is not final, and runs past the stream's end, so it
    // would be held and never released.
    let held_forever = |m: &mut MapMember| {
        let last = m.pieces.last_mut().unwrap();
        last.final_part = false;
        last.checks.crc32 = Some(crc32fast::hash(&gold[7800..]));
        last.packed.end += 100;
    };
    for at in [7800, 8000] {
        malformed(&held_forever, at);
        malformed(
            &|m| {
                held_forever(m);
                m.complete = false;
            },
            at,
        );
    }
    // Only the last piece may be final, and a complete member must end on a final piece.
    malformed(&|m| m.pieces[1].final_part = true, 0);
    malformed(&|m| m.pieces[3].final_part = false, 0);
    // A complete member's pieces must sum to its packed stream exactly.
    malformed(&|m| m.pieces[3].packed.end -= 1, 0);
    // An incomplete map's pieces may stop short.
    let partial = MemberMap::from_memory(&refs(&volumes[..2]), "big.part1.rar", None).unwrap();
    assert!(matches!(extract_err(&volumes, &partial, 0, 0, None), ExtractFromError::IncompleteMember { out: 5200 }));
}

// Catches held-back plaintext escaping the TempBytes budget, or a released hold not returning its charge.
#[test]
fn held_parts_are_charged_to_temp_bytes_and_refunded() {
    let gold = data(10_000, 7);
    let volumes = rar5_split(&gold, 2600);
    let map = MemberMap::from_memory(&refs(&volumes), "big.part1.rar", None).unwrap();
    let piece = map.members[0].pieces[2].clone();
    let mut bad = volumes.clone();
    bad[2][piece.packed.start as usize + 100] ^= 0x40;
    // Each 2,600-byte part reserves 2,616 bytes (one CBC block of slack). Parts 0 and 1 are held and released before
    // part 2 is held, so one reservation's worth suffices only if each is returned.
    for (temp, released) in [(2616, false), (2615, true)] {
        let mut options = MapOptions::new("big.part1.rar");
        options.limits.temp_bytes = temp;
        options.limits.read_chunk = 64;
        let (result, out) = extract_with(&bad, &map, 0, options.clone());
        let error = result.unwrap_err();
        assert!(
            matches!(error, ExtractFromError::PartBad { out: 5200, released: r, part: 2, .. } if r == released),
            "temp {temp}: {error:?}"
        );
        assert_eq!(&out[..5200], &gold[..5200]);
        assert_eq!(out.len() > 5200, released, "temp {temp}");
        // An intact read under the same budget succeeds either way.
        let (result, out) = extract_with(&volumes, &map, 0, options);
        assert_eq!(result.unwrap().written, 10_000);
        assert_eq!(out, gold);
    }
}

// A map that stops at a damaged header (MapEnd::Damaged) is incomplete: a member split across it cannot be read,
// members whose headers all came before it can.
#[test]
fn damaged_maps_are_incomplete() {
    let gold = data(10_000, 7);
    let mut volumes = rar5_split(&gold, 2600);
    // Volume 2's file header fails its checksum.
    let header_at = SIG.len() + main_block(true, Some(2)).len() + 6;
    volumes[2][header_at] ^= 0x55;
    let map = MemberMap::from_memory(&refs(&volumes), "big.part1.rar", None).unwrap();
    assert!(matches!(map.end, MapEnd::Damaged { volume: 2, .. }), "{:?}", map.end);
    assert!(!map.members[0].complete);
    for at in [0, 3000, 9000] {
        let error = extract_err(&volumes, &map, 0, at, None);
        assert!(matches!(error, ExtractFromError::IncompleteMember { out: 5200 }), "offset {at}: {error:?}");
    }

    let a = data(3000, 1);
    let mut bytes = common::archive(&[FileSpec::new("a.bin", &a), FileSpec::new("b.bin", b"after the damage")]);
    let good = MemberMap::from_memory(&[&bytes], "x.rar", None).unwrap();
    let b_header = good.members[1].pieces[0].header.start as usize;
    bytes[b_header + 6] ^= 0x55;
    let volumes = vec![bytes];
    let map = MemberMap::from_memory(&refs(&volumes), "x.rar", None).unwrap();
    assert!(matches!(map.end, MapEnd::Damaged { volume: 0, .. }), "{:?}", map.end);
    assert_eq!(map.members.len(), 1);
    assert_eq!(extract(&volumes, &map, 0, 1234, None), &a[1234..]);
}

// ---- Alt takeover into a persistent partial ----

#[cfg(all(feature = "persistent-partials", any(target_os = "linux", target_os = "macos")))]
mod takeover {
    use super::*;
    use std::{ffi::OsString, fs, path::Path};
    use zipfast::partial::*;
    use zipfast::progressive::*;

    struct Source {
        index: u32,
        bytes: Vec<u8>,
        holes: Vec<Range<u64>>,
    }
    impl RangeSource for Source {
        fn info(&self) -> SourceInfo {
            SourceInfo {
                id: SourceId(self.index as u128 + 1),
                generation: 0,
                extent: self.bytes.len() as u64,
                length: SourceLength::Final(self.bytes.len() as u64),
            }
        }
        fn backing_files(&self) -> &[File] {
            &[]
        }
        fn read_at(&mut self, at: u64, buf: &mut [u8], _: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
            let mut end = (at + buf.len() as u64).min(self.bytes.len() as u64);
            for hole in &self.holes {
                if hole.start <= at && at < hole.end {
                    return Ok(RangeRead::Hole { len: (hole.end - at).min(buf.len() as u64) });
                }
                if hole.start > at {
                    end = end.min(hole.start);
                }
            }
            let n = (end - at) as usize;
            buf[..n].copy_from_slice(&self.bytes[at as usize..end as usize]);
            Ok(RangeRead::Filled { count: n })
        }
    }
    struct Set {
        volumes: Vec<Option<Source>>,
    }
    impl VolumeSource for Set {
        fn protection(&mut self) -> ProgressiveResult<ProtectionDeclaration> {
            Ok(ProtectionDeclaration::Complete {
                epoch: 1,
                inventory: ProtectionInventory {
                    volumes: (0..self.volumes.len() as u32)
                        .map(|index| ProtectedVolume { index, name: name(index), backing: VolumeBacking::NonFile })
                        .collect(),
                    auxiliary_paths: Vec::new(),
                },
            })
        }
        fn volume(&mut self, request: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
            Ok(VolumeAnswer::Ready(Box::new(self.volumes[request.index as usize].take().unwrap())))
        }
    }
    fn name(index: u32) -> OsString {
        format!("set.part{:02}.rar", index + 1).into()
    }
    #[derive(Default)]
    struct Anchors(Mutex<Vec<StateAnchor>>);
    impl StateAnchorStore for Anchors {
        fn current(&self, member: &MemberKey) -> PartialResult<Option<StateAnchor>> {
            Ok(self.0.lock().unwrap().iter().find(|a| a.member() == member).cloned())
        }
        fn compare_exchange(
            &self,
            member: &MemberKey,
            expected: Option<&StateAnchor>,
            next: &StateAnchor,
        ) -> PartialResult<()> {
            let mut anchors = self.0.lock().unwrap();
            let index = anchors.iter().position(|a| a.member() == member);
            if index.map(|i| &anchors[i]) != expected {
                return Err(PartialError::new(PartialErrorKind::AnchorConflict));
            }
            match index {
                Some(index) => anchors[index] = next.clone(),
                None => anchors.push(next.clone()),
            }
            Ok(())
        }
    }

    /// Extracts set A (plain RAR5 store of `gold`) into a persistent partial while every packed byte carrying output
    /// from `cut` on is a permanent hole, as when the primary download died there. Returns the partial file.
    fn primary_died_at(dir: &Path, gold: &[u8], cut: u64) -> PartialFile {
        let volumes = rar5_split(gold, 2600);
        let map = MemberMap::from_memory(&refs(&volumes), name(0), None).unwrap();
        let sources = volumes
            .into_iter()
            .enumerate()
            .map(|(i, bytes)| {
                let holes = map.members[0]
                    .pieces
                    .iter()
                    .filter(|p| p.volume == i as u32)
                    .filter_map(|p| {
                        let out = p.out.clone().unwrap();
                        (out.end > cut).then(|| p.packed.start + cut.saturating_sub(out.start)..p.packed.end)
                    })
                    .collect();
                Some(Source { index: i as u32, bytes, holes })
            })
            .collect();
        let mut options = ProgressiveOptions::new(
            zipfast::extract::Options {
                mode: zipfast::extract::Mode::Extract,
                dest: dir.join("out"),
                overwrite: zipfast::extract::Overwrite::Always,
                flatten: false,
                threads: Some(1),
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
                encrypted_links: Default::default(),
                damaged_input: Default::default(),
                unsupported_filters: Default::default(),
                salvage_truncated_zip: false,
                unix_modes: Default::default(),
                backslashes: Default::default(),
            },
            name(0),
        );
        options.hole_policy = HolePolicy::PartialStored { fill: HoleFill::Sparse };
        let partial = PartialOptions {
            binding: ArchiveBinding { job: [1; 16], archive: [2; 32] },
            naming: PartialNaming::ArchivePath,
            state_dir: dir.join("state"),
            limits: PartialLimits::default(),
            anchors: Arc::new(Anchors::default()),
            control: SessionControl::default(),
        };
        let mut session =
            ProgressiveSession::new_partial(Box::new(Set { volumes: sources }), options, partial).unwrap();
        let mut files = Vec::new();
        for _ in 0..100_000 {
            match session.poll_event(&mut Context::from_waker(Waker::noop())) {
                Poll::Ready(Ok(Some(ProgressiveEvent::PartialReady { member, .. }))) => {
                    files.push(session.partial_file(&member).unwrap())
                }
                Poll::Ready(Ok(None)) => return files.remove(0),
                Poll::Ready(Err(e)) => panic!("{e:?}"),
                _ => {}
            }
        }
        panic!("session did not finish")
    }

    fn verify(file: &mut PartialFile) -> Verdict {
        for _ in 0..10_000 {
            if let Poll::Ready(result) = file.poll_verify(&mut Context::from_waker(Waker::noop())) {
                return result.unwrap();
            }
        }
        panic!("verification did not finish")
    }

    #[test]
    fn alt_copy_fills_the_rest_of_a_partial_and_it_verifies() {
        let gold = data(9_999, 11);
        let encrypted = rar5_encrypted(&gold, &[3001, 6400], true);
        let rar4 = r4_aes(&gold, &[4000, 3333, 2667]);
        for (alt, first) in [(&encrypted, "alt.part1.rar"), (&rar4, "alt.part01.rar")] {
            for cut in [0u64, 4321, 5200, 9_998] {
                let dir = tempfile::tempdir().unwrap();
                let mut a = primary_died_at(dir.path(), &gold, cut);
                assert_eq!(a.remaining().unwrap(), vec![cut..9_999], "cut {cut}");
                assert!(matches!(verify(&mut a), Verdict::Incomplete { .. }));

                let map = MemberMap::from_memory(&refs(alt), first, None).unwrap();
                let mut writer = a.fill_writer(cut).unwrap();
                let done = extract_member_from(&refs(alt), &map, 0, cut, Some("pw"), &mut writer).unwrap();
                writer.finish().unwrap();
                assert_eq!(done.written, 9_999 - cut);
                // RAR 4.x has no password check value: from an offset other than 0 only the partial's verify can
                // tell a wrong password.
                let rar4_suffix = std::ptr::eq(alt, &rar4) && cut != 0;
                assert_eq!(done.password_verified, !rar4_suffix, "cut {cut}");
                assert!(a.remaining().unwrap().is_empty());
                assert!(matches!(verify(&mut a), Verdict::Ok { .. }), "cut {cut}");
                assert_eq!(fs::read(dir.path().join("out/big.bin")).unwrap(), gold);
            }
        }
    }
}
