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

//! Member maps over memory and over a waiting volume source.
mod common;

use common::{FileSpec, SIG, archive, block, end_block, file_block, main_block};
use std::{
    fs::File,
    ops::Range,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};
use zipfast::map::*;
use zipfast::progressive::{
    ProgressiveResult, RangeRead, RangeSource, SourceId, SourceInfo, SourceLength, VolumeAnswer, VolumeRequest,
    VolumeSource,
};

fn refs(volumes: &[Vec<u8>]) -> Vec<&[u8]> {
    volumes.iter().map(Vec::as_slice).collect()
}

fn slice(volumes: &[Vec<u8>], spans: &[PackedSpan]) -> Vec<u8> {
    spans
        .iter()
        .flat_map(|s| volumes[s.volume as usize][s.packed.start as usize..s.packed.end as usize].iter().copied())
        .collect()
}

fn data(len: usize, seed: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + seed) % 251) as u8).collect()
}

/// Every piece's packed range holds the bytes the spans of its output range point at.
fn assert_round_trips(member: &MapMember, volumes: &[Vec<u8>], gold: &[u8], ranges: &[Range<u64>]) {
    for range in ranges {
        let spans = member.packed_spans(range.clone()).unwrap();
        let end = (range.end as usize).min(gold.len());
        let start = (range.start as usize).min(end);
        assert_eq!(slice(volumes, &spans), &gold[start..end], "range {range:?}");
    }
}

#[test]
fn rar5_single_volume_lists_exact_pieces_and_spans() {
    let a = data(5000, 1);
    let b = b"second member".to_vec();
    let mut c = FileSpec::new("c.bin", b"compressed payload stand-in");
    c.method = 3;
    c.size = Some(1000);
    let bytes = archive(&[FileSpec::new("a.bin", &a), FileSpec::new("dir/b.txt", &b), c]);
    let map = MemberMap::from_memory(&[&bytes], "x.rar", None).unwrap();
    assert_eq!(map.format, MapFormat::Rar5);
    assert!(map.complete);
    assert_eq!(map.end, MapEnd::Complete);
    assert_eq!(map.volumes, 1);
    assert!(!map.header_encrypted);
    assert_eq!(map.members.len(), 3);

    let first = &map.members[0];
    assert_eq!(first.ordinal, 0);
    assert_eq!(first.raw_name, b"a.bin");
    assert_eq!(first.name.as_deref(), Some("a.bin"));
    assert_eq!(first.method, MapMethod::Stored);
    assert_eq!(first.mapping, OutputMapping::Direct);
    assert_eq!(first.unpacked_size, Some(5000));
    assert_eq!(first.mtime, Some((1_700_000_000, 0)));
    assert_eq!(first.unix_mode, Some(0o644));
    assert!(first.complete && !first.encrypted && first.cipher.is_none());
    assert_eq!(first.checks.unwrap().crc32, Some(crc32fast::hash(&a)));
    assert_eq!(first.pieces.len(), 1);
    let piece = &first.pieces[0];
    assert_eq!((piece.volume, piece.stream_offset, piece.final_part), (0, 0, true));
    assert_eq!(piece.out, Some(0..5000));
    assert_eq!(piece.header.start, SIG.len() as u64 + main_block(false, None).len() as u64);
    assert_eq!(piece.header.end, piece.packed.start);
    assert_eq!(&bytes[piece.packed.start as usize..piece.packed.end as usize], &a[..]);
    let volumes = vec![bytes.clone()];
    assert_round_trips(first, &volumes, &a, &[0..5000, 100..300, 4900..9999, 7000..8000, 3..3]);

    assert_eq!(map.members[1].name.as_deref(), Some("dir/b.txt"));
    assert_eq!(map.members[1].pieces[0].header.start, piece.packed.end);
    assert_round_trips(&map.members[1], &volumes, &b, &[0..13, 2..5]);

    let packed = &map.members[2];
    assert_eq!(packed.method, MapMethod::Compressed { id: 3 });
    assert_eq!(packed.mapping, OutputMapping::None);
    assert_eq!(packed.unpacked_size, Some(1000));
    assert_eq!(packed.pieces[0].out, None);
    assert_eq!(packed.packed_spans(0..10), None);
}

fn split_fixture() -> (Vec<u8>, Vec<Vec<u8>>) {
    let gold = data(10_000, 7);
    let spec = FileSpec::new("big.bin", &gold);
    let volumes = common::volumes(&spec, 2600);
    (gold, volumes)
}

#[test]
fn rar5_multi_volume_stored_pieces_and_spans_round_trip() {
    let (gold, volumes) = split_fixture();
    assert_eq!(volumes.len(), 4);
    let map = MemberMap::from_memory(&refs(&volumes), "big.part1.rar", None).unwrap();
    assert!(map.complete);
    assert_eq!(map.volumes, 4);
    assert_eq!(map.members.len(), 1);
    let member = &map.members[0];
    assert!(member.complete);
    assert_eq!(member.packed_size, 10_000);
    assert_eq!(member.checks.unwrap().crc32, Some(crc32fast::hash(&gold)));
    let starts: Vec<u64> = member.pieces.iter().map(|p| p.stream_offset).collect();
    assert_eq!(starts, [0, 2600, 5200, 7800]);
    for (i, piece) in member.pieces.iter().enumerate() {
        assert_eq!(piece.volume, i as u32);
        let end = (piece.stream_offset + 2600).min(10_000);
        assert_eq!(piece.out, Some(piece.stream_offset..end));
        assert_eq!(piece.final_part, i == 3);
        let part = &gold[piece.stream_offset as usize..end as usize];
        assert_eq!(&volumes[i][piece.packed.start as usize..piece.packed.end as usize], part);
        if i < 3 {
            assert_eq!(piece.checks.crc32, Some(crc32fast::hash(part)));
        }
    }
    assert_round_trips(member, &volumes, &gold, &[0..10_000, 2500..2700, 2599..7801, 9999..10_000, 5200..5201]);
    let spans = member.packed_spans(2500..2700).unwrap();
    assert_eq!(spans.iter().map(|s| s.volume).collect::<Vec<_>>(), [0, 1]);
    assert_eq!(spans[0].stream, 2500..2600);
    assert_eq!(spans[1].stream, 2600..2700);
}

#[test]
fn partial_volume_set_is_an_incomplete_map_with_the_pieces_seen() {
    let (gold, volumes) = split_fixture();
    let map = MemberMap::from_memory(&refs(&volumes[..2]), "big.part1.rar", None).unwrap();
    assert!(!map.complete);
    assert_eq!(map.end, MapEnd::MissingVolume { volume: 2 });
    assert_eq!(map.volumes, 2);
    let member = &map.members[0];
    assert!(!member.complete);
    assert_eq!(member.checks, None);
    assert_eq!(member.unpacked_size, Some(10_000));
    assert_eq!(member.pieces.len(), 2);
    let spans = member.packed_spans(0..10_000).unwrap();
    assert_eq!(spans.last().unwrap().stream.end, 5200);
    assert_eq!(slice(&volumes, &spans), &gold[..5200]);
}

#[test]
fn a_volume_cut_short_keeps_the_headers_read() {
    let a = data(5000, 3);
    let bytes = archive(&[FileSpec::new("a.bin", &a), FileSpec::new("b.bin", b"later")]);
    let map = MemberMap::from_memory(&[&bytes[..3000]], "x.rar", None).unwrap();
    assert!(!map.complete);
    let piece_end = map.members[0].pieces[0].packed.end;
    assert_eq!(map.end, MapEnd::Truncated { volume: 0, offset: piece_end });
    assert_eq!(map.members.len(), 1);
}

// ---- Encrypted RAR5 stored data ----

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
/// The RAR5 password check value: PBKDF2-HMAC-SHA256 continued 32 rounds past the key, folded to 8 bytes.
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

/// One encrypted stored member "e.bin" of `size` bytes, its ciphertext cut at the stream offsets `cuts`.
fn encrypted_volumes(size: usize, cuts: &[usize]) -> (Vec<u8>, [u8; 8], Vec<Vec<u8>>) {
    encrypted_volumes_with(size, cuts, IV, SALT, 1)
}

/// The same member with its encryption record's IV, salt and KDF count chosen. The password check value always
/// belongs to `SALT` and count 1; maps do not test it.
fn encrypted_volumes_with(
    size: usize,
    cuts: &[usize],
    iv: [u8; 16],
    salt: [u8; 16],
    kdf: u8,
) -> (Vec<u8>, [u8; 8], Vec<Vec<u8>>) {
    let plain = data(size, 11);
    let (key, hash_key) = zipfast::crypto::derive_rar5_key_and_hash_key("pw", 1, &SALT, None).unwrap();
    let mut padded = plain.clone();
    padded.resize(size.div_ceil(16) * 16, 0);
    let cipher = zipfast::crypto::encrypt_cbc(&key, &iv, &padded).unwrap();
    let check = password_check("pw", 1);
    let mut extra = vec![48, 1, 0, 3, kdf];
    extra.extend(salt);
    extra.extend(iv);
    extra.extend(check);
    extra.extend(&zipfast::crypto::sha256(&check)[..4]);
    let mut spec = FileSpec::new("e.bin", &cipher);
    spec.size = Some(size as u64);
    spec.extra = extra;
    let bounds: Vec<usize> = std::iter::once(0).chain(cuts.iter().copied()).chain([cipher.len()]).collect();
    let volumes = bounds
        .windows(2)
        .enumerate()
        .map(|(index, pair)| {
            let part = &cipher[pair[0]..pair[1]];
            let last = pair[1] == cipher.len();
            let crc = zipfast::crypto::rar5_tweak_crc32(crc32fast::hash(if last { &plain } else { part }), &hash_key);
            let mut bytes = SIG.to_vec();
            bytes.extend(main_block(true, Some(index as u64)));
            bytes.extend(file_block(&spec, part, crc, index > 0, !last));
            bytes.extend(end_block(!last));
            bytes
        })
        .collect();
    (plain, check, volumes)
}

/// Decrypts the block-widened spans of `range` and compares them with the plaintext.
fn assert_cbc_round_trips(
    member: &MapMember,
    volumes: &[Vec<u8>],
    plain: &[u8],
    key: &[u8],
    iv: [u8; 16],
    ranges: &[Range<u64>],
) {
    for range in ranges {
        let spans = member.packed_spans(range.clone()).unwrap();
        let first = range.start & !15;
        let stream = spans.first().unwrap().stream.start..spans.last().unwrap().stream.end;
        assert_eq!(stream.start, first.saturating_sub(16), "range {range:?}");
        assert_eq!(stream.end, range.end.min(plain.len() as u64).next_multiple_of(16), "range {range:?}");
        let cipher = slice(volumes, &spans);
        let (iv, body) =
            if stream.start == 0 { (iv, &cipher[..]) } else { (cipher[..16].try_into().unwrap(), &cipher[16..]) };
        let out = zipfast::crypto::decrypt_cbc(key, &iv, body).unwrap();
        let base = if stream.start == 0 { 0 } else { stream.start as usize + 16 };
        let (a, b) = (range.start as usize, (range.end as usize).min(plain.len()));
        assert_eq!(&out[a - base..b - base], &plain[a..b], "range {range:?}");
    }
}

#[test]
fn rar5_encrypted_stored_reports_cipher_params_and_block_widened_spans() {
    let (plain, check, volumes) = encrypted_volumes(3000, &[1000, 2000]);
    let map = MemberMap::from_memory(&refs(&volumes), "e.part1.rar", None).unwrap();
    assert!(map.complete && !map.header_encrypted);
    let member = &map.members[0];
    assert!(member.encrypted);
    assert_eq!(member.method, MapMethod::Stored);
    assert_eq!(member.mapping, OutputMapping::CbcBlocks);
    assert_eq!(member.packed_size, 3008);
    let sum: [u8; 4] = zipfast::crypto::sha256(&check)[..4].try_into().unwrap();
    assert_eq!(
        member.cipher,
        Some(CipherParams::Rar5 {
            kdf_count: 1,
            salt: SALT,
            iv: Some(IV),
            check: Some((check, sum)),
            keyed_checks: true
        })
    );
    assert!(member.checks.unwrap().keyed);
    let outs: Vec<_> = member.pieces.iter().map(|p| p.out.clone().unwrap()).collect();
    assert_eq!(outs, [0..1000, 1000..2000, 2000..3000]);
    assert_eq!(member.pieces[2].packed.end - member.pieces[2].packed.start, 1008);
    let key = zipfast::crypto::derive_rar5_key_and_hash_key("pw", 1, &SALT, None).unwrap().0;
    assert_cbc_round_trips(
        member,
        &volumes,
        &plain,
        &key,
        IV,
        &[0..5, 990..1010, 1500..1510, 2995..3000, 17..2050, 0..3000, 1008..1009, 2999..5000],
    );
    // A range starting in block 0 needs no earlier block; one in block 1 needs block 0.
    assert_eq!(member.packed_spans(3..20).unwrap()[0].stream, 0..32);
    assert_eq!(member.packed_spans(16..20).unwrap()[0].stream, 0..32);
    assert_eq!(member.packed_spans(40..41).unwrap()[0].stream, 16..48);
}

// ---- RAR5 encrypted headers (-hp) ----

const HP_PASSWORD: &str = "zipfast-test-only";
const HP_SALT: [u8; 16] = [0x53; 16];
const HP_CHECK: [u8; 12] = [0x17, 0x41, 0x9a, 0xfa, 0xa6, 0x98, 0xfd, 0x50, 0xa8, 0x4b, 0x9b, 0x32];

fn hp_archive(payload: &[u8]) -> Vec<u8> {
    let iv = [0x49; 16];
    let key = zipfast::crypto::derive_rar5_key_and_hash_key(HP_PASSWORD, 4, &HP_SALT, None).unwrap().0;
    let params = [&[0, 1, 4], HP_SALT.as_slice(), HP_CHECK.as_slice()].concat();
    let mut bytes = SIG.to_vec();
    bytes.extend(block(4, 0, &params, &[], &[], false));
    let spec = FileSpec::new("secret.bin", payload);
    for (mut header, data) in [
        (main_block(false, None), b"".as_slice()),
        (file_block(&spec, payload, crc32fast::hash(payload), false, false), payload),
        (end_block(false), b"".as_slice()),
    ] {
        header.truncate(header.len() - data.len());
        header.resize(header.len().next_multiple_of(16), 0);
        bytes.extend(iv);
        bytes.extend(zipfast::crypto::encrypt_cbc(&key, &iv, &header).unwrap());
        bytes.extend(data);
    }
    bytes
}

#[test]
fn rar5_encrypted_headers_need_the_right_password() {
    let payload = data(700, 5);
    let bytes = hp_archive(&payload);
    let map = MemberMap::from_memory(&[&bytes], "hp.rar", Some(HP_PASSWORD)).unwrap();
    assert!(map.complete && map.header_encrypted);
    assert_eq!(
        map.header_cipher,
        Some(CipherParams::Rar5 {
            kdf_count: 4,
            salt: HP_SALT,
            iv: None,
            check: Some((HP_CHECK[..8].try_into().unwrap(), HP_CHECK[8..].try_into().unwrap())),
            keyed_checks: false,
        })
    );
    let member = &map.members[0];
    assert_eq!(member.name.as_deref(), Some("secret.bin"));
    assert!(!member.encrypted);
    let piece = &member.pieces[0];
    assert_eq!((piece.header.end - piece.header.start) % 16, 0, "header extent covers IV and padding");
    assert_eq!(&bytes[piece.packed.start as usize..piece.packed.end as usize], &payload[..]);
    assert_round_trips(member, std::slice::from_ref(&bytes), &payload, &[10..600, 0..700]);

    assert!(matches!(MemberMap::from_memory(&[&bytes], "hp.rar", Some("wrong")), Err(MapError::WrongPassword)));
    assert!(matches!(MemberMap::from_memory(&[&bytes], "hp.rar", None), Err(MapError::PasswordRequired)));
}

// ---- RAR4 ----

fn r4_block(kind: u8, flags: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0, 0, kind];
    bytes.extend(flags.to_le_bytes());
    bytes.extend(((body.len() + 7) as u16).to_le_bytes());
    bytes.extend(body);
    let crc = crc32fast::hash(&bytes[2..]) as u16;
    bytes[..2].copy_from_slice(&crc.to_le_bytes());
    bytes
}

fn r4_member(name: &[u8], data: &[u8], flags: u16, method: u8, size: usize, crc: u32) -> Vec<u8> {
    r4_member_version(name, data, flags, method, size, crc, 29)
}

fn r4_member_version(name: &[u8], data: &[u8], flags: u16, method: u8, size: usize, crc: u32, version: u8) -> Vec<u8> {
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
    r4_split_named(gold, chunk, b"one")
}

fn r4_split_named(gold: &[u8], chunk: usize, name: &[u8]) -> Vec<Vec<u8>> {
    let count = gold.len().div_ceil(chunk);
    gold.chunks(chunk)
        .enumerate()
        .map(|(i, payload)| {
            let flags = u16::from(i > 0) | (u16::from(i + 1 < count) * 2);
            let crc = crc32fast::hash(if i + 1 == count { gold } else { payload });
            let mut wire = b"Rar!\x1a\x07\0".to_vec();
            wire.extend(r4_block(0x73, 0x11 | if i == 0 { 0x100 } else { 0 }, &[0; 6]));
            wire.extend(r4_member(name, payload, flags, 0x30, gold.len(), crc));
            wire.extend(r4_block(0x7b, 0x4000 | u16::from(i + 1 < count), &[]));
            wire
        })
        .collect()
}

const R4_SALT: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

/// RAR4 stored member with AES data and, with `headers`, encrypted headers, its ciphertext cut at `cuts`.
fn r4_aes(gold: &[u8], headers: bool, cuts: &[usize]) -> Vec<Vec<u8>> {
    let (key, iv) = zipfast::crypto::derive_rar4_key_iv("pw", &R4_SALT);
    let mut padded = gold.to_vec();
    padded.resize(gold.len().next_multiple_of(16), 0xa5);
    let cipher = zipfast::crypto::encrypt_cbc(&key, &iv, &padded).unwrap();
    let enc_header = |mut bytes: Vec<u8>| {
        if !headers {
            return bytes;
        }
        bytes.resize(bytes.len().next_multiple_of(16), 0x5a);
        let mut wire = R4_SALT.to_vec();
        wire.extend(zipfast::crypto::encrypt_cbc(&key, &iv, &bytes).unwrap());
        wire
    };
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
            wire.extend(r4_block(0x73, 1 | if headers { 0x80 } else { 0 }, &[0; 6]));
            wire.extend(enc_header(r4_block(0x74, flags, &body)));
            wire.extend(payload);
            wire.extend(enc_header(r4_block(0x7b, 0x4000 | u16::from(i + 1 < cuts.len()), &[])));
            wire
        })
        .collect()
}

#[test]
fn rar4_single_volume_stored_and_compressed() {
    let gold = data(900, 2);
    let compressed = b"rar4 compressed bytes stand-in";
    let bytes = r4_archive(&[
        r4_member(b"one", &gold, 0, 0x30, gold.len(), crc32fast::hash(&gold)),
        r4_member(b"two", compressed, 0, 0x33, 4000, 0x1234_5678),
    ]);
    let map = MemberMap::from_memory(&[&bytes], "old.rar", None).unwrap();
    assert_eq!(map.format, MapFormat::Rar4);
    assert!(map.complete);
    assert_eq!(map.members.len(), 2);
    let one = &map.members[0];
    assert_eq!(one.name.as_deref(), Some("one"));
    assert_eq!(one.mapping, OutputMapping::Direct);
    assert_eq!(one.pieces[0].out, Some(0..900));
    assert_eq!(one.checks.unwrap().crc32, Some(crc32fast::hash(&gold)));
    assert_eq!(one.unix_mode, Some(0o100644));
    assert_round_trips(one, std::slice::from_ref(&bytes), &gold, &[0..900, 450..451]);
    let two = &map.members[1];
    assert_eq!(two.method, MapMethod::Compressed { id: 0x33 });
    assert_eq!(two.unpacked_size, Some(4000));
    assert_eq!(two.pieces[0].out, None);
    assert_eq!(&bytes[two.pieces[0].packed.start as usize..two.pieces[0].packed.end as usize], compressed);
    assert_eq!(two.packed_spans(0..10), None);
}

#[test]
fn rar4_split_stored_round_trips() {
    let gold = data(130, 9);
    let volumes = r4_split(&gold, 40);
    assert_eq!(volumes.len(), 4);
    let map = MemberMap::from_memory(&refs(&volumes), "old.part1.rar", None).unwrap();
    assert_eq!(map.format, MapFormat::Rar4);
    assert!(map.complete);
    let member = &map.members[0];
    assert_eq!(member.pieces.len(), 4);
    assert_eq!(
        member.pieces.iter().map(|p| p.out.clone().unwrap()).collect::<Vec<_>>(),
        [0..40, 40..80, 80..120, 120..130]
    );
    assert_round_trips(member, &volumes, &gold, &[0..130, 39..41, 1..129, 120..130]);
    let partial = MemberMap::from_memory(&refs(&volumes[..2]), "old.part1.rar", None).unwrap();
    assert_eq!(partial.end, MapEnd::MissingVolume { volume: 2 });
    assert_eq!(partial.members[0].pieces.len(), 2);
}

#[test]
fn rar4_encrypted_headers_and_data() {
    let gold = b"continuous CBC across two unaligned boundaries with arbitrary trailing padding";
    let (key, iv) = zipfast::crypto::derive_rar4_key_iv("pw", &R4_SALT);
    for headers in [false, true] {
        let volumes = r4_aes(gold, headers, &[29, 31, 20]);
        let password = headers.then_some("pw");
        let map = MemberMap::from_memory(&refs(&volumes), "a.part01.rar", password).unwrap();
        assert!(map.complete);
        assert_eq!(map.header_encrypted, headers);
        assert_eq!(map.header_cipher, headers.then_some(CipherParams::Rar4 { salt: R4_SALT }));
        let member = &map.members[0];
        assert!(member.encrypted);
        assert_eq!(member.cipher, Some(CipherParams::Rar4 { salt: R4_SALT }));
        assert_eq!(member.mapping, OutputMapping::CbcBlocks);
        assert_eq!(member.packed_size, 80);
        let plain = gold.as_slice();
        assert_cbc_round_trips(member, &volumes, plain, &key, iv, &[0..78, 0..1, 20..40, 60..78, 33..34]);
        if headers {
            assert!(matches!(
                MemberMap::from_memory(&refs(&volumes), "a.part01.rar", None),
                Err(MapError::PasswordRequired)
            ));
            let wrong = MemberMap::from_memory(&refs(&volumes), "a.part01.rar", Some("wrong password"));
            assert!(matches!(wrong, Err(MapError::WrongPassword)), "{wrong:?}");
        }
    }
}

// ---- A waiting volume source ----

#[derive(Default)]
struct Gate {
    ready: bool,
    wake: Option<Waker>,
    waits: usize,
}

struct Bytes {
    index: u32,
    data: Vec<u8>,
    holes: Vec<Range<u64>>,
    chunk: usize,
    gate: Arc<Mutex<Gate>>,
    reads: Reads,
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
        self.reads.lock().unwrap().push((self.index, at, n));
        Ok(RangeRead::Filled { count: n })
    }
}

struct Provider {
    volumes: Vec<Option<Bytes>>,
    gate: Arc<Mutex<Gate>>,
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
        Ok(self
            .volumes
            .get_mut(r.index as usize)
            .and_then(Option::take)
            .map_or(VolumeAnswer::Missing, |b| VolumeAnswer::Ready(Box::new(b))))
    }
}

type Reads = Arc<Mutex<Vec<(u32, u64, usize)>>>;

fn waiting_builder(
    volumes: &[Vec<u8>],
    holes: &[(u32, Range<u64>)],
    options: MapOptions,
) -> (MapBuilder, Arc<Mutex<Gate>>, Reads) {
    let gate = Arc::new(Mutex::new(Gate::default()));
    let reads = Arc::new(Mutex::new(Vec::new()));
    let volumes = volumes
        .iter()
        .enumerate()
        .map(|(i, data)| {
            Some(Bytes {
                index: i as u32,
                data: data.clone(),
                holes: holes.iter().filter(|(v, _)| *v == i as u32).map(|(_, r)| r.clone()).collect(),
                chunk: 7,
                gate: gate.clone(),
                reads: reads.clone(),
            })
        })
        .collect();
    (MapBuilder::new(Box::new(Provider { volumes, gate: gate.clone() }), options), gate, reads)
}

/// Polls to completion, releasing each wait through the waker the provider kept.
fn drive(builder: &mut MapBuilder, gate: &Arc<Mutex<Gate>>) -> Result<MemberMap, MapError> {
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..1_000_000 {
        match builder.poll_map(&mut cx) {
            Poll::Ready(result) => return result,
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
    panic!("map did not finish")
}

#[test]
fn volume_source_with_waits_matches_memory() {
    let (_, volumes) = split_fixture();
    let expected = MemberMap::from_memory(&refs(&volumes), "big.part1.rar", None).unwrap();
    let (mut builder, gate, reads) = waiting_builder(&volumes, &[], MapOptions::new("big.part1.rar"));
    let map = drive(&mut builder, &gate).unwrap();
    assert_eq!(map, expected);
    assert!(gate.lock().unwrap().waits > 10);
    assert!(matches!(
        builder.poll_map(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Err(MapError::AlreadyFinished))
    ));
    // Member data is never read.
    let member = &map.members[0];
    for &(volume, at, len) in reads.lock().unwrap().iter() {
        let read = at..at + len as u64;
        assert!(
            member
                .pieces
                .iter()
                .all(|p| p.volume != volume || read.end <= p.packed.start || read.start >= p.packed.end),
            "{volume} {read:?}"
        );
    }

    let gold = b"continuous CBC across two unaligned boundaries with arbitrary trailing padding";
    let volumes = r4_aes(gold, true, &[29, 31, 20]);
    let expected = MemberMap::from_memory(&refs(&volumes), "a.part01.rar", Some("pw")).unwrap();
    let (mut builder, gate, _) = waiting_builder(&volumes, &[], MapOptions::new("a.part01.rar").password(Some("pw")));
    assert_eq!(drive(&mut builder, &gate).unwrap(), expected);

    let (_, volumes) = split_fixture();
    let (mut builder, gate, _) = waiting_builder(&volumes[..3], &[], MapOptions::new("big.part1.rar"));
    let map = drive(&mut builder, &gate).unwrap();
    assert_eq!(map.end, MapEnd::MissingVolume { volume: 3 });
    assert_eq!(map.members[0].pieces.len(), 3);
}

#[test]
fn header_hole_is_typed_and_data_holes_are_never_reached() {
    let (_, volumes) = split_fixture();
    let (mut builder, gate, _) = waiting_builder(&volumes, &[(1, 8..12)], MapOptions::new("big.part1.rar"));
    assert!(matches!(drive(&mut builder, &gate), Err(MapError::HeaderHole { volume: 1, offset: 8 })));

    let expected = MemberMap::from_memory(&refs(&volumes), "big.part1.rar", None).unwrap();
    let data = expected.members[0].pieces[2].packed.clone();
    let (mut builder, gate, _) =
        waiting_builder(&volumes, &[(2, data.start + 5..data.end - 5)], MapOptions::new("big.part1.rar"));
    assert_eq!(drive(&mut builder, &gate).unwrap(), expected);
}

#[test]
fn header_budgets_apply() {
    let (_, volumes) = split_fixture();
    let mut options = MapOptions::new("big.part1.rar");
    options.limits.parts = 2;
    assert!(matches!(
        MemberMap::from_memory_with(&refs(&volumes), options),
        Err(MapError::Limit { resource: zipfast::progressive::Resource::Parts, .. })
    ));
    let mut options = MapOptions::new("big.part1.rar");
    options.limits.header_bytes = 40;
    assert!(matches!(
        MemberMap::from_memory_with(&refs(&volumes), options),
        Err(MapError::Limit { resource: zipfast::progressive::Resource::HeaderBytes, .. })
    ));
    assert!(matches!(MemberMap::from_memory(&[b"not an archive at all"], "x", None), Err(MapError::NotArchive)));
    assert!(matches!(MemberMap::from_memory(&[], "x", None), Err(MapError::MissingFirstVolume)));
}

// ---- ZIP ----

struct ZipSpec<'a> {
    name: &'a str,
    payload: Vec<u8>,
    method: u16,
    flags: u16,
    extra: Vec<u8>,
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
            out.extend((e.extra.len() as u16).to_le_bytes());
        };
        common(0x0403_4b50, &mut out);
        out.extend(e.name.as_bytes());
        out.extend(&e.extra);
        out.extend(&e.payload);
        common(0x0201_4b50, &mut central);
        central.extend(0u16.to_le_bytes());
        central.extend(0u16.to_le_bytes());
        central.extend(0u16.to_le_bytes());
        central.extend((0o100644u32 << 16).to_le_bytes());
        central.extend(local_at.to_le_bytes());
        central.extend(e.name.as_bytes());
        central.extend(&e.extra);
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

#[test]
fn zip_stored_and_encrypted_entries() {
    let plain = data(3000, 4);
    let zipcrypto: Vec<u8> = (0..12 + 100).map(|i| i as u8).collect();
    let salt = [0x77; 16];
    let mut aes = salt.to_vec();
    aes.extend([0xab, 0xcd]);
    aes.extend(data(500, 8));
    aes.extend([0xee; 10]);
    let aes_extra = [&[0x01, 0x99, 7, 0][..], &2u16.to_le_bytes(), b"AE", &[3], &0u16.to_le_bytes()].concat();
    let bytes = zip(&[
        ZipSpec {
            name: "plain.bin",
            payload: plain.clone(),
            method: 0,
            flags: 0,
            extra: vec![],
            crc: crc32fast::hash(&plain),
            size: 3000,
        },
        ZipSpec {
            name: "deflated.bin",
            payload: b"deflate stand-in".to_vec(),
            method: 8,
            flags: 0,
            extra: vec![],
            crc: 1,
            size: 77,
        },
        ZipSpec {
            name: "zipcrypto.bin",
            payload: zipcrypto,
            method: 0,
            flags: 1,
            extra: vec![],
            crc: 0xa1b2_c3d4,
            size: 100,
        },
        ZipSpec { name: "aes.bin", payload: aes.clone(), method: 99, flags: 1, extra: aes_extra, crc: 0, size: 500 },
    ]);
    let map = MemberMap::from_memory(&[&bytes], "x.zip", None).unwrap();
    assert_eq!(map.format, MapFormat::Zip);
    assert!(map.complete);
    assert_eq!(map.members.len(), 4);
    let volumes = vec![bytes.clone()];

    let stored = &map.members[0];
    assert_eq!(stored.name.as_deref(), Some("plain.bin"));
    assert_eq!(stored.mapping, OutputMapping::Direct);
    assert_eq!(stored.pieces[0].header.start, 0);
    assert_eq!(stored.pieces[0].header.end, 30 + 9);
    assert_eq!(stored.pieces[0].out, Some(0..3000));
    assert_eq!(stored.checks.unwrap().crc32, Some(crc32fast::hash(&plain)));
    assert_eq!(stored.unix_mode, Some(0o100644));
    assert_round_trips(stored, &volumes, &plain, &[0..3000, 1000..1001]);

    let deflated = &map.members[1];
    assert_eq!(deflated.method, MapMethod::Compressed { id: 8 });
    assert_eq!(deflated.packed_spans(0..1), None);

    let zc = &map.members[2];
    assert!(zc.encrypted);
    assert_eq!(zc.cipher, Some(CipherParams::ZipCrypto { check: 0xa1 }));
    assert_eq!(zc.mapping, OutputMapping::Sequential { skip: 12 });
    assert_eq!(zc.pieces[0].out, None);
    let spans = zc.packed_spans(50..60).unwrap();
    assert_eq!(spans[0].stream, 0..72);
    assert_eq!(spans[0].packed.start, zc.pieces[0].packed.start);

    let aes_member = &map.members[3];
    assert!(aes_member.encrypted);
    assert_eq!(aes_member.method, MapMethod::Stored);
    assert_eq!(
        aes_member.cipher,
        Some(CipherParams::WinZipAes { strength: 3, vendor_version: 2, salt: salt.to_vec(), verifier: [0xab, 0xcd] })
    );
    assert_eq!(aes_member.mapping, OutputMapping::Counter { skip: 18 });
    assert_eq!(aes_member.pieces[0].out, Some(0..500));
    assert_eq!(aes_member.checks.unwrap().crc32, None);
    let spans = aes_member.packed_spans(3..7).unwrap();
    assert_eq!(spans[0].stream, 21..25);
    assert_eq!(slice(&volumes, &spans), &aes[21..25]);
    assert_eq!(aes_member.pieces[0].packed.end - aes_member.pieces[0].packed.start, aes.len() as u64);

    let (mut builder, gate, _) = waiting_builder(&volumes, &[], MapOptions::new("x.zip"));
    assert_eq!(drive(&mut builder, &gate).unwrap(), map);
}

// ---- Review regressions ----

#[test]
fn later_volume_cut_inside_its_first_encrypted_header_is_truncated_not_a_wrong_password() {
    let gold = b"continuous CBC across two unaligned boundaries with arbitrary trailing padding";
    let volumes = r4_aes(gold, true, &[29, 31, 20]);
    for cut in 28..75 {
        let mut cut_set = volumes.clone();
        cut_set[2].truncate(cut);
        let map = MemberMap::from_memory(&refs(&cut_set), "a.part01.rar", Some("pw"))
            .unwrap_or_else(|e| panic!("cut {cut}: {e:?}"));
        assert!(!map.complete, "cut {cut}");
        assert!(matches!(map.end, MapEnd::Truncated { volume: 2, .. }), "cut {cut}: {:?}", map.end);
        assert_eq!(map.members[0].pieces.len(), 2, "cut {cut}: volume 2's file header is never complete");
    }
    // Damage in a later volume's encrypted header is damage, not a wrong password: the walk stops there.
    let mut damaged = volumes.clone();
    damaged[2][50] ^= 1;
    let map = MemberMap::from_memory(&refs(&damaged), "a.part01.rar", Some("pw")).unwrap();
    assert!(!map.complete);
    assert!(matches!(map.end, MapEnd::Damaged { volume: 2, reason: HeaderDamage::Checksum, .. }), "{:?}", map.end);
    assert_eq!(map.members[0].pieces.len(), 2);
}

#[test]
fn rar4_non_aes_data_encryption_is_not_mapped_as_cbc() {
    let data = b"old cipher payload";
    for (version, flags) in [(20u8, 0x04u16), (29, 0x04)] {
        let bytes = r4_archive(&[r4_member_version(b"old", data, flags, 0x30, data.len(), 0, version)]);
        let map = MemberMap::from_memory(&[&bytes], "old.rar", None).unwrap();
        let member = &map.members[0];
        assert!(member.encrypted);
        assert_eq!(member.cipher, Some(CipherParams::Rar4Legacy { unpack_version: version, salt: None }));
        assert_eq!(member.mapping, OutputMapping::None);
        assert_eq!(member.pieces[0].out, None);
        assert_eq!(member.packed_spans(0..4), None);
    }
}

#[test]
fn zip_method_99_without_a_valid_aes_field_is_not_zipcrypto() {
    let bad_extra = [&[0x01, 0x99, 7, 0][..], &2u16.to_le_bytes(), b"AE", &[9], &0u16.to_le_bytes()].concat();
    let bytes = zip(&[ZipSpec {
        name: "aes.bin",
        payload: vec![0; 40],
        method: 99,
        flags: 1,
        extra: bad_extra,
        crc: 0,
        size: 12,
    }]);
    let map = MemberMap::from_memory(&[&bytes], "x.zip", None).unwrap();
    let member = &map.members[0];
    assert!(member.encrypted);
    assert_eq!(member.cipher, None);
    assert_eq!(member.mapping, OutputMapping::None);
    assert_eq!(member.packed_spans(0..4), None);
}

#[test]
fn zip_with_a_stub_and_a_stored_rar_inside_maps_as_zip() {
    let inner = archive(&[FileSpec::new("inner.bin", b"inside a zip")]);
    let mut bytes = b"MZ".to_vec();
    bytes.resize(3000, 0x90);
    bytes.extend(zip(&[ZipSpec {
        name: "inner.rar",
        payload: inner.clone(),
        method: 0,
        flags: 0,
        extra: vec![],
        crc: crc32fast::hash(&inner),
        size: inner.len() as u32,
    }]));
    let map = MemberMap::from_memory(&[&bytes], "sfx.exe", None).unwrap();
    assert_eq!(map.format, MapFormat::Zip);
    assert_eq!(map.members[0].name.as_deref(), Some("inner.rar"));
    let piece = &map.members[0].pieces[0];
    assert_eq!(&bytes[piece.packed.start as usize..piece.packed.end as usize], &inner[..]);
}

#[test]
fn rar_behind_a_long_stub_is_scanned_in_chunks() {
    let mut bytes = b"MZ".to_vec();
    bytes.resize(300_000, 0x90);
    bytes.extend(archive(&[FileSpec::new("a.bin", b"behind a stub")]));
    let mut options = MapOptions::new("sfx.exe");
    options.limits.source_requests = 1000;
    let map = MemberMap::from_memory_with(&[&bytes], options).unwrap();
    assert_eq!(map.format, MapFormat::Rar5);
    assert_eq!(map.members[0].name.as_deref(), Some("a.bin"));
    let piece = &map.members[0].pieces[0];
    assert_eq!(&bytes[piece.packed.start as usize..piece.packed.end as usize], b"behind a stub");
}

#[test]
fn rar5_split_part_must_keep_the_key_but_may_restate_another_iv() {
    let (_, _, a) = encrypted_volumes(3000, &[1000, 2000]);
    let expected = MemberMap::from_memory(&refs(&a), "e.part1.rar", None).unwrap();
    // One CBC stream: only the first part's IV is used, so a later part restating another IV is accepted.
    let (_, _, other_iv) = encrypted_volumes_with(3000, &[1000, 2000], [0x42; 16], SALT, 1);
    let mixed = vec![a[0].clone(), other_iv[1].clone(), a[2].clone()];
    let map = MemberMap::from_memory(&refs(&mixed), "e.part1.rar", None).unwrap();
    assert!(map.complete);
    assert_eq!(map.members[0].cipher, expected.members[0].cipher);
    assert_eq!(map.members[0].pieces.len(), 3);
    // A different key (salt or KDF count) is a different stream.
    for (salt, kdf) in [([0x44; 16], 1), (SALT, 2)] {
        let (_, _, other) = encrypted_volumes_with(3000, &[1000, 2000], IV, salt, kdf);
        let mixed = vec![a[0].clone(), other[1].clone(), a[2].clone()];
        let map = MemberMap::from_memory(&refs(&mixed), "e.part1.rar", None).unwrap();
        assert!(!map.complete);
        assert!(
            matches!(
                map.end,
                MapEnd::Damaged { volume: 1, reason: HeaderDamage::Malformed("member continuation identity"), .. }
            ),
            "{:?}",
            map.end
        );
        assert_eq!(map.members[0].pieces.len(), 1);
    }
}

#[test]
fn zip_directory_uses_the_callers_limits() {
    let bytes = zip(&[ZipSpec {
        name: "a-long-name.bin",
        payload: b"x".to_vec(),
        method: 0,
        flags: 0,
        extra: vec![],
        crc: crc32fast::hash(b"x"),
        size: 1,
    }]);
    let mut options = MapOptions::new("x.zip");
    options.limits.name_bytes = 5;
    let error = MemberMap::from_memory_with(&[&bytes], options).unwrap_err();
    assert!(matches!(error, MapError::Limit { resource: zipfast::progressive::Resource::NameBytes, .. }), "{error:?}");
}

#[test]
fn truncated_offset_is_the_start_of_the_header_being_read() {
    let a = data(500, 3);
    let bytes = archive(&[FileSpec::new("a.bin", &a), FileSpec::new("b.bin", b"later")]);
    let full = MemberMap::from_memory(&[&bytes], "x.rar", None).unwrap();
    let next = full.members[1].pieces[0].header.start;
    for cut in [next + 1, next + 3, next + 9] {
        let map = MemberMap::from_memory(&[&bytes[..cut as usize]], "x.rar", None).unwrap();
        assert_eq!(map.end, MapEnd::Truncated { volume: 0, offset: next }, "cut {cut}");
    }
}

// Catches a WinZip AES entry whose general-purpose encryption bit is clear being mapped as plain data.
#[test]
fn zip_aes_entry_without_the_encryption_flag_is_still_encrypted() {
    let extra = [&[0x01, 0x99, 7, 0][..], &2u16.to_le_bytes(), b"AE", &[3], &0u16.to_le_bytes()].concat();
    let bytes =
        zip(&[ZipSpec { name: "aes.bin", payload: vec![7; 40], method: 99, flags: 0, extra, crc: 0, size: 12 }]);
    let map = MemberMap::from_memory(&[&bytes], "x.zip", None).unwrap();
    let member = &map.members[0];
    assert!(member.encrypted);
    assert!(matches!(member.cipher, Some(CipherParams::WinZipAes { .. })), "{:?}", member.cipher);
    assert_ne!(member.mapping, OutputMapping::Direct);
}

// ---- Single-volume maps ----

fn vol(bytes: &[u8], name: &str, password: Option<&str>) -> Result<VolumeMap, MapError> {
    MemberMap::from_volume(bytes, MapOptions::new(name).password(password))
}

fn packed_of<'a>(bytes: &'a [u8], member: &VolumeMember) -> &'a [u8] {
    &bytes[member.packed.start as usize..member.packed.end as usize]
}

#[test]
fn rar5_any_volume_maps_on_its_own() {
    let (gold, volumes) = split_fixture();
    // `.part03.rar` alone, under an obfuscated name.
    let map = vol(&volumes[2], "3f9a1c0d", None).unwrap();
    assert_eq!(map.format, MapFormat::Rar5);
    assert!(map.main_read);
    assert_eq!(map.volume_number, Some(2));
    assert!(!map.first_volume && map.multi_volume && map.new_naming && map.has_next_volume);
    assert!(!map.solid && !map.header_encrypted && map.header_cipher.is_none());
    assert_eq!(map.end, VolumeEnd::Complete);
    assert_eq!(map.members.len(), 1);
    let member = &map.members[0];
    assert_eq!(member.raw_name, b"big.bin");
    assert_eq!(member.name.as_deref(), Some("big.bin"));
    assert!(member.split_before && member.split_after);
    assert_eq!(member.unpacked_size, Some(10_000));
    assert_eq!(member.packed_size, 2600);
    assert_eq!(member.method, MapMethod::Stored);
    assert_eq!(member.mapping, OutputMapping::Direct);
    assert_eq!(packed_of(&volumes[2], member), &gold[5200..7800]);
    assert_eq!(member.header.end, member.packed.start);
    assert_eq!(member.part_checks.crc32, Some(crc32fast::hash(&gold[5200..7800])));
    assert_eq!(member.checks, None);
    assert_eq!(member.mtime, Some((1_700_000_000, 0)));
    assert_eq!(member.unix_mode, Some(0o644));

    let first = vol(&volumes[0], "big.part1.rar", None).unwrap();
    assert_eq!(first.volume_number, Some(0));
    assert!(first.first_volume && first.has_next_volume);
    assert!(!first.members[0].split_before && first.members[0].split_after);

    let last = vol(&volumes[3], "big.part4.rar", None).unwrap();
    assert_eq!(last.volume_number, Some(3));
    assert!(!last.first_volume && !last.has_next_volume);
    let member = &last.members[0];
    assert!(member.split_before && !member.split_after);
    assert_eq!(packed_of(&volumes[3], member), &gold[7800..]);
    assert_eq!(member.checks, Some(member.part_checks));
    assert_eq!(member.checks.unwrap().crc32, Some(crc32fast::hash(&gold)));

    // A single-volume archive is volume 0 and has no next volume.
    let single = vol(&archive(&[FileSpec::new("a.bin", b"alone")]), "a.rar", None).unwrap();
    assert_eq!(single.volume_number, Some(0));
    assert!(single.first_volume && !single.multi_volume && !single.has_next_volume);
}

#[test]
fn rar5_volume_prefix_lists_what_was_read() {
    let (gold, volumes) = split_fixture();
    // The first 2 KiB of volume 1: the main header and the file header, its data running past the end.
    let map = vol(&volumes[1][..2048], "big.part2.rar", None).unwrap();
    assert!(map.main_read && map.multi_volume);
    assert_eq!(map.volume_number, Some(1));
    assert!(!map.has_next_volume, "the end header was not reached");
    assert_eq!(map.members.len(), 1);
    let member = &map.members[0];
    assert!(member.split_before && member.split_after);
    assert_eq!(member.packed_size, 2600);
    assert!(member.packed.end > 2048);
    assert_eq!(map.end, VolumeEnd::Truncated { offset: member.packed.end });
    assert_eq!(
        &volumes[1][member.packed.start as usize..2048],
        &gold[2600..2600 + 2048 - member.packed.start as usize]
    );

    // Cut inside the file header: the main facts and no members.
    let header_start = member.header.start;
    let map = vol(&volumes[1][..header_start as usize + 5], "big.part2.rar", None).unwrap();
    assert!(map.main_read);
    assert_eq!(map.volume_number, Some(1));
    assert!(map.members.is_empty());
    assert_eq!(map.end, VolumeEnd::Truncated { offset: header_start });

    // Cut inside the main header: nothing but the format.
    let map = vol(&volumes[1][..SIG.len() + 3], "big.part2.rar", None).unwrap();
    assert!(!map.main_read && map.members.is_empty());
    assert_eq!(map.volume_number, None);
    assert_eq!(map.end, VolumeEnd::Truncated { offset: SIG.len() as u64 });
}

#[test]
fn volume_holding_the_end_of_one_member_and_the_start_of_the_next() {
    let a = data(3000, 1);
    let b = data(4000, 2);
    let (a_spec, b_spec) = (FileSpec::new("a.bin", &a), FileSpec::new("b.bin", &b));
    let mut bytes = SIG.to_vec();
    bytes.extend(main_block(true, Some(1)));
    bytes.extend(file_block(&a_spec, &a[1000..], crc32fast::hash(&a), true, false));
    bytes.extend(file_block(&b_spec, &b[..1500], crc32fast::hash(&b[..1500]), false, true));
    bytes.extend(end_block(true));
    let map = vol(&bytes, "x.part2.rar", None).unwrap();
    assert_eq!(map.volume_number, Some(1));
    assert!(map.has_next_volume);
    assert_eq!(map.end, VolumeEnd::Complete);
    let [tail, head] = map.members.as_slice() else { panic!("{:?}", map.members) };
    assert_eq!(tail.name.as_deref(), Some("a.bin"));
    assert!(tail.split_before && !tail.split_after);
    assert_eq!(packed_of(&bytes, tail), &a[1000..]);
    assert_eq!(tail.checks.unwrap().crc32, Some(crc32fast::hash(&a)));
    assert_eq!(head.name.as_deref(), Some("b.bin"));
    assert!(!head.split_before && head.split_after);
    assert_eq!(packed_of(&bytes, head), &b[..1500]);
    assert_eq!(head.unpacked_size, Some(4000));
    assert_eq!(head.checks, None);
    assert_eq!(head.part_checks.crc32, Some(crc32fast::hash(&b[..1500])));
    assert_eq!(head.header.start, tail.packed.end);
}

#[test]
fn rar5_hp_volume_without_a_password_reports_its_facts() {
    let payload = data(700, 5);
    let bytes = hp_archive(&payload);
    let map = vol(&bytes, "hp.rar", None).unwrap();
    assert!(map.header_encrypted && !map.main_read);
    assert!(map.members.is_empty());
    assert_eq!(map.volume_number, None);
    assert!(matches!(map.header_cipher, Some(CipherParams::Rar5 { kdf_count: 4, salt: HP_SALT, iv: None, .. })));
    let VolumeEnd::Locked { offset } = map.end else { panic!("{:?}", map.end) };
    assert_eq!(&bytes[offset as usize..offset as usize + 16], &[0x49; 16], "the first encrypted header's IV");

    let map = vol(&bytes, "hp.rar", Some(HP_PASSWORD)).unwrap();
    assert!(map.header_encrypted && map.main_read);
    assert_eq!(map.end, VolumeEnd::Complete);
    assert_eq!(map.volume_number, Some(0));
    assert_eq!(map.members.len(), 1);
    assert_eq!(map.members[0].name.as_deref(), Some("secret.bin"));
    assert_eq!(packed_of(&bytes, &map.members[0]), &payload[..]);

    assert!(matches!(vol(&bytes, "hp.rar", Some("wrong")), Err(MapError::WrongPassword)));
}

#[test]
fn rar4_hp_volume_without_a_password_reports_its_facts() {
    let gold = b"continuous CBC across two unaligned boundaries with arbitrary trailing padding";
    let volumes = r4_aes(gold, true, &[29, 31, 20]);
    let map = vol(&volumes[1], "a.part02.rar", None).unwrap();
    assert_eq!(map.format, MapFormat::Rar4);
    // RAR 4.x keeps its main header in the clear.
    assert!(map.header_encrypted && map.main_read && map.multi_volume);
    assert_eq!(map.header_cipher, Some(CipherParams::Rar4 { salt: R4_SALT }));
    assert!(map.members.is_empty());
    let main_end = 7 + 13;
    assert_eq!(map.end, VolumeEnd::Locked { offset: main_end });

    let map = vol(&volumes[1], "a.part02.rar", Some("pw")).unwrap();
    assert_eq!(map.end, VolumeEnd::Complete);
    assert!(map.has_next_volume);
    let member = &map.members[0];
    assert!(member.split_before && member.split_after && member.encrypted);
    assert_eq!(member.cipher, Some(CipherParams::Rar4 { salt: R4_SALT }));
    assert_eq!(member.packed_size, 31);
    assert_eq!(member.header.start, main_end);

    let wrong = vol(&volumes[1], "a.part02.rar", Some("wrong password"));
    assert!(matches!(wrong, Err(MapError::WrongPassword)), "{wrong:?}");
}

/// A stored RAR4 member cut into volumes, named the old way (`.rar`, `.r00`, ...) or the new way, with or without
/// the volume number in each end header.
fn r4_volumes(gold: &[u8], chunk: usize, new_naming: bool, numbered: bool) -> Vec<Vec<u8>> {
    let count = gold.len().div_ceil(chunk);
    gold.chunks(chunk)
        .enumerate()
        .map(|(i, payload)| {
            let flags = u16::from(i > 0) | (u16::from(i + 1 < count) * 2);
            let crc = crc32fast::hash(if i + 1 == count { gold } else { payload });
            let main = 0x01 | if new_naming { 0x10 } else { 0 } | if i == 0 { 0x100 } else { 0 };
            let mut wire = b"Rar!\x1a\x07\0".to_vec();
            wire.extend(r4_block(0x73, main, &[0; 6]));
            wire.extend(r4_member(b"one", payload, flags, 0x30, gold.len(), crc));
            let more = u16::from(i + 1 < count);
            if numbered {
                wire.extend(r4_block(0x7b, 0x4000 | 0x8 | more, &(i as u16).to_le_bytes()));
            } else {
                wire.extend(r4_block(0x7b, 0x4000 | more, &[]));
            }
            wire
        })
        .collect()
}

#[test]
fn rar4_volume_naming_numbers_and_next_volume() {
    let gold = data(130, 9);
    // Old naming: `x.rar`, `x.r00`, `x.r01`, `x.r02`, numbered end headers.
    let volumes = r4_volumes(&gold, 40, false, true);
    for (i, bytes) in volumes.iter().enumerate() {
        let map = vol(bytes, "x.r01", None).unwrap();
        assert_eq!(map.format, MapFormat::Rar4);
        assert!(!map.new_naming && map.multi_volume, "volume {i}");
        assert_eq!(map.volume_number, Some(i as u32));
        assert_eq!(map.first_volume, i == 0);
        assert_eq!(map.has_next_volume, i < 3);
        let member = &map.members[0];
        assert_eq!((member.split_before, member.split_after), (i > 0, i < 3));
        let start = i * 40;
        assert_eq!(packed_of(bytes, member), &gold[start..(start + 40).min(130)]);
    }
    // A prefix of volume 2 does not reach the numbered end header.
    let cut = vol(&volumes[2][..60], "x.r01", None).unwrap();
    assert_eq!(cut.volume_number, None);
    assert!(!cut.first_volume && !cut.has_next_volume);
    assert!(matches!(cut.end, VolumeEnd::Truncated { .. }));
    assert_eq!(cut.members.len(), 1);

    // New naming, end headers without numbers: only the first volume knows its number.
    let volumes = r4_volumes(&gold, 40, true, false);
    let first = vol(&volumes[0], "x.part1.rar", None).unwrap();
    assert!(first.new_naming && first.first_volume && first.has_next_volume);
    assert_eq!(first.volume_number, Some(0));
    let middle = vol(&volumes[1], "x.part2.rar", None).unwrap();
    assert!(middle.new_naming && !middle.first_volume && middle.has_next_volume);
    assert_eq!(middle.volume_number, None);
    let last = vol(&volumes[3], "x.part4.rar", None).unwrap();
    assert!(!last.has_next_volume);
    assert_eq!(last.members[0].checks.unwrap().crc32, Some(crc32fast::hash(&gold)));
    let numbered = r4_volumes(&gold, 40, true, true);
    assert_eq!(vol(&numbered[2], "x.part3.rar", None).unwrap().volume_number, Some(2));
}

#[test]
fn encrypted_data_members_list_their_cipher_params() {
    let (plain, check, volumes) = encrypted_volumes(3000, &[1000, 2000]);
    let map = vol(&volumes[1], "e.part2.rar", None).unwrap();
    assert!(!map.header_encrypted);
    let member = &map.members[0];
    assert!(member.encrypted && member.split_before && member.split_after);
    assert_eq!(member.mapping, OutputMapping::CbcBlocks);
    let sum: [u8; 4] = zipfast::crypto::sha256(&check)[..4].try_into().unwrap();
    assert_eq!(
        member.cipher,
        Some(CipherParams::Rar5 {
            kdf_count: 1,
            salt: SALT,
            iv: Some(IV),
            check: Some((check, sum)),
            keyed_checks: true
        })
    );
    assert!(member.part_checks.keyed);
    assert_eq!(member.unpacked_size, Some(plain.len() as u64));
    assert_eq!(member.packed_size, 1000);

    let gold = b"continuous CBC across two unaligned boundaries with arbitrary trailing padding";
    let volumes = r4_aes(gold, false, &[29, 31, 20]);
    let map = vol(&volumes[2], "a.part03.rar", None).unwrap();
    assert!(!map.header_encrypted && !map.has_next_volume);
    let member = &map.members[0];
    assert_eq!(member.cipher, Some(CipherParams::Rar4 { salt: R4_SALT }));
    assert!(member.split_before && !member.split_after);
}

#[test]
fn single_volume_maps_scan_stubs_reject_zip_and_respect_options() {
    let (_, volumes) = split_fixture();
    let mut stubbed = b"MZ".to_vec();
    stubbed.resize(5000, 0x90);
    stubbed.extend(&volumes[1]);
    let map = vol(&stubbed, "sfx.exe", None).unwrap();
    let plain = vol(&volumes[1], "big.part2.rar", None).unwrap();
    assert_eq!(map.volume_number, Some(1));
    assert_eq!(map.members[0].packed.start, plain.members[0].packed.start + 5000);

    let zip = zip(&[ZipSpec {
        name: "a",
        payload: b"x".to_vec(),
        method: 0,
        flags: 0,
        extra: vec![],
        crc: crc32fast::hash(b"x"),
        size: 1,
    }]);
    assert!(matches!(vol(&zip, "x.zip", None), Err(MapError::NotArchive)));
    assert!(matches!(vol(b"not an archive at all", "x", None), Err(MapError::NotArchive)));
    assert!(matches!(vol(b"", "x", None), Err(MapError::NotArchive)));

    let mut options = MapOptions::new("big.part2.rar");
    options.limits.header_bytes = 40;
    let error = MemberMap::from_volume(&volumes[1], options).unwrap_err();
    assert!(matches!(error, MapError::Limit { resource: zipfast::progressive::Resource::HeaderBytes, .. }));
    let options = MapOptions::new("big.part2.rar");
    options.control.cancel();
    assert!(matches!(MemberMap::from_volume(&volumes[1], options), Err(MapError::Source(_))));
}

/// Maps `bytes` through a range source that answers `NotYet` before every read, releasing each wait.
fn drive_volume(bytes: &[u8], hole: Option<Range<u64>>) -> (Result<VolumeMap, MapError>, usize) {
    let gate = Arc::new(Mutex::new(Gate::default()));
    let reads = Arc::new(Mutex::new(Vec::new()));
    let source = Bytes {
        index: 0,
        data: bytes.to_vec(),
        holes: hole.into_iter().collect(),
        chunk: 7,
        gate: gate.clone(),
        reads,
    };
    let mut builder = VolumeMapBuilder::new(Box::new(source), MapOptions::new("big.part3.rar"));
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        match builder.poll_map(&mut cx) {
            Poll::Ready(result) => {
                assert!(matches!(builder.poll_map(&mut cx), Poll::Ready(Err(MapError::AlreadyFinished))));
                return (result, gate.lock().unwrap().waits);
            }
            Poll::Pending => {
                let waker = {
                    let mut g = gate.lock().unwrap();
                    g.ready = true;
                    g.wake.take().expect("pending only after the source kept a waker")
                };
                waker.wake();
            }
        }
    }
}

#[test]
fn volume_builder_over_a_waiting_range_source_matches_memory() {
    let (_, volumes) = split_fixture();
    for bytes in [&volumes[2][..], &volumes[1][..2048]] {
        let expected = vol(bytes, "big.part3.rar", None).unwrap();
        let (map, waits) = drive_volume(bytes, None);
        assert_eq!(map.unwrap(), expected);
        assert!(waits > 5);
    }
    let (error, _) = drive_volume(&volumes[2], Some(9..12));
    assert!(matches!(error, Err(MapError::HeaderHole { volume: 0, offset: 9 })), "{error:?}");
}

// ---- Single-volume review regressions ----

#[test]
fn rar4_volume_cut_inside_its_main_header_is_still_rar4() {
    let volumes = r4_volumes(&data(130, 9), 40, true, true);
    for cut in [7, 10, 19] {
        let map = vol(&volumes[1][..cut], "x.part2.rar", None).unwrap();
        assert_eq!(map.format, MapFormat::Rar4, "cut {cut}");
        assert!(!map.main_read && map.members.is_empty(), "cut {cut}");
        assert_eq!(map.end, VolumeEnd::Truncated { offset: 7 }, "cut {cut}");
        let whole = MemberMap::from_memory(&[&volumes[1][..cut]], "x.part2.rar", None).unwrap();
        assert_eq!(whole.format, MapFormat::Rar4, "cut {cut}");
    }
}

#[test]
fn an_empty_password_locks_hp_volumes_in_both_formats() {
    let rar5 = hp_archive(&data(700, 5));
    let map = vol(&rar5, "hp.rar", Some("")).unwrap();
    assert!(matches!(map.end, VolumeEnd::Locked { .. }), "{:?}", map.end);
    assert!(map.header_encrypted && map.members.is_empty());
    let gold = b"continuous CBC across two unaligned boundaries with arbitrary trailing padding";
    let rar4 = r4_aes(gold, true, &[29, 31, 20]);
    let map = vol(&rar4[1], "a.part02.rar", Some("")).unwrap();
    assert_eq!(map.end, VolumeEnd::Locked { offset: 20 });
}

#[test]
fn hp_prefix_cut_inside_the_first_encrypted_header_is_truncated_with_the_right_password() {
    let gold = b"continuous CBC across two unaligned boundaries with arbitrary trailing padding";
    let volumes = r4_aes(gold, true, &[29, 31, 20]);
    let full = vol(&volumes[1], "a.part02.rar", Some("pw")).unwrap();
    let header = full.members[0].header.clone();
    assert_eq!(header.start, 20);
    for cut in header.start + 1..header.end {
        let map =
            vol(&volumes[1][..cut as usize], "a.part02.rar", Some("pw")).unwrap_or_else(|e| panic!("cut {cut}: {e:?}"));
        assert_eq!(map.end, VolumeEnd::Truncated { offset: 20 }, "cut {cut}");
        assert!(map.main_read && map.members.is_empty(), "cut {cut}");
    }
    // Once the first block decrypts, a wrong password shows in a prefix too; before that nothing can tell.
    for cut in [30, header.start + 8 + 16, header.end - 1] {
        let wrong = vol(&volumes[1][..cut as usize], "a.part02.rar", Some("wrong password"));
        if cut >= header.start + 8 + 16 {
            assert!(matches!(wrong, Err(MapError::WrongPassword)), "cut {cut}: {wrong:?}");
        } else {
            assert!(matches!(wrong, Ok(VolumeMap { end: VolumeEnd::Truncated { offset: 20 }, .. })), "{wrong:?}");
        }
    }
    // RAR 5.0 with a check value: the password is proven before any header, so a cut is a cut.
    let rar5 = hp_archive(&data(700, 5));
    let locked = vol(&rar5, "hp.rar", None).unwrap();
    let VolumeEnd::Locked { offset } = locked.end else { panic!() };
    for cut in [offset + 1, offset + 16, offset + 31] {
        let map = vol(&rar5[..cut as usize], "hp.rar", Some(HP_PASSWORD)).unwrap();
        assert_eq!(map.end, VolumeEnd::Truncated { offset }, "cut {cut}");
    }
}

#[test]
fn rar4_first_volume_flag_and_end_header_number_must_agree() {
    let gold = data(130, 9);
    // MHD_FIRSTVOLUME with an end header numbering the volume 5.
    let mut bytes = b"Rar!\x1a\x07\0".to_vec();
    bytes.extend(r4_block(0x73, 0x111, &[0; 6]));
    bytes.extend(r4_member(b"one", &gold[..40], 2, 0x30, gold.len(), crc32fast::hash(&gold[..40])));
    let end_at = bytes.len() as u64;
    bytes.extend(r4_block(0x7b, 0x4000 | 0x8 | 1, &5u16.to_le_bytes()));
    let map = vol(&bytes, "x.part1.rar", None).unwrap();
    assert_eq!(
        map.end,
        VolumeEnd::Damaged {
            offset: end_at,
            reason: HeaderDamage::Malformed("first volume with a nonzero volume number")
        }
    );
    assert_eq!((map.first_volume, map.volume_number, map.members.len()), (true, Some(0), 1), "the main header's facts");
    // A RAR 2.x first volume has no MHD_FIRSTVOLUME: its end header's 0 makes it first, and a prefix knows nothing.
    let mut old = b"Rar!\x1a\x07\0".to_vec();
    old.extend(r4_block(0x73, 0x01, &[0; 6]));
    old.extend(r4_member(b"one", &gold[..40], 2, 0x30, gold.len(), crc32fast::hash(&gold[..40])));
    let cut = old.len();
    old.extend(r4_block(0x7b, 0x4000 | 0x8 | 1, &0u16.to_le_bytes()));
    let map = vol(&old, "x.rar", None).unwrap();
    assert!(map.first_volume);
    assert_eq!(map.volume_number, Some(0));
    let prefix = vol(&old[..cut], "x.rar", None).unwrap();
    assert!(!prefix.first_volume);
    assert_eq!(prefix.volume_number, None);
    // A non-volume archive whose end header carries a stray number is not a contradiction: it is volume 0.
    let mut single = b"Rar!\x1a\x07\0".to_vec();
    single.extend(r4_block(0x73, 0x00, &[0; 6]));
    single.extend(r4_member(b"one", &gold, 0, 0x30, gold.len(), crc32fast::hash(&gold)));
    single.extend(r4_block(0x7b, 0x4000 | 0x8, &5u16.to_le_bytes()));
    let map = vol(&single, "x.rar", None).unwrap();
    assert!(!map.multi_volume);
    assert!(map.first_volume);
    assert_eq!(map.volume_number, Some(0));
}

// ---- RAR 4.x leniency of map walks ----

/// A stored RAR4 member with DOS time `dos` and `trailing` bytes left inside the header's declared size.
fn r4_member_dos(name: &[u8], data: &[u8], dos: u32, trailing: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend((data.len() as u32).to_le_bytes());
    body.extend((data.len() as u32).to_le_bytes());
    body.push(3);
    body.extend(crc32fast::hash(data).to_le_bytes());
    body.extend(dos.to_le_bytes());
    body.extend([29, 0x30]);
    body.extend((name.len() as u16).to_le_bytes());
    body.extend(0o100644u32.to_le_bytes());
    body.extend(name);
    body.extend(trailing);
    let mut bytes = r4_block(0x74, 0x8000, &body);
    bytes.extend(data);
    bytes
}

/// A legacy service block of `kind`. With `data`, LONG_BLOCK declares it in ADD_SIZE and it follows the header;
/// without, the payload sits inside the header, as in an old comment (the old subblock and recovery record always
/// start with a data size, here 0). The old comment never has data: there LONG_BLOCK is set over its own fields.
fn r4_legacy(kind: u8, data: Option<&[u8]>) -> Vec<u8> {
    match data {
        Some(_) if kind == 0x75 => r4_block(kind, 0x8000, b"\x05\x00\x0f\x30\x00\x00stuff"),
        Some(data) => {
            let mut body = (data.len() as u32).to_le_bytes().to_vec();
            body.extend([1, 2, 3, 4, 5, 6]);
            let mut bytes = r4_block(kind, 0x8000, &body);
            bytes.extend(data);
            bytes
        }
        None if matches!(kind, 0x77 | 0x78) => r4_block(kind, 0, b"\0\0\0\0\x01\x00stuff"),
        None => r4_block(kind, 0, b"\x05\x00\x0f\x30\x00\x00stuff"),
    }
}

/// Rewrites a RAR4 block's declared header size and fixes its CRC over the bytes that remain.
fn r4_resize(mut block: Vec<u8>, size: u16) -> Vec<u8> {
    block[5..7].copy_from_slice(&size.to_le_bytes());
    let end = block.len().min(usize::from(size).max(7));
    let crc = crc32fast::hash(&block[2..end]) as u16;
    block[..2].copy_from_slice(&crc.to_le_bytes());
    block
}

/// Sets the CRC of the RAR4 header starting at `at` to cover only its first `len` bytes.
fn r4_comment_crc(mut bytes: Vec<u8>, at: usize, len: usize) -> Vec<u8> {
    let crc = crc32fast::hash(&bytes[at + 2..at + len]) as u16;
    bytes[at..at + 2].copy_from_slice(&crc.to_le_bytes());
    bytes
}

const CP437: &[u8] = b"caf\x82.mkv";
const DOS: u32 = 0x5022_1884;

#[test]
fn rar4_cp437_name_is_listed_raw_by_map_walks() {
    let (a, b) = (data(300, 1), data(200, 2));
    let bytes = r4_archive(&[r4_member_dos(CP437, &a, DOS, &[]), r4_member_dos(b"next.bin", &b, DOS, &[])]);
    let map = vol(&bytes, "old.rar", None).unwrap();
    assert_eq!(map.end, VolumeEnd::Complete);
    let [first, second] = map.members.as_slice() else { panic!("{:?}", map.members) };
    assert_eq!(first.raw_name, CP437);
    assert_eq!(first.name, None);
    assert_eq!(packed_of(&bytes, first), &a[..]);
    assert_eq!(second.name.as_deref(), Some("next.bin"));
    assert_eq!(packed_of(&bytes, second), &b[..]);

    let map = MemberMap::from_memory(&[&bytes], "old.rar", None).unwrap();
    assert!(map.complete);
    let [first, second] = map.members.as_slice() else { panic!("{:?}", map.members) };
    assert_eq!((first.raw_name.as_slice(), first.name.as_deref()), (CP437, None));
    assert_round_trips(first, std::slice::from_ref(&bytes), &a, &[0..300, 150..151]);
    assert_eq!(second.name.as_deref(), Some("next.bin"));

    // A split member is matched across volumes by its raw bytes.
    let gold = data(130, 9);
    let volumes = r4_split_named(&gold, 50, CP437);
    let map = MemberMap::from_memory(&refs(&volumes), "old.part1.rar", None).unwrap();
    assert!(map.complete);
    let [member] = map.members.as_slice() else { panic!("{:?}", map.members) };
    assert_eq!((member.raw_name.as_slice(), member.name.as_deref()), (CP437, None));
    assert_eq!(member.pieces.len(), 3);
    assert_round_trips(member, &volumes, &gold, &[0..130, 49..51]);
    let middle = vol(&volumes[1], "old.part2.rar", None).unwrap();
    assert_eq!((middle.members[0].raw_name.as_slice(), middle.members[0].name.as_deref()), (CP437, None));
    // A continuation under another raw name is not the same member.
    let mut other = volumes.clone();
    other[1] = r4_split_named(&gold, 50, b"caf\x83.mkv").swap_remove(1);
    let map = MemberMap::from_memory(&refs(&other), "old.part1.rar", None).unwrap();
    assert!(!map.complete);
    assert!(
        matches!(
            map.end,
            MapEnd::Damaged { volume: 1, reason: HeaderDamage::Malformed("member continuation identity"), .. }
        ),
        "{:?}",
        map.end
    );
}

#[test]
fn rar4_leniency_stays_out_of_sessions_and_extraction() {
    use zipfast::error::{RarFailure, RarUnsupported};
    use zipfast::rar5::session::{RarSession, RarSessionOptions};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("old.rar");
    // A legacy name that isn't UTF-8 opens and lists as UnRAR reads it (U+FFFE, then U+E000 plus each byte that
    // isn't).
    std::fs::write(&path, r4_archive(&[r4_member_dos(CP437, b"payload", DOS, &[])])).unwrap();
    let session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    assert!(session.entries().next().unwrap().name().contains('\u{fffe}'));
    assert_eq!(zipfast::extract::list(&path).unwrap().len(), 1);
    let out = dir.path().join("out");
    let options = zipfast::extract::Options {
        mode: zipfast::extract::Mode::Extract,
        dest: out.clone(),
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
        damaged_input: Default::default(),
        unsupported_filters: Default::default(),
        salvage_truncated_zip: false,
        unix_modes: Default::default(),
        backslashes: Default::default(),
    };
    // written under its private-use mapping
    let summary = zipfast::extract::run(&path, &options, |_| {}).unwrap();
    assert_eq!((summary.files, summary.errors.len()), (1, 0), "{:?}", summary.errors);
    assert_eq!(std::fs::read(out.join("caf\u{e082}.mkv")).unwrap(), b"payload");
    let cases = [
        (vec![r4_legacy(0x75, None), r4_member_dos(b"one", b"payload", DOS, &[])], "legacy service block"),
        (vec![r4_member_dos(b"one", b"payload", DOS, &[0xde, 0xad])], "header extension or name encoding"),
    ];
    for (blocks, feature) in cases {
        let bytes = r4_archive(&blocks);
        assert_eq!(vol(&bytes, "old.rar", None).unwrap().members.len(), 1, "{feature}");
        std::fs::write(&path, &bytes).unwrap();
        let error = RarSession::open(&path, None, RarSessionOptions::default()).err().unwrap();
        assert!(
            matches!(error.failure.as_ref(), RarFailure::Unsupported(RarUnsupported::Rar4Feature(f)) if *f == feature),
            "{error:?}"
        );
        assert!(matches!(zipfast::extract::list(&path), Err(zipfast::Error::Unsupported(_))), "{feature}");
    }
}

#[test]
fn rar4_legacy_service_blocks_are_skipped_by_map_walks() {
    let (a, b) = (data(300, 3), data(200, 4));
    let rr = data(77, 5);
    for kind in 0x75..=0x79u8 {
        for payload in [None, Some(&rr[..])] {
            let block = r4_legacy(kind, payload);
            let bytes = r4_archive(&[
                block.clone(),
                r4_member_dos(b"a.bin", &a, DOS, &[]),
                block.clone(),
                r4_member_dos(b"b.bin", &b, DOS, &[]),
                block,
            ]);
            let map = vol(&bytes, "old.rar", None).unwrap_or_else(|e| panic!("{kind:#x}: {e}"));
            assert_eq!(map.end, VolumeEnd::Complete, "{kind:#x}");
            assert!(!map.has_next_volume && map.main_read);
            let [first, second] = map.members.as_slice() else { panic!("{kind:#x}: {:?}", map.members) };
            assert_eq!(first.name.as_deref(), Some("a.bin"));
            assert_eq!(packed_of(&bytes, first), &a[..]);
            assert_eq!(second.name.as_deref(), Some("b.bin"));
            assert_eq!(packed_of(&bytes, second), &b[..]);

            let map = MemberMap::from_memory(&[&bytes], "old.rar", None).unwrap();
            assert!(map.complete, "{kind:#x}");
            assert_eq!(map.members.len(), 2);
            assert_round_trips(&map.members[0], std::slice::from_ref(&bytes), &a, &[0..300, 150..151]);
            assert_round_trips(&map.members[1], std::slice::from_ref(&bytes), &b, &[0..200, 99..101]);
        }
    }
    // The old subblock and old recovery record carry their data size even without LONG_BLOCK, as unrar reads them.
    for kind in [0x77u8, 0x78] {
        let mut body = (rr.len() as u32).to_le_bytes().to_vec();
        body.extend([1, 2, 3]);
        let mut block = r4_block(kind, 0, &body);
        block.extend(&rr);
        let bytes = r4_archive(&[block, r4_member_dos(b"a.bin", &a, DOS, &[])]);
        let map = vol(&bytes, "old.rar", None).unwrap();
        assert_eq!(map.end, VolumeEnd::Complete);
        assert_eq!(packed_of(&bytes, &map.members[0]), &a[..]);
    }
}

#[test]
fn rar4_hostile_legacy_block_sizes_are_typed() {
    let a = data(100, 7);
    let member = r4_member_dos(b"a.bin", &a, DOS, &[]);
    // A header size below the fixed fields, and an old recovery record too short to hold its data size: damage
    // at that header, with the member before it.
    let at = (SIG.len() - 1 + 13 + member.len()) as u64;
    for (block, what) in [
        (r4_resize(r4_legacy(0x76, None), 3), "RAR4 header size"),
        (r4_block(0x78, 0, &[1, 2]), "header fields run past the header size"),
    ] {
        let bytes = r4_archive(&[member.clone(), block]);
        let map = vol(&bytes, "old.rar", None).unwrap();
        assert_eq!(map.end, VolumeEnd::Damaged { offset: at, reason: HeaderDamage::Malformed(what) });
        assert_eq!(map.members.len(), 1);
        let map = MemberMap::from_memory(&[&bytes], "old.rar", None).unwrap();
        assert_eq!(map.end, MapEnd::Damaged { volume: 0, offset: at, reason: HeaderDamage::Malformed(what) });
        assert_eq!((map.complete, map.members.len()), (false, 1));
    }
    // A data size or a header size running past the volume: the walk ends truncated at that block, with the
    // members before it.
    let mut huge = r4_block(0x77, 0x8000, &[0xff, 0xff, 0xff, 0xff, 0, 0, 0]);
    huge.extend(b"some bytes");
    let long = r4_resize(r4_legacy(0x75, None), 0xfff0);
    for block in [huge, long] {
        let bytes = r4_archive(&[member.clone(), block, member.clone()]);
        let map = vol(&bytes, "old.rar", None).unwrap();
        assert_eq!(map.members.len(), 1);
        assert!(matches!(map.end, VolumeEnd::Truncated { .. }), "{:?}", map.end);
        let map = MemberMap::from_memory(&[&bytes], "old.rar", None).unwrap();
        assert!(!map.complete);
        assert_eq!(map.members.len(), 1);
        assert!(matches!(map.end, MapEnd::Truncated { volume: 0, .. }), "{:?}", map.end);
    }
    // Skipped header bytes are charged to the header budget.
    let bytes = r4_archive(&[r4_block(0x75, 0, &vec![0x20; 4000]), member.clone()]);
    let mut options = MapOptions::new("old.rar");
    options.limits.header_bytes = 2000;
    assert!(matches!(
        MemberMap::from_volume(&bytes, options),
        Err(MapError::Limit { resource: zipfast::progressive::Resource::HeaderBytes, .. })
    ));
}

#[test]
fn rar4_trailing_header_fields_are_ignored_by_map_walks() {
    let (a, b) = (data(300, 8), data(200, 9));
    let bytes = r4_archive(&[
        r4_member_dos(b"a.bin", &a, DOS, &[0xde, 0xad, 0xbe, 0xef]),
        r4_member_dos(b"b.bin", &b, DOS, &[]),
    ]);
    let map = vol(&bytes, "old.rar", None).unwrap();
    let [first, second] = map.members.as_slice() else { panic!("{:?}", map.members) };
    assert_eq!(first.name.as_deref(), Some("a.bin"));
    assert_eq!(packed_of(&bytes, first), &a[..]);
    assert_eq!(packed_of(&bytes, second), &b[..]);
    let map = MemberMap::from_memory(&[&bytes], "old.rar", None).unwrap();
    assert!(map.complete);
    assert_round_trips(&map.members[0], std::slice::from_ref(&bytes), &a, &[0..300, 150..151]);
}

#[test]
fn rar4_dos_time_is_exposed_even_when_invalid() {
    // 2020-01-02 03:04:08, and the same with month 0.
    let valid = (40 << 25) | (1 << 21) | (2 << 16) | (3 << 11) | (4 << 5) | 4;
    let invalid = (40 << 25) | (2 << 16) | (3 << 11);
    let bytes = r4_archive(&[r4_member_dos(b"a.bin", b"aa", valid, &[]), r4_member_dos(b"b.bin", b"bb", invalid, &[])]);
    let map = vol(&bytes, "old.rar", None).unwrap();
    let [a, b] = map.members.as_slice() else { panic!("{:?}", map.members) };
    assert_eq!(a.dos_time, Some(valid));
    assert_eq!(a.mtime, Some((zipfast::extract::local_wall_clock_to_utc(1_577_934_248), 0)));
    assert_eq!(b.dos_time, Some(invalid));
    assert_eq!(b.mtime, None);
    let map = MemberMap::from_memory(&[&bytes], "old.rar", None).unwrap();
    assert_eq!((map.members[0].dos_time, map.members[1].dos_time), (Some(valid), Some(invalid)));
    assert_eq!(map.members[1].mtime, None);
    // RAR 5.0 has no DOS time.
    let bytes = archive(&[FileSpec::new("a.bin", b"x")]);
    assert_eq!(MemberMap::from_memory(&[&bytes], "x.rar", None).unwrap().members[0].dos_time, None);
    assert_eq!(vol(&bytes, "x.rar", None).unwrap().members[0].dos_time, None);
}

#[test]
fn rar4_old_comment_never_has_data_but_av_and_sign_follow_long_block() {
    // unrar reads an old comment's fixed fields and never an ADD_SIZE, even with LONG_BLOCK set; the AV and sign
    // blocks take their data size from LONG_BLOCK like any other block.
    let a = data(120, 3);
    let comment = r4_block(0x75, 0x8000, b"\x05\x00\x0f\x30\x00\x00stuff");
    let bytes = r4_archive(&[comment, r4_member_dos(b"a.bin", &a, DOS, &[])]);
    let map = vol(&bytes, "old.rar", None).unwrap();
    assert_eq!(map.end, VolumeEnd::Complete);
    assert_eq!(packed_of(&bytes, &map.members[0]), &a[..]);
    for kind in [0x76u8, 0x79] {
        let sig = data(40, 4);
        let bytes = r4_archive(&[r4_legacy(kind, Some(&sig)), r4_member_dos(b"a.bin", &a, DOS, &[])]);
        let map = vol(&bytes, "old.rar", None).unwrap();
        assert_eq!(map.end, VolumeEnd::Complete);
        assert_eq!(packed_of(&bytes, &map.members[0]), &a[..]);
        // Without LONG_BLOCK the same bytes after the header are read as the next header.
        let mut plain = r4_legacy(kind, Some(&sig));
        plain[3..5].copy_from_slice(&0u16.to_le_bytes());
        let crc = crc32fast::hash(&plain[2..7 + 10]) as u16;
        plain[..2].copy_from_slice(&crc.to_le_bytes());
        let bytes = r4_archive(&[plain, r4_member_dos(b"a.bin", &a, DOS, &[])]);
        assert!(!matches!(vol(&bytes, "old.rar", None).unwrap().end, VolumeEnd::Complete));
    }
}

#[test]
fn rar4_embedded_comments_and_odd_header_sizes_are_accepted_by_map_walks() {
    use zipfast::rar5::session::{RarSession, RarSessionOptions};
    let a = data(150, 5);
    let member = r4_member_dos(b"a.bin", &a, DOS, &[]);
    let with_main = |flags: u16, extra: &[u8]| {
        let mut body = vec![0; 6];
        body.extend(extra);
        let mut bytes = b"Rar!\x1a\x07\0".to_vec();
        bytes.extend(r4_block(0x73, flags, &body));
        bytes
    };
    // RAR 2.x: MHD_COMMENT with the comment block inside the main header, a main header with unknown extra
    // bytes, and LHD_COMMENT with the comment after the name. As RAR 2.x writes them (and unrar checks them),
    // the CRC of a commented header covers only what precedes the comment.
    let main_comment = r4_comment_crc(with_main(0x02, &r4_block(0x75, 0, b"\x05\x00\x0f\x30\x00\x00hello")), 7, 13);
    let comment = b"\x05\x00\x0f\x30\x00\x00file comment";
    let mut file_comment = r4_member_dos(b"a.bin", &[], DOS, comment);
    file_comment[3..5].copy_from_slice(&(0x8000u16 | 0x08).to_le_bytes());
    let file_comment = r4_comment_crc(file_comment.clone(), 0, file_comment.len() - comment.len());
    let cases = [
        (main_comment, member.clone()),
        (with_main(0x00, &[1, 2, 3]), member.clone()),
        (with_main(0x00, &[]), file_comment),
    ];
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("old.rar");
    for (case, (head, file)) in cases.into_iter().enumerate() {
        let mut bytes = head;
        bytes.extend(&file);
        bytes.extend(r4_block(0x7b, 0x4000, &[]));
        let map = vol(&bytes, "old.rar", None).unwrap();
        assert_eq!(map.end, VolumeEnd::Complete);
        assert!(map.main_read);
        let [listed] = map.members.as_slice() else { panic!("{:?}", map.members) };
        assert_eq!(listed.name.as_deref(), Some("a.bin"));
        assert_eq!(listed.packed.end, (bytes.len() - 7) as u64, "the end header follows the member's data");
        let map = MemberMap::from_memory(&[&bytes], "old.rar", None).unwrap();
        assert!(map.complete);
        // Sessions keep a main header comment (whose stored CRC here is wrong) and refuse the others.
        std::fs::write(&path, &bytes).unwrap();
        let session = RarSession::open(&path, None, RarSessionOptions::default());
        if case == 0 {
            assert!(session.unwrap().comment(0).is_err());
        } else {
            assert!(session.is_err());
        }
    }
    // End headers longer than their flags call for, and too short for the volume number they announce.
    for end in [r4_block(0x7b, 0x4000 | 0x8, &[2, 0, 9, 9]), r4_block(0x7b, 0x4000 | 0x8, &[2])] {
        let mut bytes = with_main(0x01, &[]);
        bytes.extend(&member);
        bytes.extend(end);
        let map = vol(&bytes, "old.r01", None).unwrap();
        assert_eq!(map.end, VolumeEnd::Complete);
        assert_eq!(map.members.len(), 1);
    }
    let mut bytes = with_main(0x01, &[]);
    bytes.extend(&member);
    bytes.extend(r4_block(0x7b, 0x4000 | 0x8, &[2, 0, 9, 9]));
    assert_eq!(vol(&bytes, "old.r01", None).unwrap().volume_number, Some(2));
}

#[test]
fn rar4_hp_with_an_encryption_version_byte_is_mapped() {
    let gold = b"continuous CBC across two unaligned boundaries with arbitrary trailing padding";
    let volumes = r4_aes(gold, true, &[29, 31, 20]);
    let with_version = |version: u8| -> Vec<Vec<u8>> {
        volumes
            .iter()
            .map(|v| {
                let mut out = v[..7].to_vec();
                out.extend(r4_block(0x73, 1 | 0x80 | 0x200, &[0, 0, 0, 0, 0, 0, version]));
                out.extend(&v[7 + 13..]);
                out
            })
            .collect()
    };
    let expected = MemberMap::from_memory(&refs(&volumes), "a.part01.rar", Some("pw")).unwrap();
    for version in [29, 36] {
        let set = with_version(version);
        let map = MemberMap::from_memory(&refs(&set), "a.part01.rar", Some("pw")).unwrap();
        assert!(map.complete && map.header_encrypted);
        assert_eq!(map.members[0].pieces.len(), expected.members[0].pieces.len());
        assert_eq!(map.members[0].raw_name, b"one");
        let single = vol(&set[1], "a.part02.rar", Some("pw")).unwrap();
        assert_eq!(single.end, VolumeEnd::Complete);
        assert_eq!(single.members[0].header.start, 7 + 14);
        assert_eq!(vol(&set[1], "a.part02.rar", None).unwrap().end, VolumeEnd::Locked { offset: 7 + 14 });
        assert!(matches!(vol(&set[1], "a.part02.rar", Some("wrong")), Err(MapError::WrongPassword)));
    }
    // A version newer than RAR 3.x's is a main header the walk cannot read.
    let error = vol(&with_version(37)[0], "a.part01.rar", Some("pw")).unwrap_err();
    assert!(matches!(error, MapError::Unsupported { volume: 0, .. }), "{error:?}");
}

#[test]
fn damage_after_the_main_header_keeps_what_was_read() {
    let (a, b) = (data(300, 1), data(200, 2));
    // RAR 4.x: a bad CRC, an unknown block that may not be skipped, and a broken name.
    let second = r4_member_dos(b"b.bin", &b, DOS, &[]);
    let mut bad_crc = second.clone();
    bad_crc[0] ^= 1;
    let mut bad_name = second.clone();
    bad_name[26..28].copy_from_slice(&200u16.to_le_bytes());
    let crc = crc32fast::hash(&bad_name[2..usize::from(u16::from_le_bytes([bad_name[5], bad_name[6]]))]) as u16;
    bad_name[..2].copy_from_slice(&crc.to_le_bytes());
    let first = r4_member_dos(b"a.bin", &a, DOS, &[]);
    let at = (7 + 13 + first.len()) as u64;
    for (block, reason) in [
        (bad_crc, HeaderDamage::Checksum),
        (r4_block(0x7c, 0, &[]), HeaderDamage::Unsupported("header type")),
        (bad_name, HeaderDamage::Malformed("header fields run past the header size")),
    ] {
        let mut bytes = b"Rar!\x1a\x07\0".to_vec();
        bytes.extend(r4_block(0x73, 0x01 | 0x10, &[0; 6]));
        bytes.extend(&first);
        bytes.extend(block);
        bytes.extend(&second);
        bytes.extend(r4_block(0x7b, 0x4000, &[]));
        let map = vol(&bytes, "old.r00", None).unwrap();
        assert_eq!(map.end, VolumeEnd::Damaged { offset: at, reason });
        assert!(map.main_read && map.multi_volume && map.new_naming && !map.has_next_volume);
        let [listed] = map.members.as_slice() else { panic!("{:?}", map.members) };
        assert_eq!(packed_of(&bytes, listed), &a[..]);
        let map = MemberMap::from_memory(&[&bytes], "old.part1.rar", None).unwrap();
        assert_eq!(map.end, MapEnd::Damaged { volume: 0, offset: at, reason });
        assert!(!map.complete);
        assert_eq!(map.volumes, 1);
        assert_eq!(map.members.len(), 1);
    }

    // RAR 5.0: the second file header's CRC.
    let bytes = archive(&[FileSpec::new("a.bin", &a), FileSpec::new("b.bin", &b)]);
    let clean = vol(&bytes, "x.rar", None).unwrap();
    let second_at = clean.members[1].header.start as usize;
    let mut broken = bytes.clone();
    broken[second_at] ^= 1;
    let map = vol(&broken, "x.rar", None).unwrap();
    assert_eq!(map.end, VolumeEnd::Damaged { offset: second_at as u64, reason: HeaderDamage::Checksum });
    assert_eq!(map.members, clean.members[..1]);
    assert_eq!(map.volume_number, Some(0));
    let map = MemberMap::from_memory(&[&broken], "x.rar", None).unwrap();
    assert_eq!(map.end, MapEnd::Damaged { volume: 0, offset: second_at as u64, reason: HeaderDamage::Checksum });
    assert_eq!(map.members.len(), 1);

    // A damaged main header still fails the walk.
    let mut bytes = r4_archive(&[r4_member_dos(b"a.bin", &a, DOS, &[])]);
    bytes[7] ^= 1;
    assert!(matches!(vol(&bytes, "old.rar", None), Err(MapError::Malformed { volume: 0, .. })));
    assert!(matches!(MemberMap::from_memory(&[&bytes], "old.rar", None), Err(MapError::Malformed { volume: 0, .. })));
    let mut broken = archive(&[FileSpec::new("a.bin", &a)]);
    broken[SIG.len()] ^= 1;
    assert!(matches!(vol(&broken, "x.rar", None), Err(MapError::Malformed { volume: 0, .. })));
}

#[test]
fn rar4_invalid_dos_times_come_back_raw() {
    let hour_24 = (40 << 25) | (1 << 21) | (2 << 16) | (24 << 11);
    let day_0 = (40 << 25) | (1 << 21) | (3 << 11);
    let all = u32::MAX;
    let bytes = r4_archive(&[
        r4_member_dos(b"a", b"a", hour_24, &[]),
        r4_member_dos(b"b", b"b", day_0, &[]),
        r4_member_dos(b"c", b"c", all, &[]),
    ]);
    let map = vol(&bytes, "old.rar", None).unwrap();
    let times: Vec<_> = map.members.iter().map(|m| (m.dos_time, m.mtime)).collect();
    assert_eq!(times, [(Some(hour_24), None), (Some(day_0), None), (Some(all), None)]);
    let map = MemberMap::from_memory(&[&bytes], "old.rar", None).unwrap();
    let times: Vec<_> = map.members.iter().map(|m| (m.dos_time, m.mtime)).collect();
    assert_eq!(times, [(Some(hour_24), None), (Some(day_0), None), (Some(all), None)]);
}

#[test]
fn rar4_commented_headers_are_checked_over_what_precedes_the_comment() {
    let a = data(90, 6);
    let mut main = b"Rar!\x1a\x07\0".to_vec();
    let mut body = vec![0; 6];
    body.extend(r4_block(0x75, 0, b"\x05\x00\x0f\x30\x00\x00hello"));
    main.extend(r4_block(0x73, 0x02, &body));
    let comment = b"\x05\x00\x0f\x30\x00\x00file comment";
    let mut file = r4_member_dos(b"a.bin", &a, DOS, comment);
    file[3..5].copy_from_slice(&(0x8000u16 | 0x08).to_le_bytes());
    let header_len = file.len() - a.len();
    let file_ok = r4_comment_crc(file.clone(), 0, header_len - comment.len());
    let main_ok = r4_comment_crc(main.clone(), 7, 13);
    let build = |main: &[u8], file: &[u8]| {
        let mut bytes = main.to_vec();
        bytes.extend(file);
        bytes.extend(file);
        bytes.extend(r4_block(0x7b, 0x4000, &[]));
        bytes
    };
    let bytes = build(&main_ok, &file_ok);
    let map = vol(&bytes, "old.rar", None).unwrap();
    assert_eq!(map.end, VolumeEnd::Complete);
    assert_eq!(map.members.len(), 2);
    assert_eq!(packed_of(&bytes, &map.members[1]), &a[..]);
    assert!(MemberMap::from_memory(&[&bytes], "old.rar", None).unwrap().complete);
    // A CRC over the whole main header is not what unrar checks: the main header cannot be read.
    let whole_main = r4_comment_crc(main.clone(), 7, main.len() - 7);
    assert!(matches!(vol(&build(&whole_main, &file_ok), "old.rar", None), Err(MapError::Malformed { volume: 0, .. })));
    // Nor is one over the whole file header, or one with the parsed fields changed.
    let whole_file = r4_comment_crc(file.clone(), 0, header_len);
    let mut changed = file_ok.clone();
    changed[11] ^= 1;
    for file in [whole_file, changed] {
        let map = vol(&build(&main_ok, &file), "old.rar", None).unwrap();
        assert_eq!(map.end, VolumeEnd::Damaged { offset: main_ok.len() as u64, reason: HeaderDamage::Checksum });
    }
    // The comment itself is not covered.
    let mut other_comment = file_ok.clone();
    other_comment[header_len - 3] ^= 0xff;
    assert_eq!(vol(&build(&main_ok, &other_comment), "old.rar", None).unwrap().members.len(), 2);
}

#[test]
fn rar4_av_sign_and_unix_owner_blocks_are_not_crc_checked() {
    let a = data(80, 7);
    let member = r4_member_dos(b"a.bin", &a, DOS, &[]);
    let broken = |mut block: Vec<u8>| {
        block[0] ^= 0x5a;
        block
    };
    // UO_HEAD (subtype 0x0101) after the data size, then a level byte and owner names.
    let uo = r4_block(0x77, 0, &[0, 0, 0, 0, 0x01, 0x01, 0, b'u', b'g']);
    let other_subblock = r4_block(0x77, 0, &[0, 0, 0, 0, 0x02, 0x01, 0, b'x']);
    for block in [broken(r4_legacy(0x76, None)), broken(r4_legacy(0x79, Some(b"sig"))), broken(uo)] {
        let bytes = r4_archive(&[block, member.clone()]);
        let map = vol(&bytes, "old.rar", None).unwrap();
        assert_eq!(map.end, VolumeEnd::Complete);
        assert_eq!(packed_of(&bytes, &map.members[0]), &a[..]);
        assert!(MemberMap::from_memory(&[&bytes], "old.rar", None).unwrap().complete);
    }
    // Every other block is still checked.
    for block in [broken(other_subblock), broken(r4_legacy(0x75, None)), broken(r4_legacy(0x78, Some(b"rr")))] {
        let bytes = r4_archive(&[member.clone(), block]);
        let map = vol(&bytes, "old.rar", None).unwrap();
        assert_eq!(
            map.end,
            VolumeEnd::Damaged { offset: (7 + 13 + member.len()) as u64, reason: HeaderDamage::Checksum }
        );
        assert_eq!(map.members.len(), 1);
    }
}

#[test]
fn limits_after_the_main_header_stay_errors() {
    let (a, b) = (data(300, 1), data(200, 2));
    let bytes = r4_archive(&[r4_member_dos(b"a.bin", &a, DOS, &[]), r4_member_dos(b"b.bin", &b, DOS, &[])]);
    for limits in [
        |l: &mut zipfast::progressive::ProgressiveLimits| l.entries = 1,
        |l: &mut zipfast::progressive::ProgressiveLimits| l.header_blocks = 2,
    ] {
        let mut options = MapOptions::new("old.rar");
        limits(&mut options.limits);
        let error = MemberMap::from_volume(&bytes, options.clone()).unwrap_err();
        assert!(matches!(error, MapError::Limit { .. }), "{error:?}");
        let error = MemberMap::from_memory_with(&[&bytes], options).unwrap_err();
        assert!(matches!(error, MapError::Limit { .. }), "{error:?}");
    }
}

// Catches a RAR4 Unicode-flagged name with nothing (or nothing decodable) after its NUL being treated as damage;
// unrar decodes the Unicode part only when the field is longer than the legacy name and its NUL.
#[test]
fn rar4_unicode_name_without_an_encoded_part_falls_back_to_the_legacy_name() {
    let gold = data(64, 3);
    for field in [&b"movie.mkv\0"[..], &b"movie.mkv\0\0"[..]] {
        let bytes = r4_archive(&[r4_member(field, &gold, 0x200, 0x30, gold.len(), crc32fast::hash(&gold))]);
        let volume = vol(&bytes, "x.rar", None).unwrap();
        assert_eq!(volume.end, VolumeEnd::Complete, "{field:?}");
        assert_eq!(volume.members.len(), 1);
        assert_eq!(volume.members[0].name.as_deref(), Some("movie.mkv"));
        let map = MemberMap::from_memory(&[&bytes], "x.rar", None).unwrap();
        assert!(map.complete);
        assert_eq!(map.members[0].name.as_deref(), Some("movie.mkv"));
        let piece = &map.members[0].pieces[0];
        assert_eq!(&bytes[piece.packed.start as usize..piece.packed.end as usize], &gold[..]);
    }
}

// Catches decoding stricter than unrar's: the name ends at the first NUL unit, data running out keeps what was
// decoded (or falls back), and a legacy fallback that is not UTF-8 is listed raw by map walks.
#[test]
fn rar4_unicode_name_decodes_as_unrar_does() {
    let gold = data(64, 5);
    let cases: [(&[u8], Option<&str>); 5] = [
        // High byte 0, then flags 00 (literal) units "\0\0": decodes to an empty name, so the legacy name is used.
        (b"movie.mkv\0\0\x00\x00\x00", Some("movie.mkv")),
        // Literal "ab" then NUL padding: the name ends at the first NUL unit.
        (b"ab\0\0\x00ab\x00\x00", Some("ab")),
        // A 16-bit op with one byte left is skipped (unrar's switch-level break); the next 1-byte op reads "A".
        (b"movie.mkv\0\0\x80\x41", Some("A")),
        // A 16-bit op with nothing after it: nothing decodes, so the legacy name is used.
        (b"movie.mkv\0\0\x80", Some("movie.mkv")),
        // An OEM legacy part behind a Unicode flag with nothing encoded: listed raw, no decoded name.
        (b"caf\x82\0", None),
    ];
    for (field, want) in cases {
        let bytes = r4_archive(&[r4_member(field, &gold, 0x200, 0x30, gold.len(), crc32fast::hash(&gold))]);
        let volume = vol(&bytes, "x.rar", None).unwrap();
        assert_eq!(volume.end, VolumeEnd::Complete, "{field:?}");
        assert_eq!(volume.members.len(), 1, "{field:?}");
        assert_eq!(volume.members[0].name.as_deref(), want, "{field:?}");
    }
}

// Catches two departures from unrar's decoder: an incomplete 16-bit op must not end decoding, and a run must stop
// at the end of the name field instead of padding with zeros.
#[test]
fn rar4_unicode_decoding_skips_incomplete_ops_and_clips_runs() {
    let gold = data(32, 7);
    // flags 0b10_01_.. : a 16-bit op with one byte left is skipped, then the 1-byte op reads that byte as "A".
    let skipped = b"zz\0\0\x60A";
    // flags 0b11_.. : a corrected run of 2+10 units over a 7-byte field stops after 7 units (each byte + 1),
    // where padding with zeros would add five more `high|correction` units.
    let clipped = b"ab\0\0\xc0\x8a\x01";
    let want = "bc\u{1}\u{1}\u{c1}\u{8b}\u{2}";
    for (field, want) in [(&skipped[..], "A"), (&clipped[..], want)] {
        let bytes = r4_archive(&[r4_member(field, &gold, 0x200, 0x30, gold.len(), crc32fast::hash(&gold))]);
        let volume = vol(&bytes, "x.rar", None).unwrap();
        assert_eq!(volume.members[0].name.as_deref(), Some(want), "{field:?}");
    }
}

/// Every RAR member lists the dictionary size its header declares, `-hp` headers included; ZIP and 7z do not.
#[test]
fn rar_members_list_their_dictionary_size() {
    let a = data(5000, 1);
    let bytes = archive(&[FileSpec::new("a.bin", &a)]);
    let map = MemberMap::from_memory(&[&bytes], "x.rar", None).unwrap();
    // the test writer's compression info leaves the dictionary bits 0: 128 KiB
    assert_eq!(map.members[0].dictionary, Some(128 << 10));
    let hp = hp_archive(&data(700, 5));
    let map = MemberMap::from_memory(&[&hp], "hp.rar", Some(HP_PASSWORD)).unwrap();
    assert_eq!(map.members[0].dictionary, Some(128 << 10), "known from decrypted headers");
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rar4");
    let mut seen = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "rar") {
            continue;
        }
        let bytes = std::fs::read(&path).unwrap();
        let Ok(map) = MemberMap::from_memory(&[&bytes], path.file_name().unwrap(), None) else { continue };
        for m in map.members.iter().filter(|m| !m.is_dir) {
            let d = m.dictionary.unwrap_or_else(|| panic!("{path:?} {:?}", m.name));
            assert!(d.is_power_of_two() && (64 << 10..=4 << 20).contains(&d), "{path:?}: {d}");
            seen += 1;
        }
    }
    assert!(seen > 0, "some RAR 4.x members were checked");
}
