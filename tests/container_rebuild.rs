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

//! `map::ContainerRebuilder`: a copy's volume bytes rebuilt from held output, compared byte for byte with the real
//! volumes. Archives are written here (RAR 5.0 plain and AES stored, WinZip AES) or taken from the 7z and RAR 4.x
//! fixtures. The z-fixture sets are in `tests/container_rebuild_z.rs`.

mod common;

use common::*;
use std::ops::Range;
use std::path::{Path, PathBuf};
use zipfast::crypto::{decrypt_cbc, derive_7z_key, derive_rar4_key_iv, derive_rar5_key, encrypt_cbc};
use zipfast::map::{
    ByteState, CipherParams, ContainerRebuilder, Crc32Check, HeaderGap, HeaderSource, HeldMembers, KeyProblem,
    KnownBytes, Layer, MemberMap, Missing, OpenAtOptions, RebuildOptions, Rebuilt, RebuiltRange, VolumeHeaders,
    open_at, skipped_spans,
};

const PASSWORD: &str = "rebuild-test-pw";
const SALT: [u8; 16] = [0x31; 16];
const IV: [u8; 16] = [0x7e; 16];
const KDF_COUNT: u8 = 4;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}

fn payload(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

fn refs(volumes: &[Vec<u8>]) -> Vec<&[u8]> {
    volumes.iter().map(Vec::as_slice).collect()
}

/// Every rebuilt byte equals the volume's; returns how many were rebuilt.
fn assert_exact(got: &RebuiltRange, volume: &[u8]) -> u64 {
    let mut n = 0;
    for r in &got.regions {
        if matches!(r.state, ByteState::Rebuilt(_)) {
            for o in r.range.clone() {
                assert_eq!(
                    got.bytes[(o - got.range.start) as usize],
                    volume[o as usize],
                    "volume {} byte {o} ({:?})",
                    got.volume,
                    r.state
                );
            }
            n += r.range.end - r.range.start;
        }
    }
    // regions cover the range back to back
    let mut at = got.range.start;
    for r in &got.regions {
        assert_eq!(r.range.start, at);
        at = r.range.end;
    }
    assert_eq!(at, got.range.end);
    n
}

fn data_ranges(map: &MemberMap, volume: u32) -> Vec<Range<u64>> {
    map.members.iter().flat_map(|m| m.pieces.iter()).filter(|p| p.volume == volume).map(|p| p.packed.clone()).collect()
}

/// The reasons bytes of `range` were not rebuilt, adjacent repeats once.
fn missing_in(got: &RebuiltRange, range: Range<u64>) -> Vec<Missing> {
    let mut out: Vec<Missing> = got
        .regions
        .iter()
        .filter(|r| r.range.start < range.end && r.range.end > range.start)
        .filter_map(|r| match &r.state {
            ByteState::Missing(m) => Some(m.clone()),
            _ => None,
        })
        .collect();
    out.dedup();
    out
}

// ---------------------------------------------------------------------------------------------------------------
// RAR 5.0 stored, plain.

/// rar's end of archive header: flagged to be skipped when unknown (0x4), as rar 7.x writes it.
fn rar_end_block(more: bool) -> Vec<u8> {
    let mut fields = Vec::new();
    vint(u64::from(more), &mut fields);
    block(5, 4, &fields, &[], &[], false)
}

/// [`volumes`] with rar's end of archive header.
fn rar_like_volumes(spec: &FileSpec<'_>, chunk: usize) -> Vec<Vec<u8>> {
    let parts: Vec<&[u8]> = spec.data.chunks(chunk).collect();
    let n = parts.len();
    parts
        .iter()
        .enumerate()
        .map(|(i, part)| {
            let mut out = SIG.to_vec();
            out.extend(main_block(true, (i > 0).then_some(i as u64)));
            let last = i + 1 == n;
            let crc = if last { crc32fast::hash(spec.data) } else { crc32fast::hash(part) };
            out.extend(file_block(spec, part, crc, i > 0, !last));
            out.extend(rar_end_block(!last));
            out
        })
        .collect()
}

#[test]
fn plain_rar5_volumes_rebuild_their_data_and_tails() {
    let data = payload(100_000, 1);
    let spec = FileSpec::new("video.mkv", &data);
    let vols = rar_like_volumes(&spec, 19_753);
    let map = MemberMap::from_memory(&refs(&vols), "v.part1.rar", None).unwrap();
    let mut rb = ContainerRebuilder::new(&map, None);
    let mut held = HeldMembers::new().with(0, &data, None);
    for (v, vol) in vols.iter().enumerate() {
        let v = v as u32;
        let data_at = data_ranges(&map, v);
        // without header sources: the data only
        let got = rb.rebuild(v, 0..vol.len() as u64, &mut held, &mut RebuildOptions::default()).unwrap();
        assert_eq!(assert_exact(&got, vol), data_at.iter().map(|r| r.end - r.start).sum::<u64>());
        assert!(got.missing().all(|r| r.state == ByteState::Missing(Missing::Header(HeaderGap::NoSource))));
        // the plain data maps to output offsets
        let first = got.regions.iter().find(|r| r.member == Some(0)).unwrap();
        assert_eq!(first.state, ByteState::Rebuilt(Rebuilt::Plain));
        assert_eq!(first.output.as_ref().unwrap().start, map.members[0].pieces[v as usize].stream_offset);
        // with the volume's headers before the data, the tail comes back too
        let head = &vol[..data_at[0].start as usize];
        let headers = VolumeHeaders {
            volume_len: vol.len() as u64,
            head: Some(head),
            more_volumes: Some(v as usize + 1 < vols.len()),
            ..Default::default()
        };
        let mut options = RebuildOptions { headers: Some(headers), ..Default::default() };
        let got = rb.rebuild(v, 0..vol.len() as u64, &mut held, &mut options).unwrap();
        let rebuilt = assert_exact(&got, vol);
        let tail = got.regions.last().unwrap();
        assert_eq!(tail.state, ByteState::Rebuilt(Rebuilt::Header(HeaderSource::Tail)));
        // only the start (signature, main and file header) is left: these sets have no quick open data
        assert_eq!(rebuilt, vol.len() as u64 - data_at[0].start);
        assert!(got.missing().all(|r| matches!(r.state, ByteState::Missing(Missing::Header(HeaderGap::NoSource)))));
    }
}

#[test]
fn holes_in_held_output_are_reported_with_their_output_offsets() {
    let data = payload(50_000, 2);
    let spec = FileSpec::new("f", &data);
    let vols = volumes(&spec, 30_000);
    let map = MemberMap::from_memory(&refs(&vols), "v.part1.rar", None).unwrap();
    let mut rb = ContainerRebuilder::new(&map, None);
    let mut held = HeldMembers::new().with(0, &data, Some(vec![0..10_000, 12_345..50_000]));
    let got = rb.rebuild(0, 0..vols[0].len() as u64, &mut held, &mut RebuildOptions::default()).unwrap();
    assert_exact(&got, &vols[0]);
    let hole = got.regions.iter().find(|r| r.state == ByteState::Missing(Missing::NotHeld)).unwrap();
    assert_eq!(hole.output, Some(10_000..12_345));
    assert_eq!(hole.member, Some(0));
    let start = map.members[0].pieces[0].packed.start;
    assert_eq!(hole.range, start + 10_000..start + 12_345);
    // a closure works as a held source too
    let mut f = |_m: usize, off: u64, buf: &mut [u8]| {
        let end = (off + buf.len() as u64).min(data.len() as u64);
        buf[..(end - off) as usize].copy_from_slice(&data[off as usize..end as usize]);
        std::iter::once(off..end).collect()
    };
    let got = rb.rebuild(1, 0..vols[1].len() as u64, &mut f, &mut RebuildOptions::default()).unwrap();
    assert_eq!(assert_exact(&got, &vols[1]), 20_000);
}

// ---------------------------------------------------------------------------------------------------------------
// RAR 5.0 stored, AES.

fn encryption_record() -> Vec<u8> {
    let mut body = vec![1, 0, 0, KDF_COUNT];
    body.extend(SALT);
    body.extend(IV);
    let mut record = Vec::new();
    vint(body.len() as u64, &mut record);
    record.extend(body);
    record
}

/// An AES stored member cut into volumes of `chunk` ciphertext bytes, the final block padded with `padding`.
fn aes_volumes(data: &[u8], chunk: usize, padding: &[u8]) -> Vec<Vec<u8>> {
    let key = derive_rar5_key(PASSWORD, KDF_COUNT, &SALT, None).unwrap();
    let mut padded = data.to_vec();
    assert_eq!((data.len() + padding.len()) % 16, 0);
    padded.extend_from_slice(padding);
    let ct = encrypt_cbc(&key, &IV, &padded).unwrap();
    let mut spec = FileSpec::new("secret.mkv", data);
    spec.extra = encryption_record();
    let parts: Vec<&[u8]> = ct.chunks(chunk).collect();
    let n = parts.len();
    parts
        .iter()
        .enumerate()
        .map(|(i, part)| {
            let mut out = SIG.to_vec();
            out.extend(main_block(true, (i > 0).then_some(i as u64)));
            let last = i + 1 == n;
            let crc = if last { crc32fast::hash(data) } else { crc32fast::hash(part) };
            out.extend(file_block(&spec, part, crc, i > 0, !last));
            out.extend(end_block(!last));
            out
        })
        .collect()
}

#[test]
fn aes_rar5_volumes_rebuild_byte_for_byte_with_the_final_block_from_a_crc() {
    let data = payload(100_014, 3); // 2 bytes of padding
    let vols = aes_volumes(&data, 19_753, &[0xa7, 0x3c]);
    let map = MemberMap::from_memory(&refs(&vols), "s.part1.rar", Some(PASSWORD)).unwrap();
    assert!(matches!(map.members[0].cipher, Some(CipherParams::Rar5 { .. })));
    let mut rb = ContainerRebuilder::new(&map, Some(PASSWORD));
    let mut held = HeldMembers::new().with(0, &data, None);
    let last = vols.len() - 1;
    for (v, vol) in vols.iter().enumerate() {
        let vi = v as u32;
        let d = data_ranges(&map, vi)[0].clone();
        let got = rb.rebuild(vi, 0..vol.len() as u64, &mut held, &mut RebuildOptions::default()).unwrap();
        let n = assert_exact(&got, vol);
        if v < last {
            assert_eq!(n, d.end - d.start, "volume {v}: all data rebuilt");
        } else {
            // the final block waits for a check
            assert_eq!(n, d.end - d.start - 16);
            assert_eq!(missing_in(&got, d.end - 16..d.end), [Missing::FinalPadding { pad: 2, searched: false }]);
            // the article's CRC32, with the header bytes known, decides it
            let known = vec![
                KnownBytes { volume: vi, offset: 0, bytes: &vol[..d.start as usize] },
                KnownBytes { volume: vi, offset: d.end, bytes: &vol[d.end as usize..] },
            ];
            let check = Crc32Check { volume: vi, range: 0..vol.len() as u64, crc32: crc32fast::hash(vol) };
            let mut options = RebuildOptions { known, checks: vec![check], ..Default::default() };
            let got = rb.rebuild(vi, 0..vol.len() as u64, &mut held, &mut options).unwrap();
            assert_eq!(assert_exact(&got, vol), d.end - d.start);
            let fin = got.regions.iter().find(|r| r.range.contains(&(d.end - 1))).unwrap();
            assert_eq!(fin.state, ByteState::Rebuilt(Rebuilt::CbcFinal { pad: 2, searched: true }));
            assert!(got.conflicts.is_empty());
            // or a callback of the caller's
            let real: [u8; 16] = vol[d.end as usize - 16..d.end as usize].try_into().unwrap();
            let mut accept = |b: &zipfast::map::FinalBlock| b.block == real;
            let mut options = RebuildOptions { accept: Some(&mut accept), ..Default::default() };
            let got = rb.rebuild(vi, d.end - 40..d.end, &mut held, &mut options).unwrap();
            assert!(got.complete());
            assert_eq!(&got.bytes[..], &vol[d.end as usize - 40..d.end as usize]);
        }
    }
}

#[test]
fn a_final_block_cut_by_an_article_boundary_needs_both_articles_crcs() {
    let data = payload(100_014, 11); // 2 bytes of padding: 65,536 candidates
    let vols = aes_volumes(&data, 19_753, &[0x5e, 0xe1]);
    let map = MemberMap::from_memory(&refs(&vols), "s.part1.rar", Some(PASSWORD)).unwrap();
    let last = vols.len() - 1;
    let (vi, vol) = (last as u32, &vols[last]);
    let d = data_ranges(&map, vi)[0].clone();
    let real = &vol[d.end as usize - 16..d.end as usize];
    // the first article ends one byte into the final block, the second holds the rest and the tail
    let cut = d.end - 15;
    let known = || {
        vec![
            KnownBytes { volume: vi, offset: 0, bytes: &vol[..d.start as usize] },
            KnownBytes { volume: vi, offset: d.end, bytes: &vol[d.end as usize..] },
        ]
    };
    let first = Crc32Check { volume: vi, range: 0..cut, crc32: crc32fast::hash(&vol[..cut as usize]) };
    let second = Crc32Check { volume: vi, range: cut..vol.len() as u64, crc32: crc32fast::hash(&vol[cut as usize..]) };
    let mut held = HeldMembers::new().with(0, &data, None);
    // the first article's CRC sees one byte of the block: about 256 paddings pass it
    let mut rb = ContainerRebuilder::new(&map, Some(PASSWORD));
    let mut options = RebuildOptions { known: known(), checks: vec![first.clone()], ..Default::default() };
    let got = rb.rebuild(vi, 0..vol.len() as u64, &mut held, &mut options).unwrap();
    assert_exact(&got, vol);
    let block: Vec<&zipfast::map::Region> =
        got.regions.iter().filter(|r| r.range.start < d.end && r.range.end > d.end - 16).collect();
    // the checked byte is certain; the other 15 are not
    assert_eq!(block[0].range, d.end - 16..d.end - 15);
    assert!(matches!(block[0].state, ByteState::Rebuilt(Rebuilt::CbcFinal { .. })));
    let ambiguous: u64 = block
        .iter()
        .filter(|r| matches!(r.state, ByteState::Missing(Missing::FinalPaddingAmbiguous { pad: 2, candidates }) if candidates > 1))
        .map(|r| r.range.end.min(d.end) - r.range.start.max(d.end - 16))
        .sum();
    assert_eq!(ambiguous, 15);
    // both articles' CRCs together leave one padding
    let mut rb = ContainerRebuilder::new(&map, Some(PASSWORD));
    let mut options = RebuildOptions { known: known(), checks: vec![first, second], ..Default::default() };
    let got = rb.rebuild(vi, 0..vol.len() as u64, &mut held, &mut options).unwrap();
    assert_eq!(assert_exact(&got, vol), d.end - d.start);
    assert_eq!(&got.bytes[d.end as usize - 16..d.end as usize], real);
}

#[test]
fn aes_ranges_cutting_through_blocks_and_volumes_rebuild_exactly() {
    let data = payload(70_000, 4);
    let vols = aes_volumes(&data, 9_999, &[0; 0]);
    let map = MemberMap::from_memory(&refs(&vols), "s.part1.rar", Some(PASSWORD)).unwrap();
    let mut held = HeldMembers::new().with(0, &data, None);
    // a fresh rebuilder per range, so every range chains from the IV or nothing
    for (v, a, b) in [(0u32, 0u64, 100u64), (1, 7, 9), (2, 1_000, 1_017), (3, 33, 10_000), (6, 5, 200), (4, 0, 10_100)]
    {
        let vol = &vols[v as usize];
        let b = b.min(vol.len() as u64);
        let mut rb = ContainerRebuilder::new(&map, Some(PASSWORD));
        let got = rb.rebuild(v, a..b, &mut held, &mut RebuildOptions::default()).unwrap();
        assert_exact(&got, vol);
        let d = data_ranges(&map, v)[0].clone();
        let want = b.min(d.end).saturating_sub(a.max(d.start));
        assert_eq!(got.rebuilt_len(), want, "volume {v} {a}..{b}");
    }
}

#[test]
fn a_hole_breaks_the_cbc_chain_until_known_bytes_give_the_previous_block() {
    let data = payload(64_000, 5);
    let vols = aes_volumes(&data, 16_000, &[]);
    let map = MemberMap::from_memory(&refs(&vols), "s.part1.rar", Some(PASSWORD)).unwrap();
    // output 20_000..21_000 is not held; volume 1 carries stream 16_000..32_000
    let mut held = HeldMembers::new().with(0, &data, Some(vec![0..20_000, 21_000..64_000]));
    let mut rb = ContainerRebuilder::new(&map, Some(PASSWORD));
    let vol = &vols[1];
    let d = data_ranges(&map, 1)[0].clone();
    let got = rb.rebuild(1, 0..vol.len() as u64, &mut held, &mut RebuildOptions::default()).unwrap();
    assert_exact(&got, vol);
    let states: Vec<_> =
        got.regions.iter().filter(|r| r.member == Some(0)).map(|r| (r.output.clone(), r.state.clone())).collect();
    assert_eq!(
        states,
        [
            (Some(16_000..20_000), ByteState::Rebuilt(Rebuilt::Cbc)),
            (Some(20_000..21_008), ByteState::Missing(Missing::NotHeld)),
            (Some(21_008..32_000), ByteState::Missing(Missing::Chain)),
        ]
    );
    // the block before 30_000 known (downloaded): the chain restarts there
    let at = d.start + (29_984 - 16_000);
    let known = vec![KnownBytes { volume: 1, offset: at, bytes: &vol[at as usize..at as usize + 16] }];
    let mut rb = ContainerRebuilder::new(&map, Some(PASSWORD));
    let mut options = RebuildOptions { known, ..Default::default() };
    let got = rb.rebuild(1, d.start + 14_000..d.end, &mut held, &mut options).unwrap();
    assert_eq!(assert_exact(&got, vol), 2_000);
    assert!(got.conflicts.is_empty());
    // a chain limit leaves the range unrebuilt rather than encrypting far
    let mut rb = ContainerRebuilder::new(&map, Some(PASSWORD));
    let mut held = HeldMembers::new().with(0, &data, None);
    let mut options = RebuildOptions { max_chain: Some(1_000), ..Default::default() };
    let got = rb.rebuild(2, 0..vols[2].len() as u64, &mut held, &mut options).unwrap();
    assert_eq!(got.rebuilt_len(), 0);
    assert!(got.missing().any(|r| r.state == ByteState::Missing(Missing::Chain)));
    // a rebuilder that already went through volume 1 continues from its checkpoint
    let mut rb = ContainerRebuilder::new(&map, Some(PASSWORD));
    rb.rebuild(1, 0..vol.len() as u64, &mut held, &mut RebuildOptions::default()).unwrap();
    let got = rb.rebuild(2, 0..vols[2].len() as u64, &mut held, &mut options).unwrap();
    assert_eq!(assert_exact(&got, &vols[2]), 16_000);
}

#[test]
fn a_wrong_password_shows_as_conflicts_with_known_bytes_and_none_without_one() {
    let data = payload(10_000, 6);
    let vols = aes_volumes(&data, 6_000, &[]);
    let map = MemberMap::from_memory(&refs(&vols), "s.part1.rar", Some(PASSWORD)).unwrap();
    let mut held = HeldMembers::new().with(0, &data, None);
    let mut rb = ContainerRebuilder::new(&map, Some("not-it"));
    let known = vec![KnownBytes { volume: 0, offset: 0, bytes: &vols[0] }];
    let mut options = RebuildOptions { known, ..Default::default() };
    let got = rb.rebuild(0, 0..vols[0].len() as u64, &mut held, &mut options).unwrap();
    assert!(!got.conflicts.is_empty());
    let mut rb = ContainerRebuilder::new(&map, None);
    let got = rb.rebuild(0, 0..vols[0].len() as u64, &mut held, &mut RebuildOptions::default()).unwrap();
    assert!(got.missing().any(|r| r.state == ByteState::Missing(Missing::Key(KeyProblem::NoPassword))));
    assert_eq!(got.rebuilt_len(), 0);
}

#[test]
fn a_member_filter_leaves_other_members_bytes() {
    let a = payload(3_000, 7);
    let b = payload(4_000, 8);
    let archive = archive(&[FileSpec::new("a", &a), FileSpec::new("b", &b)]);
    let map = MemberMap::from_memory(&[&archive], "x.rar", None).unwrap();
    let mut rb = ContainerRebuilder::new(&map, None);
    assert_eq!(rb.members_on(0), [0, 1]);
    let mut held = HeldMembers::new().with(0, &a, None).with(1, &b, None);
    let mut options = RebuildOptions { member: Some(1), ..Default::default() };
    let got = rb.rebuild(0, 0..archive.len() as u64, &mut held, &mut options).unwrap();
    assert_eq!(assert_exact(&got, &archive), 4_000);
    assert!(got.missing().any(|r| r.state == ByteState::Missing(Missing::OtherMember) && r.member == Some(0)));
    let got = rb.rebuild(0, 0..archive.len() as u64, &mut held, &mut RebuildOptions::default()).unwrap();
    assert_eq!(assert_exact(&got, &archive), 7_000);
    let mut options = RebuildOptions { member: Some(2), ..Default::default() };
    assert!(rb.rebuild(0, 0..10, &mut held, &mut options).is_err());
    assert!(rb.rebuild(0, 10..10, &mut held, &mut RebuildOptions::default()).is_err());
}

// ---------------------------------------------------------------------------------------------------------------
// Compressed members.

#[test]
fn compressed_members_are_missing_except_what_a_handover_plan_skips() {
    let packed = payload(200_000, 9);
    let mut spec = FileSpec::new("c.mkv", &packed);
    spec.method = 3;
    spec.size = Some(1_000_000);
    let vols = volumes(&spec, 50_000);
    let map = MemberMap::from_memory(&refs(&vols), "c.part1.rar", None).unwrap();
    let mut rb = ContainerRebuilder::new(&map, None);
    let mut held = HeldMembers::new();
    let got = rb.rebuild(1, 0..vols[1].len() as u64, &mut held, &mut RebuildOptions::default()).unwrap();
    assert_eq!(got.rebuilt_len(), 0);
    assert!(got.missing().any(|r| r.state == ByteState::Missing(Missing::Compressed(Layer::Rar5Compressed))));
    let plan = open_at(&map, 0, 900_000, &OpenAtOptions { search: Some(5_000), ..Default::default() }).unwrap();
    assert_eq!(plan.fetch_from, 175_000);
    let skipped = skipped_spans(&map, &plan);
    assert_eq!(skipped.iter().map(|s| s.stream.end - s.stream.start).sum::<u64>(), 175_000);
    let plans = [plan];
    let mut options = RebuildOptions { plans: &plans, ..Default::default() };
    for v in 0..4u32 {
        let got = rb.rebuild(v, 0..vols[v as usize].len() as u64, &mut held, &mut options).unwrap();
        let data = data_ranges(&map, v)[0].clone();
        let unneeded = if v < 3 { 50_000 } else { 25_000 };
        assert_eq!(got.unneeded_len(), unneeded, "volume {v}");
        let compressed = got.len_where(|s| *s == ByteState::Missing(Missing::Compressed(Layer::Rar5Compressed)));
        assert_eq!(compressed, data.end - data.start - unneeded);
    }
}

// ---------------------------------------------------------------------------------------------------------------
// WinZip AES.

#[test]
fn winzip_aes_stored_entries_rebuild_with_prefix_and_authentication_code() {
    use std::io::Cursor;
    use zipfast::zip::write::{
        AesStrength, AesVariant, DosDateTime, EntryName, EntryOptions, InputLength, Method, Permissions,
        WinZipAesRequest, WriterOptions, ZipStreamWriter,
    };
    let data = payload(100_000, 10);
    for strength in [AesStrength::Aes128, AesStrength::Aes256] {
        let mut writer = ZipStreamWriter::new(Vec::new(), WriterOptions::default()).unwrap();
        let options = EntryOptions {
            name: EntryName::Utf8("v.mkv"),
            method: Method::Stored,
            modified: DosDateTime::default(),
            extended_mtime: None,
            permissions: Permissions::new(0o644).unwrap(),
            comment: b"",
        };
        let request = WinZipAesRequest::new(PASSWORD, strength, AesVariant::Ae2).unwrap();
        writer
            .add_winzip_aes_file(
                options,
                &mut Cursor::new(&data),
                InputLength::Exact(data.len() as u64),
                request,
                |s| {
                    s.fill(0x42);
                    Ok(())
                },
            )
            .unwrap();
        let zip = writer.finish().unwrap().sink;
        let map = MemberMap::from_memory(&[&zip], "a.zip", None).unwrap();
        let d = data_ranges(&map, 0)[0].clone();
        let mut rb = ContainerRebuilder::new(&map, Some(PASSWORD));
        let mut held = HeldMembers::new().with(0, &data, None);
        let got = rb.rebuild(0, 0..zip.len() as u64, &mut held, &mut RebuildOptions::default()).unwrap();
        assert_eq!(assert_exact(&got, &zip), d.end - d.start);
        let kinds: Vec<_> = got.regions.iter().filter(|r| r.member.is_some()).map(|r| r.state.clone()).collect();
        assert_eq!(
            kinds,
            [
                ByteState::Rebuilt(Rebuilt::CounterPrefix),
                ByteState::Rebuilt(Rebuilt::Counter),
                ByteState::Rebuilt(Rebuilt::CounterAuth)
            ]
        );
        assert!(got.missing().all(|r| r.state == ByteState::Missing(Missing::Header(HeaderGap::NotRar5))));
        // a range in the middle, not on a counter block
        let got = rb.rebuild(0, d.start + 1_001..d.start + 5_555, &mut held, &mut RebuildOptions::default()).unwrap();
        assert!(got.complete());
        assert_exact(&got, &zip);
        // a hole: the authentication code needs the whole output
        let mut rb = ContainerRebuilder::new(&map, Some(PASSWORD));
        let mut held = HeldMembers::new().with(0, &data, Some(vec![0..50_000, 50_100..100_000]));
        let got = rb.rebuild(0, d.clone(), &mut held, &mut RebuildOptions::default()).unwrap();
        assert_exact(&got, &zip);
        assert_eq!(missing_in(&got, d.end - 10..d.end), [Missing::AuthCode]);
        let mut rb = ContainerRebuilder::new(&map, Some("wrong"));
        let got = rb.rebuild(0, d.clone(), &mut held, &mut RebuildOptions::default()).unwrap();
        assert!(got.missing().any(|r| r.state == ByteState::Missing(Missing::Key(KeyProblem::WrongPassword))));
    }
}

// ---------------------------------------------------------------------------------------------------------------
// 7z.

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap()
}

#[test]
fn sevenzip_aes_over_copy_rebuilds_its_folder_with_zero_padding() {
    let archive = read(&fixture("7z/encrypted_headers.7z"));
    let map = MemberMap::from_memory(&[&archive], "e.7z", Some("password")).unwrap();
    let folder = &map.folders[0];
    let Some(CipherParams::SevenZipAes { num_cycles_power, salt, iv }) = folder.cipher.clone() else { panic!() };
    let key = derive_7z_key("password", &salt, num_cycles_power).unwrap();
    let span = folder.packed[0].packed.clone();
    let plain = decrypt_cbc(&key, &iv, &archive[span.start as usize..span.end as usize]).unwrap();
    let member = map.members.iter().position(|m| m.folder.is_some()).unwrap();
    let size = map.members[member].unpacked_size.unwrap() as usize;
    let mut held = HeldMembers::new().with(member, &plain[..size], None);
    let mut rb = ContainerRebuilder::new(&map, Some("password"));
    let got = rb.rebuild(0, 0..archive.len() as u64, &mut held, &mut RebuildOptions::default()).unwrap();
    assert_eq!(assert_exact(&got, &archive), span.end - span.start);
    let fin = got.regions.iter().find(|r| r.range.contains(&(span.end - 1))).unwrap();
    assert!(matches!(fin.state, ByteState::Rebuilt(Rebuilt::CbcFinal { searched: false, .. })), "{fin:?}");
    // a range through block boundaries
    let got = rb.rebuild(0, span.start + 100..span.start + 1_337, &mut held, &mut RebuildOptions::default()).unwrap();
    assert!(got.complete());
    assert_exact(&got, &archive);
}

#[test]
fn sevenzip_copy_split_rebuilds_from_held_members() {
    let vols = [read(&fixture("7z/multi_volume.7z.001")), read(&fixture("7z/multi_volume.7z.002"))];
    let map = MemberMap::from_memory(&refs(&vols), "multi_volume.7z.001", None).unwrap();
    // the output of a Copy folder is its packed bytes
    let mut outputs = Vec::new();
    for (i, m) in map.members.iter().enumerate() {
        let mut bytes = Vec::new();
        for p in &m.pieces {
            bytes.extend_from_slice(&vols[p.volume as usize][p.packed.start as usize..p.packed.end as usize]);
        }
        outputs.push((i, bytes));
    }
    let mut held = HeldMembers::new();
    for (i, b) in &outputs {
        held = held.with(*i, b, None);
    }
    let mut rb = ContainerRebuilder::new(&map, None);
    for (v, vol) in vols.iter().enumerate() {
        let got = rb.rebuild(v as u32, 0..vol.len() as u64, &mut held, &mut RebuildOptions::default()).unwrap();
        let data: u64 = data_ranges(&map, v as u32).iter().map(|r| r.end - r.start).sum();
        assert_eq!(assert_exact(&got, vol), data);
    }
}

// ---------------------------------------------------------------------------------------------------------------
// RAR 4.x AES stored, written by WinRAR.

#[test]
fn rar4_aes_stored_volumes_rebuild_and_the_final_block_from_a_crc() {
    let names = ["win-encvol.rar", "win-encvol.r00", "win-encvol.r01", "win-encvol.r02"];
    let vols: Vec<Vec<u8>> = names.iter().map(|n| read(&fixture("rar4-archiver").join(n))).collect();
    let map = MemberMap::from_memory(&refs(&vols), "win-encvol.rar", Some("testpw123")).unwrap();
    let m = &map.members[0];
    let Some(CipherParams::Rar4 { salt }) = m.cipher else { panic!("{:?}", m.cipher) };
    let (key, iv) = derive_rar4_key_iv("testpw123", &salt);
    let mut stream = Vec::new();
    for p in &m.pieces {
        stream.extend_from_slice(&vols[p.volume as usize][p.packed.start as usize..p.packed.end as usize]);
    }
    let size = m.unpacked_size.unwrap() as usize;
    let plain = decrypt_cbc(&key, &iv, &stream).unwrap()[..size].to_vec();
    let mut held = HeldMembers::new().with(0, &plain, None);
    let mut rb = ContainerRebuilder::new(&map, Some("testpw123"));
    let last = vols.len() - 1;
    for (v, vol) in vols.iter().enumerate() {
        let d = data_ranges(&map, v as u32)[0].clone();
        let mut options = RebuildOptions::default();
        if v == last {
            options.known = vec![
                KnownBytes { volume: v as u32, offset: 0, bytes: &vol[..d.start as usize] },
                KnownBytes { volume: v as u32, offset: d.end, bytes: &vol[d.end as usize..] },
            ];
            options.checks =
                vec![Crc32Check { volume: v as u32, range: 0..vol.len() as u64, crc32: crc32fast::hash(vol) }];
        }
        let got = rb.rebuild(v as u32, 0..vol.len() as u64, &mut held, &mut options).unwrap();
        let n = assert_exact(&got, vol);
        let pad = (16 - size % 16) % 16;
        if v == last && pad > 3 {
            assert_eq!(n, d.end - d.start - 16, "a final block with {pad} padding bytes is not searched");
        } else {
            assert_eq!(n, d.end - d.start, "volume {v}");
        }
        assert!(got.missing().all(|r| matches!(r.state, ByteState::Missing(Missing::Header(HeaderGap::NotRar5)))
            || matches!(r.state, ByteState::Missing(Missing::FinalPaddingAmbiguous { pad: 2, candidates }) if candidates > 1)));
    }
}
