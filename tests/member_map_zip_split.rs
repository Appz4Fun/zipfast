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

//! Member maps of split (spanned) ZIP sets: `name.z01`, `name.z02`, ..., `name.zip`.

use std::{
    ffi::OsString,
    fs::File,
    io::{Cursor, Write},
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

fn data(len: usize, seed: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + seed) % 251) as u8).collect()
}

fn slice(volumes: &[Vec<u8>], spans: &[PackedSpan]) -> Vec<u8> {
    spans
        .iter()
        .flat_map(|s| volumes[s.volume as usize][s.packed.start as usize..s.packed.end as usize].iter().copied())
        .collect()
}

/// The member's whole packed stream, piece by piece.
fn stream(volumes: &[Vec<u8>], member: &MapMember) -> Vec<u8> {
    member
        .pieces
        .iter()
        .flat_map(|p| volumes[p.volume as usize][p.packed.start as usize..p.packed.end as usize].iter().copied())
        .collect()
}

fn assert_round_trips(member: &MapMember, volumes: &[Vec<u8>], gold: &[u8]) {
    let len = gold.len() as u64;
    let mut ranges = vec![0..len, 0..1, len.saturating_sub(1)..len];
    for p in &member.pieces {
        if let Some(out) = &p.out {
            ranges.push(out.clone());
            ranges.push(out.start.saturating_sub(3)..(out.end + 3).min(len));
        }
    }
    for range in ranges {
        let spans = member.packed_spans(range.clone()).unwrap();
        assert_eq!(slice(volumes, &spans), &gold[range.start as usize..range.end as usize], "range {range:?}");
    }
}

// ---- Building split sets ----

#[derive(Clone)]
struct Entry {
    name: &'static str,
    payload: Vec<u8>,
    method: u16,
    flags: u16,
    extra: Vec<u8>,
    crc: u32,
    size: u32,
}

impl Entry {
    fn stored(name: &'static str, payload: &[u8]) -> Self {
        Self {
            name,
            payload: payload.to_vec(),
            method: 0,
            flags: 0,
            extra: Vec::new(),
            crc: crc32fast::hash(payload),
            size: payload.len() as u32,
        }
    }
}

#[derive(Clone, Copy, Default)]
struct Layout {
    /// Start the first volume with the spanning signature.
    marker: bool,
    /// Store every disk number and offset in ZIP64 fields and end records.
    zip64: bool,
}

/// A split set.
struct Set {
    volumes: Vec<Vec<u8>>,
    /// Each entry's local header as (disk, offset).
    locals: Vec<(u32, u64)>,
    /// Where the central directory starts, as (disk, offset).
    directory: (u32, u64),
}

/// Writes the entries as one stream (marker, local records, central directory, end records) and cuts it at the
/// absolute stream offsets `cuts`. The end records must lie in the last volume.
fn split_zip(entries: &[Entry], cuts: &[usize], layout: Layout) -> Set {
    let at = |abs: usize| -> (u32, u64) {
        let disk = cuts.iter().filter(|&&c| c <= abs).count();
        let start = if disk == 0 { 0 } else { cuts[disk - 1] };
        (disk as u32, (abs - start) as u64)
    };
    let mut out = Vec::new();
    if layout.marker {
        out.extend(b"PK\x07\x08");
    }
    let header = |sig: u32, e: &Entry, out: &mut Vec<u8>, extra_len: usize| {
        out.extend(sig.to_le_bytes());
        if sig == 0x0201_4b50 {
            out.extend(((3u16 << 8) | 45).to_le_bytes());
        }
        out.extend(45u16.to_le_bytes());
        out.extend(e.flags.to_le_bytes());
        out.extend(e.method.to_le_bytes());
        out.extend(0x6000u16.to_le_bytes());
        out.extend(0x5a21u16.to_le_bytes());
        out.extend(e.crc.to_le_bytes());
        out.extend((e.payload.len() as u32).to_le_bytes());
        out.extend(e.size.to_le_bytes());
        out.extend((e.name.len() as u16).to_le_bytes());
        out.extend((extra_len as u16).to_le_bytes());
    };
    let mut locals = Vec::new();
    for e in entries {
        locals.push(at(out.len()));
        header(0x0403_4b50, e, &mut out, e.extra.len());
        out.extend(e.name.as_bytes());
        out.extend(&e.extra);
        out.extend(&e.payload);
    }
    let cd_abs = out.len();
    let last = cuts.len() as u32;
    let mut on_last = 0u64;
    for (e, &(disk, offset)) in entries.iter().zip(&locals) {
        if at(out.len()).0 == last {
            on_last += 1;
        }
        let mut extra = Vec::new();
        if layout.zip64 {
            extra.extend([1, 0, 12, 0]);
            extra.extend(offset.to_le_bytes());
            extra.extend(disk.to_le_bytes());
        }
        extra.extend(&e.extra);
        header(0x0201_4b50, e, &mut out, extra.len());
        out.extend(0u16.to_le_bytes()); // comment
        out.extend((if layout.zip64 { 0xffff } else { disk as u16 }).to_le_bytes());
        out.extend(0u16.to_le_bytes()); // internal attributes
        out.extend((0o100644u32 << 16).to_le_bytes());
        out.extend((if layout.zip64 { u32::MAX } else { offset as u32 }).to_le_bytes());
        out.extend(e.name.as_bytes());
        out.extend(&extra);
    }
    let cd_size = (out.len() - cd_abs) as u64;
    let (dd, cd_off) = at(cd_abs);
    let ends = out.len();
    let n = entries.len() as u64;
    if layout.zip64 {
        let (_, record_off) = at(out.len());
        out.extend(b"PK\x06\x06");
        out.extend(44u64.to_le_bytes());
        out.extend(45u16.to_le_bytes());
        out.extend(45u16.to_le_bytes());
        out.extend(last.to_le_bytes());
        out.extend(dd.to_le_bytes());
        out.extend(on_last.to_le_bytes());
        out.extend(n.to_le_bytes());
        out.extend(cd_size.to_le_bytes());
        out.extend(cd_off.to_le_bytes());
        out.extend(b"PK\x06\x07");
        out.extend(last.to_le_bytes());
        out.extend(record_off.to_le_bytes());
        out.extend((last + 1).to_le_bytes());
        out.extend(b"PK\x05\x06");
        out.extend([0xff; 16]);
    } else {
        out.extend(b"PK\x05\x06");
        out.extend((last as u16).to_le_bytes());
        out.extend((dd as u16).to_le_bytes());
        out.extend((on_last as u16).to_le_bytes());
        out.extend((n as u16).to_le_bytes());
        out.extend((cd_size as u32).to_le_bytes());
        out.extend((cd_off as u32).to_le_bytes());
    }
    out.extend(0u16.to_le_bytes());
    assert!(cuts.last().is_none_or(|&c| c <= ends), "the end records must lie in the last volume");
    let mut volumes = Vec::new();
    let mut start = 0;
    for &c in cuts.iter().chain(std::iter::once(&out.len())) {
        volumes.push(out[start..c].to_vec());
        start = c;
    }
    Set { volumes, locals, directory: (dd, cd_off) }
}

/// Absolute stream offset of a member's data.
fn data_abs(entries: &[Entry], index: usize, marker: bool) -> usize {
    let mut at = if marker { 4 } else { 0 };
    for e in &entries[..index] {
        at += 30 + e.name.len() + e.extra.len() + e.payload.len();
    }
    at + 30 + entries[index].name.len() + entries[index].extra.len()
}

fn map(set: &[Vec<u8>]) -> MemberMap {
    MemberMap::from_memory(&refs(set), "set.z01", None).unwrap()
}

/// Every listed piece lies inside its volume.
fn assert_in_bounds(map: &MemberMap, volumes: &[Vec<u8>]) {
    for member in &map.members {
        for piece in &member.pieces {
            let len = volumes.get(piece.volume as usize).map_or(0, Vec::len) as u64;
            assert!(piece.packed.end <= len, "{piece:?} past volume length {len}");
            assert!(piece.header.end <= piece.packed.start || piece.header.is_empty(), "{piece:?}");
        }
    }
}

// ---- Mapping ----

#[test]
fn stored_member_crossing_both_boundaries_round_trips() {
    let gold = data(10_000, 1);
    let entries = [Entry::stored("big.bin", &gold)];
    let start = data_abs(&entries, 0, true);
    let set = split_zip(&entries, &[start + 3000, start + 7000], Layout { marker: true, ..Layout::default() });
    let map = map(&set.volumes);
    assert_eq!(map.format, MapFormat::Zip);
    assert!(map.complete);
    assert_eq!(map.end, MapEnd::Complete);
    assert_eq!(map.volumes, 3);
    assert_eq!(set.directory.0, 2);
    let member = &map.members[0];
    assert_eq!(member.mapping, OutputMapping::Direct);
    assert!(member.complete);
    assert_eq!(member.packed_size, 10_000);
    assert_eq!(member.checks.unwrap().crc32, Some(crc32fast::hash(&gold)));
    let pieces: Vec<_> = member.pieces.iter().map(|p| (p.volume, p.packed.clone(), p.stream_offset)).collect();
    assert_eq!(pieces, [(0, start as u64..start as u64 + 3000, 0), (1, 0..4000, 3000), (2, 0..3000, 7000)]);
    // The local header precedes the first piece; later pieces have no header in their volume.
    assert_eq!(member.pieces[0].header, 4..start as u64);
    assert_eq!(member.pieces[1].header, 0..0);
    assert_eq!(member.pieces.iter().map(|p| p.final_part).collect::<Vec<_>>(), [false, false, true]);
    assert_eq!(member.pieces[0].checks, MapChecks::default());
    assert_eq!(member.pieces[2].checks, member.checks.unwrap());
    assert_eq!(member.pieces[1].out, Some(3000..7000));
    assert_eq!(stream(&set.volumes, member), gold);
    assert_round_trips(member, &set.volumes, &gold);
    // A span across both boundaries is cut at each.
    let spans = member.packed_spans(2990..7010).unwrap();
    assert_eq!(spans.iter().map(|s| s.volume).collect::<Vec<_>>(), [0, 1, 2]);
    assert_eq!(slice(&set.volumes, &spans), &gold[2990..7010]);
    // And the plaintext streams back from any offset.
    for at in [0, 2999, 3000, 6999, 7000, 9999, 10_000] {
        let mut out = Vec::new();
        extract_member_from(&refs(&set.volumes), &map, 0, at, None, &mut out).unwrap();
        assert_eq!(out, &gold[at as usize..], "offset {at}");
    }
}

fn several() -> (Vec<Entry>, Vec<Vec<u8>>) {
    let a = data(1500, 2);
    let b = data(4000, 3);
    let c = data(700, 4);
    let entries = vec![
        Entry::stored("a.bin", &a),
        Entry::stored("b.bin", &b),
        Entry::stored("empty.bin", b""),
        Entry::stored("c.bin", &c),
    ];
    let golds = vec![a, b, Vec::new(), c];
    (entries, golds)
}

#[test]
fn several_members_including_one_entirely_in_the_last_volume() {
    let (entries, golds) = several();
    // Volume 1 holds the end of b; volume 2 the empty member, c and the directory.
    let b_start = data_abs(&entries, 1, true);
    let empty_local = data_abs(&entries, 2, true) - 30 - "empty.bin".len();
    let set = split_zip(&entries, &[b_start + 1000, empty_local], Layout { marker: true, ..Layout::default() });
    assert_eq!(set.locals[2], (2, 0));
    assert_eq!(set.locals[3].0, 2);
    let map = map(&set.volumes);
    assert!(map.complete);
    assert_eq!(map.members.len(), 4);
    for (i, (member, gold)) in map.members.iter().zip(&golds).enumerate() {
        assert_eq!(member.ordinal, i as u64);
        assert_eq!(member.name.as_deref(), Some(entries[i].name));
        assert_eq!(stream(&set.volumes, member), *gold, "member {i}");
        if !gold.is_empty() {
            assert_round_trips(member, &set.volumes, gold);
        }
    }
    assert_eq!(map.members[0].pieces.len(), 1);
    assert_eq!(map.members[1].pieces.len(), 2);
    let empty = &map.members[2];
    assert_eq!(empty.pieces.len(), 1);
    assert_eq!(empty.pieces[0].volume, 2);
    assert_eq!(empty.pieces[0].packed, 39..39);
    let c = &map.members[3];
    assert_eq!(c.pieces.len(), 1);
    assert_eq!(c.pieces[0].volume, 2);
    assert_eq!(c.pieces[0].header.start, set.locals[3].1);
    assert_in_bounds(&map, &set.volumes);
}

#[test]
fn local_headers_and_the_directory_may_cross_volume_boundaries() {
    let (entries, golds) = several();
    let b_local = data_abs(&entries, 1, false) - 30 - "b.bin".len();
    let cd = data_abs(&entries, 3, false) + 700;
    // b's local header is cut in two, and so is the central directory's second record.
    let set = split_zip(&entries, &[b_local + 11, cd + 46 + 5 + 9], Layout::default());
    assert_eq!(set.directory.0, 1);
    let map = map(&set.volumes);
    assert!(map.complete);
    let b = &map.members[1];
    assert_eq!(b.pieces.len(), 1);
    assert_eq!(b.pieces[0].volume, 1);
    assert_eq!(b.pieces[0].header, 0..30 + 5 - 11);
    for (member, gold) in map.members.iter().zip(&golds) {
        assert_eq!(stream(&set.volumes, member), *gold);
    }
}

fn winzip_aes_payload(plain: &[u8]) -> Vec<u8> {
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
    let request = WinZipAesRequest::new("pw", AesStrength::Aes256, AesVariant::Ae1).unwrap();
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
    let single = writer.finish().unwrap().sink;
    let map = MemberMap::from_memory(&[&single], "aes.zip", None).unwrap();
    let piece = &map.members[0].pieces[0];
    single[piece.packed.start as usize..piece.packed.end as usize].to_vec()
}

fn aes_entry(plain: &[u8]) -> Entry {
    let extra = [&[0x01, 0x99, 7, 0][..], &1u16.to_le_bytes(), b"AE", &[3], &0u16.to_le_bytes()].concat();
    Entry {
        name: "aes.bin",
        payload: winzip_aes_payload(plain),
        method: 99,
        flags: 1,
        extra,
        crc: crc32fast::hash(plain),
        size: plain.len() as u32,
    }
}

#[test]
fn winzip_aes_stored_crossing_boundaries_decrypts_from_the_spans() {
    let plain = data(6000, 5);
    let entries = [Entry::stored("first.bin", b"x"), aes_entry(&plain)];
    let start = data_abs(&entries, 1, true);
    // The 18-byte salt and verifier straddle the first boundary; the data straddles the second.
    for cuts in [[start + 7, start + 4000], [start + 18, start + 18 + 6000 - 1], [start + 1, start + 2]] {
        let set = split_zip(&entries, &cuts, Layout { marker: true, ..Layout::default() });
        let map = map(&set.volumes);
        let member = &map.members[1];
        assert!(member.encrypted);
        let salt: Vec<u8> = (1..=16).collect();
        let verifier = [entries[1].payload[16], entries[1].payload[17]];
        assert_eq!(
            member.cipher,
            Some(CipherParams::WinZipAes { strength: 3, vendor_version: 1, salt, verifier }),
            "{cuts:?}"
        );
        assert_eq!(member.mapping, OutputMapping::Counter { skip: 18 });
        assert_eq!(stream(&set.volumes, member), entries[1].payload);
        // The spans of any output range hold exactly that range's ciphertext.
        let spans = member.packed_spans(100..5000).unwrap();
        assert_eq!(slice(&set.volumes, &spans), &entries[1].payload[118..5018]);
        for at in [0, 1, 17, 18, 3000, 5999, 6000] {
            let mut out = Vec::new();
            extract_member_from(&refs(&set.volumes), &map, 1, at, Some("pw"), &mut out)
                .unwrap_or_else(|e| panic!("{cuts:?} at {at}: {e:?}"));
            assert_eq!(out, &plain[at as usize..], "{cuts:?} at {at}");
        }
    }
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

#[test]
fn zipcrypto_params_are_listed_and_the_prefix_may_cross_a_boundary() {
    let plain = data(900, 6);
    let crc = crc32fast::hash(&plain);
    let zc = Entry {
        name: "zc.bin",
        payload: zipcrypto("pw", (crc >> 24) as u8, &plain),
        method: 0,
        flags: 1,
        extra: Vec::new(),
        crc,
        size: 900,
    };
    // With a data descriptor the check byte is the high byte of the DOS time.
    let mut described = zc.clone();
    described.name = "zd.bin";
    described.flags = 1 | 8;
    described.payload = zipcrypto("pw", 0x60, &plain);
    let entries = [zc, described];
    let start = data_abs(&entries, 0, false);
    let set = split_zip(&entries, &[start + 5, start + 400], Layout::default());
    let map = map(&set.volumes);
    let member = &map.members[0];
    assert_eq!(member.cipher, Some(CipherParams::ZipCrypto { check: (crc >> 24) as u8 }));
    assert_eq!(member.mapping, OutputMapping::Sequential { skip: 12 });
    assert_eq!(member.pieces.len(), 3);
    assert!(member.pieces.iter().all(|p| p.out.is_none()));
    let spans = member.packed_spans(500..510).unwrap();
    assert_eq!(spans[0].stream.start, 0);
    assert_eq!(slice(&set.volumes, &spans), &entries[0].payload[..522]);
    let mut out = Vec::new();
    extract_member_from(&refs(&set.volumes), &map, 0, 0, Some("pw"), &mut out).unwrap();
    assert_eq!(out, plain);
    assert_eq!(map.members[1].cipher, Some(CipherParams::ZipCrypto { check: 0x60 }));
}

#[test]
fn deflate_members_list_their_packed_spans_without_a_mapping() {
    let plain = data(20_000, 7);
    let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&plain).unwrap();
    let packed = encoder.finish().unwrap();
    let entry = Entry {
        name: "d.bin",
        payload: packed.clone(),
        method: 8,
        flags: 0,
        extra: Vec::new(),
        crc: crc32fast::hash(&plain),
        size: plain.len() as u32,
    };
    let entries = [entry];
    let start = data_abs(&entries, 0, true);
    let half = packed.len() / 2;
    let set = split_zip(&entries, &[start + half], Layout { marker: true, ..Layout::default() });
    let map = map(&set.volumes);
    let member = &map.members[0];
    assert_eq!(member.method, MapMethod::Compressed { id: 8 });
    assert_eq!(member.mapping, OutputMapping::None);
    assert_eq!(member.packed_spans(0..10), None);
    assert_eq!(member.pieces.len(), 2);
    assert!(member.pieces.iter().all(|p| p.out.is_none()));
    assert_eq!(member.packed_size, packed.len() as u64);
    assert_eq!(stream(&set.volumes, member), packed);
}

#[test]
fn the_spanning_marker_is_counted_in_disk_0_offsets() {
    let gold = data(3000, 8);
    let entries = [Entry::stored("m.bin", &gold)];
    for marker in [true, false] {
        let start = data_abs(&entries, 0, marker);
        let set = split_zip(&entries, &[start + 1000], Layout { marker, ..Layout::default() });
        assert_eq!(set.locals[0], (0, if marker { 4 } else { 0 }));
        assert_eq!(set.volumes[0].starts_with(b"PK\x07\x08"), marker);
        let map = map(&set.volumes);
        assert_eq!(map.members[0].pieces[0].header.start, if marker { 4 } else { 0 });
        assert_eq!(stream(&set.volumes, &map.members[0]), gold);
        if marker {
            // The marker alone says it is a split set, whatever the first volume's name.
            let other = MemberMap::from_memory(&refs(&set.volumes), "renamed.bin", None).unwrap();
            assert_eq!(other, map);
        } else {
            // Without it, a `.z01` name does.
            assert!(matches!(
                MemberMap::from_memory(&refs(&set.volumes), "renamed.bin", None),
                Err(MapError::Unsupported { .. } | MapError::Malformed { .. } | MapError::NotArchive)
            ));
        }
    }
}

#[test]
fn zip64_disk_numbers_offsets_and_end_records() {
    let (entries, golds) = several();
    let b_start = data_abs(&entries, 1, true);
    let cuts = [b_start + 100, b_start + 2000, b_start + 3500];
    let plain = split_zip(&entries, &cuts, Layout { marker: true, zip64: false });
    let wide = split_zip(&entries, &cuts, Layout { marker: true, zip64: true });
    assert_eq!(wide.volumes[1], plain.volumes[1]);
    let plain_map = map(&plain.volumes);
    let wide_map = map(&wide.volumes);
    assert!(wide_map.complete);
    assert_eq!(wide_map.volumes, 4);
    for (a, b) in plain_map.members.iter().zip(&wide_map.members) {
        let pieces = |m: &MapMember| m.pieces.iter().map(|p| (p.volume, p.packed.clone())).collect::<Vec<_>>();
        assert_eq!(pieces(a), pieces(b));
    }
    for (member, gold) in wide_map.members.iter().zip(&golds) {
        assert_eq!(stream(&wide.volumes, member), *gold);
    }
    assert_eq!(wide_map.members[1].pieces.len(), 4);
}

// ---- Missing and cut volumes ----

#[test]
fn a_missing_middle_volume_gives_a_partial_map() {
    let (entries, golds) = several();
    let b_start = data_abs(&entries, 1, true);
    let empty_local = data_abs(&entries, 2, true) - 30 - "empty.bin".len();
    let set = split_zip(&entries, &[b_start + 1000, b_start + 2000, empty_local], Layout::default());
    let full = map(&set.volumes);
    let mut holed = set.volumes.clone();
    holed[1] = Vec::new();
    let map = map(&holed);
    assert!(!map.complete);
    assert_eq!(map.end, MapEnd::MissingVolume { volume: 1 });
    assert_eq!(map.volumes, 4);
    assert_eq!(map.members.len(), 4);
    assert_eq!(map.members[0], full.members[0]);
    // b runs into the missing volume: only its first piece is listed, and it is not final.
    let b = &map.members[1];
    assert!(!b.complete);
    assert_eq!(b.checks, None);
    assert_eq!(b.pieces.len(), 1);
    let (piece, whole) = (&b.pieces[0], &full.members[1].pieces[0]);
    assert_eq!((piece.volume, &piece.packed, &piece.header), (whole.volume, &whole.packed, &whole.header));
    assert!(!piece.final_part);
    assert_eq!(piece.checks, MapChecks::default());
    assert_eq!(b.packed_spans(0..1000).map(|s| slice(&holed, &s)), Some(golds[1][..1000].to_vec()));
    // The members in the last volume are whole.
    assert_eq!(map.members[2], full.members[2]);
    assert_eq!(map.members[3], full.members[3]);
    assert_eq!(stream(&holed, &map.members[3]), golds[3]);

    // A member whose local header runs into the missing volume is listed without pieces.
    let set = split_zip(&entries, &[b_start - 20, b_start + 3000], Layout::default());
    let mut holed = set.volumes.clone();
    holed[1] = Vec::new();
    let map = MemberMap::from_memory(&refs(&holed), "set.z01", None).unwrap();
    assert_eq!(map.end, MapEnd::MissingVolume { volume: 1 });
    assert!(map.members[0].complete);
    assert!(map.members[1].pieces.is_empty() && !map.members[1].complete);
    assert_eq!(map.members[1].name.as_deref(), Some("b.bin"));
    assert!(map.members[3].complete);
}

#[test]
fn a_missing_last_volume_is_a_typed_error() {
    let (entries, _) = several();
    let b_start = data_abs(&entries, 1, true);
    let set = split_zip(&entries, &[b_start + 1000, b_start + 2000], Layout::default());
    let error = MemberMap::from_memory(&refs(&set.volumes[..2]), "set.z01", None).unwrap_err();
    assert!(matches!(error, MapError::MissingDirectory { volume: 2 }), "{error:?}");
    // A cut last volume has no end record either.
    let mut cut = set.volumes.clone();
    let len = cut[2].len();
    cut[2].truncate(len - 1);
    let error = MemberMap::from_memory(&refs(&cut), "set.z01", None).unwrap_err();
    assert!(matches!(error, MapError::MissingDirectory { .. }), "{error:?}");
    // A count that does not match the end record.
    let error =
        MemberMap::from_memory(&refs(&[set.volumes[0].clone(), set.volumes[2].clone()]), "set.z01", None).unwrap_err();
    assert!(matches!(error, MapError::Malformed { .. }), "{error:?}");
    assert!(error.to_string().contains("volume count"), "{error}");
}

#[test]
fn a_cut_middle_volume_ends_the_map_at_the_header_it_cuts() {
    let (entries, _) = several();
    let b_start = data_abs(&entries, 1, true);
    let empty_local = data_abs(&entries, 2, true) - 30 - "empty.bin".len();
    let set = split_zip(&entries, &[b_start + 1000, empty_local - 40], Layout::default());
    let b_local = set.locals[1];
    assert_eq!(b_local.0, 0);
    let mut cut = set.volumes.clone();
    cut[0].truncate(b_local.1 as usize);
    let map = map(&cut);
    assert!(!map.complete);
    assert_eq!(map.end, MapEnd::Truncated { volume: 0, offset: b_local.1 });
    assert_eq!(map.members.len(), 1);
}

// ---- Volume sources ----

#[derive(Default)]
struct Gate {
    ready: bool,
    wake: Option<Waker>,
    waits: usize,
}

struct Bytes {
    index: u32,
    data: Vec<u8>,
    chunk: usize,
    gate: Option<Arc<Mutex<Gate>>>,
    reads: Reads,
}

type Reads = Arc<Mutex<Vec<(u32, u64, usize)>>>;

fn wait(gate: &Option<Arc<Mutex<Gate>>>, cx: &Context<'_>) -> bool {
    let Some(gate) = gate else { return false };
    let mut g = gate.lock().unwrap();
    if !g.ready {
        g.waits += 1;
        g.wake = Some(cx.waker().clone());
        return true;
    }
    g.ready = false;
    false
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
        if wait(&self.gate, cx) {
            return Ok(RangeRead::NotYet);
        }
        let end = (at + buf.len().min(self.chunk) as u64).min(self.data.len() as u64);
        let n = (end - at) as usize;
        buf[..n].copy_from_slice(&self.data[at as usize..end as usize]);
        self.reads.lock().unwrap().push((self.index, at, n));
        Ok(RangeRead::Filled { count: n })
    }
}

/// Answers each volume once, by index or (`by_name`) by the name asked for.
struct Provider {
    volumes: Vec<Option<Bytes>>,
    names: Vec<OsString>,
    by_name: bool,
    gate: Option<Arc<Mutex<Gate>>>,
    asked: Arc<Mutex<Vec<VolumeRequest>>>,
}

impl VolumeSource for Provider {
    fn volume(&mut self, r: &VolumeRequest, cx: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
        if wait(&self.gate, cx) {
            return Ok(VolumeAnswer::Wait);
        }
        self.asked.lock().unwrap().push(r.clone());
        let slot = if self.by_name { self.names.iter().position(|n| *n == r.expected) } else { Some(r.index as usize) };
        Ok(slot
            .and_then(|i| self.volumes.get_mut(i))
            .and_then(Option::take)
            .map_or(VolumeAnswer::Missing, |b| VolumeAnswer::Ready(Box::new(b))))
    }
}

fn set_names(count: usize) -> Vec<OsString> {
    stem_names("set", count)
}

fn stem_names(stem: &str, count: usize) -> Vec<OsString> {
    (0..count)
        .map(|i| if i + 1 == count { format!("{stem}.zip").into() } else { format!("{stem}.z{:02}", i + 1).into() })
        .collect()
}

struct Source {
    builder: MapBuilder,
    gate: Option<Arc<Mutex<Gate>>>,
    reads: Reads,
    asked: Arc<Mutex<Vec<VolumeRequest>>>,
}

fn source(volumes: &[Option<Vec<u8>>], by_name: bool, waits: bool) -> Source {
    stem_source("set", volumes, by_name, waits)
}

fn stem_source(stem: &str, volumes: &[Option<Vec<u8>>], by_name: bool, waits: bool) -> Source {
    let gate = waits.then(|| Arc::new(Mutex::new(Gate::default())));
    let reads = Reads::default();
    let asked = Arc::new(Mutex::new(Vec::new()));
    let bytes = volumes
        .iter()
        .enumerate()
        .map(|(i, data)| {
            data.as_ref().map(|data| Bytes {
                index: i as u32,
                data: data.clone(),
                chunk: 13,
                gate: gate.clone(),
                reads: reads.clone(),
            })
        })
        .collect();
    let provider = Provider {
        volumes: bytes,
        names: stem_names(stem, volumes.len()),
        by_name,
        gate: gate.clone(),
        asked: asked.clone(),
    };
    let builder = MapBuilder::new(Box::new(provider), MapOptions::new(format!("{stem}.z01")));
    Source { builder, gate, reads, asked }
}

fn drive(source: &mut Source) -> Result<MemberMap, MapError> {
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..1_000_000 {
        match source.builder.poll_map(&mut cx) {
            Poll::Ready(result) => return result,
            Poll::Pending => {
                let gate = source.gate.as_ref().expect("pending only with waits");
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
fn volume_sources_with_waits_match_memory() {
    let (entries, _) = several();
    let b_start = data_abs(&entries, 1, true);
    let empty_local = data_abs(&entries, 2, true) - 30 - "empty.bin".len();
    let set = split_zip(&entries, &[b_start + 1000, b_start + 2000, empty_local], Layout { marker: true, zip64: true });
    let expected = map(&set.volumes);
    let all: Vec<_> = set.volumes.iter().cloned().map(Some).collect();
    for by_name in [false, true] {
        let mut src = source(&all, by_name, true);
        assert_eq!(drive(&mut src).unwrap(), expected, "by name: {by_name}");
        assert!(src.gate.as_ref().unwrap().lock().unwrap().waits > 20);
        let asked: Vec<_> = src.asked.lock().unwrap().iter().map(|r| (r.index, r.expected.clone())).collect();
        let names = set_names(4);
        // Volumes are asked for in order; the last one under its numbered name and then as `set.zip`.
        assert_eq!(asked[..3], [(0, names[0].clone()), (1, names[1].clone()), (2, names[2].clone())]);
        if by_name {
            assert_eq!(asked[3..], [(3, "set.z04".into()), (3, names[3].clone())]);
        } else {
            assert_eq!(asked[3], (3, "set.z04".into()));
            assert_eq!(asked[4..], [(4, "set.z05".into()), (4, "set.zip".into())]);
        }
        // Member data is never read, except at the start of the last volume, inside the tail searched for the
        // end record.
        for &(volume, at, len) in src.reads.lock().unwrap().iter() {
            let read = at..at + len as u64;
            for member in &expected.members {
                for p in &member.pieces {
                    if p.volume == volume && volume != 3 {
                        assert!(read.end <= p.packed.start || read.start >= p.packed.end, "{volume} {read:?}");
                    }
                }
            }
        }
    }
    // Without waits, a missing middle volume gives the memory result for an empty slot, by index and by name.
    let mut holed = set.volumes.clone();
    holed[1] = Vec::new();
    let expected = map(&holed);
    let mut sparse = all.clone();
    sparse[1] = None;
    for by_name in [false, true] {
        assert_eq!(drive(&mut source(&sparse, by_name, false)).unwrap(), expected, "by name: {by_name}");
    }
    // A missing last volume.
    let mut cut = all.clone();
    cut[3] = None;
    for by_name in [false, true] {
        let error = drive(&mut source(&cut, by_name, false)).unwrap_err();
        assert!(matches!(error, MapError::MissingDirectory { volume: 3 }), "{error:?}");
    }
}

#[test]
fn member_reader_asks_for_the_last_volume_by_its_zip_name() {
    let gold = data(10_000, 9);
    let entries = [Entry::stored("big.bin", &gold)];
    let start = data_abs(&entries, 0, true);
    let set = split_zip(&entries, &[start + 3000, start + 7000], Layout { marker: true, ..Layout::default() });
    let map = map(&set.volumes);
    let names = set_names(3);
    let volumes = set.volumes.iter().enumerate().map(|(i, data)| (names[i].clone(), data.clone())).collect::<Vec<_>>();
    struct ByName(Vec<(OsString, Vec<u8>)>, Reads);
    impl VolumeSource for ByName {
        fn volume(&mut self, r: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
            Ok(match self.0.iter().find(|(n, _)| *n == r.expected) {
                Some((_, data)) => VolumeAnswer::Ready(Box::new(Bytes {
                    index: r.index,
                    data: data.clone(),
                    chunk: 1000,
                    gate: None,
                    reads: self.1.clone(),
                })),
                None => VolumeAnswer::Missing,
            })
        }
    }
    let mut reader =
        MemberReader::new(Box::new(ByName(volumes, Reads::default())), &map, 0, 6500, MapOptions::new("set.z01"))
            .unwrap();
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        match reader.poll_read(&mut cx, &mut buf) {
            Poll::Ready(Ok(0)) => break,
            Poll::Ready(Ok(n)) => out.extend_from_slice(&buf[..n]),
            Poll::Ready(Err(e)) => panic!("{e:?}"),
            Poll::Pending => unreachable!(),
        }
    }
    assert_eq!(out, &gold[6500..]);
}

// ---- Hostile input ----

#[test]
fn hostile_disk_numbers_and_offsets_are_typed() {
    let (entries, _) = several();
    let b_start = data_abs(&entries, 1, false);
    let set = split_zip(&entries, &[b_start + 1000, b_start + 2000], Layout::default());
    let last = set.volumes.len() - 1;
    let (dd, cd_off) = set.directory;
    assert_eq!(dd as usize, last);
    let eocd = set.volumes[last].len() - 22;
    let patch = |at: usize, bytes: &[u8]| {
        let mut v = set.volumes.clone();
        v[last][at..at + bytes.len()].copy_from_slice(bytes);
        v
    };
    let cd = cd_off as usize;
    let cases: Vec<(Vec<Vec<u8>>, &str)> = vec![
        (patch(cd + 34, &7u16.to_le_bytes()), "disk past the last"),
        (patch(cd + 42, &u32::MAX.to_le_bytes()), "offset past its disk"),
        (patch(cd + 34, &0xffffu16.to_le_bytes()), "ZIP64 disk without a ZIP64 field"),
        (patch(eocd + 6, &5u16.to_le_bytes()), "directory disk past the last"),
        (patch(eocd + 4, &9u16.to_le_bytes()), "end record disk past the volumes"),
        (patch(eocd + 4, &0xffffu16.to_le_bytes()), "ZIP64 disk without a locator"),
        (patch(eocd + 16, &u32::MAX.to_le_bytes()), "directory offset"),
        (patch(eocd + 12, &1u32.to_le_bytes()), "directory size"),
    ];
    for (volumes, what) in cases {
        match MemberMap::from_memory(&refs(&volumes), "set.z01", None) {
            Err(MapError::Malformed { .. } | MapError::Unsupported { .. } | MapError::MissingDirectory { .. }) => {}
            Ok(map) => panic!("{what}: mapped {map:?}"),
            Err(e) => panic!("{what}: {e:?}"),
        }
    }
    // An offset past the end of an earlier volume reads as that volume being cut.
    let mut v = set.volumes.clone();
    v[last][cd + 46 + 5 + 42..cd + 46 + 5 + 46].copy_from_slice(&50_000u32.to_le_bytes());
    let map = MemberMap::from_memory(&refs(&v), "set.z01", None).unwrap();
    assert_eq!(map.end, MapEnd::Truncated { volume: 0, offset: 50_000 });
}

#[test]
fn truncation_and_bit_flip_sweep_never_panics() {
    let (mut entries, _) = several();
    entries.push(aes_entry(&data(300, 10)));
    let b_start = data_abs(&entries, 1, true);
    for layout in [Layout { marker: true, zip64: false }, Layout { marker: false, zip64: true }] {
        let set = split_zip(&entries, &[b_start + 700, b_start + 3900], layout);
        let check = |volumes: &[Vec<u8>]| {
            if let Ok(map) = MemberMap::from_memory(&refs(volumes), "set.z01", None) {
                assert_eq!(map.complete, map.end == MapEnd::Complete);
                assert_in_bounds(&map, volumes);
                for member in &map.members {
                    let _ = member.packed_spans(0..u64::MAX);
                }
            }
        };
        for v in 0..set.volumes.len() {
            for cut in 0..set.volumes[v].len() {
                let mut volumes = set.volumes.clone();
                volumes[v].truncate(cut);
                check(&volumes);
            }
            for at in 0..set.volumes[v].len() {
                for bit in [0x01, 0x80] {
                    let mut volumes = set.volumes.clone();
                    volumes[v][at] ^= bit;
                    check(&volumes);
                }
            }
        }
    }
}

// ---- Single volumes ----

#[test]
fn single_volume_zip_maps_are_unchanged() {
    let gold = data(2000, 11);
    let entries = [Entry::stored("one.bin", &gold)];
    let set = split_zip(&entries, &[], Layout::default());
    let map = MemberMap::from_memory(&refs(&set.volumes), "one.zip", None).unwrap();
    assert!(map.complete);
    assert_eq!(map.volumes, 1);
    let member = &map.members[0];
    assert_eq!(member.pieces.len(), 1);
    let piece = &member.pieces[0];
    assert_eq!((piece.volume, piece.header.clone(), piece.stream_offset), (0, 0..37, 0));
    assert_eq!(piece.packed, 37..2037);
    assert_eq!(piece.out, Some(0..2000));
    assert!(piece.final_part);
    assert_eq!(piece.checks, member.checks.unwrap());
    // The same bytes as a one-volume split set (with the marker) map the same way, shifted by the marker.
    let marked = split_zip(&entries, &[], Layout { marker: true, ..Layout::default() });
    let split = MemberMap::from_memory(&refs(&marked.volumes), "one.z01", None).unwrap();
    assert_eq!(split.volumes, 1);
    assert_eq!(split.members[0].pieces[0].packed, 41..2041);
    assert_eq!(split.members[0].pieces[0].header, 4..41);
    // A split set's last volume on its own is not mapped as a single archive.
    let (entries, _) = several();
    let b_start = data_abs(&entries, 1, false);
    let set = split_zip(&entries, &[b_start + 1000], Layout::default());
    let error = MemberMap::from_memory(&[&set.volumes[1]], "set.zip", None).unwrap_err();
    assert!(error.to_string().contains(".z01"), "{error}");
}

#[test]
fn a_hostile_disk_count_from_a_named_last_volume_is_charged_not_allocated() {
    let (entries, _) = several();
    let b_start = data_abs(&entries, 1, false);
    for zip64 in [false, true] {
        let set = split_zip(&entries, &[b_start + 1000], Layout { marker: true, zip64 });
        let mut zip = set.volumes[1].clone();
        let eocd = zip.len() - 22;
        if zip64 {
            // The locator's disk count.
            zip[eocd - 4..eocd].copy_from_slice(&u32::MAX.to_le_bytes());
        } else {
            zip[eocd + 4..eocd + 6].copy_from_slice(&60_000u16.to_le_bytes());
        }
        // A source keyed on names answers `set.zip` at index 1, which claims to be a much later disk.
        let volumes = [Some(set.volumes[0].clone()), Some(zip)];
        let names = vec![OsString::from("set.z01"), "set.zip".into()];
        let bytes = volumes
            .iter()
            .enumerate()
            .map(|(i, d)| {
                d.as_ref().map(|data| Bytes {
                    index: i as u32,
                    data: data.clone(),
                    chunk: 4096,
                    gate: None,
                    reads: Reads::default(),
                })
            })
            .collect();
        let provider = Provider { volumes: bytes, names, by_name: true, gate: None, asked: Default::default() };
        let mut src = Source {
            builder: MapBuilder::new(Box::new(provider), MapOptions::new("set.z01")),
            gate: None,
            reads: Reads::default(),
            asked: Default::default(),
        };
        let error = drive(&mut src).unwrap_err();
        assert!(
            matches!(error, MapError::MissingDirectory { .. } | MapError::Limit { .. } | MapError::Malformed { .. }),
            "{error:?}"
        );
    }
}

// ---- Real Info-ZIP split sets (tests/fixtures/zip-split, see its README) ----

/// The volumes of fixture set `stem`, `.z01` first and `.zip` last.
fn real_set(stem: &str) -> Vec<Vec<u8>> {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/zip-split");
    let mut volumes = Vec::new();
    for i in 1.. {
        match std::fs::read(format!("{dir}/{stem}.z{i:02}")) {
            Ok(bytes) => volumes.push(bytes),
            Err(_) => break,
        }
    }
    volumes.push(std::fs::read(format!("{dir}/{stem}.zip")).unwrap());
    volumes
}

fn real_map(stem: &str, volumes: &[Vec<u8>]) -> MemberMap {
    let map = MemberMap::from_memory(&refs(volumes), format!("{stem}.z01"), None).unwrap();
    assert!(map.complete, "{stem}: {:?}", map.end);
    assert_eq!(map.volumes as usize, volumes.len());
    // Info-ZIP starts the first volume with the spanning signature, and every offset in disk 0 counts it.
    assert!(volumes[0].starts_with(b"PK\x07\x08PK\x03\x04"));
    assert_eq!(map.members[0].pieces[0].header.start, 4);
    map
}

/// Pieces as (volume, packed range).
fn placement(member: &MapMember) -> Vec<(u32, Range<u64>)> {
    member.pieces.iter().map(|p| (p.volume, p.packed.clone())).collect()
}

/// Every Direct member's bytes, sliced from its pieces, match its CRC32 and size, and stream back from offset 0
/// and from the middle.
fn check_direct(map: &MemberMap, volumes: &[Vec<u8>]) {
    for (i, member) in map.members.iter().enumerate() {
        if member.mapping != OutputMapping::Direct {
            continue;
        }
        let bytes = stream(volumes, member);
        assert_eq!(bytes.len() as u64, member.unpacked_size.unwrap());
        assert_eq!(Some(crc32fast::hash(&bytes)), member.checks.unwrap().crc32, "{:?}", member.name);
        for at in [0, bytes.len() as u64 / 2] {
            let mut out = Vec::new();
            extract_member_from(&refs(volumes), map, i, at, None, &mut out).unwrap();
            assert_eq!(out, &bytes[at as usize..], "{:?} from {at}", member.name);
        }
    }
}

/// A source keyed on names is asked for each volume once, in order, the last as `.z{n}` and then as `.zip`.
fn check_named_source(stem: &str, volumes: &[Vec<u8>], expected: &MemberMap) {
    let all: Vec<_> = volumes.iter().cloned().map(Some).collect();
    let mut src = stem_source(stem, &all, true, true);
    assert_eq!(&drive(&mut src).unwrap(), expected);
    let asked: Vec<_> = src.asked.lock().unwrap().iter().map(|r| (r.index, r.expected.clone())).collect();
    let n = volumes.len() as u32;
    let mut want: Vec<(u32, OsString)> = (0..n).map(|i| (i, format!("{stem}.z{:02}", i + 1).into())).collect();
    want.push((n - 1, format!("{stem}.zip").into()));
    assert_eq!(asked, want);
}

#[test]
fn real_stored_set_with_a_directory() {
    let volumes = real_set("stored");
    assert_eq!(volumes.len(), 3);
    let map = real_map("stored", &volumes);
    let listed: Vec<_> =
        map.members.iter().map(|m| (m.name.clone().unwrap(), m.unpacked_size.unwrap(), m.is_dir)).collect();
    assert_eq!(
        listed,
        [("a.bin".to_owned(), 140_000, false), ("dir/".to_owned(), 0, true), ("dir/b.txt".to_owned(), 640, false)]
    );
    // a.bin crosses both boundaries; the directory and b.txt sit in the last volume.
    assert_eq!(placement(&map.members[0]), [(0, 39..65_536), (1, 0..65_536), (2, 0..8967)]);
    assert_eq!(placement(&map.members[1]), [(2, 9001..9001)]);
    assert_eq!(placement(&map.members[2]), [(2, 9040..9680)]);
    assert!(map.members.iter().all(|m| m.mapping == OutputMapping::Direct && m.cipher.is_none()));
    assert_eq!(map.members[0].checks.unwrap().crc32, Some(0x329a_e6f9));
    assert_eq!(stream(&volumes, &map.members[2]), b"hello split zip\n".repeat(40));
    check_direct(&map, &volumes);
    let spans = map.members[0].packed_spans(65_000..75_000).unwrap();
    assert_eq!(spans.iter().map(|s| s.volume).collect::<Vec<_>>(), [0, 1]);
    check_named_source("stored", &volumes, &map);
}

#[test]
fn real_deflated_set() {
    let volumes = real_set("deflated");
    assert_eq!(volumes.len(), 2);
    let map = real_map("deflated", &volumes);
    let listed: Vec<_> = map.members.iter().map(|m| (m.name.clone().unwrap(), m.unpacked_size.unwrap())).collect();
    assert_eq!(listed, [("c.txt".to_owned(), 93_336), ("dir/b.txt".to_owned(), 640)]);
    for member in &map.members {
        assert_eq!(member.method, MapMethod::Compressed { id: 8 });
        assert_eq!(member.mapping, OutputMapping::None);
        assert_eq!(member.packed_spans(0..1), None);
    }
    assert_eq!(placement(&map.members[0]), [(0, 39..65_536), (1, 0..5129)]);
    assert_eq!(placement(&map.members[1]), [(1, 5168..5193)]);
    // The packed streams inflate to data with the listed sizes and CRCs.
    for member in &map.members {
        let packed = stream(&volumes, member);
        let mut plain = Vec::new();
        std::io::Read::read_to_end(&mut flate2::read::DeflateDecoder::new(&packed[..]), &mut plain).unwrap();
        assert_eq!(plain.len() as u64, member.unpacked_size.unwrap());
        assert_eq!(Some(crc32fast::hash(&plain)), member.checks.unwrap().crc32);
    }
    assert_eq!(map.members[0].packed_size, 70_626);
    check_named_source("deflated", &volumes, &map);
}

#[test]
fn real_zipcrypto_set() {
    let volumes = real_set("crypt");
    assert_eq!(volumes.len(), 2);
    let map = real_map("crypt", &volumes);
    let member = &map.members[0];
    assert_eq!(member.name.as_deref(), Some("s.bin"));
    assert_eq!(member.unpacked_size, Some(66_000));
    assert!(member.encrypted);
    // Info-ZIP writes encrypted entries with a data descriptor, so the check byte is the DOS time's high byte
    // (03:04:05 is 0x1882), not the CRC's (0x02e571c8).
    assert_eq!(member.cipher, Some(CipherParams::ZipCrypto { check: 0x18 }));
    assert_eq!(member.mapping, OutputMapping::Sequential { skip: 12 });
    assert_eq!(member.packed_size, 66_012);
    assert_eq!(placement(member)[0], (0, 39..65_536));
    assert_eq!(placement(member)[1].0, 1);
    let mut out = Vec::new();
    extract_member_from(&refs(&volumes), &map, 0, 0, Some("password"), &mut out).unwrap();
    assert_eq!(out.len(), 66_000);
    assert_eq!(crc32fast::hash(&out), 0x02e5_71c8);
    assert!(matches!(
        extract_member_from(&refs(&volumes), &map, 0, 0, Some("wrong"), &mut Vec::new()),
        Err(ExtractFromError::WrongPassword)
    ));
    check_named_source("crypt", &volumes, &map);
}
