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

//! 7z member maps, over archives written by a minimal test-only 7z builder: Copy, 7zAES over Copy and LZMA2
//! folders, plain, LZMA, LZMA2 and 7zAES-encrypted (`-mhe`) headers, and plain byte splits.

use std::{
    fs::File,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};
use zipfast::map::*;
use zipfast::progressive::{
    ProgressiveResult, RangeRead, RangeSource, Resource, SourceId, SourceInfo, SourceLength, VolumeAnswer,
    VolumeRequest, VolumeSource,
};

// ---- A minimal 7z writer ----

const COPY: &[u8] = &[0x00];
const LZMA: &[u8] = &[0x03, 0x01, 0x01];
const LZMA2: &[u8] = &[0x21];
const AES: &[u8] = &[0x06, 0xF1, 0x07, 0x01];

fn num(out: &mut Vec<u8>, value: u64) {
    let mut first = 0u8;
    let mut mask = 0x80u8;
    let mut i = 0;
    while i < 8 {
        if value < (1u64 << (7 * (i + 1))) {
            first |= (value >> (8 * i)) as u8;
            break;
        }
        first |= mask;
        mask >>= 1;
        i += 1;
    }
    out.push(first);
    for k in 0..i {
        out.push((value >> (8 * k)) as u8);
    }
}

fn crc(bytes: &[u8]) -> u32 {
    zipfast::crc32::hash(bytes)
}

fn data(len: usize, seed: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + seed * 7 + i / 251) % 253) as u8).collect()
}

/// Bytes that do not compress.
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

#[derive(Clone)]
struct Aes {
    password: &'static str,
    power: u8,
    salt: Vec<u8>,
    iv: [u8; 16],
}

impl Aes {
    fn new(password: &'static str) -> Self {
        Self { password, power: 6, salt: vec![9, 8, 7, 6, 5, 4, 3, 2], iv: [0x5A; 16] }
    }

    fn key(&self) -> [u8; 32] {
        zipfast::crypto::derive_7z_key(self.password, &self.salt, self.power).unwrap()
    }

    fn properties(&self) -> Vec<u8> {
        let (s, i) = (self.salt.len(), 16);
        let first = self.power | if s > 0 { 0x80 } else { 0 } | 0x40;
        let second = (((s.max(1) - 1) as u8) << 4) | (i - 1) as u8;
        let mut p = vec![first, second];
        p.extend_from_slice(&self.salt);
        p.extend_from_slice(&self.iv);
        p
    }

    fn encrypt(&self, plain: &[u8]) -> Vec<u8> {
        let mut padded = plain.to_vec();
        padded.resize(plain.len().next_multiple_of(16), 0);
        zipfast::crypto::encrypt_cbc(&self.key(), &self.iv, &padded).unwrap()
    }
}

/// A coder as stored: id and properties.
struct Coder {
    id: &'static [u8],
    props: Vec<u8>,
}

/// One folder: a linear chain of coders (stored order, output first), their output sizes and the packed bytes.
struct Folder {
    coders: Vec<Coder>,
    unpack_sizes: Vec<u64>,
    packed: Vec<u8>,
    crc: Option<u32>,
}

fn write_folder(out: &mut Vec<u8>, folder: &Folder) {
    num(out, folder.coders.len() as u64);
    for c in &folder.coders {
        out.push(c.id.len() as u8 | if c.props.is_empty() { 0 } else { 0x20 });
        out.extend_from_slice(c.id);
        if !c.props.is_empty() {
            num(out, c.props.len() as u64);
            out.extend_from_slice(&c.props);
        }
    }
    // Coder i's input is fed by coder i + 1's output; the packed stream feeds the last coder.
    for i in 0..folder.coders.len() - 1 {
        num(out, i as u64);
        num(out, i as u64 + 1);
    }
}

fn lzma2_encode(plain: &[u8]) -> (Vec<u8>, u8) {
    let mut opts = liblzma::stream::LzmaOptions::new_preset(6).unwrap();
    opts.dict_size(1 << 20);
    let mut filters = liblzma::stream::Filters::new();
    filters.lzma2(&opts);
    (encode(filters, plain), 16)
}

fn lzma_encode(plain: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut opts = liblzma::stream::LzmaOptions::new_preset(6).unwrap();
    opts.dict_size(1 << 16);
    let mut filters = liblzma::stream::Filters::new();
    filters.lzma1(&opts);
    let mut props = vec![0x5D];
    props.extend_from_slice(&(1u32 << 16).to_le_bytes());
    (encode(filters, plain), props)
}

fn encode(filters: liblzma::stream::Filters, plain: &[u8]) -> Vec<u8> {
    let mut stream = liblzma::stream::Stream::new_raw_encoder(&filters).unwrap();
    let mut out = Vec::with_capacity(plain.len() + 1024);
    let mut input = plain;
    loop {
        if out.capacity() == out.len() {
            out.reserve(4096);
        }
        let before = stream.total_in();
        let status = stream.process_vec(input, &mut out, liblzma::stream::Action::Finish).unwrap();
        input = &input[(stream.total_in() - before) as usize..];
        if status == liblzma::stream::Status::StreamEnd {
            return out;
        }
    }
}

#[derive(Clone)]
enum Method {
    Copy,
    /// 7zAES over Copy, stored as `[Copy, 7zAES]`.
    AesCopy(Aes),
    /// 7zAES alone.
    AesOnly(Aes),
    Lzma2,
}

fn make_folder(method: &Method, plain: &[u8]) -> Folder {
    let n = plain.len() as u64;
    match method {
        Method::Copy => Folder {
            coders: vec![Coder { id: COPY, props: vec![] }],
            unpack_sizes: vec![n],
            packed: plain.to_vec(),
            crc: None,
        },
        Method::AesCopy(aes) => Folder {
            coders: vec![Coder { id: COPY, props: vec![] }, Coder { id: AES, props: aes.properties() }],
            unpack_sizes: vec![n, n],
            packed: aes.encrypt(plain),
            crc: None,
        },
        Method::AesOnly(aes) => Folder {
            coders: vec![Coder { id: AES, props: aes.properties() }],
            unpack_sizes: vec![n],
            packed: aes.encrypt(plain),
            crc: None,
        },
        Method::Lzma2 => {
            let (packed, prop) = lzma2_encode(plain);
            Folder { coders: vec![Coder { id: LZMA2, props: vec![prop] }], unpack_sizes: vec![n], packed, crc: None }
        }
    }
}

#[derive(Clone)]
enum HeaderMode {
    Plain,
    Lzma,
    Lzma2,
    /// `-mhe`: LZMA under 7zAES.
    Encrypted(Aes),
}

/// One archive entry: a file with data, an empty file, or a directory.
#[derive(Clone)]
enum Entry {
    File(&'static str, Vec<u8>),
    Empty(&'static str),
    Dir(&'static str),
}

/// Streams info for `folders`, whose packed streams start `pack_pos` bytes after the signature header.
fn streams_info(out: &mut Vec<u8>, pack_pos: u64, folders: &[Folder], substreams: Option<&[Vec<u64>]>, crcs: &[u32]) {
    out.push(0x06);
    num(out, pack_pos);
    num(out, folders.len() as u64);
    out.push(0x09);
    for f in folders {
        num(out, f.packed.len() as u64);
    }
    out.push(0x00);
    out.push(0x07);
    out.push(0x0B);
    num(out, folders.len() as u64);
    out.push(0x00);
    for f in folders {
        write_folder(out, f);
    }
    out.push(0x0C);
    for f in folders {
        for &s in &f.unpack_sizes {
            num(out, s);
        }
    }
    if folders.iter().any(|f| f.crc.is_some()) {
        out.push(0x0A);
        out.push(0x01);
        for f in folders {
            out.extend_from_slice(&f.crc.unwrap_or(0).to_le_bytes());
        }
    }
    out.push(0x00);
    if let Some(subs) = substreams {
        out.push(0x08);
        out.push(0x0D);
        for s in subs {
            num(out, s.len() as u64);
        }
        out.push(0x09);
        for s in subs {
            for &size in &s[..s.len().saturating_sub(1)] {
                num(out, size);
            }
        }
        out.push(0x0A);
        out.push(0x01);
        for c in crcs {
            out.extend_from_slice(&c.to_le_bytes());
        }
        out.push(0x00);
    }
    out.push(0x00);
}

/// A plain header for `groups` (each a folder method and its entries with data) and `loose` entries without data.
fn plain_header(folders: &[Folder], groups: &[(Method, Vec<Entry>)], loose: &[Entry]) -> Vec<u8> {
    let mut h = vec![0x01];
    let mut files: Vec<&Entry> = Vec::new();
    let mut subs = Vec::new();
    let mut crcs = Vec::new();
    for (_, entries) in groups {
        let mut sizes = Vec::new();
        for e in entries {
            if let Entry::File(_, bytes) = e {
                sizes.push(bytes.len() as u64);
                crcs.push(crc(bytes));
                files.push(e);
            }
        }
        subs.push(sizes);
    }
    files.extend(loose);
    if !folders.is_empty() {
        h.push(0x04);
        streams_info(&mut h, 0, folders, Some(&subs), &crcs);
    }
    h.push(0x05);
    num(&mut h, files.len() as u64);
    let empty: Vec<bool> = files.iter().map(|e| !matches!(e, Entry::File(..))).collect();
    if empty.iter().any(|&e| e) {
        let mut bits = vec![0u8; files.len().div_ceil(8)];
        for (i, &e) in empty.iter().enumerate() {
            if e {
                bits[i / 8] |= 0x80 >> (i % 8);
            }
        }
        h.push(0x0E);
        num(&mut h, bits.len() as u64);
        h.extend_from_slice(&bits);
        let empties: Vec<&&Entry> = files.iter().filter(|e| !matches!(e, Entry::File(..))).collect();
        let mut bits = vec![0u8; empties.len().div_ceil(8)];
        for (i, e) in empties.iter().enumerate() {
            if matches!(e, Entry::Empty(_)) {
                bits[i / 8] |= 0x80 >> (i % 8);
            }
        }
        h.push(0x0F);
        num(&mut h, bits.len() as u64);
        h.extend_from_slice(&bits);
    }
    let mut names = vec![0u8];
    for e in &files {
        let (Entry::File(n, _) | Entry::Empty(n) | Entry::Dir(n)) = e;
        for u in n.encode_utf16() {
            names.extend_from_slice(&u.to_le_bytes());
        }
        names.extend_from_slice(&[0, 0]);
    }
    h.push(0x11);
    num(&mut h, names.len() as u64);
    h.extend_from_slice(&names);
    let mut times = vec![1u8, 0];
    for i in 0..files.len() {
        times.extend_from_slice(&(116_444_736_000_000_000u64 + 10_000_000 * (1_700_000_000 + i as u64)).to_le_bytes());
    }
    h.push(0x14);
    num(&mut h, times.len() as u64);
    h.extend_from_slice(&times);
    let mut attrs = vec![1u8, 0];
    for e in &files {
        let a: u32 = match e {
            Entry::Dir(_) => 0x10 | 0x8000 | (0o040755 << 16),
            _ => 0x20 | 0x8000 | (0o100644 << 16),
        };
        attrs.extend_from_slice(&a.to_le_bytes());
    }
    h.push(0x15);
    num(&mut h, attrs.len() as u64);
    h.extend_from_slice(&attrs);
    h.push(0x00);
    h.push(0x00);
    h
}

/// The signature header for a next header at `body_len` bytes past it.
fn signature(body_len: u64, header: &[u8]) -> Vec<u8> {
    let mut sig = vec![b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C, 0, 4, 0, 0, 0, 0];
    sig.extend_from_slice(&body_len.to_le_bytes());
    sig.extend_from_slice(&(header.len() as u64).to_le_bytes());
    sig.extend_from_slice(&crc(header).to_le_bytes());
    let start = crc(&sig[12..32]);
    sig[8..12].copy_from_slice(&start.to_le_bytes());
    sig
}

/// Wraps a raw next header after `body` with valid CRCs.
fn wrap(body: &[u8], header: &[u8]) -> Vec<u8> {
    let mut out = signature(body.len() as u64, header);
    out.extend_from_slice(body);
    out.extend_from_slice(header);
    out
}

/// Encodes `plain` (a plain header) as an encoded header whose packed stream follows `body`.
fn encode_header(body: &mut Vec<u8>, plain: &[u8], mode: &HeaderMode) -> Vec<u8> {
    let pack_pos = body.len() as u64;
    let folder = match mode {
        HeaderMode::Plain => return plain.to_vec(),
        HeaderMode::Lzma2 => {
            let (packed, prop) = lzma2_encode(plain);
            Folder {
                coders: vec![Coder { id: LZMA2, props: vec![prop] }],
                unpack_sizes: vec![plain.len() as u64],
                packed,
                crc: Some(crc(plain)),
            }
        }
        HeaderMode::Lzma => {
            let (packed, props) = lzma_encode(plain);
            Folder {
                coders: vec![Coder { id: LZMA, props }],
                unpack_sizes: vec![plain.len() as u64],
                packed,
                crc: Some(crc(plain)),
            }
        }
        HeaderMode::Encrypted(aes) => {
            let (lz, props) = lzma_encode(plain);
            Folder {
                coders: vec![Coder { id: LZMA, props }, Coder { id: AES, props: aes.properties() }],
                unpack_sizes: vec![plain.len() as u64, lz.len() as u64],
                packed: aes.encrypt(&lz),
                crc: Some(crc(plain)),
            }
        }
    };
    body.extend_from_slice(&folder.packed);
    let mut h = vec![0x17];
    streams_info(&mut h, pack_pos, std::slice::from_ref(&folder), None, &[]);
    h
}

fn build(groups: &[(Method, Vec<Entry>)], loose: &[Entry], mode: &HeaderMode) -> Vec<u8> {
    let mut folders = Vec::new();
    let mut body = Vec::new();
    for (method, entries) in groups {
        let plain: Vec<u8> = entries
            .iter()
            .flat_map(|e| match e {
                Entry::File(_, b) => b.clone(),
                _ => Vec::new(),
            })
            .collect();
        let folder = make_folder(method, &plain);
        body.extend_from_slice(&folder.packed);
        folders.push(folder);
    }
    let plain = plain_header(&folders, groups, loose);
    let header = encode_header(&mut body, &plain, mode);
    wrap(&body, &header)
}

fn split(archive: &[u8], size: usize) -> Vec<Vec<u8>> {
    archive.chunks(size).map(<[u8]>::to_vec).collect()
}

fn refs(volumes: &[Vec<u8>]) -> Vec<&[u8]> {
    volumes.iter().map(Vec::as_slice).collect()
}

fn gather(volumes: &[Vec<u8>], spans: &[PackedSpan]) -> Vec<u8> {
    spans
        .iter()
        .flat_map(|s| volumes[s.volume as usize][s.packed.start as usize..s.packed.end as usize].iter().copied())
        .collect()
}

fn map_set(volumes: &[Vec<u8>], password: Option<&str>) -> Result<MemberMap, MapError> {
    MemberMap::from_memory(&refs(volumes), "set.7z.001", password)
}

fn assert_direct_round_trips(member: &MapMember, volumes: &[Vec<u8>], gold: &[u8]) {
    assert_eq!(member.mapping, OutputMapping::Direct);
    let n = gold.len() as u64;
    for range in [0..n, 0..1, n / 3..n / 2, n.saturating_sub(1)..n, 7..n + 100] {
        let spans = member.packed_spans(range.clone()).unwrap();
        let end = (range.end.min(n)) as usize;
        let start = (range.start as usize).min(end);
        assert_eq!(gather(volumes, &spans), &gold[start..end], "range {range:?}");
    }
}

// ---- Copy folders ----

#[test]
fn single_file_copy_maps_direct_spans() {
    let gold = data(10_000, 1);
    let archive = build(&[(Method::Copy, vec![Entry::File("movie.mkv", gold.clone())])], &[], &HeaderMode::Plain);
    let volumes = vec![archive];
    let map = map_set(&volumes, None).unwrap();
    assert_eq!(map.format, MapFormat::SevenZip);
    assert!(map.complete);
    assert_eq!(map.end, MapEnd::Complete);
    assert_eq!(map.volumes, 1);
    assert!(!map.header_encrypted);
    assert_eq!(map.members.len(), 1);
    assert_eq!(map.folders.len(), 1);
    let folder = &map.folders[0];
    assert_eq!(folder.coders.len(), 1);
    assert_eq!(folder.coders[0].kind, CoderKind::Copy);
    assert_eq!(folder.unpacked_size, 10_000);
    assert_eq!(folder.packed, vec![PackedSpan { volume: 0, packed: 32..10_032, stream: 0..10_000 }]);
    let m = &map.members[0];
    assert_eq!(m.name.as_deref(), Some("movie.mkv"));
    assert_eq!(m.raw_name, "movie.mkv".encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>());
    assert!(!m.is_dir && !m.encrypted && !m.solid && m.complete);
    assert_eq!(m.unpacked_size, Some(10_000));
    assert_eq!(m.packed_size, 10_000);
    assert_eq!(m.method, MapMethod::Stored);
    assert_eq!(m.checks.unwrap().crc32, Some(crc(&gold)));
    assert_eq!(m.folder, Some(FolderSlot { index: 0, offset: 0 }));
    assert_eq!(m.mtime, Some((1_700_000_000, 0)));
    assert_eq!(m.unix_mode, Some(0o100644));
    assert_eq!(m.pieces.len(), 1);
    assert_eq!(m.pieces[0].out, Some(0..10_000));
    assert!(m.pieces[0].final_part);
    assert_direct_round_trips(m, &volumes, &gold);

    // The stored member streams from any offset through extract_member_from, checked against its CRC.
    let mut out = Vec::new();
    extract_member_from(&refs(&volumes), &map, 0, 0, None, &mut out).unwrap();
    assert_eq!(out, gold);
    let mut out = Vec::new();
    extract_member_from(&refs(&volumes), &map, 0, 4321, None, &mut out).unwrap();
    assert_eq!(out, &gold[4321..]);
}

#[test]
fn several_files_in_one_copy_folder_get_their_substream_offsets() {
    let (a, b, c) = (data(3000, 2), data(1, 3), data(7777, 4));
    let archive = build(
        &[(
            Method::Copy,
            vec![Entry::File("a.bin", a.clone()), Entry::File("b.bin", b.clone()), Entry::File("c.bin", c.clone())],
        )],
        &[Entry::Dir("sub"), Entry::Empty("empty.txt")],
        &HeaderMode::Plain,
    );
    let volumes = vec![archive];
    let map = map_set(&volumes, None).unwrap();
    assert_eq!(map.members.len(), 5);
    assert_eq!(map.folders[0].members, 3);
    for (i, (gold, offset)) in [(&a, 0u64), (&b, 3000), (&c, 3001)].into_iter().enumerate() {
        let m = &map.members[i];
        assert_eq!(m.folder, Some(FolderSlot { index: 0, offset }), "{i}");
        assert_eq!(m.pieces[0].packed.start, 32 + offset);
        assert_eq!(m.checks.unwrap().crc32, Some(crc(gold)));
        assert_direct_round_trips(m, &volumes, gold);
        let mut out = Vec::new();
        extract_member_from(&refs(&volumes), &map, i, 0, None, &mut out).unwrap();
        assert_eq!(&out, gold);
    }
    let dir = &map.members[3];
    assert_eq!(dir.name.as_deref(), Some("sub"));
    assert!(dir.is_dir && dir.pieces.is_empty() && dir.folder.is_none());
    assert_eq!(dir.unix_mode, Some(0o040755));
    let empty = &map.members[4];
    assert!(!empty.is_dir && empty.pieces.is_empty());
    assert_eq!(empty.unpacked_size, Some(0));
    assert_eq!(empty.packed_spans(0..10), Some(vec![]));
}

#[test]
fn split_copy_set_spans_cross_volume_boundaries() {
    let (a, b) = (data(5000, 5), data(2500, 6));
    let archive = build(
        &[(Method::Copy, vec![Entry::File("a", a.clone()), Entry::File("b", b.clone())])],
        &[],
        &HeaderMode::Lzma2,
    );
    let volumes = split(&archive, 3000);
    assert_eq!(volumes.len(), 3);
    let map = map_set(&volumes, None).unwrap();
    assert!(map.complete);
    assert_eq!(map.volumes, 3);
    let (ma, mb) = (&map.members[0], &map.members[1]);
    // a: archive 32..5032, over volume 0 (32..3000) and volume 1 (0..2032).
    let pieces: Vec<_> = ma.pieces.iter().map(|p| (p.volume, p.packed.clone(), p.stream_offset)).collect();
    assert_eq!(pieces, vec![(0, 32..3000, 0), (1, 0..2032, 2968)]);
    assert!(!ma.pieces[0].final_part && ma.pieces[1].final_part);
    // b: archive 5032..7532, over volume 1 (2032..3000) and volume 2 (0..1532).
    let pieces: Vec<_> = mb.pieces.iter().map(|p| (p.volume, p.packed.clone())).collect();
    assert_eq!(pieces, vec![(1, 2032..3000), (2, 0..1532)]);
    assert_direct_round_trips(ma, &volumes, &a);
    assert_direct_round_trips(mb, &volumes, &b);
    let spans = ma.packed_spans(2900..3100).unwrap();
    assert_eq!(spans.len(), 2);
    assert_eq!(spans[0], PackedSpan { volume: 0, packed: 2932..3000, stream: 2900..2968 });
    assert_eq!(spans[1], PackedSpan { volume: 1, packed: 0..132, stream: 2968..3100 });
    assert_eq!(map.folders[0].packed.len(), 3);

    let mut out = Vec::new();
    extract_member_from(&refs(&volumes), &map, 1, 100, None, &mut out).unwrap();
    assert_eq!(out, &b[100..]);
}

#[test]
fn lzma_and_lzma2_encoded_headers_map_like_plain_ones() {
    let groups = [(Method::Copy, vec![Entry::File("x", data(999, 7)), Entry::File("y", data(5, 8))])];
    let plain = map_set(&[build(&groups, &[Entry::Dir("d")], &HeaderMode::Plain)], None).unwrap();
    for mode in [HeaderMode::Lzma, HeaderMode::Lzma2] {
        let archive = build(&groups, &[Entry::Dir("d")], &mode);
        let encoded = map_set(&[archive], None).unwrap();
        assert!(!encoded.header_encrypted && encoded.header_cipher.is_none());
        assert_eq!(encoded.members, plain.members);
        assert_eq!(encoded.folders, plain.folders);
    }
}

// ---- Coded folders ----

#[test]
fn lzma2_folder_reports_its_packed_range_and_size_without_mapping() {
    let (a, b) = (noise(20_000, 9), data(3000, 10));
    let archive = build(
        &[
            (Method::Lzma2, vec![Entry::File("a", a.clone()), Entry::File("b", b.clone())]),
            (Method::Copy, vec![Entry::File("c", data(10, 11))]),
        ],
        &[],
        &HeaderMode::Lzma2,
    );
    let volumes = split(&archive, 1000);
    let map = map_set(&volumes, None).unwrap();
    let folder = &map.folders[0];
    assert_eq!(folder.coders[0].kind, CoderKind::Lzma2);
    assert_eq!(folder.coders[0].id, 0x21);
    assert_eq!(folder.coders[0].properties, vec![16]);
    assert_eq!(folder.unpacked_size, 23_000);
    let packed_len: u64 = folder.pack_sizes.iter().sum();
    assert_eq!(folder.packed.last().unwrap().stream.end, packed_len);
    assert!(folder.packed.len() > 1, "the folder's packed bytes cross volumes");
    for (i, offset) in [(0usize, 0u64), (1, 20_000)] {
        let m = &map.members[i];
        assert_eq!(m.mapping, OutputMapping::None);
        assert_eq!(m.method, MapMethod::Coders);
        assert_eq!(m.solid, offset > 0);
        assert_eq!(m.folder, Some(FolderSlot { index: 0, offset }));
        assert_eq!(m.packed_size, packed_len);
        assert_eq!(m.packed_spans(0..10), None);
        // The pieces are the folder's packed bytes.
        let spans: Vec<_> = m.pieces.iter().map(|p| (p.volume, p.packed.clone(), p.stream_offset)).collect();
        let want: Vec<_> = folder.packed.iter().map(|s| (s.volume, s.packed.clone(), s.stream.start)).collect();
        assert_eq!(spans, want);
    }
    // The gathered packed bytes decode to the folder output.
    let packed = gather(&volumes, &folder.packed);
    let mut filters = liblzma::stream::Filters::new();
    filters.lzma2_properties(&[16]).unwrap();
    let mut stream = liblzma::stream::Stream::new_raw_decoder(&filters).unwrap();
    let mut out = Vec::with_capacity(23_000);
    stream.process_vec(&packed, &mut out, liblzma::stream::Action::Finish).unwrap();
    assert_eq!(out, [a, b].concat());
    // The Copy folder after it is still mapped.
    assert_eq!(map.members[2].mapping, OutputMapping::Direct);
    assert_eq!(map.members[2].folder, Some(FolderSlot { index: 1, offset: 0 }));
    let error = extract_member_from(&refs(&volumes), &map, 0, 0, None, &mut Vec::new()).unwrap_err();
    assert!(matches!(error, ExtractFromError::Unsupported(UnsupportedRead::Coders)), "{error:?}");
}

#[test]
fn aes_copy_folder_maps_cbc_blocks_that_decrypt_from_the_spans() {
    let aes = Aes::new("secret");
    let (a, b) = (data(1000, 12), data(77, 13));
    let archive = build(
        &[
            (Method::AesCopy(aes.clone()), vec![Entry::File("a", a.clone()), Entry::File("b", b.clone())]),
            (Method::AesOnly(aes.clone()), vec![Entry::File("c", b.clone())]),
        ],
        &[],
        &HeaderMode::Lzma2,
    );
    let volumes = split(&archive, 333);
    let map = map_set(&volumes, None).unwrap();
    assert!(!map.header_encrypted);
    let params = CipherParams::SevenZipAes { num_cycles_power: 6, salt: aes.salt.clone(), iv: aes.iv };
    assert_eq!(map.folders[0].cipher, Some(params.clone()));
    assert_eq!(map.folders[0].coders.iter().map(|c| c.kind).collect::<Vec<_>>(), vec![CoderKind::Copy, CoderKind::Aes]);
    let key = aes.key();
    let ma = &map.members[0];
    assert_eq!(ma.mapping, OutputMapping::CbcBlocks);
    assert_eq!(ma.method, MapMethod::Stored);
    assert!(ma.encrypted);
    assert_eq!(ma.cipher, Some(params.clone()));
    assert_eq!(ma.packed_size, 1008);
    for range in [0..1000u64, 0..1, 500..600, 999..1000, 16..32, 17..18] {
        let spans = ma.packed_spans(range.clone()).unwrap();
        let first = spans[0].stream.start;
        let mut bytes = gather(&volumes, &spans);
        let iv: [u8; 16] = if first == 0 { aes.iv } else { bytes.drain(..16).collect::<Vec<_>>().try_into().unwrap() };
        let plain = zipfast::crypto::decrypt_cbc(&key, &iv, &bytes).unwrap();
        let at = if first == 0 { 0 } else { first + 16 };
        let want = &a[range.start as usize..range.end as usize];
        let from = (range.start - at) as usize;
        assert_eq!(&plain[from..from + want.len()], want, "range {range:?}");
    }
    let mut out = Vec::new();
    let done = extract_member_from(&refs(&volumes), &map, 0, 0, Some("secret"), &mut out).unwrap();
    assert_eq!(out, a);
    assert!(done.password_verified);
    let mut out = Vec::new();
    extract_member_from(&refs(&volumes), &map, 0, 333, Some("secret"), &mut out).unwrap();
    assert_eq!(out, &a[333..]);
    let wrong = extract_member_from(&refs(&volumes), &map, 0, 0, Some("nope"), &mut Vec::new()).unwrap_err();
    assert!(matches!(wrong, ExtractFromError::MemberBad { .. }), "{wrong:?}");
    assert!(matches!(
        extract_member_from(&refs(&volumes), &map, 0, 0, None, &mut Vec::new()),
        Err(ExtractFromError::PasswordRequired)
    ));

    // The second member of the folder starts mid-stream: listed with the folder's bytes, not mapped.
    let mb = &map.members[1];
    assert_eq!(mb.mapping, OutputMapping::None);
    assert_eq!(mb.method, MapMethod::Stored);
    assert_eq!(mb.folder, Some(FolderSlot { index: 0, offset: 1000 }));
    assert_eq!(mb.cipher, Some(params.clone()));
    // A lone 7zAES coder maps too.
    let mc = &map.members[2];
    assert_eq!(mc.mapping, OutputMapping::CbcBlocks);
    let mut out = Vec::new();
    extract_member_from(&refs(&volumes), &map, 2, 0, Some("secret"), &mut out).unwrap();
    assert_eq!(out, b);
}

// ---- Encrypted headers ----

#[test]
fn encrypted_headers_need_the_right_password() {
    let aes = Aes::new("hunter2");
    let gold = data(4000, 14);
    let groups = [(Method::AesCopy(aes.clone()), vec![Entry::File("film.mkv", gold.clone())])];
    let archive = build(&groups, &[], &HeaderMode::Encrypted(aes.clone()));
    let volumes = split(&archive, 1500);
    assert!(matches!(map_set(&volumes, None), Err(MapError::PasswordRequired)));
    assert!(matches!(map_set(&volumes, Some("")), Err(MapError::PasswordRequired)));
    let wrong = map_set(&volumes, Some("hunter3"));
    assert!(matches!(wrong, Err(MapError::WrongPassword)), "{wrong:?}");
    let map = map_set(&volumes, Some("hunter2")).unwrap();
    assert!(map.complete && map.header_encrypted);
    assert_eq!(
        map.header_cipher,
        Some(CipherParams::SevenZipAes { num_cycles_power: 6, salt: aes.salt.clone(), iv: aes.iv })
    );
    let m = &map.members[0];
    assert_eq!(m.name.as_deref(), Some("film.mkv"));
    assert_eq!(m.mapping, OutputMapping::CbcBlocks);
    let mut out = Vec::new();
    extract_member_from(&refs(&volumes), &map, 0, 1234, Some("hunter2"), &mut out).unwrap();
    assert_eq!(out, &gold[1234..]);
}

#[test]
fn encrypted_header_kdf_respects_limits_and_cancellation() {
    let mut aes = Aes::new("pw");
    aes.power = 12;
    let archive = build(&[(Method::Copy, vec![Entry::File("f", data(10, 1))])], &[], &HeaderMode::Encrypted(aes));
    let mut options = MapOptions::new("a.7z").password(Some("pw"));
    options.limits.kdf_exponent = 11;
    let error = MemberMap::from_memory_with(&[&archive], options).unwrap_err();
    assert!(matches!(error, MapError::Limit { resource: Resource::KdfExponent, .. }), "{error:?}");
    let mut options = MapOptions::new("a.7z").password(Some("pw"));
    options.limits.kdf_derivation_blocks = 10;
    let error = MemberMap::from_memory_with(&[&archive], options).unwrap_err();
    assert!(matches!(error, MapError::Limit { resource: Resource::KdfDerivationBlocks, .. }), "{error:?}");
    let options = MapOptions::new("a.7z").password(Some("pw"));
    options.control.cancel();
    assert!(matches!(MemberMap::from_memory_with(&[&archive], options), Err(MapError::Source(_))));
}

// ---- Cut sets ----

#[test]
fn cut_sets_report_the_header_unavailable() {
    let archive = build(&[(Method::Copy, vec![Entry::File("big", data(9000, 15))])], &[], &HeaderMode::Lzma2);
    let header_at = 32 + u64::from_le_bytes(archive[12..20].try_into().unwrap());
    let volumes = split(&archive, 4000);
    assert_eq!(volumes.len(), 3);
    for present in 1..3 {
        let map = map_set(&volumes[..present], None).unwrap();
        assert!(!map.complete);
        assert_eq!(map.end, MapEnd::HeaderUnavailable { volume: present as u32, offset: header_at });
        assert_eq!(map.volumes, present as u32);
        assert!(map.members.is_empty() && map.folders.is_empty());
    }
    // The last volume cut short.
    let mut cut = volumes.clone();
    cut[2].pop();
    let map = map_set(&cut, None).unwrap();
    assert_eq!(map.end, MapEnd::HeaderUnavailable { volume: 3, offset: header_at });
    // A single file cut short, and cut inside the signature header.
    let map = map_set(&[archive[..archive.len() - 10].to_vec()], None).unwrap();
    assert!(matches!(map.end, MapEnd::HeaderUnavailable { volume: 1, .. }));
    let map = map_set(&[archive[..20].to_vec()], None).unwrap();
    assert_eq!(map.end, MapEnd::Truncated { volume: 0, offset: 0 });
}

// ---- Detection ----

#[test]
fn seven_zip_is_not_mapped_volume_by_volume_or_probed() {
    let archive = build(&[(Method::Copy, vec![Entry::File("f", data(100, 1))])], &[], &HeaderMode::Plain);
    assert!(matches!(MemberMap::from_volume(&archive, MapOptions::new("a.7z")), Err(MapError::NotArchive)));
    assert!(matches!(zipfast::probe::probe(&archive, None, None), Ok(zipfast::probe::Packing::Unknown)));
    let empty = wrap(&[], &[]);
    let map = map_set(&[empty], None).unwrap();
    assert!(map.complete && map.members.is_empty());
}

// ---- Hostile headers ----

/// Maps a plain header wrapped with valid CRCs.
fn map_header(header: &[u8], options: MapOptions) -> Result<MemberMap, MapError> {
    MemberMap::from_memory_with(&[&wrap(&[0; 64], header)], options)
}

#[test]
fn hostile_counts_are_typed_errors() {
    let options = || MapOptions::new("a.7z");
    let malformed =
        |r: Result<MemberMap, MapError>| matches!(r, Err(MapError::Malformed { .. } | MapError::Limit { .. }));
    // A file count of 2^60.
    let mut h = vec![0x01, 0x05];
    num(&mut h, 1 << 60);
    h.extend_from_slice(&[0, 0]);
    assert!(matches!(map_header(&h, options()), Err(MapError::Limit { resource: Resource::Entries, .. })));
    // A file count under the entry budget but not the metadata budget.
    let mut small = options();
    small.limits.metadata_bytes = 1000;
    let mut h = vec![0x01, 0x05];
    num(&mut h, 100_000);
    h.extend_from_slice(&[0, 0]);
    assert!(matches!(map_header(&h, small), Err(MapError::Limit { resource: Resource::MetadataBytes, .. })));
    // Folder, pack stream and coder counts beyond the header.
    for body in [
        vec![0x04, 0x06, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F],
        vec![0x04, 0x07, 0x0B, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00],
        vec![0x04, 0x07, 0x0B, 0x01, 0x00, 0x7F],
        vec![0x04, 0x06, 0x00, 0x01, 0x09, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00],
    ] {
        let mut h = vec![0x01];
        h.extend_from_slice(&body);
        h.extend_from_slice(&[0, 0, 0]);
        let result = map_header(&h, options());
        assert!(malformed(result), "{body:?}");
    }
    // An encoded header that decodes to another, and another...
    let mut body = Vec::new();
    let mut header = plain_header(&[], &[], &[Entry::Dir("d")]);
    for _ in 0..6 {
        header = encode_header(&mut body, &header, &HeaderMode::Lzma2);
    }
    let error = MemberMap::from_memory(&[&wrap(&body, &header)], "a.7z", None).unwrap_err();
    assert!(matches!(error, MapError::Malformed { .. }) && error.to_string().contains("nest"), "{error:?}");
    // A next header bigger than the header budget.
    let mut tight = options();
    tight.limits.header_bytes = 100;
    let archive = build(&[(Method::Copy, vec![Entry::File("f", data(10, 1))])], &[Entry::Dir("x")], &HeaderMode::Plain);
    let result = MemberMap::from_memory_with(&[&archive], tight);
    assert!(matches!(result, Err(MapError::Limit { resource: Resource::HeaderBytes, .. })), "{result:?}");
    // A next header offset that overflows.
    let mut sig = signature(u64::MAX - 10, &[1, 2, 3]);
    sig.extend_from_slice(&[1, 2, 3]);
    assert!(matches!(MemberMap::from_memory(&[&sig], "a.7z", None), Err(MapError::Malformed { .. })));
}

#[test]
fn truncation_and_bit_flip_sweeps_never_panic() {
    let aes = Aes::new("pw");
    let mut seeds = Vec::new();
    for mode in [HeaderMode::Plain, HeaderMode::Lzma2, HeaderMode::Encrypted(aes.clone())] {
        seeds.push(build(
            &[
                (Method::Copy, vec![Entry::File("a", data(40, 1)), Entry::File("b", data(3, 2))]),
                (Method::AesCopy(aes.clone()), vec![Entry::File("c", data(20, 3))]),
                (Method::Lzma2, vec![Entry::File("d", data(50, 4))]),
            ],
            &[Entry::Dir("dir"), Entry::Empty("e")],
            &mode,
        ));
    }
    for archive in &seeds {
        for cut in 0..archive.len() {
            let _ = map_set(&[archive[..cut].to_vec()], Some("pw"));
            let _ = map_set(&split(&archive[..cut.max(1)], 17), Some("pw"));
        }
        let header_at = 32 + u64::from_le_bytes(archive[12..20].try_into().unwrap()) as usize;
        for at in 0..archive.len() {
            for flip in [0x01u8, 0x80, 0xFF] {
                let mut bad = archive.clone();
                bad[at] ^= flip;
                let _ = map_set(&[bad.clone()], Some("pw"));
                // Past the CRC checks: re-seal the header so the parser sees the damage.
                if at >= header_at {
                    let resealed = wrap(&bad[32..header_at], &bad[header_at..]);
                    let _ = map_set(&[resealed], Some("pw"));
                }
            }
        }
    }
    // Every byte of a plain header set to hostile values, re-sealed.
    let archive = &seeds[0];
    let header_at = 32 + u64::from_le_bytes(archive[12..20].try_into().unwrap()) as usize;
    for at in header_at..archive.len() {
        for value in [0x00u8, 0x7F, 0x80, 0xC0, 0xFE, 0xFF] {
            let mut header = archive[header_at..].to_vec();
            header[at - header_at] = value;
            let _ = map_set(&[wrap(&archive[32..header_at], &header)], None);
        }
    }
}

// ---- A waiting volume source ----

#[derive(Default)]
struct Gate {
    ready: bool,
    waits: usize,
}

struct Bytes {
    data: Vec<u8>,
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
    fn read_at(&mut self, at: u64, buf: &mut [u8], _: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
        let mut g = self.gate.lock().unwrap();
        if !g.ready {
            g.waits += 1;
            g.ready = true;
            return Ok(RangeRead::NotYet);
        }
        g.ready = false;
        let end = (at as usize + buf.len().min(500)).min(self.data.len());
        let n = end - at as usize;
        buf[..n].copy_from_slice(&self.data[at as usize..end]);
        Ok(RangeRead::Filled { count: n })
    }
}

struct Provider {
    volumes: Vec<Vec<u8>>,
    gate: Arc<Mutex<Gate>>,
    asked: Arc<Mutex<Vec<(u32, String)>>>,
}

impl VolumeSource for Provider {
    fn volume(&mut self, r: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
        let mut g = self.gate.lock().unwrap();
        if !g.ready {
            g.waits += 1;
            g.ready = true;
            return Ok(VolumeAnswer::Wait);
        }
        g.ready = false;
        self.asked.lock().unwrap().push((r.index, r.expected.to_string_lossy().into_owned()));
        Ok(match self.volumes.get(r.index as usize) {
            Some(data) => VolumeAnswer::Ready(Box::new(Bytes { data: data.clone(), gate: self.gate.clone() })),
            None => VolumeAnswer::Missing,
        })
    }
}

#[test]
fn map_builder_waits_and_names_numbered_volumes() {
    let aes = Aes::new("pw");
    let gold = data(6000, 16);
    let archive = build(&[(Method::Copy, vec![Entry::File("f", gold.clone())])], &[], &HeaderMode::Encrypted(aes));
    let volumes = split(&archive, 2500);
    let gate = Arc::new(Mutex::new(Gate::default()));
    let asked = Arc::new(Mutex::new(Vec::new()));
    let provider = Provider { volumes: volumes.clone(), gate: gate.clone(), asked: asked.clone() };
    let mut builder = MapBuilder::new(Box::new(provider), MapOptions::new("dir/set.7z.001").password(Some("pw")));
    let mut cx = Context::from_waker(Waker::noop());
    let mut pending = 0;
    let map = loop {
        match builder.poll_map(&mut cx) {
            Poll::Ready(result) => break result.unwrap(),
            Poll::Pending => pending += 1,
        }
        assert!(pending < 10_000);
    };
    assert!(pending > 0 && gate.lock().unwrap().waits == pending);
    assert_eq!(map.members, MemberMap::from_memory(&refs(&volumes), "x", Some("pw")).unwrap().members);
    let names: Vec<_> = asked.lock().unwrap().iter().take(3).cloned().collect();
    assert_eq!(names, vec![(0, "dir/set.7z.001".into()), (1, "dir/set.7z.002".into()), (2, "dir/set.7z.003".into())]);
    assert_direct_round_trips(&map.members[0], &volumes, &gold);
}
