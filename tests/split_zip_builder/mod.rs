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

//! Builds Info-ZIP spanned sets (`name.z01`, ..., `name.zip`) in memory for tests: entries written as one stream
//! and cut at chosen offsets, with each local header's and the directory's (disk, offset) as a spanned set has them.
#![allow(dead_code)]

use std::io::Cursor;

pub fn data(len: usize, seed: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + seed) % 251) as u8).collect()
}

/// Absolute stream offset of a member's data.
pub fn data_abs(entries: &[Entry], index: usize, marker: bool) -> usize {
    let mut at = if marker { 4 } else { 0 };
    for e in &entries[..index] {
        at += 30 + e.name.len() + e.extra.len() + e.payload.len() + if e.flags & 8 != 0 { 16 } else { 0 };
    }
    at + 30 + entries[index].name.len() + entries[index].extra.len()
}

// ---- Building split sets ----

#[derive(Clone)]
pub struct Entry {
    pub name: &'static str,
    pub payload: Vec<u8>,
    pub method: u16,
    pub flags: u16,
    pub extra: Vec<u8>,
    pub crc: u32,
    pub size: u32,
}

impl Entry {
    pub fn stored(name: &'static str, payload: &[u8]) -> Self {
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
pub struct Layout {
    /// Start the first volume with the spanning signature.
    pub marker: bool,
    /// Store every disk number and offset in ZIP64 fields and end records.
    pub zip64: bool,
}

/// A split set.
pub struct Set {
    pub volumes: Vec<Vec<u8>>,
    /// Each entry's local header as (disk, offset).
    pub locals: Vec<(u32, u64)>,
    /// Where the central directory starts, as (disk, offset).
    pub directory: (u32, u64),
}

/// Writes the entries as one stream (marker, local records, central directory, end records) and cuts it at the
/// absolute stream offsets `cuts`. The end records must lie in the last volume.
pub fn split_zip(entries: &[Entry], cuts: &[usize], layout: Layout) -> Set {
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
        if e.flags & 8 != 0 {
            out.extend(b"PK\x07\x08");
            out.extend(e.crc.to_le_bytes());
            out.extend((e.payload.len() as u32).to_le_bytes());
            out.extend(e.size.to_le_bytes());
        }
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

pub fn winzip_aes_payload(plain: &[u8]) -> Vec<u8> {
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
    let map = zipfast::map::MemberMap::from_memory(&[&single], "aes.zip", None).unwrap();
    let piece = &map.members[0].pieces[0];
    single[piece.packed.start as usize..piece.packed.end as usize].to_vec()
}

pub fn aes_entry(plain: &[u8]) -> Entry {
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

/// Traditional PKWARE encryption of `plain` under `password`, with the 12-byte header ending in `check`.
pub fn zipcrypto(password: &str, check: u8, plain: &[u8]) -> Vec<u8> {
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
