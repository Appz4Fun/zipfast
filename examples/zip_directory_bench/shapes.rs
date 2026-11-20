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

//! Writes ZIP archives with large central directories: the shapes measured in
//! `docs/zipfast-parser-performance.md`.
//!
//! Each archive holds `count` stored members. The first two share a name
//! (`duplicate.bin`, or member 0's long name in the unicode shape) and hold
//! `first` and `second`; every later member holds its index as four
//! little-endian bytes. A shape varies the names and the central
//! metadata:
//!
//! - short: 9-byte names (`e00000002`), no extra fields or comments.
//! - rich: 205-byte names, a 196-byte private extra field and a 148-byte
//!   comment on every member after the first two.
//! - unicode: 205-byte raw names plus an Info-ZIP Unicode Path extra (0x7075)
//!   naming each member under `üv/`.
//!
//! A `prefix` puts that many bytes before the archive, as a self-extractor
//! stub does; the stored offsets stay relative to the archive. A directory of
//! 65,535 or more members, or one with `force_zip64`, gets ZIP64 end records.
//! Every archive ends with the comment [`COMMENT`].
//!
//! Shared by `examples/zip_directory_bench` and `tests/zip_directory_shapes.rs`.

use std::io::{self, Write};

/// The archive comment every shape ends with.
pub const COMMENT: &[u8] = b"zipfast-phase2";

/// How many bytes of raw name a rich or unicode member has.
pub const LONG_NAME_BYTES: usize = 205;

/// What one archive looks like.
#[derive(Clone, Copy, Debug)]
pub struct Shape {
    /// The file stem the benchmark writes it under.
    pub label: &'static str,
    /// Members in the archive.
    pub count: usize,
    /// Long names, private extras and comments.
    pub rich: bool,
    /// Long raw names with Unicode Path extras.
    pub unicode: bool,
    /// Bytes of stub before the archive. Not combined with ZIP64.
    pub prefix: u64,
    /// Write ZIP64 end records even for a small directory.
    pub force_zip64: bool,
}

impl Shape {
    /// Whether the archive has ZIP64 end records.
    pub fn zip64(&self) -> bool {
        self.force_zip64 || self.count >= 0xffff
    }
}

/// The shapes `docs/zipfast-parser-performance.md` reports.
pub const BENCH_SHAPES: [Shape; 5] = [
    Shape { label: "short-20k", count: 20_000, rich: false, unicode: false, prefix: 0, force_zip64: false },
    Shape { label: "rich-prefix-20k", count: 20_000, rich: true, unicode: false, prefix: 8192, force_zip64: false },
    Shape { label: "short-zip64-200k", count: 200_000, rich: false, unicode: false, prefix: 0, force_zip64: false },
    Shape { label: "rich-zip64-200k", count: 200_000, rich: true, unicode: false, prefix: 0, force_zip64: false },
    Shape { label: "unicode-zip64-200k", count: 200_000, rich: false, unicode: true, prefix: 0, force_zip64: false },
];

/// One member as the central directory describes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    /// The raw name bytes, in both headers.
    pub raw_name: Vec<u8>,
    /// The name a reader that honours the Unicode Path extra reports.
    pub name: String,
    /// The stored member's bytes.
    pub payload: Vec<u8>,
    /// CRC-32 of `payload`.
    pub crc32: u32,
    /// Offset of the local header as stored: relative to the archive, not the prefix.
    pub local_at: u64,
    /// Bytes of central extra fields.
    pub extra_len: usize,
    /// Bytes of member comment.
    pub comment_len: usize,
}

/// What [`write`] produced.
#[derive(Debug)]
pub struct Written {
    /// Every member, in central order.
    pub members: Vec<Member>,
    /// Where the central directory starts, relative to the archive.
    pub directory_at: u64,
    /// Bytes of central directory records.
    pub directory_len: u64,
    /// Bytes written, prefix included.
    pub len: u64,
}

fn raw_long_name(index: usize) -> Vec<u8> {
    let mut name = format!("dir/{index:08}-").into_bytes();
    name.extend(std::iter::repeat_n(b'n', 188));
    name.extend_from_slice(b".bin");
    debug_assert_eq!(name.len(), LONG_NAME_BYTES);
    name
}

fn raw_name(shape: &Shape, index: usize) -> Vec<u8> {
    if shape.unicode {
        // The first two share a name, as in every shape.
        raw_long_name(if index < 2 { 0 } else { index })
    } else if index < 2 {
        b"duplicate.bin".to_vec()
    } else if shape.rich {
        raw_long_name(index)
    } else {
        format!("e{index:08}").into_bytes()
    }
}

/// The payload of the member at `index`.
pub fn payload(index: usize) -> Vec<u8> {
    match index {
        0 => b"first".to_vec(),
        1 => b"second".to_vec(),
        _ => u32::try_from(index).expect("member index fits u32").to_le_bytes().to_vec(),
    }
}

/// The central extra field and comment of the member at `index`, and the name a Unicode-aware reader reports.
fn central_fields(shape: &Shape, index: usize, raw: &[u8]) -> (Vec<u8>, Vec<u8>, String) {
    if shape.unicode {
        let unicode = format!("üv/{}", std::str::from_utf8(&raw[4..]).expect("generated names are ASCII"));
        let mut body = vec![1];
        body.extend_from_slice(&crc32fast::hash(raw).to_le_bytes());
        body.extend_from_slice(unicode.as_bytes());
        let mut extra = Vec::with_capacity(4 + body.len());
        extra.extend_from_slice(&0x7075u16.to_le_bytes());
        extra.extend_from_slice(&u16::try_from(body.len()).expect("extra fits u16").to_le_bytes());
        extra.extend_from_slice(&body);
        return (extra, Vec::new(), unicode);
    }
    let name = String::from_utf8(raw.to_vec()).expect("generated names are ASCII");
    if shape.rich && index >= 2 {
        let mut extra = Vec::with_capacity(196);
        extra.extend_from_slice(&0xcafeu16.to_le_bytes());
        extra.extend_from_slice(&192u16.to_le_bytes());
        extra.extend(std::iter::repeat_n(b'x', 192));
        return (extra, vec![b'c'; 148], name);
    }
    (Vec::new(), Vec::new(), name)
}

/// A writer that counts what passes through it.
struct Counting<W> {
    inner: W,
    at: u64,
}

impl<W: Write> Counting<W> {
    fn put(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.inner.write_all(bytes)?;
        self.at += bytes.len() as u64;
        Ok(())
    }
}

fn u16_of(value: usize) -> u16 {
    u16::try_from(value).expect("field fits u16")
}

fn u32_of(value: u64) -> u32 {
    u32::try_from(value).expect("field fits u32")
}

/// Writes `shape` to `out` and returns what its central directory says.
///
/// # Panics
///
/// When `shape` combines a prefix with ZIP64, or its directory would pass
/// 4 GiB.
pub fn write<W: Write>(shape: &Shape, out: W) -> io::Result<Written> {
    assert!(shape.prefix == 0 || !shape.zip64(), "a prefix is not combined with ZIP64");
    let mut out = Counting { inner: out, at: 0 };
    let prefix = vec![b'S'; usize::try_from(shape.prefix).expect("prefix fits usize")];
    out.put(&prefix)?;

    let mut members = Vec::with_capacity(shape.count);
    for index in 0..shape.count {
        let raw = raw_name(shape, index);
        let payload = payload(index);
        let crc32 = crc32fast::hash(&payload);
        let local_at = out.at - shape.prefix;
        let mut header = Vec::with_capacity(30);
        header.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        for field in [20u16, 0, 0, 0, 33] {
            header.extend_from_slice(&field.to_le_bytes());
        }
        header.extend_from_slice(&crc32.to_le_bytes());
        header.extend_from_slice(&u32_of(payload.len() as u64).to_le_bytes());
        header.extend_from_slice(&u32_of(payload.len() as u64).to_le_bytes());
        header.extend_from_slice(&u16_of(raw.len()).to_le_bytes());
        header.extend_from_slice(&0u16.to_le_bytes());
        out.put(&header)?;
        out.put(&raw)?;
        out.put(&payload)?;
        let (extra, comment, name) = central_fields(shape, index, &raw);
        members.push(Member {
            raw_name: raw,
            name,
            payload,
            crc32,
            local_at,
            extra_len: extra.len(),
            comment_len: comment.len(),
        });
    }

    let directory_at = out.at - shape.prefix;
    let mut record = Vec::with_capacity(46 + 2 * LONG_NAME_BYTES + 200);
    for (index, member) in members.iter().enumerate() {
        let (extra, comment, _) = central_fields(shape, index, &member.raw_name);
        record.clear();
        record.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        for field in [20u16, 20, 0, 0, 0, 33] {
            record.extend_from_slice(&field.to_le_bytes());
        }
        record.extend_from_slice(&member.crc32.to_le_bytes());
        record.extend_from_slice(&u32_of(member.payload.len() as u64).to_le_bytes());
        record.extend_from_slice(&u32_of(member.payload.len() as u64).to_le_bytes());
        record.extend_from_slice(&u16_of(member.raw_name.len()).to_le_bytes());
        record.extend_from_slice(&u16_of(extra.len()).to_le_bytes());
        record.extend_from_slice(&u16_of(comment.len()).to_le_bytes());
        for field in [0u16, 0] {
            record.extend_from_slice(&field.to_le_bytes());
        }
        record.extend_from_slice(&0u32.to_le_bytes());
        record.extend_from_slice(&u32_of(member.local_at).to_le_bytes());
        record.extend_from_slice(&member.raw_name);
        record.extend_from_slice(&extra);
        record.extend_from_slice(&comment);
        out.put(&record)?;
    }
    let directory_len = out.at - shape.prefix - directory_at;
    let count = shape.count as u64;

    let mut end = Vec::with_capacity(98 + COMMENT.len());
    if shape.zip64() {
        let zip64_end_at = out.at - shape.prefix;
        end.extend_from_slice(&0x0606_4b50u32.to_le_bytes());
        end.extend_from_slice(&44u64.to_le_bytes());
        end.extend_from_slice(&45u16.to_le_bytes());
        end.extend_from_slice(&45u16.to_le_bytes());
        end.extend_from_slice(&0u32.to_le_bytes());
        end.extend_from_slice(&0u32.to_le_bytes());
        for field in [count, count, directory_len, directory_at] {
            end.extend_from_slice(&field.to_le_bytes());
        }
        end.extend_from_slice(&0x0706_4b50u32.to_le_bytes());
        end.extend_from_slice(&0u32.to_le_bytes());
        end.extend_from_slice(&zip64_end_at.to_le_bytes());
        end.extend_from_slice(&1u32.to_le_bytes());
    }
    let (classic_count, classic_len, classic_at) = if shape.zip64() {
        (0xffff, 0xffff_ffff, 0xffff_ffff)
    } else {
        (u16_of(shape.count), u32_of(directory_len), u32_of(directory_at))
    };
    end.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    for field in [0u16, 0, classic_count, classic_count] {
        end.extend_from_slice(&field.to_le_bytes());
    }
    end.extend_from_slice(&classic_len.to_le_bytes());
    end.extend_from_slice(&classic_at.to_le_bytes());
    end.extend_from_slice(&u16_of(COMMENT.len()).to_le_bytes());
    end.extend_from_slice(COMMENT);
    out.put(&end)?;
    out.inner.flush()?;

    Ok(Written { members, directory_at, directory_len, len: out.at })
}
