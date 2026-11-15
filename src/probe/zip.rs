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

//! ZIP for the probe: local headers walked from the head, the central directory read from the tail.

use super::{Candidate, CipherKind};
use crate::map::{CipherParams, MapError, MapMethod, OutputMapping};
use crate::progressive::{FailureKind, ProgressiveFailure, ProgressiveLimits};
use std::ops::Range;
use zip_container::{LOCAL_HEADER_LEN, LocalHeader};

const FLAG_ENCRYPTED: u16 = 0x0001;
const FLAG_DESCRIPTOR: u16 = 0x0008;
const FLAG_STRONG: u16 = 0x0040;
const FLAG_UTF8: u16 = 0x0800;
const METHOD_AES: u16 = 99;
const LOCAL_SIG: &[u8; 4] = b"PK\x03\x04";
const CENTRAL_SIG: &[u8; 4] = b"PK\x01\x02";
const END_SIG: &[u8; 4] = b"PK\x05\x06";
const SPAN_SIG: &[u8; 4] = b"PK\x07\x08";
/// The most unknown bytes before the tail a directory read may cover (they read as zeros).
const MAX_UNKNOWN: u64 = 128 << 10;

/// Whether `head` starts like a ZIP archive: a local header, an empty archive's end record, or a spanned archive's
/// marker before a local header.
pub(super) fn starts_zip(head: &[u8]) -> bool {
    head.starts_with(LOCAL_SIG)
        || head.starts_with(END_SIG)
        || (head.starts_with(SPAN_SIG) && head.get(4..8) == Some(LOCAL_SIG.as_slice()))
}

pub(super) struct Listing {
    pub(super) candidates: Vec<Candidate>,
    /// The central directory was read from the tail.
    pub(super) directory: bool,
    /// Every member is listed: the central directory was read, or the head reached it.
    pub(super) complete: bool,
    pub(super) spanned: bool,
}

fn malformed(reason: &'static str) -> MapError {
    MapError::Malformed { volume: 0, failure: Box::new(ProgressiveFailure::new(FailureKind::Malformed(reason))) }
}

/// What one entry's fields say, from the central directory or a local header.
struct Fields<'a> {
    raw_name: &'a [u8],
    name: Option<String>,
    flags: u16,
    method: u16,
    aes_info: Option<(u8, u16, u16)>,
    crc32: u32,
    size: Option<u64>,
    packed: Option<u64>,
    is_dir: bool,
}

/// Local header facts found in the head at `at`: (header range, data start, DOS time).
fn local_at(head: &[u8], at: u64) -> Option<(Range<u64>, u64, u16, LocalHeader)> {
    let start = usize::try_from(at).ok()?;
    let header = LocalHeader::parse(head.get(start..)?).ok()?;
    let data = at + LOCAL_HEADER_LEN as u64 + u64::from(header.name_len) + u64::from(header.extra_len);
    Some((at..data, data, header.mod_time, header))
}

/// Builds the probe's view of one entry, as the member map decides cipher and mapping (`src/map/zip.rs`).
fn candidate(head: &[u8], fields: Fields<'_>, local: Option<(Range<u64>, u64, u16)>) -> Candidate {
    let is_aes = fields.method == METHOD_AES || fields.aes_info.is_some();
    let encrypted = fields.flags & FLAG_ENCRYPTED != 0 || is_aes;
    let method =
        if fields.method == METHOD_AES { fields.aes_info.map_or(fields.method, |a| a.2) } else { fields.method };
    let stored = method == 0;
    let (header, data_start, mod_time) = match local {
        Some((header, data, time)) => (Some(header), Some(data), Some(time)),
        None => (None, None, None),
    };
    let (cipher_kind, cipher, mapping) = if !encrypted {
        (None, None, if stored { OutputMapping::Direct } else { OutputMapping::None })
    } else if fields.flags & FLAG_STRONG != 0 {
        (Some(CipherKind::Unknown), None, OutputMapping::None)
    } else if is_aes {
        match fields.aes_info {
            Some((strength, vendor_version, _)) => {
                let prefix = 4 + 4 * usize::from(strength) + 2;
                let salt = data_start.and_then(|at| {
                    let at = usize::try_from(at).ok()?;
                    let bytes = head.get(at..at + prefix)?;
                    fields.packed.is_none_or(|p| p >= prefix as u64).then_some(bytes)
                });
                let cipher = salt.map(|bytes| CipherParams::WinZipAes {
                    strength,
                    vendor_version,
                    salt: bytes[..prefix - 2].to_vec(),
                    verifier: [bytes[prefix - 2], bytes[prefix - 1]],
                });
                let mapping = if stored { OutputMapping::Counter { skip: prefix as u64 } } else { OutputMapping::None };
                (Some(CipherKind::WinZipAes { strength }), cipher, mapping)
            }
            None => (Some(CipherKind::Unknown), None, OutputMapping::None),
        }
    } else {
        let check = match mod_time {
            Some(time) if fields.flags & FLAG_DESCRIPTOR != 0 => (time >> 8) as u8,
            _ => (fields.crc32 >> 24) as u8,
        };
        (
            Some(CipherKind::ZipCrypto),
            Some(CipherParams::ZipCrypto { check }),
            if stored { OutputMapping::Sequential { skip: 12 } } else { OutputMapping::None },
        )
    };
    Candidate {
        raw_name: fields.raw_name.to_vec(),
        name: fields.name,
        is_dir: fields.is_dir,
        size: fields.size,
        packed_size: fields.packed,
        header,
        data: data_start.map(|start| start..fields.packed.map_or(u64::MAX, |p| start.saturating_add(p))),
        continued: false,
        method: if stored { MapMethod::Stored } else { MapMethod::Compressed { id: method } },
        solid: false,
        encrypted,
        cipher_kind,
        cipher,
        mapping,
    }
}

pub(super) fn list(
    head: &[u8],
    tail: Option<&[u8]>,
    archive_len: Option<u64>,
    limits: &ProgressiveLimits,
) -> Result<Listing, MapError> {
    let spanned = head.starts_with(SPAN_SIG);
    if !spanned && let Some(entries) = tail.and_then(|tail| directory(tail, archive_len, limits)) {
        let candidates = entries
            .iter()
            .map(|entry| {
                // The local header must be in the head and agree on the name to be trusted for the data offset.
                let local = local_at(head, entry.local_at).filter(|(_, _, _, header)| {
                    let at = entry.local_at as usize + LOCAL_HEADER_LEN;
                    let raw = head.get(at..at + usize::from(header.name_len));
                    raw.is_none_or(|raw| decode(raw, header.flags).as_deref() == Some(entry.name.as_str()))
                });
                let fields = Fields {
                    raw_name: entry.name.as_bytes(),
                    name: Some(entry.name.clone()),
                    flags: entry.flags,
                    method: entry.method,
                    aes_info: entry.aes_info,
                    crc32: entry.crc32,
                    size: Some(entry.size),
                    packed: Some(entry.packed),
                    is_dir: entry.is_dir(),
                };
                candidate(head, fields, local.map(|(h, d, t, _)| (h, d, t)))
            })
            .collect();
        return Ok(Listing { candidates, directory: true, complete: true, spanned });
    }
    let (candidates, complete) = walk_locals(head, if spanned { 4 } else { 0 })?;
    Ok(Listing { candidates, directory: false, complete, spanned })
}

fn decode(raw: &[u8], flags: u16) -> Option<String> {
    crate::zip::decode_name(raw, flags & FLAG_UTF8 != 0).ok()
}

/// A local header's sizes: when either is 0xFFFFFFFF, both come from the ZIP64 extra field (a local header's
/// ZIP64 field always holds both, uncompressed first).
fn zip64_sizes(extra: &[u8], header: &LocalHeader) -> (Option<u64>, Option<u64>) {
    if header.unpacked_size != u32::MAX && header.packed_size != u32::MAX {
        return (Some(u64::from(header.unpacked_size)), Some(u64::from(header.packed_size)));
    }
    let (mut size, mut packed) = (None, None);
    let mut p = 0;
    while p + 4 <= extra.len() {
        let id = u16::from_le_bytes([extra[p], extra[p + 1]]);
        let len = usize::from(u16::from_le_bytes([extra[p + 2], extra[p + 3]]));
        let Some(body) = extra.get(p + 4..p + 4 + len) else { break };
        if id == 0x0001 {
            let mut fields = body.as_chunks::<8>().0.iter().map(|c| u64::from_le_bytes(*c));
            size = fields.next();
            packed = fields.next();
            break;
        }
        p += 4 + len;
    }
    (size, packed)
}

/// Walks local headers from `start` while they are in the head. Returns the entries and whether the central
/// directory (or the end record) was reached.
fn walk_locals(head: &[u8], start: usize) -> Result<(Vec<Candidate>, bool), MapError> {
    let mut out = Vec::new();
    let mut at = start;
    loop {
        let Some(sig) = head.get(at..at + 4) else { return Ok((out, false)) };
        if sig == CENTRAL_SIG || sig == END_SIG {
            return Ok((out, true));
        }
        if sig != LOCAL_SIG {
            if out.is_empty() && at == start {
                return Err(malformed("local header signature"));
            }
            // Not a header where one should be: stop listing.
            return Ok((out, false));
        }
        let Some(fixed) = head.get(at..at + LOCAL_HEADER_LEN) else { return Ok((out, false)) };
        let header = LocalHeader::parse(fixed).map_err(|_| malformed("local header"))?;
        let name_at = at + LOCAL_HEADER_LEN;
        let extra_at = name_at + usize::from(header.name_len);
        let data_at = extra_at + usize::from(header.extra_len);
        let (Some(raw_name), Some(extra)) = (head.get(name_at..extra_at), head.get(extra_at..data_at)) else {
            return Ok((out, false));
        };
        let descriptor = header.flags & FLAG_DESCRIPTOR != 0;
        let (mut size, mut packed) = zip64_sizes(extra, &header);
        if descriptor && header.packed_size == 0 {
            // Sizes follow the data in a descriptor (streamed writers): unknown from the head.
            (size, packed) = (None, None);
        }
        let name = decode(raw_name, header.flags);
        let fields = Fields {
            raw_name,
            is_dir: raw_name.ends_with(b"/"),
            name,
            flags: header.flags,
            method: header.method,
            aes_info: crate::crypto::aes_extra_info(extra),
            crc32: header.crc32,
            size,
            packed,
        };
        out.push(candidate(head, fields, Some((at as u64..data_at as u64, data_at as u64, header.mod_time))));
        let Some(next) = packed.and_then(|p| usize::try_from(p).ok()).and_then(|p| data_at.checked_add(p)) else {
            return Ok((out, false));
        };
        at = next;
        if descriptor {
            // CRC and sizes, with an optional signature; ZIP64 sizes are 8 bytes each.
            let wide = header.packed_size == u32::MAX || header.unpacked_size == u32::MAX;
            let body = if wide { 20 } else { 12 };
            at += body + if head.get(at..at + 4) == Some(SPAN_SIG.as_slice()) { 4 } else { 0 };
        }
    }
}

/// The archive length implied by the end records in `tail`, the archive's last bytes.
fn implied_len(tail: &[u8]) -> Option<u64> {
    let le16 = |at: usize| u16::from_le_bytes(tail[at..at + 2].try_into().unwrap());
    let le32 = |at: usize| u32::from_le_bytes(tail[at..at + 4].try_into().unwrap());
    let le64 = |at: usize| u64::from_le_bytes(tail[at..at + 8].try_into().unwrap());
    let end = (0..tail.len().saturating_sub(21))
        .rev()
        .find(|&at| tail[at..].starts_with(END_SIG) && usize::from(le16(at + 20)) == tail.len() - at - 22)?;
    let (entries, size, offset) = (le16(end + 10), le32(end + 12), le32(end + 16));
    let after = (tail.len() - end) as u64;
    if entries != u16::MAX && size != u32::MAX && offset != u32::MAX {
        return u64::from(offset).checked_add(u64::from(size))?.checked_add(after);
    }
    // ZIP64: the locator right before the end record names where the ZIP64 end record starts.
    let locator = end.checked_sub(20)?;
    if &tail[locator..locator + 4] != b"PK\x06\x07" {
        return None;
    }
    let record_at = le64(locator + 8);
    let record = (0..locator.saturating_sub(55)).rev().find(|&at| {
        tail[at..].starts_with(b"PK\x06\x06") && (at as u64).checked_add(12 + le64(at + 4)) == Some(locator as u64)
    })?;
    record_at.checked_add((tail.len() - record) as u64)
}

/// The central directory, when the tail holds all of it.
fn directory(tail: &[u8], archive_len: Option<u64>, limits: &ProgressiveLimits) -> Option<Vec<crate::zip::ZipEntry>> {
    let len = archive_len.or_else(|| implied_len(tail))?;
    let tail_start = len.checked_sub(tail.len() as u64)?;
    let limits = crate::map::zip::zip_limits(limits);
    let mut parser = crate::zip::projected_parser(len, limits).ok()?;
    let zeros = [0u8; 4096];
    while let Some(range) = parser.next_read().ok()? {
        // A read reaching into the tail may start before it (the end-record search window): the bytes before the
        // tail are not known and read as zeros, which no record matches. A read wholly before the tail means the
        // directory is not in it.
        if range.end <= tail_start || tail_start.saturating_sub(range.start) > MAX_UNKNOWN {
            return None;
        }
        let mut at = range.start;
        while at < range.end {
            if at < tail_start {
                let n = (tail_start - at).min(zeros.len() as u64) as usize;
                parser.supply(at, &zeros[..n]).ok()?;
                at += n as u64;
            } else {
                let from = (at - tail_start) as usize;
                let to = (range.end - tail_start) as usize;
                parser.supply(at, &tail[from..to]).ok()?;
                at = range.end;
            }
        }
    }
    let mut found = parser.finish().ok()?;
    crate::zip::relocate_projected(&mut found.entries, found.prefix_shift, len, None).ok()?;
    Some(found.entries)
}
