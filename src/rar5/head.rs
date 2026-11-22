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

//! Rebuilds the start of a RAR 5.0 volume from its end: the signature, the main header and the file headers, from
//! the quick open record rar keeps behind each volume's data.
//!
//! RAR 5.0 volumes made with quick open data (rar's default) end with a `QO` service header whose data caches an
//! exact copy of file headers in the volume, each with its distance back from the service header. With the main
//! header's few fields (the volume flags and number, and a locator naming where that service header is) the lost
//! first bytes of a volume, typically its first Usenet article, come back byte for byte from its last bytes.
//! [`rebuild_volume_head`] does that and says whether the result is certain ([`RebuiltHead::exact`]).

use super::frame::{self, MainHeader, read_block, read_vint};
use crate::error::{Error, Result};

/// How far before the end of the given bytes the end of archive header is looked for: rar pads a middle volume
/// with fewer zeros than this after it.
const END_SCAN: usize = 4096;
/// The longest end of archive and quick open service headers looked at: rar's are 4 and about 15 bytes. Bounding
/// them bounds the checksum work of the backward scans to a small multiple of the tail's length, whatever it holds.
const MAX_END_HEADER: u64 = 64;
const MAX_QUICK_OPEN_HEADER: u64 = 256;
/// Compression information bit of a file that continues the solid stream.
const SOLID_FILE: u64 = 0x40;

/// What [`rebuild_volume_head`] may use besides the volume's own last bytes.
#[derive(Clone, Copy, Debug, Default)]
pub struct HeadOptions<'a> {
    /// The volume's number in its set, 0-based (from its name: `name.part3.rar` is 2). A volume's start does not
    /// say it anywhere else. `None` infers 0 for a volume whose first cached file starts in it, with
    /// [`HeadDoubt::VolumeNumberInferred`], and refuses a volume that starts inside a file.
    pub volume: Option<u64>,
    /// The start of any intact volume of the same set, through at least its main header. Its archive flags (solid,
    /// locked), extra records and locator field width are the set's: with it the main header is certain. Without
    /// it they are inferred from the cached file headers, and the result always carries
    /// [`HeadDoubt::ArchiveFlagsInferred`]: a locked archive (`-k`) is not detectable that way.
    pub sibling: Option<&'a [u8]>,
}

/// A header copied in the quick open data, placed in its volume.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachedHeader {
    /// Where the header starts in the volume.
    pub offset: u64,
    /// The header block, CRC32 included, exactly as in the volume.
    pub bytes: Vec<u8>,
    /// The size of the data area that follows it in this volume.
    pub data_len: u64,
    /// The header type: 2 for a file, 3 for a service header.
    pub kind: u64,
    /// The header flags (0x8: the file continues from the previous volume, 0x10: in the next).
    pub flags: u64,
}

/// The rebuilt start of a volume.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RebuiltHead {
    /// The volume's bytes from offset 0: the signature, the main header and, when it follows the main header
    /// directly, the first file header. Its data starts at `bytes.len()` then.
    pub bytes: Vec<u8>,
    /// The main header alone, field by field (also in `bytes`, after the 8-byte signature).
    pub main: MainHeader,
    /// Every header the quick open data copies, in volume order. The first is in `bytes` when it directly follows
    /// the main header.
    pub headers: Vec<CachedHeader>,
    /// Where the quick open service header starts in the volume.
    pub quick_open_offset: u64,
    /// Whether the end of archive header says more volumes follow.
    pub more_volumes: bool,
    /// Whether `bytes` are certain to be what rar wrote. When `false`, [`Self::doubt`] says why.
    pub exact: bool,
    /// Why the result might differ from the original, when it is not [`Self::exact`].
    pub doubt: Option<HeadDoubt>,
}

/// Why a rebuilt head might differ from the original.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeadDoubt {
    /// [`HeadOptions::volume`] was not given: the volume was taken for the first.
    VolumeNumberInferred,
    /// [`HeadOptions::volume`] says 0, but the volume's first file continues from a previous volume.
    VolumeNumberContradicted,
    /// No sibling was given: the archive flags were inferred. The lock flag (`-k`) shows only in the main header, so
    /// this is said whenever there is no sibling; the archive is taken as unlocked, and as solid only when a cached
    /// file continues the solid stream.
    ArchiveFlagsInferred,
    /// Something the quick open data does not copy lies between headers it does: a file whose header rar's default
    /// quick open mode skips (4096 bytes of packed data or less), an archive comment or another service header. The
    /// headers listed are still exact, but `bytes` stop at the main header, whose locator field width was then
    /// taken from the sibling or guessed.
    UncachedHeaders,
    /// The main header as rebuilt does not end where the first cached header starts, and nothing can lie between:
    /// the archive's main header holds records the sibling (or the default layout) does not.
    MainHeaderSize,
}

/// Rebuilds the start of RAR 5.0 volume from `tail`, its last bytes: at least its quick open service header (with
/// data) and its end of archive header, plus any zero padding after it. `volume_len` is the volume's exact length,
/// from the par2 file description or the yEnc `=ybegin size=` (not from the NZB).
///
/// Fails with [`Error::NotAnArchive`] when `tail` does not end with a RAR 5.0 end of archive header (and zero
/// padding), [`Error::Unsupported`] when no quick open service header ends right before it (a volume made with
/// `-qo-`, a recovery record, `-hp` encrypted headers), [`Error::Corrupt`] when that header's records fail their
/// checks or place headers impossibly, and with [`Error::Unsupported`] when the volume starts inside a file and
/// [`HeadOptions::volume`] is not given.
pub fn rebuild_volume_head(tail: &[u8], volume_len: u64, options: &HeadOptions<'_>) -> Result<RebuiltHead> {
    let base = volume_len.checked_sub(tail.len() as u64).ok_or(Error::Corrupt("the tail is longer than the volume"))?;
    let (end_at, more_volumes) = end_header(tail).ok_or(Error::NotAnArchive)?;
    let (qo_at, data_at) = quick_open(tail, end_at)?;
    let qo_pos = base + qo_at as u64;
    let mut headers = cached_headers(&tail[data_at..end_at], qo_pos)?;
    headers.sort_by_key(|h| h.offset);
    let sig = frame::SIGNATURE.len() as u64;
    let mut at = sig + 3; // the smallest main header
    for h in &headers {
        if h.offset < at {
            return Err(Error::Corrupt("RAR 5.0 quick open records overlap"));
        }
        at = h
            .offset
            .checked_add(h.bytes.len() as u64)
            .and_then(|e| e.checked_add(h.data_len))
            .ok_or(Error::Corrupt("RAR 5.0 quick open record"))?;
    }
    if at > qo_pos {
        return Err(Error::Corrupt("RAR 5.0 quick open record places data past it"));
    }
    let first = headers.first().ok_or(Error::Corrupt("RAR 5.0 quick open data without records"))?;
    let mut doubt = None;
    let continues = first.flags & super::HFL_SPLIT_BEFORE != 0;
    let volume = match options.volume {
        Some(0) if continues => {
            doubt = Some(HeadDoubt::VolumeNumberContradicted);
            0
        }
        Some(v) => v,
        None if continues => {
            return Err(Error::Unsupported(
                "the volume starts inside a file: its number is needed (HeadOptions::volume)".into(),
            ));
        }
        None => {
            doubt = Some(HeadDoubt::VolumeNumberInferred);
            0
        }
    };
    let gaps = headers.windows(2).any(|w| w[0].offset + w[0].bytes.len() as u64 + w[0].data_len != w[1].offset)
        || at != qo_pos;
    let locator_offset = qo_pos - sig;
    let template = match options.sibling {
        Some(sibling) => Some(sibling_main(sibling)?),
        None => None,
    };
    let (mut main, width) = match &template {
        Some(t) => {
            let width = t.locator.and_then(|l| l.quick_open).map(|(_, w)| w).unwrap_or(frame::vint_len(locator_offset));
            (t.for_volume(volume), width)
        }
        None => {
            // The lock flag (`-k`) shows nowhere but in the main header, so without a sibling the archive flags are
            // never certain: solidity may show in the cached headers, the lock never does.
            let solid = solidity(&headers);
            doubt = doubt.or(Some(HeadDoubt::ArchiveFlagsInferred));
            let flags = super::MHFL_VOLUME | if solid == Some(true) { super::MHFL_SOLID } else { 0 };
            let main = MainHeader {
                header_flags: super::HFL_EXTRA | 0x4,
                archive_flags: flags,
                volume_number: (volume > 0).then_some(volume),
                locator: None,
                other_extra: Vec::new(),
            };
            // The width rar gave the locator's quick open offset: the one that ends the main header where the first
            // cached header starts, else rar's usual (two bytes more than the volume length takes).
            let fit = (1..=frame::MAX_VINT_LEN).filter(|&w| w >= frame::vint_len(locator_offset)).find(|&w| {
                let mut m = main.clone();
                m.locator = Some(frame::Locator { quick_open: Some((locator_offset, w)), recovery: None });
                sig + m.encode().len() as u64 == first.offset
            });
            let usual = (frame::vint_len(volume_len) + 2).clamp(frame::vint_len(locator_offset), frame::MAX_VINT_LEN);
            (main, fit.unwrap_or(usual))
        }
    };
    let recovery = main.locator.and_then(|l| l.recovery);
    if recovery.is_some() {
        return Err(Error::Unsupported("a RAR 5.0 recovery record cannot be rebuilt".into()));
    }
    main.locator = Some(frame::Locator { quick_open: Some((locator_offset, width)), recovery: None });
    let encoded = main.encode();
    let main_end = sig + encoded.len() as u64;
    let mut bytes = frame::SIGNATURE.to_vec();
    bytes.extend_from_slice(&encoded);
    if first.offset == main_end {
        bytes.extend_from_slice(&first.bytes);
        if gaps {
            doubt = doubt.or(Some(HeadDoubt::UncachedHeaders));
        }
    } else if first.offset > main_end {
        doubt = doubt.or(Some(HeadDoubt::UncachedHeaders));
    } else {
        doubt = doubt.or(Some(HeadDoubt::MainHeaderSize));
    }
    Ok(RebuiltHead { bytes, main, headers, quick_open_offset: qo_pos, more_volumes, exact: doubt.is_none(), doubt })
}

/// The end of archive header near the end of `tail`, followed only by zeros: its offset and whether it says more
/// volumes follow.
fn end_header(tail: &[u8]) -> Option<(usize, bool)> {
    let from = tail.len().saturating_sub(END_SCAN);
    let last_nonzero = tail.iter().rposition(|&b| b != 0)?;
    (from..=last_nonzero).rev().find_map(|at| {
        let b = small_block(tail, at, MAX_END_HEADER)?;
        if b.kind != super::HEAD_END || b.data_len != 0 || tail[b.header_end..].iter().any(|&c| c != 0) {
            return None;
        }
        let mut c = super::Cursor::new(&tail[b.fields.clone()]);
        let flags = c.vint().ok()?;
        Some((at, flags & super::EOAFL_MORE_VOLUMES != 0))
    })
}

/// The block at `at` when its header claims at most `max` bytes (only then is its checksum computed).
fn small_block(tail: &[u8], at: usize, max: u64) -> Option<frame::Block> {
    let (size, _) = read_vint(tail, at.checked_add(4)?)?;
    if size > max {
        return None;
    }
    #[cfg(test)]
    HASHED.with(|h| h.set(h.get() + size));
    read_block(tail, at).ok()?
}

#[cfg(test)]
thread_local! {
    /// Header bytes the scans checksummed, for the test bounding their work.
    static HASHED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// The quick open service header whose data ends where the end header starts: its offset and its data's.
fn quick_open(tail: &[u8], end_at: usize) -> Result<(usize, usize)> {
    for at in (0..end_at.saturating_sub(5)).rev() {
        // Cheap checks first: the size, type, flags and data size must put the data's end at the end header.
        let Some((size, size_len)) = read_vint(tail, at + 4) else { continue };
        let start = at + 4 + size_len;
        let Some(end) = usize::try_from(size).ok().and_then(|s| start.checked_add(s)).filter(|&e| e <= end_at) else {
            continue;
        };
        let Some((kind, n)) = read_vint(tail, start).filter(|_| start < end) else { continue };
        if kind != super::HEAD_SERVICE {
            continue;
        }
        let Some((flags, m)) = read_vint(tail, start + n) else { continue };
        if flags & super::HFL_DATA == 0 {
            continue;
        }
        let mut p = start + n + m;
        if flags & super::HFL_EXTRA != 0 {
            let Some((_, k)) = read_vint(tail, p) else { continue };
            p += k;
        }
        let Some((data, _)) = read_vint(tail, p) else { continue };
        if (end as u64).checked_add(data) != Some(end_at as u64) {
            continue;
        }
        if size > MAX_QUICK_OPEN_HEADER {
            continue;
        }
        let Some(b) = small_block(tail, at, MAX_QUICK_OPEN_HEADER) else { continue };
        return match service_name(&tail[b.fields.clone()]) {
            Some(b"QO") => Ok((at, b.header_end)),
            Some(b"RR") => Err(Error::Unsupported("a RAR 5.0 recovery record cannot be rebuilt".into())),
            _ => Err(Error::Unsupported("a RAR 5.0 service header other than quick open ends the volume".into())),
        };
    }
    Err(Error::Unsupported("no RAR 5.0 quick open data before the end of archive header".into()))
}

/// A service header's name, from its fields.
fn service_name(fields: &[u8]) -> Option<&[u8]> {
    let mut c = super::Cursor::new(fields);
    let file_flags = c.vint().ok()?;
    c.vint().ok()?; // unpacked size
    c.vint().ok()?; // attributes
    if file_flags & super::FHFL_UTIME != 0 {
        c.u32().ok()?;
    }
    if file_flags & super::FHFL_CRC32 != 0 {
        c.u32().ok()?;
    }
    c.vint().ok()?; // compression information
    c.vint().ok()?; // host OS
    let len = c.vsize().ok()?;
    c.bytes(len).ok()
}

/// The quick open records in `data`, each a header placed at its distance back from the service header at `qo_pos`.
fn cached_headers(data: &[u8], qo_pos: u64) -> Result<Vec<CachedHeader>> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < data.len() {
        let crc = u32::from_le_bytes(
            data.get(at..at + 4).ok_or(Error::Corrupt("RAR 5.0 quick open record"))?.try_into().unwrap(),
        );
        let (size, size_len) = read_vint(data, at + 4).ok_or(Error::Corrupt("RAR 5.0 quick open record"))?;
        let body_at = at + 4 + size_len;
        let end = usize::try_from(size)
            .ok()
            .and_then(|s| body_at.checked_add(s))
            .filter(|&e| e <= data.len())
            .ok_or(Error::Corrupt("RAR 5.0 quick open record"))?;
        if crate::crc32::hash(&data[at + 4..end]) != crc {
            return Err(Error::Corrupt("RAR 5.0 quick open record checksum"));
        }
        let body = &data[body_at..end];
        let (_flags, a) = read_vint(body, 0).ok_or(Error::Corrupt("RAR 5.0 quick open record"))?;
        let (back, b) = read_vint(body, a).ok_or(Error::Corrupt("RAR 5.0 quick open record"))?;
        let (len, c) = read_vint(body, a + b).ok_or(Error::Corrupt("RAR 5.0 quick open record"))?;
        let header = &body[a + b + c..];
        if header.len() as u64 != len {
            return Err(Error::Corrupt("RAR 5.0 quick open record size"));
        }
        let block = read_block(header, 0)?
            .filter(|blk| blk.header_end == header.len())
            .ok_or(Error::Corrupt("RAR 5.0 cached header"))?;
        if block.kind != super::HEAD_FILE && block.kind != super::HEAD_SERVICE {
            return Err(Error::Corrupt("RAR 5.0 quick open record caches no file header"));
        }
        let offset = qo_pos
            .checked_sub(back)
            .filter(|&o| o >= frame::SIGNATURE.len() as u64)
            .ok_or(Error::Corrupt("RAR 5.0 quick open record offset"))?;
        out.push(CachedHeader {
            offset,
            bytes: header.to_vec(),
            data_len: block.data_len,
            kind: block.kind,
            flags: block.flags,
        });
        at = end;
    }
    Ok(out)
}

/// Whether the archive is solid, as far as the cached file headers show: a file continuing the solid stream says
/// so; a file other than the first without that bit says it is not (the archive's first file never has it).
fn solidity(headers: &[CachedHeader]) -> Option<bool> {
    let mut not_solid = false;
    for (i, h) in headers.iter().enumerate().filter(|(_, h)| h.kind == super::HEAD_FILE) {
        let Ok(Some(b)) = read_block(&h.bytes, 0) else { continue };
        let Some(solid) = file_is_solid(&h.bytes[b.fields.clone()]) else { continue };
        if solid {
            return Some(true);
        }
        if i > 0 {
            not_solid = true;
        }
    }
    not_solid.then_some(false)
}

fn file_is_solid(fields: &[u8]) -> Option<bool> {
    let mut c = super::Cursor::new(fields);
    let file_flags = c.vint().ok()?;
    c.vint().ok()?; // unpacked size
    c.vint().ok()?; // attributes
    if file_flags & super::FHFL_UTIME != 0 {
        c.u32().ok()?;
    }
    if file_flags & super::FHFL_CRC32 != 0 {
        c.u32().ok()?;
    }
    Some(c.vint().ok()? & SOLID_FILE != 0)
}

/// The main header of a sibling volume, from its start.
fn sibling_main(sibling: &[u8]) -> Result<MainHeader> {
    let sig = frame::SIGNATURE.len();
    if sibling.len() < sig || &sibling[..sig] != frame::SIGNATURE {
        return Err(Error::NotAnArchive);
    }
    match read_block(sibling, sig)? {
        Some(b) if b.kind == super::HEAD_CRYPT => {
            Err(Error::Unsupported("encrypted RAR 5.0 headers cannot be rebuilt exactly".into()))
        }
        Some(_) => MainHeader::parse(&sibling[sig..]),
        None => Err(Error::Truncated),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tail with a sound end header and, before it, thousands of fake service headers each claiming a header that
    /// runs up to the end header: the scans checksum a bounded amount, not each overlapping suffix again.
    #[test]
    fn hostile_tails_cost_linear_checksum_work() {
        let mut tail = vec![0x11u8; 128 << 10];
        let end = frame::end_of_archive(true);
        let end_at = tail.len();
        // Every 16 bytes: CRC, size (a 3-byte vint), type 3, flags 2 (data area), data size, so that the header
        // and its data end exactly where the end header starts.
        for at in (0..end_at - 64).step_by(16) {
            let data = 1u64;
            let size = (end_at - (at + 4 + 3)) as u64 - data;
            let mut v = Vec::new();
            frame::put_vint_min(&mut v, size, 3);
            tail[at + 4..at + 7].copy_from_slice(&v);
            tail[at + 7..at + 10].copy_from_slice(&[3, 2, data as u8]);
        }
        tail.extend_from_slice(&end);
        HASHED.with(|h| h.set(0));
        let result = rebuild_volume_head(&tail, tail.len() as u64, &HeadOptions { volume: Some(1), sibling: None });
        assert!(matches!(result, Err(Error::Unsupported(_))), "{result:?}");
        let hashed = HASHED.with(|h| h.get());
        assert!(hashed <= 4 * tail.len() as u64, "{hashed} header bytes checksummed for a {}-byte tail", tail.len());
    }
}
