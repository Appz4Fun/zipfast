//! Rebuilds the end of a RAR 5.0 volume byte for byte: the bytes after the last file's packed data.
//!
//! When the end of a volume is lost (its last articles, say) but its start survives, everything after the packed
//! data of the volume's last file is derivable from the volume's own headers and its length:
//!
//! * the quick open service header (`QO`), when the main header's locator says there is one. Its data caches an
//!   exact copy of every file header in the volume, each with its distance back from the service header;
//! * the end of archive header, whose one flag says whether more volumes follow;
//! * zero padding up to the volume's length (rar reserves room for the quick open data before it knows its size).
//!
//! [`rebuild_volume_tail`] produces those bytes as rar writes them and says whether the result is certain to match
//! the original ([`RebuiltTail::exact`]), so a caller claims a par2-clean volume only when it is.
//!
//! Written from the RAR 5.0 archive format description and checked against volume sets made by rar 7.30
//! (`-ma5 -m0 -v`, with and without `-qo`, with `-p`, several files per volume).

use super::Cursor;
use crate::error::{Error, Result};

const SIGNATURE: &[u8; 8] = b"Rar!\x1a\x07\x01\x00";
const HEAD_MAIN: u64 = 1;
const HEAD_FILE: u64 = 2;
const HEAD_SERVICE: u64 = 3;
const HEAD_CRYPT: u64 = 4;
const HEAD_ENDARC: u64 = 5;
/// Header flags: an extra area size follows, a data area size follows, the file continues from the previous
/// volume, the file continues in the next.
const FLAG_EXTRA: u64 = 0x1;
const FLAG_DATA: u64 = 0x2;
const FLAG_SPLIT_AFTER: u64 = 0x10;
/// Main header archive flags: a volume number follows, the archive has a recovery record.
const ARCHIVE_VOLUME_NUMBER: u64 = 0x2;
const ARCHIVE_RECOVERY: u64 = 0x8;
/// Main header extra record: the locator, and its flags.
const EXTRA_LOCATOR: u64 = 1;
const LOCATOR_QUICK_OPEN: u64 = 0x1;
const LOCATOR_RECOVERY: u64 = 0x2;

/// The rebuilt end of a volume.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RebuiltTail {
    /// Offset in the volume where [`Self::bytes`] start: the end of the last file's packed data.
    pub offset: u64,
    /// The volume's bytes from `offset` to its length.
    pub bytes: Vec<u8>,
    /// Whether the bytes are certain to be the ones rar wrote. When `false`, [`Self::doubt`] says why.
    pub exact: bool,
    pub doubt: Option<TailDoubt>,
}

/// Why a rebuilt tail might differ from the original.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TailDoubt {
    /// The last file ends in this volume and the caller did not say whether more volumes follow: the end of archive
    /// header's "more volumes" flag was inferred as clear.
    MoreVolumesInferred,
    /// The locator puts the quick open header somewhere other than right after the last file's data: something the
    /// surviving bytes do not show lies in between.
    QuickOpenElsewhere,
    /// There is no quick open header and the tail does not end exactly at the volume's length: padding or headers
    /// not shown by the surviving bytes.
    UnexpectedPadding,
    /// The quick open data is too large for the field widths seen in rar's output.
    LargeQuickOpen,
    /// Bytes the caller supplied past [`RebuiltTail::offset`] differ from the rebuilt ones.
    DiffersFromSupplied,
}

/// A file header found in the surviving bytes: where it starts and its bytes.
struct FileHead<'a> {
    at: usize,
    bytes: &'a [u8],
    host_os: u64,
    split_after: bool,
}

/// Rebuilds the bytes of a RAR 5.0 volume after its last file's packed data.
///
/// `head` is the surviving start of the volume: at least through the last file header in it (the packed data need
/// not be there). Bytes beyond the end of that file's data, if any, are compared with the rebuilt ones.
/// `volume_len` is the volume's full length (from the NZB or the par2 set). `more_volumes` says whether volumes
/// follow this one; `None` infers it from the last file header (a file that continues means more volumes).
///
/// Fails with [`Error::NotAnArchive`] for anything but a RAR 5.0 volume starting at offset 0,
/// [`Error::Truncated`] when `head` ends before a file header does, and [`Error::Unsupported`] for encrypted headers
/// (each header starts with a random IV, so no rebuild can match) or a recovery record (its data covers the whole
/// volume).
pub fn rebuild_volume_tail(head: &[u8], volume_len: u64, more_volumes: Option<bool>) -> Result<RebuiltTail> {
    if head.len() < SIGNATURE.len() || &head[..SIGNATURE.len()] != SIGNATURE {
        return Err(Error::NotAnArchive);
    }
    let main_at = SIGNATURE.len();
    let mut pos = main_at;
    let mut quick_open: Option<u64> = None;
    let mut saw_main = false;
    let mut files: Vec<FileHead<'_>> = Vec::new();
    // Where the volume's tail starts: after the last file's data, or at a service or end header seen in `head`.
    let tail_at = loop {
        // After a file, a header that fails to parse is where the damage starts: the tail is rebuilt from there and
        // the supplied bytes past it are compared (and differ).
        let parsed = match block(head, pos) {
            Err(_) if !files.is_empty() => break pos,
            parsed => parsed?,
        };
        let Some((kind, flags, data_size, body, end)) = parsed else {
            // The surviving bytes stop inside the next header (or its CRC): the tail starts here, if a file came.
            if files.is_empty() {
                return Err(Error::Truncated);
            }
            break pos;
        };
        match kind {
            HEAD_MAIN if !saw_main && pos == main_at => {
                saw_main = true;
                let (archive_flags, locator) = main_header(flags, body)?;
                if archive_flags & ARCHIVE_RECOVERY != 0 || locator.is_some_and(|(f, _)| f & LOCATOR_RECOVERY != 0) {
                    return Err(Error::Unsupported("a RAR 5.0 recovery record cannot be rebuilt".into()));
                }
                quick_open = locator.and_then(|(_, offset)| offset);
            }
            HEAD_CRYPT => return Err(Error::Unsupported("encrypted RAR 5.0 headers cannot be rebuilt exactly".into())),
            HEAD_FILE if saw_main => {
                let (host_os, split_after) = file_header(flags, body)?;
                files.push(FileHead { at: pos, bytes: &head[pos..end], host_os, split_after });
            }
            HEAD_SERVICE | HEAD_ENDARC if !files.is_empty() => break pos,
            _ => return Err(Error::Unsupported(format!("RAR 5.0 header type {kind} before the volume's tail"))),
        }
        pos = end
            .checked_add(usize::try_from(data_size).map_err(|_| Error::Corrupt("data size"))?)
            .ok_or(Error::Corrupt("data size"))?;
        if pos >= head.len() {
            if files.is_empty() {
                return Err(Error::Truncated);
            }
            break pos;
        }
    };
    let last = files.last().expect("a file header was found");
    let mut doubt = None;
    let more = match more_volumes {
        Some(more) => more,
        None if last.split_after => true,
        None => {
            doubt = Some(TailDoubt::MoreVolumesInferred);
            false
        }
    };
    let mut bytes = Vec::new();
    if let Some(offset) = quick_open {
        let qo_at = (main_at as u64).checked_add(offset).ok_or(Error::Corrupt("quick open offset"))?;
        if qo_at != tail_at as u64 {
            doubt = doubt.or(Some(TailDoubt::QuickOpenElsewhere));
        }
        let (header, large) = quick_open_header(&files, tail_at)?;
        if large {
            doubt = doubt.or(Some(TailDoubt::LargeQuickOpen));
        }
        bytes.extend(header);
    }
    bytes.extend(end_of_archive(more));
    let used = (tail_at as u64).checked_add(bytes.len() as u64).ok_or(Error::Corrupt("volume length"))?;
    let Some(padding) = volume_len.checked_sub(used) else {
        return Err(Error::Corrupt("the volume is shorter than its headers"));
    };
    if quick_open.is_none() && padding != 0 {
        doubt = doubt.or(Some(TailDoubt::UnexpectedPadding));
    }
    bytes.resize(bytes.len() + usize::try_from(padding).map_err(|_| Error::Corrupt("volume length"))?, 0);
    if head.len() > tail_at {
        let supplied = &head[tail_at..];
        if supplied.len() > bytes.len() || supplied != &bytes[..supplied.len()] {
            doubt = doubt.or(Some(TailDoubt::DiffersFromSupplied));
        }
    }
    Ok(RebuiltTail { offset: tail_at as u64, bytes, exact: doubt.is_none(), doubt })
}

/// The block at `pos`: (type, header flags, data size, the header's fields after the size, offset after the
/// header). `None` when `head` ends inside it. A header whose CRC fails is corruption.
#[allow(clippy::type_complexity)]
fn block(head: &[u8], pos: usize) -> Result<Option<(u64, u64, u64, &[u8], usize)>> {
    if head.len().saturating_sub(pos) < 5 {
        return Ok(None);
    }
    let mut size_cursor = Cursor::new(&head[pos + 4..]);
    let Ok(size) = size_cursor.vsize() else { return Ok(None) };
    let start = pos + 4 + size_cursor.pos();
    let Some(end) = start.checked_add(size).filter(|&end| end <= head.len()) else { return Ok(None) };
    let crc = u32::from_le_bytes(head[pos..pos + 4].try_into().unwrap());
    if crate::crc32::hash(&head[pos + 4..end]) != crc {
        return Err(Error::Corrupt("RAR 5.0 header checksum"));
    }
    let mut c = Cursor::new(&head[start..end]);
    let kind = c.vint()?;
    let flags = c.vint()?;
    let extra = if flags & FLAG_EXTRA != 0 { c.vint()? } else { 0 };
    let data = if flags & FLAG_DATA != 0 { c.vint()? } else { 0 };
    let body = &head[start + c.pos()..end];
    if extra > body.len() as u64 {
        return Err(Error::Corrupt("RAR 5.0 extra area size"));
    }
    Ok(Some((kind, flags, data, body, end)))
}

/// Archive flags and the locator record (its flags and quick open offset) of a main header's fields.
/// A main header's locator record: its flags and the quick open header's offset from the main header.
type Locator = (u64, Option<u64>);

fn main_header(flags: u64, body: &[u8]) -> Result<(u64, Option<Locator>)> {
    let mut c = Cursor::new(body);
    let archive_flags = c.vint()?;
    if archive_flags & ARCHIVE_VOLUME_NUMBER != 0 {
        c.vint()?;
    }
    let mut locator = None;
    if flags & FLAG_EXTRA != 0 {
        while c.remaining() > 0 {
            let size = c.vsize()?;
            let record = c.bytes(size)?;
            let mut r = Cursor::new(record);
            if r.vint()? == EXTRA_LOCATOR {
                let locator_flags = r.vint()?;
                let quick_open = if locator_flags & LOCATOR_QUICK_OPEN != 0 { Some(r.vint()?) } else { None };
                locator = Some((locator_flags, quick_open));
            }
        }
    }
    Ok((archive_flags, locator))
}

/// Host OS and whether the file continues in the next volume, from a file header's fields.
fn file_header(flags: u64, body: &[u8]) -> Result<(u64, bool)> {
    let mut c = Cursor::new(body);
    let file_flags = c.vint()?;
    c.vint()?; // unpacked size
    c.vint()?; // attributes
    if file_flags & 0x2 != 0 {
        c.u32()?; // mtime
    }
    if file_flags & 0x4 != 0 {
        c.u32()?; // data CRC32
    }
    c.vint()?; // compression information
    let host_os = c.vint()?;
    Ok((host_os, flags & FLAG_SPLIT_AFTER != 0))
}

/// `value` as a RAR vint, written in at least `min` bytes (rar pads some fields with continuation bytes).
fn vint(out: &mut Vec<u8>, mut value: u64, min: usize) {
    let mut written = 0;
    loop {
        let low = (value & 0x7f) as u8;
        value >>= 7;
        written += 1;
        if value == 0 && written >= min {
            out.push(low);
            return;
        }
        out.push(low | 0x80);
    }
}

/// A header block: CRC32, size, then `fields`.
fn header(fields: &[u8]) -> Vec<u8> {
    let mut sized = Vec::with_capacity(fields.len() + 6);
    vint(&mut sized, fields.len() as u64, 1);
    sized.extend_from_slice(fields);
    let mut out = crate::crc32::hash(&sized).to_le_bytes().to_vec();
    out.extend(sized);
    out
}

/// The quick open service header at `at` with its data, caching each of `files`; and whether its data is larger
/// than the two-byte size fields seen in rar's output.
fn quick_open_header(files: &[FileHead<'_>], at: usize) -> Result<(Vec<u8>, bool)> {
    let mut data = Vec::new();
    for file in files {
        let mut record = Vec::new();
        vint(&mut record, 0, 1); // flags
        vint(&mut record, (at - file.at) as u64, 1); // distance back to the cached header
        vint(&mut record, file.bytes.len() as u64, 1);
        record.extend_from_slice(file.bytes);
        let mut sized = Vec::new();
        vint(&mut sized, record.len() as u64, 1);
        sized.extend(record);
        data.extend(crate::crc32::hash(&sized).to_le_bytes());
        data.extend(sized);
    }
    let large = data.len() >= 1 << 14;
    let host_os = files.last().map_or(0, |f| f.host_os);
    let mut fields = Vec::new();
    vint(&mut fields, HEAD_SERVICE, 1);
    vint(&mut fields, FLAG_DATA | 0x4, 1); // data area, skip if unknown
    vint(&mut fields, data.len() as u64, 2);
    vint(&mut fields, 0, 1); // file flags
    vint(&mut fields, data.len() as u64, 2); // unpacked size
    vint(&mut fields, 0, 1); // attributes
    vint(&mut fields, 0, 2); // compression information: stored
    vint(&mut fields, host_os, 1);
    vint(&mut fields, 2, 1);
    fields.extend_from_slice(b"QO");
    let mut out = header(&fields);
    out.extend(data);
    Ok((out, large))
}

/// The end of archive header, with "more volumes" set when `more`.
fn end_of_archive(more: bool) -> Vec<u8> {
    let mut fields = Vec::new();
    vint(&mut fields, HEAD_ENDARC, 1);
    vint(&mut fields, 0x4, 1); // skip if unknown
    vint(&mut fields, u64::from(more), 1);
    header(&fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vints_pad_to_the_minimum_width_with_continuation_bytes() {
        let mut out = Vec::new();
        vint(&mut out, 60, 2);
        assert_eq!(out, [0xbc, 0x00]);
        out.clear();
        vint(&mut out, 0, 2);
        assert_eq!(out, [0x80, 0x00]);
        out.clear();
        vint(&mut out, 102_221, 1);
        assert_eq!(out, [0xcd, 0x9e, 0x06]);
    }

    #[test]
    fn the_end_of_archive_header_matches_rar() {
        // From a rar 7.30 middle volume (`03 05 04 01`, more volumes) with its CRC.
        assert_eq!(end_of_archive(true), [0x8b, 0x47, 0x51, 0x26, 0x03, 0x05, 0x04, 0x01]);
    }
}
