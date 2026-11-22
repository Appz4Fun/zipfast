//! Rebuilds the end of a RAR 5.0 volume byte for byte: the bytes after the last file's packed data.
//!
//! When the end of a volume is lost (its last articles, say) but its start survives, everything after the packed
//! data of the volume's last file is derivable from the volume's own headers and its length:
//!
//! * the quick open service header (`QO`), when the main header's locator says there is one. Its data caches an
//!   exact copy of file headers in the volume, each with its distance back from the service header: with `-qo+`
//!   every one ([`QuickOpenMode::All`]), and by default only those whose packed data in the volume is more than
//!   4096 bytes ([`QuickOpenMode::LargeFiles`]); with none to cache there is no service header;
//! * the end of archive header, whose one flag says whether more volumes follow;
//! * zero padding up to the volume's length (rar reserves room for the quick open data before it knows its size),
//!   returned as a count.
//!
//! [`rebuild_volume_tail`] produces those bytes as rar writes them and says whether the result is certain to match
//! the original ([`RebuiltTail::exact`]), so a caller claims a par2-clean volume only when it is.
//!
//! Written from the RAR 5.0 archive format description and checked against volume sets made by rar 7.30
//! (`-ma5 -m0 -v`; quick open off, on and default; `-p`; several files per volume, small and large pieces).

use super::Cursor;
use super::frame::{end_of_archive, put_vint_min as vint, seal_header as header};
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
/// The most zero padding a rebuilt middle volume may end with and still be called exact, beyond the room of
/// headers the quick open data skips.
const MAX_PADDING: u64 = 64;
/// rar's default quick open mode caches a file header only when the file has more than this much packed data in
/// the volume (rar 7.30: 4096 skipped, 4097 cached).
const SMALL_PIECE: u64 = 4096;

/// Which file headers rar caches in a volume's quick open data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuickOpenMode {
    /// Every file header (`-qo+`).
    All,
    /// Only files with more than 4096 bytes of packed data in the volume (rar's default `-qo`).
    LargeFiles,
}

/// The rebuilt end of a volume.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RebuiltTail {
    /// Offset in the volume where [`Self::bytes`] start: the end of the last file's packed data.
    pub offset: u64,
    /// The volume's headers from `offset`: the quick open data, if any, and the end of archive header.
    pub bytes: Vec<u8>,
    /// Zero bytes that follow `bytes` up to the volume's length (rar reserves room for the quick open data before
    /// it knows its size). Not held in memory: write this many zeros after `bytes`.
    pub padding: u64,
    /// Whether `bytes` and `padding` are certain to be what rar wrote. When `false`, [`Self::doubt`] says why.
    pub exact: bool,
    /// Why the result might differ from the original, when it is not [`Self::exact`].
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
    /// The padding is not what rar usually leaves: any after the last volume's end header, or after a middle
    /// volume's more than 64 bytes (plus the room reserved for a skipped last header). So the volume's length is
    /// wrong, it holds headers the surviving bytes do not show, or rar reserved unusually much (it does with `-qo+`
    /// and many small files, about 6 bytes per cached header): a doubt, not a certain mismatch.
    UnexpectedPadding,
    /// The caller said no volumes follow, but the volume's last file continues in the next one.
    MoreVolumesContradicted,
    /// More volumes follow, but the last file the surviving bytes show ends in this volume rather than continuing:
    /// a further file header may have been lost with the tail (rar normally fills a middle volume with a file that
    /// continues). Supply the volume's bytes past that file's data to check.
    LastFileEnds,
    /// The quick open data is too large for the field widths seen in rar's output.
    LargeQuickOpen,
    /// The volume has files with 4096 bytes of packed data or less, which only `-qo+` caches, and the set's quick
    /// open mode is not known: the bytes assume rar's default. Pass the mode (see [`quick_open_mode`]) to be sure.
    QuickOpenMode,
    /// Bytes the caller supplied past [`RebuiltTail::offset`] differ from the rebuilt ones.
    DiffersFromSupplied,
}

/// A file header found in the surviving bytes: where it starts and its bytes.
struct FileHead<'a> {
    at: usize,
    bytes: &'a [u8],
    host_os: u64,
    split_after: bool,
    /// Packed data of the file in this volume.
    data: u64,
}

impl FileHead<'_> {
    fn cached(&self, mode: QuickOpenMode) -> bool {
        mode == QuickOpenMode::All || self.data > SMALL_PIECE
    }
}

/// Rebuilds the bytes of a RAR 5.0 volume after its last file's packed data.
///
/// `head` is the surviving start of the volume: at least through the last file header in it (the packed data need
/// not be there). Bytes beyond the end of that file's data, if any, are compared with the rebuilt ones.
/// `volume_len` is the volume's exact length in bytes: from the par2 file description or the yEnc `=ybegin size=`,
/// not from the NZB, whose segment sizes count encoded articles. `more_volumes` says whether volumes follow this one;
/// `None` infers it from the last file header (a file that continues means more volumes).
///
/// Fails with [`Error::NotAnArchive`] for anything but a RAR 5.0 volume starting at offset 0,
/// [`Error::Truncated`] when `head` ends before a file header does, and [`Error::Unsupported`] for encrypted headers
/// (each header starts with a random IV, so no rebuild can match) or a recovery record (its data covers the whole
/// volume).
///
/// When the volume holds a file with 4096 bytes of packed data or less, the bytes depend on the set's quick open mode,
/// which the volume's start does not show: see [`rebuild_volume_tail_with`].
pub fn rebuild_volume_tail(head: &[u8], volume_len: u64, more_volumes: Option<bool>) -> Result<RebuiltTail> {
    rebuild_volume_tail_with(head, volume_len, more_volumes, None)
}

/// [`rebuild_volume_tail`] with the set's quick open mode, when known (from an intact volume of the same set, with
/// [`quick_open_mode`]). A supplied mode is trusted: the volume's length cannot always tell a wrong one. With `None`, a volume holding small files is rebuilt in the one mode that fits its length,
/// or, if both fit, in rar's default mode with [`TailDoubt::QuickOpenMode`].
pub fn rebuild_volume_tail_with(
    head: &[u8],
    volume_len: u64,
    more_volumes: Option<bool>,
    mode: Option<QuickOpenMode>,
) -> Result<RebuiltTail> {
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
                files.push(FileHead { at: pos, bytes: &head[pos..end], host_os, split_after, data: data_size });
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
        Some(false) if last.split_after => {
            doubt = Some(TailDoubt::MoreVolumesContradicted);
            false
        }
        Some(more) => more,
        None if last.split_after => true,
        None => {
            doubt = Some(TailDoubt::MoreVolumesInferred);
            false
        }
    };
    // The headers in each quick open mode, and the room a skipped header leaves as padding.
    let build = |mode: QuickOpenMode| -> Result<(Vec<u8>, u64, bool)> {
        let mut bytes = Vec::new();
        let mut large = false;
        let mut skipped = 0;
        if quick_open.is_some() {
            let cached: Vec<&FileHead<'_>> = files.iter().filter(|f| f.cached(mode)).collect();
            // rar reserves room for the volume's last header when it starts the file; skipped, that room is padding.
            // (Earlier skipped headers leave nothing: rar's padding does not grow with them.)
            let last = files.last().expect("a file header was found");
            if !last.cached(mode) {
                skipped = record(last, tail_at).len() as u64 + 32;
            }
            // With nothing to cache rar writes no service header (and a zero locator offset).
            if !cached.is_empty() {
                let (header, too_large) = quick_open_header(&cached, files.last().map_or(0, |f| f.host_os), tail_at);
                large = too_large;
                bytes.extend(header);
            }
        }
        bytes.extend(end_of_archive(more));
        Ok((bytes, skipped, large))
    };
    let fits = |bytes: &[u8]| (tail_at as u64).checked_add(bytes.len() as u64).is_some_and(|end| end <= volume_len);
    let small = quick_open.is_some() && files.iter().any(|f| f.data <= SMALL_PIECE);
    let (bytes, skipped, large) = match mode {
        Some(mode) => build(mode)?,
        None if !small => build(QuickOpenMode::All)?,
        None => {
            let all = build(QuickOpenMode::All)?;
            let default = build(QuickOpenMode::LargeFiles)?;
            let none_cached = quick_open == Some(0);
            if none_cached || (fits(&default.0) && !fits(&all.0)) {
                default
            } else if fits(&all.0) && !fits(&default.0) {
                all
            } else {
                doubt = doubt.or(Some(TailDoubt::QuickOpenMode));
                default
            }
        }
    };
    if large {
        doubt = doubt.or(Some(TailDoubt::LargeQuickOpen));
    }
    if let Some(offset) = quick_open {
        // The locator names the service header's offset from the main header, or 0 when there is none.
        let expected = if bytes.len() > 8 { (tail_at - main_at) as u64 } else { 0 };
        if offset != expected {
            doubt = doubt.or(Some(TailDoubt::QuickOpenElsewhere));
        }
    }
    let used = (tail_at as u64).checked_add(bytes.len() as u64).ok_or(Error::Corrupt("volume length"))?;
    let Some(padding) = volume_len.checked_sub(used) else {
        return Err(Error::Corrupt("the volume is shorter than its headers"));
    };
    // rar ends the last volume right after its end of archive header. A middle volume ends with what rar reserved
    // and did not use: the room of skipped headers and a few bytes more (with no quick open data at all, rar can
    // still leave some), so more than that means the length is wrong or headers are missing.
    if padding != 0 && !more || padding > MAX_PADDING.saturating_add(skipped) {
        doubt = doubt.or(Some(TailDoubt::UnexpectedPadding));
    }
    // A middle volume whose last surviving file ends in it may have lost a later header: only supplied bytes past
    // that file covering a whole header (its CRC and size, compared below) rule that out.
    if more && !last.split_after && head.len().saturating_sub(tail_at) < bytes.len().min(8) {
        doubt = doubt.or(Some(TailDoubt::LastFileEnds));
    }
    if head.len() > tail_at {
        let supplied = &head[tail_at..];
        let (headers, zeros) = supplied.split_at(supplied.len().min(bytes.len()));
        if headers != &bytes[..headers.len()] || zeros.len() as u64 > padding || zeros.iter().any(|&b| b != 0) {
            doubt = doubt.or(Some(TailDoubt::DiffersFromSupplied));
        }
    }
    Ok(RebuiltTail { offset: tail_at as u64, bytes, padding, exact: doubt.is_none(), doubt })
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

/// A main header's locator record: its flags and the quick open header's offset from the main header.
type Locator = (u64, Option<u64>);

/// Archive flags and the locator record of a main header's fields.
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

/// One quick open record caching `file`, for a service header at `at`: CRC32, size, flags, distance back, header
/// size, the header's bytes.
fn record(file: &FileHead<'_>, at: usize) -> Vec<u8> {
    let mut body = Vec::new();
    vint(&mut body, 0, 1); // flags
    vint(&mut body, (at - file.at) as u64, 1); // distance back to the cached header
    vint(&mut body, file.bytes.len() as u64, 1);
    body.extend_from_slice(file.bytes);
    let mut sized = Vec::new();
    vint(&mut sized, body.len() as u64, 1);
    sized.extend(body);
    let mut out = crate::crc32::hash(&sized).to_le_bytes().to_vec();
    out.extend(sized);
    out
}

/// The quick open service header at `at` with its data, caching each of `files`; and whether its data is larger
/// than the two-byte size fields seen in rar's output.
fn quick_open_header(files: &[&FileHead<'_>], host_os: u64, at: usize) -> (Vec<u8>, bool) {
    let data: Vec<u8> = files.iter().flat_map(|f| record(f, at)).collect();
    let large = data.len() >= 1 << 14;
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
    (out, large)
}

/// The quick open mode of a set, from one of its intact volumes: `Some` when the volume holds a file with 4096 bytes
/// of packed data or less (rar's default skips its header, `-qo+` caches it), `None` when it shows nothing either way
/// (no small file, no quick open data, or a volume this cannot read).
pub fn quick_open_mode(volume: &[u8]) -> Option<QuickOpenMode> {
    if volume.len() < SIGNATURE.len() || &volume[..SIGNATURE.len()] != SIGNATURE {
        return None;
    }
    let mut pos = SIGNATURE.len();
    let mut small = Vec::new();
    let mut has_quick_open = false;
    loop {
        let (kind, _flags, data_size, body, end) = block(volume, pos).ok()??;
        match kind {
            HEAD_MAIN => has_quick_open = main_header(_flags, body).ok()?.1.is_some_and(|(_, o)| o.is_some()),
            HEAD_FILE if data_size <= SMALL_PIECE => small.push(pos),
            HEAD_FILE => {}
            HEAD_SERVICE if has_quick_open && body.ends_with(b"\x02QO") => {
                // The quick open data: does any record cache a small file's header?
                let data = volume.get(end..end.checked_add(usize::try_from(data_size).ok()?)?)?;
                let mut cached = Vec::new();
                let mut c = Cursor::new(data);
                while c.remaining() > 0 {
                    c.u32().ok()?;
                    let size = c.vsize().ok()?;
                    let mut r = Cursor::new(c.bytes(size).ok()?);
                    r.vint().ok()?;
                    let back = usize::try_from(r.vint().ok()?).ok()?;
                    cached.push(pos.checked_sub(back)?);
                }
                if small.is_empty() {
                    return None;
                }
                let all = small.iter().all(|at| cached.contains(at));
                let none = small.iter().all(|at| !cached.contains(at));
                return match (all, none) {
                    (true, false) => Some(QuickOpenMode::All),
                    (false, true) => Some(QuickOpenMode::LargeFiles),
                    _ => None,
                };
            }
            // No service header before the end: small files exist and nothing cached them (default mode), or
            // there is no quick open data.
            HEAD_ENDARC => return (has_quick_open && !small.is_empty()).then_some(QuickOpenMode::LargeFiles),
            _ => return None,
        }
        pos = end.checked_add(usize::try_from(data_size).ok()?)?;
    }
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
