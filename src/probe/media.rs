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

//! Media container recognition from a file's first bytes and from its name.

/// A media container recognised by its magic or its file name.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum MediaKind {
    /// Matroska (EBML, DocType `matroska`).
    Mkv,
    /// WebM (EBML, DocType `webm`).
    Webm,
    /// ISO base media file format (`ftyp` with a brand other than `qt  `): mp4, m4v.
    Mp4,
    /// QuickTime (`ftyp` brand `qt  `, or a file starting with a `moov`, `mdat`, `wide`, `free`, `skip` or `pnot`
    /// atom).
    Mov,
    /// RIFF AVI.
    Avi,
    /// MPEG transport stream, 188-byte packets.
    MpegTs,
    /// Blu-ray BDAV transport stream: 192-byte packets, a 4-byte timestamp before each 0x47 sync byte.
    M2ts,
    /// Advanced Systems Format (wmv, wma, asf): the two cannot be told apart from the header GUID alone.
    Asf,
    /// MPEG program stream (mpg, mpeg, vob): a pack header `00 00 01 BA`.
    MpegPs,
}

/// How strongly the bytes support a [`MediaKind`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Confidence {
    /// The magic and the structure after it check out (see `docs/probe.md` for what each kind checks).
    Validated,
    /// The magic matches, but the bytes end before the structure could be checked, or a secondary check was
    /// inconclusive.
    Magic,
}

/// A recognised media container.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MediaMatch {
    pub kind: MediaKind,
    pub confidence: Confidence,
}

impl MediaMatch {
    fn new(kind: MediaKind, confidence: Confidence) -> Self {
        Self { kind, confidence }
    }
}

/// The media kind a file name's extension names, case-insensitively: `mkv`/`mk3d`, `webm`, `mp4`/`m4v`,
/// `mov`/`qt`, `avi`, `ts`/`trp`, `m2ts`/`mts`, `wmv`/`asf`, `mpg`/`mpeg`/`vob`/`m2p`.
pub fn media_kind_for_name(name: &str) -> Option<MediaKind> {
    let ext = extension(name)?;
    Some(match ext.as_str() {
        "mkv" | "mk3d" => MediaKind::Mkv,
        "webm" => MediaKind::Webm,
        "mp4" | "m4v" => MediaKind::Mp4,
        "mov" | "qt" => MediaKind::Mov,
        "avi" => MediaKind::Avi,
        "ts" | "trp" => MediaKind::MpegTs,
        "m2ts" | "mts" => MediaKind::M2ts,
        "wmv" | "asf" => MediaKind::Asf,
        "mpg" | "mpeg" | "vob" | "m2p" => MediaKind::MpegPs,
        _ => return None,
    })
}

/// Whether the name is a small side file of a release (nfo, sfv, txt, images, subtitles, par2, ...), never chosen
/// as the release's main file while a larger member exists.
pub(crate) fn is_side_file(name: &str) -> bool {
    extension(name).is_some_and(|ext| {
        matches!(
            ext.as_str(),
            "nfo"
                | "sfv"
                | "txt"
                | "jpg"
                | "jpeg"
                | "png"
                | "gif"
                | "bmp"
                | "srr"
                | "srs"
                | "nzb"
                | "par2"
                | "md5"
                | "sha1"
                | "sha256"
                | "url"
                | "diz"
                | "log"
                | "cue"
                | "srt"
                | "sub"
                | "idx"
                | "ass"
                | "ssa"
                | "htm"
                | "html"
        )
    })
}

fn extension(name: &str) -> Option<String> {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let (stem, ext) = base.rsplit_once('.')?;
    (!stem.is_empty() && !ext.is_empty()).then(|| ext.to_ascii_lowercase())
}

/// Recognises a media container from the first bytes of a file. See `docs/probe.md` for the rules.
pub fn sniff(bytes: &[u8]) -> Option<MediaMatch> {
    ebml(bytes)
        .or_else(|| riff_avi(bytes))
        .or_else(|| asf(bytes))
        .or_else(|| packets(bytes, 188, 0, MediaKind::MpegTs))
        .or_else(|| packets(bytes, 192, 4, MediaKind::M2ts))
        .or_else(|| mpeg_ps(bytes))
        .or_else(|| iso_boxes(bytes))
}

/// An EBML variable-length integer at `at`: (value with the length marker removed, encoded length).
fn ebml_vint(bytes: &[u8], at: usize, keep_marker: bool) -> Option<(u64, usize)> {
    let first = *bytes.get(at)?;
    let len = first.leading_zeros() as usize + 1;
    if len > 8 {
        return None;
    }
    let mut value = if keep_marker { u64::from(first) } else { u64::from(first) & (0xff >> len) };
    for i in 1..len {
        value = (value << 8) | u64::from(*bytes.get(at + i)?);
    }
    Some((value, len))
}

const EBML_ID: [u8; 4] = [0x1a, 0x45, 0xdf, 0xa3];
const SEGMENT_ID: [u8; 4] = [0x18, 0x53, 0x80, 0x67];
const DOCTYPE_ID: u64 = 0x4282;

fn ebml(bytes: &[u8]) -> Option<MediaMatch> {
    if !bytes.starts_with(&EBML_ID) {
        return None;
    }
    let Some((size, size_len)) = ebml_vint(bytes, 4, false) else {
        // Cut inside the header's size: the magic alone.
        return (bytes.len() < 12).then_some(MediaMatch::new(MediaKind::Mkv, Confidence::Magic));
    };
    // An EBML header is a few dozen bytes; anything larger is not one.
    if size > 4096 {
        return None;
    }
    let body = 4 + size_len;
    let end = body + size as usize;
    let mut at = body;
    let mut doctype = None;
    while at < end {
        let Some((id, id_len)) = ebml_vint(bytes, at, true) else { break };
        let Some((len, len_len)) = ebml_vint(bytes, at + id_len, false) else { break };
        let value = at + id_len + len_len;
        let next = value.checked_add(usize::try_from(len).ok()?)?;
        if next > end {
            return None;
        }
        if id == DOCTYPE_ID {
            let Some(raw) = bytes.get(value..next) else { break };
            doctype = Some(raw.split(|b| *b == 0).next().unwrap_or(raw));
            break;
        }
        at = next;
    }
    let kind = match doctype {
        Some(b"matroska") => MediaKind::Mkv,
        Some(b"webm") => MediaKind::Webm,
        Some(_) => return None,
        // Cut before the DocType, or a header without one (Matroska's default).
        None => return Some(MediaMatch::new(MediaKind::Mkv, Confidence::Magic)),
    };
    let confidence = match bytes.get(end..end + 4) {
        Some(id) if id == SEGMENT_ID => Confidence::Validated,
        _ => Confidence::Magic,
    };
    Some(MediaMatch::new(kind, confidence))
}

fn riff_avi(bytes: &[u8]) -> Option<MediaMatch> {
    if bytes.get(..4)? != b"RIFF" || bytes.get(8..12)? != b"AVI " {
        return None;
    }
    let confidence = match bytes.get(12..16) {
        Some(b"LIST") => Confidence::Validated,
        _ => Confidence::Magic,
    };
    Some(MediaMatch::new(MediaKind::Avi, confidence))
}

const ASF_HEADER: [u8; 16] =
    [0x30, 0x26, 0xb2, 0x75, 0x8e, 0x66, 0xcf, 0x11, 0xa6, 0xd9, 0x00, 0xaa, 0x00, 0x62, 0xce, 0x6c];

fn asf(bytes: &[u8]) -> Option<MediaMatch> {
    if !bytes.starts_with(&ASF_HEADER) {
        return None;
    }
    let confidence = match (bytes.get(16..24), bytes.get(28..30)) {
        (Some(size), Some(&[1, 2])) if u64::from_le_bytes(size.try_into().unwrap()) >= 30 => Confidence::Validated,
        (Some(size), _) if u64::from_le_bytes(size.try_into().unwrap()) < 30 => return None,
        _ => Confidence::Magic,
    };
    Some(MediaMatch::new(MediaKind::Asf, confidence))
}

/// Fixed-size packets with a 0x47 sync byte `offset` bytes into each: at least 3 syncs, every one present in the
/// bytes matching (up to 16 checked); 8 or more is validated.
fn packets(bytes: &[u8], stride: usize, offset: usize, kind: MediaKind) -> Option<MediaMatch> {
    const MIN: usize = 3;
    const VALIDATED: usize = 8;
    const MAX: usize = 16;
    let mut seen = 0;
    for i in 0..MAX {
        match bytes.get(i * stride + offset) {
            Some(0x47) => seen += 1,
            Some(_) => return None,
            None => break,
        }
    }
    match seen {
        n if n >= VALIDATED => Some(MediaMatch::new(kind, Confidence::Validated)),
        n if n >= MIN => Some(MediaMatch::new(kind, Confidence::Magic)),
        _ => None,
    }
}

/// An MPEG program stream: a pack header (MPEG-2: 14 bytes plus stuffing; MPEG-1: 12 bytes) with its marker bits,
/// validated by the start code that must follow it.
fn mpeg_ps(bytes: &[u8]) -> Option<MediaMatch> {
    if bytes.get(..4)? != [0, 0, 1, 0xba] {
        return None;
    }
    let magic = Some(MediaMatch::new(MediaKind::MpegPs, Confidence::Magic));
    let Some(&first) = bytes.get(4) else { return magic };
    let next = if first >> 6 == 0b01 {
        // MPEG-2: marker bits in bytes 4, 6, 8 and 9, the low two bits of byte 12, then stuffing.
        let Some(fixed) = bytes.get(4..14) else { return magic };
        let markers = fixed[0] & 0x04 != 0 && fixed[2] & 0x04 != 0 && fixed[4] & 0x04 != 0 && fixed[5] & 0x01 != 0;
        if !markers || fixed[8] & 0x03 != 0x03 {
            return None;
        }
        14 + usize::from(fixed[9] & 0x07)
    } else if first >> 4 == 0b0010 {
        // MPEG-1: marker bits in bytes 4, 6, 8, 9 and 11.
        let Some(fixed) = bytes.get(4..12) else { return magic };
        if fixed[0] & 0x01 == 0 || fixed[2] & 0x01 == 0 || fixed[4] & 0x01 == 0 || fixed[5] & 0x80 == 0 {
            return None;
        }
        if fixed[7] & 0x01 == 0 {
            return None;
        }
        12
    } else {
        return None;
    };
    match bytes.get(next..next + 3) {
        Some([0, 0, 1]) => Some(MediaMatch::new(MediaKind::MpegPs, Confidence::Validated)),
        Some(_) => None,
        None => magic,
    }
}

const FIRST_BOXES: [&[u8; 4]; 7] = [b"ftyp", b"moov", b"mdat", b"wide", b"free", b"skip", b"pnot"];
const KNOWN_BOXES: [&[u8; 4]; 16] = [
    b"ftyp", b"moov", b"mdat", b"wide", b"free", b"skip", b"pnot", b"uuid", b"moof", b"mfra", b"sidx", b"styp",
    b"meta", b"pdin", b"prft", b"junk",
];

/// One box header at `at`: (type, total size; None for "to the end of the file").
fn iso_box(bytes: &[u8], at: usize) -> Option<([u8; 4], Option<u64>)> {
    let size = u32::from_be_bytes(bytes.get(at..at + 4)?.try_into().unwrap());
    let kind: [u8; 4] = bytes.get(at + 4..at + 8)?.try_into().unwrap();
    let size = match size {
        0 => None,
        1 => {
            let large = u64::from_be_bytes(bytes.get(at + 8..at + 16)?.try_into().unwrap());
            (large >= 16).then_some(large)?;
            Some(large)
        }
        2..8 => return None,
        n => Some(u64::from(n)),
    };
    Some((kind, size))
}

fn iso_boxes(bytes: &[u8]) -> Option<MediaMatch> {
    let (kind, size) = iso_box(bytes, 0)?;
    if !FIRST_BOXES.contains(&&kind) {
        return None;
    }
    // The box after the first one: known, or past the bytes (or the first box runs to the end).
    let next_known = || -> Option<bool> {
        let next = usize::try_from(size?).ok()?;
        match iso_box(bytes, next) {
            Some((kind, _)) => Some(KNOWN_BOXES.contains(&&kind)),
            None if bytes.len() < next + 8 => None,
            None => Some(false),
        }
    };
    if &kind == b"ftyp" {
        let size = size?;
        if !(16..=4096).contains(&size) || (size - 16) % 4 != 0 {
            return None;
        }
        let brand: [u8; 4] = bytes.get(8..12)?.try_into().unwrap();
        if !brand.iter().all(|b| (0x20..0x7f).contains(b)) {
            return None;
        }
        let media = if &brand == b"qt  " { MediaKind::Mov } else { MediaKind::Mp4 };
        let confidence = match next_known() {
            Some(false) => Confidence::Magic,
            _ => Confidence::Validated,
        };
        return Some(MediaMatch::new(media, confidence));
    }
    // A QuickTime file without `ftyp`: a second known atom validates it; one that is not an atom rejects it.
    match next_known() {
        Some(true) => Some(MediaMatch::new(MediaKind::Mov, Confidence::Validated)),
        Some(false) => None,
        None => Some(MediaMatch::new(MediaKind::Mov, Confidence::Magic)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(media_kind_for_name("Movie.2024.MKV"), Some(MediaKind::Mkv));
        assert_eq!(media_kind_for_name("dir/a.m2ts"), Some(MediaKind::M2ts));
        assert_eq!(media_kind_for_name("mkv"), None);
        assert_eq!(media_kind_for_name(".mkv"), None);
        assert!(is_side_file("x/release.NFO"));
        assert!(!is_side_file("release.mkv"));
    }

    #[test]
    fn short_inputs_never_panic() {
        for len in 0..64 {
            for fill in [0u8, 0x47, 0xff] {
                let mut bytes = vec![fill; len];
                let _ = sniff(&bytes);
                for magic in [&EBML_ID[..], b"RIFF\0\0\0\0AVI ", &ASF_HEADER, b"\0\0\0\x18ftypisom", &[0, 0, 1, 0xba]] {
                    bytes.splice(..magic.len().min(len), magic[..magic.len().min(len)].iter().copied());
                    let _ = sniff(&bytes);
                }
            }
        }
    }
}
