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

//! A set's identity read from its last volume alone: [`last_volume_identity`].
//!
//! RAR volumes carry their members' headers at the start, ZIP and 7z sets their directory at the end of the last
//! volume. A downloader holding the first and last bytes of a set's last volume (its first and last articles) can
//! learn which members end there, with their final sizes and checks, and where the volume stands in its set, to
//! match the set against another copy without the first volume.
use super::sevenzip::{self, TailSearch};
use super::zip_split::{self, TailZip};
use super::{MapChecks, MapError, MapFormat, MapMember, MapOptions, MemberMap, VolumeEnd, VolumeMap, VolumeMember};
use crate::progressive::{FailureKind, ProgressiveFailure};
use crate::rar5::RarEndRecord;
use std::ops::Range;

const RAR4_SIGNATURE: &[u8] = b"Rar!\x1a\x07\x00";
const RAR5_SIGNATURE: &[u8] = b"Rar!\x1a\x07\x01\x00";
/// How far from the end a RAR end of archive header is looked for. RAR 5.0's is 8 bytes or so, RAR 4.x's at most
/// 20 with every optional field.
const RAR_END_WINDOW: usize = 64;

/// The bytes held of one volume: its first bytes, its last bytes, or both. The whole volume is both.
#[derive(Clone, Copy, Debug)]
pub struct HeldVolume<'a> {
    head: &'a [u8],
    tail: &'a [u8],
    len: u64,
}

impl<'a> HeldVolume<'a> {
    /// The whole volume.
    pub fn whole(bytes: &'a [u8]) -> Self {
        Self { head: bytes, tail: bytes, len: bytes.len() as u64 }
    }

    /// `head`, the volume's first bytes, and `tail`, its last bytes, of a volume `len` bytes long. Either may be
    /// empty, and they may overlap. None when either is longer than the volume.
    pub fn new(head: &'a [u8], tail: &'a [u8], len: u64) -> Option<Self> {
        (head.len() as u64 <= len && tail.len() as u64 <= len).then_some(Self { head, tail, len })
    }

    pub fn head(&self) -> &'a [u8] {
        self.head
    }

    pub fn tail(&self) -> &'a [u8] {
        self.tail
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Which members [`LastVolumeIdentity::members`] lists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum IdentityScope {
    /// RAR: the members whose last part is in this volume, from their headers in it.
    EndingHere,
    /// ZIP and 7z: every member of the set, from the directory at the end of the last volume.
    WholeSet,
}

/// One member as the last volume identifies it.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct IdentityMember {
    /// The name exactly as stored (for ZIP, the UTF-8 bytes of the decoded name; for 7z, UTF-16LE).
    pub raw_name: Vec<u8>,
    /// The name decoded by the format's rules, when it decodes.
    pub name: Option<String>,
    pub is_dir: bool,
    /// The member's final unpacked size, when the header states it.
    pub unpacked_size: Option<u64>,
    /// The member's final checks. RAR 5.0 checks of encrypted members may be keyed with the password
    /// ([`MapChecks::keyed`]).
    pub checks: Option<MapChecks>,
    pub encrypted: bool,
    /// RAR: the member started in an earlier volume. None for ZIP and 7z.
    pub split_before: Option<bool>,
    /// Modification time as seconds since 1970 and nanoseconds.
    pub mtime: Option<(i64, u32)>,
}

impl IdentityMember {
    fn from_part(part: &VolumeMember) -> Self {
        Self {
            raw_name: part.raw_name.clone(),
            name: part.name.clone(),
            is_dir: part.is_dir,
            unpacked_size: part.unpacked_size,
            checks: part.checks,
            encrypted: part.encrypted,
            split_before: Some(part.split_before),
            mtime: part.mtime,
        }
    }

    fn from_member(member: &MapMember) -> Self {
        Self {
            raw_name: member.raw_name.clone(),
            name: member.name.clone(),
            is_dir: member.is_dir,
            unpacked_size: member.unpacked_size,
            checks: member.checks,
            encrypted: member.encrypted,
            split_before: None,
            mtime: member.mtime,
        }
    }
}

/// Format-specific facts about the set, as the last volume states them.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SetFacts {
    Rar {
        /// The volume's headers read from its first bytes: main header facts (volume number, solid, naming,
        /// header encryption, the RAR 5.0 locator) and every part header, including the parts that go on in a
        /// later volume.
        volume: Box<VolumeMap>,
        /// The end of archive header, from the first bytes when they reach it, else from the last bytes. None
        /// when neither holds it, or the headers are encrypted and the first bytes stop before it.
        end_record: Option<RarEndRecord>,
    },
    Zip {
        /// The end of central directory record's offset in the volume.
        end_at: u64,
        /// The central directory's bytes in the volume.
        directory: Range<u64>,
        /// Whether the directory is described by a ZIP64 end record.
        zip64: bool,
        /// The archive comment as stored.
        comment: Vec<u8>,
    },
    SevenZip {
        /// Where the volume starts in the archive, the concatenation of the split's volumes: with the size of the
        /// volumes before it, the volume's index.
        archive_offset: u64,
        /// The archive header's bytes in the volume; they run to its end.
        header: Range<u64>,
        /// Whether the header is encoded (compressed, and with `-mhe` encrypted).
        encoded: bool,
        /// Whether the header is encrypted.
        header_encrypted: bool,
    },
}

/// What a set's last volume says about the set: see [`last_volume_identity`].
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct LastVolumeIdentity {
    pub format: MapFormat,
    /// Which members `members` lists.
    pub scope: IdentityScope,
    /// The volume's zero-based position in its set, when the bytes state it. RAR 5.0: the main header's; RAR 4.x:
    /// the end header's number, or 0 for a first volume; ZIP: the end record's disk. None for 7z, whose volumes
    /// are plain byte cuts (see [`SetFacts::SevenZip::archive_offset`]).
    pub volume_number: Option<u32>,
    /// Whether the volume is its set's last. RAR: from the end header, None when it was not read. ZIP and 7z:
    /// always true, since the directory or header found ends the set.
    pub is_last: Option<bool>,
    /// How many volumes the set has, when known: the volume number plus one for a last volume.
    pub volumes: Option<u32>,
    pub members: Vec<IdentityMember>,
    pub set: SetFacts,
}

fn canceled() -> MapError {
    MapError::Source(Box::new(ProgressiveFailure::new(FailureKind::Canceled)))
}

/// Reads a set's identity from its last volume alone: which members end there, with their final sizes and
/// checks, where the volume stands in its set, and the end of archive record.
///
/// What each format needs:
///
/// - **RAR 4.x and 5.0**: the volume's first bytes (one article is usually enough), read as
///   [`MemberMap::from_volume`] reads them. Every part header records the member's name and unpacked size, and the
///   last part's header its final CRC32 or BLAKE2sp, so the members ending here ([`IdentityScope::EndingHere`]) are
///   identified even when their data runs past the bytes held. The end of archive header (last volume or not, and
///   for RAR 4.x the volume number) is read from the first bytes when they reach it, else from the last bytes.
/// - **ZIP**, single-disk or the `.zip` of a split set: the last bytes, holding the end of central directory
///   record and the whole central directory, which must lie on this volume ([`IdentityScope::WholeSet`]).
/// - **7z**, a single archive or the last of `.7z.001`, `.7z.002`, ...: the last bytes, holding the archive header
///   and, for an encoded header, its packed stream. The signature header in the first volume, which says where the
///   header is, is not needed: the header is found by its structure and checked, an encoded one by its CRC, and
///   it also tells where the volume starts in the archive ([`SetFacts::SevenZip::archive_offset`]).
///
/// Nothing in the bytes is trusted: offsets and counts are checked against the bytes held and the volume length,
/// and every [`MapOptions`] budget applies (header bytes, entries, names, KDF work), as does its cancellation.
/// Headers encrypted with a password need [`MapOptions::password`]: a RAR volume without one gives its main facts
/// only (RAR 4.x) or nothing ([`VolumeEnd::Locked`]); a 7z header without one is [`MapError::PasswordRequired`].
///
/// When the bytes needed for a ZIP directory or a 7z encoded header lie further from the end than the tail held,
/// the result is [`MapError::TailTooShort`] with how many bytes before the end the tail must hold. Bytes of no
/// format named here are [`MapError::NotArchive`].
pub fn last_volume_identity(held: HeldVolume<'_>, options: MapOptions) -> Result<LastVolumeIdentity, MapError> {
    if options.control.is_canceled() {
        return Err(canceled());
    }
    let head = held.head;
    if head.starts_with(RAR5_SIGNATURE) || head.starts_with(RAR4_SIGNATURE) {
        return rar(held, options);
    }
    let mut need = None;
    match zip_split::from_tail(held.tail, held.len, &options)? {
        TailZip::Found(found) => return Ok(zip(*found)),
        TailZip::NeedBytes(n) => need = Some(n),
        TailZip::NotFound => {}
    }
    if options.control.is_canceled() {
        return Err(canceled());
    }
    let mut seven_error = None;
    match sevenzip::from_tail(held.tail, held.len, &options)? {
        TailSearch::Found(found) => return Ok(seven(*found)),
        TailSearch::NeedBytes(n) => need = Some(need.map_or(n, |m: u64| m.min(n))),
        TailSearch::NotFound(error) => seven_error = error,
    }
    // A self-extracting stub before a RAR volume.
    if !head.is_empty() {
        match rar(held, options) {
            Err(MapError::NotArchive) => {}
            other => return other,
        }
    }
    if let Some(from_end) = need {
        return Err(MapError::TailTooShort { from_end });
    }
    // A 7z header that parsed to the end of the bytes but failed its checks is reported as such.
    Err(seven_error.unwrap_or(MapError::NotArchive))
}

fn rar(held: HeldVolume<'_>, options: MapOptions) -> Result<LastVolumeIdentity, MapError> {
    let volume = MemberMap::from_volume(held.head, options)?;
    let mut end_record = volume.end_record;
    let mut volume_number = volume.volume_number;
    let mut has_next = (volume.end == VolumeEnd::Complete).then_some(volume.has_next_volume);
    if end_record.is_none() && !volume.header_encrypted && volume.main_read {
        let start = held.len - held.tail.len() as u64;
        let found = match volume.format {
            MapFormat::Rar4 => rar4_end(held.tail, start),
            _ => rar5_end(held.tail, start),
        };
        // Past the headers already read: an end header lies after every member's data.
        let after = volume.members.last().map_or(0, |m| m.packed.end);
        if let Some(record) = found.filter(|r| r.offset >= after) {
            end_record = Some(record);
            has_next = Some(record.flags & 1 != 0);
            if volume.multi_volume
                && let Some(number) = record.volume_number.and_then(|n| u32::try_from(n).ok())
            {
                // As the single-volume walk does: a first volume numbered otherwise contradicts itself.
                if !(volume.first_volume && number != 0) {
                    volume_number = Some(number);
                }
            }
        }
    }
    let is_last = has_next.map(|next| !next);
    let members = volume.members.iter().filter(|m| !m.split_after).map(IdentityMember::from_part).collect();
    Ok(LastVolumeIdentity {
        format: volume.format,
        scope: IdentityScope::EndingHere,
        volume_number,
        is_last,
        volumes: match (is_last, volume_number) {
            (Some(true), Some(n)) => n.checked_add(1),
            _ => None,
        },
        members,
        set: SetFacts::Rar { volume: Box::new(volume), end_record },
    })
}

fn zip(found: zip_split::TailDirectory) -> LastVolumeIdentity {
    LastVolumeIdentity {
        format: MapFormat::Zip,
        scope: IdentityScope::WholeSet,
        volume_number: Some(found.last),
        is_last: Some(true),
        volumes: found.last.checked_add(1),
        members: found.members.iter().map(IdentityMember::from_member).collect(),
        set: SetFacts::Zip {
            end_at: found.end_at,
            directory: found.directory,
            zip64: found.zip64,
            comment: found.comment,
        },
    }
}

fn seven(found: sevenzip::TailHeader) -> LastVolumeIdentity {
    LastVolumeIdentity {
        format: MapFormat::SevenZip,
        scope: IdentityScope::WholeSet,
        volume_number: None,
        is_last: Some(true),
        volumes: None,
        members: found.map.members.iter().map(IdentityMember::from_member).collect(),
        set: SetFacts::SevenZip {
            archive_offset: found.archive_offset,
            header: found.header,
            encoded: found.encoded,
            header_encrypted: found.map.header_encrypted,
        },
    }
}

/// A RAR 5.0 vint at `at`: its value and length.
fn vint(bytes: &[u8], at: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for i in 0..10 {
        let b = *bytes.get(at + i)?;
        value |= u64::from(b & 0x7f).checked_shl(7 * i as u32)?;
        if b & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    None
}

/// A RAR 5.0 end of archive header ending exactly at the end of `tail`, whose first byte is at volume offset
/// `start`. Its CRC32 must match.
fn rar5_end(tail: &[u8], start: u64) -> Option<RarEndRecord> {
    let lowest = tail.len().saturating_sub(RAR_END_WINDOW);
    (lowest..tail.len()).rev().find_map(|c| {
        let crc = u32::from_le_bytes(tail.get(c..c + 4)?.try_into().ok()?);
        let (size, size_len) = vint(tail, c + 4)?;
        let body = c + 4 + size_len;
        if size == 0 || body.checked_add(usize::try_from(size).ok()?)? != tail.len() {
            return None;
        }
        if crate::crc32::hash(&tail[c + 4..]) != crc {
            return None;
        }
        let (kind, n) = vint(tail, body)?;
        if kind != 5 {
            return None;
        }
        let (flags, m) = vint(tail, body + n)?;
        let mut at = body + n + m;
        if flags & 1 != 0 {
            // An extra area; its size comes first and it follows the fields.
            at += vint(tail, at)?.1;
        }
        let end_flags = vint(tail, at).map_or(0, |(f, _)| f);
        Some(RarEndRecord { flags: end_flags, data_crc: None, volume_number: None, offset: start + c as u64 })
    })
}

/// A RAR 4.x end of archive header ending exactly at the end of `tail`, whose first byte is at volume offset
/// `start`. Its CRC16 (the low half of the CRC32 of the header after the CRC) must match.
fn rar4_end(tail: &[u8], start: u64) -> Option<RarEndRecord> {
    let lowest = tail.len().saturating_sub(RAR_END_WINDOW);
    (lowest..tail.len().saturating_sub(6)).rev().find_map(|c| {
        let header = &tail[c..];
        if header[2] != 0x7b || usize::from(u16::from_le_bytes([header[5], header[6]])) != header.len() {
            return None;
        }
        let crc = u16::from_le_bytes([header[0], header[1]]);
        if crate::crc32::hash(&header[2..]) & 0xffff != u32::from(crc) {
            return None;
        }
        let flags = u16::from_le_bytes([header[3], header[4]]);
        let data_crc =
            (flags & 2 != 0).then(|| header.get(7..11)).flatten().map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
        let at = 7 + usize::from(flags & 2 != 0) * 4;
        let volume_number = (flags & 8 != 0)
            .then(|| header.get(at..at + 2))
            .flatten()
            .map(|n| u64::from(u16::from_le_bytes([n[0], n[1]])));
        Some(RarEndRecord { flags: u64::from(flags), data_crc, volume_number, offset: start + c as u64 })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn held_volume_bounds() {
        assert!(HeldVolume::new(b"abc", b"", 2).is_none());
        assert!(HeldVolume::new(b"", b"abc", 2).is_none());
        let held = HeldVolume::new(b"ab", b"bc", 3).unwrap();
        assert_eq!((held.head(), held.tail(), held.len()), (&b"ab"[..], &b"bc"[..], 3));
    }

    #[test]
    fn rar5_end_header_needs_its_crc() {
        // CRC32, size 3, type 5, flags 0, end flags 0.
        let body = [3u8, 5, 0, 0];
        let mut header = crate::crc32::hash(&body).to_le_bytes().to_vec();
        header.extend_from_slice(&body);
        let mut tail = vec![0xAA; 20];
        tail.extend_from_slice(&header);
        let found = rar5_end(&tail, 100).unwrap();
        assert_eq!((found.flags, found.offset), (0, 120));
        let last = tail.len() - 1;
        tail[last] = 1;
        assert!(rar5_end(&tail, 100).is_none(), "the CRC covers the end flags");
    }

    #[test]
    fn rar4_end_header_fields() {
        // Type 0x7B, flags EARC_NEXT_VOLUME | EARC_DATACRC | EARC_VOLNUMBER, size 13.
        let mut header = vec![0, 0, 0x7b, 0x0b, 0x00, 13, 0];
        header.extend_from_slice(&0xDEADBEEFu32.to_le_bytes());
        header.extend_from_slice(&7u16.to_le_bytes());
        let crc = (crate::crc32::hash(&header[2..]) & 0xffff) as u16;
        header[..2].copy_from_slice(&crc.to_le_bytes());
        let found = rar4_end(&header, 0).unwrap();
        assert_eq!(found.data_crc, Some(0xDEADBEEF));
        assert_eq!(found.volume_number, Some(7));
        assert_eq!(found.flags & 1, 1);
        header[11] = 8;
        assert!(rar4_end(&header, 0).is_none());
    }
}
