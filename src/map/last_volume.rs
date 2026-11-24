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
//!
//! **Nothing here is verified.** Every field comes from the volume's own bytes, so a volume can claim any set's
//! identity at no cost. Treat the result as a hint: confirm it with data checks (the members' CRCs or hashes over
//! the bytes actually fetched) before using it as a twin or alternate key.
use super::sevenzip::{self, TailSearch};
use super::zip_split::{self, TailZip};
use super::{
    CoderKind, MapChecks, MapError, MapFolder, MapFormat, MapMember, MapMethod, MapOptions, MemberMap, VolumeEnd,
    VolumeMap, VolumeMember,
};
use crate::progressive::{FailureKind, ProgressiveFailure};
use crate::rar5::RarEndRecord;
use std::collections::HashMap;
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
    /// How the member is packed: stored, or compressed with the format's method (see [`MapMethod`]).
    pub method: MapMethod,
    /// The dictionary size the format states for the member: RAR from its header, 7z from its folder's LZMA or
    /// LZMA2 coder properties. None for directories, ZIP entries and other 7z coders.
    pub dictionary: Option<u64>,
}

/// The dictionary a 7z folder's LZMA or LZMA2 coder states, if it has exactly one.
pub(super) fn folder_dictionary(folder: &MapFolder) -> Option<u64> {
    let mut found = folder.coders.iter().filter_map(|c| match c.kind {
        CoderKind::Lzma => c.properties.get(1..5).map(|b| u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))),
        CoderKind::Lzma2 => c.properties.first().map(|&b| crate::codec::lzma2_dict(b)),
        _ => None,
    });
    let first = found.next()?;
    found.next().is_none().then_some(first)
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
            method: part.method,
            dictionary: part.dictionary,
        }
    }

    fn from_member(member: &MapMember, folders: &[MapFolder]) -> Self {
        let dictionary = member.dictionary.or_else(|| {
            let slot = member.folder?;
            folders.get(slot.index as usize).and_then(folder_dictionary)
        });
        Self {
            raw_name: member.raw_name.clone(),
            name: member.name.clone(),
            is_dir: member.is_dir,
            unpacked_size: member.unpacked_size,
            checks: member.checks,
            encrypted: member.encrypted,
            split_before: None,
            mtime: member.mtime,
            method: member.method,
            dictionary: if member.is_dir { None } else { dictionary },
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
///   header is, is not needed: the header is found by its structure. An encoded header is taken only when its
///   folder states a CRC and its packed stream decodes to it; a plain header has no CRC there and is taken when it
///   parses to the end and passes the whole-archive checks. The header also tells where the volume starts in the
///   archive ([`SetFacts::SevenZip::archive_offset`]).
///
/// **The identity is an unverified hint.** It is what the volume says about itself, and a forged volume can claim
/// another set's names, sizes and checks for free. Confirm it with data checks (member CRCs or hashes over the
/// bytes fetched) before matching sets on it, for example as twin or alternate keys.
///
/// Nothing in the bytes is trusted for safety: offsets and counts are checked against the bytes held and the volume
/// length (RAR parts whose header or data claim to run past the volume, and locator offsets past it, are dropped),
/// and every [`MapOptions`] budget applies (header bytes, entries, names, KDF work), as does its cancellation.
/// Headers encrypted with a password need [`MapOptions::password`]: a RAR volume without one gives its main facts
/// only (RAR 4.x) or nothing ([`VolumeEnd::Locked`]); a 7z header without one is [`MapError::PasswordRequired`].
///
/// When the bytes needed for a ZIP directory or a 7z encoded header lie further from the end than the tail held,
/// the result is [`MapError::TailTooShort`] with how many bytes before the end the tail must hold. Bytes of no
/// format named here are [`MapError::NotArchive`]. A 7z header search that spends its work bound (256 Mi parse
/// steps over all candidates) before taking one is [`MapError::TailSearchExhausted`].
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
        TailSearch::Exhausted => seven_error = Some(MapError::TailSearchExhausted),
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
    let mut volume = MemberMap::from_volume(held.head, options)?;
    // A head may end before the data it announces, but nothing in the volume lies past its length: parts whose
    // header or data claim to, and locator offsets past it, are dropped.
    volume.members.retain(|m| m.header.end <= held.len && m.packed.end <= held.len);
    if let Some(locator) = volume.locator
        && (locator.quick_open.is_some_and(|o| o >= held.len) || locator.recovery.is_some_and(|o| o >= held.len))
    {
        volume.locator = None;
    }
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
        members: found.members.iter().map(|m| IdentityMember::from_member(m, &[])).collect(),
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
        members: found
            .map
            .members
            .iter()
            .zip(found.dictionaries.iter().copied().chain(std::iter::repeat(None)))
            .map(|(m, dictionary)| {
                let mut member = IdentityMember::from_member(m, &[]);
                member.dictionary = dictionary;
                member
            })
            .collect(),
        set: SetFacts::SevenZip {
            archive_offset: found.archive_offset,
            header: found.header,
            encoded: found.encoded,
            header_encrypted: found.map.header_encrypted,
        },
    }
}

/// Which held volume supplied a fact of a [`SetMember`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FactSource {
    /// The first volume's bytes.
    First,
    /// The last volume's bytes.
    Last,
}

/// One member of a set, from whatever its first and last volumes' held bytes state. Every fact is `None` when
/// neither volume states it; `*_from` says which volume supplied it.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct SetMember {
    /// The name exactly as stored (members of the two volumes are matched by it).
    pub raw_name: Vec<u8>,
    /// The name decoded by the format's rules, when it decodes.
    pub name: Option<String>,
    pub is_dir: bool,
    /// The member's whole unpacked size.
    pub unpacked_size: Option<u64>,
    pub size_from: Option<FactSource>,
    /// Stored or compressed, and with which method.
    pub method: Option<MapMethod>,
    /// The dictionary size, where the format states it (see [`IdentityMember::dictionary`]).
    pub dictionary: Option<u64>,
    pub method_from: Option<FactSource>,
    /// Whether the member's data is encrypted.
    pub encrypted: Option<bool>,
    /// The member's whole-file checks: CRC32 and/or BLAKE2sp (RAR 5.0 checks of encrypted members may be keyed
    /// with the password, [`MapChecks::keyed`]). RAR states them in the header of the member's last part, so a
    /// member split across volumes has them only from the volume where it ends.
    pub checks: Option<MapChecks>,
    pub checks_from: Option<FactSource>,
}

/// A set's identity from the held bytes of its first volume, its last volume, or both: see [`set_identity`].
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct SetIdentity {
    pub format: MapFormat,
    /// Members in the order the volumes list them: the first volume's, then any only the last volume lists.
    pub members: Vec<SetMember>,
}

impl SetMember {
    fn new(raw_name: &[u8], name: &Option<String>, is_dir: bool) -> Self {
        Self {
            raw_name: raw_name.to_vec(),
            name: name.clone(),
            is_dir,
            unpacked_size: None,
            size_from: None,
            method: None,
            dictionary: None,
            method_from: None,
            encrypted: None,
            checks: None,
            checks_from: None,
        }
    }

    /// Whether `m` can be this member: every whole-member fact both state is equal.
    fn agrees(&self, m: &IdentityMember) -> bool {
        fn same<T: PartialEq>(a: Option<T>, b: Option<T>) -> bool {
            a.zip(b).is_none_or(|(a, b)| a == b)
        }
        self.is_dir == m.is_dir
            && same(self.unpacked_size, m.unpacked_size)
            && same(self.method, Some(m.method))
            && same(self.encrypted, Some(m.encrypted))
            && same(self.dictionary, m.dictionary)
    }

    /// Takes the facts `source` states that are still unknown.
    fn learn(
        &mut self,
        source: FactSource,
        size: Option<u64>,
        method: MapMethod,
        dictionary: Option<u64>,
        encrypted: bool,
        checks: Option<MapChecks>,
    ) {
        if self.unpacked_size.is_none() && size.is_some() {
            self.unpacked_size = size;
            self.size_from = Some(source);
        }
        if self.method.is_none() {
            self.method = Some(method);
            self.dictionary = dictionary;
            self.method_from = Some(source);
        }
        self.encrypted.get_or_insert(encrypted);
        if self.checks.is_none() && checks.is_some() {
            self.checks = checks;
            self.checks_from = Some(source);
        }
    }
}

/// Identifies a set's members from the held bytes of its first volume, its last volume, or both, for example
/// the one article at each end of a download: name, unpacked size, packing method, encryption and the whole-file
/// checks, each `None` when the bytes held do not state it. Two copies of a release whose members agree in size
/// and checks hold the same files, whatever their containers.
///
/// - RAR: every part header states the member's name, size, method and encryption; the header of its last part
///   also states its final checks. `first` is read from its first bytes as [`MemberMap::from_volume`] reads a
///   volume, `last` as [`last_volume_identity`] reads one. A member split across volumes therefore gets its
///   checks only from `last`.
/// - ZIP and 7z: the directory at the end of the last volume lists every member with its checks, so `last`
///   decides (`first` adds nothing). With `last` None, `first` is read as a last volume, which suits a
///   single-volume archive.
///
/// For a single-volume archive pass the same bytes as both, or either alone. `options` carries the password for
/// encrypted headers (RAR `-hp`, 7z `-mhe`). Fails with the first volume's error, or the last's, when either
/// cannot be read; [`MapError::NotArchive`] when neither is given.
pub fn set_identity(
    first: Option<HeldVolume<'_>>,
    last: Option<HeldVolume<'_>>,
    options: MapOptions,
) -> Result<SetIdentity, MapError> {
    // Members are matched across the two volumes by name, by kind (a RAR part going on into later volumes
    // matches the part continuing in the last one; whole members match only when both inputs are the same
    // volume) and by occurrence among equal names and kinds, so two entries of one name never merge.
    #[derive(Clone, Copy, PartialEq, Eq, Hash)]
    enum Kind {
        Whole,
        Spanning,
    }
    /// Checked between entries of long loops: an archive may list hundreds of thousands of members.
    const CANCEL_EVERY: usize = 4096;
    let control = options.control.clone();
    let check = |i: usize| -> Result<(), MapError> {
        if i.is_multiple_of(CANCEL_EVERY) && control.is_canceled() { Err(canceled()) } else { Ok(()) }
    };
    let mut format = None;
    let mut members: Vec<SetMember> = Vec::new();
    // Each first-volume entry by (raw name, kind, occurrence among equal names and kinds): its index in `members`.
    let mut firsts: HashMap<(Vec<u8>, Kind, usize), usize> = HashMap::new();
    let mut first_volume_number = None;
    let mut first_is_rar = false;
    // A first-volume RAR error waits for the last volume: a ZIP or 7z directory there identifies the set even
    // when the RAR the scanner found in the first volume is one stored inside it that cannot be read.
    let mut first_error = None;
    if let Some(held) = first {
        // The RAR scanner finds a volume behind a self-extracting stub; anything else is read as a last volume.
        match MemberMap::from_volume(held.head, options.clone()) {
            Ok(volume) => {
                first_is_rar = true;
                format = Some(volume.format);
                first_volume_number = volume.volume_number;
                let mut counts: HashMap<(&[u8], Kind), usize> = HashMap::new();
                let parts = volume.members.iter().filter(|p| p.header.end <= held.len && p.packed.end <= held.len);
                for (i, part) in parts.enumerate() {
                    check(i)?;
                    let kind = if part.split_after { Kind::Spanning } else { Kind::Whole };
                    let count = counts.entry((part.raw_name.as_slice(), kind)).or_insert(0);
                    let occurrence = *count;
                    *count += 1;
                    let mut member = SetMember::new(&part.raw_name, &part.name, part.is_dir);
                    member.learn(
                        FactSource::First,
                        part.unpacked_size,
                        part.method,
                        part.dictionary,
                        part.encrypted,
                        part.checks,
                    );
                    firsts.insert((part.raw_name.clone(), kind, occurrence), members.len());
                    members.push(member);
                }
            }
            Err(MapError::NotArchive) => {}
            Err(error) if control.is_canceled() => return Err(error),
            Err(error) => first_error = Some(error),
        }
    }
    let rar = |f: MapFormat| matches!(f, MapFormat::Rar4 | MapFormat::Rar5);
    // Reads a first volume's held bytes as a last volume, for a ZIP or 7z directory they may hold.
    let probe = |held: HeldVolume<'_>, options: MapOptions| {
        #[cfg(test)]
        tests::BEFORE_PROBE.with(|hook| {
            if let Some(hook) = hook.get() {
                hook(&options.control)
            }
        });
        last_volume_identity(held, options)
    };
    let (identity, source) = match (last, first) {
        (Some(held), _) => match last_volume_identity(held, options) {
            // The last volume is RAR too, so the first volume's error is the set's own.
            Ok(identity) if first_error.is_some() && rar(identity.format) => {
                return Err(first_error.expect("checked"));
            }
            Ok(identity) => (Some(identity), FactSource::Last),
            Err(error) if control.is_canceled() => return Err(error),
            Err(error) => return Err(first_error.unwrap_or(error)),
        },
        // Only the first volume: a ZIP or 7z directory in its held bytes (a whole single-volume archive, maybe
        // behind a self-extracting stub) decides over a RAR the scanner found stored inside it.
        (None, Some(held)) if first_is_rar || first_error.is_some() => match probe(held, options) {
            Ok(identity) if !rar(identity.format) => (Some(identity), FactSource::First),
            // A cancellation during the probe is the caller's, never a reason to fall back.
            Err(error) if control.is_canceled() => return Err(error),
            _ if control.is_canceled() => return Err(canceled()),
            _ => match first_error {
                Some(error) => return Err(error),
                None => (None, FactSource::Last),
            },
        },
        (None, Some(held)) => (Some(last_volume_identity(held, options)?), FactSource::First),
        (None, None) => return Err(MapError::NotArchive),
    };
    if let Some(identity) = identity {
        if first_is_rar && !rar(identity.format) {
            // A ZIP or 7z directory in the last volume decides the set: a RAR found in the first volume was one
            // stored inside it (a split ZIP's .z01 holding a .rar, say), not the set itself.
            members.clear();
            firsts.clear();
            format = None;
        }
        format.get_or_insert(identity.format);
        // Whole members of the first volume are the last volume's only when both are the same volume.
        // Same volume only on evidence: equal stated numbers, or the very same bytes. Legacy RAR volumes may state
        // no number at all, and two unknowns prove nothing.
        let same_bytes = match (first, last) {
            (Some(a), Some(b)) => a.len == b.len && a.head == b.head && a.tail == b.tail,
            _ => false,
        };
        let same_number = matches!((first_volume_number, identity.volume_number), (Some(a), Some(b)) if a == b);
        let same_volume = !firsts.is_empty() && (same_number || same_bytes);
        let mut counts: HashMap<(&[u8], Kind), usize> = HashMap::new();
        for (i, m) in identity.members.iter().enumerate() {
            check(i)?;
            let matched = if firsts.is_empty() {
                None
            } else {
                let kind = if m.split_before == Some(true) { Kind::Spanning } else { Kind::Whole };
                let count = counts.entry((m.raw_name.as_slice(), kind)).or_insert(0);
                let occurrence = *count;
                *count += 1;
                // the occurrence count, the first-volume lookup and the agreement check
                crate::work::add(crate::work::Work::SetIdentitySteps, 3);
                (kind == Kind::Spanning || same_volume)
                    .then(|| firsts.get(&(m.raw_name.clone(), kind, occurrence)).copied())
                    .flatten()
                    // Two members of one name (one ending in a middle volume, another starting there) are
                    // one member only when every whole-member fact both state agrees.
                    .filter(|&at| members[at].agrees(m))
            };
            let at = matched.unwrap_or_else(|| {
                members.push(SetMember::new(&m.raw_name, &m.name, m.is_dir));
                members.len() - 1
            });
            members[at].learn(source, m.unpacked_size, m.method, m.dictionary, m.encrypted, m.checks);
        }
    }
    Ok(SetIdentity { format: format.expect("a volume was read"), members })
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
        if flags & 2 != 0 {
            // A data area would follow the header, past the end of the volume: only an empty one fits.
            let (data, k) = vint(tail, at)?;
            if data != 0 {
                return None;
            }
            at += k;
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

    thread_local! {
        /// Called just before `set_identity` probes a first-volume RAR's bytes for a ZIP or 7z directory.
        pub(super) static BEFORE_PROBE: std::cell::Cell<Option<fn(&crate::progressive::SessionControl)>> =
            const { std::cell::Cell::new(None) };
    }

    /// A one-member RAR 5.0 archive, stored, in one volume.
    fn rar5_single(name: &str, data: &[u8]) -> Vec<u8> {
        fn vint(mut v: u64, out: &mut Vec<u8>) {
            loop {
                let b = (v & 0x7f) as u8;
                v >>= 7;
                if v == 0 {
                    out.push(b);
                    break;
                }
                out.push(b | 0x80);
            }
        }
        fn block(kind: u64, flags: u64, fields: &[u8], data_len: Option<u64>) -> Vec<u8> {
            let mut body = Vec::new();
            vint(kind, &mut body);
            vint(flags | if data_len.is_some() { 2 } else { 0 }, &mut body);
            if let Some(n) = data_len {
                vint(n, &mut body);
            }
            body.extend_from_slice(fields);
            let mut size = Vec::new();
            vint(body.len() as u64, &mut size);
            let mut covered = size.clone();
            covered.extend_from_slice(&body);
            let mut out = crate::crc32::hash(&covered).to_le_bytes().to_vec();
            out.extend(covered);
            out
        }
        let mut out = RAR5_SIGNATURE.to_vec();
        out.extend(block(1, 0, &[0], None));
        let mut fields = Vec::new();
        vint(4, &mut fields); // file flags: CRC32 present
        vint(data.len() as u64, &mut fields);
        vint(0x20, &mut fields); // attributes
        fields.extend(crate::crc32::hash(data).to_le_bytes());
        vint(0, &mut fields); // compression info: stored
        vint(0, &mut fields); // host OS
        vint(name.len() as u64, &mut fields);
        fields.extend_from_slice(name.as_bytes());
        out.extend(block(2, 0, &fields, Some(data.len() as u64)));
        out.extend_from_slice(data);
        out.extend(block(5, 0, &[0], None));
        out
    }

    #[test]
    fn a_cancellation_during_the_first_only_probe_is_returned() {
        let rar = rar5_single("a.bin", b"payload");
        let held = HeldVolume::whole(&rar);
        // Without a cancellation the first volume alone identifies the archive.
        let s = set_identity(Some(held), None, MapOptions::new("a.rar")).unwrap();
        assert_eq!(s.members.len(), 1);
        BEFORE_PROBE.with(|hook| hook.set(Some(|control| control.cancel())));
        let result = set_identity(Some(held), None, MapOptions::new("a.rar"));
        BEFORE_PROBE.with(|hook| hook.set(None));
        assert!(matches!(result, Err(MapError::Source(_))), "{result:?}");
    }

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
    fn rar5_end_header_data_area() {
        let header = |body: &[u8]| {
            let mut h = crate::crc32::hash(body).to_le_bytes().to_vec();
            h.extend_from_slice(body);
            h
        };
        // Flags 0x2 (data area) with a data size of 0, then end flags 1: read past the data size.
        let found = rar5_end(&header(&[4, 5, 2, 0, 1]), 0).unwrap();
        assert_eq!(found.flags, 1);
        // A nonzero data area cannot follow a header that ends the volume.
        assert!(rar5_end(&header(&[4, 5, 2, 9, 1]), 0).is_none());
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
