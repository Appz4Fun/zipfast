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

//! Probing: how a release is packed, judged from the first bytes of its first file (one Usenet article).
//!
//! [`probe`] takes the first bytes of a file (`head`), optionally its last bytes (`tail`), and a password, and says
//! whether the file is bare media ([`MediaKind`]), a RAR 4.x or 5.0 volume, or a ZIP archive. For archives it
//! picks the first media member (see [`Selection`]), says how that member is packed ([`MemberPacking`]), and gives
//! a [`Borrowable`] verdict: whether output offsets of that member map to packed bytes, so that bytes of another
//! copy of the same content (an "alt") can stand in for missing ones. See `docs/probe.md`.

mod media;
mod zip;

pub use media::{Confidence, MediaKind, MediaMatch, media_kind_for_name, sniff};

use crate::map::{
    CipherParams, MapError, MapFormat, MapMethod, MapOptions, MemberMap, OutputMapping, VolumeEnd, VolumeMap,
};
use crate::progressive::ProgressiveLimits;
use std::ops::Range;

/// The most member data decrypted to sniff a media magic.
const SNIFF_DECRYPT: usize = 64 << 10;

/// Options for [`probe_with`].
#[derive(Clone, Default)]
#[non_exhaustive]
pub struct ProbeOptions {
    /// Header byte, name, entry, metadata and KDF budgets for archive headers.
    pub limits: ProgressiveLimits,
    /// The whole file's length, when known (a yEnc `size=`). Without it the ZIP central directory's position is
    /// inferred from the end records in `tail`.
    pub file_len: Option<u64>,
}

impl ProbeOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn file_len(mut self, len: Option<u64>) -> Self {
        self.file_len = len;
        self
    }
}

/// How a file is packed.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Packing {
    /// A media file, not an archive. Always [`Borrowable::Yes`]: output offset `o` is file offset `o`.
    BareMedia(MediaMatch),
    /// A RAR 4.x or 5.0 volume.
    Rar(RarPacking),
    /// A ZIP archive.
    Zip(ZipPacking),
    /// Neither recognised media nor an archive this module reads.
    Unknown,
}

impl Packing {
    /// The borrowable verdict: [`Borrowable::Yes`] for bare media, the archive's verdict, or
    /// [`Borrowable::Unknown`] with [`Undecided::NotRecognised`].
    pub fn borrowable(&self) -> Borrowable {
        match self {
            Self::BareMedia(_) => Borrowable::Yes,
            Self::Rar(rar) => rar.borrowable,
            Self::Zip(zip) => zip.borrowable,
            Self::Unknown => Borrowable::Unknown(Undecided::NotRecognised),
        }
    }

    /// The chosen media member of an archive.
    pub fn first_media(&self) -> Option<&MemberFacts> {
        match self {
            Self::Rar(rar) => rar.first_media.as_ref(),
            Self::Zip(zip) => zip.first_media.as_ref(),
            _ => None,
        }
    }
}

/// The RAR format version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RarVersion {
    Rar4,
    Rar5,
}

/// Where a RAR volume sits in its set, from its main header (and end header when the bytes reach it). See
/// [`VolumeMap`] for each field's rules.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct VolumeFacts {
    /// Whether the main header was read; when false (a locked RAR 5.0 volume, or bytes ending inside the main
    /// header) the facts below are defaults.
    pub known: bool,
    pub volume_number: Option<u32>,
    pub first_volume: bool,
    pub multi_volume: bool,
    /// `.partNN.rar` naming (always for RAR 5.0) rather than `.rar`, `.r00`, ...
    pub new_naming: bool,
    /// The end header says another volume follows. False when the bytes do not reach the end header.
    pub has_next_volume: bool,
    /// The archive is solid.
    pub solid: bool,
}

/// What a probe found in a RAR volume.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct RarPacking {
    pub version: RarVersion,
    pub volume: VolumeFacts,
    /// The headers are encrypted (`-hp`).
    pub header_encrypted: bool,
    /// The headers are encrypted and could not be read: no password, or the wrong one ([`Borrowable::NeedsPassword`]
    /// says which). No members are listed.
    pub locked: bool,
    /// The chosen media member, when one was listed.
    pub first_media: Option<MemberFacts>,
    pub borrowable: Borrowable,
    /// The full single-volume map the facts come from ([`MemberMap::from_volume`]).
    pub map: VolumeMap,
}

/// What a probe found in a ZIP archive.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ZipPacking {
    /// The central directory was read from `tail`; members, sizes and methods come from it.
    pub directory: bool,
    /// Every member is listed: the central directory was read, or the local headers in the head reached it.
    pub complete: bool,
    /// The head starts with the spanned-archive marker (`PK\x07\x08`): the first part of a split ZIP.
    pub spanned: bool,
    /// Members listed.
    pub members: usize,
    pub first_media: Option<MemberFacts>,
    pub borrowable: Borrowable,
}

/// How the chosen member was picked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Selection {
    /// The first member whose name has a media extension ([`media_kind_for_name`]).
    Extension,
    /// The first member whose stored data in the head starts with a media magic ([`sniff`]), with no media
    /// extension.
    Magic,
    /// No member is media by name or magic: the largest listed member that is not a side file (nfo, sfv, txt,
    /// images, subtitles, par2, ...), or, when every member is listed, the largest of all.
    Largest,
}

/// The cipher of encrypted member data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CipherKind {
    /// RAR 5.0 AES-256-CBC.
    Rar5Aes256,
    /// RAR 4.x AES-128-CBC.
    Rar4Aes128,
    /// Older RAR data encryption (not mapped).
    Rar4Legacy,
    /// Traditional PKWARE encryption.
    ZipCrypto,
    /// WinZip AES (`strength` 1 to 3: AES-128, -192, -256).
    WinZipAes { strength: u8 },
    /// ZIP strong encryption, or a WinZip AES entry without a valid AES extra field.
    Unknown,
}

/// How the chosen member's data is packed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MemberPacking {
    /// Stored as is, in the clear.
    Stored,
    /// Compressed with the format's method number ([`MapMethod::Compressed`]); `solid` when it depends on earlier
    /// members.
    Compressed { method: u16, solid: bool },
    /// The data is encrypted; `stored` when it is not also compressed.
    DataEncrypted { cipher: CipherKind, stored: bool },
}

/// The chosen media member of an archive.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct MemberFacts {
    /// Zero-based position among the members listed.
    pub index: usize,
    /// The name exactly as stored.
    pub raw_name: Vec<u8>,
    /// The name decoded by the format's rules, when it decodes.
    pub name: Option<String>,
    /// The unpacked size, when the header records it.
    pub size: Option<u64>,
    /// Packed bytes of this member (RAR: of this volume's part), when known.
    pub packed_size: Option<u64>,
    pub method: MapMethod,
    pub packing: MemberPacking,
    pub mapping: OutputMapping,
    pub cipher: Option<CipherParams>,
    /// The member continues from an earlier volume (RAR): its data here is not the start of the file.
    pub continued: bool,
    /// The header's extent in the head's coordinates, when it was read.
    pub header: Option<Range<u64>>,
    /// The packed data's offsets in the head's coordinates, when the header was read. They may run past the end of
    /// the head (`u64::MAX` when the size is unknown).
    pub data: Option<Range<u64>>,
    /// The media kind the name's extension names.
    pub name_kind: Option<MediaKind>,
    /// The media kind the member's first bytes show: plain stored data, or encrypted stored data decrypted with
    /// the password, starting inside the head.
    pub sniffed: Option<MediaMatch>,
    pub selected: Selection,
}

impl MemberFacts {
    /// The member's media kind: sniffed from its bytes, else from its name.
    pub fn media(&self) -> Option<MediaKind> {
        self.sniffed.map(|m| m.kind).or(self.name_kind)
    }
}

/// Whether the bytes of the chosen member can be borrowed: its output offsets map to packed bytes, so another copy
/// of the same content can supply missing output ranges, and this copy's packed bytes can be turned into output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Borrowable {
    /// Plain stored data (or bare media): output byte `o` is a known packed byte.
    Yes,
    /// Stored data that is encrypted (or behind encrypted headers): it maps once decrypted with the password that
    /// was given, and the proof says what showed that password to be right.
    YesWithPassword(PasswordProof),
    /// Stored data, encrypted with a mapped cipher, and a password that nothing could check or refute: no check
    /// value, and the member's first bytes are not in the head (or its name names no media to compare with).
    /// **Do not borrow on this verdict**: a wrong password would turn borrowed bytes into noise. Prove the password
    /// another way first (a full decrypt against the member's CRC).
    PasswordUnverified,
    /// A password is needed and was not given, or the one given is wrong.
    NeedsPassword(PasswordNeed),
    /// Output offsets do not map to packed bytes.
    No(NotBorrowable),
    /// The bytes do not tell.
    Unknown(Undecided),
}

/// What showed the given password to be right, strongest first.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PasswordProof {
    /// The format's password check matched: a RAR 5.0 check value, or a WinZip AES 2-byte verifier (which a wrong
    /// password passes about once in 65,536).
    Verifier,
    /// The decrypted first bytes of the member are a recognised media magic, of the kind its name names when the
    /// name has a media extension.
    Plaintext,
    /// The password decrypted the archive's encrypted headers (`-hp`).
    Headers,
}

/// Why a password is needed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PasswordNeed {
    /// The headers are encrypted (`-hp`) and no password was given.
    HeaderEncrypted,
    /// The member's data is encrypted and no password was given.
    DataEncrypted,
    /// The password given fails a check: encrypted headers, a RAR 5.0 check value, a WinZip AES verifier, or a
    /// member named as a kind whose start is mandatory (Matroska, WebM, AVI, ASF, MP4, QuickTime) whose decrypted
    /// first bytes (at least 4 KiB, or the whole member) do not start that way. Never for a password the encrypted
    /// headers proved.
    WrongPassword,
}

/// Why output offsets do not map to packed bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum NotBorrowable {
    /// The member is compressed.
    Compressed,
    /// The member is compressed in a solid stream that depends on earlier members.
    Solid,
    /// The cipher does not map offsets (older RAR encryption, ZIP strong encryption, AES without its parameters), or
    /// its key derivation is past what the probe derives (a RAR 5.0 KDF count above 20).
    UnsupportedCipher,
    /// ZipCrypto: output byte `o` needs every earlier byte of the stream decrypted first.
    SequentialCipher,
}

/// Why the bytes do not decide.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Undecided {
    /// The head ends, or a damaged header stops the listing ([`VolumeEnd::Damaged`]), before a member that could be
    /// chosen.
    Truncated,
    /// No member listed so far is media by name or magic, and the listing is incomplete: a media member may follow.
    /// [`Packing::first_media`] holds the largest member so far ([`Selection::Largest`]), tentatively.
    NoMediaYet,
    /// The archive (or volume) lists no files.
    NoMembers,
    /// The file is neither recognised media nor an archive.
    NotRecognised,
}

/// One listed member as the probe sees it, from a RAR volume map or ZIP headers.
pub(crate) struct Candidate {
    raw_name: Vec<u8>,
    name: Option<String>,
    is_dir: bool,
    size: Option<u64>,
    packed_size: Option<u64>,
    header: Option<Range<u64>>,
    data: Option<Range<u64>>,
    continued: bool,
    method: MapMethod,
    solid: bool,
    encrypted: bool,
    cipher_kind: Option<CipherKind>,
    cipher: Option<CipherParams>,
    mapping: OutputMapping,
}

/// [`probe_with`] with default options.
pub fn probe(head: &[u8], tail: Option<&[u8]>, password: Option<&str>) -> Result<Packing, MapError> {
    probe_with(head, tail, password, &ProbeOptions::default())
}

/// Says how a file is packed from its first bytes `head` and, optionally, its last bytes `tail`.
///
/// Detection order: a RAR signature at the start, a ZIP local header (or empty-archive end record, or spanned
/// marker) at the start, a media magic at the start ([`sniff`]), then the RAR scanner for a self-extracting stub.
/// `tail` is used only for ZIP, to read the central directory. An empty password is no password.
///
/// Errors are the member map's: damaged or unsupported RAR headers, a ZIP head whose first local header is
/// damaged, or a budget in [`ProbeOptions::limits`]. A wrong password for encrypted headers is not an error but
/// [`Borrowable::NeedsPassword`] with [`PasswordNeed::WrongPassword`].
pub fn probe_with(
    head: &[u8],
    tail: Option<&[u8]>,
    password: Option<&str>,
    options: &ProbeOptions,
) -> Result<Packing, MapError> {
    let password = password.filter(|p| !p.is_empty());
    if head.starts_with(b"Rar!") {
        return rar(head, password, options);
    }
    if zip::starts_zip(head) {
        return zip_packing(head, tail, password, options);
    }
    if let Some(found) = sniff(head) {
        return Ok(Packing::BareMedia(found));
    }
    match rar(head, password, options) {
        Err(MapError::NotArchive) => Ok(Packing::Unknown),
        other => other,
    }
}

fn rar(head: &[u8], password: Option<&str>, options: &ProbeOptions) -> Result<Packing, MapError> {
    let map_options = |password| {
        let mut o = MapOptions::new("probe").password(password);
        o.limits = options.limits.clone();
        o
    };
    let (map, wrong) = match MemberMap::from_volume(head, map_options(password)) {
        Ok(map) => (map, false),
        Err(MapError::WrongPassword) => (MemberMap::from_volume(head, map_options(None))?, true),
        Err(e) => return Err(e),
    };
    let version = if map.format == MapFormat::Rar4 { RarVersion::Rar4 } else { RarVersion::Rar5 };
    let volume = VolumeFacts {
        known: map.main_read,
        volume_number: map.volume_number,
        first_volume: map.first_volume,
        multi_volume: map.multi_volume,
        new_naming: map.new_naming,
        has_next_volume: map.has_next_volume,
        solid: map.solid,
    };
    let locked = matches!(map.end, VolumeEnd::Locked { .. });
    let (first_media, borrowable) = if locked {
        let need = if wrong { PasswordNeed::WrongPassword } else { PasswordNeed::HeaderEncrypted };
        (None, Borrowable::NeedsPassword(need))
    } else {
        let candidates: Vec<Candidate> = map
            .members
            .iter()
            .map(|m| Candidate {
                raw_name: m.raw_name.clone(),
                name: m.name.clone(),
                is_dir: m.is_dir,
                size: m.unpacked_size,
                packed_size: Some(m.packed_size),
                header: Some(m.header.clone()),
                data: Some(m.packed.clone()),
                continued: m.split_before,
                method: m.method,
                solid: m.solid,
                encrypted: m.encrypted,
                cipher_kind: m.cipher.as_ref().map(cipher_kind),
                cipher: m.cipher.clone(),
                mapping: m.mapping,
            })
            .collect();
        let complete = map.end == VolumeEnd::Complete;
        decide(head, &candidates, complete, password, map.header_encrypted, &mut KdfMeter::new(&options.limits))?
    };
    Ok(Packing::Rar(RarPacking {
        version,
        volume,
        header_encrypted: map.header_encrypted,
        locked,
        first_media,
        borrowable,
        map,
    }))
}

fn zip_packing(
    head: &[u8],
    tail: Option<&[u8]>,
    password: Option<&str>,
    options: &ProbeOptions,
) -> Result<Packing, MapError> {
    let listing = zip::list(head, tail, options.file_len, &options.limits)?;
    let (first_media, borrowable) =
        decide(head, &listing.candidates, listing.complete, password, false, &mut KdfMeter::new(&options.limits))?;
    Ok(Packing::Zip(ZipPacking {
        directory: listing.directory,
        complete: listing.complete,
        spanned: listing.spanned,
        members: listing.candidates.len(),
        first_media,
        borrowable,
    }))
}

fn cipher_kind(params: &CipherParams) -> CipherKind {
    match params {
        CipherParams::Rar5 { .. } => CipherKind::Rar5Aes256,
        CipherParams::Rar4 { .. } => CipherKind::Rar4Aes128,
        CipherParams::Rar4Legacy { .. } => CipherKind::Rar4Legacy,
        CipherParams::ZipCrypto { .. } => CipherKind::ZipCrypto,
        CipherParams::WinZipAes { strength, .. } => CipherKind::WinZipAes { strength: *strength },
        // 7z is not probed (a 7z first article is `Packing::Unknown`).
        CipherParams::SevenZipAes { .. } => CipherKind::Unknown,
    }
}

/// The member's packed bytes present in the head, from the start of its data, when that is the start of the file.
fn data_in_head<'a>(head: &'a [u8], c: &Candidate) -> Option<&'a [u8]> {
    if c.continued {
        return None;
    }
    let data = c.data.as_ref()?;
    let start = usize::try_from(data.start).ok()?;
    let end = usize::try_from(data.end).unwrap_or(usize::MAX).min(head.len());
    head.get(start..end).filter(|b| !b.is_empty())
}

/// The media magic of plain stored data starting in the head.
fn plain_sniff(head: &[u8], c: &Candidate) -> Option<MediaMatch> {
    if c.encrypted || c.method != MapMethod::Stored {
        return None;
    }
    let bytes = data_in_head(head, c)?;
    sniff(&bytes[..bytes.len().min(c.size.map_or(usize::MAX, |s| usize::try_from(s).unwrap_or(usize::MAX)))])
}

/// Picks the first media member (see [`Selection`]).
fn select(head: &[u8], candidates: &[Candidate], complete: bool) -> Option<(usize, Selection, Option<MediaMatch>)> {
    for (i, c) in candidates.iter().enumerate() {
        if c.is_dir {
            continue;
        }
        let sniffed = plain_sniff(head, c);
        if c.name.as_deref().and_then(media_kind_for_name).is_some() {
            return Some((i, Selection::Extension, sniffed));
        }
        if sniffed.is_some() {
            return Some((i, Selection::Magic, sniffed));
        }
    }
    let weight = |c: &Candidate| c.size.or(c.packed_size).unwrap_or(0);
    let largest = |side_files: bool| {
        candidates
            .iter()
            .enumerate()
            .filter(|(_, c)| !c.is_dir && (side_files || !c.name.as_deref().is_some_and(media::is_side_file)))
            // The first of equals wins.
            .fold(None::<(usize, &Candidate)>, |best, (i, c)| match best {
                Some((_, b)) if weight(b) >= weight(c) => best,
                _ => Some((i, c)),
            })
            .map(|(i, _)| i)
    };
    let index = largest(false).or_else(|| if complete { largest(true) } else { None })?;
    Some((index, Selection::Largest, plain_sniff(head, &candidates[index])))
}

fn decide(
    head: &[u8],
    candidates: &[Candidate],
    complete: bool,
    password: Option<&str>,
    header_encrypted: bool,
    kdf: &mut KdfMeter,
) -> Result<(Option<MemberFacts>, Borrowable), MapError> {
    let Some((index, selected, mut sniffed)) = select(head, candidates, complete) else {
        let reason =
            if complete && candidates.iter().all(|c| c.is_dir) { Undecided::NoMembers } else { Undecided::Truncated };
        return Ok((None, Borrowable::Unknown(reason)));
    };
    let c = &candidates[index];
    let name_kind = c.name.as_deref().and_then(media_kind_for_name);
    let stored = c.method == MapMethod::Stored;
    let borrowable = if c.encrypted && c.cipher_kind == Some(CipherKind::Unknown) {
        // ZIP strong encryption, or method 99 without its AES field: the method itself is not known.
        Borrowable::No(NotBorrowable::UnsupportedCipher)
    } else {
        match (c.method, c.encrypted) {
            (MapMethod::Compressed { .. }, _) if c.solid => Borrowable::No(NotBorrowable::Solid),
            (MapMethod::Compressed { .. } | MapMethod::Coders, _) => Borrowable::No(NotBorrowable::Compressed),
            (_, false) if header_encrypted => Borrowable::YesWithPassword(PasswordProof::Headers),
            (_, false) => Borrowable::Yes,
            (_, true) => match c.mapping {
                OutputMapping::CbcBlocks | OutputMapping::Counter { .. } => match password {
                    None => Borrowable::NeedsPassword(PasswordNeed::DataEncrypted),
                    Some(password) => {
                        let (verdict, plain) = judge(head, c, password, name_kind, header_encrypted, kdf)?;
                        sniffed = sniffed.or(plain);
                        verdict
                    }
                },
                OutputMapping::Sequential { .. } => Borrowable::No(NotBorrowable::SequentialCipher),
                _ => Borrowable::No(NotBorrowable::UnsupportedCipher),
            },
        }
    };
    // A largest-member pick from an incomplete listing is tentative: a media member may follow.
    let borrowable = if selected == Selection::Largest && !complete {
        Borrowable::Unknown(Undecided::NoMediaYet)
    } else {
        borrowable
    };
    let packing = match (c.encrypted, c.method) {
        (true, _) => MemberPacking::DataEncrypted { cipher: c.cipher_kind.unwrap_or(CipherKind::Unknown), stored },
        (false, MapMethod::Compressed { id }) => MemberPacking::Compressed { method: id, solid: c.solid },
        (false, _) => MemberPacking::Stored,
    };
    let facts = MemberFacts {
        index,
        raw_name: c.raw_name.clone(),
        name: c.name.clone(),
        size: c.size,
        packed_size: c.packed_size,
        method: c.method,
        packing,
        mapping: c.mapping,
        cipher: c.cipher.clone(),
        continued: c.continued,
        header: c.header.clone(),
        data: c.data.clone(),
        name_kind,
        sniffed,
        selected,
    };
    Ok((Some(facts), borrowable))
}

/// Whether a sniffed kind is the kind a name names, counting each container family as one (a `.mkv` holding WebM,
/// a `.mp4` with a QuickTime brand, a `.ts` written with 192-byte packets).
fn same_family(a: MediaKind, b: MediaKind) -> bool {
    use MediaKind::*;
    let family = |k| match k {
        Mkv | Webm => 0,
        Mp4 | Mov => 1,
        MpegTs | M2ts => 2,
        Avi => 3,
        Asf => 4,
        MpegPs => 5,
    };
    family(a) == family(b)
}

/// The verdict for an encrypted stored member and a password, and the sniffed kind of its decrypted first bytes.
fn judge(
    head: &[u8],
    c: &Candidate,
    password: &str,
    name_kind: Option<MediaKind>,
    header_encrypted: bool,
    kdf: &mut KdfMeter,
) -> Result<(Borrowable, Option<MediaMatch>), MapError> {
    let (verified, plain) = match prove(head, c, password, kdf)? {
        Proved::Wrong => return Ok((Borrowable::NeedsPassword(PasswordNeed::WrongPassword), None)),
        Proved::Unsupported => return Ok((Borrowable::No(NotBorrowable::UnsupportedCipher), None)),
        Proved::Checked { verified, plain } => (verified, plain),
    };
    let sniffed = plain.as_deref().and_then(sniff);
    let plaintext_proof = match (sniffed, name_kind) {
        (Some(found), Some(named)) => same_family(found.kind, named),
        (Some(_), None) => true,
        (None, _) => false,
    };
    let contradicted = sniffed.is_none()
        && match (plain.as_deref(), name_kind) {
            (Some(plain), Some(named)) => {
                let enough = c.size.map_or(MIN_CONTRADICTION, |s| s.min(MIN_CONTRADICTION as u64) as usize);
                plain.len() >= enough && contradicts(named, plain)
            }
            _ => false,
        };
    let verdict = if verified {
        // A RAR 5.0 check value is 8 bytes and stands; a WinZip AES verifier is 2 and the plaintext can still refute it.
        let weak = matches!(c.cipher, Some(CipherParams::WinZipAes { .. }));
        if weak && contradicted {
            Borrowable::NeedsPassword(PasswordNeed::WrongPassword)
        } else {
            Borrowable::YesWithPassword(PasswordProof::Verifier)
        }
    } else if plaintext_proof {
        Borrowable::YesWithPassword(PasswordProof::Plaintext)
    } else if header_encrypted {
        // The headers already proved the password; the data's plaintext does not overrule that.
        Borrowable::YesWithPassword(PasswordProof::Headers)
    } else if contradicted {
        Borrowable::NeedsPassword(PasswordNeed::WrongPassword)
    } else {
        Borrowable::PasswordUnverified
    };
    let sniffed = if matches!(verdict, Borrowable::NeedsPassword(_)) { None } else { sniffed };
    Ok((verdict, sniffed))
}

/// Whether plaintext that sniffs as no media contradicts the media kind a member's name names. Only kinds whose start
/// is mandatory count: Matroska/WebM must start with the EBML magic, AVI with `RIFF`, ASF with its header GUID, and
/// MP4/QuickTime with something that parses as a box header (a size of 0, 1 or at least 8, then four printable
/// bytes), since a fragment may start with `styp`, `moof` and others, or with an `ftyp` too large to sniff. A
/// transport stream may start mid-packet or use other packet sizes, and an MPEG file may be an elementary stream:
/// for those nothing is a contradiction.
fn contradicts(named: MediaKind, plain: &[u8]) -> bool {
    match named {
        MediaKind::Mkv | MediaKind::Webm => !plain.starts_with(&[0x1a, 0x45, 0xdf, 0xa3]),
        MediaKind::Avi => !plain.starts_with(b"RIFF"),
        MediaKind::Asf => !plain.starts_with(&media::ASF_HEADER),
        MediaKind::Mp4 | MediaKind::Mov => {
            let Some(header) = plain.get(..8) else { return false };
            let size = u32::from_be_bytes(header[..4].try_into().unwrap());
            let sized = size == 0 || size == 1 || size >= 8;
            !(sized && header[4..].iter().all(|b| (0x20..0x7f).contains(b)))
        }
        MediaKind::MpegTs | MediaKind::M2ts | MediaKind::MpegPs => false,
    }
}

/// The largest RAR 5.0 KDF count the probe derives (`2^20` rounds); larger counts are an unsupported cipher.
const MAX_KDF_COUNT: u8 = 20;

/// Decrypted bytes needed before a member named as media whose plaintext sniffs as nothing proves a wrong password.
const MIN_CONTRADICTION: usize = 4096;

/// Meters data key derivations against [`ProbeOptions::limits`]: the KDF exponent, blocks per derivation, and
/// blocks over the whole probe.
struct KdfMeter {
    limits: ProgressiveLimits,
    derivation: u64,
    session: u64,
}

impl KdfMeter {
    fn new(limits: &ProgressiveLimits) -> Self {
        Self { limits: limits.clone(), derivation: 0, session: 0 }
    }

    fn start(&mut self) {
        self.derivation = 0;
    }
}

impl crate::crypto::KdfControl for KdfMeter {
    fn charge(&mut self, blocks: u64) -> Result<(), crate::crypto::KdfControlError> {
        use crate::progressive::Resource;
        for (resource, used) in
            [(Resource::KdfDerivationBlocks, &mut self.derivation), (Resource::KdfSessionBlocks, &mut self.session)]
        {
            let limit = self.limits.limit(resource);
            let attempted = used.saturating_add(blocks);
            if attempted > limit {
                return Err(crate::crypto::KdfControlError::Limit { resource, limit, attempted });
            }
            *used = attempted;
        }
        Ok(())
    }
}

fn kdf_limit(error: crate::crypto::KdfControlError) -> MapError {
    match error {
        crate::crypto::KdfControlError::Limit { resource, limit, attempted } => {
            MapError::Limit { resource, limit, attempted }
        }
        crate::crypto::KdfControlError::Canceled => MapError::Source(Box::new(
            crate::progressive::ProgressiveFailure::new(crate::progressive::FailureKind::Canceled),
        )),
    }
}

/// What checking a password against an encrypted stored member gave.
enum Proved {
    /// A check proves the password wrong.
    Wrong,
    /// The cipher's key derivation is outside what is derived (a RAR 5.0 KDF count above 20).
    Unsupported,
    /// Whether a check value matched, and the decrypted first bytes in the head (up to 64 KiB, cut at the size).
    Checked { verified: bool, plain: Option<Vec<u8>> },
}

/// Checks `password` against an encrypted stored member. KDF budgets in the meter are [`MapError::Limit`].
fn prove(head: &[u8], c: &Candidate, password: &str, kdf: &mut KdfMeter) -> Result<Proved, MapError> {
    use crate::progressive::Resource;
    let size_cap = |mut plain: Vec<u8>| {
        if let Some(size) = c.size.and_then(|s| usize::try_from(s).ok()) {
            plain.truncate(size);
        }
        plain
    };
    let cbc = |key: &[u8], iv: &[u8; 16]| {
        let bytes = data_in_head(head, c)?;
        let n = bytes.len().min(SNIFF_DECRYPT) & !15;
        crate::crypto::decrypt_cbc(key, iv, bytes.get(..n).filter(|b| !b.is_empty())?).map(size_cap)
    };
    kdf.start();
    match &c.cipher {
        Some(CipherParams::Rar5 { kdf_count, salt, iv, check, .. }) => {
            use crate::crypto::{ControlledKdfError, Rar5CryptError, derive_rar5_keys_controlled};
            // The derivation supports counts up to 20; within that, the caller's exponent budget applies.
            if *kdf_count > MAX_KDF_COUNT {
                return Ok(Proved::Unsupported);
            }
            let limit = kdf.limits.limit(Resource::KdfExponent);
            if u64::from(*kdf_count) > limit {
                return Err(MapError::Limit {
                    resource: Resource::KdfExponent,
                    limit,
                    attempted: u64::from(*kdf_count),
                });
            }
            match derive_rar5_keys_controlled(password, *kdf_count, salt, *check, kdf) {
                Err(ControlledKdfError::Crypt(Rar5CryptError::WrongPassword)) => Ok(Proved::Wrong),
                Err(ControlledKdfError::Crypt(_)) => Ok(Proved::Unsupported),
                Err(ControlledKdfError::Control(error)) => Err(kdf_limit(error)),
                Ok(keys) => Ok(Proved::Checked {
                    verified: keys.evidence == crate::error::RarPasswordEvidence::VerifierMatched,
                    plain: iv.as_ref().and_then(|iv| cbc(&keys.key, iv)),
                }),
            }
        }
        Some(CipherParams::Rar4 { salt }) => {
            let (key, iv) = crate::crypto::derive_rar4_key_iv_controlled(password, salt, kdf).map_err(kdf_limit)?;
            Ok(Proved::Checked { verified: false, plain: cbc(&key, &iv) })
        }
        Some(CipherParams::WinZipAes { strength, salt, verifier, .. }) => {
            let key_len = (usize::from(*strength) + 1) * 8;
            let Some(derived) = crate::crypto::aes_derive(password.as_bytes(), salt, key_len) else {
                return Ok(Proved::Unsupported);
            };
            if derived.get(key_len * 2..) != Some(verifier.as_slice()) {
                return Ok(Proved::Wrong);
            }
            let prefix = salt.len() + 2;
            let plain = data_in_head(head, c).and_then(|bytes| {
                let body = bytes.get(prefix..)?;
                crate::crypto::decrypt_winzip_ctr(&derived[..key_len], &body[..body.len().min(SNIFF_DECRYPT)])
                    .map(size_cap)
            });
            Ok(Proved::Checked { verified: true, plain })
        }
        _ => Ok(Proved::Checked { verified: false, plain: None }),
    }
}
