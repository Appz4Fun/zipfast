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

//! Bounded metadata for a RAR4 or RAR5 volume set. A session owns the read-only
//! files used for its catalogue. Member metadata describes the headers,
//! including any known issue that would prevent reading a payload.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::batch::read_at_detailed;
use crate::error::{
    Error, IoOperation, RarFailure, RarFault, RarIntegrityReason, RarPasswordEvidence, RarResource, RarResult,
    RarScope, RarUnsupported,
};
use crate::extract::{Cancellation, RarRunError, RarRunSummary};
use crate::volume::next_volume;

use super::physical::{PhysicalMember as Member, PhysicalModel, PhysicalPart as Part, continuation_issue};
use super::reader::{Block, Volume, read_failure};
use super::source::SourceStamp;
use super::{
    FileHeader, FileWire, MHFL_LOCK, MHFL_PROTECT, MHFL_VOLNUMBER, MainHeader, MemberCrypt, RarTime, Redirection,
};

mod selection;
#[cfg(unix)]
pub use selection::control::*;
pub use selection::{RarDecodeLimits, RarPrintOptions, RarSelection};

const MAX_VOLUMES: u64 = 4_096;

/// Independent limits on catalogue work and storage.
#[derive(Clone, Copy, Debug)]
pub struct RarCatalogueLimits {
    /// Retained descriptors, with a maximum of 4,096.
    pub volumes: u64,
    pub entries: u64,
    pub name_bytes: u64,
    /// Retained catalogue bytes. The default, [`Self::DEFAULT_CAPACITY`], is a floor that grows with what the
    /// archive's headers justify: [`Self::CAPACITY_PER_BLOCK`] bytes for each header block read so far and
    /// [`Self::CAPACITY_PER_HEADER_BYTE`] for each header byte, so it stays bounded by [`Self::header_blocks`] and
    /// [`Self::read_bytes`]. Any other value is an exact cap.
    pub capacity: u64,
    pub parts: u64,
    pub header_blocks: u64,
    pub read_bytes: u64,
}

impl RarCatalogueLimits {
    /// The default [`Self::capacity`] (128 MiB), which scales with the archive; see the field.
    pub const DEFAULT_CAPACITY: u64 = 128 << 20;
    /// What one header block can make the catalogue retain, with room for each vector to double: a member, a part,
    /// a listed header and an issue, plus a header kept on its own (a continuation or service header).
    pub const CAPACITY_PER_BLOCK: u64 = 2
        * (size_of::<Member>() + size_of::<Part>() + size_of::<HeaderRecord>() + size_of::<RarFailure>()) as u64
        + size_of::<FileHeader>() as u64;
    /// What one header byte read can make the catalogue retain: its decoded and stored name, redirection target,
    /// SubData and extra records, each a few copies at most.
    pub const CAPACITY_PER_HEADER_BYTE: u64 = 8;

    /// The capacity allowed once the catalogue has charged `usage`: exact unless [`Self::capacity`] is the default.
    pub(crate) fn capacity_for(&self, usage: &RarCatalogueUsage) -> u64 {
        if self.capacity != Self::DEFAULT_CAPACITY {
            return self.capacity;
        }
        let blocks = usage.header_blocks.saturating_mul(Self::CAPACITY_PER_BLOCK);
        let bytes = usage.read_bytes.saturating_mul(Self::CAPACITY_PER_HEADER_BYTE);
        Self::DEFAULT_CAPACITY.max(blocks.saturating_add(bytes))
    }
}

impl Default for RarCatalogueLimits {
    fn default() -> Self {
        Self {
            volumes: 64,
            entries: 1_000_000,
            name_bytes: 64 << 20,
            capacity: Self::DEFAULT_CAPACITY,
            parts: 1_000_000,
            header_blocks: 2_000_000,
            read_bytes: 512 << 20,
        }
    }
}

/// Options for opening a catalogue.
#[derive(Clone)]
pub struct RarSessionOptions {
    pub limits: RarCatalogueLimits,
    pub cancel: Cancellation,
    /// Follow the end header's "more volumes" mark to later volumes (the default). With false the session holds
    /// only the named volume, as UnRAR's `l` does without `-v`: a member split past it is catalogued as incomplete.
    pub follow_volumes: bool,
    /// Opened at a later volume whose first member continues from an earlier one, start the catalogue at the set's
    /// first volume instead, as UnRAR 7.30 does for `x`/`t` from a later volume, when every volume back to one that
    /// starts no continued member exists and opens (otherwise the named volume, as before).
    /// [`RarSession::restarted_from`] says where it started. Off by default.
    pub restart_from_first_volume: bool,
    /// What a damaged header does to the catalogue ([`crate::extract::Options::damaged_input`]): refused (the
    /// default), or read past as UnRAR 7.30 does (`Salvage`), or also searched past (`Resync`). What was read past
    /// is in [`RarArchiveMetadata::damaged_headers`]; the members catalogued past it list and extract as any other.
    pub damaged_input: crate::extract::DamagedInput,
}

impl Default for RarSessionOptions {
    fn default() -> Self {
        Self {
            limits: RarCatalogueLimits::default(),
            cancel: Cancellation::default(),
            follow_volumes: true,
            restart_from_first_volume: false,
            damaged_input: Default::default(),
        }
    }
}

/// Work and retained capacity used when opening the catalogue.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RarCatalogueUsage {
    pub volumes: u64,
    pub entries: u64,
    pub name_bytes: u64,
    pub capacity: u64,
    pub parts: u64,
    pub header_blocks: u64,
    pub read_bytes: u64,
}

/// Summary of a RAR catalogue.
#[derive(Debug, Default)]
pub struct RarArchiveMetadata {
    format: super::RarFormat,
    volumes: usize,
    orphan_continuations: u64,
    missing_volume: Option<PathBuf>,
    damaged_headers: Vec<crate::extract::HeaderDamage>,
}

impl RarArchiveMetadata {
    /// Headers the catalogue read past under [`RarSessionOptions::damaged_input`] (at most 4096 kept). Non-empty
    /// means the headers are damaged: UnRAR says "Corrupt header is found" and 7-Zip "Headers Error".
    pub fn damaged_headers(&self) -> &[crate::extract::HeaderDamage] {
        &self.damaged_headers
    }

    /// The next volume the set names when it wasn't found: the catalogue ends at the volume before it, and a member
    /// split into it fails on its own ([`RarFailure::MissingVolume`]).
    pub fn missing_volume(&self) -> Option<&Path> {
        self.missing_volume.as_deref()
    }

    pub fn format(&self) -> super::RarFormat {
        self.format
    }

    pub fn volume_count(&self) -> usize {
        self.volumes
    }

    pub fn orphan_continuations(&self) -> u64 {
        self.orphan_continuations
    }
}

/// Header metadata for an observed volume.
#[derive(Debug)]
pub struct RarVolumeMetadata {
    format: super::RarFormat,
    main: MainHeader,
    encrypted_headers: bool,
    sfx_size: u64,
    end: Option<VolumeEnd>,
    end_record: Option<super::RarEndRecord>,
    headers: std::ops::Range<usize>,
    comment: Option<usize>,
    quick_open: RarQuickOpen,
}

/// What a RAR 5.0 volume's quick open locator points at. UnRAR reads the block header at the main header's start
/// plus the locator's quick open offset when it opens a volume: a header whose CRC fails there makes it report
/// "Corrupt header is found" and "Main archive header is corrupt" (exit code 3), and one running past the end of the
/// volume "Unexpected end of archive" (exit code 1). Either way it goes on listing and extracting. The recovery
/// record offset is not read at open.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum RarQuickOpen {
    /// No locator, no quick open offset, or an offset of 0; and every RAR 4.x volume.
    #[default]
    Absent,
    /// A block header with a valid CRC starts at the offset.
    Valid,
    /// The block header at the offset fails its CRC (UnRAR: main archive header corrupt).
    Corrupt,
    /// The block header at the offset, or the offset itself, runs past the end of the volume (UnRAR: unexpected end
    /// of archive).
    Truncated,
    /// Not checked: the headers are encrypted, so the block at the offset is ciphertext.
    Encrypted,
    /// Not checked: reading the block header at the offset would exceed the catalogue's read budget
    /// (`RarCatalogueLimits::read_bytes`).
    Unchecked,
}

#[derive(Clone, Copy, Debug)]
struct VolumeEnd {
    more_volumes: bool,
    volume_number: Option<u64>,
}

impl RarVolumeMetadata {
    pub fn format(&self) -> super::RarFormat {
        self.format
    }

    /// The normalized main header flags (`MHFL_*`). For RAR 4.x only the
    /// volume and solid bits are carried over; see [`Self::rar4_flags`].
    pub fn flags(&self) -> u64 {
        self.main.flags
    }

    /// The RAR 4.x main header's own flags (`MHD_*`) as stored. None for RAR 5.0.
    pub fn rar4_flags(&self) -> Option<u16> {
        self.main.rar4_flags
    }

    /// Whether the set uses `NAME.partN.rar` volume names: always for RAR 5.0,
    /// and for RAR 4.x when the main header sets `MHD_NEWNUMBERING` (0x0010).
    /// UnRAR's `VolNameToFirstName` uses it to tell `.partN.rar` numbering from
    /// the `.rar`, `.r00`, `.r01`, ... scheme.
    pub fn new_numbering(&self) -> bool {
        match self.format {
            super::RarFormat::Rar5 => true,
            super::RarFormat::Rar4 => self.main.rar4_flags.is_some_and(|flags| flags & super::MHD_NEWNUMBERING != 0),
        }
    }

    pub fn declared_number(&self) -> Option<u64> {
        (self.main.flags & MHFL_VOLNUMBER != 0).then_some(self.main.volume_number)
    }

    pub fn encrypted_headers(&self) -> bool {
        self.encrypted_headers
    }

    /// RAR 5.0: what the main header's quick open locator points at; see [`RarQuickOpen`].
    pub fn quick_open(&self) -> RarQuickOpen {
        self.quick_open
    }

    /// The end of archive header's flags, CRC, volume number and offset, when the volume has one.
    pub fn end_record(&self) -> Option<super::RarEndRecord> {
        self.end_record
    }

    /// RAR 5.0: the main header's locator record (quick open and recovery record offsets).
    pub fn main_locator(&self) -> Option<super::RarLocator> {
        self.main.locator
    }

    /// RAR 5.0: the main header's extra records in stored order.
    pub fn main_extra_records(&self) -> &[super::RarExtraRecord] {
        &self.main.extra_records
    }

    /// Whether the main header marks the archive solid (`MHD_SOLID`, `MHFL_SOLID`).
    pub fn is_solid(&self) -> bool {
        self.main.is_solid()
    }

    /// Whether the main header marks this file as a volume (`MHD_VOLUME`, `MHFL_VOLUME`).
    pub fn is_volume(&self) -> bool {
        self.main.is_volume()
    }

    /// Whether the archive is locked against changes (`MHD_LOCK` 0x0004, `MHFL_LOCK` 0x0010).
    pub fn locked(&self) -> bool {
        match self.main.rar4_flags {
            Some(flags) => flags & 0x0004 != 0,
            None => self.main.flags & MHFL_LOCK != 0,
        }
    }

    /// Whether the main header announces a recovery record (`MHD_PROTECT` 0x0040, `MHFL_PROTECT` 0x0008). UnRAR
    /// prints "recovery record" on its details line from this flag.
    pub fn protected(&self) -> bool {
        match self.main.rar4_flags {
            Some(flags) => flags & 0x0040 != 0,
            None => self.main.flags & MHFL_PROTECT != 0,
        }
    }

    /// Whether this is the first volume: RAR 4.x `MHD_FIRSTVOLUME` (0x0100, written by RAR 3.0 and later), or a RAR
    /// 5.0 volume with no volume number. Always true for a file that is not a volume.
    pub fn first_volume(&self) -> bool {
        if !self.is_volume() {
            return true;
        }
        match self.main.rar4_flags {
            Some(flags) => flags & 0x0100 != 0,
            None => self.main.flags & MHFL_VOLNUMBER == 0,
        }
    }

    /// Bytes before the archive signature, such as a self-extracting module.
    pub fn sfx_size(&self) -> u64 {
        self.sfx_size
    }

    /// The zero-based volume number a RAR 5.0 volume declares in its main header; 0 for a first volume, which stores
    /// none. UnRAR's details line prints it plus one ("RAR 5, volume N"). None for RAR 4.x and for a RAR 5.0 file
    /// that is not a volume.
    pub fn rar5_volume_number(&self) -> Option<u64> {
        (self.format == super::RarFormat::Rar5 && self.is_volume()).then(|| self.declared_number().unwrap_or(0))
    }

    /// The zero-based volume number in a RAR 4.x end-of-archive header (`EARC_VOLNUMBER`, written when
    /// [`Self::rar4_store_vol_number`] holds). UnRAR's listing footer prints it plus one ("volume N").
    pub fn rar4_end_volume_number(&self) -> Option<u64> {
        (self.format == super::RarFormat::Rar4).then(|| self.end.and_then(|end| end.volume_number)).flatten()
    }

    /// Whether the RAR 4.x end-of-archive header stores a volume number (`EARC_VOLNUMBER`, UnRAR's
    /// `StoreVolNumber`). False for RAR 5.0 and when the volume has no end header.
    pub fn rar4_store_vol_number(&self) -> bool {
        self.rar4_end_volume_number().is_some()
    }

    /// Whether the volume has an end-of-archive header. A volume cut short before it has none.
    pub fn has_end_header(&self) -> bool {
        self.end.is_some()
    }

    /// Whether the end-of-archive header marks a later volume. False without an end header.
    pub fn more_volumes(&self) -> bool {
        self.end.is_some_and(|end| end.more_volumes)
    }

    /// The original archive name a RAR 5.0 main header stores (`-ams`), as raw bytes (UTF-8 in practice).
    pub fn original_name(&self) -> Option<&[u8]> {
        self.main.original_name.as_deref()
    }

    /// The original archive time a RAR 5.0 main header stores (`-ams`).
    pub fn original_time(&self) -> Option<RarTime> {
        self.main.original_time
    }

    /// Positions of this volume's headers in [`RarSession::headers`].
    pub fn header_range(&self) -> std::ops::Range<usize> {
        self.headers.clone()
    }

    /// Position in [`RarSession::headers`] of the archive comment header (the service header named `CMT`) in this
    /// volume, if any. [`RarSession::comment`] reads its text.
    pub fn comment_header(&self) -> Option<usize> {
        self.comment
    }
}

struct HeaderRecord {
    volume: usize,
    header: StoredHeader,
    raw_name: Option<Arc<Vec<u8>>>,
}

/// Where a listed header's fields live. The header that starts a member is that member's own
/// ([`PhysicalModel::members`]), so it is kept once; a continuation, orphan or service header is kept here.
enum StoredHeader {
    Member(usize),
    Owned(Box<FileHeader>),
}

impl HeaderRecord {
    fn header<'a>(&'a self, members: &'a [Member]) -> &'a FileHeader {
        match &self.header {
            StoredHeader::Member(index) => &members[*index].header,
            StoredHeader::Owned(header) => header,
        }
    }
}

/// One file or service header as stored in a volume, without merging the parts of a split member. Listing every
/// header of [`RarSession::headers`] in order gives UnRAR's `lt` and `v` output, orphan continuations included.
///
/// UnRAR's totals add [`Self::packed_size`] for every file header, but [`Self::unpacked_size`] and the file count
/// only for headers where [`Self::split_before`] is false.
#[derive(Clone, Copy)]
pub struct RarHeader<'a> {
    record: &'a HeaderRecord,
    header: &'a FileHeader,
}

impl<'a> RarHeader<'a> {
    fn new(record: &'a HeaderRecord, members: &'a [Member]) -> Self {
        Self { record, header: record.header(members) }
    }

    /// Zero-based volume position in the session.
    pub fn volume(&self) -> usize {
        self.record.volume
    }

    pub fn format(&self) -> super::RarFormat {
        self.header.format
    }

    /// Whether this is a service header (RAR 5.0 type 3, RAR 4.x `NEWSUB_HEAD`) rather than a file header.
    pub fn is_service(&self) -> bool {
        self.header.service
    }

    /// RAR 5.0: the Unix owner record (owner and group names, numeric ids), when the header has one.
    pub fn owner(&self) -> Option<&'a super::UnixOwner> {
        self.header.owner.as_ref()
    }

    /// For a service header, its type name: `CMT`, `QO`, `RR`, `ACL`, `STM` or another.
    pub fn service_name(&self) -> Option<&'a str> {
        self.is_service().then_some(self.header.name.as_str())
    }

    /// A service header's SubData as stored, such as the stream name of an `STM` header (UnRAR's "Target"; UTF-8
    /// in RAR 5.0, UTF-16LE in RAR 4.x). Empty for file headers.
    pub fn service_data(&self) -> &'a [u8] {
        &self.header.sub_data
    }

    /// The part continues a member from an earlier volume.
    pub fn split_before(&self) -> bool {
        self.header.split_before()
    }

    /// The member continues in a later volume.
    pub fn split_after(&self) -> bool {
        self.header.split_after()
    }

    /// Stored name bytes, including RAR 4.x legacy and Unicode encoding.
    pub fn raw_name(&self) -> &'a [u8] {
        match &self.record.raw_name {
            Some(name) => name,
            None => self.header.name.as_bytes(),
        }
    }

    /// Name decoded by the header parser. RAR 4.x legacy names that are not UTF-8 decode to an empty string; use
    /// [`Self::raw_name`].
    pub fn name(&self) -> &'a str {
        &self.header.name
    }

    /// The name UnRAR on Unix gives a RAR 5.0 header, as raw `wchar_t` units; see [`RarMember::unrar_name`].
    pub fn unrar_name(&self) -> Option<Vec<u32>> {
        (self.format() == super::RarFormat::Rar5).then(|| super::unrar_name(self.raw_name()))
    }

    /// The declared unpacked size of the whole member, or None when the header marks it unknown.
    pub fn unpacked_size(&self) -> Option<u64> {
        (!self.header.size_unknown()).then_some(self.header.unpacked_size)
    }

    /// Packed bytes of this part in this volume.
    pub fn packed_size(&self) -> u64 {
        self.header.packed_size
    }

    /// Offset of this part's data in its volume.
    pub fn data_offset(&self) -> u64 {
        self.header.data_at
    }

    pub fn attributes(&self) -> u64 {
        self.header.attributes
    }

    /// Normalized host: 0 Windows (RAR 4.x MS-DOS, OS/2, Win32), 1 Unix, 2 other. RAR 4.x keeps its own value in
    /// [`super::Rar4Metadata::host`].
    pub fn host_os(&self) -> u64 {
        self.header.host_os
    }

    pub fn rar4_metadata(&self) -> Option<super::Rar4Metadata> {
        self.header.rar4
    }

    pub fn modified(&self) -> Option<RarTime> {
        let header = &self.header;
        header.mtime.map(|seconds| RarTime {
            seconds,
            nanos: header.mtime_nanos,
            resolution_nanos: header.mtime_resolution,
        })
    }

    pub fn created(&self) -> Option<RarTime> {
        self.header.ctime
    }

    pub fn accessed(&self) -> Option<RarTime> {
        self.header.atime
    }

    /// Which clock the times were read from: RAR 4.x local wall clock, RAR 5.0 UTC.
    pub fn time_origin(&self) -> crate::extract::MtimeOrigin {
        match self.format() {
            super::RarFormat::Rar4 => crate::extract::MtimeOrigin::LocalWallClock,
            super::RarFormat::Rar5 => crate::extract::MtimeOrigin::Utc,
        }
    }

    /// Declared checks. A part with [`Self::split_after`] set checks its own packed bytes, not the member.
    pub fn checks(&self) -> RarChecks {
        let header = &self.header;
        RarChecks { crc32: header.crc32, blake2sp: header.blake2sp, keyed: header.crypt.is_some_and(|c| c.tweaked_crc) }
    }

    /// The CRC-32 of the member's unpacked data, declared by a final part.
    pub fn crc32(&self) -> Option<u32> {
        self.header.crc32.filter(|_| !self.split_after())
    }

    /// The CRC-32 of this part's packed data, declared by a part with a later continuation (UnRAR's "Pack-CRC32").
    /// A RAR 1.5 part (unpack version under 20) lists its stored field here as UnRAR does, although neither UnRAR
    /// nor zipfast checks it there, so [`Self::checks`] leaves it out.
    pub fn pack_crc32(&self) -> Option<u32> {
        let header = &self.header;
        header
            .crc32
            .or_else(|| header.rar4.filter(|r| r.unpack_version < 20).map(|r| r.stored_crc))
            .filter(|_| self.split_after())
    }

    pub fn blake2sp(&self) -> Option<[u8; 32]> {
        self.header.blake2sp
    }

    /// Compression level: 0 is stored, 1 to 5 are `-m1` to `-m5`.
    pub fn method(&self) -> u8 {
        self.header.method
    }

    /// RAR 5.0 algorithm: 0 for RAR 5.0 ("v50"), 1 for RAR 7.0 ("v70"). RAR 4.x keeps its unpack version in
    /// [`super::Rar4Metadata::unpack_version`].
    pub fn algorithm(&self) -> u8 {
        self.header.algorithm
    }

    /// The file version number of an older revision kept by `-ver` (RAR 5.0 version record).
    pub fn version(&self) -> Option<u64> {
        self.header.version
    }

    pub fn dictionary(&self) -> u64 {
        self.header.dictionary
    }

    /// The header's own solid flag (RAR 4.x `LHD_SOLID`, RAR 5.0 compression info), which UnRAR lists as "solid".
    /// The first member of a RAR 4.x solid archive does not set it.
    pub fn solid(&self) -> bool {
        self.header.solid
    }

    pub fn encrypted(&self) -> bool {
        self.header.encrypted
    }

    pub fn is_directory(&self) -> bool {
        self.header.is_dir()
    }

    pub fn redirection(&self) -> Option<&'a Redirection> {
        self.header.redirection.as_ref()
    }
}

/// Checksum values declared by a part header. These describe packed bytes
/// for intermediate parts and decoded bytes for a final part.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RarChecks {
    pub crc32: Option<u32>,
    pub blake2sp: Option<[u8; 32]>,
    pub keyed: bool,
}

/// Observed data range for one associated part.
#[derive(Clone, Copy)]
pub struct RarPart<'a>(&'a Part);

impl RarPart<'_> {
    /// Zero-based volume position in the session.
    pub fn volume(&self) -> usize {
        self.0.volume
    }

    pub fn data_offset(&self) -> u64 {
        self.0.data_offset
    }

    pub fn packed_size(&self) -> u64 {
        self.0.packed_size
    }

    pub fn checks(&self) -> RarChecks {
        self.0.checks
    }
}

/// Borrowed metadata for one logical member, in archive order.
#[derive(Clone, Copy)]
pub struct RarMember<'a> {
    ordinal: u64,
    member: &'a Member,
    parts: &'a [Part],
    issue: Option<&'a RarFailure>,
}

impl<'a> RarMember<'a> {
    pub fn format(&self) -> super::RarFormat {
        self.member.header.format
    }

    pub fn rar4_metadata(&self) -> Option<super::Rar4Metadata> {
        self.member.header.rar4
    }

    /// Original wire name, including RAR4 legacy and Unicode encoding.
    pub fn raw_name(&self) -> &'a [u8] {
        &self.member.wire.name
    }

    /// The name UnRAR on Unix gives a RAR5 member, as raw `wchar_t` units; see [`super::unrar_name`]. It can differ
    /// from [`Self::name`] when the stored bytes aren't valid UTF-8: UnRAR keeps overlong forms and encoded surrogates
    /// and stops at the first malformed byte, where `name()` puts U+FFFD. [`super::unrar_name_to_string`] turns it
    /// into text when every unit is a scalar value. None for RAR4 members, whose names UnRAR decodes another way.
    pub fn unrar_name(&self) -> Option<Vec<u32>> {
        (self.format() == super::RarFormat::Rar5).then(|| super::unrar_name(self.raw_name()))
    }

    /// Raw RAR5 compression bits. Returns None for RAR4 members.
    pub fn rar5_compression_info(&self) -> Option<u64> {
        (self.format() == super::RarFormat::Rar5).then_some(self.member.wire.compression)
    }

    pub fn ordinal(&self) -> u64 {
        self.ordinal
    }

    /// Name decoded by the member format parser. Original bytes remain available through raw_name().
    pub fn name(&self) -> &'a str {
        &self.member.header.name
    }

    pub fn unpacked_size(&self) -> Option<u64> {
        self.member.unpacked_size
    }

    pub fn packed_size(&self) -> u64 {
        self.member.packed_size
    }

    pub fn is_directory(&self) -> bool {
        self.member.header.is_dir()
    }

    pub fn redirection(&self) -> Option<&'a Redirection> {
        self.member.header.redirection.as_ref()
    }

    /// RAR 5.0: the file header's extra records in stored order, type and bytes.
    pub fn extra_records(&self) -> &'a [super::RarExtraRecord] {
        &self.member.header.extra_records
    }

    /// RAR 5.0: the redirection record's raw flags (0x1: the link target is a directory). Zero without one.
    pub fn redirection_flags(&self) -> u64 {
        self.member.header.redirection_flags
    }

    /// RAR 5.0: the file header's raw file flags (0x1 directory, 0x2 time, 0x4 CRC, 0x8 unknown size). None for
    /// RAR4 members.
    pub fn rar5_file_flags(&self) -> Option<u64> {
        (self.format() == super::RarFormat::Rar5).then_some(self.member.header.file_flags)
    }

    pub fn version(&self) -> Option<u64> {
        self.member.header.version
    }

    /// The name as UnRAR shows it: an older revision's version number appended after `;` (`notes.txt;2`), the name
    /// [`super::RarSelection::with_versions`] extracts it under.
    pub fn display_name(&self) -> std::borrow::Cow<'_, str> {
        self.member.header.display_name()
    }

    pub fn modified(&self) -> Option<(i64, u32)> {
        let header = &self.member.header;
        header.mtime.map(|seconds| (seconds, header.mtime_nanos))
    }

    pub fn attributes(&self) -> u64 {
        self.member.header.attributes
    }

    pub fn host_os(&self) -> u64 {
        self.member.header.host_os
    }

    pub fn method(&self) -> u8 {
        self.member.header.method
    }

    /// RAR5 algorithm value. For RAR4, use rar4_metadata().unpack_version.
    pub fn algorithm(&self) -> u8 {
        self.member.header.algorithm
    }

    /// RAR5 wire bits, or zero for RAR4. Prefer rar5_compression_info() for format-aware callers.
    pub fn compression_info(&self) -> u64 {
        self.member.wire.compression
    }

    pub fn dictionary(&self) -> u64 {
        self.member.header.dictionary
    }

    pub fn solid(&self) -> bool {
        self.member.header.solid
    }

    pub fn encrypted(&self) -> bool {
        self.member.header.encrypted
    }

    /// RAR 5.0: the file encryption record's version, flags and KDF count as stored, for a 7-Zip-style method
    /// string (`AES:15:3`). None for unencrypted and RAR4 members.
    pub fn rar5_crypt_record(&self) -> Option<super::Rar5CryptRecord> {
        self.member.header.crypt_record
    }

    /// Whether the observed parts include a final header.
    pub fn is_complete(&self) -> bool {
        self.member.complete
    }

    /// First issue discovered in the member's headers that blocks decoding.
    pub fn payload_issue(&self) -> Option<&'a RarFailure> {
        self.issue
    }

    pub fn final_checks(&self) -> Option<RarChecks> {
        self.is_complete().then(|| self.parts.last().expect("each member has a part").checks)
    }

    pub fn parts(&self) -> impl ExactSizeIterator<Item = RarPart<'a>> {
        self.parts.iter().map(RarPart)
    }

    /// Where byte `offset` of a stored, unencrypted member's data lies: `(volume, offset within that volume)`, the
    /// volume as [`RarPart::volume`] counts it. The member's bytes are its parts' packed bytes in order, so this
    /// walks [`Self::parts`]; parts of zero length are passed over, and an offset on a part boundary is the first
    /// byte of the next part.
    ///
    /// None for an offset at or past the unpacked size, a directory, a compressed member, or an encrypted one:
    /// its packed bytes are AES-CBC ciphertext, padded to whole 16-byte blocks, and decrypting byte `offset` needs
    /// its whole block and the block before it as IV. [`crate::map::MapMember::packed_spans`] gives those spans.
    pub fn locate(&self, offset: u64) -> Option<(usize, u64)> {
        let header = &self.member.header;
        // the member's resolved size: a first part may mark it unknown and a later one state it; with no size
        // known at all, the part walk bounds the offset
        if header.method != 0
            || header.encrypted
            || header.is_dir()
            || self.member.unpacked_size.is_some_and(|s| offset >= s)
        {
            return None;
        }
        let mut start = 0u64;
        for part in self.parts {
            let end = start.checked_add(part.packed_size)?;
            if offset < end {
                return Some((part.volume, part.data_offset.checked_add(offset - start)?));
            }
            start = end;
        }
        None
    }
}

struct HeldVolume {
    metadata: RarVolumeMetadata,
    file: File,
    path: PathBuf,
    stamp: SourceStamp,
}

/// A read-only RAR catalogue with the original volume descriptors held open.
pub struct RarSession {
    archive: RarArchiveMetadata,
    volumes: Vec<HeldVolume>,
    model: PhysicalModel,
    headers: Vec<HeaderRecord>,
    issues: Vec<RarFailure>,
    usage: RarCatalogueUsage,
    password: String,
    /// Whether a password was given at all: an empty one is still tried on RAR 3.x members.
    password_given: bool,
    /// RAR 5.0 keys derived for the password, by salt and count: every selection of the session shares them.
    rar5_keys: crate::crypto::SharedRar5Keys,
    options: RarSessionOptions,
    token: Arc<selection::SessionToken>,
    invalid_binding: Option<Arc<RarFailure>>,
    restarted_from: Option<PathBuf>,
    members_before_named: u64,
}

impl RarSession {
    /// The session's RAR 5.0 key cache.
    pub(crate) fn rar5_keys(&self) -> std::sync::MutexGuard<'_, crate::crypto::Rar5KeyCache> {
        self.rar5_keys.lock()
    }

    /// The earlier volume the catalogue started at instead of the one named, with
    /// [`RarSessionOptions::restart_from_first_volume`]; None when it started at the named volume.
    pub fn restarted_from(&self) -> Option<&Path> {
        self.restarted_from.as_deref()
    }

    /// How many members start in the volumes before the one named, after a restart (0 without one): UnRAR's
    /// listing positions, which count from the volume named, are the catalogue's positions minus this.
    pub fn members_before_named(&self) -> u64 {
        self.members_before_named
    }

    /// Read the volume headers and check their source binding. Member
    /// payloads are neither decoded nor checked by catalogue construction.
    #[allow(clippy::result_large_err, reason = "reuse the typed RAR error with partial counts")]
    pub fn open(first: &Path, password: Option<&str>, options: RarSessionOptions) -> Result<Self, RarRunError> {
        Self::open_inner(first, password, options, None)
    }

    /// Open a catalogue while rejecting an output alias of each input file
    /// actually opened, before parsing that file's headers. Output identity is
    /// captured once from this descriptor; no output bytes are written.
    ///
    /// Keep the descriptor open and use that same file for output. A successful
    /// session can recheck its held source bindings and output identity with
    /// [`Self::check_output_file`] before writing. This check does not cover
    /// archive paths that catalogue construction never opens.
    #[cfg(unix)]
    #[allow(clippy::result_large_err, reason = "reuse the typed RAR error with partial counts")]
    pub fn open_with_output_file(
        first: &Path,
        password: Option<&str>,
        options: RarSessionOptions,
        output: &File,
    ) -> Result<Self, RarRunError> {
        Self::open_inner(first, password, options, Some(output))
    }

    #[allow(clippy::result_large_err, reason = "reuse the typed RAR error with partial counts")]
    fn open_inner(
        first: &Path,
        password: Option<&str>,
        options: RarSessionOptions,
        _output: Option<&File>,
    ) -> Result<Self, RarRunError> {
        let mut catalogue = Catalogue {
            session: Self {
                archive: RarArchiveMetadata::default(),
                volumes: Vec::new(),
                model: PhysicalModel::default(),
                headers: Vec::new(),
                issues: Vec::new(),
                usage: RarCatalogueUsage::default(),
                password: String::new(),
                password_given: false,
                rar5_keys: Default::default(),
                options: options.clone(),
                token: Arc::new(selection::SessionToken { _private: 0 }),
                invalid_binding: None,
                restarted_from: None,
                members_before_named: 0,
            },
            options,
            owned_capacity: 0,
            output_identity: None,
            pending: false,
            history_barrier: false,
            chain: None,
            last_compressed: None,
        };
        let result = (|| {
            check_cancel(&catalogue.options.cancel)?;
            #[cfg(unix)]
            if let Some(output) = _output {
                use std::os::unix::fs::MetadataExt;
                let metadata = output
                    .metadata()
                    .map_err(|source| RarFault::output(IoOperation::Metadata, None, None, source, false))?;
                catalogue.output_identity = Some((metadata.dev(), metadata.ino()));
            }
            catalogue.session.password_given = password.is_some();
            let password = password.unwrap_or_default();
            limit(password.len() as u64, catalogue.allowed(), RarResource::CatalogueCapacity)?;
            catalogue.session.password.try_reserve_exact(password.len()).map_err(|_| allocation())?;
            catalogue.session.password.push_str(password);
            catalogue.owned_capacity = catalogue.session.password.capacity() as u64;
            catalogue.update_capacity()?;
            // Restart discovery reads under the catalogue's budget and cancellation, with its source checks.
            let restart = if catalogue.options.restart_from_first_volume && catalogue.options.follow_volumes {
                catalogue.restart_volume(first, Some(password))?
            } else {
                None
            };
            catalogue.scan(restart.as_deref().unwrap_or(first), Some(password))?;
            if let Some(from) = restart {
                catalogue.session.members_before_named = catalogue.members_before(first);
                catalogue.session.restarted_from = Some(from);
            }
            catalogue.shrink()?;
            RarResult::Ok(())
        })();
        if let Err(fault) = result {
            let partial = RarRunSummary {
                encountered: catalogue.session.usage.entries,
                volumes: catalogue.session.usage.volumes,
                ..RarRunSummary::default()
            };
            return Err(RarRunError {
                partial,
                entry: None,
                failure: Arc::from(fault.failure),
                partial_member_bytes: 0,
            });
        }
        Ok(catalogue.session)
    }

    pub fn archive(&self) -> &RarArchiveMetadata {
        &self.archive
    }

    pub fn volumes(&self) -> impl ExactSizeIterator<Item = &RarVolumeMetadata> {
        self.volumes.iter().map(|volume| &volume.metadata)
    }

    /// The path of each volume, in the order of [`Self::volumes`].
    pub fn volume_paths(&self) -> impl ExactSizeIterator<Item = &Path> {
        self.volumes.iter().map(|volume| volume.path.as_path())
    }

    pub fn entries(&self) -> impl ExactSizeIterator<Item = RarMember<'_>> {
        self.model.members.iter().enumerate().map(|(index, member)| RarMember {
            ordinal: index as u64,
            member,
            parts: &self.model.parts[member.parts.clone()],
            issue: member.issue.map(|index| &self.issues[index]),
        })
    }

    pub fn usage(&self) -> RarCatalogueUsage {
        self.usage
    }

    /// Every file and service header in volume order, orphan continuations and each part of a split member
    /// included. [`RarVolumeMetadata::header_range`] selects one volume's headers.
    pub fn headers(&self) -> impl ExactSizeIterator<Item = RarHeader<'_>> {
        self.headers.iter().map(|record| RarHeader::new(record, &self.model.members))
    }

    /// The headers of one volume, in order. Empty for a volume index past the end.
    pub fn volume_headers(&self, volume: usize) -> impl ExactSizeIterator<Item = RarHeader<'_>> {
        let range = self.volumes.get(volume).map_or(0..0, |held| held.metadata.headers.clone());
        self.headers[range].iter().map(|record| RarHeader::new(record, &self.model.members))
    }

    /// Read the archive comment of a volume, as stored: UTF-8 for RAR 5.0, the archiver's code page for RAR 4.x.
    /// It is the data of the volume's `CMT` service header or, in a RAR 2.x archive, the comment embedded in the
    /// main header (`MHD_COMMENT`). None when the volume has neither. Bytes are returned as stored, including a
    /// trailing NUL RAR 5.0 writes; UnRAR prints up to the first NUL.
    ///
    /// A stored comment, or a RAR 4.x comment compressed by RAR 1.5 to 2.9 (unpack versions 15, 20, 26 and 29), is
    /// decoded; an encrypted or split comment, or a compressed RAR 5.0 one, is refused as unsupported. Packed and
    /// unpacked sizes are limited to 1 MiB, the decoder's dictionary to 4 MiB and its other memory to 16 MiB. The
    /// stored CRC is checked: CRC-32 for a `CMT` header, its low 16 bits for a RAR 2.x comment.
    pub fn comment(&self, volume: usize) -> Result<Option<Vec<u8>>, Arc<RarFailure>> {
        let Some(held) = self.volumes.get(volume) else { return Ok(None) };
        if let Some(index) = held.metadata.comment {
            return service_comment(held, self.headers[index].header(&self.model.members), &self.options.cancel)
                .map(Some);
        }
        match &held.metadata.main.embedded_comment {
            Some(block) => rar2_comment(held, block, &self.options.cancel).map(Some),
            None => Ok(None),
        }
    }
}

const MAX_COMMENT: u64 = 1 << 20;
const COMMENT_WINDOW: u64 = 4 << 20;
const COMMENT_MEMORY: u64 = 16 << 20;

fn comment_scope(held: &HeldVolume) -> RarScope {
    RarScope::Header { volume: held.path.clone() }
}

fn comment_unsupported(what: &str) -> Arc<RarFailure> {
    Arc::new(RarFailure::Unsupported(RarUnsupported::Decoder(format!("{what} archive comment"))))
}

fn comment_limit(requested: u64) -> Arc<RarFailure> {
    Arc::new(RarFailure::Limit {
        resource: RarResource::CatalogueReadBytes,
        requested: Some(requested),
        allowed: Some(MAX_COMMENT),
    })
}

fn comment_integrity(held: &HeldVolume, reason: RarIntegrityReason) -> Arc<RarFailure> {
    Arc::new(RarFailure::integrity(comment_scope(held), reason, RarPasswordEvidence::NotEncrypted, false))
}

fn read_comment(held: &HeldVolume, at: u64, len: u64) -> Result<Vec<u8>, Arc<RarFailure>> {
    held.stamp.check(&held.file, &held.path).map_err(|fault| Arc::from(fault.failure))?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(len as usize).map_err(|_| Arc::from(allocation().failure))?;
    bytes.resize(len as usize, 0);
    read_at_detailed(&held.file, &mut bytes, at).map_err(|error| {
        Arc::from(read_failure(error, Some(held.path.clone()), RarIntegrityReason::TruncatedData).failure)
    })?;
    Ok(bytes)
}

fn service_comment(held: &HeldVolume, header: &FileHeader, cancel: &Cancellation) -> Result<Vec<u8>, Arc<RarFailure>> {
    if header.encrypted {
        return Err(comment_unsupported("encrypted"));
    }
    if header.split_before() || header.split_after() {
        return Err(comment_unsupported("split"));
    }
    if header.packed_size > MAX_COMMENT {
        return Err(comment_limit(header.packed_size));
    }
    let packed = read_comment(held, header.data_at, header.packed_size)?;
    let bytes = match (header.method, header.rar4) {
        (0, _) => packed,
        (_, Some(rar4)) => {
            if header.size_unknown() {
                return Err(comment_unsupported("unknown-size"));
            }
            if header.unpacked_size > MAX_COMMENT {
                return Err(comment_limit(header.unpacked_size));
            }
            decode_rar4_comment(held, &packed, rar4.unpack_version, header.dictionary, header.unpacked_size, cancel)?
        }
        _ => return Err(comment_unsupported("compressed RAR 5.0")),
    };
    if let Some(expected) = header.crc32
        && crate::crc32::hash(&bytes) != expected
    {
        return Err(comment_integrity(held, RarIntegrityReason::FinalChecks { crc32: true, blake2sp: false }));
    }
    Ok(bytes)
}

/// A RAR 2.x comment embedded in the main header: a `COMM_HEAD` (CRC, type 0x75, flags, size, then unpacked size,
/// unpack version, method and the comment's 16-bit CRC) followed by the packed comment, as UnRAR's `DoGetComment`
/// reads it.
fn rar2_comment(held: &HeldVolume, block: &[u8], cancel: &Cancellation) -> Result<Vec<u8>, Arc<RarFailure>> {
    let framing = |reason| comment_integrity(held, RarIntegrityReason::HeaderFraming(reason));
    let field = |at: usize| block.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let (Some(size), Some(unpacked), Some(&version), Some(&method), Some(crc)) =
        (field(5), field(7), block.get(9), block.get(10), field(11))
    else {
        return Err(framing("RAR 2.x comment header"));
    };
    let size = usize::from(size);
    if size < 13 {
        return Err(framing("RAR 2.x comment header"));
    }
    // The main header's CRC covers only its own 13 bytes: the comment header carries its own, over its fields.
    if field(0) != Some(crate::crc32::hash(&block[2..13]) as u16) {
        return Err(comment_integrity(held, RarIntegrityReason::HeaderCrc));
    }
    let Some(packed) = block.get(13..size) else { return Err(framing("RAR 2.x comment size")) };
    let bytes = if method == 0x30 {
        let mut stored = Vec::new();
        stored.try_reserve_exact(packed.len()).map_err(|_| Arc::from(allocation().failure))?;
        stored.extend_from_slice(packed);
        stored
    } else if (0x31..=0x35).contains(&method) {
        decode_rar4_comment(held, packed, version, 65_536, u64::from(unpacked), cancel)?
    } else {
        return Err(comment_unsupported("RAR 2.x method"));
    };
    if crate::crc32::hash(&bytes) as u16 != crc {
        return Err(comment_integrity(held, RarIntegrityReason::FinalChecks { crc32: true, blake2sp: false }));
    }
    Ok(bytes)
}

fn decode_rar4_comment(
    held: &HeldVolume,
    packed: &[u8],
    version: u8,
    dictionary: u64,
    unpacked: u64,
    cancel: &Cancellation,
) -> Result<Vec<u8>, Arc<RarFailure>> {
    use super::unpack::rar4::Rar4Decoder;
    if !matches!(version, 15 | 20 | 26 | 29) {
        return Err(comment_unsupported("RAR 4.x unpack version"));
    }
    let failed = |error: super::unpack::rar4::Rar4DecodeError| Arc::from(error.detailed(comment_scope(held)).failure);
    let mut out = Vec::new();
    out.try_reserve_exact(unpacked as usize).map_err(|_| Arc::from(allocation().failure))?;
    let mut decoder =
        Rar4Decoder::new_with_cancel(dictionary, packed.len() as u64, unpacked, COMMENT_WINDOW, Some(cancel.clone()))
            .map_err(failed)?;
    decoder.set_memory_limit(COMMENT_MEMORY);
    decoder.set_version(version).map_err(failed)?;
    let mut sink = |bytes: &[u8]| -> crate::error::Result<()> {
        if (out.len() + bytes.len()) as u64 > unpacked {
            return Err(Error::Corrupt("RAR comment longer than declared"));
        }
        out.extend_from_slice(bytes);
        Ok(())
    };
    decoder.feed(packed, &mut sink).map_err(failed)?;
    decoder.finish(&mut sink).map_err(failed)?;
    if out.len() as u64 != unpacked {
        return Err(comment_integrity(
            held,
            RarIntegrityReason::DecodedSize { expected: unpacked, actual: out.len() as u64 },
        ));
    }
    Ok(out)
}

struct Catalogue {
    session: RarSession,
    options: RarSessionOptions,
    owned_capacity: u64,
    output_identity: Option<(u64, u64)>,
    pending: bool,
    history_barrier: bool,
    chain: Option<usize>,
    last_compressed: Option<usize>,
}

impl Catalogue {
    /// The volume to start at instead of `first` (see [`RarSessionOptions::restart_from_first_volume`]): back by name
    /// while each volume's first member continues from an earlier one, to one that does not. None when `first`
    /// does not start with a continued member, or a volume on the way is missing, unreadable or not a RAR volume.
    /// Probes open without blocking, check the source as the scan does, and count against the catalogue's budget.
    fn restart_volume(&mut self, first: &Path, password: Option<&str>) -> RarResult<Option<PathBuf>> {
        let mut current = std::path::absolute(first)
            .map_err(|error| RarFault::input(IoOperation::Open, Some(first.to_path_buf()), None, error))?;
        if self.probe_continues(&current, password)? != Some(true) {
            return Ok(None);
        }
        for _ in 0..MAX_VOLUMES {
            let Some(previous) = crate::volume::previous_volume(&current) else { return Ok(None) };
            current = previous;
            match self.probe_continues(&current, password)? {
                Some(true) => {}
                Some(false) => return Ok(Some(current)),
                None => return Ok(None),
            }
        }
        Ok(None)
    }

    /// Whether the first member in the volume at `path` continues from an earlier volume; None when the volume
    /// cannot be read as one. Only cancellation, the catalogue's limits and an output aliasing the volume are errors.
    fn probe_continues(&mut self, path: &Path, password: Option<&str>) -> RarResult<Option<bool>> {
        fn soft(fault: RarFault) -> RarResult<Option<bool>> {
            match fault.failure.as_ref() {
                // an output that aliases a volume this probe opened is refused as for any input the session opens
                RarFailure::Canceled | RarFailure::Limit { .. } | RarFailure::OutputAliasesInput => Err(fault),
                _ => Ok(None),
            }
        }
        check_cancel(&self.options.cancel)?;
        let Ok(file) = open_read_only(path) else { return Ok(None) };
        let stamp = match SourceStamp::capture_for_output(&file, path, self.output_identity) {
            Ok(stamp) => stamp,
            Err(fault) => return soft(fault),
        };
        let damaged = self.options.damaged_input;
        let keys = self.session.rar5_keys.clone();
        let mut volume =
            match Volume::open_catalogue(path, file, stamp.len, password, &mut self.scan_budget(), damaged, keys) {
                Ok(volume) => volume,
                Err(fault) => return soft(fault),
            };
        loop {
            match volume.next_catalogue(&mut self.scan_budget()) {
                Ok(Some((Block::File(header), _, _))) => return Ok(Some(header.split_before())),
                Ok(Some((Block::End { .. }, _, _))) | Ok(None) => return Ok(Some(false)),
                Ok(Some(_)) => {}
                Err(fault) => return soft(fault),
            }
        }
    }

    /// Members that start in the volumes scanned before `named` (UnRAR's listing of `named` counts from there).
    fn members_before(&self, named: &Path) -> u64 {
        let Ok(named) = std::path::absolute(named) else { return 0 };
        let Some(index) = self.session.volumes.iter().position(|v| v.path == named) else { return 0 };
        self.session
            .headers
            .iter()
            .map(|h| (h.volume, h.header(&self.session.model.members)))
            .filter(|(volume, header)| *volume < index && !header.service && !header.split_before())
            .count() as u64
    }

    fn scan(&mut self, first: &Path, password: Option<&str>) -> RarResult<()> {
        if !cfg!(unix) {
            return Err(RarFault::new(
                RarFailure::Unsupported(RarUnsupported::SourceIdentity),
                Error::Unsupported("RAR session source identity unavailable".into()),
            ));
        }
        let mut path = std::path::absolute(first)
            .map_err(|error| RarFault::input(IoOperation::Open, Some(first.to_path_buf()), None, error))?;
        let mut required = None;
        loop {
            check_cancel(&self.options.cancel)?;
            if required == Some(false) {
                match fs::metadata(&path) {
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => break,
                    Err(error) => return Err(RarFault::input(IoOperation::Metadata, Some(path), None, error)),
                }
            }
            let volumes = add(self.session.usage.volumes, 1)?;
            limit(volumes, self.options.limits.volumes.min(MAX_VOLUMES), RarResource::CatalogueVolumes)?;
            let path_bytes = path.capacity() as u64;
            self.reserve_volume(path_bytes)?;
            let file = match open_read_only(&path) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::NotFound && required == Some(true) => {
                    // As UnRAR: the members before stand, and the one split into the missing volume fails.
                    if std::mem::take(&mut self.pending) {
                        let index = self.session.model.members.len() - 1;
                        if self.session.model.members[index].issue.is_none() {
                            let issue = RarFailure::MissingVolume { path: path.clone() };
                            self.session.model.members[index].issue = self.retain_issue(Some(issue))?;
                        }
                    }
                    self.owned_capacity = add(self.owned_capacity, path_bytes)?;
                    self.session.archive.missing_volume = Some(path);
                    self.update_capacity()?;
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound && required == Some(false) => break,
                Err(error) => return Err(RarFault::input(IoOperation::Open, Some(path), None, error)),
            };
            let stamp = SourceStamp::capture_for_output(&file, &path, self.output_identity)?;
            if self.session.volumes.iter().any(|v| (v.stamp.device, v.stamp.inode) == (stamp.device, stamp.inode)) {
                return Err(volume_framing(&path, "RAR volume identity repeats"));
            }
            self.owned_capacity = add(self.owned_capacity, path_bytes)?;
            let damaged = self.options.damaged_input;
            let keys = self.session.rar5_keys.clone();
            let mut volume =
                Volume::open_catalogue(&path, file, stamp.len, password, &mut self.scan_budget(), damaged, keys)?;
            let format = volume.format();
            if self.session.volumes.is_empty() {
                self.session.archive.format = format;
            } else if self.session.archive.format != format {
                return Err(volume_framing(&path, "RAR volume format changed"));
            }
            self.session.usage.volumes = volumes;
            let encrypted_headers = volume.encrypted_headers();
            if self.session.volumes.first().is_some_and(|v| v.metadata.encrypted_headers != encrypted_headers) {
                return Err(volume_framing(&path, "RAR volume header encryption changed"));
            }
            let volume_index = self.session.volumes.len();
            let mut next = volume.main.is_volume().then_some(false);
            let first_header = self.session.headers.len();
            let mut end = None;
            let mut comment = None;
            loop {
                let parsed = volume.next_catalogue(&mut self.scan_budget());
                let damage = volume.take_damage();
                // bytes passed over break the solid history: a solid member after them chains to nothing
                if damage.iter().any(|d| d.passed_over) {
                    self.history_barrier = true;
                }
                self.keep_damage(damage)?;
                let Some((block, crypt, wire)) = parsed? else { break };
                match block {
                    Block::File(header) => {
                        let wire = wire.expect("catalogue file metadata includes the wire name");
                        // Only the member keeps its extra records (RarMember::extra_records), charged to capacity.
                        self.owned_capacity = add(self.owned_capacity, extra_records_bytes(&header.extra_records))?;
                        self.update_capacity()?;
                        let raw_name = wire.name.clone();
                        let listed = self.add_part(volume_index, header, crypt, wire)?;
                        self.add_header(volume_index, listed, Some(raw_name))?;
                    }
                    Block::Service(mut header) => {
                        // a service header's extra records are not kept
                        header.extra_records = Vec::new();
                        if comment.is_none() && header.name == "CMT" {
                            comment = Some(self.session.headers.len());
                        }
                        self.add_header(volume_index, owned(header), wire.map(|wire| wire.name))?;
                    }
                    Block::End { more_volumes, volume_number } => {
                        next = more_volumes.then_some(true);
                        end = Some(VolumeEnd { more_volumes, volume_number });
                        break;
                    }
                    Block::Main(_) | Block::Crypt => return Err(volume_framing(&path, "unexpected RAR volume header")),
                    Block::Unknown => {}
                }
            }
            let original = add(
                volume.main.original_name.as_ref().map_or(0, |name| name.capacity() as u64),
                volume.main.embedded_comment.as_ref().map_or(0, |block| block.capacity() as u64),
            )?;
            let original = add(original, extra_records_bytes(&volume.main.extra_records))?;
            self.owned_capacity = add(self.owned_capacity, original)?;
            let metadata = RarVolumeMetadata {
                format,
                main: volume.main.clone(),
                encrypted_headers,
                sfx_size: volume.sfx_size(),
                end,
                end_record: volume.end_record(),
                headers: first_header..self.session.headers.len(),
                comment,
                quick_open: RarQuickOpen::Absent,
            };
            let file = volume.into_catalogue_file();
            stamp.check(&file, &path)?;
            if !self.options.follow_volumes {
                next = None;
            }
            let next_path = next.and_then(|_| next_volume(&path));
            self.session.volumes.push(HeldVolume { metadata, file, path, stamp });
            self.update_capacity()?;
            match (next, next_path) {
                (_, Some(next_path)) => {
                    path = next_path;
                    required = next;
                }
                (Some(true), None) => {
                    let path = self.session.volumes.last().unwrap().path.clone();
                    return Err(RarFault::new(
                        RarFailure::UnnamedVolume { path: path.clone() },
                        Error::UnnamedVolume(path),
                    ));
                }
                _ => break,
            }
        }
        self.end_incomplete()?;
        // The quick open checks are optional, so they run only once every required header is read, each within
        // what is left of the read budget: they can never take budget a later volume's headers need.
        for index in 0..self.session.volumes.len() {
            let status = {
                let Self { session, options, .. } = self;
                let mut budget =
                    ScanBudget { cancel: &options.cancel, limits: options.limits, usage: &mut session.usage };
                let volume = &session.volumes[index];
                quick_open(&mut budget, &volume.file, &volume.path, volume.stamp.len, &volume.metadata)?
            };
            self.session.volumes[index].metadata.quick_open = status;
        }
        #[cfg(all(test, unix))]
        BEFORE_FINAL_BINDING_CHECK.with_borrow_mut(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
        for volume in &self.session.volumes {
            check_cancel(&self.options.cancel)?;
            volume.stamp.check(&volume.file, &volume.path)?;
        }
        check_cancel(&self.options.cancel)?;
        self.session.archive.volumes = self.session.volumes.len();
        Ok(())
    }

    /// Keeps what a salvaging volume read past, its memory charged to the catalogue.
    fn keep_damage(&mut self, damage: Vec<crate::extract::HeaderDamage>) -> RarResult<()> {
        for d in damage {
            if self.session.archive.damaged_headers.len() >= crate::extract::MAX_HEADER_DAMAGE {
                break;
            }
            let kept = &mut self.session.archive.damaged_headers;
            // the vector grows by doubling, up to the cap, and every slot it holds is charged
            let grow = if kept.len() == kept.capacity() {
                kept.capacity().saturating_mul(2).clamp(4, crate::extract::MAX_HEADER_DAMAGE) - kept.capacity()
            } else {
                0
            };
            let slots = (grow * size_of::<crate::extract::HeaderDamage>()) as u64;
            let owned = (d.volume.capacity() + d.name.as_ref().map_or(0, String::capacity)) as u64;
            self.owned_capacity = add(add(self.owned_capacity, slots)?, owned)?;
            self.update_capacity()?;
            let kept = &mut self.session.archive.damaged_headers;
            kept.try_reserve_exact(grow).map_err(|_| allocation())?;
            kept.push(d);
        }
        Ok(())
    }

    fn scan_budget(&mut self) -> ScanBudget<'_> {
        ScanBudget { cancel: &self.options.cancel, limits: self.options.limits, usage: &mut self.session.usage }
    }

    /// Catalogue one file header as a part, and return where its listed copy lives: the member it starts, or its own
    /// copy (without extra records) when it continues a member or is an orphan continuation.
    fn add_part(
        &mut self,
        volume: usize,
        header: FileHeader,
        crypt: MemberCrypt,
        wire: FileWire,
    ) -> RarResult<StoredHeader> {
        let parts = add(self.session.usage.parts, 1)?;
        limit(parts, self.options.limits.parts, RarResource::CatalogueParts)?;
        self.session.usage.parts = parts;
        let associated = self.pending
            && self.session.model.members.last().is_some_and(|member| member.matches_continuation(&header, &wire));
        if !associated {
            self.end_incomplete()?;
            if header.split_before() {
                self.session.archive.orphan_continuations = add(self.session.archive.orphan_continuations, 1)?;
                self.history_barrier |= header.method != 0;
                return Ok(owned(header));
            }
        }
        let final_part = !header.split_after();
        let part = Part::new(volume, &header, crypt, &wire);
        let ordinal =
            if associated { self.session.model.members.len() - 1 } else { self.session.model.members.len() } as u64;
        let issue = if associated {
            let initial = self.session.model.members.last().unwrap();
            if initial.issue.is_some() {
                None
            } else if let Some(reason) = continuation_issue(initial, &header) {
                Some(member_integrity(ordinal, reason))
            } else {
                payload_issue(&header, crypt, ordinal).or_else(|| {
                    (final_part && header.blake2sp.is_some() && initial.header.blake2sp.is_none())
                        .then(|| member_integrity(ordinal, RarIntegrityReason::DeclaredHashUnavailable))
                })
            }
        } else {
            payload_issue(&header, crypt, ordinal)
        };
        let issue_minimum = u64::from(issue.is_some() && self.session.issues.len() == self.session.issues.capacity())
            * size_of::<RarFailure>() as u64;
        let part_index = self.session.model.parts.len();
        if associated {
            let base = add(self.capacity_without::<Part>(self.session.model.parts.capacity())?, issue_minimum)?;
            let allowed = self.allowed();
            reserve_one(&mut self.session.model.parts, base, allowed)?;
            let issue = self.retain_issue(issue)?;
            let member = self.session.model.members.last_mut().unwrap();
            member.append(&header, &part)?;
            if issue.is_some() {
                member.issue = issue;
            }
            self.session.model.parts.push(part);
            self.pending = !final_part;
            self.update_capacity()?;
            return Ok(owned(header));
        } else {
            let entries = add(self.session.usage.entries, 1)?;
            limit(entries, self.options.limits.entries, RarResource::CatalogueEntries)?;
            let target = target_name(&header);
            let name_bytes =
                add(add(header.name.len() as u64, wire.name.len() as u64)?, target.map_or(0, |t| t.len() as u64))?;
            let names = add(self.session.usage.name_bytes, name_bytes)?;
            limit(names, self.options.limits.name_bytes, RarResource::CatalogueNameBytes)?;
            let allocation = add(
                add(
                    add(header.name.capacity() as u64, wire.name.capacity() as u64)?,
                    header.owner.as_ref().map_or(0, |o| o.heap_capacity() as u64),
                )?,
                add(target.map_or(0, |t| t.capacity() as u64), crate::rar5::RAW_NAME_OWNER_BYTES as u64)?,
            )?;
            let part_minimum = u64::from(self.session.model.parts.len() == self.session.model.parts.capacity())
                * size_of::<Part>() as u64;
            let base = add(
                self.capacity_without::<Member>(self.session.model.members.capacity())?,
                add(add(allocation, part_minimum)?, issue_minimum)?,
            )?;
            let allowed = self.allowed();
            reserve_one(&mut self.session.model.members, base, allowed)?;
            let base = add(
                self.capacity_without::<Part>(self.session.model.parts.capacity())?,
                add(allocation, issue_minimum)?,
            )?;
            let allowed = self.allowed();
            reserve_one(&mut self.session.model.parts, base, allowed)?;
            self.owned_capacity = add(self.owned_capacity, allocation)?;
            let issue = self.retain_issue(issue)?;
            self.session.usage.entries = entries;
            self.session.usage.name_bytes = names;
            let compressed = header.method != 0 && !header.is_dir() && header.redirection.is_none();
            let chain = if compressed {
                let index = self.session.model.members.len();
                if !header.solid {
                    self.chain = Some(index);
                } else if self.history_barrier {
                    self.chain = None;
                } else if let Some(previous) = self.last_compressed
                    && self.chain.is_some()
                {
                    self.session.model.members[previous].has_successor = true;
                }
                self.history_barrier = false;
                self.last_compressed = Some(index);
                self.chain
            } else {
                None
            };
            let mut member = Member::new(header, wire, part_index, &part)?;
            member.issue = issue;
            member.chain = chain;
            self.session.model.members.push(member);
        }
        self.session.model.parts.push(part);
        self.pending = !final_part;
        self.update_capacity()?;
        Ok(StoredHeader::Member(self.session.model.members.len() - 1))
    }

    /// Retain one file or service header for [`RarSession::headers`]. A header kept apart from its member is charged
    /// here with its decoded name, redirection target and SubData; the raw name too unless a member already owns (and
    /// was charged for) it, as with an orphan continuation or a service header.
    fn add_header(&mut self, volume: usize, header: StoredHeader, raw_name: Option<Arc<Vec<u8>>>) -> RarResult<()> {
        let unowned_name = raw_name
            .as_ref()
            .filter(|name| Arc::strong_count(name) == 1)
            .map_or(0, |name| (name.capacity() + crate::rar5::RAW_NAME_OWNER_BYTES) as u64);
        let kept = match &header {
            StoredHeader::Member(_) => 0,
            StoredHeader::Owned(header) => add(
                add(size_of::<FileHeader>() as u64, header.name.capacity() as u64)?,
                add(
                    add(header.sub_data.capacity() as u64, target_name(header).map_or(0, |t| t.capacity() as u64))?,
                    header.owner.as_ref().map_or(0, |o| o.heap_capacity() as u64),
                )?,
            )?,
        };
        let allocation = add(kept, unowned_name)?;
        let base = add(self.capacity_without::<HeaderRecord>(self.session.headers.capacity())?, allocation)?;
        let allowed = self.allowed();
        reserve_one(&mut self.session.headers, base, allowed)?;
        self.owned_capacity = add(self.owned_capacity, allocation)?;
        self.session.headers.push(HeaderRecord { volume, header, raw_name });
        self.update_capacity()
    }

    fn end_incomplete(&mut self) -> RarResult<()> {
        if std::mem::take(&mut self.pending) {
            let index = self.session.model.members.len() - 1;
            if self.session.model.members[index].issue.is_none() {
                let issue = member_integrity(index as u64, RarIntegrityReason::MissingSplitContinuation);
                self.session.model.members[index].issue = self.retain_issue(Some(issue))?;
                self.update_capacity()?;
            }
        }
        Ok(())
    }

    fn reserve_volume(&mut self, path_bytes: u64) -> RarResult<()> {
        let base = add(self.capacity_without::<HeldVolume>(self.session.volumes.capacity())?, path_bytes)?;
        let allowed = self.allowed();
        reserve_one(&mut self.session.volumes, base, allowed)
    }

    fn retain_issue(&mut self, issue: Option<RarFailure>) -> RarResult<Option<usize>> {
        let Some(issue) = issue else { return Ok(None) };
        let base = self.capacity_without::<RarFailure>(self.session.issues.capacity())?;
        let allowed = self.allowed();
        reserve_one(&mut self.session.issues, base, allowed)?;
        let index = self.session.issues.len();
        self.session.issues.push(issue);
        Ok(Some(index))
    }

    fn capacity(&self) -> RarResult<u64> {
        let volumes = add(
            vector_bytes::<HeldVolume>(self.session.volumes.capacity())?,
            vector_bytes::<RarFailure>(self.session.issues.capacity())?,
        )?;
        let model = add(
            vector_bytes::<Member>(self.session.model.members.capacity())?,
            vector_bytes::<Part>(self.session.model.parts.capacity())?,
        )?;
        let headers = vector_bytes::<HeaderRecord>(self.session.headers.capacity())?;
        add(add(self.owned_capacity, volumes)?, add(model, headers)?)
    }

    fn capacity_without<T>(&self, count: usize) -> RarResult<u64> {
        Ok(self.capacity()? - vector_bytes::<T>(count)?)
    }

    fn update_capacity(&mut self) -> RarResult<()> {
        let capacity = self.capacity()?;
        limit(capacity, self.allowed(), RarResource::CatalogueCapacity)?;
        self.session.usage.capacity = capacity;
        Ok(())
    }

    /// The capacity the catalogue may retain now ([`RarCatalogueLimits::capacity_for`]).
    fn allowed(&self) -> u64 {
        self.options.limits.capacity_for(&self.session.usage)
    }

    /// Give back the room each vector grew into past what the catalogue holds.
    fn shrink(&mut self) -> RarResult<()> {
        self.session.model.members.shrink_to_fit();
        self.session.model.parts.shrink_to_fit();
        self.session.headers.shrink_to_fit();
        self.session.issues.shrink_to_fit();
        self.session.volumes.shrink_to_fit();
        self.update_capacity()
    }
}

/// A header listed apart from any member it belongs to. Only a member keeps the extra records.
fn owned(mut header: FileHeader) -> StoredHeader {
    header.extra_records = Vec::new();
    StoredHeader::Owned(Box::new(header))
}

/// The heap bytes a header's extra records hold: the vector and each record's data.
fn extra_records_bytes(records: &Vec<super::RarExtraRecord>) -> u64 {
    (records.capacity() * size_of::<super::RarExtraRecord>() + records.iter().map(|r| r.data.capacity()).sum::<usize>())
        as u64
}

fn target_name(header: &FileHeader) -> Option<&String> {
    match header.redirection.as_ref()? {
        Redirection::UnixSymlink(name)
        | Redirection::WindowsSymlink(name)
        | Redirection::Junction(name)
        | Redirection::HardLink(name)
        | Redirection::FileCopy(name) => Some(name),
        Redirection::Unknown(_) => None,
    }
}

fn payload_issue(header: &FileHeader, crypt: MemberCrypt, ordinal: u64) -> Option<RarFailure> {
    if let Some(reason) = header.rar4_unsupported() {
        return Some(RarFailure::Unsupported(reason));
    }
    match crypt {
        Some(Err(error)) => Some(RarFailure::crypt(error, RarScope::Member { index: Some(ordinal) })),
        _ if header.method != 0 && header.algorithm != 0 => {
            Some(RarFailure::Unsupported(RarUnsupported::CompressionAlgorithm {
                algorithm: header.algorithm,
                method: header.method,
            }))
        }
        _ => None,
    }
}

fn member_integrity(ordinal: u64, reason: RarIntegrityReason) -> RarFailure {
    RarFailure::integrity(RarScope::Member { index: Some(ordinal) }, reason, RarPasswordEvidence::NotEncrypted, false)
}

fn volume_framing(path: &Path, reason: &'static str) -> RarFault {
    RarFault::new(
        RarFailure::integrity(
            RarScope::Header { volume: path.to_path_buf() },
            RarIntegrityReason::HeaderFraming(reason),
            RarPasswordEvidence::NotEncrypted,
            false,
        ),
        Error::Corrupt(reason),
    )
}

fn reserve_one<T>(items: &mut Vec<T>, base: u64, allowed: u64) -> RarResult<()> {
    if items.len() < items.capacity() {
        return limit(add(base, vector_bytes::<T>(items.capacity())?)?, allowed, RarResource::CatalogueCapacity);
    }
    let count = items.len().checked_add(1).ok_or_else(RarFault::counter_limit)?;
    let needed = add(base, vector_bytes::<T>(count)?)?;
    limit(needed, allowed, RarResource::CatalogueCapacity)?;
    let slots = (allowed - base) / size_of::<T>() as u64;
    let target = count.max(items.capacity().saturating_mul(2)).min(usize::try_from(slots).unwrap_or(usize::MAX));
    items.try_reserve_exact(target - items.len()).map_err(|_| allocation())?;
    limit(add(base, vector_bytes::<T>(items.capacity())?)?, allowed, RarResource::CatalogueCapacity)
}

fn vector_bytes<T>(count: usize) -> RarResult<u64> {
    (count as u64).checked_mul(size_of::<T>() as u64).ok_or_else(RarFault::counter_limit)
}

fn add(left: u64, right: u64) -> RarResult<u64> {
    left.checked_add(right).ok_or_else(RarFault::counter_limit)
}

pub(super) fn allocation() -> RarFault {
    RarFault::new(
        RarFailure::Limit { resource: RarResource::CatalogueAllocation, requested: None, allowed: None },
        Error::Unsupported("RAR catalogue allocation".into()),
    )
}

fn limit(requested: u64, allowed: u64, resource: RarResource) -> RarResult<()> {
    if requested <= allowed {
        Ok(())
    } else {
        Err(RarFault::new(
            RarFailure::Limit { resource, requested: Some(requested), allowed: Some(allowed) },
            Error::Unsupported("RAR catalogue resource limit".into()),
        ))
    }
}

fn check_cancel(cancel: &Cancellation) -> RarResult<()> {
    if cancel.is_canceled() {
        Err(RarFault::new(RarFailure::Canceled, io::Error::from(io::ErrorKind::Interrupted).into()))
    } else {
        Ok(())
    }
}

pub(super) struct ScanBudget<'a> {
    pub(super) cancel: &'a Cancellation,
    limits: RarCatalogueLimits,
    usage: &'a mut RarCatalogueUsage,
}

impl ScanBudget<'_> {
    pub(super) fn temporary(&self, bytes: u64) -> RarResult<()> {
        limit(add(self.usage.capacity, bytes)?, self.limits.capacity_for(self.usage), RarResource::CatalogueCapacity)
    }

    pub(super) fn names(&self, bytes: u64) -> RarResult<()> {
        limit(add(self.usage.name_bytes, bytes)?, self.limits.name_bytes, RarResource::CatalogueNameBytes)
    }

    pub(super) fn check(&self) -> RarResult<()> {
        check_cancel(self.cancel)
    }

    pub(super) fn block(&mut self) -> RarResult<()> {
        self.check()?;
        let blocks = add(self.usage.header_blocks, 1)?;
        limit(blocks, self.limits.header_blocks, RarResource::CatalogueBlocks)?;
        self.usage.header_blocks = blocks;
        Ok(())
    }

    pub(super) fn read(&mut self, file: &File, path: &Path, bytes: &mut [u8], at: u64) -> RarResult<()> {
        self.check_read(bytes.len())?;
        self.usage.read_bytes += bytes.len() as u64;
        read_at_detailed(file, bytes, at)
            .map_err(|error| read_failure(error, Some(path.to_path_buf()), RarIntegrityReason::TruncatedHeader))
    }

    /// How many more bytes the catalogue's read budget allows.
    pub(super) fn read_room(&self) -> u64 {
        self.limits.read_bytes.saturating_sub(self.usage.read_bytes)
    }

    pub(super) fn check_read(&self, len: usize) -> RarResult<()> {
        self.check()?;
        let total = add(self.usage.read_bytes, len as u64)?;
        limit(total, self.limits.read_bytes, RarResource::CatalogueReadBytes)
    }
}

/// Reads the block header the quick open locator of `metadata` points at, as UnRAR does when it opens a volume,
/// within what is left of `budget`'s read bytes (`Unchecked` when it doesn't fit).
fn quick_open(
    budget: &mut ScanBudget<'_>,
    file: &File,
    path: &Path,
    len: u64,
    metadata: &RarVolumeMetadata,
) -> RarResult<RarQuickOpen> {
    let Some(offset) = metadata.main.locator.and_then(|l| l.quick_open).filter(|&o| o > 0) else {
        return Ok(RarQuickOpen::Absent);
    };
    if metadata.format != super::RarFormat::Rar5 {
        return Ok(RarQuickOpen::Absent);
    }
    if metadata.encrypted_headers {
        return Ok(RarQuickOpen::Encrypted);
    }
    // the main header starts right after the signature, which follows any SFX module
    let Some(at) = (metadata.sfx_size + super::SIGNATURE.len() as u64).checked_add(offset) else {
        return Ok(RarQuickOpen::Truncated);
    };
    // CRC32, then the header size as a vint of at most three bytes (a header is at most 2 MiB)
    let mut head = [0u8; 7];
    let have = len.saturating_sub(at).min(head.len() as u64) as usize;
    if have < 5 {
        return Ok(RarQuickOpen::Truncated);
    }
    // the check is optional: it never fails the open, so it stops where the read budget would
    if budget.read_room() < have as u64 {
        return Ok(RarQuickOpen::Unchecked);
    }
    budget.read(file, path, &mut head[..have], at)?;
    let (mut size, mut n) = (0u64, 0usize);
    loop {
        let Some(&b) = head[4..have].get(n) else { return Ok(RarQuickOpen::Truncated) };
        size |= u64::from(b & 0x7f) << (7 * n);
        n += 1;
        if b & 0x80 == 0 {
            break;
        }
        if n == 3 {
            return Ok(RarQuickOpen::Corrupt);
        }
    }
    if size == 0 || size > 2 << 20 {
        return Ok(RarQuickOpen::Corrupt);
    }
    let body = n as u64 + size;
    if at + 4 + body > len {
        return Ok(RarQuickOpen::Truncated);
    }
    // The header is hashed in fixed pieces, so a locator pointing into packed data at a large size field costs
    // no allocation; and it is read only within the catalogue's read budget, checked before any of it is read.
    if budget.read_room() < body {
        return Ok(RarQuickOpen::Unchecked);
    }
    let mut piece = [0u8; 8192];
    let mut hasher = crate::crc32::Hasher::new();
    let mut done = 0u64;
    while done < body {
        let n = (body - done).min(piece.len() as u64) as usize;
        budget.read(file, path, &mut piece[..n], at + 4 + done)?;
        hasher.update(&piece[..n]);
        done += n as u64;
    }
    let stored = u32::from_le_bytes(head[..4].try_into().unwrap());
    Ok(if hasher.finalize() == stored { RarQuickOpen::Valid } else { RarQuickOpen::Corrupt })
}

fn open_read_only(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    #[cfg(all(test, unix))]
    OPENED.with(|opened| opened.set(opened.get() + 1));
    Ok(file)
}

#[cfg(all(test, unix))]
thread_local! {
    static OPENED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static BEFORE_FINAL_BINDING_CHECK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn output_open_rejects_direct_and_hardlink_aliases_before_first_header_parse() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("malformed.rar");
        let bytes = b"not a RAR header";
        fs::write(&path, bytes).unwrap();
        let alias = dir.path().join("alias");
        fs::hard_link(&path, &alias).unwrap();
        for output_path in [&path, &alias] {
            let output = OpenOptions::new().append(true).open(output_path).unwrap();
            let error =
                RarSession::open_with_output_file(&path, None, RarSessionOptions::default(), &output).err().unwrap();
            assert!(matches!(error.failure.as_ref(), RarFailure::OutputAliasesInput));
            assert_eq!(error.partial.volumes, 0);
            assert_eq!(error.partial.encountered, 0);
            assert_eq!(fs::read(&path).unwrap(), bytes);
            assert!(matches!(
                RarSession::open(&path, None, RarSessionOptions::default()).err().unwrap().failure.as_ref(),
                RarFailure::NotRar
            ));
        }
    }

    #[test]
    fn output_open_rejects_later_alias_before_its_header_parse() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("set.part1.rar");
        let second = dir.path().join("set.part2.rar");
        let main = [0xc5, 0x1a, 0x33, 0x32, 3, 1, 0, 0];
        let more = [0x8f, 0x82, 0x3d, 0x42, 3, 5, 0, 1];
        let first_bytes = [super::super::SIGNATURE.as_slice(), &main, &more].concat();
        fs::write(&first, &first_bytes).unwrap();
        fs::write(&second, b"malformed later input").unwrap();
        let alias = dir.path().join("alias");
        fs::hard_link(&second, &alias).unwrap();
        let output = OpenOptions::new().append(true).open(alias).unwrap();
        let error =
            RarSession::open_with_output_file(&first, None, RarSessionOptions::default(), &output).err().unwrap();
        assert!(matches!(error.failure.as_ref(), RarFailure::OutputAliasesInput));
        assert_eq!(error.partial.volumes, 1);
        assert_eq!(fs::read(first).unwrap(), first_bytes);
        assert_eq!(fs::read(second).unwrap(), b"malformed later input");
    }

    #[test]
    fn output_open_alias_check_precedes_a_source_path_binding_failure() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("volume.rar");
        fs::write(&path, b"original").unwrap();
        let held = File::open(&path).unwrap();
        let stamp = SourceStamp::capture(&held, &path).unwrap();
        fs::rename(&path, dir.path().join("held-input")).unwrap();
        fs::write(&path, b"replacement").unwrap();
        let fault = SourceStamp::capture_for_output(&held, &path, Some((stamp.device, stamp.inode))).err().unwrap();
        assert!(matches!(fault.failure.as_ref(), RarFailure::OutputAliasesInput));
        assert!(matches!(
            SourceStamp::capture(&held, &path).err().unwrap().failure.as_ref(),
            RarFailure::SourceChanged { .. }
        ));
    }

    #[test]
    fn output_open_keeps_safe_errors_and_existing_open_behavior() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let malformed = dir.path().join("malformed.rar");
        fs::write(&malformed, b"bad").unwrap();
        let mut output = tempfile::tempfile().unwrap();
        let failure =
            RarSession::open_with_output_file(&malformed, None, RarSessionOptions::default(), &output).err().unwrap();
        assert!(matches!(failure.failure.as_ref(), RarFailure::NotRar));
        // A safe descriptor can carry the caller's normal early diagnostic.
        writeln!(output, "safe diagnostic").unwrap();
        assert_eq!(output.metadata().unwrap().len(), 16);
        let missing = dir.path().join("missing.rar");
        let failure =
            RarSession::open_with_output_file(&missing, None, RarSessionOptions::default(), &output).err().unwrap();
        assert!(
            matches!(failure.failure.as_ref(), RarFailure::Input { operation: IoOperation::Open, source, .. } if source.kind() == io::ErrorKind::NotFound)
        );
        let cancel = Cancellation::default();
        cancel.cancel();
        let failure = RarSession::open_with_output_file(
            &malformed,
            None,
            RarSessionOptions { cancel, ..RarSessionOptions::default() },
            &output,
        )
        .err()
        .unwrap();
        assert!(matches!(failure.failure.as_ref(), RarFailure::Canceled));
    }

    #[test]
    fn output_open_accepts_distinct_regular_and_pipe_like_descriptors() {
        use std::os::fd::OwnedFd;
        use std::os::unix::net::UnixStream;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.rar");
        let main = [0xc5, 0x1a, 0x33, 0x32, 3, 1, 0, 0];
        let end = [0x19, 0xb2, 0x3a, 0x35, 3, 5, 0, 0];
        let bytes = [super::super::SIGNATURE.as_slice(), &main, &end].concat();
        fs::write(&path, &bytes).unwrap();
        let (_reader, writer) = UnixStream::pair().unwrap();
        for output in [tempfile::tempfile().unwrap(), File::from(OwnedFd::from(writer))] {
            let mut session =
                RarSession::open_with_output_file(&path, None, RarSessionOptions::default(), &output).unwrap();
            session.check_output_file(&output).unwrap();
            assert_eq!(session.entries().len(), 0);
            assert_eq!(session.archive().volume_count(), 1);
            assert_eq!(fs::read(&path).unwrap(), bytes);
        }
    }

    #[test]
    fn opens_each_volume_once_and_keeps_it_until_drop() {
        const CHILD: &str = "ZIPFAST_TEST_RAR_CATALOGUE_FD_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "rar5::session::tests::opens_each_volume_once_and_keeps_it_until_drop"])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("set.part1.rar");
        let second = dir.path().join("set.part2.rar");
        // CRC-checked main (no flags), end (more and final respectively).
        let main = [0xc5, 0x1a, 0x33, 0x32, 3, 1, 0, 0];
        let more = [0x8f, 0x82, 0x3d, 0x42, 3, 5, 0, 1];
        let end = [0x19, 0xb2, 0x3a, 0x35, 3, 5, 0, 0];
        for (path, tail) in [(&first, more), (&second, end)] {
            fs::write(path, [super::super::SIGNATURE.as_slice(), &main, &tail].concat()).unwrap();
        }
        OPENED.set(0);
        let session = RarSession::open(&first, None, RarSessionOptions::default()).unwrap();
        assert_eq!(OPENED.get(), 2);
        assert_eq!(session.volumes.len(), 2);
        let mut descriptors = Vec::new();
        for (volume, path) in session.volumes.iter().zip([first, second]) {
            assert_eq!(volume.path, path);
            let fd = volume.file.as_raw_fd();
            // SAFETY: F_GETFL queries an open descriptor without additional arguments.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            assert!(flags >= 0);
            assert_eq!(flags & libc::O_ACCMODE, libc::O_RDONLY);
            descriptors.push(fd);
        }
        drop(session);
        for fd in descriptors {
            // SAFETY: F_GETFD accepts an open or closed descriptor number.
            assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
        }
    }

    #[test]
    fn catalogue_open_detects_volume_replacement_before_returning_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first.rar");
        let replacement = dir.path().join("replacement");
        let main = [0xc5, 0x1a, 0x33, 0x32, 3, 1, 0, 0];
        let end = [0x19, 0xb2, 0x3a, 0x35, 3, 5, 0, 0];
        let bytes = [super::super::SIGNATURE.as_slice(), &main, &end].concat();
        fs::write(&first, &bytes).unwrap();
        fs::write(&replacement, &bytes).unwrap();
        let observed = first.clone();
        BEFORE_FINAL_BINDING_CHECK.with_borrow_mut(|hook| {
            *hook = Some(Box::new(move || fs::rename(replacement, observed).unwrap()));
        });
        let failure = RarSession::open(&first, None, RarSessionOptions::default()).err().unwrap();
        assert!(matches!(failure.failure.as_ref(), RarFailure::SourceChanged { path } if path == &first));
        assert_eq!(failure.partial.volumes, 1);
        assert_eq!(fs::read(first).unwrap(), bytes);
    }

    #[test]
    fn checks_the_source_descriptor_against_rebound_and_modified_paths() {
        use std::fs::FileTimes;
        use std::io::Write;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("volume.rar");
        fs::write(&path, b"old").unwrap();
        let held = open_read_only(&path).unwrap();
        let stamp = SourceStamp::capture(&held, &path).unwrap();
        let original_time = held.metadata().unwrap().modified().unwrap();
        // Same size and the old mtime: only ctime shows the change, so it must land in a later tick.
        crate::test_stamps::await_stamp_tick(&path);
        let mut output = OpenOptions::new().write(true).open(&path).unwrap();
        output.write_all(b"new").unwrap();
        output.set_times(FileTimes::new().set_modified(original_time)).unwrap();
        let fault = stamp.check(&held, &path).unwrap_err();
        assert!(matches!(fault.failure.as_ref(), RarFailure::SourceChanged { path: changed } if changed == &path));

        let stamp = SourceStamp::capture(&held, &path).unwrap();
        fs::rename(&path, dir.path().join("previous")).unwrap();
        fs::write(&path, b"new").unwrap();
        let fault = stamp.check(&held, &path).unwrap_err();
        assert!(matches!(fault.failure.as_ref(), RarFailure::SourceChanged { path: changed } if changed == &path));
    }

    #[test]
    fn capacity_counts_each_grown_vector_and_retained_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("growth.rar");
        let main = [0xc5, 0x1a, 0x33, 0x32, 3, 1, 0, 0];
        let end = [0x19, 0xb2, 0x3a, 0x35, 3, 5, 0, 0];
        let mut bytes = [super::super::SIGNATURE.as_slice(), &main].concat();
        for name in b'a'..=b'i' {
            let body = [2, 1, 3, 0, 0, 0, 0, 1, 1, name, 2, 1, 0];
            let mut sized = vec![body.len() as u8];
            sized.extend(body);
            bytes.extend(crate::crc32::hash(&sized).to_le_bytes());
            bytes.extend(sized);
        }
        bytes.extend(end);
        fs::write(&path, bytes).unwrap();
        let session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
        assert_eq!(session.entries().len(), 9);
        assert_eq!(session.issues.len(), 9);
        let variable = session.volumes[0].path.capacity()
            + session
                .model
                .members
                .iter()
                .map(|row| {
                    row.header.name.capacity()
                        + row.wire.name.capacity()
                        + crate::rar5::RAW_NAME_OWNER_BYTES
                        + extra_records_bytes(&row.header.extra_records) as usize
                })
                .sum::<usize>()
            + session
                .headers
                .iter()
                .map(|row| match &row.header {
                    StoredHeader::Member(_) => 0,
                    StoredHeader::Owned(header) => {
                        size_of::<FileHeader>() + header.name.capacity() + header.sub_data.capacity()
                    }
                })
                .sum::<usize>();
        let actual = variable
            + session.headers.capacity() * size_of::<HeaderRecord>()
            + session.model.members.capacity() * size_of::<Member>()
            + session.model.parts.capacity() * size_of::<Part>()
            + session.issues.capacity() * size_of::<RarFailure>()
            + session.volumes.capacity() * size_of::<HeldVolume>();
        assert_eq!(session.usage().capacity, actual as u64);
        let impossible = variable
            + 9 * (size_of::<Member>() + size_of::<Part>() + size_of::<RarFailure>() + size_of::<HeaderRecord>())
            + size_of::<HeldVolume>()
            - 1;
        let mut options = RarSessionOptions::default();
        options.limits.capacity = impossible as u64;
        let failure = RarSession::open(&path, None, options).err().unwrap();
        assert!(matches!(failure.failure.as_ref(), RarFailure::Limit { resource: RarResource::CatalogueCapacity, .. }));
    }

    #[test]
    fn rejects_packed_range_overflow_and_truncation_during_scan() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ranges.rar");
        let main = [0xc5, 0x1a, 0x33, 0x32, 3, 1, 0, 0];
        for (encoded_size, overflow) in [(&[0xff; 9][..], true), (&[1][..], false)] {
            let mut body = vec![2, 2];
            body.extend(encoded_size);
            if overflow {
                body.push(1);
            }
            body.extend([0, 1, 0, 0, 1, 1, b'a']);
            let mut sized = vec![body.len() as u8];
            sized.extend(body);
            let mut bytes = [super::super::SIGNATURE.as_slice(), &main].concat();
            bytes.extend(crate::crc32::hash(&sized).to_le_bytes());
            bytes.extend(sized);
            fs::write(&path, bytes).unwrap();
            let failure = RarSession::open(&path, None, RarSessionOptions::default()).err().unwrap();
            assert!(matches!(
                (overflow, failure.failure.as_ref()),
                (true, RarFailure::Integrity { reason: RarIntegrityReason::HeaderFraming("data size"), .. })
                    | (false, RarFailure::Integrity { reason: RarIntegrityReason::TruncatedData, .. })
            ));
        }
    }
}
