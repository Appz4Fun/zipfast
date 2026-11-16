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
    pub capacity: u64,
    pub parts: u64,
    pub header_blocks: u64,
    pub read_bytes: u64,
}

impl Default for RarCatalogueLimits {
    fn default() -> Self {
        Self {
            volumes: 64,
            entries: 1_000_000,
            name_bytes: 64 << 20,
            capacity: 128 << 20,
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
}

impl Default for RarSessionOptions {
    fn default() -> Self {
        Self { limits: RarCatalogueLimits::default(), cancel: Cancellation::default(), follow_volumes: true }
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
}

impl RarArchiveMetadata {
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
    headers: std::ops::Range<usize>,
    comment: Option<usize>,
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
    header: FileHeader,
    raw_name: Option<Arc<Vec<u8>>>,
}

/// One file or service header as stored in a volume, without merging the parts of a split member. Listing every
/// header of [`RarSession::headers`] in order gives UnRAR's `lt` and `v` output, orphan continuations included.
///
/// UnRAR's totals add [`Self::packed_size`] for every file header, but [`Self::unpacked_size`] and the file count
/// only for headers where [`Self::split_before`] is false.
#[derive(Clone, Copy)]
pub struct RarHeader<'a>(&'a HeaderRecord);

impl<'a> RarHeader<'a> {
    /// Zero-based volume position in the session.
    pub fn volume(&self) -> usize {
        self.0.volume
    }

    pub fn format(&self) -> super::RarFormat {
        self.0.header.format
    }

    /// Whether this is a service header (RAR 5.0 type 3, RAR 4.x `NEWSUB_HEAD`) rather than a file header.
    pub fn is_service(&self) -> bool {
        self.0.header.service
    }

    /// For a service header, its type name: `CMT`, `QO`, `RR`, `ACL`, `STM` or another.
    pub fn service_name(&self) -> Option<&'a str> {
        self.is_service().then_some(self.0.header.name.as_str())
    }

    /// A service header's SubData as stored, such as the stream name of an `STM` header (UnRAR's "Target"; UTF-8
    /// in RAR 5.0, UTF-16LE in RAR 4.x). Empty for file headers.
    pub fn service_data(&self) -> &'a [u8] {
        &self.0.header.sub_data
    }

    /// The part continues a member from an earlier volume.
    pub fn split_before(&self) -> bool {
        self.0.header.split_before()
    }

    /// The member continues in a later volume.
    pub fn split_after(&self) -> bool {
        self.0.header.split_after()
    }

    /// Stored name bytes, including RAR 4.x legacy and Unicode encoding.
    pub fn raw_name(&self) -> &'a [u8] {
        match &self.0.raw_name {
            Some(name) => name,
            None => self.0.header.name.as_bytes(),
        }
    }

    /// Name decoded by the header parser. RAR 4.x legacy names that are not UTF-8 decode to an empty string; use
    /// [`Self::raw_name`].
    pub fn name(&self) -> &'a str {
        &self.0.header.name
    }

    /// The name UnRAR on Unix gives a RAR 5.0 header, as raw `wchar_t` units; see [`RarMember::unrar_name`].
    pub fn unrar_name(&self) -> Option<Vec<u32>> {
        (self.format() == super::RarFormat::Rar5).then(|| super::unrar_name(self.raw_name()))
    }

    /// The declared unpacked size of the whole member, or None when the header marks it unknown.
    pub fn unpacked_size(&self) -> Option<u64> {
        (!self.0.header.size_unknown()).then_some(self.0.header.unpacked_size)
    }

    /// Packed bytes of this part in this volume.
    pub fn packed_size(&self) -> u64 {
        self.0.header.packed_size
    }

    /// Offset of this part's data in its volume.
    pub fn data_offset(&self) -> u64 {
        self.0.header.data_at
    }

    pub fn attributes(&self) -> u64 {
        self.0.header.attributes
    }

    /// Normalized host: 0 Windows (RAR 4.x MS-DOS, OS/2, Win32), 1 Unix, 2 other. RAR 4.x keeps its own value in
    /// [`super::Rar4Metadata::host`].
    pub fn host_os(&self) -> u64 {
        self.0.header.host_os
    }

    pub fn rar4_metadata(&self) -> Option<super::Rar4Metadata> {
        self.0.header.rar4
    }

    pub fn modified(&self) -> Option<RarTime> {
        let header = &self.0.header;
        header.mtime.map(|seconds| RarTime {
            seconds,
            nanos: header.mtime_nanos,
            resolution_nanos: header.mtime_resolution,
        })
    }

    pub fn created(&self) -> Option<RarTime> {
        self.0.header.ctime
    }

    pub fn accessed(&self) -> Option<RarTime> {
        self.0.header.atime
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
        let header = &self.0.header;
        RarChecks { crc32: header.crc32, blake2sp: header.blake2sp, keyed: header.crypt.is_some_and(|c| c.tweaked_crc) }
    }

    /// The CRC-32 of the member's unpacked data, declared by a final part.
    pub fn crc32(&self) -> Option<u32> {
        self.0.header.crc32.filter(|_| !self.split_after())
    }

    /// The CRC-32 of this part's packed data, declared by a part with a later continuation (UnRAR's "Pack-CRC32").
    pub fn pack_crc32(&self) -> Option<u32> {
        self.0.header.crc32.filter(|_| self.split_after())
    }

    pub fn blake2sp(&self) -> Option<[u8; 32]> {
        self.0.header.blake2sp
    }

    /// Compression level: 0 is stored, 1 to 5 are `-m1` to `-m5`.
    pub fn method(&self) -> u8 {
        self.0.header.method
    }

    /// RAR 5.0 algorithm: 0 for RAR 5.0 ("v50"), 1 for RAR 7.0 ("v70"). RAR 4.x keeps its unpack version in
    /// [`super::Rar4Metadata::unpack_version`].
    pub fn algorithm(&self) -> u8 {
        self.0.header.algorithm
    }

    /// The file version number of an older revision kept by `-ver` (RAR 5.0 version record).
    pub fn version(&self) -> Option<u64> {
        self.0.header.version
    }

    pub fn dictionary(&self) -> u64 {
        self.0.header.dictionary
    }

    /// The header's own solid flag (RAR 4.x `LHD_SOLID`, RAR 5.0 compression info), which UnRAR lists as "solid".
    /// The first member of a RAR 4.x solid archive does not set it.
    pub fn solid(&self) -> bool {
        self.0.header.solid
    }

    pub fn encrypted(&self) -> bool {
        self.0.header.encrypted
    }

    pub fn is_directory(&self) -> bool {
        self.0.header.is_dir()
    }

    pub fn redirection(&self) -> Option<&'a Redirection> {
        self.0.header.redirection.as_ref()
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

    pub fn version(&self) -> Option<u64> {
        self.member.header.version
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
        if header.method != 0 || header.encrypted || header.is_dir() || offset >= header.unpacked_size {
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
    options: RarSessionOptions,
    token: Arc<selection::SessionToken>,
    invalid_binding: Option<Arc<RarFailure>>,
}

impl RarSession {
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
                options: options.clone(),
                token: Arc::new(selection::SessionToken { _private: 0 }),
                invalid_binding: None,
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
            let password = password.unwrap_or_default();
            limit(password.len() as u64, catalogue.options.limits.capacity, RarResource::CatalogueCapacity)?;
            catalogue.session.password.try_reserve_exact(password.len()).map_err(|_| allocation())?;
            catalogue.session.password.push_str(password);
            catalogue.owned_capacity = catalogue.session.password.capacity() as u64;
            catalogue.update_capacity()?;
            catalogue.scan(first, Some(password))
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
        self.headers.iter().map(RarHeader)
    }

    /// The headers of one volume, in order. Empty for a volume index past the end.
    pub fn volume_headers(&self, volume: usize) -> impl ExactSizeIterator<Item = RarHeader<'_>> {
        let range = self.volumes.get(volume).map_or(0..0, |held| held.metadata.headers.clone());
        self.headers[range].iter().map(RarHeader)
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
            return service_comment(held, &self.headers[index].header, &self.options.cancel).map(Some);
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
                    return Err(RarFault::new(
                        RarFailure::MissingVolume { path: path.clone() },
                        Error::MissingVolume(path),
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound && required == Some(false) => break,
                Err(error) => return Err(RarFault::input(IoOperation::Open, Some(path), None, error)),
            };
            let stamp = SourceStamp::capture_for_output(&file, &path, self.output_identity)?;
            if self.session.volumes.iter().any(|v| (v.stamp.device, v.stamp.inode) == (stamp.device, stamp.inode)) {
                return Err(volume_framing(&path, "RAR volume identity repeats"));
            }
            self.owned_capacity = add(self.owned_capacity, path_bytes)?;
            let mut volume = Volume::open_catalogue(&path, file, stamp.len, password, &mut self.scan_budget())?;
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
            while let Some((block, crypt, wire)) = volume.next_catalogue(&mut self.scan_budget())? {
                match block {
                    Block::File(header) => {
                        let wire = wire.expect("catalogue file metadata includes the wire name");
                        let listed = header.clone();
                        let raw_name = wire.name.clone();
                        self.add_part(volume_index, header, crypt, wire)?;
                        self.add_header(volume_index, listed, Some(raw_name))?;
                    }
                    Block::Service(header) => {
                        if comment.is_none() && header.name == "CMT" {
                            comment = Some(self.session.headers.len());
                        }
                        self.add_header(volume_index, header, wire.map(|wire| wire.name))?;
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
            self.owned_capacity = add(self.owned_capacity, original)?;
            let metadata = RarVolumeMetadata {
                format,
                main: volume.main.clone(),
                encrypted_headers,
                sfx_size: volume.sfx_size(),
                end,
                headers: first_header..self.session.headers.len(),
                comment,
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

    fn scan_budget(&mut self) -> ScanBudget<'_> {
        ScanBudget { cancel: &self.options.cancel, limits: self.options.limits, usage: &mut self.session.usage }
    }

    fn add_part(&mut self, volume: usize, header: FileHeader, crypt: MemberCrypt, wire: FileWire) -> RarResult<()> {
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
                return Ok(());
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
            reserve_one(&mut self.session.model.parts, base, self.options.limits.capacity)?;
            let issue = self.retain_issue(issue)?;
            let member = self.session.model.members.last_mut().unwrap();
            member.append(&header, &part)?;
            if issue.is_some() {
                member.issue = issue;
            }
        } else {
            let entries = add(self.session.usage.entries, 1)?;
            limit(entries, self.options.limits.entries, RarResource::CatalogueEntries)?;
            let target = target_name(&header);
            let name_bytes =
                add(add(header.name.len() as u64, wire.name.len() as u64)?, target.map_or(0, |t| t.len() as u64))?;
            let names = add(self.session.usage.name_bytes, name_bytes)?;
            limit(names, self.options.limits.name_bytes, RarResource::CatalogueNameBytes)?;
            let allocation = add(
                add(header.name.capacity() as u64, wire.name.capacity() as u64)?,
                add(target.map_or(0, |t| t.capacity() as u64), crate::rar5::RAW_NAME_OWNER_BYTES as u64)?,
            )?;
            let part_minimum = u64::from(self.session.model.parts.len() == self.session.model.parts.capacity())
                * size_of::<Part>() as u64;
            let base = add(
                self.capacity_without::<Member>(self.session.model.members.capacity())?,
                add(add(allocation, part_minimum)?, issue_minimum)?,
            )?;
            reserve_one(&mut self.session.model.members, base, self.options.limits.capacity)?;
            let base = add(
                self.capacity_without::<Part>(self.session.model.parts.capacity())?,
                add(allocation, issue_minimum)?,
            )?;
            reserve_one(&mut self.session.model.parts, base, self.options.limits.capacity)?;
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
        self.update_capacity()
    }

    /// Retain one file or service header for [`RarSession::headers`]. The decoded name, redirection target and
    /// SubData are charged here; the raw name too unless a member already owns (and was charged for) it, as with an
    /// orphan continuation or a service header.
    fn add_header(&mut self, volume: usize, header: FileHeader, raw_name: Option<Arc<Vec<u8>>>) -> RarResult<()> {
        let unowned_name = raw_name
            .as_ref()
            .filter(|name| Arc::strong_count(name) == 1)
            .map_or(0, |name| (name.capacity() + crate::rar5::RAW_NAME_OWNER_BYTES) as u64);
        let allocation = add(
            add(header.name.capacity() as u64, target_name(&header).map_or(0, |t| t.capacity() as u64))?,
            add(header.sub_data.capacity() as u64, unowned_name)?,
        )?;
        let base = add(self.capacity_without::<HeaderRecord>(self.session.headers.capacity())?, allocation)?;
        reserve_one(&mut self.session.headers, base, self.options.limits.capacity)?;
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
        reserve_one(&mut self.session.volumes, base, self.options.limits.capacity)
    }

    fn retain_issue(&mut self, issue: Option<RarFailure>) -> RarResult<Option<usize>> {
        let Some(issue) = issue else { return Ok(None) };
        let base = self.capacity_without::<RarFailure>(self.session.issues.capacity())?;
        reserve_one(&mut self.session.issues, base, self.options.limits.capacity)?;
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
        limit(capacity, self.options.limits.capacity, RarResource::CatalogueCapacity)?;
        self.session.usage.capacity = capacity;
        Ok(())
    }
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
    cancel: &'a Cancellation,
    limits: RarCatalogueLimits,
    usage: &'a mut RarCatalogueUsage,
}

impl ScanBudget<'_> {
    pub(super) fn temporary(&self, bytes: u64) -> RarResult<()> {
        limit(add(self.usage.capacity, bytes)?, self.limits.capacity, RarResource::CatalogueCapacity)
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

    pub(super) fn check_read(&self, len: usize) -> RarResult<()> {
        self.check()?;
        let total = add(self.usage.read_bytes, len as u64)?;
        limit(total, self.limits.read_bytes, RarResource::CatalogueReadBytes)
    }
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
                .map(|row| row.header.name.capacity() + row.wire.name.capacity() + crate::rar5::RAW_NAME_OWNER_BYTES)
                .sum::<usize>()
            + session
                .headers
                .iter()
                .map(|row| row.header.name.capacity() + row.header.sub_data.capacity())
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
