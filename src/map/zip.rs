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

//! The single-disk ZIP walker: the central directory through its range-requesting parser, then each entry's local
//! header (and, for WinZip AES, the salt and verifier at the start of its data).
use super::{
    CipherParams, Got, MapChecks, MapEnd, MapError, MapFormat, MapInput, MapMember, MapMethod, MapOptions, MapPiece,
    MemberMap, OutputMapping, read,
};
use crate::progressive::{FailureKind, ProgressiveFailure, ProgressiveLimits, Resource, Usage};
use crate::zip::ZipEntry;
use std::task::{Context, Poll};
use zip_container::{DirectoryError, DirectoryParser, LOCAL_HEADER_LEN, Limits, LocalHeader, local_layout};

const FLAG_ENCRYPTED: u16 = 0x0001;
const FLAG_DESCRIPTOR: u16 = 0x0008;
const FLAG_STRONG: u16 = 0x0040;
const METHOD_AES: u16 = 99;
const CHUNK: usize = 64 << 10;

enum Phase {
    Start,
    Directory(Box<DirectoryParser<ZipEntry>>),
    Locals { entries: Vec<ZipEntry>, index: usize },
}

pub(super) struct ZipWalker {
    usage: Usage,
    limits: Limits,
    phase: Phase,
    len: u64,
    parked: Option<usize>,
    buffer: Vec<u8>,
    /// Bytes gathered for the current entry: its local header, then its AES prefix.
    scratch: Vec<u8>,
    /// The current entry's local header range and payload range, once parsed.
    local: Option<(std::ops::Range<u64>, std::ops::Range<u64>, LocalHeader)>,
    members: Vec<MapMember>,
}

/// WinZip AES, decided as the extractor decides it.
fn is_aes(entry: &ZipEntry) -> bool {
    entry.method == METHOD_AES || entry.aes_info.is_some()
}

fn malformed(reason: &'static str) -> MapError {
    MapError::Malformed { volume: 0, failure: Box::new(ProgressiveFailure::new(FailureKind::Malformed(reason))) }
}

/// Directory parser limits within the caller's budgets.
fn zip_limits(limits: &ProgressiveLimits) -> Limits {
    let default = Limits::default();
    Limits {
        directory_bytes: default.directory_bytes.min(limits.header_bytes),
        entries: default.entries.min(limits.entries),
        fetched_bytes: default.fetched_bytes.min(limits.header_bytes),
        name_bytes: default.name_bytes.min(limits.name_bytes),
        extra_bytes: default.extra_bytes.min(limits.metadata_bytes),
        comment_bytes: default.comment_bytes.min(limits.metadata_bytes),
        ..default
    }
}

fn directory(error: DirectoryError, limits: &Limits) -> MapError {
    match error {
        DirectoryError::Limit(kind) => {
            use zip_container::LimitKind;
            let (resource, limit) = match kind {
                LimitKind::Entries => (Resource::Entries, limits.entries),
                LimitKind::NameBytes => (Resource::NameBytes, limits.name_bytes),
                LimitKind::ExtraBytes => (Resource::MetadataBytes, limits.extra_bytes),
                LimitKind::CommentBytes => (Resource::MetadataBytes, limits.comment_bytes),
                LimitKind::FetchedBytes => (Resource::HeaderBytes, limits.fetched_bytes),
                LimitKind::DirectoryBytes => (Resource::HeaderBytes, limits.directory_bytes),
                LimitKind::RangeBytes => (Resource::ReadChunk, limits.range_bytes),
                LimitKind::WorkUnits => (Resource::HeaderBytes, limits.work_units),
                LimitKind::ScratchBytes => (Resource::HeaderAllocation, limits.directory_bytes),
            };
            // The directory parser reports the budget, not the amount it tried.
            MapError::Limit { resource, limit, attempted: limit.saturating_add(1) }
        }
        DirectoryError::Ownership(zip_container::OwnershipError::LimitExceeded { kind, needed, limit }) => {
            use zip_container::OwnershipKind;
            let resource = match kind {
                OwnershipKind::Entries => Resource::Entries,
                OwnershipKind::NameBytes => Resource::NameBytes,
                OwnershipKind::ExtraBytes | OwnershipKind::CommentBytes => Resource::MetadataBytes,
            };
            MapError::Limit { resource, limit: limit as u64, attempted: needed as u64 }
        }
        DirectoryError::NotZip => MapError::NotArchive,
        DirectoryError::UnsupportedDisk => MapError::Unsupported {
            volume: 0,
            failure: Box::new(ProgressiveFailure::new(FailureKind::Malformed("split ZIP archive"))),
        },
        DirectoryError::Ownership(_) | DirectoryError::Allocation => MapError::Unsupported {
            volume: 0,
            failure: Box::new(ProgressiveFailure::new(FailureKind::Malformed(
                "ZIP directory exceeds the listing limit",
            ))),
        },
        DirectoryError::MalformedEnd => malformed("central directory size or offset"),
        DirectoryError::MalformedZip64 => malformed("ZIP64 metadata"),
        DirectoryError::EntryCount { .. } => malformed("central directory entry count"),
        DirectoryError::InvalidLocalOffset => malformed("local header offset"),
        DirectoryError::Supply(_) | DirectoryError::Incomplete => malformed("ZIP directory source range"),
        DirectoryError::Parse(_) => malformed("central directory record"),
    }
}

impl ZipWalker {
    pub(super) fn new(usage: Usage, limits: &ProgressiveLimits) -> Self {
        Self {
            usage,
            limits: zip_limits(limits),
            phase: Phase::Start,
            len: 0,
            parked: None,
            buffer: vec![0; CHUNK],
            scratch: Vec::new(),
            local: None,
            members: Vec::new(),
        }
    }

    pub(super) fn poll(
        &mut self,
        input: &mut dyn MapInput,
        cx: &mut Context<'_>,
        options: &MapOptions,
    ) -> Poll<Result<MemberMap, MapError>> {
        match self.poll_inner(input, cx, options) {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(map)) => Poll::Ready(Ok(map)),
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    /// Reads up to `want` bytes at `offset` into the buffer. None means pending.
    fn fetch(
        &mut self,
        input: &mut dyn MapInput,
        cx: &mut Context<'_>,
        offset: u64,
        want: usize,
    ) -> Result<Option<usize>, MapError> {
        let n = self.parked.take().unwrap_or_else(|| want.min(self.buffer.len()));
        match read(input, &self.usage, offset, &mut self.buffer[..n], cx).map_err(|e| MapError::from_failure(0, e))? {
            Got::NotYet => {
                self.parked = Some(n);
                Ok(None)
            }
            Got::Hole => Err(MapError::HeaderHole { volume: 0, offset }),
            Got::Eof => Err(malformed("ZIP header past the end of the archive")),
            Got::Filled(count) => Ok(Some(count.min(n))),
        }
    }

    fn poll_inner(
        &mut self,
        input: &mut dyn MapInput,
        cx: &mut Context<'_>,
        options: &MapOptions,
    ) -> Result<Poll<MemberMap>, MapError> {
        loop {
            if options.control.is_canceled() {
                return Err(MapError::Source(Box::new(ProgressiveFailure::new(FailureKind::Canceled))));
            }
            match &mut self.phase {
                Phase::Start => {
                    self.len = input.len();
                    let parser =
                        crate::zip::projected_parser(self.len, self.limits).map_err(|e| directory(e, &self.limits))?;
                    self.phase = Phase::Directory(Box::new(parser));
                }
                Phase::Directory(parser) => {
                    let limits = self.limits;
                    let Some(range) = parser.next_read().map_err(|e| directory(e, &limits))? else {
                        let Phase::Directory(parser) = std::mem::replace(&mut self.phase, Phase::Start) else {
                            unreachable!()
                        };
                        let mut found = parser.finish().map_err(|e| directory(e, &limits))?;
                        crate::zip::relocate_projected(&mut found.entries, found.prefix_shift, self.len, None)
                            .map_err(|_| malformed("local header offset"))?;
                        self.usage
                            .charge(Resource::Entries, found.entries.len() as u64)
                            .and_then(|_| self.usage.charge(Resource::Parts, found.entries.len() as u64))
                            .map_err(|e| MapError::from_failure(0, e))?;
                        self.phase = Phase::Locals { entries: found.entries, index: 0 };
                        continue;
                    };
                    let want = usize::try_from(range.end - range.start).unwrap_or(usize::MAX);
                    let Some(count) = self.fetch(input, cx, range.start, want)? else { return Ok(Poll::Pending) };
                    let Phase::Directory(parser) = &mut self.phase else { unreachable!() };
                    self.usage.charge(Resource::HeaderBytes, count as u64).map_err(|e| MapError::from_failure(0, e))?;
                    parser.supply(range.start, &self.buffer[..count]).map_err(|e| directory(e, &limits))?;
                }
                Phase::Locals { entries, index } => {
                    let Some(entry) = entries.get(*index).cloned() else {
                        return Ok(Poll::Ready(MemberMap {
                            format: MapFormat::Zip,
                            header_encrypted: false,
                            header_cipher: None,
                            complete: true,
                            end: MapEnd::Complete,
                            volumes: 1,
                            members: std::mem::take(&mut self.members),
                        }));
                    };
                    let local_at = entry.local_at;
                    let aes_prefix = is_aes(&entry)
                        .then_some(entry.aes_info)
                        .flatten()
                        .map(|(strength, _, _)| 4 + 4 * usize::from(strength) + 2);
                    // Gather the local header, then the AES salt and verifier.
                    let (at, want) = match &self.local {
                        None => (local_at + self.scratch.len() as u64, LOCAL_HEADER_LEN - self.scratch.len()),
                        Some((_, payload, _)) => match aes_prefix {
                            Some(prefix) if (self.scratch.len() as u64) < (prefix as u64).min(entry.packed) => {
                                let have = self.scratch.len();
                                (payload.start + have as u64, prefix.min(entry.packed as usize) - have)
                            }
                            _ => {
                                let member = self.member(&entry, aes_prefix)?;
                                self.members.push(member);
                                self.local = None;
                                self.scratch.clear();
                                let Phase::Locals { index, .. } = &mut self.phase else { unreachable!() };
                                *index += 1;
                                continue;
                            }
                        },
                    };
                    let Some(count) = self.fetch(input, cx, at, want)? else { return Ok(Poll::Pending) };
                    self.usage.charge(Resource::HeaderBytes, count as u64).map_err(|e| MapError::from_failure(0, e))?;
                    self.scratch.extend_from_slice(&self.buffer[..count]);
                    if self.local.is_none() && self.scratch.len() == LOCAL_HEADER_LEN {
                        let header =
                            LocalHeader::parse(&self.scratch).map_err(|_| malformed("local header signature"))?;
                        let layout = local_layout(header, entry.local_at, self.len)
                            .map_err(|_| malformed("local header size"))?;
                        let payload = layout
                            .payload_range(entry.packed, self.len)
                            .map_err(|_| malformed("ZIP entry data past the end of the archive"))?;
                        self.local = Some((entry.local_at..payload.start, payload, header));
                        self.scratch.clear();
                    }
                }
            }
        }
    }

    fn member(&self, entry: &ZipEntry, aes_prefix: Option<usize>) -> Result<MapMember, MapError> {
        let (header_range, payload, local) = self.local.clone().expect("local header parsed");
        self.usage
            .charge(
                Resource::MetadataBytes,
                (std::mem::size_of::<MapMember>() + std::mem::size_of::<MapPiece>() + 2 * entry.name.len()) as u64,
            )
            .map_err(|e| MapError::from_failure(0, e))?;
        // As the extractor decides (src/zip.rs): flag bit 0, method 99, or an AES extra field.
        let encrypted = entry.flags & FLAG_ENCRYPTED != 0 || is_aes(entry);
        let method_id = entry.effective_method();
        let stored = method_id == 0;
        let (cipher, mapping) = if !encrypted {
            (None, if stored { OutputMapping::Direct } else { OutputMapping::None })
        } else if entry.flags & FLAG_STRONG != 0 {
            (None, OutputMapping::None)
        } else if is_aes(entry) {
            // As the extractor decides: method 99 or an AES extra field. Without a valid extra field (or with data
            // too short for the salt and verifier) nothing is mapped.
            match (entry.aes_info, aes_prefix) {
                (Some((strength, vendor_version, _)), Some(prefix)) if self.scratch.len() == prefix => (
                    Some(CipherParams::WinZipAes {
                        strength,
                        vendor_version,
                        salt: self.scratch[..prefix - 2].to_vec(),
                        verifier: [self.scratch[prefix - 2], self.scratch[prefix - 1]],
                    }),
                    if stored { OutputMapping::Counter { skip: prefix as u64 } } else { OutputMapping::None },
                ),
                _ => (None, OutputMapping::None),
            }
        } else {
            let check = if entry.flags & FLAG_DESCRIPTOR != 0 {
                (local.mod_time >> 8) as u8
            } else {
                (entry.crc32 >> 24) as u8
            };
            (
                Some(CipherParams::ZipCrypto { check }),
                if stored { OutputMapping::Sequential { skip: 12 } } else { OutputMapping::None },
            )
        };
        let crc_known = !(encrypted && is_aes(entry) && matches!(entry.aes_info, Some((_, 2, _))));
        let checks = MapChecks { crc32: crc_known.then_some(entry.crc32), blake2sp: None, keyed: false };
        let size = Some(entry.size);
        let out = mapping.out_of(0..entry.packed, size);
        Ok(MapMember {
            ordinal: self.members.len() as u64,
            raw_name: entry.name.as_bytes().to_vec(),
            name: Some(entry.name.clone()),
            is_dir: entry.is_dir(),
            unpacked_size: size,
            packed_size: entry.packed,
            method: if stored { MapMethod::Stored } else { MapMethod::Compressed { id: method_id } },
            mapping,
            solid: false,
            encrypted,
            cipher,
            checks: Some(checks),
            mtime: entry.mtime.map(|s| (s, entry.nanos)),
            attributes: u64::from(entry.external),
            unix_mode: entry.unix_mode(),
            complete: true,
            pieces: vec![MapPiece {
                volume: 0,
                packed: payload,
                header: header_range,
                stream_offset: 0,
                out,
                checks,
                final_part: true,
            }],
        })
    }
}
