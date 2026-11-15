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
use crate::progressive::{FailureKind, ProgressiveFailure, Resource, Usage};
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

fn malformed(reason: &'static str) -> MapError {
    MapError::Malformed { volume: 0, failure: Box::new(ProgressiveFailure::new(FailureKind::Malformed(reason))) }
}

fn directory(error: DirectoryError) -> MapError {
    match error {
        DirectoryError::NotZip => MapError::NotArchive,
        DirectoryError::UnsupportedDisk => MapError::Unsupported {
            volume: 0,
            failure: Box::new(ProgressiveFailure::new(FailureKind::Malformed("split ZIP archive"))),
        },
        DirectoryError::Limit(_) | DirectoryError::Ownership(_) | DirectoryError::Allocation => MapError::Unsupported {
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
    pub(super) fn new(usage: Usage) -> Self {
        Self {
            usage,
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
                    let parser = crate::zip::projected_parser(self.len, Limits::default()).map_err(directory)?;
                    self.phase = Phase::Directory(Box::new(parser));
                }
                Phase::Directory(parser) => {
                    let Some(range) = parser.next_read().map_err(directory)? else {
                        let Phase::Directory(parser) = std::mem::replace(&mut self.phase, Phase::Start) else {
                            unreachable!()
                        };
                        let mut found = parser.finish().map_err(directory)?;
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
                    parser.supply(range.start, &self.buffer[..count]).map_err(directory)?;
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
                    let aes_prefix = (entry.method == METHOD_AES && entry.flags & FLAG_ENCRYPTED != 0)
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
        let encrypted = entry.flags & FLAG_ENCRYPTED != 0;
        let method_id = match entry.aes_info {
            Some((_, _, actual)) if entry.method == METHOD_AES => actual,
            _ => entry.method,
        };
        let stored = method_id == 0;
        let (cipher, mapping) = if !encrypted {
            (None, if stored { OutputMapping::Direct } else { OutputMapping::None })
        } else if entry.flags & FLAG_STRONG != 0 {
            (None, OutputMapping::None)
        } else if let (Some((strength, vendor_version, _)), Some(prefix)) = (entry.aes_info, aes_prefix) {
            let cipher = (self.scratch.len() == prefix).then(|| CipherParams::WinZipAes {
                strength,
                vendor_version,
                salt: self.scratch[..prefix - 2].to_vec(),
                verifier: [self.scratch[prefix - 2], self.scratch[prefix - 1]],
            });
            (cipher, if stored { OutputMapping::Counter { skip: prefix as u64 } } else { OutputMapping::None })
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
        let crc_known = !matches!(entry.aes_info, Some((_, 2, _)) if entry.method == METHOD_AES);
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
