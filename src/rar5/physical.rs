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

//! Shared physical metadata. Each logical member owns its wire name exactly once.
use super::session::RarChecks;
use super::{FileHeader, FileWire, MemberCrypt};
use crate::error::RarIntegrityReason;
use std::ops::Range;

pub(crate) struct PhysicalPart {
    pub(crate) volume: usize,
    pub(crate) data_offset: u64,
    pub(crate) packed_size: u64,
    pub(crate) checks: RarChecks,
    pub(crate) crypt: MemberCrypt,
    pub(crate) final_part: bool,
    pub(crate) wire_extent: Range<u64>,
    pub(crate) raw_flags: u64,
    pub(crate) raw_compression: u64,
    pub(crate) plain_extent: Option<Range<u64>>,
}

pub(crate) struct PhysicalMember {
    pub(crate) header: FileHeader,
    pub(crate) wire: FileWire,
    pub(crate) parts: Range<usize>,
    pub(crate) packed_size: u64,
    pub(crate) unpacked_size: Option<u64>,
    pub(crate) complete: bool,
    pub(crate) final_checks: Option<RarChecks>,
    pub(crate) issue: Option<usize>,
    pub(crate) chain: Option<usize>,
    pub(crate) has_successor: bool,
}

/// The same continuation encoding and size checks serve catalogue and progressive adapters.
pub(crate) fn continuation_issue(initial: &PhysicalMember, header: &FileHeader) -> Option<RarIntegrityReason> {
    if (header.method == 0) != (initial.header.method == 0)
        || header.algorithm != initial.header.algorithm
        || header.encrypted != initial.header.encrypted
        || header.is_dir() != initial.header.is_dir()
        || header.redirection != initial.header.redirection
    {
        Some(RarIntegrityReason::ChangedContinuationEncoding)
    } else if let (Some(expected), Some(actual)) =
        (initial.unpacked_size, (!header.size_unknown()).then_some(header.unpacked_size))
        && expected != actual
    {
        Some(RarIntegrityReason::SplitSizeMismatch { expected, actual })
    } else {
        None
    }
}

#[derive(Default)]
pub(crate) struct PhysicalModel {
    pub(crate) members: Vec<PhysicalMember>,
    pub(crate) parts: Vec<PhysicalPart>,
}
impl PhysicalPart {
    pub(crate) fn new(volume: usize, header: &FileHeader, crypt: MemberCrypt, wire: &FileWire) -> Self {
        Self {
            volume,
            data_offset: header.data_at,
            packed_size: header.packed_size,
            checks: RarChecks {
                crc32: header.crc32,
                blake2sp: header.blake2sp,
                keyed: header.crypt.is_some_and(|c| c.tweaked_crc),
            },
            crypt,
            final_part: !header.split_after(),
            wire_extent: wire.extent.clone(),
            raw_flags: header.block_flags,
            raw_compression: wire.compression,
            plain_extent: None,
        }
    }
}
impl PhysicalMember {
    pub(crate) fn new(
        header: FileHeader,
        wire: FileWire,
        index: usize,
        part: &PhysicalPart,
    ) -> crate::error::RarResult<Self> {
        let unpacked_size = (!header.size_unknown()).then_some(header.unpacked_size);
        Ok(Self {
            header,
            wire,
            parts: index..index.checked_add(1).ok_or_else(crate::error::RarFault::counter_limit)?,
            packed_size: part.packed_size,
            unpacked_size,
            complete: part.final_part,
            final_checks: part.final_part.then_some(part.checks),
            issue: None,
            chain: None,
            has_successor: false,
        })
    }
    pub(crate) fn matches_continuation(&self, header: &FileHeader, wire: &FileWire) -> bool {
        header.split_before() && self.wire.name == wire.name
    }
    pub(crate) fn append(&mut self, header: &FileHeader, part: &PhysicalPart) -> crate::error::RarResult<()> {
        self.parts.end = self.parts.end.checked_add(1).ok_or_else(crate::error::RarFault::counter_limit)?;
        self.packed_size =
            self.packed_size.checked_add(part.packed_size).ok_or_else(crate::error::RarFault::counter_limit)?;
        self.unpacked_size = self.unpacked_size.or((!header.size_unknown()).then_some(header.unpacked_size));
        self.complete = part.final_part;
        self.final_checks = part.final_part.then_some(part.checks);
        Ok(())
    }
}
