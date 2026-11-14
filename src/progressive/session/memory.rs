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

//! The only memory source allowed to establish whole-set publication authority.
use super::super::*;
use std::{ffi::OsString, fs::File, task::Context};

pub(crate) struct SealedMemory {
    volumes: Vec<(OsString, Option<Box<[u8]>>)>,
    pub(crate) metadata_bytes: u64,
    pub(crate) name_bytes: u64,
    pub(crate) source_bytes: u64,
}
impl SealedMemory {
    pub(crate) fn new(
        volumes: Vec<(OsString, Box<[u8]>)>,
        first: &std::ffi::OsStr,
        limits: &ProgressiveLimits,
    ) -> ProgressiveResult<Self> {
        let usage = Usage::new(limits.clone());
        usage.check(Resource::Entries, volumes.len() as u64)?;
        if volumes.len() as u64 > u64::from(u32::MAX) {
            return Err(invalid());
        }
        if volumes.is_empty() {
            return Err(ProgressiveFailure::new(FailureKind::MissingVolume));
        }
        let mut expected = first.to_owned();
        let mut metadata_bytes = (volumes.capacity() as u64)
            .checked_mul(std::mem::size_of::<(OsString, Option<Box<[u8]>>)>() as u64)
            .ok_or_else(invalid)?;
        let mut name_bytes = 0u64;
        let mut source_bytes = 0u64;
        for (i, (name, bytes)) in volumes.iter().enumerate() {
            if *name != expected {
                return Err(invalid());
            }
            name_bytes = name_bytes.checked_add(name.capacity() as u64).ok_or_else(invalid)?;
            source_bytes = source_bytes.checked_add(bytes.len() as u64).ok_or_else(invalid)?;
            if i + 1 < volumes.len() {
                expected = crate::volume::next_volume_os(name).ok_or_else(invalid)?;
            }
        }
        metadata_bytes =
            metadata_bytes.checked_add(name_bytes).and_then(|n| n.checked_add(source_bytes)).ok_or_else(invalid)?;
        usage.check(Resource::MetadataBytes, metadata_bytes)?;
        usage.check(Resource::NameBytes, name_bytes)?;
        usage.check(Resource::SourceBytes, source_bytes)?;
        Ok(Self {
            volumes: volumes.into_iter().map(|(n, b)| (n, Some(b))).collect(),
            metadata_bytes,
            name_bytes,
            source_bytes,
        })
    }
}
fn invalid() -> ProgressiveFailure {
    ProgressiveFailure::new(FailureKind::SourceContract)
}
impl VolumeSource for SealedMemory {
    fn volume(&mut self, request: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
        let Some((name, data)) = self.volumes.get_mut(request.index as usize) else { return Ok(VolumeAnswer::Missing) };
        if name != &request.expected {
            return Err(invalid());
        }
        let data = data.take().ok_or_else(invalid)?;
        Ok(VolumeAnswer::Ready(Box::new(MemoryRange { data, id: SourceId(u128::from(request.index) + 1) })))
    }
}
struct MemoryRange {
    data: Box<[u8]>,
    id: SourceId,
}
impl RangeSource for MemoryRange {
    fn info(&self) -> SourceInfo {
        SourceInfo {
            id: self.id,
            generation: 0,
            extent: self.data.len() as u64,
            length: SourceLength::Final(self.data.len() as u64),
        }
    }
    fn backing_files(&self) -> &[File] {
        &[]
    }
    fn read_at(&mut self, offset: u64, buf: &mut [u8], _: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
        let offset = usize::try_from(offset).map_err(|_| invalid())?;
        let bytes = self.data.get(offset..).ok_or_else(invalid)?;
        let count = bytes.len().min(buf.len());
        buf[..count].copy_from_slice(&bytes[..count]);
        Ok(RangeRead::Filled { count })
    }
}
