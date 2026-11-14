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

//! Finite budgets. These bound engine work, not provider allocations, RSS or disk space.
use super::{FailureKind, ProgressiveFailure, ProgressiveResult};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum Resource {
    VolumeHandles,
    ActiveOutputs,
    RetainedArtifacts,
    ReadChunk,
    HeaderAllocation,
    HeaderBytes,
    VolumeHeaderBytes,
    MetadataBytes,
    NameBytes,
    Entries,
    Parts,
    HoleIntervals,
    HeaderBlocks,
    SourceRequests,
    SourceBookkeeping,
    ProviderWakes,
    SourceBytes,
    LogicalOutputBytes,
    TempBytes,
    VerifyBytes,
    DecoderWindow,
    PackedWorkPerPoll,
    KdfExponent,
    KdfDerivationBlocks,
    KdfSessionBlocks,
    PasswordUtf8Bytes,
    PasswordEncodedBytes,
    ProtectionPaths,
    ProtectionPathBytes,
    OutputWriteBytes,
}
/// Adjustable budgets; descriptor and protection-inventory safety ceilings remain fixed.
/// Counts are cumulative unless a consumer explicitly establishes a smaller scope
/// (single allocation, volume, derivation, member, or poll).
#[derive(Clone, Debug)]
pub struct ProgressiveLimits {
    pub volume_handles: u64,
    pub active_outputs: u64,
    pub retained_artifacts: u64,
    pub read_chunk: u64,
    pub header_allocation: u64,
    pub header_bytes: u64,
    pub volume_header_bytes: u64,
    pub metadata_bytes: u64,
    pub name_bytes: u64,
    pub entries: u64,
    pub parts: u64,
    pub hole_intervals: u64,
    pub header_blocks: u64,
    pub source_requests: u64,
    /// Session-wide metadata comparisons/moves, plus native byte-comparison allowance.
    pub source_bookkeeping: u64,
    pub provider_wakes: u64,
    pub source_bytes: u64,
    pub logical_output_bytes: u64,
    pub temp_bytes: u64,
    /// Cumulative attempted output writes, including zero fill, patches and retries.
    pub output_write_bytes: u64,
    pub verify_bytes: u64,
    pub decoder_window: u64,
    pub packed_work_per_poll: u64,
    pub kdf_exponent: u64,
    pub kdf_derivation_blocks: u64,
    pub kdf_session_blocks: u64,
    pub password_utf8_bytes: u64,
    pub password_encoded_bytes: u64,
    pub protection_paths: u64,
    pub protection_path_bytes: u64,
}
impl Default for ProgressiveLimits {
    fn default() -> Self {
        Self {
            volume_handles: 64,
            active_outputs: 1,
            retained_artifacts: 16,
            read_chunk: 1048576,
            header_allocation: 2097152,
            header_bytes: 67108864,
            volume_header_bytes: 8388608,
            metadata_bytes: 134217728,
            name_bytes: 67108864,
            entries: 1000000,
            parts: 1000000,
            hole_intervals: 65536,
            header_blocks: 2000000,
            source_requests: 4194304,
            source_bookkeeping: 64 * 1024 * 1024,
            provider_wakes: 1048576,
            source_bytes: 68719476736,
            logical_output_bytes: 68719476736,
            temp_bytes: 68719476736,
            output_write_bytes: 68719476736,
            verify_bytes: 68719476736,
            decoder_window: 268435456,
            packed_work_per_poll: 1048576,
            kdf_exponent: 20,
            kdf_derivation_blocks: 4194304,
            kdf_session_blocks: 67108864,
            password_utf8_bytes: 4096,
            password_encoded_bytes: 8192,
            protection_paths: 4096,
            protection_path_bytes: 1048576,
        }
    }
}
impl ProgressiveLimits {
    pub(crate) fn limit(&self, resource: Resource) -> u64 {
        let configured = match resource {
            Resource::VolumeHandles => self.volume_handles,
            Resource::ActiveOutputs => self.active_outputs,
            Resource::RetainedArtifacts => self.retained_artifacts,
            Resource::ReadChunk => self.read_chunk,
            Resource::HeaderAllocation => self.header_allocation,
            Resource::HeaderBytes => self.header_bytes,
            Resource::VolumeHeaderBytes => self.volume_header_bytes,
            Resource::MetadataBytes => self.metadata_bytes,
            Resource::NameBytes => self.name_bytes,
            Resource::Entries => self.entries,
            Resource::Parts => self.parts,
            Resource::HoleIntervals => self.hole_intervals,
            Resource::HeaderBlocks => self.header_blocks,
            Resource::SourceRequests => self.source_requests,
            Resource::SourceBookkeeping => self.source_bookkeeping,
            Resource::ProviderWakes => self.provider_wakes,
            Resource::SourceBytes => self.source_bytes,
            Resource::LogicalOutputBytes => self.logical_output_bytes,
            Resource::TempBytes => self.temp_bytes,
            Resource::OutputWriteBytes => self.output_write_bytes,
            Resource::VerifyBytes => self.verify_bytes,
            Resource::DecoderWindow => self.decoder_window,
            Resource::PackedWorkPerPoll => self.packed_work_per_poll,
            Resource::KdfExponent => self.kdf_exponent,
            Resource::KdfDerivationBlocks => self.kdf_derivation_blocks,
            Resource::KdfSessionBlocks => self.kdf_session_blocks,
            Resource::PasswordUtf8Bytes => self.password_utf8_bytes,
            Resource::PasswordEncodedBytes => self.password_encoded_bytes,
            Resource::ProtectionPaths => self.protection_paths,
            Resource::ProtectionPathBytes => self.protection_path_bytes,
        };
        match resource {
            Resource::VolumeHandles | Resource::ProtectionPaths => configured.min(4096),
            Resource::ProtectionPathBytes => configured.min(1 << 20),
            Resource::KdfExponent => configured.min(20),
            _ => configured,
        }
    }
}
struct UsageState {
    limits: ProgressiveLimits,
    used: [u64; 30],
}
impl UsageState {
    pub(crate) fn new(limits: ProgressiveLimits) -> Self {
        Self { limits, used: [0; 30] }
    }
    pub(crate) fn check(&self, resource: Resource, attempted: u64) -> ProgressiveResult<()> {
        let limit = self.limits.limit(resource);
        if attempted > limit {
            return Err(ProgressiveFailure::new(FailureKind::Limit { resource, limit, attempted }));
        }
        Ok(())
    }
    pub(crate) fn charge(&mut self, resource: Resource, amount: u64) -> ProgressiveResult<()> {
        let i = resource as usize;
        let attempted = self.used[i].checked_add(amount).ok_or_else(|| {
            ProgressiveFailure::new(FailureKind::Limit {
                resource,
                limit: self.limits.limit(resource),
                attempted: u64::MAX,
            })
        })?;
        self.check(resource, attempted)?;
        self.used[i] = attempted;
        Ok(())
    }
}

/// Shared cumulative accounting only. Callers never hold this mutex across IO or callbacks.
#[derive(Clone)]
pub(crate) struct Usage(std::sync::Arc<std::sync::Mutex<UsageState>>);
impl Usage {
    pub(crate) fn new(limits: ProgressiveLimits) -> Self {
        Self(std::sync::Arc::new(std::sync::Mutex::new(UsageState::new(limits))))
    }
    pub(crate) fn check(&self, resource: Resource, attempted: u64) -> ProgressiveResult<()> {
        self.0.lock().unwrap().check(resource, attempted)
    }
    pub(crate) fn output_extent(&self, amount: u64) -> ProgressiveResult<()> {
        let mut state = self.0.lock().unwrap();
        for resource in [Resource::TempBytes, Resource::LogicalOutputBytes] {
            let total = state.used[resource as usize].checked_add(amount).ok_or_else(|| {
                ProgressiveFailure::new(FailureKind::Limit {
                    resource,
                    limit: state.limits.limit(resource),
                    attempted: u64::MAX,
                })
            })?;
            state.check(resource, total)?;
        }
        state.charge(Resource::TempBytes, amount)?;
        state.charge(Resource::LogicalOutputBytes, amount)
    }

    pub(crate) fn charge(&self, resource: Resource, amount: u64) -> ProgressiveResult<()> {
        self.0.lock().unwrap().charge(resource, amount)
    }
}
