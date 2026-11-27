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
    VerifyWorkBytes,
}
impl Resource {
    /// Every resource, in declaration order.
    pub const ALL: [Resource; 31] = [
        Resource::VolumeHandles,
        Resource::ActiveOutputs,
        Resource::RetainedArtifacts,
        Resource::ReadChunk,
        Resource::HeaderAllocation,
        Resource::HeaderBytes,
        Resource::VolumeHeaderBytes,
        Resource::MetadataBytes,
        Resource::NameBytes,
        Resource::Entries,
        Resource::Parts,
        Resource::HoleIntervals,
        Resource::HeaderBlocks,
        Resource::SourceRequests,
        Resource::SourceBookkeeping,
        Resource::ProviderWakes,
        Resource::SourceBytes,
        Resource::LogicalOutputBytes,
        Resource::TempBytes,
        Resource::VerifyBytes,
        Resource::DecoderWindow,
        Resource::PackedWorkPerPoll,
        Resource::KdfExponent,
        Resource::KdfDerivationBlocks,
        Resource::KdfSessionBlocks,
        Resource::PasswordUtf8Bytes,
        Resource::PasswordEncodedBytes,
        Resource::ProtectionPaths,
        Resource::ProtectionPathBytes,
        Resource::OutputWriteBytes,
        Resource::VerifyWorkBytes,
    ];
}
/// A read-only snapshot of one budget: what the session has charged so far and the effective ceiling (the
/// configured limit, clamped by any fixed safety ceiling). Leased scratch counts only while it is live, and a
/// resource scoped to a smaller unit (one allocation, poll or derivation) reports its cumulative charge as well.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceUsage {
    pub used: u64,
    pub limit: u64,
}
impl ResourceUsage {
    /// What is left before the limit.
    pub fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }
}
/// Adjustable budgets; descriptor and protection-inventory safety ceilings remain fixed.
/// Counts are cumulative unless a consumer explicitly establishes a smaller scope
/// (single allocation, volume, derivation, member, or poll).
/// Scratch memory that an operation frees again (persistent-partial transaction
/// copies, encodings, compare buffers) is charged only while it is live.
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
    /// Byte-span processing passes during verification; not physical IO or CPU time.
    pub verify_work_bytes: u64,
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
/// The default of every byte-total limit (source, logical output, temp, output writes, verify): 1 TiB.
pub const DEFAULT_BYTE_TOTAL: u64 = 1 << 40;

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
            // Byte totals are not where a hostile archive is stopped (declared sizes, the decoder window and the
            // per-poll work are): they only have to exceed real sets, such as 70-100 GB UHD remux posts. 1 TiB each.
            source_bytes: DEFAULT_BYTE_TOTAL,
            logical_output_bytes: DEFAULT_BYTE_TOTAL,
            temp_bytes: DEFAULT_BYTE_TOTAL,
            output_write_bytes: DEFAULT_BYTE_TOTAL,
            verify_bytes: DEFAULT_BYTE_TOTAL,
            verify_work_bytes: DEFAULT_BYTE_TOTAL,
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
            Resource::VerifyWorkBytes => self.verify_work_bytes,
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
    /// Checks a 7zAES `NumCyclesPower` against `kdf_exponent`. The shared ceiling of 20 in [`Self::limit`] is the
    /// RAR 5.0 derivation's own; 7zAES derives up to 2^24 rounds, as 7-Zip accepts, so its ceiling is 24.
    pub(crate) fn check_seven_zip_kdf(&self, num_cycles_power: u8) -> ProgressiveResult<()> {
        let limit = self.kdf_exponent.min(u64::from(crate::crypto::SEVEN_ZIP_MAX_CYCLES_POWER));
        let attempted = u64::from(num_cycles_power);
        if num_cycles_power != 0x3F && attempted > limit {
            return Err(ProgressiveFailure::new(FailureKind::Limit {
                resource: Resource::KdfExponent,
                limit,
                attempted,
            }));
        }
        Ok(())
    }
}
struct UsageState {
    limits: ProgressiveLimits,
    used: [u64; 31],
    /// RAR 5.0 key material the session derived, by password, salt and count: a later member with the same input
    /// costs no derivation work.
    rar5_keys: crate::crypto::Rar5KeyCache,
    /// RAR 3.x keys the session derived, by password and salt.
    rar4_keys: crate::crypto::Rar4Keys,
    /// 7zAES keys the session derived, by password, cycle power and salt.
    seven_zip_keys: crate::crypto::KdfCache<(u8, Vec<u8>), [u8; 32]>,
}
impl UsageState {
    pub(crate) fn new(limits: ProgressiveLimits) -> Self {
        Self {
            limits,
            used: [0; 31],
            rar5_keys: Default::default(),
            rar4_keys: Default::default(),
            seven_zip_keys: Default::default(),
        }
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
pub(crate) struct Usage(std::sync::Arc<std::sync::Mutex<UsageState>>, Option<std::sync::Arc<UsageScope>>);
/// Resources a [`Usage::scoped`] view gives back when its last clone drops: memory that lives exactly as long
/// as the owner of the scope (a persistent member's core), never work done.
const SCOPED: [Resource; 3] = [Resource::MetadataBytes, Resource::ProtectionPaths, Resource::ProtectionPathBytes];
fn scoped_index(resource: Resource) -> Option<usize> {
    SCOPED.iter().position(|r| *r == resource)
}
/// What one scope has charged to the shared accounting, refunded when the scope's last [`Usage`] drops.
pub(crate) struct UsageScope {
    state: std::sync::Arc<std::sync::Mutex<UsageState>>,
    charged: std::sync::Mutex<[u64; SCOPED.len()]>,
}
impl Drop for UsageScope {
    fn drop(&mut self) {
        let charged = *self.charged.get_mut().unwrap_or_else(|e| e.into_inner());
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        for (resource, amount) in SCOPED.iter().zip(charged) {
            let used = &mut state.used[*resource as usize];
            *used = used.saturating_sub(amount);
        }
    }
}
impl Usage {
    pub(crate) fn new(limits: ProgressiveLimits) -> Self {
        Self(std::sync::Arc::new(std::sync::Mutex::new(UsageState::new(limits))), None)
    }
    /// A view of the same accounting whose metadata and protection path charges are given back once every clone
    /// of the view has dropped. Charges keep counting against the shared limits while it lives.
    #[cfg_attr(not(feature = "persistent-partials"), allow(dead_code, reason = "persistent partial cores scope usage"))]
    pub(crate) fn scoped(&self) -> Self {
        let scope = UsageScope { state: self.0.clone(), charged: std::sync::Mutex::new([0; SCOPED.len()]) };
        Self(self.0.clone(), Some(std::sync::Arc::new(scope)))
    }
    fn record(&self, resource: Resource, amount: u64, add: bool) {
        if let (Some(scope), Some(index)) = (&self.1, scoped_index(resource)) {
            let mut charged = scope.charged.lock().unwrap_or_else(|e| e.into_inner());
            charged[index] =
                if add { charged[index].saturating_add(amount) } else { charged[index].saturating_sub(amount) };
        }
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

    /// RAR 5.0 key material this session derived before for the input, when it serves a member with `check`
    /// ([`crate::crypto::Rar5Derived::serves`]).
    pub(crate) fn rar5_cached(
        &self,
        password: &[u8],
        kdf_count: u8,
        salt: &[u8; 16],
        check: Option<([u8; 8], [u8; 4])>,
    ) -> Option<crate::crypto::Rar5Derived> {
        self.0.lock().unwrap().rar5_keys.get(password, &(kdf_count, *salt)).filter(|derived| derived.serves(check))
    }
    /// Keeps RAR 5.0 key material derived for the input for the rest of the session.
    pub(crate) fn rar5_remember(
        &self,
        password: &[u8],
        kdf_count: u8,
        salt: &[u8; 16],
        derived: crate::crypto::Rar5Derived,
    ) {
        self.0.lock().unwrap().rar5_keys.insert(password, (kdf_count, *salt), derived);
    }
    /// The RAR 3.x key and IV this session derived before for the password and salt.
    pub(crate) fn rar4_cached(&self, password: &[u8], salt: &[u8; 8]) -> Option<([u8; 16], [u8; 16])> {
        self.0.lock().unwrap().rar4_keys.get(password, salt)
    }
    /// Keeps a RAR 3.x key and IV derived for the password and salt for the rest of the session.
    pub(crate) fn rar4_remember(&self, password: &[u8], salt: &[u8; 8], keys: ([u8; 16], [u8; 16])) {
        self.0.lock().unwrap().rar4_keys.insert(password, *salt, keys);
    }
    /// The 7zAES key this session derived before for the password, cycle power and salt.
    pub(crate) fn seven_zip_cached(&self, password: &[u8], cycles: u8, salt: &[u8]) -> Option<[u8; 32]> {
        self.0.lock().unwrap().seven_zip_keys.get(password, &(cycles, salt.to_vec()))
    }
    /// Keeps a 7zAES key derived for the password, cycle power and salt for the rest of the session.
    pub(crate) fn seven_zip_remember(&self, password: &[u8], cycles: u8, salt: &[u8], key: [u8; 32]) {
        self.0.lock().unwrap().seven_zip_keys.insert(password, (cycles, salt.to_vec()), key);
    }
    pub(crate) fn charge(&self, resource: Resource, amount: u64) -> ProgressiveResult<()> {
        self.0.lock().unwrap().charge(resource, amount)?;
        self.record(resource, amount, true);
        Ok(())
    }
    /// What has been charged to `resource` so far.
    #[cfg(test)]
    pub(crate) fn used(&self, resource: Resource) -> u64 {
        self.0.lock().unwrap().used[resource as usize]
    }
    pub(crate) fn snapshot(&self, resource: Resource) -> ResourceUsage {
        let state = self.0.lock().unwrap();
        ResourceUsage { used: state.used[resource as usize], limit: state.limits.limit(resource) }
    }
    /// Tightens one budget mid-session, so a test can bound a single step.
    #[cfg_attr(
        not(feature = "persistent-partials"),
        allow(dead_code, reason = "persistent partial files lease scratch")
    )]
    #[cfg(test)]
    pub(crate) fn set_limit_for_test(&self, resource: Resource, limit: u64) {
        let mut state = self.0.lock().unwrap();
        match resource {
            Resource::MetadataBytes => state.limits.metadata_bytes = limit,
            _ => unimplemented!("only MetadataBytes is tightened by tests"),
        }
    }
    /// Charge `amount` until the returned lease drops. For memory that is
    /// freed again when its owner goes away (scratch buffers, encodings,
    /// transaction copies): the budget then bounds what is live at once, not
    /// what was ever allocated.
    #[cfg_attr(
        not(feature = "persistent-partials"),
        allow(dead_code, reason = "persistent partial files lease scratch")
    )]
    pub(crate) fn lease(&self, resource: Resource, amount: u64) -> ProgressiveResult<Lease> {
        let mut lease = Lease::empty(self, resource);
        lease.grow(amount)?;
        Ok(lease)
    }
}

/// A scoped [`Usage`] charge, released when dropped.
#[cfg_attr(not(feature = "persistent-partials"), allow(dead_code, reason = "persistent partial files lease scratch"))]
#[must_use = "a lease releases its charge when dropped"]
pub(crate) struct Lease {
    usage: Usage,
    resource: Resource,
    amount: u64,
}
#[cfg_attr(not(feature = "persistent-partials"), allow(dead_code, reason = "persistent partial files lease scratch"))]
impl Lease {
    pub(crate) fn empty(usage: &Usage, resource: Resource) -> Self {
        Self { usage: usage.clone(), resource, amount: 0 }
    }
    pub(crate) fn grow(&mut self, amount: u64) -> ProgressiveResult<()> {
        self.usage.charge(self.resource, amount)?;
        self.amount += amount;
        Ok(())
    }
    /// Turns the lease into an ordinary cumulative charge.
    pub(crate) fn keep(mut self) {
        self.amount = 0;
    }
    /// Takes over `other`'s charge, which then lasts as long as this lease.
    pub(crate) fn absorb(&mut self, mut other: Lease) {
        debug_assert!(other.resource == self.resource);
        self.amount += std::mem::take(&mut other.amount);
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        if self.amount != 0 {
            {
                let mut state = self.usage.0.lock().unwrap_or_else(|e| e.into_inner());
                let used = &mut state.used[self.resource as usize];
                *used = used.saturating_sub(self.amount);
            }
            self.usage.record(self.resource, self.amount, false);
        }
    }
}

#[cfg(test)]
mod seven_zip_kdf_tests {
    use super::*;

    #[test]
    fn seven_zip_kdf_ceiling_is_24_while_the_shared_one_stays_20() {
        let limits = ProgressiveLimits { kdf_exponent: 64, ..ProgressiveLimits::default() };
        assert_eq!(limits.limit(Resource::KdfExponent), 20);
        assert!(limits.check_seven_zip_kdf(24).is_ok());
        assert!(limits.check_seven_zip_kdf(0x3F).is_ok(), "0x3F is no hashing at all");
        let error = limits.check_seven_zip_kdf(25).unwrap_err();
        assert!(matches!(error.kind, FailureKind::Limit { resource: Resource::KdfExponent, limit: 24, attempted: 25 }));
        let tight = ProgressiveLimits { kdf_exponent: 19, ..ProgressiveLimits::default() };
        assert!(tight.check_seven_zip_kdf(19).is_ok() && tight.check_seven_zip_kdf(20).is_err());
    }
}

#[cfg(test)]
mod usage_snapshot_tests {
    use super::*;

    #[test]
    fn all_lists_each_resource_at_its_index_and_snapshots_track_charges() {
        for (i, r) in Resource::ALL.iter().enumerate() {
            assert_eq!(*r as usize, i);
        }
        let usage =
            Usage::new(ProgressiveLimits { metadata_bytes: 100, volume_handles: 1 << 40, ..Default::default() });
        assert_eq!(usage.snapshot(Resource::MetadataBytes), ResourceUsage { used: 0, limit: 100 });
        usage.charge(Resource::MetadataBytes, 30).unwrap();
        let snap = usage.snapshot(Resource::MetadataBytes);
        assert_eq!((snap.used, snap.limit, snap.remaining()), (30, 100, 70));
        assert_eq!(usage.snapshot(Resource::VolumeHandles).limit, 4096, "the fixed ceiling is reported");
    }

    #[test]
    fn a_scoped_view_gives_back_its_memory_charges_when_its_last_clone_drops() {
        let usage = Usage::new(ProgressiveLimits { metadata_bytes: 100, ..Default::default() });
        usage.charge(Resource::MetadataBytes, 10).unwrap();
        let scope = usage.scoped();
        scope.charge(Resource::MetadataBytes, 50).unwrap();
        scope.charge(Resource::VerifyWorkBytes, 7).unwrap();
        // The shared limit still applies while the scope lives.
        assert!(scope.charge(Resource::MetadataBytes, 41).is_err());
        let mut lease = scope.lease(Resource::MetadataBytes, 20).unwrap();
        lease.grow(5).unwrap();
        drop(lease);
        assert_eq!(usage.snapshot(Resource::MetadataBytes).used, 60);
        let clone = scope.clone();
        drop(scope);
        assert_eq!(usage.snapshot(Resource::MetadataBytes).used, 60, "a clone keeps the scope alive");
        drop(clone);
        assert_eq!(usage.snapshot(Resource::MetadataBytes).used, 10);
        // Work done is not memory: it stays charged.
        assert_eq!(usage.snapshot(Resource::VerifyWorkBytes).used, 7);
    }
}
