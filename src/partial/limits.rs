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

use super::*;
use crate::progressive::{Lease, Resource, Usage};
use std::sync::{Arc, Mutex};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[repr(usize)]
pub enum PartialResource {
    StateWire,
    StatePages,
    LedgerBytes,
    JournalBytes,
    JournalRecords,
    CrcLeaves,
    OpenFiles,
    OpenPartials,
    Events,
    FillBytes,
}
#[derive(Clone, Debug)]
pub struct PartialLimits {
    pub state_wire_bytes: u32,
    pub state_pages: u32,
    pub ledger_bytes: u64,
    pub journal_bytes: u64,
    pub journal_records: u32,
    pub crc_leaves: u32,
    pub open_files: u32,
    pub open_partials: u32,
    pub events: u32,
    /// Bytes of one `fill` or `fill_packed` call, one `refill_from_packed` step and one extraction write; also the
    /// buffer of a [`FillWriter`](super::FillWriter). Default 1 MiB, at most 64 MiB.
    pub fill_bytes: u32,
    /// Output bytes that extraction writes and [`FillWriter`](super::FillWriter) / `fill_from` fills group into one
    /// durable transaction: one anchored intent before the first write of the group, one output sync and one
    /// anchored commit after the last. Default 64 MiB, at most 16 GiB; 0 commits every write on its own.
    pub group_commit_bytes: u64,
    /// A group is also committed at the first write (or provider wait of the session) after it has been open this
    /// long. Default 2 s, at most one hour.
    pub group_commit_interval: std::time::Duration,
}
/// Hard cap of [`PartialLimits::group_commit_bytes`].
const GROUP_COMMIT_BYTES_MAX: u64 = 16 << 30;
/// Hard cap of [`PartialLimits::group_commit_interval`].
const GROUP_COMMIT_INTERVAL_MAX: std::time::Duration = std::time::Duration::from_secs(3600);
impl Default for PartialLimits {
    fn default() -> Self {
        Self {
            state_wire_bytes: 65_536,
            state_pages: 128,
            ledger_bytes: 67_108_864,
            journal_bytes: 67_108_864,
            journal_records: 65_536,
            crc_leaves: 1_048_576,
            open_files: 64,
            open_partials: 16,
            events: 64,
            fill_bytes: 1_048_576,
            group_commit_bytes: 64 << 20,
            group_commit_interval: std::time::Duration::from_secs(2),
        }
    }
}
impl PartialLimits {
    pub(super) fn value(&self, resource: PartialResource) -> u64 {
        match resource {
            PartialResource::StateWire => self.state_wire_bytes.into(),
            PartialResource::StatePages => self.state_pages.into(),
            PartialResource::LedgerBytes => self.ledger_bytes,
            PartialResource::JournalBytes => self.journal_bytes,
            PartialResource::JournalRecords => self.journal_records.into(),
            PartialResource::CrcLeaves => self.crc_leaves.into(),
            PartialResource::OpenFiles => self.open_files.into(),
            PartialResource::OpenPartials => self.open_partials.into(),
            PartialResource::Events => self.events.into(),
            PartialResource::FillBytes => self.fill_bytes.into(),
        }
    }
    pub(super) fn validate(&self) -> PartialResult<()> {
        for (r, hard) in [
            (PartialResource::StateWire, 65_536),
            (PartialResource::StatePages, 128),
            (PartialResource::LedgerBytes, 67_108_864),
            (PartialResource::JournalBytes, 67_108_864),
            (PartialResource::JournalRecords, 65_536),
            (PartialResource::CrcLeaves, 1_048_576),
            (PartialResource::OpenFiles, 4096),
            (PartialResource::OpenPartials, 4096),
            (PartialResource::Events, 64),
            (PartialResource::FillBytes, 64 << 20),
        ] {
            let n = self.value(r);
            if n > hard {
                return Err(limit(r, hard, n));
            }
        }
        if self.group_commit_bytes > GROUP_COMMIT_BYTES_MAX || self.group_commit_interval > GROUP_COMMIT_INTERVAL_MAX {
            return Err(err(PartialErrorKind::InvalidOptions));
        }
        Ok(())
    }
    pub(super) fn check(&self, r: PartialResource, n: u64) -> PartialResult<()> {
        let cap = self.value(r);
        if n > cap { Err(limit(r, cap, n)) } else { Ok(()) }
    }
}
pub(super) fn limit(resource: PartialResource, limit: u64, attempted: u64) -> PartialError {
    err(PartialErrorKind::Limit { resource, limit, attempted })
}
#[derive(Clone)]
pub(crate) struct PartialBudget {
    pub limits: PartialLimits,
    pub usage: Usage,
    pub exclusions: Arc<PartialExclusions>,
    counters: Arc<Mutex<[u64; 10]>>,
    prepaid: Arc<Mutex<[Vec<Reservation>; 10]>>,
    genesis: Arc<Mutex<Option<GenesisCredits>>>,
}
// Only the concrete genesis transaction uses these credits; future mutations cannot consume them.
struct GenesisCredits {
    pages: usize,
    journal_metadata: u64,
    remaining: Option<[u64; 4]>,
    native_bookkeeping: u64,
    bookkeeping_admitted: bool,
}
pub(super) struct Reservation {
    counters: Arc<Mutex<[u64; 10]>>,
    resource: PartialResource,
    amount: u64,
}
impl Reservation {
    // Growing a recovered short journal file must admit the missing bytes
    // before touching the file, without double-counting its retained prefix.
    pub(super) fn grow_to(&mut self, amount: u64, limits: &PartialLimits) -> PartialResult<()> {
        if amount <= self.amount {
            return Ok(());
        }
        let mut counts = self.counters.lock().unwrap();
        let next = counts[self.resource as usize]
            .checked_add(amount - self.amount)
            .ok_or_else(|| limit(self.resource, limits.value(self.resource), u64::MAX))?;
        limits.check(self.resource, next)?;
        counts[self.resource as usize] = next;
        self.amount = amount;
        Ok(())
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        self.counters.lock().unwrap()[self.resource as usize] -= self.amount;
    }
}
impl PartialBudget {
    pub(super) fn new(limits: PartialLimits, usage: Usage, exclusions: Arc<PartialExclusions>) -> PartialResult<Self> {
        limits.validate()?;
        let counters = exclusions.counters.clone();
        Ok(Self {
            limits,
            usage,
            exclusions,
            counters,
            prepaid: Arc::new(Mutex::new(std::array::from_fn(|_| Vec::new()))),
            genesis: Arc::new(Mutex::new(None)),
        })
    }
    pub(super) fn reserve(&self, resource: PartialResource, amount: u64) -> PartialResult<Reservation> {
        {
            let mut pool = self.prepaid.lock().unwrap();
            if let Some(index) = pool[resource as usize].iter().position(|r| r.amount == amount) {
                return Ok(pool[resource as usize].swap_remove(index));
            }
        }
        self.reserve_fresh(resource, amount)
    }
    fn reserve_fresh(&self, resource: PartialResource, amount: u64) -> PartialResult<Reservation> {
        let mut counts = self.counters.lock().unwrap();
        let n = counts[resource as usize]
            .checked_add(amount)
            .ok_or_else(|| limit(resource, self.limits.value(resource), u64::MAX))?;
        self.limits.check(resource, n)?;
        counts[resource as usize] = n;
        Ok(Reservation { counters: self.counters.clone(), resource, amount })
    }
    pub(super) fn prepay(&self, requests: &[(PartialResource, u64)]) -> PartialResult<()> {
        let mut reservations = self.vector(requests.len())?;
        for &(resource, amount) in requests {
            reservations.push(self.reserve_fresh(resource, amount)?);
        }
        let mut pool = self.prepaid.lock().unwrap();
        for r in &reservations {
            pool[r.resource as usize].try_reserve_exact(1).map_err(|_| malformed())?;
        }
        for r in reservations {
            pool[r.resource as usize].push(r);
        }
        Ok(())
    }
    pub(super) fn prepare_genesis(&self, pages: usize, journal_metadata: u64) {
        *self.genesis.lock().unwrap() = Some(GenesisCredits {
            pages,
            journal_metadata,
            remaining: None,
            native_bookkeeping: 0,
            bookkeeping_admitted: false,
        });
    }
    pub(super) fn genesis_pages(&self) -> PartialResult<usize> {
        self.genesis.lock().unwrap().as_ref().map(|g| g.pages).ok_or_else(|| err(PartialErrorKind::InvalidOptions))
    }
    pub(super) fn admit_genesis(&self, exclusion_bytes: u64) -> PartialResult<()> {
        let mut genesis = self.genesis.lock().unwrap();
        let genesis = genesis.as_mut().ok_or_else(|| err(PartialErrorKind::InvalidOptions))?;
        let paths = genesis.pages as u64 + 5;
        let metadata = genesis.journal_metadata.checked_add(exclusion_bytes).ok_or_else(malformed)?;
        self.usage.charge(Resource::ProtectionPaths, paths)?;
        self.usage.charge(Resource::ProtectionPathBytes, exclusion_bytes)?;
        self.usage.charge(Resource::MetadataBytes, metadata)?;
        genesis.remaining = Some([metadata, paths, exclusion_bytes, 0]);
        Ok(())
    }
    pub(crate) fn prepare_native_bookkeeping(&self, amount: u64) {
        self.genesis.lock().unwrap().as_mut().expect("prepared genesis").native_bookkeeping = amount;
    }
    pub(super) fn admit_genesis_bookkeeping(&self) -> PartialResult<()> {
        let entries = self.exclusions.entry_count() as u64;
        let mut scope = self.genesis.lock().unwrap();
        let scope = scope.as_mut().ok_or_else(malformed)?;
        if scope.bookkeeping_admitted {
            return Ok(());
        }
        let names = scope.pages as u64 + 5;
        let visits = names
            .checked_mul(entries)
            .and_then(|n| n.checked_add(names * (names - 1) / 2))
            .and_then(|n| n.checked_add(scope.native_bookkeeping))
            .ok_or_else(malformed)?;
        self.usage.charge(Resource::SourceBookkeeping, visits)?;
        scope.remaining.as_mut().ok_or_else(malformed)?[3] = visits;
        scope.bookkeeping_admitted = true;
        Ok(())
    }
    pub(crate) fn bookkeeping(&self, amount: u64) -> crate::progressive::ProgressiveResult<()> {
        let mut remaining = amount;
        if let Some(credits) = self.genesis.lock().unwrap().as_mut().and_then(|g| g.remaining.as_mut()) {
            let prepaid = credits[3].min(amount);
            credits[3] -= prepaid;
            remaining -= prepaid;
        }
        if remaining != 0 {
            self.usage.charge(Resource::SourceBookkeeping, remaining)?;
        }
        Ok(())
    }
    pub(super) fn finish_genesis(&self) {
        *self.genesis.lock().unwrap() = None;
    }
    pub(super) fn exclude(&self, path: &PartialProtectedPath) -> PartialResult<()> {
        let active = self.genesis.lock().unwrap().as_ref().is_some_and(|g| g.remaining.is_some());
        if active { self.exclusions.reserve_created(path, self) } else { self.exclusions.reserve(path) }
    }
    pub(super) fn creation_charge(&self, resource: Resource, amount: u64) -> PartialResult<()> {
        let index = match resource {
            Resource::MetadataBytes => 0,
            Resource::ProtectionPaths => 1,
            Resource::ProtectionPathBytes => 2,
            _ => unreachable!("genesis credits only cover its three prepared charges"),
        };
        let mut remaining = amount;
        if let Some(credits) = self.genesis.lock().unwrap().as_mut().and_then(|g| g.remaining.as_mut()) {
            let prepaid = credits[index].min(amount);
            credits[index] -= prepaid;
            remaining -= prepaid;
        }
        if remaining != 0 {
            self.usage.charge(resource, remaining)?;
        }
        Ok(())
    }
    pub(super) fn metadata(&self, bytes: u64) -> PartialResult<()> {
        self.creation_charge(Resource::MetadataBytes, bytes)
    }
    /// [`Self::metadata`] for memory freed when the returned lease drops.
    /// Prepaid genesis credits are consumed first, exactly as there.
    pub(super) fn metadata_lease(&self, bytes: u64) -> PartialResult<Lease> {
        let mut remaining = bytes;
        if let Some(credits) = self.genesis.lock().unwrap().as_mut().and_then(|g| g.remaining.as_mut()) {
            let prepaid = credits[0].min(bytes);
            credits[0] -= prepaid;
            remaining -= prepaid;
        }
        Ok(self.usage.lease(Resource::MetadataBytes, remaining)?)
    }
    /// [`Self::vector`] whose charge lasts only as long as the returned lease.
    pub(super) fn leased_vector<T>(&self, count: usize) -> PartialResult<(Vec<T>, Lease)> {
        let bytes = count.checked_mul(std::mem::size_of::<T>()).ok_or_else(malformed)?;
        let lease = self.metadata_lease(bytes as u64)?;
        let mut v = Vec::new();
        v.try_reserve_exact(count).map_err(|_| malformed())?;
        Ok((v, lease))
    }
    pub(super) fn vector<T>(&self, count: usize) -> PartialResult<Vec<T>> {
        let bytes = count.checked_mul(std::mem::size_of::<T>()).ok_or_else(malformed)?;
        self.metadata(bytes as u64)?;
        let mut v = Vec::new();
        v.try_reserve_exact(count).map_err(|_| malformed())?;
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recovered_journal_reservation_growth_admits_before_mutation() {
        let usage = Usage::new(crate::progressive::ProgressiveLimits::default());
        let exclusions = Arc::new(PartialExclusions::new(usage.clone()));
        let limits = PartialLimits { journal_bytes: 100, ..Default::default() };
        let budget = PartialBudget::new(limits, usage, exclusions).unwrap();
        let mut prefix = budget.reserve(PartialResource::JournalBytes, 2).unwrap();
        let other = budget.reserve(PartialResource::JournalBytes, 95).unwrap();
        let error = prefix.grow_to(6, &budget.limits).unwrap_err();
        assert!(matches!(
            error.kind,
            PartialErrorKind::Limit { resource: PartialResource::JournalBytes, limit: 100, attempted: 101 }
        ));
        assert_eq!(prefix.amount, 2);
        assert_eq!(budget.counters.lock().unwrap()[PartialResource::JournalBytes as usize], 97);
        prefix.grow_to(5, &budget.limits).unwrap();
        assert_eq!(budget.counters.lock().unwrap()[PartialResource::JournalBytes as usize], 100);
        drop(prefix);
        drop(other);
        assert_eq!(budget.counters.lock().unwrap()[PartialResource::JournalBytes as usize], 0);
    }
    #[test]
    fn genesis_bookkeeping_credits_end_before_live_operations() {
        let usage = Usage::new(crate::progressive::ProgressiveLimits { source_bookkeeping: 100, ..Default::default() });
        let exclusions = Arc::new(PartialExclusions::new(usage.clone()));
        let budget = PartialBudget::new(PartialLimits::default(), usage, exclusions).unwrap();
        budget.prepare_genesis(0, 0);
        budget.admit_genesis(0).unwrap();
        budget.admit_genesis_bookkeeping().unwrap(); // five entries, ten comparisons
        budget.bookkeeping(3).unwrap();
        budget.finish_genesis(); // seven unused credits cannot escape this scope
        let error = budget.bookkeeping(91).unwrap_err();
        assert!(matches!(
            error.kind,
            crate::progressive::FailureKind::Limit {
                resource: Resource::SourceBookkeeping,
                limit: 100,
                attempted: 101
            }
        ));
        budget.bookkeeping(90).unwrap();
        assert!(budget.bookkeeping(1).is_err());
    }
}
