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
use crate::progressive::{Resource, Usage};
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
    pub fill_bytes: u32,
}
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
            (PartialResource::FillBytes, 1_048_576),
        ] {
            let n = self.value(r);
            if n > hard {
                return Err(limit(r, hard, n));
            }
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
}
pub(super) struct Reservation {
    counters: Arc<Mutex<[u64; 10]>>,
    resource: PartialResource,
    amount: u64,
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
    pub(super) fn metadata(&self, bytes: u64) -> PartialResult<()> {
        self.usage.charge(Resource::MetadataBytes, bytes).map_err(Into::into)
    }
    pub(super) fn vector<T>(&self, count: usize) -> PartialResult<Vec<T>> {
        let bytes = count.checked_mul(std::mem::size_of::<T>()).ok_or_else(malformed)?;
        self.metadata(bytes as u64)?;
        let mut v = Vec::new();
        v.try_reserve_exact(count).map_err(|_| malformed())?;
        Ok(v)
    }
}
