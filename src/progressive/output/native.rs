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

//! Native identity binding; growth is deliberately not part of progressive identity.
use super::super::limits::Usage;
use super::super::{
    FailureKind, InputOperation, ProgressiveFailure, ProgressiveResult, ProtectedPath, ProtectionDeclaration,
    ProtectionInventory, Resource, VolumeBacking,
};
use std::{
    fs::{self, File, Metadata},
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct Identity(pub u64, pub u64);
impl Identity {
    pub(crate) fn metadata(meta: &Metadata) -> std::io::Result<Self> {
        if !meta.is_file() && !meta.is_dir() {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "unsupported native file kind"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Ok(Self(meta.dev(), meta.ino()))
        }
        #[cfg(not(unix))]
        {
            Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "native identity unavailable"))
        }
    }
    pub(crate) fn file(file: &File) -> std::io::Result<Self> {
        Self::metadata(&file.metadata()?)
    }
}
/// Every declared path in binding order: volume backings by index, then auxiliary paths.
fn inventory_paths(i: &ProtectionInventory) -> ProgressiveResult<Vec<&ProtectedPath>> {
    let mut paths = Vec::new();
    let count = i
        .volumes
        .iter()
        .map(|v| match &v.backing {
            VolumeBacking::Native(p) => p.len(),
            VolumeBacking::NonFile => 0,
        })
        .sum::<usize>()
        + i.auxiliary_paths.len();
    paths.try_reserve_exact(count).map_err(|_| contract())?;
    paths.extend(
        i.volumes
            .iter()
            .flat_map(|v| match &v.backing {
                VolumeBacking::Native(p) => p.as_slice(),
                VolumeBacking::NonFile => &[],
            })
            .chain(i.auxiliary_paths.iter()),
    );
    Ok(paths)
}
fn input(e: std::io::Error) -> ProgressiveFailure {
    ProgressiveFailure::new(FailureKind::Input { operation: InputOperation::Metadata, cause: e })
}
fn changed() -> ProgressiveFailure {
    ProgressiveFailure::new(FailureKind::SourceChanged)
}
fn contract() -> ProgressiveFailure {
    ProgressiveFailure::new(FailureKind::SourceContract)
}
struct Binding {
    path: PathBuf,
    identity: Option<Identity>,
    handle: Option<Arc<File>>,
}
struct ImmutableBinding {
    path: PathBuf,
    stamp: crate::rar5::source::SourceStamp,
    // Bindings and held handles are append-only and never rebind once set,
    // so the handle found for this identity stays the same open file.
    slot: Option<Slot>,
}
#[derive(Clone, Copy)]
enum Slot {
    Binding(usize),
    Held(usize),
}
/// How much of the protected state a refresh re-proves.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Sweep {
    /// Every binding, immutable stamp and uncovered admission.
    Full,
    /// The newest immutable stamp plus one rotating binding and stamp.
    Step,
}
/// Address and shape of the Complete declaration last fully refreshed.
/// `SourceDriver` replaces its declaration only after a full refresh of the
/// replacement, so a stale value only ever forces another full refresh.
#[derive(Clone, Copy, Eq, PartialEq)]
struct Fingerprint {
    epoch: u64,
    volumes: (usize, usize),
    auxiliary: (usize, usize),
}
impl Fingerprint {
    fn of(declaration: &ProtectionDeclaration) -> Option<Self> {
        let ProtectionDeclaration::Complete { epoch, inventory } = declaration else { return None };
        Some(Self {
            epoch: *epoch,
            volumes: (inventory.volumes.as_ptr() as usize, inventory.volumes.len()),
            auxiliary: (inventory.auxiliary_paths.as_ptr() as usize, inventory.auxiliary_paths.len()),
        })
    }
}
// Only a prepared persistent genesis has prepaid work. Legacy drivers and
// normal later operations retain the original cumulative Usage accounting.
macro_rules! bookkeeping {
    ($native:expr, $usage:expr, $amount:expr) => {{
        #[cfg(feature = "persistent-partials")]
        {
            if let Some(budget) = &$native.partial_genesis {
                budget.bookkeeping($amount)
            } else {
                $usage.charge(Resource::SourceBookkeeping, $amount)
            }
        }
        #[cfg(not(feature = "persistent-partials"))]
        {
            $usage.charge(Resource::SourceBookkeeping, $amount)
        }
    }};
}
pub(crate) struct NativeProtection {
    #[cfg(feature = "persistent-partials")]
    partial_genesis: Option<crate::partial::PartialBudget>,
    bindings: Vec<Binding>,
    admitted: Vec<(u32, Identity)>,
    complete: bool,
    native_only: bool,
    cwd: PathBuf,
    held: Vec<File>,
    immutable: Vec<ImmutableBinding>,
    // Prefix of `admitted` already proven covered by the Complete declaration.
    // A covered pair stays covered: the declaration is fixed once Complete
    // (only absent handles may be added) and descriptor identities never change.
    covered: usize,
    // Declaration whose bindings were all observed by the last full refresh.
    fingerprint: Option<Fingerprint>,
    // Rotating cursors for step refreshes.
    next_binding: usize,
    next_immutable: usize,
    // First binding of each declared volume, by inventory position, plus the end of the volume bindings, so an
    // admission observes only the admitted volume's own paths.
    starts: Vec<usize>,
}
/// First binding of each volume of `inventory` in binding order, then the end of the volume bindings.
fn volume_starts(inventory: &ProtectionInventory, usage: &mut Usage) -> ProgressiveResult<Vec<usize>> {
    usage.charge(Resource::SourceBookkeeping, inventory.volumes.len() as u64 + 1)?;
    usage.charge(Resource::MetadataBytes, ((inventory.volumes.len() + 1) * std::mem::size_of::<usize>()) as u64)?;
    let mut starts = Vec::new();
    starts.try_reserve_exact(inventory.volumes.len() + 1).map_err(|_| contract())?;
    let mut at = 0usize;
    for volume in &inventory.volumes {
        starts.push(at);
        if let VolumeBacking::Native(paths) = &volume.backing {
            at = at.checked_add(paths.len()).ok_or_else(contract)?;
        }
    }
    starts.push(at);
    Ok(starts)
}
impl NativeProtection {
    #[cfg(feature = "persistent-partials")]
    pub(crate) fn prepare_partial_genesis(
        &mut self,
        output: &Path,
        bundle: &Path,
        declaration: &ProtectionDeclaration,
        budget: &crate::partial::PartialBudget,
    ) -> ProgressiveResult<()> {
        let ProtectionDeclaration::Complete { inventory, .. } = declaration else {
            return Err(contract());
        };
        let partial_output = future_path(output)?;
        let partial_bundle = future_path(bundle)?;
        let mut work = (inventory.volumes.len() + inventory.auxiliary_paths.len() + self.bindings.len()) as u64;
        for binding in &self.bindings {
            let base = 1 + binding.path.as_os_str().len() as u64;
            let out = base + output.as_os_str().len() as u64;
            let bundle = base + bundle.as_os_str().len() as u64;
            let partial_out = base + partial_output.as_os_str().len() as u64;
            let partial_bundle = base + partial_bundle.as_os_str().len() as u64;
            // refresh, three initial target checks, then four native checks
            // (create, intent acknowledgement, output sync, commit acknowledgement).
            work = work
                .checked_add(base + 2 * out + bundle + 4 * (base + partial_out + 2 * partial_bundle + out))
                .ok_or_else(contract)?;
        }
        budget.prepare_native_bookkeeping(work);
        self.partial_genesis = Some(budget.clone());
        Ok(())
    }
    pub(crate) fn handle_count(&self) -> usize {
        self.held.len() + self.bindings.iter().filter(|b| b.handle.is_some()).count()
    }
    pub(crate) fn new(usage: &Usage) -> ProgressiveResult<Self> {
        // Reserve bounded native-path workspace before the standard filesystem helper.
        // This is cumulative metadata accounting, not a process-allocation guarantee.
        usage.charge(Resource::MetadataBytes, 4096)?;
        let cwd = std::env::current_dir().map_err(input)?;
        usage.charge(Resource::MetadataBytes, cwd.capacity().saturating_sub(4096) as u64)?;
        Ok(Self {
            #[cfg(feature = "persistent-partials")]
            partial_genesis: None,
            bindings: Vec::new(),
            admitted: Vec::new(),
            complete: false,
            native_only: false,
            cwd,
            held: Vec::new(),
            immutable: Vec::new(),
            covered: 0,
            fingerprint: None,
            next_binding: 0,
            next_immutable: 0,
            starts: Vec::new(),
        })
    }

    /// Re-prove every protected fact: each binding's path identity, each
    /// immutable stamp and coverage of every admission not yet covered.
    pub(crate) fn refresh(
        &mut self,
        declaration: &ProtectionDeclaration,
        usage: &mut Usage,
        external_handles: usize,
    ) -> ProgressiveResult<()> {
        self.fingerprint = None;
        self.check_immutable(usage, Sweep::Full)?;
        let ProtectionDeclaration::Complete { inventory, .. } = declaration else { return Ok(()) };
        bookkeeping!(
            self,
            usage,
            (inventory.volumes.len() + inventory.auxiliary_paths.len() + self.bindings.len()) as u64
        )?;
        let paths = inventory
            .volumes
            .iter()
            .flat_map(|v| match &v.backing {
                VolumeBacking::Native(p) => p.as_slice(),
                VolumeBacking::NonFile => &[],
            })
            .chain(inventory.auxiliary_paths.iter());
        // Check the combined live inventory before retaining any newly declared
        // handle, including an Opaque -> Complete upgrade or newly resolved path.
        let added = if self.complete {
            self.bindings
                .iter()
                .zip(paths.clone())
                .filter(|(b, p)| b.identity.is_none() && b.handle.is_none() && p.file.is_some())
                .count()
        } else {
            paths.clone().filter(|p| p.file.is_some()).count()
        };
        usage.check(Resource::VolumeHandles, (external_handles + self.handle_count() + added) as u64)?;
        if !self.complete {
            let mut count = inventory.auxiliary_paths.len();
            // Structural NonFile declarations carry no library-owned memory authority.
            // Auxiliary native paths cannot supply the missing volume provenance.
            let mut native_only = !inventory.volumes.is_empty();
            for volume in &inventory.volumes {
                match &volume.backing {
                    VolumeBacking::Native(paths) if !paths.is_empty() => count += paths.len(),
                    _ => native_only = false,
                }
            }
            usage.charge(Resource::SourceBookkeeping, count as u64)?;
            usage.charge(Resource::ProtectionPaths, count as u64)?;
            usage.charge(Resource::MetadataBytes, (count * std::mem::size_of::<Binding>()) as u64)?;
            self.bindings.try_reserve_exact(count).map_err(|_| contract())?;
            usage.charge(
                Resource::MetadataBytes,
                (self.bindings.capacity().saturating_sub(count) * std::mem::size_of::<Binding>()) as u64,
            )?;
            for p in paths {
                usage.charge(Resource::SourceBookkeeping, 1 + p.path.as_os_str().len() as u64)?;
                let capacity =
                    p.path.as_os_str().len() + if p.path.is_absolute() { 0 } else { self.cwd.as_os_str().len() + 1 };
                usage.charge(Resource::MetadataBytes, capacity as u64)?;
                let path = if p.path.is_absolute() { p.path.clone() } else { self.cwd.join(&p.path) };
                usage.charge(Resource::MetadataBytes, path.capacity().saturating_sub(capacity) as u64)?;
                usage.charge(Resource::ProtectionPathBytes, path.capacity() as u64)?;
                let identity = observe(&path, p.file.as_deref())?;
                self.bindings.push(Binding { path, identity, handle: p.file.clone() });
            }
            self.starts = volume_starts(inventory, usage)?;
            self.native_only = native_only;
            self.complete = true;
        } else {
            for (binding, path) in self.bindings.iter_mut().zip(paths) {
                bookkeeping!(self, usage, 1 + binding.path.as_os_str().len() as u64)?;
                let now = observe(&binding.path, path.file.as_deref())?;
                if binding.identity.is_some() && binding.identity != now {
                    return Err(changed());
                }
                if binding.identity.is_none() {
                    binding.identity = now;
                    binding.handle = path.file.clone();
                }
            }
        }
        usage.check(Resource::VolumeHandles, (external_handles + self.handle_count()) as u64)?;
        // Every prior native source must be covered by its declared indexed volume,
        // including sources admitted before an Opaque -> Complete upgrade.
        for &(index, identity) in &self.admitted[self.covered..] {
            self.covers(index, identity, declaration, usage)?;
        }
        self.covered = self.admitted.len();
        self.fingerprint = Fingerprint::of(declaration);
        Ok(())
    }
    /// Bounded per-step refresh for the declaration last fully refreshed.
    ///
    /// Each step re-checks the newest immutable stamp (the volume being read),
    /// one more stamp and one binding in rotation, so every binding and stamp
    /// is still re-observed every few steps at a cost independent of the set
    /// size. Volume admission, publication and every other authority point use
    /// [`Self::refresh`]; anything else, including a first or changed
    /// declaration, falls back to it here.
    pub(crate) fn refresh_step(
        &mut self,
        declaration: &ProtectionDeclaration,
        usage: &mut Usage,
        external_handles: usize,
    ) -> ProgressiveResult<()> {
        let fingerprint = Fingerprint::of(declaration);
        if fingerprint.is_some() && (!self.complete || self.fingerprint != fingerprint) {
            return self.refresh(declaration, usage, external_handles);
        }
        self.check_immutable(usage, Sweep::Step)?;
        if fingerprint.is_none() {
            return Ok(());
        }
        // A full refresh of this declaration bound every declared handle and
        // covered every admission; admit keeps later admissions covered.
        usage.check(Resource::VolumeHandles, (external_handles + self.handle_count()) as u64)?;
        if self.covered != self.admitted.len() {
            return self.refresh(declaration, usage, external_handles);
        }
        if self.bindings.is_empty() {
            return Ok(());
        }
        let i = self.next_binding % self.bindings.len();
        self.next_binding = (i + 1) % self.bindings.len();
        let binding = &self.bindings[i];
        bookkeeping!(self, usage, 1 + binding.path.as_os_str().len() as u64)?;
        if observe(&binding.path, binding.handle.as_deref())? != binding.identity {
            return Err(changed());
        }
        Ok(())
    }
    /// Refresh before admitting volume `index` of the declaration last fully refreshed.
    ///
    /// The admitted volume's own bindings are observed in full, because that is the file about to be read;
    /// the rest of the protected state gets the bounded step check (newest stamp, one rotating stamp and one
    /// rotating binding), exactly as after a header or data step. Sweeping every binding and stamp here made a
    /// Complete declaration cost O(V * P) per admission and O(V^2 * P) per session. Every other binding is still
    /// re-observed every few steps, and publication and member boundaries keep the full refresh, so a replaced
    /// input is still caught before any output is published. A first or changed declaration falls back to the
    /// full refresh.
    pub(crate) fn refresh_admission(
        &mut self,
        declaration: &ProtectionDeclaration,
        index: u32,
        usage: &mut Usage,
        external_handles: usize,
    ) -> ProgressiveResult<()> {
        let fingerprint = Fingerprint::of(declaration);
        if fingerprint.is_none() {
            return self.refresh(declaration, usage, external_handles);
        }
        if !self.complete || self.fingerprint != fingerprint || self.covered != self.admitted.len() {
            return self.refresh(declaration, usage, external_handles);
        }
        let ProtectionDeclaration::Complete { inventory, .. } = declaration else { unreachable!() };
        if self.starts.len() != inventory.volumes.len() + 1 {
            return self.refresh(declaration, usage, external_handles);
        }
        self.refresh_step(declaration, usage, external_handles)?;
        usage.charge(Resource::SourceBookkeeping, 1 + inventory.volumes.len().max(1).ilog2() as u64)?;
        let Ok(position) = inventory.volumes.binary_search_by_key(&index, |v| v.index) else {
            // Undeclared: admission refuses it on name coverage.
            return Ok(());
        };
        let VolumeBacking::Native(paths) = &inventory.volumes[position].backing else { return Ok(()) };
        let start = self.starts[position];
        if start.checked_add(paths.len()) != Some(self.starts[position + 1])
            || self.starts[position + 1] > self.bindings.len()
        {
            return Err(contract());
        }
        for (binding, path) in self.bindings[start..start + paths.len()].iter_mut().zip(paths) {
            bookkeeping!(self, usage, 1 + binding.path.as_os_str().len() as u64)?;
            let now = observe(&binding.path, path.file.as_deref())?;
            if binding.identity.is_some() && binding.identity != now {
                return Err(changed());
            }
            if binding.identity.is_none() {
                binding.identity = now;
                binding.handle = path.file.clone();
            }
        }
        usage.check(Resource::VolumeHandles, (external_handles + self.handle_count()) as u64)
    }
    /// Realigns the bindings of a bound Complete inventory `old` to `new`, which keeps every old path unchanged
    /// and in order. Old bindings keep their observed identities; appended paths are observed and bound here.
    /// The caller then refreshes against `new`, which checks every binding again.
    pub(crate) fn extend(
        &mut self,
        old: &ProtectionInventory,
        new: &ProtectionInventory,
        usage: &mut Usage,
        external_handles: usize,
    ) -> ProgressiveResult<()> {
        // Extension rebuilds the bindings in canonical order, so cached binding positions may now name other files.
        for immutable in &mut self.immutable {
            immutable.slot = None;
        }
        if !self.complete {
            // Nothing is bound yet; the refresh binds `new` whole.
            return Ok(());
        }
        bookkeeping!(self, usage, (old.volumes.len() + new.volumes.len() + 2 * self.bindings.len()) as u64)?;
        let (old, new_paths) = (inventory_paths(old)?, inventory_paths(new)?);
        if old.len() != self.bindings.len() || new_paths.len() < old.len() {
            return Err(contract());
        }
        let added = new_paths.len() - old.len();
        let added_handles = new_paths
            .iter()
            .filter(|p| p.file.is_some())
            .count()
            .saturating_sub(old.iter().filter(|p| p.file.is_some()).count());
        usage.check(Resource::VolumeHandles, (external_handles + self.handle_count() + added_handles) as u64)?;
        usage.charge(Resource::ProtectionPaths, added as u64)?;
        // The new binding list, the appended bindings, the order and both borrowed path lists.
        usage.charge(
            Resource::MetadataBytes,
            ((new_paths.len() + added) * std::mem::size_of::<Binding>()
                + (old.len() + new_paths.len()) * std::mem::size_of::<usize>()
                + new_paths.len()) as u64,
        )?;
        // Observe every appended path before changing anything, so a failure leaves the old bindings intact.
        let mut fresh = Vec::new();
        fresh.try_reserve_exact(added).map_err(|_| contract())?;
        let mut keep = Vec::new();
        keep.try_reserve_exact(new_paths.len()).map_err(|_| contract())?;
        let mut at = 0;
        for p in new_paths.iter().copied() {
            usage.charge(Resource::SourceBookkeeping, 1 + p.path.as_os_str().len() as u64)?;
            if old.get(at).is_some_and(|o| o.path == p.path) {
                at += 1;
                keep.push(true);
                continue;
            }
            let capacity =
                p.path.as_os_str().len() + if p.path.is_absolute() { 0 } else { self.cwd.as_os_str().len() + 1 };
            usage.charge(Resource::MetadataBytes, capacity as u64)?;
            let path = if p.path.is_absolute() { p.path.clone() } else { self.cwd.join(&p.path) };
            usage.charge(Resource::MetadataBytes, path.capacity().saturating_sub(capacity) as u64)?;
            usage.charge(Resource::ProtectionPathBytes, path.capacity() as u64)?;
            let identity = observe(&path, p.file.as_deref())?;
            fresh.push(Binding { path, identity, handle: p.file.clone() });
            keep.push(false);
        }
        if at != old.len() {
            return Err(changed());
        }
        let mut next = Vec::new();
        next.try_reserve_exact(new_paths.len()).map_err(|_| contract())?;
        let (mut kept, mut fresh) = (std::mem::take(&mut self.bindings).into_iter(), fresh.into_iter());
        for keep in keep {
            next.extend(if keep { kept.next() } else { fresh.next() });
        }
        self.bindings = next;
        self.starts = volume_starts(new, usage)?;
        self.native_only = !new.volumes.is_empty()
            && new.volumes.iter().all(|v| matches!(&v.backing, VolumeBacking::Native(p) if !p.is_empty()));
        Ok(())
    }
    /// Whether every admission not yet covered is one of the files `declaration` names for its volume. `false` when
    /// a declared native volume names other files only (a replaced inode); structural mismatches are still errors.
    pub(crate) fn covers_admitted(
        &self,
        declaration: &ProtectionDeclaration,
        usage: &mut Usage,
    ) -> ProgressiveResult<bool> {
        for &(index, identity) in &self.admitted[self.covered..] {
            if !self.matches(index, identity, declaration, usage)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
    fn covers(
        &self,
        index: u32,
        identity: Identity,
        declaration: &ProtectionDeclaration,
        usage: &mut Usage,
    ) -> ProgressiveResult<()> {
        if self.matches(index, identity, declaration, usage)? { Ok(()) } else { Err(contract()) }
    }
    fn matches(
        &self,
        index: u32,
        identity: Identity,
        declaration: &ProtectionDeclaration,
        usage: &mut Usage,
    ) -> ProgressiveResult<bool> {
        let ProtectionDeclaration::Complete { inventory, .. } = declaration else { return Ok(true) };
        // A binary search of the canonical inventory.
        usage.charge(Resource::SourceBookkeeping, 1 + inventory.volumes.len().max(1).ilog2() as u64)?;
        let v = inventory
            .volumes
            .binary_search_by_key(&index, |v| v.index)
            .ok()
            .map(|i| &inventory.volumes[i])
            .ok_or_else(contract)?;
        let VolumeBacking::Native(paths) = &v.backing else { return Err(contract()) };
        for p in paths {
            usage.charge(Resource::SourceBookkeeping, 1 + p.path.as_os_str().len() as u64)?;
            if let Some(file) = &p.file
                && Identity::file(file).map_err(input)? == identity
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
    pub(crate) fn admit(
        &mut self,
        index: u32,
        files: &[File],
        declaration: &ProtectionDeclaration,
        usage: &mut Usage,
        external_handles: usize,
    ) -> ProgressiveResult<()> {
        // Only an Opaque driver searches `admitted` (to share held handles); the handle count below is a filter.
        usage.charge(
            Resource::SourceBookkeeping,
            (files.len() + if self.complete { 0 } else { self.admitted.len() + self.bindings.len() }) as u64,
        )?;
        usage.check(
            Resource::VolumeHandles,
            (external_handles
                + self.held.len()
                + self.bindings.iter().filter(|b| b.handle.is_some()).count()
                + files.len() * if self.complete { 1 } else { 2 }) as u64,
        )?;
        usage.charge(Resource::MetadataBytes, (files.len() * std::mem::size_of::<(u32, Identity)>()) as u64)?;
        if !self.complete {
            usage.charge(Resource::MetadataBytes, std::mem::size_of_val(files) as u64)?;
            self.held.try_reserve_exact(files.len()).map_err(|_| contract())?;
        }
        self.admitted.try_reserve_exact(files.len()).map_err(|_| contract())?;
        for file in files {
            let meta = file.metadata().map_err(input)?;
            if !meta.is_file() {
                return Err(contract());
            }
            let id = Identity::metadata(&meta).map_err(input)?;
            self.covers(index, id, declaration, usage)?;
            if !self.complete {
                usage.charge(Resource::SourceBookkeeping, self.admitted.len() as u64)?;
            }
            if !self.complete && !self.admitted.iter().any(|(_, old)| *old == id) {
                let retained = file.try_clone().map_err(|cause| {
                    ProgressiveFailure::new(FailureKind::Input { operation: InputOperation::Open, cause })
                })?;
                self.held.push(retained);
            }
            // Only a Complete declaration proves coverage; an Opaque admission
            // is covered by the full refresh that upgrades to Complete.
            let proven =
                matches!(declaration, ProtectionDeclaration::Complete { .. }) && self.covered == self.admitted.len();
            self.admitted.push((index, id));
            if proven {
                self.covered = self.admitted.len();
            }
        }
        Ok(())
    }
    pub(crate) fn remember_immutable(
        &mut self,
        file: &File,
        path: &Path,
        stamp: crate::rar5::source::SourceStamp,
        volume: Option<(u32, &ProtectionDeclaration)>,
        usage: &Usage,
    ) -> ProgressiveResult<()> {
        usage.charge(Resource::SourceBookkeeping, 8 + path.as_os_str().len() as u64)?;
        stamp.check(file, path).map_err(super::super::source::immutable_error)?;
        usage.charge(Resource::MetadataBytes, path.as_os_str().len() as u64)?;
        let old = self.immutable.capacity();
        if self.immutable.len() == old {
            // Grow geometrically: the copy is charged once per doubling, so the list costs O(V) in all.
            let target = old.saturating_mul(2).max(4);
            usage.charge(Resource::SourceBookkeeping, self.immutable.len() as u64)?;
            usage.charge(Resource::MetadataBytes, ((target - old) * std::mem::size_of::<ImmutableBinding>()) as u64)?;
            self.immutable.try_reserve_exact(target - old).map_err(|_| contract())?;
            usage.charge(
                Resource::MetadataBytes,
                (self.immutable.capacity().saturating_sub(target) * std::mem::size_of::<ImmutableBinding>()) as u64,
            )?;
        }
        // The stamp normally resolves to a handle of the admitted volume's own declared paths: look there first,
        // instead of searching every binding when the stamp is next checked.
        let id = Identity(stamp.device, stamp.inode);
        let mut slot = None;
        if let Some((index, ProtectionDeclaration::Complete { inventory, .. })) = volume
            && self.complete
            && self.starts.len() == inventory.volumes.len() + 1
        {
            usage.charge(Resource::SourceBookkeeping, 1 + inventory.volumes.len().max(1).ilog2() as u64)?;
            if let Ok(position) = inventory.volumes.binary_search_by_key(&index, |v| v.index) {
                let range = self.starts[position]..self.starts[position + 1].min(self.bindings.len());
                usage.charge(Resource::SourceBookkeeping, range.len() as u64)?;
                slot = range
                    .clone()
                    .find(|&b| self.bindings[b].identity == Some(id) && self.bindings[b].handle.is_some())
                    .map(Slot::Binding);
            }
        }
        self.immutable.push(ImmutableBinding { path: path.to_path_buf(), stamp, slot });
        Ok(())
    }
    fn check_immutable(&mut self, usage: &Usage, sweep: Sweep) -> ProgressiveResult<()> {
        let n = self.immutable.len();
        if n == 0 {
            return Ok(());
        }
        if sweep == Sweep::Full {
            for i in 0..n {
                self.check_stamp(i, usage)?;
            }
            return Ok(());
        }
        // The newest stamp belongs to the volume being read; rotate the rest.
        self.check_stamp(n - 1, usage)?;
        if n > 1 {
            let i = self.next_immutable % (n - 1);
            self.next_immutable = (i + 1) % (n - 1);
            self.check_stamp(i, usage)?;
        }
        Ok(())
    }
    fn check_stamp(&mut self, i: usize, usage: &Usage) -> ProgressiveResult<()> {
        let immutable = &self.immutable[i];
        let slot = match immutable.slot {
            Some(slot) => {
                usage.charge(Resource::SourceBookkeeping, 8 + immutable.path.as_os_str().len() as u64)?;
                slot
            }
            None => {
                usage.charge(
                    Resource::SourceBookkeeping,
                    (self.bindings.len() + self.held.len() + 8 + immutable.path.as_os_str().len()) as u64,
                )?;
                let id = Identity(immutable.stamp.device, immutable.stamp.inode);
                let mut slot = self
                    .bindings
                    .iter()
                    .position(|binding| binding.identity == Some(id) && binding.handle.is_some())
                    .map(Slot::Binding);
                if slot.is_none() {
                    for (h, held) in self.held.iter().enumerate() {
                        if Identity::file(held).map_err(input)? == id {
                            slot = Some(Slot::Held(h));
                            break;
                        }
                    }
                }
                let slot = slot.ok_or_else(contract)?;
                self.immutable[i].slot = Some(slot);
                slot
            }
        };
        let file = match slot {
            Slot::Binding(b) => self.bindings[b].handle.as_deref().ok_or_else(contract)?,
            Slot::Held(h) => &self.held[h],
        };
        let immutable = &self.immutable[i];
        immutable.stamp.check(file, &immutable.path).map_err(super::super::source::immutable_error)
    }
    pub(crate) fn resolved_for_publication(&self, usage: &Usage) -> ProgressiveResult<bool> {
        usage.charge(Resource::SourceBookkeeping, self.bindings.len() as u64)?;
        // An unbound name may alias a differently spelled target on a case-folding
        // filesystem. Until it binds, keep the output provisional on every platform.
        Ok(self.complete && self.native_only && self.bindings.iter().all(|binding| binding.identity.is_some()))
    }
    #[cfg(feature = "persistent-partials")]
    pub(crate) fn check_partial_bindings(&self, usage: &Usage) -> ProgressiveResult<()> {
        for binding in &self.bindings {
            bookkeeping!(self, usage, 1 + binding.path.as_os_str().len() as u64)?;
            if binding.identity.is_some() && observe(&binding.path, binding.handle.as_deref())? != binding.identity {
                return Err(changed());
            }
        }
        Ok(())
    }
    #[cfg(feature = "persistent-partials")]
    pub(crate) fn check_partial_subtree(&self, path: &Path, usage: &mut Usage) -> ProgressiveResult<()> {
        let path = future_path(path)?;
        for binding in &self.bindings {
            bookkeeping!(self, usage, 1 + (path.as_os_str().len() + binding.path.as_os_str().len()) as u64)?;
            if future_path(&binding.path)?.starts_with(&path) {
                return Err(ProgressiveFailure::new(FailureKind::UnsafePath));
            }
        }
        self.check_partial_target(&path, usage)
    }
    #[cfg(feature = "persistent-partials")]
    pub(crate) fn check_partial_target(&self, path: &Path, usage: &mut Usage) -> ProgressiveResult<()> {
        let path = future_path(path)?;
        for binding in &self.bindings {
            bookkeeping!(self, usage, 1 + (path.as_os_str().len() + binding.path.as_os_str().len()) as u64)?;
            let source = future_path(&binding.path)?;
            if path == source {
                return Err(ProgressiveFailure::new(FailureKind::UnsafePath));
            }
        }
        if let Ok(meta) = fs::symlink_metadata(&path) {
            let identity = Identity::metadata(&meta).map_err(input)?;
            if self.bindings.iter().any(|b| b.identity == Some(identity))
                || self.admitted.iter().any(|(_, id)| *id == identity)
            {
                return Err(ProgressiveFailure::new(FailureKind::UnsafePath));
            }
        }
        Ok(())
    }
    pub(crate) fn check_target(
        &self,
        path: &Path,
        identity: Option<Identity>,
        usage: &mut Usage,
    ) -> ProgressiveResult<()> {
        for binding in &self.bindings {
            bookkeeping!(self, usage, 1 + (path.as_os_str().len() + binding.path.as_os_str().len()) as u64)?;
            if path == binding.path || (identity.is_some() && identity == binding.identity) {
                return Err(ProgressiveFailure::new(FailureKind::UnsafePath));
            }
            // Canonical parent matching protects an absent future filename through aliases.
            if path.file_name() == binding.path.file_name() {
                let a = path.parent().ok_or_else(contract)?.canonicalize().map_err(input)?;
                let b = binding.path.parent().ok_or_else(contract)?.canonicalize().map_err(input)?;
                if a == b {
                    return Err(ProgressiveFailure::new(FailureKind::UnsafePath));
                }
            }
        }
        bookkeeping!(self, usage, self.admitted.len() as u64)?;
        if identity.is_some_and(|id| self.admitted.iter().any(|(_, old)| *old == id)) {
            return Err(ProgressiveFailure::new(FailureKind::UnsafePath));
        }
        Ok(())
    }
}
fn observe(path: &Path, file: Option<&File>) -> ProgressiveResult<Option<Identity>> {
    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if file.is_some() {
                return Err(changed());
            }
            return Ok(None);
        }
        Err(e) => return Err(input(e)),
    };
    if !meta.is_file() {
        return Err(contract());
    }
    let identity = Identity::metadata(&meta).map_err(input)?;
    let held = file.ok_or_else(contract)?;
    if Identity::file(held).map_err(input)? != identity {
        return Err(changed());
    }
    Ok(Some(identity))
}

#[cfg(feature = "persistent-partials")]
pub(crate) fn future_path(path: &Path) -> ProgressiveResult<PathBuf> {
    let absolute = std::path::absolute(path).map_err(input)?;
    let mut ancestor = absolute.as_path();
    loop {
        match ancestor.canonicalize() {
            Ok(mut canonical) => {
                let suffix = absolute.strip_prefix(ancestor).map_err(|_| contract())?;
                // Pushing an empty suffix appends a separator, changing the
                // charged path length when the previously absent name appears.
                if !suffix.as_os_str().is_empty() {
                    canonical.push(suffix);
                }
                return Ok(canonical);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => ancestor = ancestor.parent().ok_or_else(contract)?,
            Err(e) => return Err(input(e)),
        }
    }
}
