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
    FailureKind, InputOperation, ProgressiveFailure, ProgressiveResult, ProtectionDeclaration, Resource, VolumeBacking,
};
use std::{
    fs::{self, File, Metadata},
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
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
}
pub(crate) struct NativeProtection {
    bindings: Vec<Binding>,
    admitted: Vec<(u32, Identity)>,
    complete: bool,
    native_only: bool,
    cwd: PathBuf,
    held: Vec<File>,
    immutable: Vec<ImmutableBinding>,
}
impl NativeProtection {
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
            bindings: Vec::new(),
            admitted: Vec::new(),
            complete: false,
            native_only: false,
            cwd,
            held: Vec::new(),
            immutable: Vec::new(),
        })
    }

    pub(crate) fn refresh(
        &mut self,
        declaration: &ProtectionDeclaration,
        usage: &mut Usage,
        external_handles: usize,
    ) -> ProgressiveResult<()> {
        self.check_immutable(usage)?;
        let ProtectionDeclaration::Complete { inventory, .. } = declaration else { return Ok(()) };
        usage.charge(
            Resource::SourceBookkeeping,
            (inventory.volumes.len() + inventory.auxiliary_paths.len() + self.bindings.len()) as u64,
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
            self.native_only = native_only;
            self.complete = true;
        } else {
            for (binding, path) in self.bindings.iter_mut().zip(paths) {
                usage.charge(Resource::SourceBookkeeping, 1 + binding.path.as_os_str().len() as u64)?;
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
        for &(index, identity) in &self.admitted {
            self.covers(index, identity, declaration, usage)?;
        }
        Ok(())
    }
    fn covers(
        &self,
        index: u32,
        identity: Identity,
        declaration: &ProtectionDeclaration,
        usage: &mut Usage,
    ) -> ProgressiveResult<()> {
        let ProtectionDeclaration::Complete { inventory, .. } = declaration else { return Ok(()) };
        usage.charge(Resource::SourceBookkeeping, inventory.volumes.len() as u64 + self.bindings.len() as u64)?;
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
                return Ok(());
            }
        }
        Err(contract())
    }
    pub(crate) fn admit(
        &mut self,
        index: u32,
        files: &[File],
        declaration: &ProtectionDeclaration,
        usage: &mut Usage,
        external_handles: usize,
    ) -> ProgressiveResult<()> {
        usage.charge(Resource::SourceBookkeeping, (self.bindings.len() + self.admitted.len() + files.len()) as u64)?;
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
            usage.charge(Resource::SourceBookkeeping, self.admitted.len() as u64)?;
            if !self.complete && !self.admitted.iter().any(|(_, old)| *old == id) {
                let retained = file.try_clone().map_err(|cause| {
                    ProgressiveFailure::new(FailureKind::Input { operation: InputOperation::Open, cause })
                })?;
                self.held.push(retained);
            }
            self.admitted.push((index, id));
        }
        Ok(())
    }
    pub(crate) fn remember_immutable(
        &mut self,
        file: &File,
        path: &Path,
        stamp: crate::rar5::source::SourceStamp,
        usage: &Usage,
    ) -> ProgressiveResult<()> {
        usage.charge(Resource::SourceBookkeeping, 8 + path.as_os_str().len() as u64 + self.immutable.len() as u64)?;
        stamp.check(file, path).map_err(super::super::source::immutable_error)?;
        usage.charge(
            Resource::MetadataBytes,
            (std::mem::size_of::<ImmutableBinding>() + path.as_os_str().len()) as u64,
        )?;
        let old = self.immutable.capacity();
        self.immutable.try_reserve_exact(1).map_err(|_| contract())?;
        usage.charge(
            Resource::MetadataBytes,
            (self.immutable.capacity().saturating_sub(old + 1) * std::mem::size_of::<ImmutableBinding>()) as u64,
        )?;
        self.immutable.push(ImmutableBinding { path: path.to_path_buf(), stamp });
        Ok(())
    }
    fn check_immutable(&self, usage: &Usage) -> ProgressiveResult<()> {
        for immutable in &self.immutable {
            usage.charge(
                Resource::SourceBookkeeping,
                (self.bindings.len() + self.held.len() + 8 + immutable.path.as_os_str().len()) as u64,
            )?;
            let id = Identity(immutable.stamp.device, immutable.stamp.inode);
            let mut file = self
                .bindings
                .iter()
                .find(|binding| binding.identity == Some(id))
                .and_then(|binding| binding.handle.as_deref());
            if file.is_none() {
                for held in &self.held {
                    if Identity::file(held).map_err(input)? == id {
                        file = Some(held);
                        break;
                    }
                }
            }
            immutable
                .stamp
                .check(file.ok_or_else(contract)?, &immutable.path)
                .map_err(super::super::source::immutable_error)?;
        }
        Ok(())
    }
    pub(crate) fn resolved_for_publication(&self, usage: &Usage) -> ProgressiveResult<bool> {
        usage.charge(Resource::SourceBookkeeping, self.bindings.len() as u64)?;
        // An unbound name may alias a differently spelled target on a case-folding
        // filesystem. Until it binds, keep the output provisional on every platform.
        Ok(self.complete && self.native_only && self.bindings.iter().all(|binding| binding.identity.is_some()))
    }
    pub(crate) fn check_target(
        &self,
        path: &Path,
        identity: Option<Identity>,
        usage: &mut Usage,
    ) -> ProgressiveResult<()> {
        for binding in &self.bindings {
            usage.charge(
                Resource::SourceBookkeeping,
                1 + (path.as_os_str().len() + binding.path.as_os_str().len()) as u64,
            )?;
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
        usage.charge(Resource::SourceBookkeeping, self.admitted.len() as u64)?;
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
