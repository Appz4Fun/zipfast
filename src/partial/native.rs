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

//! Named file ownership. Dropping an owner closes descriptors only.
use super::limits::{PartialBudget, Reservation};
use super::*;
use crate::progressive::{
    FailureKind, OutputOperation, ProgressiveFailure, ProgressiveResult, ProtectionDeclaration, Resource, Usage, guard,
    native::{Identity, NativeProtection},
};
use std::{
    ffi::OsStr,
    fs::{self, File},
    io,
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
};

pub(crate) struct PartialProtectedPath {
    pub path: PathBuf,
    pub identity: Option<Identity>,
    pub root: PathBuf,
    pub root_identity: Identity,
    pub parent: PathBuf,
    pub parent_identity: Identity,
    pub directory: bool,
}
impl Clone for PartialProtectedPath {
    fn clone(&self) -> Self {
        Self {
            path: self.path.clone(),
            identity: self.identity,
            root: self.root.clone(),
            root_identity: self.root_identity,
            parent: self.parent.clone(),
            parent_identity: self.parent_identity,
            directory: self.directory,
        }
    }
}
pub(crate) struct PartialExclusions {
    entries: Mutex<Vec<Arc<PartialProtectedPath>>>,
    revision: std::sync::atomic::AtomicU64,
    usage: Usage,
    pub(super) counters: Arc<Mutex<[u64; 10]>>,
}
impl PartialExclusions {
    pub(crate) fn new(usage: Usage) -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            revision: std::sync::atomic::AtomicU64::new(0),
            usage,
            counters: Arc::new(Mutex::new([0; 10])),
        }
    }
    pub(crate) fn reserve(&self, path: &PartialProtectedPath) -> PartialResult<()> {
        self.reserve_inner(path, None)
    }
    pub(super) fn reserve_created(&self, path: &PartialProtectedPath, budget: &PartialBudget) -> PartialResult<()> {
        self.reserve_inner(path, Some(budget))
    }
    fn reserve_inner(&self, path: &PartialProtectedPath, budget: Option<&PartialBudget>) -> PartialResult<()> {
        let mut list = self.entries.lock().unwrap();
        match budget {
            Some(budget) => budget.bookkeeping(list.len() as u64)?,
            None => self.usage.charge(Resource::SourceBookkeeping, list.len() as u64)?,
        }
        if let Some(old) = list.iter().find(|p| p.path == path.path) {
            if path.identity.is_some() && old.identity.is_some() && path.identity != old.identity {
                return Err(err(PartialErrorKind::OutputChanged));
            }
            return Ok(());
        }
        let charge = |resource, amount| match budget {
            Some(budget) => budget.creation_charge(resource, amount),
            None => self.usage.charge(resource, amount).map_err(Into::into),
        };
        charge(Resource::ProtectionPaths, 1)?;
        let bytes = path.path.as_os_str().len()
            + path.root.as_os_str().len()
            + path.parent.as_os_str().len()
            + std::mem::size_of::<PartialProtectedPath>()
            + 3 * std::mem::size_of::<usize>();
        charge(Resource::MetadataBytes, bytes as u64)?;
        charge(Resource::ProtectionPathBytes, bytes as u64)?;
        list.try_reserve_exact(1).map_err(|_| malformed())?;
        let next = self.revision.load(Ordering::Relaxed).checked_add(1).ok_or_else(malformed)?;
        list.push(Arc::new(path.clone()));
        self.revision.store(next, Ordering::Release);
        Ok(())
    }
    // Called only after acknowledged retirement has actually removed the name.
    pub(super) fn retire(&self, path: &Path) {
        let mut list = self.entries.lock().unwrap();
        if list.iter().any(|entry| entry.path == path) {
            // Exhaustion retains a conservative exclusion; it never wraps or
            // silently makes an old snapshot current again.
            if let Some(next) = self.revision.load(Ordering::Relaxed).checked_add(1) {
                list.retain(|entry| entry.path != path);
                self.revision.store(next, Ordering::Release);
            }
        }
    }
    pub(crate) fn bind(&self, path: &Path, file: &File) -> PartialResult<()> {
        let identity = Identity::file(file).map_err(|e| io_error(OutputOperation::Metadata, e))?;
        let mut list = self.entries.lock().unwrap();
        let item = list.iter_mut().find(|p| p.path == path).ok_or_else(malformed)?;
        if item.identity.is_some_and(|old| old != identity) {
            return Err(err(PartialErrorKind::OutputChanged));
        }
        if item.identity.is_none() {
            let next = self.revision.load(Ordering::Relaxed).checked_add(1).ok_or_else(malformed)?;
            // A reader may still hold the immutable pre-bind facts while doing
            // path IO. Copy only this changed entry, never the entire registry.
            if Arc::strong_count(item) > 1 {
                self.usage.charge(
                    Resource::MetadataBytes,
                    (std::mem::size_of::<PartialProtectedPath>()
                        + 2 * std::mem::size_of::<usize>()
                        + item.path.as_os_str().len()
                        + item.root.as_os_str().len()
                        + item.parent.as_os_str().len()) as u64,
                )?;
            }
            Arc::make_mut(item).identity = Some(identity);
            self.revision.store(next, Ordering::Release);
        }
        Ok(())
    }
    pub(super) fn entry_count(&self) -> usize {
        self.entries.lock().unwrap().len()
    }
    pub(crate) fn revision(&self) -> u64 {
        self.revision.load(Ordering::Acquire)
    }
    pub(crate) fn check_input(&self, paths: &[PathBuf], files: &[File]) -> ProgressiveResult<()> {
        self.check_input_revision(paths, files).map(|_| ())
    }
    /// Refuses a declared path naming an output, lock or state bundle (or a path inside a bundle) by any
    /// spelling: both sides are canonicalised as member creation canonicalises, so a symlinked-directory alias
    /// is caught too. Path IO runs outside the registry lock.
    pub(crate) fn check_declared<'a>(&self, paths: impl IntoIterator<Item = &'a Path>) -> ProgressiveResult<()> {
        let entries = {
            let list = self.entries.lock().unwrap();
            self.usage.charge(
                Resource::MetadataBytes,
                (list.len() * std::mem::size_of::<Arc<PartialProtectedPath>>()) as u64,
            )?;
            list.clone()
        };
        if entries.is_empty() {
            return Ok(());
        }
        let mut declared = Vec::new();
        for path in paths {
            self.usage.charge(Resource::SourceBookkeeping, 1 + path.as_os_str().len() as u64)?;
            let canonical = crate::progressive::native::future_path(path)?;
            self.usage.charge(
                Resource::MetadataBytes,
                (std::mem::size_of::<PathBuf>() + canonical.as_os_str().len()) as u64,
            )?;
            declared.try_reserve(1).map_err(|_| ProgressiveFailure::new(FailureKind::SourceContract))?;
            declared.push(canonical);
        }
        for entry in entries {
            self.usage
                .charge(Resource::SourceBookkeeping, 1 + entry.path.as_os_str().len() as u64 + declared.len() as u64)?;
            let excluded = crate::progressive::native::future_path(&entry.path)?;
            if declared.iter().any(|path| *path == excluded || (entry.directory && path.starts_with(&excluded))) {
                return Err(ProgressiveFailure::new(FailureKind::UnsafePath));
            }
        }
        Ok(())
    }
    /// None requests a bounded retry: the examined snapshot was retired while
    /// path IO ran. No filesystem or caller callback runs under the registry lock.
    pub(crate) fn check_input_revision(&self, paths: &[PathBuf], files: &[File]) -> ProgressiveResult<Option<u64>> {
        // Keep path facts alive without repeatedly allocating three paths per
        // live state file on every source callback. IO remains outside the lock.
        let (revision, entries) = {
            let list = self.entries.lock().unwrap();
            self.usage.charge(
                Resource::MetadataBytes,
                (list.len() * std::mem::size_of::<Arc<PartialProtectedPath>>()) as u64,
            )?;
            (self.revision.load(Ordering::Relaxed), list.clone())
        };
        let unsafe_path = || ProgressiveFailure::new(FailureKind::UnsafePath);
        for entry in entries {
            for (path, expected) in [(&entry.root, entry.root_identity), (&entry.parent, entry.parent_identity)] {
                let m = fs::symlink_metadata(path).map_err(|_| unsafe_path())?;
                if !m.is_dir() || Identity::metadata(&m).map_err(|_| unsafe_path())? != expected {
                    return Err(unsafe_path());
                }
            }
            for path in paths {
                if path == &entry.path || (entry.directory && path.starts_with(&entry.path)) {
                    return Err(unsafe_path());
                }
            }
            for file in files {
                if Some(Identity::file(file).map_err(|_| unsafe_path())?) == entry.identity {
                    return Err(unsafe_path());
                }
            }
        }
        Ok((revision == self.revision()).then_some(revision))
    }
}

pub(super) struct PreparedNative {
    root: PathBuf,
    state_root: PathBuf,
    output: PathBuf,
    bundle: PathBuf,
    parents: Vec<Directory>,
    protection: NativeProtection,
}
impl PreparedNative {
    pub(super) fn paths(&self) -> (&Path, &Path) {
        (&self.output, &self.bundle)
    }
    pub(super) fn new(spec: &CreateSpec, budget: &PartialBudget) -> PartialResult<Self> {
        Self::layout(
            &spec.output_root,
            &spec.state_root,
            &spec.relative_output,
            &spec.member,
            &spec.protection,
            budget,
            true,
        )
    }
    fn layout(
        output_root: &Path,
        state_root: &Path,
        relative: &Path,
        member: &MemberKey,
        declaration: &ProtectionDeclaration,
        budget: &PartialBudget,
        create: bool,
    ) -> PartialResult<Self> {
        budget.metadata(
            (output_root.as_os_str().len() + state_root.as_os_str().len() + relative.as_os_str().len()) as u64 * 4
                + 8192,
        )?;
        let root = std::path::absolute(output_root).map_err(|e| io_error(OutputOperation::Metadata, e))?;
        let state_root = std::path::absolute(state_root).map_err(|e| io_error(OutputOperation::Metadata, e))?;
        let output = root.join(relative);
        guard::check_parents(&root, &output, &budget.usage)?;
        let bundle = state_root.join(bundle_name(member));
        let parents = budget.vector(relative.components().count().saturating_sub(1))?;
        let mut protection = NativeProtection::new(&budget.usage)?;
        let mut usage = budget.usage.clone();
        protection.refresh(declaration, &mut usage, 0)?;
        if create {
            protection.check_partial_target(&output, &mut usage)?;
            protection.check_partial_subtree(&bundle, &mut usage)?;
            let entry = std::mem::size_of::<PartialProtectedPath>() + 3 * std::mem::size_of::<usize>();
            let output_bytes = output.as_os_str().len()
                + root.as_os_str().len()
                + output.parent().ok_or_else(malformed)?.as_os_str().len()
                + entry;
            let bundle_bytes = bundle.as_os_str().len() + 2 * state_root.as_os_str().len() + entry;
            let lock_bytes = 2 * bundle.as_os_str().len() + 5 + state_root.as_os_str().len() + entry;
            let immutable_bytes = 3 * bundle.as_os_str().len() + 67 + entry;
            let bytes = output_bytes
                .checked_add(bundle_bytes)
                .and_then(|n| n.checked_add(lock_bytes))
                .and_then(|n| {
                    immutable_bytes
                        .checked_mul(budget.genesis_pages().ok()?.checked_add(2)?)
                        .and_then(|v| n.checked_add(v))
                })
                .ok_or_else(malformed)?;
            budget.admit_genesis(bytes as u64)?;
            protection.prepare_partial_genesis(&output, &bundle, declaration, budget)?;
        }
        Ok(Self { root, state_root, output, bundle, parents, protection })
    }
}

pub(super) struct HeldFile {
    pub file: File,
    _reservation: Reservation,
}
impl HeldFile {
    fn from(file: File, reservation: Reservation) -> Arc<Self> {
        Arc::new(Self { file, _reservation: reservation })
    }
}
pub(super) struct Directory {
    pub path: PathBuf,
    pub held: Arc<HeldFile>,
    pub identity: Identity,
}
impl Directory {
    pub(super) fn open(path: PathBuf, budget: &PartialBudget) -> PartialResult<Self> {
        let reservation = budget.reserve(PartialResource::OpenFiles, 1)?;
        let file = guard::open_directory(&path)?;
        let identity = Identity::file(&file).map_err(|e| io_error(OutputOperation::Metadata, e))?;
        let value = Self { path, held: HeldFile::from(file, reservation), identity };
        value.check()?;
        Ok(value)
    }
    pub(super) fn check(&self) -> PartialResult<()> {
        guard::check_directory(&self.path, &self.held.file, self.identity).map_err(Into::into)
    }
}
#[derive(Clone)]
pub(crate) struct NativeBinding {
    pub root: Identity,
    pub parent: Identity,
    pub output: Identity,
    pub bundle: Identity,
}
pub(crate) struct PersistentNative {
    pub(super) output: Arc<HeldFile>,
    pub(super) output_path: PathBuf,
    root: Directory,
    parents: Vec<Directory>,
    state_root: Directory,
    pub(super) bundle: Directory,
    lock: Arc<HeldFile>,
    lock_identity: Identity,
    pub(super) binding: NativeBinding,
    protection: NativeProtection,
    usage: Usage,
}
pub(super) fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 15) as usize] as char);
    }
    s
}
pub(super) fn bundle_name(member: &MemberKey) -> String {
    let mut bytes = Vec::with_capacity(96);
    bytes.extend_from_slice(b"ZFPART-BUNDLE-1");
    bytes.extend_from_slice(&member.binding.job);
    bytes.extend_from_slice(&member.binding.archive);
    bytes.extend_from_slice(&member.ordinal.to_le_bytes());
    bytes.extend_from_slice(&member.identity);
    hex(&crate::crypto::sha256(&bytes))
}
pub(super) fn validate_relative(path: &Path) -> PartialResult<()> {
    if path.as_os_str().is_empty() || !path.components().all(|c| matches!(c, Component::Normal(_))) {
        return Err(err(PartialErrorKind::UnsafePath));
    }
    Ok(())
}
pub(super) fn platform() -> PartialResult<()> {
    if cfg!(any(target_os = "linux", target_os = "macos")) {
        Ok(())
    } else {
        Err(err(PartialErrorKind::UnsupportedPlatform))
    }
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn cname(name: &OsStr) -> PartialResult<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(name.as_bytes()).map_err(|_| err(PartialErrorKind::UnsafePath))
}
pub(super) fn open_at(dir: &File, name: &OsStr, create: bool, budget: &PartialBudget) -> PartialResult<Arc<HeldFile>> {
    platform()?;
    let reservation = budget.reserve(PartialResource::OpenFiles, 1)?;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::os::fd::{AsRawFd, FromRawFd};
        let name = cname(name)?;
        let flags = libc::O_RDWR
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | libc::O_NONBLOCK
            | if create { libc::O_CREAT | libc::O_EXCL } else { 0 };
        // The directory descriptor is held and name is exactly one checked component.
        let raw = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags, 0o600) };
        if raw < 0 {
            let cause = io::Error::last_os_error();
            return Err(if cause.kind() == io::ErrorKind::AlreadyExists {
                err(PartialErrorKind::AlreadyExists)
            } else {
                io_error(OutputOperation::Create, cause)
            });
        }
        // openat returned a newly owned descriptor.
        let file = unsafe { File::from_raw_fd(raw) };
        regular(&file)?;
        Ok(HeldFile::from(file, reservation))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (dir, name, create, reservation);
        Err(err(PartialErrorKind::UnsupportedPlatform))
    }
}
fn regular(file: &File) -> PartialResult<()> {
    let m = file.metadata().map_err(|e| io_error(OutputOperation::Metadata, e))?;
    if !m.is_file() {
        return Err(err(PartialErrorKind::UnsafePath));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if m.nlink() != 1 {
            return Err(err(PartialErrorKind::UnsafePath));
        }
    }
    Ok(())
}
fn lock(file: &File) -> PartialResult<()> {
    platform()?;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::os::fd::AsRawFd;
        // Nonblocking advisory exclusion; held descriptor lifetime owns the lock.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let cause = io::Error::last_os_error();
            if cause.kind() == io::ErrorKind::WouldBlock {
                return Err(err(PartialErrorKind::Busy));
            }
            return Err(io_error(OutputOperation::Create, cause));
        }
    }
    Ok(())
}
fn mkdir_at(dir: &File, name: &OsStr) -> PartialResult<()> {
    platform()?;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::os::fd::AsRawFd;
        let name = cname(name)?;
        // Exclusive creation of a single name beneath a held directory.
        if unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            let e = io::Error::last_os_error();
            return Err(if e.kind() == io::ErrorKind::AlreadyExists {
                err(PartialErrorKind::AlreadyExists)
            } else {
                io_error(OutputOperation::Create, e)
            });
        }
    }
    Ok(())
}
struct NativeSpec<'a> {
    member: &'a MemberKey,
    output_root: &'a Path,
    state_root: &'a Path,
    relative_output: &'a Path,
    size: u64,
    protection: &'a ProtectionDeclaration,
}
impl PersistentNative {
    pub(crate) fn create(spec: &CreateSpec, budget: &PartialBudget, prepared: PreparedNative) -> PartialResult<Self> {
        Self::bind(
            NativeSpec {
                member: &spec.member,
                output_root: &spec.output_root,
                state_root: &spec.state_root,
                relative_output: &spec.relative_output,
                size: spec.size,
                protection: &spec.protection,
            },
            true,
            None,
            budget,
            Some(prepared),
        )
    }
    pub(crate) fn reopen(spec: &ReopenSpec, budget: &PartialBudget) -> PartialResult<Self> {
        let (_, _, _, head) = state::decode_record(&spec.state.wire, &budget.limits)?;
        Self::bind(
            NativeSpec {
                member: &head.member,
                output_root: &spec.context.output_root,
                state_root: &spec.context.state_root,
                relative_output: &head.relative_output,
                size: head.size,
                protection: &spec.context.protection,
            },
            false,
            Some(&head.binding),
            budget,
            None,
        )
    }
    fn bind(
        spec: NativeSpec<'_>,
        create: bool,
        expected: Option<&NativeBinding>,
        budget: &PartialBudget,
        prepared: Option<PreparedNative>,
    ) -> PartialResult<Self> {
        platform()?;
        validate_relative(spec.relative_output)?;
        if !matches!(spec.protection, ProtectionDeclaration::Complete { .. }) {
            return Err(err(PartialErrorKind::InvalidOptions));
        }
        let PreparedNative {
            root: root_path,
            state_root: state_path,
            output: output_path,
            bundle: bundle_path,
            mut parents,
            mut protection,
        } = match prepared {
            Some(prepared) => prepared,
            None => PreparedNative::layout(
                spec.output_root,
                spec.state_root,
                spec.relative_output,
                spec.member,
                spec.protection,
                budget,
                false,
            )?,
        };
        let root = Directory::open(root_path, budget)?;
        let state_root = Directory::open(state_path, budget)?;
        let mut at = root.path.clone();
        if let Some(relative) = spec.relative_output.parent() {
            for c in relative.components() {
                at.push(c);
                parents.push(Directory::open(at.clone(), budget)?);
            }
        }
        let parent = parents.last().unwrap_or(&root);
        let mut usage = budget.usage.clone();
        protection.refresh(spec.protection, &mut usage, 0)?;
        protection.check_target(&output_path, None, &mut usage)?;
        protection.check_target(&bundle_path, None, &mut usage)?;
        budget.exclude(&PartialProtectedPath {
            path: output_path.clone(),
            identity: None,
            root: root.path.clone(),
            root_identity: root.identity,
            parent: parent.path.clone(),
            parent_identity: parent.identity,
            directory: false,
        })?;
        budget.exclude(&PartialProtectedPath {
            path: bundle_path.clone(),
            identity: None,
            root: state_root.path.clone(),
            root_identity: state_root.identity,
            parent: state_root.path.clone(),
            parent_identity: state_root.identity,
            directory: true,
        })?;
        if create {
            match fs::symlink_metadata(&output_path) {
                Ok(_) => return Err(err(PartialErrorKind::AlreadyExists)),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(io_error(OutputOperation::Metadata, e)),
            }
            root.check()?;
            state_root.check()?;
            parent.check()?;
            mkdir_at(&state_root.held.file, bundle_path.file_name().ok_or_else(malformed)?)?;
        }
        let location = PartialLocation { output: output_path.clone(), state_bundle: bundle_path.clone() };
        let result = (|| {
            let parent = parents.last().unwrap_or(&root);
            let bundle = Directory::open(bundle_path, budget)?;
            let lock_path = bundle.path.join("lock");
            budget.exclude(&PartialProtectedPath {
                path: lock_path.clone(),
                identity: None,
                root: state_root.path.clone(),
                root_identity: state_root.identity,
                parent: bundle.path.clone(),
                parent_identity: bundle.identity,
                directory: false,
            })?;
            let lock_file = open_at(&bundle.held.file, OsStr::new("lock"), create, budget)?;
            budget.exclusions.bind(&lock_path, &lock_file.file)?;
            lock(&lock_file.file)?;
            let lock_identity = Identity::file(&lock_file.file).map_err(|e| io_error(OutputOperation::Metadata, e))?;
            let output = open_at(&parent.held.file, output_path.file_name().ok_or_else(malformed)?, create, budget)?;
            lock(&output.file)?;
            let binding = NativeBinding {
                root: root.identity,
                parent: parent.identity,
                output: Identity::file(&output.file).map_err(|e| io_error(OutputOperation::Metadata, e))?,
                bundle: bundle.identity,
            };
            if expected.is_some_and(|b| {
                b.root != binding.root
                    || b.parent != binding.parent
                    || b.output != binding.output
                    || b.bundle != binding.bundle
            }) {
                return Err(err(PartialErrorKind::BindingMismatch(BindingField::Output)));
            }
            protection.check_target(&output_path, Some(binding.output), &mut usage)?;
            budget.exclusions.bind(&output_path, &output.file)?;
            budget.exclusions.bind(&bundle.path, &bundle.held.file)?;
            let native = Self {
                output,
                output_path,
                root,
                parents,
                state_root,
                bundle,
                lock: lock_file,
                lock_identity,
                binding,
                protection,
                usage,
            };
            native.check(if create { 0 } else { spec.size })?;
            Ok(native)
        })();
        result.map_err(|mut error: PartialError| {
            if create {
                error.location = Some(location);
            }
            error
        })
    }
    pub(crate) fn check(&self, expected_len: u64) -> PartialResult<()> {
        self.root.check()?;
        self.state_root.check()?;
        self.bundle.check()?;
        for parent in &self.parents {
            parent.check()?;
        }
        for (path, file, expected) in [
            (&self.output_path, &self.output.file, self.binding.output),
            (&self.bundle.path.join("lock"), &self.lock.file, self.lock_identity),
        ] {
            regular(file)?;
            let m = fs::symlink_metadata(path).map_err(|e| io_error(OutputOperation::Metadata, e))?;
            if !m.is_file()
                || Identity::metadata(&m).map_err(|e| io_error(OutputOperation::Metadata, e))? != expected
                || Identity::file(file).map_err(|e| io_error(OutputOperation::Metadata, e))? != expected
            {
                return Err(err(PartialErrorKind::OutputChanged));
            }
        }
        if self.output.file.metadata().map_err(|e| io_error(OutputOperation::Metadata, e))?.len() != expected_len {
            return Err(err(PartialErrorKind::OutputChanged));
        }
        self.protection.check_partial_bindings(&self.usage)?;
        self.protection.check_partial_target(&self.output_path, &mut self.usage.clone())?;
        self.protection.check_partial_subtree(&self.bundle.path, &mut self.usage.clone())?;
        self.protection.check_target(&self.output_path, Some(self.binding.output), &mut self.usage.clone())?;
        Ok(())
    }
    pub(crate) fn sync(&self) -> PartialResult<()> {
        self.output.file.sync_all().map_err(|e| io_error(OutputOperation::Flush, e))
    }
    pub(super) fn sync_parents(&self) -> PartialResult<()> {
        for file in [&self.root.held.file, &self.state_root.held.file, &self.bundle.held.file] {
            file.sync_all().map_err(|e| io_error(OutputOperation::Flush, e))?;
        }
        for p in &self.parents {
            p.held.file.sync_all().map_err(|e| io_error(OutputOperation::Flush, e))?;
        }
        Ok(())
    }
}

/// What a genesis asks the session to check before creating any name: each parent directory, then the output
/// file and the state bundle, after every parent's check.
pub(crate) enum GenesisPath<'a> {
    Parent(&'a Path),
    Output(&'a Path),
    Bundle(&'a Path),
}
/// Holds every observed ancestor through the independent Core binding.
pub(crate) struct PreparedParents {
    held: Vec<Directory>,
}
impl PreparedParents {
    pub(crate) fn check(&self) -> PartialResult<()> {
        for directory in &self.held {
            directory.check()?;
        }
        Ok(())
    }
}
pub(super) fn prepare_parents(
    spec: &CreateSpec,
    genesis: &PartialBudget,
    control: &SessionControl,
    targets: (&Path, &Path),
    mut check: impl FnMut(GenesisPath<'_>) -> PartialResult<()>,
) -> PartialResult<PreparedParents> {
    // Separate transient reservations cannot consume the prepared Core's credits.
    let budget = PartialBudget::new(genesis.limits.clone(), genesis.usage.clone(), genesis.exclusions.clone())?;
    let mut paths = Vec::<PathBuf>::new();
    let output = std::path::absolute(&spec.output_root).map_err(|e| io_error(OutputOperation::Metadata, e))?;
    let state = std::path::absolute(&spec.state_root).map_err(|e| io_error(OutputOperation::Metadata, e))?;
    for target in [&output, &state, &output.join(&spec.relative_output).parent().ok_or_else(malformed)?.to_path_buf()] {
        let mut at = target.as_path();
        loop {
            canceled(control)?;
            budget.usage.charge(Resource::SourceBookkeeping, paths.len() as u64 + 1)?;
            if !paths.iter().any(|p| p == at) {
                budget.metadata((std::mem::size_of::<PathBuf>() + at.as_os_str().len()) as u64)?;
                paths.try_reserve_exact(1).map_err(|_| malformed())?;
                paths.push(at.to_path_buf());
            }
            match fs::symlink_metadata(at) {
                Ok(meta) => {
                    if !meta.is_dir() {
                        return Err(err(PartialErrorKind::UnsafePath));
                    }
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => at = at.parent().ok_or_else(malformed)?,
                Err(e) => return Err(io_error(OutputOperation::Metadata, e)),
            }
        }
    }
    paths.sort_by_key(|p| p.components().count());
    let mut held = budget.vector::<Directory>(paths.len())?;
    let mut missing = budget.vector::<PathBuf>(paths.len())?;
    let reservations = budget.vector::<(PartialResource, u64)>(paths.len())?;
    let mut reservations = reservations;
    reservations.resize(paths.len(), (PartialResource::OpenFiles, 1));
    budget.prepay(&reservations)?;
    // All existing ancestors are held, all missing names reserved, and every
    // provider callback has returned before the first mkdirat.
    for path in paths {
        check(GenesisPath::Parent(&path))?;
        for directory in &held {
            directory.check()?;
        }
        match fs::symlink_metadata(&path) {
            Ok(meta) => {
                if !meta.is_dir() {
                    return Err(err(PartialErrorKind::UnsafePath));
                }
                held.push(Directory::open(path, &budget)?);
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let ancestor = held.iter().rev().find(|d| path.starts_with(&d.path)).ok_or_else(malformed)?;
                budget.exclusions.reserve(&PartialProtectedPath {
                    path: path.clone(),
                    identity: None,
                    root: ancestor.path.clone(),
                    root_identity: ancestor.identity,
                    parent: ancestor.path.clone(),
                    parent_identity: ancestor.identity,
                    directory: false,
                })?;
                missing.push(path);
            }
            Err(e) => return Err(io_error(OutputOperation::Metadata, e)),
        }
    }
    // The parent checks read the declaration again, so it may have grown since the output and bundle were
    // checked against it; their exclusions do not exist until the genesis, so an extension cannot see them.
    check(GenesisPath::Output(targets.0))?;
    check(GenesisPath::Bundle(targets.1))?;
    for directory in &held {
        directory.check()?;
    }
    // The remaining native rechecks and exclusion-table visits are predictable
    // now: provider callbacks and provisional parent reservations have finished.
    genesis.admit_genesis_bookkeeping()?;
    for path in missing {
        canceled(control)?;
        for directory in &held {
            directory.check()?;
        }
        let parent = held.iter().find(|d| Some(d.path.as_path()) == path.parent()).ok_or_else(malformed)?;
        mkdir_at(&parent.held.file, path.file_name().ok_or_else(malformed)?)?;
        parent.held.file.sync_all().map_err(|e| io_error(OutputOperation::Flush, e))?;
        let directory = Directory::open(path, &budget)?;
        budget.exclusions.bind(&directory.path, &directory.held.file)?;
        held.push(directory);
    }
    let prepared = PreparedParents { held };
    prepared.check()?;
    Ok(prepared)
}
