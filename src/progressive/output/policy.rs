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

//! Target policy shared by staged files, read-only skips and directories.
use super::*;
pub(super) struct Policy<'a> {
    pub(super) root: &'a Root,
    pub(super) usage: &'a Usage,
}
pub(super) struct Directory {
    path: PathBuf,
    identity: native::Identity,
    meta: crate::extract::Meta,
    depth: usize,
    order: usize,
}
impl Policy<'_> {
    pub(super) fn target(&self, member: MemberId, name: &str, windows_names: bool) -> ProgressiveResult<Target> {
        self.target_kind(member, name, windows_names, false)
    }
    fn target_kind(
        &self,
        member: MemberId,
        name: &str,
        windows_names: bool,
        directory: bool,
    ) -> ProgressiveResult<Target> {
        self.root.check()?;
        self.usage.charge(Resource::SourceBookkeeping, (name.len() as u64).saturating_mul(8))?;
        self.usage.charge(Resource::NameBytes, name.len() as u64)?;
        self.usage
            .charge(Resource::MetadataBytes, (name.len() * 3 + self.root.path.as_os_str().len() * 2 + 4) as u64)?;
        let relative = crate::path::sanitize_fallible(name, windows_names)
            .map_err(|_| ProgressiveFailure::new(FailureKind::UnsafePath))?;
        let relative =
            if self.root.flatten { Path::new(relative.file_name().ok_or_else(invalid)?) } else { relative.as_path() };
        let path = self.root.path.join(relative);
        self.parents(&path)?;
        let initial = target_stamp(&path, directory)?;
        let mut parent_path = path.parent().ok_or_else(invalid)?.to_path_buf();
        loop {
            self.usage.charge(Resource::SourceBookkeeping, 1 + parent_path.as_os_str().len() as u64)?;
            match fs::symlink_metadata(&parent_path) {
                Ok(_) => break,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    if !parent_path.pop() {
                        return Err(invalid());
                    }
                }
                Err(e) => return Err(out(OutputOperation::Metadata, e, 0)),
            }
        }
        let parent = open_directory(&parent_path)?;
        let parent_identity = native::Identity::file(&parent).map_err(|e| out(OutputOperation::Metadata, e, 0))?;
        Ok(Target {
            path,
            initial,
            directory,
            parent_path,
            parent,
            parent_identity,
            parent_unbound: false,
            member,
            stage_identity: None,
        })
    }
    pub(super) fn parents(&self, path: &Path) -> ProgressiveResult<()> {
        self.root.check()?;
        guard::check_parents(&self.root.path, path, self.usage)
    }
    pub(super) fn prepare_parents(
        &self,
        target: &mut Target,
        source: &mut crate::progressive::source::SourceDriver,
    ) -> ProgressiveResult<()> {
        target.check_parent()?;
        let relative =
            target.path.parent().ok_or_else(invalid)?.strip_prefix(&target.parent_path).map_err(|_| invalid())?;
        self.usage.charge(Resource::MetadataBytes, (target.path.as_os_str().len() as u64).saturating_mul(2))?;
        let mut at = target.parent_path.clone();
        for component in relative.components() {
            self.root.check()?;
            target.check_parent()?;
            at.push(component);
            self.usage.charge(Resource::SourceBookkeeping, 8 + at.as_os_str().len() as u64)?;
            self.usage.charge(Resource::MetadataBytes, at.as_os_str().len() as u64)?;
            let bound_path = at.clone();
            self.usage
                .charge(Resource::MetadataBytes, bound_path.capacity().saturating_sub(at.as_os_str().len()) as u64)?;
            match fs::symlink_metadata(&at) {
                Ok(m) if m.is_dir() && !m.file_type().is_symlink() => {}
                Ok(_) => return Err(ProgressiveFailure::new(FailureKind::UnsafePath)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    for (protected, _) in &self.root.protected {
                        self.usage.charge(
                            Resource::SourceBookkeeping,
                            1 + (protected.as_os_str().len() + at.as_os_str().len()) as u64,
                        )?;
                        if protected == &at {
                            return Err(ProgressiveFailure::new(FailureKind::UnsafePath));
                        }
                    }
                    if !source.publication_check(&at, None)? {
                        return Err(ProgressiveFailure::new(FailureKind::SourceContract));
                    }
                    // If creation/open/check cannot finish, a retry must never adopt
                    // an unbound directory left by this attempt or its replacement.
                    target.parent_unbound = true;
                    fs::create_dir(&at).map_err(|e| out(OutputOperation::Create, e, 0))?;
                }
                Err(e) => return Err(out(OutputOperation::Metadata, e, 0)),
            }
            target.parent_unbound = true;
            let parent = open_directory(&at)?;
            let identity = native::Identity::file(&parent).map_err(|e| out(OutputOperation::Metadata, e, 0))?;
            let meta = fs::symlink_metadata(&at).map_err(|e| out(OutputOperation::Metadata, e, 0))?;
            if !meta.is_dir()
                || native::Identity::metadata(&meta).map_err(|e| out(OutputOperation::Metadata, e, 0))? != identity
            {
                return Err(invalid());
            }
            // One retained parent descriptor, plus the transient replacement above.
            // Each successfully prepared prefix survives errors in later components.
            target.parent_path = bound_path;
            target.parent = parent;
            target.parent_identity = identity;
            target.parent_unbound = false;
        }
        Ok(())
    }
    pub(super) fn check_target(
        &self,
        target: &Target,
        source: &mut crate::progressive::source::SourceDriver,
    ) -> ProgressiveResult<bool> {
        self.parents(&target.path)?;
        target.check_parent()?;
        if target_stamp(&target.path, target.directory)? != target.initial {
            return Err(invalid());
        }
        let authority = self.authorize(&target.path, target.initial.map(TargetStamp::identity), source)?;
        // Protection refresh can call the provider. Never accept a target rebound
        // during that callback, including a read-only Skip or a directory admission.
        self.parents(&target.path)?;
        target.check_parent()?;
        if target_stamp(&target.path, target.directory)? != target.initial {
            return Err(invalid());
        }
        Ok(authority)
    }
    fn authorize(
        &self,
        target: &Path,
        identity: Option<native::Identity>,
        source: &mut crate::progressive::source::SourceDriver,
    ) -> ProgressiveResult<bool> {
        let mut unresolved_protected = false;
        for (path, old) in &self.root.protected {
            self.usage
                .charge(Resource::SourceBookkeeping, 1 + (path.as_os_str().len() + target.as_os_str().len()) as u64)?;
            let now = match fs::metadata(path) {
                Ok(m) => Some(native::Identity::metadata(&m).map_err(|e| out(OutputOperation::Metadata, e, 0))?),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => return Err(out(OutputOperation::Metadata, e, 0)),
            };
            unresolved_protected |= old.is_none() || now.is_none();
            if old.is_some() && old != &now {
                return Err(ProgressiveFailure::new(FailureKind::SourceChanged));
            }
            if path == target || (identity.is_some() && (identity == *old || identity == now)) {
                return Err(ProgressiveFailure::new(FailureKind::UnsafePath));
            }
        }
        Ok(source.publication_check(target, identity)? && !unresolved_protected)
    }
}

/// What the directory policy did with a directory entry.
pub(crate) enum DirectoryVerdict {
    Done {
        created: bool,
    },
    /// The session lacks authority to create it; nothing was created. The path is relative to the root.
    Deferred(PathBuf),
}

impl OutputContext {
    pub(crate) fn prepare_target(
        &self,
        member: MemberId,
        name: &str,
        windows_names: bool,
    ) -> ProgressiveResult<Target> {
        Policy { root: &self.root, usage: &self.usage }.target(member, name, windows_names)
    }
    pub(crate) fn check_target(
        &self,
        target: &Target,
        source: &mut crate::progressive::source::SourceDriver,
    ) -> ProgressiveResult<bool> {
        Policy { root: &self.root, usage: &self.usage }.check_target(target, source)
    }
    /// Creates a link at `target` once it is checked ([`crate::extract::link`]): a symbolic link, or a hard link or
    /// copy of a file this session published, with the same parent and target checks a file's publication makes.
    /// It replaces a file there only under `Overwrite::Always`. A hard link's or copy's earlier file gone or
    /// changed is an unsafe path.
    pub(crate) fn link(
        &mut self,
        target: &mut Target,
        kind: &crate::extract::link::LinkKind,
        modified: Option<std::time::SystemTime>,
        source: &mut crate::progressive::source::SourceDriver,
    ) -> ProgressiveResult<()> {
        use crate::extract::link;
        let policy = Policy { root: &self.root, usage: &self.usage };
        if !policy.check_target(target, source)? {
            return Err(ProgressiveFailure::new(FailureKind::PublicationAuthorityRequired));
        }
        target.check_parent()?;
        policy.prepare_parents(target, source)?;
        target.check_parent()?;
        policy.parents(&target.path)?;
        if target_stamp(&target.path, target.directory)? != target.initial {
            return Err(invalid());
        }
        let replace = target.initial.is_some() && matches!(self.root.overwrite, crate::extract::Overwrite::Always);
        let root = &self.root.path;
        link::make(root, kind, &self.extracted, &target.path, replace, modified).map_err(
            |e| match link::member_failure(&e) {
                Some(_) if e.kind() != std::io::ErrorKind::Unsupported => {
                    ProgressiveFailure::new(FailureKind::UnsafePath)
                }
                _ => out(OutputOperation::Publish, e, 0),
            },
        )?;
        let rel = target.path.strip_prefix(root).map_err(|_| invalid())?.to_path_buf();
        link::placed(root, &rel, kind, &target.path, &mut self.extracted);
        Ok(())
    }
    /// The file published at `target` is one a later hard link or file copy may take.
    pub(crate) fn published(&mut self, target: &Target) {
        if let Ok(rel) = target.path.strip_prefix(&self.root.path) {
            let rel = rel.to_path_buf();
            self.extracted.file(&self.root.path, &rel, &target.path);
        }
    }
    pub(crate) fn directory(
        &mut self,
        member: MemberId,
        header: &crate::rar5::FileHeader,
        source: &mut crate::progressive::source::SourceDriver,
    ) -> ProgressiveResult<DirectoryVerdict> {
        let policy = Policy { root: &self.root, usage: &self.usage };
        let name = header.output_name().unwrap_or(std::borrow::Cow::Borrowed(&header.name));
        let mut target = policy.target_kind(member, &name, !header.is_unix(), true)?;
        if !policy.check_target(&target, source)? {
            // Without whole-set authority nothing is created: the sanitized, root-contained path is handed back
            // so the caller can create the directory itself.
            let relative = target.path.strip_prefix(&self.root.path).map_err(|_| invalid())?.to_path_buf();
            return Ok(DirectoryVerdict::Deferred(relative));
        }
        // Geometric growth bounds total relocation work; reserve before mutation.
        self.usage.charge(Resource::MetadataBytes, target.path.as_os_str().len() as u64)?;
        if self.directories.len() == self.directories.capacity() {
            let old = self.directories.capacity();
            let wanted = old.saturating_mul(2).max(4);
            self.usage.charge(Resource::SourceBookkeeping, old as u64)?;
            self.usage.charge(
                Resource::MetadataBytes,
                (wanted - old).saturating_mul(std::mem::size_of::<Directory>()) as u64,
            )?;
            self.directories.try_reserve_exact(wanted - old).map_err(|_| invalid())?;
            self.usage.charge(
                Resource::MetadataBytes,
                self.directories.capacity().saturating_sub(wanted).saturating_mul(std::mem::size_of::<Directory>())
                    as u64,
            )?;
        }
        policy.prepare_parents(&mut target, source)?;
        if !policy.check_target(&target, source)? {
            return Err(ProgressiveFailure::new(FailureKind::PublicationAuthorityRequired));
        }
        let created = target.initial.is_none();
        if created {
            fs::create_dir(&target.path).map_err(|e| out(OutputOperation::Create, e, 0))?;
        }
        let file = open_directory(&target.path)?;
        let identity = native::Identity::file(&file).map_err(|e| out(OutputOperation::Metadata, e, 0))?;
        if target_stamp(&target.path, true)? != Some(TargetStamp::Directory(identity))
            || target.initial.is_some_and(|initial| initial != TargetStamp::Directory(identity))
        {
            return Err(invalid());
        }
        self.usage.charge(Resource::SourceBookkeeping, target.path.as_os_str().len() as u64 + 1)?;
        let depth = target.path.components().count();
        self.directories.push(Directory {
            path: target.path,
            identity,
            meta: crate::extract::Meta::from(header),
            depth,
            order: self.directories.len(),
        });
        Ok(DirectoryVerdict::Done { created })
    }
    pub(crate) fn skip_directories(&mut self) {
        self.directories.clear();
    }
    pub(crate) fn finish_directories(
        &mut self,
        source: &mut crate::progressive::source::SourceDriver,
    ) -> ProgressiveResult<()> {
        let mut dirs = std::mem::take(&mut self.directories);
        if self.authority.control.is_canceled() {
            return Ok(());
        }
        let count = dirs.len() as u64;
        // Comparisons operate on cached fixed-width depth/order keys. Reserve a conservative
        // O(n log n) sort/move budget before the standard in-place worst-case-bounded sort.
        self.usage.charge(
            Resource::SourceBookkeeping,
            count.saturating_mul(16).saturating_mul(u64::from(count.max(1).ilog2()) + 1),
        )?;
        dirs.sort_unstable_by_key(|d| {
            (std::cmp::Reverse(d.depth), d.identity.0, d.identity.1, std::cmp::Reverse(d.order))
        });
        let mut previous = None;
        let policy = Policy { root: &self.root, usage: &self.usage };
        for dir in dirs {
            let key = (dir.depth, dir.identity);
            if previous == Some(key) {
                continue;
            }
            previous = Some(key);
            // The last directory header wins. Earlier duplicate metadata must not
            // make this directory inaccessible before its final metadata is applied.
            if self.authority.control.is_canceled() {
                return Ok(());
            }
            policy.parents(&dir.path)?;
            if target_stamp(&dir.path, true)? != Some(TargetStamp::Directory(dir.identity)) {
                return Err(invalid());
            }
            if !policy.authorize(&dir.path, Some(dir.identity), source)? {
                return Err(ProgressiveFailure::new(FailureKind::PublicationAuthorityRequired));
            }
            // Authorization calls the provider. Recheck every binding it could
            // have changed before following ancestors to the retained leaf.
            policy.parents(&dir.path)?;
            if target_stamp(&dir.path, true)? != Some(TargetStamp::Directory(dir.identity)) {
                return Err(invalid());
            }
            let file = open_directory(&dir.path)?;
            if native::Identity::file(&file).map_err(|e| out(OutputOperation::Metadata, e, 0))? != dir.identity {
                return Err(invalid());
            }
            if self.authority.control.is_canceled() {
                return Ok(());
            }
            crate::extract::finish_file(&file, &dir.meta);
        }
        Ok(())
    }
}
impl Target {
    pub(crate) fn exists(&self) -> bool {
        self.initial.is_some()
    }
}
