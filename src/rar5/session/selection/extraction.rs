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

use std::io::Write;
use std::os::unix::fs::MetadataExt;

use crate::error::RarPolicyReason;
use crate::extract::{Meta, Options, Overwrite, RarSkipReason, VersionNaming, finish_file, make_dirs_detailed};
use crate::output::{Output, temporary};
use crate::path::sanitize;

use super::*;

impl RarSession {
    /// Extract the selected members in catalogue order. All regular-file
    /// output is staged until verification, and an existing target is
    /// checked again before replacement.
    ///
    /// Uses the destination, overwrite, flatten and protected paths in
    /// `options`. Selected extraction is synchronous. Keep the
    /// destination namespace under caller control during extraction.
    ///
    /// With `Overwrite::RenameNew` or `Overwrite::RenameExisting` nothing is
    /// replaced: once a member is verified, it is published under the first
    /// free renamed name, or the existing file is first moved to one, each
    /// with a no-replace rename. `RarRunSummary::renames` lists the renames.
    #[allow(clippy::result_large_err, reason = "reuse the typed RAR error with partial counts")]
    pub fn extract_selected(
        &mut self,
        selection: &RarSelection,
        options: &Options,
        limits: RarDecodeLimits,
        on_entry: impl FnMut(&RarEntryOutcome),
    ) -> Result<RarRunSummary, RarRunError> {
        if options.select.is_some() {
            return Err(member_filter_refused(self));
        }
        let mut extraction = Extraction::new(options);
        extraction.versions = selection.takes_versions();
        self.execute_selected(selection, limits, |run, session, index| extraction.member(run, session, index), on_entry)
    }
}

pub(super) struct Extraction<'a> {
    options: &'a Options,
    /// older file revisions are written, as `name;N` ([`RarSelection::with_versions`])
    pub(super) versions: bool,
    dirs: Vec<DirectoryOutput>,
    /// the files this run published, where each landed: the files a hard link or file copy may take
    extracted: crate::extract::link::Extracted,
}

pub(super) struct DirectoryOutput {
    path: PathBuf,
    identity: (u64, u64),
    ordinal: usize,
    meta: Meta,
}

impl<'a> Extraction<'a> {
    pub(super) fn new(options: &'a Options) -> Self {
        Self {
            options,
            versions: false,
            dirs: Vec::new(),
            extracted: crate::extract::link::Extracted::for_output(options),
        }
    }

    fn member(
        &mut self,
        run: &mut SelectedRun,
        session: &mut RarSession,
        index: usize,
    ) -> Result<RarOutcome, Arc<RarFailure>> {
        let entry = RarEntryIdentity { index: Some(index as u64), order: index as u64, name: String::new() };
        match self.member_controlled(run, session, index, &entry, &mut LegacyHooks) {
            Ok(outcome) => Ok(outcome),
            Err(SelectedStop::Native(failure)) => Err(failure),
            Err(_) => unreachable!("legacy extraction has no control stops"),
        }
    }

    pub(super) fn member_controlled(
        &mut self,
        run: &mut SelectedRun,
        session: &mut RarSession,
        index: usize,
        entry: &RarEntryIdentity,
        hooks: &mut impl ExtractionHooks,
    ) -> Result<RarOutcome, SelectedStop> {
        let result = self.member_inner(run, session, index, entry, hooks);
        hooks.release_parent();
        match result {
            Err(SelectedStop::Native(failure)) if !is_terminal(&failure) => Ok(RarOutcome::Failed(failure)),
            result => result,
        }
    }

    fn member_inner(
        &mut self,
        run: &mut SelectedRun,
        session: &mut RarSession,
        index: usize,
        entry: &RarEntryIdentity,
        hooks: &mut impl ExtractionHooks,
    ) -> Result<RarOutcome, SelectedStop> {
        check_cancel(&session.options.cancel).map_err(own_fault)?;
        run.write_unfiltered = self.options.unsupported_filters == crate::extract::UnsupportedFilters::WriteUnfiltered;
        let member = &session.model.members[index];
        let header = &member.header;
        if let Some(version) = header.version.filter(|_| !self.versions) {
            return Ok(RarOutcome::Skipped(RarSkipReason::OlderVersion(version)));
        }
        let link = match &header.redirection {
            Some(redirection) if member.issue.is_none() => crate::extract::link::from_rar5(
                redirection,
                !header.is_unix(),
                self.options.windows_safe_names,
                self.options.flatten,
            ),
            _ => None,
        };
        if link.is_none() && (member.issue.is_some() || header.redirection.is_some()) {
            return run.test(session, index, None).map_err(SelectedStop::Native);
        }
        if !projectable_name(header, &member.wire.name) {
            return Err(Arc::new(RarFailure::Unsupported(RarUnsupported::NameEncoding)).into());
        }
        let relative = hooks.project(header, self.options.version_naming)?;
        let meta = if header.is_dir() {
            self.options.dir_meta(Meta::from(header))
        } else {
            self.options.meta(Meta::from(header))
        };
        if header.is_dir() {
            let outcome = run.test(session, index, None)?;
            if !self.options.flatten && matches!(outcome, RarOutcome::Directory) {
                let path = hooks.target(self.options, &relative, false)?;
                self.protect_source_name(session, &path)?;
                hooks.before_path(index);
                hooks.reserve_directory(
                    &mut self.dirs,
                    &path,
                    path.capacity(),
                    &self.options.dest,
                    &session.model.members[index].header,
                    &session.model.members[index].wire.name,
                )?;
                hooks.before_directories();
                self.ensure_root().map_err(own_fault)?;
                make_dirs_detailed(&self.options.dest, &relative).map_err(own_fault)?;
                let observed =
                    fs::symlink_metadata(&path).map_err(|source| output_fault(IoOperation::Metadata, &path, source))?;
                if !observed.is_dir() {
                    return Err(policy(RarPolicyReason::TargetChanged, path).into());
                }
                hooks.created(&path);
                // a folder has no data: its own parts (where its header lies) are all it read
                let mut sources = [0; VOLUME_WORDS];
                mark_volumes(&mut sources, &session.model.parts[session.model.members[index].parts.clone()]);
                let identity = (observed.dev(), observed.ino());
                if let Some(failure) =
                    hooks.complete_directory(session, &sources, &self.options.dest, &path, identity)?
                {
                    return Ok(RarOutcome::Failed(failure));
                }
                hooks.directory_committed();
                self.dirs.push(DirectoryOutput {
                    path,
                    identity: (observed.dev(), observed.ino()),
                    ordinal: index,
                    meta,
                });
            }
            return Ok(outcome);
        }
        let parent = relative.parent().expect("sanitized relative path");
        let target = hooks.target(self.options, &relative, self.options.flatten)?;
        let parent = if self.options.flatten { Path::new("") } else { parent };
        // a RAR 5.0 redirection's target is checked before anything is touched
        let link = match link {
            Some(Ok(kind)) => {
                let selected = selected_relative(&relative, self.options.flatten);
                match crate::extract::link::refusal_before_place(selected, &kind, &self.extracted) {
                    None => Some(Some(kind)),
                    Some(_) => {
                        let reason = match kind {
                            crate::extract::link::LinkKind::Symbolic(_) => RarPolicyReason::LinkTarget,
                            _ => RarPolicyReason::HardLinkTarget,
                        };
                        return Err(policy(reason, target).into());
                    }
                }
            }
            Some(Err(_)) => return Err(policy(RarPolicyReason::HardLinkTarget, target).into()),
            None if header.is_rar4_symlink() => Some(None),
            None => None,
        };
        if matches!(link, Some(None)) && header.unpacked_size > crate::extract::link::MAX_TARGET {
            return Err(Arc::new(RarFailure::Unsupported(RarUnsupported::Rar4Feature("symbolic link"))).into());
        }
        let initial = self.inspect_target(session, &target)?;
        hooks.before_path(index);
        // a link this run placed at the target, which Options::replace_placed_links lets the member replace
        let owned_link = initial.is_some()
            && self.options.replace_placed_links
            && fs::symlink_metadata(&target).is_ok_and(|meta| self.extracted.owns_link(&meta));
        let sources = member_volumes(run, session, index);
        if !hooks.replace(session, &sources, entry, &target, initial, owned_link, self.options.overwrite)? {
            return Ok(RarOutcome::Skipped(RarSkipReason::ExistingTarget));
        }
        if let Some(kind) = link {
            let relative = selected_relative(&relative, self.options.flatten).to_path_buf();
            return self.link(run, session, index, &relative, parent, &target, initial, hooks, kind);
        }
        let mut output = None;
        let mut sink = |chunk: &[u8]| {
            if output.is_none() {
                output = Some(self.open_stage(parent, &target, hooks)?);
            }
            #[cfg(test)]
            event(Event::Write, &target)
                .map_err(|source| RarFault::output(IoOperation::Write, Some(target.clone()), None, source, false))?;
            output.as_mut().unwrap().write_detailed(chunk).map_err(|error| error.detailed(false))
        };
        let outcome = run.test(session, index, Some(&mut sink))?;
        // Options::keep_broken: a member that fails on its own data is published as a verified one would be (every
        // recheck and hook alike), with what was written, and reported failed; a canceled run publishes nothing
        let (verified, broken) = match outcome {
            RarOutcome::Verified { bytes, checks, .. } => (Some((bytes, checks)), None),
            // UnsupportedFilters::WriteUnfiltered: written in full, published as keep_broken publishes, and failed
            RarOutcome::Failed(failure)
                if (self.options.keep_broken || super::unfiltered_written(&failure))
                    && check_cancel(&session.options.cancel).is_ok() =>
            {
                (None, Some(failure))
            }
            outcome => return Ok(outcome),
        };
        // only a verified member is a target later links may resolve to (a kept broken one is not, as in the
        // whole-archive runner)
        let whole = verified.is_some();
        let done = move || match (verified, broken) {
            (Some((bytes, checks)), _) => RarOutcome::Verified { bytes, checks, output: RarOutput::Written },
            (None, Some(failure)) => RarOutcome::Failed(failure),
            (None, None) => unreachable!("one of the two"),
        };
        let output = match output {
            Some(output) => output,
            None => self.open_stage(parent, &target, hooks).map_err(own_fault)?,
        };
        let mut file = output.handoff_detailed().map_err(|error| own_fault(error.detailed(false)))?;
        #[cfg(test)]
        event(Event::Flush, &target).map_err(|source| output_fault(IoOperation::Flush, &target, source))?;
        file.file.flush().map_err(|source| output_fault(IoOperation::Flush, &target, source))?;
        finish_file(&file.file, &meta);
        let stage_stamp = self.stage_stamp(&file.file, &target)?;
        hooks.stage(index, stage_stamp);
        #[cfg(test)]
        event(Event::BeforePublish, &target).map_err(|source| output_fault(IoOperation::Publish, &target, source))?;

        check_cancel(&session.options.cancel).map_err(own_fault)?;
        let sources = member_volumes(run, session, index);
        check_volumes(session, &sources)?;
        hooks.recheck(session, &sources, &target, initial)?;
        if self.inspect_target(session, &target)? != initial {
            return Err(policy(RarPolicyReason::TargetChanged, target).into());
        }
        if self.stage_stamp(&file.file, &target)? != stage_stamp {
            return Err(policy(RarPolicyReason::StageChanged, target).into());
        }
        let selected = selected_relative(&relative, self.options.flatten).to_path_buf();
        if let Some(mode) = self.options.overwrite.rename() {
            let landed = self.publish_renamed(run, session, index, file, &target, initial, mode, hooks)?;
            if whole {
                self.extracted.file(&self.options.dest, &selected, &landed);
            }
            return Ok(done());
        }
        hooks.before_publication(index, initial);
        // a link this run placed there is replaced (inspect_target let it through): publication checks it is still it
        let link = fs::symlink_metadata(&target)
            .ok()
            .filter(|meta| self.options.replace_placed_links && self.extracted.owns_link(meta))
            .map(|meta| crate::extract::link::identity(&meta));
        if hooks.observe_publication() {
            file.publish_selected_observed(initial.is_some(), link, |held, published| {
                hooks.published(index, &target, held, published)
            })
        } else {
            file.publish_selected(initial.is_some(), link)
        }
        .map_err(|error| own_fault(error.detailed(false)))?;
        if whole {
            self.extracted.file(&self.options.dest, &selected, &target);
        }
        Ok(done())
    }

    /// Publishes a verified stage for a rename mode. Nothing is replaced: every name is claimed with a no-replace
    /// rename, and a candidate that is a protected name is passed over. `initial` is what the target inspection found
    /// at `target`, unchanged since: a regular file, or a folder, or for `RenameNew` a protected input (it has
    /// refused a symlink, and for `RenameExisting` a protected path or a folder holding one).
    ///
    /// `RenameExisting` moves that file or folder to the first free renamed name and records the move in `run.renames` before
    /// publishing at `target`, so a failed publication still reports where the existing file went. `RenameNew`
    /// publishes at `target` when it was free, else (or when it was taken since) at the first free renamed name.
    #[allow(clippy::too_many_arguments)]
    fn publish_renamed(
        &self,
        run: &mut SelectedRun,
        session: &RarSession,
        index: usize,
        file: crate::output::WriteFile,
        target: &Path,
        initial: Option<SourceStamp>,
        mode: crate::extract::RenameMode,
        hooks: &mut impl ExtractionHooks,
    ) -> Result<PathBuf, SelectedStop> {
        use crate::extract::{RenameError, RenameMode, RenamedOutput, claim_candidate, rename_noreplace};
        use crate::output::OutputError;
        let skip = |candidate: &Path| self.protect_source_name(session, candidate).is_err();
        // the engine itself unlinks nothing here: the incumbent, if any, is moved, never replaced
        hooks.before_publication(index, None);
        let publish_fault = |path: &Path, source| OutputError::Io {
            operation: IoOperation::Publish,
            path: Some(path.to_path_buf()),
            source,
        };
        // Running out of names and a file system that can't move without replacing fail this member only.
        let refused = |error| match error {
            RenameError::Exhausted => OutputError::RenameExhausted(target.to_path_buf()),
            RenameError::Unsupported => OutputError::RenameUnsupported(target.to_path_buf()),
            RenameError::Io(path, source) => publish_fault(&path, source),
        };
        if let (RenameMode::Existing(style), Some(_)) = (mode, initial) {
            let moved = claim_candidate(target, style, &mut run.rename_budget, skip, |to| rename_noreplace(target, to))
                .map_err(|error| own_fault(refused(error).detailed(false)))?;
            run.renames.push(RenamedOutput {
                requested: target.to_path_buf(),
                path: target.to_path_buf(),
                existing: Some(moved.0),
            });
        }
        let mut chosen = None;
        let observe = hooks.observe_publication();
        file.publish_selected_with(
            |temporary, target| {
                let temporary = match (mode, initial) {
                    (RenameMode::New(_), Some(_)) => temporary,
                    _ => match temporary.persist_noclobber(target) {
                        Ok(()) => return Ok(target.to_path_buf()),
                        Err(error)
                            if matches!(mode, RenameMode::New(_))
                                && error.error.kind() == io::ErrorKind::AlreadyExists =>
                        {
                            error.path
                        }
                        Err(error) => return Err(publish_fault(target, error.error)),
                    },
                };
                let mut temporary = Some(temporary);
                let found = claim_candidate(target, mode.style(), &mut run.rename_budget, skip, |candidate| {
                    match temporary.take().expect("unpublished stage").persist_noclobber(candidate) {
                        Ok(()) => Ok(()),
                        Err(error) => {
                            temporary = Some(error.path);
                            Err(error.error)
                        }
                    }
                });
                match found {
                    Ok((path, ())) => {
                        chosen = Some(path.clone());
                        Ok(path)
                    }
                    Err(error) => Err(refused(error)),
                }
            },
            |held, published| {
                // A renamed new file has no binding of its own to verify; the stage it came from was checked.
                if observe && published.is_none_or(|path| path == target) {
                    hooks.published(index, target, held, published.is_some());
                }
            },
        )
        .map_err(|error| own_fault(error.detailed(false)))?;
        if let Some(path) = chosen {
            run.renames.push(RenamedOutput { requested: target.to_path_buf(), path: path.clone(), existing: None });
            return Ok(path);
        }
        Ok(target.to_path_buf())
    }

    /// A link member: a RAR 5.0 redirection already checked (`kind`), or a RAR 4.x symbolic link (`None`), whose
    /// target is decoded and checked like a file's data. The link is created at `target` when a symbolic link's
    /// target stays inside the destination, or a hard link or file copy takes a file this run published
    /// ([`crate::extract::link`]). It replaces what is there only as a file would, and is never written through a
    /// link.
    #[allow(clippy::too_many_arguments)]
    fn link(
        &mut self,
        run: &mut SelectedRun,
        session: &mut RarSession,
        index: usize,
        relative: &Path,
        parent: &Path,
        target: &Path,
        initial: Option<SourceStamp>,
        hooks: &mut impl ExtractionHooks,
        kind: Option<crate::extract::link::LinkKind>,
    ) -> Result<RarOutcome, SelectedStop> {
        use crate::extract::link;
        let (kind, bytes, checks) = match kind {
            Some(kind) => {
                let checks = RarVerification {
                    size_checked: false,
                    crc32_checked: false,
                    blake2sp_checked: false,
                    password: crate::error::RarPasswordEvidence::NotEncrypted,
                };
                (kind, 0, checks)
            }
            None => {
                let (text, bytes, checks) = match rar4_link_text(run, session, index)? {
                    Ok(decoded) => decoded,
                    Err(outcome) => return Ok(outcome),
                };
                // written mapped as the member names it may point at; an empty target is refused below
                let text = link::rar4_target(&text).unwrap_or_default();
                // with placeholders the target is checked as the link is placed, after its path
                if !self.extracted.placeholder() && !link::contained(relative, &text) {
                    return Err(policy(RarPolicyReason::LinkTarget, target.to_path_buf()).into());
                }
                (link::LinkKind::Symbolic(text), bytes, checks)
            }
        };
        hooks.before_directories();
        self.ensure_root().map_err(own_fault)?;
        let directories = make_dirs_detailed(&self.options.dest, parent);
        hooks.created(if directories.is_ok() { target.parent().expect("target parent") } else { &self.options.dest });
        directories.map_err(own_fault)?;
        check_cancel(&session.options.cancel).map_err(own_fault)?;
        let mut sources = [0; VOLUME_WORDS];
        mark_volumes(&mut sources, &session.model.parts[session.model.members[index].parts.clone()]);
        check_volumes(session, &sources)?;
        hooks.recheck(session, &sources, target, initial)?;
        if self.inspect_target(session, target)? != initial {
            return Err(policy(RarPolicyReason::TargetChanged, target.to_path_buf()).into());
        }
        let dest = &self.options.dest;
        let modified = self.options.meta(Meta::from(&session.model.members[index].header)).modified();
        // a refused symbolic link leaves its placeholder where the link would have gone, with placeholders on
        let stood_in = std::cell::Cell::new(None);
        let create = |path: &Path, replace: bool| {
            let made = link::make_or_stand_in(
                dest,
                relative,
                &kind,
                &self.extracted,
                path,
                replace,
                modified,
                &mut |_| Ok(()),
            );
            made.map(|refused_with| stood_in.set(stood_in.get().or(refused_with)))
        };
        // a hard link's or copy's earlier file gone or changed fails this member only
        let failed = |path: &Path, source: io::Error| -> Arc<RarFailure> {
            match link::member_failure(&source) {
                Some(_) if source.kind() == io::ErrorKind::Unsupported => {
                    Arc::new(RarFailure::Unsupported(RarUnsupported::Rar4Feature("symbolic link")))
                }
                Some(link::FOREIGN_LINK | link::LINK_LEAVES | link::UNSAFE_TARGET) => {
                    policy(RarPolicyReason::LinkTarget, path.to_path_buf())
                }
                Some(_) => policy(RarPolicyReason::HardLinkTarget, path.to_path_buf()),
                None => output_fault(IoOperation::Publish, path, source),
            }
        };
        // what is placed, so the diagnostic guard takes it as this run's own change
        let placed = match &kind {
            link::LinkKind::Symbolic(text) => PlacedLink::Symbolic { target: text },
            link::LinkKind::Hard(source) => PlacedLink::Hard { source: self.extracted.landed_identity(source) },
            link::LinkKind::Copy(_) => PlacedLink::Copy,
        };
        let rename = self.options.overwrite.rename().filter(|_| initial.is_some());
        hooks.before_publication(index, if rename.is_some() { None } else { initial });
        let placement = (|| -> Result<PathBuf, Arc<RarFailure>> {
            use crate::extract::{RenameError, RenameMode, RenamedOutput, claim_candidate, rename_noreplace};
            let Some(mode) = rename else {
                create(target, initial.is_some()).map_err(|source| failed(target, source))?;
                return Ok(target.to_path_buf());
            };
            let skip = |candidate: &Path| self.protect_source_name(session, candidate).is_err();
            let refused = |error| match error {
                RenameError::Exhausted => {
                    own_fault(policy_fault(RarPolicyReason::RenameExhausted, target.to_path_buf()))
                }
                RenameError::Unsupported => {
                    own_fault(policy_fault(RarPolicyReason::RenameUnsupported, target.to_path_buf()))
                }
                RenameError::Io(path, source) => failed(&path, source),
            };
            match mode {
                // the existing file or folder moves aside; the link takes its name
                RenameMode::Existing(style) => {
                    let moved =
                        claim_candidate(target, style, &mut run.rename_budget, skip, |to| rename_noreplace(target, to))
                            .map_err(refused)?;
                    run.renames.push(RenamedOutput {
                        requested: target.to_path_buf(),
                        path: target.to_path_buf(),
                        existing: Some(moved.0),
                    });
                    create(target, false).map_err(|source| failed(target, source))?;
                    Ok(target.to_path_buf())
                }
                // the link goes to the first free renamed name
                RenameMode::New(style) => {
                    let (path, ()) = claim_candidate(target, style, &mut run.rename_budget, skip, |candidate| {
                        create(candidate, false)
                    })
                    .map_err(refused)?;
                    run.renames.push(RenamedOutput {
                        requested: target.to_path_buf(),
                        path: path.clone(),
                        existing: None,
                    });
                    Ok(path)
                }
            }
        })();
        let stood_in = stood_in.get();
        // what was placed is a placeholder file when the link was refused
        let placed = if stood_in.is_some() { PlacedLink::Placeholder } else { placed };
        // also after a failure: staging a hard link may have touched the earlier file
        hooks.linked(index, target, placement.as_deref().ok(), placed);
        let landed = placement?;
        if stood_in.is_some() {
            // the placeholder is a file this run wrote; the member is refused as without it
            link::stood_in(&self.options.dest, relative, &landed, &mut self.extracted);
            return Err(policy(RarPolicyReason::LinkTarget, target.to_path_buf()).into());
        }
        link::placed(&self.options.dest, relative, &kind, &landed, &mut self.extracted);
        Ok(RarOutcome::Verified { bytes, checks, output: RarOutput::Written })
    }

    fn ensure_root(&self) -> RarResult<()> {
        let root = &self.options.dest;
        match fs::symlink_metadata(root) {
            Ok(meta) if meta.file_type().is_symlink() => Err(policy_fault(RarPolicyReason::Symlink, root.clone())),
            Ok(meta) if meta.is_dir() => Ok(()),
            Ok(_) => Err(policy_fault(RarPolicyReason::ParentIsFile, root.clone())),
            Err(error) if error.kind() == io::ErrorKind::NotFound => fs::create_dir_all(root).map_err(|source| {
                RarFault::output(IoOperation::CreateDirectory, Some(root.clone()), None, source, false)
            }),
            Err(source) => Err(RarFault::output(IoOperation::Metadata, Some(root.clone()), None, source, false)),
        }
    }

    fn inspect_target(&self, session: &RarSession, target: &Path) -> Result<Option<SourceStamp>, Arc<RarFailure>> {
        let Some(parent) = target.parent() else {
            return Err(policy(RarPolicyReason::UnsafePath, target.to_path_buf()));
        };
        self.inspect_parents(parent)?;
        // `RenameNew` leaves what is at the requested name alone, so a protected input or a folder there is only a
        // name in use: the member goes to a renamed name (7-Zip's `-aou`). A missing protected name is still refused.
        let rename = self.options.overwrite.rename();
        let keeps = matches!(rename, Some(crate::extract::RenameMode::New(_)));
        let named = self.protect_source_name(session, target);
        if !keeps {
            named.clone()?;
        }
        let metadata = match fs::symlink_metadata(target) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return named.map(|()| None),
            Err(source) => return Err(output_fault(IoOperation::Metadata, target, source)),
        };
        if metadata.file_type().is_symlink() {
            // A symbolic link this run placed is replaced by rename (never followed) when asked, as UnRAR 7.30 `e -y`
            // does; otherwise, and for any other link, the member is refused, as 7-Zip 26.06 does.
            if self.options.replace_placed_links && self.extracted.owns_link(&metadata) {
                return named.map(|()| Some(SourceStamp::from_entry_metadata(&metadata)));
            }
            return Err(policy(RarPolicyReason::Symlink, target.to_path_buf()));
        }
        let identity = (metadata.dev(), metadata.ino());
        if !keeps
            && (session.volumes.iter().any(|volume| (volume.stamp.device, volume.stamp.inode) == identity)
                || self
                    .options
                    .protected_paths
                    .iter()
                    .any(|path| fs::metadata(path).is_ok_and(|other| (other.dev(), other.ino()) == identity)))
        {
            return Err(policy(RarPolicyReason::ProtectedInput, target.to_path_buf()));
        }
        if metadata.is_dir() {
            match rename {
                None => return Err(policy(RarPolicyReason::Directory, target.to_path_buf())),
                Some(crate::extract::RenameMode::New(_)) => {}
                // `RenameExisting` moves the folder aside with its contents (7-Zip's `-aot`), unless that would move
                // an archive volume or another protected path with it.
                Some(crate::extract::RenameMode::Existing(_)) => {
                    let dir = fs::canonicalize(target)
                        .map_err(|source| output_fault(IoOperation::Metadata, target, source))?;
                    let inside = |path: &Path| fs::canonicalize(path).is_ok_and(|path| path.starts_with(&dir));
                    if session.volumes.iter().any(|volume| inside(&volume.path))
                        || self.options.protected_paths.iter().any(|path| path.starts_with(&dir) || inside(path))
                    {
                        return Err(policy(RarPolicyReason::ProtectedInput, target.to_path_buf()));
                    }
                }
            }
            return Ok(Some(SourceStamp::from_entry_metadata(&metadata)));
        }
        let stamp = SourceStamp::from_metadata(metadata)
            .map_err(|source| output_fault(IoOperation::Metadata, target, source))?;
        Ok(Some(stamp))
    }

    fn protect_source_name(&self, session: &RarSession, target: &Path) -> Result<(), Arc<RarFailure>> {
        let absolute =
            std::path::absolute(target).map_err(|source| output_fault(IoOperation::Metadata, target, source))?;
        let target_parent = std::cell::OnceCell::new();
        for source in session.volumes.iter().map(|volume| &volume.path).chain(self.options.protected_paths.iter()) {
            if absolute == *source
                || (target.file_name() == source.file_name()
                    && target_parent
                        .get_or_init(|| absolute.parent().and_then(|parent| fs::canonicalize(parent).ok()))
                        .as_ref()
                        .is_some_and(|parent| {
                            source.parent().and_then(|path| fs::canonicalize(path).ok()).as_ref() == Some(parent)
                        }))
            {
                return Err(policy(RarPolicyReason::ProtectedInput, target.to_path_buf()));
            }
        }
        Ok(())
    }

    fn stage_stamp(&self, file: &File, target: &Path) -> Result<SourceStamp, Arc<RarFailure>> {
        file.metadata()
            .and_then(SourceStamp::from_metadata)
            .map_err(|source| output_fault(IoOperation::Metadata, target, source))
    }

    fn inspect_parents(&self, parent: &Path) -> Result<(), Arc<RarFailure>> {
        let root = &self.options.dest;
        let relative = parent.strip_prefix(root).expect("target is under selected destination");
        let mut path = root.clone();
        for part in std::iter::once(None).chain(relative.components().map(Some)) {
            if let Some(part) = part {
                path.push(part);
            }
            match fs::symlink_metadata(&path) {
                Ok(meta) if meta.file_type().is_symlink() => return Err(policy(RarPolicyReason::Symlink, path)),
                Ok(meta) if meta.is_dir() => {}
                Ok(_) => return Err(policy(RarPolicyReason::ParentIsFile, path)),
                Err(error) if error.kind() == io::ErrorKind::NotFound => break,
                Err(source) => return Err(output_fault(IoOperation::Metadata, &path, source)),
            }
        }
        Ok(())
    }

    fn open_stage(&self, parent: &Path, target: &Path, hooks: &mut impl ExtractionHooks) -> RarResult<Output> {
        hooks.before_directories();
        self.ensure_root()?;
        let directories = make_dirs_detailed(&self.options.dest, parent);
        // Capture completed native directory preparation before tempfile creation
        // or payload verification can fail. before_path already checked the old
        // bindings; this advances only that known engine change. On a partial
        // preparation error only the completed root is known, so do not adopt
        // an uncertain descendant merely because it now exists.
        hooks.created(if directories.is_ok() { target.parent().expect("target parent") } else { &self.options.dest });
        directories?;
        let stage = temporary(target.parent().expect("target has a parent")).map_err(|source| {
            RarFault::output(IoOperation::CreateFile, Some(target.to_path_buf()), None, source, false)
        })?;
        let (file, path) = stage.into_parts();
        Output::staged_direct(file, path, target.to_path_buf())
            .map_err(|source| RarFault::output(IoOperation::Metadata, Some(target.to_path_buf()), None, source, false))
    }
}

impl Extraction<'_> {
    pub(super) fn finalize(&mut self) {
        use std::os::unix::fs::OpenOptionsExt;

        use std::cmp::Reverse;

        // Apply metadata once per directory, using the last selected record
        // even when an earlier record would make the directory unreadable.
        self.dirs.sort_unstable_by_key(|entry| (entry.identity, Reverse(entry.ordinal)));
        self.dirs.dedup_by_key(|entry| entry.identity);
        self.dirs.sort_unstable_by_key(|entry| Reverse(entry.path.components().count()));
        for entry in &self.dirs {
            let Some(parent) = entry.path.parent() else { continue };
            if self.inspect_parents(parent).is_err() {
                continue;
            }
            match OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(&entry.path)
            {
                Ok(dir) if dir.metadata().is_ok_and(|meta| (meta.dev(), meta.ino()) == entry.identity) => {
                    finish_file(&dir, &entry.meta);
                }
                Err(error) if error.kind() == io::ErrorKind::PermissionDenied => restore_unreadable_mode(entry),
                _ => {}
            }
        }
        self.dirs = Vec::new();
    }
}

impl Drop for Extraction<'_> {
    fn drop(&mut self) {
        self.finalize();
    }
}

/// Whether a member's decoded name may become an output path, the same rule as whole-archive extraction: U+FFFE
/// marks a RAR5 Unix name holding bytes that aren't UTF-8 (mapped into private-use characters), and a RAR5 wire
/// name must itself be UTF-8. A RAR4 wire name is the legacy name, then for a Unicode name a NUL and the encoded
/// UTF-16 stream, which need not be UTF-8; its decoded name is what the catalogue decoded and lists. Either way the
/// name still goes through `sanitize` before it reaches the file system.
pub(super) fn projectable_name(header: &FileHeader, wire_name: &[u8]) -> bool {
    header.output_name().is_some() && (header.format != RarFormat::Rar5 || std::str::from_utf8(wire_name).is_ok())
}

// The controlled native path and optional inventory share this exact target
// projection, including flattening. Budgets admit its allocation beforehand.
pub(super) fn selected_relative(relative: &Path, flatten: bool) -> &Path {
    if flatten { Path::new(relative.file_name().expect("sanitized relative file")) } else { relative }
}
pub(super) fn target_capacity(options: &Options, relative: &Path, flatten: bool) -> Option<usize> {
    options
        .dest
        .as_os_str()
        .len()
        .checked_add(selected_relative(relative, flatten).as_os_str().len())
        .and_then(|n| n.checked_add(1))
}
pub(super) fn project_target(
    options: &Options,
    relative: &Path,
    flatten: bool,
    capacity: usize,
) -> Result<PathBuf, std::collections::TryReserveError> {
    let mut target = PathBuf::new();
    target.try_reserve_exact(capacity)?;
    target.push(&options.dest);
    target.push(selected_relative(relative, flatten));
    Ok(target)
}

/// A RAR 4.x symbolic link's target, decoded and checked like a file's data, and kept for the member's outcome; or
/// the member's outcome when it did not verify.
#[allow(clippy::type_complexity)]
pub(super) fn rar4_link_text(
    run: &mut SelectedRun,
    session: &mut RarSession,
    index: usize,
) -> Result<Result<(Vec<u8>, u64, RarVerification), RarOutcome>, SelectedStop> {
    use crate::extract::link;
    let mut text = Vec::new();
    let mut sink = |chunk: &[u8]| -> RarResult<()> {
        let room = (link::MAX_TARGET as usize + 1).saturating_sub(text.len()).min(chunk.len());
        text.extend_from_slice(&chunk[..room]);
        Ok(())
    };
    let outcome = run.test(session, index, Some(&mut sink))?;
    let RarOutcome::Verified { bytes, checks, .. } = outcome else {
        return Ok(Err(outcome));
    };
    run.link = Some(Redirection::UnixSymlink(String::from_utf8_lossy(&text).into_owned()));
    Ok(Ok((text, bytes, checks)))
}

pub(super) trait ExtractionHooks {
    fn before_directories(&mut self) {}
    fn before_publication(&mut self, _index: usize, _initial: Option<SourceStamp>) {}
    fn before_path(&mut self, _index: usize) {}
    fn observe_publication(&self) -> bool {
        false
    }
    /// The member's path relative to the destination; an older revision (taken only when the selection includes
    /// them) is named by `naming`.
    fn project(&mut self, header: &FileHeader, naming: VersionNaming) -> Result<PathBuf, SelectedStop>;
    fn target(&mut self, options: &Options, relative: &Path, flatten: bool) -> Result<PathBuf, SelectedStop>;
    fn reserve_directory(
        &mut self,
        dirs: &mut Vec<DirectoryOutput>,
        path: &Path,
        path_capacity: usize,
        root: &Path,
        header: &FileHeader,
        wire_name: &[u8],
    ) -> Result<(), SelectedStop>;
    /// A qualified native directory-creation failure is recoverable for this
    /// member only. All other stops keep the executor's ordinary classification.
    fn complete_directory(
        &mut self,
        _session: &mut RarSession,
        _sources: &VolumeSet,
        _root: &Path,
        _path: &Path,
        _identity: (u64, u64),
    ) -> Result<Option<Arc<RarFailure>>, SelectedStop> {
        Ok(None)
    }
    /// `owned_link`: what is at the target is a symbolic link this run placed, which the member may replace
    /// ([`Options::replace_placed_links`]). `sources`: the volumes the member's bytes depend on
    /// ([`member_volumes`]), which must not change across a callback.
    #[allow(clippy::too_many_arguments)]
    fn replace(
        &mut self,
        session: &mut RarSession,
        sources: &VolumeSet,
        entry: &RarEntryIdentity,
        target: &Path,
        initial: Option<SourceStamp>,
        owned_link: bool,
        legacy: Overwrite,
    ) -> Result<bool, SelectedStop>;
    /// `sources`: the volumes the member's published bytes depend on, just checked by the native route.
    fn recheck(
        &mut self,
        _session: &mut RarSession,
        _sources: &VolumeSet,
        _target: &Path,
        _initial: Option<SourceStamp>,
    ) -> Result<(), SelectedStop> {
        Ok(())
    }
    fn release_parent(&mut self) {}
    fn created(&mut self, _path: &Path) {}
    fn directory_committed(&mut self) {}
    fn stage(&mut self, _index: usize, _stamp: SourceStamp) {}
    fn published(&mut self, _index: usize, _target: &Path, _held: &File, _published: bool) {}
    /// A link member was placed at `landed` for `target` (None: nothing was placed).
    fn linked(&mut self, _index: usize, _target: &Path, _landed: Option<&Path>, _placed: PlacedLink<'_>) {}
}

/// What a link member placed, as the diagnostic guard checks it.
#[derive(Clone, Copy, Debug)]
pub(super) enum PlacedLink<'a> {
    /// A symbolic link to these target bytes.
    Symbolic { target: &'a [u8] },
    /// A hard link to the file this run extracted with this device and inode (a copy where linking fails).
    Hard { source: Option<(u64, u64)> },
    /// A copy of a file this run extracted.
    Copy,
    /// The empty regular file a refused symbolic link leaves with
    /// [`crate::extract::Options::refused_link_placeholder`].
    Placeholder,
}
struct LegacyHooks;
impl ExtractionHooks for LegacyHooks {
    fn project(&mut self, header: &FileHeader, naming: VersionNaming) -> Result<PathBuf, SelectedStop> {
        // an older revision gets this far only when the selection includes revisions: it is named by `naming`
        let name = header.output_name_as(Some(naming)).unwrap_or(std::borrow::Cow::Borrowed(&header.name));
        sanitize(&name, !header.is_unix())
            .map_err(|_| policy(RarPolicyReason::UnsafePath, PathBuf::from(&header.name)).into())
    }
    fn target(&mut self, options: &Options, relative: &Path, flatten: bool) -> Result<PathBuf, SelectedStop> {
        Ok(options.dest.join(if flatten { Path::new(relative.file_name().expect("sanitized file")) } else { relative }))
    }
    fn reserve_directory(
        &mut self,
        dirs: &mut Vec<DirectoryOutput>,
        _: &Path,
        _: usize,
        _: &Path,
        _: &FileHeader,
        _: &[u8],
    ) -> Result<(), SelectedStop> {
        dirs.try_reserve(1).map_err(|_| SelectedStop::Native(own_fault(allocation())))
    }
    fn replace(
        &mut self,
        _: &mut RarSession,
        _: &VolumeSet,
        _: &RarEntryIdentity,
        _: &Path,
        initial: Option<SourceStamp>,
        _: bool,
        legacy: Overwrite,
    ) -> Result<bool, SelectedStop> {
        Ok(initial.is_none() || legacy != Overwrite::Skip)
    }
}

fn restore_unreadable_mode(entry: &DirectoryOutput) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let Some(mode) = entry.meta.mode else { return };
    let Ok(path) = CString::new(entry.path.as_os_str().as_bytes()) else { return };
    if fs::symlink_metadata(&entry.path).is_ok_and(|meta| meta.is_dir() && (meta.dev(), meta.ino()) == entry.identity) {
        // The controlled namespace keeps the checked directory bound
        // between these calls. Refuse symlinks in the chmod call as well.
        unsafe { libc::fchmodat(libc::AT_FDCWD, path.as_ptr(), (mode & 0o777) as _, libc::AT_SYMLINK_NOFOLLOW) };
    }
}

fn policy(reason: RarPolicyReason, path: PathBuf) -> Arc<RarFailure> {
    own_fault(policy_fault(reason, path))
}

fn policy_fault(reason: RarPolicyReason, path: PathBuf) -> RarFault {
    RarFault::new(RarFailure::Policy { reason, path }, Error::Corrupt("selected RAR target refused"))
}

fn own_fault(fault: RarFault) -> Arc<RarFailure> {
    Arc::from(fault.failure)
}

fn output_fault(operation: IoOperation, path: &Path, source: io::Error) -> Arc<RarFailure> {
    own_fault(RarFault::output(operation, Some(path.to_path_buf()), None, source, false))
}

#[cfg(test)]
#[derive(Clone, Copy, Eq, PartialEq)]
enum Event {
    Write,
    Flush,
    BeforePublish,
}

#[cfg(test)]
type Hook = Box<dyn FnMut(Event, &Path) -> io::Result<()>>;

#[cfg(test)]
thread_local! {
    static HOOK: std::cell::RefCell<Option<Hook>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn event(event: Event, path: &Path) -> io::Result<()> {
    HOOK.with_borrow_mut(|hook| hook.as_mut().map_or(Ok(()), |hook| hook(event, path)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::Mode;
    use crate::rar5::{HEAD_END, HEAD_FILE, HEAD_MAIN, SIGNATURE};

    fn block(bytes: &mut Vec<u8>, body: &[u8], payload: &[u8]) {
        let mut framed = vec![body.len() as u8];
        framed.extend(body);
        bytes.extend(crate::crc32::hash(&framed).to_le_bytes());
        bytes.extend(framed);
        bytes.extend(payload);
    }

    fn archive(more: bool, files: &[(u8, u8)]) -> Vec<u8> {
        let mut bytes = SIGNATURE.to_vec();
        block(&mut bytes, &[HEAD_MAIN as u8, 0, u8::from(more)], &[]);
        for &(name, data) in files {
            let mut body = vec![HEAD_FILE as u8, 2, 1, 4, 1, 0x80, 0x03];
            body.extend(crate::crc32::hash(&[data]).to_le_bytes());
            body.extend([0, 1, 1, name]);
            block(&mut bytes, &body, &[data]);
        }
        block(&mut bytes, &[HEAD_END as u8, 0, u8::from(more)], &[]);
        bytes
    }

    fn options(path: &Path) -> Options {
        Options {
            mode: Mode::Extract,
            dest: path.to_path_buf(),
            overwrite: Overwrite::Always,
            flatten: false,
            threads: None,
            protected_paths: Default::default(),
            parallel_min: None,
            select: None,
            windows_safe_names: false,
            special_entries: Default::default(),
            fallback_mtime: None,
            compressed_tar: Default::default(),
            version_naming: Default::default(),
            preexisting_links: Default::default(),
            refused_link_placeholder: false,
            restart_from_first_volume: false,
            replace_placed_links: false,
            keep_broken: false,
            attempt_continued_members: false,
            unsupported_filters: Default::default(),
            salvage_truncated_zip: false,
            unix_modes: Default::default(),
            backslashes: Default::default(),
        }
    }

    fn with_hook<T>(hook: impl FnMut(Event, &Path) -> io::Result<()> + 'static, run: impl FnOnce() -> T) -> T {
        struct Clear;
        impl Drop for Clear {
            fn drop(&mut self) {
                HOOK.with_borrow_mut(|hook| *hook = None);
            }
        }
        let _clear = Clear;
        HOOK.with_borrow_mut(|stored| *stored = Some(Box::new(hook)));
        run()
    }

    #[test]
    fn replaced_stage_name_is_neither_published_nor_removed() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("archive.rar");
        fs::write(&source, archive(false, &[(b'x', b'n')])).unwrap();
        let dest = dir.path().join("out");
        fs::create_dir(&dest).unwrap();
        let target = dest.join("x");
        fs::write(&target, b"old").unwrap();
        let mut session = RarSession::open(&source, None, RarSessionOptions::default()).unwrap();
        let selection = session.select(|_| true).unwrap();
        let moved = dest.join("displaced");
        let displaced = moved.clone();
        let result = with_hook(
            move |event, target| {
                if event == Event::BeforePublish {
                    let stage = fs::read_dir(target.parent().unwrap())?
                        .map(|entry| entry.unwrap().path())
                        .find(|path| path != target)
                        .expect("the same-directory stage");
                    fs::rename(&stage, &displaced)?;
                    fs::write(stage, b"foreign")?;
                }
                Ok(())
            },
            || session.extract_selected(&selection, &options(&dest), RarDecodeLimits::default(), |_| {}).unwrap(),
        );
        assert_eq!((result.files, result.failed), (0, 1));
        assert_eq!(fs::read(&target).unwrap(), b"old");
        assert_eq!(fs::read(&moved).unwrap(), b"n");
        assert!(fs::read_dir(&dest).unwrap().any(|entry| fs::read(entry.unwrap().path()).unwrap() == b"foreign"));
    }

    #[test]
    fn a_later_volume_alias_installed_before_publish_is_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("set.part1.rar");
        let second = dir.path().join("set.part2.rar");
        let original = archive(false, &[]);
        fs::write(&first, archive(true, &[(b'x', b'n')])).unwrap();
        fs::write(&second, &original).unwrap();
        let target = dir.path().join("x");
        fs::write(&target, b"old").unwrap();
        let mut session = RarSession::open(&first, None, RarSessionOptions::default()).unwrap();
        let selection = session.select(|_| true).unwrap();
        let alias = second.clone();
        let result = with_hook(
            move |event, target| {
                if event == Event::BeforePublish {
                    fs::remove_file(target)?;
                    fs::hard_link(&alias, target)?;
                }
                Ok(())
            },
            || {
                session
                    .extract_selected(&selection, &options(dir.path()), RarDecodeLimits::default(), |event| {
                        assert!(matches!(&event.outcome, RarOutcome::Failed(failure) if matches!(failure.as_ref(),
                            RarFailure::Policy { reason: RarPolicyReason::ProtectedInput, .. }
                        )));
                    })
                    .unwrap()
            },
        );
        assert_eq!((result.files, result.failed), (0, 1));
        assert_eq!(fs::read(&target).unwrap(), original);
        assert_eq!(fs::read(&second).unwrap(), original);
        assert_eq!(fs::metadata(target).unwrap().ino(), fs::metadata(second).unwrap().ino());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 3);
    }

    #[test]
    fn write_flush_and_publish_errors_keep_prior_output_and_original_target() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("archive.rar");
        fs::write(&source, archive(false, &[(b'a', b'A'), (b'b', b'B')])).unwrap();
        let dest = dir.path().join("out");
        fs::create_dir(&dest).unwrap();
        let second = dest.join("b");
        fs::write(&second, b"original").unwrap();
        for (fault, operation) in [
            (Event::Write, IoOperation::Write),
            (Event::Flush, IoOperation::Flush),
            (Event::BeforePublish, IoOperation::Publish),
        ] {
            let mut session = RarSession::open(&source, None, RarSessionOptions::default()).unwrap();
            let selection = session.select(|_| true).unwrap();
            let mut seen = Vec::new();
            let mut terminal = None;
            let failure = with_hook(
                move |event, target| {
                    if event == fault && target.ends_with("b") {
                        return Err(io::Error::from_raw_os_error(libc::EIO));
                    }
                    Ok(())
                },
                || {
                    session
                        .extract_selected(&selection, &options(&dest), RarDecodeLimits::default(), |event| {
                            seen.push(event.entry.order);
                            if let RarOutcome::Failed(failure) = &event.outcome {
                                terminal = Some(Arc::clone(failure));
                            }
                        })
                        .unwrap_err()
                },
            );
            assert!(matches!(failure.failure.as_ref(),
                RarFailure::Output { operation: actual, path: Some(path), source, .. }
                    if *actual == operation && path == &second && source.raw_os_error() == Some(libc::EIO)
            ));
            assert!(Arc::ptr_eq(&failure.failure, &terminal.unwrap()));
            assert_eq!((failure.partial.files, failure.partial.failed), (1, 1));
            assert_eq!(seen, [0, 1]);
            assert_eq!(fs::read(dest.join("a")).unwrap(), b"A");
            assert_eq!(fs::read(&second).unwrap(), b"original");
            assert_eq!(fs::read_dir(&dest).unwrap().count(), 2);
        }
    }
    #[test]
    fn rar4_late_output_alias_is_refused_before_publication() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("source.rar");
        let original = crate::rar5::unpack::rar4::fixed_fixture();
        fs::write(&first, &original).unwrap();
        let dest = dir.path().join("out");
        fs::create_dir(&dest).unwrap();
        let target = dest.join("x");
        fs::write(&target, b"keep").unwrap();
        let mut session = RarSession::open(&first, None, RarSessionOptions::default()).unwrap();
        let all = session.select(|_| true).unwrap();
        let alias = first.clone();
        let result = with_hook(
            move |event, target| {
                if event == Event::BeforePublish {
                    fs::remove_file(target)?;
                    fs::hard_link(&alias, target)?;
                }
                Ok(())
            },
            || {
                session.extract_selected(&all,&options(&dest),RarDecodeLimits::default(),|event| {
            assert!(matches!(&event.outcome,RarOutcome::Failed(failure) if matches!(failure.as_ref(),RarFailure::SourceChanged{..})));
        }).unwrap_err()
            },
        );
        assert_eq!((result.partial.files, result.partial.failed), (0, 1));
        assert!(matches!(result.failure.as_ref(), RarFailure::SourceChanged { .. }));
        assert_eq!(fs::read(&first).unwrap(), original);
        assert_eq!(fs::read(&target).unwrap(), original);
        assert_eq!(fs::metadata(&first).unwrap().ino(), fs::metadata(&target).unwrap().ino());
        assert_eq!(fs::read_dir(&dest).unwrap().count(), 1);
    }

    #[test]
    fn controlled_write_failure_keeps_completed_parent_preparation_admitted() {
        use crate::rar5::session::{
            RarDecisionError, RarDiagnostic, RarExtractControl, RarExtractControlLimits, RarExtractError,
            RarExtractObserver, RarOverwriteConflict, RarOverwriteDecision, RarOverwriteMode,
        };
        struct Observer {
            events: usize,
        }
        impl RarExtractObserver for Observer {
            fn overwrite(
                &mut self,
                _: &RarOverwriteConflict<'_>,
                _: RarDiagnostic<'_>,
            ) -> Result<RarOverwriteDecision, RarDecisionError> {
                panic!("new target");
            }
            fn entry(&mut self, event: &RarEntryOutcome, mut diagnostic: RarDiagnostic<'_>) {
                assert!(
                    matches!(&event.outcome, RarOutcome::Failed(failure) if matches!(failure.as_ref(), RarFailure::Output { operation: IoOperation::Write, .. }))
                );
                diagnostic
                    .writer()
                    .expect("native failure may still describe created directories")
                    .write_all(b"failed\n")
                    .unwrap();
                self.events += 1;
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.rar");
        fs::write(&source, archive(false, &[(b'x', b'n')])).unwrap();
        let dest = dir.path().join("new/destination");
        let log = dir.path().join("log");
        let file = OpenOptions::new().create_new(true).append(true).open(&log).unwrap();
        let mut session = RarSession::open(&source, None, RarSessionOptions::default()).unwrap();
        let selected = session.select(|_| true).unwrap();
        let mut control =
            RarExtractControl::new(Some(file), RarOverwriteMode::Always, RarExtractControlLimits::default());
        let mut observer = Observer { events: 0 };
        let mut report = with_hook(
            |event, _| {
                if event == Event::Write { Err(io::Error::from_raw_os_error(libc::EIO)) } else { Ok(()) }
            },
            || {
                session.extract_selected_controlled(
                    &selected,
                    &options(&dest),
                    RarDecodeLimits::default(),
                    &mut control,
                    &mut observer,
                )
            },
        );
        assert!(
            matches!(report.outcome(), Err(RarExtractError::Native(error)) if error.partial.files == 0 && error.partial.failed == 1 && matches!(error.failure.as_ref(), RarFailure::Output { operation: IoOperation::Write, source, .. } if source.raw_os_error() == Some(libc::EIO)))
        );
        assert_eq!(fs::read_dir(&dest).unwrap().count(), 0);
        report
            .diagnostic()
            .writer()
            .expect("terminal diagnostic after native failure")
            .write_all(b"terminal\n")
            .unwrap();
        assert!(report.finish().diagnostic_failure.is_none());
        assert_eq!(observer.events, 1);
        assert_eq!(fs::read(log).unwrap(), b"failed\nterminal\n");
    }
}
