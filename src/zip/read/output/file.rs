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

//! Controlled named-file preparation; lexical reservations precede acquisition.
use super::*;
use crate::zip::read::shared::{LedgerAccess, LedgerView};
use std::ffi::CStr;
use std::os::fd::AsRawFd;

pub(super) struct PreparedNamed {
    pub(super) parent: parent::HeldParent,
    pub(super) directory: directory::PrivateDirectory,
    pub(super) inode: named::NamedFile,
    pub(super) child: policy::ChildPolicy,
    pub(super) mode: Option<u32>,
    pub(super) mtime: Option<(i64, u32)>,
    pub(super) overwrite: crate::extract::Overwrite,
}
fn merge(error: &mut Option<ZipReadError>, report: ObjectCleanupReport) {
    if !report.is_empty() {
        *error = Some(match error.take() {
            Some(error) => error.merge_cleanup(report),
            None => report.into(),
        });
    }
}
fn merge_error(error: &mut Option<ZipReadError>, next: ZipReadError) {
    *error = Some(match error.take() {
        Some(error) => error.merge_cleanup_only(next),
        None => next,
    });
}
fn metadata_fault(error: &mut Option<ZipReadError>, fault: ReadFault) {
    let mut report = ObjectCleanupReport::new(OwnedObject::Output);
    report.push(CleanupFault {
        object: OwnedObject::Output,
        operation: ReadIoOperation::Stat,
        offset: None,
        close: CloseDisposition::NotApplicable,
        cause: CleanupCause::Admission(fault),
    });
    merge(error, report);
}
impl PreparedNamed {
    #[allow(clippy::result_large_err)]
    fn finish_published(
        mut self,
        ledger: &impl LedgerAccess,
        encrypted: bool,
        cancel: &Cancellation,
    ) -> ZipReadResult<()> {
        let mut result = self.directory.close_final(ledger, encrypted);
        if result.is_ok() {
            result = self.directory.remove_empty_normal(ledger, &self.parent, encrypted, cancel);
        }
        let mut error = result.err();
        if error.is_some() {
            ledger.with_state(|s| s.poisoned = true);
            let parent_ok = match self.parent.verify_cleanup_name(ledger) {
                Ok(()) => true,
                Err(fault) => {
                    let mut report = ObjectCleanupReport::new(OwnedObject::OutputParent);
                    report.push(fault);
                    merge(&mut error, report);
                    false
                }
            };
            let report = if parent_ok {
                self.directory.cleanup(ledger, &self.parent, encrypted)
            } else {
                self.directory.cleanup_blocked(ledger, encrypted)
            };
            merge(&mut error, report);
        }
        if let Err(fault) = self.child.finish(ledger) {
            metadata_fault(&mut error, fault);
        }
        if let Err(next) = self.parent.finish_observed(ledger, error.is_none(), encrypted) {
            if error.is_some() {
                merge_error(&mut error, next);
            } else {
                error = Some(next);
            }
        }
        error.map_or(Ok(()), Err)
    }
    fn finish_unpublished(
        mut self,
        ledger: &impl LedgerAccess,
        encrypted: bool,
        normal_output_close: bool,
    ) -> (bool, Option<ZipReadError>) {
        let mut error = None;
        let parent_ok = match self.parent.verify_cleanup_name(ledger) {
            Ok(()) => true,
            Err(fault) => {
                let mut report = ObjectCleanupReport::new(OwnedObject::OutputParent);
                report.push(fault);
                merge(&mut error, report);
                false
            }
        };
        let (clear, report) = if parent_ok {
            if normal_output_close {
                self.inode.retire_normal(ledger, &self.parent, &self.directory, encrypted)
            } else {
                self.inode.retire(ledger, &self.parent, &self.directory, encrypted)
            }
        } else {
            self.inode.retire_blocked(ledger, &self.parent, &self.directory, encrypted)
        };
        merge(&mut error, report);
        // Normal-success admission remains required even though no-clobber
        // collision/Skip transfers no target. One actual close, no retry.
        if let Err(next) = self.directory.close_final(ledger, encrypted) {
            let next =
                if normal_output_close { next.retirement_cleanup(OwnedObject::OutputPrivateDirectory) } else { next };
            error = Some(match error.take() {
                Some(prior) => prior.merge_cleanup_only(next.retirement_cleanup(OwnedObject::OutputPrivateDirectory)),
                None => next,
            });
        }
        let report = if parent_ok {
            self.directory.cleanup(ledger, &self.parent, encrypted)
        } else {
            self.directory.cleanup_blocked(ledger, encrypted)
        };
        merge(&mut error, report);
        if let Err(fault) = self.child.finish(ledger) {
            metadata_fault(&mut error, fault);
        }
        if let Err(next) = self.parent.finish_observed(ledger, error.is_none(), encrypted) {
            let next = if normal_output_close { next.retirement_cleanup(OwnedObject::OutputParent) } else { next };
            if error.is_some() {
                merge_error(&mut error, next);
            } else {
                error = Some(next);
            }
        }
        if error.is_some() || !clear {
            ledger.with_state(|s| s.poisoned = true);
        }
        (clear, error)
    }
    fn cleanup(
        mut self,
        ledger: &impl LedgerAccess,
        file: Option<File>,
        encrypted: bool,
    ) -> (bool, Option<ZipReadError>) {
        ledger.with_state(|s| s.poisoned = true);
        self.inode.file = file;
        let mut error = None;
        let parent_ok = match self.parent.verify_cleanup_name(ledger) {
            Ok(()) => true,
            Err(fault) => {
                let mut report = ObjectCleanupReport::new(OwnedObject::OutputParent);
                report.push(fault);
                merge(&mut error, report);
                false
            }
        };
        let directory_ok = if parent_ok {
            match self.directory.reopen_cleanup(ledger, &self.parent) {
                Ok(()) => true,
                Err(fault) => {
                    let mut report = ObjectCleanupReport::new(OwnedObject::OutputPrivateDirectory);
                    report.push(fault);
                    merge(&mut error, report);
                    false
                }
            }
        } else {
            false
        };
        let (clear, report) = if parent_ok && directory_ok {
            self.inode.retire(ledger, &self.parent, &self.directory, encrypted)
        } else {
            self.inode.retire_blocked(ledger, &self.parent, &self.directory, encrypted)
        };
        merge(&mut error, report);
        let directory = if parent_ok && directory_ok {
            self.directory.cleanup(ledger, &self.parent, encrypted)
        } else {
            self.directory.cleanup_blocked(ledger, encrypted)
        };
        merge(&mut error, directory);
        if let Err(fault) = self.child.finish(ledger) {
            metadata_fault(&mut error, fault);
        }
        if let Err(next) = self.parent.finish_observed(ledger, false, encrypted) {
            merge_error(&mut error, next);
        }
        (clear, error)
    }
}
fn native_mut(named: &mut Option<Prepared>) -> Option<&mut PreparedNamed> {
    match named.as_mut() {
        Some(Prepared::Native(ready)) => Some(ready),
        _ => None,
    }
}
/// A prepared stage on either backend.
pub(super) enum Prepared {
    Native(PreparedNamed),
    Portable(portable::PreparedPortable),
}
// Test control: treat every destination as outside the native allow-list.
#[cfg(test)]
thread_local! {pub(in crate::zip::read) static FORCE_UNSUPPORTED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };}
/// Chooses the staged backend for one held parent: native where the filesystem is on the allow-list (and the
/// caller allows it), the portable fallback where it is not and the caller allows that.
fn select_backend(
    ledger: &impl LedgerAccess,
    parent: &parent::HeldParent,
    encrypted: bool,
    storage: StagedStorage,
    publication: Publication,
    cancel: &Cancellation,
) -> Result<StagedBackend, ReadFault> {
    if storage == StagedStorage::PortableOnly
        || publication == Publication::Bulk && storage != StagedStorage::NativeOnly
    {
        return Ok(StagedBackend::Portable);
    }
    let native = io::operation(
        ledger,
        encrypted,
        RunCategory::StorageBackendOperations,
        IoStage::Output,
        ReadIoOperation::Stat,
        Some(cancel),
        || {
            spool::syscall(ReadIoOperation::Stat, parent.file.as_raw_fd(), || {
                #[cfg(test)]
                if FORCE_UNSUPPORTED.with(|f| f.get()) {
                    return Err(std::io::ErrorKind::Unsupported.into());
                }
                native_policy::backend(parent.file.as_raw_fd())
            })
        },
    );
    match native {
        Ok(()) => Ok(StagedBackend::Native),
        Err(ReadFault::Io { error, .. }) if error.kind() == std::io::ErrorKind::Unsupported => match storage {
            StagedStorage::NativeOnly => Err(ReadFault::UnsupportedStorage),
            _ => Ok(StagedBackend::Portable),
        },
        Err(fault) => Err(fault),
    }
}
struct Preparing<'a> {
    ledger: LedgerView<'a>,
    encrypted: bool,
    bytes: u64,
    parent: Option<parent::HeldParent>,
    directory: Option<directory::PrivateDirectory>,
    inode: Option<named::NamedFile>,
    child: Option<policy::ChildPolicy>,
    snapshot: Option<policy::ParentPolicy>,
    temp: Option<portable::PortableTemp>,
    parent_unbound: bool,
    parent_observed: Option<bool>,
    stage_unbound: bool,
    storage_clear: bool,
    finished: bool,
}
impl Preparing<'_> {
    fn cleanup(&mut self) -> Option<ZipReadError> {
        if self.finished {
            return None;
        }
        self.finished = true;
        self.ledger.with_state(|s| s.poisoned = true);
        let mut error = None;
        if let Some(snapshot) = self.snapshot.take()
            && let Err(fault) = snapshot.finish(&self.ledger)
        {
            metadata_fault(&mut error, fault);
        }
        if let Some(parent) = self.parent.take() {
            if let Some(mut temp) = self.temp.take() {
                let (clear, report) = temp.retire(&self.ledger, &parent, self.encrypted, false);
                self.storage_clear = clear;
                merge(&mut error, report);
            }
            let parent_ok = match self.parent_observed.take() {
                Some(valid) => valid,
                None => match parent.verify_cleanup_name(&self.ledger) {
                    Ok(()) => true,
                    Err(fault) => {
                        let mut report = ObjectCleanupReport::new(OwnedObject::OutputParent);
                        report.push(fault);
                        merge(&mut error, report);
                        false
                    }
                },
            };
            if let Some(mut directory) = self.directory.take() {
                if let Some(mut inode) = self.inode.take() {
                    let ready = parent_ok
                        && directory
                            .reopen_cleanup(&self.ledger, &parent)
                            .map_err(|fault| {
                                let mut report = ObjectCleanupReport::new(OwnedObject::OutputPrivateDirectory);
                                report.push(fault);
                                merge(&mut error, report);
                            })
                            .is_ok();
                    let (clear, report) = if ready {
                        inode.retire(&self.ledger, &parent, &directory, self.encrypted)
                    } else {
                        inode.retire_blocked(&self.ledger, &parent, &directory, self.encrypted)
                    };
                    self.storage_clear = clear;
                    merge(&mut error, report);
                    let report = if ready {
                        directory.cleanup(&self.ledger, &parent, self.encrypted)
                    } else {
                        directory.cleanup_blocked(&self.ledger, self.encrypted)
                    };
                    merge(&mut error, report);
                } else {
                    let report = if parent_ok {
                        directory.cleanup(&self.ledger, &parent, self.encrypted)
                    } else {
                        directory.cleanup_blocked(&self.ledger, self.encrypted)
                    };
                    merge(&mut error, report);
                }
            }
            if let Err(next) = parent.finish_observed(&self.ledger, false, self.encrypted) {
                merge_error(&mut error, next);
            }
        }
        if let Some(child) = self.child.take()
            && let Err(fault) = child.finish(&self.ledger)
        {
            metadata_fault(&mut error, fault);
        }
        if self.parent_unbound {
            self.ledger.with_state(|s| s.retire_fd(true));
            self.parent_unbound = false;
        }
        if self.stage_unbound {
            self.ledger.with_state(|s| s.retire_fd(true));
            self.stage_unbound = false;
        }
        if self.storage_clear {
            self.ledger.with_state(|s| s.release_bytes(self.encrypted, self.bytes));
        }
        error
    }
}
impl Drop for Preparing<'_> {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.cleanup();
        }
    }
}
#[allow(clippy::result_large_err)]
fn acquire(
    ledger: LedgerView<'_>,
    binding: &FileBinding<'_>,
    options: &crate::extract::Options,
    context: &EncryptedReadContext,
    cancel: &Cancellation,
    blocked: &mut Option<target::Refusal>,
    allow_blocked: bool,
) -> ZipReadResult<Option<Prepared>> {
    ledger.with_state(|s| s.reserve(binding.encrypted, binding.bytes, 2))?;
    let mut preparing = Preparing {
        ledger,
        encrypted: binding.encrypted,
        bytes: binding.bytes,
        parent: None,
        directory: None,
        inode: None,
        child: None,
        snapshot: None,
        temp: None,
        parent_unbound: true,
        parent_observed: None,
        stage_unbound: true,
        storage_clear: true,
        finished: false,
    };
    let result = (|| -> ZipReadResult<bool> {
        let frozen = context.action.as_ref().and_then(|a| a.policy.as_ref()).ok_or(ReadFault::InvalidPlan)?;
        let relative = binding.relative;
        preparing.parent_unbound = false;
        match parent::open_parent(&ledger, &options.dest, relative, frozen.cwd(), cancel) {
            Ok(parent) => preparing.parent = Some(parent),
            // open_parent has already given its slot back
            Err(error) if allow_blocked && parent::nondirectory_parent(&error) => {
                *blocked = Some(target::Refusal::ParentNotDirectory);
                return Ok(false);
            }
            Err(error) => {
                ledger.with_state(|s| s.poisoned = true);
                return Err(error);
            }
        }
        let parent = preparing.parent.as_mut().unwrap();
        let mut scratch = policy::PolicyScratch::new(ledger)?;
        match target::inspect(&ledger, parent, frozen, options.overwrite, RunCategory::PathSteps, &mut scratch, cancel)?
        {
            target::Target::Skip => return Ok(false),
            target::Target::Blocked(refusal) if allow_blocked => {
                *blocked = Some(refusal);
                return Ok(false);
            }
            target::Target::Blocked(refusal) => return Err(refusal.fault().into()),
            _ => {}
        }
        // A run's start hook (`MemberFilter::on_start`) is asked here: after the target checks, so a target that
        // Skip keeps or that is blocked is never offered, and before anything is staged or decoded. It sees the path
        // the member is published at (flattened when flattening); a rename mode picks its name only at publication,
        // so the hook sees the requested name.
        if allow_blocked
            && let Some(select) = &options.select
            && select.starts(&crate::extract::MemberStart { path: &options.dest.join(relative) })
                == crate::extract::StartDecision::Skip
        {
            return Ok(false);
        }
        let tilde = !parent.target().to_bytes().contains(&b'~');
        if select_backend(
            &ledger,
            parent,
            binding.encrypted,
            context.options.staged_storage,
            context.options.publication,
            cancel,
        )? == StagedBackend::Portable
        {
            preparing.stage_unbound = false;
            preparing.storage_clear = false;
            match portable::PortableTemp::create(&ledger, parent, binding.encrypted, tilde, cancel) {
                Ok(temp) => preparing.temp = Some(temp),
                Err((error, clear)) => {
                    preparing.storage_clear = clear;
                    return Err(error);
                }
            }
            return Ok(true);
        }
        let (snapshot, child) = policy::probe(&ledger, &parent.file, frozen.uid, tilde, &mut scratch, cancel)?;
        preparing.snapshot = Some(snapshot);
        preparing.child = Some(child);
        match directory::PrivateDirectory::create(
            &ledger,
            parent,
            binding.encrypted,
            frozen.uid,
            tilde,
            &mut scratch,
            cancel,
        ) {
            Ok(directory) => preparing.directory = Some(directory),
            Err(failure) => {
                preparing.parent_observed = Some(failure.parent_valid);
                return Err(failure.error);
            }
        }
        let mut group = io::CreationGroup::new(&ledger, binding.encrypted, IoStage::Output, cancel)?;
        preparing.stage_unbound = false;
        preparing.storage_clear = false;
        match named::NamedFile::create_and_place(
            &ledger,
            parent,
            preparing.directory.as_ref().unwrap(),
            preparing.snapshot.as_ref().unwrap(),
            preparing.child.as_ref().unwrap(),
            binding.encrypted,
            binding.bytes,
            tilde,
            &mut group,
            &mut scratch,
            cancel,
        ) {
            Ok(inode) => preparing.inode = Some(inode),
            Err(failure) => {
                preparing.storage_clear = failure.retired;
                preparing.parent_observed = Some(failure.parent_valid);
                return Err(failure.error);
            }
        }
        preparing.directory.as_mut().unwrap().close_before_payload(&ledger, binding.encrypted)?;
        preparing.snapshot.take().unwrap().finish(&ledger)?;
        Ok(true)
    })();
    match result {
        Ok(true) if preparing.temp.is_some() => {
            let ready = portable::PreparedPortable {
                parent: preparing.parent.take().unwrap(),
                temp: preparing.temp.take().unwrap(),
                mode: binding.mode,
                mtime: binding.mtime,
                overwrite: options.overwrite,
                // Bulk drops the per-file flush only in a run, which flushes the directories once at its end; a
                // standalone stage has no such boundary and keeps its own.
                sync: context.options.publication != Publication::Bulk || !allow_blocked,
            };
            preparing.finished = true;
            Ok(Some(Prepared::Portable(ready)))
        }
        Ok(true) => {
            let ready = PreparedNamed {
                parent: preparing.parent.take().unwrap(),
                directory: preparing.directory.take().unwrap(),
                inode: preparing.inode.take().unwrap(),
                child: preparing.child.take().unwrap(),
                mode: binding.mode,
                mtime: binding.mtime,
                overwrite: options.overwrite,
            };
            preparing.finished = true;
            Ok(Some(Prepared::Native(ready)))
        }
        Ok(false) => {
            // Skip is a successful no-storage outcome. Retire the held parent
            // normally without poisoning this completed selected action.
            let parent = preparing.parent.take();
            preparing.finished = true;
            ledger.with_state(|s| {
                s.retire_fd(true);
                s.release_bytes(binding.encrypted, binding.bytes);
            });
            // No parent is held when a nondirectory above the target refused it.
            if let Some(parent) = parent {
                parent.finish(&ledger)?;
            }
            Ok(None)
        }
        Err(error) => Err(match preparing.cleanup() {
            Some(cleanup) => error.merge_cleanup_only(cleanup),
            None => error,
        }),
    }
}
#[allow(clippy::result_large_err)]
impl ZipReadStage {
    /// Prepares one original regular entry in its actual destination parent.
    /// The returned stage owns no borrow of the original source or entry.
    pub fn prepare_file(
        entry: ZipStageEntry<'_>,
        relative: &Path,
        options: &crate::extract::Options,
        cancel: &Cancellation,
        context: &mut EncryptedReadContext,
    ) -> ZipReadResult<Option<Self>> {
        // one named entry: the whole-archive member filter has nothing to choose, and a renamed output would have no
        // report to be named in
        if options.select.is_some() || options.overwrite.rename().is_some() {
            return Err(ReadFault::InvalidPlan.into());
        }
        Self::prepare_file_inner(entry, relative, options, cancel, context, &mut None, false)
    }
    pub(in crate::zip::read) fn prepare_run_file(
        entry: ZipStageEntry<'_>,
        relative: &Path,
        options: &crate::extract::Options,
        cancel: &Cancellation,
        context: &mut EncryptedReadContext,
    ) -> ZipReadResult<(Option<Self>, Option<ReadFault>)> {
        let mut blocked = None;
        let ready = Self::prepare_file_inner(entry, relative, options, cancel, context, &mut blocked, true)?;
        Ok((ready, blocked.map(target::Refusal::fault)))
    }
    #[allow(clippy::too_many_arguments)]
    fn prepare_file_inner(
        mut entry: ZipStageEntry<'_>,
        relative: &Path,
        options: &crate::extract::Options,
        cancel: &Cancellation,
        context: &mut EncryptedReadContext,
        blocked: &mut Option<target::Refusal>,
        allow_blocked: bool,
    ) -> ZipReadResult<Option<Self>> {
        if allow_blocked
            && !context.action.as_ref().is_some_and(|a| a.run_bound && a.scope == ProjectedReadScope::AllRegular)
        {
            return Err(ReadFault::InvalidPlan.into());
        }
        let binding = entry.bind_file(relative, options, cancel, context)?;
        let token = context.ledger.mint_reservation()?;
        let result = acquire(token.view(), &binding, options, context, cancel, blocked, allow_blocked);
        let boundary = entry.observe_source(context);
        let result = match (result, boundary) {
            (Ok(ready), Ok(())) => Ok(ready),
            (Err(error), Ok(())) => Err(error),
            (Err(error), Err(boundary)) => Err(error.merge_source_boundary(boundary)),
            (Ok(ready), Err(error)) => {
                let mut error = error;
                if let Some(ready) = ready {
                    let (clear, cleanup) = match ready {
                        Prepared::Native(mut ready) => {
                            let file = ready.inode.file.take();
                            ready.cleanup(&token, file, binding.encrypted)
                        }
                        Prepared::Portable(ready) => ready.cleanup(&token, None, binding.encrypted),
                    };
                    if clear {
                        token.with_state(|s| s.release_bytes(binding.encrypted, binding.bytes));
                    }
                    if let Some(cleanup) = cleanup {
                        error = error.merge_cleanup_only(cleanup);
                    }
                }
                Err(error)
            }
        };
        match result {
            Ok(None) => Ok(None),
            Ok(Some(ready)) => {
                let (file, identity, uid, named) = match ready {
                    Prepared::Native(mut ready) => (
                        ready.inode.file.take().ok_or(ReadFault::InvalidPlan)?,
                        ready.inode.identity.ok_or(ReadFault::InvalidPlan)?,
                        ready.child.uid,
                        Prepared::Native(ready),
                    ),
                    Prepared::Portable(mut ready) => (
                        ready.temp.file.take().ok_or(ReadFault::InvalidPlan)?,
                        ready.temp.identity.ok_or(ReadFault::InvalidPlan)?,
                        // SAFETY: geteuid has no failure mode or memory effects.
                        unsafe { libc::geteuid() },
                        Prepared::Portable(ready),
                    ),
                };
                let handle = file_handle(&file);
                Ok(Some(Self {
                    file: Some(file),
                    reservation: OutputReservation {
                        ledger: token,
                        encrypted: binding.encrypted,
                        bytes: binding.bytes,
                        written: 0,
                        fds: 1,
                        identity,
                        handle,
                        retired: false,
                        loose_identity: false,
                    },
                    source: binding.source,
                    uid,
                    descriptor: (0, 0, 0, 0),
                    terminal: false,
                    named: Some(named),
                }))
            }
            Err(error) => {
                context.ledger.with_state(|s| s.poisoned = true);
                Err(token.with_state(|s| {
                    error.with_usage(s.encrypted.usage, s.run.usage).with_policy_usage(s.policy_metadata)
                }))
            }
        }
    }
    /// The whole-run normal member-error route never clears an emergency poison.
    pub(in crate::zip::read) fn finish_member_error(
        mut self,
        mut error: ZipReadError,
        context: &mut EncryptedReadContext,
        cancel: &Cancellation,
        mut source: impl FnMut(&mut EncryptedReadContext) -> ZipReadResult<()>,
    ) -> ZipReadError {
        let valid = context.action.as_ref().is_some_and(|a| {
            a.run_bound
                && a.scope == ProjectedReadScope::AllRegular
                && a.active_ordinal.is_some()
                && a.controlled_output
        }) && self.reservation.ledger.identity() == context.ledger.identity()
            && !context.ledger.with_state(|s| s.poisoned);
        if !valid {
            return self.finish_error_with_final_source(error, context, &mut source);
        }
        if let Err(boundary) = self.source.observe(context, &mut source) {
            return self.finish_error_with_final_source(error.merge_source_boundary(boundary), context, &mut source);
        }
        if let Some(ready) = self.take_portable() {
            self.terminal = true;
            let mut ready = ready;
            ready.temp.file = self.file.take();
            let (clear, cleanup) = ready.finish_unpublished(&self.reservation.ledger, self.reservation.encrypted, true);
            if clear {
                self.reservation
                    .ledger
                    .with_state(|s| s.release_bytes(self.reservation.encrypted, self.reservation.bytes));
            }
            self.reservation.retired = true;
            if let Some(cleanup) = cleanup {
                error = error.merge_cleanup_only(cleanup);
            }
            if let Err(boundary) = self.source.observe(context, &mut source) {
                error = error.merge_source_boundary(boundary);
            }
            return self.usage(error);
        }
        let reopened = (|| -> ZipReadResult<()> {
            let ready = native_mut(&mut self.named).ok_or(ReadFault::InvalidPlan)?;
            let mut scratch = policy::PolicyScratch::new(self.reservation.ledger.view())?;
            ready.directory.reopen_normal(
                &self.reservation.ledger,
                &ready.parent,
                self.reservation.encrypted,
                &mut scratch,
                cancel,
            )
        })();
        if let Err(boundary) = reopened {
            return self.finish_error_with_final_source(
                error.merge_cleanup_only(
                    boundary.owned_boundary_error(OwnedObject::OutputPrivateDirectory, ReadIoOperation::Open),
                ),
                context,
                &mut source,
            );
        }
        self.terminal = true;
        let mut ready = self.take_native().unwrap();
        ready.inode.file = self.file.take();
        let (clear, cleanup) = ready.finish_unpublished(&self.reservation.ledger, self.reservation.encrypted, true);
        if clear {
            self.reservation.ledger.with_state(|s| s.release_bytes(self.reservation.encrypted, self.reservation.bytes));
        }
        self.reservation.retired = true;
        if let Some(cleanup) = cleanup {
            error = error.merge_cleanup_only(cleanup);
        }
        if let Err(boundary) = self.source.observe(context, &mut source) {
            error = error.merge_source_boundary(boundary);
        }
        self.usage(error)
    }
    fn finish_error_with_final_source(
        self,
        error: ZipReadError,
        context: &mut EncryptedReadContext,
        source: &mut impl FnMut(&mut EncryptedReadContext) -> ZipReadResult<()>,
    ) -> ZipReadError {
        let mut error = self.finish_error(error, context);
        if let Err(boundary) = source(context) {
            error = error.merge_source_boundary(boundary);
        }
        error.with_usage(context.usage(), context.run_usage()).with_policy_usage(context.policy_metadata_usage())
    }
    pub(super) fn retire_named(&mut self) -> Option<ZipReadError> {
        let (clear, error) = match self.named.take()? {
            Prepared::Portable(ready) => {
                ready.cleanup(&self.reservation.ledger, self.file.take(), self.reservation.encrypted)
            }
            Prepared::Native(ready) => {
                ready.cleanup(&self.reservation.ledger, self.file.take(), self.reservation.encrypted)
            }
        };
        if clear && !self.reservation.retired {
            self.reservation.ledger.with_state(|s| s.release_bytes(self.reservation.encrypted, self.reservation.bytes));
        }
        self.reservation.retired = true;
        error
    }
}

/// Publishes the verified stage for a rename mode, with one no-replace rename per attempt; each attempt after the
/// first is charged like the single publication of the other modes. `existing` is what the final target inspection
/// found at the requested name, which it has already refused if `Overwrite::Always` would.
///
/// `RenameNew` publishes at the requested name when it was free, else (or when it was taken since) at the first free
/// renamed name. `RenameExisting` first moves the file at the requested name to the first free renamed name, then
/// publishes at the requested name; once moved, the existing file stays where it went whatever happens next, and
/// `renamed` reports it. Candidate names are leaves in the held parent, so they stay inside it, and a no-replace
/// rename can never land on a protected file. The `io::Result` is the final publication's; `None` means every renamed
/// name was taken, which fails only this member.
#[allow(clippy::too_many_arguments, clippy::result_large_err)]
fn publish_renamed(
    parent: &parent::HeldParent,
    dir: std::os::fd::RawFd,
    stage_leaf: &CStr,
    portable: Option<Option<(u64, u64)>>,
    mode: crate::extract::RenameMode,
    existing: bool,
    ledger: &impl LedgerAccess,
    encrypted: bool,
    cancel: &Cancellation,
    renamed: &mut Option<crate::extract::RenamedOutput>,
    stage_left: &mut bool,
) -> ZipReadResult<Option<std::io::Result<()>>> {
    use crate::extract::{RenameMode, RenamedOutput, renamed_name};
    use std::os::unix::ffi::OsStrExt;
    let mut publisher = RenamePublisher {
        parent: parent.file.as_raw_fd(),
        name: std::ffi::OsStr::from_bytes(parent.target().to_bytes()),
        style: mode.style(),
        ledger,
        encrypted,
        cancel,
        charged: false,
        portable: portable.is_some(),
        expected: portable.flatten(),
        stage_left: false,
    };
    let leaf = parent.target();
    let named = |n: u32| {
        let mut path = parent.path().to_bytes().to_vec();
        path.push(b'/');
        path.extend_from_slice(leaf.to_bytes());
        let requested = PathBuf::from(std::ffi::OsStr::from_bytes(&path));
        let renamed = requested.with_file_name(renamed_name(publisher.name, n, mode.style()));
        (requested, renamed)
    };
    match mode {
        RenameMode::New(_) => {
            if !existing {
                match publisher.attempt(dir, stage_leaf, leaf, true)? {
                    Some(Err(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    result => {
                        *stage_left = publisher.stage_left;
                        return Ok(result);
                    }
                }
            }
            let claimed = publisher.claim(dir, stage_leaf, true)?;
            *stage_left = publisher.stage_left;
            Ok(claimed.map(|claimed| {
                claimed.map(|n| {
                    let (requested, path) = named(n);
                    *renamed = Some(RenamedOutput { requested, path, existing: None });
                })
            }))
        }
        RenameMode::Existing(_) => {
            if existing {
                let n = match publisher.claim(publisher.parent, leaf, false)? {
                    Some(Ok(n)) => n,
                    Some(Err(error)) => return Ok(Some(Err(error))),
                    None => return Ok(None),
                };
                let (requested, moved) = named(n);
                *renamed = Some(RenamedOutput { path: requested.clone(), requested, existing: Some(moved) });
            }
            let result = publisher.attempt(dir, stage_leaf, leaf, true);
            *stage_left = publisher.stage_left;
            result
        }
    }
}

struct RenamePublisher<'a, L> {
    parent: std::os::fd::RawFd,
    name: &'a std::ffi::OsStr,
    style: crate::extract::RenameStyle,
    ledger: &'a L,
    encrypted: bool,
    cancel: &'a Cancellation,
    charged: bool,
    /// Publish with the portable no-replace ladder instead of the native no-replace rename.
    portable: bool,
    /// The portable stage's (device, inode), checked against its name before each stage rename.
    expected: Option<(u64, u64)>,
    /// A hard-link publication could not remove the stage name.
    stage_left: bool,
}

#[allow(clippy::result_large_err)]
impl<L: LedgerAccess> RenamePublisher<'_, L> {
    /// One no-replace rename of `from_leaf` in `from` to `to` in the held parent. Every attempt after the first takes
    /// one of the plan's reserved rename attempts; `None` when they are used up.
    fn attempt(
        &mut self,
        from: std::os::fd::RawFd,
        from_leaf: &CStr,
        to: &CStr,
        stage: bool,
    ) -> ZipReadResult<Option<std::io::Result<()>>> {
        if std::mem::replace(&mut self.charged, true) {
            if !self.ledger.with_state(|s| s.take_rename_attempt())? {
                return Ok(None);
            }
            self.ledger.with_state(|s| s.charge_category(RunCategory::StageFinalization, 1))?;
            io::canceled(Some(self.cancel))?;
            self.ledger.with_state(|s| s.attempt(self.encrypted))?;
        }
        Ok(Some(spool::syscall(ReadIoOperation::Publish, self.parent, || {
            if self.portable {
                let expected = if stage { self.expected } else { None };
                native_policy::rename_portable(from, from_leaf, self.parent, to, false, expected).map(|published| {
                    if stage && published == native_policy::Published::StageLeft {
                        self.stage_left = true;
                    }
                })
            } else {
                native_policy::rename_file(from, from_leaf, self.parent, to, false)
            }
        })))
    }

    /// Moves `from_leaf` to the first free renamed name: its number, the failed attempt that stopped the search, or
    /// `None` when every number up to `RENAME_LIMIT` is taken or the run's reserved rename attempts are used up.
    fn claim(
        &mut self,
        from: std::os::fd::RawFd,
        from_leaf: &CStr,
        stage: bool,
    ) -> ZipReadResult<Option<std::io::Result<u32>>> {
        use std::os::unix::ffi::OsStrExt;
        // NAME_MAX plus the longest number and a NUL, kept off the heap like the rest of publication
        let mut buffer = [0u8; 272];
        for n in 1..=crate::extract::RENAME_LIMIT {
            let candidate = crate::extract::renamed_name(self.name, n, self.style);
            let bytes = candidate.as_bytes();
            let Some(slot) = buffer.get_mut(..=bytes.len()) else {
                return Ok(Some(Err(std::io::Error::from_raw_os_error(libc::ENAMETOOLONG))));
            };
            slot[..bytes.len()].copy_from_slice(bytes);
            slot[bytes.len()] = 0;
            let to = CStr::from_bytes_with_nul(slot).map_err(|_| ReadFault::InvalidPlan)?;
            match self.attempt(from, from_leaf, to, stage)? {
                None => return Ok(None),
                Some(Ok(())) => return Ok(Some(Ok(n))),
                Some(Err(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Some(Err(error)) => return Ok(Some(Err(error))),
            }
        }
        Ok(None)
    }
}

/// The checked-format reason a member fails with when every renamed name is taken. Only that member fails.
pub(in crate::zip::read) const RENAME_EXHAUSTED: &str = "every renamed output name is taken";

fn same_time(a: Option<(i64, u32)>, b: Option<(i64, u32)>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some((a, b)), Some((c, d))) => crate::extract::archive_time(a, b) == crate::extract::archive_time(c, d),
        _ => false,
    }
}
#[allow(clippy::result_large_err)] // Two fixed5120-byte terminal values merge without allocation.
fn boundary<T>(result: ZipReadResult<T>, observed: ZipReadResult<()>) -> ZipReadResult<T> {
    match (result, observed) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(observed)) => Err(error.merge_source_boundary(observed)),
    }
}

#[allow(clippy::result_large_err)]
impl ZipReadStage {
    fn validate_file(
        &self,
        mode: Option<u32>,
        mtime: Option<(i64, u32)>,
        context: &EncryptedReadContext,
    ) -> Result<(), ReadFault> {
        if self.reservation.ledger.identity() != context.ledger.identity()
            || self.reservation.ledger.with_state(|s| s.poisoned)
        {
            return Err(ReadFault::InvalidPlan);
        }
        context.verify_identity(self.source.owner)?;
        let action = context.action.as_ref().ok_or(ReadFault::InvalidPlan)?;
        let (ready_mode, ready_mtime) = match &self.named {
            Some(Prepared::Native(ready)) => (ready.mode, ready.mtime),
            Some(Prepared::Portable(ready)) => (ready.mode, ready.mtime),
            None => return Err(ReadFault::InvalidPlan),
        };
        if !action.controlled_output
            || action.raw_output
            || !action.consumed
            || !action.completed
            || action.output != budget::PlannedOutput::StagedFiles
            || self.reservation.written != self.reservation.bytes
            || mode.map(|m| m & 0o777) != ready_mode.map(|m| m & 0o777)
            || !same_time(mtime, ready_mtime)
            || self.file.as_ref().is_none_or(|file| file_handle(file) != self.reservation.handle)
        {
            return Err(ReadFault::InvalidPlan);
        }
        Ok(())
    }
    /// Publishes only after exact original read completion and fresh successful
    /// checked-source observations at both final boundaries.
    pub fn publish(
        mut self,
        mode: Option<u32>,
        mtime: Option<(i64, u32)>,
        cancel: &Cancellation,
        context: &mut EncryptedReadContext,
        mut final_check: impl FnMut(&mut EncryptedReadContext) -> ZipReadResult<()>,
    ) -> ZipReadResult<bool> {
        if let Err(fault) = self.validate_file(mode, mtime, context) {
            return Err(self.finish_error(fault.into(), context));
        }
        if self.backend() == StagedBackend::Portable {
            return self.publish_portable(cancel, context, final_check);
        }
        let mut publication = PublicationState::NotPublished;
        let mut renamed = None;
        let mut exhausted = false;
        let result = (|| -> ZipReadResult<bool> {
            let ledger = &self.reservation.ledger;
            let encrypted = self.reservation.encrypted;
            let mut scratch = policy::PolicyScratch::new(ledger.view())?;
            let ready = native_mut(&mut self.named).ok_or(ReadFault::InvalidPlan)?;
            let metadata = (|| -> ZipReadResult<()> {
                ready.directory.reopen_normal(ledger, &ready.parent, encrypted, &mut scratch, cancel)?;
                metadata::restore(
                    ledger,
                    encrypted,
                    self.file.as_ref().ok_or(ReadFault::InvalidPlan)?,
                    &metadata::MetadataPlan {
                        identity: self.reservation.identity,
                        uid: ready.child.uid,
                        gid: ready.child.gid,
                        bytes: self.reservation.bytes,
                        baseline: ready.child.mode,
                        mode,
                        mtime,
                        acl: ready.child.acl.as_deref(),
                    },
                    &mut scratch,
                    cancel,
                )?;
                Ok(())
            })();
            boundary(metadata, self.source.observe(context, &mut final_check))?;
            let closed =
                ready.inode.close_for_publish(ledger, self.file.take().ok_or(ReadFault::InvalidPlan)?, encrypted);
            if let Err(error) = closed {
                return boundary(Err(error), self.source.observe(context, &mut final_check));
            }
            let eligible = (|| -> ZipReadResult<Option<bool>> {
                ready.parent.verify_normal_name(ledger, encrypted, cancel)?;
                ready.inode.check_inside(ledger, &ready.directory, ready.child.gid, encrypted, cancel)?;
                let frozen = context.action.as_ref().and_then(|a| a.policy.as_ref()).ok_or(ReadFault::InvalidPlan)?;
                let target = target::inspect(
                    ledger,
                    &mut ready.parent,
                    frozen,
                    ready.overwrite,
                    RunCategory::StageFinalization,
                    &mut scratch,
                    cancel,
                )?;
                match target {
                    target::Target::Skip => Ok(None),
                    target::Target::Blocked(refusal) => Err(refusal.fault().into()),
                    target::Target::Existing => Ok(Some(true)),
                    target::Target::Missing => Ok(Some(false)),
                }
            })();
            let Some(existing) = boundary(eligible, self.source.observe(context, &mut final_check))? else {
                return Ok(false);
            };
            // The source proof immediately precedes this one-shot mutation.
            ledger.with_state(|s| s.charge_category(RunCategory::StageFinalization, 1))?;
            io::canceled(Some(cancel))?;
            ledger.with_state(|s| s.attempt(encrypted))?;
            let dir = ready.directory.file.as_ref().ok_or(ReadFault::InvalidPlan)?.as_raw_fd();
            let moved = match ready.overwrite.rename() {
                None => spool::syscall(ReadIoOperation::Publish, ready.parent.file.as_raw_fd(), || {
                    native_policy::rename_file(
                        dir,
                        ready.inode.leaf(),
                        ready.parent.file.as_raw_fd(),
                        ready.parent.target(),
                        ready.overwrite == crate::extract::Overwrite::Always,
                    )
                }),
                Some(mode) => {
                    let leaf = ready.inode.leaf();
                    match publish_renamed(
                        &ready.parent,
                        dir,
                        leaf,
                        None,
                        mode,
                        existing,
                        ledger,
                        encrypted,
                        cancel,
                        &mut renamed,
                        &mut false.clone(),
                    )? {
                        Some(result) => result,
                        None => {
                            exhausted = true;
                            return Ok(false);
                        }
                    }
                }
            };
            match moved {
                Ok(_) => {
                    publication = PublicationState::Published;
                    ready.inode.published();
                    Ok(true)
                }
                Err(error)
                    if ready.overwrite == crate::extract::Overwrite::Skip
                        && error.kind() == std::io::ErrorKind::AlreadyExists =>
                {
                    Ok(false)
                }
                Err(error) => {
                    if error.kind() == std::io::ErrorKind::Interrupted
                        || error.raw_os_error() == Some(libc::EIO)
                        || error.raw_os_error().is_none()
                    {
                        publication = PublicationState::Unknown;
                    }
                    Err(ReadFault::Io { stage: IoStage::Output, operation: ReadIoOperation::Publish, offset: 0, error }
                        .into())
                }
            }
        })();
        // An existing file moved aside stays reported even when the publication then fails.
        if let Some(action) = context.action.as_mut() {
            action.renamed = renamed;
        }
        match result {
            Err(error) => Err(self.finish_error(error.with_publication(publication, 0), context)),
            Ok(true) => {
                self.terminal = true;
                self.reservation.retired = true;
                self.reservation
                    .ledger
                    .with_state(|s| s.release_bytes(self.reservation.encrypted, self.reservation.bytes));
                let ready = self.take_native().ok_or(ReadFault::InvalidPlan)?;
                ready
                    .finish_published(&self.reservation.ledger, self.reservation.encrypted, cancel)
                    .map(|_| true)
                    .map_err(|error| self.usage(error.with_publication(PublicationState::Published, 0)))
            }
            Ok(false) => {
                self.terminal = true;
                let ready = self.take_native().ok_or(ReadFault::InvalidPlan)?;
                let (clear, cleanup) =
                    ready.finish_unpublished(&self.reservation.ledger, self.reservation.encrypted, false);
                if clear {
                    self.reservation
                        .ledger
                        .with_state(|s| s.release_bytes(self.reservation.encrypted, self.reservation.bytes));
                }
                self.reservation.retired = true;
                let finality = self.source.observe(context, &mut final_check);
                let result = boundary(cleanup.map_or(Ok(false), Err), finality);
                if result.is_err() {
                    self.reservation.ledger.with_state(|s| s.poisoned = true);
                }
                // Out of renamed names: the stage is retired like a skip, and only this member fails.
                let result = match result {
                    Ok(false) if exhausted => Err(ReadFault::CheckedFormat { reason: RENAME_EXHAUSTED }.into()),
                    result => result,
                };
                result.map_err(|error| self.usage(error.with_publication(PublicationState::NotPublished, 0)))
            }
        }
    }

    /// [`Self::publish`] on the portable backend: the same final source and target checks and overwrite policy, then
    /// one rename of the temporary file in the held parent.
    fn publish_portable(
        mut self,
        cancel: &Cancellation,
        context: &mut EncryptedReadContext,
        mut final_check: impl FnMut(&mut EncryptedReadContext) -> ZipReadResult<()>,
    ) -> ZipReadResult<bool> {
        let mut publication = PublicationState::NotPublished;
        let mut renamed = None;
        let mut exhausted = false;
        let mut stage_left = false;
        let result = (|| -> ZipReadResult<bool> {
            let ledger = &self.reservation.ledger;
            let encrypted = self.reservation.encrypted;
            let ready = match self.named.as_mut() {
                Some(Prepared::Portable(ready)) => ready,
                _ => return Err(ReadFault::InvalidPlan.into()),
            };
            let metadata = ready
                .restore(
                    ledger,
                    encrypted,
                    self.file.as_ref().ok_or(ReadFault::InvalidPlan)?,
                    self.reservation.bytes,
                    cancel,
                )
                .map_err(ZipReadError::from);
            // The identity the descriptor holds now, just before close, is what publication must still find.
            let current = boundary(metadata, self.source.observe(context, &mut final_check))?;
            ready.temp.identity = Some(current);
            let expected = Some((current.dev, current.ino));
            let closed =
                ready.temp.close_for_publish(ledger, self.file.take().ok_or(ReadFault::InvalidPlan)?, encrypted);
            if let Err(error) = closed {
                return boundary(Err(error), self.source.observe(context, &mut final_check));
            }
            let eligible = (|| -> ZipReadResult<Option<bool>> {
                ready.parent.verify_normal_name(ledger, encrypted, cancel)?;
                let mut scratch = policy::PolicyScratch::new(ledger.view())?;
                let frozen = context.action.as_ref().and_then(|a| a.policy.as_ref()).ok_or(ReadFault::InvalidPlan)?;
                let target = target::inspect(
                    ledger,
                    &mut ready.parent,
                    frozen,
                    ready.overwrite,
                    RunCategory::StageFinalization,
                    &mut scratch,
                    cancel,
                )?;
                match target {
                    target::Target::Skip => Ok(None),
                    target::Target::Blocked(refusal) => Err(refusal.fault().into()),
                    target::Target::Existing => Ok(Some(true)),
                    target::Target::Missing => Ok(Some(false)),
                }
            })();
            let Some(existing) = boundary(eligible, self.source.observe(context, &mut final_check))? else {
                return Ok(false);
            };
            ledger.with_state(|s| s.charge_category(RunCategory::StageFinalization, 1))?;
            io::canceled(Some(cancel))?;
            ledger.with_state(|s| s.attempt(encrypted))?;
            let dir = ready.parent.file.as_raw_fd();
            let moved = match ready.overwrite.rename() {
                None => spool::syscall(ReadIoOperation::Publish, dir, || {
                    native_policy::rename_portable(
                        dir,
                        ready.temp.leaf(),
                        dir,
                        ready.parent.target(),
                        ready.overwrite == crate::extract::Overwrite::Always,
                        expected,
                    )
                    .map(|published| stage_left = published == native_policy::Published::StageLeft)
                }),
                Some(mode) => {
                    let leaf = ready.temp.leaf();
                    match publish_renamed(
                        &ready.parent,
                        dir,
                        leaf,
                        Some(expected),
                        mode,
                        existing,
                        ledger,
                        encrypted,
                        cancel,
                        &mut renamed,
                        &mut stage_left,
                    )? {
                        Some(result) => result,
                        None => {
                            exhausted = true;
                            return Ok(false);
                        }
                    }
                }
            };
            match moved {
                Ok(()) => {
                    publication = PublicationState::Published;
                    // A hard-link publication whose stage unlink failed keeps the name for `retire` to remove.
                    if !stage_left {
                        ready.temp.published();
                    }
                    Ok(true)
                }
                Err(error)
                    if ready.overwrite == crate::extract::Overwrite::Skip
                        && error.kind() == std::io::ErrorKind::AlreadyExists =>
                {
                    Ok(false)
                }
                Err(error) => {
                    if error.kind() == std::io::ErrorKind::Interrupted
                        || error.raw_os_error() == Some(libc::EIO)
                        || error.raw_os_error().is_none()
                    {
                        publication = PublicationState::Unknown;
                    }
                    Err(ReadFault::Io { stage: IoStage::Output, operation: ReadIoOperation::Publish, offset: 0, error }
                        .into())
                }
            }
        })();
        if let Some(action) = context.action.as_mut() {
            action.renamed = renamed;
        }
        match result {
            Err(error) => Err(self.finish_error(error.with_publication(publication, 0), context)),
            Ok(true) => {
                self.terminal = true;
                self.reservation.retired = true;
                self.reservation
                    .ledger
                    .with_state(|s| s.release_bytes(self.reservation.encrypted, self.reservation.bytes));
                let ready = self.take_portable().ok_or(ReadFault::InvalidPlan)?;
                ready
                    .finish_published(&self.reservation.ledger, self.reservation.encrypted)
                    .map(|_| true)
                    .map_err(|error| self.usage(error.with_publication(PublicationState::Published, 0)))
            }
            Ok(false) => {
                self.terminal = true;
                let ready = self.take_portable().ok_or(ReadFault::InvalidPlan)?;
                let (clear, cleanup) =
                    ready.finish_unpublished(&self.reservation.ledger, self.reservation.encrypted, false);
                if clear {
                    self.reservation
                        .ledger
                        .with_state(|s| s.release_bytes(self.reservation.encrypted, self.reservation.bytes));
                }
                self.reservation.retired = true;
                let finality = self.source.observe(context, &mut final_check);
                let result = boundary(cleanup.map_or(Ok(false), Err), finality);
                if result.is_err() {
                    self.reservation.ledger.with_state(|s| s.poisoned = true);
                }
                let result = match result {
                    Ok(false) if exhausted => Err(ReadFault::CheckedFormat { reason: RENAME_EXHAUSTED }.into()),
                    result => result,
                };
                result.map_err(|error| self.usage(error.with_publication(PublicationState::NotPublished, 0)))
            }
        }
    }
    /// The storage backend this stage writes through.
    pub fn backend(&self) -> StagedBackend {
        if matches!(self.named, Some(Prepared::Portable(_))) { StagedBackend::Portable } else { StagedBackend::Native }
    }
    fn take_native(&mut self) -> Option<PreparedNamed> {
        match self.named.take() {
            Some(Prepared::Native(ready)) => Some(ready),
            other => {
                self.named = other;
                None
            }
        }
    }
    fn take_portable(&mut self) -> Option<portable::PreparedPortable> {
        match self.named.take() {
            Some(Prepared::Portable(ready)) => Some(ready),
            other => {
                self.named = other;
                None
            }
        }
    }
}

#[cfg(test)]
pub(super) fn control_layout() -> [usize; 12] {
    use std::mem::size_of;
    [
        size_of::<ZipReadStage>(),
        size_of::<PreparedNamed>(),
        size_of::<Preparing<'_>>(),
        size_of::<ZipStageEntry<'_>>(),
        size_of::<FileBinding<'_>>(),
        size_of::<parent::HeldParent>(),
        size_of::<directory::PrivateDirectory>(),
        size_of::<named::NamedFile>(),
        size_of::<metadata::MetadataPlan<'_>>(),
        size_of::<policy::PolicyScratch<'_>>(),
        size_of::<directory::DirectoryFailure>(),
        size_of::<named::PlacementFailure>(),
    ]
}
