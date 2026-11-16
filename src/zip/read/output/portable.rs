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

//! Portable staged output for filesystems outside the native allow-list (ZFS, NFS, SMB, FUSE, overlayfs, exFAT,
//! HFS+, ...): a 0600 temporary file in the held target parent, payload, metadata, a flush where supported, then one
//! rename. Path containment, the held parent, target inspection, overwrite policy and source checks are the native
//! path's own; what is dropped is everything that needs filesystem-specific guarantees. See `docs/zip-staged-output.md`.
use super::*;
use crate::zip::read::shared::LedgerAccess;
use parent::HeldParent;
use std::ffi::CStr;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};

/// The temporary file: a random hidden leaf in the held parent, and its descriptor until publication.
pub(in crate::zip::read) struct PortableTemp {
    pub(in crate::zip::read) file: Option<File>,
    pub(in crate::zip::read) identity: Option<FileIdentity>,
    name: [u8; 41],
    /// Our name may still exist in the parent (created, or a create whose outcome is unknown).
    named: bool,
    /// The reserved descriptor slot has not been retired yet.
    fd_reserved: bool,
}
#[allow(clippy::unnecessary_cast)]
fn identity(stat: &libc::stat) -> FileIdentity {
    FileIdentity { dev: stat.st_dev as u64, ino: stat.st_ino as u64 }
}
fn statat(fd: i32, name: &CStr) -> std::io::Result<libc::stat> {
    let mut stat = std::mem::MaybeUninit::uninit();
    native_policy::cvt(unsafe { libc::fstatat(fd, name.as_ptr(), stat.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW) })?;
    Ok(unsafe { stat.assume_init() })
}
fn cleanup_fault(operation: ReadIoOperation, cause: CleanupCause) -> CleanupFault {
    CleanupFault { object: OwnedObject::Output, operation, offset: None, close: CloseDisposition::NotApplicable, cause }
}
impl PortableTemp {
    pub(in crate::zip::read) fn leaf(&self) -> &CStr {
        CStr::from_bytes_with_nul(&self.name).expect("generated portable stage leaf")
    }
    /// Creates the temporary file in `parent`. On failure everything this created is already retired, and the flag
    /// says whether its storage is clear.
    #[allow(clippy::result_large_err)]
    pub(in crate::zip::read) fn create(
        ledger: &impl LedgerAccess,
        parent: &HeldParent,
        encrypted: bool,
        tilde: bool,
        cancel: &Cancellation,
    ) -> Result<Self, (ZipReadError, bool)> {
        let mut temp = Self { file: None, identity: None, name: [0; 41], named: false, fd_reserved: true };
        let result = (|| -> Result<(), ReadFault> {
            let mut group = io::CreationGroup::new(ledger, encrypted, IoStage::Output, cancel)?;
            let scope = spool::PrivateScope {
                encrypted,
                object: OwnedObject::Output,
                parent: OwnedObject::OutputParent,
                stage: IoStage::Output,
            };
            let fd = loop {
                group.ensure_next()?;
                spool::namespace(ledger, cancel, scope, ReadIoOperation::Read, || {
                    spool::random_leaf(&mut temp.name, tilde)
                })?;
                let leaf = CStr::from_bytes_with_nul(&temp.name).expect("generated portable stage leaf");
                let created = group.create_once(cancel, || {
                    temp.named = true;
                    spool::syscall(ReadIoOperation::Create, parent.file.as_raw_fd(), || {
                        native_policy::portable_file(parent.file.as_raw_fd(), leaf)
                    })
                });
                match created {
                    Ok(fd) => break fd,
                    Err(ReadFault::Io { error, .. }) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        temp.named = false;
                    }
                    Err(ReadFault::Io { error, .. })
                        if error.raw_os_error().is_some() && error.kind() != std::io::ErrorKind::Interrupted =>
                    {
                        // A definite refusal created nothing.
                        temp.named = false;
                        return Err(ReadFault::Io {
                            stage: IoStage::Output,
                            operation: ReadIoOperation::Create,
                            offset: 0,
                            error,
                        });
                    }
                    Err(error) => return Err(error),
                }
            };
            temp.file = Some(unsafe { File::from_raw_fd(fd) });
            let actual = spool::namespace(ledger, cancel, scope, ReadIoOperation::Stat, || {
                native_policy::stat(temp.file.as_ref().unwrap().as_raw_fd())
            })?;
            temp.identity = Some(identity(&actual));
            // The one property kept from the native birth proof: an empty regular file nobody else can open.
            if actual.st_mode & libc::S_IFMT != libc::S_IFREG || actual.st_size != 0 || actual.st_mode & 0o077 != 0 {
                return Err(ReadFault::CheckedFormat { reason: "portable output stage changed" });
            }
            Ok(())
        })();
        match result {
            Ok(()) => Ok(temp),
            Err(fault) => {
                ledger.with_state(|s| s.poisoned = true);
                let (clear, report) = temp.retire(ledger, parent, encrypted, false);
                let error = ZipReadError::from(fault);
                Err((if report.is_empty() { error } else { error.merge_cleanup(report) }, clear))
            }
        }
    }
    /// Closes the descriptor ahead of publication.
    #[allow(clippy::result_large_err)]
    pub(in crate::zip::read) fn close_for_publish(
        &mut self,
        ledger: &impl LedgerAccess,
        file: File,
        encrypted: bool,
    ) -> ZipReadResult<()> {
        let fd = file.into_raw_fd();
        let closed =
            io::retire_in(ledger, encrypted, OwnedObject::Output, Some(RunCategory::StageFinalization), true, || {
                spool::syscall(ReadIoOperation::Close, fd, || {
                    native_policy::cvt(unsafe { libc::close(fd) }).map(|_| ())
                })
            });
        self.fd_reserved = false;
        let mut error = closed.admission.map(ZipReadError::from);
        if let Some(fault) = closed.fault {
            let mut report = ObjectCleanupReport::new(OwnedObject::Output);
            report.push(fault);
            error = Some(match error {
                Some(error) => error.merge_cleanup(report),
                None => report.into(),
            });
        }
        error.map_or(Ok(()), Err)
    }
    pub(in crate::zip::read) fn published(&mut self) {
        self.named = false;
    }
    /// Removes the temporary name (only while it still names a regular file of the stage's size class) and closes
    /// the descriptor. Returns whether storage is clear.
    pub(in crate::zip::read) fn retire(
        &mut self,
        ledger: &impl LedgerAccess,
        parent: &HeldParent,
        encrypted: bool,
        normal_close: bool,
    ) -> (bool, ObjectCleanupReport) {
        let mut report = ObjectCleanupReport::new(OwnedObject::Output);
        let emergency = |op, call: &mut dyn FnMut() -> std::io::Result<()>| -> Result<(), CleanupCause> {
            ledger
                .with_state(|s| s.charge_category(RunCategory::EmergencyCleanup, 1))
                .map_err(|_| CleanupCause::Policy("output cleanup allowance exhausted"))?;
            spool::syscall(op, -1, call).map_err(CleanupCause::Io)
        };
        let mut clear = !self.named;
        if self.named {
            let cleanup = (|| -> Result<(), (ReadIoOperation, CleanupCause)> {
                let mut actual = None;
                emergency(ReadIoOperation::Stat, &mut || {
                    match statat(parent.file.as_raw_fd(), self.leaf()) {
                        Ok(stat) => actual = Some(stat),
                        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {}
                        Err(error) => return Err(error),
                    }
                    Ok(())
                })
                .map_err(|e| (ReadIoOperation::Stat, e))?;
                let Some(actual) = actual else {
                    return Ok(());
                };
                // Some portable filesystems (exFAT, SMB, FUSE) do not keep stable inode numbers, so the name is
                // matched as a regular file under our random 128-bit leaf rather than by identity alone.
                // `dev_t` is `u64` on Linux but `i32` on macOS.
                #[allow(clippy::unnecessary_cast)]
                let actual_dev = actual.st_dev as u64;
                if actual.st_mode & libc::S_IFMT != libc::S_IFREG
                    || self.identity.is_some_and(|id| id.dev != actual_dev)
                {
                    return Err((ReadIoOperation::Stat, CleanupCause::Policy("replaced stage name preserved")));
                }
                emergency(ReadIoOperation::Unlink, &mut || {
                    native_policy::cvt(unsafe { libc::unlinkat(parent.file.as_raw_fd(), self.leaf().as_ptr(), 0) })
                        .map(|_| ())
                })
                .map_err(|e| (ReadIoOperation::Unlink, e))?;
                Ok(())
            })();
            match cleanup {
                Ok(()) => {
                    self.named = false;
                    clear = true;
                }
                Err((operation, cause)) => report.push(cleanup_fault(operation, cause)),
            }
        }
        let mut closed = true;
        if let Some(file) = self.file.take() {
            let fd = file.into_raw_fd();
            let retired = io::retire_in(
                ledger,
                encrypted,
                OwnedObject::Output,
                Some(RunCategory::StageFinalization),
                normal_close,
                || {
                    spool::syscall(ReadIoOperation::Close, fd, || {
                        native_policy::cvt(unsafe { libc::close(fd) }).map(|_| ())
                    })
                },
            );
            if let Some(fault) = retired.admission {
                report.push(cleanup_fault(ReadIoOperation::Close, CleanupCause::Admission(fault)));
            }
            closed = retired.closed;
            if let Some(fault) = retired.fault {
                report.push(fault);
            }
            self.fd_reserved = false;
        } else if self.fd_reserved {
            ledger.with_state(|s| s.retire_fd(true));
            self.fd_reserved = false;
        }
        let clear = clear && closed;
        if !clear || !report.is_empty() {
            ledger.with_state(|s| s.poisoned = true);
        }
        (clear, report)
    }
}

/// A prepared portable stage: the held parent and the temporary file, with the member's metadata and policy.
pub(in crate::zip::read) struct PreparedPortable {
    pub(in crate::zip::read) parent: HeldParent,
    pub(in crate::zip::read) temp: PortableTemp,
    pub(in crate::zip::read) mode: Option<u32>,
    pub(in crate::zip::read) mtime: Option<(i64, u32)>,
    pub(in crate::zip::read) overwrite: crate::extract::Overwrite,
    /// Flush before publication; false under [`Publication::Bulk`], which flushes directories once per run.
    pub(in crate::zip::read) sync: bool,
}
fn merge(error: &mut Option<ZipReadError>, report: ObjectCleanupReport) {
    if !report.is_empty() {
        *error = Some(match error.take() {
            Some(error) => error.merge_cleanup(report),
            None => report.into(),
        });
    }
}
impl PreparedPortable {
    /// Best-effort archived time and mode, the creation-mask baseline, a flush where supported, and a final check
    /// that the descriptor still holds exactly the staged bytes.
    #[allow(clippy::unnecessary_cast)]
    pub(in crate::zip::read) fn restore(
        &self,
        ledger: &impl LedgerAccess,
        encrypted: bool,
        file: &File,
        bytes: u64,
        cancel: &Cancellation,
    ) -> Result<FileIdentity, ReadFault> {
        let fd = file.as_raw_fd();
        let op = |operation, call: &mut dyn FnMut() -> std::io::Result<()>| {
            io::operation(
                ledger,
                encrypted,
                RunCategory::StageFinalization,
                IoStage::Output,
                operation,
                Some(cancel),
                || spool::syscall(operation, fd, &mut *call),
            )
        };
        let ordinary = |result: Result<(), ReadFault>| match result {
            Ok(()) | Err(ReadFault::Io { .. }) => Ok(()),
            Err(error) => Err(error),
        };
        if let Some((seconds, nanos)) = self.mtime
            && let Some(modified) = metadata::time(Some((seconds, nanos)))
        {
            let times = [libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_OMIT as libc::c_long }, modified];
            ordinary(op(ReadIoOperation::SetTime, &mut || {
                native_policy::cvt(unsafe { libc::futimens(fd, times.as_ptr()) }).map(|_| ())
            }))?;
        }
        // The stage was born 0600; give it what an ordinary creation would have had, then the archived mode.
        // Filesystems without Unix modes (exFAT, SMB without extensions) may refuse or ignore either change.
        let baseline = 0o666 & !native_policy::creation_mask();
        let chmod = |mode: u32| {
            op(ReadIoOperation::DescriptorMode, &mut || {
                native_policy::cvt(unsafe { libc::fchmod(fd, mode as libc::mode_t) }).map(|_| ())
            })
        };
        // One fchmod when the archive has a mode; the baseline only stands in when it has none or it is refused.
        let archived = match self.mode {
            Some(mode) => chmod(mode & 0o777),
            None => Err(ReadFault::InvalidPlan),
        };
        match archived {
            Ok(()) => {}
            Err(ReadFault::Io { .. }) | Err(ReadFault::InvalidPlan) => ordinary(chmod(baseline))?,
            Err(error) => return Err(error),
        }
        if self.sync {
            op(ReadIoOperation::Flush, &mut || native_policy::portable_sync(fd))?;
        }
        let mut actual = None;
        op(ReadIoOperation::Stat, &mut || {
            actual = Some(native_policy::stat(fd)?);
            Ok(())
        })?;
        let actual = actual.ok_or(ReadFault::InvalidPlan)?;
        if actual.st_mode & libc::S_IFMT != libc::S_IFREG || actual.st_size < 0 || actual.st_size as u64 != bytes {
            return Err(ReadFault::CheckedFormat { reason: "portable output stage changed" });
        }
        Ok(identity(&actual))
    }
    /// After publication: removes a stage name a hard-link publication could not unlink, then closes the parent.
    #[allow(clippy::result_large_err)]
    pub(in crate::zip::read) fn finish_published(
        mut self,
        ledger: &impl LedgerAccess,
        encrypted: bool,
    ) -> ZipReadResult<()> {
        let mut error = None;
        if self.temp.named {
            let (_, report) = self.temp.retire(ledger, &self.parent, encrypted, true);
            merge(&mut error, report);
        }
        let closed = self.parent.finish_observed(ledger, error.is_none(), encrypted);
        match (error, closed) {
            (None, result) => result,
            (Some(error), Ok(())) => Err(error),
            (Some(error), Err(next)) => Err(error.merge_cleanup_only(next)),
        }
    }
    /// Without publication (skip, refusal, failure): removes the temporary file and closes the parent.
    pub(in crate::zip::read) fn finish_unpublished(
        mut self,
        ledger: &impl LedgerAccess,
        encrypted: bool,
        normal: bool,
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
        // The held parent descriptor still names the directory the stage was created in, so the stage name can be
        // removed through it even when the parent's spelling changed.
        let (clear, report) = self.temp.retire(ledger, &self.parent, encrypted, normal);
        merge(&mut error, report);
        let _ = parent_ok;
        if let Err(next) = self.parent.finish_observed(ledger, error.is_none(), encrypted) {
            error = Some(match error.take() {
                Some(prior) => prior.merge_cleanup_only(next),
                None => next,
            });
        }
        if error.is_some() || !clear {
            ledger.with_state(|s| s.poisoned = true);
        }
        (clear, error)
    }
    /// Emergency cleanup with the descriptor handed back by the stage.
    pub(in crate::zip::read) fn cleanup(
        mut self,
        ledger: &impl LedgerAccess,
        file: Option<File>,
        encrypted: bool,
    ) -> (bool, Option<ZipReadError>) {
        ledger.with_state(|s| s.poisoned = true);
        if file.is_some() {
            self.temp.file = file;
        }
        self.finish_unpublished(ledger, encrypted, false)
    }
}
