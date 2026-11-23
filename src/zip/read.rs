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

//! Checked ZIP read policy, bounded output leases, and inline terminal evidence.
mod budget;
mod cipher;
mod codecs;
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) mod diagnostic;
mod error;
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub use diagnostic::{
    ZipDiagnosticCompletion, ZipDiagnosticResult, ZipDiagnosticScope, ZipDiagnosticSink, ZipDiagnosticStatus,
    ZipDiagnosticStop, ZipDiagnosticUsage, ZipDiagnosticWriter, ZipDirectDiagnostics, ZipObserverFault,
    ZipObserverResult, ZipRunObserver,
};
mod output;
#[cfg(unix)]
mod policy;
mod projected;
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod run;
pub use output::{ZipReadStage, ZipStageEntry};
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) use run::{with_opened_context, with_opened_policy};
#[cfg(unix)]
mod native_policy;
pub use io::{BootstrapPhase, BootstrapUsage};
pub use projected::ProjectedReadSession;
#[cfg(test)]
pub(in crate::zip) use projected::observe as observe_projected;
pub(crate) use projected::{CheckedOpen, ProjectedOwner};
pub(in crate::zip) use projected::{checked_read, identity as projected_identity};
pub(super) mod io;
mod shared;
mod spool;
use crate::extract::Cancellation;
pub use budget::{EncryptedReadLimits, EncryptedReadUsage, PolicyAllocationUsage, PolicyMetadataUsage, RunUsage};
pub use error::*;
use shared::{ContextLedger, ReservationLedger};
use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
};

/// Where checked staged output ([`crate::zip::run_with_policy`], [`ZipReadStage`]) may be written.
///
/// The native backend proves private, ownership-checked creation and a no-replace publication with
/// filesystem-specific guarantees, and only runs on local APFS (macOS) or ext4, XFS, Btrfs and tmpfs (Linux). The
/// portable backend runs anywhere (ZFS, NFS, SMB, FUSE such as mergerfs/shfs, overlayfs, exFAT, HFS+, ...): a 0600
/// temporary file in the target directory, a flush where supported, then a rename. It keeps every path, parent,
/// target, overwrite and source check; `docs/zip-staged-output.md` lists exactly which guarantees it gives up.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum StagedStorage {
    /// Native where the destination filesystem is on the allow-list, portable elsewhere (the default).
    #[default]
    Auto,
    /// Native only: a destination outside the allow-list fails with [`ReadFault::UnsupportedStorage`].
    NativeOnly,
    /// Portable everywhere, even on an allow-listed filesystem.
    PortableOnly,
}
/// How checked staged output is made durable ([`EncryptedReadOverrides::publication`]).
///
/// `docs/zip-staged-output.md` lists exactly what [`Publication::Bulk`] gives up.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum Publication {
    /// Per-member staging as chosen by [`StagedStorage`]: native private staging where allowed, otherwise the
    /// portable stage flushed with `fsync`/`fdatasync` before its rename (the default).
    #[default]
    Staged,
    /// For archives of many small files: every member takes the portable stage (temp file in its target directory,
    /// then one rename) with no per-file flush, and each directory the run published into is flushed once when the
    /// run ends. Path containment, target, overwrite, source and verification checks are unchanged.
    /// [`StagedStorage::NativeOnly`] takes precedence and keeps native staging.
    Bulk,
}
/// The backend one staged output was written through; see [`StagedStorage`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StagedBackend {
    Native,
    Portable,
}
#[derive(Clone, Debug)]
pub struct EncryptedReadOptions {
    limits: EncryptedReadLimits,
    temp_dir: Option<PathBuf>,
    lzma_memory_bytes: u64,
    zstd_window_log_max: u32,
    staged_storage: StagedStorage,
    publication: Publication,
    /// Set only by the checked run before it plans: staged AES members stream instead of spooling.
    stream_staged_aes: bool,
}
impl Default for EncryptedReadOptions {
    fn default() -> Self {
        Self {
            limits: Default::default(),
            temp_dir: None,
            lzma_memory_bytes: 256 << 20,
            zstd_window_log_max: 27,
            staged_storage: StagedStorage::Auto,
            publication: Publication::Staged,
            stream_staged_aes: false,
        }
    }
}
impl EncryptedReadOptions {
    pub fn with_staged_storage(mut self, storage: StagedStorage) -> Self {
        self.staged_storage = storage;
        self
    }
    pub fn staged_storage(&self) -> StagedStorage {
        self.staged_storage
    }
    pub fn with_publication(mut self, publication: Publication) -> Self {
        self.publication = publication;
        self
    }
    pub fn publication(&self) -> Publication {
        self.publication
    }
    pub fn with_limits(mut self, limits: EncryptedReadLimits) -> Self {
        self.limits = limits;
        self
    }
    pub fn with_temp_dir(mut self, directory: PathBuf) -> Self {
        self.temp_dir = Some(directory);
        self
    }
    pub fn with_lzma_memory_bytes(mut self, bytes: u64) -> Self {
        self.lzma_memory_bytes = bytes;
        self
    }
    pub fn with_zstd_window_log_max(mut self, log: u32) -> Self {
        self.zstd_window_log_max = log;
        self
    }
    pub fn limits(&self) -> &EncryptedReadLimits {
        &self.limits
    }
}
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct EncryptedReadOverrides {
    pub member_packed_bytes: Option<u64>,
    pub member_decoded_bytes: Option<u64>,
    pub live_spool_bytes: Option<u128>,
    pub packed_bytes: Option<u128>,
    pub decoded_bytes: Option<u128>,
    pub io_bytes: Option<u128>,
    pub work_bytes: Option<u128>,
    pub io_attempts: Option<u128>,
    pub codec_steps: Option<u128>,
    pub members: Option<u64>,
    pub kdf_calls: Option<u64>,
    pub password_bytes: Option<u64>,
    pub interrupted_retries: Option<u64>,
    pub create_attempts: Option<u64>,
    pub temp_dir: Option<PathBuf>,
    /// Staged-output backend choice for contexts these overrides plan; see [`StagedStorage`].
    pub staged_storage: StagedStorage,
    /// Per-file durable staging or bulk publication for contexts these overrides plan; see [`Publication`].
    pub publication: Publication,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProjectedReadScope {
    AllRegular,
    Entry(usize),
}
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum ZipReadOutput<'a> {
    Discard,
    Callback,
    StagedFiles { destination: &'a Path },
    VerifiedStdout,
}

/// An action-local policy and two ledgers. Contexts and leases stay on one thread.
/// ```compile_fail
/// use zipfast::zip::{EncryptedReadContext, EncryptedReadOptions};
/// let context = EncryptedReadContext::new(EncryptedReadOptions::default()).unwrap();
/// std::thread::spawn(move || drop(context));
/// ```
/// ```compile_fail
/// use zipfast::zip::EncryptedReadContext;
/// fn sync<T: Sync>() {} sync::<EncryptedReadContext>();
/// ```
pub struct EncryptedReadContext {
    ledger: ContextLedger,
    options: EncryptedReadOptions,
    bootstrap: io::BootstrapIo,
    action: Option<projected::Action>,
    temp: Option<spool::ResolvedTempDirectory>,
}
impl Drop for EncryptedReadContext {
    fn drop(&mut self) {
        if let Some(temp) = self.temp.take() {
            let result = temp.finish_capacity(&self.ledger);
            debug_assert!(result.is_ok(), "same ledger owns temporary path capacity");
        }
        if let Some(action) = self.action.take() {
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            if let Some(policy) = action.policy
                && policy.finish(&self.ledger).is_err()
            {
                self.ledger.with_state(|s| s.poisoned = true);
            }
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            {
                let owned = match action.auxiliary {
                    projected::ActionAuxiliary::Empty => None,
                    projected::ActionAuxiliary::Directories(index) => {
                        if index.finish(&self.ledger).is_err() {
                            self.ledger.with_state(|s| s.poisoned = true);
                        }
                        None
                    }
                    projected::ActionAuxiliary::DirectDiagnostics(mut state) => state.cwd.take(),
                };
                if let Some(cwd) = owned
                    && cwd.finish(&self.ledger).is_err()
                {
                    self.ledger.with_state(|s| s.poisoned = true);
                }
            }
            drop(action.destination);
        }
    }
}
impl EncryptedReadContext {
    pub(in crate::zip) fn has_action_plan(&self) -> bool {
        self.ledger.with_state(|s| s.bound())
    }
    pub(in crate::zip) fn verify_identity(&self, identity: u64) -> Result<(), ReadFault> {
        if let Some(action) = &self.action {
            if action.identity != identity {
                return Err(ReadFault::InvalidPlan);
            }
            self.ledger.with_state(|s| s.verify_action(action))?;
        }
        Ok(())
    }
    // Fixed inline terminal evidence (measured in core tests) cannot be boxed on failure.
    #[allow(clippy::result_large_err)]
    pub fn new(options: EncryptedReadOptions) -> ZipReadResult<Self> {
        let state = budget::LedgerState::new(&options)?;
        let mut bootstrap = io::BootstrapIo::new(129 << 20, options.limits.interrupted_retries)?;
        bootstrap.acquisition(shared::SHARED_LEDGER_CAPACITY)?;
        let ledger = ContextLedger::try_new(state).map_err(|error| error.with_bootstrap(bootstrap.usage()))?;
        Ok(Self { ledger, options, bootstrap, action: None, temp: None })
    }
    #[cfg(unix)]
    #[allow(clippy::result_large_err, clippy::unnecessary_cast)] // Fixed evidence and platform dev/ino widths.
    pub(in crate::zip) fn admit_output_descriptor(
        &mut self,
        owner: u64,
        source: super::session::SourceStamp,
        fd: std::os::fd::BorrowedFd<'_>,
    ) -> ZipReadResult<()> {
        use std::os::fd::AsRawFd;
        if self.ledger.with_state(|s| s.poisoned) {
            return Err(ReadFault::InvalidPlan.into());
        }
        self.verify_identity(owner)?;
        self.ledger.with_state(|s| s.verify_source(source))?;
        let stat = io::operation(
            &self.ledger,
            false,
            RunCategory::StageFinalization,
            IoStage::Output,
            ReadIoOperation::Stat,
            None,
            || native_policy::stat(fd.as_raw_fd()),
        )?;
        if source.dev == stat.st_dev as u64 && source.ino == stat.st_ino as u64 {
            return Err(ReadFault::CheckedFormat { reason: "output aliases ZIP source" }.into());
        }
        let conflicts = self.ledger.with_state(|s| {
            let conflicts = stat.st_mode & libc::S_IFMT == libc::S_IFREG
                && s.diagnostic_identities
                    .iter()
                    .flatten()
                    .any(|&(dev, ino)| dev == stat.st_dev as u64 && ino == stat.st_ino as u64);
            if conflicts {
                s.poisoned = true;
            }
            conflicts
        });
        if conflicts {
            return Err(ReadFault::InvalidPlan.into());
        }
        let descriptor = (fd.as_raw_fd() as usize, stat.st_dev as u64, stat.st_ino as u64, stat.st_mode as u32);
        let action = self.action.as_mut().ok_or(ReadFault::InvalidPlan)?;
        if action.controlled_output && action.output_descriptor != Some(descriptor) {
            return Err(ReadFault::InvalidPlan.into());
        }
        action.output_descriptor = Some(descriptor);
        Ok(())
    }
    pub(in crate::zip) fn successful_source_observation(
        &mut self,
        owner: u64,
        source: super::session::SourceStamp,
    ) -> Result<(), ReadFault> {
        self.verify_identity(owner)?;
        // Legacy checked observation also works before any action is bound;
        // it cannot issue a controlled-stage proof.
        if self.action.is_none() {
            return Ok(());
        }
        self.ledger.with_state(|s| s.verify_source(source))?;
        let action = self.action.as_mut().ok_or(ReadFault::InvalidPlan)?;
        let Some(next) = action.source_observation.checked_add(1) else {
            self.ledger.with_state(|s| s.poisoned = true);
            return Err(ReadFault::CounterOverflow);
        };
        action.source_observation = next;
        Ok(())
    }
    pub(in crate::zip) fn source_group(&mut self, source: super::session::SourceStamp) -> Result<(), ReadFault> {
        self.ledger.with_state(|s| {
            if s.bound() {
                s.verify_source(source)?;
                s.charge_category(RunCategory::SourceCheckGroups, 1)?;
            }
            Ok(())
        })
    }
    pub(in crate::zip) fn source_stat<T>(
        &mut self,
        stage: IoStage,
        mut call: impl FnMut() -> std::io::Result<T>,
    ) -> Result<T, io::SourceCheckError> {
        if !self.ledger.with_state(|s| s.bound()) {
            return self.bootstrap.stat(stage, call);
        }
        let mut retries = 0u64;
        loop {
            self.ledger.with_state(|s| s.attempt(false)).map_err(io::SourceCheckError::Admission)?;
            match call() {
                Ok(value) => return Ok(value),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                    retries =
                        retries.checked_add(1).ok_or(io::SourceCheckError::Admission(ReadFault::CounterOverflow))?;
                    budget::admit(
                        ReadResource::InterruptedRetries,
                        self.options.limits.interrupted_retries.into(),
                        retries.into(),
                    )
                    .map_err(io::SourceCheckError::Admission)?;
                }
                Err(error) => {
                    return Err(io::SourceCheckError::Source(CheckedSourceFault::Unavailable { stage, error }));
                }
            }
        }
    }
    pub fn usage(&self) -> EncryptedReadUsage {
        self.ledger.with_state(|s| s.encrypted.usage)
    }
    pub fn policy_metadata_usage(&self) -> PolicyMetadataUsage {
        self.ledger.with_state(|s| s.policy_metadata)
    }
    pub fn run_usage(&self) -> RunUsage {
        self.ledger.with_state(|s| s.run.usage)
    }
    pub fn options(&self) -> &EncryptedReadOptions {
        &self.options
    }
    /// Registers caller-owned files; the token borrows neither the context nor handles.
    /// Registration does not close caller handles. Unconfirmed drop retains unresolved resource usage and poisons acquisition.
    /// A catalogue-bound action is required; an unbound context refuses before I/O.
    /// The raw caller keeps the registered handles open, preserves descriptor
    /// flags, and owns actual close/storage cleanup. Caller seeks are harmless
    /// to writes, which use the lease's positional offset. Unconfirmed drop
    /// cannot prove resources retired and permanently poisons this action.
    #[allow(clippy::result_large_err)] // Fixed no-allocation terminal evidence.
    pub fn reserve_output(
        &mut self,
        file: &File,
        parent: Option<&File>,
        bytes: u64,
    ) -> ZipReadResult<OutputReservation> {
        if !cfg!(unix) {
            return Err(ReadFault::UnsupportedIdentity.into());
        }
        if !self.ledger.with_state(|s| s.bound()) {
            return Err(ReadFault::InvalidPlan.into());
        }
        let encrypted = self.ledger.with_state(|s| s.output_encrypted())?;
        if let Some(action) = self.action.as_mut() {
            if action.controlled_output {
                return Err(ReadFault::InvalidPlan.into());
            }
            action.raw_output = true;
        }
        let token = self.ledger.mint_reservation()?;
        let result = (|| {
            let identity = io::operation(
                &token,
                encrypted,
                RunCategory::StageFinalization,
                IoStage::Output,
                ReadIoOperation::Stat,
                None,
                || file.metadata(),
            )?;
            if bytes > i64::MAX as u64 {
                return Err(ReadFault::CounterOverflow);
            }
            #[cfg(unix)]
            {
                use std::os::fd::AsRawFd;
                let flags = io::operation(
                    &token,
                    encrypted,
                    RunCategory::StageFinalization,
                    IoStage::Output,
                    ReadIoOperation::DescriptorMode,
                    None,
                    || {
                        // SAFETY: File keeps this descriptor open for one nonmutating syscall.
                        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
                        if flags < 0 { Err(std::io::Error::last_os_error()) } else { Ok(flags) }
                    },
                )?;
                if flags & libc::O_APPEND != 0 || flags & libc::O_ACCMODE == libc::O_RDONLY {
                    return Err(ReadFault::InvalidPlan);
                }
            }
            if !identity.is_file() || identity.len() != 0 {
                return Err(ReadFault::InvalidPlan);
            }
            if let Some(parent) = parent {
                let metadata = io::operation(
                    &token,
                    encrypted,
                    RunCategory::StageFinalization,
                    IoStage::Output,
                    ReadIoOperation::Stat,
                    None,
                    || parent.metadata(),
                )?;
                if !metadata.is_dir() {
                    return Err(ReadFault::InvalidPlan);
                }
            }
            let loose_identity = loose_identity(&token, encrypted, file)?;
            // Task4 binds member scope; selected clear registrations must never spend encrypted quota.
            token.with_state(|s| s.reserve(encrypted, bytes, if parent.is_some() { 2 } else { 1 }))?;
            Ok(OutputReservation {
                ledger: token,
                encrypted,
                bytes,
                written: 0,
                fds: if parent.is_some() { 2 } else { 1 },
                identity: FileIdentity::capture(&identity),
                handle: file_handle(file),
                retired: false,
                loose_identity,
            })
        })();
        result.map_err(|fault: ReadFault| ZipReadError::from(fault).with_usage(self.usage(), self.run_usage()))
    }
}
/// Whether a caller's output file lives outside the native allow-list, where an open file's inode number need not
/// stay stable (exFAT numbers it by its first cluster, so it changes once data is written). The filesystem probe is
/// admitted and charged like the registration's other I/O.
fn loose_identity(ledger: &impl shared::LedgerAccess, encrypted: bool, file: &File) -> Result<bool, ReadFault> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        use std::os::fd::AsRawFd;
        let probe = io::operation(
            ledger,
            encrypted,
            RunCategory::StageFinalization,
            IoStage::Output,
            ReadIoOperation::Stat,
            None,
            || native_policy::backend(file.as_raw_fd()),
        );
        match probe {
            Ok(()) => Ok(false),
            Err(ReadFault::Io { error, .. }) => Ok(error.kind() == std::io::ErrorKind::Unsupported),
            Err(fault) => Err(fault),
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (ledger, encrypted, file);
        Ok(false)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    dev: u64,
    ino: u64,
}
impl FileIdentity {
    fn capture(metadata: &std::fs::Metadata) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Self { dev: metadata.dev(), ino: metadata.ino() }
        }
        #[cfg(not(unix))]
        {
            let _ = metadata;
            Self { dev: 0, ino: 0 }
        }
    }
}
fn file_handle(file: &File) -> usize {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        file.as_raw_fd() as usize
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        file.as_raw_handle() as usize
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        0
    }
}
struct PositionedWriter<'a> {
    file: &'a File,
    offset: u64,
}
impl Write for PositionedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let offset = libc::off_t::try_from(self.offset)
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
            // SAFETY: the borrowed File remains live; this immutable slice is valid
            // for its entire length. One pwrite is exactly one budgeted attempt.
            let n = unsafe { libc::pwrite(self.file.as_raw_fd(), bytes.as_ptr().cast(), bytes.len(), offset) };
            if n < 0 { Err(std::io::Error::last_os_error()) } else { Ok(n as usize) }
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::FileExt;
            self.file.seek_write(bytes, self.offset)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = bytes;
            Err(std::io::ErrorKind::Unsupported.into())
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
/// A bounded lease for one registered output. It is neither Send nor Sync.
/// ```compile_fail
/// use zipfast::zip::OutputReservation;
/// fn send<T: Send>() {} send::<OutputReservation>();
/// ```
/// ```compile_fail
/// use zipfast::zip::OutputReservation;
/// fn sync<T: Sync>() {} sync::<OutputReservation>();
/// ```
pub struct OutputReservation {
    ledger: ReservationLedger,
    encrypted: bool,
    bytes: u64,
    written: u64,
    fds: u64,
    identity: FileIdentity,
    handle: usize,
    retired: bool,
    /// A portable stage (see [`StagedStorage`]): exFAT and similar renumber the inode of an open file as it is
    /// unlinked and written, so only the device and file type identify it.
    loose_identity: bool,
}
struct ScratchLease<'a> {
    ledger: &'a ReservationLedger,
    bytes: u64,
}
impl Drop for ScratchLease<'_> {
    fn drop(&mut self) {
        self.ledger.with_state(|s| s.release_capacity(self.bytes));
    }
}
impl OutputReservation {
    fn check_file(&self, file: &File, cancel: &Cancellation) -> Result<(), ReadFault> {
        let metadata = io::operation(
            &self.ledger,
            self.encrypted,
            RunCategory::StageFinalization,
            IoStage::Output,
            ReadIoOperation::Stat,
            Some(cancel),
            || file.metadata(),
        )?;
        let actual = FileIdentity::capture(&metadata);
        let same = if self.loose_identity { actual.dev == self.identity.dev } else { actual == self.identity };
        if file_handle(file) != self.handle {
            return Err(ReadFault::InvalidPlan);
        }
        // A stage that is no longer the file we wrote is a typed, reportable failure, not a caller bug.
        if !metadata.is_file() || !same || metadata.len() != self.bytes {
            return Err(ReadFault::CheckedFormat { reason: "verified output stage changed before it was copied" });
        }
        Ok(())
    }
    pub fn write_all(&mut self, file: &mut File, bytes: &[u8], cancel: &Cancellation) -> ZipSinkResult<()> {
        if file_handle(file) != self.handle {
            return Err(ZipSinkFault::StageChanged);
        }
        io::canceled(Some(cancel)).map_err(io::sink)?;
        let next = self.written.checked_add(bytes.len() as u64).ok_or(ZipSinkFault::StageChanged)?;
        if next > self.bytes {
            return Err(ZipSinkFault::Limit {
                resource: ReadResource::MemberDecodedBytes,
                limit: self.bytes.into(),
                attempted: next.into(),
            });
        }
        let mut remaining = bytes;
        while !remaining.is_empty() {
            let n = io::write(
                &self.ledger,
                self.encrypted,
                &mut PositionedWriter { file, offset: self.written },
                IoStage::Output,
                self.written,
                remaining,
                cancel,
            )
            .map_err(io::sink)?;
            self.written += n as u64;
            remaining = &remaining[n..];
        }
        Ok(())
    }
    /// Call only after successful verification and a final source check.
    #[allow(clippy::result_large_err)] // Fixed no-allocation terminal evidence.
    pub fn copy_to(&mut self, file: &mut File, out: &mut impl Write, cancel: &Cancellation) -> ZipReadResult<u64> {
        let mut accepted = 0u64;
        self.ledger.with_state(|s| s.reserve_capacity(io::WINDOW as u64))?;
        let scratch = ScratchLease { ledger: &self.ledger, bytes: io::WINDOW as u64 };
        let result = (|| {
            self.check_file(file, cancel)?;
            if self.written != self.bytes {
                return Err(ReadFault::InvalidPlan);
            }
            io::rewind(&self.ledger, self.encrypted, file, cancel)?;
            let mut buffer = [0; io::WINDOW];
            let mut fetched = 0;
            while fetched < self.bytes {
                let count = (self.bytes - fetched).min(buffer.len() as u64) as usize;
                let n = io::read(
                    &self.ledger,
                    self.encrypted,
                    file,
                    IoStage::Output,
                    fetched,
                    &mut buffer[..count],
                    cancel,
                )?;
                if n == 0 {
                    return Err(ReadFault::Io {
                        stage: IoStage::Output,
                        operation: ReadIoOperation::Read,
                        offset: fetched,
                        error: std::io::ErrorKind::UnexpectedEof.into(),
                    });
                }
                fetched += n as u64;
                let mut remaining = &buffer[..n];
                while !remaining.is_empty() {
                    let n = io::write(
                        &self.ledger,
                        self.encrypted,
                        out,
                        IoStage::ExternalOutput,
                        accepted,
                        remaining,
                        cancel,
                    )?;
                    accepted += n as u64;
                    remaining = &remaining[n..];
                }
            }
            Ok(accepted)
        })();
        drop(scratch);
        result.map_err(|fault: ReadFault| {
            self.ledger
                .with_state(|s| ZipReadError::from(fault).with_usage(s.encrypted.usage, s.run.usage).accepted(accepted))
        })
    }
}
impl OutputReservation {
    #[allow(dead_code)] // Task5 controlled stage alone confirms its owned resources retired.
    pub(crate) fn retire_confirmed(mut self) {
        self.ledger.with_state(|s| {
            s.release_bytes(self.encrypted, self.bytes);
            for _ in 0..self.fds {
                s.retire_fd(true);
            }
        });
        self.retired = true;
    }
}
impl Drop for OutputReservation {
    fn drop(&mut self) {
        if !self.retired {
            // Caller still owns the imported resources. Registration ending proves
            // neither close nor storage cleanup: retain usage and poison acquisition.
            self.ledger.with_state(|s| s.poisoned = true);
        }
    }
}
#[non_exhaustive]
pub enum ZipRunEvent<'a> {
    /// A rename mode ([`crate::extract::Overwrite::RenameNew`] or [`crate::extract::Overwrite::RenameExisting`])
    /// renamed this member's output or moved its existing target aside. It comes just before the member's own
    /// `MemberSucceeded` or `MemberFailed`: an existing file moved aside is reported even when the member then
    /// fails. ZIP and tar (including a lone compressed stream) give the member's `ordinal`. It is `None` for the RAR
    /// and 7z runs [`crate::extract::run_with_policy`] hands to the legacy runners: they send this event as each
    /// rename is made, in the run's order, before any `LegacyDiagnostic` for that member, and also when the run then
    /// stops with an error.
    #[non_exhaustive]
    MemberRenamed {
        ordinal: Option<u64>,
        renamed: &'a crate::extract::RenamedOutput,
    },
    MemberFailed {
        ordinal: u64,
        name: &'a str,
        error: &'a ZipReadError,
    },
    MemberSkipped {
        ordinal: u64,
        name: &'a str,
    },
    MemberSucceeded {
        ordinal: u64,
        name: &'a str,
        decoded_bytes: u64,
    },
    /// Original mixed non-ZIP callbacks: skip/progress text as well as errors.
    /// Normal renderers use this channel and ignore LegacyError.
    LegacyDiagnostic {
        message: &'a str,
    },
    /// Borrowed original legacy Summary.errors text, in its original order.
    /// Quiet renderers use this channel; silent renderers ignore both channels.
    /// Plain closure observers receive both and choose what to render.
    #[non_exhaustive]
    LegacyError {
        message: &'a str,
    },
    RunEnded {
        report: &'a ZipRunReport,
        error: Option<&'a ZipReadError>,
    },
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ZipRunReport {
    matched: u64,
    files: u64,
    dirs: u64,
    skipped: u64,
    failed: u64,
    volumes: u64,
    decoded_bytes: u128,
    portable_files: u64,
    usage: EncryptedReadUsage,
    run_usage: RunUsage,
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    diagnostic_usage: ZipDiagnosticUsage,
}
impl ZipRunReport {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    pub(crate) fn from_legacy(summary: &crate::extract::Summary) -> Self {
        Self {
            matched: summary.matched,
            files: summary.files,
            dirs: summary.dirs,
            skipped: summary.skipped,
            failed: summary.errors.len() as u64,
            volumes: summary.volumes,
            decoded_bytes: summary.bytes as u128,
            ..Default::default()
        }
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    pub fn diagnostic_usage(&self) -> ZipDiagnosticUsage {
        self.diagnostic_usage
    }
    /// Members (files and folders) taken by [`crate::extract::Options::select`], whatever became of them: every
    /// member when there is no filter. Zero means nothing matched.
    pub fn matched(&self) -> u64 {
        self.matched
    }
    pub fn files(&self) -> u64 {
        self.files
    }
    pub fn dirs(&self) -> u64 {
        self.dirs
    }
    pub fn skipped(&self) -> u64 {
        self.skipped
    }
    pub fn failed(&self) -> u64 {
        self.failed
    }
    pub fn volumes(&self) -> u64 {
        self.volumes
    }
    pub fn decoded_bytes(&self) -> u128 {
        self.decoded_bytes
    }
    /// Files an extracting run published through the native staged backend ([`StagedBackend::Native`]): every
    /// file not counted by [`Self::portable_files`]. Zero for a test run, which publishes nothing.
    pub fn native_files(&self) -> u64 {
        self.files - self.portable_files.min(self.files)
    }
    /// Files published through the portable staged backend ([`StagedBackend::Portable`]), with the weaker
    /// guarantees [`StagedStorage`] describes. Zero when every destination was on the native allow-list.
    pub fn portable_files(&self) -> u64 {
        self.portable_files
    }
    pub fn usage(&self) -> EncryptedReadUsage {
        self.usage
    }
    pub fn run_usage(&self) -> RunUsage {
        self.run_usage
    }
}
#[cfg(test)]
mod tests;
