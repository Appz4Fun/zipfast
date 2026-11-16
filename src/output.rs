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

//! An extracted file being written. A big file is written on a thread of its own, so the disk works while the
//! next stretch is decoded; a small one is written directly.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread::{self, JoinHandle};

use tempfile::{NamedTempFile, TempPath};

use crate::error::{Error, IoOperation, RarFailure, RarFault, RarInternal, RarPolicyReason};

/// Files from this size up (or of unknown size) get a writer thread.
const BACKGROUND_MIN: u64 = 4 << 20;
/// Bytes gathered before they go to the writer. With the queue below, a file being written holds at most about
/// six of these: big enough to keep the disk busy, small enough to keep memory near what a direct write uses.
const CHUNK: usize = 1 << 20;
/// Chunks that may wait for the writer before writes block.
const DEPTH: usize = 4;

pub(crate) struct Output {
    inner: Inner,
    pending: Option<PendingPath>,
}

#[derive(Debug)]
pub(crate) enum OutputError {
    Io {
        operation: IoOperation,
        path: Option<PathBuf>,
        source: io::Error,
    },
    Worker(WriterFailure),
    Symlink(PathBuf),
    #[cfg(unix)]
    StageChanged(PathBuf),
    /// Every renamed name for this path was taken.
    #[cfg(unix)]
    RenameExhausted(PathBuf),
    /// The file system can neither rename without replacing nor make a hard link.
    #[cfg(unix)]
    RenameUnsupported(PathBuf),
}

impl OutputError {
    fn into_legacy(self) -> io::Error {
        match self {
            Self::Io { source, .. } => source,
            Self::Worker(failure) => failure.into_legacy(),
            Self::Symlink(_) => io::Error::new(io::ErrorKind::AlreadyExists, "a symlink is in the way"),
            #[cfg(unix)]
            Self::StageChanged(_) => io::Error::other("the verified output stage changed"),
            #[cfg(unix)]
            Self::RenameExhausted(_) => io::Error::new(io::ErrorKind::AlreadyExists, "no free name to rename to"),
            #[cfg(unix)]
            Self::RenameUnsupported(_) => {
                io::Error::new(io::ErrorKind::Unsupported, "the file system can't rename without replacing")
            }
        }
    }

    pub(crate) fn detailed(self, preserve_eof: bool) -> RarFault {
        match self {
            Self::Io { operation, path, source } => RarFault::output(operation, path, None, source, preserve_eof),
            Self::Worker(failure) => {
                let reason = match failure {
                    WriterFailure::Panicked => RarInternal::WorkerPanic,
                    WriterFailure::MissingFile => RarInternal::Invariant("no file"),
                    _ => RarInternal::WorkerStopped,
                };
                RarFault::new(RarFailure::Internal(reason), Error::Io(failure.into_legacy()))
            }
            Self::Symlink(path) => RarFault::new(
                RarFailure::Policy { reason: RarPolicyReason::Symlink, path },
                Error::Io(io::Error::new(io::ErrorKind::AlreadyExists, "a symlink is in the way")),
            ),
            #[cfg(unix)]
            Self::StageChanged(path) => RarFault::new(
                RarFailure::Policy { reason: RarPolicyReason::StageChanged, path },
                Error::Io(io::Error::other("the verified output stage changed")),
            ),
            #[cfg(unix)]
            Self::RenameExhausted(path) => RarFault::new(
                RarFailure::Policy { reason: RarPolicyReason::RenameExhausted, path },
                Error::Io(io::Error::new(io::ErrorKind::AlreadyExists, "no free name to rename to")),
            ),
            #[cfg(unix)]
            Self::RenameUnsupported(path) => RarFault::new(
                RarFailure::Policy { reason: RarPolicyReason::RenameUnsupported, path },
                Error::Io(io::Error::new(io::ErrorKind::Unsupported, "the file system can't rename without replacing")),
            ),
        }
    }
}

#[derive(Debug)]
pub(crate) enum WriterFailure {
    Io(io::Error),
    MissingFile,
    Stopped,
    Panicked,
    AlreadyStopped,
}

impl WriterFailure {
    fn into_legacy(self) -> io::Error {
        match self {
            Self::Io(e) => e,
            Self::MissingFile => io::Error::other("no file"),
            Self::Stopped => io::Error::other("the file writer stopped"),
            Self::Panicked => io::Error::other("the file writer failed"),
            Self::AlreadyStopped => io::Error::other("the file writer already stopped"),
        }
    }

    fn detailed(self, pending: Option<&PendingPath>) -> OutputError {
        match self {
            Self::Io(source) => OutputError::Io {
                operation: IoOperation::Write,
                path: pending.and_then(PendingPath::target).map(Path::to_path_buf),
                source,
            },
            failure => OutputError::Worker(failure),
        }
    }
}

pub(crate) struct WriteFile {
    pub file: File,
    pending: Option<PendingPath>,
}

enum PendingPath {
    New(Cleanup),
    Replacement(TempPath, PathBuf),
    #[cfg(unix)]
    Selected(SelectedStage, PathBuf),
}

#[cfg(unix)]
struct SelectedStage {
    path: Option<TempPath>,
    identity: (u64, u64),
}

#[cfg(unix)]
impl SelectedStage {
    fn owns_name(&self) -> bool {
        self.path.as_ref().is_some_and(|path| owns_stage_name(path, self.identity).unwrap_or(false))
    }
}

#[cfg(unix)]
impl Drop for SelectedStage {
    fn drop(&mut self) {
        if !self.owns_name()
            && let Some(path) = &mut self.path
        {
            path.disable_cleanup(true);
        }
    }
}

/// Removes a file this run created and then gave up on. On Unix only while the name still holds the file created
/// (`identity`): two members whose names a file system folds together (NFC and NFD spellings, letter case) may
/// both be in flight, and one's failure must not remove the other's output.
struct Cleanup(Option<PathBuf>, Option<(u64, u64)>);

impl Cleanup {
    fn new(file: &File, path: PathBuf) -> Self {
        Self(Some(path), file_identity(file))
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let Some(path) = &self.0 else { return };
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let current = fs::symlink_metadata(path).ok().filter(|m| m.is_file()).map(|m| (m.dev(), m.ino()));
            if self.1.is_none() || current != self.1 {
                return;
            }
        }
        let _ = fs::remove_file(path);
    }
}

#[cfg(unix)]
fn file_identity(file: &File) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    file.metadata().ok().map(|m| (m.dev(), m.ino()))
}

#[cfg(not(unix))]
fn file_identity(_: &File) -> Option<(u64, u64)> {
    None
}

/// What every staged output's name starts with, so a caller can tell a temporary that a crash left behind from a
/// finished file.
pub const STAGED_PREFIX: &str = ".zipfast-";

/// Use the same default mode as a regular newly created output file.
pub(crate) fn temporary(parent: &Path) -> io::Result<NamedTempFile> {
    let builder = &mut tempfile::Builder::new();
    builder.prefix(STAGED_PREFIX);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(fs::Permissions::from_mode(0o666));
    }
    builder.tempfile_in(parent)
}

pub(crate) fn replace(temporary: TempPath, target: &Path) -> io::Result<()> {
    replace_detailed(temporary, target).map_err(OutputError::into_legacy)
}

fn replace_detailed(temporary: TempPath, target: &Path) -> Result<(), OutputError> {
    let fault = |operation, source| OutputError::Io { operation, path: Some(target.to_path_buf()), source };
    // An earlier check cannot account for a symlink installed while decoding.
    match fs::symlink_metadata(target) {
        Ok(meta) if meta.file_type().is_symlink() => return Err(OutputError::Symlink(target.to_path_buf())),
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(fault(IoOperation::Metadata, e)),
    }
    temporary.persist(target).map_err(|e| fault(IoOperation::Publish, e.error))
}

enum Inner {
    Direct(File),
    Background(Background),
}

struct Background {
    tx: Option<SyncSender<Vec<u8>>>,
    /// emptied buffers coming back for reuse
    spare: Receiver<Vec<u8>>,
    cur: Vec<u8>,
    handle: Option<JoinHandle<Result<File, WriterFailure>>>,
}

impl PendingPath {
    fn target(&self) -> Option<&Path> {
        match self {
            Self::New(cleanup) => cleanup.0.as_deref(),
            Self::Replacement(_, target) => Some(target),
            #[cfg(unix)]
            Self::Selected(_, target) => Some(target),
        }
    }
}

impl WriteFile {
    pub(crate) fn target(&self) -> Option<&Path> {
        self.pending.as_ref().and_then(PendingPath::target)
    }

    #[cfg(unix)]
    pub(crate) fn publish_selected(self, replace: bool) -> Result<(), OutputError> {
        self.publish_selected_observed(replace, |_, _| {})
    }

    #[cfg(unix)]
    pub(crate) fn publish_selected_observed(
        self,
        replace: bool,
        mut observe: impl FnMut(&File, bool),
    ) -> Result<(), OutputError> {
        self.publish_selected_with(
            |temporary, target| {
                if replace {
                    replace_detailed(temporary, target)?;
                } else {
                    temporary.persist_noclobber(target).map_err(|error| OutputError::Io {
                        operation: IoOperation::Publish,
                        path: Some(target.to_path_buf()),
                        source: error.error,
                    })?;
                }
                Ok(target.to_path_buf())
            },
            |file, published| observe(file, published.is_some()),
        )
    }

    /// Publishes the verified stage with `publish`, which moves the stage's temporary name to the final path and
    /// returns that path. `observe` sees the original descriptor and the final path on success, `None` on failure.
    #[cfg(unix)]
    pub(crate) fn publish_selected_with(
        self,
        publish: impl FnOnce(TempPath, &Path) -> Result<PathBuf, OutputError>,
        observe: impl FnOnce(&File, Option<&Path>),
    ) -> Result<(), OutputError> {
        let Self { file, pending } = self;
        let Some(PendingPath::Selected(mut stage, target)) = pending else {
            unreachable!("selected output has a stage");
        };
        if !stage.owns_name() {
            return Err(OutputError::StageChanged(target));
        }
        let temporary = stage.path.take().expect("selected stage pathname");
        let result = publish(temporary, &target);
        observe(&file, result.as_ref().ok().map(PathBuf::as_path));
        drop(file);
        result.map(drop)
    }

    pub(crate) fn publish(self) -> Result<(), OutputError> {
        let Self { file, pending } = self;
        drop(file);
        match pending {
            Some(PendingPath::Replacement(temporary, target)) => replace_detailed(temporary, &target),
            #[cfg(unix)]
            Some(PendingPath::Selected(_, _)) => unreachable!("selected output uses checked publication"),
            Some(PendingPath::New(mut cleanup)) => {
                cleanup.0 = None;
                Ok(())
            }
            None => Ok(()),
        }
    }
}

impl Output {
    /// Output to `file`, which is expected to receive `size` bytes.
    pub fn new(file: File, size: Option<u64>) -> Output {
        if size.is_some_and(|s| s < BACKGROUND_MIN) {
            return Output { inner: Inner::Direct(file), pending: None };
        }
        let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(DEPTH);
        let (back, spare) = mpsc::channel::<Vec<u8>>();
        // the file moves to the thread only if the thread starts; otherwise it is written directly
        let slot = std::sync::Arc::new(std::sync::Mutex::new(Some(file)));
        let theirs = std::sync::Arc::clone(&slot);
        let spawned = thread::Builder::new().name("zipfast-write".into()).spawn(move || {
            let mut file = theirs.lock().ok().and_then(|mut f| f.take()).ok_or(WriterFailure::MissingFile)?;
            for mut buf in rx {
                file.write_all(&buf).map_err(WriterFailure::Io)?;
                buf.clear();
                let _ = back.send(buf);
            }
            Ok(file)
        });
        match spawned {
            Ok(handle) => Output {
                pending: None,
                inner: Inner::Background(Background {
                    tx: Some(tx),
                    spare,
                    cur: Vec::with_capacity(CHUNK),
                    handle: Some(handle),
                }),
            },
            Err(_) => {
                let file = slot.lock().ok().and_then(|mut f| f.take()).expect("the thread never started");
                Output { inner: Inner::Direct(file), pending: None }
            }
        }
    }

    pub fn created(file: File, size: Option<u64>, path: PathBuf) -> Self {
        let cleanup = Cleanup::new(&file, path);
        let mut output = Self::new(file, size);
        output.pending = Some(PendingPath::New(cleanup));
        output
    }

    pub fn staged(file: File, size: Option<u64>, temporary: TempPath, target: PathBuf) -> Self {
        let mut output = Self::new(file, size);
        output.pending = Some(PendingPath::Replacement(temporary, target));
        output
    }

    #[cfg(unix)]
    pub(crate) fn staged_direct(file: File, temporary: TempPath, target: PathBuf) -> io::Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;
        let stage = SelectedStage { path: Some(temporary), identity: (metadata.dev(), metadata.ino()) };
        Ok(Self { inner: Inner::Direct(file), pending: Some(PendingPath::Selected(stage, target)) })
    }

    pub(crate) fn write_detailed(&mut self, data: &[u8]) -> Result<(), OutputError> {
        self.write_inner(data).map_err(|failure| failure.detailed(self.pending.as_ref()))
    }

    pub fn write(&mut self, data: &[u8]) -> io::Result<()> {
        self.write_inner(data).map_err(WriterFailure::into_legacy)
    }

    fn write_inner(&mut self, mut data: &[u8]) -> Result<(), WriterFailure> {
        match &mut self.inner {
            Inner::Direct(file) => file.write_all(data).map_err(WriterFailure::Io),
            Inner::Background(b) => {
                while !data.is_empty() {
                    let take = (CHUNK - b.cur.len()).min(data.len());
                    b.cur.extend_from_slice(&data[..take]);
                    data = &data[take..];
                    if b.cur.len() == CHUNK {
                        b.send()?;
                    }
                }
                Ok(())
            }
        }
    }

    /// Waits for pending writes and hands the file and its cleanup guard to a positional writer.
    pub(crate) fn handoff_detailed(self) -> Result<WriteFile, OutputError> {
        let file = (|| match self.inner {
            Inner::Direct(file) => Ok(file),
            Inner::Background(mut b) => {
                if !b.cur.is_empty() {
                    b.send()?;
                }
                b.tx = None;
                b.join()
            }
        })()
        .map_err(|failure| failure.detailed(self.pending.as_ref()))?;
        Ok(WriteFile { file, pending: self.pending })
    }

    pub fn resume(file: WriteFile, size: Option<u64>) -> Self {
        let mut output = Self::new(file.file, size);
        output.pending = file.pending;
        output
    }

    /// Prepares metadata and publishes a verified replacement after every write has finished.
    pub fn finish(self, prepare: impl FnOnce(&File)) -> io::Result<()> {
        self.finish_detailed(prepare).map_err(OutputError::into_legacy)
    }

    pub(crate) fn finish_detailed(self, prepare: impl FnOnce(&File)) -> Result<(), OutputError> {
        let output = self.handoff_detailed()?;
        prepare(&output.file);
        output.publish()
    }
}

impl Background {
    fn send(&mut self) -> Result<(), WriterFailure> {
        let next = self.spare.try_recv().unwrap_or_else(|_| Vec::with_capacity(CHUNK));
        let full = std::mem::replace(&mut self.cur, next);
        let sent = self.tx.as_ref().is_some_and(|tx| tx.send(full).is_ok());
        if sent {
            return Ok(());
        }
        // the writer stopped: its error says why
        self.tx = None;
        Err(self.join().err().unwrap_or(WriterFailure::Stopped))
    }

    fn join(&mut self) -> Result<File, WriterFailure> {
        match self.handle.take().map(JoinHandle::join) {
            Some(Ok(result)) => result,
            Some(Err(_)) => Err(WriterFailure::Panicked),
            None => Err(WriterFailure::AlreadyStopped),
        }
    }
}

impl Drop for Background {
    /// A file given up on: whatever is queued is still written, so the caller can remove the file once this returns.
    fn drop(&mut self) {
        self.tx = None;
        let _ = self.join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn writes_everything_in_order_both_ways() {
        let dir = std::env::temp_dir().join(format!("zipfast-output-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let data: Vec<u8> = (0..(CHUNK * 3 + 12345)).map(|i| (i * 7 % 251) as u8).collect();
        for (name, size) in [("small", Some(10)), ("big", Some(data.len() as u64)), ("unknown", None)] {
            let path = dir.join(name);
            let mut out = Output::new(File::create(&path).unwrap(), size);
            for piece in data.chunks(1_000_003) {
                out.write(piece).unwrap();
            }
            out.finish(|_| {}).unwrap();
            let mut back = Vec::new();
            File::open(&path).unwrap().read_to_end(&mut back).unwrap();
            assert!(back == data, "{name}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_given_up_file_is_removed_only_while_its_name_still_holds_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("member");
        let out = Output::created(File::create(&path).unwrap(), Some(4), path.clone());
        // another member, spelled differently but folded to the same name, replaced the file meanwhile
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"other member").unwrap();
        drop(out);
        assert_eq!(fs::read(&path).unwrap(), b"other member");
        let out = Output::created(File::create(dir.path().join("own")).unwrap(), Some(4), dir.path().join("own"));
        drop(out);
        assert!(!dir.path().join("own").exists(), "an untouched file is still removed");
    }

    #[test]
    fn staged_temporaries_carry_the_zipfast_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let temp = temporary(dir.path()).unwrap();
        let name = temp.path().file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with(STAGED_PREFIX), "{name}");
    }

    #[test]
    fn a_staged_background_write_error_preserves_existing_output() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        fs::write(&target, b"original").unwrap();
        let before = fs::metadata(&target).unwrap();
        let temp = temporary(dir.path()).unwrap();
        let file = File::open(temp.path()).unwrap();
        let mut out = Output::staged(file, None, temp.into_temp_path(), target.clone());
        out.write(b"buffered bytes").unwrap();

        assert!(out.finish(|_| panic!("a failed write cannot prepare publication")).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"original");
        let after = fs::metadata(&target).unwrap();
        assert_eq!(after.modified().unwrap(), before.modified().unwrap());
        assert_eq!(after.permissions(), before.permissions());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn a_failed_staged_rename_leaves_the_target_directory_and_removes_the_temp() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        let (file, temp) = temporary(dir.path()).unwrap().into_parts();
        let mut out = Output::staged(file, Some(4), temp, target.clone());
        out.write(b"data").unwrap();

        fs::create_dir(&target).unwrap();
        fs::write(target.join("keep"), b"original").unwrap();
        assert!(out.finish(|_| {}).is_err());
        assert_eq!(fs::read(target.join("keep")).unwrap(), b"original");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn detailed_finish_distinguishes_background_write_and_publish() {
        use crate::error::{IoOperation, RarFailure};
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        fs::write(&target, b"original").unwrap();
        let temp = temporary(dir.path()).unwrap();
        let file = File::open(temp.path()).unwrap();
        let mut out = Output::staged(file, None, temp.into_temp_path(), target.clone());
        out.write(b"buffered").unwrap();
        let fault = out.finish_detailed(|_| panic!("failed write reached publication")).unwrap_err().detailed(false);
        assert!(matches!(fault.failure.as_ref(), RarFailure::Output {
            operation: IoOperation::Write, path: Some(path), source, ..
        } if path == &target && source.raw_os_error() == Some(libc::EBADF)));
        assert_eq!(fs::read(&target).unwrap(), b"original");

        fs::remove_file(&target).unwrap();
        fs::create_dir(&target).unwrap();
        fs::write(target.join("keep"), b"original").unwrap();
        let (file, temp) = temporary(dir.path()).unwrap().into_parts();
        let mut out = Output::staged(file, Some(4), temp, target.clone());
        out.write(b"data").unwrap();
        let fault = out.finish_detailed(|_| {}).unwrap_err().detailed(false);
        assert!(matches!(fault.failure.as_ref(), RarFailure::Output {
            operation: IoOperation::Publish, path: Some(path), source, ..
        } if path == &target && source.raw_os_error().is_some()));
        assert_eq!(fs::read(target.join("keep")).unwrap(), b"original");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}

/// Retryable private stage. Unlike legacy WriteFile, failed publication retains ownership.
/// Name removal is guarded; it is not a defense against a concurrent same-UID attacker.
pub(crate) struct OwnedStage {
    file: Option<File>,
    path: TempPath,
    identity: (u64, u64),
    removed: bool,
}
impl OwnedStage {
    pub(crate) fn create(parent: &Path) -> io::Result<Self> {
        // tempfile's default mode is 0600, unlike legacy extraction temporary().
        let temporary = tempfile::Builder::new().prefix(".zipfast-progressive-").tempfile_in(parent)?;
        let identity = stage_identity(&temporary.as_file().metadata()?)?;
        let (file, mut path) = temporary.into_parts();
        path.disable_cleanup(true);
        Ok(Self { file: Some(file), path, identity, removed: false })
    }
    pub(crate) fn file(&self) -> &File {
        self.file.as_ref().expect("live owned stage")
    }
    fn owns_name(&self) -> io::Result<bool> {
        owns_stage_name(&self.path, self.identity)
    }
    pub(crate) fn check(&self, len: u64) -> io::Result<()> {
        if self.removed || !self.owns_name()? {
            return Err(io::Error::other("output stage name changed"));
        }
        let metadata = self.file().metadata()?;
        if !metadata.is_file() || stage_identity(&metadata)? != self.identity || metadata.len() != len {
            return Err(io::Error::other("output stage descriptor changed"));
        }
        Ok(())
    }
    pub(crate) fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        range::read_at(self.file(), offset, buf)
    }
    pub(crate) fn write_at(&self, offset: u64, buf: &[u8]) -> io::Result<usize> {
        #[cfg(test)]
        let buf = match owned_stage_fault(OwnedOperation::Write)? {
            Some(n) => &buf[..n.min(buf.len())],
            None => buf,
        };
        range::write_at(self.file(), offset, buf)
    }
    pub(crate) fn set_len(&self, len: u64) -> io::Result<()> {
        self.file().set_len(len)
    }
    pub(crate) fn discard(&mut self) -> io::Result<()> {
        if self.removed {
            return Ok(());
        }
        if !self.owns_name()? {
            return Err(io::Error::other("output stage name changed; cleanup unconfirmed"));
        }
        #[cfg(test)]
        owned_stage_fault(OwnedOperation::Remove)?;
        fs::remove_file(&self.path)?;
        self.removed = true;
        self.file.take();
        Ok(())
    }
    /// Returns an optional cleanup error only AFTER successful no-clobber publication.
    /// Errors returned directly are prepublication and leave the stage owned.
    #[allow(dead_code)]
    pub(crate) fn publish(&mut self, target: &Path, replace: bool) -> io::Result<Option<io::Error>> {
        self.publish_observed(target, replace, |_| {})
    }
    /// The callback receives the original descriptor only after atomic publication.
    pub(crate) fn publish_observed(
        &mut self,
        target: &Path,
        replace: bool,
        published: impl FnOnce(&File),
    ) -> io::Result<Option<io::Error>> {
        if self.removed || !self.owns_name()? {
            return Err(io::Error::other("output stage name changed"));
        }
        match fs::symlink_metadata(target) {
            Ok(m) if m.file_type().is_symlink() => return Err(io::ErrorKind::AlreadyExists.into()),
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        #[cfg(test)]
        owned_stage_fault(OwnedOperation::Publish)?;
        if replace {
            fs::rename(&self.path, target)?;
            published(self.file());
            self.removed = true;
            self.file.take();
            Ok(None)
        } else {
            // hard_link is an atomic no-clobber publication on this same filesystem.
            fs::hard_link(&self.path, target)?;
            published(self.file());
            let cleanup = self.discard().err();
            Ok(cleanup)
        }
    }
}
fn stage_identity(meta: &fs::Metadata) -> io::Result<(u64, u64)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok((meta.dev(), meta.ino()))
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        Err(io::ErrorKind::Unsupported.into())
    }
}
impl Drop for OwnedStage {
    fn drop(&mut self) {
        if !self.removed {
            let _ = self.discard();
        }
    }
}
#[cfg(test)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum OwnedOperation {
    Write,
    Publish,
    Remove,
}
#[cfg(test)]
type OwnedFault = (OwnedOperation, Result<Option<usize>, i32>);
#[cfg(test)]
thread_local! {
    pub(crate) static OWNED_STAGE_FAULT: std::cell::RefCell<Option<OwnedFault>> = const {std::cell::RefCell::new(None)};
}
#[cfg(test)]
fn owned_stage_fault(operation: OwnedOperation) -> io::Result<Option<usize>> {
    OWNED_STAGE_FAULT.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.as_ref().is_some_and(|(op, _)| *op == operation) {
            slot.take().expect("injected native fault").1.map_err(io::Error::from_raw_os_error)
        } else {
            Ok(None)
        }
    })
}

fn owns_stage_name(path: &Path, identity: (u64, u64)) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(meta) => Ok(meta.is_file() && stage_identity(&meta)? == identity),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

pub(crate) mod range;
