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

//! Library-owned native files that another process is still writing or appending (`docs/growing-volumes.md`).
//!
//! [`GrowingFileVolumes`] finds each volume next to the first one, waits while a volume is absent, and declares a
//! complete native protection inventory naming every volume that exists so far. [`GrowingFileSource`] reads one
//! such file: bytes past the current end answer `NotYet`, and bytes already read are bound by identity, a
//! non-decreasing length and sampled block checksums, so an in-place rewrite, a truncation or a replacement fails
//! closed with `SourceChanged`.
use super::{
    FailureKind, InputOperation, ProgressiveFailure, ProgressiveResult, ProtectedPath, ProtectedVolume,
    ProtectionDeclaration, ProtectionInventory, RangeRead, RangeSource, SourceId, SourceInfo, SourceLength,
    VolumeAnswer, VolumeBacking, VolumeRequest, VolumeSource,
};
use std::{
    ffi::{OsStr, OsString},
    fmt,
    fs::{self, File, Metadata},
    io,
    path::{Component, Path, PathBuf},
    sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError},
    task::{Context, Waker},
    time::{Duration, Instant},
};

/// Tuning for [`GrowingFileVolumes`] and [`GrowingFileSource`].
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct GrowingOptions {
    /// How long after a `Wait` or `NotYet` the provider wakes the session to look again. `None` schedules no
    /// periodic wake: the caller wakes it with [`GrowthNotifier::notify`] (for example from a file-system watcher),
    /// and the idle deadline still wakes it once so a stall is reported instead of hanging.
    pub poll_interval: Option<Duration>,
    /// How long the awaited file may stay absent, or the file being read stay at the same length, before the
    /// provider gives up: an absent volume answers `Missing` (`FailureKind::MissingVolume`), and a stalled read
    /// fails with `FailureKind::IdleTimeout`.
    pub idle_timeout: Duration,
    /// Size of the blocks whose CRC-32 the source remembers for bytes it has served. At least 1.
    pub check_block: u32,
    /// Re-read and compare one remembered block for every `check_every` blocks served (and one more at every
    /// protection query). `0` disables sampling; re-reads of served bytes are still compared.
    pub check_every: u32,
}
impl Default for GrowingOptions {
    fn default() -> Self {
        Self {
            poll_interval: Some(Duration::from_millis(250)),
            idle_timeout: Duration::from_secs(600),
            check_block: 64 * 1024,
            check_every: 8,
        }
    }
}

fn input(operation: InputOperation, cause: io::Error) -> ProgressiveFailure {
    ProgressiveFailure::new(FailureKind::Input { operation, cause })
}
fn changed() -> ProgressiveFailure {
    ProgressiveFailure::new(FailureKind::SourceChanged)
}
fn contract() -> ProgressiveFailure {
    ProgressiveFailure::new(FailureKind::SourceContract)
}
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

type Identity = (u64, u64);
fn identity(meta: &Metadata) -> ProgressiveResult<Identity> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok((meta.dev(), meta.ino()))
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        Err(input(InputOperation::Metadata, io::ErrorKind::Unsupported.into()))
    }
}
fn pread(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        loop {
            match file.read_at(buf, offset) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                result => return result,
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (file, buf, offset);
        Err(io::ErrorKind::Unsupported.into())
    }
}
/// Fills `buf` unless the file ends first; returns the bytes read.
fn pread_full(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    let mut done = 0;
    while done < buf.len() {
        let n = pread(file, &mut buf[done..], offset + done as u64)?;
        if n == 0 {
            break;
        }
        done += n;
    }
    Ok(done)
}
/// Opens without following a final symlink and without blocking on a FIFO.
fn open_nofollow(path: &Path) -> io::Result<File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_NOCTTY);
    }
    options.open(path)
}
/// `name` must be one plain path component: volume names never leave the first volume's directory.
fn plain_name(name: &OsStr) -> ProgressiveResult<()> {
    let mut components = Path::new(name).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(n)), None) if n == name => Ok(()),
        _ => Err(contract()),
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Waking without a runtime: one lazily spawned timer thread per provider, parked on a condition variable.

#[derive(Default)]
struct PacerState {
    parked: Vec<(Waker, Option<Instant>)>,
    thread: bool,
    shutdown: bool,
}
#[derive(Default)]
struct PacerShared {
    state: Mutex<PacerState>,
    cv: Condvar,
}
impl PacerShared {
    fn wake_all(&self) {
        let parked = std::mem::take(&mut lock(&self.state).parked);
        // Waker code runs outside the lock.
        for (waker, _) in parked {
            waker.wake();
        }
    }
}
/// Owner of the timer thread, shared by a provider and the sources it opened; the thread exits with the last one.
struct Pacer(Arc<PacerShared>);
impl Drop for Pacer {
    fn drop(&mut self) {
        let parked = {
            let mut state = lock(&self.0.state);
            state.shutdown = true;
            std::mem::take(&mut state.parked)
        };
        self.0.cv.notify_all();
        drop(parked);
    }
}
impl Pacer {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(PacerShared::default())))
    }
    /// Keeps `waker` until `deadline` (when the timer wakes it) or a [`GrowthNotifier::notify`].
    fn park(&self, waker: &Waker, deadline: Option<Instant>) -> ProgressiveResult<()> {
        let incoming = waker.clone();
        let (previous, spawn) = {
            let mut state = lock(&self.0.state);
            let previous = match state.parked.iter().position(|(w, _)| w.will_wake(&incoming)) {
                Some(i) => Some(std::mem::replace(&mut state.parked[i], (incoming, deadline))),
                None => {
                    state.parked.push((incoming, deadline));
                    None
                }
            };
            let spawn = deadline.is_some() && !state.thread;
            state.thread |= spawn;
            (previous, spawn)
        };
        drop(previous);
        if spawn {
            let shared = self.0.clone();
            if let Err(cause) =
                std::thread::Builder::new().name("zipfast-growing-wake".into()).spawn(move || run_pacer(&shared))
            {
                lock(&self.0.state).thread = false;
                return Err(input(InputOperation::Read, cause));
            }
        }
        self.0.cv.notify_all();
        Ok(())
    }
}
fn run_pacer(shared: &PacerShared) {
    let mut state = lock(&shared.state);
    loop {
        if state.shutdown {
            state.thread = false;
            return;
        }
        let now = Instant::now();
        let mut due = Vec::new();
        let mut i = 0;
        while i < state.parked.len() {
            if state.parked[i].1.is_some_and(|deadline| deadline <= now) {
                due.push(state.parked.swap_remove(i).0);
            } else {
                i += 1;
            }
        }
        if !due.is_empty() {
            drop(state);
            for waker in due {
                waker.wake();
            }
            state = lock(&shared.state);
            continue;
        }
        state = match state.parked.iter().filter_map(|(_, deadline)| *deadline).min() {
            Some(deadline) => shared.cv.wait_timeout(state, deadline - now).unwrap_or_else(PoisonError::into_inner).0,
            None => shared.cv.wait(state).unwrap_or_else(PoisonError::into_inner),
        };
    }
}

/// Wakes a parked session at once, instead of at the next poll interval. Call it from a file-system watcher when
/// a file in the set's directory is created or grows. Spurious notifications are harmless.
#[derive(Clone)]
pub struct GrowthNotifier(Arc<PacerShared>);
impl GrowthNotifier {
    pub fn notify(&self) {
        self.0.wake_all();
    }
}
impl fmt::Debug for GrowthNotifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrowthNotifier").finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Prefix stability: block CRC-32s of every byte served, sampled re-reads, and a non-decreasing length.

struct Ledger {
    /// Longest length observed; a shorter file is a truncation.
    max_len: u64,
    block: u64,
    every: u64,
    /// CRC-32 of each complete block of `[0, crcs.len() * block)`.
    crcs: Vec<u32>,
    partial: crc32fast::Hasher,
    partial_len: u64,
    credit: u64,
    /// Next block of the current sweep, and where the sweep ends: the remembered blocks when it began.
    next: usize,
    sweep_end: usize,
}
impl Ledger {
    fn new(max_len: u64, options: &GrowingOptions) -> Self {
        Self {
            max_len,
            block: u64::from(options.check_block.max(1)),
            every: u64::from(options.check_every),
            crcs: Vec::new(),
            partial: crc32fast::Hasher::new(),
            partial_len: 0,
            credit: 0,
            next: 0,
            sweep_end: 0,
        }
    }
    fn complete(&self) -> u64 {
        self.crcs.len() as u64 * self.block
    }
    fn frontier(&self) -> u64 {
        self.complete() + self.partial_len
    }
    fn hash(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let take = ((self.block - self.partial_len) as usize).min(bytes.len());
            self.partial.update(&bytes[..take]);
            self.partial_len += take as u64;
            bytes = &bytes[take..];
            if self.partial_len == self.block {
                self.crcs.push(std::mem::replace(&mut self.partial, crc32fast::Hasher::new()).finalize());
                self.partial_len = 0;
            }
        }
    }
    /// Remembers `bytes`, served at `offset`. A gap before them (bytes never served) is hashed from the file.
    fn absorb(&mut self, file: &File, offset: u64, bytes: &[u8], scratch: &mut Vec<u8>) -> ProgressiveResult<()> {
        let end = offset + bytes.len() as u64;
        let mut frontier = self.frontier();
        if end <= frontier {
            return Ok(());
        }
        while frontier < offset {
            let n = (offset - frontier).min(self.block) as usize;
            scratch.resize(n, 0);
            let got = pread_full(file, &mut scratch[..n], frontier).map_err(|e| input(InputOperation::Read, e))?;
            if got < n {
                return Err(changed());
            }
            self.hash(&scratch[..n]);
            frontier += n as u64;
        }
        self.hash(&bytes[(frontier - offset) as usize..]);
        Ok(())
    }
    fn verify_block(&self, file: &File, index: usize, scratch: &mut Vec<u8>) -> ProgressiveResult<()> {
        let n = self.block as usize;
        scratch.resize(n, 0);
        let at = index as u64 * self.block;
        let got = pread_full(file, &mut scratch[..n], at).map_err(|e| input(InputOperation::Read, e))?;
        if got < n || crc32fast::hash(&scratch[..n]) != self.crcs[index] {
            return Err(changed());
        }
        Ok(())
    }
    /// Compares every remembered block that `[offset, offset + bytes.len())` touches: from `bytes` when the read
    /// covers the whole block, otherwise by reading the block again.
    fn verify_overlap(&self, file: &File, offset: u64, bytes: &[u8], scratch: &mut Vec<u8>) -> ProgressiveResult<()> {
        let end = (offset + bytes.len() as u64).min(self.complete());
        if offset >= end {
            return Ok(());
        }
        for index in (offset / self.block) as usize..=((end - 1) / self.block) as usize {
            let start = index as u64 * self.block;
            if start >= offset && start + self.block <= offset + bytes.len() as u64 {
                let from = (start - offset) as usize;
                if crc32fast::hash(&bytes[from..from + self.block as usize]) != self.crcs[index] {
                    return Err(changed());
                }
            } else {
                self.verify_block(file, index, scratch)?;
            }
        }
        Ok(())
    }
    /// Re-reads one remembered block per `every` blocks of credit, at most two per call.
    fn sample(&mut self, file: &File, credit: u64, scratch: &mut Vec<u8>) -> ProgressiveResult<()> {
        if self.every == 0 || self.crcs.is_empty() {
            return Ok(());
        }
        let unit = self.block.saturating_mul(self.every);
        self.credit = self.credit.saturating_add(credit);
        for _ in 0..2 {
            if self.credit < unit {
                break;
            }
            self.credit -= unit;
            self.check_next(file, scratch)?;
        }
        self.credit = self.credit.min(unit);
        Ok(())
    }
    /// Re-reads the next block of the current sweep. A sweep covers the blocks remembered when it began, so it
    /// finishes even while the file keeps growing, and the next sweep starts again from block 0.
    fn check_next(&mut self, file: &File, scratch: &mut Vec<u8>) -> ProgressiveResult<()> {
        if self.next >= self.sweep_end {
            self.next = 0;
            self.sweep_end = self.crcs.len();
        }
        if self.sweep_end == 0 {
            return Ok(());
        }
        let index = self.next;
        self.next += 1;
        self.verify_block(file, index, scratch)
    }
}

/// One file of the set, shared by the provider's declaration and every source opened on it.
struct VolumeState {
    name: OsString,
    path: PathBuf,
    file: Arc<File>,
    identity: Identity,
    ledger: Mutex<Ledger>,
}
impl VolumeState {
    /// Opens `path` without following a final symlink; `None` while it does not exist.
    fn open(name: OsString, path: PathBuf, options: &GrowingOptions) -> ProgressiveResult<Option<Self>> {
        let file = match open_nofollow(&path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(input(InputOperation::Open, e)),
        };
        let meta = file.metadata().map_err(|e| input(InputOperation::Metadata, e))?;
        if !meta.is_file() {
            return Err(contract());
        }
        let id = identity(&meta)?;
        let bound = fs::symlink_metadata(&path).map_err(|e| input(InputOperation::Metadata, e))?;
        if !bound.is_file() || identity(&bound)? != id {
            return Err(changed());
        }
        let ledger = Mutex::new(Ledger::new(meta.len(), options));
        Ok(Some(Self { name, path, file: Arc::new(file), identity: id, ledger }))
    }
    /// The current length after checking that the handle is still a regular file at the bound path and that the
    /// file has not shrunk. Returns whether it grew.
    fn observe(&self) -> ProgressiveResult<(u64, bool)> {
        let meta = self.file.metadata().map_err(|e| input(InputOperation::Metadata, e))?;
        if !meta.is_file() || identity(&meta)? != self.identity {
            return Err(changed());
        }
        match fs::symlink_metadata(&self.path) {
            Ok(bound) if bound.is_file() && identity(&bound)? == self.identity => {}
            Ok(_) => return Err(changed()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(changed()),
            Err(e) => return Err(input(InputOperation::Metadata, e)),
        }
        let len = meta.len();
        let mut ledger = lock(&self.ledger);
        if len < ledger.max_len {
            return Err(changed());
        }
        let grew = len > ledger.max_len;
        ledger.max_len = len;
        Ok((len, grew))
    }
}

/// The wake time for a wait that started (or last saw progress) at `since`.
fn deadline(options: &GrowingOptions, now: Instant, since: Instant) -> Option<Instant> {
    let idle = since.checked_add(options.idle_timeout);
    let poll = options.poll_interval.and_then(|p| now.checked_add(p));
    match (idle, poll) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// A native file another process may still be appending to.
///
/// [`RangeSource::info`] reports `SourceLength::Advertised(u64::MAX)` (the EOF is not known) and the observed
/// length as `extent`. A read past the current end answers `NotYet` and schedules a wake after the poll interval;
/// after the idle timeout without growth it fails with `FailureKind::IdleTimeout`. Every read re-checks that the
/// handle is still the regular file bound at the path and that the length never decreased, compares any re-read of
/// served bytes with their remembered block CRC-32s, and samples earlier blocks; any difference is
/// `SourceChanged`.
pub struct GrowingFileSource {
    state: Arc<VolumeState>,
    options: GrowingOptions,
    pacer: Arc<Pacer>,
    extent: u64,
    last_progress: Instant,
    scratch: Vec<u8>,
}
impl GrowingFileSource {
    /// Opens one growing file outside a volume set; the file must exist.
    pub fn open(path: &Path, options: GrowingOptions) -> ProgressiveResult<Self> {
        let path = std::path::absolute(path).map_err(|e| input(InputOperation::Open, e))?;
        let name = path.file_name().ok_or_else(contract)?.to_owned();
        let state = VolumeState::open(name, path, &options)?
            .ok_or_else(|| input(InputOperation::Open, io::ErrorKind::NotFound.into()))?;
        Ok(Self::with_state(Arc::new(state), options, Pacer::new()))
    }
    fn with_state(state: Arc<VolumeState>, options: GrowingOptions, pacer: Arc<Pacer>) -> Self {
        let extent = lock(&state.ledger).max_len;
        Self { state, options, pacer, extent, last_progress: Instant::now(), scratch: Vec::new() }
    }
    /// Wakes this source's parked reads at once; see [`GrowthNotifier`].
    pub fn notifier(&self) -> GrowthNotifier {
        GrowthNotifier(self.pacer.0.clone())
    }
    pub fn path(&self) -> &Path {
        &self.state.path
    }
}
impl fmt::Debug for GrowingFileSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrowingFileSource").field("path", &self.state.path).field("extent", &self.extent).finish()
    }
}
impl RangeSource for GrowingFileSource {
    fn info(&self) -> SourceInfo {
        let (device, inode) = self.state.identity;
        SourceInfo {
            id: SourceId((u128::from(device) << 64) | u128::from(inode)),
            generation: 0,
            extent: self.extent,
            length: SourceLength::Advertised(u64::MAX),
        }
    }
    fn backing_files(&self) -> &[File] {
        std::slice::from_ref(self.state.file.as_ref())
    }
    fn read_at(&mut self, offset: u64, buf: &mut [u8], cx: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
        let now = Instant::now();
        let (len, grew) = self.state.observe()?;
        if grew || len > self.extent {
            self.last_progress = now;
        }
        self.extent = self.extent.max(len);
        if offset >= len || buf.is_empty() {
            let idle = now.saturating_duration_since(self.last_progress);
            if idle >= self.options.idle_timeout {
                let mut failure = ProgressiveFailure::new(FailureKind::IdleTimeout { idle: self.options.idle_timeout });
                failure.context.packed_offset = Some(offset);
                return Err(failure);
            }
            self.pacer.park(cx.waker(), deadline(&self.options, now, self.last_progress))?;
            return Ok(RangeRead::NotYet);
        }
        let n = (len - offset).min(buf.len() as u64) as usize;
        let count = pread(&self.state.file, &mut buf[..n], offset).map_err(|cause| {
            let mut e = input(InputOperation::Read, cause);
            e.context.packed_offset = Some(offset);
            e
        })?;
        if count == 0 {
            // The file ended before its observed length: a truncation, unless a replacement is reported first.
            self.state.observe()?;
            return Err(changed());
        }
        {
            let mut ledger = lock(&self.state.ledger);
            let file = self.state.file.as_ref();
            ledger.verify_overlap(file, offset, &buf[..count], &mut self.scratch)?;
            let before = ledger.frontier();
            ledger.absorb(file, offset, &buf[..count], &mut self.scratch)?;
            let served = ledger.frontier() - before;
            ledger.sample(file, served, &mut self.scratch)?;
        }
        // The bytes were read from the file still bound at the path, at a length that never decreased.
        let (len, _) = self.state.observe()?;
        self.extent = self.extent.max(len);
        self.last_progress = now;
        Ok(RangeRead::Filled { count })
    }
}

/// A volume set whose files another process (a downloader, say) is still creating and appending.
///
/// Each volume's path is the session's [`VolumeRequest::expected`] name joined to the first volume's directory.
/// A volume that does not exist yet answers `Wait` (woken after the poll interval or by a [`GrowthNotifier`]),
/// and `Missing` once it has stayed absent for the idle timeout. Its protection declaration is Complete and native:
/// it names every volume that exists so far, each bound to the handle the provider holds, and grows with a higher
/// epoch as later volumes appear, so verified members publish Strict under the same alias and target guards as
/// [`super::ImmutableFileSource`]. An ordinary session accepts this growth only from this library-owned provider,
/// and refuses (`UnsafePath`) a new volume that is an output file the session created.
///
/// Pass [`Self::first_name`] as `ProgressiveOptions::first_name`.
///
/// ```no_run
/// use std::{task::{Context, Poll}, time::Duration};
/// use zipfast::progressive::{GrowingFileVolumes, GrowingOptions, ProgressiveOptions, ProgressiveSession};
///
/// let mut growing = GrowingOptions::default();
/// growing.idle_timeout = Duration::from_secs(120);
/// let volumes = GrowingFileVolumes::new("/downloads/show.part01.rar", growing)?;
/// let notifier = volumes.notifier(); // hand to a file-system watcher, if there is one
/// let extract = zipfast::extract::Options {
///     mode: zipfast::extract::Mode::Extract,
///     dest: "/media/show".into(),
///     overwrite: zipfast::extract::Overwrite::Skip,
///     flatten: false,
///     threads: None,
///     protected_paths: Default::default(),
///     parallel_min: None,
///     select: None,
///     windows_safe_names: false,
///     special_entries: Default::default(),
///     fallback_mtime: None,
///     compressed_tar: Default::default(),
///     version_naming: Default::default(),
///     preexisting_links: Default::default(),
///     refused_link_placeholder: false,
///     restart_from_first_volume: false,
///     replace_placed_links: false,
///     keep_broken: false,
///     attempt_continued_members: false,
///     encrypted_links: Default::default(),
///     damaged_input: Default::default(),
///     unsupported_filters: Default::default(),
///     unverified_output: Default::default(),
///     salvage_truncated_zip: false,
///     seven_zip_strict: false,
///     unix_modes: Default::default(),
///     backslashes: Default::default(),
/// };
/// let options = ProgressiveOptions::new(extract, volumes.first_name().to_owned());
/// let mut session = ProgressiveSession::new(Box::new(volumes), options)?;
/// # let waker = std::task::Waker::noop();
/// // Poll with your task's waker; the provider wakes it when there is more to read.
/// while let Poll::Ready(Ok(Some(_event))) = session.poll_event(&mut Context::from_waker(&waker)) {}
/// # drop(notifier);
/// # Ok::<(), zipfast::progressive::ProgressiveFailure>(())
/// ```
pub struct GrowingFileVolumes {
    dir: PathBuf,
    first: OsString,
    options: GrowingOptions,
    volumes: Vec<Arc<VolumeState>>,
    epoch: u64,
    /// Volumes named by the last declaration handed out.
    published: usize,
    waiting: Option<(u32, Instant)>,
    pacer: Arc<Pacer>,
    next_check: usize,
    scratch: Vec<u8>,
}
impl GrowingFileVolumes {
    /// `first` is the first volume's path; it need not exist yet.
    pub fn new(first: impl AsRef<Path>, options: GrowingOptions) -> ProgressiveResult<Self> {
        let first = std::path::absolute(first.as_ref()).map_err(|e| input(InputOperation::Open, e))?;
        let name = first.file_name().ok_or_else(contract)?.to_owned();
        plain_name(&name)?;
        let dir = first.parent().ok_or_else(contract)?.to_path_buf();
        Ok(Self {
            dir,
            first: name,
            options,
            volumes: Vec::new(),
            epoch: 0,
            published: 0,
            waiting: None,
            pacer: Pacer::new(),
            next_check: 0,
            scratch: Vec::new(),
        })
    }
    /// The first volume's file name, which `ProgressiveOptions::first_name` must equal.
    pub fn first_name(&self) -> &OsStr {
        &self.first
    }
    pub fn directory(&self) -> &Path {
        &self.dir
    }
    /// Wakes a parked session at once; see [`GrowthNotifier`].
    pub fn notifier(&self) -> GrowthNotifier {
        GrowthNotifier(self.pacer.0.clone())
    }
    /// The name volume `self.volumes.len()` must have: the session derives it the same way.
    fn next_name(&self) -> Option<OsString> {
        match self.volumes.last() {
            None => Some(self.first.clone()),
            Some(last) => crate::volume::next_volume_os(&last.name),
        }
    }
    /// Re-checks one declared volume per call, in rotation (identity, bound path, no truncation, and one sampled
    /// block when sampling is on), so a protection query costs O(1) whatever the number of volumes. Every declared
    /// volume is re-checked once per `volumes.len()` queries, and all of them whenever a new volume is declared.
    fn check_declared(&mut self) -> ProgressiveResult<()> {
        if self.volumes.is_empty() {
            return Ok(());
        }
        let index = self.next_check % self.volumes.len();
        self.next_check = (index + 1) % self.volumes.len();
        let volume = &self.volumes[index];
        volume.observe()?;
        if self.options.check_every != 0 {
            lock(&volume.ledger).check_next(&volume.file, &mut self.scratch)?;
        }
        Ok(())
    }
    /// Declares every further volume that now exists, in order.
    fn discover(&mut self) -> ProgressiveResult<()> {
        let mut grew = false;
        while let Some(name) = self.next_name() {
            plain_name(&name)?;
            let path = self.dir.join(&name);
            let Some(state) = VolumeState::open(name, path, &self.options)? else { break };
            if self.volumes.iter().any(|v| v.identity == state.identity) {
                return Err(contract());
            }
            self.volumes.push(Arc::new(state));
            grew = true;
        }
        if grew {
            self.epoch = self.epoch.checked_add(1).ok_or_else(contract)?;
            for volume in &self.volumes {
                volume.observe()?;
            }
        }
        Ok(())
    }
}
impl fmt::Debug for GrowingFileVolumes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrowingFileVolumes")
            .field("dir", &self.dir)
            .field("first", &self.first)
            .field("declared", &self.volumes.len())
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}
impl VolumeSource for GrowingFileVolumes {
    fn volume(&mut self, request: &VolumeRequest, cx: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
        plain_name(&request.expected)?;
        let index = request.index as usize;
        if index < self.published {
            let state = &self.volumes[index];
            if state.name != request.expected {
                return Err(contract());
            }
            self.waiting = None;
            return Ok(VolumeAnswer::Ready(Box::new(GrowingFileSource::with_state(
                state.clone(),
                self.options.clone(),
                self.pacer.clone(),
            ))));
        }
        // Volumes are requested in order, each after the one before was declared and admitted.
        if index != self.volumes.len() || self.next_name().as_deref() != Some(request.expected.as_os_str()) {
            return Err(contract());
        }
        let path = self.dir.join(&request.expected);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                // It exists but is not declared yet: the session reads the declaration again before asking for
                // the volume, and that declaration names it (or refuses a file that is not a regular one).
                self.waiting = None;
                cx.waker().wake_by_ref();
                Ok(VolumeAnswer::Wait)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let now = Instant::now();
                let since = match self.waiting {
                    Some((i, since)) if i == request.index => since,
                    _ => {
                        self.waiting = Some((request.index, now));
                        now
                    }
                };
                if now.saturating_duration_since(since) >= self.options.idle_timeout {
                    return Ok(VolumeAnswer::Missing);
                }
                self.pacer.park(cx.waker(), deadline(&self.options, now, since))?;
                Ok(VolumeAnswer::Wait)
            }
            Err(e) => Err(input(InputOperation::Metadata, e)),
        }
    }
    fn protection(&mut self) -> ProgressiveResult<ProtectionDeclaration> {
        self.check_declared()?;
        self.discover()?;
        self.published = self.volumes.len();
        if self.volumes.is_empty() {
            return Ok(ProtectionDeclaration::Opaque);
        }
        Ok(ProtectionDeclaration::Complete {
            epoch: self.epoch,
            inventory: ProtectionInventory {
                volumes: self
                    .volumes
                    .iter()
                    .enumerate()
                    .map(|(index, volume)| ProtectedVolume {
                        index: index as u32,
                        name: volume.name.clone(),
                        backing: VolumeBacking::Native(vec![ProtectedPath {
                            path: volume.path.clone(),
                            file: Some(volume.file.clone()),
                        }]),
                    })
                    .collect(),
                auxiliary_paths: Vec::new(),
            },
        })
    }
    fn extends_protection(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(block: u32, every: u32) -> GrowingOptions {
        GrowingOptions { check_block: block, check_every: every, ..GrowingOptions::default() }
    }

    #[test]
    fn names_stay_in_the_first_volumes_directory() {
        for bad in ["", "..", ".", "a/b", "/abs", "a/"] {
            assert!(plain_name(OsStr::new(bad)).is_err(), "{bad:?}");
        }
        plain_name(OsStr::new("a.part02.rar")).unwrap();
    }

    #[test]
    fn ledger_detects_a_rewritten_block_and_tolerates_appends() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v");
        fs::write(&path, b"0123456789abcdef").unwrap();
        let file = File::open(&path).unwrap();
        let mut ledger = Ledger::new(16, &options(4, 1));
        let mut scratch = Vec::new();
        ledger.absorb(&file, 0, b"0123456", &mut scratch).unwrap();
        // A gap is hashed from the file.
        ledger.absorb(&file, 10, b"ab", &mut scratch).unwrap();
        assert_eq!(ledger.crcs.len(), 3);
        for _ in 0..3 {
            ledger.check_next(&file, &mut scratch).unwrap();
        }
        ledger.verify_overlap(&file, 0, b"01234567", &mut scratch).unwrap();
        assert!(ledger.verify_overlap(&file, 0, b"0123x567", &mut scratch).is_err());
        let mut append = fs::OpenOptions::new().append(true).open(&path).unwrap();
        std::io::Write::write_all(&mut append, b"more").unwrap();
        ledger.check_next(&file, &mut scratch).unwrap();
        let writer = fs::OpenOptions::new().write(true).open(&path).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::FileExt::write_at(&writer, b"X", 5).unwrap();
        let failed = (0..3).any(|_| ledger.check_next(&file, &mut scratch).is_err());
        assert!(failed, "a rewrite of a remembered block must be found by the rotation");
    }

    #[test]
    fn pacer_wakes_after_its_deadline_and_on_notify() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Count(AtomicUsize);
        impl std::task::Wake for Count {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let count = Arc::new(Count(AtomicUsize::new(0)));
        let waker = Waker::from(count.clone());
        let pacer = Pacer::new();
        pacer.park(&waker, Some(Instant::now() + Duration::from_millis(20))).unwrap();
        let start = Instant::now();
        while count.0.load(Ordering::SeqCst) == 0 {
            assert!(start.elapsed() < Duration::from_secs(10), "timer never fired");
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(start.elapsed() >= Duration::from_millis(10));
        pacer.park(&waker, None).unwrap();
        GrowthNotifier(pacer.0.clone()).notify();
        assert_eq!(count.0.load(Ordering::SeqCst), 2);
        // Re-parking the same waker replaces its deadline instead of queueing a second wake.
        pacer.park(&waker, Some(Instant::now() + Duration::from_secs(3600))).unwrap();
        pacer.park(&waker, Some(Instant::now() + Duration::from_secs(3600))).unwrap();
        assert_eq!(lock(&pacer.0.state).parked.len(), 1);
    }

    /// Bookkeeping charged per wake while waiting for volume `declared`, after `declared` volumes were admitted.
    fn wait_wake_cost(declared: usize) -> (u64, u64) {
        use super::super::{ProgressiveLimits, Resource, SessionControl, source::SourceDriver};
        let dir = tempfile::tempdir().unwrap();
        let mut name = OsString::from("w.part01.rar");
        let mut names = Vec::new();
        for _ in 0..declared {
            fs::write(dir.path().join(&name), b"x").unwrap();
            names.push(name.clone());
            name = crate::volume::next_volume_os(&name).unwrap();
        }
        names.push(name);
        let growing = GrowingOptions { poll_interval: None, ..GrowingOptions::default() };
        let provider = GrowingFileVolumes::new(dir.path().join(&names[0]), growing).unwrap();
        let notifier = provider.notifier();
        let mut driver = SourceDriver::new(
            Box::new(provider),
            names[0].clone(),
            ProgressiveLimits::default(),
            SessionControl::default(),
        )
        .unwrap();
        let usage = driver.shared_usage();
        let mut cx = Context::from_waker(Waker::noop());
        let mut buf = [0u8; 1];
        for (index, name) in names.iter().enumerate() {
            if index > 0 {
                driver.select_volume(VolumeRequest { index: index as u32, expected: name.clone() }).unwrap();
            }
            if index < declared {
                assert!(driver.poll_step(&mut cx, &mut buf).is_ready(), "volume {index} opens");
            }
        }
        assert!(driver.poll_step(&mut cx, &mut buf).is_pending(), "the absent volume waits");
        let (bookkeeping, requests) = (usage.used(Resource::SourceBookkeeping), usage.used(Resource::SourceRequests));
        const WAKES: u64 = 100;
        for _ in 0..WAKES {
            notifier.notify();
            assert!(driver.poll_step(&mut cx, &mut buf).is_pending());
        }
        (
            (usage.used(Resource::SourceBookkeeping) - bookkeeping) / WAKES,
            (usage.used(Resource::SourceRequests) - requests) / WAKES,
        )
    }

    #[test]
    fn an_unchanged_wait_wake_costs_the_same_whatever_the_declared_volume_count() {
        let (small, small_requests) = wait_wake_cost(2);
        let (large, large_requests) = wait_wake_cost(40);
        eprintln!("per wake: bookkeeping {small} / {large}, requests {small_requests} / {large_requests}");
        assert_eq!(small, large, "per-wake bookkeeping must not grow with the declared volumes");
        assert_eq!(small_requests, large_requests);
        assert!(small <= 16, "{small} bookkeeping units per wake");
    }
}
