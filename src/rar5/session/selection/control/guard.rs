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

use super::*;
use crate::rar5::session::selection::extraction::PlacedLink;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::mem::MaybeUninit;
use std::ops::Range;
use std::os::{fd::AsRawFd, unix::ffi::OsStrExt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Stamp {
    pub dev: u64,
    pub ino: u64,
    pub len: u64,
    pub mtime: (i64, i64),
    pub ctime: (i64, i64),
    pub mode: libc::mode_t,
    pub links: u64,
}
impl Stamp {
    fn identity(self) -> (u64, u64) {
        (self.dev, self.ino)
    }
    fn directory(self) -> bool {
        self.mode & libc::S_IFMT == libc::S_IFDIR
    }
    fn regular(self) -> bool {
        self.mode & libc::S_IFMT == libc::S_IFREG
    }
    pub(super) fn source(self) -> SourceStamp {
        SourceStamp { device: self.dev, inode: self.ino, len: self.len, mtime: self.mtime, ctime: self.ctime }
    }
}
fn convert(s: libc::stat) -> io::Result<Stamp> {
    #[cfg(target_os = "macos")]
    let (mtime, ctime) = ((s.st_mtime, s.st_mtime_nsec), (s.st_ctime, s.st_ctime_nsec));
    #[cfg(not(target_os = "macos"))]
    let (mtime, ctime) = ((s.st_mtime, s.st_mtime_nsec), (s.st_ctime, s.st_ctime_nsec));
    #[cfg(target_os = "macos")]
    let device = s.st_dev as u64;
    #[cfg(not(target_os = "macos"))]
    let device = s.st_dev;
    #[allow(
        clippy::useless_conversion,
        reason = "libc st_nlink is u16 on macOS, u32 on Linux ARM64 and u64 on Linux AMD64"
    )]
    let links = u64::from(s.st_nlink);
    Ok(Stamp {
        links,
        dev: device,
        ino: s.st_ino,
        len: u64::try_from(s.st_size).map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))?,
        mtime,
        ctime,
        mode: s.st_mode,
    })
}
pub(super) fn stat_fd(file: &File) -> io::Result<Stamp> {
    let mut out = MaybeUninit::uninit();
    if unsafe { libc::fstat(file.as_raw_fd(), out.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    convert(unsafe { out.assume_init() })
}
pub(super) fn stat_at(fd: libc::c_int, path: &[u8]) -> io::Result<Option<Stamp>> {
    stat_at_flags(fd, path, libc::AT_SYMLINK_NOFOLLOW)
}
pub(super) fn stat_at_flags(fd: libc::c_int, path: &[u8], flags: libc::c_int) -> io::Result<Option<Stamp>> {
    stat_at_probe(fd, path, flags, true)
}
/// Whether the symbolic link at `path` (NUL-terminated, relative to `fd`) reads back as exactly `expected`, read
/// with `readlinkat` into a buffer on the stack. A target longer than any link placed here never matches.
fn link_reads_at(fd: libc::c_int, path: &[u8], expected: &[u8]) -> io::Result<bool> {
    let mut buf = [0u8; crate::extract::link::MAX_TARGET as usize + 1];
    let n = unsafe { libc::readlinkat(fd, path.as_ptr().cast(), buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    // a full buffer may have been cut short, so it never matches
    let n = n as usize;
    Ok(n < buf.len() && buf[..n] == *expected)
}
fn stat_at_probe(fd: libc::c_int, path: &[u8], flags: libc::c_int, missing_parent: bool) -> io::Result<Option<Stamp>> {
    let mut out = MaybeUninit::uninit();
    let result = unsafe { libc::fstatat(fd, path.as_ptr().cast(), out.as_mut_ptr(), flags) };
    if result < 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ENOENT) || (missing_parent && e.raw_os_error() == Some(libc::ENOTDIR)) {
            return Ok(None);
        }
        return Err(e);
    }
    convert(unsafe { out.assume_init() }).map(Some)
}
pub(super) fn search_flags() -> libc::c_int {
    #[cfg(target_os = "macos")]
    let access = libc::O_SEARCH;
    #[cfg(not(target_os = "macos"))]
    let access = libc::O_PATH;
    access | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC
}
/// No binding: an empty twin, list end or list head.
const NONE: usize = usize::MAX;
/// How many further bindings, and how many source volumes, each refresh during the run re-validates in rotation,
/// beyond the current member's own bindings and those this member's engine changes touched.
///
/// A refresh used to walk every binding and every volume, so a run that lends a writer at each member did quadratic
/// proof work and ran out of the default budget near 1,000 members. A writer lent mid-run is now proved against what
/// the current member can still change (its own names and parents, and what its engine changes adopted) plus this
/// rotating window, which keeps re-checking older names at a constant cost per refresh. A refresh after the run
/// (a terminal writer) walks everything once more, as before. Older names are only ones the run has finished
/// with: a foreign change to one can't make the engine write through it, and the diagnostic File itself is never
/// an object the engine wrote (its identity is checked against every stage, target and volume when they are
/// admitted), so a change there is reported by the next rotation or terminal refresh instead of the very next one.
const ROTATION: usize = 8;

#[derive(Clone, Copy)]
struct Link {
    prev: usize,
    next: usize,
}
const UNLINKED: Link = Link { prev: NONE, next: NONE };

/// One observed name: an exact probe, followed or not, and the object expected there.
///
/// Every selected member's path admits a binding per prefix, so members under the same parents used to hold a copy
/// of each shared parent, and every hook walked all of them. A name is now one binding however many members reach
/// it, and the per-member [`Record`]s point at it, so an engine change updates a name once and a hook finds the
/// names it touches by lookup instead of by walking every target recorded so far.
struct Binding {
    /// NUL-terminated absolute probe, exactly as admitted
    path: Vec<u8>,
    expected: Option<Stamp>,
    original: Option<(u64, u64)>,
    follow: bool,
    /// the first member that admitted it, reported on a failure, as the first of its copies was
    ordinal: u64,
    /// whether it was that member's target
    leaf: bool,
    /// for a no-follow binding: the followed binding of the same probe, or NONE
    twin: usize,
    /// the bindings expecting the same regular file (keyed by identity in `Guard::same`)
    same: Link,
    /// the followed bindings that expect nothing yet (`Guard::open`)
    open: Link,
    /// the hook call (`Guard::generation`) that last handled it, so each binding takes one rule per call
    mark: u64,
    /// the member (`Guard::epoch`) during which an engine change last updated it
    touched: u64,
    /// a no-follow binding's position in `Guard::index` (NONE for a followed one), from which the bindings at the
    /// same path and under it are its neighbours, found without a search
    slot: usize,
}
impl Binding {
    fn name(&self) -> &Path {
        as_path(&self.path[..self.path.len() - 1])
    }
    fn alias(&self) -> RarDiagnosticFailure {
        if self.leaf {
            RarDiagnosticFailure::AliasTarget { ordinal: self.ordinal }
        } else {
            RarDiagnosticFailure::AliasAncestor { ordinal: Some(self.ordinal) }
        }
    }
}
/// One selected member's prefix (or its target): records are in member order, so a member's are found by search.
struct Record {
    binding: usize,
    ordinal: u64,
    leaf: bool,
    stage: Option<(u64, u64)>,
}
fn agrees(expected: Option<Stamp>, now: Option<Stamp>) -> bool {
    match (expected, now) {
        (Some(a), Some(b)) if a.directory() && b.directory() => a.identity() == b.identity(),
        (a, b) => a == b,
    }
}
struct SourceProbe {
    path: Vec<u8>,
}
#[derive(Clone, Copy)]
struct PendingUnlink {
    index: usize,
    old: Stamp,
}
pub(super) struct Guard {
    pub(super) anchor: Option<File>,
    bindings: Vec<Binding>,
    records: Vec<Record>,
    /// the no-follow bindings ordered by path (component-wise), so a name, its prefixes and what lies below it are
    /// found by binary search; a followed binding is reached through its no-follow twin
    index: Vec<usize>,
    /// head of each list of bindings expecting one regular file, by its identity
    same: HashMap<(u64, u64), usize>,
    /// head of the list of followed bindings that expect nothing yet
    open: usize,
    /// the bindings the current member's engine changes updated
    touched: Vec<usize>,
    current: Option<u64>,
    /// while preparing: the previous member's records
    previous: Range<usize>,
    epoch: u64,
    generation: u64,
    cursor: usize,
    source_cursor: usize,
    sources: Vec<SourceProbe>,
    prepared: bool,
    identity: Option<(u64, u64)>,
    deferred: Option<RarDiagnosticFailure>,
    pending_unlink: Option<PendingUnlink>,
    pending_publication: Option<usize>,
}
impl Default for Guard {
    fn default() -> Self {
        Self {
            anchor: None,
            bindings: Vec::new(),
            records: Vec::new(),
            index: Vec::new(),
            same: HashMap::new(),
            open: NONE,
            touched: Vec::new(),
            current: None,
            previous: 0..0,
            epoch: 0,
            generation: 0,
            cursor: 0,
            source_cursor: 0,
            sources: Vec::new(),
            prepared: false,
            identity: None,
            deferred: None,
            pending_unlink: None,
            pending_publication: None,
        }
    }
}
fn metadata(source: io::Error) -> RarDiagnosticFailure {
    RarDiagnosticFailure::Metadata { operation: IoOperation::Metadata, source }
}
fn checked(a: u64, b: u64) -> Result<u64, RarDiagnosticFailure> {
    a.checked_add(b).ok_or(RarDiagnosticFailure::CounterOverflow)
}
// Restores ownership even if a probe/fault hook unwinds; cleanup must never
// devolve into an unobserved File drop for a newly introduced handle.
struct GuardLease<'a> {
    control: &'a mut RarExtractControl,
    guard: Option<Guard>,
}
impl Drop for GuardLease<'_> {
    fn drop(&mut self) {
        self.control.guard = self.guard.take().expect("guard lease");
        if std::thread::panicking() {
            self.control.release_guard();
        }
    }
}
impl RarExtractControl {
    fn with_guard<T>(&mut self, f: impl FnOnce(&mut Guard, &mut RarExtractControl) -> T) -> T {
        let guard = std::mem::take(&mut self.guard);
        let mut lease = GuardLease { control: self, guard: Some(guard) };
        f(lease.guard.as_mut().expect("guard lease"), lease.control)
    }

    pub(super) fn proof_work(&mut self, n: u64) -> Result<(), RarDiagnosticFailure> {
        let next = checked(self.usage.diagnostics.work, n)?;
        if next > self.limits.diagnostics.work {
            return Err(RarDiagnosticFailure::Limit(RarDiagnosticLimit::Work));
        }
        self.usage.diagnostics.work = next;
        Ok(())
    }
    fn proof_io(&mut self, checkpoint: &mut u64) -> Result<(), RarDiagnosticFailure> {
        let next = checked(self.usage.diagnostics.io_attempts, 1)?;
        let local = checked(*checkpoint, 1)?;
        if next > self.limits.diagnostics.io_attempts {
            return Err(RarDiagnosticFailure::Limit(RarDiagnosticLimit::IoAttempts));
        }
        if local > self.limits.diagnostics.checkpoint_attempts {
            return Err(RarDiagnosticFailure::Limit(RarDiagnosticLimit::CheckpointAttempts));
        }
        self.usage.diagnostics.io_attempts = next;
        *checkpoint = local;
        self.usage.diagnostics.checkpoint_attempts_peak = self.usage.diagnostics.checkpoint_attempts_peak.max(local);
        Ok(())
    }
    fn proof_capacity(&mut self, bytes: u64) -> Result<(), RarDiagnosticFailure> {
        let next = checked(self.usage.diagnostics.capacity, bytes)?;
        if next > self.limits.diagnostics.capacity {
            return Err(RarDiagnosticFailure::Limit(RarDiagnosticLimit::Capacity));
        }
        self.usage.diagnostics.capacity = next;
        self.usage.diagnostics.capacity_peak = self.usage.diagnostics.capacity_peak.max(next);
        Ok(())
    }
    fn release_capacity(&mut self, bytes: u64) -> Result<(), RarDiagnosticFailure> {
        self.usage.diagnostics.capacity =
            self.usage.diagnostics.capacity.checked_sub(bytes).ok_or(RarDiagnosticFailure::CounterOverflow)?;
        Ok(())
    }
    fn reserve_proof<T>(&mut self, items: &mut Vec<T>, additional: usize) -> Result<(), RarDiagnosticFailure> {
        let wanted = items.len().checked_add(additional).ok_or(RarDiagnosticFailure::CounterOverflow)?;
        if wanted <= items.capacity() {
            return Ok(());
        }
        let old = items.capacity();
        let minimum = wanted
            .checked_sub(old)
            .and_then(|v| v.checked_mul(size_of::<T>()))
            .ok_or(RarDiagnosticFailure::CounterOverflow)?;
        let current = self.usage.diagnostics.capacity;
        let requested = checked(current, minimum as u64)?;
        if requested > self.limits.diagnostics.capacity {
            return Err(RarDiagnosticFailure::Limit(RarDiagnosticLimit::Capacity));
        }
        items.try_reserve_exact(additional).map_err(RarDiagnosticFailure::Allocation)?;
        self.usage.diagnostics.capacity = current;
        self.proof_capacity(
            items
                .capacity()
                .checked_sub(old)
                .and_then(|v| v.checked_mul(size_of::<T>()))
                .ok_or(RarDiagnosticFailure::CounterOverflow)? as u64,
        )
    }
    /// Gives back a temporary vector's charged capacity as it is dropped.
    fn release_vec<T>(&mut self, items: Vec<T>) -> Result<(), RarDiagnosticFailure> {
        let bytes = items.capacity().checked_mul(size_of::<T>()).ok_or(RarDiagnosticFailure::CounterOverflow)?;
        drop(items);
        self.release_capacity(bytes as u64)
    }
    fn proof_path(&mut self, path: &[u8]) -> Result<Vec<u8>, RarDiagnosticFailure> {
        self.proof_work(
            (path.len() as u64)
                .checked_mul(2)
                .and_then(|n| n.checked_add(1))
                .ok_or(RarDiagnosticFailure::CounterOverflow)?,
        )?;
        if path.contains(&0) {
            return Err(metadata(io::Error::from_raw_os_error(libc::EINVAL)));
        }
        let mut out = Vec::new();
        self.reserve_proof(&mut out, path.len().checked_add(1).ok_or(RarDiagnosticFailure::CounterOverflow)?)?;
        out.extend_from_slice(path);
        out.push(0);
        Ok(out)
    }
    pub(super) fn prepare(
        &mut self,
        session: &RarSession,
        selection: &RarSelection,
        options: &crate::extract::Options,
    ) {
        if matches!(self.state, RarDiagnosticState::Muted(_) | RarDiagnosticState::Closed) {
            return;
        }
        let mut attempts = 0;
        let result = self.with_guard(|guard, c| guard.prepare(c, session, selection, options, &mut attempts));
        if let Err(f) = result {
            self.mute(f);
        }
    }
    pub(super) fn refresh(&mut self, sources: Option<&[HeldVolume]>) -> Result<(), RarDiagnosticFailure> {
        let checkpoints = checked(self.usage.diagnostics.checkpoints, 1)?;
        self.usage.diagnostics.checkpoints = checkpoints;
        let mut attempts = 0;
        self.with_guard(|guard, c| guard.refresh(c, sources, &mut attempts))
    }
    pub(super) fn capture_before_path(&mut self, index: usize) {
        if !self.guard.prepared || self.failure.is_some() {
            return;
        }
        let mut attempts = 0;
        let result = self.with_guard(|guard, c| guard.before_path(c, index, &mut attempts));
        if let Err(f) = result {
            self.mute(f);
        }
    }
    pub(super) fn capture_before_directories(&mut self) {
        if !self.guard.prepared || self.failure.is_some() {
            return;
        }
        let mut attempts = 0;
        let result = self.with_guard(|guard, c| guard.check_followed(c, guard.current, &mut attempts));
        if let Err(failure) = result {
            self.mute(failure);
        }
    }
    pub(super) fn capture_created(&mut self, path: &Path) {
        if !self.guard.prepared || self.failure.is_some() {
            return;
        }
        let mut attempts = 0;
        let result = self.with_guard(|guard, c| guard.created(c, path, &mut attempts));
        if let Err(f) = result {
            self.mute(f);
        }
    }
    pub(super) fn capture_stage(&mut self, index: usize, stamp: SourceStamp) {
        if self.failure.is_some() {
            return;
        }
        let identity = (stamp.device, stamp.inode);
        // only this member's own target records take the stage: found by search, not by walking every record
        let result = self.with_guard(|guard, c| {
            for i in guard.chain(c, index as u64)? {
                c.proof_work(1)?;
                let r = &mut guard.records[i];
                if r.leaf {
                    r.stage = Some(identity);
                }
            }
            Ok(())
        });
        if let Err(failure) = result {
            self.mute(failure);
            return;
        }
        if self.guard.identity == Some(identity) {
            self.mute(RarDiagnosticFailure::AliasTarget { ordinal: index as u64 });
        }
    }
    pub(super) fn capture_before_publication(&mut self, index: usize, initial: Option<SourceStamp>) {
        if !self.guard.prepared || self.failure.is_some() {
            return;
        }
        let mut attempts = 0;
        let result = self.with_guard(|guard, c| guard.before_publication(c, index, initial, &mut attempts));
        if let Err(failure) = result {
            self.mute(failure);
        }
    }
    pub(super) fn capture_published(&mut self, index: usize, target: &Path, held: &File, published: bool) {
        if !self.guard.prepared || self.failure.is_some() {
            return;
        }
        if !published {
            return;
        }
        let mut attempts = 0;
        let result = self.with_guard(|guard, c| guard.published(c, index, target, held, &mut attempts));
        if let Err(f) = result {
            self.mute(f);
        }
    }
    /// A link member the engine placed at `landed` (None when nothing was placed) is the engine's own change, as a
    /// published file is: see [`Guard::linked`].
    pub(super) fn capture_linked(
        &mut self,
        index: usize,
        target: &Path,
        landed: Option<&Path>,
        placed: PlacedLink<'_>,
    ) {
        if !self.guard.prepared || self.failure.is_some() {
            return;
        }
        let mut attempts = 0;
        let result = self.with_guard(|guard, c| guard.linked(c, index, target, landed, placed, &mut attempts));
        if let Err(f) = result {
            self.mute(f);
        }
    }
}
/// Work charged for a binary search over `n` items, beyond its comparisons.
fn search_work(n: usize) -> u64 {
    u64::from(usize::BITS - n.leading_zeros()) + 1
}
impl Guard {
    fn classify(&mut self, c: &mut RarExtractControl, attempts: &mut u64) -> Result<bool, RarDiagnosticFailure> {
        if c.diagnostic.is_none() {
            return Err(RarDiagnosticFailure::NoDescriptor);
        }
        c.proof_work(1)?;
        c.proof_io(attempts)?;
        let file = c.diagnostic.as_ref().expect("diagnostic exists");
        let stamp = stat_fd(file).map_err(metadata)?;
        if stamp.regular() {
            if self.identity.is_some_and(|identity| identity != stamp.identity()) {
                return Err(RarDiagnosticFailure::BindingChanged { ordinal: None });
            }
            self.identity = Some(stamp.identity());
            Ok(true)
        } else if [libc::S_IFCHR, libc::S_IFIFO, libc::S_IFSOCK].contains(&(stamp.mode & libc::S_IFMT)) {
            c.state = RarDiagnosticState::AllowedByKind;
            Ok(false)
        } else {
            Err(RarDiagnosticFailure::UnsupportedKind)
        }
    }
    fn prepare(
        &mut self,
        c: &mut RarExtractControl,
        session: &RarSession,
        selection: &RarSelection,
        options: &crate::extract::Options,
        attempts: &mut u64,
    ) -> Result<(), RarDiagnosticFailure> {
        if !self.classify(c, attempts)? {
            return Ok(());
        }
        // Known aliases are examined before namespace binding faults.
        for (i, volume) in session.volumes.iter().enumerate() {
            c.proof_work(1)?;
            if self.identity == Some((volume.stamp.device, volume.stamp.inode)) {
                return Err(RarDiagnosticFailure::AliasInput { volume: i as u64 });
            }
        }
        c.handle_admission(RarControlHandleKind::Guard).map_err(|e| match e {
            RarExtractControlError::CounterOverflow => RarDiagnosticFailure::CounterOverflow,
            _ => RarDiagnosticFailure::Limit(RarDiagnosticLimit::OpenHandles),
        })?;
        c.proof_io(attempts)?;
        self.anchor = Some(
            handles::open_search(b"/\0")
                .map_err(|source| RarDiagnosticFailure::Metadata { operation: IoOperation::Open, source })?,
        );
        c.acquired(RarControlHandleKind::Guard);
        for volume in &session.volumes {
            c.proof_work(1)?;
            c.reserve_proof(&mut self.sources, 1)?;
            let path = c.proof_path(volume.path.as_os_str().as_bytes())?;
            self.sources.push(SourceProbe { path });
        }
        let cwd = cwd(c, attempts)?;
        for (word, mut bits) in selection.bits.iter().copied().enumerate() {
            c.proof_work(1)?;
            while bits != 0 {
                let index = word * 64 + bits.trailing_zeros() as usize;
                bits &= bits - 1;
                let header = &session.model.members[index].header;
                // Precharge a conservative bound for UTF-8 validation,
                // component splitting, normalization, copying and final parsing.
                let name_work = checked(header.name.len() as u64, session.model.members[index].wire.name.len() as u64)?
                    .checked_mul(8)
                    .and_then(|n| n.checked_add(2))
                    .ok_or(RarDiagnosticFailure::CounterOverflow)?;
                c.proof_work(name_work)?;
                if header.is_dir() && options.flatten {
                    continue;
                }
                let targets = checked(c.usage.diagnostics.targets, 1)?;
                if targets > c.limits.diagnostics.targets {
                    return Err(RarDiagnosticFailure::Limit(RarDiagnosticLimit::Targets));
                }
                if !super::super::extraction::projectable_name(header, &session.model.members[index].wire.name) {
                    return Err(RarDiagnosticFailure::ProjectionUnavailable { ordinal: index as u64 });
                }
                // Temporary projection capacity is charged while live, then released.
                if checked(c.usage.diagnostics.capacity, header.name.len() as u64)? > c.limits.diagnostics.capacity {
                    return Err(RarDiagnosticFailure::Limit(RarDiagnosticLimit::Capacity));
                }
                let name = header
                    .output_name_as(selection.takes_versions().then_some(options.version_naming))
                    .unwrap_or(std::borrow::Cow::Borrowed(&header.name));
                let relative = crate::path::sanitize_fallible(&name, !header.is_unix()).map_err(|e| match e {
                    crate::path::ProjectionError::Unsafe => {
                        RarDiagnosticFailure::ProjectionUnavailable { ordinal: index as u64 }
                    }
                    crate::path::ProjectionError::Allocation(e) => RarDiagnosticFailure::Allocation(e),
                })?;
                c.proof_capacity(relative.capacity() as u64)?;
                let projection_work =
                    checked(options.dest.as_os_str().len() as u64, relative.as_os_str().len() as u64)?
                        .checked_mul(4)
                        .and_then(|n| n.checked_add(2))
                        .ok_or(RarDiagnosticFailure::CounterOverflow)?;
                c.proof_work(projection_work)?;
                let target_capacity = super::super::extraction::target_capacity(options, &relative, options.flatten)
                    .ok_or(RarDiagnosticFailure::CounterOverflow)?;
                if checked(c.usage.diagnostics.capacity, target_capacity as u64)? > c.limits.diagnostics.capacity {
                    return Err(RarDiagnosticFailure::Limit(RarDiagnosticLimit::Capacity));
                }
                c.proof_work(target_capacity as u64)?;
                let native_target =
                    super::super::extraction::project_target(options, &relative, options.flatten, target_capacity)
                        .map_err(RarDiagnosticFailure::Allocation)?;
                c.proof_capacity(native_target.capacity() as u64)?;
                let target = project_bytes(c, &cwd, &native_target, Path::new(""))?;
                self.admit_path(c, &target, index as u64, attempts)?;
                let released = checked(
                    checked(target.capacity() as u64, relative.capacity() as u64)?,
                    native_target.capacity() as u64,
                )?;
                drop(target);
                drop(relative);
                drop(native_target);
                c.release_capacity(released)?;
                c.usage.diagnostics.targets = targets;
            }
        }
        self.index_bindings(c)?;
        if let Some(failure) = self.deferred.take() {
            return Err(failure);
        }
        self.prepared = true;
        Ok(())
    }
    fn admit_path(
        &mut self,
        c: &mut RarExtractControl,
        path: &[u8],
        ordinal: u64,
        attempts: &mut u64,
    ) -> Result<(), RarDiagnosticFailure> {
        c.proof_work(path.len() as u64)?;
        let start = self.records.len();
        for end in (1..=path.len()).filter(|&i| i == path.len() || path[i] == b'/') {
            c.proof_work(end as u64)?;
            let leaf = end == path.len();
            let expected = self.admit_record(c, &path[..end], ordinal, leaf, false, start, attempts)?;
            if expected.is_some_and(|stamp| stamp.mode & libc::S_IFMT == libc::S_IFLNK) {
                // Keep the no-follow binding and separately protect the object
                // reached when this prefix is traversed by the actual lookup.
                self.admit_record(c, &path[..end], ordinal, leaf, true, start, attempts)?;
            }
        }
        self.previous = start..self.records.len();
        Ok(())
    }
    /// Admits one member's prefix (the member's records begin at `start`) and a record pointing at its binding.
    /// The previous member's record at the same position usually holds the very same probe, a parent both share:
    /// its binding is taken as observed once rather than observed and stored again, so a run of members under the
    /// same parents admits each parent once. Any other probe gets a binding of its own, and
    /// [`Self::index_bindings`] later folds the bindings of one exact probe into one. A followed admission directly
    /// follows the no-follow admission of the same probe and becomes its twin.
    #[allow(clippy::too_many_arguments)]
    fn admit_record(
        &mut self,
        c: &mut RarExtractControl,
        path: &[u8],
        ordinal: u64,
        leaf: bool,
        follow: bool,
        start: usize,
        attempts: &mut u64,
    ) -> Result<Option<Stamp>, RarDiagnosticFailure> {
        let parents = checked(c.usage.diagnostics.parents, 1)?;
        if parents > c.limits.diagnostics.parents {
            return Err(RarDiagnosticFailure::Limit(RarDiagnosticLimit::Parents));
        }
        c.reserve_proof(&mut self.records, 1)?;
        let shared = self.previous.start + (self.records.len() - start);
        if shared < self.previous.end {
            let b = self.records[shared].binding;
            let binding = &self.bindings[b];
            comparison_work(c, binding.path.len(), path.len())?;
            if binding.follow == follow && binding.path.strip_suffix(&[0]) == Some(path) {
                let expected = binding.expected;
                self.records.push(Record { binding: b, ordinal, leaf, stage: None });
                c.usage.diagnostics.parents = parents;
                return Ok(expected);
            }
        }
        c.reserve_proof(&mut self.bindings, 1)?;
        let probe = c.proof_path(path)?;
        let expected = match self.observe(c, &probe, attempts, follow) {
            Ok(observation) => observation,
            Err(failure @ RarDiagnosticFailure::Metadata { .. }) => {
                if self.deferred.is_none() {
                    self.deferred = Some(failure);
                }
                None
            }
            Err(failure) => return Err(failure),
        };
        if expected.is_some_and(|stamp| self.identity == Some(stamp.identity())) {
            return Err(if leaf {
                RarDiagnosticFailure::AliasTarget { ordinal }
            } else {
                RarDiagnosticFailure::AliasAncestor { ordinal: Some(ordinal) }
            });
        }
        let id = self.bindings.len();
        self.bindings.push(Binding {
            path: probe,
            expected,
            original: expected.map(Stamp::identity),
            follow,
            ordinal,
            leaf,
            twin: NONE,
            same: UNLINKED,
            open: UNLINKED,
            mark: 0,
            touched: 0,
            slot: NONE,
        });
        // the no-follow admission of the same probe was this member's previous record
        if follow
            && let Some(sibling) = self.records.last().map(|r| r.binding)
            && self.bindings[sibling].twin == NONE
        {
            self.bindings[sibling].twin = id;
        }
        self.records.push(Record { binding: id, ordinal, leaf, stage: None });
        c.usage.diagnostics.parents = parents;
        Ok(expected)
    }
    /// Folds the admitted bindings of one exact probe into the first one, orders the no-follow ones by path and
    /// links the identity and unresolved lists. Copies observed differently during preparation mean the name changed
    /// under it, which is reported as the later refresh comparing the copies would have.
    fn index_bindings(&mut self, c: &mut RarExtractControl) -> Result<(), RarDiagnosticFailure> {
        let n = self.bindings.len();
        let mut order = Vec::new();
        c.reserve_proof(&mut order, n)?;
        let mut remap = Vec::new();
        c.reserve_proof(&mut remap, n)?;
        let mut fresh = Vec::new();
        c.reserve_proof(&mut fresh, n)?;
        // a conservative bound for the sort's comparisons
        let depth = search_work(n);
        for b in self.bindings.iter().filter(|b| !b.follow) {
            c.proof_work(
                checked(b.path.len() as u64, 1)?
                    .checked_mul(2)
                    .and_then(|w| w.checked_mul(depth))
                    .ok_or(RarDiagnosticFailure::CounterOverflow)?,
            )?;
        }
        order.extend((0..n).filter(|&i| !self.bindings[i].follow));
        let bindings = &self.bindings;
        order.sort_unstable_by(|&a, &b| {
            let (x, y) = (&bindings[a], &bindings[b]);
            x.name().cmp(y.name()).then_with(|| x.path.cmp(&y.path)).then(a.cmp(&b))
        });
        remap.resize(n, NONE);
        let (mut kept, mut k) = (0, 0);
        while k < order.len() {
            let first = order[k];
            while k < order.len() && self.bindings[order[k]].path == self.bindings[first].path {
                c.proof_work(checked(self.bindings[order[k]].path.len() as u64, 1)?)?;
                remap[order[k]] = first;
                k += 1;
            }
            order[kept] = first;
            kept += 1;
        }
        order.truncate(kept);
        for k in 0..n {
            c.proof_work(1)?;
            let b = &self.bindings[k];
            if b.follow || b.twin == NONE {
                continue;
            }
            let (twin, first) = (b.twin, remap[k]);
            remap[twin] = if first == k || self.bindings[first].twin == NONE {
                self.bindings[first].twin = twin;
                twin
            } else {
                self.bindings[first].twin
            };
        }
        let (mut released, mut count) = (0, 0);
        for k in 0..n {
            c.proof_work(1)?;
            if remap[k] == NONE {
                // a followed admission always has a no-follow sibling; one without stays on its own
                remap[k] = k;
            }
            let first = remap[k];
            if first != k {
                if self.deferred.is_none() && !agrees(self.bindings[first].expected, self.bindings[k].expected) {
                    self.deferred =
                        Some(RarDiagnosticFailure::BindingChanged { ordinal: Some(self.bindings[first].ordinal) });
                }
                released = checked(released, self.bindings[k].path.capacity() as u64)?;
                fresh.push(NONE);
            } else {
                fresh.push(count);
                count += 1;
            }
        }
        let mut k = 0;
        self.bindings.retain(|_| {
            let keep = remap[k] == k;
            k += 1;
            keep
        });
        c.release_capacity(released)?;
        for b in &mut self.bindings {
            if b.twin != NONE {
                b.twin = fresh[b.twin];
            }
        }
        for r in &mut self.records {
            r.binding = fresh[remap[r.binding]];
        }
        for entry in &mut order {
            *entry = fresh[*entry];
        }
        self.index = order;
        for (slot, &b) in self.index.iter().enumerate() {
            self.bindings[b].slot = slot;
        }
        for i in 0..self.bindings.len() {
            let b = &self.bindings[i];
            let (expected, follow) = (b.expected, b.follow);
            if let Some(stamp) = expected.filter(|s| s.regular()) {
                self.link_same(c, i, stamp.identity())?;
            }
            if follow && expected.is_none() {
                self.link_open(i);
            }
        }
        c.release_vec(remap)?;
        c.release_vec(fresh)
    }
    fn link_same(&mut self, c: &mut RarExtractControl, i: usize, key: (u64, u64)) -> Result<(), RarDiagnosticFailure> {
        c.proof_work(1)?;
        if self.same.len() == self.same.capacity() {
            let entry = size_of::<((u64, u64), usize)>() as u64 + 1;
            if checked(c.usage.diagnostics.capacity, entry)? > c.limits.diagnostics.capacity {
                return Err(RarDiagnosticFailure::Limit(RarDiagnosticLimit::Capacity));
            }
            let before = self.same.capacity();
            self.same.try_reserve(1).map_err(RarDiagnosticFailure::Allocation)?;
            c.proof_capacity(
                ((self.same.capacity() - before) as u64)
                    .checked_mul(entry)
                    .ok_or(RarDiagnosticFailure::CounterOverflow)?,
            )?;
        }
        let head = self.same.insert(key, i).unwrap_or(NONE);
        self.bindings[i].same = Link { prev: NONE, next: head };
        if head != NONE {
            self.bindings[head].same.prev = i;
        }
        Ok(())
    }
    fn unlink_same(&mut self, i: usize, key: (u64, u64)) {
        let Link { prev, next } = self.bindings[i].same;
        if prev != NONE {
            self.bindings[prev].same.next = next;
        } else if next != NONE {
            if let Some(head) = self.same.get_mut(&key) {
                *head = next;
            }
        } else {
            self.same.remove(&key);
        }
        if next != NONE {
            self.bindings[next].same.prev = prev;
        }
        self.bindings[i].same = UNLINKED;
    }
    fn link_open(&mut self, i: usize) {
        let head = self.open;
        self.bindings[i].open = Link { prev: NONE, next: head };
        if head != NONE {
            self.bindings[head].open.prev = i;
        }
        self.open = i;
    }
    fn unlink_open(&mut self, i: usize) {
        let Link { prev, next } = self.bindings[i].open;
        if prev != NONE {
            self.bindings[prev].open.next = next;
        } else {
            self.open = next;
        }
        if next != NONE {
            self.bindings[next].open.prev = prev;
        }
        self.bindings[i].open = UNLINKED;
    }
    /// The one way an expected object changes: keeps the identity and unresolved lists current and notes the binding
    /// as touched by the current member, so the next refresh re-validates it.
    fn set_expected(
        &mut self,
        c: &mut RarExtractControl,
        i: usize,
        new: Option<Stamp>,
    ) -> Result<(), RarDiagnosticFailure> {
        let b = &self.bindings[i];
        let old_key = b.expected.filter(|s| s.regular()).map(Stamp::identity);
        let new_key = new.filter(|s| s.regular()).map(Stamp::identity);
        let (was_open, open) = (b.follow && b.expected.is_none(), b.follow && new.is_none());
        if old_key != new_key {
            if let Some(key) = old_key {
                self.unlink_same(i, key);
            }
            if let Some(key) = new_key {
                self.link_same(c, i, key)?;
            }
        }
        if was_open != open {
            if open {
                self.link_open(i);
            } else {
                self.unlink_open(i);
            }
        }
        self.bindings[i].expected = new;
        if self.bindings[i].touched != self.epoch {
            c.reserve_proof(&mut self.touched, 1)?;
            self.touched.push(i);
            self.bindings[i].touched = self.epoch;
        }
        Ok(())
    }
    /// The records of member `ordinal`.
    fn chain(&self, c: &mut RarExtractControl, ordinal: u64) -> Result<Range<usize>, RarDiagnosticFailure> {
        c.proof_work(search_work(self.records.len()).saturating_mul(2))?;
        let start = self.records.partition_point(|r| r.ordinal < ordinal);
        let end = start + self.records[start..].partition_point(|r| r.ordinal == ordinal);
        Ok(start..end)
    }
    /// The index positions of the no-follow bindings at `name` (component-wise, as `Path` compares) and, with
    /// `below`, of those under it too: one contiguous run in path order.
    fn lookup(
        &self,
        c: &mut RarExtractControl,
        name: &[u8],
        below: bool,
    ) -> Result<Range<usize>, RarDiagnosticFailure> {
        let path = as_path(name);
        let (mut start, mut end) = (0, self.index.len());
        while start < end {
            let mid = start + (end - start) / 2;
            let b = &self.bindings[self.index[mid]];
            comparison_work(c, b.path.len(), name.len())?;
            if b.name() < path {
                start = mid + 1;
            } else {
                end = mid;
            }
        }
        let mut end = start;
        while end < self.index.len() {
            let b = &self.bindings[self.index[end]];
            comparison_work(c, b.path.len(), name.len())?;
            if !(b.name() == path || below && b.name().starts_with(path)) {
                break;
            }
            end += 1;
        }
        Ok(start..end)
    }
    /// The index positions of the no-follow bindings at the same path as no-follow binding `b` and, with `below`, of
    /// those under it: `b`'s neighbours in path order, so a member's own names cost no search however many there are.
    fn around(&self, c: &mut RarExtractControl, b: usize, below: bool) -> Result<Range<usize>, RarDiagnosticFailure> {
        let binding = &self.bindings[b];
        let (slot, name, len) = (binding.slot, binding.name(), binding.path.len());
        if slot == NONE {
            return self.lookup(c, &binding.path[..len - 1], below);
        }
        let mut start = slot;
        while start > 0 {
            let p = &self.bindings[self.index[start - 1]];
            comparison_work(c, p.path.len(), len)?;
            if p.name() != name {
                break;
            }
            start -= 1;
        }
        let mut end = slot + 1;
        while end < self.index.len() {
            let p = &self.bindings[self.index[end]];
            comparison_work(c, p.path.len(), len)?;
            if !(p.name() == name || below && p.name().starts_with(name)) {
                break;
            }
            end += 1;
        }
        Ok(start..end)
    }
    /// Member `ordinal`'s no-follow target binding at `target` (any target binding when `target` is None).
    fn leaf_at(
        &self,
        c: &mut RarExtractControl,
        ordinal: u64,
        target: Option<&[u8]>,
    ) -> Result<Option<usize>, RarDiagnosticFailure> {
        for r in self.chain(c, ordinal)? {
            let record = &self.records[r];
            let b = &self.bindings[record.binding];
            if !record.leaf || b.follow {
                continue;
            }
            let Some(target) = target else {
                return Ok(Some(record.binding));
            };
            comparison_work(c, b.path.len(), target.len())?;
            if b.name() == as_path(target) {
                return Ok(Some(record.binding));
            }
        }
        Ok(None)
    }
    fn observe(
        &self,
        c: &mut RarExtractControl,
        path: &[u8],
        attempts: &mut u64,
        follow: bool,
    ) -> Result<Option<Stamp>, RarDiagnosticFailure> {
        loop {
            c.proof_io(attempts)?;
            match stat_at_probe(
                self.anchor.as_ref().expect("guard anchor").as_raw_fd(),
                anchored(path),
                if follow { 0 } else { libc::AT_SYMLINK_NOFOLLOW },
                !follow,
            ) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                result => return result.map_err(metadata),
            }
        }
    }
    fn link_reads(
        &self,
        c: &mut RarExtractControl,
        path: &[u8],
        expected: &[u8],
        attempts: &mut u64,
    ) -> Result<bool, RarDiagnosticFailure> {
        loop {
            c.proof_io(attempts)?;
            match link_reads_at(self.anchor.as_ref().expect("guard anchor").as_raw_fd(), anchored(path), expected) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                result => return result.map_err(metadata),
            }
        }
    }
    fn observe_source(
        &self,
        c: &mut RarExtractControl,
        path: &[u8],
        attempts: &mut u64,
    ) -> Result<Option<Stamp>, RarDiagnosticFailure> {
        loop {
            c.proof_io(attempts)?;
            match stat_at_flags(self.anchor.as_ref().expect("anchor").as_raw_fd(), anchored(path), 0) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                result => return result.map_err(metadata),
            }
        }
    }
    /// Re-observes binding `i` for a refresh: an alias of the diagnostic File is an error at once, a changed
    /// object is returned as `false` so an alias found later in the same refresh still takes precedence.
    fn verify(&self, c: &mut RarExtractControl, i: usize, attempts: &mut u64) -> Result<bool, RarDiagnosticFailure> {
        let b = &self.bindings[i];
        c.proof_work(checked(b.path.len() as u64, 1)?)?;
        if b.original.is_some() && b.original == self.identity {
            return Err(b.alias());
        }
        let now = self.observe(c, &b.path, attempts, b.follow)?;
        if now.is_some_and(|s| Some(s.identity()) == self.identity) {
            return Err(b.alias());
        }
        Ok(agrees(b.expected, now))
    }
    fn refresh(
        &mut self,
        c: &mut RarExtractControl,
        sources: Option<&[HeldVolume]>,
        attempts: &mut u64,
    ) -> Result<(), RarDiagnosticFailure> {
        if !self.classify(c, attempts)? {
            return Ok(());
        }
        if !self.prepared {
            c.state = RarDiagnosticState::PendingTargets;
            return Ok(());
        }
        let sources = sources.ok_or(RarDiagnosticFailure::BindingChanged { ordinal: None })?;
        // Mid-run, each refresh proves a constant number of volumes in rotation (see ROTATION): every volume's
        // identity was compared with the diagnostic File's at preparation, both identities are fixed for the run,
        // and the engine's own source checks still prove each member's volumes before it is published. A
        // refresh after the run proves them all.
        let full = c.usage.phase != RarExtractControlPhase::Extracting;
        let span = if full { sources.len() } else { sources.len().min(ROTATION) };
        let start = if full { 0 } else { self.source_cursor % sources.len().max(1) };
        for k in 0..span {
            let i = (start + k) % sources.len();
            let source = &sources[i];
            c.proof_work(checked(source.path.as_os_str().len() as u64, 1)?)?;
            if self.identity == Some((source.stamp.device, source.stamp.inode)) {
                return Err(RarDiagnosticFailure::AliasInput { volume: i as u64 });
            }
            c.proof_io(attempts)?;
            let held = stat_fd(&source.file).map_err(metadata)?;
            let probe = self.sources.get(i).ok_or(RarDiagnosticFailure::BindingChanged { ordinal: None })?;
            let bound = self.observe_source(c, &probe.path, attempts)?;
            if held.source() != source.stamp || bound.map(Stamp::source) != Some(source.stamp) {
                return Err(RarDiagnosticFailure::BindingChanged { ordinal: None });
            }
        }
        if !full {
            self.source_cursor = (start + span) % sources.len().max(1);
        }
        // Alias detection precedes unrelated binding faults in this single inventory pass.
        let mut changed = None;
        let mut note = |guard: &Self, i: usize, agrees: bool| {
            if !agrees && changed.is_none() {
                changed = Some(guard.bindings[i].ordinal);
            }
        };
        if full {
            for i in 0..self.bindings.len() {
                let agrees = self.verify(c, i, attempts)?;
                note(self, i, agrees);
            }
        } else {
            // the current member's own names and parents, followed where they are links
            if let Some(current) = self.current {
                for r in self.chain(c, current)? {
                    let b = self.records[r].binding;
                    if self.bindings[b].follow {
                        continue;
                    }
                    for i in [b, self.bindings[b].twin] {
                        if i != NONE {
                            let agrees = self.verify(c, i, attempts)?;
                            note(self, i, agrees);
                        }
                    }
                }
            }
            // what this member's engine changes adopted, wherever it is
            for k in 0..self.touched.len() {
                let i = self.touched[k];
                let agrees = self.verify(c, i, attempts)?;
                note(self, i, agrees);
            }
            // and a constant window of every other name, in rotation
            let n = self.bindings.len();
            for _ in 0..n.min(ROTATION) {
                let i = self.cursor % n;
                self.cursor = (i + 1) % n;
                let agrees = self.verify(c, i, attempts)?;
                note(self, i, agrees);
            }
        }
        if let Some(ordinal) = changed {
            return Err(RarDiagnosticFailure::BindingChanged { ordinal: Some(ordinal) });
        }
        c.state = RarDiagnosticState::AllowedByBindings;
        Ok(())
    }
    fn before_path(
        &mut self,
        c: &mut RarExtractControl,
        index: usize,
        attempts: &mut u64,
    ) -> Result<(), RarDiagnosticFailure> {
        // A new member: refreshes now prove its names, and what its engine changes touch from here on.
        if self.current != Some(index as u64) {
            self.current = Some(index as u64);
            self.epoch = checked(self.epoch, 1)?;
            self.touched.clear();
        }
        // Validate the previous expected binding before any known engine change.
        // This cannot adopt a foreign object and then erase its identity at publish.
        // Only this member's own records can be changed by its engine work: found by search.
        for r in self.chain(c, index as u64)? {
            c.proof_work(1)?;
            let record = &self.records[r];
            let b = &self.bindings[record.binding];
            c.proof_work(b.path.len() as u64)?;
            let now = self.observe(c, &b.path, attempts, b.follow)?;
            if now.is_some_and(|s| Some(s.identity()) == self.identity) {
                return Err(if record.leaf {
                    RarDiagnosticFailure::AliasTarget { ordinal: index as u64 }
                } else {
                    RarDiagnosticFailure::AliasAncestor { ordinal: Some(record.ordinal) }
                });
            }
            if !agrees(b.expected, now) {
                return Err(RarDiagnosticFailure::BindingChanged { ordinal: Some(record.ordinal) });
            }
        }
        Ok(())
    }
    fn check_one_followed(
        &self,
        c: &mut RarExtractControl,
        i: usize,
        attempts: &mut u64,
    ) -> Result<(), RarDiagnosticFailure> {
        let b = &self.bindings[i];
        c.proof_work(b.path.len() as u64)?;
        let now = self.observe(c, &b.path, attempts, true)?;
        if now.is_some_and(|stamp| Some(stamp.identity()) == self.identity) {
            return Err(b.alias());
        }
        if !agrees(b.expected, now) {
            return Err(RarDiagnosticFailure::BindingChanged { ordinal: Some(b.ordinal) });
        }
        Ok(())
    }
    /// Before the engine creates directories or publishes for member `ordinal`, proves every followed binding a
    /// following capture could adopt a new observation into: those of the member's own names and parents (and of
    /// anything under its target, which a symbolic link placed there redirects), and every followed binding still
    /// expecting nothing, which `created`, `published` and `linked` adopt wherever it is. Bindings expecting the
    /// incumbent are proved by `before_publication`. Any other followed binding keeps its expected object through
    /// this member's changes, so it is left to refreshes rather than walked for every member.
    fn check_followed(
        &self,
        c: &mut RarExtractControl,
        ordinal: Option<u64>,
        attempts: &mut u64,
    ) -> Result<(), RarDiagnosticFailure> {
        let Some(ordinal) = ordinal else {
            for i in 0..self.bindings.len() {
                c.proof_work(1)?;
                if self.bindings[i].follow {
                    self.check_one_followed(c, i, attempts)?;
                }
            }
            return Ok(());
        };
        for r in self.chain(c, ordinal)? {
            c.proof_work(1)?;
            let record = &self.records[r];
            let b = &self.bindings[record.binding];
            if b.follow {
                continue;
            }
            if b.twin != NONE {
                self.check_one_followed(c, b.twin, attempts)?;
            }
            if record.leaf {
                for k in self.around(c, record.binding, true)? {
                    let d = self.index[k];
                    if d != record.binding && self.bindings[d].twin != NONE {
                        self.check_one_followed(c, self.bindings[d].twin, attempts)?;
                    }
                }
            }
        }
        let mut i = self.open;
        while i != NONE {
            c.proof_work(1)?;
            self.check_one_followed(c, i, attempts)?;
            i = self.bindings[i].open.next;
        }
        Ok(())
    }
    fn followed_created_directory(
        &mut self,
        c: &mut RarExtractControl,
        known: Stamp,
        attempts: &mut u64,
    ) -> Result<(), RarDiagnosticFailure> {
        // only a followed binding still expecting nothing can be adopted here
        let mut i = self.open;
        while i != NONE {
            c.proof_work(1)?;
            let next = self.bindings[i].open.next;
            let b = &self.bindings[i];
            c.proof_work(b.path.len() as u64)?;
            let now = self.observe(c, &b.path, attempts, true)?;
            if now.is_some_and(|stamp| stamp.directory() && stamp.identity() == known.identity()) {
                self.set_expected(c, i, now)?;
            }
            i = next;
        }
        Ok(())
    }
    fn created(
        &mut self,
        c: &mut RarExtractControl,
        path: &Path,
        attempts: &mut u64,
    ) -> Result<(), RarDiagnosticFailure> {
        let cwd = cwd(c, attempts)?;
        let target = project_bytes(c, &cwd, path, Path::new(""))?;
        // A binding the creation may have made is one at a component prefix of `path` (or `path` itself) that
        // expected nothing. `path` lies on the current member's own target path, so those are the bindings at the
        // member's own records' paths (every member under the same name shares the binding, and one admitted with
        // other bytes for the same path is a neighbour in path order), found without walking every binding.
        let generation = self.next_generation()?;
        let leaf = match self.current {
            Some(current) => self.leaf_at(c, current, None)?,
            None => None,
        };
        let on_leaf = match leaf {
            Some(b) => {
                comparison_work(c, self.bindings[b].path.len(), target.len())?;
                self.bindings[b].name().starts_with(as_path(&target))
            }
            None => false,
        };
        if let (true, Some(current)) = (on_leaf, self.current) {
            for r in self.chain(c, current)? {
                let b = self.records[r].binding;
                if self.bindings[b].follow {
                    continue;
                }
                comparison_work(c, self.bindings[b].path.len(), target.len())?;
                if as_path(&target).starts_with(self.bindings[b].name()) {
                    let names = self.around(c, b, false)?;
                    self.adopt_created(c, names, generation, attempts)?;
                }
            }
        } else {
            // not on the current member's path: each component prefix is looked up, from the root down
            c.proof_work(target.len() as u64)?;
            let mut previous = None;
            for end in (1..=target.len()).filter(|&i| i == 1 || i == target.len() || target[i] == b'/') {
                let name = &target[..end];
                if let Some(previous) = previous {
                    comparison_work(c, previous, end)?;
                    if as_path(&target[..previous]) == as_path(name) {
                        continue;
                    }
                }
                previous = Some(end);
                let names = self.lookup(c, name, false)?;
                self.adopt_created(c, names, generation, attempts)?;
            }
        }
        c.release_capacity(target.capacity() as u64)
    }
    /// Adopts, at the index positions `names`, each binding (and its followed twin) that expected nothing and now
    /// holds a directory, as one the engine just created; anything else there is a binding change.
    fn adopt_created(
        &mut self,
        c: &mut RarExtractControl,
        names: Range<usize>,
        generation: u64,
        attempts: &mut u64,
    ) -> Result<(), RarDiagnosticFailure> {
        for k in names {
            let b = self.index[k];
            for i in [b, self.bindings[b].twin] {
                c.proof_work(1)?;
                if i == NONE || self.bindings[i].mark == generation {
                    continue;
                }
                self.bindings[i].mark = generation;
                if self.bindings[i].expected.is_some() {
                    continue;
                }
                let now = self.observe(c, &self.bindings[i].path, attempts, self.bindings[i].follow)?;
                if let Some(stamp) = now {
                    if !stamp.directory() {
                        return Err(RarDiagnosticFailure::BindingChanged { ordinal: Some(self.bindings[i].ordinal) });
                    }
                    self.set_expected(c, i, Some(stamp))?;
                    self.followed_created_directory(c, stamp, attempts)?;
                }
            }
        }
        Ok(())
    }
    fn before_publication(
        &mut self,
        c: &mut RarExtractControl,
        index: usize,
        initial: Option<SourceStamp>,
        attempts: &mut u64,
    ) -> Result<(), RarDiagnosticFailure> {
        self.pending_unlink = None;
        self.pending_publication = None;
        self.check_followed(c, Some(index as u64), attempts)?;
        let Some(initial) = initial else {
            self.pending_publication = Some(index);
            return Ok(());
        };
        let mut old = None;
        for r in self.chain(c, index as u64)? {
            c.proof_work(1)?;
            if self.records[r].leaf {
                old = self.bindings[self.records[r].binding].expected;
                break;
            }
        }
        let old = old
            .filter(|stamp| stamp.regular() && stamp.source() == initial && stamp.links != 0)
            .ok_or(RarDiagnosticFailure::BindingChanged { ordinal: Some(index as u64) })?;
        // Validate every known binding to the incumbent immediately before the
        // engine's one unlink. No foreign observation becomes a new baseline.
        // They are exactly the bindings on the incumbent's identity list.
        c.proof_work(1)?;
        let mut i = self.same.get(&old.identity()).copied().unwrap_or(NONE);
        while i != NONE {
            c.proof_work(1)?;
            let b = &self.bindings[i];
            c.proof_work(b.path.len() as u64)?;
            if b.expected != Some(old) || self.observe(c, &b.path, attempts, b.follow)? != Some(old) {
                return Err(RarDiagnosticFailure::BindingChanged { ordinal: Some(b.ordinal) });
            }
            i = b.same.next;
        }
        self.pending_unlink = Some(PendingUnlink { index, old });
        self.pending_publication = Some(index);
        Ok(())
    }
    /// The head of the list of bindings expecting the regular file `identity`.
    fn same_head(&self, c: &mut RarExtractControl, identity: (u64, u64)) -> Result<usize, RarDiagnosticFailure> {
        c.proof_work(1)?;
        Ok(self.same.get(&identity).copied().unwrap_or(NONE))
    }
    fn next_generation(&mut self) -> Result<u64, RarDiagnosticFailure> {
        self.generation = checked(self.generation, 1)?;
        Ok(self.generation)
    }
    /// Takes a published file as the engine's own change. Each binding takes the first rule that fits it, as one
    /// pass over every record did, but the bindings each rule can apply to are found directly: those at the target,
    /// the followed ones expecting nothing, and those expecting the unlinked incumbent.
    fn published(
        &mut self,
        c: &mut RarExtractControl,
        index: usize,
        target: &Path,
        held: &File,
        attempts: &mut u64,
    ) -> Result<(), RarDiagnosticFailure> {
        let pending = self.pending_unlink.take().filter(|pending| pending.index == index);
        let prepared = self.pending_publication.take() == Some(index);
        let cwd = cwd(c, attempts)?;
        let target = project_bytes(c, &cwd, target, Path::new(""))?;
        c.proof_io(attempts)?;
        let stamp = stat_fd(held).map_err(metadata)?;
        if self.identity == Some(stamp.identity()) {
            return Err(RarDiagnosticFailure::AliasTarget { ordinal: index as u64 });
        }
        let generation = self.next_generation()?;
        // the bindings at the target: the member's own target binding's neighbours, else (no such binding) by search
        let at = match self.leaf_at(c, index as u64, Some(&target))? {
            Some(b) => self.around(c, b, false)?,
            None => self.lookup(c, &target, false)?,
        };
        for k in at {
            let b = self.index[k];
            for i in [b, self.bindings[b].twin] {
                c.proof_work(1)?;
                if i == NONE {
                    continue;
                }
                self.bindings[i].mark = generation;
                let now = self.observe(c, &self.bindings[i].path, attempts, self.bindings[i].follow)?;
                if now != Some(stamp) {
                    return Err(RarDiagnosticFailure::PublicationUnverified { ordinal: index as u64 });
                }
                self.set_expected(c, i, Some(stamp))?;
            }
        }
        let mut found = false;
        for r in self.chain(c, index as u64)? {
            c.proof_work(1)?;
            let record = &self.records[r];
            let b = &self.bindings[record.binding];
            if !record.leaf {
                continue;
            }
            comparison_work(c, b.path.len(), target.len())?;
            if b.name() == as_path(&target) {
                if record.stage != Some(stamp.identity()) {
                    return Err(RarDiagnosticFailure::PublicationUnverified { ordinal: index as u64 });
                }
                found = true;
            }
        }
        if prepared {
            let mut i = self.open;
            while i != NONE {
                c.proof_work(1)?;
                let next = self.bindings[i].open.next;
                if self.bindings[i].mark != generation {
                    self.bindings[i].mark = generation;
                    let now = self.observe(c, &self.bindings[i].path, attempts, true)?;
                    if now == Some(stamp) {
                        self.set_expected(c, i, now)?;
                    } else if now.is_some() {
                        return Err(RarDiagnosticFailure::BindingChanged { ordinal: Some(self.bindings[i].ordinal) });
                    }
                }
                i = next;
            }
        }
        if let Some(pending) = pending {
            let mut i = self.same_head(c, pending.old.identity())?;
            while i != NONE {
                c.proof_work(1)?;
                let next = self.bindings[i].same.next;
                if self.bindings[i].mark != generation {
                    self.bindings[i].mark = generation;
                    let b = &self.bindings[i];
                    c.proof_work(b.path.len() as u64)?;
                    let now = self
                        .observe(c, &b.path, attempts, b.follow)?
                        .ok_or(RarDiagnosticFailure::BindingChanged { ordinal: Some(b.ordinal) })?;
                    let permitted = Stamp {
                        ctime: now.ctime,
                        links: pending.old.links.checked_sub(1).ok_or(RarDiagnosticFailure::CounterOverflow)?,
                        ..pending.old
                    };
                    let follows_published = b.follow && now == stamp;
                    // Exactly the known link removal may advance ctime. Every
                    // other field stays strict, including all future checkpoints.
                    if b.expected != Some(pending.old) || (!follows_published && now != permitted) {
                        return Err(RarDiagnosticFailure::BindingChanged { ordinal: Some(b.ordinal) });
                    }
                    self.set_expected(c, i, Some(now))?;
                }
                i = next;
            }
        }
        c.release_capacity(target.capacity() as u64)?;
        if !found {
            return Err(RarDiagnosticFailure::PublicationUnverified { ordinal: index as u64 });
        }
        Ok(())
    }
    /// Admits the followed twin of no-follow binding `at`, member `ordinal`'s target, where the engine just placed a
    /// symbolic link, so its referent is checked against the diagnostic file as a link found in preparation is.
    fn admit_twin(
        &mut self,
        c: &mut RarExtractControl,
        at: usize,
        ordinal: u64,
        attempts: &mut u64,
    ) -> Result<(), RarDiagnosticFailure> {
        let parents = checked(c.usage.diagnostics.parents, 1)?;
        if parents > c.limits.diagnostics.parents {
            return Err(RarDiagnosticFailure::Limit(RarDiagnosticLimit::Parents));
        }
        c.reserve_proof(&mut self.bindings, 1)?;
        let name = &self.bindings[at].path;
        let probe = c.proof_path(&name[..name.len() - 1])?;
        let expected = match self.observe(c, &probe, attempts, true) {
            Ok(observation) => observation,
            Err(failure @ RarDiagnosticFailure::Metadata { .. }) => {
                if self.deferred.is_none() {
                    self.deferred = Some(failure);
                }
                None
            }
            Err(failure) => return Err(failure),
        };
        if expected.is_some_and(|stamp| self.identity == Some(stamp.identity())) {
            return Err(RarDiagnosticFailure::AliasTarget { ordinal });
        }
        let id = self.bindings.len();
        self.bindings.push(Binding {
            path: probe,
            expected: None,
            original: expected.map(Stamp::identity),
            follow: true,
            ordinal,
            leaf: true,
            twin: NONE,
            same: UNLINKED,
            open: UNLINKED,
            mark: 0,
            touched: 0,
            slot: NONE,
        });
        self.link_open(id);
        self.set_expected(c, id, expected)?;
        self.bindings[at].twin = id;
        c.usage.diagnostics.parents = parents;
        Ok(())
    }
    /// Takes a link member the engine placed as its own change, as [`Self::published`] does for a file. There is no
    /// held stage to compare with, so the object at the target is checked to be what was placed, seen without
    /// following a link: a symbolic link whose target (read back with `readlinkat`) is the bytes placed, or a regular file for a hard link or copy, and
    /// never the diagnostic file. Only then do the bindings at the target, any reached through a symbolic link just
    /// placed there, and a hard link's earlier file (its link count and ctime alone) take the new observation. Every
    /// other binding stays strict. Each binding takes the first rule that fits it, as one pass over every record
    /// did; the bindings each rule can apply to are found by lookup or from their list.
    #[allow(clippy::too_many_arguments)]
    fn linked(
        &mut self,
        c: &mut RarExtractControl,
        index: usize,
        target: &Path,
        landed: Option<&Path>,
        placed: PlacedLink<'_>,
        attempts: &mut u64,
    ) -> Result<(), RarDiagnosticFailure> {
        let ordinal = index as u64;
        let pending = self.pending_unlink.take().filter(|pending| pending.index == index);
        let prepared = self.pending_publication.take() == Some(index);
        let at_target = landed == Some(target);
        let cwd = cwd(c, attempts)?;
        let target = project_bytes(c, &cwd, target, Path::new(""))?;
        let (mut stamp, mut at) = (None, None);
        if at_target {
            at = self.leaf_at(c, ordinal, Some(&target))?;
            if let Some(i) = at {
                stamp = self.observe(c, &self.bindings[i].path, attempts, false)?;
            }
            let now = stamp.ok_or(RarDiagnosticFailure::PublicationUnverified { ordinal })?;
            if self.identity == Some(now.identity()) {
                return Err(RarDiagnosticFailure::AliasTarget { ordinal });
            }
            let fits = match placed {
                // the link must read back as the very target placed, not only one of its length
                PlacedLink::Symbolic { target: placed } => {
                    now.mode & libc::S_IFMT == libc::S_IFLNK
                        && now.len == placed.len() as u64
                        && match at {
                            Some(i) => {
                                c.proof_work(placed.len() as u64)?;
                                self.link_reads(c, &self.bindings[i].path, placed, attempts)?
                            }
                            None => false,
                        }
                }
                PlacedLink::Hard { .. } | PlacedLink::Copy | PlacedLink::Placeholder => now.regular(),
            };
            if !fits {
                return Err(RarDiagnosticFailure::PublicationUnverified { ordinal });
            }
            // A symbolic link placed where none was has no followed binding: one is added, so its referent is
            // checked against the diagnostic file now and on every later refresh, as a link found in preparation is.
            if let (PlacedLink::Symbolic { .. }, Some(i)) = (placed, at)
                && self.bindings[i].twin == NONE
            {
                self.admit_twin(c, i, ordinal, attempts)?;
            }
        }
        let symbolic = matches!(placed, PlacedLink::Symbolic { .. });
        let source = match placed {
            PlacedLink::Hard { source } => source,
            _ => None,
        };
        let generation = self.next_generation()?;
        if let Some(stamp) = stamp {
            // at the target: the placed object
            let names = match at {
                Some(b) => self.around(c, b, false)?,
                None => self.lookup(c, &target, false)?,
            };
            for k in names {
                let b = self.index[k];
                for i in [b, self.bindings[b].twin] {
                    c.proof_work(1)?;
                    if i == NONE {
                        continue;
                    }
                    self.bindings[i].mark = generation;
                    let r = &self.bindings[i];
                    let now = self.observe(c, &r.path, attempts, r.follow)?;
                    if now.is_some_and(|s| Some(s.identity()) == self.identity) {
                        return Err(r.alias());
                    }
                    // followed, a symbolic link leads wherever its target does; anything else is the placed object
                    if (!r.follow || !symbolic) && now != Some(stamp) {
                        return Err(RarDiagnosticFailure::PublicationUnverified { ordinal });
                    }
                    self.set_expected(c, i, now)?;
                }
            }
            if symbolic {
                // a later member's path now runs through the symbolic link just placed
                let names = match at {
                    Some(b) => self.around(c, b, true)?,
                    None => self.lookup(c, &target, true)?,
                };
                for k in names {
                    let b = self.index[k];
                    for i in [b, self.bindings[b].twin] {
                        c.proof_work(1)?;
                        if i == NONE || self.bindings[i].mark == generation {
                            continue;
                        }
                        self.bindings[i].mark = generation;
                        let r = &self.bindings[i];
                        let now = self.observe(c, &r.path, attempts, r.follow)?;
                        if now.is_some_and(|s| Some(s.identity()) == self.identity) {
                            return Err(r.alias());
                        }
                        self.set_expected(c, i, now)?;
                    }
                }
            }
            if prepared {
                let mut i = self.open;
                while i != NONE {
                    c.proof_work(1)?;
                    let next = self.bindings[i].open.next;
                    if self.bindings[i].mark != generation {
                        self.bindings[i].mark = generation;
                        let r = &self.bindings[i];
                        let now = self.observe(c, &r.path, attempts, true)?;
                        if now.is_some_and(|s| Some(s.identity()) == self.identity) {
                            return Err(r.alias());
                        }
                        if symbolic || now == Some(stamp) {
                            self.set_expected(c, i, now)?;
                        } else if now.is_some() {
                            return Err(RarDiagnosticFailure::BindingChanged { ordinal: Some(r.ordinal) });
                        }
                    }
                    i = next;
                }
            }
        }
        if let Some(source) = source {
            // A hard link (or its stage, removed again) adds a name to the earlier file: only its link count,
            // by at most one, and its ctime may change.
            let mut i = self.same_head(c, source)?;
            while i != NONE {
                c.proof_work(1)?;
                let next = self.bindings[i].same.next;
                let r = &self.bindings[i];
                if r.mark != generation
                    && let Some(old) = r.expected.filter(|old| old.regular())
                {
                    self.bindings[i].mark = generation;
                    let r = &self.bindings[i];
                    let now = self
                        .observe(c, &r.path, attempts, r.follow)?
                        .ok_or(RarDiagnosticFailure::BindingChanged { ordinal: Some(r.ordinal) })?;
                    let permitted = Stamp { ctime: now.ctime, links: now.links, ..old };
                    let counted = now.links == old.links || Some(now.links) == old.links.checked_add(1);
                    if now != permitted || !counted {
                        return Err(RarDiagnosticFailure::BindingChanged { ordinal: Some(r.ordinal) });
                    }
                    self.set_expected(c, i, Some(now))?;
                }
                i = next;
            }
        }
        if let (Some(stamp), Some(pending)) = (stamp, pending) {
            let mut i = self.same_head(c, pending.old.identity())?;
            while i != NONE {
                c.proof_work(1)?;
                let next = self.bindings[i].same.next;
                if self.bindings[i].mark != generation {
                    self.bindings[i].mark = generation;
                    let r = &self.bindings[i];
                    let now = self
                        .observe(c, &r.path, attempts, r.follow)?
                        .ok_or(RarDiagnosticFailure::BindingChanged { ordinal: Some(r.ordinal) })?;
                    let permitted = Stamp {
                        ctime: now.ctime,
                        links: pending.old.links.checked_sub(1).ok_or(RarDiagnosticFailure::CounterOverflow)?,
                        ..pending.old
                    };
                    let follows_placed = r.follow && Some(now) == Some(stamp);
                    if r.expected != Some(pending.old) || (!follows_placed && now != permitted) {
                        return Err(RarDiagnosticFailure::BindingChanged { ordinal: Some(r.ordinal) });
                    }
                    self.set_expected(c, i, Some(now))?;
                }
                i = next;
            }
        }
        c.release_capacity(target.capacity() as u64)
    }
}
fn cwd(c: &mut RarExtractControl, attempts: &mut u64) -> Result<[u8; 4096], RarDiagnosticFailure> {
    let mut bytes = [0; 4096];
    c.proof_work(4096)?;
    c.proof_io(attempts)?;
    if unsafe { libc::getcwd(bytes.as_mut_ptr().cast(), bytes.len()) }.is_null() {
        return Err(metadata(io::Error::last_os_error()));
    }
    Ok(bytes)
}
fn project_bytes(
    c: &mut RarExtractControl,
    cwd: &[u8],
    root: &Path,
    relative: &Path,
) -> Result<Vec<u8>, RarDiagnosticFailure> {
    c.proof_work(cwd.len() as u64)?;
    let cwd = &cwd[..cwd.iter().position(|&b| b == 0).unwrap_or(cwd.len())];
    let root = root.as_os_str().as_bytes();
    let relative = relative.as_os_str().as_bytes();
    let mut out = Vec::new();
    let size = root
        .len()
        .checked_add(relative.len())
        .and_then(|n| n.checked_add(cwd.len()))
        .and_then(|n| n.checked_add(2))
        .ok_or(RarDiagnosticFailure::CounterOverflow)?;
    c.proof_work(
        (size as u64).checked_mul(2).and_then(|n| n.checked_add(1)).ok_or(RarDiagnosticFailure::CounterOverflow)?,
    )?;
    c.reserve_proof(&mut out, size)?;
    if !root.starts_with(b"/") {
        out.extend_from_slice(cwd);
        out.push(b'/');
    }
    out.extend_from_slice(root);
    if !relative.is_empty() {
        if !out.ends_with(b"/") {
            out.push(b'/');
        }
        out.extend_from_slice(relative);
    }
    while out.len() > 1 && out.ends_with(b"/") {
        out.pop();
    }
    Ok(out)
}

fn as_path(bytes: &[u8]) -> &Path {
    Path::new(OsStr::from_bytes(bytes))
}
fn comparison_work(c: &mut RarExtractControl, a: usize, b: usize) -> Result<(), RarDiagnosticFailure> {
    let work = checked(a as u64, b as u64)?
        .checked_mul(4)
        .and_then(|n| n.checked_add(2))
        .ok_or(RarDiagnosticFailure::CounterOverflow)?;
    c.proof_work(work)
}

fn anchored(path: &[u8]) -> &[u8] {
    path.strip_prefix(b"/").unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_link_reads_back_only_as_its_exact_target() {
        use std::os::fd::AsRawFd;
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("abc", dir.path().join("l")).unwrap();
        std::fs::write(dir.path().join("f"), b"abc").unwrap();
        let fd = File::open(dir.path()).unwrap();
        let at = |path: &[u8], expected: &[u8]| link_reads_at(fd.as_raw_fd(), path, expected);
        assert!(at(b"l\0", b"abc").unwrap());
        // the same length is not enough
        assert!(!at(b"l\0", b"abd").unwrap());
        assert!(!at(b"l\0", b"ab").unwrap());
        assert!(at(b"f\0", b"abc").is_err(), "a regular file is no link");
    }
    #[test]
    fn optional_reservation_refusal_retains_owned_cause_and_has_no_allocation_in_cleanup() {
        let mut c = RarExtractControl::new(None, RarOverwriteMode::Ask, RarExtractControlLimits::default());
        crate::test_alloc::REFUSE_ALLOCATIONS.with(|s| s.set(true));
        let error = c.proof_path(b"a").unwrap_err();
        c.mute(error);
        let recovery = c.into_diagnostic();
        crate::test_alloc::REFUSE_ALLOCATIONS.with(|s| s.set(false));
        assert!(matches!(recovery.aftermath.diagnostic_failure, Some(RarDiagnosticFailure::Allocation(_))));
        assert_eq!(recovery.aftermath.usage.diagnostics.capacity_peak, 0);
    }
    #[test]
    fn overflow_never_wraps_into_diagnostic_permission() {
        let mut c = RarExtractControl::new(None, RarOverwriteMode::Ask, RarExtractControlLimits::default());
        c.usage.diagnostics.writer_requests = u64::MAX;
        assert!(c.early_diagnostic().writer().is_none());
        assert_eq!(c.usage.diagnostics.writer_requests, u64::MAX);
        assert!(matches!(c.failure, Some(RarDiagnosticFailure::CounterOverflow)));
        c.usage.diagnostics.checkpoints = u64::MAX;
        assert!(matches!(c.refresh(None), Err(RarDiagnosticFailure::CounterOverflow)));
        assert_eq!(c.usage.diagnostics.checkpoints, u64::MAX);
        c.usage.diagnostics.work = u64::MAX;
        assert!(matches!(c.proof_work(1), Err(RarDiagnosticFailure::CounterOverflow)));
        assert_eq!(c.usage.diagnostics.work, u64::MAX);
        c.usage.diagnostics.io_attempts = u64::MAX;
        assert!(matches!(c.proof_io(&mut 0), Err(RarDiagnosticFailure::CounterOverflow)));
        c.usage.diagnostics.capacity = u64::MAX;
        assert!(matches!(c.proof_capacity(1), Err(RarDiagnosticFailure::CounterOverflow)));
    }
}
