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

//! Pull-driven RAR5 extraction over the single production source driver.
pub(crate) mod memory;
#[cfg(feature = "persistent-partials")]
mod partial;
mod rar4;
#[path = "recovery.rs"]
pub(crate) mod recovery;
mod salvage;
use super::{
    output::{Capacity, DirectoryVerdict, OutputContext, Publication, Stage, Target},
    source::{SourceDriver, SourceStep},
    *,
};
use crate::rar5::{
    framing::{HeaderParser, ParserStep, PhysicalFrame, progressive_fault},
    member::MemberMachine,
    physical::{PhysicalMember, PhysicalModel, PhysicalPart, continuation_issue},
    reader::Block,
};
pub use recovery::ExpectedInner;
use std::{
    ffi::OsString,
    num::NonZeroU64,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};

#[non_exhaustive]
pub enum ProgressiveEvent {
    #[cfg(feature = "persistent-partials")]
    PartialReady {
        member: crate::partial::MemberKey,
        state: crate::partial::PartialState,
    },
    /// A member an earlier persistent session created under the same roots and anchor store was adopted instead
    /// of created: its output and state bundle were reopened (nothing was created or rewritten) and its known
    /// output rehashed. `produced` is its committed `produced`. When `finished` its canonical finish is committed:
    /// its data is not read again and its `MemberFinished` follows with its current outcome. Otherwise extraction
    /// continues from `produced`. Obtain a handle with `partial_file`, as after `PartialReady`.
    #[cfg(feature = "persistent-partials")]
    PartialAdopted {
        member: crate::partial::MemberKey,
        state: crate::partial::PartialState,
        produced: u64,
        finished: bool,
    },
    #[cfg(feature = "persistent-partials")]
    Hole(crate::partial::HoleReport),
    #[cfg(feature = "persistent-partials")]
    PartVerified {
        member: crate::partial::MemberKey,
        check: crate::partial::PartCheck,
    },
    VolumeOpened {
        index: u32,
        id: SourceId,
    },
    /// A damaged header of zero-based `volume` was read past under
    /// [`crate::extract::Options::damaged_input`] (`Salvage` or `Resync`; never under the default `Refuse`, which
    /// fails the session as before). Delivered before anything read from the header, so a member whose header
    /// failed its checksum but parsed has this event just before its `MemberStarted`. Only bytes the source
    /// delivered are judged: a header still to come is waited on and one in a `Hole` answer is `HeaderHole`. Non-empty
    /// means the headers are damaged, as [`crate::extract::Summary::damaged_headers`] does for a whole archive.
    HeaderDamaged {
        volume: u32,
        damage: crate::extract::HeaderDamage,
    },
    MemberStarted {
        member: MemberId,
        name: Arc<Vec<u8>>,
        size: Option<u64>,
    },
    BytesWritten {
        member: MemberId,
        valid_bytes: u64,
        logical_end: u64,
    },
    MemberFinished {
        member: MemberId,
        outcome: MemberOutcome,
    },
    CapacityNeeded {
        retained: u64,
    },
    SessionTerminated {
        failure: ProgressiveFailure,
        artifact: Option<Artifact>,
        cleanup_failure: Option<ProgressiveFailure>,
    },
}
/// A tested member has no publication capability; optional absent checks remain missing.
#[derive(Clone, Debug)]
pub struct TestEvidence {
    inner_size: u64,
    checksum: Option<ChecksumValue>,
    size: CheckVerdict,
    crc32: CheckVerdict,
    blake2sp: CheckVerdict,
    packed: PackedEvidence,
    authentication: AuthenticationEvidence,
}
impl TestEvidence {
    pub fn inner_size(&self) -> u64 {
        self.inner_size
    }
    pub fn checksum(&self) -> Option<&ChecksumValue> {
        self.checksum.as_ref()
    }
    pub fn size_verdict(&self) -> CheckVerdict {
        self.size
    }
    pub fn crc32_verdict(&self) -> CheckVerdict {
        self.crc32
    }
    pub fn blake2sp_verdict(&self) -> CheckVerdict {
        self.blake2sp
    }
    pub fn packed(&self) -> PackedEvidence {
        self.packed
    }
    pub fn authentication(&self) -> AuthenticationEvidence {
        self.authentication
    }
}
#[non_exhaustive]
pub enum MemberOutcome {
    #[cfg(feature = "persistent-partials")]
    PersistentPartial {
        member: crate::partial::MemberKey,
        state: crate::partial::PartialState,
        expected: crate::partial::MemberChecks,
    },
    #[cfg(feature = "persistent-partials")]
    PersistentComplete {
        member: crate::partial::MemberKey,
        state: crate::partial::PartialState,
        verdict: crate::partial::Verdict,
    },
    /// Under [`crate::extract::Options::keep_broken`] with [`crate::extract::UnverifiedOutput::Emit`] only: a
    /// persistent session's member cut off by the failure that ends the session (a missing volume, a set truncated
    /// inside the member). Its output keeps every byte extracted so far, unverified: no check judged it, and no
    /// archive metadata was applied. `missing` lists the output ranges still unknown (holes and the part never
    /// reached), as [`crate::partial::PartialFile::remaining`] does; `state` is the committed state. The session's
    /// failure follows as the next `poll_event` error. Nothing else is committed: a later session over the same
    /// roots and anchor store adopts the member and resumes it from its committed `produced`.
    #[cfg(feature = "persistent-partials")]
    PersistentUnverified {
        member: crate::partial::MemberKey,
        state: crate::partial::PartialState,
        expected: crate::partial::MemberChecks,
        missing: Vec<std::ops::Range<u64>>,
    },
    Tested(TestEvidence),
    Skipped(crate::extract::RarSkipReason),
    /// A persistent session refused the member before creating any output or state for it, skipped its data
    /// (every part, across volumes) without reading it, and goes on with the next member. Extract it with an
    /// ordinary session.
    #[cfg(feature = "persistent-partials")]
    Refused {
        reason: crate::partial::RefusalReason,
    },
    /// Policy completed. False also includes Test and flattened directory entries. In a persistent session,
    /// true when this session created the directory, for this entry or earlier as the parent of a member stored
    /// before it; only such a directory gets the entry's metadata.
    Directory {
        created: bool,
        /// Set when the session lacks whole-set authority to create directories (an undeclared, Opaque source):
        /// nothing was created, and this is the sanitized target path, relative to the destination root and
        /// contained in it, for the caller to create itself. `None` otherwise.
        deferred: Option<std::path::PathBuf>,
    },
    Verified(Verification),
    /// Publication succeeded; a subsequent failure stopped the session. An artifact,
    /// when present, owns only a leftover staging name, never the final target.
    PublishedWithFailure {
        verification: Verification,
        failure: ProgressiveFailure,
        cleanup_failure: Option<ProgressiveFailure>,
        artifact: Option<Artifact>,
    },
    RecoveredInner(Verification),
    Provisional(Artifact),
    Partial(Artifact),
    Stopped {
        inner_offset: u64,
        restart: RestartAvailability,
        failure: ProgressiveFailure,
        artifact: Option<Artifact>,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestartAvailability {
    None,
    EarlierStart { inner_offset: u64 },
    Known { inner_offset: u64, packed_offset: u64 },
}

enum Phase {
    Header,
    Start(Box<PhysicalFrame>),
    Stage,
    Part,
    Finish,
    Verdict,
    NextVolume,
    /// A [`crate::extract::DamagedInput::Resync`] search past an unreadable header.
    Resync(Box<salvage::Resync>),
    Done,
}
/// The longest `Hole` answer a persistent session accepts in one read (see `SourceDriver::allow_long_hole`):
/// 256 MiB, or less where a usize is smaller.
#[cfg(feature = "persistent-partials")]
const LONG_HOLE: u64 = if usize::MAX as u64 > (256 << 20) { 256 << 20 } else { usize::MAX as u64 };
/// A serialized, caller-driven extraction session. Delivered artifacts outlive it.
pub struct ProgressiveSession {
    #[cfg(feature = "persistent-partials")]
    partial: Option<partial::Persistent>,
    driver: SourceDriver,
    output: Option<OutputContext>,
    options: ProgressiveOptions,
    control: SessionControl,
    usage: Usage,
    nonce: NonZeroU64,
    ordinal: u64,
    volume: u32,
    expected: OsString,
    cursor: u64,
    parser: HeaderParser,
    phase: Phase,
    main_seen: bool,
    volume_set: Option<bool>,
    header_encryption: Option<bool>,
    model: PhysicalModel,
    machine: Option<MemberMachine>,
    history: Option<crate::rar5::unpack::Unpacker>,
    history_failure: Option<u64>,
    rar4_independent: Option<rar4::Independent>,
    /// the RAR4 decoder a solid successor goes on from
    rar4_history: Option<crate::rar5::member::Rar4Owner>,
    /// every member so far was written by an archiver older than RAR 2.9, which writes no end-of-archive block
    pre_29: bool,
    /// A pre-2.9 volume that names itself part of a set ended between members (or the rest of a damaged one was
    /// passed over under [`crate::extract::Options::damaged_input`]): the next volume is asked for, and only a sealed
    /// in-memory set (every volume given up front) or a declared last volume may end there with no next volume.
    pre_29_open_end: bool,
    /// Damaged headers read past, each delivered as a [`ProgressiveEvent::HeaderDamaged`].
    damage: std::collections::VecDeque<(u32, crate::extract::HeaderDamage)>,
    /// The bytes a resync searched, kept for the next one.
    resync_window: Vec<u8>,
    /// The resync work done in the current volume.
    resync_work: salvage::ResyncWork,
    solid_archive: Option<bool>,
    archive_format: Option<crate::rar5::RarFormat>,
    disposition: Disposition,
    start_event: Option<ProgressiveEvent>,
    finalizer: Option<MemberMachine>,
    stage: Option<Stage>,
    target: Option<Target>,
    member: Option<MemberId>,
    produced: u64,
    /// the target of the symbolic link being decoded ([`Disposition::Link`])
    link_text: Vec<u8>,
    /// the RAR 5.0 redirection the member is, already checked: placed in place of a file, or recorded when tested
    link_kind: Option<crate::extract::link::LinkKind>,
    /// the members a test session found whole, by name: the files a tested hard link or copy may take (an
    /// extracting session keeps its published files with its output)
    tested: crate::extract::link::Extracted,
    remaining: u64,
    had_stage: bool,
    buffer: Vec<u8>,
    /// Length of a driver read that returned `Pending`; the resumed read must ask for the same length.
    parked_read: Option<usize>,
    verify_job: Option<recovery::VerifyJob>,
    replacement_revision: u64,
    witnesses: Vec<recovery::WireVolume>,
    replacement_epoch: Arc<AtomicU64>,
    recovery_closed: bool,
    extraction_active: bool,
    part_evidence: Vec<PackedEvidence>,
}
enum Disposition {
    Write,
    Test,
    Skip(crate::extract::RarSkipReason),
    Directory,
    /// A RAR 4.x symbolic link: its target is decoded, checked and the link created in place of a file.
    Link,
    /// A persistent session refused the member: its data is skipped without being read.
    #[cfg(feature = "persistent-partials")]
    Refused(crate::partial::RefusalReason),
}
static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);
fn nonce() -> ProgressiveResult<NonZeroU64> {
    allocate_nonce(&NEXT_SESSION)
}
fn allocate_nonce(next: &AtomicU64) -> ProgressiveResult<NonZeroU64> {
    next.try_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(1))
        .ok()
        .and_then(NonZeroU64::new)
        .ok_or_else(|| ProgressiveFailure::new(FailureKind::InvalidCapability))
}
impl ProgressiveSession {
    pub fn new(provider: Box<dyn VolumeSource>, options: ProgressiveOptions) -> ProgressiveResult<Self> {
        Self::validate_options(&options)?;
        let control = SessionControl::default();
        let driver = SourceDriver::new(provider, options.first_name.clone(), options.limits.clone(), control.clone())?;
        Self::assemble(driver, control, options)
    }
    pub fn from_sealed_memory(
        volumes: Vec<(OsString, Box<[u8]>)>,
        options: ProgressiveOptions,
    ) -> ProgressiveResult<Self> {
        Self::validate_options(&options)?;
        let provider = memory::SealedMemory::new(volumes, &options.first_name, &options.limits)?;
        let control = SessionControl::default();
        let driver =
            SourceDriver::sealed_memory(provider, options.first_name.clone(), options.limits.clone(), control.clone())?;
        Self::assemble(driver, control, options)
    }
    fn validate_options(options: &ProgressiveOptions) -> ProgressiveResult<()> {
        // a session chooses members by its own events; the whole-archive member filter doesn't apply here
        // Nor do the rename modes: a session publishes at names it binds ahead of time and has no report to name a
        // renamed file in. Both are refused before any source or output is touched.
        if options.extract.select.is_some() || options.extract.overwrite.rename().is_some() {
            return Err(ProgressiveFailure::new(FailureKind::InvalidCapability));
        }
        let usage = Usage::new(options.limits.clone());
        if options.extract.mode == crate::extract::Mode::Extract {
            usage.check(Resource::ActiveOutputs, 1)?;
            usage.check(Resource::RetainedArtifacts, 1)?;
        }
        usage.check(Resource::MetadataBytes, options.first_name.capacity() as u64)?;
        usage.check(Resource::NameBytes, options.first_name.capacity() as u64)?;
        Ok(())
    }
    fn assemble(driver: SourceDriver, control: SessionControl, options: ProgressiveOptions) -> ProgressiveResult<Self> {
        let usage = driver.shared_usage();
        let output = (options.extract.mode == crate::extract::Mode::Extract)
            .then(|| OutputContext::new(&options, usage.clone(), control.clone()))
            .transpose()?;
        Self::assemble_with_output(driver, control, options, output)
    }
    fn assemble_with_output(
        driver: SourceDriver,
        control: SessionControl,
        options: ProgressiveOptions,
        output: Option<OutputContext>,
    ) -> ProgressiveResult<Self> {
        let usage = driver.shared_usage();
        let nonce = nonce()?;
        let chunk = options.limits.read_chunk.min(options.limits.packed_work_per_poll).min(1 << 20);
        usage.check(Resource::ReadChunk, 1)?;
        usage.check(Resource::PackedWorkPerPoll, 1)?;
        usage.charge(Resource::MetadataBytes, chunk)?;
        usage.charge(Resource::MetadataBytes, (options.first_name.capacity() as u64).saturating_mul(3))?;
        usage.charge(Resource::NameBytes, (options.first_name.capacity() as u64).saturating_mul(3))?;
        let expected = options.first_name.clone();
        let mut parser = HeaderParser::from_start(expected.clone().into(), usage.clone());
        parser.set_rar4_unknown_part_crc(options.rar4_unknown_part_crc);
        parser.set_salvage(options.extract.damaged_input);
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(chunk as usize)
            .map_err(|_| ProgressiveFailure::new(FailureKind::Malformed("input buffer allocation")))?;
        usage.charge(Resource::MetadataBytes, buffer.capacity() as u64 - chunk)?;
        buffer.resize(chunk as usize, 0);
        Ok(Self {
            #[cfg(feature = "persistent-partials")]
            partial: None,
            driver,
            output,
            options,
            control,
            usage,
            nonce,
            ordinal: 0,
            volume: 0,
            expected,
            cursor: 0,
            parser,
            phase: Phase::Header,
            main_seen: false,
            volume_set: None,
            header_encryption: None,
            model: PhysicalModel::default(),
            machine: None,
            history: None,
            history_failure: None,
            rar4_independent: None,
            rar4_history: None,
            pre_29: true,
            pre_29_open_end: false,
            damage: Default::default(),
            resync_window: Vec::new(),
            resync_work: Default::default(),
            solid_archive: None,
            archive_format: None,
            disposition: Disposition::Write,
            start_event: None,
            finalizer: None,
            stage: None,
            target: None,
            member: None,
            produced: 0,
            link_text: Vec::new(),
            link_kind: None,
            tested: Default::default(),
            remaining: 0,
            had_stage: false,
            buffer,
            parked_read: None,
            verify_job: None,
            replacement_revision: 0,
            witnesses: Vec::new(),
            replacement_epoch: Arc::new(AtomicU64::new(0)),
            recovery_closed: false,
            extraction_active: false,
            part_evidence: Vec::new(),
        })
    }
    /// What this session has charged to `resource` so far, and its effective limit. Read-only: a caller can
    /// budget further work (such as a Complete declaration) from real numbers rather than estimates.
    pub fn resource_usage(&self, resource: Resource) -> ResourceUsage {
        let mut usage = self.usage.snapshot(resource);
        // Tracked apart from the charged counters: held descriptors by the source driver, outputs by their quota.
        match resource {
            Resource::VolumeHandles => usage.used = self.driver.held_handles(),
            Resource::ActiveOutputs | Resource::RetainedArtifacts => {
                usage.used = self.output.as_ref().map_or(0, |output| output.occupancy(resource));
            }
            _ => {}
        }
        usage
    }
    /// [`Self::resource_usage`] for every resource, in [`Resource::ALL`] order.
    pub fn resource_usages(&self) -> impl Iterator<Item = (Resource, ResourceUsage)> + '_ {
        Resource::ALL.into_iter().map(|r| (r, self.resource_usage(r)))
    }
    /// The limits this session was opened with, as configured; [`Self::resource_usage`] reports the effective
    /// ceiling after fixed safety clamps.
    pub fn limits(&self) -> &ProgressiveLimits {
        &self.options.limits
    }
    pub fn control(&self) -> SessionControl {
        self.control.clone()
    }
    pub fn poll_event(&mut self, cx: &mut Context<'_>) -> Poll<ProgressiveResult<Option<ProgressiveEvent>>> {
        if self.verify_job.is_some() {
            return Poll::Ready(Err(ProgressiveFailure::new(FailureKind::InvalidCapability)));
        }
        // damage found by the last read is delivered even when that read ended the session
        if let Some((volume, damage)) = self.damage.pop_front() {
            return Poll::Ready(Ok(Some(ProgressiveEvent::HeaderDamaged { volume, damage })));
        }
        // a persistent member a cut-off ended is reported before the failure (Options::keep_broken, Emit)
        #[cfg(feature = "persistent-partials")]
        if let Some(result) = self.partial_ending() {
            return Poll::Ready(result);
        }
        if matches!(self.phase, Phase::Done) {
            self.extraction_active = false;
            return Poll::Ready(Ok(None));
        }
        self.control.register(cx.waker());
        self.extraction_active = true;
        let result = match self.poll_inner(cx) {
            Ok(p) => p,
            Err(e) => Poll::Ready(self.terminate(e)),
        };
        if matches!(
            &result,
            Poll::Ready(
                Err(_)
                    | Ok(None
                        | Some(ProgressiveEvent::MemberFinished { .. } | ProgressiveEvent::SessionTerminated { .. }))
            )
        ) || matches!(self.phase, Phase::Done)
        {
            // a session that reached its end is no longer extracting, whatever its last event (a damaged end
            // header's HeaderDamaged, say)
            self.extraction_active = false;
        }
        result
    }
    fn scope(&self, mut failure: ProgressiveFailure) -> ProgressiveFailure {
        failure.context.member = failure.context.member.or(self.member);
        failure.context.volume_index = failure.context.volume_index.or(Some(self.volume));
        failure.context.packed_offset = failure.context.packed_offset.or(Some(self.cursor));
        failure.context.inner_offset = failure.context.inner_offset.or(self.member.map(|_| self.produced));
        failure
    }
    fn terminate(&mut self, failure: ProgressiveFailure) -> ProgressiveResult<Option<ProgressiveEvent>> {
        let mut failure = self.scope(failure);
        if failure.context.expected.is_none() {
            failure.context.expected = Some(std::mem::take(&mut self.expected));
        }
        self.phase = Phase::Done;
        self.recovery_closed = true;
        self.machine.take();
        self.finalizer.take();
        self.rar4_independent.take();
        self.target.take();
        self.history.take();
        self.rar4_history.take();
        // Options::keep_broken with Emit: a persistent member cut off is reported first, then the failure.
        #[cfg(feature = "persistent-partials")]
        let failure = match self.partial_cut_off(failure) {
            Ok(()) => return self.partial_ending().unwrap_or(Ok(None)),
            Err(failure) => failure,
        };
        if let Some(stage) = self.stage.take() {
            let output = self.output.as_mut().expect("output");
            let mut termination = output.terminate(stage, failure);
            if termination.cleanup_failure.is_some() {
                // Preserve the one actual cleanup failure; do not start a second
                // fallible cleanup or allow its pending metadata to be retried.
                output.skip_directories();
            } else {
                termination.cleanup_failure = output.finish_directories(&mut self.driver).err();
            }
            return Ok(Some(ProgressiveEvent::SessionTerminated {
                failure: termination.failure,
                artifact: termination.artifact,
                cleanup_failure: termination.cleanup_failure,
            }));
        }
        let directory_failure =
            self.output.as_mut().and_then(|output| output.finish_directories(&mut self.driver).err());
        if self.had_stage || directory_failure.is_some() {
            Ok(Some(ProgressiveEvent::SessionTerminated {
                failure,
                artifact: None,
                cleanup_failure: directory_failure,
            }))
        } else {
            Err(failure)
        }
    }
    /// Bytes to request from the driver: a parked read resumes with exactly its earlier length (a retained
    /// driver rejects any other), otherwise `full` bounded by the poll's remaining packed-work budget.
    fn read_len(&mut self, full: usize, work: u64) -> usize {
        match self.parked_read.take() {
            Some(parked) if parked <= full => parked,
            _ => full.min((self.options.limits.packed_work_per_poll.min(1 << 20) - work) as usize),
        }
    }
    fn poll_inner(
        &mut self,
        cx: &mut Context<'_>,
    ) -> ProgressiveResult<Poll<ProgressiveResult<Option<ProgressiveEvent>>>> {
        let mut work = 0u64;
        loop {
            if self.control.is_canceled() {
                return Err(ProgressiveFailure::new(FailureKind::Canceled));
            }
            if let Some((volume, damage)) = self.damage.pop_front() {
                return Ok(Poll::Ready(Ok(Some(ProgressiveEvent::HeaderDamaged { volume, damage }))));
            }
            if work >= self.options.limits.packed_work_per_poll.min(1 << 20) {
                cx.waker().wake_by_ref();
                return Ok(Poll::Pending);
            }
            if let Some(stage) = &mut self.stage {
                let n = stage.fill_step(
                    self.buffer.len().min((self.options.limits.packed_work_per_poll.min(1 << 20) - work) as usize),
                )?;
                if n > 0 {
                    work += n as u64;
                    continue;
                }
            }
            #[cfg(feature = "persistent-partials")]
            if let Some(event) = self.partial.as_mut().and_then(|p| p.ready.take()).map(|(event, _lease)| event) {
                return Ok(Poll::Ready(Ok(Some(event))));
            }
            #[cfg(feature = "persistent-partials")]
            if let Some(report) = self.partial.as_mut().and_then(|p| p.holes.pop_front()) {
                return Ok(Poll::Ready(Ok(Some(ProgressiveEvent::Hole(report)))));
            }
            #[cfg(feature = "persistent-partials")]
            if let Some(event) = self.partial.as_mut().and_then(|p| p.written.take()) {
                return Ok(Poll::Ready(Ok(Some(event))));
            }
            match &self.phase {
                Phase::Done => return Ok(Poll::Ready(Ok(None))),
                Phase::Resync(_) => {
                    if let Some(poll) = self.poll_resync(cx, &mut work)? {
                        return Ok(poll);
                    }
                }
                Phase::NextVolume
                    if self.pre_29_open_end
                        && (self.driver.sealed_volume_count().is_some_and(|n| n <= self.volume as usize + 1)
                            || self.driver.declared_last_volume(self.volume)?) =>
                {
                    // Every volume of a sealed set was given up front, and a final Complete declaration names
                    // every volume of the set: a volume that ends between members with no next volume after it
                    // is the last.
                    self.pre_29_open_end = false;
                    if let Some(output) = &mut self.output {
                        output.finish_directories(&mut self.driver)?;
                    }
                    #[cfg(feature = "persistent-partials")]
                    self.partial_finish_directories()?;
                    self.phase = Phase::Done;
                }
                Phase::NextVolume => {
                    self.pre_29_open_end = false;
                    self.volume = self
                        .volume
                        .checked_add(1)
                        .ok_or_else(|| ProgressiveFailure::new(FailureKind::SourceContract))?;
                    self.expected = crate::volume::next_volume_os(&self.expected)
                        .ok_or_else(|| ProgressiveFailure::new(FailureKind::MissingVolume))?;
                    self.driver.select_volume(VolumeRequest { index: self.volume, expected: self.expected.clone() })?;
                    self.usage.charge(Resource::MetadataBytes, self.expected.capacity() as u64)?;
                    self.parser = HeaderParser::from_start(self.expected.clone().into(), self.usage.clone());
                    self.parser.set_rar4_unknown_part_crc(self.options.rar4_unknown_part_crc);
                    self.parser.set_salvage(self.damaged_input());
                    self.resync_work = Default::default();
                    self.cursor = 0;
                    self.main_seen = false;
                    self.phase = Phase::Header;
                }
                Phase::Start(_) => {
                    let Phase::Start(frame) = std::mem::replace(&mut self.phase, Phase::Part) else { unreachable!() };
                    let event = self.start(*frame)?;
                    if matches!(self.disposition, Disposition::Write) {
                        self.start_event = Some(event);
                        self.phase = Phase::Stage;
                    } else {
                        return Ok(Poll::Ready(Ok(Some(event))));
                    }
                }
                Phase::Stage => {
                    #[cfg(feature = "persistent-partials")]
                    if self.partial.is_some() {
                        self.partial_create()?;
                        self.phase = Phase::Part;
                        return Ok(Poll::Ready(Ok(self.start_event.take())));
                    }
                    let output = self.output.as_mut().expect("extract output");
                    match output.poll_capacity(cx)? {
                        Capacity::Needed { retained } => {
                            return Ok(Poll::Ready(Ok(Some(ProgressiveEvent::CapacityNeeded { retained }))));
                        }
                        Capacity::Pending => return Ok(Poll::Pending),
                        Capacity::Ready => {}
                    }
                    let member = self.model.members.last().expect("member");
                    let mut stage = output.create(self.member.expect("member"), member.unpacked_size)?;
                    self.had_stage = true;
                    stage.bind_target(self.target.as_mut().expect("target"))?;
                    if let Some(identity) = self.target.as_ref().and_then(|target| target.stage_identity()) {
                        // A growing declaration must never name this file as an input.
                        self.driver.record_output(identity)?;
                    }
                    stage.set_metadata(self.options.extract.rar_meta(&member.header));
                    self.stage = Some(stage);
                    self.phase = Phase::Part;
                    return Ok(Poll::Ready(Ok(self.start_event.take())));
                }
                Phase::Finish => {
                    #[cfg(feature = "persistent-partials")]
                    if self.partial_active() {
                        self.partial_finish_decode()?;
                        continue;
                    }
                    let before = self.produced;
                    if let Some(bound) = &self.rar4_independent {
                        self.driver.validate_current()?;
                        bound.validate(
                            self.member,
                            self.volume,
                            self.driver.observed_info(self.volume),
                            &self.model,
                            &self.witnesses,
                            &self.usage,
                        )?;
                        self.machine.as_ref().expect("machine").check_rar4_binding(bound.binding())?;
                    }
                    let mut machine = self.machine.take().expect("active decoder");
                    let mut sink = StageSink {
                        stage: self.stage.as_mut(),
                        usage: &self.usage,
                        control: &self.control,
                        produced: &mut self.produced,
                        link: matches!(self.disposition, Disposition::Link).then_some(&mut self.link_text),
                        chunk: self.options.limits.read_chunk.min(1 << 20) as usize,
                        failure: None,
                        fill: match self.options.hole_policy {
                            HolePolicy::PartialStored { fill } => fill,
                            _ => HoleFill::Sparse,
                        },
                    };
                    let result = machine.finish_decode(&mut sink);
                    if let Some(e) = sink.failure {
                        return Err(e);
                    }
                    if let Err(error) = result {
                        return self.member_error(error).map(|e| Poll::Ready(Ok(Some(e))));
                    }
                    self.driver.validate_current()?;
                    self.finalizer = Some(machine);
                    self.phase = Phase::Verdict;
                    if self.stage.is_some() && self.produced > before {
                        return Ok(Poll::Ready(Ok(Some(ProgressiveEvent::BytesWritten {
                            member: self.member.expect("member"),
                            valid_bytes: self.produced - before,
                            logical_end: self.produced,
                        }))));
                    }
                }
                Phase::Verdict => {
                    #[cfg(feature = "persistent-partials")]
                    if self.partial_active() {
                        return self.partial_finish(cx);
                    }
                    return self.finish().map(|e| Poll::Ready(Ok(Some(e))));
                }
                Phase::Header => {
                    let (_, step) = match self.parser.advance_salvaging(&[])? {
                        Ok(step) => step,
                        Err(kind) => {
                            self.salvage_header(kind)?;
                            continue;
                        }
                    };
                    let (offset, len) = match step {
                        ParserStep::LegacyKeyRequired { salt } => {
                            let password = self
                                .options
                                .password()
                                .filter(|p| !p.is_empty())
                                .ok_or_else(|| ProgressiveFailure::new(FailureKind::PasswordRequired))?;
                            let (key, iv) = crate::rar5::member::controlled_legacy_keys(
                                password,
                                &salt,
                                &self.usage,
                                &self.control,
                            )?;
                            self.parser.set_legacy_keys(&key, iv)?;
                            continue;
                        }
                        ParserStep::Need { offset, len } => (offset, len),
                        // only a salvaging parser knows the volume's length: it ends here without its end header
                        ParserStep::End if self.parser.salvages() => {
                            self.salvage_volume_end()?;
                            continue;
                        }
                        ParserStep::End => return Err(self.parser.truncated()),
                        ParserStep::Frame(_) => unreachable!("frames require input"),
                    };
                    if offset != self.cursor {
                        self.driver.seek(offset)?;
                        self.cursor = offset;
                    }
                    let n = self.read_len(len.min(self.buffer.len()), work);
                    match self.driver.poll_step(cx, &mut self.buffer[..n]) {
                        Poll::Pending => {
                            self.parked_read = Some(n);
                            #[cfg(feature = "persistent-partials")]
                            self.partial_wait()?;
                            return Ok(Poll::Pending);
                        }
                        Poll::Ready(Err(e)) => return Err(e),
                        Poll::Ready(Ok(SourceStep::VolumeOpened { index, id })) => {
                            self.driver.validate_step()?;
                            // Under salvage a header or data running past a volume's known end is a volume cut
                            // short, as for a whole volume. An open-ended source (a growing file) has no known end.
                            if self.parser.salvages()
                                && let Some(info) = self.driver.observed_info(index)
                                && info.length.value() != u64::MAX
                            {
                                self.parser.set_complete_len(info.length.value());
                            }
                            return Ok(Poll::Ready(Ok(Some(ProgressiveEvent::VolumeOpened { index, id }))));
                        }
                        Poll::Ready(Ok(SourceStep::EndOfVolume))
                            if self.main_seen
                                && self.ordinal > 0
                                && self.pre_29
                                && self.parser.at_rar4_block_start() =>
                        {
                            // Archives older than RAR 2.9 write no end-of-archive block: UnRAR ends them at a block
                            // boundary, going on to the next volume while a member waits for its next part.
                            // A volume whose main header has MHD_VOLUME set expects more volumes, so ending
                            // between members there is not the end of the set: ask for the next one.
                            if self.member.is_some() {
                                self.phase = Phase::NextVolume;
                            } else if self.volume_set == Some(true) {
                                self.pre_29_open_end = true;
                                self.phase = Phase::NextVolume;
                            } else {
                                if let Some(output) = &mut self.output {
                                    output.finish_directories(&mut self.driver)?;
                                }
                                #[cfg(feature = "persistent-partials")]
                                self.partial_finish_directories()?;
                                self.phase = Phase::Done;
                            }
                        }
                        Poll::Ready(Ok(SourceStep::EndOfVolume)) if self.parser.salvages() => {
                            self.salvage_volume_end()?;
                        }
                        Poll::Ready(Ok(SourceStep::EndOfVolume)) => {
                            return Err(self.parser.truncated());
                        }
                        Poll::Ready(Ok(SourceStep::Hole { .. })) => {
                            return Err(ProgressiveFailure::new(FailureKind::HeaderHole));
                        }
                        Poll::Ready(Ok(SourceStep::Filled { offset, count })) => {
                            self.cursor = offset + count as u64;
                            work += count as u64;
                            recovery::record_header(
                                &mut self.witnesses,
                                self.volume,
                                offset,
                                &self.buffer[..count],
                                &self.usage,
                            )?;
                            #[cfg(feature = "persistent-partials")]
                            if let Some(partial) = &mut self.partial {
                                partial.record_header(offset, &self.buffer[..count], &self.usage)?;
                            }
                            let (used, step) = match self.parser.advance_salvaging(&self.buffer[..count])? {
                                Ok(step) => step,
                                Err(kind) => {
                                    self.driver.validate_step()?;
                                    self.salvage_header(kind)?;
                                    continue;
                                }
                            };
                            if used != count {
                                return Err(ProgressiveFailure::new(FailureKind::SourceContract));
                            }
                            self.driver.validate_step()?;
                            if let ParserStep::Frame(frame) = step
                                && (!frame.damaged || self.damaged_frame(&frame)?)
                            {
                                #[cfg(feature = "persistent-partials")]
                                if let Some(partial) = &mut self.partial {
                                    partial.frame_header(self.volume, &frame, &self.usage)?;
                                }
                                self.frame(frame)?;
                            }
                        }
                    }
                }
                Phase::Part => {
                    #[cfg(feature = "persistent-partials")]
                    if self.partial_resuming() {
                        match self.partial_resume_step(cx, &mut work)? {
                            partial::ResumeStep::Continue => continue,
                            partial::ResumeStep::Pending => return Ok(Poll::Pending),
                            partial::ResumeStep::Done => {}
                        }
                    }
                    #[cfg(feature = "persistent-partials")]
                    if self.remaining > 0 && matches!(self.disposition, Disposition::Refused(_)) {
                        self.partial_skip_refused()?;
                        continue;
                    }
                    if self.remaining == 0 {
                        #[cfg(feature = "persistent-partials")]
                        if self.partial_active() {
                            self.partial_part_damage()?;
                        }
                        let part = self.model.parts.last().expect("active part");
                        if let Some(machine) = &mut self.machine {
                            machine.finish_part(part)?;
                            self.usage.charge(Resource::MetadataBytes, std::mem::size_of::<PackedEvidence>() as u64)?;
                            self.usage.charge(Resource::SourceBookkeeping, self.part_evidence.len() as u64)?;
                            self.part_evidence
                                .try_reserve_exact(1)
                                .map_err(|_| ProgressiveFailure::new(FailureKind::InvalidCapability))?;
                            self.part_evidence.push(if machine.part_missing() {
                                PackedEvidence::Missing
                            } else {
                                PackedEvidence::Passed
                            });
                        }
                        self.phase = if part.final_part {
                            if self.machine.is_some() { Phase::Finish } else { Phase::Verdict }
                        } else {
                            Phase::Header
                        };
                        #[cfg(feature = "persistent-partials")]
                        if let Some(event) = self.partial_part_event()? {
                            return Ok(Poll::Ready(Ok(Some(event))));
                        }
                        continue;
                    }
                    let n = self.read_len(self.remaining.min(self.buffer.len() as u64) as usize, work);
                    // A persistent session records a hole without buffering it, so the source may answer one
                    // longer than the buffer, up to the end of this part: one record and one event per range.
                    // At most LONG_HOLE per answer, so recording one (a pass over its blocks when encrypted)
                    // stays a bounded step between cancellation checks, and its length fits a usize.
                    #[cfg(feature = "persistent-partials")]
                    if self.partial_active() {
                        self.driver.allow_long_hole(self.remaining.min(LONG_HOLE));
                    }
                    match self.driver.poll_step(cx, &mut self.buffer[..n]) {
                        Poll::Pending => {
                            self.parked_read = Some(n);
                            #[cfg(feature = "persistent-partials")]
                            self.partial_wait()?;
                            return Ok(Poll::Pending);
                        }
                        Poll::Ready(Err(e)) => return Err(e),
                        Poll::Ready(Ok(SourceStep::EndOfVolume)) => {
                            return Err(ProgressiveFailure::new(FailureKind::Truncated));
                        }
                        Poll::Ready(Ok(SourceStep::VolumeOpened { .. })) => {
                            return Err(ProgressiveFailure::new(FailureKind::SourceContract));
                        }
                        Poll::Ready(Ok(SourceStep::Hole { offset, len })) => {
                            self.cursor = offset + len;
                            #[cfg(feature = "persistent-partials")]
                            if self.partial_active() {
                                self.remaining -= len;
                                // Recorded holes are delivered from the queue before any further read.
                                self.partial_feed(len as usize, Some(offset))?;
                                continue;
                            }
                            let recover = self.stage.is_some()
                                && matches!(self.options.hole_policy, HolePolicy::PartialStored { .. })
                                && self.model.members.last().is_some_and(|m| {
                                    m.header.method == 0 && (!m.header.encrypted || m.unpacked_size.is_some())
                                });
                            if recover {
                                self.remaining -= len;
                                work += len;
                                self.machine
                                    .as_mut()
                                    .expect("machine")
                                    .reserve_progressive_scratch(len as usize, &self.usage)?;
                                let mut sink = StageSink {
                                    stage: self.stage.as_mut(),
                                    usage: &self.usage,
                                    control: &self.control,
                                    produced: &mut self.produced,
                                    link: matches!(self.disposition, Disposition::Link).then_some(&mut self.link_text),
                                    chunk: self.options.limits.read_chunk.min(1 << 20) as usize,
                                    failure: None,
                                    fill: match self.options.hole_policy {
                                        HolePolicy::PartialStored { fill } => fill,
                                        _ => unreachable!(),
                                    },
                                };
                                let result =
                                    self.machine.as_mut().expect("machine").feed_stored(None, len as usize, &mut sink);
                                if let Some(e) = sink.failure {
                                    return Err(e);
                                }
                                result?;
                                self.driver.validate_step()?;
                                continue;
                            }
                            let mut failure = ProgressiveFailure::new(FailureKind::DataHole);
                            failure.context.packed_offset = Some(offset);
                            if self.model.parts.last().expect("part").final_part {
                                return self.stop(failure).map(|e| Poll::Ready(Ok(Some(e))));
                            }
                            return Err(failure);
                        }
                        Poll::Ready(Ok(SourceStep::Filled { offset, count })) => {
                            self.cursor = offset + count as u64;
                            self.remaining -= count as u64;
                            work += count as u64;
                            #[cfg(feature = "persistent-partials")]
                            if self.partial_active() {
                                let written = self.partial_feed(count, None)?;
                                if written == 0 {
                                    continue;
                                }
                                let event = ProgressiveEvent::BytesWritten {
                                    member: self.member.unwrap(),
                                    valid_bytes: written,
                                    logical_end: self.produced,
                                };
                                // A data feed of an encrypted member can record a CipherNeighbour hole below
                                // `logical_end`: deliver it first.
                                let persistent = self.partial.as_mut().unwrap();
                                if persistent.holes.is_empty() {
                                    return Ok(Poll::Ready(Ok(Some(event))));
                                }
                                persistent.written = Some(event);
                                continue;
                            }
                            let before = self.stage.as_ref().map_or(self.produced, |s| s.valid);
                            let mut sink = StageSink {
                                stage: self.stage.as_mut(),
                                usage: &self.usage,
                                control: &self.control,
                                produced: &mut self.produced,
                                link: matches!(self.disposition, Disposition::Link).then_some(&mut self.link_text),
                                chunk: self.options.limits.read_chunk.min(1 << 20) as usize,
                                failure: None,
                                fill: match self.options.hole_policy {
                                    HolePolicy::PartialStored { fill } => fill,
                                    _ => HoleFill::Sparse,
                                },
                            };
                            let result = if let Some(machine) = &mut self.machine {
                                if matches!(self.options.hole_policy, HolePolicy::PartialStored { .. })
                                    && self.model.members.last().is_some_and(|m| m.header.method == 0)
                                    && sink.stage.is_some()
                                {
                                    machine.reserve_progressive_scratch(count, &self.usage)?;
                                    machine.feed_stored(Some(&self.buffer[..count]), count, &mut sink)
                                } else {
                                    machine.feed(&self.buffer[..count], &mut sink)
                                }
                            } else {
                                Ok(())
                            };
                            if let Some(e) = sink.failure {
                                return Err(e);
                            }
                            if let Err(error) = result {
                                return self.member_error(error).map(|e| Poll::Ready(Ok(Some(e))));
                            }
                            self.driver.validate_step()?;
                            if self.stage.as_ref().is_some_and(|s| s.valid > before) {
                                return Ok(Poll::Ready(Ok(Some(ProgressiveEvent::BytesWritten {
                                    member: self.member.expect("member"),
                                    valid_bytes: self.stage.as_ref().unwrap().valid - before,
                                    logical_end: self.produced,
                                }))));
                            }
                        }
                    }
                }
            }
        }
    }
    fn frame(&mut self, frame: PhysicalFrame) -> ProgressiveResult<()> {
        match &frame.block {
            Block::Crypt => {
                #[cfg(feature = "persistent-partials")]
                if self.partial.is_some() {
                    return Err(partial::error(crate::partial::PartialErrorKind::UnsupportedMethod));
                }
                if self.main_seen || self.parser.encrypted() {
                    return Err(ProgressiveFailure::new(FailureKind::Malformed("encryption header order")));
                }
                let params = frame
                    .header_crypt
                    .ok_or_else(|| ProgressiveFailure::new(FailureKind::Malformed("encryption header")))?
                    .map_err(|e| {
                        progressive_fault(crate::error::RarFault::new(
                            crate::error::RarFailure::crypt(
                                e,
                                crate::error::RarScope::Header { volume: self.expected.clone().into() },
                            ),
                            crate::Error::Encrypted,
                        ))
                    })?;
                let password =
                    self.options.password().ok_or_else(|| ProgressiveFailure::new(FailureKind::PasswordRequired))?;
                self.parser.enable_encryption(password, params, &self.usage, &self.control)?;
            }
            Block::Main(main) => {
                let format = self.parser.format();
                // RAR4 header encryption (`-hp`) is refused like RAR5's, before the first encrypted header is read.
                #[cfg(feature = "persistent-partials")]
                if self.partial.is_some() && format == crate::rar5::RarFormat::Rar4 && self.parser.encrypted() {
                    return Err(partial::error(crate::partial::PartialErrorKind::UnsupportedMethod));
                }
                if self.archive_format.is_some_and(|prior| prior != format) {
                    return Err(ProgressiveFailure::new(FailureKind::Malformed("volume archive format changed")));
                }
                self.archive_format = Some(format);
                let encrypted = self.parser.encrypted();
                if self.header_encryption.is_some_and(|initial| initial != encrypted) {
                    return Err(ProgressiveFailure::new(FailureKind::Malformed("volume header encryption changed")));
                }
                self.header_encryption = Some(encrypted);
                if self.main_seen
                    || (main.flags & crate::rar5::MHFL_VOLNUMBER != 0 && main.volume_number != u64::from(self.volume))
                    || (self.volume > 0 && !main.is_volume())
                    || self.volume_set.is_some_and(|v| v != main.is_volume())
                {
                    return Err(ProgressiveFailure::new(FailureKind::Malformed("volume main identity/order")));
                }
                if self.solid_archive.is_some_and(|solid| solid != main.is_solid()) {
                    return Err(ProgressiveFailure::new(FailureKind::Malformed("volume solid flag changed")));
                }
                self.solid_archive = Some(main.is_solid());
                self.volume_set = Some(main.is_volume());
                self.main_seen = true;
            }
            Block::File(header) => {
                // RAR 2.9 introduced the extended-time record and always writes an end-of-archive block.
                if header.rar4.is_none_or(|raw| raw.unpack_version >= 29 || raw.flags & 0x1000 != 0) {
                    self.pre_29 = false;
                }
                // A member a persistent session refuses is never decoded: only what walking past its data needs
                // is checked (the continuation identity of its later parts below).
                #[cfg(feature = "persistent-partials")]
                let refused = self.partial_refused(header)?;
                #[cfg(not(feature = "persistent-partials"))]
                let refused = false;
                if !refused
                    && let Some(reason) = header
                        .rar4_progressive_unsupported(frame.wire.as_ref().and_then(|w| w.legacy).and_then(|w| w.crypt))
                {
                    return Err(ProgressiveFailure::new(FailureKind::Rar(Box::new(
                        crate::error::RarFailure::Unsupported(reason),
                    ))));
                }
                if !self.main_seen {
                    return Err(ProgressiveFailure::new(FailureKind::Malformed("member before main")));
                }
                if !refused && let Some(Err(error)) = frame.crypt {
                    return Err(progressive_fault(crate::error::RarFault::new(
                        crate::error::RarFailure::crypt(
                            error,
                            crate::error::RarScope::Member {
                                index: Some(self.member.map_or(self.ordinal, |member| member.ordinal)),
                            },
                        ),
                        crate::Error::Encrypted,
                    )));
                }
                if self.member.is_some() {
                    let member = self.model.members.last_mut().expect("member");
                    let wire = frame
                        .wire
                        .as_ref()
                        .ok_or_else(|| ProgressiveFailure::new(FailureKind::Malformed("missing wire identity")))?;
                    if member.wire.legacy.and_then(|w| w.crypt) != wire.legacy.and_then(|w| w.crypt) {
                        return Err(ProgressiveFailure::new(FailureKind::Rar(Box::new(
                            crate::error::RarFailure::Unsupported(crate::error::RarUnsupported::Rar4Feature(
                                "changed split encryption salt or scheme",
                            )),
                        ))));
                    }
                    if member.complete
                        || !member.matches_continuation(header, wire)
                        || continuation_issue(member, header).is_some()
                        || member.wire.compression != wire.compression
                    {
                        return Err(ProgressiveFailure::new(FailureKind::Malformed("member continuation identity")));
                    }
                    self.usage.charge(Resource::Parts, 1)?;
                    self.usage.charge(Resource::MetadataBytes, std::mem::size_of::<PhysicalPart>() as u64)?;
                    let part = PhysicalPart::new(self.volume as usize, header, frame.crypt, wire);
                    member.append(header, &part).map_err(progressive_fault)?;
                    if let Some(machine) = &mut self.machine {
                        machine.begin_part(&part);
                        machine.extend_rar4(part.packed_size)?;
                    }
                    self.remaining = part.packed_size;
                    self.model
                        .parts
                        .try_reserve_exact(1)
                        .map_err(|_| ProgressiveFailure::new(FailureKind::Malformed("part allocation")))?;
                    self.model.parts.push(part);
                    #[cfg(feature = "persistent-partials")]
                    if self.partial_active() {
                        self.partial_extend()?;
                    }
                    self.phase = Phase::Part;
                } else {
                    self.usage.charge(Resource::MetadataBytes, std::mem::size_of::<PhysicalFrame>() as u64)?;
                    self.phase = Phase::Start(Box::new(frame));
                }
            }
            Block::End { more_volumes, .. } => {
                if !self.main_seen {
                    return Err(ProgressiveFailure::new(FailureKind::Malformed("end before main")));
                }
                if *more_volumes {
                    self.phase = Phase::NextVolume;
                } else if self.member.is_some() {
                    return Err(ProgressiveFailure::new(FailureKind::Truncated));
                } else {
                    if let Some(output) = &mut self.output {
                        output.finish_directories(&mut self.driver)?;
                    }
                    #[cfg(feature = "persistent-partials")]
                    self.partial_finish_directories()?;
                    self.phase = Phase::Done;
                }
            }
            Block::Service(_) | Block::Unknown => {
                if !self.main_seen {
                    return Err(ProgressiveFailure::new(FailureKind::Malformed("block before main")));
                }
            }
        }
        Ok(())
    }
    fn start(&mut self, frame: PhysicalFrame) -> ProgressiveResult<ProgressiveEvent> {
        // a folder whose damaged header claims data is created and its data passed over, as UnRAR 7.30 does
        let damaged = frame.damaged;
        let Block::File(header) = frame.block else { unreachable!() };
        #[cfg(feature = "persistent-partials")]
        let refusal = self.partial.as_ref().and_then(|_| partial::refusal(&header));
        #[cfg(not(feature = "persistent-partials"))]
        let refusal: Option<std::convert::Infallible> = None;
        if refusal.is_none()
            && let Some(reason) =
                header.rar4_progressive_unsupported(frame.wire.as_ref().and_then(|w| w.legacy).and_then(|w| w.crypt))
        {
            return Err(ProgressiveFailure::new(FailureKind::Rar(Box::new(crate::error::RarFailure::Unsupported(
                reason,
            )))));
        }
        if header.split_before() {
            return Err(ProgressiveFailure::new(FailureKind::Malformed("orphan continuation")));
        }
        self.usage.charge(Resource::Entries, 1)?;
        self.usage.charge(Resource::Parts, 1)?;
        self.usage.charge(
            Resource::MetadataBytes,
            (std::mem::size_of::<PhysicalMember>() + std::mem::size_of::<PhysicalPart>()) as u64,
        )?;
        let wire = frame
            .wire
            .ok_or_else(|| ProgressiveFailure::new(FailureKind::Malformed("missing member wire identity")))?;
        let name = wire.name.clone();
        let member = MemberId { session: self.nonce, ordinal: self.ordinal };
        self.ordinal =
            self.ordinal.checked_add(1).ok_or_else(|| ProgressiveFailure::new(FailureKind::InvalidCapability))?;
        self.member = Some(member);
        self.produced = 0;
        self.part_evidence.clear();
        let size = (!header.size_unknown()).then_some(header.unpacked_size);
        // A refused member's name is never used, so it is not checked either.
        if refusal.is_none() && (self.options.extract.mode == crate::extract::Mode::Test || header.is_dir()) {
            self.usage.charge(Resource::MetadataBytes, (header.name.len() as u64).saturating_mul(3))?;
            self.usage.charge(Resource::SourceBookkeeping, (header.name.len() as u64).saturating_mul(8))?;
            let name = header.output_name().unwrap_or(std::borrow::Cow::Borrowed(&header.name));
            crate::path::sanitize_fallible(&name, !header.is_unix())
                .map_err(|_| ProgressiveFailure::new(FailureKind::UnsafePath))?;
        }
        // A RAR 5.0 redirection is checked as soon as its header is in: a symbolic link's target must stay inside
        // the destination, and a hard link or file copy must take a file this session published or tested.
        self.link_kind = None;
        let mut unverified_link = None;
        // An encrypted link whose password needs no checking by its cipher: let go (PlaceUnverified) or already
        // verified (VerifyFirst), with the evidence it reports
        let mut checked_link = None;
        let mut link_rel = None;
        if let Some(redirection) = header.redirection.as_ref().filter(|_| refusal.is_none()) {
            let unsupported = || {
                ProgressiveFailure::new(FailureKind::Rar(Box::new(crate::error::RarFailure::Unsupported(
                    crate::error::RarUnsupported::Redirection { kind: redirection.kind() },
                ))))
            };
            let extract = &self.options.extract;
            let kind = crate::extract::link::from_rar5(
                redirection,
                !header.is_unix(),
                extract.windows_safe_names,
                extract.flatten,
            );
            // Options::encrypted_links: VerifyFirst reports a password that doesn't verify before the link's target
            // and the overwrite decision are looked at (an older revision is still skipped first, as it is below)
            if kind.is_some()
                && header.encrypted
                && extract.encrypted_links == crate::extract::EncryptedLinks::VerifyFirst
                && (header.version.is_none() || extract.mode == crate::extract::Mode::Test)
            {
                checked_link = Some(self.link_password_first(&header, member.ordinal)?);
            }
            let extract = &self.options.extract;
            match kind {
                None => return Err(unsupported()),
                Some(Err(_)) => return Err(ProgressiveFailure::new(FailureKind::UnsafePath)),
                Some(Ok(_)) if !cfg!(unix) && extract.mode != crate::extract::Mode::Test => return Err(unsupported()),
                Some(Ok(kind)) => {
                    // its target is checked once the disposition says it is placed or tested (below)
                    link_rel = Some(self.link_rel(&header)?);
                    // An encrypted link is placed only on a password its check value verifies: the member's cipher
                    // refuses no password or a wrong one, and one with no usable check value is refused, as a link has
                    // no data to check a password against (`crate::extract::link::rar5_password`). The refusal waits
                    // for the disposition: a member that is skipped (an older revision, an existing target) is never
                    // placed or tested, so it is skipped as before.
                    // Options::encrypted_links set to PlaceUnverified lets the password go unchecked, as 7-Zip does.
                    if header.encrypted
                        && self.options.password().is_some_and(|p| !p.is_empty())
                        && extract.encrypted_links != crate::extract::EncryptedLinks::PlaceUnverified
                    {
                        unverified_link = header.crypt.as_ref().and_then(crate::extract::link::rar5_unverifiable);
                    }
                    self.link_kind = Some(kind);
                }
            }
        }
        // A name mapped from bytes that aren't UTF-8 is written under its private-use characters
        // (`crate::path::rar_output_name`); one that can't be written one to one is refused, and so is any mapped
        // name in a persistent session, whose states record the name as decoded.
        #[cfg(feature = "persistent-partials")]
        let persistent = self.partial.is_some();
        #[cfg(not(feature = "persistent-partials"))]
        let persistent = false;
        if refusal.is_none()
            && self.options.extract.mode != crate::extract::Mode::Test
            && (header.output_name().is_none() || (persistent && header.name.contains('\u{FFFE}')))
        {
            return Err(ProgressiveFailure::new(FailureKind::Rar(Box::new(crate::error::RarFailure::Unsupported(
                crate::error::RarUnsupported::NameEncoding,
            )))));
        }
        #[cfg(feature = "persistent-partials")]
        let refused = refusal.map(Disposition::Refused);
        #[cfg(not(feature = "persistent-partials"))]
        let refused: Option<Disposition> = None;
        self.disposition = if let Some(refused) = refused {
            refused
        } else if let Some(version) = header.version.filter(|_| self.options.extract.mode != crate::extract::Mode::Test)
        {
            // An older file revision is skipped, a folder too, as every route skips it unless revisions are asked
            // for (a progressive session never asks).
            if header.is_dir()
                && (header.split_after()
                    || header.packed_size != 0
                    || header.size_unknown()
                    || header.unpacked_size != 0)
            {
                return Err(ProgressiveFailure::new(FailureKind::Malformed("directory payload or continuation")));
            }
            Disposition::Skip(crate::extract::RarSkipReason::OlderVersion(version))
        } else if header.is_dir() {
            if header.split_after()
                || (!damaged && (header.packed_size != 0 || header.size_unknown() || header.unpacked_size != 0))
            {
                return Err(ProgressiveFailure::new(FailureKind::Malformed("directory payload or continuation")));
            }
            Disposition::Directory
        } else if self.options.extract.mode == crate::extract::Mode::Test {
            Disposition::Test
        } else {
            #[cfg(feature = "persistent-partials")]
            if self.partial.is_some() {
                Disposition::Write
            } else {
                self.prepare_legacy_target(member, &header)?
            }
            #[cfg(not(feature = "persistent-partials"))]
            self.prepare_legacy_target(member, &header)?
        };
        if self.link_kind.is_some() && matches!(self.disposition, Disposition::Write) {
            self.disposition = Disposition::Link;
        } else if header.is_rar4_symlink() && matches!(self.disposition, Disposition::Write) {
            if header.unpacked_size > crate::extract::link::MAX_TARGET || !cfg!(unix) {
                return Err(ProgressiveFailure::new(FailureKind::Rar(Box::new(
                    crate::error::RarFailure::Unsupported(crate::error::RarUnsupported::Rar4Feature("symbolic link")),
                ))));
            }
            self.link_text.clear();
            self.disposition = Disposition::Link;
        }
        // A RAR 5.0 redirection placed or tested: a symbolic link's target must stay inside the destination, and a
        // hard link or file copy must take a file this session published or tested. One that is skipped (an older
        // revision, an existing target under Overwrite::Skip, as UnRAR's `-o-` skips it) places and touches nothing,
        // so it is skipped without them.
        if let (Some(rel), Some(kind)) = (&link_rel, &self.link_kind)
            && matches!(self.disposition, Disposition::Link | Disposition::Test)
        {
            let extracted = self.output.as_ref().map_or(&self.tested, |output| &output.extracted);
            if crate::extract::link::refusal_before_place(rel, kind, extracted).is_some() {
                return Err(ProgressiveFailure::new(FailureKind::UnsafePath));
            }
        }
        if let Some(verifier) = unverified_link
            && matches!(self.disposition, Disposition::Link | Disposition::Test)
        {
            return Err(ProgressiveFailure::new(FailureKind::Rar(Box::new(
                crate::error::RarFailure::EncryptedIntegrity {
                    scope: crate::error::RarScope::Member { index: Some(member.ordinal) },
                    reason: crate::error::RarIntegrityReason::UnverifiableLinkPassword,
                    verifier,
                },
            ))));
        }
        let mut context = crate::extract::EntryContext {
            entry: crate::extract::RarEntryIdentity {
                index: Some(member.ordinal),
                order: member.ordinal,
                name: String::new(),
            },
            method: header.method,
            password: crate::error::RarPasswordEvidence::NotEncrypted,
            renamed: None,
            link: None,
        };
        let decode = matches!(self.disposition, Disposition::Write | Disposition::Test | Disposition::Link)
            || (matches!(self.disposition, Disposition::Skip(_))
                && self.solid_archive == Some(true)
                && header.method != 0);
        self.rar4_independent = None;
        let rar4_history = if header.format == crate::rar5::RarFormat::Rar4 && header.method != 0 {
            self.rar4_history.take()
        } else {
            None
        };
        let mut unchecked_sums = false;
        let mut machine = if decode && header.format == crate::rar5::RarFormat::Rar4 && header.method != 0 {
            self.history.take();
            let source = self
                .driver
                .observed_info(self.volume)
                .ok_or_else(|| ProgressiveFailure::new(FailureKind::SourceContract))?;
            let core = rar4::core_frame(member, &header, wire.legacy.and_then(|w| w.crypt))?;
            if header.solid && rar4_history.is_none() {
                // A missing dependency is handled after recording the physical boundary below.
                None
            } else {
                self.usage.charge(Resource::MetadataBytes, std::mem::size_of::<rar4::Independent>() as u64)?;
                let witness = recovery::WireSnapshot::capture_current(&self.witnesses, self.volume, &self.usage)?;
                let stream = crate::rar5::member::Rar4Stream {
                    history: rar4_history.filter(|_| header.solid),
                    solid_archive: self.solid_archive == Some(true),
                    password: self.options.password(),
                    legacy: wire.legacy.and_then(|w| w.crypt),
                };
                let (machine, binding) = MemberMachine::new_rar4(
                    &header,
                    context,
                    core,
                    self.options.limits.decoder_window,
                    &self.usage,
                    &self.control,
                    stream,
                )?;
                // A member split over volumes is checked part by part instead.
                if !header.split_after() {
                    self.rar4_independent =
                        Some(rar4::Independent::new(member, self.volume, source, binding, &header, &wire, witness));
                }
                Some(machine)
            }
        } else if decode && self.link_kind.is_some() && header.packed_size == 0 && !header.split_after() {
            // A RAR 5.0 redirection without data moves past the decoder as the complete route's `past_link` does:
            // a method it carries neither needs a solid predecessor nor resets the history the next file goes on from.
            let mut stored = crate::rar5::FileHeader { method: 0, solid: false, ..header.clone() };
            let mut password = self.options.password();
            if header.encrypted
                && self.options.extract.encrypted_links == crate::extract::EncryptedLinks::PlaceUnverified
            {
                checked_link = Some(crate::error::RarPasswordEvidence::Unverified);
            }
            if let Some(evidence) = checked_link.filter(|_| header.encrypted) {
                // Options::encrypted_links: the password isn't checked for an encrypted link (PlaceUnverified, as
                // 7-Zip doesn't check it), or was checked as its header was read (VerifyFirst: no second key
                // derivation). With no data nothing is decrypted, and a checksum of nothing (converted by a key the
                // password may not give) is passed over, here and at the final verdict: the target is all it carries.
                stored.encrypted = false;
                stored.crypt = None;
                stored.crc32 = None;
                stored.blake2sp = None;
                password = None;
                context.password = evidence;
                unchecked_sums = true;
            }
            Some(MemberMachine::new_with_history(
                &stored,
                context,
                password,
                &self.usage,
                &self.control,
                None,
                wire.legacy.and_then(|w| w.crypt),
            )?)
        } else if decode {
            let decoder = if header.method != 0 {
                if header.solid {
                    if !crate::rar5::member::continue_decoder(&mut self.history, header.dictionary, size) {
                        self.history.take();
                        None
                    } else {
                        self.usage.check(Resource::DecoderWindow, self.history.as_ref().unwrap().window_size())?;
                        self.history.take()
                    }
                } else {
                    let window = crate::rar5::unpack::window_for_detailed(
                        header.dictionary,
                        size,
                        self.solid_archive == Some(true),
                    )
                    .map_err(|e| progressive_fault(e.detailed(context.scope())))?;
                    self.usage.check(Resource::DecoderWindow, window.size)?;
                    crate::rar5::member::reset_decoder(
                        &mut self.history,
                        window,
                        size,
                        self.options.extract.threads,
                        self.options.extract.parallel_min,
                    )
                    .map_err(|e| progressive_fault(e.detailed(context.scope())))?;
                    self.usage.check(Resource::DecoderWindow, self.history.as_ref().unwrap().window_size())?;
                    self.history_failure = None;
                    self.history.take()
                }
            } else {
                None
            };
            // A missing dependency is handled after recording the physical boundary below.
            if header.method != 0 && header.solid && decoder.is_none() {
                None
            } else {
                Some(MemberMachine::new_with_history(
                    &header,
                    context,
                    self.options.password(),
                    &self.usage,
                    &self.control,
                    decoder,
                    wire.legacy.and_then(|w| w.crypt),
                )?)
            }
        } else {
            None
        };
        let mut part = PhysicalPart::new(self.volume as usize, &header, frame.crypt, &wire);
        if unchecked_sums {
            part.checks = crate::rar5::session::RarChecks { crc32: None, blake2sp: None, keyed: false };
        }
        if let Some(machine) = &mut machine {
            machine.begin_part(&part);
            // Options::keep_broken: a persistent member failing its checksum is kept, judged Bad by verification.
            #[cfg(feature = "persistent-partials")]
            if self.partial.is_some() && self.options.extract.keep_broken {
                machine.keep_broken();
            }
        }
        self.remaining = part.packed_size;
        self.model.members.clear();
        self.model.parts.clear();
        self.model
            .members
            .try_reserve_exact(1)
            .map_err(|_| ProgressiveFailure::new(FailureKind::Malformed("member allocation")))?;
        self.model
            .parts
            .try_reserve_exact(1)
            .map_err(|_| ProgressiveFailure::new(FailureKind::Malformed("part allocation")))?;
        self.model.members.push(PhysicalMember::new(header, wire, 0, &part).map_err(progressive_fault)?);
        self.model.parts.push(part);
        self.machine = machine;
        if matches!(self.disposition, Disposition::Directory) {
            self.phase = Phase::Verdict;
        }
        Ok(ProgressiveEvent::MemberStarted { member, name, size })
    }
    /// [`crate::extract::EncryptedLinks::VerifyFirst`]: an encrypted RAR 5.0 link's password is checked as its header
    /// is read, as the member's cipher would check it, and one its check value can't verify is refused, as below. On
    /// success, the evidence the member reports (its data-less machine then needs no second derivation).
    fn link_password_first(
        &self,
        header: &crate::rar5::FileHeader,
        ordinal: u64,
    ) -> ProgressiveResult<crate::error::RarPasswordEvidence> {
        let scope = crate::error::RarScope::Member { index: Some(ordinal) };
        let password = self
            .options
            .password()
            .filter(|p| !p.is_empty())
            .ok_or_else(|| ProgressiveFailure::new(FailureKind::PasswordRequired))?;
        let params =
            header.crypt.ok_or_else(|| ProgressiveFailure::new(FailureKind::Malformed("member encryption record")))?;
        if let Some(verifier) = crate::extract::link::rar5_unverifiable(&params) {
            return Err(ProgressiveFailure::new(FailureKind::Rar(Box::new(
                crate::error::RarFailure::EncryptedIntegrity {
                    scope,
                    reason: crate::error::RarIntegrityReason::UnverifiableLinkPassword,
                    verifier,
                },
            ))));
        }
        crate::rar5::member::controlled_keys(password, params, &self.usage, &self.control, scope)
            .map(|keys| keys.evidence)
    }

    /// Where a link member goes, relative to the destination, as its target is checked: a flattened output drops
    /// the member's folders.
    fn link_rel(&self, header: &crate::rar5::FileHeader) -> ProgressiveResult<std::path::PathBuf> {
        let name = header.output_name().unwrap_or(std::borrow::Cow::Borrowed(&header.name));
        let rel = crate::path::sanitize(&name, !header.is_unix())
            .map_err(|_| ProgressiveFailure::new(FailureKind::UnsafePath))?;
        Ok(if self.options.extract.flatten {
            std::path::PathBuf::from(rel.file_name().ok_or_else(|| ProgressiveFailure::new(FailureKind::UnsafePath))?)
        } else {
            rel
        })
    }
    fn prepare_legacy_target(
        &mut self,
        member: MemberId,
        header: &crate::rar5::FileHeader,
    ) -> ProgressiveResult<Disposition> {
        let output = self.output.as_ref().expect("output");
        let name = header.output_name().unwrap_or(std::borrow::Cow::Borrowed(&header.name));
        // Overwrite::Skip: a symbolic link already at the target (one an earlier run placed, say) is skipped, as
        // UnRAR's `-o-` skips it; nothing is written through it or over it
        if self.options.extract.overwrite == crate::extract::Overwrite::Skip
            && output.symlink_at(&name, !header.is_unix())?
        {
            self.target = None;
            return Ok(Disposition::Skip(crate::extract::RarSkipReason::ExistingTarget));
        }
        let target = output.prepare_target(member, &name, !header.is_unix())?;
        let skip = self.options.extract.overwrite == crate::extract::Overwrite::Skip && target.exists();
        if skip {
            output.check_target(&target, &mut self.driver)?;
        }
        self.target = Some(target);
        Ok(if skip { Disposition::Skip(crate::extract::RarSkipReason::ExistingTarget) } else { Disposition::Write })
    }
    fn stop(&mut self, failure: ProgressiveFailure) -> ProgressiveResult<ProgressiveEvent> {
        let mut failure = self.scope(failure);
        if failure.context.expected.is_none() {
            self.usage.charge(Resource::MetadataBytes, self.expected.capacity() as u64)?;
            self.usage.charge(Resource::NameBytes, self.expected.capacity() as u64)?;
            failure.context.expected = Some(self.expected.clone());
        }
        self.machine.take();
        self.finalizer.take();
        self.rar4_independent.take();
        self.target.take();
        if self.model.members.last().is_some_and(|m| m.header.method != 0) {
            self.history.take();
            self.rar4_history.take();
            self.history_failure = self.member.map(|m| m.ordinal);
        }
        let part = self.model.parts.last().expect("part");
        self.driver.seek(part.data_offset + part.packed_size)?;
        self.cursor = part.data_offset + part.packed_size;
        self.phase = Phase::Header;
        let t = if let Some(stage) = self.stage.take() {
            self.output.as_ref().expect("output").terminate(stage, failure)
        } else {
            super::output::Termination { failure, artifact: None, cleanup_failure: None }
        };
        if t.cleanup_failure.is_some() {
            self.phase = Phase::Done;
            return Ok(ProgressiveEvent::SessionTerminated {
                failure: t.failure,
                artifact: t.artifact,
                cleanup_failure: t.cleanup_failure,
            });
        }
        Ok(ProgressiveEvent::MemberFinished {
            member: self.member.take().expect("member"),
            outcome: MemberOutcome::Stopped {
                inner_offset: self.produced,
                restart: RestartAvailability::None,
                failure: t.failure,
                artifact: t.artifact,
            },
        })
    }
    fn member_error(&mut self, failure: ProgressiveFailure) -> ProgressiveResult<ProgressiveEvent> {
        if matches!(failure.kind, FailureKind::Rar(_) | FailureKind::UnsupportedMethod)
            && self.solid_archive == Some(true)
            && self.model.members.last().is_some_and(|member| member.header.method != 0)
            && self.model.parts.last().is_some_and(|part| part.final_part)
        {
            self.stop(failure)
        } else {
            Err(failure)
        }
    }
    fn finish_skip(&mut self, reason: crate::extract::RarSkipReason) -> ProgressiveResult<ProgressiveEvent> {
        self.driver.validate_current()?;
        if let Some(target) = &self.target {
            self.output.as_ref().expect("output").check_target(target, &mut self.driver)?;
        }
        self.target.take();
        self.phase = Phase::Header;
        Ok(ProgressiveEvent::MemberFinished {
            member: self.member.take().unwrap(),
            outcome: MemberOutcome::Skipped(reason),
        })
    }
    fn finish(&mut self) -> ProgressiveResult<ProgressiveEvent> {
        #[cfg(feature = "persistent-partials")]
        if let Disposition::Refused(reason) = self.disposition {
            self.driver.validate_current()?;
            self.phase = Phase::Header;
            return Ok(ProgressiveEvent::MemberFinished {
                member: self.member.take().unwrap(),
                outcome: MemberOutcome::Refused { reason },
            });
        }
        #[cfg(feature = "persistent-partials")]
        if self.partial.is_some() && matches!(self.disposition, Disposition::Directory) {
            return self.partial_directory();
        }
        if matches!(self.disposition, Disposition::Directory) {
            let header = &self.model.members.last().expect("member").header;
            let (created, deferred) =
                if self.options.extract.mode == crate::extract::Mode::Test || self.options.extract.flatten {
                    (false, None)
                } else {
                    match self.output.as_mut().expect("output").directory(
                        self.member.expect("member"),
                        header,
                        &mut self.driver,
                    ) {
                        Ok(DirectoryVerdict::Done { created }) => (created, None),
                        Ok(DirectoryVerdict::Deferred(path)) => (false, Some(path)),
                        Err(e) if matches!(e.kind, FailureKind::PublicationAuthorityRequired) => return self.stop(e),
                        Err(e) => return Err(e),
                    }
                };
            self.phase = Phase::Header;
            return Ok(ProgressiveEvent::MemberFinished {
                member: self.member.take().unwrap(),
                outcome: MemberOutcome::Directory { created, deferred },
            });
        }
        if self.finalizer.is_none() {
            let physical = self.model.members.last().expect("member");
            let needs_history = physical.header.method != 0
                && physical.header.solid
                && (self.solid_archive == Some(true) || !matches!(self.disposition, Disposition::Skip(_)));
            if needs_history {
                return self.stop(ProgressiveFailure::new(FailureKind::Rar(Box::new(
                    crate::error::RarFailure::SolidHistoryUnavailable {
                        predecessor: self.history_failure,
                        cause: None,
                    },
                ))));
            }
            if let Disposition::Skip(reason) = self.disposition {
                return self.finish_skip(reason);
            }
        }
        // The successfully decoded machine lives in a non-feedable slot.
        // Take before the verdict and drop on every result, including failure.
        let mut machine = self.finalizer.take().expect("decoded machine");
        let physical = self.model.members.last().expect("member");
        if let Err(error) = machine.finish_member(physical) {
            return self.member_error(error);
        }
        self.driver.validate_current()?;
        if let Some(bound) = self.rar4_independent.take() {
            bound.validate(
                self.member,
                self.volume,
                self.driver.observed_info(self.volume),
                &self.model,
                &self.witnesses,
                &self.usage,
            )?;
        }
        if let Some(size) = physical.unpacked_size
            && let Some(stage) = &mut self.stage
        {
            stage.reconcile_final_size(size)?;
        }
        if machine.missing && self.stage.is_some() {
            let record = self.recovery_record(&machine)?;
            let mut artifact = self.stage.take().expect("stage").into_artifact();
            artifact.recovery = Some(record);
            self.phase = Phase::Header;
            return Ok(ProgressiveEvent::MemberFinished {
                member: self.member.take().unwrap(),
                outcome: MemberOutcome::Partial(artifact),
            });
        }
        let checks = physical.final_checks.expect("final member checks");
        let checksum = checks
            .blake2sp
            .map(ChecksumValue::Blake2sp)
            .or_else(|| checks.crc32.map(|c| ChecksumValue::Crc32(c.to_le_bytes())));
        // a RAR 5.0 redirection has no data, so it has nothing to check when its header carries no checksum
        let redirection = self.link_kind.is_some() && physical.unpacked_size == Some(0);
        let verification = if let (true, Some(_)) = (checksum.is_some() || redirection, physical.unpacked_size) {
            Some(Verification {
                inner_size: self.produced,
                read_back: 0,
                checksum,
                replacement_revision: None,
                caller: None,
                size: CheckVerdict::Passed,
                crc32: if checks.crc32.is_some() { CheckVerdict::Passed } else { CheckVerdict::Missing },
                blake2sp: if checks.blake2sp.is_some() { CheckVerdict::Passed } else { CheckVerdict::Missing },
                level: VerificationLevel::Strict,
                origin: EvidenceOrigin::Archive,
                packed: PackedEvidence::Passed,
                authentication: if physical.header.encrypted || self.parser.encrypted() {
                    AuthenticationEvidence::CbcChecksOnly
                } else {
                    AuthenticationEvidence::NotApplicable
                },
            })
        } else {
            None
        };
        // a redirection without data decoded nothing, so the history stays as it was
        let dataless_link =
            self.link_kind.is_some() && physical.header.packed_size == 0 && !physical.header.split_after();
        if dataless_link {
            // nothing to take back
        } else if physical.header.method != 0 && physical.header.format == crate::rar5::RarFormat::Rar5 {
            self.history =
                machine.take_rar5_decoder().map_err(|_| ProgressiveFailure::new(FailureKind::InvalidCapability))?;
            self.history_failure = None;
        } else if physical.header.method != 0 && self.solid_archive == Some(true) {
            self.rar4_history = machine.take_rar4_history();
            self.history_failure = None;
        }
        if matches!(self.disposition, Disposition::Test) {
            let evidence = TestEvidence {
                inner_size: self.produced,
                checksum: checks
                    .blake2sp
                    .map(ChecksumValue::Blake2sp)
                    .or_else(|| checks.crc32.map(|c| ChecksumValue::Crc32(c.to_le_bytes()))),
                size: if physical.unpacked_size.is_some() { CheckVerdict::Passed } else { CheckVerdict::Missing },
                crc32: if checks.crc32.is_some() { CheckVerdict::Passed } else { CheckVerdict::Missing },
                blake2sp: if checks.blake2sp.is_some() { CheckVerdict::Passed } else { CheckVerdict::Missing },
                packed: PackedEvidence::Passed,
                authentication: if physical.header.encrypted || self.parser.encrypted() {
                    AuthenticationEvidence::CbcChecksOnly
                } else {
                    AuthenticationEvidence::NotApplicable
                },
            };
            // a tested file, or a tested hard link or copy, is one a later hard link or copy may take
            let header = &self.model.members.last().expect("member").header;
            if let Ok(rel) = self.link_rel(header) {
                let extracted = self.output.as_mut().map_or(&mut self.tested, |output| &mut output.extracted);
                match self.link_kind.take() {
                    Some(kind) => crate::extract::link::tested(&rel, &kind, extracted),
                    None if header.is_rar4_symlink() => extracted.replaced(&rel),
                    None => extracted.tested(&rel),
                }
            }
            self.phase = Phase::Header;
            return Ok(ProgressiveEvent::MemberFinished {
                member: self.member.take().unwrap(),
                outcome: MemberOutcome::Tested(evidence),
            });
        }
        if let Disposition::Skip(reason) = self.disposition {
            return self.finish_skip(reason);
        }
        if matches!(self.disposition, Disposition::Link) {
            let v = verification.ok_or_else(|| ProgressiveFailure::new(FailureKind::InvalidCapability))?;
            let header = &self.model.members.last().expect("member").header;
            let kind = match self.link_kind.take() {
                Some(kind) => kind,
                None => {
                    let rel = self.link_rel(header)?;
                    // written mapped as the member names it may point at; an empty target is refused below
                    let text =
                        crate::extract::link::rar4_target(&std::mem::take(&mut self.link_text)).unwrap_or_default();
                    // with placeholders the target is checked as the link is placed, after its path
                    let placeholder = self.output.as_ref().is_some_and(|output| output.extracted.placeholder());
                    if !placeholder && !crate::extract::link::contained(&rel, &text) {
                        return Err(ProgressiveFailure::new(FailureKind::UnsafePath));
                    }
                    crate::extract::link::LinkKind::Symbolic(text)
                }
            };
            let modified = self.options.extract.meta(crate::extract::Meta::from(header)).modified();
            let mut target = self.target.take().expect("target");
            match self.output.as_mut().expect("output").link(&mut target, &kind, modified, &mut self.driver) {
                Ok(()) => {}
                Err(e) if matches!(e.kind, FailureKind::PublicationAuthorityRequired) => return self.stop(e),
                Err(e) => return Err(e),
            }
            self.phase = Phase::Header;
            return Ok(ProgressiveEvent::MemberFinished {
                member: self.member.take().unwrap(),
                outcome: MemberOutcome::Verified(v),
            });
        }
        let mut outcome = if let Some(v) = verification {
            let stage = self.stage.as_mut().unwrap();
            let permit = stage.bind_verification(v.clone())?;
            match stage.publish(self.target.as_mut().expect("target"), &permit, &mut self.driver)? {
                Publication::Provisional => MemberOutcome::Provisional(self.stage.take().unwrap().into_artifact()),
                Publication::Published { cleanup_failure: None } => {
                    self.stage.take();
                    self.output.as_mut().expect("output").published(self.target.as_ref().expect("target"));
                    MemberOutcome::Verified(v)
                }
                Publication::Published { cleanup_failure: Some(failure) } => {
                    let artifact = Some(self.stage.take().expect("published leftover").into_artifact());
                    self.target.take();
                    self.history.take();
                    self.phase = Phase::Done;
                    self.recovery_closed = true;
                    return Ok(ProgressiveEvent::MemberFinished {
                        member: self.member.take().expect("member"),
                        outcome: MemberOutcome::PublishedWithFailure {
                            verification: v,
                            failure,
                            cleanup_failure: None,
                            artifact,
                        },
                    });
                }
            }
        } else {
            MemberOutcome::Provisional(self.stage.take().unwrap().into_artifact())
        };
        if let MemberOutcome::Provisional(artifact) = &mut outcome {
            artifact.recovery = Some(self.recovery_record(&machine)?);
            artifact.stage.as_mut().unwrap().assessment.get_mut().evidence_epoch = self.replacement_revision;
        }
        self.target.take();
        self.phase = Phase::Header;
        Ok(ProgressiveEvent::MemberFinished { member: self.member.take().unwrap(), outcome })
    }
}
impl Drop for ProgressiveSession {
    fn drop(&mut self) {
        self.driver.cancel();
    }
}
struct StageSink<'a> {
    stage: Option<&'a mut Stage>,
    usage: &'a Usage,
    control: &'a SessionControl,
    produced: &'a mut u64,
    /// a symbolic link's target, gathered instead of written
    link: Option<&'a mut Vec<u8>>,
    chunk: usize,
    failure: Option<ProgressiveFailure>,
    fill: HoleFill,
}
impl crate::rar5::unpack::Sink for StageSink<'_> {
    fn put(&mut self, mut bytes: &[u8]) -> crate::error::Result<()> {
        while !bytes.is_empty() {
            let n = bytes.len().min(self.chunk);
            let result = if self.control.is_canceled() {
                Err(ProgressiveFailure::new(FailureKind::Canceled))
            } else if let Some(stage) = &mut self.stage {
                stage.write_at(*self.produced, &bytes[..n])
            } else {
                if let Some(link) = self.link.as_deref_mut() {
                    // more than a target may hold fails the size check or the target check
                    let room = (crate::extract::link::MAX_TARGET as usize + 1).saturating_sub(link.len()).min(n);
                    link.extend_from_slice(&bytes[..room]);
                }
                self.usage.charge(Resource::LogicalOutputBytes, n as u64).map(|()| n)
            };
            match result {
                Ok(count) => {
                    *self.produced += count as u64;
                    bytes = &bytes[count..];
                }
                Err(e) => {
                    self.failure = Some(e);
                    return Err(crate::Error::Corrupt("progressive output sink stopped"));
                }
            }
        }
        Ok(())
    }
}

impl crate::rar5::member::RecoverySink for StageSink<'_> {
    fn hole(&mut self, len: u64) -> crate::error::Result<()> {
        let result = if self.control.is_canceled() {
            Err(ProgressiveFailure::new(FailureKind::Canceled))
        } else if let Some(stage) = &mut self.stage {
            stage.hole(*self.produced, len, self.fill)
        } else {
            Err(ProgressiveFailure::new(FailureKind::DataHole))
        };
        match result {
            Ok(()) => {
                *self.produced += len;
                Ok(())
            }
            Err(e) => {
                self.failure = Some(e);
                Err(crate::Error::Corrupt("progressive hole sink stopped"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn published_cleanup_failure_has_public_outcome_and_owned_afterlife() {
        fn block(body: &[u8], data: &[u8]) -> Vec<u8> {
            assert!(body.len() < 128);
            let mut sized = vec![body.len() as u8];
            sized.extend(body);
            let mut bytes = crate::crc32::hash(&sized).to_le_bytes().to_vec();
            bytes.extend(sized);
            bytes.extend(data);
            bytes
        }
        let temp = tempfile::tempdir().unwrap();
        let mut bytes = b"Rar!\x1a\x07\x01\x00".to_vec();
        bytes.extend(block(&[1, 0, 0], &[]));
        let mut header = vec![2, 2, 3, 4, 3, 0]; // file, data-size, packed-size, CRC flag, size, attributes
        header.extend(crate::crc32::hash(b"new").to_le_bytes());
        header.extend([0, 0, 6]); // stored, DOS host, name length
        header.extend(b"target");
        bytes.extend(block(&header, b"new"));
        bytes.extend(block(&[5, 0, 0], &[]));
        let options = ProgressiveOptions::new(
            crate::extract::Options {
                mode: crate::extract::Mode::Extract,
                dest: temp.path().into(),
                overwrite: crate::extract::Overwrite::Skip,
                flatten: false,
                threads: Some(1),
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
                encrypted_links: Default::default(),
                damaged_input: Default::default(),
                unsupported_filters: Default::default(),
                unverified_output: Default::default(),
                salvage_truncated_zip: false,
                seven_zip_strict: false,
                unix_modes: Default::default(),
                backslashes: Default::default(),
                hard_link_targets: Default::default(),
            },
            "a.rar".into(),
        );
        let mut session =
            ProgressiveSession::from_sealed_memory(vec![("a.rar".into(), bytes.into_boxed_slice())], options).unwrap();
        crate::output::OWNED_STAGE_FAULT
            .with(|slot| *slot.borrow_mut() = Some((crate::output::OwnedOperation::Remove, Err(libc::EACCES))));
        let mut artifact = loop {
            match session.poll_event(&mut Context::from_waker(std::task::Waker::noop())) {
                Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished {
                    outcome: MemberOutcome::PublishedWithFailure { verification, failure, cleanup_failure, artifact },
                    ..
                }))) => {
                    assert_eq!(verification.inner_size(), 3);
                    assert!(matches!(failure.kind, FailureKind::Output { operation: OutputOperation::Remove, .. }));
                    assert!(cleanup_failure.is_none());
                    break artifact.expect("owned leftover");
                }
                Poll::Ready(Ok(Some(_))) | Poll::Pending => {}
                _ => panic!("published outcome required"),
            }
        };
        assert!(matches!(
            session.poll_event(&mut Context::from_waker(std::task::Waker::noop())),
            Poll::Ready(Ok(None))
        ));
        assert_eq!(artifact.publication(), ArtifactPublication::Strict);
        assert!(matches!(artifact.evidence(), ArtifactEvidence::Verified(v) if v.level() == VerificationLevel::Strict));
        assert!(matches!(artifact.read_at(0, &mut [0; 3]).unwrap_err().kind, FailureKind::InvalidCapability));
        assert!(matches!(session.patch(&mut artifact, 0, b"bad").unwrap_err().kind, FailureKind::InvalidCapability));
        assert!(matches!(
            session.poll_verify(&mut artifact, &mut Context::from_waker(std::task::Waker::noop())),
            Poll::Ready(Err(ProgressiveFailure { kind: FailureKind::InvalidCapability, .. }))
        ));
        drop(session);
        artifact.discard().unwrap();
        assert_eq!(std::fs::read(temp.path().join("target")).unwrap(), b"new");
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
    }
    #[test]
    fn task4b_r1_stage_cleanup_precedes_pending_directory_failure() {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::atomic::AtomicBool;
        struct Provider {
            path: std::path::PathBuf,
            file: Arc<std::fs::File>,
            armed: Arc<AtomicBool>,
            cleanup_calls: Arc<AtomicU64>,
        }
        impl VolumeSource for Provider {
            fn volume(&mut self, _: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
                Ok(VolumeAnswer::Ready(Box::new(ImmutableFileSource::open(&self.path)?)))
            }
            fn protection(&mut self) -> ProgressiveResult<ProtectionDeclaration> {
                if self.armed.load(Ordering::SeqCst) {
                    self.cleanup_calls.fetch_add(1, Ordering::SeqCst);
                    return Err(ProgressiveFailure::new(FailureKind::SourceContract));
                }
                Ok(ProtectionDeclaration::Complete {
                    epoch: 1,
                    inventory: ProtectionInventory {
                        volumes: vec![ProtectedVolume {
                            index: 0,
                            name: "a.rar".into(),
                            backing: VolumeBacking::Native(vec![ProtectedPath {
                                path: self.path.clone(),
                                file: Some(self.file.clone()),
                            }]),
                        }],
                        auxiliary_paths: vec![],
                    },
                })
            }
        }
        fn block(body: &[u8], data: &[u8]) -> Vec<u8> {
            let mut sized = vec![u8::try_from(body.len()).unwrap()];
            sized.extend(body);
            let mut bytes = crate::crc32::hash(&sized).to_le_bytes().to_vec();
            bytes.extend(sized);
            bytes.extend(data);
            bytes
        }
        // The same pending callback fails in the successful-removal control, and
        // must never run when removal has already produced the sole cleanup error.
        for (remove_failure, directory_failure, retain) in [
            (true, true, false),
            (true, false, false),
            (false, true, false),
            (false, false, false),
            (false, true, true),
            (false, false, true),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let dest = temp.path().join("out");
            std::fs::create_dir(&dest).unwrap();
            let mut bytes = b"Rar!\x1a\x07\x01\x00".to_vec();
            bytes.extend(block(&[1, 0, 0], &[]));
            // Directory: flag1, size0, Unix mode0500 as vint, stored, Unix host.
            bytes.extend(block(&[2, 0, 1, 0, 0xc0, 2, 0, 1, 3, b'd', b'i', b'r'], &[]));
            let mut header = vec![2, 2, 3, 4, 3, 0];
            header.extend(crate::crc32::hash(b"old").to_le_bytes());
            header.extend([0, 0, 6]);
            header.extend(b"target");
            bytes.extend(block(&header, b"new"));
            bytes.extend(block(&[5, 0, 0], &[]));
            let path = temp.path().join("a.rar");
            std::fs::write(&path, bytes).unwrap();
            let armed = Arc::new(AtomicBool::new(false));
            let cleanup_calls = Arc::new(AtomicU64::new(0));
            let mut options = ProgressiveOptions::new(
                crate::extract::Options {
                    mode: crate::extract::Mode::Extract,
                    dest: dest.clone(),
                    overwrite: crate::extract::Overwrite::Always,
                    flatten: false,
                    threads: Some(1),
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
                    encrypted_links: Default::default(),
                    damaged_input: Default::default(),
                    unsupported_filters: Default::default(),
                    unverified_output: Default::default(),
                    salvage_truncated_zip: false,
                    seven_zip_strict: false,
                    unix_modes: Default::default(),
                    backslashes: Default::default(),
                    hard_link_targets: Default::default(),
                },
                "a.rar".into(),
            );
            if retain {
                options.artifact_aftermath = ArtifactAftermath::RetainProvisional;
            }
            let mut session = ProgressiveSession::new(
                Box::new(Provider {
                    file: Arc::new(std::fs::File::open(&path).unwrap()),
                    path,
                    armed: armed.clone(),
                    cleanup_calls: cleanup_calls.clone(),
                }),
                options,
            )
            .unwrap();
            let mut started = false;
            let (failure, cleanup, mut artifact) = loop {
                match session.poll_event(&mut Context::from_waker(std::task::Waker::noop())) {
                    Poll::Ready(Ok(Some(ProgressiveEvent::MemberStarted { name, .. })))
                        if name.as_slice() == b"target" =>
                    {
                        started = true;
                        std::fs::set_permissions(dest.join("dir"), std::fs::Permissions::from_mode(0o700)).unwrap();
                        armed.store(directory_failure, Ordering::SeqCst);
                        if remove_failure {
                            crate::output::OWNED_STAGE_FAULT.with(|slot| {
                                *slot.borrow_mut() = Some((crate::output::OwnedOperation::Remove, Err(libc::EACCES)))
                            });
                        }
                    }
                    Poll::Ready(Ok(Some(ProgressiveEvent::SessionTerminated {
                        failure,
                        cleanup_failure,
                        artifact,
                    }))) => break (failure, cleanup_failure, artifact),
                    Poll::Ready(Ok(Some(_))) | Poll::Pending => {}
                    Poll::Ready(Err(e)) => panic!("terminal checksum event required: {e:?}"),
                    _ => panic!("unexpected end"),
                }
            };
            assert!(started);
            assert!(
                matches!(failure.kind, FailureKind::Rar(ref error) if matches!(error.as_ref(), crate::error::RarFailure::Integrity { reason: crate::error::RarIntegrityReason::FinalChecks { crc32: true, blake2sp: false }, .. })),
                "{failure:?}"
            );
            assert_eq!(cleanup_calls.load(Ordering::SeqCst), u64::from(directory_failure && !remove_failure));
            if remove_failure {
                assert!(
                    matches!(cleanup.unwrap().kind, FailureKind::Output { operation: OutputOperation::Remove, cause } if cause.raw_os_error() == Some(libc::EACCES))
                );
            } else if directory_failure {
                assert!(matches!(cleanup.unwrap().kind, FailureKind::SourceContract));
            } else {
                assert!(cleanup.is_none());
            }
            assert_eq!(artifact.is_some(), remove_failure || retain);
            assert_eq!(failure.context.inner_offset, Some(3));
            assert_eq!(
                std::fs::metadata(dest.join("dir")).unwrap().permissions().mode() & 0o777,
                if directory_failure || remove_failure { 0o700 } else { 0o500 }
            );
            assert!(!dest.join("target").exists());
            assert!(matches!(
                session.poll_event(&mut Context::from_waker(std::task::Waker::noop())),
                Poll::Ready(Ok(None))
            ));
            // Even an explicit internal cleanup call cannot retry the drained queue.
            session.output.as_mut().unwrap().finish_directories(&mut session.driver).unwrap();
            assert_eq!(cleanup_calls.load(Ordering::SeqCst), u64::from(directory_failure && !remove_failure));
            drop(session);
            if let Some(ref mut artifact) = artifact {
                let mut buffer = [0; 3];
                assert_eq!(artifact.read_at(0, &mut buffer).unwrap(), ArtifactRead::Filled { count: 3 });
                assert_eq!(&buffer, b"new");
                artifact.discard().unwrap();
            }
            assert_eq!(std::fs::read_dir(&dest).unwrap().count(), 1);
        }
    }
    #[test]
    fn nonce_exhaustion_never_wraps_or_reuses_identity() {
        let counter = AtomicU64::new(u64::MAX - 1);
        assert_eq!(allocate_nonce(&counter).unwrap().get(), u64::MAX - 1);
        for _ in 0..3 {
            assert!(matches!(allocate_nonce(&counter).unwrap_err().kind, FailureKind::InvalidCapability));
            assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
        }
    }
    #[test]
    fn session_and_artifact_are_send() {
        fn send<T: Send>() {}
        send::<ProgressiveSession>();
        send::<Artifact>();
    }
}
