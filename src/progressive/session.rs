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
#[path = "recovery.rs"]
pub(crate) mod recovery;
use super::{
    output::{Capacity, OutputContext, Publication, Stage, Target},
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
    VolumeOpened {
        index: u32,
        id: SourceId,
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
    Tested(TestEvidence),
    Skipped(crate::extract::RarSkipReason),
    /// Policy completed. False also includes Test and flattened directory entries.
    Directory {
        created: bool,
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
    Done,
}
/// A serialized, caller-driven extraction session. Delivered artifacts outlive it.
pub struct ProgressiveSession {
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
    solid_archive: Option<bool>,
    archive_format: Option<crate::rar5::RarFormat>,
    disposition: Disposition,
    start_event: Option<ProgressiveEvent>,
    finalizer: Option<MemberMachine>,
    stage: Option<Stage>,
    target: Option<Target>,
    member: Option<MemberId>,
    produced: u64,
    remaining: u64,
    had_stage: bool,
    buffer: Vec<u8>,
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
        let nonce = nonce()?;
        let chunk = options.limits.read_chunk.min(options.limits.packed_work_per_poll).min(1 << 20);
        usage.check(Resource::ReadChunk, 1)?;
        usage.check(Resource::PackedWorkPerPoll, 1)?;
        usage.charge(Resource::MetadataBytes, chunk)?;
        usage.charge(Resource::MetadataBytes, (options.first_name.capacity() as u64).saturating_mul(3))?;
        usage.charge(Resource::NameBytes, (options.first_name.capacity() as u64).saturating_mul(3))?;
        let expected = options.first_name.clone();
        let parser = HeaderParser::from_start(expected.clone().into(), usage.clone());
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(chunk as usize)
            .map_err(|_| ProgressiveFailure::new(FailureKind::Malformed("input buffer allocation")))?;
        usage.charge(Resource::MetadataBytes, buffer.capacity() as u64 - chunk)?;
        buffer.resize(chunk as usize, 0);
        Ok(Self {
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
            solid_archive: None,
            archive_format: None,
            disposition: Disposition::Write,
            start_event: None,
            finalizer: None,
            stage: None,
            target: None,
            member: None,
            produced: 0,
            remaining: 0,
            had_stage: false,
            buffer,
            verify_job: None,
            replacement_revision: 0,
            witnesses: Vec::new(),
            replacement_epoch: Arc::new(AtomicU64::new(0)),
            recovery_closed: false,
            extraction_active: false,
            part_evidence: Vec::new(),
        })
    }
    pub fn control(&self) -> SessionControl {
        self.control.clone()
    }
    pub fn poll_event(&mut self, cx: &mut Context<'_>) -> Poll<ProgressiveResult<Option<ProgressiveEvent>>> {
        if self.verify_job.is_some() {
            return Poll::Ready(Err(ProgressiveFailure::new(FailureKind::InvalidCapability)));
        }
        if matches!(self.phase, Phase::Done) {
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
        ) {
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
        self.target.take();
        self.history.take();
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
    fn poll_inner(
        &mut self,
        cx: &mut Context<'_>,
    ) -> ProgressiveResult<Poll<ProgressiveResult<Option<ProgressiveEvent>>>> {
        let mut work = 0u64;
        loop {
            if self.control.is_canceled() {
                return Err(ProgressiveFailure::new(FailureKind::Canceled));
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
            match &self.phase {
                Phase::Done => return Ok(Poll::Ready(Ok(None))),
                Phase::NextVolume => {
                    self.volume = self
                        .volume
                        .checked_add(1)
                        .ok_or_else(|| ProgressiveFailure::new(FailureKind::SourceContract))?;
                    self.expected = crate::volume::next_volume_os(&self.expected)
                        .ok_or_else(|| ProgressiveFailure::new(FailureKind::MissingVolume))?;
                    self.driver.select_volume(VolumeRequest { index: self.volume, expected: self.expected.clone() })?;
                    self.usage.charge(Resource::MetadataBytes, self.expected.capacity() as u64)?;
                    self.parser = HeaderParser::from_start(self.expected.clone().into(), self.usage.clone());
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
                    stage.set_metadata(crate::extract::Meta::from(&member.header));
                    self.stage = Some(stage);
                    self.phase = Phase::Part;
                    return Ok(Poll::Ready(Ok(self.start_event.take())));
                }
                Phase::Finish => {
                    let before = self.produced;
                    let mut machine = self.machine.take().expect("active decoder");
                    let mut sink = StageSink {
                        stage: self.stage.as_mut(),
                        usage: &self.usage,
                        control: &self.control,
                        produced: &mut self.produced,
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
                Phase::Verdict => return self.finish().map(|e| Poll::Ready(Ok(Some(e)))),
                Phase::Header => {
                    let (_, step) = self.parser.advance(&[])?;
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
                        ParserStep::End => return Err(self.parser.truncated()),
                        ParserStep::Frame(_) => unreachable!("frames require input"),
                    };
                    if offset != self.cursor {
                        self.driver.seek(offset)?;
                        self.cursor = offset;
                    }
                    let n = len
                        .min(self.buffer.len())
                        .min((self.options.limits.packed_work_per_poll.min(1 << 20) - work) as usize);
                    match self.driver.poll_step(cx, &mut self.buffer[..n]) {
                        Poll::Pending => return Ok(Poll::Pending),
                        Poll::Ready(Err(e)) => return Err(e),
                        Poll::Ready(Ok(SourceStep::VolumeOpened { index, id })) => {
                            self.driver.validate_current()?;
                            return Ok(Poll::Ready(Ok(Some(ProgressiveEvent::VolumeOpened { index, id }))));
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
                            let (used, step) = self.parser.advance(&self.buffer[..count])?;
                            if used != count {
                                return Err(ProgressiveFailure::new(FailureKind::SourceContract));
                            }
                            self.driver.validate_current()?;
                            if let ParserStep::Frame(frame) = step {
                                self.frame(frame)?;
                            }
                        }
                    }
                }
                Phase::Part => {
                    if self.remaining == 0 {
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
                        continue;
                    }
                    let n = self
                        .remaining
                        .min(self.buffer.len() as u64)
                        .min(self.options.limits.packed_work_per_poll.min(1 << 20) - work)
                        as usize;
                    match self.driver.poll_step(cx, &mut self.buffer[..n]) {
                        Poll::Pending => return Ok(Poll::Pending),
                        Poll::Ready(Err(e)) => return Err(e),
                        Poll::Ready(Ok(SourceStep::EndOfVolume)) => {
                            return Err(ProgressiveFailure::new(FailureKind::Truncated));
                        }
                        Poll::Ready(Ok(SourceStep::VolumeOpened { .. })) => {
                            return Err(ProgressiveFailure::new(FailureKind::SourceContract));
                        }
                        Poll::Ready(Ok(SourceStep::Hole { offset, len })) => {
                            self.cursor = offset + len;
                            let recover = self.stage.is_some()
                                && matches!(self.options.hole_policy, HolePolicy::PartialStored { .. })
                                && self.model.members.last().is_some_and(|m| {
                                    m.header.method == 0 && (!m.header.encrypted || m.unpacked_size.is_some())
                                });
                            if recover {
                                self.remaining -= len;
                                work += len;
                                let mut sink = StageSink {
                                    stage: self.stage.as_mut(),
                                    usage: &self.usage,
                                    control: &self.control,
                                    produced: &mut self.produced,
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
                                self.driver.validate_current()?;
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
                            let before = self.stage.as_ref().map_or(self.produced, |s| s.valid);
                            let mut sink = StageSink {
                                stage: self.stage.as_mut(),
                                usage: &self.usage,
                                control: &self.control,
                                produced: &mut self.produced,
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
                            self.driver.validate_current()?;
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
                if let Some(reason) = header
                    .rar4_progressive_unsupported(frame.wire.as_ref().and_then(|w| w.legacy).and_then(|w| w.crypt))
                {
                    return Err(ProgressiveFailure::new(FailureKind::Rar(Box::new(
                        crate::error::RarFailure::Unsupported(reason),
                    ))));
                }
                if !self.main_seen {
                    return Err(ProgressiveFailure::new(FailureKind::Malformed("member before main")));
                }
                if let Some(Err(error)) = frame.crypt {
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
                    }
                    self.remaining = part.packed_size;
                    self.model
                        .parts
                        .try_reserve_exact(1)
                        .map_err(|_| ProgressiveFailure::new(FailureKind::Malformed("part allocation")))?;
                    self.model.parts.push(part);
                    self.phase = Phase::Part;
                } else {
                    self.usage.charge(Resource::MetadataBytes, std::mem::size_of::<PhysicalFrame>() as u64)?;
                    self.phase = Phase::Start(Box::new(frame));
                }
            }
            Block::End { more_volumes } => {
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
        let Block::File(header) = frame.block else { unreachable!() };
        if let Some(reason) =
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
        if self.options.extract.mode == crate::extract::Mode::Test || header.is_dir() {
            self.usage.charge(Resource::MetadataBytes, (header.name.len() as u64).saturating_mul(3))?;
            self.usage.charge(Resource::SourceBookkeeping, (header.name.len() as u64).saturating_mul(8))?;
            crate::path::sanitize_fallible(&header.name, !header.is_unix())
                .map_err(|_| ProgressiveFailure::new(FailureKind::UnsafePath))?;
        }
        if let Some(redirection) = &header.redirection {
            let kind = match redirection {
                crate::rar5::Redirection::UnixSymlink(_) => 1,
                crate::rar5::Redirection::WindowsSymlink(_) => 2,
                crate::rar5::Redirection::Junction(_) => 3,
                crate::rar5::Redirection::HardLink(_) => 4,
                crate::rar5::Redirection::FileCopy(_) => 5,
                crate::rar5::Redirection::Unknown(kind) => *kind,
            };
            return Err(ProgressiveFailure::new(FailureKind::Rar(Box::new(crate::error::RarFailure::Unsupported(
                crate::error::RarUnsupported::Redirection { kind },
            )))));
        }
        self.disposition = if header.is_dir() {
            if header.split_after() || header.packed_size != 0 || header.size_unknown() || header.unpacked_size != 0 {
                return Err(ProgressiveFailure::new(FailureKind::Malformed("directory payload or continuation")));
            }
            Disposition::Directory
        } else if self.options.extract.mode == crate::extract::Mode::Test {
            Disposition::Test
        } else if let Some(version) = header.version {
            Disposition::Skip(crate::extract::RarSkipReason::OlderVersion(version))
        } else {
            let output = self.output.as_ref().expect("output");
            let target = output.prepare_target(member, &header.name, !header.is_unix())?;
            let skip = self.options.extract.overwrite == crate::extract::Overwrite::Skip && target.exists();
            if skip {
                output.check_target(&target, &mut self.driver)?;
            }
            self.target = Some(target);
            if skip { Disposition::Skip(crate::extract::RarSkipReason::ExistingTarget) } else { Disposition::Write }
        };
        let context = crate::extract::EntryContext {
            entry: crate::extract::RarEntryIdentity {
                index: Some(member.ordinal),
                order: member.ordinal,
                name: String::new(),
            },
            method: header.method,
            password: crate::error::RarPasswordEvidence::NotEncrypted,
        };
        let decode = matches!(self.disposition, Disposition::Write | Disposition::Test)
            || (matches!(self.disposition, Disposition::Skip(_))
                && self.solid_archive == Some(true)
                && header.method != 0);
        let mut machine = if decode {
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
        let part = PhysicalPart::new(self.volume as usize, &header, frame.crypt, &wire);
        if let Some(machine) = &mut machine {
            machine.begin_part(&part);
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
    fn stop(&mut self, failure: ProgressiveFailure) -> ProgressiveResult<ProgressiveEvent> {
        let mut failure = self.scope(failure);
        if failure.context.expected.is_none() {
            self.usage.charge(Resource::MetadataBytes, self.expected.capacity() as u64)?;
            self.usage.charge(Resource::NameBytes, self.expected.capacity() as u64)?;
            failure.context.expected = Some(self.expected.clone());
        }
        self.machine.take();
        self.finalizer.take();
        self.target.take();
        if self.model.members.last().is_some_and(|m| m.header.method != 0) {
            self.history.take();
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
        if matches!(self.disposition, Disposition::Directory) {
            let header = &self.model.members.last().expect("member").header;
            let created = if self.options.extract.mode == crate::extract::Mode::Test || self.options.extract.flatten {
                false
            } else {
                match self.output.as_mut().expect("output").directory(
                    self.member.expect("member"),
                    header,
                    &mut self.driver,
                ) {
                    Ok(created) => created,
                    Err(e) if matches!(e.kind, FailureKind::PublicationAuthorityRequired) => return self.stop(e),
                    Err(e) => return Err(e),
                }
            };
            self.phase = Phase::Header;
            return Ok(ProgressiveEvent::MemberFinished {
                member: self.member.take().unwrap(),
                outcome: MemberOutcome::Directory { created },
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
        let verification = if let (Some(checksum), Some(_)) = (checksum, physical.unpacked_size) {
            Some(Verification {
                inner_size: self.produced,
                checksum: Some(checksum),
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
        if physical.header.method != 0 {
            self.history = machine.decoder.take();
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
            self.phase = Phase::Header;
            return Ok(ProgressiveEvent::MemberFinished {
                member: self.member.take().unwrap(),
                outcome: MemberOutcome::Tested(evidence),
            });
        }
        if let Disposition::Skip(reason) = self.disposition {
            return self.finish_skip(reason);
        }
        let mut outcome = if let Some(v) = verification {
            let stage = self.stage.as_mut().unwrap();
            let permit = stage.bind_verification(v.clone())?;
            match stage.publish(self.target.as_mut().expect("target"), &permit, &mut self.driver)? {
                Publication::Provisional => MemberOutcome::Provisional(self.stage.take().unwrap().into_artifact()),
                Publication::Published { cleanup_failure: None } => {
                    self.stage.take();
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
