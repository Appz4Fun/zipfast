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
use std::{
    ffi::OsString,
    num::NonZeroU64,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};

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
pub enum MemberOutcome {
    Verified(Verification),
    RecoveredInner(Verification),
    Provisional(Artifact),
    Partial(Artifact),
    Stopped { inner_offset: u64, restart: RestartAvailability, failure: ProgressiveFailure, artifact: Option<Artifact> },
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
    Part,
    Finish,
    Verdict,
    NextVolume,
    Done,
}
/// A serialized, caller-driven extraction session. Delivered artifacts outlive it.
pub struct ProgressiveSession {
    driver: SourceDriver,
    output: OutputContext,
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
    finalizer: Option<MemberMachine>,
    stage: Option<Stage>,
    target: Option<Target>,
    member: Option<MemberId>,
    produced: u64,
    remaining: u64,
    had_stage: bool,
    buffer: Vec<u8>,
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
        if options.extract.mode != crate::extract::Mode::Extract {
            return Err(ProgressiveFailure::new(FailureKind::UnsupportedMethod));
        }
        let usage = Usage::new(options.limits.clone());
        usage.check(Resource::ActiveOutputs, 1)?;
        usage.check(Resource::RetainedArtifacts, 1)?;
        usage.check(Resource::MetadataBytes, options.first_name.capacity() as u64)?;
        usage.check(Resource::NameBytes, options.first_name.capacity() as u64)?;
        Ok(())
    }
    fn assemble(driver: SourceDriver, control: SessionControl, options: ProgressiveOptions) -> ProgressiveResult<Self> {
        let usage = driver.shared_usage();
        let output = OutputContext::new(&options, usage.clone(), control.clone())?;
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
            finalizer: None,
            stage: None,
            target: None,
            member: None,
            produced: 0,
            remaining: 0,
            had_stage: false,
            buffer,
        })
    }
    pub fn control(&self) -> SessionControl {
        self.control.clone()
    }
    pub fn poll_event(&mut self, cx: &mut Context<'_>) -> Poll<ProgressiveResult<Option<ProgressiveEvent>>> {
        if matches!(self.phase, Phase::Done) {
            return Poll::Ready(Ok(None));
        }
        self.control.register(cx.waker());
        match self.poll_inner(cx) {
            Ok(p) => p,
            Err(e) => Poll::Ready(self.terminate(e)),
        }
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
        self.machine.take();
        self.finalizer.take();
        self.target.take();
        if let Some(stage) = self.stage.take() {
            let t = self.output.terminate(stage, failure);
            return Ok(Some(ProgressiveEvent::SessionTerminated {
                failure: t.failure,
                artifact: t.artifact,
                cleanup_failure: t.cleanup_failure,
            }));
        }
        if self.had_stage {
            Ok(Some(ProgressiveEvent::SessionTerminated { failure, artifact: None, cleanup_failure: None }))
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
                    match self.output.poll_capacity(cx)? {
                        Capacity::Needed { retained } => {
                            return Ok(Poll::Ready(Ok(Some(ProgressiveEvent::CapacityNeeded { retained }))));
                        }
                        Capacity::Pending => return Ok(Poll::Pending),
                        Capacity::Ready => {}
                    }
                    let Phase::Start(frame) = std::mem::replace(&mut self.phase, Phase::Part) else { unreachable!() };
                    let event = self.start(*frame)?;
                    return Ok(Poll::Ready(Ok(Some(event))));
                }
                Phase::Finish => {
                    let before = self.produced;
                    let mut machine = self.machine.take().expect("active decoder");
                    let mut sink = StageSink {
                        stage: self.stage.as_mut().expect("stage"),
                        produced: &mut self.produced,
                        chunk: self.options.limits.read_chunk.min(1 << 20) as usize,
                        failure: None,
                    };
                    let result = machine.finish_decode(&mut sink);
                    if let Some(e) = sink.failure {
                        return Err(e);
                    }
                    result?;
                    self.driver.validate_current()?;
                    self.finalizer = Some(machine);
                    self.phase = Phase::Verdict;
                    if self.produced > before {
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
                        ParserStep::Need { offset, len } => (offset, len),
                        ParserStep::End => return Err(ProgressiveFailure::new(FailureKind::Truncated)),
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
                            return Err(ProgressiveFailure::new(FailureKind::Truncated));
                        }
                        Poll::Ready(Ok(SourceStep::Hole { .. })) => {
                            return Err(ProgressiveFailure::new(FailureKind::HeaderHole));
                        }
                        Poll::Ready(Ok(SourceStep::Filled { offset, count })) => {
                            self.cursor = offset + count as u64;
                            work += count as u64;
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
                        self.machine.as_mut().expect("active decoder").finish_part(part)?;
                        self.phase = if part.final_part { Phase::Finish } else { Phase::Header };
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
                            let before = self.produced;
                            let mut sink = StageSink {
                                stage: self.stage.as_mut().expect("stage"),
                                produced: &mut self.produced,
                                chunk: self.options.limits.read_chunk.min(1 << 20) as usize,
                                failure: None,
                            };
                            let result = self.machine.as_mut().expect("decoder").feed(&self.buffer[..count], &mut sink);
                            if let Some(e) = sink.failure {
                                return Err(e);
                            }
                            result?;
                            self.driver.validate_current()?;
                            if self.produced > before {
                                return Ok(Poll::Ready(Ok(Some(ProgressiveEvent::BytesWritten {
                                    member: self.member.expect("member"),
                                    valid_bytes: self.produced - before,
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
                self.volume_set = Some(main.is_volume());
                self.main_seen = true;
            }
            Block::File(header) => {
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
                if let Some(machine) = &mut self.machine {
                    let member = self.model.members.last_mut().expect("member");
                    let wire = frame
                        .wire
                        .as_ref()
                        .ok_or_else(|| ProgressiveFailure::new(FailureKind::Malformed("missing wire identity")))?;
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
                    machine.begin_part(&part);
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
                } else if self.machine.is_some() {
                    return Err(ProgressiveFailure::new(FailureKind::Truncated));
                } else {
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
        let size = (!header.size_unknown()).then_some(header.unpacked_size);
        self.stage = Some(self.output.create(member, size)?);
        self.had_stage = true;
        let stage = self.stage.as_mut().unwrap();
        self.target = Some(stage.target(&header.name, !header.is_unix())?);
        if header.is_dir() || header.redirection.is_some() {
            return Err(ProgressiveFailure::new(FailureKind::UnsupportedMethod));
        }
        let context = crate::extract::EntryContext {
            entry: crate::extract::RarEntryIdentity {
                index: Some(member.ordinal),
                order: member.ordinal,
                name: String::new(),
            },
            method: header.method,
            password: crate::error::RarPasswordEvidence::NotEncrypted,
        };
        let mut machine = MemberMachine::new(&header, context, self.options.password(), &self.usage, &self.control)?;
        let part = PhysicalPart::new(self.volume as usize, &header, frame.crypt, &wire);
        machine.begin_part(&part);
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
        self.machine = Some(machine);
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
        self.target.take();
        let part = self.model.parts.last().expect("part");
        self.driver.seek(part.data_offset + part.packed_size)?;
        self.cursor = part.data_offset + part.packed_size;
        self.phase = Phase::Header;
        let t = self.output.terminate(self.stage.take().expect("stage"), failure);
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
    fn finish(&mut self) -> ProgressiveResult<ProgressiveEvent> {
        // The successfully decoded machine lives in a non-feedable slot.
        // Take before the verdict and drop on every result, including failure.
        let mut machine = self.finalizer.take().expect("decoded machine");
        let physical = self.model.members.last().expect("member");
        machine.finish_member(physical)?;
        self.driver.validate_current()?;
        if let Some(size) = physical.unpacked_size {
            self.stage.as_mut().expect("stage").reconcile_final_size(size)?;
        }
        let checks = physical.final_checks.expect("final member checks");
        let checksum = checks
            .blake2sp
            .map(ChecksumValue::Blake2sp)
            .or_else(|| checks.crc32.map(|c| ChecksumValue::Crc32(c.to_le_bytes())));
        let verification = if let (Some(checksum), Some(_)) = (checksum, physical.unpacked_size) {
            Some(Verification {
                inner_size: self.produced,
                checksum,
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
        let outcome = if let Some(v) = verification {
            let stage = self.stage.as_mut().unwrap();
            let permit = stage.bind_verification(v.clone())?;
            match stage.publish(self.target.as_mut().expect("target"), &permit, &mut self.driver)? {
                Publication::Provisional => MemberOutcome::Provisional(self.stage.take().unwrap().into_artifact()),
                Publication::Published { cleanup_failure: None } => {
                    self.stage.take();
                    MemberOutcome::Verified(v)
                }
                Publication::Published { cleanup_failure: Some(e) } => return Err(e),
            }
        } else {
            MemberOutcome::Provisional(self.stage.take().unwrap().into_artifact())
        };
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
    stage: &'a mut Stage,
    produced: &'a mut u64,
    chunk: usize,
    failure: Option<ProgressiveFailure>,
}
impl crate::rar5::unpack::Sink for StageSink<'_> {
    fn put(&mut self, mut bytes: &[u8]) -> crate::error::Result<()> {
        while !bytes.is_empty() {
            let n = bytes.len().min(self.chunk);
            match self.stage.write_at(*self.produced, &bytes[..n]) {
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

#[cfg(test)]
mod tests {
    use super::*;
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
