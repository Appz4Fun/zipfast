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

//! Persistent output uses the canonical parser, physical model and member machine.
use super::*;
use crate::partial::*;
use crate::rar5::member::RecoverySink;
use crate::rar5::unpack::Sink;

pub(super) struct Persistent {
    options: PartialOptions,
    exclusions: Arc<PartialExclusions>,
    cores: Vec<(MemberKey, Arc<PartialCore>)>,
    current: Option<usize>,
    header_start: u64,
    header: Vec<u8>,
    witness: Option<HeaderWitness>,
    pub(super) ready: Option<(ProgressiveEvent, PartialEventLease)>,
}
impl Persistent {
    pub(super) fn record_header(&mut self, offset: u64, bytes: &[u8], usage: &Usage) -> ProgressiveResult<()> {
        if self.header.is_empty() {
            self.header_start = offset;
        }
        if self.header_start + self.header.len() as u64 != offset {
            return Err(ProgressiveFailure::new(FailureKind::SourceContract));
        }
        usage.charge(Resource::MetadataBytes, bytes.len() as u64)?;
        self.header
            .try_reserve_exact(bytes.len())
            .map_err(|_| ProgressiveFailure::new(FailureKind::InvalidCapability))?;
        self.header.extend_from_slice(bytes);
        Ok(())
    }
    pub(super) fn frame_header(&mut self, volume: u32, frame: &PhysicalFrame, usage: &Usage) -> ProgressiveResult<()> {
        if matches!(frame.block, Block::File(_)) {
            let start = frame
                .extent
                .start
                .checked_sub(self.header_start)
                .ok_or_else(|| ProgressiveFailure::new(FailureKind::SourceContract))? as usize;
            let len = (frame.extent.end - frame.extent.start) as usize;
            let bytes = self
                .header
                .get(start..start + len)
                .ok_or_else(|| ProgressiveFailure::new(FailureKind::SourceContract))?;
            usage.charge(Resource::MetadataBytes, len as u64)?;
            self.witness = Some(HeaderWitness { volume, packed: frame.extent.clone(), bytes: bytes.to_vec() });
        }
        self.header.clear();
        Ok(())
    }
    fn active(&self) -> (&MemberKey, &Arc<PartialCore>) {
        let (key, core) = &self.cores[self.current.expect("persistent member")];
        (key, core)
    }
}
impl ProgressiveSession {
    pub(super) fn partial_active(&self) -> bool {
        self.partial.as_ref().is_some_and(|persistent| persistent.current.is_some())
    }

    pub fn new_partial(
        provider: Box<dyn VolumeSource>,
        options: ProgressiveOptions,
        partial: PartialOptions,
    ) -> ProgressiveResult<Self> {
        Self::validate_options(&options)?;
        partial.validate_session().map_err(failure)?;
        if options.extract.mode != crate::extract::Mode::Extract || options.extract.flatten {
            return Err(error(PartialErrorKind::InvalidOptions));
        }
        let control = SessionControl::default();
        let mut driver =
            SourceDriver::new_retained(provider, options.first_name.clone(), options.limits.clone(), control.clone())?;
        driver.require_partial_catalogue()?;
        let exclusions = Arc::new(PartialExclusions::new(driver.shared_usage()));
        driver.install_partial_exclusions(exclusions.clone())?;
        let mut session = Self::assemble_with_output(driver, control, options, None)?;
        session.partial = Some(Persistent {
            options: partial,
            exclusions,
            cores: Vec::new(),
            current: None,
            header_start: 0,
            header: Vec::new(),
            witness: None,
            ready: None,
        });
        Ok(session)
    }
    #[allow(clippy::result_large_err, reason = "preserve the public typed partial receipt API")]
    pub fn partial_file(&mut self, member: &MemberKey) -> PartialResult<PartialFile> {
        self.partial
            .as_ref()
            .and_then(|p| p.cores.iter().find(|(key, _)| key == member))
            .map(|(_, core)| PartialFile::from_core(core.clone()))
            .ok_or_else(|| PartialError::new(PartialErrorKind::BindingMismatch(BindingField::Member)))
    }
    pub(super) fn partial_header(&self, header: &crate::rar5::FileHeader) -> ProgressiveResult<()> {
        if header.format != crate::rar5::RarFormat::Rar5 {
            return Err(error(PartialErrorKind::UnsupportedFormat));
        }
        if header.method != 0 || header.encrypted || header.is_dir() || header.redirection.is_some() {
            return Err(error(PartialErrorKind::UnsupportedMethod));
        }
        if header.size_unknown() {
            return Err(error(PartialErrorKind::UnknownMemberSize));
        }
        Ok(())
    }
    #[allow(clippy::result_large_err, reason = "genesis callback propagates typed partial receipts")]
    pub(super) fn partial_create(&mut self) -> ProgressiveResult<()> {
        let persistent = self.partial.as_mut().unwrap();
        let physical = self.model.members.last().unwrap();
        let header = &physical.header;
        let witness = persistent.witness.take().ok_or_else(|| error(PartialErrorKind::StateMalformed))?;
        self.usage.charge(Resource::MetadataBytes, (witness.bytes.len() + header.name.len() + 32) as u64)?;
        let mut identity = b"zipfast/plain-stored/member/v1\0".to_vec();
        identity.extend_from_slice(&witness.bytes);
        let key = MemberKey::new(
            persistent.options.binding.clone(),
            self.member.unwrap().ordinal,
            crate::crypto::sha256(&identity),
        );
        let mut relative = crate::path::sanitize_fallible(&header.name, !header.is_unix())
            .map_err(|_| error(PartialErrorKind::UnsafePath))?;
        if let PartialNaming::Suffix(suffix) = &persistent.options.naming {
            let mut name = relative.file_name().ok_or_else(|| error(PartialErrorKind::UnsafePath))?.to_os_string();
            name.push(suffix);
            relative.set_file_name(name);
        }
        let part = &mut self.model.parts[0];
        part.plain_extent = Some(0..part.packed_size);
        let plain = plain_part(part, 0)?;
        let checks = member_checks(physical);
        let admission = SourceAdmission {
            volume: self.volume,
            info: self
                .driver
                .observed_info(self.volume)
                .ok_or_else(|| ProgressiveFailure::new(FailureKind::SourceContract))?,
            expected: self.expected.clone(),
        };
        let spec = CreateSpec {
            member: key.clone(),
            name: Arc::from(header.name.as_bytes()),
            output_root: self.options.extract.dest.clone(),
            state_root: persistent.options.state_dir.clone(),
            relative_output: relative,
            size: header.unpacked_size,
            protection: self.driver.partial_catalogue()?,
            evidence: InitialEvidence {
                metadata: crate::extract::Meta::from(header),
                parts: vec![plain],
                admissions: vec![admission],
                headers: vec![witness],
            },
        };
        self.usage.charge(Resource::MetadataBytes, std::mem::size_of::<(MemberKey, Arc<PartialCore>)>() as u64)?;
        persistent.cores.try_reserve_exact(1).map_err(|_| error(PartialErrorKind::StateMalformed))?;
        let mut prepared = PartialCore::prepare_create(
            spec,
            checks,
            CoreOptions {
                limits: persistent.options.limits.clone(),
                usage: self.usage.clone(),
                read_chunk: self.options.limits.read_chunk,
                anchors: persistent.options.anchors.clone(),
                control: persistent.options.control.clone(),
                exclusions: persistent.exclusions.clone(),
            },
        )
        .map_err(failure)?;
        prepared.reserve_ready_state().map_err(failure)?;
        let parents = prepared
            .prepare_parents(|path| self.driver.check_partial_target(path).map_err(Into::into))
            .map_err(failure)?;
        parents.check().map_err(failure)?;
        let (core, state, event_lease) = prepared.complete_ready().map_err(failure)?;
        persistent.current = Some(persistent.cores.len());
        persistent.cores.push((key.clone(), core));
        persistent.ready = Some((ProgressiveEvent::PartialReady { member: key, state }, event_lease));
        Ok(())
    }
    pub(super) fn partial_extend(&mut self) -> ProgressiveResult<()> {
        let persistent = self.partial.as_mut().unwrap();
        let index = self.model.parts.len() - 1;
        let out = self.model.parts[..index]
            .iter()
            .try_fold(0u64, |sum, p| sum.checked_add(p.packed_size))
            .ok_or_else(|| error(PartialErrorKind::StateMalformed))?;
        let part = &mut self.model.parts[index];
        let end = out.checked_add(part.packed_size).ok_or_else(|| error(PartialErrorKind::StateMalformed))?;
        part.plain_extent = Some(out..end);
        let plain = plain_part(part, index as u64)?;
        let witness = persistent.witness.take().ok_or_else(|| error(PartialErrorKind::StateMalformed))?;
        let admission = SourceAdmission {
            volume: self.volume,
            info: self
                .driver
                .observed_info(self.volume)
                .ok_or_else(|| ProgressiveFailure::new(FailureKind::SourceContract))?,
            expected: self.expected.clone(),
        };
        persistent
            .active()
            .1
            .extend_evidence(EvidenceUpdate {
                parts: vec![plain],
                admissions: vec![admission],
                headers: vec![witness],
                checks: self.model.members.last().filter(|m| m.complete).map(member_checks),
            })
            .map_err(failure)
    }
    pub(super) fn partial_feed(
        &mut self,
        count: usize,
        hole: Option<u64>,
    ) -> ProgressiveResult<Option<ProgressiveEvent>> {
        let persistent = self.partial.as_ref().unwrap();
        let (key, core) = persistent.active();
        let report = if let Some(packed) = hole {
            let revision = core.next_revision().map_err(failure)?;
            Some(HoleReport {
                id: revision,
                revision,
                member: key.clone(),
                name: Arc::from(self.model.members.last().unwrap().header.name.as_bytes()),
                out: self.produced..self.produced + count as u64,
                packed: vec![PackedSpan { volume: self.volume, range: packed..packed + count as u64 }],
                cause: HoleCause::Missing,
            })
        } else {
            None
        };
        let mut sink = PersistentSink { core, produced: &mut self.produced, report: report.clone(), failure: None };
        let machine = self.machine.as_mut().unwrap();
        machine.reserve_progressive_scratch(count, &self.usage)?;
        let result = machine.feed_stored(hole.is_none().then_some(&self.buffer[..count]), count, &mut sink);
        if let Some(error) = sink.failure {
            return Err(error);
        }
        result?;
        self.driver.validate_current()?;
        Ok(report.map(ProgressiveEvent::Hole))
    }
    pub(super) fn partial_part_event(&self) -> ProgressiveResult<Option<ProgressiveEvent>> {
        if !self.partial_active() {
            return Ok(None);
        }
        let persistent = self.partial.as_ref().unwrap();
        let part = self.model.parts.last().unwrap();
        if part.final_part
            || self.machine.as_ref().unwrap().part_missing()
            || (part.checks.crc32.is_none() && part.checks.blake2sp.is_none())
        {
            return Ok(None);
        }
        persistent.active().1.validate_current().map_err(failure)?;
        Ok(Some(ProgressiveEvent::PartVerified {
            member: persistent.active().0.clone(),
            check: PartCheck {
                volume: self.volume,
                part: (self.model.parts.len() - 1) as u64,
                range: part.plain_extent.clone().ok_or_else(|| error(PartialErrorKind::StateMalformed))?,
                crc32: if part.checks.crc32.is_some() { CheckResult::Passed } else { CheckResult::Missing },
                blake2sp: if part.checks.blake2sp.is_some() { CheckResult::Passed } else { CheckResult::Missing },
            },
        }))
    }
    pub(super) fn partial_finish_decode(&mut self) -> ProgressiveResult<()> {
        let core = self.partial.as_ref().unwrap().active().1;
        let mut sink = PersistentSink { core, produced: &mut self.produced, report: None, failure: None };
        let mut machine = self.machine.take().unwrap();
        let result = machine.finish_decode(&mut sink);
        if let Some(error) = sink.failure {
            return Err(error);
        }
        result?;
        self.driver.validate_current()?;
        self.finalizer = Some(machine);
        self.phase = Phase::Verdict;
        Ok(())
    }
    pub(super) fn partial_finish(
        &mut self,
        cx: &mut Context<'_>,
    ) -> ProgressiveResult<Poll<ProgressiveResult<Option<ProgressiveEvent>>>> {
        if let Some(mut machine) = self.finalizer.take() {
            machine.finish_member(self.model.members.last().unwrap())?;
            self.partial.as_ref().unwrap().active().1.finish_member().map_err(failure)?;
            // Expose a bounded poll boundary after durable canonical completion,
            // before any deferred readback. Surviving handles can finish that work.
            cx.waker().wake_by_ref();
            return Ok(Poll::Pending);
        }
        let persistent = self.partial.as_mut().unwrap();
        let (key, core) = persistent.active();
        let mut file = PartialFile::from_core(core.clone());
        let verdict = match file.poll_verify(cx) {
            Poll::Pending => return Ok(Poll::Pending),
            Poll::Ready(v) => v.map_err(failure)?,
        };
        core.compact().map_err(failure)?;
        let state = core.state().map_err(failure)?;
        let outcome = if matches!(verdict, Verdict::Incomplete { .. }) {
            MemberOutcome::PersistentPartial {
                member: key.clone(),
                state,
                expected: member_checks(self.model.members.last().unwrap()),
            }
        } else {
            MemberOutcome::PersistentComplete { member: key.clone(), state, verdict }
        };
        persistent.current = None;
        self.phase = Phase::Header;
        Ok(Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { member: self.member.take().unwrap(), outcome }))))
    }
}
fn member_checks(member: &PhysicalMember) -> MemberChecks {
    let checks = member.final_checks;
    MemberChecks {
        size: member.unpacked_size.unwrap(),
        crc32: checks.and_then(|c| c.crc32),
        blake2sp: checks.and_then(|c| c.blake2sp),
    }
}
fn plain_part(part: &PhysicalPart, ordinal: u64) -> ProgressiveResult<PlainPart> {
    Ok(PlainPart {
        ordinal,
        packed: PackedSpan {
            volume: part.volume as u32,
            range: part.data_offset
                ..part
                    .data_offset
                    .checked_add(part.packed_size)
                    .ok_or_else(|| error(PartialErrorKind::StateMalformed))?,
        },
        out: part.plain_extent.clone().ok_or_else(|| error(PartialErrorKind::StateMalformed))?,
        final_part: part.final_part,
        crc32: part.checks.crc32,
        blake2sp: part.checks.blake2sp,
    })
}
struct PersistentSink<'a> {
    core: &'a Arc<PartialCore>,
    produced: &'a mut u64,
    report: Option<HoleReport>,
    failure: Option<ProgressiveFailure>,
}
impl Sink for PersistentSink<'_> {
    fn put(&mut self, bytes: &[u8]) -> crate::error::Result<()> {
        match self.core.write_original(*self.produced, bytes) {
            Ok(()) => {
                *self.produced += bytes.len() as u64;
                Ok(())
            }
            Err(error) => {
                self.failure = Some(failure(error));
                Err(crate::Error::Corrupt("persistent output"))
            }
        }
    }
}
impl RecoverySink for PersistentSink<'_> {
    fn hole(&mut self, len: u64) -> crate::error::Result<()> {
        let report = self.report.take().ok_or(crate::Error::Corrupt("unmapped hole"))?;
        match self.core.record_hole(report) {
            Ok(()) => {
                *self.produced += len;
                Ok(())
            }
            Err(error) => {
                self.failure = Some(failure(error));
                Err(crate::Error::Corrupt("persistent hole"))
            }
        }
    }
}
pub(super) fn error(kind: PartialErrorKind) -> ProgressiveFailure {
    failure(PartialError::new(kind))
}
fn failure(error: PartialError) -> ProgressiveFailure {
    match error.kind {
        PartialErrorKind::Progressive(inner) if matches!(inner.kind, FailureKind::Partial(_)) => *inner,
        _ => ProgressiveFailure::new(FailureKind::Partial(Box::new(error))),
    }
}
