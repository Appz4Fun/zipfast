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
use std::collections::VecDeque;
use std::ops::Range;

pub(super) struct Persistent {
    options: PartialOptions,
    exclusions: Arc<PartialExclusions>,
    cores: Vec<(MemberKey, Arc<PartialCore>)>,
    current: Option<usize>,
    header_start: u64,
    header: Vec<u8>,
    witness: Option<HeaderWitness>,
    pub(super) ready: Option<(ProgressiveEvent, PartialEventLease)>,
    /// Hole reports recorded but not yet delivered as events; one feed can record several.
    pub(super) holes: VecDeque<HoleReport>,
    /// A `BytesWritten` event held back until the holes the same feed recorded are delivered, so no event
    /// reports a `logical_end` past a hole not yet delivered.
    pub(super) written: Option<ProgressiveEvent>,
    /// Ciphertext stream bytes of the active member fed so far (the output offset for a plain member).
    stream: u64,
    /// Recently unavailable stream ranges of the active member, and whether the caller declared them damaged.
    /// Kept until every block they touch is produced, to give each hole block its cause.
    unavailable: Vec<(Range<u64>, bool)>,
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
            holes: VecDeque::new(),
            written: None,
            stream: 0,
            unavailable: Vec::new(),
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
    /// Declares archive bytes `range` of zero-based `volume` damaged, at any time, including bytes already
    /// extracted (for example when an article's yEnc CRC turns out wrong after it was consumed).
    ///
    /// Output already written from those bytes becomes `DeclaredBad` holes in each affected member, returned in
    /// the receipt; finished members stay fillable through their `PartialFile` and verify again once filled.
    /// Bytes not read yet are answered as holes when the session reaches them. Damage on bytes the session
    /// has not read yet must not cover a member header; lost-header recovery is not supported yet.
    pub fn declare_hole(&mut self, volume: u32, range: Range<u64>) -> ProgressiveResult<DamageReceipt> {
        if self.partial.is_none() || range.is_empty() {
            return Err(error(PartialErrorKind::InvalidOptions));
        }
        let (index, cursor) = self.driver.position();
        let split = match volume.cmp(&index) {
            std::cmp::Ordering::Less => range.end,
            std::cmp::Ordering::Equal => range.end.min(cursor).max(range.start),
            std::cmp::Ordering::Greater => range.start,
        };
        let read = range.start..split;
        let future = split..range.end;
        let mut holes = Vec::new();
        let mut mapped = Vec::new();
        if !read.is_empty() {
            let persistent = self.partial.as_ref().unwrap();
            let active = persistent.current.map(|index| persistent.cores[index].0.clone());
            // The active member first: its machine must learn of streamed damage even if another member fails.
            let order = active
                .as_ref()
                .and_then(|key| persistent.cores.iter().find(|(k, _)| k == key))
                .into_iter()
                .chain(persistent.cores.iter().filter(|(k, _)| Some(k) != active.as_ref()));
            let mut fed = Vec::new();
            if active.is_some() {
                fed = self.fed_damage(volume, &read)?;
            }
            for (key, core) in order {
                if !core.touches(volume, &read) {
                    continue;
                }
                let (reports, ranges) = core.declare_damage(volume, &read).map_err(failure)?;
                if active.as_ref() == Some(key) && !fed.is_empty() {
                    // Encrypted bytes the machine still holds in its CBC state: taint that state, so a block not
                    // produced yet comes out as a DeclaredBad hole and the block after the damage as a
                    // CipherNeighbour hole, and skip the checks those bytes fed.
                    for (stream, packed) in &fed {
                        mapped.push(packed.clone());
                        if let Some(machine) = self.machine.as_mut() {
                            machine.declare_cipher_damage(stream.clone());
                        }
                    }
                    let current_part = self.model.parts.last().is_some_and(|part| {
                        part.volume as u32 == volume
                            && fed.iter().any(|(_, p)| {
                                p.start < part.data_offset.saturating_add(part.packed_size) && part.data_offset < p.end
                            })
                    });
                    if let Some(machine) = self.machine.as_mut() {
                        machine.declare_missing(current_part);
                    }
                }
                if active.as_ref() == Some(key) && !reports.is_empty() {
                    // The member machine checked those bytes as they streamed; it must not judge the member or
                    // the part still being read by them now.
                    let current_part = self.model.parts.last().is_some_and(|part| {
                        part.volume as u32 == volume
                            && reports.iter().any(|r| {
                                r.packed.iter().any(|p| {
                                    p.range.start < part.data_offset.saturating_add(part.packed_size)
                                        && part.data_offset < p.range.end
                                })
                            })
                    });
                    if let Some(machine) = self.machine.as_mut().or(self.finalizer.as_mut()) {
                        machine.declare_missing(current_part);
                    }
                }
                holes.extend(reports);
                mapped.extend(ranges);
            }
            let persistent = self.partial.as_mut().unwrap();
            for (stream, _) in fed {
                self.usage.charge(Resource::MetadataBytes, std::mem::size_of::<(Range<u64>, bool)>() as u64)?;
                persistent.unavailable.try_reserve(1).map_err(|_| error(PartialErrorKind::StateMalformed))?;
                persistent.unavailable.push((stream, true));
            }
        }
        if !future.is_empty() {
            self.driver.declare_future(volume, future.clone())?;
        }
        mapped.sort_by_key(|r: &Range<u64>| r.start);
        let mut unmapped = Vec::new();
        let mut at = read.start;
        for r in mapped {
            if r.start > at {
                unmapped.push(PackedSpan { volume, range: at..r.start });
            }
            at = at.max(r.end);
        }
        if at < read.end {
            unmapped.push(PackedSpan { volume, range: at..read.end });
        }
        let pending = if future.is_empty() { Vec::new() } else { vec![PackedSpan { volume, range: future }] };
        Ok(DamageReceipt { holes, pending, unmapped })
    }
    /// Stream and packed ranges of `range` (on `volume`) that the machine of an active encrypted member still
    /// holds in its CBC state: the block being assembled, and the last complete block, which decrypts the next.
    fn fed_damage(&self, volume: u32, range: &Range<u64>) -> ProgressiveResult<Vec<(Range<u64>, Range<u64>)>> {
        let persistent = self.partial.as_ref().unwrap();
        let mut fed = Vec::new();
        if !self.model.members.last().is_some_and(|m| m.header.encrypted) {
            return Ok(fed);
        }
        let floor = (self.produced & !15).saturating_sub(16);
        let mut stream = 0u64;
        for part in &self.model.parts {
            let start = range.start.max(part.data_offset);
            let end = range.end.min(part.data_offset.saturating_add(part.packed_size));
            if part.volume as u32 == volume && start < end {
                let a = (stream + (start - part.data_offset)).max(floor);
                let b = (stream + (end - part.data_offset)).min(persistent.stream);
                if a < b {
                    self.usage.charge(Resource::MetadataBytes, std::mem::size_of::<[Range<u64>; 2]>() as u64)?;
                    fed.try_reserve(1).map_err(|_| error(PartialErrorKind::StateMalformed))?;
                    let packed = part.data_offset + (a - stream);
                    fed.push((a..b, packed..packed + (b - a)));
                }
            }
            stream = stream.saturating_add(part.packed_size);
        }
        Ok(fed)
    }
    pub(super) fn partial_header(&self, header: &crate::rar5::FileHeader) -> ProgressiveResult<()> {
        if header.format != crate::rar5::RarFormat::Rar5 {
            return Err(error(PartialErrorKind::UnsupportedFormat));
        }
        // Encrypted stored members are admitted; their password must be in the session options.
        if header.method != 0 || header.is_dir() || header.redirection.is_some() {
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
        part.plain_extent = Some(extent(header, 0, part.packed_size)?);
        let plain = plain_part(part, 0)?;
        // The extraction's machine holds the keys of an encrypted member; the core keeps them in memory only.
        let keys = match self.machine.as_ref().and_then(|machine| machine.cipher.as_ref()) {
            Some(cipher) => Some(MemberKeys::new(
                cipher.aes,
                *cipher.checksum_key().ok_or_else(|| error(PartialErrorKind::UnsupportedMethod))?,
            )),
            None if header.encrypted => return Err(error(PartialErrorKind::PasswordRequired)),
            None => None,
        };
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
        if let Some(keys) = keys {
            prepared.set_keys(keys);
        }
        prepared.reserve_ready_state().map_err(failure)?;
        let parents = prepared
            .prepare_parents(|path| self.driver.check_partial_target(path).map_err(Into::into))
            .map_err(failure)?;
        parents.check().map_err(failure)?;
        let (core, state, event_lease) = prepared.complete_ready().map_err(failure)?;
        persistent.current = Some(persistent.cores.len());
        persistent.cores.push((key.clone(), core));
        persistent.stream = 0;
        persistent.unavailable.clear();
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
        let header = &self.model.members.last().unwrap().header;
        let part = &mut self.model.parts[index];
        part.plain_extent = Some(extent(header, out, part.packed_size)?);
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
    /// Feeds `count` packed bytes (a hole when `hole` holds their packed offset) to the active member. Holes the
    /// machine emits, including the `CipherNeighbour` block a data feed of an encrypted member can emit, are
    /// recorded durably and queued as events. Returns the output bytes written.
    pub(super) fn partial_feed(&mut self, count: usize, hole: Option<u64>) -> ProgressiveResult<u64> {
        let encrypted = self.model.members.last().unwrap().header.encrypted;
        let declared =
            hole.is_some_and(|packed| self.driver.declared_covers(self.volume, &(packed..packed + count as u64)));
        let persistent = self.partial.as_mut().unwrap();
        let stream = persistent.stream;
        persistent.stream = stream.checked_add(count as u64).ok_or_else(|| error(PartialErrorKind::StateMalformed))?;
        if hole.is_some() {
            self.usage.charge(Resource::MetadataBytes, std::mem::size_of::<(Range<u64>, bool)>() as u64)?;
            persistent.unavailable.try_reserve(1).map_err(|_| error(PartialErrorKind::StateMalformed))?;
            persistent.unavailable.push((stream..stream + count as u64, declared));
        }
        let Persistent { cores, current, holes, unavailable, .. } = persistent;
        let core = &cores[current.expect("persistent member")].1;
        let mut sink = PersistentSink {
            core,
            produced: &mut self.produced,
            encrypted,
            unavailable,
            blocks: Vec::new(),
            reports: holes,
            usage: &self.usage,
            written: 0,
            failure: None,
        };
        let machine = self.machine.as_mut().unwrap();
        machine.reserve_progressive_scratch(count, &self.usage)?;
        let result = machine.feed_stored(hole.is_none().then_some(&self.buffer[..count]), count, &mut sink);
        let written = sink.written;
        if let Some(error) = sink.failure {
            return Err(error);
        }
        result?;
        // A range stays until every block it touches is produced.
        let floor = if encrypted { self.produced & !15 } else { self.produced };
        unavailable.retain(|(range, _)| range.end > floor);
        self.driver.validate_current()?;
        Ok(written)
    }
    pub(super) fn partial_part_event(&self) -> ProgressiveResult<Option<ProgressiveEvent>> {
        if !self.partial_active() {
            return Ok(None);
        }
        let persistent = self.partial.as_ref().unwrap();
        let part = self.model.parts.last().unwrap();
        // Encrypted part checks cover ciphertext, never plaintext output, so they have no plaintext mirror.
        if part.final_part
            || self.model.members.last().unwrap().header.encrypted
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
        let encrypted = self.model.members.last().unwrap().header.encrypted;
        let Persistent { cores, current, holes, unavailable, .. } = self.partial.as_mut().unwrap();
        let core = &cores[current.expect("persistent member")].1;
        let mut sink = PersistentSink {
            core,
            produced: &mut self.produced,
            encrypted,
            unavailable,
            blocks: Vec::new(),
            reports: holes,
            usage: &self.usage,
            written: 0,
            failure: None,
        };
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
        persistent.unavailable.clear();
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
/// Output range of a part starting at stream offset `stream`: the stream itself for a plain member, clipped at the
/// unpacked size for an encrypted one (the final padding maps to no output).
fn extent(header: &crate::rar5::FileHeader, stream: u64, packed: u64) -> ProgressiveResult<Range<u64>> {
    let end = stream.checked_add(packed).ok_or_else(|| error(PartialErrorKind::StateMalformed))?;
    Ok(if header.encrypted { stream.min(header.unpacked_size)..end.min(header.unpacked_size) } else { stream..end })
}
struct PersistentSink<'a> {
    core: &'a Arc<PartialCore>,
    produced: &'a mut u64,
    encrypted: bool,
    unavailable: &'a [(Range<u64>, bool)],
    /// Ciphertext blocks the machine handed over for the next hole run.
    blocks: Vec<CipherBlock>,
    reports: &'a mut VecDeque<HoleReport>,
    usage: &'a Usage,
    written: u64,
    failure: Option<ProgressiveFailure>,
}
impl PersistentSink<'_> {
    /// Cause of a hole over stream `range`: the source said it was unavailable (declared by the caller or not),
    /// or, for an encrypted member, only the previous ciphertext block was.
    fn cause(&self, range: &Range<u64>) -> HoleCause {
        let mut overlapping =
            self.unavailable.iter().filter(|(r, _)| r.start < range.end && range.start < r.end).peekable();
        if overlapping.peek().is_none() {
            return if self.encrypted { HoleCause::CipherNeighbour } else { HoleCause::Missing };
        }
        if overlapping.all(|(_, declared)| *declared) { HoleCause::DeclaredBad } else { HoleCause::Missing }
    }
    #[allow(clippy::result_large_err, reason = "carries the typed partial receipt into the sink failure")]
    fn record(&mut self, len: u64) -> PartialResult<()> {
        let end = self.produced.checked_add(len).ok_or_else(|| PartialError::new(PartialErrorKind::StateMalformed))?;
        while *self.produced < end {
            let at = *self.produced;
            let (cause, stop) = if self.encrypted {
                // One cause per 16-byte block, judged on the block's ciphertext; runs of equal causes join.
                let cause = self.cause(&(at & !15..(at & !15) + 16));
                let mut stop = ((at & !15) + 16).min(end);
                while stop < end && self.cause(&(stop..stop + 16)) == cause {
                    stop = (stop + 16).min(end);
                }
                (cause, stop)
            } else {
                (self.cause(&(at..end)), end)
            };
            let report = self.core.hole_report(at..stop, cause)?;
            let blocks = std::mem::take(&mut self.blocks);
            self.core.record_hole_with(report.clone(), &blocks)?;
            *self.produced = stop;
            self.usage.charge(Resource::MetadataBytes, std::mem::size_of::<HoleReport>() as u64)?;
            self.reports.try_reserve(1).map_err(|_| PartialError::new(PartialErrorKind::StateMalformed))?;
            self.reports.push_back(report);
        }
        Ok(())
    }
}
impl Sink for PersistentSink<'_> {
    fn put(&mut self, bytes: &[u8]) -> crate::error::Result<()> {
        match self.core.write_original(*self.produced, bytes) {
            Ok(()) => {
                *self.produced += bytes.len() as u64;
                self.written += bytes.len() as u64;
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
        self.record(len).map_err(|error| {
            self.failure = Some(failure(error));
            crate::Error::Corrupt("persistent hole")
        })
    }
    fn cipher_block(&mut self, offset: u64, block: &[u8; 16]) -> crate::error::Result<()> {
        let admitted =
            self.usage.charge(Resource::MetadataBytes, std::mem::size_of::<CipherBlock>() as u64).and_then(|()| {
                self.blocks.try_reserve(1).map_err(|_| ProgressiveFailure::new(FailureKind::InvalidCapability))
            });
        if let Err(error) = admitted {
            self.failure = Some(error);
            return Err(crate::Error::Corrupt("persistent cipher block"));
        }
        self.blocks.push(CipherBlock { offset, have: 0..16, bytes: *block });
        Ok(())
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
