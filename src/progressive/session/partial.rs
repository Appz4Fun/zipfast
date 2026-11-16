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
    cores: Vec<Slot>,
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
    /// How the active member, adopted from an earlier session, is resumed; `None` for a member this session
    /// created, and for an adopted member once extraction has resumed at its committed `produced`.
    resume: Option<Resume>,
    /// Directories of directory entries, whose metadata is applied when the walk reaches the end of the set.
    directories: Vec<PendingDirectory>,
    /// Identities of every directory this session created: parents of its outputs and directory entries.
    created: Vec<crate::progressive::native::Identity>,
}
/// A member this session created or adopted. Its core (state pages, descriptors, `open_partials` lease) is held
/// until the member has finished and the caller has taken its handle with `partial_file`; then the session keeps
/// only a weak reference, and the core lives exactly as long as the caller's handles.
struct Slot {
    key: MemberKey,
    core: Option<Arc<PartialCore>>,
    weak: std::sync::Weak<PartialCore>,
    output: std::path::PathBuf,
    taken: bool,
    finished: bool,
    /// Packed ranges of the recorded parts, kept once the core is released so declared damage still maps.
    spans: Vec<PackedSpan>,
}
impl Slot {
    fn new(key: MemberKey, core: Arc<PartialCore>) -> Self {
        let output = core.output_path().to_path_buf();
        Self {
            key,
            weak: Arc::downgrade(&core),
            core: Some(core),
            output,
            taken: false,
            finished: false,
            spans: Vec::new(),
        }
    }
    /// The core while anyone holds it.
    fn live(&self) -> Option<Arc<PartialCore>> {
        self.core.clone().or_else(|| self.weak.upgrade())
    }
    fn release_if_done(&mut self) {
        if self.taken
            && self.finished
            && let Some(core) = self.core.take()
        {
            self.spans = core.packed_parts();
        }
    }
}
/// A directory entry's directory: its metadata waits until nothing more is created inside it.
struct PendingDirectory {
    path: std::path::PathBuf,
    identity: crate::progressive::native::Identity,
    meta: crate::extract::Meta,
}
/// An adopted member being walked to its resume point.
struct Resume {
    /// Its canonical finish is committed: every part is walked header by header and its data is never read.
    finished: bool,
    /// The committed `produced` extraction continues from.
    produced: u64,
    /// The ciphertext stream offset (the output offset for a plain member) the machine is fed from again.
    stream: u64,
    /// Where an encrypted member's previous ciphertext block starts: bytes `iv_from..stream` are read into `iv`
    /// and decrypt nothing themselves.
    iv_from: u64,
    iv: [u8; 16],
    iv_known: bool,
    /// The member machine, held back until the resume point so the bytes before it never reach it.
    machine: Option<MemberMachine>,
}
/// What the resume walk did with the active part.
pub(super) enum ResumeStep {
    /// Moved forward; poll again.
    Continue,
    /// The source must wait.
    Pending,
    /// Nothing to do: the part ends here (or the member resumed); handle it as usual.
    Done,
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
        let slot = &self.cores[self.current.expect("persistent member")];
        (&slot.key, slot.core.as_ref().expect("the active member's core is held"))
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
            resume: None,
            directories: Vec::new(),
            created: Vec::new(),
        });
        Ok(session)
    }
    #[allow(clippy::result_large_err, reason = "preserve the public typed partial receipt API")]
    ///
    /// Once a member has finished and its handle was taken here, the session releases its own reference: the
    /// member's state pages, descriptors and `open_partials` lease are freed when the caller drops its last handle,
    /// so a set with many members does not run out of them. A released member is never verified or extracted
    /// again by the session; while any handle lives this returns another one, and after the last is dropped it is
    /// `BindingMismatch(Member)`: reopen the member with [`PartialFile::open`] from its state.
    pub fn partial_file(&mut self, member: &MemberKey) -> PartialResult<PartialFile> {
        let slot = self
            .partial
            .as_mut()
            .and_then(|p| p.cores.iter_mut().find(|slot| slot.key == *member))
            .ok_or_else(|| PartialError::new(PartialErrorKind::BindingMismatch(BindingField::Member)))?;
        let core =
            slot.live().ok_or_else(|| PartialError::new(PartialErrorKind::BindingMismatch(BindingField::Member)))?;
        slot.taken = true;
        slot.release_if_done();
        Ok(PartialFile::from_core(core))
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
        let mut released = Vec::new();
        if !read.is_empty() {
            let persistent = self.partial.as_ref().unwrap();
            let active = persistent.current.map(|index| persistent.cores[index].key.clone());
            // The active member first: its machine must learn of streamed damage even if another member fails.
            // Released members whose handles were all dropped are reported in `released`, from the packed
            // ranges kept at release: their damage is the caller's to declare on a reopened handle.
            // One snapshot per slot: a handle dropped meanwhile cannot move a span between the two lists.
            let ordered = active
                .as_ref()
                .and_then(|key| persistent.cores.iter().find(|slot| slot.key == *key))
                .into_iter()
                .chain(persistent.cores.iter().filter(|slot| Some(&slot.key) != active.as_ref()));
            let mut live: Vec<(MemberKey, Arc<PartialCore>)> = Vec::new();
            for slot in ordered {
                if let Some(core) = slot.live() {
                    live.push((slot.key.clone(), core));
                    continue;
                }
                for span in slot.spans.iter().filter(|span| span.volume == volume) {
                    let hit = span.range.start.max(read.start)..span.range.end.min(read.end);
                    if hit.start < hit.end {
                        mapped.push(hit.clone());
                        released.push((slot.key.clone(), PackedSpan { volume, range: hit }));
                    }
                }
            }
            let order = live.iter().map(|(key, core)| (key, core));
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
        // An adopted encrypted member reading its previous ciphertext block holds its machine back, so neither the
        // machine nor `fed_damage` sees damage on those bytes: mark the block unknown, so the first block after
        // the resume point becomes a `CipherNeighbour` hole instead of output decrypted with damaged ciphertext.
        if let Some(resume) = self.partial.as_ref().and_then(|p| p.resume.as_ref())
            && !resume.finished
            && resume.iv_from < resume.stream
        {
            let (iv, mut stream, mut hit) = (resume.iv_from..resume.stream, 0u64, false);
            for part in &self.model.parts {
                let start = range.start.max(part.data_offset);
                let end = range.end.min(part.data_offset.saturating_add(part.packed_size));
                if part.volume as u32 == volume && start < end {
                    let a = stream + (start - part.data_offset);
                    let b = stream + (end - part.data_offset);
                    hit |= a < iv.end && iv.start < b;
                }
                stream = stream.saturating_add(part.packed_size);
            }
            // A part not parsed yet holds no byte of the block: it lies before the resume point.
            if hit {
                self.partial.as_mut().unwrap().resume.as_mut().unwrap().iv_known = false;
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
        Ok(DamageReceipt { holes, pending, unmapped, released })
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
    /// Whether the member `header` starts or continues is refused, so that it is walked past without being
    /// decoded. A later part of an admitted member that would be refused fails the session, as it always did.
    pub(super) fn partial_refused(&self, header: &crate::rar5::FileHeader) -> ProgressiveResult<bool> {
        if self.partial.is_none() {
            return Ok(false);
        }
        if self.member.is_none() {
            return Ok(refusal(header).is_some());
        }
        if matches!(self.disposition, Disposition::Refused(_)) {
            return Ok(true);
        }
        match refusal(header) {
            None => Ok(false),
            Some(RefusalReason::UnknownSize) => Err(error(PartialErrorKind::UnknownMemberSize)),
            Some(_) => Err(error(PartialErrorKind::UnsupportedMethod)),
        }
    }
    /// Skips the rest of a refused member's active part without reading it. Damage declared on those bytes is
    /// dropped: no output was produced from them and none ever will be.
    pub(super) fn partial_skip_refused(&mut self) -> ProgressiveResult<()> {
        let part = self.model.parts.last().unwrap();
        let from = part.data_offset + (part.packed_size - self.remaining);
        let at = part.data_offset + part.packed_size;
        // Data running past the end of its volume is truncated, as reading it would find.
        if self.driver.observed_info(self.volume).is_some_and(|info| info.length.value() < at) {
            return Err(ProgressiveFailure::new(FailureKind::Truncated));
        }
        drop(self.driver.take_declared(self.volume, &(from..at)));
        self.driver.seek(at)?;
        self.cursor = at;
        self.remaining = 0;
        Ok(())
    }
    /// Creates a directory entry's directory with the checks a member creation applies to its parents, and
    /// queues its metadata for the end of the set.
    #[allow(clippy::result_large_err, reason = "the path check callback returns typed partial receipts")]
    pub(super) fn partial_directory(&mut self) -> ProgressiveResult<ProgressiveEvent> {
        let header = &self.model.members.last().unwrap().header;
        let relative = crate::path::sanitize_fallible(&header.name, !header.is_unix())
            .map_err(|_| error(PartialErrorKind::UnsafePath))?;
        let meta = crate::extract::Meta::from(header);
        let persistent = self.partial.as_mut().unwrap();
        self.usage.charge(
            Resource::MetadataBytes,
            (std::mem::size_of::<PendingDirectory>()
                + relative.as_os_str().len()
                + self.options.extract.dest.as_os_str().len()) as u64,
        )?;
        persistent.directories.try_reserve(1).map_err(|_| error(PartialErrorKind::StateMalformed))?;
        // Room to remember every directory this may create, admitted before any is created.
        let root = std::path::absolute(&self.options.extract.dest).map_err(|_| error(PartialErrorKind::UnsafePath))?;
        reserve_created(&mut persistent.created, root.join(&relative).components().count(), &self.usage)?;
        let driver = &mut self.driver;
        let (_, identity, made) = create_directory(
            &self.options.extract.dest,
            &relative,
            persistent.options.limits.clone(),
            self.usage.clone(),
            persistent.exclusions.clone(),
            &persistent.options.control,
            |path| match path {
                GenesisPath::Parent(path) | GenesisPath::Output(path) => Ok(driver.check_partial_target(path)?),
                GenesisPath::Bundle(path) => Ok(driver.check_partial_subtree(path)?),
            },
        )
        .map_err(failure)?;
        let path = std::path::absolute(&self.options.extract.dest)
            .map_err(|_| error(PartialErrorKind::UnsafePath))?
            .join(&relative);
        // Only a directory this session created, for this entry or earlier as the parent of a member stored before
        // its entry (as RAR usually stores them), gets the entry's metadata; an existing one is left as it is.
        persistent.created.extend(made);
        let created = persistent.created.contains(&identity);
        if created {
            persistent.directories.push(PendingDirectory { path, identity, meta });
        }
        self.driver.validate_current()?;
        self.phase = Phase::Header;
        Ok(ProgressiveEvent::MemberFinished {
            member: self.member.take().unwrap(),
            outcome: MemberOutcome::Directory { created, deferred: None },
        })
    }
    /// At the end of the set: applies each directory entry's modified time and permissions to the directory this
    /// session created for it, deepest first and the last entry for a directory winning. A directory that is, or
    /// holds, the state root or a path the declaration names gets no metadata at all, and one that holds an output
    /// of this session keeps its owner's read, write and search permission. A directory replaced since fails with
    /// `OutputChanged` and is left alone.
    pub(super) fn partial_finish_directories(&mut self) -> ProgressiveResult<()> {
        if self.partial.as_ref().is_none_or(|p| p.directories.is_empty()) {
            return Ok(());
        }
        let protection = self.driver.partial_catalogue()?;
        let persistent = self.partial.as_mut().unwrap();
        let mut directories = std::mem::take(&mut persistent.directories);
        let count = directories.len() as u64;
        self.usage.charge(
            Resource::SourceBookkeeping,
            count.saturating_mul(16).saturating_mul(u64::from(count.max(1).ilog2()) + 1),
        )?;
        // Directories that must stay as they are: the state root and every declared path, with their ancestors.
        let mut kept = Vec::new();
        let mut protected = vec![persistent.options.state_dir.clone()];
        if let ProtectionDeclaration::Complete { inventory, .. } = &protection {
            for volume in &inventory.volumes {
                if let VolumeBacking::Native(paths) = &volume.backing {
                    protected.extend(paths.iter().map(|p| p.path.clone()));
                }
            }
            protected.extend(inventory.auxiliary_paths.iter().map(|p| p.path.clone()));
        }
        for path in &protected {
            ancestor_identities(path, &mut kept, &self.usage)?;
        }
        // Directories that must stay usable: those holding an output of this session.
        let mut holding = Vec::new();
        for slot in &persistent.cores {
            ancestor_identities(&slot.output, &mut holding, &self.usage)?;
        }
        // Stable: among entries for one directory the last stays last.
        directories.sort_by_key(|d| std::cmp::Reverse(d.path.components().count()));
        for (index, directory) in directories.iter().enumerate() {
            if directories[index + 1..].iter().any(|later| later.identity == directory.identity)
                || kept.contains(&directory.identity)
            {
                continue;
            }
            if self.control.is_canceled() || persistent.options.control.is_canceled() {
                return Ok(());
            }
            let file = crate::progressive::guard::open_directory(&directory.path)
                .map_err(|_| error(PartialErrorKind::OutputChanged))?;
            let identity = crate::progressive::native::Identity::file(&file)
                .map_err(|_| error(PartialErrorKind::OutputChanged))?;
            if identity != directory.identity {
                return Err(error(PartialErrorKind::OutputChanged));
            }
            let mut meta = directory.meta;
            if holding.contains(&directory.identity) {
                meta.mode = meta.mode.map(|mode| mode | 0o700);
            }
            crate::extract::finish_file(&file, &meta);
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
        // Each format has its own identity domain, so a RAR4 and a RAR5 member never share a key or a bundle.
        let format = header.format;
        let mut identity = match format {
            crate::rar5::RarFormat::Rar5 => b"zipfast/plain-stored/member/v1\0".to_vec(),
            crate::rar5::RarFormat::Rar4 => b"zipfast/rar4-stored/member/v1\0".to_vec(),
        };
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
            // A RAR4 cipher has no checksum key (its CRC is plain) but an IV derived with its key; the machine has
            // decrypted nothing yet, so its IV is still the first one.
            Some(cipher) if format == crate::rar5::RarFormat::Rar4 => {
                Some(MemberKeys::new(cipher.aes, [0; 32]).with_iv(cipher.iv))
            }
            Some(cipher) => Some(MemberKeys::new(
                cipher.aes,
                *cipher.checksum_key().ok_or_else(|| error(PartialErrorKind::UnsupportedMethod))?,
            )),
            None if header.encrypted => return Err(error(PartialErrorKind::PasswordRequired)),
            None => None,
        };
        // A member an earlier session created has its anchor already: adopt it instead of creating it again.
        if let Some(anchor) = persistent.options.anchors.current(&key).map_err(failure)? {
            return self.partial_adopt(key, anchor, relative, plain, witness, keys);
        }
        let checks = member_checks(physical);
        let admission = SourceAdmission {
            volume: self.volume,
            info: self
                .driver
                .observed_info(self.volume)
                .ok_or_else(|| ProgressiveFailure::new(FailureKind::SourceContract))?,
            expected: self.expected.clone(),
        };
        let mut spec = CreateSpec {
            member: key.clone(),
            name: Arc::from(header.name.as_bytes()),
            output_root: self.options.extract.dest.clone(),
            state_root: persistent.options.state_dir.clone(),
            relative_output: relative,
            size: header.unpacked_size,
            protection: crate::progressive::ProtectionDeclaration::Opaque,
            evidence: InitialEvidence {
                format,
                metadata: crate::extract::Meta::from(header),
                parts: vec![plain],
                admissions: vec![admission],
                headers: vec![witness],
            },
        };
        self.usage.charge(Resource::MetadataBytes, std::mem::size_of::<(MemberKey, Arc<PartialCore>)>() as u64)?;
        persistent.cores.try_reserve_exact(1).map_err(|_| error(PartialErrorKind::StateMalformed))?;
        // The output and bundle are checked against a snapshot of the declaration, but the parent checks read it
        // again and an extension may land meanwhile. Their exclusions are registered only by the genesis, so the
        // extension's own check cannot see them: after the parents, and before any name is created, both are
        // checked against the current declaration, and creation is prepared again if it grew.
        // Room to remember every directory the parents may create (output and state roots included), admitted
        // before any is created.
        let root = std::path::absolute(&self.options.extract.dest).map_err(|_| error(PartialErrorKind::UnsafePath))?;
        let state =
            std::path::absolute(&persistent.options.state_dir).map_err(|_| error(PartialErrorKind::UnsafePath))?;
        let bound = root.join(&spec.relative_output).components().count() + state.components().count();
        reserve_created(&mut persistent.created, bound, &self.usage)?;
        let mut attempts = 0;
        let (prepared, parents) = loop {
            spec.protection = self.driver.partial_catalogue()?;
            let epoch = self.driver.protection_epoch();
            let mut prepared = PartialCore::prepare_create(
                spec.clone(),
                checks.clone(),
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
            if let Some(keys) = &keys {
                prepared.set_keys(keys.clone());
            }
            prepared.reserve_ready_state().map_err(failure)?;
            let mut grew = false;
            let driver = &mut self.driver;
            let parents = prepared.prepare_parents(|path| {
                match path {
                    GenesisPath::Parent(path) | GenesisPath::Output(path) => driver.check_partial_target(path)?,
                    GenesisPath::Bundle(path) => {
                        driver.check_partial_subtree(path)?;
                        // The last provider callback before the genesis creates a name.
                        if driver.protection_epoch() != epoch {
                            grew = true;
                            return Err(ProgressiveFailure::new(FailureKind::SourceChanged).into());
                        }
                    }
                }
                Ok(())
            });
            match parents {
                Ok(parents) => {
                    parents.check().map_err(failure)?;
                    break (prepared, parents);
                }
                Err(_) if grew && attempts < 3 => attempts += 1,
                Err(e) => return Err(failure(e)),
            }
        };
        // Parents created here are this session's: a directory entry arriving later gives them its metadata.
        persistent.created.extend_from_slice(parents.created());
        let (core, state, event_lease) = prepared.complete_ready().map_err(failure)?;
        persistent.current = Some(persistent.cores.len());
        persistent.cores.push(Slot::new(key.clone(), core));
        persistent.stream = 0;
        persistent.unavailable.clear();
        persistent.resume = None;
        persistent.ready = Some((ProgressiveEvent::PartialReady { member: key, state }, event_lease));
        Ok(())
    }
    /// Adopts the member an earlier session created under `key`: reopens its output and state bundle (nothing is
    /// created or written), checks that it is this member (output path, name, size, and the first part with its
    /// header witness), and arranges the walk to its resume point. A member that does not match fails the session
    /// with the typed error, and its files are left as they are.
    #[allow(clippy::result_large_err, reason = "adoption propagates typed partial receipts")]
    fn partial_adopt(
        &mut self,
        key: MemberKey,
        anchor: StateAnchor,
        relative: std::path::PathBuf,
        plain: PlainPart,
        witness: HeaderWitness,
        keys: Option<MemberKeys>,
    ) -> ProgressiveResult<()> {
        let persistent = self.partial.as_mut().unwrap();
        let header = &self.model.members.last().unwrap().header;
        let (output, bundle) = member_paths(&self.options.extract.dest, &persistent.options.state_dir, &relative, &key)
            .map_err(failure)?;
        // The paths are checked against the current declaration as a creation checks them, before anything is
        // opened, and again once the adopted paths are registered, in case the declaration grew meanwhile.
        let root = std::path::absolute(&self.options.extract.dest).map_err(|_| error(PartialErrorKind::UnsafePath))?;
        let parents: Vec<std::path::PathBuf> =
            relative.ancestors().skip(1).filter(|p| !p.as_os_str().is_empty()).map(|p| root.join(p)).collect();
        let check = |driver: &mut SourceDriver| -> ProgressiveResult<()> {
            for parent in &parents {
                driver.check_partial_target(parent)?;
            }
            driver.check_partial_target(&output)?;
            driver.check_partial_subtree(&bundle)
        };
        check(&mut self.driver)?;
        self.usage.charge(Resource::MetadataBytes, std::mem::size_of::<(MemberKey, Arc<PartialCore>)>() as u64)?;
        persistent.cores.try_reserve_exact(1).map_err(|_| error(PartialErrorKind::StateMalformed))?;
        let (core, state, event_lease) = PartialCore::adopt(
            AdoptSpec {
                member: key.clone(),
                anchor,
                output_root: self.options.extract.dest.clone(),
                state_root: persistent.options.state_dir.clone(),
                protection: self.driver.partial_catalogue()?,
                keys,
            },
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
        check(&mut self.driver)?;
        core.check_adopted(&relative, header.name.as_bytes(), header.unpacked_size).map_err(failure)?;
        if !core.recorded_part(&plain, &witness).map_err(failure)? {
            return Err(error(PartialErrorKind::StateMalformed));
        }
        let (produced, finished, size) = core.resume_point().map_err(failure)?;
        let encrypted = header.encrypted;
        // An encrypted member resumes on a block boundary; once every output byte is known it resumes past the
        // final padding, which belongs to the last block.
        let stream = if encrypted && produced == size {
            size.div_ceil(16) * 16
        } else if encrypted && produced % 16 != 0 {
            return Err(error(PartialErrorKind::StateMalformed));
        } else {
            produced
        };
        let iv_from = if encrypted && produced < size { stream.saturating_sub(16) } else { stream };
        let machine = self.machine.take();
        if finished {
            self.produced = size;
        }
        let persistent = self.partial.as_mut().unwrap();
        persistent.current = Some(persistent.cores.len());
        persistent.cores.push(Slot::new(key.clone(), core));
        persistent.stream = 0;
        persistent.unavailable.clear();
        persistent.resume = Some(Resume {
            finished,
            produced,
            stream,
            iv_from,
            iv: [0; 16],
            iv_known: true,
            machine: if finished { None } else { machine },
        });
        persistent.ready =
            Some((ProgressiveEvent::PartialAdopted { member: key, state, produced, finished }, event_lease));
        Ok(())
    }
    pub(super) fn partial_resuming(&self) -> bool {
        self.partial.as_ref().is_some_and(|p| p.current.is_some() && p.resume.is_some())
    }
    /// One step of walking an adopted member's active part to its resume point. A finished member's data is
    /// skipped; otherwise the data before the resume point is skipped (except an encrypted member's previous
    /// ciphertext block, which is read), and at the resume point the machine is restored with the hash state of
    /// the output already produced and fed from there on.
    pub(super) fn partial_resume_step(
        &mut self,
        cx: &mut Context<'_>,
        work: &mut u64,
    ) -> ProgressiveResult<ResumeStep> {
        let index = self.model.parts.len() - 1;
        let part = &self.model.parts[index];
        let start = self.model.parts[..index]
            .iter()
            .try_fold(0u64, |sum, p| sum.checked_add(p.packed_size))
            .ok_or_else(|| error(PartialErrorKind::StateMalformed))?;
        let packed_size = part.packed_size;
        let data_offset = part.data_offset;
        let out_start = part.plain_extent.as_ref().ok_or_else(|| error(PartialErrorKind::StateMalformed))?.start;
        let pos = start + (packed_size - self.remaining);
        let resume = self.partial.as_mut().unwrap().resume.as_mut().unwrap();
        if resume.finished {
            self.skip(self.remaining)?;
            return Ok(ResumeStep::Done);
        }
        if pos == resume.stream {
            return self.partial_restore(pos - start, out_start).map(|()| ResumeStep::Continue);
        }
        if self.remaining == 0 || pos > resume.stream {
            return Ok(ResumeStep::Done);
        }
        if pos < resume.iv_from {
            let n = (resume.iv_from - pos).min(self.remaining);
            self.skip(n)?;
            return Ok(ResumeStep::Continue);
        }
        let iv_from = resume.iv_from;
        let want = (resume.stream - pos).min(self.remaining) as usize;
        let at = data_offset + (packed_size - self.remaining);
        // Damage declared on the block's bytes in this part: the output an earlier session decrypted from them
        // becomes `DeclaredBad` holes (as for skipped bytes), and the block is unknown, so the first block after
        // the resume point becomes a `CipherNeighbour` hole. The bytes are then read as usual.
        let declared = self.driver.take_declared(self.volume, &(at..at + want as u64));
        if !declared.is_empty() {
            self.apply_declared(declared)?;
            self.partial.as_mut().unwrap().resume.as_mut().unwrap().iv_known = false;
        }
        if at != self.cursor {
            self.driver.seek(at)?;
            self.cursor = at;
        }
        let n = self.read_len(want, *work);
        match self.driver.poll_step(cx, &mut self.buffer[..n]) {
            Poll::Pending => {
                self.parked_read = Some(n);
                self.partial_wait()?;
                Ok(ResumeStep::Pending)
            }
            Poll::Ready(Err(e)) => Err(e),
            Poll::Ready(Ok(SourceStep::EndOfVolume)) => Err(ProgressiveFailure::new(FailureKind::Truncated)),
            Poll::Ready(Ok(SourceStep::VolumeOpened { .. })) => {
                Err(ProgressiveFailure::new(FailureKind::SourceContract))
            }
            Poll::Ready(Ok(SourceStep::Hole { offset, len })) => {
                self.cursor = offset + len;
                self.remaining -= len;
                *work += len;
                self.partial.as_mut().unwrap().resume.as_mut().unwrap().iv_known = false;
                Ok(ResumeStep::Continue)
            }
            Poll::Ready(Ok(SourceStep::Filled { offset, count })) => {
                self.cursor = offset + count as u64;
                self.remaining -= count as u64;
                *work += count as u64;
                let resume = self.partial.as_mut().unwrap().resume.as_mut().unwrap();
                let into = (pos - iv_from) as usize;
                resume.iv[into..into + count].copy_from_slice(&self.buffer[..count]);
                self.driver.validate_step()?;
                Ok(ResumeStep::Continue)
            }
        }
    }
    /// Skips `n` data bytes of the active part without reading them. Damage declared on them (with
    /// `declare_hole`, while they were still ahead of the session) is applied to the output already produced from
    /// them: its runs become `DeclaredBad` holes, delivered as `Hole` events, instead of being seeked over.
    fn skip(&mut self, n: u64) -> ProgressiveResult<()> {
        if n == 0 {
            return Ok(());
        }
        let part = self.model.parts.last().unwrap();
        let from = part.data_offset + (part.packed_size - self.remaining);
        let at = from + n;
        let declared = self.driver.take_declared(self.volume, &(from..at));
        self.apply_declared(declared)?;
        self.driver.seek(at)?;
        self.cursor = at;
        self.remaining -= n;
        Ok(())
    }
    /// Applies damage declared on packed `ranges` of the current volume to the active member's produced output,
    /// queueing the `DeclaredBad` (and, encrypted, `CipherNeighbour`) holes it records as events.
    fn apply_declared(&mut self, ranges: Vec<Range<u64>>) -> ProgressiveResult<()> {
        if ranges.is_empty() {
            return Ok(());
        }
        let persistent = self.partial.as_mut().unwrap();
        let core = persistent.active().1.clone();
        for range in ranges {
            let (reports, _) = core.declare_damage(self.volume, &range).map_err(failure)?;
            self.usage.charge(Resource::MetadataBytes, (reports.len() * std::mem::size_of::<HoleReport>()) as u64)?;
            persistent.holes.try_reserve(reports.len()).map_err(|_| error(PartialErrorKind::StateMalformed))?;
            persistent.holes.extend(reports);
        }
        Ok(())
    }
    /// Restores the held-back machine at the resume point: `part_bytes` of the active part lie before it, whose
    /// output starts at `out_start`.
    fn partial_restore(&mut self, part_bytes: u64, out_start: u64) -> ProgressiveResult<()> {
        let persistent = self.partial.as_mut().unwrap();
        let resume = persistent.resume.take().unwrap();
        let mut machine = resume.machine.ok_or_else(|| error(PartialErrorKind::StateMalformed))?;
        let core =
            persistent.cores[persistent.current.unwrap()].core.as_ref().expect("the active member's core is held");
        let encrypted = machine.cipher.is_some();
        let member_blake = machine.inner.as_ref().is_some_and(|inner| inner.blake.is_some());
        // Encrypted part checks cover ciphertext, which the resume skipped: the resumed part's check is not judged.
        let hashes = core
            .prefix_hashes(resume.produced, out_start.min(resume.produced), member_blake, !encrypted)
            .map_err(failure)?;
        let iv = if resume.stream == 0 {
            machine.cipher.as_ref().map(|cipher| cipher.iv)
        } else {
            resume.iv_known.then_some(resume.iv)
        };
        machine.resume_stored(
            self.model.parts.last().unwrap(),
            crate::rar5::member::StoredResume {
                delivered: resume.produced,
                part_bytes,
                member: hashes.member,
                part: if encrypted && part_bytes > 0 { None } else { hashes.part },
                iv: if encrypted { iv } else { None },
                padding: (resume.stream - resume.produced.min(resume.stream)) as usize,
            },
        )?;
        self.machine = Some(machine);
        self.produced = resume.produced;
        persistent.stream = resume.stream;
        Ok(())
    }
    /// Before the session waits for a provider: commit the active member's open group if it has been open for
    /// `group_commit_interval`, so a stalled source does not keep written output uncommitted.
    pub(super) fn partial_wait(&self) -> ProgressiveResult<()> {
        if let Some(persistent) = &self.partial
            && let Some(index) = persistent.current
        {
            persistent.cores[index]
                .core
                .as_ref()
                .expect("the active member's core is held")
                .commit_due()
                .map_err(failure)?;
        }
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
        // A part an earlier session recorded (of an adopted member) must be the same part; it is not recorded again.
        if persistent.active().1.recorded_part(&plain, &witness).map_err(failure)? {
            return Ok(());
        }
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
        let core = cores[current.expect("persistent member")].core.as_ref().expect("the active member's core is held");
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
        // A part an adopted member skipped has no machine: it was checked when an earlier session produced it.
        if part.final_part
            || self.model.members.last().unwrap().header.encrypted
            || self.machine.as_ref().is_none_or(MemberMachine::part_missing)
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
        let core = cores[current.expect("persistent member")].core.as_ref().expect("the active member's core is held");
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
        // A member adopted already finished is reported as it stands, without writing anything.
        let adopted_finished = persistent.resume.as_ref().is_some_and(|resume| resume.finished);
        if !adopted_finished {
            core.compact().map_err(failure)?;
        }
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
        let slot = &mut persistent.cores[persistent.current.take().expect("persistent member")];
        slot.finished = true;
        slot.release_if_done();
        persistent.unavailable.clear();
        persistent.resume = None;
        self.phase = Phase::Header;
        Ok(Poll::Ready(Ok(Some(ProgressiveEvent::MemberFinished { member: self.member.take().unwrap(), outcome }))))
    }
}
/// Why a persistent session refuses the member `header` starts, if it does. Directory entries are not refused
/// (they create their directory), except a compressed RAR4 one, which the RAR4 path does not read.
pub(super) fn refusal(header: &crate::rar5::FileHeader) -> Option<RefusalReason> {
    let rar4 = header.format == crate::rar5::RarFormat::Rar4;
    if header.redirection.is_some() || header.is_rar4_symlink() {
        Some(RefusalReason::Redirection)
    } else if header.encrypted && crate::partial::member_crypt(header).is_none() {
        // Encrypted stored members are admitted (their password is in the session options): RAR5 ones, and RAR4
        // ones with RAR 3.x AES and a salt. Older RAR4 ciphers are not.
        Some(RefusalReason::Encrypted)
    } else if header.is_dir() && !(rar4 && header.method != 0) {
        None
    } else if header.method != 0 {
        Some(RefusalReason::Compressed { method: header.method })
    } else if header.size_unknown() || (rar4 && matches!(header.unpacked_size, u64::MAX | 0xffff_ffff)) {
        // RAR4 has no unknown-size flag: the progressive RAR4 path reads an all-ones size as unknown.
        Some(RefusalReason::UnknownSize)
    } else {
        None
    }
}
/// Admits and reserves room for `count` more identities in the session's created-directory list.
fn reserve_created(
    created: &mut Vec<crate::progressive::native::Identity>,
    count: usize,
    usage: &Usage,
) -> ProgressiveResult<()> {
    let spare = created.capacity() - created.len();
    if count > spare {
        usage.charge(
            Resource::MetadataBytes,
            ((count - spare) * std::mem::size_of::<crate::progressive::native::Identity>()) as u64,
        )?;
        created.try_reserve_exact(count - spare).map_err(|_| error(PartialErrorKind::StateMalformed))?;
    }
    Ok(())
}
/// Adds the identity of `path` (when it exists, through any links) and of each of its existing ancestors.
fn ancestor_identities(
    path: &std::path::Path,
    out: &mut Vec<crate::progressive::native::Identity>,
    usage: &Usage,
) -> ProgressiveResult<()> {
    let Ok(path) = std::path::absolute(path) else { return Ok(()) };
    for at in path.ancestors() {
        usage.charge(Resource::SourceBookkeeping, 1 + out.len() as u64)?;
        if let Ok(identity) =
            std::fs::metadata(at).and_then(|meta| crate::progressive::native::Identity::metadata(&meta))
            && !out.contains(&identity)
        {
            usage.charge(Resource::MetadataBytes, std::mem::size_of_val(&identity) as u64)?;
            out.try_reserve(1).map_err(|_| error(PartialErrorKind::StateMalformed))?;
            out.push(identity);
        }
    }
    Ok(())
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
