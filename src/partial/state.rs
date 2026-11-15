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

//! Bounded canonical manifest and page codec. Checksums are hints, never authority.
use super::*;
use super::{
    limits::PartialBudget,
    native::{NativeBinding, bundle_name, hex},
};
use crate::progressive::{SourceId, SourceInfo, SourceLength, native::Identity};
use std::{
    ffi::OsString,
    ops::Range,
    path::{Path, PathBuf},
    sync::Arc,
};
const MAGIC: &[u8; 8] = b"ZFPART1\0";
pub(super) const PAGE_MAX: usize = 1_048_576;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PageKind {
    Geometry = 1,
    Validity = 2,
    HeaderWitnesses = 3,
}
#[derive(Clone)]
pub(crate) struct PageRef {
    pub kind: PageKind,
    pub digest: [u8; 32],
    pub len: u32,
}
#[derive(Clone)]
pub(crate) struct CommittedState {
    pub member: MemberKey,
    pub sequence: u64,
    pub revision: u64,
    pub relative_output: PathBuf,
    pub size: u64,
    pub produced: u64,
    pub member_finished: bool,
    pub checks: MemberChecks,
    pub binding: NativeBinding,
    pub pages: Vec<PageRef>,
    pub metadata: crate::extract::Meta,
    pub cursor: Option<CursorRef>,
}
// R1 reserves this layout; H2 emits only None and rejects cursor-bearing heads.
#[expect(dead_code, reason = "reserved cursor fields belong to R1; H2 rejects cursor state")]
#[derive(Clone)]
pub(crate) struct CursorRef {
    pub version: u16,
    pub digest: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Provenance {
    Original = 1,
    Alt = 2,
}
#[derive(Clone)]
pub(super) struct KnownLeaf {
    pub range: Range<u64>,
    pub crc: u32,
    pub hasher: crate::crc32::Hasher,
    pub provenance: Provenance,
    pub _lease: Arc<super::limits::Reservation>,
}
/// Ciphertext of one 16-byte CBC block of an encrypted member, kept because a hole next to it needs it to decrypt
/// later archive bytes. `offset` is the block's offset in the member's ciphertext stream (a multiple of 16) and
/// `have` the bytes of the block that are known; a whole block has `0..16`. Never key material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CipherBlock {
    pub offset: u64,
    pub have: Range<u8>,
    pub bytes: [u8; 16],
}
impl CipherBlock {
    pub fn whole(&self) -> bool {
        self.have == (0..16)
    }
}
#[derive(Clone)]
pub(super) struct Snapshot {
    pub head: CommittedState,
    pub name: Arc<[u8]>,
    pub evidence: InitialEvidence,
    pub known: Vec<KnownLeaf>,
    pub holes: Vec<HoleReport>,
    /// Encryption parameters parsed from the member's header witnesses; `None` for a plain member. Derived from the
    /// evidence on every load, never encoded separately.
    pub crypt: Option<crate::crypto::Rar5CryptParams>,
    /// Ciphertext blocks next to holes of an encrypted member, sorted by offset.
    pub cipher: Vec<CipherBlock>,
}
pub(crate) struct MutationIntent {
    pub transaction: u64,
    pub parent: Option<StateAnchor>,
    pub conservative: CommittedState,
    pub affected: Vec<Range<u64>>,
}
pub(crate) struct MutationCommit {
    pub transaction: u64,
    pub parent: StateAnchor,
    pub valid: CommittedState,
}
#[derive(Clone, Debug)]
pub struct PartialState {
    pub(super) wire: Vec<u8>,
    pub(super) member: MemberKey,
    pub(super) anchor: StateAnchor,
}
impl PartialState {
    pub fn member(&self) -> &MemberKey {
        &self.member
    }
    pub fn anchor(&self) -> &StateAnchor {
        &self.anchor
    }
    pub(super) fn parse(wire: Vec<u8>, limits: &PartialLimits) -> PartialResult<Self> {
        limits.check(PartialResource::StateWire, wire.len() as u64)?;
        let (_, _, _, head) = decode_record(&wire, limits)?;
        let anchor = StateAnchor::new(head.member.clone(), head.sequence, crate::crypto::sha256(&wire));
        Ok(Self { wire, member: head.member, anchor })
    }
    /// Reads exactly the independently selected anchored head, never a newer tail.
    pub fn load(state_root: &Path, anchor: &StateAnchor, limits: &PartialLimits) -> PartialResult<Self> {
        limits.validate()?;
        let usage = crate::progressive::Usage::new(crate::progressive::ProgressiveLimits::default());
        let budget = PartialBudget::new(limits.clone(), usage.clone(), Arc::new(PartialExclusions::new(usage)))?;
        Self::load_budgeted(state_root, anchor, &budget)
    }
    pub(super) fn load_budgeted(
        state_root: &Path,
        anchor: &StateAnchor,
        budget: &PartialBudget,
    ) -> PartialResult<Self> {
        super::native::platform()?;
        let limits = &budget.limits;
        let path = state_root.join(bundle_name(anchor.member()));
        let _fd = budget.reserve(PartialResource::OpenFiles, 1)?;
        let dir = crate::progressive::guard::open_directory(&path).map_err(|failure| {
            if matches!(&failure.kind,crate::progressive::FailureKind::Output {cause,..} if cause.kind()==std::io::ErrorKind::NotFound) {err(PartialErrorKind::StateUnavailable)} else {failure.into()}
        })?;
        let f =
            super::native::open_at(&dir, std::ffi::OsStr::new(&format!("r-{}", hex(anchor.digest()))), false, budget)
                .map_err(|e| match e.kind {
                PartialErrorKind::Io { ref cause, .. } if cause.kind() == std::io::ErrorKind::NotFound => {
                    err(PartialErrorKind::StateUnavailable)
                }
                _ => e,
            })?;
        let bytes = read_bounded(&f.file, limits.state_wire_bytes as usize, budget)?;
        let state = Self::parse(bytes, limits)?;
        if state.anchor() != anchor {
            return Err(err(PartialErrorKind::BindingMismatch(BindingField::Anchor)));
        }
        Ok(state)
    }
}
pub(super) fn read_bounded(file: &std::fs::File, max: usize, budget: &PartialBudget) -> PartialResult<Vec<u8>> {
    let len = file.metadata().map_err(|e| io_error(crate::progressive::OutputOperation::Metadata, e))?.len();
    if len > max as u64 {
        return Err(limit(PartialResource::StateWire, max as u64, len));
    }
    let mut bytes = budget.vector(len as usize)?;
    bytes.resize(len as usize, 0);
    let mut at = 0;
    while at < bytes.len() {
        let n = crate::output::range::read_at(file, at as u64, &mut bytes[at..])
            .map_err(|e| io_error(crate::progressive::OutputOperation::Read, e))?;
        if n == 0 {
            return Err(err(PartialErrorKind::StateUnavailable));
        }
        at += n;
    }
    if file.metadata().map_err(|e| io_error(crate::progressive::OutputOperation::Metadata, e))?.len() != len {
        return Err(err(PartialErrorKind::JournalCorrupt));
    }
    Ok(bytes)
}
struct Encoder {
    bytes: Vec<u8>,
    max: usize,
    usage: Option<crate::progressive::Usage>,
}
impl Encoder {
    fn new(max: usize) -> Self {
        Self { bytes: Vec::new(), max, usage: None }
    }
    fn budgeted(max: usize, budget: &PartialBudget) -> Self {
        Self { bytes: Vec::new(), max, usage: Some(budget.usage.clone()) }
    }
    fn raw(&mut self, b: &[u8]) -> PartialResult<()> {
        let n = self.bytes.len().checked_add(b.len()).ok_or_else(malformed)?;
        if n > self.max {
            return Err(limit(PartialResource::StateWire, self.max as u64, n as u64));
        }
        if self.bytes.capacity() < n {
            let capacity = self.bytes.capacity().saturating_mul(2).max(n).min(self.max);
            if let Some(usage) = &self.usage {
                usage.charge(crate::progressive::Resource::MetadataBytes, (capacity - self.bytes.capacity()) as u64)?;
                usage.charge(crate::progressive::Resource::SourceBookkeeping, self.bytes.len() as u64)?;
            }
            self.bytes.try_reserve_exact(capacity - self.bytes.len()).map_err(|_| malformed())?;
        }
        self.bytes.extend_from_slice(b);
        Ok(())
    }
    fn u8(&mut self, v: u8) -> PartialResult<()> {
        self.raw(&[v])
    }
    fn u16(&mut self, v: u16) -> PartialResult<()> {
        self.raw(&v.to_le_bytes())
    }
    fn u32(&mut self, v: u32) -> PartialResult<()> {
        self.raw(&v.to_le_bytes())
    }
    fn u64(&mut self, v: u64) -> PartialResult<()> {
        self.raw(&v.to_le_bytes())
    }
    fn blob(&mut self, b: &[u8]) -> PartialResult<()> {
        self.u32(b.len().try_into().map_err(|_| malformed())?)?;
        self.raw(b)
    }
    fn range(&mut self, r: &Range<u64>) -> PartialResult<()> {
        self.u64(r.start)?;
        self.u64(r.end)
    }
    fn option32(&mut self, v: Option<u32>) -> PartialResult<()> {
        self.u8(v.is_some() as u8)?;
        if let Some(v) = v {
            self.u32(v)?;
        }
        Ok(())
    }
    fn hash(&mut self, v: Option<[u8; 32]>) -> PartialResult<()> {
        self.u8(v.is_some() as u8)?;
        if let Some(v) = v {
            self.raw(&v)?;
        }
        Ok(())
    }
    fn member(&mut self, m: &MemberKey) -> PartialResult<()> {
        self.raw(&m.binding.job)?;
        self.raw(&m.binding.archive)?;
        self.u64(m.ordinal)?;
        self.raw(&m.identity)
    }
}
struct Decoder<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }
    fn take(&mut self, n: usize) -> PartialResult<&'a [u8]> {
        let end = self.at.checked_add(n).ok_or_else(malformed)?;
        let b = self.bytes.get(self.at..end).ok_or_else(malformed)?;
        self.at = end;
        Ok(b)
    }
    fn u8(&mut self) -> PartialResult<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> PartialResult<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> PartialResult<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> PartialResult<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn bool(&mut self) -> PartialResult<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(malformed()),
        }
    }
    fn count(&mut self, max: usize, min: usize) -> PartialResult<usize> {
        let n = self.u32()? as usize;
        if n > max || n.checked_mul(min).is_none_or(|v| v > self.bytes.len() - self.at) {
            return Err(malformed());
        }
        Ok(n)
    }
    fn blob(&mut self, max: usize) -> PartialResult<&'a [u8]> {
        let n = self.count(max, 1)?;
        self.take(n)
    }
    fn range(&mut self) -> PartialResult<Range<u64>> {
        let start = self.u64()?;
        let end = self.u64()?;
        if start > end {
            return Err(malformed());
        }
        Ok(start..end)
    }
    fn option32(&mut self) -> PartialResult<Option<u32>> {
        if self.bool()? { Ok(Some(self.u32()?)) } else { Ok(None) }
    }
    fn hash(&mut self) -> PartialResult<Option<[u8; 32]>> {
        if self.bool()? { Ok(Some(self.take(32)?.try_into().unwrap())) } else { Ok(None) }
    }
    fn member(&mut self) -> PartialResult<MemberKey> {
        Ok(MemberKey::new(
            ArchiveBinding { job: self.take(16)?.try_into().unwrap(), archive: self.take(32)?.try_into().unwrap() },
            self.u64()?,
            self.take(32)?.try_into().unwrap(),
        ))
    }
    fn end(&self) -> PartialResult<()> {
        if self.at == self.bytes.len() { Ok(()) } else { Err(malformed()) }
    }
}
fn os_bytes(value: &std::ffi::OsStr) -> &[u8] {
    value.as_encoded_bytes()
}
fn os_decode(bytes: &[u8]) -> PartialResult<OsString> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        Ok(OsString::from_vec(bytes.to_vec()))
    }
    #[cfg(not(unix))]
    {
        let _ = bytes;
        Err(err(PartialErrorKind::UnsupportedPlatform))
    }
}
pub(super) fn encode_record(
    kind: u8,
    transaction: u64,
    parent: Option<&StateAnchor>,
    head: &CommittedState,
    limits: &PartialLimits,
) -> PartialResult<PartialState> {
    if head.cursor.is_some() {
        return Err(err(PartialErrorKind::StateVersion));
    }
    let mut p = Encoder::new(limits.state_wire_bytes as usize);
    p.member(&head.member)?;
    p.u64(head.revision)?;
    p.blob(os_bytes(head.relative_output.as_os_str()))?;
    p.u64(head.size)?;
    p.u64(head.produced)?;
    p.u8(head.member_finished as u8)?;
    p.option32(head.checks.crc32)?;
    p.hash(head.checks.blake2sp)?;
    for id in [head.binding.root, head.binding.parent, head.binding.output, head.binding.bundle] {
        p.u64(id.0)?;
        p.u64(id.1)?;
    }
    p.u8(head.metadata.mtime.is_some() as u8)?;
    if let Some(t) = head.metadata.mtime {
        p.u64(t as u64)?;
    }
    p.u32(head.metadata.nanos)?;
    p.option32(head.metadata.mode)?;
    p.u8(0)?;
    p.u32(head.pages.len().try_into().map_err(|_| malformed())?)?;
    for page in &head.pages {
        p.u8(page.kind as u8)?;
        p.raw(&page.digest)?;
        p.u32(page.len)?;
    }
    let mut e = Encoder::new(limits.state_wire_bytes as usize);
    e.raw(MAGIC)?;
    e.u16(1)?;
    e.u8(kind)?;
    e.u64(head.sequence)?;
    e.u64(transaction)?;
    e.raw(parent.map(|a| a.digest()).unwrap_or(&[0; 32]))?;
    e.blob(&p.bytes)?;
    let crc = crc32fast::hash(&e.bytes);
    e.u32(crc)?;
    PartialState::parse(e.bytes, limits)
}
pub(super) fn decode_record(
    bytes: &[u8],
    limits: &PartialLimits,
) -> PartialResult<(u8, u64, [u8; 32], CommittedState)> {
    limits.check(PartialResource::StateWire, bytes.len() as u64)?;
    if bytes.len() < 4 {
        return Err(malformed());
    }
    let split = bytes.len() - 4;
    if crc32fast::hash(&bytes[..split]) != u32::from_le_bytes(bytes[split..].try_into().unwrap()) {
        return Err(err(PartialErrorKind::JournalCorrupt));
    }
    let mut d = Decoder::new(&bytes[..split]);
    if d.take(8)? != MAGIC {
        return Err(malformed());
    }
    if d.u16()? != 1 {
        return Err(err(PartialErrorKind::StateVersion));
    }
    let kind = d.u8()?;
    if !(1..=4).contains(&kind) {
        return Err(malformed());
    }
    let sequence = d.u64()?;
    let transaction = d.u64()?;
    let previous = d.take(32)?.try_into().unwrap();
    let payload = d.blob(limits.state_wire_bytes as usize)?;
    d.end()?;
    let mut d = Decoder::new(payload);
    let member = d.member()?;
    let revision = d.u64()?;
    let relative_output = PathBuf::from(os_decode(d.blob(limits.state_wire_bytes as usize)?)?);
    super::native::validate_relative(&relative_output)?;
    let size = d.u64()?;
    let produced = d.u64()?;
    if produced > size {
        return Err(malformed());
    }
    let member_finished = d.bool()?;
    let checks = MemberChecks { size, crc32: d.option32()?, blake2sp: d.hash()? };
    let mut ids = [Identity(0, 0); 4];
    for id in &mut ids {
        *id = Identity(d.u64()?, d.u64()?);
    }
    let mtime = if d.bool()? { Some(d.u64()? as i64) } else { None };
    let nanos = d.u32()?;
    if nanos >= 1_000_000_000 {
        return Err(malformed());
    }
    let mode = d.option32()?;
    if d.u8()? != 0 {
        return Err(err(PartialErrorKind::StateVersion));
    }
    let count = d.count(limits.state_pages as usize, 37)?;
    let mut pages = Vec::new();
    pages.try_reserve_exact(count).map_err(|_| malformed())?;
    for _ in 0..count {
        let kind = match d.u8()? {
            1 => PageKind::Geometry,
            2 => PageKind::Validity,
            3 => PageKind::HeaderWitnesses,
            _ => return Err(malformed()),
        };
        let digest = d.take(32)?.try_into().unwrap();
        let len = d.u32()?;
        if len as usize > PAGE_MAX || len < 15 {
            return Err(malformed());
        }
        pages.push(PageRef { kind, digest, len });
    }
    d.end()?;
    Ok((
        kind,
        transaction,
        previous,
        CommittedState {
            member,
            sequence,
            revision,
            relative_output,
            size,
            produced,
            member_finished,
            checks,
            binding: NativeBinding { root: ids[0], parent: ids[1], output: ids[2], bundle: ids[3] },
            pages,
            metadata: crate::extract::Meta { mtime, nanos, mode },
            cursor: None,
        },
    ))
}
pub(super) fn page_bytes(kind: PageKind, payload: &[u8]) -> PartialResult<Vec<u8>> {
    let mut e = Encoder::new(PAGE_MAX);
    e.raw(MAGIC)?;
    e.u16(1)?;
    e.u8(kind as u8)?;
    e.blob(payload)?;
    Ok(e.bytes)
}
pub(super) fn page_payload(kind: PageKind, bytes: &[u8]) -> PartialResult<&[u8]> {
    let mut d = Decoder::new(bytes);
    if d.take(8)? != MAGIC || d.u16()? != 1 || d.u8()? != kind as u8 {
        return Err(malformed());
    }
    let b = d.blob(PAGE_MAX)?;
    d.end()?;
    Ok(b)
}
pub(super) fn encode_pages(snapshot: &Snapshot, budget: &PartialBudget) -> PartialResult<Vec<(PageKind, Vec<u8>)>> {
    let mut geometry = Encoder::budgeted(budget.limits.ledger_bytes as usize, budget);
    geometry.blob(&snapshot.name)?;
    geometry.u32(snapshot.evidence.parts.len().try_into().map_err(|_| malformed())?)?;
    for p in &snapshot.evidence.parts {
        geometry.u64(p.ordinal)?;
        geometry.u32(p.packed.volume)?;
        geometry.range(&p.packed.range)?;
        geometry.range(&p.out)?;
        geometry.u8(p.final_part as u8)?;
        geometry.option32(p.crc32)?;
        geometry.hash(p.blake2sp)?;
    }
    geometry.u32(snapshot.evidence.admissions.len().try_into().map_err(|_| malformed())?)?;
    for a in &snapshot.evidence.admissions {
        geometry.u32(a.volume)?;
        geometry.raw(&a.info.id.0.to_le_bytes())?;
        geometry.u64(a.info.generation)?;
        geometry.u64(a.info.extent)?;
        geometry.u8(matches!(a.info.length, SourceLength::Final(_)) as u8)?;
        geometry.u64(a.info.length.value())?;
        geometry.blob(os_bytes(&a.expected))?;
    }
    let mut extent_count = snapshot.known.len() as u64;
    let mut end = 0;
    for leaf in &snapshot.known {
        if leaf.range.start < end
            || leaf.range.end > snapshot.head.size
            || leaf.range.is_empty()
            || leaf.range.end - leaf.range.start > 65_536
        {
            return Err(malformed());
        }
        extent_count = extent_count.checked_add((leaf.range.start - end).div_ceil(65_536)).ok_or_else(malformed)?;
        end = leaf.range.end;
    }
    extent_count = extent_count.checked_add((snapshot.head.size - end).div_ceil(65_536)).ok_or_else(malformed)?;
    budget.limits.check(
        PartialResource::LedgerBytes,
        extent_count.checked_mul(21).and_then(|n| n.checked_add(8)).ok_or_else(malformed)?,
    )?;
    let mut validity = Encoder::budgeted(budget.limits.ledger_bytes as usize, budget);
    validity.u32(extent_count.try_into().map_err(|_| malformed())?)?;
    let mut end = 0;
    for leaf in &snapshot.known {
        while end < leaf.range.start {
            let stop = end.saturating_add(65_536).min(leaf.range.start);
            validity.range(&(end..stop))?;
            validity.u8(0)?;
            validity.u32(0)?;
            end = stop;
        }
        validity.range(&leaf.range)?;
        validity.u8(leaf.provenance as u8)?;
        validity.u32(leaf.crc)?;
        end = leaf.range.end;
    }
    while end < snapshot.head.size {
        let stop = end.saturating_add(65_536).min(snapshot.head.size);
        validity.range(&(end..stop))?;
        validity.u8(0)?;
        validity.u32(0)?;
        end = stop;
    }
    validity.u32(snapshot.holes.len().try_into().map_err(|_| malformed())?)?;
    for h in &snapshot.holes {
        validity.u64(h.id)?;
        validity.u64(h.revision)?;
        validity.range(&h.out)?;
        validity.u32(h.packed.len().try_into().map_err(|_| malformed())?)?;
        for p in &h.packed {
            validity.u32(p.volume)?;
            validity.range(&p.range)?;
        }
    }
    // Trailing cause section, written only when some hole is not Missing so that states without declared
    // damage stay readable by builds that predate it. States without it decode every hole as Missing. The
    // ciphertext block section follows it, so it forces the cause section.
    let causes = snapshot.holes.iter().any(|h| h.cause != HoleCause::Missing) || !snapshot.cipher.is_empty();
    for h in snapshot.holes.iter().filter(|_| causes) {
        validity.u8(match h.cause {
            HoleCause::Missing => 0,
            HoleCause::DeclaredBad => 1,
            HoleCause::CipherNeighbour => 2,
            HoleCause::HeaderLost => 3,
        })?;
    }
    // Versioned ciphertext block section of encrypted members, written only when some block is kept.
    if !snapshot.cipher.is_empty() {
        validity.u8(1)?;
        validity.u32(snapshot.cipher.len().try_into().map_err(|_| malformed())?)?;
        for block in &snapshot.cipher {
            validity.u64(block.offset)?;
            validity.u8(block.have.start)?;
            validity.u8(block.have.end)?;
            validity.raw(&block.bytes)?;
        }
    }
    let mut headers = Encoder::budgeted(budget.limits.ledger_bytes as usize, budget);
    headers.u32(snapshot.evidence.headers.len().try_into().map_err(|_| malformed())?)?;
    for h in &snapshot.evidence.headers {
        headers.u32(h.volume)?;
        headers.range(&h.packed)?;
        headers.blob(&h.bytes)?;
    }
    let total = geometry
        .bytes
        .len()
        .checked_add(validity.bytes.len())
        .and_then(|n| n.checked_add(headers.bytes.len()))
        .ok_or_else(malformed)?;
    budget.limits.check(PartialResource::LedgerBytes, total as u64)?;
    budget.metadata(total as u64)?;
    let mut out = Vec::new();
    for (kind, bytes) in [
        (PageKind::Geometry, geometry.bytes),
        (PageKind::Validity, validity.bytes),
        (PageKind::HeaderWitnesses, headers.bytes),
    ] {
        for chunk in bytes.chunks(PAGE_MAX - 15) {
            budget.limits.check(PartialResource::StatePages, (out.len() + 1) as u64)?;
            out.push((kind, page_bytes(kind, chunk)?));
        }
    }
    Ok(out)
}
pub(super) fn decode_pages(
    head: CommittedState,
    pages: Vec<(PageKind, Vec<u8>)>,
    budget: &PartialBudget,
    reusable: &[KnownLeaf],
) -> PartialResult<Snapshot> {
    let mut buffers: [Vec<u8>; 3] = [Vec::new(), Vec::new(), Vec::new()];
    let mut total = 0usize;
    let mut last = 0;
    for (kind, bytes) in pages {
        let index = kind as usize;
        if index < last {
            return Err(malformed());
        }
        last = index;
        let b = page_payload(kind, &bytes)?;
        total = total.checked_add(b.len()).ok_or_else(malformed)?;
        budget.limits.check(PartialResource::LedgerBytes, total as u64)?;
        budget.metadata(b.len() as u64)?;
        buffers[index - 1].try_reserve_exact(b.len()).map_err(|_| malformed())?;
        buffers[index - 1].extend_from_slice(b);
    }
    let mut d = Decoder::new(&buffers[0]);
    let raw_name = d.blob(budget.limits.ledger_bytes as usize)?;
    budget.metadata(raw_name.len() as u64)?;
    budget.usage.charge(crate::progressive::Resource::NameBytes, raw_name.len() as u64)?;
    let name: Arc<[u8]> = Arc::from(raw_name);
    let count = d.count(usize::MAX, 47)?;
    budget.usage.check(crate::progressive::Resource::Parts, count as u64)?;
    let mut parts = budget.vector(count)?;
    for _ in 0..count {
        parts.push(PlainPart {
            ordinal: d.u64()?,
            packed: PackedSpan { volume: d.u32()?, range: d.range()? },
            out: d.range()?,
            final_part: d.bool()?,
            crc32: d.option32()?,
            blake2sp: d.hash()?,
        });
    }
    let count = d.count(usize::MAX, 45)?;
    let mut admissions = budget.vector(count)?;
    for _ in 0..count {
        let volume = d.u32()?;
        let id = SourceId(u128::from_le_bytes(d.take(16)?.try_into().unwrap()));
        let generation = d.u64()?;
        let extent = d.u64()?;
        let final_length = d.bool()?;
        let length = d.u64()?;
        let raw_expected = d.blob(budget.limits.ledger_bytes as usize)?;
        budget.metadata(raw_expected.len() as u64)?;
        let expected = os_decode(raw_expected)?;
        admissions.push(SourceAdmission {
            volume,
            info: SourceInfo {
                id,
                generation,
                extent,
                length: if final_length { SourceLength::Final(length) } else { SourceLength::Advertised(length) },
            },
            expected,
        });
    }
    d.end()?;
    let mut d = Decoder::new(&buffers[1]);
    let count = d.count(usize::MAX, 21)?;
    let mut known = Vec::new();
    let mut end = 0;
    for _ in 0..count {
        let range = d.range()?;
        let tag = d.u8()?;
        let crc = d.u32()?;
        if range.start != end || range.end > head.size || range.is_empty() || range.end - range.start > 65_536 {
            return Err(malformed());
        }
        end = range.end;
        let provenance = match tag {
            0 => {
                if crc != 0 {
                    return Err(malformed());
                }
                continue;
            }
            1 => Provenance::Original,
            2 => Provenance::Alt,
            _ => return Err(malformed()),
        };
        budget.limits.check(PartialResource::CrcLeaves, (known.len() + 1) as u64)?;
        if known.len() == known.capacity() {
            let capacity = known.len().saturating_mul(2).max(1).min(budget.limits.crc_leaves as usize);
            budget.metadata(((capacity - known.capacity()) * std::mem::size_of::<KnownLeaf>()) as u64)?;
            known.try_reserve_exact(capacity - known.len()).map_err(|_| malformed())?;
        }
        // Immutable matching records share one logical lease; old state stays intact on failure.
        let existing = reusable
            .binary_search_by_key(&range.start, |leaf| leaf.range.start)
            .ok()
            .map(|index| &reusable[index])
            .filter(|leaf| leaf.range == range && leaf.crc == crc && leaf.provenance == provenance);
        let lease = match existing {
            Some(leaf) => leaf._lease.clone(),
            None => Arc::new(budget.reserve(PartialResource::CrcLeaves, 1)?),
        };
        known.push(KnownLeaf { range, crc, hasher: crate::crc32::Hasher::new(), provenance, _lease: lease });
    }
    if end != head.size {
        return Err(malformed());
    }
    let count = d.count(budget.limits.journal_records as usize, 36)?;
    budget.usage.check(crate::progressive::Resource::HoleIntervals, count as u64)?;
    let mut holes = budget.vector(count)?;
    for _ in 0..count {
        let id = d.u64()?;
        let revision = d.u64()?;
        let out = d.range()?;
        if out.end > head.size {
            return Err(malformed());
        }
        let n = d.count(usize::MAX, 20)?;
        let mut packed = budget.vector(n)?;
        for _ in 0..n {
            packed.push(PackedSpan { volume: d.u32()?, range: d.range()? });
        }
        holes.push(HoleReport {
            id,
            revision,
            member: head.member.clone(),
            name: name.clone(),
            out,
            packed,
            cause: HoleCause::Missing,
        });
    }
    if d.at < d.bytes.len() {
        for hole in &mut holes {
            hole.cause = match d.u8()? {
                0 => HoleCause::Missing,
                1 => HoleCause::DeclaredBad,
                2 => HoleCause::CipherNeighbour,
                3 => HoleCause::HeaderLost,
                _ => return Err(malformed()),
            };
        }
    }
    let mut cipher = Vec::new();
    if d.at < d.bytes.len() {
        if d.u8()? != 1 {
            return Err(err(PartialErrorKind::StateVersion));
        }
        let count = d.count(budget.limits.journal_records as usize, 26)?;
        budget.usage.check(crate::progressive::Resource::HoleIntervals, count as u64)?;
        budget.metadata((count * std::mem::size_of::<CipherBlock>()) as u64)?;
        cipher = budget.vector(count)?;
        for _ in 0..count {
            let offset = d.u64()?;
            let have = d.u8()?..d.u8()?;
            let bytes: [u8; 16] = d.take(16)?.try_into().unwrap();
            if offset % 16 != 0
                || have.start >= have.end
                || have.end > 16
                || cipher.last().is_some_and(|last: &CipherBlock| last.offset >= offset)
            {
                return Err(malformed());
            }
            cipher.push(CipherBlock { offset, have, bytes });
        }
    }
    d.end()?;
    let mut d = Decoder::new(&buffers[2]);
    let count = d.count(usize::MAX, 24)?;
    let mut headers = budget.vector(count)?;
    for _ in 0..count {
        let volume = d.u32()?;
        let packed = d.range()?;
        let raw = d.blob(budget.limits.ledger_bytes as usize)?;
        budget.metadata(raw.len() as u64)?;
        let bytes = raw.to_vec();
        if packed.end - packed.start != bytes.len() as u64 {
            return Err(malformed());
        }
        headers.push(HeaderWitness { volume, packed, bytes });
    }
    d.end()?;
    let evidence = InitialEvidence { metadata: head.metadata, parts, admissions, headers };
    let mut snapshot = Snapshot { head, name, evidence, known, holes, crypt: None, cipher };
    snapshot.crypt = validate_evidence(&snapshot.name, snapshot.head.size, &snapshot.evidence, budget)?;
    if !snapshot.cipher.is_empty() && snapshot.crypt.is_none() {
        return Err(malformed());
    }
    Ok(snapshot)
}
/// Checks every part against its header witness and returns the member's encryption parameters (`None` when the
/// member is plain). Plain parts map packed bytes one to one onto output. Encrypted parts form one continuous CBC
/// ciphertext stream: stream offset `c` is output offset `c`, clipped at the unpacked size, and the final padding
/// maps to no output.
pub(super) fn validate_evidence(
    name: &[u8],
    size: u64,
    evidence: &InitialEvidence,
    budget: &PartialBudget,
) -> PartialResult<Option<crate::crypto::Rar5CryptParams>> {
    use crate::rar5::{
        framing::{HeaderParser, ParserStep},
        reader::Block,
    };
    if evidence.parts.is_empty() || evidence.headers.is_empty() || evidence.admissions.is_empty() {
        return Err(malformed());
    }
    budget.usage.check(crate::progressive::Resource::Parts, evidence.parts.len() as u64)?;
    let mut end = 0;
    let mut stream = 0u64;
    let mut crypt = None;
    for (index, part) in evidence.parts.iter().enumerate() {
        let packed = part.packed.range.end.checked_sub(part.packed.range.start).ok_or_else(malformed)?;
        let stream_end = stream.checked_add(packed).ok_or_else(malformed)?;
        if part.ordinal != index as u64 || part.out.start != end || part.out.end > size {
            return Err(malformed());
        }
        end = part.out.end;
        let admission = evidence.admissions.iter().find(|a| a.volume == part.packed.volume).ok_or_else(malformed)?;
        if admission.info.extent > admission.info.length.value()
            || part.packed.range.end > admission.info.length.value()
        {
            return Err(malformed());
        }
        let witness = evidence
            .headers
            .iter()
            .find(|h| h.volume == part.packed.volume && h.packed.end == part.packed.range.start)
            .ok_or_else(malformed)?;
        if witness.packed.end.checked_sub(witness.packed.start) != Some(witness.bytes.len() as u64) {
            return Err(malformed());
        }
        let mut parser =
            HeaderParser::progressive(PathBuf::from(&admission.expected), witness.packed.start, budget.usage.clone());
        let mut step = parser.advance(&[])?.1;
        let frame = loop {
            match step {
                ParserStep::Need { offset, len } => {
                    let at = offset.checked_sub(witness.packed.start).ok_or_else(malformed)? as usize;
                    let bytes =
                        witness.bytes.get(at..at.checked_add(len).ok_or_else(malformed)?).ok_or_else(malformed)?;
                    step = parser.advance(bytes)?.1;
                }
                ParserStep::Frame(frame) => break frame,
                _ => return Err(malformed()),
            }
        };
        let Block::File(header) = frame.block else { return Err(malformed()) };
        if index == 0 {
            let actual = crate::extract::Meta::from(&header);
            if actual.mtime != evidence.metadata.mtime
                || actual.nanos != evidence.metadata.nanos
                || actual.mode != evidence.metadata.mode
            {
                return Err(err(PartialErrorKind::BindingMismatch(BindingField::Member)));
            }
        }
        if header.format != crate::rar5::RarFormat::Rar5 {
            return Err(err(PartialErrorKind::UnsupportedFormat));
        }
        if header.method != 0 || header.is_dir() || header.redirection.is_some() {
            return Err(err(PartialErrorKind::UnsupportedMethod));
        }
        let params = if header.encrypted {
            Some(header.crypt.ok_or_else(|| err(PartialErrorKind::UnsupportedMethod))?)
        } else {
            None
        };
        if index == 0 {
            crypt = params;
        } else if params != crypt {
            return Err(err(PartialErrorKind::BindingMismatch(BindingField::Member)));
        }
        let padded = size.checked_next_multiple_of(16).ok_or_else(malformed)?;
        let geometry = if crypt.is_some() {
            part.out == (stream.min(size)..stream_end.min(size))
                && stream_end <= padded
                && (!part.final_part || stream_end == padded)
        } else {
            part.out == (stream..stream_end)
        };
        if !geometry {
            return Err(malformed());
        }
        stream = stream_end;
        if header.name.as_bytes() != name
            || header.size_unknown()
            || header.unpacked_size != size
            || header.data_at != part.packed.range.start
            || header.packed_size != part.packed.range.end - part.packed.range.start
            || header.crc32 != part.crc32
            || header.blake2sp != part.blake2sp
            || header.split_after() == part.final_part
        {
            return Err(err(PartialErrorKind::BindingMismatch(BindingField::Member)));
        }
    }
    Ok(crypt)
}

impl serde::Serialize for PartialState {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.wire)
    }
}
impl<'de> serde::Deserialize<'de> for PartialState {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ManifestVisitor;
        impl<'de> serde::de::Visitor<'de> for ManifestVisitor {
            type Value = PartialState;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a canonical partial manifest bounded to 65536 bytes")
            }
            fn visit_bytes<E: serde::de::Error>(self, bytes: &[u8]) -> Result<PartialState, E> {
                if bytes.len() > 65_536 {
                    return Err(E::custom("partial state byte limit exceeded"));
                }
                let mut wire = Vec::new();
                wire.try_reserve_exact(bytes.len()).map_err(E::custom)?;
                wire.extend_from_slice(bytes);
                PartialState::parse(wire, &PartialLimits::default()).map_err(E::custom)
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut sequence: A) -> Result<PartialState, A::Error> {
                use serde::de::Error;
                if sequence.size_hint().is_some_and(|n| n > 65_536) {
                    return Err(A::Error::custom("partial state sequence limit exceeded"));
                }
                let mut wire = Vec::new();
                while let Some(byte) = sequence.next_element::<u8>()? {
                    if wire.len() == 65_536 {
                        return Err(A::Error::custom("partial state sequence limit exceeded"));
                    }
                    wire.try_reserve(1).map_err(A::Error::custom)?;
                    wire.push(byte);
                }
                PartialState::parse(wire, &PartialLimits::default()).map_err(A::Error::custom)
            }
        }
        deserializer.deserialize_bytes(ManifestVisitor)
    }
}
