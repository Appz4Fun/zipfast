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
/// Header witness page tag of a RAR4 member.
const FORMAT_RAR4: u8 = 4;
/// Header witness page tag of a direct member (created from a member map): no witnesses follow the count, and the
/// tag is followed by the [`DirectFacts`]. Its validity ledger lists only known leaves; unknown output is implicit.
const FORMAT_DIRECT: u8 = 0xD1;
/// Header witness page section listing the witnesses read past as damage ([`HeaderWitness::salvaged`]), version 1:
/// the tag, the version, a count and the ascending witness indices. Written only when some witness is salvaged, and
/// before the format tag, so every other state stays byte-identical and a build that predates it refuses such a
/// state with `StateVersion` (an unknown tag) instead of reading a damaged witness strictly.
const SALVAGED_WITNESSES: u8 = 0x5A;
/// Header witness page section listing the parts recorded cut short ([`InitialEvidence::cut`]: their volume's final
/// length ends inside their data), version 1: the tag, the version, a count and the ascending part ordinals. Written
/// only when some part is cut, after the salvaged section and before the format tag, so every other state stays
/// byte-identical and a build that predates it refuses such a state with `StateVersion` (an unknown tag) instead of
/// reading it as malformed.
const CUT_PARTS: u8 = 0xC7;
/// Validity page section listing the kept leaves of a plain member ([`Snapshot::kept`]), version 1: the tag, the
/// version, a count and each leaf's output range and CRC-32. Written only when some leaf is kept, after the hole
/// cause section (which it forces) and in place of the ciphertext block section (kept leaves are plain-only, kept
/// ciphertext encrypted-only), so every other state stays byte-identical and a build that predates it refuses such
/// a state with `StateVersion` (it reads the tag as an unknown ciphertext section version).
const KEPT_LEAVES: u8 = 0x4B;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PageKind {
    Geometry = 1,
    Validity = 2,
    HeaderWitnesses = 3,
    /// A direct member's decoder cursor ([`super::PartialFile::set_cursor`]): opaque caller bytes committed with the
    /// output they describe. Only written when a cursor is set, so other states are unchanged.
    Cursor = 4,
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
    /// Set once the tail past `produced` was abandoned (`member_finished` is then true): which checks verify it.
    pub tail: Option<TailChecks>,
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
/// Drops the kept leaves of `snapshot` that a later write (`written`) touches or that no longer fit it: each must lie
/// inside one part, inside a `DeclaredBad` hole, and off every known leaf. The leaves are sorted, so is `known`.
pub(super) fn prune_kept(snapshot: &mut Snapshot, written: &[Range<u64>]) {
    if snapshot.kept.is_empty() {
        return;
    }
    let overlaps = |a: &Range<u64>, b: &Range<u64>| a.start < b.end && b.start < a.end;
    let mut kept = std::mem::take(&mut snapshot.kept);
    if snapshot.crypt.is_some() || snapshot.evidence.direct.is_some() {
        return;
    }
    // The DeclaredBad hole outputs, sorted, so each leaf finds its hole by a binary search. A list that cannot be
    // allocated keeps no leaf (they only save reads).
    let mut declared: Vec<Range<u64>> = Vec::new();
    let count = snapshot.holes.iter().filter(|h| h.cause == HoleCause::DeclaredBad).count();
    if declared.try_reserve_exact(count).is_err() {
        return;
    }
    declared.extend(snapshot.holes.iter().filter(|h| h.cause == HoleCause::DeclaredBad).map(|h| h.out.clone()));
    declared.sort_by_key(|r| r.start);
    kept.retain(|leaf| {
        let first = snapshot.known.partition_point(|k| k.range.end <= leaf.range.start);
        let on_known = snapshot.known.get(first).is_some_and(|k| k.range.start < leaf.range.end);
        let in_part = snapshot.part_end(leaf.range.start).is_some_and(|end| leaf.range.end <= end);
        // Hole outputs are disjoint: only the last one starting at or before the leaf can hold it.
        let upto = declared.partition_point(|h| h.start <= leaf.range.start);
        let inside = upto > 0 && leaf.range.end <= declared[upto - 1].end;
        !on_known && in_part && inside && !written.iter().any(|w| overlaps(w, &leaf.range))
    });
    snapshot.kept = kept;
}
impl Snapshot {
    /// End of the output a write may reach: the last recorded part's, or the size once the tail is abandoned.
    pub(super) fn writable_end(&self) -> Option<u64> {
        if self.head.tail.is_some() { Some(self.head.size) } else { self.evidence.parts.last().map(|p| p.out.end) }
    }
    /// End of the part holding output `at` (leaves never cross it), or the size past the last part of a member
    /// whose tail is abandoned.
    pub(super) fn part_end(&self, at: u64) -> Option<u64> {
        let parts = &self.evidence.parts;
        match parts.get(parts.partition_point(|p| p.out.end <= at)) {
            Some(part) => Some(part.out.end),
            None => self.head.tail.map(|_| self.head.size).filter(|&end| at < end),
        }
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
    /// Leaves of a plain member's output that a part check later found wrong somewhere (a `DeclaredBad` hole the
    /// session declared over a whole part, or the caller with `declare_hole`): the bytes are still in the output and
    /// these are their CRC-32s, so `refill_declared_from_packed` can re-read only the repaired ranges and let the
    /// part's own check decide. Sorted, disjoint, each inside a `DeclaredBad` hole and disjoint from `known`; a write
    /// over one drops it in the write's intent, before any byte changes.
    pub kept: Vec<KnownLeaf>,
    /// A direct member's cursor, as last set (committed with the next commit) or as the loaded state holds it.
    pub cursor: Option<Arc<[u8]>>,
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
    read_bounded_with(file, max, |len| budget.vector(len))
}
/// [`read_bounded`] for a transient copy, charged until the returned lease drops.
pub(super) fn read_bounded_leased(
    file: &std::fs::File,
    max: usize,
    budget: &PartialBudget,
) -> PartialResult<(Vec<u8>, Lease)> {
    let mut lease = None;
    let bytes = read_bounded_with(file, max, |len| {
        let (bytes, charge) = budget.leased_vector(len)?;
        lease = Some(charge);
        Ok(bytes)
    })?;
    Ok((bytes, lease.unwrap_or_else(|| Lease::empty(&budget.usage, crate::progressive::Resource::MetadataBytes))))
}
fn read_bounded_with(
    file: &std::fs::File,
    max: usize,
    allocate: impl FnOnce(usize) -> PartialResult<Vec<u8>>,
) -> PartialResult<Vec<u8>> {
    let len = file.metadata().map_err(|e| io_error(crate::progressive::OutputOperation::Metadata, e))?.len();
    if len > max as u64 {
        return Err(limit(PartialResource::StateWire, max as u64, len));
    }
    let mut bytes = allocate(len as usize)?;
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
    // The buffer is scratch: its bytes are copied into pages and it is dropped
    // with the encoder, so its capacity is leased rather than charged for good.
    usage: Option<(crate::progressive::Usage, Lease)>,
}
impl Encoder {
    fn new(max: usize) -> Self {
        Self { bytes: Vec::new(), max, usage: None }
    }
    fn budgeted(max: usize, budget: &PartialBudget) -> Self {
        let lease = Lease::empty(&budget.usage, crate::progressive::Resource::MetadataBytes);
        Self { bytes: Vec::new(), max, usage: Some((budget.usage.clone(), lease)) }
    }
    /// Reserves room for `n` bytes up front, so encoding a known size moves nothing.
    fn reserve(&mut self, n: usize) -> PartialResult<()> {
        let n = n.min(self.max);
        if self.bytes.capacity() < n {
            self.grow_to(n)?;
        }
        Ok(())
    }
    fn grow_to(&mut self, capacity: usize) -> PartialResult<()> {
        if let Some((usage, lease)) = &mut self.usage {
            lease.grow((capacity - self.bytes.capacity()) as u64)?;
            usage.charge(crate::progressive::Resource::SourceBookkeeping, self.bytes.len() as u64)?;
        }
        self.bytes.try_reserve_exact(capacity - self.bytes.len()).map_err(|_| malformed())
    }
    fn raw(&mut self, b: &[u8]) -> PartialResult<()> {
        let n = self.bytes.len().checked_add(b.len()).ok_or_else(malformed)?;
        if n > self.max {
            return Err(limit(PartialResource::StateWire, self.max as u64, n as u64));
        }
        if self.bytes.capacity() < n {
            self.grow_to(self.bytes.capacity().saturating_mul(2).max(n).min(self.max))?;
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
    // 0 running, 1 finished, 2 tail abandoned with the archive's checks, 3 with checks the caller supplied.
    p.u8(match head.tail {
        None => head.member_finished as u8,
        Some(TailChecks::Archive) => 2,
        Some(TailChecks::Supplied) => 3,
    })?;
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
    let (member_finished, tail) = match d.u8()? {
        0 => (false, None),
        1 => (true, None),
        2 => (true, Some(TailChecks::Archive)),
        3 => (true, Some(TailChecks::Supplied)),
        _ => return Err(malformed()),
    };
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
            4 => PageKind::Cursor,
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
            tail,
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
pub(super) type EncodedPages = Vec<(PageKind, Vec<u8>)>;
/// Encodes the snapshot's ledger pages. The returned lease covers the page
/// bytes; callers keep it while they hold the pages.
pub(super) fn encode_pages(snapshot: &Snapshot, budget: &PartialBudget) -> PartialResult<(EncodedPages, Lease)> {
    // Every encoder is sized up front from the snapshot (an upper bound of the
    // fields written below), so encoding moves no bytes as it grows.
    let mut geometry = Encoder::budgeted(budget.limits.ledger_bytes as usize, budget);
    geometry.reserve(
        12 + snapshot.name.len()
            + 83 * snapshot.evidence.parts.len()
            + snapshot.evidence.admissions.iter().map(|a| 49 + os_bytes(&a.expected).len()).sum::<usize>(),
    )?;
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
    // Large members split the validity ledger into pages by output window (see `validity_window`), so a commit
    // rewrites only the pages whose windows changed. Their unknown gaps are cut on absolute 64 KiB boundaries,
    // which makes each window's extents depend only on the leaves inside it.
    let window = validity_window(snapshot.head.size, budget.limits.state_pages);
    let aligned = window.is_some();
    // A direct member lists only its known leaves: the output nothing has written yet is implicit, so a member
    // born with all of it unknown records nothing for it, whatever its size.
    let sparse = snapshot.evidence.direct.is_some();
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
        if !sparse {
            extent_count =
                extent_count.checked_add(gap_pieces(end, leaf.range.start, aligned)).ok_or_else(malformed)?;
        }
        end = leaf.range.end;
    }
    if !sparse {
        extent_count = extent_count.checked_add(gap_pieces(end, snapshot.head.size, aligned)).ok_or_else(malformed)?;
    }
    budget.limits.check(
        PartialResource::LedgerBytes,
        extent_count.checked_mul(21).and_then(|n| n.checked_add(8)).ok_or_else(malformed)?,
    )?;
    let mut validity = Encoder::budgeted(budget.limits.ledger_bytes as usize, budget);
    validity.reserve(
        (extent_count.saturating_mul(21) as usize)
            .saturating_add(13)
            .saturating_add(snapshot.holes.iter().map(|h| 37 + 20 * h.packed.len()).sum::<usize>())
            .saturating_add(snapshot.cipher.iter().map(|b| 10 + b.bytes.len()).sum::<usize>())
            .saturating_add(snapshot.kept.len().saturating_mul(20).saturating_add(6)),
    )?;
    // Byte offsets in `validity` where a page must start: after the extent count, at the first extent of each
    // window, and before the hole section. Only the windowed layout uses them.
    let mut breaks = Vec::new();
    validity.u32(extent_count.try_into().map_err(|_| malformed())?)?;
    let mut next_window = 0u64;
    let mut extent = |validity: &mut Encoder, range: Range<u64>, tag: u8, crc: u32| -> PartialResult<()> {
        if let Some(window) = window
            && range.start >= next_window
        {
            breaks.try_reserve(1).map_err(|_| malformed())?;
            breaks.push(validity.bytes.len());
            next_window = (range.start / window + 1) * window;
        }
        validity.range(&range)?;
        validity.u8(tag)?;
        validity.u32(crc)
    };
    let mut end = 0;
    for leaf in &snapshot.known {
        while !sparse && end < leaf.range.start {
            let stop = gap_piece_end(end, leaf.range.start, aligned);
            extent(&mut validity, end..stop, 0, 0)?;
            end = stop;
        }
        extent(&mut validity, leaf.range.clone(), leaf.provenance as u8, leaf.crc)?;
        end = leaf.range.end;
    }
    while !sparse && end < snapshot.head.size {
        let stop = gap_piece_end(end, snapshot.head.size, aligned);
        extent(&mut validity, end..stop, 0, 0)?;
        end = stop;
    }
    if aligned {
        breaks.try_reserve(1).map_err(|_| malformed())?;
        breaks.push(validity.bytes.len());
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
    if !snapshot.kept.is_empty() && !snapshot.cipher.is_empty() {
        return Err(malformed());
    }
    let causes = snapshot.holes.iter().any(|h| h.cause != HoleCause::Missing)
        || !snapshot.cipher.is_empty()
        || !snapshot.kept.is_empty();
    for h in snapshot.holes.iter().filter(|_| causes) {
        validity.u8(match h.cause {
            HoleCause::Missing => 0,
            HoleCause::DeclaredBad => 1,
            HoleCause::CipherNeighbour => 2,
            HoleCause::HeaderLost => 3,
            HoleCause::TailAbandoned => 4,
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
    if !snapshot.kept.is_empty() {
        validity.u8(KEPT_LEAVES)?;
        validity.u8(1)?;
        validity.u32(snapshot.kept.len().try_into().map_err(|_| malformed())?)?;
        for leaf in &snapshot.kept {
            validity.range(&leaf.range)?;
            validity.u32(leaf.crc)?;
        }
    }
    let mut headers = Encoder::budgeted(budget.limits.ledger_bytes as usize, budget);
    headers.reserve(5 + snapshot.evidence.headers.iter().map(|h| 28 + h.bytes.len()).sum::<usize>())?;
    headers.u32(snapshot.evidence.headers.len().try_into().map_err(|_| malformed())?)?;
    for h in &snapshot.evidence.headers {
        headers.u32(h.volume)?;
        headers.range(&h.packed)?;
        headers.blob(&h.bytes)?;
    }
    let salvaged = snapshot.evidence.headers.iter().filter(|h| h.salvaged).count();
    if salvaged > 0 {
        headers.reserve(6 + 4 * salvaged)?;
        headers.u8(SALVAGED_WITNESSES)?;
        headers.u8(1)?;
        headers.u32(salvaged.try_into().map_err(|_| malformed())?)?;
        for (index, _) in snapshot.evidence.headers.iter().enumerate().filter(|(_, h)| h.salvaged) {
            headers.u32(index.try_into().map_err(|_| malformed())?)?;
        }
    }
    if !snapshot.evidence.cut.is_empty() {
        headers.reserve(6 + 8 * snapshot.evidence.cut.len())?;
        headers.u8(CUT_PARTS)?;
        headers.u8(1)?;
        headers.u32(snapshot.evidence.cut.len().try_into().map_err(|_| malformed())?)?;
        for ordinal in &snapshot.evidence.cut {
            headers.u64(*ordinal)?;
        }
    }
    // Trailing format tag, written only for RAR4 members so that RAR5 states stay byte-identical and readable by
    // builds that predate RAR4 support. States without it are RAR5.
    if let Some(direct) = &snapshot.evidence.direct {
        headers.reserve(48)?;
        headers.u8(FORMAT_DIRECT)?;
        headers.u8(1)?;
        headers.u8(direct.container)?;
        match &direct.keyed {
            None => headers.u8(0)?,
            Some(keyed) => {
                headers.u8(1)?;
                headers.u8(keyed.kdf_count)?;
                headers.raw(&keyed.salt)?;
                match &keyed.check {
                    None => headers.u8(0)?,
                    Some((value, sum)) => {
                        headers.u8(1)?;
                        headers.raw(value)?;
                        headers.raw(sum)?;
                    }
                }
            }
        }
    } else if snapshot.evidence.format == crate::rar5::RarFormat::Rar4 {
        headers.u8(FORMAT_RAR4)?;
    }
    let cursor: &[u8] = snapshot.cursor.as_deref().unwrap_or(&[]);
    let total = geometry
        .bytes
        .len()
        .checked_add(validity.bytes.len())
        .and_then(|n| n.checked_add(headers.bytes.len()))
        .and_then(|n| n.checked_add(cursor.len()))
        .ok_or_else(malformed)?;
    budget.limits.check(PartialResource::LedgerBytes, total as u64)?;
    let lease = budget.metadata_lease(total as u64)?;
    let mut out = Vec::new();
    // Pages of one kind are concatenated on decode, so where a kind is cut into pages is free: the single-stream
    // layout cuts every PAGE_MAX bytes, the windowed validity ledger also at its window breaks.
    for (kind, bytes, breaks) in [
        (PageKind::Geometry, geometry.bytes, &[][..]),
        (PageKind::Validity, validity.bytes, &breaks[..]),
        (PageKind::HeaderWitnesses, headers.bytes, &[][..]),
    ] {
        let mut start = 0;
        for stop in breaks.iter().copied().chain(std::iter::once(bytes.len())) {
            for chunk in bytes[start..stop].chunks(PAGE_MAX - 15) {
                budget.limits.check(PartialResource::StatePages, (out.len() + 1) as u64)?;
                out.push((kind, page_bytes(kind, chunk)?));
            }
            start = stop;
        }
        if bytes.is_empty() {
            budget.limits.check(PartialResource::StatePages, (out.len() + 1) as u64)?;
            out.push((kind, page_bytes(kind, &bytes)?));
        }
    }
    if snapshot.cursor.is_some() {
        for chunk in cursor.chunks(PAGE_MAX - 15) {
            budget.limits.check(PartialResource::StatePages, (out.len() + 1) as u64)?;
            out.push((PageKind::Cursor, page_bytes(PageKind::Cursor, chunk)?));
        }
        if cursor.is_empty() {
            budget.limits.check(PartialResource::StatePages, (out.len() + 1) as u64)?;
            out.push((PageKind::Cursor, page_bytes(PageKind::Cursor, cursor)?));
        }
    }
    Ok((out, lease))
}
/// Validity extent bytes per page targeted by the windowed layout, and the most windows a member is cut into.
const WINDOW_BYTES: u64 = 64 * 1024;
const WINDOWS_MAX: u64 = 24;
/// Output bytes covered by one validity page of a member whose extent list is large, or `None` for the
/// single-stream layout of smaller members (which stays byte-identical to earlier builds). A window is a multiple of
/// 64 KiB, so absolute 64 KiB gap pieces and leaves (which never cross a 64 KiB boundary) never straddle two.
///
/// The live pages of a windowed state (geometry, extent count, windows, holes, header witnesses) take at most half
/// of `state_pages`, which also bounds the bundle's superseded pages until compaction; a budget too small for
/// two windows keeps the single-stream layout.
pub(super) fn validity_window(size: u64, state_pages: u32) -> Option<u64> {
    let bytes = size.div_ceil(65_536).saturating_mul(21);
    if bytes <= 2 * WINDOW_BYTES {
        return None;
    }
    let room = (u64::from(state_pages) / 2).saturating_sub(4);
    let windows = bytes.div_ceil(WINDOW_BYTES).min(WINDOWS_MAX).min(room);
    if windows < 2 {
        return None;
    }
    Some(size.div_ceil(windows).next_multiple_of(65_536))
}
/// End of the unknown piece starting at `end` of a gap ending at `limit`: at most 64 KiB, cut on absolute 64 KiB
/// boundaries when `aligned`.
fn gap_piece_end(end: u64, limit: u64, aligned: bool) -> u64 {
    if aligned { limit.min((end / 65_536 + 1) * 65_536) } else { end.saturating_add(65_536).min(limit) }
}
/// Number of unknown pieces `gap_piece_end` cuts the gap `end..limit` into.
fn gap_pieces(end: u64, limit: u64, aligned: bool) -> u64 {
    if end >= limit {
        0
    } else if aligned {
        (limit - 1) / 65_536 - end / 65_536 + 1
    } else {
        (limit - end).div_ceil(65_536)
    }
}
pub(super) fn decode_pages(
    head: CommittedState,
    pages: Vec<(PageKind, Vec<u8>)>,
    budget: &PartialBudget,
    reusable: &[KnownLeaf],
) -> PartialResult<Snapshot> {
    let mut buffers: [Vec<u8>; 4] = [Vec::new(), Vec::new(), Vec::new(), Vec::new()];
    let mut has_cursor = false;
    let mut total = 0usize;
    let mut last = 0;
    for (kind, bytes) in pages {
        let index = kind as usize;
        if index < last {
            return Err(malformed());
        }
        last = index;
        has_cursor |= kind == PageKind::Cursor;
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
        headers.push(HeaderWitness { volume, packed, bytes, salvaged: false });
    }
    if d.bytes.get(d.at) == Some(&SALVAGED_WITNESSES) {
        d.u8()?;
        if d.u8()? != 1 {
            return Err(err(PartialErrorKind::StateVersion));
        }
        let count = d.count(headers.len(), 4)?;
        if count == 0 {
            return Err(malformed());
        }
        let mut next = 0;
        for _ in 0..count {
            let index = d.u32()? as usize;
            if index < next || index >= headers.len() {
                return Err(malformed());
            }
            headers[index].salvaged = true;
            next = index + 1;
        }
    }
    let mut cut = Vec::new();
    if d.bytes.get(d.at) == Some(&CUT_PARTS) {
        d.u8()?;
        if d.u8()? != 1 {
            return Err(err(PartialErrorKind::StateVersion));
        }
        // Each listed ordinal names a distinct part (checked against the parts by `validate_evidence`).
        let count = d.count(parts.len(), 8)?;
        if count == 0 {
            return Err(malformed());
        }
        cut = budget.vector(count)?;
        for _ in 0..count {
            let ordinal = d.u64()?;
            if cut.last().is_some_and(|&last| last >= ordinal) {
                return Err(malformed());
            }
            cut.push(ordinal);
        }
    }
    let mut format = crate::rar5::RarFormat::Rar5;
    let mut direct = None;
    if d.at < d.bytes.len() {
        match d.u8()? {
            FORMAT_RAR4 => format = crate::rar5::RarFormat::Rar4,
            FORMAT_DIRECT => {
                if d.u8()? != 1 {
                    return Err(err(PartialErrorKind::StateVersion));
                }
                let container = d.u8()?;
                let keyed = match d.u8()? {
                    0 => None,
                    1 => {
                        let kdf_count = d.u8()?;
                        let salt = d.take(16)?.try_into().unwrap();
                        let check = match d.u8()? {
                            0 => None,
                            1 => Some((d.take(8)?.try_into().unwrap(), d.take(4)?.try_into().unwrap())),
                            _ => return Err(malformed()),
                        };
                        Some(KeyedChecks { kdf_count, salt, check })
                    }
                    _ => return Err(malformed()),
                };
                direct = Some(DirectFacts { container, keyed });
            }
            _ => return Err(err(PartialErrorKind::StateVersion)),
        }
    }
    d.end()?;
    let sparse = direct.is_some();
    let mut d = Decoder::new(&buffers[1]);
    let count = d.count(usize::MAX, 21)?;
    let mut known = Vec::new();
    let mut end = 0;
    for _ in 0..count {
        let range = d.range()?;
        let tag = d.u8()?;
        let crc = d.u32()?;
        let placed = if sparse { range.start >= end } else { range.start == end };
        if !placed || range.end > head.size || range.is_empty() || range.end - range.start > 65_536 {
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
    if !sparse && end != head.size {
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
                4 => HoleCause::TailAbandoned,
                _ => return Err(malformed()),
            };
        }
    }
    let mut cipher = Vec::new();
    if d.at < d.bytes.len() && d.bytes.get(d.at) != Some(&KEPT_LEAVES) {
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
    let mut kept = Vec::new();
    if d.at < d.bytes.len() {
        if d.u8()? != KEPT_LEAVES || d.u8()? != 1 {
            return Err(err(PartialErrorKind::StateVersion));
        }
        let count = d.count(budget.limits.crc_leaves as usize, 20)?;
        if count == 0 || !cipher.is_empty() || sparse {
            return Err(malformed());
        }
        budget.limits.check(PartialResource::CrcLeaves, (known.len() + count) as u64)?;
        budget.metadata((count * std::mem::size_of::<KnownLeaf>()) as u64)?;
        kept = budget.vector(count)?;
        let mut end = 0;
        for _ in 0..count {
            let range = d.range()?;
            let crc = d.u32()?;
            if range.start < end || range.is_empty() || range.end > head.produced || range.end - range.start > 65_536 {
                return Err(malformed());
            }
            end = range.end;
            let hasher = crate::crc32::Hasher::from_parts(crc, range.end - range.start);
            let lease = Arc::new(budget.reserve(PartialResource::CrcLeaves, 1)?);
            kept.push(KnownLeaf { range, crc, hasher, provenance: Provenance::Original, _lease: lease });
        }
    }
    d.end()?;
    let evidence = InitialEvidence { format, metadata: head.metadata, parts, admissions, headers, cut, direct };
    if has_cursor && evidence.direct.is_none() {
        return Err(malformed());
    }
    let cursor = has_cursor.then(|| Arc::from(std::mem::take(&mut buffers[3]).into_boxed_slice()));
    let mut snapshot = Snapshot { head, name, evidence, known, holes, crypt: None, cipher, cursor, kept };
    snapshot.crypt = validate_evidence(&snapshot.name, snapshot.head.size, &snapshot.evidence, budget)?;
    if (!snapshot.cipher.is_empty() && snapshot.crypt.is_none())
        || (!snapshot.kept.is_empty() && snapshot.crypt.is_some())
    {
        return Err(malformed());
    }
    // Kept leaves only lower what a refill must read, so ones that no longer fit the state (across a part boundary,
    // over known output, outside every DeclaredBad hole) are dropped rather than refusing the state.
    prune_kept(&mut snapshot, &[]);
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
    if evidence.direct.is_some() {
        // One synthetic part over the whole output, no packed bytes behind it, no part checks (the member checks
        // are in the head), and nothing parsed from an archive.
        let whole = PlainPart {
            ordinal: 0,
            packed: PackedSpan { volume: 0, range: 0..0 },
            out: 0..size,
            final_part: true,
            crc32: None,
            blake2sp: None,
        };
        if evidence.parts != [whole]
            || !evidence.headers.is_empty()
            || !evidence.cut.is_empty()
            || !evidence.admissions.is_empty()
            || evidence.format != crate::rar5::RarFormat::Rar5
            || name.is_empty()
        {
            return Err(malformed());
        }
        return Ok(None);
    }
    if evidence.parts.is_empty() || evidence.headers.is_empty() || evidence.admissions.is_empty() {
        return Err(malformed());
    }
    budget.usage.check(crate::progressive::Resource::Parts, evidence.parts.len() as u64)?;
    // Cut parts are listed once each, ascending, and each names a recorded part.
    if evidence.cut.windows(2).any(|w| w[0] >= w[1])
        || evidence.cut.last().is_some_and(|&last| last >= evidence.parts.len() as u64)
    {
        return Err(malformed());
    }
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
        // A part lies within its volume, except a part recorded cut short: its volume's final length ends inside
        // its data (after its header, which the witness below must still match).
        let within = if evidence.cut.binary_search(&part.ordinal).is_ok() {
            matches!(admission.info.length, SourceLength::Final(n)
                if part.packed.range.start <= n && n < part.packed.range.end)
        } else {
            part.packed.range.end <= admission.info.length.value()
        };
        if admission.info.extent > admission.info.length.value() || !within {
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
        let header = witness_header(witness, evidence.format, &admission.expected, budget)?;
        if index == 0 {
            let actual = crate::extract::Meta::from(&header);
            if actual.mtime != evidence.metadata.mtime
                || actual.nanos != evidence.metadata.nanos
                || actual.mode != evidence.metadata.mode
            {
                return Err(err(PartialErrorKind::BindingMismatch(BindingField::Member)));
            }
        }
        if header.format != evidence.format {
            return Err(err(PartialErrorKind::UnsupportedFormat));
        }
        if header.method != 0 || header.is_dir() || header.redirection.is_some() || header.is_rar4_symlink() {
            return Err(err(PartialErrorKind::UnsupportedMethod));
        }
        // RAR4 is admitted plain or AES with a salt; any header the progressive RAR4 path refuses stays out.
        let legacy = header.rar4.map(|raw| crate::rar5::LegacyCrypt { version: raw.unpack_version, salt: raw.salt });
        if header.format == crate::rar5::RarFormat::Rar4 && header.rar4_progressive_unsupported(legacy).is_some() {
            return Err(err(PartialErrorKind::UnsupportedMethod));
        }
        let params = if header.encrypted {
            Some(member_crypt(&header).ok_or_else(|| err(PartialErrorKind::UnsupportedMethod))?)
        } else {
            None
        };
        if index == 0 {
            crypt = params;
        } else if !same_member_crypt(params.as_ref(), crypt.as_ref()) {
            return Err(err(PartialErrorKind::BindingMismatch(BindingField::Member)));
        }
        // rar (7.00) sets the RAR 5.0 "tweaked checksums" flag only in the final part's encryption record: the
        // earlier parts' CRCs are plain checks of their ciphertext, and the final part's member checks are keyed.
        // So the member's checks are keyed as its final part says.
        if part.final_part
            && let (Some(member), Some(last)) = (crypt.as_mut(), params.as_ref())
        {
            member.tweaked_crc = last.tweaked_crc;
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
            || (header.crc32 != part.crc32 && !rar4_unknown_part_crc(&header, part.crc32))
            || header.blake2sp != part.blake2sp
            || header.split_after() == part.final_part
        {
            return Err(err(PartialErrorKind::BindingMismatch(BindingField::Member)));
        }
    }
    Ok(crypt)
}

/// Whether a continuation part's cipher parameters name the same encrypted member as its first part's: the same KDF
/// count, salt and password check. The parts are one CBC stream, so only the first part's IV is used (a later part
/// restating another is accepted, as member maps accept it), and the tweaked-checksum flag may appear on the final
/// part only (rar 7.00 writes it there), so neither is compared.
/// Parses a header witness again: strictly, or as it stands when it was read past as damage
/// ([`HeaderWitness::salvaged`]), as the session read it. Only a file header is a witness.
pub(super) fn witness_header(
    witness: &HeaderWitness,
    format: crate::rar5::RarFormat,
    expected: &std::ffi::OsStr,
    budget: &PartialBudget,
) -> PartialResult<crate::rar5::FileHeader> {
    use crate::rar5::{
        framing::{HeaderParser, ParserStep},
        reader::Block,
    };
    let mut parser = HeaderParser::progressive(PathBuf::from(expected), witness.packed.start, budget.usage.clone());
    if format == crate::rar5::RarFormat::Rar4 {
        parser.set_format(crate::rar5::RarFormat::Rar4);
    }
    if witness.salvaged {
        parser.set_salvage(crate::extract::DamagedInput::Salvage);
    }
    let mut step = parser.advance(&[])?.1;
    let frame = loop {
        match step {
            ParserStep::Need { offset, len } => {
                let at = offset.checked_sub(witness.packed.start).ok_or_else(malformed)? as usize;
                let bytes = witness.bytes.get(at..at.checked_add(len).ok_or_else(malformed)?).ok_or_else(malformed)?;
                step = parser.advance(bytes)?.1;
            }
            ParserStep::Frame(frame) => break frame,
            _ => return Err(malformed()),
        }
    };
    let Block::File(header) = frame.block else { return Err(malformed()) };
    Ok(header)
}
/// Whether two readings of the header at one archive position describe the same member as far as its output is
/// concerned: name, sizes, where its data starts, method, checks, splitting, encryption and the host system (which
/// decides how the name is made a path). Times and attributes are left out: they change no output byte. Used when one
/// of the readings was damaged, to rebind a member to its header once the header is repaired.
pub(crate) fn same_member_header(a: &crate::rar5::FileHeader, b: &crate::rar5::FileHeader) -> bool {
    let legacy = |h: &crate::rar5::FileHeader| h.rar4.map(|raw| (raw.unpack_version, raw.salt, raw.method));
    a.format == b.format
        && a.name == b.name
        && a.packed_size == b.packed_size
        && a.data_at == b.data_at
        && a.unpacked_size == b.unpacked_size
        && a.size_unknown() == b.size_unknown()
        && a.crc32 == b.crc32
        && a.blake2sp == b.blake2sp
        && a.method == b.method
        && a.is_dir() == b.is_dir()
        && a.redirection.is_none()
        && b.redirection.is_none()
        && a.split_before() == b.split_before()
        && a.split_after() == b.split_after()
        && a.encrypted == b.encrypted
        && a.crypt == b.crypt
        && legacy(a) == legacy(b)
        && a.is_unix() == b.is_unix()
}
pub(crate) fn same_member_crypt(
    part: Option<&crate::crypto::Rar5CryptParams>,
    first: Option<&crate::crypto::Rar5CryptParams>,
) -> bool {
    match (part, first) {
        (None, None) => true,
        (Some(p), Some(f)) => p.kdf_count == f.kdf_count && p.salt == f.salt && p.check == f.check,
        _ => false,
    }
}

/// A part recorded with no CRC by a session that opted in to
/// [`crate::progressive::ProgressiveOptions::rar4_unknown_part_crc`]: its header, re-read here without that option,
/// shows the 0 the caller stored. Only a RAR 4.x part that continues into the next volume qualifies.
fn rar4_unknown_part_crc(header: &crate::rar5::FileHeader, recorded: Option<u32>) -> bool {
    header.format == crate::rar5::RarFormat::Rar4
        && header.split_after()
        && header.crc32 == Some(0)
        && recorded.is_none()
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

/// The cipher parameters a partial keeps for an encrypted stored member: a RAR5 header's own, or for a RAR4 member
/// (RAR 3.x AES-128-CBC, which needs its salt) the salt in the first 8 salt bytes and no check value. A RAR4 IV is
/// derived from the password with the key, so it lives in the in-memory keys and `iv` here is zero.
pub(crate) fn member_crypt(header: &crate::rar5::FileHeader) -> Option<crate::crypto::Rar5CryptParams> {
    match header.format {
        crate::rar5::RarFormat::Rar5 => header.crypt,
        crate::rar5::RarFormat::Rar4 => {
            let raw = header.rar4?;
            let salt8 = raw.salt.filter(|_| header.encrypted && raw.unpack_version == 29)?;
            let mut salt = [0; 16];
            salt[..8].copy_from_slice(&salt8);
            Some(crate::crypto::Rar5CryptParams { kdf_count: 0, salt, iv: [0; 16], check: None, tweaked_crc: false })
        }
    }
}
