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
use crate::progressive::{
    OutputOperation, OutputRange, ProgressiveLimits, ProtectionDeclaration, SessionControl, SourceInfo, Usage,
};
use std::{ffi::OsString, io, ops::Range, path::PathBuf, sync::Arc};

pub type PartialResult<T> = Result<T, PartialError>;
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveBinding {
    pub job: [u8; 16],
    pub archive: [u8; 32],
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberKey {
    pub(super) binding: ArchiveBinding,
    pub(super) ordinal: u64,
    pub(super) identity: [u8; 32],
}
impl MemberKey {
    pub fn new(binding: ArchiveBinding, ordinal: u64, identity: [u8; 32]) -> Self {
        Self { binding, ordinal, identity }
    }
    pub fn binding(&self) -> &ArchiveBinding {
        &self.binding
    }
    pub fn ordinal(&self) -> u64 {
        self.ordinal
    }
    pub fn identity(&self) -> &[u8; 32] {
        &self.identity
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateAnchor {
    pub(super) member: MemberKey,
    pub(super) sequence: u64,
    pub(super) digest: [u8; 32],
}
impl StateAnchor {
    pub fn new(member: MemberKey, sequence: u64, digest: [u8; 32]) -> Self {
        Self { member, sequence, digest }
    }
    pub fn member(&self) -> &MemberKey {
        &self.member
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}
/// The caller store must atomically and durably compare and replace an anchor.
/// An error may mean the replacement persisted. Keep this authority independent
/// from untrusted queue blobs and retain its referenced bundle with queue state.
pub trait StateAnchorStore: Send + Sync + 'static {
    fn current(&self, member: &MemberKey) -> PartialResult<Option<StateAnchor>>;
    fn compare_exchange(
        &self,
        member: &MemberKey,
        expected: Option<&StateAnchor>,
        next: &StateAnchor,
    ) -> PartialResult<()>;
}
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum PartialNaming {
    ArchivePath,
    Suffix(OsString),
}
pub struct PartialOptions {
    pub binding: ArchiveBinding,
    pub naming: PartialNaming,
    pub state_dir: PathBuf,
    pub limits: PartialLimits,
    pub anchors: Arc<dyn StateAnchorStore>,
    pub control: SessionControl,
}
pub struct PartialOpenContext {
    pub output_root: PathBuf,
    pub state_root: PathBuf,
    pub expected_member: MemberKey,
    pub expected_anchor: StateAnchor,
    pub protection: ProtectionDeclaration,
    pub limits: PartialLimits,
    pub progressive_limits: ProgressiveLimits,
    pub anchors: Arc<dyn StateAnchorStore>,
    pub control: SessionControl,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackedSpan {
    pub volume: u32,
    pub range: Range<u64>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum HoleCause {
    Missing,
    DeclaredBad,
    CipherNeighbour,
    HeaderLost,
}
#[derive(Clone, Debug)]
pub struct HoleReport {
    pub id: u64,
    pub revision: u64,
    pub member: MemberKey,
    pub name: Arc<[u8]>,
    pub out: Range<u64>,
    pub packed: Vec<PackedSpan>,
    pub cause: HoleCause,
}
/// What a session made of damage declared with `ProgressiveSession::declare_hole`.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct DamageReceipt {
    /// Output that was already written from the damaged bytes and is now a `DeclaredBad` hole, per member.
    pub holes: Vec<HoleReport>,
    /// Damaged bytes not read yet. They are answered as holes when reached and reported then as
    /// `ProgressiveEvent::Hole` with cause `DeclaredBad`.
    pub pending: Vec<PackedSpan>,
    /// Damaged bytes already read that map to no persistent output, such as headers or padding.
    pub unmapped: Vec<PackedSpan>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberChecks {
    pub size: u64,
    pub crc32: Option<u32>,
    pub blake2sp: Option<[u8; 32]>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BindingField {
    Job,
    Archive,
    Member,
    Root,
    Output,
    Source,
    Anchor,
}
#[derive(Clone, Debug)]
pub struct PartialLocation {
    pub output: PathBuf,
    pub state_bundle: PathBuf,
}
#[derive(Debug)]
#[non_exhaustive]
pub enum PartialErrorKind {
    Progressive(Box<crate::progressive::ProgressiveFailure>),
    UnsupportedPlatform,
    UnsupportedFormat,
    UnsupportedMethod,
    InvalidOptions,
    UnknownMemberSize,
    AlreadyExists,
    UnsafePath,
    BindingMismatch(BindingField),
    StateVersion,
    StateMalformed,
    StateStale {
        latest: StateAnchor,
    },
    StateUnavailable,
    JournalCorrupt,
    AnchorConflict,
    AnchorCommitUncertain,
    Busy,
    Canceled,
    OverlapMismatch {
        range: Range<u64>,
    },
    IncompleteOutput,
    OutputChanged,
    /// Reading the caller's archive volume failed in `refill_from_packed`; `volume` and `packed_offset` say where.
    PackedRead(io::Error),
    /// Reading the caller's plaintext failed (or ended early) in `PartialFile::fill_from`; `output` says how far the
    /// fill got.
    FillRead(io::Error),
    Limit {
        resource: PartialResource,
        limit: u64,
        attempted: u64,
    },
    Io {
        operation: OutputOperation,
        cause: io::Error,
    },
}
#[derive(Debug)]
pub struct PartialError {
    pub member: Option<MemberKey>,
    pub volume: Option<u32>,
    pub packed_offset: Option<u64>,
    pub output: Option<OutputRange>,
    pub committed: Option<StateAnchor>,
    pub location: Option<PartialLocation>,
    /// Set when `fill_packed` or `refill_from_packed` fails after some work became durable: output already applied,
    /// and alt ranges found wrong. A corrected range whose rewrite did not finish may be a `DeclaredBad` hole now
    /// (check `remaining`); if so, a retry fills it but reports it as `applied`, not `corrected`, so keep this list.
    pub packed_progress: Option<Box<PackedFillResult>>,
    pub kind: PartialErrorKind,
}
impl PartialError {
    pub fn new(kind: PartialErrorKind) -> Self {
        Self {
            member: None,
            volume: None,
            packed_offset: None,
            output: None,
            committed: None,
            location: None,
            packed_progress: None,
            kind,
        }
    }
}
impl std::fmt::Display for PartialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "persistent partial: {:?}", self.kind)
    }
}
impl std::error::Error for PartialError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.kind {
            PartialErrorKind::Io { cause, .. }
            | PartialErrorKind::PackedRead(cause)
            | PartialErrorKind::FillRead(cause) => Some(cause),
            PartialErrorKind::Progressive(cause) => Some(cause.as_ref()),
            _ => None,
        }
    }
}
pub(super) fn err(kind: PartialErrorKind) -> PartialError {
    PartialError::new(kind)
}
pub(super) fn malformed() -> PartialError {
    err(PartialErrorKind::StateMalformed)
}
pub(super) fn io_error(operation: OutputOperation, cause: io::Error) -> PartialError {
    err(PartialErrorKind::Io { operation, cause })
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PlainPart {
    pub ordinal: u64,
    pub packed: PackedSpan,
    pub out: Range<u64>,
    pub final_part: bool,
    pub crc32: Option<u32>,
    pub blake2sp: Option<[u8; 32]>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SourceAdmission {
    pub volume: u32,
    pub info: SourceInfo,
    pub expected: OsString,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HeaderWitness {
    pub volume: u32,
    pub packed: Range<u64>,
    pub bytes: Vec<u8>,
}
#[derive(Clone)]
pub(crate) struct InitialEvidence {
    pub metadata: crate::extract::Meta,
    pub parts: Vec<PlainPart>,
    pub admissions: Vec<SourceAdmission>,
    pub headers: Vec<HeaderWitness>,
}
pub(crate) struct CreateSpec {
    pub member: MemberKey,
    pub name: Arc<[u8]>,
    pub output_root: PathBuf,
    pub state_root: PathBuf,
    pub relative_output: PathBuf,
    pub size: u64,
    pub protection: ProtectionDeclaration,
    pub evidence: InitialEvidence,
}
pub(crate) struct ReopenSpec {
    pub state: PartialState,
    pub context: PartialOpenContext,
}
pub(crate) struct CoreOptions {
    pub limits: PartialLimits,
    pub usage: Usage,
    pub read_chunk: u64,
    pub anchors: Arc<dyn StateAnchorStore>,
    pub control: SessionControl,
    pub exclusions: Arc<PartialExclusions>,
}

impl From<crate::progressive::ProgressiveFailure> for PartialError {
    fn from(failure: crate::progressive::ProgressiveFailure) -> Self {
        err(PartialErrorKind::Progressive(Box::new(failure)))
    }
}

pub(crate) struct EvidenceUpdate {
    pub parts: Vec<PlainPart>,
    pub admissions: Vec<SourceAdmission>,
    pub headers: Vec<HeaderWitness>,
    pub checks: Option<MemberChecks>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CheckResult {
    Passed,
    Missing,
    Pending,
    Failed,
}
#[derive(Clone, Debug)]
pub struct PartCheck {
    pub volume: u32,
    pub part: u64,
    pub range: Range<u64>,
    pub crc32: CheckResult,
    pub blake2sp: CheckResult,
}
#[derive(Clone, Debug)]
pub struct FillResult {
    pub revision: u64,
    pub applied: Vec<Range<u64>>,
    pub state: PartialState,
    pub part_checks: Vec<PartCheck>,
    pub needs_verification: bool,
}
/// What [`PartialFile::fill_packed`](super::PartialFile::fill_packed) or
/// [`refill_from_packed`](super::PartialFile::refill_from_packed) did.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct PackedFillResult {
    pub revision: u64,
    /// Output ranges written: former holes plus corrected alt bytes.
    pub applied: Vec<Range<u64>>,
    /// Output ranges that had been filled from an alt with different bytes. The archive bytes replaced them.
    pub corrected: Vec<Range<u64>>,
    /// Supplied packed bytes that map to no produced output of this member (headers, padding, other members, or
    /// output the extraction has not reached yet). They were not used.
    pub unmapped: Vec<PackedSpan>,
    pub state: PartialState,
    pub part_checks: Vec<PartCheck>,
    pub needs_verification: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum VerifyPath {
    ExtentCombine,
    TargetedReadback,
    WholeReadback,
    ReopenRehash,
}
#[derive(Debug)]
#[non_exhaustive]
pub enum AttributeResult {
    Applied,
    NotRequested,
    Failed(io::Error),
}
#[derive(Debug)]
pub struct MetadataResult {
    pub modified: AttributeResult,
    pub permissions: AttributeResult,
}
#[derive(Debug)]
#[non_exhaustive]
pub enum Verdict {
    Ok { revision: u64, parts: Vec<PartCheck>, path: VerifyPath, metadata: MetadataResult },
    PartBad { revision: u64, volume: u32, part: u64, which: crate::progressive::ChecksumAlgorithm },
    Bad { revision: u64, which: crate::progressive::ChecksumAlgorithm },
    Incomplete { revision: u64, holes: Vec<Range<u64>>, parts: Vec<PartCheck>, missing_checks: bool },
}
