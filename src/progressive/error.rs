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

//! Typed progressive failures, independent of legacy extraction errors.
use super::Resource;
use std::{ffi::OsString, fmt, io};

/// Opaque identity within a session; only the engine can construct one.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MemberId {
    pub(crate) session: std::num::NonZeroU64,
    pub(crate) ordinal: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FailureContext {
    pub output_range: Option<Box<OutputRange>>,
    pub member: Option<MemberId>,
    pub volume_index: Option<u32>,
    pub expected: Option<OsString>,
    pub packed_offset: Option<u64>,
    pub inner_offset: Option<u64>,
}
/// Positioned output attempt. Completed bytes are committed only when explicitly reported.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutputRange {
    pub offset: u64,
    pub attempted: u64,
    pub completed: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputOperation {
    Read,
    Metadata,
    Open,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputOperation {
    Create,
    Read,
    Write,
    Seek,
    Flush,
    Publish,
    Remove,
    Metadata,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChecksumAlgorithm {
    Crc32,
    Blake2sp,
    Sha1,
    Sha256,
}
/// Closed checksum widths; error evidence cannot retain arbitrary byte buffers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChecksumValue {
    Crc32([u8; 4]),
    Blake2sp([u8; 32]),
    Sha1([u8; 20]),
    Sha256([u8; 32]),
}
impl ChecksumValue {
    pub fn algorithm(&self) -> ChecksumAlgorithm {
        match self {
            Self::Crc32(_) => ChecksumAlgorithm::Crc32,
            Self::Blake2sp(_) => ChecksumAlgorithm::Blake2sp,
            Self::Sha1(_) => ChecksumAlgorithm::Sha1,
            Self::Sha256(_) => ChecksumAlgorithm::Sha256,
        }
    }
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Crc32(v) => v,
            Self::Blake2sp(v) => v.as_slice(),
            Self::Sha1(v) => v.as_slice(),
            Self::Sha256(v) => v.as_slice(),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChecksumScope {
    Header,
    PackedData,
    Member,
    Volume,
}
#[derive(Debug)]
#[non_exhaustive]
pub enum FailureKind {
    #[cfg(feature = "persistent-partials")]
    Partial(Box<crate::partial::PartialError>),
    Malformed(&'static str),
    Rar(Box<crate::error::RarFailure>),
    PasswordRequired,
    WrongPassword,
    ChecksumMismatch {
        algorithm: ChecksumAlgorithm,
        scope: ChecksumScope,
        expected: Box<ChecksumValue>,
        actual: Box<ChecksumValue>,
    },
    Truncated,
    MissingVolume,
    HeaderHole,
    DataHole,
    UnsupportedMethod,
    UnsafePath,
    SourceChanged,
    SourceContract,
    Canceled,
    Input {
        operation: InputOperation,
        cause: io::Error,
    },
    Output {
        operation: OutputOperation,
        cause: io::Error,
    },
    Limit {
        resource: Resource,
        limit: u64,
        attempted: u64,
    },
    IncompleteOutput,
    PublicationAuthorityRequired,
    InvalidCapability,
}
#[derive(Debug)]
pub struct ProgressiveFailure {
    pub context: FailureContext,
    pub kind: FailureKind,
}
pub type ProgressiveResult<T> = Result<T, ProgressiveFailure>;
impl ProgressiveFailure {
    pub fn new(kind: FailureKind) -> Self {
        Self { context: FailureContext::default(), kind }
    }
}
impl fmt::Display for ProgressiveFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "progressive archive failure: {:?} ({:?})", self.kind, self.context)
    }
}
impl std::error::Error for ProgressiveFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.kind {
            FailureKind::Input { cause, .. } | FailureKind::Output { cause, .. } => Some(cause),
            FailureKind::Rar(failure) => Some(failure.as_ref()),
            #[cfg(feature = "persistent-partials")]
            FailureKind::Partial(failure) => Some(failure.as_ref()),
            _ => None,
        }
    }
}
