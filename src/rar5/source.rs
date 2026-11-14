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

//! Shared immutable native source stamps.
use crate::error::{Error, IoOperation, RarFailure, RarFault, RarResult};
use std::{
    fs::{self, File, Metadata},
    io,
    path::Path,
};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct SourceStamp {
    pub(crate) len: u64,
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) mtime: (i64, i64),
    pub(crate) ctime: (i64, i64),
}

impl SourceStamp {
    pub(crate) fn capture(file: &File, path: &Path) -> RarResult<Self> {
        Self::capture_for_output(file, path, None)
    }

    pub(crate) fn capture_for_output(
        file: &File,
        path: &Path,
        _output_identity: Option<(u64, u64)>,
    ) -> RarResult<Self> {
        let metadata_error = |error| RarFault::input(IoOperation::Metadata, Some(path.to_path_buf()), None, error);
        let metadata = file.metadata().map_err(metadata_error)?;
        // Reject aliases before a binding or framing error could be reported
        // through that same descriptor. This performs no extra metadata read.
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if _output_identity == Some((metadata.dev(), metadata.ino())) {
                return Err(RarFault::new(RarFailure::OutputAliasesInput, Error::Corrupt("RAR output aliases input")));
            }
        }
        let before = Self::from_metadata(metadata).map_err(metadata_error)?;
        let bound = Self::from_metadata(fs::metadata(path).map_err(metadata_error)?).map_err(metadata_error)?;
        let after = Self::from_metadata(file.metadata().map_err(metadata_error)?).map_err(metadata_error)?;
        if before != bound || before != after {
            return Err(Self::changed(path));
        }
        Ok(before)
    }

    pub(crate) fn check(self, file: &File, path: &Path) -> RarResult<()> {
        let current = Self::capture(file, path);
        if matches!(&current, Ok(stamp) if *stamp != self) {
            return Err(Self::changed(path));
        }
        current.map(|_| ())
    }

    pub(crate) fn changed(path: &Path) -> RarFault {
        RarFault::new(RarFailure::SourceChanged { path: path.to_path_buf() }, Error::Corrupt("RAR source changed"))
    }

    #[cfg(unix)]
    pub(crate) fn from_metadata(metadata: Metadata) -> io::Result<Self> {
        use std::os::unix::fs::MetadataExt;

        if !metadata.is_file() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "RAR source is not a regular file"));
        }
        Ok(Self {
            len: metadata.len(),
            device: metadata.dev(),
            inode: metadata.ino(),
            mtime: (metadata.mtime(), metadata.mtime_nsec()),
            ctime: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }

    #[cfg(not(unix))]
    pub(crate) fn from_metadata(_: Metadata) -> io::Result<Self> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "RAR session source identity unavailable"))
    }
}
