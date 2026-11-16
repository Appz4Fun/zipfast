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

//! The archive's bytes on disk: the volumes of a split set as one run of bytes, packed streams read from them, and the
//! volume source the member map is built through.
use std::cell::RefCell;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::task::Context;

use super::coders::Fault;
use crate::extract::Cancellation;
use crate::map::PackedSpan;
use crate::progressive::{
    FailureKind, InputOperation, ProgressiveFailure, ProgressiveResult, RangeRead, RangeSource, SourceId, SourceInfo,
    SourceLength, VolumeAnswer, VolumeRequest, VolumeSource,
};

/// Volumes kept open at once while reading member data.
const OPEN_VOLUMES: usize = 16;

/// Positional read, whatever the platform.
fn read_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.read_at(buf, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        file.seek_read(buf, offset)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (file, buf, offset);
        Err(io::ErrorKind::Unsupported.into())
    }
}

/// The volumes of the archive by index, opened on demand. Volume 0 is the path given; later ones are named by the
/// member map's rule (`name.7z.001` → `name.7z.002`).
pub(crate) struct VolumeSet {
    paths: Vec<PathBuf>,
    /// Open volumes, least recently used first.
    open: Vec<(u32, File)>,
}

impl VolumeSet {
    /// The set of `count` volumes starting at `first`.
    pub(crate) fn new(first: &Path, count: u32) -> Self {
        let mut paths = vec![first.to_path_buf()];
        while paths.len() < count as usize {
            let next = crate::map::next_volume_name(paths.last().expect("first").as_os_str());
            paths.push(PathBuf::from(next));
        }
        Self { paths, open: Vec::new() }
    }

    pub(crate) fn paths(&self) -> &[PathBuf] {
        &self.paths
    }

    fn read(&mut self, volume: u32, offset: u64, buf: &mut [u8]) -> Result<usize, Fault> {
        let at = match self.open.iter().position(|(v, _)| *v == volume) {
            Some(at) => at,
            None => {
                let path = self.paths.get(volume as usize).ok_or(Fault::Data("7z packed data in an unknown volume"))?;
                let file = match File::open(path) {
                    Ok(file) => file,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(Fault::Missing(path.clone())),
                    Err(e) => return Err(Fault::Input(e)),
                };
                if self.open.len() >= OPEN_VOLUMES {
                    self.open.remove(0);
                }
                self.open.push((volume, file));
                self.open.len() - 1
            }
        };
        let entry = self.open.remove(at);
        let result = loop {
            match read_at(&entry.1, buf, offset) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                other => break other,
            }
        };
        self.open.push(entry);
        result.map_err(Fault::Input)
    }
}

/// One packed stream of a folder: its spans, read in order.
pub(crate) struct PackReader {
    set: Rc<RefCell<VolumeSet>>,
    spans: Vec<PackedSpan>,
    /// The span being read and the offset in it.
    span: usize,
    at: u64,
    cancel: Cancellation,
}

impl PackReader {
    /// The spans of `all` (a folder's packed spans, in stream order) that cover `range` of the folder's packed stream.
    pub(crate) fn new(
        set: Rc<RefCell<VolumeSet>>,
        all: &[PackedSpan],
        range: std::ops::Range<u64>,
        cancel: Cancellation,
    ) -> Self {
        let mut spans = Vec::new();
        for span in all {
            let a = span.stream.start.max(range.start);
            let b = span.stream.end.min(range.end);
            if a < b {
                let skip = a - span.stream.start;
                let start = span.packed.start + skip;
                spans.push(PackedSpan { volume: span.volume, packed: start..start + (b - a), stream: a..b });
            }
        }
        Self { set, spans, span: 0, at: 0, cancel }
    }
}

impl Read for PackReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.cancel.is_canceled() {
            return Err(Fault::Canceled.into());
        }
        loop {
            let Some(span) = self.spans.get(self.span) else { return Ok(0) };
            let len = span.packed.end - span.packed.start;
            if self.at == len {
                self.span += 1;
                self.at = 0;
                continue;
            }
            if buf.is_empty() {
                return Ok(0);
            }
            let n = (len - self.at).min(buf.len() as u64) as usize;
            let got = self.set.borrow_mut().read(span.volume, span.packed.start + self.at, &mut buf[..n])?;
            if got == 0 {
                return Err(Fault::Truncated.into());
            }
            self.at += got as u64;
            return Ok(got);
        }
    }
}

/// A file as a [`RangeSource`] for the member map. Unlike [`crate::progressive::ImmutableFileSource`] it follows a
/// symbolic link to the archive, as every other extraction entry point does.
struct FileRange {
    file: Arc<File>,
    info: SourceInfo,
}

impl RangeSource for FileRange {
    fn info(&self) -> SourceInfo {
        self.info
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8], _: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
        let n = self.info.extent.saturating_sub(offset).min(buf.len() as u64) as usize;
        let count = loop {
            match read_at(&self.file, &mut buf[..n], offset) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                other => break other,
            }
        }
        .map_err(|cause| ProgressiveFailure::new(FailureKind::Input { operation: InputOperation::Read, cause }))?;
        if count == 0 && n != 0 {
            return Err(ProgressiveFailure::new(FailureKind::Truncated));
        }
        Ok(RangeRead::Filled { count })
    }

    fn backing_files(&self) -> &[File] {
        std::slice::from_ref(&self.file)
    }
}

/// The archive's volumes on disk, for the member map: volume 0 is `first`, later ones the names the map asks for.
pub(crate) struct FileVolumes {
    pub(crate) first: PathBuf,
}

impl VolumeSource for FileVolumes {
    fn volume(&mut self, request: &VolumeRequest, _: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
        let path = if request.index == 0 { self.first.clone() } else { PathBuf::from(&request.expected) };
        let open = |cause| ProgressiveFailure::new(FailureKind::Input { operation: InputOperation::Open, cause });
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound && request.index > 0 => return Ok(VolumeAnswer::Missing),
            Err(e) => return Err(open(e)),
        };
        let len = file.metadata().map_err(open)?.len();
        let info = SourceInfo {
            id: SourceId(u128::from(request.index) + 1),
            generation: 0,
            extent: len,
            length: SourceLength::Final(len),
        };
        Ok(VolumeAnswer::Ready(Box::new(FileRange { file: Arc::new(file), info })))
    }
}
