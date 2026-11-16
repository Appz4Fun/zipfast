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

//! Streaming plaintext fills for ranges larger than one fill transaction.

use super::*;
use std::io;

/// Streams plaintext into a [`PartialFile`] from a starting output offset, for example the output of extracting the
/// same member from an alt. Bytes are buffered `PartialLimits::fill_bytes` at a time, so memory stays bounded
/// whatever the range size. Full buffers are written into a group commit like the extraction's own writes: one
/// durable commit per `PartialLimits::group_commit_bytes` (or `group_commit_interval`), not one per buffer. With
/// `group_commit_bytes` 0 each buffer is its own [`PartialFile::fill`] transaction.
///
/// Call [`finish`](Self::finish) to write the last buffered bytes, commit, and get the combined result. Dropping the
/// writer without finishing discards the bytes still buffered; bytes it already handed over are committed with the
/// handle's next operation (or when its last owner drops). An error from [`io::Write::write`] or
/// [`io::Write::flush`] carries the message of the typed [`PartialError`], which `finish` then returns; the writer
/// accepts no more bytes after an error. On an error the writer commits what it wrote before, if it can, and
/// [`position`](Self::position) is then the end of the committed bytes.
pub struct FillWriter<'a> {
    file: &'a mut PartialFile,
    /// Output offset of `buffer[0]`: the end of the bytes handed to the handle.
    at: u64,
    /// End of the bytes known committed.
    committed: u64,
    buffer: Vec<u8>,
    chunk: usize,
    applied: Vec<Range<u64>>,
    failed: Option<PartialError>,
    /// Charge for the part of the buffer above 1 MiB.
    _lease: Option<crate::progressive::Lease>,
}

impl<'a> FillWriter<'a> {
    pub(super) fn new(file: &'a mut PartialFile, offset: u64) -> PartialResult<Self> {
        let chunk = file.core.budget.limits.value(PartialResource::FillBytes).min(usize::MAX as u64) as usize;
        if chunk == 0 {
            return Err(err(PartialErrorKind::InvalidOptions));
        }
        // The first MiB is not charged to the cumulative metadata budget: the buffer is freed with the writer, the
        // same bound as a caller slice passed to `fill`. A larger `fill_bytes` leases the rest while the writer lives.
        let lease = match chunk.saturating_sub(1 << 20) {
            0 => None,
            extra => Some(file.core.budget.metadata_lease(extra as u64)?),
        };
        let mut buffer = Vec::new();
        buffer.try_reserve_exact(chunk).map_err(|_| err(PartialErrorKind::InvalidOptions))?;
        Ok(Self {
            file,
            at: offset,
            committed: offset,
            buffer,
            chunk,
            applied: Vec::new(),
            failed: None,
            _lease: lease,
        })
    }
    /// The output offset the next written byte lands at. After an error it is the end of the committed bytes, the
    /// point to resume from.
    pub fn position(&self) -> u64 {
        if self.failed.is_some() { self.committed } else { self.at + self.buffer.len() as u64 }
    }
    fn commit(&mut self) -> PartialResult<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let (applied, committed) = match self.file.core.fill_grouped(self.at, &self.buffer) {
            Ok(result) => result,
            Err(error) => {
                // Commit what earlier buffers wrote, so the caller can resume after it.
                if self.file.core.commit_group().is_ok() {
                    self.committed = self.at;
                }
                return Err(error);
            }
        };
        for range in &applied {
            match self.applied.last_mut() {
                Some(last) if last.end == range.start => last.end = range.end,
                _ => self.applied.push(range.clone()),
            }
        }
        self.at += self.buffer.len() as u64;
        self.buffer.clear();
        if committed {
            self.committed = self.at;
        }
        Ok(())
    }
    /// Commits through `io::Write`: keeps the typed error for `finish` and poisons the writer.
    fn commit_io(&mut self) -> io::Result<()> {
        self.commit().map_err(|error| {
            let io = io::Error::other(error.to_string());
            self.failed = Some(error);
            io
        })
    }
    /// Writes what is still buffered, commits, and returns the committed result with `applied` covering every
    /// range this writer filled. A writer that never received bytes returns the current state with nothing applied.
    pub fn finish(mut self) -> PartialResult<FillResult> {
        if let Some(error) = self.failed.take() {
            return Err(error);
        }
        self.commit()?;
        let mut result = self.file.core.commit_fills()?;
        result.applied = std::mem::take(&mut self.applied);
        Ok(result)
    }
}

impl io::Write for FillWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.failed.is_some() {
            return Err(io::Error::other("an earlier fill of this writer failed"));
        }
        let n = bytes.len().min(self.chunk - self.buffer.len());
        self.buffer.extend_from_slice(&bytes[..n]);
        if self.buffer.len() == self.chunk {
            self.commit_io()?;
        }
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.failed.is_some() {
            return Err(io::Error::other("an earlier fill of this writer failed"));
        }
        self.commit_io()
    }
}

/// Sets how far a streamed fill got on an error that does not say already.
fn progress(mut error: PartialError, offset: u64, attempted: u64, completed: u64) -> PartialError {
    error.output.get_or_insert(crate::progressive::OutputRange { offset, attempted, completed });
    error
}

impl PartialFile {
    /// A [`FillWriter`] that fills plaintext starting at output `offset`, for streaming a large range (for example
    /// `[offset_reached, end)` from an alt) without holding it in memory.
    pub fn fill_writer(&mut self, offset: u64) -> PartialResult<FillWriter<'_>> {
        FillWriter::new(self, offset)
    }
    /// Fills exactly `len` plaintext bytes at output `offset` read from `reader`, buffered `PartialLimits::fill_bytes`
    /// at a time and committed as a [`FillWriter`] commits. A read error or an early end of input is
    /// [`PartialErrorKind::FillRead`]. On any error, ranges committed before it stay filled (the writer commits what
    /// it wrote, if it can) and the error's `output` says how far the committed fill got.
    pub fn fill_from<R: io::Read>(&mut self, offset: u64, len: u64, reader: &mut R) -> PartialResult<FillResult> {
        offset.checked_add(len).ok_or_else(|| err(PartialErrorKind::InvalidOptions))?;
        let mut writer = self.fill_writer(offset)?;
        let mut left = len;
        while left > 0 {
            let done = writer.committed - offset;
            canceled(&writer.file.core.control).map_err(|e| progress(e, offset, len, done))?;
            let room = (writer.chunk - writer.buffer.len()).min(left.min(usize::MAX as u64) as usize);
            let start = writer.buffer.len();
            writer.buffer.resize(start + room, 0);
            let read = loop {
                match reader.read(&mut writer.buffer[start..]) {
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    other => break other,
                }
            };
            let n = match read {
                Ok(0) => Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                Ok(n) => Ok(n),
                Err(e) => Err(e),
            };
            let n = match n {
                Ok(n) if n > room => Err(io::Error::new(io::ErrorKind::InvalidData, "reader returned more than asked")),
                other => other,
            };
            let n = match n {
                Ok(n) => n,
                Err(cause) => {
                    writer.buffer.truncate(start);
                    // Commit what was written before the input failed.
                    if writer.file.core.commit_group().is_ok() {
                        writer.committed = writer.at;
                    }
                    let done = writer.committed - offset;
                    let mut error = err(PartialErrorKind::FillRead(cause));
                    error.output = Some(crate::progressive::OutputRange { offset, attempted: len, completed: done });
                    return Err(error);
                }
            };
            writer.buffer.truncate(start + n);
            left -= n as u64;
            if writer.buffer.len() == writer.chunk {
                writer.commit().map_err(|e| progress(e, offset, len, writer.committed - offset))?;
            }
        }
        let fill = |writer: &mut FillWriter<'_>| -> PartialResult<FillResult> {
            writer.commit()?;
            let mut result = writer.file.core.commit_fills()?;
            result.applied = std::mem::take(&mut writer.applied);
            Ok(result)
        };
        fill(&mut writer).map_err(|e| progress(e, offset, len, writer.committed - offset))
    }
}
