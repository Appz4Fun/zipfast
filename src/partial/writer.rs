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
/// same member from an alt. Bytes are buffered and committed as [`PartialFile::fill`] transactions of at most
/// `PartialLimits::fill_bytes` each, so memory stays bounded whatever the range size.
///
/// Call [`finish`](Self::finish) to commit the last buffered bytes and get the combined result. Dropping the writer
/// without finishing discards the bytes still buffered; everything committed before stays committed. An error from
/// [`io::Write::write`] or [`io::Write::flush`] carries the message of the typed [`PartialError`], which `finish` then returns; the writer
/// accepts no more bytes after an error.
pub struct FillWriter<'a> {
    file: &'a mut PartialFile,
    /// Output offset of `buffer[0]`.
    at: u64,
    buffer: Vec<u8>,
    chunk: usize,
    applied: Vec<Range<u64>>,
    last: Option<FillResult>,
    failed: Option<PartialError>,
}

impl<'a> FillWriter<'a> {
    pub(super) fn new(file: &'a mut PartialFile, offset: u64) -> PartialResult<Self> {
        let chunk = file.core.budget.limits.value(PartialResource::FillBytes).min(usize::MAX as u64) as usize;
        if chunk == 0 {
            return Err(err(PartialErrorKind::InvalidOptions));
        }
        let buffer = file.core.budget.vector(chunk)?;
        Ok(Self { file, at: offset, buffer, chunk, applied: Vec::new(), last: None, failed: None })
    }
    /// The output offset the next written byte lands at.
    pub fn position(&self) -> u64 {
        self.at + self.buffer.len() as u64
    }
    fn commit(&mut self) -> PartialResult<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let result = self.file.fill(self.at, &self.buffer)?;
        for range in &result.applied {
            match self.applied.last_mut() {
                Some(last) if last.end == range.start => last.end = range.end,
                _ => self.applied.push(range.clone()),
            }
        }
        self.at += self.buffer.len() as u64;
        self.buffer.clear();
        self.last = Some(result);
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
    /// Commits what is still buffered and returns the last transaction's result with `applied` covering every range
    /// this writer filled. A writer that never received bytes returns the current state with nothing applied.
    pub fn finish(mut self) -> PartialResult<FillResult> {
        if let Some(error) = self.failed.take() {
            return Err(error);
        }
        self.commit()?;
        let mut result = match self.last.take() {
            Some(result) => result,
            None => self.file.fill(self.at, &[])?,
        };
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

impl PartialFile {
    /// A [`FillWriter`] that fills plaintext starting at output `offset`, for streaming a large range (for example
    /// `[offset_reached, end)` from an alt) without holding it in memory.
    pub fn fill_writer(&mut self, offset: u64) -> PartialResult<FillWriter<'_>> {
        FillWriter::new(self, offset)
    }
    /// Fills exactly `len` plaintext bytes at output `offset` read from `reader`, in transactions of at most
    /// `PartialLimits::fill_bytes`. A read error or an early end of input is [`PartialErrorKind::FillRead`]; ranges
    /// committed before it stay filled, and the error's `output` says how far the fill got.
    pub fn fill_from<R: io::Read>(&mut self, offset: u64, len: u64, reader: &mut R) -> PartialResult<FillResult> {
        offset.checked_add(len).ok_or_else(|| err(PartialErrorKind::InvalidOptions))?;
        let mut writer = self.fill_writer(offset)?;
        let mut left = len;
        while left > 0 {
            canceled(&writer.file.core.control)?;
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
                Ok(n) => n,
                Err(cause) => {
                    writer.buffer.truncate(start);
                    let done = writer.at - offset;
                    let mut error = err(PartialErrorKind::FillRead(cause));
                    error.output = Some(crate::progressive::OutputRange { offset, attempted: len, completed: done });
                    return Err(error);
                }
            };
            writer.buffer.truncate(start + n);
            left -= n as u64;
            if writer.buffer.len() == writer.chunk {
                writer.commit()?;
            }
        }
        writer.finish()
    }
}
