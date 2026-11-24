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

//! Streaming gzip, bzip2, xz and zstd encoders as `Write` adapters, so
//! `TarWriter::new(CompressedWriter::new(file, Compression::Gzip { level: 6 })?, opts)` writes `.tar.gz` and friends.

use std::io::{self, Write};

use bzip2::write::BzEncoder;
use flate2::GzBuilder;
use flate2::write::GzEncoder;
use liblzma::write::XzEncoder;
use zstd::stream::write::Encoder as ZstdEncoder;

/// Which compressor to put behind the tar writer. Levels follow each tool: gzip 0-9, bzip2 1-9, xz 0-9, zstd 1-22.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Compression {
    None,
    Gzip { level: u32 },
    Bzip2 { level: u32 },
    Xz { level: u32 },
    Zstd { level: i32 },
}

enum Inner<W: Write> {
    Plain(W),
    Gzip(GzEncoder<W>),
    Bzip2(BzEncoder<W>),
    Xz(XzEncoder<W>),
    Zstd(ZstdEncoder<'static, W>),
}

/// A `Write` that compresses into `W`. Call [`finish`](CompressedWriter::finish) to write the trailer; dropping
/// without it leaves a truncated stream.
pub struct CompressedWriter<W: Write>(Inner<W>);

fn bad(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, what.to_string())
}

impl<W: Write> CompressedWriter<W> {
    /// Wrap `sink`. Gzip writes the header GNU tar's `gzip` would (mtime 0, no name, OS Unix).
    pub fn new(sink: W, compression: Compression) -> io::Result<Self> {
        Ok(CompressedWriter(match compression {
            Compression::None => Inner::Plain(sink),
            Compression::Gzip { level } if level <= 9 => {
                Inner::Gzip(GzBuilder::new().mtime(0).operating_system(3).write(sink, flate2::Compression::new(level)))
            }
            Compression::Bzip2 { level } if (1..=9).contains(&level) => {
                Inner::Bzip2(BzEncoder::new(sink, bzip2::Compression::new(level)))
            }
            Compression::Xz { level } if level <= 9 => Inner::Xz(XzEncoder::new(sink, level)),
            Compression::Zstd { level } if (1..=22).contains(&level) => Inner::Zstd(ZstdEncoder::new(sink, level)?),
            _ => return Err(bad("compression level out of range")),
        }))
    }

    /// Flush the compressor, write its trailer and return the sink.
    pub fn finish(self) -> io::Result<W> {
        match self.0 {
            Inner::Plain(mut w) => {
                w.flush()?;
                Ok(w)
            }
            Inner::Gzip(e) => e.finish(),
            Inner::Bzip2(e) => e.finish(),
            Inner::Xz(e) => e.finish(),
            Inner::Zstd(e) => e.finish(),
        }
    }
}

impl<W: Write> Write for CompressedWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match &mut self.0 {
            Inner::Plain(w) => w.write(buf),
            Inner::Gzip(w) => w.write(buf),
            Inner::Bzip2(w) => w.write(buf),
            Inner::Xz(w) => w.write(buf),
            Inner::Zstd(w) => w.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.0 {
            Inner::Plain(w) => w.flush(),
            Inner::Gzip(w) => w.flush(),
            Inner::Bzip2(w) => w.flush(),
            Inner::Xz(w) => w.flush(),
            Inner::Zstd(w) => w.flush(),
        }
    }
}
