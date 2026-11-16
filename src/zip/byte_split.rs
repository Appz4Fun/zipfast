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

//! A raw byte-split ZIP (`name.zip.001`, `name.zip.002`, ...): one archive cut into pieces at arbitrary byte offsets,
//! as `7z a -v` or `split` writes it. Unlike an Info-ZIP spanned set (`.z01`), the pieces carry no disk numbers; the
//! archive is the pieces concatenated, which is how 7-Zip opens it. Volumes are named by the 7z split rule
//! ([`crate::map::next_volume_name`]).
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// The most volumes a set may have.
const MAX_VOLUMES: usize = 100_000;

/// The pieces of a byte-split set read as one file.
pub(crate) struct ByteSplit {
    /// Each volume and the archive offset it starts at, in order.
    volumes: Vec<(File, u64)>,
    len: u64,
    pos: u64,
}

impl ByteSplit {
    /// The set starting at `first` when it is the first volume of a byte-split set of two or more pieces: its name
    /// ends in a dot and digits counting from 1 (`.001`) and the next piece exists. None otherwise.
    pub(crate) fn open(first: &Path) -> io::Result<Option<(Self, Vec<PathBuf>)>> {
        if !is_split_set(first) {
            return Ok(None);
        }
        let mut paths = vec![first.to_path_buf()];
        let mut volumes = Vec::new();
        let mut len = 0u64;
        loop {
            let path = paths.last().expect("first");
            let file = File::open(path)?;
            let size = file.metadata()?.len();
            volumes.push((file, len));
            len = len.checked_add(size).ok_or_else(|| io::Error::other("split archive size overflows"))?;
            let next = PathBuf::from(crate::map::next_volume_name(path.as_os_str()));
            if !next.is_file() || volumes.len() >= MAX_VOLUMES {
                break;
            }
            paths.push(next);
        }
        Ok(Some((Self { volumes, len, pos: 0 }, paths)))
    }

    pub(crate) fn len(&self) -> u64 {
        self.len
    }
}

/// Whether `first` is the first piece of a set of two or more.
pub(crate) fn is_split_set(first: &Path) -> bool {
    is_first_piece(first) && Path::new(&crate::map::next_volume_name(first.as_os_str())).is_file()
}

/// Whether the file name ends in `.` and digits whose value is 1 (`x.zip.001`, `x.zip.01`).
fn is_first_piece(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else { return false };
    let digits = name.bytes().rev().take_while(u8::is_ascii_digit).count();
    let start = name.len() - digits;
    (2..=18).contains(&digits) && name[..start].ends_with('.') && name[start..].parse::<u64>() == Ok(1)
}

impl Read for ByteSplit {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.pos >= self.len {
            return Ok(0);
        }
        let index = self.volumes.partition_point(|(_, start)| *start <= self.pos) - 1;
        let end = self.volumes.get(index + 1).map_or(self.len, |(_, start)| *start);
        let (file, start) = &mut self.volumes[index];
        let offset = self.pos - *start;
        file.seek(SeekFrom::Start(offset))?;
        let want = buf.len().min(usize::try_from(end - self.pos).unwrap_or(usize::MAX));
        let n = file.read(&mut buf[..want])?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "split archive volume shrank"));
        }
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for ByteSplit {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let target = match pos {
            SeekFrom::Start(at) => Some(at),
            SeekFrom::End(delta) => self.len.checked_add_signed(delta),
            SeekFrom::Current(delta) => self.pos.checked_add_signed(delta),
        };
        self.pos = target.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek before the start"))?;
        Ok(self.pos)
    }
}

/// The bytes an [`super::Archive`] reads: one file, or the pieces of a byte-split set.
pub(crate) enum ArchiveSource {
    File(File),
    Split(ByteSplit),
}

impl Read for ArchiveSource {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::File(f) => f.read(buf),
            Self::Split(s) => s.read(buf),
        }
    }
}

impl Seek for ArchiveSource {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match self {
            Self::File(f) => f.seek(pos),
            Self::Split(s) => s.seek(pos),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_piece_names() {
        for (name, want) in [
            ("a.zip.001", true),
            ("a.zip.01", true),
            ("a.ZIP.0001", true),
            ("a.zip.002", false),
            ("a.zip", false),
            ("a.zip.1", false),
            ("a001", false),
        ] {
            assert_eq!(is_first_piece(Path::new(name)), want, "{name}");
        }
    }

    #[test]
    fn reads_across_pieces() {
        let dir = tempfile::tempdir().unwrap();
        let data: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
        for (i, chunk) in data.chunks(300).enumerate() {
            std::fs::write(dir.path().join(format!("x.zip.{:03}", i + 1)), chunk).unwrap();
        }
        let (mut split, paths) = ByteSplit::open(&dir.path().join("x.zip.001")).unwrap().unwrap();
        assert_eq!((split.len(), paths.len()), (1000, 4));
        let mut all = Vec::new();
        split.read_to_end(&mut all).unwrap();
        assert_eq!(all, data);
        split.seek(SeekFrom::Start(290)).unwrap();
        let mut buf = [0; 20];
        split.read_exact(&mut buf).unwrap();
        assert_eq!(buf[..], data[290..310]);
        split.seek(SeekFrom::End(-5)).unwrap();
        let mut tail = Vec::new();
        split.read_to_end(&mut tail).unwrap();
        assert_eq!(tail, data[995..]);
        // A lone `.001` is not a set.
        let lone = tempfile::tempdir().unwrap();
        std::fs::write(lone.path().join("y.zip.001"), b"PK").unwrap();
        assert!(ByteSplit::open(&lone.path().join("y.zip.001")).unwrap().is_none());
    }
}
