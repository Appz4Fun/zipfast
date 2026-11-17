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
//! archive is the pieces concatenated, which is how 7-Zip opens it. Pieces count up keeping their width, growing
//! it past all nines (`.999` → `.1000`).
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// The most volumes a set may have.
const MAX_VOLUMES: usize = 100_000;
/// How many names past a gap are probed for a later piece, which makes the gap a missing volume.
const GAP_PROBE: u64 = 16;

/// The pieces of a byte-split set read as one file. Only one piece is held open at a time.
pub(crate) struct ByteSplit {
    /// Each volume and the archive offset it starts at, in order.
    volumes: Vec<(PathBuf, u64)>,
    /// The piece currently open.
    open: Option<(usize, File)>,
    /// The first missing piece, when a later one exists: the set is read up to the gap.
    missing: Option<PathBuf>,
    len: u64,
    pos: u64,
}

impl ByteSplit {
    /// The set starting at `first` when it is the first volume of a byte-split set of two or more pieces: its name
    /// ends in a dot and digits counting from 1 (`.001`) and the next piece exists. None otherwise. A gap followed
    /// by a later piece ends the set at the gap, with [`Self::missing`] naming the absent piece.
    pub(crate) fn open(first: &Path) -> crate::error::Result<Option<Self>> {
        if !is_split_set(first) {
            return Ok(None);
        }
        let mut volumes = Vec::new();
        let mut len = 0u64;
        let mut path = first.to_path_buf();
        let mut missing = None;
        loop {
            let size = std::fs::metadata(&path)?.len();
            volumes.push((path.clone(), len));
            len = len.checked_add(size).ok_or_else(|| io::Error::other("split archive size overflows"))?;
            let next = next_piece(&path).expect("a piece name ends in digits");
            if !next.is_file() {
                let mut probe = next.clone();
                for _ in 0..GAP_PROBE {
                    probe = next_piece(&probe).expect("digits");
                    if probe.is_file() {
                        missing = Some(next);
                        break;
                    }
                }
                break;
            }
            if volumes.len() >= MAX_VOLUMES {
                return Err(crate::error::Error::Unsupported("byte-split ZIP has too many pieces".into()));
            }
            path = next;
        }
        Ok(Some(Self { volumes, open: None, missing, len, pos: 0 }))
    }

    pub(crate) fn len(&self) -> u64 {
        self.len
    }

    /// The first absent piece of a set with a gap.
    pub(crate) fn missing(&self) -> Option<&Path> {
        self.missing.as_deref()
    }

    pub(crate) fn paths(&self) -> impl Iterator<Item = &Path> {
        self.volumes.iter().map(|(p, _)| p.as_path())
    }
}

/// The piece after `path`: its trailing digits counted up, keeping their width and growing it past all nines
/// (`.999` → `.1000`). None when the name does not end in `.` and digits.
fn next_piece(path: &Path) -> Option<PathBuf> {
    let name = path.file_name()?.to_str()?;
    let digits = name.bytes().rev().take_while(u8::is_ascii_digit).count();
    let start = name.len() - digits;
    if !(1..=18).contains(&digits) || !name[..start].ends_with('.') {
        return None;
    }
    let n: u64 = name[start..].parse().ok()?;
    Some(path.with_file_name(format!("{}{:0width$}", &name[..start], n + 1, width = digits)))
}

/// Whether `first` is the first piece of a set of two or more (counting a set whose second piece is missing).
pub(crate) fn is_split_set(first: &Path) -> bool {
    is_first_piece(first) && later_piece_exists(first)
}

/// Whether a piece after `path` exists: the next one, or one up to [`GAP_PROBE`] names further past a gap.
fn later_piece_exists(path: &Path) -> bool {
    let mut probe = path.to_path_buf();
    (0..=GAP_PROBE).any(|_| {
        probe = next_piece(&probe).expect("a piece name ends in digits");
        probe.is_file()
    })
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
        let offset = self.pos - self.volumes[index].1;
        if self.open.as_ref().is_none_or(|(i, _)| *i != index) {
            self.open = None;
            let path = &self.volumes[index].0;
            let file = File::open(path).map_err(|e| {
                if e.kind() == io::ErrorKind::NotFound {
                    io::Error::new(e.kind(), format!("missing volume {}", path.display()))
                } else {
                    e
                }
            })?;
            self.open = Some((index, file));
        }
        let file = &mut self.open.as_mut().expect("opened").1;
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

/// The members whose local headers lie before `len`, walking from offset 0, for a set cut short by a missing piece
/// (no central directory to read): as 7-Zip lists such a set. The walk stops at anything but a local header, at a
/// header whose sizes are only in a data descriptor, and after a member whose data runs past `len`.
pub(crate) fn scan_local_headers(
    source: &mut (impl Read + Seek),
    len: u64,
) -> crate::error::Result<Vec<super::ZipEntry>> {
    use zip_container::{LOCAL_HEADER_LEN, LocalHeader};
    let mut entries = Vec::new();
    let mut at = 0u64;
    while at + LOCAL_HEADER_LEN as u64 <= len && entries.len() < 1_000_000 {
        let mut head = [0u8; LOCAL_HEADER_LEN];
        source.seek(SeekFrom::Start(at))?;
        source.read_exact(&mut head)?;
        let Ok(h) = LocalHeader::parse(&head) else { break };
        let name_at = at + LOCAL_HEADER_LEN as u64;
        if name_at + u64::from(h.name_len) > len {
            break;
        }
        let mut raw = vec![0u8; usize::from(h.name_len)];
        source.read_exact(&mut raw)?;
        let descriptor = h.flags & 0x08 != 0 && h.packed_size == 0;
        if descriptor || h.packed_size == u32::MAX || h.unpacked_size == u32::MAX {
            break;
        }
        let name = super::decode_name(&raw, h.flags & super::FLAG_UTF8 != 0)
            .unwrap_or_else(|_| String::from_utf8_lossy(&raw).into_owned());
        let mtime = super::dos_time(h.mod_time, h.mod_date);
        entries.push(super::ZipEntry {
            name,
            flags: h.flags,
            method: h.method,
            crc32: h.crc32,
            packed: u64::from(h.packed_size),
            size: u64::from(h.unpacked_size),
            local_at: at,
            mtime,
            mtime_origin: mtime.map(|_| crate::extract::MtimeOrigin::LocalWallClock),
            ..Default::default()
        });
        let end = name_at + u64::from(h.name_len) + u64::from(h.extra_len) + u64::from(h.packed_size);
        if end > len {
            break;
        }
        at = end;
    }
    Ok(entries)
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
        let mut split = ByteSplit::open(&dir.path().join("x.zip.001")).unwrap().unwrap();
        assert_eq!((split.len(), split.paths().count()), (1000, 4));
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
        // A missing middle piece ends the set at the gap and is named.
        std::fs::remove_file(dir.path().join("x.zip.002")).unwrap();
        std::fs::write(dir.path().join("x.zip.002"), b"").unwrap();
        std::fs::remove_file(dir.path().join("x.zip.003")).unwrap();
        let split = ByteSplit::open(&dir.path().join("x.zip.001")).unwrap().unwrap();
        assert!(split.missing().unwrap().ends_with("x.zip.003"));
        assert_eq!((split.len(), split.paths().count()), (300, 2));
    }

    #[test]
    fn piece_names_grow_past_all_nines() {
        assert_eq!(next_piece(Path::new("d/a.zip.009")).unwrap(), Path::new("d/a.zip.010"));
        assert_eq!(next_piece(Path::new("d/a.zip.999")).unwrap(), Path::new("d/a.zip.1000"));
        assert!(next_piece(Path::new("a.zip")).is_none());
    }
}
