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
/// (no central directory to read): as 7-Zip lists such a set. A member whose sizes are only in a data descriptor
/// (flag bit 3) is passed over by finding its signed descriptor, as 7-Zip's FindDescriptor does: the first
/// `PK\x07\x08` whose compressed size equals the distance scanned (the ZIP64 form when the local header has ZIP64 sizes). The walk stops
/// at anything but a local header and after a member whose data runs past `len`; a streamed one cut off that way
/// gets the bytes left as its packed size and 0 as its size. Each byte is scanned at most once, so crafted input stays linear.
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
        let data_at = name_at + u64::from(h.name_len) + u64::from(h.extra_len);
        let streamed = h.flags & 0x08 != 0;
        let (crc32, packed, size, next) = if streamed {
            match find_descriptor(source, data_at, len, h.packed_size == u32::MAX || h.unpacked_size == u32::MAX)? {
                Some(d) => (d.crc32, d.packed, d.size, Some(data_at + d.packed + d.len)),
                // The descriptor is past the gap: as 7-Zip, the packed size is what is left before it, the size is
                // unknown (0), and the walk ends.
                None => (h.crc32, len.saturating_sub(data_at), 0, None),
            }
        } else {
            if h.packed_size == u32::MAX || h.unpacked_size == u32::MAX {
                break;
            }
            let packed = u64::from(h.packed_size);
            (h.crc32, packed, u64::from(h.unpacked_size), Some(data_at + packed))
        };
        let name = super::decode_name(&raw, h.flags & super::FLAG_UTF8 != 0)
            .unwrap_or_else(|_| String::from_utf8_lossy(&raw).into_owned());
        let mtime = super::dos_time(h.mod_time, h.mod_date);
        entries.push(super::ZipEntry {
            name,
            flags: h.flags,
            method: h.method,
            crc32,
            packed,
            size,
            local_at: at,
            mtime,
            mtime_origin: mtime.map(|_| crate::extract::MtimeOrigin::LocalWallClock),
            ..Default::default()
        });
        match next {
            Some(end) if end <= len => at = end,
            _ => break,
        }
    }
    Ok(entries)
}

/// A data descriptor found after a streamed member's data.
struct Descriptor {
    crc32: u32,
    packed: u64,
    size: u64,
    /// The descriptor's own length.
    len: u64,
}

/// The first signed data descriptor after `data_at` whose compressed size is the distance from `data_at` to it,
/// reading forward once in chunks.
/// `zip64`: the local header carries ZIP64 sizes, so the descriptor's sizes are 8 bytes each.
fn find_descriptor(
    source: &mut (impl Read + Seek),
    data_at: u64,
    len: u64,
    zip64: bool,
) -> io::Result<Option<Descriptor>> {
    const SIG: [u8; 4] = *b"PK\x07\x08";
    const CHUNK: usize = 64 << 10;
    const KEEP: usize = 23; // the longest descriptor (ZIP64, 24 bytes) less one byte
    if data_at >= len {
        return Ok(None);
    }
    let mut buf: Vec<u8> = Vec::with_capacity(CHUNK + KEEP);
    // `base` is the archive offset of buf[0]; `checked` how many leading positions have been tried.
    let (mut base, mut checked) = (data_at, 0usize);
    let mut read_at = data_at;
    source.seek(SeekFrom::Start(data_at))?;
    loop {
        let want = usize::try_from((len - read_at).min(CHUNK as u64)).unwrap_or(CHUNK);
        let old = buf.len();
        buf.resize(old + want, 0);
        source.read_exact(&mut buf[old..])?;
        read_at += want as u64;
        let at_end = read_at >= len;
        while checked + 4 <= buf.len() {
            // A candidate needs its fields in the buffer, unless the archive ends first.
            if !at_end && checked + KEEP >= buf.len() {
                break;
            }
            let p = checked;
            checked += 1;
            if buf[p..p + 4] != SIG {
                continue;
            }
            let distance = base + p as u64 - data_at;
            let field = |at: usize, n: usize| buf.get(p + at..p + at + n);
            let crc = field(4, 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()));
            if let (false, Some(crc32), Some(c), Some(u)) = (zip64, crc, field(8, 4), field(12, 4)) {
                let packed = u64::from(u32::from_le_bytes(c.try_into().unwrap()));
                if packed == distance {
                    let size = u64::from(u32::from_le_bytes(u.try_into().unwrap()));
                    return Ok(Some(Descriptor { crc32, packed, size, len: 16 }));
                }
            }
            if let (true, Some(crc32), Some(c), Some(u)) = (zip64, crc, field(8, 8), field(16, 8)) {
                let packed = u64::from_le_bytes(c.try_into().unwrap());
                if packed == distance {
                    let size = u64::from_le_bytes(u.try_into().unwrap());
                    return Ok(Some(Descriptor { crc32, packed, size, len: 24 }));
                }
            }
        }
        if at_end {
            return Ok(None);
        }
        // Keep the positions not yet tried.
        buf.drain(..checked);
        base += checked as u64;
        checked = 0;
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

    #[test]
    fn descriptors_are_found_across_chunks_and_decoys() {
        use std::io::Cursor;
        // 100000 bytes of data full of decoy signatures with wrong sizes, then the real descriptor.
        let mut data = Vec::new();
        while data.len() < 100_000 {
            data.extend(b"PK\x07\x08\0\0\0\0\x05\0\0\0\x05\0\0\0xx");
        }
        data.truncate(100_000);
        let mut bytes = vec![0u8; 10];
        bytes.extend(&data);
        bytes.extend(b"PK\x07\x08");
        bytes.extend(7u32.to_le_bytes());
        bytes.extend(100_000u32.to_le_bytes());
        bytes.extend(123_456u32.to_le_bytes());
        let len = bytes.len() as u64;
        let d = find_descriptor(&mut Cursor::new(&bytes), 10, len, false).unwrap().unwrap();
        assert_eq!((d.crc32, d.packed, d.size, d.len), (7, 100_000, 123_456, 16));
        // the ZIP64 form
        let mut z = vec![1u8; 40];
        z.extend(b"PK\x07\x08");
        z.extend(9u32.to_le_bytes());
        z.extend(40u64.to_le_bytes());
        z.extend(41u64.to_le_bytes());
        let d = find_descriptor(&mut Cursor::new(&z), 0, z.len() as u64, true).unwrap().unwrap();
        assert_eq!((d.crc32, d.packed, d.size, d.len), (9, 40, 41, 24));
        // none before the end
        assert!(find_descriptor(&mut Cursor::new(&data), 0, data.len() as u64, false).unwrap().is_none());
    }
}
