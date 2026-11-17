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

//! An Info-ZIP spanned set (`name.z01`, `name.z02`, ..., `name.zip`): one archive whose disks are numbered from 0 in
//! that order, the end record and (usually) the central directory in the `.zip`. Every offset is relative to the
//! disk it names, and data runs on from one disk into the next, so the disks concatenated are the archive with each
//! (disk, offset) at the disk's start plus the offset. 7-Zip opens such a set from its `.zip` the same way.
//!
//! Volume names follow [`crate::map::zip_split::split_volume_name`], the names zipfast writes: `.z01` to `.z99`, then
//! `.z100` and on, upper case when the `.zip`'s extension is.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::map::zip_split::{find_end, split_volume_name};

const END_LEN: usize = 22;
const LOCATOR_LEN: usize = 20;
const END64_LEN: usize = 56;
/// The end record, a comment of up to 64 KiB, and the ZIP64 locator before it.
const TAIL_MAX: u64 = (END_LEN + u16::MAX as usize + LOCATOR_LEN) as u64;
/// The most disks a set may have.
const MAX_DISKS: u32 = 100_000;
/// How many names past an absent numbered volume are probed for a later one, when the `.zip` is missing too.
const GAP_PROBE: u32 = 16;
/// How much of a `.zip`'s end is read first for its end record: enough unless it has a long comment.
const TAIL_FIRST: u64 = 4096;
/// The spanning signature a set's first volume starts with; offsets in disk 0 count it.
pub(crate) const SPLIT_MARKER: &[u8; 4] = b"PK\x07\x08";

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}
fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().expect("4 bytes"))
}
fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().expect("8 bytes"))
}

/// The `.zip` of the set `path` belongs to: `path` itself when it is a regular `.zip` (whether it is a set's last
/// volume is for its end record and the numbered volumes beside it to say: its `.z01` may be the one missing), or
/// the `.zip` beside a `.z01` given instead. None for anything else.
pub(crate) fn last_volume(path: &Path) -> Option<PathBuf> {
    let ext = path.extension()?.to_str()?;
    if ext.eq_ignore_ascii_case("zip") {
        is_regular(path).then(|| path.to_path_buf())
    } else if ext.eq_ignore_ascii_case("z01") {
        let last = Path::new(&split_volume_name(path.as_os_str(), 0, true)).to_path_buf();
        is_regular(&last).then_some(last)
    } else {
        None
    }
}

/// The volumes present of a set whose `.zip` is missing, opened from its `.z01`: there is no end record, so the set
/// can only be read by walking its local headers, as 7-Zip does.
pub(crate) struct Headless {
    /// `.z01`, `.z02`, ... up to the first absent one.
    pub volumes: Vec<PathBuf>,
    /// The first absent volume: the `.zip`, unless a later numbered volume shows a numbered one is missing first.
    pub missing: PathBuf,
}

impl Headless {
    /// The set whose `.z01` is `path` when its `.zip` is absent (or not a regular file). The `.z01` must be a regular
    /// file starting with the spanning signature, or with a local header and no end record ending at its end (a
    /// lone archive named `.z01` stays one).
    pub(crate) fn open(path: &Path) -> Option<Self> {
        let ext = path.extension()?.to_str()?;
        if !ext.eq_ignore_ascii_case("z01") {
            return None;
        }
        let last = PathBuf::from(split_volume_name(path.as_os_str(), 0, true));
        if is_regular(&last) {
            return None;
        }
        let mut file = open_regular(path).ok()?;
        let mut head = [0u8; 4];
        file.read_exact(&mut head).ok()?;
        if head != *SPLIT_MARKER {
            if head != *b"PK\x03\x04" {
                return None;
            }
            let len = file.metadata().ok()?.len();
            let span = len.min(TAIL_MAX);
            let mut tail = vec![0u8; span as usize];
            file.seek(SeekFrom::Start(len - span)).ok()?;
            file.read_exact(&mut tail).ok()?;
            if find_end(&tail).is_some() {
                return None;
            }
        }
        let name = |i: u32| PathBuf::from(split_volume_name(path.as_os_str(), i, false));
        let mut volumes = vec![path.to_path_buf()];
        while volumes.len() < MAX_DISKS as usize {
            let next = name(volumes.len() as u32);
            if !is_regular(&next) {
                break;
            }
            volumes.push(next);
        }
        let gap = volumes.len() as u32;
        // a later numbered volume makes the first absent one the gap; otherwise the set ends at its absent `.zip`
        let later = (gap + 1..gap.saturating_add(GAP_PROBE).min(MAX_DISKS)).any(|i| is_regular(&name(i)));
        Some(Self { volumes, missing: if later { name(gap) } else { last } })
    }
}

/// Whether `path` is a regular file (following a symbolic link): a FIFO, device or folder where a volume should be
/// counts as missing.
pub(crate) fn is_regular(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.is_file())
}

/// Opens `path` for reading only when it is a regular file, checked on the open handle. On Unix the open doesn't
/// wait: a FIFO with no writer, put where a volume should be, is refused instead of blocking the open.
pub(crate) fn open_regular(path: &Path) -> io::Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("{} is not a regular file", path.display())));
    }
    Ok(file)
}

/// Whether `path` is the `.zip` (or the `.z01`) of a spanned set: an end record naming more than one disk (a lone
/// `.zip` with a stray `.z01` beside it stays a lone archive), or a `.z01` whose `.zip` is missing ([`Headless`]).
pub(crate) fn is_spanned(path: &Path) -> bool {
    matches!(Spanned::open(path), Ok(Some(_))) || Headless::open(path).is_some()
}

/// A spanned set, found from its end record.
pub(crate) struct Spanned {
    /// Every disk's volume, in order, the `.zip` last.
    pub volumes: Vec<PathBuf>,
    /// The first absent volume: the set is read only up to it.
    pub missing: Option<PathBuf>,
    /// The classic end record's offset in the last volume.
    pub end_at: u64,
    /// The disk the central directory starts on.
    pub directory_disk: u32,
    /// The ZIP64 end record's disk and offset, from the locator.
    pub zip64: Option<(u32, u64)>,
}

impl Spanned {
    /// The set whose `.zip` (or `.z01`) is `path`, or None when `path` is not one: no end record ending at its end
    /// (trailing bytes, damage), or one naming a single disk (a lone archive, whether or not a `.z01` is beside it).
    /// Each of those is left to the single-file reader. Only once the end record names more than one disk is a fault
    /// the set's; the `.z01` and other numbered volumes may then be missing, but not all of them.
    pub(crate) fn open(path: &Path) -> Result<Option<Self>> {
        let Some(last) = last_volume(path) else { return Ok(None) };
        let Ok(mut file) = open_regular(&last) else { return Ok(None) };
        let len = file.metadata()?.len();
        // most archives end with a short (or no) comment: read a little first, the longest tail only when needed
        let mut span = len.min(TAIL_FIRST);
        let mut tail = vec![0u8; span as usize];
        file.seek(SeekFrom::Start(len - span))?;
        file.read_exact(&mut tail)?;
        let mut found = find_end(&tail);
        // past a short window, also when the ZIP64 locator before the record could be cut off
        if found.is_none_or(|at| at < LOCATOR_LEN) && len > span {
            span = len.min(TAIL_MAX);
            tail = vec![0u8; span as usize];
            file.seek(SeekFrom::Start(len - span))?;
            file.read_exact(&mut tail)?;
            found = find_end(&tail);
        }
        let Some(at) = found else { return Ok(None) };
        let record = &tail[at..at + END_LEN];
        let locator = at
            .checked_sub(LOCATOR_LEN)
            .map(|l| &tail[l..at])
            .filter(|l| l.starts_with(b"PK\x06\x07"))
            .map(|l| ((le32(l, 4), le64(l, 8)), le32(l, 16)));
        let disk = match (le16(record, 4), locator) {
            (0xffff, Some((_, total))) if total > 1 => total - 1,
            // a ZIP64 archive of one disk, or a locator that names no disk count: not a set
            (0xffff, _) => return Ok(None),
            (disk, _) => u32::from(disk),
        };
        if disk == 0 {
            return Ok(None);
        }
        if disk >= MAX_DISKS {
            return Err(Error::Unsupported("split ZIP has too many volumes".into()));
        }
        if locator.is_some_and(|((vol, _), total)| u64::from(total) != u64::from(disk) + 1 || vol > disk) {
            return Err(Error::Corrupt("ZIP64 end locator disk count"));
        }
        let mut volumes: Vec<PathBuf> =
            (0..disk).map(|i| PathBuf::from(split_volume_name(last.as_os_str(), i, false))).collect();
        volumes.push(last.clone());
        // A `.zip` with no numbered volume beside it is no set to recover: it stays a lone file, so the checked route
        // still rejects its multi-disk end record instead of handing it to the split reader.
        if !volumes[..disk as usize].iter().any(|v| is_regular(v)) {
            return Ok(None);
        }
        let missing = volumes.iter().find(|v| !is_regular(v)).cloned();
        let zip64 = locator.map(|(at, _)| at);
        let directory_disk = match (le16(record, 6), zip64) {
            (0xffff, Some((vol, off))) => {
                let path = &volumes[vol as usize];
                let mut end = [0u8; END64_LEN];
                let read = open_regular(path).and_then(|mut f| {
                    f.seek(SeekFrom::Start(off))?;
                    f.read_exact(&mut end)
                });
                match read {
                    Ok(()) if end.starts_with(b"PK\x06\x06") => le32(&end, 20),
                    Ok(()) => return Err(Error::Corrupt("ZIP64 end record")),
                    Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(Error::MissingVolume(path.clone())),
                    Err(e) => return Err(e.into()),
                }
            }
            (0xffff, None) => return Err(Error::Corrupt("ZIP64 end locator")),
            (d, _) => u32::from(d),
        };
        if directory_disk > disk {
            return Err(Error::Corrupt("central directory disk"));
        }
        Ok(Some(Self { volumes, missing, end_at: len - span + at as u64, directory_disk, zip64 }))
    }

    /// The last disk's number.
    pub(crate) fn last_disk(&self) -> u32 {
        (self.volumes.len() - 1) as u32
    }
}

/// A view of `inner` from `base` on, as the central directory parser reads a spanned set from the directory's disk.
pub(crate) struct Window<'a, R> {
    pub inner: &'a mut R,
    pub base: u64,
}

impl<R: Read> Read for Window<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<R: Seek> Seek for Window<'_, R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match pos {
            SeekFrom::Start(at) => {
                let at = self.base.checked_add(at).ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
                self.inner.seek(SeekFrom::Start(at)).map(|at| at - self.base)
            }
            _ => Err(io::Error::from(io::ErrorKind::Unsupported)),
        }
    }
}
