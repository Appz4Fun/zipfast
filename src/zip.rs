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

//! ZIP archives, read from PKWARE's published APPNOTE: the end of central directory record (and its ZIP64 form),
//! the central directory, and each entry's local header. Entries are stored, deflated, or compressed with bzip2,
//! LZMA, xz or zstd.

use std::fs::File;
use std::io::{BufRead, BufReader, Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use flate2::{Decompress, FlushDecompress, Status};
use zip_container::{
    Directory, DirectoryError, DirectoryParser, LOCAL_HEADER_LEN, Limits, LocalHeader, OwnershipError, ParseError,
    Profile, ReducedCentralRecord, local_layout,
};

use crate::error::{Error, Result};
use crate::extract::{
    Cancellation, Entry, Meta, Mode, MtimeOrigin, Options, RenameLog, RunError, Summary, Target, finish_dirs,
    finish_file, open_target,
};
use crate::path::sanitize_with;
use crate::rar5::Redirection;
use crate::stream::{LZMA_MEMORY_LIMIT, zstd_decoder};

mod byte_split;
pub mod create;
pub mod read;
pub mod recovery;
mod spanned;
pub use read::*;
pub mod rewrite;
mod session;
pub mod write;

pub(crate) use session::InspectionSource;
pub use session::{
    EntryId, EntryMetadata, Metadata, ReadSession, SelectedZipEntry, SessionError, SessionResult, SourceChange,
};
pub use zip_container::{
    AesFields, CentralHeader, CentralLocation, DirectoryDeclaration, EndRecord, ExtraMtime, ResolvedFields, Usage,
    Zip64End, Zip64Fields, Zip64Locator,
};

const FLAG_ENCRYPTED: u16 = 0x0001;
const FLAG_DESCRIPTOR: u16 = 0x0008;

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn descriptor_matches(bytes: &[u8], wide: bool, signed: bool, crc: u32, sizes: (u64, u64)) -> bool {
    let body = if signed {
        let Some(body) = bytes.strip_prefix(b"PK\x07\x08") else { return false };
        body
    } else {
        bytes
    };
    let width = if wide { 8 } else { 4 };
    if body.len() != 4 + 2 * width || body[..4] != crc.to_le_bytes() {
        return false;
    }
    let size = |bytes: &[u8]| {
        let mut field = [0; 8];
        field[..width].copy_from_slice(bytes);
        u64::from_le_bytes(field)
    };
    (size(&body[4..4 + width]), size(&body[4 + width..])) == sizes
}
const FLAG_UTF8: u16 = 0x0800;

const METHOD_STORED: u16 = 0;
const METHOD_DEFLATE: u16 = 8;
const METHOD_DEFLATE64: u16 = 9;
const METHOD_BZIP2: u16 = 12;
const METHOD_LZMA: u16 = 14;
const METHOD_ZSTD: u16 = 93;
const METHOD_XZ: u16 = 95;
/// PPMd variant I revision 1, as 7-Zip writes it (`-mm=PPMd`)
const METHOD_PPMD: u16 = 98;
/// An LZMA entry ends with an end marker instead of at its stated size.
const FLAG_LZMA_EOS: u16 = 0x0002;

/// Whether entries compressed with `method` can be read.
fn supported(method: u16) -> bool {
    matches!(
        method,
        METHOD_STORED
            | METHOD_DEFLATE
            | METHOD_DEFLATE64
            | METHOD_BZIP2
            | METHOD_LZMA
            | METHOD_ZSTD
            | METHOD_XZ
            | METHOD_PPMD
    )
}

const HOST_UNIX: u8 = 3;
const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;

const BUF: usize = 1 << 20;
const ENCRYPTED_PACKED_LIMIT: u64 = 128 << 20;
// A cancelable parse polls between bounded reads and parser supplies. The
// shared parser also bounds the tail it may consume from cache in one poll.
const CANCELABLE_DIRECTORY_CHUNK: usize = 64 << 10;

/// Whether the file starts the way a ZIP archive does.
pub fn sniff(head: &[u8]) -> bool {
    head.len() >= 4 && head[..2] == *b"PK" && matches!(head[2..4], [3, 4] | [5, 6] | [7, 8])
}

/// One central directory entry.
#[derive(Clone, Debug, Default)]
pub struct ZipEntry {
    pub name: String,
    pub flags: u16,
    pub method: u16,
    pub host: u8,
    pub crc32: u32,
    pub packed: u64,
    pub size: u64,
    pub local_at: u64,
    pub external: u32,
    pub mtime: Option<i64>,
    pub nanos: u32,
    /// Which clock `mtime` was read from: `Utc` from an extended-timestamp
    /// (0x5455) or NTFS (0x000a) extra, `LocalWallClock` from the DOS fields.
    pub mtime_origin: Option<MtimeOrigin>,
    pub aes_info: Option<(u8, u16, u16)>,
}

impl ZipEntry {
    pub fn unix_mode(&self) -> Option<u32> {
        extraction_unix_mode(self.host, self.external)
    }

    /// The raw Windows attribute bits: the low 16 bits of the external
    /// attributes when the host stores MS-DOS attributes there.
    pub fn windows_attributes(&self) -> Option<u32> {
        windows_attributes(self.host, self.external)
    }

    pub fn is_dir(&self) -> bool {
        is_dir(&self.name, self.host, self.external)
    }

    pub fn is_link(&self) -> bool {
        is_link(self.host, self.external)
    }

    pub fn encrypted(&self) -> bool {
        self.read_description().encrypted()
    }

    pub fn effective_method(&self) -> u16 {
        self.read_description().effective_method()
    }

    fn read_description(&self) -> ReadDescription<'_> {
        ReadDescription {
            name: &self.name,
            flags: self.flags,
            method: self.method,
            crc32: self.crc32,
            packed: self.packed,
            size: self.size,
            local_at: self.local_at,
            aes_info: self.aes_info,
            keep_cut: false,
        }
    }

    fn meta(&self) -> Meta {
        Meta { mtime: self.mtime, nanos: self.nanos, mode: self.unix_mode() }
    }
}

fn extraction_unix_mode(host: u8, external: u32) -> Option<u32> {
    (host == HOST_UNIX && external >> 16 != 0).then_some(external >> 16)
}

/// Hosts whose external attributes carry MS-DOS/Windows attribute bits in the
/// low 16 bits: 0 FAT, 6 OS/2 HPFS, 10 NTFS (APPNOTE 4.4.2), 11 NTFS (Info-ZIP
/// and 7-Zip numbering) and 14 VFAT.
fn windows_attributes(host: u8, external: u32) -> Option<u32> {
    matches!(host, 0 | 6 | 10 | 11 | 14).then_some(external & 0xffff)
}

fn is_dir(name: &str, host: u8, external: u32) -> bool {
    name.ends_with('/')
        || extraction_unix_mode(host, external).is_some_and(|mode| mode & S_IFMT == S_IFDIR)
        || (host != HOST_UNIX && external & 0x10 != 0)
}

fn is_link(host: u8, external: u32) -> bool {
    extraction_unix_mode(host, external).is_some_and(|mode| mode & S_IFMT == S_IFLNK)
}

struct ReadDescription<'a> {
    name: &'a str,
    flags: u16,
    method: u16,
    crc32: u32,
    packed: u64,
    size: u64,
    local_at: u64,
    aes_info: Option<(u8, u16, u16)>,
    /// the bytes before a cut (a missing volume, a truncated file) are passed on before the read fails, for
    /// [`crate::extract::Options::keep_broken`]; otherwise only whole reads are
    keep_cut: bool,
}

impl ReadDescription<'_> {
    fn encrypted(&self) -> bool {
        self.flags & FLAG_ENCRYPTED != 0 || self.method == 99 || self.aes_info.is_some()
    }

    fn effective_method(&self) -> u16 {
        if self.method == 99 { self.aes_info.map_or(self.method, |(_, _, m)| m) } else { self.method }
    }
}

pub(crate) fn check_selected_legacy(entry: &ZipEntry, limit: u64) -> Result<()> {
    check_selection(entry.is_dir(), entry.is_link(), entry.packed, entry.size, limit)
}
fn check_selection(is_dir: bool, is_link: bool, packed: u64, size: u64, limit: u64) -> Result<()> {
    if is_dir || is_link {
        return Err(Error::Unsupported("the selected ZIP entry is not a regular file".into()));
    }
    if packed > limit || size > limit {
        return Err(Error::Unsupported("the selected ZIP entry exceeds the byte limit".into()));
    }
    Ok(())
}

fn read_local_header(file: &mut (impl Read + Seek), at: u64) -> Result<[u8; LOCAL_HEADER_LEN]> {
    file.seek(SeekFrom::Start(at))?;
    let mut buf = [0; LOCAL_HEADER_LEN];
    file.read_exact(&mut buf)?;
    Ok(buf)
}

fn directory_error(error: DirectoryError) -> Error {
    match error {
        DirectoryError::NotZip => Error::NotAnArchive,
        DirectoryError::MalformedEnd => Error::Corrupt("central directory size or offset"),
        DirectoryError::MalformedZip64 => Error::Corrupt("ZIP64 metadata"),
        DirectoryError::EntryCount { .. } => Error::Corrupt("central directory entry count"),
        DirectoryError::InvalidLocalOffset => Error::Corrupt("local header offset"),
        DirectoryError::UnsupportedDisk => Error::Unsupported("split ZIP archives (.z01 and on)".into()),
        DirectoryError::Limit(_)
        | DirectoryError::Ownership(OwnershipError::CounterOverflow { .. } | OwnershipError::LimitExceeded { .. }) => {
            Error::Unsupported("ZIP directory exceeds the listing limit".into())
        }
        DirectoryError::Allocation | DirectoryError::Ownership(OwnershipError::Allocation { .. }) => {
            Error::Unsupported("cannot allocate ZIP directory metadata".into())
        }
        DirectoryError::Supply(_) => Error::Corrupt("ZIP directory source range"),
        DirectoryError::Incomplete => Error::Truncated,
        DirectoryError::Parse(_) => Error::Corrupt("central directory record"),
    }
}

fn check_cancel(cancel: Option<&Cancellation>) -> Result<()> {
    Ok(cancel.map_or(Ok(()), Cancellation::check_io)?)
}

fn read_directory<T>(
    file: &mut (impl Read + Seek),
    len: u64,
    mut parser: DirectoryParser<T>,
    cancel: Option<&Cancellation>,
) -> Result<Directory<T>> {
    let mut buf = Vec::new();
    let mut file_at = None;
    loop {
        check_cancel(cancel)?;
        let Some(range) = parser.next_read().map_err(directory_error)? else { break };
        // DirectoryParser checks each pending range and cumulative source
        // usage against Limits before issuing a request.
        let size = range
            .end
            .checked_sub(range.start)
            .filter(|&size| size != 0 && range.end <= len)
            .and_then(|size| usize::try_from(size).ok())
            .ok_or(Error::Corrupt("ZIP directory source range"))?;
        let chunk_size = if cancel.is_some() { size.min(CANCELABLE_DIRECTORY_CHUNK) } else { size };
        if chunk_size > buf.len() {
            buf.try_reserve_exact(chunk_size - buf.len()).map_err(|_| directory_error(DirectoryError::Allocation))?;
            buf.resize(chunk_size, 0);
        }
        check_cancel(cancel)?;
        if file_at != Some(range.start) {
            file.seek(SeekFrom::Start(range.start))?;
        }
        file.read_exact(&mut buf[..chunk_size])?;
        file_at = Some(range.start + chunk_size as u64);
        check_cancel(cancel)?;
        parser.supply(range.start, &buf[..chunk_size]).map_err(directory_error)?;
        // A strict walk can finish at a noncentral trailer before the end
        // of a pending range. Poll again before reading any remainder.
    }
    check_cancel(cancel)?;
    parser.finish().map_err(directory_error)
}

/// An open archive: the file (or the pieces of a byte-split `.zip.001` set) and its central directory.
pub struct Archive {
    file: byte_split::ArchiveSource,
    len: u64,
    /// Every piece of a byte-split set; empty for one file.
    pieces: Vec<PathBuf>,
    /// The first absent piece of a byte-split set with a gap: `entries` are then the members found before it.
    missing: Option<PathBuf>,
    /// The last entry's size is unknown: a streamed member whose descriptor is past the gap of `missing`.
    last_size_unknown: bool,
    /// Where the absent pieces would be: past the end of a byte-split set cut short, or the disks of a spanned set
    /// that are missing while its central directory is not. A member whose bytes reach one fails as missing it.
    holes: Vec<std::ops::Range<u64>>,
    /// For each entry of a spanned set whose local header is on an absent disk, that disk's volume: such a member
    /// is never read, and fails as missing it. Empty when no entry is.
    lost: Vec<Option<PathBuf>>,
    /// One file cut short, its end record gone, read by walking its local headers ([`Archive::open_truncated`]): a
    /// member whose bytes reach the end fails as truncated, and so does the run.
    truncated: bool,
    pub entries: Vec<ZipEntry>,
}

impl Archive {
    pub fn open(path: &Path) -> Result<Archive> {
        Self::open_cancelable(path, None)
    }

    pub(crate) fn open_cancelable(path: &Path, cancel: Option<&Cancellation>) -> Result<Archive> {
        if let Some(set) = spanned::Spanned::open(path)? {
            return Self::open_spanned(set, cancel);
        }
        if let Some(set) = spanned::Headless::open(path) {
            check_cancel(cancel)?;
            let pieces = set.volumes.clone();
            return Self::open_local_walk(pieces, set.volumes, set.missing);
        }
        let (mut file, len, pieces, missing) = match byte_split::ByteSplit::open(path)? {
            Some(split) => {
                let pieces = split.paths().map(Path::to_path_buf).collect();
                let len = split.len();
                let missing = split.missing().map(Path::to_path_buf);
                (byte_split::ArchiveSource::Split(split), len, pieces, missing)
            }
            None => {
                let file = File::open(path)?;
                let len = file.metadata()?.len();
                (byte_split::ArchiveSource::File(file), len, Vec::new(), None)
            }
        };
        check_cancel(cancel)?;
        // A set cut short by a missing piece has no central directory: list the local headers before the gap.
        let (entries, last_size_unknown) = match missing {
            Some(_) => byte_split::scan_local_headers(&mut file, 0, len)?,
            None => (read_projected_legacy(&mut file, len, cancel)?.0, false),
        };
        let holes = if missing.is_some() { std::iter::once(len..u64::MAX).collect() } else { Vec::new() };
        Ok(Archive {
            file,
            len,
            pieces,
            missing,
            last_size_unknown,
            holes,
            lost: Vec::new(),
            truncated: false,
            entries,
        })
    }

    /// [`Self::open_cancelable`], and with `salvage` ([`Options::salvage_truncated_zip`]) one file (not a split or
    /// spanned set) whose end record can't be found is read by walking its local headers ([`Self::open_truncated`]).
    pub(crate) fn open_salvaging(path: &Path, salvage: bool, cancel: Option<&Cancellation>) -> Result<Archive> {
        match Self::open_cancelable(path, cancel) {
            Err(Error::NotAnArchive) if salvage && !is_split_set(path) => Self::open_truncated(path, cancel),
            other => other,
        }
    }

    /// One file cut short, its central directory or end record gone, read as 7-Zip reads it: by walking the local
    /// headers from its start. The members are those whose local headers lie before the cut; one whose bytes reach
    /// the cut fails as truncated, and so does the run. A file that doesn't start with a local header (or the
    /// spanning marker before one) is not a ZIP archive.
    pub(crate) fn open_truncated(path: &Path, cancel: Option<&Cancellation>) -> Result<Archive> {
        let mut file = File::open(path)?;
        let len = file.metadata()?.len();
        check_cancel(cancel)?;
        let mut head = [0u8; 8];
        let got = crate::tar::read_full(&mut file, &mut head)?;
        let start = local_walk_start(&head[..got]).ok_or(Error::NotAnArchive)?;
        let mut file = byte_split::ArchiveSource::File(file);
        let (entries, last_size_unknown) = byte_split::scan_local_headers(&mut file, start, len)?;
        if entries.is_empty() {
            return Err(Error::Truncated);
        }
        check_cancel(cancel)?;
        Ok(Archive {
            file,
            len,
            pieces: Vec::new(),
            missing: None,
            last_size_unknown,
            holes: std::iter::once(len..u64::MAX).collect(),
            lost: Vec::new(),
            truncated: true,
            entries,
        })
    }

    /// The `present` disks of a spanned set read as one, up to the absent volume `missing`, with no central directory
    /// to read: the members are those whose local headers lie before the gap, as for a byte-split set cut short.
    fn open_local_walk(pieces: Vec<PathBuf>, present: Vec<PathBuf>, missing: PathBuf) -> Result<Archive> {
        let mut split = byte_split::ByteSplit::from_volumes(present, 0)?;
        let len = split.len();
        // offsets in disk 0 count the spanning marker
        let mut head = [0u8; 4];
        let start =
            if len >= 4 && split.read_exact(&mut head).is_ok() && head == *spanned::SPLIT_MARKER { 4 } else { 0 };
        let mut file = byte_split::ArchiveSource::Split(split);
        let (entries, last_size_unknown) = byte_split::scan_local_headers(&mut file, start, len)?;
        let holes = std::iter::once(len..u64::MAX).collect();
        Ok(Archive {
            file,
            len,
            pieces,
            missing: Some(missing),
            last_size_unknown,
            holes,
            lost: Vec::new(),
            truncated: false,
            entries,
        })
    }

    /// The cause of a failed read of `e`, when its bytes reach a hole of a set cut short or missing a volume (that
    /// piece is missing), or the end of one file cut short (it is truncated): the cut is the cause, not the entry.
    /// The payload starts past the local header, its name and its extra field.
    fn gap_crossed(&mut self, e: &ZipEntry) -> Option<Error> {
        let cause = match &self.missing {
            Some(missing) => Error::MissingVolume(missing.clone()),
            None if self.truncated => Error::Truncated,
            None => return None,
        };
        let crosses = data_at(&mut self.file, self.len, &e.read_description()).map_or(true, |start| {
            // a streamed member also needs its descriptor: 16 bytes, 24 with ZIP64 sizes
            let zip64 = e.packed >= u64::from(u32::MAX) || e.size >= u64::from(u32::MAX);
            let descriptor = match (e.flags & 0x08 != 0, zip64) {
                (false, _) => 0,
                (true, false) => 16,
                (true, true) => 24,
            };
            let end = start.saturating_add(e.packed).saturating_add(descriptor);
            self.holes.iter().any(|hole| e.local_at < hole.end && end > hole.start)
        });
        crosses.then_some(cause)
    }

    /// The absent volume the entry at `index` starts on, if any: it can't be read at all.
    fn lost_volume(&self, index: usize) -> Option<&Path> {
        self.lost.get(index).and_then(Option::as_deref)
    }

    /// An Info-ZIP spanned set read as its disks concatenated, each entry's (disk, offset) made an offset there. With
    /// a volume missing, the central directory is still read when its own disks are all there, as 7-Zip does: every
    /// member is listed, and one whose bytes reach the missing volume fails as missing it. Otherwise the local
    /// headers before the gap are listed.
    fn open_spanned(set: spanned::Spanned, cancel: Option<&Cancellation>) -> Result<Archive> {
        let pieces = set.volumes.clone();
        let last = set.last_disk();
        let directory_whole = set.volumes[set.directory_disk as usize..].iter().all(|v| spanned::is_regular(v));
        if let Some(missing) = set.missing.clone().filter(|_| !directory_whole) {
            let present = set.volumes.iter().take_while(|v| **v != missing).cloned().collect();
            return Self::open_local_walk(pieces, present, missing);
        }
        // an absent disk stands in at the set's split size: every numbered volume but the last has it
        let nominal = set.volumes[..last as usize]
            .iter()
            .find_map(|v| std::fs::metadata(v).ok().filter(|m| m.is_file()).map(|m| m.len()))
            .unwrap_or(0);
        let mut split = byte_split::ByteSplit::from_volumes(set.volumes.clone(), nominal)?;
        let len = split.len();
        let holes = split.holes();
        let starts: Vec<u64> = split.starts().collect();
        let base = starts[set.directory_disk as usize];
        let end_at = starts[last as usize] + set.end_at - base;
        let parser = DirectoryParser::spanned_at_eocd(len - base, end_at, Limits::default(), crate::crc32::hash, |r| {
            let disk = r.resolved().disk_start;
            Ok((project_record(r)?, disk))
        })
        .map_err(directory_error)?;
        let found = read_directory(&mut spanned::Window { inner: &mut split, base }, len - base, parser, cancel)?;
        if found.prefix_shift != 0 {
            return Err(Error::Corrupt("central directory offset"));
        }
        // The parser looks for the ZIP64 end record in the concatenation: it must be the one the locator names.
        if let Some(record) = &found.zip64_end {
            let at = set.zip64.filter(|(vol, _)| *vol >= set.directory_disk && *vol <= last);
            if at.map(|(vol, off)| starts[vol as usize] + off - base) != Some(record.source.start) {
                return Err(Error::Corrupt("ZIP64 end record"));
            }
        }
        let mut entries = Vec::with_capacity(found.entries.len());
        let mut lost = Vec::new();
        let absent: Vec<bool> = set.volumes.iter().map(|v| set.missing.is_some() && !spanned::is_regular(v)).collect();
        for (mut entry, disk) in found.entries {
            check_cancel(cancel)?;
            let start =
                starts.get(disk as usize).filter(|_| disk <= last).ok_or(Error::Corrupt("ZIP local header disk"))?;
            // A member starting on an absent disk is listed, as 7-Zip lists it, but never read: the hole there has
            // only a nominal size, so its offset can't be trusted to land in it.
            if absent[disk as usize] {
                lost.resize(entries.len(), None);
                lost.push(Some(set.volumes[disk as usize].clone()));
                entry.local_at = *start;
                entries.push(entry);
                continue;
            }
            entry.local_at = start
                .checked_add(entry.local_at)
                .filter(|&at| at < len)
                .ok_or(Error::Corrupt("local header offset"))?;
            entries.push(entry);
        }
        Ok(Archive {
            file: byte_split::ArchiveSource::Split(split),
            len,
            pieces,
            missing: set.missing,
            last_size_unknown: false,
            holes,
            lost,
            truncated: false,
            entries,
        })
    }

    /// Decodes the entry at a zero-based index and checks its integrity.
    ///
    /// Both its packed and unpacked sizes must be at most `max_bytes`.
    /// The sink receives provisional data. Only publish it after success.
    pub fn read_at(
        &mut self,
        index: usize,
        password: Option<&str>,
        max_bytes: u64,
        sink: impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        self.read_at_cancelable(index, password, max_bytes, None, sink)
    }

    pub(crate) fn selected_entry(&self, index: usize, limit: u64) -> Result<&ZipEntry> {
        let entry = self.entries.get(index).ok_or_else(|| Error::Unsupported("entry index is out of range".into()))?;
        check_selection(entry.is_dir(), entry.is_link(), entry.packed, entry.size, limit)?;
        Ok(entry)
    }

    pub(crate) fn read_at_cancelable(
        &mut self,
        index: usize,
        password: Option<&str>,
        limit: u64,
        cancel: Option<&Cancellation>,
        mut sink: impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        self.selected_entry(index, limit)?;
        if let Some(volume) = self.lost_volume(index) {
            return Err(Error::MissingVolume(volume.to_path_buf()));
        }
        let entry = self.entries[index].read_description();
        let mut buffer = vec![0; BUF];
        read_entry(&mut self.file, self.len, &entry, password, &mut buffer, &mut sink, cancel)
    }
}

pub(crate) fn projected_parser(
    len: u64,
    limits: Limits,
) -> std::result::Result<DirectoryParser<ZipEntry>, DirectoryError> {
    DirectoryParser::with_projection_and_name_crc32(len, Profile::Zipfast, limits, crate::crc32::hash, project_record)
}
pub(crate) fn relocate_projected(
    entries: &mut [ZipEntry],
    shift: u64,
    len: u64,
    cancel: Option<&Cancellation>,
) -> std::result::Result<(), read::ReadFault> {
    if shift != 0 {
        for entry in entries {
            if cancel.is_some_and(Cancellation::is_canceled) {
                return Err(read::ReadFault::Cancelled);
            }
            entry.local_at = entry
                .local_at
                .checked_add(shift)
                .filter(|at| *at < len)
                .ok_or(read::ReadFault::CheckedFormat { reason: "invalid local header offset" })?;
        }
    }
    Ok(())
}
fn read_projected_legacy(
    file: &mut (impl Read + Seek),
    len: u64,
    cancel: Option<&Cancellation>,
) -> Result<(Vec<ZipEntry>, Usage)> {
    let parser = projected_parser(len, Limits::default()).map_err(directory_error)?;
    let directory = read_directory(file, len, parser, cancel)?;
    let usage = directory.usage;
    let mut entries = directory.entries;
    relocate_projected(&mut entries, directory.prefix_shift, len, cancel).map_err(|fault| match fault {
        read::ReadFault::Cancelled => {
            Error::Io(std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "operation canceled"))
        }
        _ => Error::Corrupt("local header offset"),
    })?;
    check_cancel(cancel)?;
    Ok((entries, usage))
}

/// [`Options::seven_zip_strict`]: how the entry's local header differs from its central record, if it does. A local
/// header that can't be read is left for the read to report.
fn local_mismatch(
    file: &mut (impl Read + Seek),
    len: u64,
    e: &ZipEntry,
) -> Option<crate::extract::LocalHeaderMismatch> {
    if e.local_at.checked_add(LOCAL_HEADER_LEN as u64).is_none_or(|end| end > len) {
        return None;
    }
    let header = LocalHeader::parse(&read_local_header(file, e.local_at).ok()?).ok()?;
    crate::extract::LocalHeaderMismatch::compare(&header, e.flags, e.method, e.crc32, e.packed, e.size)
}

/// Where an entry's data starts, from its local header.
fn data_at(file: &mut (impl Read + Seek), len: u64, e: &ReadDescription<'_>) -> Result<u64> {
    if e.local_at.checked_add(LOCAL_HEADER_LEN as u64).is_none_or(|end| end > len) {
        return Err(Error::Truncated);
    }
    let head = read_local_header(file, e.local_at)?;
    let header = LocalHeader::parse(&head).map_err(|error| match error {
        ParseError::BadSignature { .. } => Error::Corrupt("local header signature"),
        _ => Error::Truncated,
    })?;
    let layout = local_layout(header, e.local_at, len).map_err(|_| Error::Truncated)?;
    match layout.payload_range(e.packed, len) {
        Ok(range) => Ok(range.start),
        // Options::keep_broken: a payload running past what is there (a missing volume) is read to the cut
        Err(_) if e.keep_cut => Ok(layout.payload_range(0, len).map_err(|_| Error::Truncated)?.start),
        Err(_) => Err(Error::Truncated),
    }
}

/// Reads an entry's data, decompressed, into `sink`, and checks its size and CRC.
fn read_entry(
    file: &mut (impl Read + Seek),
    len: u64,
    e: &ReadDescription<'_>,
    password: Option<&str>,
    buf: &mut [u8],
    sink: &mut dyn FnMut(&[u8]) -> Result<()>,
    cancel: Option<&Cancellation>,
) -> Result<()> {
    let check = || cancel.map_or(Ok(()), Cancellation::check_io);
    check()?;
    let at = data_at(file, len, e)?;
    file.seek(SeekFrom::Start(at))?;
    let mut crc = crate::crc32::Hasher::new();
    let mut size = 0u64;
    let mut emit = |chunk: &[u8]| -> Result<()> {
        let room = e.size.saturating_sub(size);
        size = size.saturating_add(chunk.len() as u64);
        if size > e.size {
            // the bytes up to the declared size go out first: a file kept with Options::keep_broken holds them, as
            // 7-Zip 26.06 `x` writes it (the entry fails all the same)
            let within = usize::try_from(room).map_or(chunk.len(), |room| room.min(chunk.len()));
            if within != 0 {
                check()?;
                sink(&chunk[..within])?;
            }
            return Err(Error::Corrupt("more data than the directory says"));
        }
        crc.update(chunk);
        check()?;
        sink(chunk)
    };
    if e.encrypted() {
        if e.packed > ENCRYPTED_PACKED_LIMIT {
            return Err(Error::Unsupported("encrypted ZIP entry exceeds the 128 MiB packed limit".into()));
        }
        let pw = password
            .filter(|s| !s.is_empty())
            .ok_or_else(|| Error::Unsupported("encrypted (password required)".into()))?;
        let packed_len = usize::try_from(e.packed).map_err(|_| Error::Corrupt("encrypted entry too large"))?;
        let mut raw = vec![0u8; packed_len];
        if cancel.is_some() {
            for chunk in raw.chunks_mut(buf.len()) {
                check()?;
                file.read_exact(chunk)?;
            }
            check()?;
        } else {
            file.read_exact(&mut raw)?;
        }
        let mut skip_crc = false;
        let payload = if e.method == 99 || e.aes_info.is_some() {
            let (strength, vendor, _) = e.aes_info.ok_or(Error::Corrupt("missing WinZip AES extra field"))?;
            if vendor == 2 {
                skip_crc = true;
            }
            crate::crypto::decrypt_winzip_aes_in_place(pw, strength, &mut raw, check)?
                .ok_or(Error::Corrupt("wrong password or damaged AES stream"))?
        } else {
            let password_check = if e.flags & 0x0008 != 0 {
                let head = read_local_header(file, e.local_at)?;
                head[11]
            } else {
                (e.crc32 >> 24) as u8
            };
            crate::crypto::decrypt_zipcrypto_in_place(pw, password_check, &mut raw, check)?
                .ok_or(Error::Corrupt("wrong password"))?
        };
        let decrypted = &raw[payload];
        let method = e.effective_method();
        match method {
            METHOD_STORED => {
                if decrypted.len() as u64 != e.size {
                    // the bytes up to the declared size go out first, as for an entry that isn't encrypted
                    let within = usize::try_from(e.size).map_or(decrypted.len(), |size| size.min(decrypted.len()));
                    if decrypted.len() as u64 > e.size && within != 0 {
                        check()?;
                        emit(&decrypted[..within])?;
                    }
                    return Err(Error::Corrupt("stored entry's sizes differ"));
                }
                if cancel.is_some() {
                    for chunk in decrypted.chunks(buf.len()) {
                        check()?;
                        emit(chunk)?;
                    }
                } else {
                    emit(decrypted)?;
                }
            }
            METHOD_DEFLATE => {
                let mut z = Decompress::new(false);
                let mut out = vec![0u8; BUF];
                let mut input = decrypted;
                loop {
                    check()?;
                    let (before_in, before_out) = (z.total_in(), z.total_out());
                    let status = z
                        .decompress(input, &mut out, FlushDecompress::None)
                        .map_err(|_| Error::Corrupt("deflate data"))?;
                    let used = (z.total_in() - before_in) as usize;
                    let made = (z.total_out() - before_out) as usize;
                    input = &input[used..];
                    emit(&out[..made])?;
                    if status == Status::StreamEnd {
                        break;
                    }
                    if made == out.len() {
                        continue;
                    }
                    if input.is_empty() || (used == 0 && made == 0) {
                        return Err(Error::Corrupt("deflate data"));
                    }
                }
            }
            METHOD_DEFLATE64 | METHOD_BZIP2 | METHOD_LZMA | METHOD_ZSTD | METHOD_XZ | METHOD_PPMD => {
                let mut dec = stream_decoder(e, method, BufReader::new(Cursor::new(decrypted)))?;
                loop {
                    check()?;
                    let n = dec.read(buf).map_err(|_| Error::Corrupt("compressed data is damaged"))?;
                    if n == 0 {
                        break;
                    }
                    emit(&buf[..n])?;
                }
            }
            m => return Err(Error::Unsupported(format!("compression method {m}"))),
        }
        if size != e.size {
            return Err(Error::Corrupt("less data than the directory says"));
        }
        if !skip_crc && crc.finalize() != e.crc32 {
            return Err(Error::BadChecksum(e.name.to_owned()));
        }
        return Ok(());
    }
    let mut left = e.packed;
    match e.method {
        METHOD_STORED => {
            // an entry carrying more than its declared size has the bytes up to it read out first: a file kept with
            // Options::keep_broken holds them, as 7-Zip 26.06 `x` writes it; it fails all the same
            let over = e.packed > e.size;
            if e.packed != e.size && !over {
                return Err(Error::Corrupt("stored entry's sizes differ"));
            }
            if over {
                left = e.size;
            }
            while left > 0 {
                check()?;
                let n = (left.min(buf.len() as u64)) as usize;
                let (got, cut) = fill(file, &mut buf[..n], e.keep_cut)?;
                emit(&buf[..got])?;
                if let Some(cut) = cut {
                    return Err(cut.into());
                }
                left -= n as u64;
            }
            if over {
                return Err(Error::Corrupt("stored entry's sizes differ"));
            }
        }
        METHOD_DEFLATE => {
            let mut z = Decompress::new(false);
            let mut out = vec![0u8; BUF];
            let mut done = false;
            while !done {
                let n = (left.min(buf.len() as u64)) as usize;
                let (got, mut cut) = fill(file, &mut buf[..n], e.keep_cut)?;
                left -= n as u64;
                let mut input = &buf[..got];
                loop {
                    check()?;
                    let (before_in, before_out) = (z.total_in(), z.total_out());
                    let status = z
                        .decompress(input, &mut out, FlushDecompress::None)
                        .map_err(|_| Error::Corrupt("deflate data"))?;
                    let used = (z.total_in() - before_in) as usize;
                    let made = (z.total_out() - before_out) as usize;
                    input = &input[used..];
                    emit(&out[..made])?;
                    if status == Status::StreamEnd {
                        done = true;
                        break;
                    }
                    // a full output buffer means there may be more to come from the same input
                    if made == out.len() {
                        continue;
                    }
                    if input.is_empty() {
                        if let Some(cut) = cut.take() {
                            return Err(cut.into());
                        }
                        if left == 0 {
                            return Err(Error::Corrupt("deflate data ends early"));
                        }
                        break;
                    }
                    if used == 0 && made == 0 {
                        return Err(Error::Corrupt("deflate data"));
                    }
                }
            }
        }
        METHOD_DEFLATE64 | METHOD_BZIP2 | METHOD_LZMA | METHOD_ZSTD | METHOD_XZ | METHOD_PPMD => {
            let packed = BufReader::with_capacity(1 << 20, CheckedInput { input: file.take(e.packed), cancel });
            let mut dec = stream_decoder(e, e.method, packed)?;
            loop {
                check()?;
                let decoded = dec.read(buf);
                check()?;
                let n = match decoded {
                    Ok(n) => n,
                    Err(io) if io.kind() == std::io::ErrorKind::UnexpectedEof => return Err(Error::Truncated),
                    Err(io) if io.raw_os_error().is_some() => return Err(Error::Io(io)),
                    Err(_) => return Err(Error::Corrupt("compressed data is damaged")),
                };
                if n == 0 {
                    break;
                }
                emit(&buf[..n])?;
            }
        }
        m => return Err(Error::Unsupported(format!("compression method {m}"))),
    }
    if size != e.size {
        return Err(Error::Corrupt("less data than the directory says"));
    }
    if crc.finalize() != e.crc32 {
        return Err(Error::BadChecksum(e.name.to_owned()));
    }
    Ok(())
}

/// Fills `buf`: whole (an error otherwise), or with `keep_cut` as much as is there before a cut, with what cut it
/// (the input's end, or its own I/O error, kept as it is so a failing source still stops the run).
fn fill(file: &mut impl Read, buf: &mut [u8], keep_cut: bool) -> std::io::Result<(usize, Option<std::io::Error>)> {
    if !keep_cut {
        file.read_exact(buf)?;
        return Ok((buf.len(), None));
    }
    let mut got = 0;
    while got < buf.len() {
        match file.read(&mut buf[got..]) {
            Ok(0) => return Ok((got, Some(std::io::ErrorKind::UnexpectedEof.into()))),
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Ok((got, Some(e))),
        }
    }
    Ok((got, None))
}

// The buffered codecs may consume several input windows before producing
// output. Poll at the source as well as between decoder output chunks.
struct CheckedInput<'a, R> {
    input: R,
    cancel: Option<&'a Cancellation>,
}

impl<R: Read> Read for CheckedInput<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if let Some(cancel) = self.cancel {
            cancel.check_io()?;
        }
        self.input.read(buffer)
    }
}

/// A reader of an entry's data for the methods that have a stream decoder.
fn stream_decoder<'a>(e: &ReadDescription<'_>, method: u16, packed: impl BufRead + 'a) -> Result<Box<dyn Read + 'a>> {
    Ok(match method {
        METHOD_DEFLATE64 => Box::new(crate::inflate64::Inflate64Reader::new(packed)),
        METHOD_BZIP2 => Box::new(bzip2::bufread::MultiBzDecoder::new(packed)),
        METHOD_ZSTD => Box::new(zstd_decoder(packed)?),
        // the model's memory, which the stream's header asks for, is held to the LZMA dictionary limit
        METHOD_PPMD => Box::new(crate::ppmd8::Reader::new(packed, LZMA_MEMORY_LIMIT)),
        METHOD_XZ => {
            let stream = liblzma::stream::Stream::new_stream_decoder(LZMA_MEMORY_LIMIT, liblzma::stream::CONCATENATED)
                .map_err(|_| Error::Corrupt("xz data"))?;
            Box::new(liblzma::bufread::XzDecoder::new_stream(packed, stream))
        }
        _ => {
            // APPNOTE 5.8.8: a version, the length of the properties, then the properties and the raw LZMA data.
            // Put back together with the size as the classic .lzma header, it reads with the stock decoder.
            let mut packed = packed;
            let mut head = [0u8; 4];
            packed.read_exact(&mut head)?;
            let props_len = u16::from_le_bytes([head[2], head[3]]) as usize;
            if props_len != 5 {
                return Err(Error::Corrupt("LZMA properties"));
            }
            let mut alone = vec![0u8; 13];
            packed.read_exact(&mut alone[..5])?;
            let size = if e.flags & FLAG_LZMA_EOS != 0 { u64::MAX } else { e.size };
            alone[5..].copy_from_slice(&size.to_le_bytes());
            let stream = liblzma::stream::Stream::new_lzma_decoder(LZMA_MEMORY_LIMIT)
                .map_err(|_| Error::Corrupt("LZMA data"))?;
            Box::new(liblzma::bufread::XzDecoder::new_stream(BufReader::new(Cursor::new(alone).chain(packed)), stream))
        }
    })
}

pub(crate) fn project_record(record: ReducedCentralRecord<'_>) -> std::result::Result<ZipEntry, DirectoryError> {
    #[cfg(test)]
    read::observe_projected(2);
    let view = record.view();
    let known = record.known();
    project_entry(
        view.header(),
        record.resolved(),
        view.raw_name(),
        known.unicode_path.map(|path| path.path_bytes()),
        known.mtime_override,
        known.aes,
    )
}

fn project_entry(
    header: CentralHeader,
    resolved: ResolvedFields,
    raw_name: &[u8],
    unicode_path: Option<&[u8]>,
    mtime_override: Option<ExtraMtime>,
    aes: Option<AesFields>,
) -> std::result::Result<ZipEntry, DirectoryError> {
    let (mtime, nanos) = project_mtime(header, mtime_override);
    let mtime_origin = project_mtime_origin(mtime, mtime_override);
    Ok(ZipEntry {
        name: decode_name(unicode_path.unwrap_or(raw_name), unicode_path.is_some() || header.flags & FLAG_UTF8 != 0)?,
        flags: header.flags,
        method: header.method,
        host: (header.version_made_by >> 8) as u8,
        crc32: header.crc32,
        packed: resolved.packed_size,
        size: resolved.unpacked_size,
        local_at: resolved.local_header_offset,
        external: header.external_attributes,
        mtime,
        nanos,
        mtime_origin,
        aes_info: project_aes(aes),
    })
}

fn project_mtime(header: CentralHeader, mtime_override: Option<ExtraMtime>) -> (Option<i64>, u32) {
    match mtime_override {
        Some(ExtraMtime::NtfsFiletime(ticks)) => {
            (Some((ticks / 10_000_000) as i64 - 11_644_473_600), ((ticks % 10_000_000) * 100) as u32)
        }
        Some(ExtraMtime::UnixSeconds(seconds)) => (Some(unix_extra_seconds(seconds, header.mod_date)), 0),
        None => (dos_time(header.mod_time, header.mod_date).map(crate::localtime::local_to_utc), 0),
    }
}

/// Widens a 32-bit extended-timestamp (UT) value. Writers store times past
/// 2038-01-19 truncated into the field, so a negative value is read as
/// unsigned when the entry's DOS date says 2038 or later; otherwise the field
/// stays signed, which keeps pre-1970 times.
pub(crate) fn unix_extra_seconds(seconds: i32, dos_date: u16) -> i64 {
    let dos_year = 1980 + u32::from(dos_date >> 9);
    if seconds < 0 && dos_year >= 2038 { i64::from(seconds as u32) } else { i64::from(seconds) }
}

/// An extended-timestamp or NTFS extra overrides the DOS fields (the last one
/// in the central extra field wins) and is UTC; the DOS fields are local.
fn project_mtime_origin(mtime: Option<i64>, mtime_override: Option<ExtraMtime>) -> Option<MtimeOrigin> {
    mtime.map(|_| if mtime_override.is_some() { MtimeOrigin::Utc } else { MtimeOrigin::LocalWallClock })
}

fn project_aes(aes: Option<AesFields>) -> Option<(u8, u16, u16)> {
    aes.filter(|fields| (1..=3).contains(&fields.strength))
        .map(|fields| (fields.strength, fields.vendor_version, fields.method))
}

/// MS-DOS date and time, which carry no time zone, as wall-clock seconds written as if UTC; readers convert them with
/// [`crate::localtime::local_to_utc`].
pub(crate) fn dos_time(time: u16, date: u16) -> Option<i64> {
    let (year, month, day) = (1980 + i64::from(date >> 9), i64::from((date >> 5) & 15), i64::from(date & 31));
    let (hour, min, sec) = (i64::from(time >> 11), i64::from((time >> 5) & 63), i64::from(time & 31) * 2);
    if !(1..=12).contains(&month) || day == 0 || hour > 23 || min > 59 || sec > 59 {
        return None;
    }
    // days since 1970 for a civil date (proleptic Gregorian)
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hour * 3600 + min * 60 + sec)
}

/// The high half of code page 437, the encoding of names without the UTF-8 flag.
const CP437_HIGH: [char; 128] = [
    'Ç', 'ü', 'é', 'â', 'ä', 'à', 'å', 'ç', 'ê', 'ë', 'è', 'ï', 'î', 'ì', 'Ä', 'Å', 'É', 'æ', 'Æ', 'ô', 'ö', 'ò', 'û',
    'ù', 'ÿ', 'Ö', 'Ü', '¢', '£', '¥', '₧', 'ƒ', 'á', 'í', 'ó', 'ú', 'ñ', 'Ñ', 'ª', 'º', '¿', '⌐', '¬', '½', '¼', '¡',
    '«', '»', '░', '▒', '▓', '│', '┤', '╡', '╢', '╖', '╕', '╣', '║', '╗', '╝', '╜', '╛', '┐', '└', '┴', '┬', '├', '─',
    '┼', '╞', '╟', '╚', '╔', '╩', '╦', '╠', '═', '╬', '╧', '╨', '╤', '╥', '╙', '╘', '╒', '╓', '╫', '╪', '┘', '┌', '█',
    '▄', '▌', '▐', '▀', 'α', 'ß', 'Γ', 'π', 'Σ', 'σ', 'µ', 'τ', 'Φ', 'Θ', 'Ω', 'δ', '∞', 'φ', 'ε', '∩', '≡', '±', '≥',
    '≤', '⌠', '⌡', '÷', '≈', '°', '∙', '·', '√', 'ⁿ', '²', '■', '\u{a0}',
];

fn cp437(byte: u8) -> char {
    if byte < 0x80 { byte as char } else { CP437_HIGH[usize::from(byte - 0x80)] }
}

pub(crate) fn decode_name(raw: &[u8], utf8: bool) -> std::result::Result<String, DirectoryError> {
    #[cfg(test)]
    read::observe_projected(3);
    // Many tools write valid UTF-8 without setting the flag.
    if let Ok(valid) = std::str::from_utf8(raw) {
        let mut name = String::new();
        name.try_reserve_exact(valid.len()).map_err(|_| DirectoryError::Allocation)?;
        name.push_str(valid);
        return Ok(name);
    }
    decode_invalid_name(raw, utf8, |_| Ok(()))
}

// Charge the exact additional allocation before reserving a decoded name.
// Raw names and Unicode extra bodies are bounded by wire u16 lengths.
fn decode_invalid_name(
    raw: &[u8],
    utf8: bool,
    charge: impl FnOnce(usize) -> std::result::Result<(), DirectoryError>,
) -> std::result::Result<String, DirectoryError> {
    let len = if utf8 {
        // Utf8Chunks reproduces from_utf8_lossy's replacement boundaries.
        raw.utf8_chunks().map(|chunk| chunk.valid().len() + 3 * usize::from(!chunk.invalid().is_empty())).sum()
    } else {
        raw.iter().copied().map(|byte| cp437(byte).len_utf8()).sum()
    };
    charge(len)?;
    let mut name = String::new();
    name.try_reserve_exact(len).map_err(|_| DirectoryError::Allocation)?;
    if utf8 {
        for chunk in raw.utf8_chunks() {
            name.push_str(chunk.valid());
            if !chunk.invalid().is_empty() {
                name.push('\u{fffd}');
            }
        }
    } else {
        name.extend(raw.iter().copied().map(cp437));
    }
    Ok(name)
}

/// Whether `path` is the first piece of a raw byte-split set (`name.zip.001` with `name.zip.002` beside it), or the
/// `.zip` (or `.z01`) of an Info-ZIP spanned set (`name.z01`, ..., `name.zip`), which [`list`], [`Archive::open`]
/// and [`run`] read as the pieces concatenated, as 7-Zip does.
/// Whether `path` is the `.zip` (or `.z01`) of an Info-ZIP spanned set, whose `.zip` may start mid-member.
pub(crate) fn is_spanned(path: &Path) -> bool {
    spanned::is_spanned(path)
}

/// Whether `path` is the `.z01` of an Info-ZIP spanned set whose `.zip` is missing: read only by walking its local
/// headers, on the unchecked routes ([`list`], [`run`]); the checked route refuses it.
pub(crate) fn is_headless_spanned(path: &Path) -> bool {
    spanned::Headless::open(path).is_some()
}

/// Where a walk of the local headers starts in a file with this head: at its first local header, past the spanning
/// marker of a single-segment set. `None` when the head starts with neither.
fn local_walk_start(head: &[u8]) -> Option<u64> {
    let start = if head.starts_with(spanned::SPLIT_MARKER) { 4 } else { 0 };
    (head.get(start..start + 4) == Some(b"PK\x03\x04".as_slice())).then_some(start as u64)
}

/// Whether the file at `path` is one that [`Archive::open_truncated`] can walk: not a split or spanned set, and
/// starting with a local header. [`Options::salvage_truncated_zip`] falls back to it only then.
pub(crate) fn salvageable(path: &Path) -> bool {
    if is_split_set(path) {
        return false;
    }
    let mut head = [0u8; 8];
    File::open(path)
        .and_then(|mut file| crate::tar::read_full(&mut file, &mut head))
        .is_ok_and(|got| local_walk_start(&head[..got]).is_some())
}

/// Whether `path` names a split or spanned set in any form, which [`Archive::open_cancelable`] reads across volumes.
fn is_split_set(path: &Path) -> bool {
    is_spanned(path) || is_headless_spanned(path) || is_byte_split(path)
}

pub(crate) fn is_byte_split(path: &Path) -> bool {
    byte_split::is_split_set(path) || spanned::is_spanned(path)
}

pub fn list(path: &Path) -> Result<Vec<Entry>> {
    list_detailed(path).map(|listing| listing.entries)
}

/// [`list`], also saying whether the archive ended unexpectedly: a byte-split set cut short by a missing piece,
/// listed from the local headers before the gap.
pub fn list_detailed(path: &Path) -> Result<crate::extract::Listing> {
    list_archive(Archive::open(path)?)
}

/// [`list_detailed`], and with [`Options::salvage_truncated_zip`] one file whose end record is missing (cut short)
/// is listed from its local headers, as 7-Zip lists it: [`crate::extract::Listing::truncated`] then says so.
pub fn list_detailed_with_options(path: &Path, options: &Options) -> Result<crate::extract::Listing> {
    list_archive(Archive::open_salvaging(path, options.salvage_truncated_zip, None)?)
}

/// The entries of one ZIP file cut short, from its local headers ([`Archive::open_truncated`]).
pub(crate) fn list_truncated(path: &Path) -> Result<Vec<Entry>> {
    list_archive(Archive::open_truncated(path, None)?).map(|listing| listing.entries)
}

fn list_archive(mut archive: Archive) -> Result<crate::extract::Listing> {
    let missing_volume = archive.missing.clone();
    let truncated = archive.truncated;
    // A symbolic link's target is its data: read for a listing when it is small, stored or deflated, and not
    // encrypted; otherwise left empty.
    let mut targets = Vec::with_capacity(archive.entries.len());
    let mut buf = vec![0u8; BUF];
    // The names are already held by the central directory; the targets read here are counted in a listing budget.
    let mut budget = crate::extract::ListingBudget::default();
    for (index, e) in archive.entries.iter().enumerate() {
        let mut text = Vec::new();
        if e.is_link()
            && archive.lost_volume(index).is_none()
            && !e.encrypted()
            && e.size <= crate::extract::link::MAX_TARGET
            && supported(e.effective_method())
        {
            let read = read_entry(
                &mut archive.file,
                archive.len,
                &e.read_description(),
                None,
                &mut buf,
                &mut |b| {
                    text.extend_from_slice(b);
                    Ok(())
                },
                None,
            );
            if read.is_err() {
                text.clear();
            }
            // The listing keeps the lossy decoding, so charge that length (each invalid byte becomes three).
            if let std::borrow::Cow::Owned(decoded) = String::from_utf8_lossy(&text) {
                text = decoded.into_bytes();
            }
            budget.record_link_bytes(text.len())?;
        }
        targets.push(text);
    }
    let unknown_at = archive.last_size_unknown.then(|| archive.entries.len().wrapping_sub(1));
    let entries = archive
        .entries
        .into_iter()
        .zip(targets)
        .enumerate()
        .map(|(i, (e, target))| {
            let dir = e.is_dir();
            let encrypted = e.encrypted();
            let link = e.is_link().then(|| Redirection::UnixSymlink(String::from_utf8_lossy(&target).into_owned()));
            let mode = e.unix_mode();
            let attributes = e.windows_attributes();
            Entry {
                mode,
                mtime_origin: e.mtime_origin,
                ctime: None,
                atime: None,
                tar: None,
                attributes,
                name: e.name,
                size: e.size,
                size_unknown: unknown_at == Some(i),
                packed: e.packed,
                mtime: e.mtime,
                crc32: (!dir).then_some(e.crc32),
                method: e.method.min(255) as u8,
                method_name: None,
                dir,
                encrypted,
                solid: false,
                link,
                version: None,
            }
        })
        .collect();
    Ok(crate::extract::Listing { entries, missing_volume, truncated, damaged_headers: Vec::new() })
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[allow(clippy::result_large_err)] // The public checked result preserves fixed failure evidence.
pub fn run_with_policy(
    path: &Path,
    options: &Options,
    password: Option<&str>,
    cancel: &Cancellation,
    overrides: &EncryptedReadOverrides,
    observe: impl ZipRunObserver,
) -> ZipReadResult<ZipRunReport> {
    read::with_opened_policy(ProjectedReadSession::open(path, cancel)?, options, password, cancel, overrides, observe)
}
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[allow(clippy::result_large_err)] // The public checked result preserves fixed failure evidence.
pub fn run_with_context(
    path: &Path,
    options: &Options,
    password: Option<&str>,
    cancel: &Cancellation,
    context: &mut EncryptedReadContext,
    observe: impl ZipRunObserver,
) -> ZipReadResult<ZipRunReport> {
    read::with_opened_context(ProjectedReadSession::open(path, cancel)?, options, password, cancel, context, observe)
}
pub fn run(path: &Path, opts: &Options, report: impl FnMut(&str)) -> Result<Summary> {
    run_with_password(path, opts, None, report)
}

pub fn run_with_password(
    path: &Path,
    opts: &Options,
    password: Option<&str>,
    mut report: impl FnMut(&str),
) -> Result<Summary> {
    run_renaming(path, opts, password, None, &mut report).map_err(|e| e.error)
}

/// [`run_with_password`], whose terminal error keeps the renames a rename mode made before it, and whose report
/// callback hears of each rename as it is made.
pub(crate) fn run_renaming(
    path: &Path,
    opts: &Options,
    password: Option<&str>,
    cancel: Option<&Cancellation>,
    report: &mut impl crate::extract::LegacyReport,
) -> std::result::Result<Summary, RunError> {
    let archive = Archive::open_salvaging(path, opts.salvage_truncated_zip, cancel)?;
    run_archive(archive, path, opts, password, cancel, report)
}

/// [`run_renaming`] for one file cut short, read by walking its local headers ([`Archive::open_truncated`]): the
/// checked route found no end record and [`Options::salvage_truncated_zip`] is on.
pub(crate) fn run_truncated(
    path: &Path,
    opts: &Options,
    password: Option<&str>,
    cancel: Option<&Cancellation>,
    report: &mut impl crate::extract::LegacyReport,
) -> std::result::Result<Summary, RunError> {
    run_archive(Archive::open_truncated(path, cancel)?, path, opts, password, cancel, report)
}

fn run_archive(
    mut archive: Archive,
    path: &Path,
    opts: &Options,
    password: Option<&str>,
    cancel: Option<&Cancellation>,
    report: &mut impl crate::extract::LegacyReport,
) -> std::result::Result<Summary, RunError> {
    use crate::extract::LegacyMember;
    let mut opts = opts.protecting(path)?;
    // Protect every piece of a byte-split set, not only the first.
    for piece in &archive.pieces {
        if let Ok(canonical) = piece.canonicalize() {
            opts.to_mut().protected_paths.insert(canonical);
        }
    }
    let opts = &*opts;
    let mut summary = Summary { volumes: archive.pieces.len().max(1) as u64, ..Summary::default() };
    let mut buf = vec![0u8; BUF];
    let entries = std::mem::take(&mut archive.entries);
    let password = password.filter(|s| !s.is_empty());
    /// A member failed: a line, and as its outcome the member's failure.
    fn fail(
        summary: &mut Summary,
        report: &mut impl crate::extract::LegacyReport,
        (ordinal, name): (u64, &str),
        why: &str,
    ) {
        let line = format!("{name}: {why}");
        report.line(&line);
        report.member(LegacyMember::Failed { ordinal, name, error: Error::Io(std::io::Error::other(why.to_owned())) });
        summary.errors.push(line);
    }
    /// A member passed over: a line, and as its outcome a skip.
    fn skipped(
        summary: &mut Summary,
        report: &mut impl crate::extract::LegacyReport,
        (ordinal, name): (u64, &str),
        why: &str,
    ) {
        report.line(&format!("{name}: {why}, skipped"));
        summary.skipped += 1;
        report.member(LegacyMember::Skipped { ordinal, name });
    }
    // ZIP holds no hard links: only symbolic ones are placed, and they never replace a file the run relies on.
    let mut extracted = crate::extract::link::Extracted::new(opts);
    // A run that stops early still says which files a rename mode renamed or moved aside.
    let result = (|| -> Result<()> {
        for (ordinal, e) in entries.iter().enumerate() {
            if let Some(cancel) = cancel {
                cancel.check_io()?;
            }
            if !opts.selects(&e.name, None, e.is_dir(), ordinal as u64) {
                continue;
            }
            let member = (ordinal as u64, e.name.as_str());
            summary.matched += 1;
            if e.is_dir() && crate::path::names_root_with(&e.name, !opts.literal_backslashes()) {
                continue;
            }
            let rel = match sanitize_with(&e.name, opts.zip_windows_names(e.host), opts.windows_safe_names) {
                Ok(rel) => rel,
                Err(err) => {
                    fail(&mut summary, report, member, &err.to_string());
                    continue;
                }
            };
            let rel = if opts.flatten { PathBuf::from(rel.file_name().unwrap_or_default()) } else { rel };
            if e.is_dir() {
                if opts.mode == Mode::Extract && !opts.flatten {
                    if let Some(why) = crate::extract::make_member_dirs(&opts.dest, &rel)? {
                        fail(&mut summary, report, member, why);
                        continue;
                    }
                    summary.dir_meta.push((opts.dest.join(&rel), opts.dir_meta(e.meta())));
                }
                summary.dirs += 1;
                report.member(LegacyMember::Succeeded { ordinal: member.0, name: member.1, bytes: 0 });
                continue;
            }
            let eff_method = e.effective_method();
            let refuse = if let Some(volume) = archive.lost_volume(ordinal) {
                Some(Error::MissingVolume(volume.to_path_buf()).to_string())
            } else if e.encrypted() && password.is_none() {
                Some("encrypted (password required)".to_string())
            } else if !supported(eff_method) {
                Some(format!("compression method {} is not supported yet", eff_method))
            } else if e.is_link() && e.size > crate::extract::link::MAX_TARGET {
                Some("the link's target is too long".to_string())
            } else {
                None
            };
            if let Some(why) = refuse {
                fail(&mut summary, report, member, &why);
                continue;
            }
            if e.is_link() {
                // The target is the member's data: read and checked whole before anything is placed.
                let mut text = Vec::new();
                let entry = e.read_description();
                let limit = crate::extract::link::MAX_TARGET as usize;
                let read = read_entry(
                    &mut archive.file,
                    archive.len,
                    &entry,
                    password,
                    &mut buf,
                    &mut |chunk| {
                        if text.len() + chunk.len() > limit {
                            return Err(Error::Corrupt("the link's target is too long"));
                        }
                        text.extend_from_slice(chunk);
                        Ok(())
                    },
                    cancel,
                );
                // a target reaching a missing volume fails only this link, as for a file
                if read.is_err()
                    && let Some(cause) = archive.gap_crossed(e)
                {
                    fail(&mut summary, report, member, &cause.to_string());
                    continue;
                }
                match read {
                    Err(Error::Io(io)) if io.kind() != std::io::ErrorKind::UnexpectedEof => return Err(Error::Io(io)),
                    Err(err) => {
                        fail(&mut summary, report, member, &err.to_string());
                        continue;
                    }
                    Ok(()) => {}
                }
                // testing checks the target as extracting would
                let kind = crate::extract::link::LinkKind::Symbolic(text);
                if let Some(why) = crate::extract::link::refusal_before_place(&rel, &kind, &extracted) {
                    fail(&mut summary, report, member, why);
                    continue;
                }
                if opts.mode == Mode::Extract {
                    let mut log = RenameLog {
                        placed: opts.replace_placed_links.then_some(&extracted),
                        budget: &mut summary.rename_budget,
                        record: &mut |renamed| {
                            report.renamed_member(member.0, &renamed);
                            summary.renames.push(renamed);
                        },
                    };
                    let place = match crate::extract::check_target(opts, &rel, None, &mut log)? {
                        crate::extract::Checked::Write(place) => place,
                        crate::extract::Checked::Exists => {
                            skipped(&mut summary, report, member, "exists");
                            continue;
                        }
                        crate::extract::Checked::Declined => {
                            skipped(&mut summary, report, member, "declined");
                            continue;
                        }
                        crate::extract::Checked::Blocked(why) => {
                            fail(&mut summary, report, member, why);
                            continue;
                        }
                    };
                    if let Err(io) = crate::extract::link::publish(
                        &opts.dest,
                        &rel,
                        place,
                        &kind,
                        opts.meta(e.meta()).modified(),
                        &mut extracted,
                    ) {
                        if let Some(why) = crate::extract::link::member_failure(&io) {
                            fail(&mut summary, report, member, why);
                            continue;
                        }
                        finish_dirs(&mut summary);
                        return Err(Error::Io(io));
                    }
                }
                summary.files += 1;
                report.member(LegacyMember::Succeeded { ordinal: member.0, name: member.1, bytes: 0 });
                continue;
            }
            let mut target = None;
            if opts.mode == Mode::Extract {
                let mut log = RenameLog {
                    placed: opts.replace_placed_links.then_some(&extracted),
                    budget: &mut summary.rename_budget,
                    record: &mut |renamed| {
                        report.renamed_member(member.0, &renamed);
                        summary.renames.push(renamed);
                    },
                };
                match open_target(opts, &rel, Some(e.size), &mut log)? {
                    Target::Write(out) => target = Some(out),
                    Target::Exists => {
                        skipped(&mut summary, report, member, "exists");
                        continue;
                    }
                    Target::Declined => {
                        skipped(&mut summary, report, member, "declined");
                        continue;
                    }
                    Target::Blocked(why) => {
                        fail(&mut summary, report, member, why);
                        continue;
                    }
                }
            }
            // Options::seven_zip_strict: a local header that differs from the central record fails the member before
            // it is decoded, as 7-Zip's "Headers Error" (with keep_broken its file stays empty, as 7-Zip leaves it)
            if opts.seven_zip_strict
                && let Some(found) = local_mismatch(&mut archive.file, archive.len, e)
            {
                let found = found.named(member.0, member.1);
                match target {
                    Some(out) if opts.keep_broken => {
                        let _ = out.finish(|file| crate::extract::keep_written(file, &opts.meta(e.meta())));
                    }
                    target => drop(target),
                }
                fail(&mut summary, report, member, &found.to_string());
                summary.local_header_mismatches.push(found);
                continue;
            }
            let mut entry = e.read_description();
            entry.keep_cut = opts.keep_broken;
            // The last member of a walk cut off before its descriptor has no known size: what is there of it is
            // read (it then fails at the gap), so a kept file (Options::keep_broken) holds it, as 7-Zip's does.
            if archive.last_size_unknown && ordinal + 1 == entries.len() {
                entry.size = if entry.effective_method() == METHOD_STORED { entry.packed } else { u64::MAX };
            }
            // a failure writing the output, told apart from a failure reading the entry: it is never kept
            let mut output_failed = false;
            let read = match target.as_mut() {
                Some(out) => read_entry(
                    &mut archive.file,
                    archive.len,
                    &entry,
                    password,
                    &mut buf,
                    &mut |chunk| {
                        out.write(chunk).map_err(|error| {
                            output_failed = true;
                            Error::Io(error)
                        })
                    },
                    cancel,
                ),
                None => read_entry(&mut archive.file, archive.len, &entry, password, &mut buf, &mut |_| Ok(()), cancel),
            };
            match read {
                Ok(()) => {
                    if let Some(out) = target
                        && let Err(io) = out.finish(|file| finish_file(file, &opts.meta(e.meta())))
                    {
                        finish_dirs(&mut summary);
                        return Err(Error::Io(io));
                    }
                    summary.files += 1;
                    summary.bytes += e.size;
                    report.member(LegacyMember::Succeeded { ordinal: member.0, name: member.1, bytes: e.size });
                }
                Err(err) => {
                    let gap = archive.gap_crossed(e);
                    // Options::keep_broken: what was written of an entry whose data fails stays (a failure writing
                    // the output stops the run, and the output is removed as always)
                    let writing = output_failed
                        || gap.is_none()
                            && matches!(&err, Error::Io(io) if io.kind() != std::io::ErrorKind::UnexpectedEof);
                    // a canceled run publishes nothing of the member in progress, whatever the read met
                    let canceled = cancel.is_some_and(Cancellation::is_canceled);
                    match target {
                        Some(out) if opts.keep_broken && !writing && !canceled => {
                            let _ = out.finish(|file| crate::extract::keep_written(file, &opts.meta(e.meta()), None));
                        }
                        target => drop(target),
                    }
                    if let Some(cause) = gap {
                        fail(&mut summary, report, member, &cause.to_string());
                        continue;
                    }
                    match err {
                        // a failure writing out stops the run; anything about this entry's data fails only the entry
                        Error::Io(io) if io.kind() != std::io::ErrorKind::UnexpectedEof => {
                            finish_dirs(&mut summary);
                            return Err(Error::Io(io));
                        }
                        Error::Io(_) => fail(&mut summary, report, member, &Error::Truncated.to_string()),
                        other => fail(&mut summary, report, member, &other.to_string()),
                    }
                }
            }
        }
        // a cancel from the last member's outcome callback is seen here, as the per-member check never runs again
        if let Some(cancel) = cancel {
            cancel.check_io()?;
        }
        // Members after the gap are unknown: the set as a whole is incomplete.
        if let Some(missing) = &archive.missing {
            let line = Error::MissingVolume(missing.clone()).to_string();
            report.line(&line);
            summary.errors.push(line);
        }
        // One file cut short (Options::salvage_truncated_zip): members past the cut are unknown, as for a set.
        if archive.truncated {
            let line = Error::Truncated.to_string();
            report.line(&line);
            summary.errors.push(line);
        }
        Ok(())
    })();
    match result {
        Ok(()) => {
            finish_dirs(&mut summary);
            Ok(summary)
        }
        Err(error) => Err(RunError::new(error, std::mem::take(&mut summary.renames))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::{self, Write};
    use std::ops::Range;

    /// Codex on #292: a partial read followed by a real input error gives the bytes and that error, not a made-up
    /// end of input, so a failing source still stops the run (`keep_cut` or not); a short input gives an end.
    #[test]
    fn fill_keeps_the_input_error_after_a_partial_read() {
        struct Failing(usize);
        impl io::Read for Failing {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.0 == 0 {
                    return Err(io::Error::from_raw_os_error(libc::EIO));
                }
                let n = self.0.min(buf.len());
                buf[..n].fill(7);
                self.0 -= n;
                Ok(n)
            }
        }
        let mut buf = [0u8; 16];
        let (got, cut) = fill(&mut Failing(5), &mut buf, true).unwrap();
        assert_eq!((got, cut.and_then(|e| e.raw_os_error())), (5, Some(libc::EIO)));
        let (got, cut) = fill(&mut &[1u8, 2, 3][..], &mut buf, true).unwrap();
        assert_eq!((got, cut.map(|e| e.kind())), (3, Some(io::ErrorKind::UnexpectedEof)));
        let (got, cut) = fill(&mut &[1u8; 20][..], &mut buf, true).unwrap();
        assert!(got == 16 && cut.is_none());
        assert_eq!(fill(&mut Failing(5), &mut buf, false).unwrap_err().raw_os_error(), Some(libc::EIO));
    }

    #[test]
    fn unix_extra_seconds_follows_the_dos_year() {
        let year = |y: u16| (y - 1980) << 9;
        assert_eq!(unix_extra_seconds(i32::MIN, year(2038)), 0x8000_0000);
        assert_eq!(unix_extra_seconds(-1, year(2106)), i64::from(u32::MAX));
        assert_eq!(unix_extra_seconds(-1, year(2037)), -1);
        assert_eq!(unix_extra_seconds(-1, year(1980)), -1);
        assert_eq!(unix_extra_seconds(i32::MAX, year(2107)), i64::from(i32::MAX));
        assert_eq!(unix_extra_seconds(5, year(2039)), 5);
    }

    fn sparse_directory(entries: u16, comment_len: u16, directory_size: u32) -> (tempfile::NamedTempFile, u64) {
        let mut archive = tempfile::NamedTempFile::new().unwrap();
        let mut central = [0; 50];
        central[..4].copy_from_slice(b"PK\x01\x02");
        central[28..30].copy_from_slice(&4u16.to_le_bytes());
        central[32..34].copy_from_slice(&comment_len.to_le_bytes());
        central[46..].copy_from_slice(b"item");
        for ordinal in 0..u64::from(entries) {
            let at = 30 + ordinal * (50 + u64::from(comment_len));
            archive.seek(SeekFrom::Start(at)).unwrap();
            archive.write_all(&central).unwrap();
        }

        let mut end = [0; 22];
        end[..4].copy_from_slice(b"PK\x05\x06");
        end[8..10].copy_from_slice(&entries.to_le_bytes());
        end[10..12].copy_from_slice(&entries.to_le_bytes());
        end[12..16].copy_from_slice(&directory_size.to_le_bytes());
        end[16..20].copy_from_slice(&30u32.to_le_bytes());
        archive.seek(SeekFrom::Start(30 + u64::from(directory_size))).unwrap();
        archive.write_all(&end).unwrap();
        (archive, 30 + u64::from(directory_size) + 22)
    }

    #[derive(Default)]
    struct ReadTrace {
        at: u64,
        ranges: Vec<Range<u64>>,
    }

    struct TracedFile<'a> {
        file: File,
        trace: ReadTrace,
        cancel_on_read_at: Option<(u64, &'a Cancellation)>,
    }

    impl Read for TracedFile<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.file.read(buf)?;
            let at = self.trace.at;
            self.trace.at += n as u64;
            self.trace.ranges.push(at..self.trace.at);
            if let Some((target, cancel)) = self.cancel_on_read_at
                && at == target
            {
                cancel.cancel();
            }
            Ok(n)
        }
    }

    impl Seek for TracedFile<'_> {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            self.trace.at = self.file.seek(pos)?;
            Ok(self.trace.at)
        }
    }

    fn read_traced_directory(
        file: &mut TracedFile<'_>,
        len: u64,
        cancel: Option<&Cancellation>,
    ) -> Result<Directory<ZipEntry>> {
        let parser = DirectoryParser::with_projection_and_name_crc32(
            len,
            Profile::Zipfast,
            Limits::default(),
            crate::crc32::hash,
            project_record,
        )
        .unwrap();
        read_directory(file, len, parser, cancel)
    }

    #[test]
    fn cancelable_open_accepts_a_large_directory_with_a_noncentral_trailer() {
        let (file, _) = sparse_directory(2, 0, 128 << 20);
        let cancel = Cancellation::default();
        let archive = Archive::open_cancelable(file.path(), Some(&cancel)).unwrap();
        assert_eq!(archive.entries.len(), 2);
        assert!(archive.entries.iter().all(|entry| entry.name == "item"));
    }

    #[test]
    fn directory_driver_bounds_source_requests_and_avoids_local_payloads() {
        const COUNT: u16 = 260;
        let (file, len) = sparse_directory(COUNT, u16::MAX, u32::from(COUNT) * (50 + u32::from(u16::MAX)));
        let mut file =
            TracedFile { file: file.reopen().unwrap(), trace: ReadTrace::default(), cancel_on_read_at: None };
        let parsed = read_traced_directory(&mut file, len, None).unwrap();
        assert_eq!(parsed.entries.len(), usize::from(COUNT));
        let sizes = file.trace.ranges.iter().map(|r| r.end - r.start);
        assert!(sizes.clone().max().unwrap() <= 16 << 20);
        assert!(file.trace.ranges.iter().all(|r| r.start >= 30 && r.end <= len));
        assert_eq!(sizes.sum::<u64>(), parsed.usage.fetched_bytes);
        assert!((16 << 20..=129 << 20).contains(&parsed.usage.fetched_bytes));
    }

    #[test]
    fn directory_byte_limit_stops_before_reading_the_sparse_directory() {
        let (file, len) = sparse_directory(2, 0, (128 << 20) + 1);
        let mut file =
            TracedFile { file: file.reopen().unwrap(), trace: ReadTrace::default(), cancel_on_read_at: None };
        assert!(matches!(read_traced_directory(&mut file, len, None), Err(Error::Unsupported(_))));
        assert_eq!(file.trace.ranges, vec![len - 65_633..len]);
    }

    #[test]
    fn directory_driver_stops_at_the_first_canceled_chunk() {
        let (file, len) = sparse_directory(2, 0, 128 << 20);
        let cancel = Cancellation::default();
        let mut file = TracedFile {
            file: file.reopen().unwrap(),
            trace: ReadTrace::default(),
            cancel_on_read_at: Some((76, &cancel)),
        };
        assert!(matches!(
            read_traced_directory(&mut file, len, Some(&cancel)),
            Err(Error::Io(error)) if error.kind() == io::ErrorKind::ConnectionAborted
        ));
        assert_eq!(file.trace.ranges.last(), Some(&(76..76 + (64 << 10))));
    }

    #[test]
    fn canceled_open_does_not_read_directory_metadata() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), [0; 22]).unwrap();
        let cancel = Cancellation::default();
        cancel.cancel();
        assert!(matches!(
            Archive::open_cancelable(file.path(), Some(&cancel)),
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::ConnectionAborted
        ));
    }

    #[test]
    fn dos_times() {
        // 2024-02-29 13:37:58
        let date = ((2024 - 1980) << 9) | (2 << 5) | 29;
        let time = (13 << 11) | (37 << 5) | 29;
        assert_eq!(dos_time(time, date), Some(1_709_213_878));
        assert_eq!(dos_time(0, 0), None);
    }

    #[test]
    fn names() {
        assert_eq!(decode_name(b"caf\x82", false).unwrap(), "café");
        assert_eq!(decode_name("café".as_bytes(), false).unwrap(), "café");
        assert_eq!(decode_name(b"a\xffb", true).unwrap(), "a\u{fffd}b");
    }
}
