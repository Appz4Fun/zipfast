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

//! tar archives, read from the POSIX ustar and pax layouts plus GNU's long-name records, either plain or inside a
//! gzip, xz, zstd or bzip2 stream. A compressed stream that holds no tar archive is one file, and comes out as that
//! file.

use std::fs::File;
use std::io::{self, BufReader, Read, Seek};
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::extract::link::{self, Extracted, LinkKind};
use crate::extract::{
    Cancellation, Checked, CompressedTar, Entry, LegacyMember, LegacyReport, ListingBudget, Meta, Mode, MtimeOrigin,
    Options, Overwrite, Place, RenameLog, RunError, SpecialEntries, Summary, check_target, create_sparse_target,
    create_target, finish_dirs, finish_file, make_member_dirs,
};
use crate::output::{Output, replace, replace_link, temporary};
use crate::path::sanitize;
use crate::rar5::Redirection;
use crate::stream::{self, Codec};

mod compress;
mod cpio;
mod iso;
mod table;
mod wim;
pub mod write;
mod xar;

pub use wim::WimInfo;

/// A member's data read from its own place in the file (xar, WIM, ISO 9660), not from the archive's stream.
trait MemberData: Read {
    /// Why the last read failed, when it was the data's own fault (a checksum, a size).
    fn fault(&mut self) -> Option<&'static str>;

    /// The data's length in the archive, when it differs from its size as extracted (compressed).
    fn packed(&self) -> Option<u64> {
        None
    }
}

/// An archive whose members are found by a table read first (xar's TOC, an ISO 9660 image's folders), each with
/// its data where the table puts it.
trait RandomAccess {
    fn next(&mut self) -> Result<Option<RandomMember>>;
}

/// A member of a [`RandomAccess`] archive, and a reader of its data when it has any.
type RandomMember = (Member, Option<Box<dyn MemberData>>);

const BLOCK: usize = 512;
/// Bytes moved per read.
const BUF: usize = 4 << 20;
/// The longest name, link target or pax record set taken from an extension record.
const MAX_EXT: u64 = 1 << 20;
const COMPRESSED_LIST_LIMIT: u64 = 8 << 30;
/// The most zero bytes an empty archive is taken to be: GNU tar pads one to 10 KiB, other writers to whole
/// records of up to this much.
const EMPTY_MAX: usize = 1 << 20;
/// The most pieces of data a sparse member's map may list. GNU tar starts a new map entry for every run of data,
/// so a real file needs about one per extent; this is far beyond that but keeps a hostile map to a few MiB.
const MAX_SPARSE_ENTRIES: usize = 1 << 18;
/// The most bytes a sparse map stored outside the headers may take: pax 1.0's in the data area, padding included,
/// or old GNU's extension blocks. A map in pax records is held to the records' own 1 MiB.
const MAX_SPARSE_MAP_BYTES: u64 = 8 << 20;
/// A sparse member may always make a file this long...
const SPARSE_FREE_SIZE: u64 = 1 << 30;
/// ...or this many times its stored data, whichever is more. A real sparse file (a VM image, a database) stores far
/// more than a thousandth of itself; a few KiB claiming a TiB is a bomb, and on a file system without holes (HFS+,
/// FAT, exFAT, or NTFS when the file can't be marked sparse) its holes would take real space. Such a member fails
/// on its own, whatever the route, and the members after it are still read.
const SPARSE_MAX_RATIO: u64 = 1024;

/// Whether the file starts with a tar header: a block whose checksum adds up, or the two zero blocks that make an
/// empty archive.
pub fn sniff_tar(head: &[u8]) -> bool {
    (head.len() >= BLOCK && checksum_ok(&head[..BLOCK])) || (head.len() >= 2 * BLOCK && zero(&head[..2 * BLOCK]))
}

/// Whether the file starts with a cpio header (binary in either byte order, odc, newc or newc with checksums),
/// which this module reads as it reads tar.
pub fn sniff_cpio(head: &[u8]) -> bool {
    cpio::sniff(head).is_some()
}

/// Whether the file starts with a xar header (`.xar`, a macOS `.pkg`), which this module reads as it reads tar.
pub fn sniff_xar(head: &[u8]) -> bool {
    head.len() >= 28 && head.starts_with(xar::MAGIC) && u16::from_be_bytes([head[4], head[5]]) >= 28
}

/// Whether the file starts with a WIM (Windows Imaging) header, which this module reads as it reads tar.
pub fn sniff_wim(head: &[u8]) -> bool {
    wim::sniff(head)
}

/// What the header of the WIM file at `path` says: its GUID, image count and compression.
pub fn wim_info(path: &Path) -> Result<WimInfo> {
    wim::info(&File::open(path)?)
}

/// Lists image `image` (from 1) of the WIM file at `path`; [`list`] and extraction take image 1.
pub fn list_wim_image(path: &Path, image: u32) -> Result<Vec<Entry>> {
    let mut head = [0u8; 16];
    let n = read_full(&mut File::open(path)?, &mut head)?;
    if !sniff_wim(&head[..n]) {
        return Err(Error::NotAnArchive);
    }
    // only the requested image's metadata is read: image 1 may be damaged while this one is whole
    list_members(Reader::open_image(path, 1, Some(COMPRESSED_LIST_LIMIT), None, false, image)?)
}

/// Whether `file` is an ISO 9660 image: "CD001" in the volume descriptor 32 KiB in.
pub fn sniff_iso(file: &File) -> bool {
    iso::sniff(file)
}

fn zero(b: &[u8]) -> bool {
    b.iter().all(|&b| b == 0)
}

/// The header checksum: every byte of the block added up, with the checksum field counted as spaces. Old writers
/// summed signed bytes, so either sum is taken.
fn checksum_ok(h: &[u8]) -> bool {
    if h.iter().all(|&b| b == 0) {
        return false;
    }
    let Some(stored) = octal(&h[148..156]) else { return false };
    let (mut unsigned, mut signed) = (0u64, 0i64);
    for (i, &b) in h[..BLOCK].iter().enumerate() {
        let b = if (148..156).contains(&i) { b' ' } else { b };
        unsigned += b as u64;
        signed += b as i8 as i64;
    }
    stored == unsigned || stored as i64 == signed
}

/// An octal field: optional leading spaces, digits, then a space or NUL. An empty field is no number.
fn octal(field: &[u8]) -> Option<u64> {
    let mut digits = field.iter().skip_while(|&&b| b == b' ').take_while(|&&b| b != 0 && b != b' ').peekable();
    digits.peek()?;
    let mut v: u64 = 0;
    for &d in digits {
        if !(b'0'..=b'7').contains(&d) {
            return None;
        }
        v = v.checked_mul(8)?.checked_add((d - b'0') as u64)?;
    }
    Some(v)
}

/// A numeric field: octal, or GNU's base-256 form when the top bit of the first byte is set. Negative base-256
/// values (a first byte of 0xff) are returned as negative.
fn number(field: &[u8]) -> Option<i64> {
    match field.first() {
        Some(&b) if b & 0x80 != 0 => {
            // the bits after the marker are a big-endian two's complement number
            let mut v = (b & 0x7f) as i64;
            if b & 0x40 != 0 {
                v -= 0x80;
            }
            for &b in &field[1..] {
                v = v.checked_mul(256)?.checked_add(b as i64)?;
            }
            Some(v)
        }
        _ => octal(field).and_then(|v| i64::try_from(v).ok()),
    }
}

/// Text from a NUL-padded field.
fn text(field: &[u8]) -> &[u8] {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    &field[..end]
}

/// Opens `path`, which on Unix has to be the file `expect` describes (same device and inode) when given: opened
/// then without following a symlink and without blocking on a FIFO put in its place.
fn open_same(path: &Path, expect: Option<&std::fs::Metadata>) -> Result<File> {
    #[cfg(unix)]
    if let Some(expect) = expect {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let file =
            std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)?;
        let got = file.metadata()?;
        if (got.dev(), got.ino()) != (expect.dev(), expect.ino()) {
            return Err(Error::Unsupported(format!("{} changed while it was being read", path.display())));
        }
        return Ok(file);
    }
    #[cfg(not(unix))]
    let _ = expect;
    Ok(File::open(path)?)
}

fn name_of(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Where the archive's bytes come from: the file itself, which can be skipped through, or a compressed stream,
/// which has to be read.
enum Source {
    Plain {
        r: BufReader<File>,
        len: u64,
        pos: u64,
        cancel: Option<Cancellation>,
    },
    /// the decoder, its codec, and how many decoded bytes have been read from it
    Packed(Box<dyn Read>, Codec, u64),
}

impl Source {
    fn open(mut file: File, threads: usize, limit: Option<u64>, cancel: Option<Cancellation>) -> Result<Source> {
        let mut head = [0u8; stream::SNIFF_BYTES];
        let n = read_full(&mut file, &mut head)?;
        file.rewind()?;
        let len = file.metadata()?.len();
        let Some(codec) = Codec::sniff(&head[..n]) else {
            return Ok(Source::Plain { r: BufReader::with_capacity(1 << 20, file), len, pos: 0, cancel });
        };
        // A cancellation is checked as the packed bytes are read and as decoded bytes come out, so a decoder that
        // loops on its input without producing output still stops.
        let Some(limit) = limit.or(cancel.as_ref().map(|_| u64::MAX)) else {
            let reader = BufReader::with_capacity(1 << 20, file);
            return Ok(Source::Packed(codec.open(reader, threads).map_err(read_error)?, codec, 0));
        };
        if len > limit {
            return Err(Error::Unsupported("compressed stream exceeds the input byte limit".into()));
        }
        let packed = Limited {
            inner: file,
            remaining: limit,
            cancel: cancel.clone(),
            message: "compressed stream exceeds the input byte limit",
        };
        let decoder = codec.open_reader(BufReader::with_capacity(1 << 20, packed), threads).map_err(read_error)?;
        let decoded = Limited {
            inner: decoder,
            remaining: limit,
            cancel,
            message: "compressed stream exceeds the decoded byte limit",
        };
        Ok(Source::Packed(Box::new(decoded), codec, 0))
    }

    /// Fills `buf` unless the stream ends first; returns how much was read.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let n = match self {
            Source::Plain { r, pos, cancel, .. } => {
                if let Some(cancel) = cancel {
                    cancel.check_io()?;
                }
                let n = read_full(r, buf).map_err(read_error)?;
                *pos += n as u64;
                n
            }
            Source::Packed(r, _, decoded) => {
                let n = read_full(r, buf).map_err(read_error)?;
                *decoded += n as u64;
                n
            }
        };
        Ok(n)
    }

    /// Passes over `n` bytes, which must all be there.
    fn skip(&mut self, n: u64, buf: &mut [u8]) -> Result<()> {
        match self {
            Source::Plain { r, len, pos, cancel } => {
                if let Some(cancel) = cancel {
                    cancel.check_io()?;
                }
                if *len - *pos < n {
                    return Err(Error::Truncated);
                }
                r.seek_relative(n as i64)?;
                *pos += n;
                Ok(())
            }
            Source::Packed(..) => {
                let mut left = n;
                while left > 0 {
                    let want = left.min(buf.len() as u64) as usize;
                    let got = self.read(&mut buf[..want])?;
                    if got < want {
                        return Err(Error::Truncated);
                    }
                    left -= got as u64;
                }
                Ok(())
            }
        }
    }

    /// Puts `bytes`, just read, back in front of what is left.
    fn unread(&mut self, bytes: Vec<u8>) -> Result<()> {
        match self {
            Source::Plain { r, pos, .. } => {
                r.seek_relative(-(bytes.len() as i64))?;
                *pos -= bytes.len() as u64;
            }
            Source::Packed(r, _, _) => {
                let rest = std::mem::replace(r, Box::new(io::empty()));
                *r = Box::new(io::Cursor::new(bytes).chain(rest));
            }
        }
        Ok(())
    }

    /// Fails once the run is canceled: for reads that don't go through [`Source::read`] (a member's data read
    /// from its own place in the file).
    fn check_cancel(&self) -> Result<()> {
        if let Source::Plain { cancel: Some(cancel), .. } = self {
            cancel.check_io()?;
        }
        Ok(())
    }

    fn codec(&self) -> Option<Codec> {
        match self {
            Source::Packed(_, c, _) => Some(*c),
            Source::Plain { .. } => None,
        }
    }
}

struct Limited<R> {
    inner: R,
    remaining: u64,
    cancel: Option<Cancellation>,
    message: &'static str,
}

impl<R: Read> Read for Limited<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(cancel) = &self.cancel {
            cancel.check_io()?;
        }
        if buf.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            return match self.inner.read(&mut [0])? {
                0 => Ok(0),
                _ => Err(io::Error::new(io::ErrorKind::FileTooLarge, self.message)),
            };
        }
        let len = self.remaining.min(buf.len() as u64) as usize;
        let count = self.inner.read(&mut buf[..len])?;
        self.remaining -= count as u64;
        Ok(count)
    }
}

pub(crate) fn read_full(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

/// A failed read of the archive. The decoders report damage in different ways, so anything but a failure of the
/// disk itself counts as damage.
fn read_error(e: io::Error) -> Error {
    match e.kind() {
        io::ErrorKind::ConnectionAborted => Error::Io(e),
        io::ErrorKind::FileTooLarge if e.raw_os_error().is_none() => Error::Unsupported(e.to_string()),
        io::ErrorKind::UnexpectedEof => Error::Truncated,
        io::ErrorKind::PermissionDenied | io::ErrorKind::NotFound | io::ErrorKind::Interrupted => Error::Io(e),
        _ if e.raw_os_error().is_some() => Error::Io(e),
        _ => Error::Corrupt("compressed data is damaged"),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    File,
    Dir,
    Symlink,
    HardLink,
    /// a device, a pipe, or a GNU record this reader doesn't restore
    Other(u8),
}

/// One member, with any long-name and pax records before it already applied.
#[derive(Clone, Debug)]
struct Member {
    name: String,
    /// the stored name's bytes, kept only when they aren't UTF-8 and `name` had to replace some
    raw_name: Option<Vec<u8>>,
    link: String,
    /// the stored link target's bytes, kept only when they aren't UTF-8 and `link` had to replace some
    raw_link: Option<Vec<u8>>,
    size: u64,
    kind: Kind,
    mtime: Option<i64>,
    nanos: u32,
    mode: u32,
    atime: Option<(i64, u32)>,
    ctime: Option<(i64, u32)>,
    /// read from a cpio archive: its listing entry carries no tar metadata
    cpio: bool,
    tar: Box<TarMetadata>,
    /// A sparse member's map: `size` is then the stored data only, and the file is `real_size` bytes long.
    sparse: Option<Box<SparseMap>>,
}

/// Where a sparse member's stored data goes in the file: every byte not in a piece is a hole (zeros).
#[derive(Clone, Debug, PartialEq, Eq)]
struct SparseMap {
    real_size: u64,
    /// (offset, length) pieces, sorted and not overlapping, each inside `real_size`; their lengths add up to the
    /// member's stored size
    pieces: Vec<(u64, u64)>,
}

impl SparseMap {
    /// Checks a map read from the archive against the file's size and the stored data's size.
    fn checked(real_size: u64, pieces: Vec<(u64, u64)>, stored: u64) -> Result<Box<SparseMap>> {
        let bad = |why| Err(Error::Corrupt(why));
        if pieces.len() > MAX_SPARSE_ENTRIES {
            return bad("a sparse map has too many entries");
        }
        let (mut end, mut total) = (0u64, 0u64);
        for &(offset, len) in &pieces {
            if offset < end {
                return bad("a sparse map's entries are out of order or overlap");
            }
            end = match offset.checked_add(len) {
                Some(e) if e <= real_size => e,
                _ => return bad("a sparse map's entry lies past the end of the file"),
            };
            total += len;
        }
        if total != stored {
            return bad("a sparse map's entries don't add up to the stored data");
        }
        Ok(Box::new(SparseMap { real_size, pieces }))
    }
}

/// A piece of a member's data on its way out: bytes, or a run of zeros left as a hole where the file system can.
enum Piece<'a> {
    Data(&'a [u8]),
    Hole(u64),
}

/// The GNU sparse records of a member's own pax header, in whichever of the 0.0, 0.1 and 1.0 forms it uses.
#[derive(Clone, Debug, Default)]
struct SparsePax {
    major: Option<u64>,
    minor: Option<u64>,
    /// `GNU.sparse.name`: the member's real name (its header holds a made-up `GNUSparseFile.<pid>/` one)
    name: Option<String>,
    /// `GNU.sparse.realsize` (1.0) or `GNU.sparse.size` (0.x)
    real_size: Option<u64>,
    /// `GNU.sparse.map` (0.1): "offset,length,offset,length,..."
    map: Option<Vec<u8>>,
    /// `GNU.sparse.offset` and `GNU.sparse.numbytes` records in turn (0.0)
    pairs: Vec<(u64, Option<u64>)>,
}

/// Sets a sparse record's value, which a second record may repeat but not change.
fn once<T: PartialEq>(slot: &mut Option<T>, value: T) -> Result<()> {
    match slot {
        Some(old) if *old != value => Err(Error::Corrupt("a sparse member's pax records conflict")),
        _ => {
            *slot = Some(value);
            Ok(())
        }
    }
}

/// Most pax records kept for a listing per member.
const MAX_PAX_RECORDS: usize = 256;
/// Bytes of pax records and raw headers kept across a whole listing.
const META_BUDGET: usize = 64 << 20;

/// The listing-wide budget for [`TarMetadata::pax_records`] and [`TarMetadata::header`]: past it, members keep
/// neither.
struct MetaBudget {
    left: usize,
    /// Whether the last [`Self::take`] kept its records.
    kept: bool,
}

impl MetaBudget {
    fn new() -> Self {
        Self { left: META_BUDGET, kept: true }
    }

    /// Charges a member's records; false (and nothing charged) when they don't fit. No records always fit.
    fn take(&mut self, records: &[(String, Vec<u8>)]) -> bool {
        let cost: usize = records.iter().map(|(k, v)| k.len() + v.len() + 2 * std::mem::size_of::<Vec<u8>>()).sum();
        self.kept = cost <= self.left;
        if self.kept {
            self.left -= cost;
        }
        self.kept
    }

    fn take_header(&mut self) -> bool {
        let fits = self.left >= BLOCK;
        if fits {
            self.left -= BLOCK;
        }
        fits
    }
}

/// Which header layout a tar member uses, from its magic field (bytes 257..265).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum TarMagic {
    /// POSIX ustar (`ustar\0` and a version): what 7-Zip lists as `POSIX`.
    Ustar,
    /// GNU tar (`ustar  \0`): 7-Zip's `GNU`.
    Gnu,
    /// No magic: a pre-POSIX (V7) header.
    V7,
    /// Anything else.
    Other,
}

impl TarMagic {
    fn of(h: &[u8; BLOCK]) -> Self {
        match &h[257..265] {
            m if &m[..6] == b"ustar\0" => Self::Ustar,
            b"ustar  \0" => Self::Gnu,
            m if m.iter().all(|&b| b == 0) => Self::V7,
            _ => Self::Other,
        }
    }
}

/// What a tar header records beyond the common listing fields, for a 7-Zip-style `l -slt` (User, Group, User ID,
/// Group ID, Device Major/Minor, Characteristics, and the pax header's name as Comment).
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct TarMetadata {
    pub magic: TarMagic,
    /// The type flag byte (`0` file, `5` folder, `2` symlink, ...), as stored.
    pub typeflag: u8,
    /// Owner name: a pax `uname` record, else the header's (None in a V7 header, which has no such field).
    pub user: Option<String>,
    /// Group name: a pax `gname` record, else the header's (None in a V7 header).
    pub group: Option<String>,
    /// Owner id: a pax `uid` record, else the header's, when it reads as a number.
    pub uid: Option<u64>,
    pub gid: Option<u64>,
    /// Device numbers when the header's fields read as numbers (GNU tar leaves them blank; None in V7 headers).
    pub device_major: Option<u64>,
    pub device_minor: Option<u64>,
    /// The name field of the member's own pax extended header (`PaxHeader/name`), when it has one.
    pub pax_header_name: Option<String>,
    /// The member's own pax records (not global ones) in order, as key and raw value; at most 256 are kept per
    /// member, and none once the listing's 64 MiB budget for records and headers is spent.
    pub pax_records: Vec<(String, Vec<u8>)>,
    /// The member had pax records that the listing's budget left out of `pax_records`.
    pub pax_records_truncated: bool,
    /// The member's header block exactly as stored; None once the listing's budget is spent.
    pub header: Option<Box<[u8; BLOCK]>>,
}

impl Member {
    fn meta(&self) -> Meta {
        Meta { mtime: self.mtime, nanos: self.nanos, mode: Some(self.mode) }
    }

    /// A character or block device or a FIFO, which [`SpecialEntries::EmptyFile`] writes as an empty file.
    fn is_special(&self) -> bool {
        matches!(self.kind, Kind::Other(b'3' | b'4' | b'6'))
    }

    /// Turns a device or FIFO member into an empty regular file. Its data, if the header claims any, stays unread
    /// and is passed over with the padding.
    fn as_empty_file(&mut self) {
        self.kind = Kind::File;
        self.size = 0;
        self.sparse = None;
    }

    /// The length of the file the member makes: its sparse size, or its stored size.
    fn real_size(&self) -> u64 {
        self.sparse.as_ref().map_or(self.size, |s| s.real_size)
    }

    /// Why a sparse member is refused: it would make a file far larger than its stored data warrants.
    fn sparse_refusal(&self) -> Option<&'static str> {
        let map = self.sparse.as_ref()?;
        let most = SPARSE_FREE_SIZE.max(self.size.saturating_mul(SPARSE_MAX_RATIO));
        (map.real_size > most).then_some(
            "a sparse member's real size is more than 1 GiB and 1024 times its stored data: refused as a bomb",
        )
    }

    fn into_entry(self) -> Entry {
        let real_size = self.real_size();
        let link = match self.kind {
            Kind::Symlink => Some(Redirection::UnixSymlink(self.link)),
            Kind::HardLink => Some(Redirection::HardLink(self.link)),
            _ => None,
        };
        let data = self.kind == Kind::File;
        Entry {
            mode: Some(self.mode),
            mtime_origin: self.mtime.map(|_| MtimeOrigin::Utc),
            ctime: self.ctime,
            atime: self.atime,
            tar: (!self.cpio).then_some(self.tar),
            attributes: None,
            name: self.name,
            size: if data { real_size } else { 0 },
            size_unknown: false,
            packed: if data { self.size } else { 0 },
            mtime: self.mtime,
            crc32: None,
            method: 0,
            method_name: None,
            dir: self.kind == Kind::Dir,
            encrypted: false,
            solid: false,
            link,
            version: None,
        }
    }
}

/// Values from pax records, for the next member or (from a global record) for every member after.
#[derive(Clone, Debug, Default)]
struct Pax {
    /// `path` and `linkpath` as stored: a pax header with `hdrcharset=BINARY` may hold bytes that aren't UTF-8
    path: Option<Vec<u8>>,
    linkpath: Option<Vec<u8>>,
    size: Option<u64>,
    mtime: Option<(i64, u32)>,
    atime: Option<(i64, u32)>,
    ctime: Option<(i64, u32)>,
    /// Owner fields: None when no record set them, `Some(None)` when an empty record deleted them (the header's
    /// field applies again, not a global record's).
    uname: Option<Option<String>>,
    gname: Option<Option<String>>,
    uid: Option<Option<u64>>,
    gid: Option<Option<u64>>,
    sparse: bool,
    gnu_sparse: SparsePax,
    /// Every record, in order, as stored.
    records: Vec<(String, Vec<u8>)>,
}

impl Pax {
    /// Records of the form "<length> <key>=<value>\n", where the length counts the whole record.
    fn parse(&mut self, data: &[u8]) -> Result<()> {
        let bad = || Error::Corrupt("a pax record is malformed");
        let mut rest = data;
        while !rest.is_empty() {
            if rest.iter().all(|&b| b == 0) {
                break;
            }
            let space = rest.iter().position(|&b| b == b' ').ok_or_else(bad)?;
            let len: usize = std::str::from_utf8(&rest[..space]).ok().and_then(|s| s.parse().ok()).ok_or_else(bad)?;
            if len <= space + 1 || len > rest.len() || rest[len - 1] != b'\n' {
                return Err(bad());
            }
            let record = &rest[space + 1..len - 1];
            rest = &rest[len..];
            let eq = record.iter().position(|&b| b == b'=').ok_or_else(bad)?;
            let (key, value) = (&record[..eq], &record[eq + 1..]);
            if self.records.len() < MAX_PAX_RECORDS {
                self.records.push((name_of(key), value.to_vec()));
            }
            let id = || -> Result<Option<u64>> {
                if value.is_empty() {
                    return Ok(None);
                }
                std::str::from_utf8(value).ok().and_then(|s| s.parse().ok()).map(Some).ok_or_else(bad)
            };
            let owner = || (!value.is_empty()).then(|| name_of(value));
            match key {
                b"atime" => self.atime = parse_time(value),
                b"ctime" => self.ctime = parse_time(value),
                b"uname" => self.uname = Some(owner()),
                b"gname" => self.gname = Some(owner()),
                b"uid" => self.uid = Some(id()?),
                b"gid" => self.gid = Some(id()?),
                b"path" => self.path = Some(value.to_vec()),
                b"linkpath" => self.linkpath = Some(value.to_vec()),
                b"size" => {
                    self.size = Some(std::str::from_utf8(value).ok().and_then(|s| s.parse().ok()).ok_or_else(bad)?)
                }
                b"mtime" => self.mtime = parse_time(value),
                k if k.starts_with(b"GNU.sparse.") => {
                    self.sparse = true;
                    let num = || -> Result<u64> {
                        std::str::from_utf8(value).ok().and_then(|s| s.parse().ok()).ok_or_else(bad)
                    };
                    let g = &mut self.gnu_sparse;
                    match &k[11..] {
                        b"major" => once(&mut g.major, num()?)?,
                        b"minor" => once(&mut g.minor, num()?)?,
                        b"name" => once(&mut g.name, name_of(value))?,
                        b"realsize" | b"size" => once(&mut g.real_size, num()?)?,
                        b"map" => once(&mut g.map, value.to_vec())?,
                        b"offset" => {
                            if g.pairs.len() >= MAX_SPARSE_ENTRIES {
                                return Err(Error::Corrupt("a sparse map has too many entries"));
                            }
                            g.pairs.push((num()?, None));
                        }
                        b"numbytes" => match g.pairs.last_mut() {
                            Some((_, len @ None)) => *len = Some(num()?),
                            _ => return Err(Error::Corrupt("a sparse map's numbytes has no offset before it")),
                        },
                        _ => {}
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// `self` over `under`, key by key.
    fn over(&self, under: &Pax) -> Pax {
        Pax {
            path: self.path.clone().or_else(|| under.path.clone()),
            linkpath: self.linkpath.clone().or_else(|| under.linkpath.clone()),
            size: self.size.or(under.size),
            mtime: self.mtime.or(under.mtime),
            atime: self.atime.or(under.atime),
            ctime: self.ctime.or(under.ctime),
            uname: self.uname.clone().or_else(|| under.uname.clone()),
            gname: self.gname.clone().or_else(|| under.gname.clone()),
            uid: self.uid.or(under.uid),
            gid: self.gid.or(under.gid),
            // a sparse map belongs to one member: a global record can't give one
            sparse: self.sparse,
            gnu_sparse: self.gnu_sparse.clone(),
            // only the member's own records
            records: self.records.clone(),
        }
    }
}

/// A pax time: decimal seconds, maybe negative, maybe with a fraction.
fn parse_time(v: &[u8]) -> Option<(i64, u32)> {
    let s = std::str::from_utf8(v).ok()?;
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    let secs: i64 = whole.parse().ok()?;
    if !frac.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut digits: String = frac.chars().take(9).collect();
    while digits.len() < 9 {
        digits.push('0');
    }
    let mut nanos: u32 = digits.parse().ok()?;
    let mut secs = secs;
    // "-1.5" is half a second before -1, so a negative time with a fraction borrows a second
    if whole.starts_with('-') && nanos > 0 {
        secs = secs.checked_sub(1)?;
        nanos = 1_000_000_000 - nanos;
    }
    Some((secs, nanos))
}

/// What the archive turned out to hold.
enum Content {
    Tar,
    /// one compressed file; the start of its data is in the reader's buffer
    Single,
}

struct Reader {
    src: Source,
    /// the run's cancellation, also checked between the publications of a staged (compressed) tar
    cancel: Option<Cancellation>,
    content: Content,
    /// the start of the data, read to tell tar from a lone compressed file: one header block for tar
    first: Option<Vec<u8>>,
    /// data and padding of the current member not read yet
    unread: u64,
    global: Pax,
    /// What is left of the listing's budget for pax records and raw headers.
    meta_budget: MetaBudget,
    scratch: Vec<u8>,
    /// set when the archive is cpio, not tar
    cpio: Option<Box<cpio::State>>,
    /// the checksum of the current member's data, in a newc archive with checksums
    crc: Option<CpioCrc>,
    /// set when the archive is read from a table (xar's TOC, a WIM's lookup table, an ISO 9660 image's folders):
    /// its members, and the current one's data
    random: Option<Box<dyn RandomAccess>>,
    member_data: Option<Box<dyn MemberData>>,
}

/// A newc `070702` member's checksum: the sum of its data bytes, checked as the last of them is read.
struct CpioCrc {
    want: u32,
    sum: u32,
    left: u64,
}

impl Reader {
    fn open_with_limit(
        path: &Path,
        threads: usize,
        limit: Option<u64>,
        cancel: Option<Cancellation>,
        whole: bool,
    ) -> Result<Reader> {
        Self::open_checked(path, None, threads, limit, cancel, whole, 1)
    }

    /// [`Reader::open_with_limit`], taking image `wim_image` (from 1) of a WIM file.
    fn open_image(
        path: &Path,
        threads: usize,
        limit: Option<u64>,
        cancel: Option<Cancellation>,
        whole: bool,
        wim_image: u32,
    ) -> Result<Reader> {
        Self::open_checked(path, None, threads, limit, cancel, whole, wim_image)
    }

    /// [`Reader::open_with_limit`] for image `wim_image` (from 1) of a WIM file, refusing (on Unix) to read any file
    /// at `path` but the one `expect` describes, so a path swapped after the caller checked it is not read in its place.
    fn open_checked(
        path: &Path,
        expect: Option<&std::fs::Metadata>,
        threads: usize,
        limit: Option<u64>,
        cancel: Option<Cancellation>,
        whole: bool,
        wim_image: u32,
    ) -> Result<Reader> {
        let open = || open_same(path, expect);
        let mut src = Source::open(open()?, threads, limit, cancel.clone())?;
        let mut first = vec![0u8; BLOCK];
        let n = src.read(&mut first)?;
        first.truncate(n);
        let mut cpio = None;
        let mut random: Option<Box<dyn RandomAccess>> = None;
        let plain = matches!(src, Source::Plain { .. });
        // CompressedTar::Whole: whatever is inside a compression layer is one file, as 7-Zip reads it
        let whole = whole && src.codec().is_some();
        let mut content = if whole {
            Some(Content::Single)
        } else if n == BLOCK && checksum_ok(&first) {
            Some(Content::Tar)
        } else if plain && sniff_xar(&first) {
            // xar data is read where the table of contents puts it, from the file itself
            let file = open()?;
            let len = file.metadata()?.len();
            random = Some(Box::new(xar::open(file, len)?));
            first.clear();
            Some(Content::Tar)
        } else if plain && sniff_wim(&first) {
            // WIM data is read where the lookup table puts it, from the file itself; image 1 unless asked for another
            let file = open()?;
            let len = file.metadata()?.len();
            random = Some(Box::new(wim::open(file, len, wim_image)?));
            first.clear();
            Some(Content::Tar)
        } else if plain && n == BLOCK && iso::sniff(&open()?) {
            // an ISO 9660 image: its tree is read from the volume descriptors 32 KiB in
            let file = open()?;
            let len = file.metadata()?.len();
            random = Some(Box::new(iso::open(file, len)?));
            first.clear();
            Some(Content::Tar)
        } else if let Some(format) = cpio::sniff(&first) {
            // cpio headers aren't blocks: what was read goes back, and members are read from the start
            src.unread(std::mem::take(&mut first))?;
            cpio = Some(Box::new(cpio::State::new(format)));
            Some(Content::Tar)
        } else if src.codec().is_some() {
            Some(Content::Single)
        } else {
            None
        };
        if !whole && n == BLOCK && cpio.is_none() && random.is_none() && zero(&first) {
            // an empty archive is zero blocks and nothing else; a compressed file that only starts with zeros is
            // a file
            first.resize(EMPTY_MAX + 1, 0);
            let more = src.read(&mut first[BLOCK..])?;
            first.truncate(BLOCK + more);
            let len = first.len();
            if (2 * BLOCK..=EMPTY_MAX).contains(&len) && len.is_multiple_of(BLOCK) && zero(&first) {
                content = Some(Content::Tar);
                // nothing is left for the first header: the archive ends at once
                first.clear();
            }
        }
        let Some(content) = content else { return Err(Error::NotAnArchive) };
        Ok(Reader {
            src,
            cancel,
            content,
            first: Some(first),
            unread: 0,
            global: Pax::default(),
            meta_budget: MetaBudget::new(),
            scratch: vec![0; 64 << 10],
            cpio,
            crc: None,
            random,
            member_data: None,
        })
    }

    /// The next header block, or None at the end of the archive: a zero block, or the end of the data exactly at
    /// a block boundary (some writers leave out the end marker).
    fn header_block(&mut self) -> Result<Option<[u8; BLOCK]>> {
        if let Some(first) = self.first.take() {
            // an empty archive leaves nothing here
            return Ok(first.as_slice().try_into().ok());
        }
        let mut block = [0u8; BLOCK];
        match self.src.read(&mut block)? {
            0 => Ok(None),
            BLOCK if block.iter().all(|&b| b == 0) => Ok(None),
            BLOCK if checksum_ok(&block) => Ok(Some(block)),
            BLOCK => Err(Error::Corrupt("a tar header fails its checksum")),
            _ => Err(Error::Truncated),
        }
    }

    /// The data of an extension record, `size` bytes followed by padding.
    fn ext_data(&mut self, size: u64) -> Result<Vec<u8>> {
        if size > MAX_EXT {
            return Err(Error::Corrupt("an extension record is too long"));
        }
        let mut data = vec![0u8; size as usize];
        if self.src.read(&mut data)? < data.len() {
            return Err(Error::Truncated);
        }
        self.src.skip(padding(size), &mut self.scratch)?;
        Ok(data)
    }

    /// The next member, after passing over whatever is left of the one before.
    fn next(&mut self) -> Result<Option<Member>> {
        if self.cpio.is_some() {
            return self.next_cpio();
        }
        if let Some(state) = &mut self.random {
            self.member_data = None;
            self.src.check_cancel()?;
            let Some((member, data)) = state.next()? else { return Ok(None) };
            self.member_data = data;
            return Ok(Some(member));
        }
        if self.unread > 0 {
            let n = std::mem::take(&mut self.unread);
            self.src.skip(n, &mut self.scratch)?;
        }
        let mut long_name: Option<Vec<u8>> = None;
        let mut long_link: Option<Vec<u8>> = None;
        let mut pax = Pax::default();
        let mut pax_header_name = None;
        loop {
            let Some(h) = self.header_block()? else { return Ok(None) };
            let kind = h[156];
            let size = number(&h[124..136]).and_then(|v| u64::try_from(v).ok());
            let Some(size) = size else { return Err(Error::Corrupt("a tar header's size is unreadable")) };
            match kind {
                b'L' => {
                    long_name = Some(text(&self.ext_data(size)?).to_vec());
                    continue;
                }
                b'K' => {
                    long_link = Some(text(&self.ext_data(size)?).to_vec());
                    continue;
                }
                b'x' | b'X' => {
                    pax_header_name = Some(name_of(text(&h[0..100])));
                    let data = self.ext_data(size)?;
                    pax.parse(&data)?;
                    continue;
                }
                b'g' => {
                    let data = self.ext_data(size)?;
                    self.global.parse(&data)?;
                    // a name or size shared by every member after would make no sense: only times carry over
                    self.global.path = None;
                    self.global.linkpath = None;
                    self.global.size = None;
                    self.global.records.clear();
                    self.global.sparse = false;
                    self.global.gnu_sparse = SparsePax::default();
                    continue;
                }
                _ => {}
            }
            let p = pax.over(&self.global);
            let ustar = &h[257..263] == b"ustar\0";
            let mut name = text(&h[0..100]).to_vec();
            if ustar {
                let prefix = text(&h[345..500]);
                if !prefix.is_empty() {
                    name = [prefix, b"/", &name].concat();
                }
            }
            let real_name = if p.sparse { p.gnu_sparse.name.clone() } else { None };
            let (name, raw_name) = match real_name {
                Some(path) => (path, None),
                None => {
                    let stored = p.path.clone().or(long_name).unwrap_or(name);
                    let decoded = name_of(&stored);
                    (decoded, std::str::from_utf8(&stored).is_err().then_some(stored))
                }
            };
            let stored_link = p.linkpath.clone().or(long_link).unwrap_or_else(|| text(&h[157..257]).to_vec());
            let link = name_of(&stored_link);
            let raw_link = std::str::from_utf8(&stored_link).is_err().then_some(stored_link);
            let mut size = p.size.unwrap_or(size);
            // the size with its padding has to be a number too
            if size > u64::MAX - BLOCK as u64 {
                return Err(Error::Corrupt("a tar member's size is impossible"));
            }
            let (mtime, nanos) = match p.mtime {
                Some((s, n)) => (Some(s), n),
                None => (number(&h[136..148]), 0),
            };
            let mode = number(&h[100..108]).unwrap_or(0o644) as u32 & 0o7777;
            let kind = match kind {
                b'0' | 0 | b'7' if name.ends_with('/') => Kind::Dir,
                b'5' | b'D' => Kind::Dir,
                b'1' => Kind::HardLink,
                b'2' => Kind::Symlink,
                // an old GNU sparse member; its map shares the header with a ustar name prefix, so a ustar one is
                // not understood
                b'S' if !ustar => Kind::File,
                b'3' | b'4' | b'6' | b'S' | b'M' | b'V' => Kind::Other(kind),
                // POSIX: a type this reader doesn't know is read as a regular file
                _ => Kind::File,
            };
            let sparse = if h[156] == b'S' && !ustar {
                Some(self.old_gnu_sparse(&h, size)?)
            } else if p.sparse && kind == Kind::File {
                Some(self.pax_sparse(&p.gnu_sparse, &mut size)?)
            } else {
                None
            };
            // links and folders carry no data, whatever the size field says, except GNU's dump folders
            let has_data = !matches!(kind, Kind::HardLink | Kind::Symlink) && !(kind == Kind::Dir && h[156] == b'5');
            self.unread = if has_data { size + padding(size) } else { 0 };
            return Ok(Some(Member {
                name,
                raw_name,
                link,
                raw_link,
                size: if has_data { size } else { 0 },
                kind,
                mtime,
                nanos,
                mode,
                atime: p.atime,
                ctime: p.ctime,
                cpio: false,
                tar: Box::new(TarMetadata {
                    magic: TarMagic::of(&h),
                    typeflag: h[156],
                    user: p.uname.clone().flatten().or_else(|| (h[257] != 0).then(|| name_of(text(&h[265..297])))),
                    group: p.gname.clone().flatten().or_else(|| (h[257] != 0).then(|| name_of(text(&h[297..329])))),
                    uid: p.uid.flatten().or_else(|| number(&h[108..116]).and_then(|v| u64::try_from(v).ok())),
                    gid: p.gid.flatten().or_else(|| number(&h[116..124]).and_then(|v| u64::try_from(v).ok())),
                    device_major: number(&h[329..337]).and_then(|v| u64::try_from(v).ok()).filter(|_| h[257] != 0),
                    device_minor: number(&h[337..345]).and_then(|v| u64::try_from(v).ok()).filter(|_| h[257] != 0),
                    pax_header_name,
                    pax_records_truncated: !self.meta_budget.take(&p.records),
                    pax_records: if self.meta_budget.kept { p.records } else { Vec::new() },
                    header: self.meta_budget.take_header().then(|| Box::new(h)),
                }),
                sparse,
            }));
        }
    }

    /// An old GNU sparse member's map: four entries in the header, then as many extension blocks of 21 as the
    /// header and each block flag, between the header and the data.
    fn old_gnu_sparse(&mut self, h: &[u8; BLOCK], stored: u64) -> Result<Box<SparseMap>> {
        let mut pieces = Vec::new();
        let mut take = |entries: &[u8]| -> Result<()> {
            for e in entries.as_chunks::<24>().0 {
                // an entry with no offset ends the list
                if text(&e[..12]).is_empty() {
                    break;
                }
                let field = |f: &[u8]| number(f).and_then(|v| u64::try_from(v).ok());
                let (Some(offset), Some(len)) = (field(&e[..12]), field(&e[12..])) else {
                    return Err(Error::Corrupt("a sparse map entry is unreadable"));
                };
                if pieces.len() >= MAX_SPARSE_ENTRIES {
                    return Err(Error::Corrupt("a sparse map has too many entries"));
                }
                pieces.push((offset, len));
            }
            Ok(())
        };
        take(&h[386..482])?;
        let mut more = h[482] != 0;
        let mut map_bytes = 0u64;
        while more {
            map_bytes += BLOCK as u64;
            if map_bytes > MAX_SPARSE_MAP_BYTES {
                return Err(Error::Corrupt("a sparse map is too long"));
            }
            let mut ext = [0u8; BLOCK];
            if self.src.read(&mut ext)? < BLOCK {
                return Err(Error::Truncated);
            }
            take(&ext[..504])?;
            more = ext[504] != 0;
        }
        let real_size = number(&h[483..495]).and_then(|v| u64::try_from(v).ok());
        let real_size = real_size.unwrap_or_else(|| pieces.last().map_or(stored, |&(o, l)| o.saturating_add(l)));
        SparseMap::checked(real_size, pieces, stored)
    }

    /// A pax sparse member's map: from its records (0.0, 0.1), or from the start of its data (1.0), which is then
    /// taken off `size`.
    fn pax_sparse(&mut self, g: &SparsePax, size: &mut u64) -> Result<Box<SparseMap>> {
        let bad = |why| Error::Corrupt(why);
        let pieces = if g.major == Some(1) {
            if g.minor.is_some_and(|m| m != 0) {
                return Err(Error::Unsupported("a pax sparse format newer than 1.0".into()));
            }
            self.sparse_map_in_data(size)?
        } else if g.major.is_some_and(|m| m != 0) {
            return Err(Error::Unsupported("a pax sparse format newer than 1.0".into()));
        } else if let Some(map) = &g.map {
            let numbers = map
                .split(|&b| b == b',')
                .filter(|n| !n.is_empty())
                .map(|n| std::str::from_utf8(n).ok().and_then(|s| s.parse::<u64>().ok()))
                .collect::<Option<Vec<u64>>>()
                .ok_or_else(|| bad("a sparse map is unreadable"))?;
            if numbers.len() % 2 != 0 {
                return Err(bad("a sparse map has an offset without a length"));
            }
            if numbers.len() / 2 > MAX_SPARSE_ENTRIES {
                return Err(bad("a sparse map has too many entries"));
            }
            numbers.as_chunks::<2>().0.iter().map(|p| (p[0], p[1])).collect()
        } else if !g.pairs.is_empty() {
            g.pairs
                .iter()
                .map(|&(o, l)| l.map(|l| (o, l)))
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| bad("a sparse map's offset has no numbytes after it"))?
        } else {
            return Err(bad("a pax sparse member has no map"));
        };
        let real_size = match g.real_size {
            Some(r) => r,
            None => pieces.last().map_or(*size, |&(o, l)| o.saturating_add(l)),
        };
        SparseMap::checked(real_size, pieces, *size)
    }

    /// The pax 1.0 map at the start of the data: decimal numbers, one a line (the count, then an offset and a
    /// length for each entry), padded with zeros to a whole block.
    fn sparse_map_in_data(&mut self, size: &mut u64) -> Result<Vec<(u64, u64)>> {
        let bad = || Error::Corrupt("a sparse map is unreadable");
        let mut block = [0u8; BLOCK];
        let mut used = BLOCK;
        let mut consumed = 0u64;
        let mut next_number = |src: &mut Source| -> Result<u64> {
            let mut v: u64 = 0;
            let mut digits = 0;
            loop {
                if used == BLOCK {
                    consumed += BLOCK as u64;
                    if consumed > MAX_SPARSE_MAP_BYTES || consumed > *size {
                        return Err(Error::Corrupt("a sparse map is too long"));
                    }
                    if src.read(&mut block)? < BLOCK {
                        return Err(Error::Truncated);
                    }
                    used = 0;
                }
                let b = block[used];
                used += 1;
                match b {
                    b'0'..=b'9' if digits < 20 => {
                        v = v.checked_mul(10).and_then(|v| v.checked_add(u64::from(b - b'0'))).ok_or_else(bad)?;
                        digits += 1;
                    }
                    b'\n' if digits > 0 => return Ok(v),
                    _ => return Err(bad()),
                }
            }
        };
        let count = next_number(&mut self.src)?;
        if count > MAX_SPARSE_ENTRIES as u64 {
            return Err(Error::Corrupt("a sparse map has too many entries"));
        }
        let mut pieces = Vec::new();
        for _ in 0..count {
            let offset = next_number(&mut self.src)?;
            let len = next_number(&mut self.src)?;
            pieces.push((offset, len));
        }
        // the rest of the last block is padding
        *size -= consumed;
        Ok(pieces)
    }

    /// The current member's data in file order, holes included, to `sink`.
    fn read_member(&mut self, m: &Member, buf: &mut [u8], sink: &mut dyn FnMut(Piece) -> Result<()>) -> Result<()> {
        let Some(map) = &m.sparse else {
            return self.read_data(m.size, buf, &mut |d| sink(Piece::Data(d)));
        };
        let mut at = 0u64;
        for &(offset, len) in &map.pieces {
            if offset > at {
                sink(Piece::Hole(offset - at))?;
            }
            self.read_data(len, buf, &mut |d| sink(Piece::Data(d)))?;
            at = offset + len;
        }
        if map.real_size > at {
            sink(Piece::Hole(map.real_size - at))?;
        }
        Ok(())
    }

    /// The current member's data, in pieces, to `sink`. Reads exactly its size and leaves the padding for later.
    fn read_data(&mut self, size: u64, buf: &mut [u8], sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        if size == 0
            && let Some(data) = &mut self.member_data
        {
            // nothing comes out of an empty member, but its reader still checks it (a checksum, a stray byte)
            if let Err(e) = data.read(&mut [0u8; 1]) {
                return Err(data.fault().map_or_else(|| read_error(e), Error::Corrupt));
            }
        }
        let mut left = size;
        while left > 0 {
            let want = left.min(buf.len() as u64) as usize;
            if self.member_data.is_some() {
                self.src.check_cancel()?;
            }
            let got = match &mut self.member_data {
                Some(data) => match read_full(data, &mut buf[..want]) {
                    Ok(n) => n,
                    Err(e) => return Err(data.fault().map_or_else(|| read_error(e), Error::Corrupt)),
                },
                None => {
                    let got = self.src.read(&mut buf[..want])?;
                    self.unread -= got as u64;
                    got
                }
            };
            if let Some(crc) = &mut self.crc {
                crc.sum = buf[..got].iter().fold(crc.sum, |s, &b| s.wrapping_add(u32::from(b)));
                crc.left = crc.left.saturating_sub(got as u64);
                if crc.left == 0 && crc.sum != crc.want {
                    return Err(Error::Corrupt("a cpio member fails its checksum"));
                }
            }
            if got > 0 {
                sink(&buf[..got])?;
            }
            if got < want {
                return Err(Error::Truncated);
            }
            left -= got as u64;
        }
        Ok(())
    }

    /// Reads to the end of the stream, so that every checksum in it is checked.
    fn drain(&mut self, buf: &mut [u8]) -> Result<()> {
        while self.src.read(buf)? > 0 {}
        Ok(())
    }

    /// The whole data of a lone compressed file, starting with the block read when the archive was opened.
    fn read_single(&mut self, buf: &mut [u8], sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<u64> {
        let mut total = 0u64;
        if let Some(first) = self.first.take() {
            if !first.is_empty() {
                sink(&first)?;
            }
            total += first.len() as u64;
        }
        loop {
            let got = self.src.read(buf)?;
            if got == 0 {
                return Ok(total);
            }
            sink(&buf[..got])?;
            total += got as u64;
        }
    }
}

pub(crate) struct Selected {
    reader: Reader,
    path: PathBuf,
    pub name: String,
    /// the member, or None for a lone compressed file
    member: Option<Box<Member>>,
    pub meta: Meta,
}

impl Selected {
    /// Opens member `index` (as [`list_with_options`] numbers them under `compressed`); `special` decides whether a
    /// device or FIFO member opens as an empty file or is refused.
    pub(crate) fn open(
        path: &Path,
        index: usize,
        limit: u64,
        cancel: Cancellation,
        special: SpecialEntries,
        compressed: CompressedTar,
    ) -> Result<Self> {
        let whole = compressed == CompressedTar::Whole;
        let mut reader = Reader::open_with_limit(path, 1, Some(limit), Some(cancel), whole)?;
        if matches!(reader.content, Content::Single) {
            let codec = reader.src.codec().ok_or(Error::NotAnArchive)?;
            if index == 0 {
                return Ok(Self {
                    name: single_name(codec, path),
                    reader,
                    path: path.to_path_buf(),
                    member: None,
                    meta: single_meta(path),
                });
            }
        } else {
            let mut current = 0;
            while let Some(member) = reader.next()? {
                if member.kind == Kind::Other(b'V') {
                    continue;
                }
                if current == index {
                    // data read from its own place in the file doesn't pass the packed stream's limit: its stored
                    // length is held to it here
                    if reader.member_data.as_ref().and_then(|d| d.packed()).is_some_and(|p| p > limit) {
                        return Err(Error::Unsupported("the selected member exceeds the byte limit".into()));
                    }
                    let mut member = member;
                    if member.kind != Kind::File {
                        if !(special == SpecialEntries::EmptyFile && member.is_special()) {
                            return Err(Error::Unsupported("the selected tar member is not a regular file".into()));
                        }
                        // read as an empty file: any data the header claims is passed over
                        member.as_empty_file();
                    }
                    // a sparse member counts at its full size: its holes come out as zeros
                    if member.real_size() > limit {
                        return Err(Error::Unsupported("the selected member exceeds the byte limit".into()));
                    }
                    if let Some(why) = member.sparse_refusal() {
                        return Err(Error::Unsupported(why.into()));
                    }
                    let meta = member.meta();
                    return Ok(Self {
                        reader,
                        path: path.to_path_buf(),
                        name: member.name.clone(),
                        member: Some(Box::new(member)),
                        meta,
                    });
                }
                current += 1;
            }
        }
        Err(Error::Unsupported("entry index is out of range".into()))
    }

    pub(crate) fn source_path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn read(mut self, sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        let mut buf = vec![0; BUF];
        if let Some(member) = self.member.take() {
            let zeros = [0u8; 64 << 10];
            self.reader.read_member(&member, &mut buf, &mut |piece| match piece {
                Piece::Data(data) => sink(data),
                Piece::Hole(mut left) => {
                    while left > 0 {
                        let n = left.min(zeros.len() as u64) as usize;
                        sink(&zeros[..n])?;
                        left -= n as u64;
                    }
                    Ok(())
                }
            })?;
            if self.reader.src.codec().is_some() {
                self.reader.drain(&mut buf)?;
            }
        } else {
            self.reader.read_single(&mut buf, sink)?;
        }
        Ok(())
    }
}

fn padding(size: u64) -> u64 {
    (BLOCK as u64 - size % BLOCK as u64) % BLOCK as u64
}

/// The name a lone compressed file comes out as: the one in its gzip header, or the archive's own name without
/// its compression ending. Either is cleaned the way a member's name is, and only its last part is kept: a stored
/// name is a file name, never a place to write to.
/// The time a lone compressed file comes out with, as gunzip -N, xz, bzip2 and 7-Zip give it: the gzip header's
/// MTIME when it holds one, otherwise the compressed file's own modification time.
fn single_meta(path: &Path) -> Meta {
    let own = || {
        let at = std::fs::metadata(path).ok()?.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?;
        Some((i64::try_from(at.as_secs()).ok()?, at.subsec_nanos()))
    };
    let (mtime, nanos) = match stream::gzip_mtime(path).map(|s| (s, 0)).or_else(own) {
        Some((s, n)) => (Some(s), n),
        None => (None, 0),
    };
    Meta { mtime, nanos, ..Meta::default() }
}

fn single_name(codec: Codec, path: &Path) -> String {
    let clean = |name: &str| {
        let last = name.rsplit(['/', '\\']).find(|s| !s.is_empty() && *s != "." && *s != "..")?;
        // as a Windows name, so a drive prefix such as "C:" can't take the path out of the destination
        let rel = sanitize(last, true).ok()?;
        Some(rel.file_name()?.to_string_lossy().into_owned())
    };
    if codec == Codec::Gzip
        && let Some(name) = stream::gzip_name(path).as_deref().and_then(clean)
    {
        return name;
    }
    single_fallback(codec, path, &clean)
}

fn single_fallback(codec: Codec, path: &Path, clean: &dyn Fn(&str) -> Option<String>) -> String {
    let file = path.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default();
    let lower = file.to_ascii_lowercase();
    for (ending, becomes) in codec.endings() {
        if lower.ends_with(ending) && lower.len() > ending.len() {
            let stem = format!("{}{becomes}", &file[..file.len() - ending.len()]);
            return clean(&stem).unwrap_or_else(|| "file".to_string());
        }
    }
    clean(&format!("{file}.out")).unwrap_or_else(|| "file".to_string())
}

/// The archive's members. A lone compressed file is decoded to find its size: the gzip trailer holds only the
/// last member's size, and only below 4 GiB, and other formats may not record it at all.
pub fn list(path: &Path) -> Result<Vec<Entry>> {
    list_reading(path, false)
}

/// [`list`], numbering entries as [`run`] and [`crate::extract::SelectedEntry`] with the same `options` do: with
/// [`CompressedTar::Whole`](crate::extract::CompressedTar::Whole) a compressed tar is the one entry its decompressed
/// stream makes (`pax.tgz` lists `pax.tar`), as 7-Zip lists it.
pub fn list_with_options(path: &Path, options: &Options) -> Result<Vec<Entry>> {
    list_reading(path, options.compressed_tar == CompressedTar::Whole)
}

fn list_reading(path: &Path, whole: bool) -> Result<Vec<Entry>> {
    let mut reader = Reader::open_with_limit(path, 1, Some(COMPRESSED_LIST_LIMIT), None, whole)?;
    if let (Content::Single, Some(codec)) = (&reader.content, reader.src.codec()) {
        let gzip = codec == Codec::Gzip;
        let packed = std::fs::metadata(path)?.len();
        let mut buf = vec![0u8; BUF];
        let size = reader.read_single(&mut buf, &mut |_| Ok(()))?;
        // RFC 1952: MTIME is Unix time, 0 when none was recorded.
        let mtime = if gzip { stream::gzip_mtime(path) } else { None };
        return Ok(vec![Entry {
            mode: None,
            size_unknown: false,
            mtime_origin: mtime.map(|_| MtimeOrigin::Utc),
            ctime: None,
            atime: None,
            tar: None,
            attributes: None,
            name: single_name(codec, path),
            size,
            packed,
            mtime,
            crc32: None,
            method: if gzip { 8 } else { 0 },
            method_name: None,
            dir: false,
            encrypted: false,
            solid: false,
            link: None,
            version: None,
        }]);
    }
    list_members(reader)
}

/// Lists what is left of `reader`'s members.
fn list_members(reader: Reader) -> Result<Vec<Entry>> {
    list_members_within(reader, &mut ListingBudget::default())
}

/// [`list_members`] under `budget`, which counts each member's name and link target (a `K` record's, a pax
/// `linkpath`'s or the header's), all kept in the listing.
fn list_members_within(mut reader: Reader, budget: &mut ListingBudget) -> Result<Vec<Entry>> {
    let mut out = Vec::new();
    while let Some(m) = reader.next()? {
        if m.kind != Kind::Other(b'V') {
            budget.record_with_link(&m.name, &m.link)?;
            let packed = reader.member_data.as_ref().and_then(|d| d.packed());
            let mut entry = m.into_entry();
            if let Some(packed) = packed {
                entry.packed = packed;
            }
            out.push(entry);
        }
    }
    if reader.src.codec().is_some() {
        let mut buffer = vec![0; BUF];
        reader.drain(&mut buffer)?;
    }
    Ok(out)
}

pub fn run(path: &Path, opts: &Options, mut report: impl FnMut(&str)) -> Result<Summary> {
    run_reporting(path, opts, &mut report).map_err(|e| e.error)
}

/// Tests or extracts a tar archive or lone compressed stream with the same options, cancellation and observer as
/// [`crate::extract::run_with_policy`], which dispatches here for these formats.
///
/// Members are reported live through `observe` with their listing index: `MemberSucceeded`, `MemberSkipped` or
/// `MemberFailed`, preceded by `MemberRenamed { ordinal: Some(..) }` when a rename mode renamed. Members of a
/// compressed tar are published (and reported) once the whole stream has decoded and checked out. A canceled run
/// returns [`crate::zip::ReadFault::Cancelled`]; files already published stay, the member in progress does not.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[allow(clippy::result_large_err)]
pub fn run_with_policy(
    path: &Path,
    options: &Options,
    cancel: &Cancellation,
    observe: impl crate::zip::ZipRunObserver,
) -> crate::zip::ZipReadResult<crate::zip::ZipRunReport> {
    use crate::extract::LegacyRoute;
    if !is_tar_or_stream(path).map_err(crate::zip::ReadFault::Legacy)? {
        return Err(crate::zip::ReadFault::Legacy(Error::NotAnArchive).into());
    }
    crate::extract::legacy_zip_report(LegacyRoute::Tar, path, options, None, cancel, observe)
}

/// Whether the file starts like a tar archive or one of the compressed streams this module reads.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn is_tar_or_stream(path: &Path) -> Result<bool> {
    let mut head = [0u8; 2 * BLOCK];
    let mut file = File::open(path)?;
    let n = read_full(&mut file, &mut head)?;
    let head = &head[..n];
    Ok(Codec::sniff(head).is_some()
        || sniff_tar(head)
        || sniff_cpio(head)
        || sniff_xar(head)
        || sniff_wim(head)
        || sniff_iso(&file))
}

/// [`run`], reporting a rename mode's renames to `report` as they happen. A terminal error keeps them too.
pub(crate) fn run_reporting(
    path: &Path,
    opts: &Options,
    report: &mut impl LegacyReport,
) -> std::result::Result<Summary, RunError> {
    run_reporting_cancelable(path, opts, None, report)
}

/// [`run_reporting`], stopping with [`crate::extract::canceled_error`] once `cancel` is triggered.
pub(crate) fn run_reporting_cancelable(
    path: &Path,
    opts: &Options,
    cancel: Option<&Cancellation>,
    report: &mut impl LegacyReport,
) -> std::result::Result<Summary, RunError> {
    let threads = opts.threads.unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()));
    let whole = opts.compressed_tar == CompressedTar::Whole;
    let mut reader = Reader::open_with_limit(path, threads, None, cancel.cloned(), whole)?;
    let opts = &*opts.protecting(path)?;
    if opts.mode == Mode::Extract {
        std::fs::create_dir_all(&opts.dest).map_err(Error::from)?;
    }
    let mut summary = Summary { volumes: 1, ..Summary::default() };
    let mut buf = vec![0u8; BUF];
    let result = match reader.content {
        Content::Single => run_single(&mut reader, path, opts, &mut summary, &mut buf, report),
        Content::Tar => run_tar(&mut reader, opts, &mut summary, &mut buf, report),
    };
    finish_dirs(&mut summary);
    match result {
        Ok(()) => Ok(summary),
        Err(error) => Err(RunError::new(error, std::mem::take(&mut summary.renames))),
    }
}

fn fail(summary: &mut Summary, report: &mut impl LegacyReport, name: &str, why: &str) {
    let line = format!("{name}: {why}");
    report.line(&line);
    summary.errors.push(line);
}

/// [`fail`] for one member, also reported as its outcome.
fn fail_member(
    summary: &mut Summary,
    report: &mut impl LegacyReport,
    ordinal: u64,
    name: &str,
    why: &str,
    error: Error,
) {
    fail(summary, report, name, why);
    report.member(LegacyMember::Failed { ordinal, name, error });
}

/// A member written (or found whole, when testing).
fn succeeded(summary: &mut Summary, report: &mut impl LegacyReport, ordinal: u64, name: &str, bytes: u64) {
    summary.files += 1;
    summary.bytes += bytes;
    report.member(LegacyMember::Succeeded { ordinal, name, bytes });
}

/// A folder made (or found, when testing).
fn folder(summary: &mut Summary, report: &mut impl LegacyReport, ordinal: u64, name: &str) {
    summary.dirs += 1;
    report.member(LegacyMember::Succeeded { ordinal, name, bytes: 0 });
}

fn skipped(summary: &mut Summary, report: &mut impl LegacyReport, ordinal: u64, name: &str) {
    report.line(&format!("{name}: exists, skipped"));
    summary.skipped += 1;
    report.member(LegacyMember::Skipped { ordinal, name });
}

/// Opens where `rel` is to be written, or says why not. `Ok(None)` means skip it, already reported.
fn target(
    opts: &Options,
    rel: &Path,
    (ordinal, name): (u64, &str),
    (size, sparse): (Option<u64>, bool),
    placed: Option<&Extracted>,
    summary: &mut Summary,
    report: &mut impl LegacyReport,
) -> Result<Option<(Output, PathBuf)>> {
    let Some(place) = checked_place(opts, rel, (ordinal, name), placed, summary, report)? else { return Ok(None) };
    // where the data lands: a rename mode's reserved name, else the target
    let landed = match &place.reserved {
        Some(reserved) => reserved.path().to_path_buf(),
        None => place.path.clone(),
    };
    // a sparse file is marked sparse where that needs asking, and not preallocated, so its holes stay holes
    let output = if sparse { create_sparse_target(place, size)? } else { create_target(place, size)? };
    Ok(Some((output, landed)))
}

/// Why a hard link to a sparse file fails where it would have to be a copy past the run's budget of holes.
const HOLE_COPY: &str = "the hard link would have to copy a sparse file, and its holes pass the archive's budget of \
                         holes: refused as a bomb";

/// The holes a whole run may make: 1 GiB, plus 1024 times the data each sparse member stores. Without it, many
/// members each under [`SPARSE_MAX_RATIO`] would add up to a bomb (a thousand 1.5 KiB members claiming 1 GiB each)
/// on a file system that keeps no holes. Extraction and testing share it; a read by index has its own byte limit.
struct HoleBudget {
    left: u64,
    /// the holes in each sparse file extracted so far, by member path: a hard link to one that has to be made as a
    /// copy writes them all as data, and is charged for them
    extracted: std::collections::HashMap<PathBuf, u64>,
}

impl HoleBudget {
    fn new() -> Self {
        HoleBudget { left: SPARSE_FREE_SIZE, extracted: Default::default() }
    }

    /// The member at `rel` was extracted with `holes` bytes of holes (none for a file that isn't sparse).
    fn extracted(&mut self, rel: &Path, holes: u64) {
        if holes > 0 {
            self.extracted.insert(rel.to_path_buf(), holes);
        } else {
            self.extracted.remove(rel);
        }
    }

    /// Charges a copy of the file at `target` (a hard link that couldn't be made) for its holes.
    fn copy(&mut self, target: &Path) -> io::Result<()> {
        let holes = self.extracted.get(target).copied().unwrap_or(0);
        match self.left.checked_sub(holes) {
            Some(left) => {
                self.left = left;
                Ok(())
            }
            None => Err(io::Error::new(io::ErrorKind::FileTooLarge, HOLE_COPY)),
        }
    }

    /// Takes a sparse member's holes from what is left, or says why it is refused, leaving the budget as it was.
    fn take(&mut self, m: &Member) -> Option<&'static str> {
        let map = m.sparse.as_ref()?;
        let allowed = self.left.saturating_add(m.size.saturating_mul(SPARSE_MAX_RATIO));
        match allowed.checked_sub(map.real_size.saturating_sub(m.size)) {
            Some(left) => {
                self.left = left;
                None
            }
            None => Some(
                "the archive's sparse members together claim more than 1 GiB of holes plus 1024 times their stored \
                 data: refused as a bomb",
            ),
        }
    }
}

/// How a member's data went: written whole, or the error that stopped it.
enum Outcome {
    Done,
    /// the archive itself is damaged or cut short: the member fails and nothing after it can be found
    Archive(Error),
}

enum StagedMember {
    Directory { relative: PathBuf, meta: Meta, ordinal: u64, name: String },
    Link { relative: PathBuf, name: String, kind: LinkKind, ordinal: u64, meta: Meta },
    File { relative: PathBuf, name: String, temporary: tempfile::TempPath, size: u64, holes: u64, ordinal: u64 },
}

#[derive(Default)]
struct StagedTar {
    members: Vec<StagedMember>,
    budget: ListingBudget,
}

impl StagedTar {
    fn publish(
        self,
        opts: &Options,
        holes: &mut HoleBudget,
        summary: &mut Summary,
        report: &mut impl LegacyReport,
        cancel: Option<&Cancellation>,
    ) -> Result<()> {
        let mut extracted = Extracted::new(opts);
        for member in self.members {
            // a cancellation from an earlier member's outcome stops the rest from being published
            if let Some(cancel) = cancel {
                cancel.check_io()?;
            }
            match member {
                StagedMember::Link { relative, name, kind, ordinal, meta } => {
                    let member = (ordinal, name.as_str(), &meta);
                    link_member(opts, &relative, member, &kind, (&mut extracted, holes), summary, report)?;
                }
                StagedMember::Directory { relative, meta, ordinal, name } => {
                    if let Some(why) = make_member_dirs(&opts.dest, &relative)? {
                        fail_member(summary, report, ordinal, &name, why, Error::UnsafePath(name.clone()));
                        continue;
                    }
                    summary.dir_meta.push((opts.dest.join(relative), meta));
                    folder(summary, report, ordinal, &name);
                }
                StagedMember::File { relative, name, temporary, size, holes: file_holes, ordinal } => {
                    let Some(place) =
                        checked_place(opts, &relative, (ordinal, &name), Some(&extracted), summary, report)?
                    else {
                        continue;
                    };
                    let landed = match &place.reserved {
                        Some(reserved) => reserved.path().to_path_buf(),
                        None => place.path.clone(),
                    };
                    if let Some(reserved) = place.reserved {
                        // the rename mode's own empty file, created with O_EXCL a moment ago, takes the data
                        replace(temporary, reserved.path())?;
                        drop(reserved.into_parts());
                    } else if place.replace {
                        replace_link(temporary, &place.path, place.link)?;
                    } else if let Err(error) = temporary.persist_noclobber(place.path) {
                        if opts.overwrite == Overwrite::Skip && error.error.kind() == io::ErrorKind::AlreadyExists {
                            skipped(summary, report, ordinal, &name);
                            continue;
                        }
                        return Err(error.error.into());
                    }
                    extracted.file(&opts.dest, &relative, &landed);
                    holes.extracted(&relative, file_holes);
                    succeeded(summary, report, ordinal, &name, size);
                }
            }
        }
        Ok(())
    }
}

/// A link member: refused when its target is unsafe (or, for a hard link, not a file this run extracted), else
/// placed under the run's overwrite choice. Testing only checks the target.
fn link_member(
    opts: &Options,
    rel: &Path,
    (ordinal, name, meta): (u64, &str, &Meta),
    kind: &LinkKind,
    (extracted, holes): (&mut Extracted, &mut HoleBudget),
    summary: &mut Summary,
    report: &mut impl LegacyReport,
) -> Result<()> {
    // testing checks the target as extracting would
    if let Some(why) = link::refusal_before_place(rel, kind, extracted) {
        fail_member(summary, report, ordinal, name, why, Error::UnsafePath(name.to_owned()));
        return Ok(());
    }
    if opts.mode == Mode::Extract {
        let Some(place) = checked_place(opts, rel, (ordinal, name), Some(extracted), summary, report)? else {
            return Ok(());
        };
        let mut copy = |_| match kind {
            LinkKind::Hard(target) | LinkKind::Copy(target) => holes.copy(target),
            LinkKind::Symbolic(_) => Ok(()),
        };
        if let Err(e) = link::publish_charging(&opts.dest, rel, place, kind, meta.modified(), extracted, &mut copy) {
            if e.kind() == io::ErrorKind::FileTooLarge {
                fail_member(summary, report, ordinal, name, HOLE_COPY, Error::Unsupported(HOLE_COPY.to_owned()));
                return Ok(());
            }
            if !cfg!(unix) || e.kind() == io::ErrorKind::Unsupported {
                let why = link::UNSUPPORTED;
                fail_member(summary, report, ordinal, name, why, Error::Unsupported(why.to_owned()));
                return Ok(());
            }
            // the earlier file changed since it was extracted: this member fails, the run goes on
            if let Some(why) = link::member_failure(&e) {
                fail_member(summary, report, ordinal, name, why, Error::UnsafePath(name.to_owned()));
                return Ok(());
            }
            return Err(e.into());
        }
        // the link's own path now holds the target's holes too, so a link to this link is charged the same
        let link_holes = match kind {
            LinkKind::Hard(target) | LinkKind::Copy(target) => holes.extracted.get(target).copied().unwrap_or(0),
            LinkKind::Symbolic(_) => 0,
        };
        holes.extracted(rel, link_holes);
    }
    if opts.mode != Mode::Extract {
        link::tested(rel, kind, extracted);
    }
    succeeded(summary, report, ordinal, name, 0);
    Ok(())
}

fn checked_place(
    opts: &Options,
    relative: &Path,
    (ordinal, name): (u64, &str),
    placed: Option<&Extracted>,
    summary: &mut Summary,
    report: &mut impl LegacyReport,
) -> Result<Option<Place>> {
    let mut log = RenameLog {
        placed: placed.filter(|_| opts.replace_placed_links),
        budget: &mut summary.rename_budget,
        record: &mut |renamed| {
            report.renamed_member(ordinal, &renamed);
            summary.renames.push(renamed);
        },
    };
    match check_target(opts, relative, None, &mut log)? {
        Checked::Write(place) => Ok(Some(place)),
        Checked::Exists => {
            skipped(summary, report, ordinal, name);
            Ok(None)
        }
        Checked::Declined => {
            report.line(&format!("{name}: declined, skipped"));
            summary.skipped += 1;
            report.member(LegacyMember::Skipped { ordinal, name });
            Ok(None)
        }
        Checked::Blocked(why) => {
            fail_member(summary, report, ordinal, name, why, Error::Io(io::Error::other(why)));
            Ok(None)
        }
    }
}

fn staging_parent(destination: &Path, relative: &Path) -> Result<PathBuf> {
    let mut directory = destination.to_path_buf();
    if let Some(parent) = relative.parent() {
        for component in parent.components() {
            let next = directory.join(component);
            match std::fs::symlink_metadata(&next) {
                Ok(metadata) if metadata.is_dir() => directory = next,
                // never staged through a link: the member fails when it is placed, and the run goes on
                Ok(metadata) if metadata.file_type().is_symlink() => break,
                Ok(_) => return Err(Error::UnsafePath(next.display().to_string())),
                Err(error) if error.kind() == io::ErrorKind::NotFound => break,
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(directory)
}

/// Reads one member's data into its output (or nowhere, when testing), finishing or removing the output file.
/// A failure to write stops the run; a failure in the archive's data fails the member.
fn copy_out(
    mut target: Option<Output>,
    meta: &Meta,
    read: impl FnOnce(&mut dyn FnMut(Piece) -> Result<()>) -> Result<()>,
) -> Result<Outcome> {
    // write errors are kept apart from read errors so the two can be told apart afterwards
    let mut write_error: Option<io::Error> = None;
    let read = {
        let mut sink = |piece: Piece| -> Result<()> {
            if let Some(out) = target.as_mut()
                && let Err(e) = match piece {
                    Piece::Data(chunk) => out.write(chunk),
                    Piece::Hole(len) => out.write_hole(len),
                }
            {
                write_error = Some(e);
                return Err(Error::Corrupt("write failed"));
            }
            Ok(())
        };
        read(&mut sink)
    };
    if let Some(e) = write_error {
        return Err(Error::Io(e));
    }
    match read {
        Ok(()) => {
            if let Some(out) = target {
                out.finish(|file| finish_file(file, meta))?;
            }
            Ok(Outcome::Done)
        }
        // the disk under the archive failed: stop
        Err(Error::Io(io)) => Err(Error::Io(io)),
        Err(other) => Ok(Outcome::Archive(other)),
    }
}

fn run_single(
    reader: &mut Reader,
    path: &Path,
    opts: &Options,
    summary: &mut Summary,
    buf: &mut [u8],
    report: &mut impl LegacyReport,
) -> Result<()> {
    let name = single_name(reader.src.codec().unwrap_or(Codec::Gzip), path);
    if !opts.selects(&name, None, false, 0) {
        return Ok(());
    }
    summary.matched += 1;
    let mut out = None;
    if opts.mode == Mode::Extract {
        let rel = PathBuf::from(&name);
        match target(opts, &rel, (0, &name), (None, false), None, summary, report)? {
            Some((t, _)) => out = Some(t),
            None => return Ok(()),
        }
    }
    let mut total = 0u64;
    let outcome = copy_out(out, &single_meta(path), |sink| {
        total = reader.read_single(buf, &mut |data| sink(Piece::Data(data)))?;
        Ok(())
    })?;
    match outcome {
        Outcome::Done => succeeded(summary, report, 0, &name, total),
        Outcome::Archive(e) => fail_member(summary, report, 0, &name, &e.to_string(), e),
    }
    Ok(())
}

fn run_tar(
    reader: &mut Reader,
    opts: &Options,
    summary: &mut Summary,
    buf: &mut [u8],
    report: &mut impl LegacyReport,
) -> Result<()> {
    let mut staged = (opts.mode == Mode::Extract && reader.src.codec().is_some()).then(StagedTar::default);
    // the files written so far, for hard links (a staged run tracks them as it publishes)
    let mut extracted = Extracted::new(opts);
    // the next member's position in a listing, which leaves out volume labels
    let mut ordinal = 0u64;
    let mut holes = HoleBudget::new();
    loop {
        let mut m = match reader.next() {
            Ok(Some(m)) => m,
            Ok(None) => {
                // compressed streams check their data at the end, which may lie past the end marker
                if let Source::Packed(..) = reader.src {
                    match reader.drain(buf) {
                        Ok(()) => {}
                        Err(Error::Io(e)) => return Err(Error::Io(e)),
                        Err(e) => {
                            fail(summary, report, "archive", &e.to_string());
                            return Ok(());
                        }
                    }
                }
                if let Some(staged) = staged {
                    staged.publish(opts, &mut holes, summary, report, reader.cancel.as_ref())?;
                }
                return Ok(());
            }
            Err(Error::Io(e)) => return Err(Error::Io(e)),
            Err(e) => {
                // nothing after a damaged header or a cut-short archive can be found
                fail(summary, report, "archive", &e.to_string());
                return Ok(());
            }
        };
        // a volume label is no member: a listing leaves it out, and a filter never sees it, but without a filter its
        // name is still checked as it always was
        let label = m.kind == Kind::Other(b'V');
        let position = ordinal;
        if !label {
            ordinal += 1;
        }
        // "./" stands for the destination itself
        if m.kind == Kind::Dir && m.name.split('/').all(|p| p.is_empty() || p == ".") {
            continue;
        }
        // an unselected member's data is passed over by the next call to `next`
        if opts.select.is_some()
            && (label || !opts.selects(&m.name, m.raw_name.as_deref(), m.kind == Kind::Dir, position))
        {
            continue;
        }
        if !label {
            summary.matched += 1;
        }
        let rel = match crate::path::sanitize_with(&m.name, false, opts.windows_safe_names) {
            Ok(rel) => rel,
            Err(e) => {
                fail_member(summary, report, position, &m.name, &e.to_string(), e);
                continue;
            }
        };
        let rel = if opts.flatten { PathBuf::from(rel.file_name().unwrap_or_default()) } else { rel };
        // what the hole budget held before this member took from it: a member skipped or refused at its target
        // makes no holes, and gives back what it took
        let hole_mark = holes.left;
        let why = match m.kind {
            Kind::Dir => {
                if opts.mode == Mode::Extract && !opts.flatten {
                    if let Some(staged) = &mut staged {
                        staged.budget.record(&m.name)?;
                        let meta = opts.dir_meta(m.meta());
                        staged.members.push(StagedMember::Directory {
                            relative: rel,
                            meta,
                            ordinal: position,
                            name: m.name,
                        });
                        continue;
                    }
                    if let Some(why) = make_member_dirs(&opts.dest, &rel)? {
                        fail_member(summary, report, position, &m.name, why, Error::UnsafePath(m.name.clone()));
                        continue;
                    }
                    summary.dir_meta.push((opts.dest.join(&rel), opts.dir_meta(m.meta())));
                }
                folder(summary, report, position, &m.name);
                continue;
            }
            Kind::File => m.sparse_refusal().or_else(|| holes.take(&m)),
            Kind::Symlink | Kind::HardLink => {
                let kind = if m.kind == Kind::Symlink {
                    LinkKind::Symbolic(m.link.clone().into_bytes())
                } else {
                    match crate::path::sanitize_with(&m.link, false, opts.windows_safe_names) {
                        Ok(target) if opts.flatten => {
                            LinkKind::Hard(PathBuf::from(target.file_name().unwrap_or_default()))
                        }
                        Ok(target) => LinkKind::Hard(target),
                        Err(e) => {
                            fail_member(summary, report, position, &m.name, link::HARD_TARGET, e);
                            continue;
                        }
                    }
                };
                if let Some(staged) = &mut staged {
                    staged.budget.record_with_link(&m.name, &m.link)?;
                    let meta = opts.meta(m.meta());
                    staged.members.push(StagedMember::Link {
                        relative: rel,
                        name: m.name,
                        kind,
                        ordinal: position,
                        meta,
                    });
                } else {
                    let member = (position, m.name.as_str(), &opts.meta(m.meta()));
                    link_member(opts, &rel, member, &kind, (&mut extracted, &mut holes), summary, report)?;
                }
                continue;
            }
            Kind::Other(b'V') => continue,
            Kind::Other(b'S') => Some("an old GNU sparse member in a ustar header is not understood"),
            Kind::Other(b'M') => Some("multi-volume tar archives are not supported yet"),
            Kind::Other(_) if opts.special_entries == SpecialEntries::EmptyFile && m.is_special() => {
                // 7-Zip's choice: an empty regular file with the member's mode and time
                m.as_empty_file();
                None
            }
            Kind::Other(_) => Some("devices and pipes are not extracted"),
        };
        if let Some(why) = why {
            fail_member(summary, report, position, &m.name, why, Error::Unsupported(why.to_owned()));
            continue;
        }
        if let Some(staged) = &mut staged {
            let parent = staging_parent(&opts.dest, &rel)?;
            // An early look at the target saves decoding a member that is to be skipped or refused; a rename mode
            // settles its target only when publishing, so it renames once.
            if opts.overwrite.rename().is_none()
                && opts.dest.join(&rel).parent() == Some(parent.as_path())
                && checked_place(opts, &rel, (position, &m.name), Some(&extracted), summary, report)?.is_none()
            {
                holes.left = hole_mark;
                continue;
            }
            staged.budget.record(&m.name)?;
            let (file, temporary) = temporary(&parent)?.into_parts();
            if m.sparse.is_some() {
                crate::output::mark_sparse(&file);
            }
            let output = Output::new(file, Some(m.real_size()));
            match copy_out(Some(output), &opts.meta(m.meta()), |sink| reader.read_member(&m, buf, sink))? {
                Outcome::Done => {
                    let (size, holes) = (m.real_size(), m.real_size() - m.size);
                    let name = m.name;
                    let file = StagedMember::File { relative: rel, name, temporary, size, holes, ordinal: position };
                    staged.members.push(file);
                }
                Outcome::Archive(error) => {
                    fail_member(summary, report, position, &m.name, &error.to_string(), error);
                    return Ok(());
                }
            }
            continue;
        }
        let mut out = None;
        if opts.mode == Mode::Extract {
            match target(
                opts,
                &rel,
                (position, &m.name),
                (Some(m.real_size()), m.sparse.is_some()),
                Some(&extracted),
                summary,
                report,
            )? {
                Some(t) => out = Some(t),
                None => {
                    holes.left = hole_mark;
                    continue;
                }
            }
        } else if let (Source::Plain { .. }, true) = (&reader.src, reader.crc.is_none() && reader.member_data.is_none())
        {
            // tar keeps no checksum of the data (nor does cpio, but for newc's own), so a test only has to find that
            // all of it is there: the data and its padding, whichever format's
            let size = reader.unread;
            match reader.src.skip(size, &mut reader.scratch) {
                Ok(()) => {
                    reader.unread = 0;
                    extracted.tested(&rel);
                    succeeded(summary, report, position, &m.name, m.real_size());
                    continue;
                }
                Err(Error::Io(e)) => return Err(Error::Io(e)),
                Err(e) => {
                    fail_member(summary, report, position, &m.name, &e.to_string(), e);
                    return Ok(());
                }
            }
        }
        let (out, landed) = match out {
            Some((out, landed)) => (Some(out), Some(landed)),
            None => (None, None),
        };
        match copy_out(out, &opts.meta(m.meta()), |sink| reader.read_member(&m, buf, sink))? {
            Outcome::Done => {
                match &landed {
                    Some(landed) => {
                        extracted.file(&opts.dest, &rel, landed);
                        holes.extracted(&rel, m.real_size() - m.size);
                    }
                    None => extracted.tested(&rel),
                }
                succeeded(summary, report, position, &m.name, m.real_size())
            }
            Outcome::Archive(e) => {
                fail_member(summary, report, position, &m.name, &e.to_string(), e);
                return Ok(());
            }
        }
    }
}

/// What a member is, as the repacker writes it again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RawKind {
    File,
    Dir,
    Symlink,
    HardLink,
    CharDevice,
    BlockDevice,
    Fifo,
}

/// A member as the repacker sees it: the stored name's own bytes, its link target, kind and mode, the length of the
/// file it makes (a sparse member's holes included) and a device's numbers. Times and owners are left out on
/// purpose: a repack replaces them.
#[derive(Clone, Debug)]
pub(crate) struct RawMember {
    pub name: Vec<u8>,
    pub link: Vec<u8>,
    pub kind: RawKind,
    pub mode: u32,
    pub size: u64,
    pub device: (u64, u64),
}

/// The data of the member just handed out by [`walk_members`].
pub(crate) struct RepackData<'a> {
    reader: &'a mut Reader,
    member: &'a Member,
    buf: &'a mut [u8],
}

impl RepackData<'_> {
    /// The file's bytes in order to `sink`, a sparse member's holes as zeros.
    pub(crate) fn read(self, sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        let zeros = [0u8; 64 << 10];
        self.reader.read_member(self.member, self.buf, &mut |piece| match piece {
            Piece::Data(d) => sink(d),
            Piece::Hole(mut left) => {
                while left > 0 {
                    let n = left.min(zeros.len() as u64) as usize;
                    sink(&zeros[..n])?;
                    left -= n as u64;
                }
                Ok(())
            }
        })
    }
}

/// Every member of a tar or cpio archive, plain or compressed, in stored order, with the listing's limits: at most
/// `limit` decoded bytes from a compressed stream, the listing's entry and name budget, and the sparse bomb check.
/// A volume label is passed over; a member this crate cannot write again (a multi-volume continuation, a socket)
/// fails the walk. A lone compressed file is not an archive here. Returns the bytes the walk cost: the file's
/// length, or for a compressed stream every byte decoded, whichever is more.
pub(crate) fn walk_members(
    path: &Path,
    input: &File,
    limit: u64,
    mut each: impl FnMut(RawMember, RepackData<'_>) -> Result<()>,
) -> Result<u64> {
    let expect = input.metadata()?;
    let mut reader = Reader::open_checked(path, Some(&expect), 1, Some(limit), None, false, 1)?;
    if matches!(reader.content, Content::Single) {
        return Err(Error::NotAnArchive);
    }
    let mut budget = ListingBudget::default();
    let mut buf = vec![0u8; BUF];
    while let Some(m) = reader.next()? {
        let kind = match m.kind {
            Kind::File => RawKind::File,
            Kind::Dir => RawKind::Dir,
            Kind::Symlink => RawKind::Symlink,
            Kind::HardLink => RawKind::HardLink,
            Kind::Other(b'V') => continue,
            Kind::Other(b'3') => RawKind::CharDevice,
            Kind::Other(b'4') => RawKind::BlockDevice,
            Kind::Other(b'6') => RawKind::Fifo,
            Kind::Other(t) => {
                return Err(Error::Unsupported(format!(
                    "tar member {:?} has type {:?}, which a repack cannot write again",
                    m.name, t as char
                )));
            }
        };
        if let Some(why) = m.sparse_refusal() {
            return Err(Error::Unsupported(why.into()));
        }
        let device = matches!(kind, RawKind::CharDevice | RawKind::BlockDevice);
        if device && m.cpio && m.tar.device_major.is_none() {
            // an odc or bin header's one device number splits differently by system: a guess could change the device
            return Err(Error::Unsupported(format!(
                "cpio device {:?} has no major and minor numbers a repack can keep",
                m.name
            )));
        }
        budget.record_with_link(&m.name, &m.link)?;
        let raw = RawMember {
            name: m.raw_name.clone().unwrap_or_else(|| m.name.clone().into_bytes()),
            link: m.raw_link.clone().unwrap_or_else(|| m.link.clone().into_bytes()),
            kind,
            mode: m.mode,
            size: if kind == RawKind::File { m.real_size() } else { 0 },
            device: (m.tar.device_major.unwrap_or(0), m.tar.device_minor.unwrap_or(0)),
        };
        each(raw, RepackData { reader: &mut reader, member: &m, buf: &mut buf })?;
    }
    if reader.src.codec().is_some() {
        reader.drain(&mut buf)?;
    }
    let len = expect.len();
    Ok(match reader.src {
        Source::Packed(_, _, decoded) => decoded.max(len),
        Source::Plain { .. } => len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ustar header block for `name`.
    fn test_header(name: &str, kind: u8, size: u64, link: &str) -> [u8; BLOCK] {
        let mut h = [0u8; BLOCK];
        h[..name.len()].copy_from_slice(name.as_bytes());
        let octal = |h: &mut [u8; BLOCK], at: usize, width: usize, v: u64| {
            h[at..at + width].copy_from_slice(format!("{v:0w$o}\0", w = width - 1).as_bytes());
        };
        octal(&mut h, 100, 8, 0o644);
        octal(&mut h, 108, 8, 0);
        octal(&mut h, 116, 8, 0);
        octal(&mut h, 124, 12, size);
        octal(&mut h, 136, 12, 0);
        h[156] = kind;
        h[157..157 + link.len()].copy_from_slice(link.as_bytes());
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        h[148..156].fill(b' ');
        let sum: u64 = h.iter().map(|&b| u64::from(b)).sum();
        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        h
    }

    /// A member data block run: `data` padded to whole blocks.
    fn test_padded(mut data: Vec<u8>) -> Vec<u8> {
        data.resize(data.len().div_ceil(BLOCK) * BLOCK, 0);
        data
    }

    /// A symbolic link `name` whose target comes in a pax `linkpath` record.
    fn test_pax_link(name: &str, target: &str) -> Vec<u8> {
        let body = record("linkpath", target);
        let mut out = test_header(&format!("PaxHeaders/{name}"), b'x', body.len() as u64, "").to_vec();
        out.extend(test_padded(body.into_bytes()));
        out.extend(test_header(name, b'2', 0, ""));
        out
    }

    fn test_listing(tar: &[u8], budget: &mut ListingBudget) -> Result<Vec<Entry>> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("links.tar");
        std::fs::write(&path, tar).unwrap();
        let reader = Reader::open_with_limit(&path, 1, Some(COMPRESSED_LIST_LIMIT), None, false)?;
        list_members_within(reader, budget)
    }

    /// Many members whose pax `linkpath` targets are about 1 MiB each go over a listing budget that their names alone
    /// would stay well inside.
    #[test]
    fn pax_link_targets_count_in_the_listing_budget() {
        // as long as a target can be: its record (length, key and all) fills a 1 MiB extension header
        let target = "t".repeat(MAX_EXT as usize - 64);
        let mut tar = Vec::new();
        for i in 0..8 {
            tar.extend(test_pax_link(&format!("l{i}"), &target));
        }
        tar.extend([0u8; 2 * BLOCK]);
        let mut budget = ListingBudget::with_limits(1_000_000, 4 << 20);
        let err = test_listing(&tar, &mut budget).unwrap_err();
        assert!(matches!(err, Error::Unsupported(ref why) if why.contains("link target")), "{err:?}");
        // the default budget holds them
        assert_eq!(test_listing(&tar, &mut ListingBudget::default()).unwrap().len(), 8);
    }

    /// A tar with ordinary links (a header's target, a GNU `K` record's, a pax `linkpath`'s) still lists, and the
    /// budget's total is the names and targets together.
    #[test]
    fn a_tar_with_links_lists_and_counts_its_targets() {
        let long = format!("deep/{}/target", "d".repeat(200));
        let mut tar = test_header("file", b'0', 1, "").to_vec();
        tar.extend(test_padded(b"x".to_vec()));
        tar.extend(test_header("sym", b'2', 0, "file"));
        tar.extend(test_header("hard", b'1', 0, "file"));
        let mut k = long.clone().into_bytes();
        k.push(0);
        tar.extend(test_header("././@LongLink", b'K', k.len() as u64, ""));
        tar.extend(test_padded(k));
        tar.extend(test_header("gnu", b'2', 0, ""));
        tar.extend(test_pax_link("pax", "pax/target"));
        tar.extend([0u8; 2 * BLOCK]);
        let mut budget = ListingBudget::default();
        let entries = test_listing(&tar, &mut budget).unwrap();
        let links: Vec<_> = entries.iter().map(|e| e.link.as_ref().map(|l| l.target().to_owned())).collect();
        assert_eq!(
            links,
            [None, Some("file".into()), Some("file".into()), Some(long.clone()), Some("pax/target".into())]
        );
        let names = "file".len() + "sym".len() + "hard".len() + "gnu".len() + "pax".len();
        assert_eq!(budget.bytes(), names + 4 + 4 + long.len() + "pax/target".len());
    }

    /// A pax 0.1 sparse member: one byte of data at the very end of a file `real` bytes long.
    fn test_sparse(name: &str, real: u64) -> Vec<u8> {
        let mut body = Vec::new();
        for (k, v) in [
            ("GNU.sparse.name", name.to_owned()),
            ("GNU.sparse.size", real.to_string()),
            ("GNU.sparse.map", format!("{},1", real - 1)),
        ] {
            let tail = format!(" {k}={v}\n");
            let mut n = tail.len() + 1;
            while format!("{n}{tail}").len() != n {
                n += 1;
            }
            body.extend_from_slice(format!("{n}{tail}").as_bytes());
        }
        let mut out = test_header("PaxHeaders/x", b'x', body.len() as u64, "").to_vec();
        body.resize(body.len().div_ceil(BLOCK) * BLOCK, 0);
        out.extend(body);
        out.extend(test_header("GNUSparseFile.0/x", b'0', 1, ""));
        let mut data = vec![0u8; BLOCK];
        data[0] = b'z';
        out.extend(data);
        out
    }

    /// Where hard links fail (FAT, exFAT), each link to a sparse file is a copy that writes its holes as data: the
    /// copies are charged to the run's budget of holes, and refused one by one once it is spent.
    #[cfg(unix)]
    #[cfg(unix)]
    #[test]
    fn a_walk_reads_only_the_file_it_was_given() {
        let dir = tempfile::tempdir().unwrap();
        let tar_of = |name: &str| {
            let mut t = test_header(name, b'0', 1, "").to_vec();
            t.extend_from_slice(&[b'x'; BLOCK]);
            t.resize(t.len() + 2 * BLOCK, 0);
            t
        };
        let path = dir.path().join("in.tar");
        std::fs::write(&path, tar_of("checked")).unwrap();
        let checked = File::open(&path).unwrap();
        let walk = |file: &File| {
            let mut names = Vec::new();
            walk_members(&path, file, u64::MAX, |raw, _| {
                names.push(raw.name);
                Ok(())
            })
            .map(|_| names)
        };
        assert_eq!(walk(&checked).unwrap(), [b"checked".to_vec()]);
        // another file renamed over the path after it was checked is not read in its place
        let other = dir.path().join("other.tar");
        std::fs::write(&other, tar_of("swapped")).unwrap();
        std::fs::rename(&other, &path).unwrap();
        assert!(matches!(walk(&checked), Err(Error::Unsupported(_))));
    }

    #[test]
    fn hard_links_copied_in_place_of_linking_are_charged_for_holes() {
        copies_are_charged(false);
    }

    /// The same through a chain of links, each to the one before: every copy is charged the first file's holes.
    #[cfg(unix)]
    #[test]
    fn a_chain_of_hard_links_copied_is_charged_as_direct_links_are() {
        copies_are_charged(true);
    }

    #[cfg(unix)]
    fn copies_are_charged(chained: bool) {
        use std::io::Write;
        const MIB: u64 = 1 << 20;
        // 1 GiB + 1 KiB allowed for "big"'s one byte, less its holes: 20 MiB left
        let big = SPARSE_FREE_SIZE - 20 * MIB + 1025;
        let mut tar = test_sparse("big", big);
        // 8 MiB of holes: 12 MiB and 1 KiB left, enough for one copy of "s"
        tar.extend(test_sparse("s", 8 * MIB + 1));
        // direct links to "s", and when `chained`, each to the one before it
        for i in 0..5 {
            let target = if chained && i > 0 { format!("h{}", i - 1) } else { "s".to_owned() };
            tar.extend(test_header(&format!("h{i}"), b'1', 0, &target));
        }
        tar.extend(test_header("after.txt", b'0', 5, ""));
        let mut after = b"after".to_vec();
        after.resize(BLOCK, 0);
        tar.extend(after);
        tar.extend([0u8; 2 * BLOCK]);
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&tar).unwrap();
        let tgz = gz.finish().unwrap();
        link::NO_HARD_LINKS.with(|n| n.set(true));
        for (name, bytes) in [("c.tar", tar), ("c.tgz", tgz)] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join(name);
            std::fs::write(&path, bytes).unwrap();
            let dest = dir.path().join("out");
            let opts = Options {
                mode: Mode::Extract,
                dest: dest.clone(),
                overwrite: Overwrite::Skip,
                flatten: false,
                threads: None,
                protected_paths: Default::default(),
                parallel_min: None,
                select: None,
                windows_safe_names: false,
                special_entries: Default::default(),
                fallback_mtime: None,
                compressed_tar: Default::default(),
                version_naming: Default::default(),
                preexisting_links: Default::default(),
                refused_link_placeholder: false,
                restart_from_first_volume: false,
                replace_placed_links: false,
                keep_broken: false,
                attempt_continued_members: false,
                unix_modes: Default::default(),
                backslashes: Default::default(),
            };
            let s = run(&path, &opts, |_| {}).unwrap();
            assert_eq!(s.errors.len(), 4, "{name} chained {chained}: {:?}", s.errors);
            let over = |e: &String| e.contains("would have to copy a sparse file");
            if chained {
                // h1 is refused; h2 to h4 then link to names that were never placed
                assert!(s.errors[0].starts_with("h1") && over(&s.errors[0]), "{name}: {:?}", s.errors);
                assert!(s.errors[1..].iter().all(|e| e.contains(link::HARD_TARGET)), "{name}: {:?}", s.errors);
            } else {
                assert!(s.errors.iter().all(over), "{name}: {:?}", s.errors);
            }
            assert_eq!(s.files, 4, "{name}: big, s, h0, after.txt");
            let h0 = std::fs::read(dest.join("h0")).unwrap();
            assert_eq!(h0.len() as u64, 8 * MIB + 1, "{name}");
            assert_eq!(h0.last(), Some(&b'z'));
            use std::os::unix::fs::MetadataExt;
            let ino = |n: &str| std::fs::metadata(dest.join(n)).unwrap().ino();
            assert_ne!(ino("h0"), ino("s"), "{name}: a copy, not a link");
            for i in 1..5 {
                assert!(!dest.join(format!("h{i}")).exists(), "{name}: h{i}");
            }
            assert_eq!(std::fs::read(dest.join("after.txt")).unwrap(), b"after", "{name}");
        }
        link::NO_HARD_LINKS.with(|n| n.set(false));
    }

    /// A sparse member skipped because its file exists makes no holes, so it takes nothing from the run's budget:
    /// two members of 600 MiB of holes each, the first already there, extract the second.
    #[test]
    fn a_skipped_sparse_member_leaves_the_hole_budget_alone() {
        use std::io::Write;
        const MIB: u64 = 1 << 20;
        let mut tar = test_sparse("a", 600 * MIB);
        tar.extend(test_sparse("b", 600 * MIB));
        tar.extend([0u8; 2 * BLOCK]);
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&tar).unwrap();
        let tgz = gz.finish().unwrap();
        for (name, bytes) in [("s.tar", tar), ("s.tgz", tgz)] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join(name);
            std::fs::write(&path, bytes).unwrap();
            let dest = dir.path().join("out");
            std::fs::create_dir(&dest).unwrap();
            std::fs::write(dest.join("a"), b"kept").unwrap();
            let opts = Options {
                mode: Mode::Extract,
                dest: dest.clone(),
                overwrite: Overwrite::Skip,
                flatten: false,
                threads: None,
                protected_paths: Default::default(),
                parallel_min: None,
                select: None,
                windows_safe_names: false,
                special_entries: Default::default(),
                fallback_mtime: None,
                compressed_tar: Default::default(),
                version_naming: Default::default(),
                preexisting_links: Default::default(),
                refused_link_placeholder: false,
                restart_from_first_volume: false,
                replace_placed_links: false,
                keep_broken: false,
                attempt_continued_members: false,
                unix_modes: Default::default(),
                backslashes: Default::default(),
            };
            let s = run(&path, &opts, |_| {}).unwrap();
            assert!(s.errors.is_empty(), "{name}: {:?}", s.errors);
            assert_eq!((s.files, s.skipped), (1, 1), "{name}");
            assert_eq!(std::fs::read(dest.join("a")).unwrap(), b"kept", "{name}");
            assert_eq!(std::fs::metadata(dest.join("b")).unwrap().len(), 600 * MIB, "{name}");
            // testing still charges every member
            let s = run(&path, &Options { mode: Mode::Test, ..opts }, |_| {}).unwrap();
            assert_eq!(s.errors.len(), 1, "{name}: {:?}", s.errors);
        }
    }

    #[test]
    fn numbers() {
        assert_eq!(octal(b"0000644\0"), Some(0o644));
        assert_eq!(octal(b"   755 \0"), Some(0o755));
        assert_eq!(octal(b"\0\0\0\0"), None);
        assert_eq!(octal(b"0009\0"), None);
        let mut big = [0u8; 12];
        big[0] = 0x80;
        big[4..].copy_from_slice(&(10u64 << 32).to_be_bytes());
        assert_eq!(number(&big), Some(10 << 32));
        let neg = [0xffu8; 12];
        assert_eq!(number(&neg), Some(-1));
    }

    #[test]
    fn pax_records() {
        let mut p = Pax::default();
        let rec = |k: &str, v: &str| {
            let body = format!(" {k}={v}\n");
            let mut n = body.len() + 1;
            while format!("{n}{body}").len() != n {
                n += 1;
            }
            format!("{n}{body}")
        };
        let data =
            format!("{}{}{}", rec("path", "a/é/long name.mkv"), rec("size", "12345678901"), rec("mtime", "-1.25"));
        p.parse(data.as_bytes()).unwrap();
        assert_eq!(p.path.as_deref(), Some("a/é/long name.mkv".as_bytes()));
        assert_eq!(p.size, Some(12_345_678_901));
        assert_eq!(p.mtime, Some((-2, 750_000_000)));
        assert!(Pax::default().parse(b"99 path=x\n").is_err());
        // a time whose borrowed second doesn't fit is dropped, not wrapped
        assert_eq!(parse_time(b"-9223372036854775808.1"), None);
        assert_eq!(parse_time(b"-9223372036854775808"), Some((i64::MIN, 0)));
    }

    fn record(k: &str, v: &str) -> String {
        let body = format!(" {k}={v}\n");
        let mut n = body.len() + 1;
        while format!("{n}{body}").len() != n {
            n += 1;
        }
        format!("{n}{body}")
    }

    #[test]
    fn an_empty_owner_record_deletes_the_global_one() {
        let mut global = Pax::default();
        global.parse(format!("{}{}", record("uid", "7"), record("uname", "g")).as_bytes()).unwrap();
        let mut local = Pax::default();
        local.parse(format!("{}{}", record("uid", ""), record("uname", "")).as_bytes()).unwrap();
        let p = local.over(&global);
        // deleted: neither the global value nor anything else, so the header's field applies
        assert_eq!((p.uid, p.uname), (Some(None), Some(None)));
        let p = Pax::default().over(&global);
        assert_eq!((p.uid, p.uname.clone()), (Some(Some(7)), Some(Some("g".to_string()))));
        // an unreadable id is damage, not a reason to fall back
        assert!(Pax::default().parse(record("gid", "x1").as_bytes()).is_err());
    }

    #[test]
    fn the_metadata_budget_spans_the_listing() {
        let mut budget = MetaBudget { left: 3 * BLOCK, kept: true };
        let big = vec![("comment".to_string(), vec![0; 2 * BLOCK])];
        assert!(budget.take(&big));
        assert!(!budget.take(&big), "a second member's records no longer fit");
        assert!(budget.take(&[]));
        assert!(!budget.take_header() || budget.left < BLOCK);
        let mut spent = MetaBudget { left: BLOCK - 1, kept: true };
        assert!(!spent.take_header());
    }

    #[test]
    fn padding_rounds_to_blocks() {
        assert_eq!(padding(0), 0);
        assert_eq!(padding(1), 511);
        assert_eq!(padding(512), 0);
        assert_eq!(padding(513), 511);
    }
}
