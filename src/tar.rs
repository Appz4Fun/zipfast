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
use crate::extract::{
    Cancellation, Checked, Entry, LegacyMember, LegacyReport, ListingBudget, Meta, Mode, MtimeOrigin, Options,
    Overwrite, Place, RenameLog, RunError, Summary, check_target, create_target, finish_dirs, finish_file, make_dirs,
};
use crate::output::{Output, replace, temporary};
use crate::path::sanitize;
use crate::rar5::Redirection;
use crate::stream::{self, Codec};

const BLOCK: usize = 512;
/// Bytes moved per read.
const BUF: usize = 4 << 20;
/// The longest name, link target or pax record set taken from an extension record.
const MAX_EXT: u64 = 1 << 20;
const COMPRESSED_LIST_LIMIT: u64 = 8 << 30;
/// The most zero bytes an empty archive is taken to be: GNU tar pads one to 10 KiB, other writers to whole
/// records of up to this much.
const EMPTY_MAX: usize = 1 << 20;

/// Whether the file starts with a tar header: a block whose checksum adds up, or the two zero blocks that make an
/// empty archive.
pub fn sniff_tar(head: &[u8]) -> bool {
    (head.len() >= BLOCK && checksum_ok(&head[..BLOCK])) || (head.len() >= 2 * BLOCK && zero(&head[..2 * BLOCK]))
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

fn name_of(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Where the archive's bytes come from: the file itself, which can be skipped through, or a compressed stream,
/// which has to be read.
enum Source {
    Plain { r: BufReader<File>, len: u64, pos: u64, cancel: Option<Cancellation> },
    Packed(Box<dyn Read>, Codec),
}

impl Source {
    fn open(path: &Path, threads: usize, limit: Option<u64>, cancel: Option<Cancellation>) -> Result<Source> {
        let mut file = File::open(path)?;
        let mut head = [0u8; 6];
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
            return Ok(Source::Packed(codec.open(reader, threads).map_err(read_error)?, codec));
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
        Ok(Source::Packed(Box::new(decoded), codec))
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
            Source::Packed(r, _) => read_full(r, buf).map_err(read_error)?,
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

    fn codec(&self) -> Option<Codec> {
        match self {
            Source::Packed(_, c) => Some(*c),
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
    size: u64,
    kind: Kind,
    mtime: Option<i64>,
    nanos: u32,
    mode: u32,
    atime: Option<(i64, u32)>,
    ctime: Option<(i64, u32)>,
    tar: Box<TarMetadata>,
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

    fn into_entry(self) -> Entry {
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
            tar: Some(self.tar),
            attributes: None,
            name: self.name,
            size: if data { self.size } else { 0 },
            packed: if data { self.size } else { 0 },
            mtime: self.mtime,
            crc32: None,
            method: 0,
            method_name: None,
            dir: self.kind == Kind::Dir,
            encrypted: false,
            solid: false,
            link,
        }
    }
}

/// Values from pax records, for the next member or (from a global record) for every member after.
#[derive(Clone, Debug, Default)]
struct Pax {
    path: Option<String>,
    linkpath: Option<String>,
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
                b"path" => self.path = Some(name_of(value)),
                b"linkpath" => self.linkpath = Some(name_of(value)),
                b"size" => {
                    self.size = Some(std::str::from_utf8(value).ok().and_then(|s| s.parse().ok()).ok_or_else(bad)?)
                }
                b"mtime" => self.mtime = parse_time(value),
                k if k.starts_with(b"GNU.sparse.") => self.sparse = true,
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
            sparse: self.sparse || under.sparse,
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
    content: Content,
    /// the start of the data, read to tell tar from a lone compressed file: one header block for tar
    first: Option<Vec<u8>>,
    /// data and padding of the current member not read yet
    unread: u64,
    global: Pax,
    /// What is left of the listing's budget for pax records and raw headers.
    meta_budget: MetaBudget,
    scratch: Vec<u8>,
}

impl Reader {
    fn open_with_limit(
        path: &Path,
        threads: usize,
        limit: Option<u64>,
        cancel: Option<Cancellation>,
    ) -> Result<Reader> {
        let mut src = Source::open(path, threads, limit, cancel)?;
        let mut first = vec![0u8; BLOCK];
        let n = src.read(&mut first)?;
        first.truncate(n);
        let mut content = if n == BLOCK && checksum_ok(&first) {
            Some(Content::Tar)
        } else if src.codec().is_some() {
            Some(Content::Single)
        } else {
            None
        };
        if n == BLOCK && zero(&first) {
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
            content,
            first: Some(first),
            unread: 0,
            global: Pax::default(),
            meta_budget: MetaBudget::new(),
            scratch: vec![0; 64 << 10],
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
        if self.unread > 0 {
            let n = std::mem::take(&mut self.unread);
            self.src.skip(n, &mut self.scratch)?;
        }
        let mut long_name: Option<Vec<u8>> = None;
        let mut long_link: Option<String> = None;
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
                    long_link = Some(name_of(text(&self.ext_data(size)?)));
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
            let (name, raw_name) = match p.path.clone() {
                Some(path) => (path, None),
                None => {
                    let stored = long_name.unwrap_or(name);
                    let decoded = name_of(&stored);
                    (decoded, std::str::from_utf8(&stored).is_err().then_some(stored))
                }
            };
            let link = p.linkpath.clone().or(long_link).unwrap_or_else(|| name_of(text(&h[157..257])));
            let size = p.size.unwrap_or(size);
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
                b'3' | b'4' | b'6' | b'S' | b'M' | b'V' => Kind::Other(kind),
                _ if p.sparse => Kind::Other(b'S'),
                // POSIX: a type this reader doesn't know is read as a regular file
                _ => Kind::File,
            };
            // an old GNU sparse member's map can go on in extension blocks between the header and the data;
            // they are passed over so the member after it is still found
            if h[156] == b'S' && &h[257..263] != b"ustar\0" && h[482] != 0 {
                loop {
                    let mut ext = [0u8; BLOCK];
                    if self.src.read(&mut ext)? < BLOCK {
                        return Err(Error::Truncated);
                    }
                    if ext[504] == 0 {
                        break;
                    }
                }
            }
            // links and folders carry no data, whatever the size field says, except GNU's dump folders
            let has_data = !matches!(kind, Kind::HardLink | Kind::Symlink) && !(kind == Kind::Dir && h[156] == b'5');
            self.unread = if has_data { size + padding(size) } else { 0 };
            return Ok(Some(Member {
                name,
                raw_name,
                link,
                size: if has_data { size } else { 0 },
                kind,
                mtime,
                nanos,
                mode,
                atime: p.atime,
                ctime: p.ctime,
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
            }));
        }
    }

    /// The current member's data, in pieces, to `sink`. Reads exactly its size and leaves the padding for later.
    fn read_data(&mut self, size: u64, buf: &mut [u8], sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        let mut left = size;
        while left > 0 {
            let want = left.min(buf.len() as u64) as usize;
            let got = self.src.read(&mut buf[..want])?;
            self.unread -= got as u64;
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
    size: Option<u64>,
    pub meta: Meta,
}

impl Selected {
    pub(crate) fn open(path: &Path, index: usize, limit: u64, cancel: Cancellation) -> Result<Self> {
        let mut reader = Reader::open_with_limit(path, 1, Some(limit), Some(cancel))?;
        if matches!(reader.content, Content::Single) {
            let codec = reader.src.codec().ok_or(Error::NotAnArchive)?;
            if index == 0 {
                return Ok(Self {
                    name: single_name(codec, path),
                    reader,
                    path: path.to_path_buf(),
                    size: None,
                    meta: Meta::default(),
                });
            }
        } else {
            let mut current = 0;
            while let Some(member) = reader.next()? {
                if member.kind == Kind::Other(b'V') {
                    continue;
                }
                if current == index {
                    if member.kind != Kind::File {
                        return Err(Error::Unsupported("the selected tar member is not a regular file".into()));
                    }
                    if member.size > limit {
                        return Err(Error::Unsupported("the selected member exceeds the byte limit".into()));
                    }
                    let meta = member.meta();
                    return Ok(Self {
                        reader,
                        path: path.to_path_buf(),
                        name: member.name,
                        size: Some(member.size),
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
        if let Some(size) = self.size {
            self.reader.read_data(size, &mut buf, sink)?;
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
    let mut reader = Reader::open_with_limit(path, 1, Some(COMPRESSED_LIST_LIMIT), None)?;
    if let (Content::Single, Some(codec)) = (&reader.content, reader.src.codec()) {
        let gzip = codec == Codec::Gzip;
        let packed = std::fs::metadata(path)?.len();
        let mut buf = vec![0u8; BUF];
        let size = reader.read_single(&mut buf, &mut |_| Ok(()))?;
        // RFC 1952: MTIME is Unix time, 0 when none was recorded.
        let mtime = if gzip { stream::gzip_mtime(path) } else { None };
        return Ok(vec![Entry {
            mode: None,
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
        }]);
    }
    let mut out = Vec::new();
    let mut budget = ListingBudget::default();
    while let Some(m) = reader.next()? {
        if m.kind != Kind::Other(b'V') {
            budget.record(&m.name)?;
            out.push(m.into_entry());
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
    let n = read_full(&mut File::open(path)?, &mut head)?;
    Ok(Codec::sniff(&head[..n]).is_some() || sniff_tar(&head[..n]))
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
    let mut reader = Reader::open_with_limit(path, threads, None, cancel.cloned())?;
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
    size: Option<u64>,
    summary: &mut Summary,
    report: &mut impl LegacyReport,
) -> Result<Option<Output>> {
    checked_place(opts, rel, (ordinal, name), summary, report)?.map(|place| create_target(place, size)).transpose()
}

/// How a member's data went: written whole, or the error that stopped it.
enum Outcome {
    Done,
    /// the archive itself is damaged or cut short: the member fails and nothing after it can be found
    Archive(Error),
}

enum StagedMember {
    Directory { relative: PathBuf, meta: Meta, ordinal: u64, name: String },
    File { relative: PathBuf, name: String, temporary: tempfile::TempPath, size: u64, ordinal: u64 },
}

#[derive(Default)]
struct StagedTar {
    members: Vec<StagedMember>,
    budget: ListingBudget,
}

impl StagedTar {
    fn publish(self, opts: &Options, summary: &mut Summary, report: &mut impl LegacyReport) -> Result<()> {
        for member in self.members {
            match member {
                StagedMember::Directory { relative, meta, ordinal, name } => {
                    make_dirs(&opts.dest, &relative)?;
                    summary.dir_meta.push((opts.dest.join(relative), meta));
                    folder(summary, report, ordinal, &name);
                }
                StagedMember::File { relative, name, temporary, size, ordinal } => {
                    let Some(place) = checked_place(opts, &relative, (ordinal, &name), summary, report)? else {
                        continue;
                    };
                    if let Some(reserved) = place.reserved {
                        // the rename mode's own empty file, created with O_EXCL a moment ago, takes the data
                        replace(temporary, reserved.path())?;
                        drop(reserved.into_parts());
                    } else if place.replace {
                        replace(temporary, &place.path)?;
                    } else if let Err(error) = temporary.persist_noclobber(place.path) {
                        if opts.overwrite == Overwrite::Skip && error.error.kind() == io::ErrorKind::AlreadyExists {
                            skipped(summary, report, ordinal, &name);
                            continue;
                        }
                        return Err(error.error.into());
                    }
                    succeeded(summary, report, ordinal, &name, size);
                }
            }
        }
        Ok(())
    }
}

fn checked_place(
    opts: &Options,
    relative: &Path,
    (ordinal, name): (u64, &str),
    summary: &mut Summary,
    report: &mut impl LegacyReport,
) -> Result<Option<Place>> {
    let mut log = RenameLog {
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
    read: impl FnOnce(&mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()>,
) -> Result<Outcome> {
    // write errors are kept apart from read errors so the two can be told apart afterwards
    let mut write_error: Option<io::Error> = None;
    let read = {
        let mut sink = |chunk: &[u8]| -> Result<()> {
            if let Some(out) = target.as_mut()
                && let Err(e) = out.write(chunk)
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
        match target(opts, &rel, (0, &name), None, summary, report)? {
            Some(t) => out = Some(t),
            None => return Ok(()),
        }
    }
    let mut total = 0u64;
    let outcome = copy_out(out, &Meta::default(), |sink| {
        total = reader.read_single(buf, sink)?;
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
    // the next member's position in a listing, which leaves out volume labels
    let mut ordinal = 0u64;
    loop {
        let m = match reader.next() {
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
                    staged.publish(opts, summary, report)?;
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
        let rel = match sanitize(&m.name, false) {
            Ok(rel) => rel,
            Err(e) => {
                fail_member(summary, report, position, &m.name, &e.to_string(), e);
                continue;
            }
        };
        let rel = if opts.flatten { PathBuf::from(rel.file_name().unwrap_or_default()) } else { rel };
        let why = match m.kind {
            Kind::Dir => {
                if opts.mode == Mode::Extract && !opts.flatten {
                    if let Some(staged) = &mut staged {
                        staged.budget.record(&m.name)?;
                        let meta = m.meta();
                        staged.members.push(StagedMember::Directory {
                            relative: rel,
                            meta,
                            ordinal: position,
                            name: m.name,
                        });
                        continue;
                    }
                    make_dirs(&opts.dest, &rel)?;
                    summary.dir_meta.push((opts.dest.join(&rel), m.meta()));
                }
                folder(summary, report, position, &m.name);
                continue;
            }
            Kind::File => None,
            Kind::Symlink | Kind::HardLink => Some("links are not supported yet"),
            Kind::Other(b'V') => continue,
            Kind::Other(b'S') => Some("sparse files are not supported yet"),
            Kind::Other(b'M') => Some("multi-volume tar archives are not supported yet"),
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
                && checked_place(opts, &rel, (position, &m.name), summary, report)?.is_none()
            {
                continue;
            }
            staged.budget.record(&m.name)?;
            let (file, temporary) = temporary(&parent)?.into_parts();
            let output = Output::new(file, Some(m.size));
            match copy_out(Some(output), &m.meta(), |sink| reader.read_data(m.size, buf, sink))? {
                Outcome::Done => {
                    let (name, size) = (m.name, m.size);
                    staged.members.push(StagedMember::File { relative: rel, name, temporary, size, ordinal: position });
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
            match target(opts, &rel, (position, &m.name), Some(m.size), summary, report)? {
                Some(t) => out = Some(t),
                None => continue,
            }
        } else if let Source::Plain { .. } = reader.src {
            // tar keeps no checksum of the data, so a test only has to find that all of it is there
            let size = m.size + padding(m.size);
            match reader.src.skip(size, &mut reader.scratch) {
                Ok(()) => {
                    reader.unread = 0;
                    succeeded(summary, report, position, &m.name, m.size);
                    continue;
                }
                Err(Error::Io(e)) => return Err(Error::Io(e)),
                Err(e) => {
                    fail_member(summary, report, position, &m.name, &e.to_string(), e);
                    return Ok(());
                }
            }
        }
        let size = m.size;
        match copy_out(out, &m.meta(), |sink| reader.read_data(size, buf, sink))? {
            Outcome::Done => succeeded(summary, report, position, &m.name, m.size),
            Outcome::Archive(e) => {
                fail_member(summary, report, position, &m.name, &e.to_string(), e);
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(p.path.as_deref(), Some("a/é/long name.mkv"));
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
