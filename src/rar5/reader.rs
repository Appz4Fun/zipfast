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

//! Walks one RAR 5.0 volume block by block.

use std::fs::File;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, SyncSender, channel, sync_channel};

use crate::batch::{PositionReadError, read_at_detailed};

use super::session::{ScanBudget, allocation};
use super::*;
use crate::error::{
    Error, IoOperation, RarFailure, RarFault, RarIntegrityReason, RarInternal, RarPasswordEvidence, RarResult,
    RarScope, RarUnsupported, Result,
};
use crate::extract::{DamagedInput, HeaderDamage, HeaderDamageKind};

pub enum Block {
    Main(MainHeader),
    File(FileHeader),
    Service(FileHeader),
    End {
        more_volumes: bool,
        /// The volume number a RAR4 end header records (`EARC_VOLNUMBER`). RAR 5.0 keeps it in the main header.
        volume_number: Option<u64>,
    },
    /// Headers from here on are encrypted.
    Crypt,
    Unknown,
}

pub(crate) enum ReadDataError<E> {
    Input(RarFault),
    Sink(E),
}

type ParsedBlock = (Block, MemberCrypt, Option<FileWire>);

/// The longest member name a [`HeaderDamage`] keeps.
const MAX_DAMAGE_NAME: usize = 1024;

/// [`Volume::resync`] reads the volume this many bytes at a time.
const RESYNC_CHUNK: usize = 1 << 20;
/// The first chunk a resync reads: most land on a header within it, and a run of resyncs close together reads little.
const RESYNC_FIRST_CHUNK: usize = 64;
/// Bytes past each chunk a resync reads, so that every position in the chunk shows its header's fixed fields.
const RESYNC_LOOKAHEAD: usize = 32;
/// The longest RAR 5.0 file or service header a resync checks: real ones, names and extra records included, are far
/// shorter. An end header is at most [`RESYNC_END_MAX`].
const RESYNC_HEADER_MAX: usize = 8 << 10;
const RESYNC_END_MAX: usize = 32;
/// The longest RAR 4.x file or service header a resync checks: 32 fixed bytes, a name of at most 2 KiB, and room for
/// the high sizes, salt and extended times.
const RESYNC_RAR4_HEADER_MAX: usize = 32 + 2048 + 64;
/// Work (bytes read and checksummed) all the resyncs in a volume may do per byte of the volume (plus 1 MiB), keeping
/// them linear.
const RESYNC_WORK_PER_BYTE: u64 = 16;

/// The length of the header [`Volume::resync`] would check at the start of `b` (up to [`RESYNC_LOOKAHEAD`] bytes of
/// it), from its fixed fields alone: a file, service or end header of a plausible size and with plausible fields. None
/// when it is none. Random bytes pass about once in a few thousand positions, with a short header, so that checking
/// what passes costs about a byte per byte scanned.
fn resync_shape(b: &[u8], format: RarFormat) -> Option<usize> {
    if b.len() < 7 {
        return None;
    }
    match format {
        RarFormat::Rar5 => {
            let mut size = 0usize;
            let mut size_len = 0;
            loop {
                let byte = b[4 + size_len];
                size |= usize::from(byte & 0x7f) << (7 * size_len);
                size_len += 1;
                if byte & 0x80 == 0 {
                    // RAR writes the shortest form: a last byte of 0 after a continued one is not a size it wrote
                    if byte == 0 && size_len > 1 {
                        return None;
                    }
                    break;
                }
                if size_len == 3 {
                    return None;
                }
            }
            let kind = *b.get(4 + size_len)?;
            // header flags: one byte, with only the defined bits (extra, data, skip, split before and after, child,
            // inherited)
            let flags = *b.get(5 + size_len)?;
            let most = match kind {
                2 | 3 => RESYNC_HEADER_MAX,
                5 => RESYNC_END_MAX,
                _ => return None,
            };
            ((3..=most).contains(&size) && flags < 0x80).then_some(4 + size_len + size)
        }
        RarFormat::Rar4 => {
            let size = usize::from(u16::from_le_bytes([b[5], b[6]]));
            match b[2] {
                0x74 | 0x7a => {
                    // LONG_BLOCK; host OS 0..=5; unpack version 15..=36 (RAR 1.5 to 3.6 formats); method 0x30..=0x35;
                    // a name that fits in the header
                    let fields = b.get(..28)?;
                    let name = usize::from(u16::from_le_bytes([fields[26], fields[27]]));
                    let plausible = fields[4] & 0x80 != 0
                        && fields[15] <= 5
                        && (15..=36).contains(&fields[24])
                        && (0x30..=0x35).contains(&fields[25])
                        && name > 0
                        && 32 + name <= size
                        && size <= RESYNC_RAR4_HEADER_MAX;
                    plausible.then_some(size)
                }
                0x7b => (7..=20).contains(&size).then_some(size),
                _ => None,
            }
        }
    }
}

/// Whether the whole header `h` (as long as [`resync_shape`] said) passes its checksum.
fn resync_checks(h: &[u8], format: RarFormat) -> bool {
    match format {
        RarFormat::Rar5 => crate::crc32::hash(&h[4..]) == u32::from_le_bytes([h[0], h[1], h[2], h[3]]),
        RarFormat::Rar4 => crate::crc32::hash(&h[2..]) as u16 == u16::from_le_bytes([h[0], h[1]]),
    }
}

fn header_buffer(size: usize) -> RarResult<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(size).map_err(|_| allocation())?;
    bytes.resize(size, 0);
    Ok(bytes)
}

pub(super) fn read_failure(e: PositionReadError, path: Option<PathBuf>, reason: RarIntegrityReason) -> RarFault {
    match e {
        PositionReadError::Eof => RarFault::new(
            RarFailure::integrity(
                RarScope::Header { volume: path.unwrap_or_default() },
                reason,
                RarPasswordEvidence::NotEncrypted,
                false,
            ),
            Error::Truncated,
        ),
        PositionReadError::Io { offset, source } => RarFault::input(IoOperation::Read, path, Some(offset), source),
    }
}

#[derive(Debug)]
enum SourceError {
    Read(PositionReadError),
    Clone(std::io::Error),
    Spawn(std::io::Error),
    Stopped,
}

impl SourceError {
    fn detailed(self, path: &Path, reason: RarIntegrityReason) -> RarFault {
        match self {
            Self::Read(e) => read_failure(e, Some(path.to_path_buf()), reason),
            Self::Clone(e) => RarFault::input(IoOperation::Open, Some(path.to_path_buf()), None, e),
            Self::Spawn(e) => RarFault::new(RarFailure::Internal(RarInternal::WorkerStopped), e.into()),
            Self::Stopped => RarFault::new(RarFailure::Internal(RarInternal::WorkerStopped), Error::Truncated),
        }
    }
}

/// Reads `buf.len()` bytes of a volume at `at`. Every read of a volume's bytes goes through this (here and in
/// [`crate::batch::stored_detailed`]), so a test can check that each byte is read once.
pub(crate) fn read_volume(file: &File, buf: &mut [u8], at: u64) -> std::result::Result<(), PositionReadError> {
    #[cfg(all(test, unix))]
    count_read(file, at, buf.len());
    read_at_detailed(file, buf, at)
}

/// A volume read in tests: the file's (device, inode), where, and how many bytes.
#[cfg(all(test, unix))]
pub(crate) type VolumeRead = ((u64, u64), u64, u64);

/// Every volume read in tests.
#[cfg(all(test, unix))]
pub(crate) static VOLUME_READS: std::sync::Mutex<Vec<VolumeRead>> = std::sync::Mutex::new(Vec::new());

#[cfg(all(test, unix))]
fn count_read(file: &File, at: u64, len: usize) {
    use std::os::unix::fs::MetadataExt;
    if let Ok(meta) = file.metadata() {
        VOLUME_READS.lock().unwrap_or_else(|e| e.into_inner()).push(((meta.dev(), meta.ino()), at, len as u64));
    }
}

/// Bytes read from a volume at a time. Headers and the data of small files after them come in together, so a
/// run of small files takes one read for several of them.
const READ: usize = 1 << 20;

/// Pieces read ahead of the one in use, once the volume is read straight through, by each reading thread.
const AHEAD: usize = 2;

/// Threads reading ahead for stored data ([`Volume::read_fast`]), which is only checked (and copied) as it comes:
/// that takes it faster than one thread copies it out of the page cache, so two take turns. Compressed data comes no
/// faster than it is decoded, so one thread keeps up there, and a second would only take time from the decoding.
const FAST_READERS: usize = 2;

/// A move forward by up to this much past what is read reads on through; a longer one starts again at the place.
const SKIP_MAX: u64 = 2 * READ as u64;

/// A piece of a volume as it was read, shared with whatever keeps its bytes without copying them (the decoder's
/// workers). Once the last reference goes, the buffer goes back to the thread reading ahead, if it came from one, to
/// be filled again.
pub struct Piece {
    bytes: Vec<u8>,
    home: Option<Sender<Vec<u8>>>,
}

impl Piece {
    fn new(bytes: Vec<u8>, home: Option<Sender<Vec<u8>>>) -> Arc<Piece> {
        Arc::new(Piece { bytes, home })
    }

    /// `bytes` as a piece of their own.
    #[cfg(test)]
    pub fn of(bytes: Vec<u8>) -> Arc<Piece> {
        Piece::new(bytes, None)
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for Piece {
    fn drop(&mut self) {
        if let Some(home) = self.home.take()
            && self.bytes.capacity() > 0
        {
            // the thread may have stopped; the buffer is freed then
            let _ = home.send(std::mem::take(&mut self.bytes));
        }
    }
}

/// A volume read in pieces of [`READ`] bytes. Read straight through, the pieces come from a thread of its own
/// that keeps [`AHEAD`] of them ready, so the reading is off the caller's thread. All reads are by position, so
/// nothing depends on where the file stands.
struct Source {
    file: File,
    len: u64,
    /// the piece in use, which starts at `at` in the file; `off` of it is used up
    piece: Arc<Piece>,
    at: u64,
    off: usize,
    /// set while pieces are read in order, so the next one can come from the threads
    sequential: bool,
    ahead: Option<Ahead>,
    /// how many threads read ahead, from when they next start
    readers: usize,
}

/// The threads reading ahead, the one the next piece comes from, and where that piece starts.
struct Ahead {
    pieces: Vec<Receiver<std::result::Result<Vec<u8>, PositionReadError>>>,
    turn: usize,
    spare: Sender<Vec<u8>>,
    next: u64,
}

impl Ahead {
    fn start(file: &File, from: u64, len: u64, readers: usize) -> std::result::Result<Ahead, SourceError> {
        let (spare, spares) = channel::<Vec<u8>>();
        let spares = Arc::new(std::sync::Mutex::new(spares));
        let mut pieces = Vec::with_capacity(readers);
        for k in 0..readers {
            let file = file.try_clone().map_err(SourceError::Clone)?;
            let (send, recv) = sync_channel(AHEAD);
            let spares = Arc::clone(&spares);
            std::thread::Builder::new()
                .name("rar5-read".into())
                .spawn(move || read_ahead(&file, from + (k * READ) as u64, readers, len, &send, &spares))
                .map_err(SourceError::Spawn)?;
            pieces.push(recv);
        }
        Ok(Ahead { pieces, turn: 0, spare, next: from })
    }

    /// The next piece, in order.
    fn recv(&mut self) -> std::result::Result<Vec<u8>, SourceError> {
        let piece = self.pieces[self.turn].recv().map_err(|_| SourceError::Stopped)?;
        self.turn = (self.turn + 1) % self.pieces.len();
        piece.map_err(SourceError::Read)
    }
}

/// Reads every `readers`th piece from `at` to `len` in order and sends them, until the receiver goes away.
fn read_ahead(
    file: &File,
    mut at: u64,
    readers: usize,
    len: u64,
    send: &SyncSender<std::result::Result<Vec<u8>, PositionReadError>>,
    spares: &std::sync::Mutex<Receiver<Vec<u8>>>,
) {
    while at < len {
        let n = (len - at).min(READ as u64) as usize;
        let mut buf = spares.lock().ok().and_then(|s| s.try_recv().ok()).unwrap_or_default();
        buf.resize(n, 0);
        let read = read_volume(file, &mut buf, at).map(|()| buf);
        let failed = read.is_err();
        if send.send(read).is_err() || failed {
            return;
        }
        at += (readers * READ) as u64;
    }
}

impl Source {
    /// A source whose first piece is `head`, the volume's first bytes as they were read to find its signature, so
    /// they aren't read again. At most `len` of them are kept.
    fn new(file: File, len: u64, mut head: Vec<u8>) -> Source {
        head.truncate(usize::try_from(len).unwrap_or(usize::MAX));
        Source { file, len, piece: Piece::new(head, None), at: 0, off: 0, sequential: false, ahead: None, readers: 1 }
    }

    /// What is left of the piece in use.
    fn held(&self) -> &[u8] {
        &self.piece.bytes[self.off..]
    }

    /// The piece in use, and where what is left of it starts.
    fn held_shared(&self) -> (&Arc<Piece>, usize) {
        (&self.piece, self.off)
    }

    /// Lets go of the piece in use: its buffer goes back to the thread, or is kept to read into next when nothing
    /// else holds it.
    fn release(&mut self) -> Vec<u8> {
        let used = std::mem::replace(&mut self.piece, Piece::new(Vec::new(), None));
        match Arc::try_unwrap(used) {
            Ok(mut piece) if piece.home.is_none() => std::mem::take(&mut piece.bytes),
            _ => Vec::new(),
        }
    }

    fn consume(&mut self, n: usize) {
        self.off += n;
    }

    /// Moves to `at`.
    fn seek(&mut self, at: u64) {
        let end = self.at + self.piece.bytes.len() as u64;
        if (self.at..=end).contains(&at) {
            self.off = (at - self.at) as usize;
        } else if at > end && at - end <= SKIP_MAX {
            // close ahead: read on to it, so a run of small blocks keeps its pieces coming
            self.at = end;
            let _ = self.release();
            self.off = (at - end) as usize;
        } else {
            self.ahead = None;
            self.sequential = false;
            self.at = at;
            let _ = self.release();
            self.off = 0;
        }
    }

    /// Makes sure the piece in use has bytes left, unless the file ends. False at the end of the file.
    fn fill(&mut self) -> std::result::Result<bool, SourceError> {
        while self.off >= self.piece.bytes.len() {
            let skip = self.off - self.piece.bytes.len();
            let from = self.at + self.piece.bytes.len() as u64;
            if from >= self.len {
                return Ok(false);
            }
            let used = self.release();
            if self.ahead.as_ref().is_some_and(|a| a.next != from) {
                self.ahead = None;
            }
            if self.ahead.is_none() && self.sequential {
                self.ahead = Some(Ahead::start(&self.file, from, self.len, self.readers)?);
            }
            self.piece = match self.ahead.as_mut() {
                Some(a) => {
                    if used.capacity() > 0 {
                        // the thread fills it again rather than making a new one
                        let _ = a.spare.send(used);
                    }
                    let bytes = a.recv()?;
                    a.next += bytes.len() as u64;
                    // back to the thread once nothing holds it
                    Piece::new(bytes, Some(a.spare.clone()))
                }
                None => {
                    // the first piece after a move is read here; read on past it, and the thread takes over
                    let mut buf = used;
                    buf.resize((self.len - from).min(READ as u64) as usize, 0);
                    read_volume(&self.file, &mut buf, from).map_err(SourceError::Read)?;
                    self.sequential = true;
                    Piece::new(buf, None)
                }
            };
            self.at = from;
            self.off = skip;
        }
        Ok(true)
    }
}

pub struct Volume {
    pub path: PathBuf,
    src: Source,
    /// where the next block starts
    next: u64,
    len: u64,
    pub main: MainHeader,
    password: Option<String>,
    header_key: Option<crate::crypto::Rar5Keys>,
    /// RAR 3.x encrypted headers (`-hp`): each header carries its own salt, the keys derived once per salt.
    legacy_keys: Option<crate::crypto::Rar4KeyCache>,
    parser: Option<super::framing::HeaderParser>,
    format: RarFormat,
    /// Bytes before the signature: a self-extracting module or other prefix.
    sfx: u64,
    /// The end of archive header's fields, once it is read.
    end_record: Option<super::RarEndRecord>,
    /// What a damaged header does ([`crate::extract::Options::damaged_input`]).
    damaged_input: DamagedInput,
    /// Headers read past since [`Self::take_damage`] last ran.
    damage: Vec<HeaderDamage>,
    /// Whether this volume's damage is already accounted for to its end (no "unexpected end" on top).
    damage_closed: bool,
    /// A block found where the main header should be, under salvage: handed out first.
    held_block: Option<ParsedBlock>,
    /// Checksum work the resyncs in this volume have left, once one has run.
    resync_work: Option<u64>,
    /// The run's cancellation, for a resync's search.
    cancel: Option<crate::extract::Cancellation>,
}

pub(crate) const SIGNATURE_PROBE_BYTES: u64 = MAX_SFX + SIGNATURE.len() as u64;

fn volume_length(path: &Path, metadata: impl FnOnce() -> std::io::Result<std::fs::Metadata>) -> RarResult<u64> {
    metadata()
        .map(|meta| meta.len())
        .map_err(|e| RarFault::input(IoOperation::Metadata, Some(path.to_path_buf()), None, e))
}

pub(crate) fn signature_end(head: &[u8]) -> Result<u64> {
    signature_location(head).map(|(offset, _)| offset)
}

fn signature_location(head: &[u8]) -> Result<(u64, RarFormat)> {
    super::framing::SignatureParser::default().advance(head).1.ok_or(Error::NotAnArchive)
}

fn signature_fault(e: Error) -> RarFault {
    let failure = match e {
        Error::NotAnArchive => RarFailure::NotRar,
        _ => RarFailure::Unsupported(RarUnsupported::ArchiveVersion(4)),
    };
    RarFault::new(failure, e)
}

#[cfg(all(test, unix))]
thread_local! {
    pub(crate) static VOLUME_OPENS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Recognition and its initial held data handle cannot become separated. The bytes read to recognize it (from the
/// start of the file) are kept, so the volume doesn't read them again.
pub(crate) struct HeldSignature {
    file: File,
    len: u64,
    next: u64,
    format: RarFormat,
    head: Vec<u8>,
}
impl HeldSignature {
    pub(crate) fn recognize(file: File, len: u64, head: Vec<u8>) -> std::result::Result<Self, File> {
        match signature_location(&head) {
            Ok((next, format)) => Ok(Self { file, len, next, format, head }),
            Err(_) => Err(file),
        }
    }
}
impl Volume {
    pub(crate) fn from_held_signature(
        path: &Path,
        signature: HeldSignature,
        password: Option<&str>,
        damaged: DamagedInput,
    ) -> Result<Self> {
        let HeldSignature { file, len, next, format, head } = signature;
        Self::initialize_held(path, file, len, password, (head, next, format), false, None, damaged)
            .map_err(RarFault::into_legacy)
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    pub(crate) fn from_held_signature_detailed(
        path: &Path,
        signature: HeldSignature,
        password: Option<&str>,
        damaged: DamagedInput,
    ) -> RarResult<Self> {
        let HeldSignature { file, len, next, format, head } = signature;
        Self::initialize_held(path, file, len, password, (head, next, format), true, None, damaged)
    }
    /// Opens the volume in `file` (at `path`), whose first bytes `head` were read already (to tell its format): they
    /// are kept rather than read again, and only what the signature search needs past them is read.
    pub(crate) fn open_head(
        path: &Path,
        file: File,
        head: Vec<u8>,
        password: Option<&str>,
        damaged: DamagedInput,
    ) -> Result<Volume> {
        Self::open_head_impl(path, file, head, password, false, damaged).map_err(RarFault::into_legacy)
    }
    pub(crate) fn open_head_detailed(
        path: &Path,
        file: File,
        head: Vec<u8>,
        password: Option<&str>,
        damaged: DamagedInput,
    ) -> RarResult<Volume> {
        Self::open_head_impl(path, file, head, password, true, damaged)
    }
    fn open_head_impl(
        path: &Path,
        file: File,
        head: Vec<u8>,
        password: Option<&str>,
        detailed: bool,
        damaged: DamagedInput,
    ) -> RarResult<Volume> {
        #[cfg(all(test, unix))]
        VOLUME_OPENS.set(VOLUME_OPENS.get() + 1);
        let len = volume_length(path, || file.metadata())?;
        let found = Self::probe_head(path, &file, len, head)?;
        Self::initialize_held(path, file, len, password, found, detailed, None, damaged)
    }
    pub fn open(path: &Path) -> Result<Volume> {
        Self::open_with_password(path, None)
    }

    pub fn open_with_password(path: &Path, password: Option<&str>) -> Result<Volume> {
        Self::open_damaged(path, password, DamagedInput::Refuse)
    }

    /// [`Self::open_with_password`], reading damaged headers as `damaged` says
    /// ([`crate::extract::Options::damaged_input`]); [`Self::take_damage`] hands out what was read past.
    pub fn open_damaged(path: &Path, password: Option<&str>, damaged: DamagedInput) -> Result<Volume> {
        Self::open_impl(path, password, false, damaged).map_err(RarFault::into_legacy)
    }

    pub(crate) fn open_detailed_damaged(
        path: &Path,
        password: Option<&str>,
        damaged: DamagedInput,
    ) -> RarResult<Volume> {
        Self::open_impl(path, password, true, damaged)
    }

    fn open_impl(path: &Path, password: Option<&str>, detailed: bool, damaged: DamagedInput) -> RarResult<Volume> {
        let file =
            File::open(path).map_err(|e| RarFault::input(IoOperation::Open, Some(path.to_path_buf()), None, e))?;
        #[cfg(all(test, unix))]
        VOLUME_OPENS.set(VOLUME_OPENS.get() + 1);
        let len = volume_length(path, || file.metadata())?;
        let found = Self::probe_head(path, &file, len, Vec::new())?;
        Self::initialize_held(path, file, len, password, found, detailed, None, damaged)
    }

    /// Opens a volume for the catalogue, whose reads are counted by `budget`: it reads the signature's bytes, and
    /// searches the rest of the window only when they aren't one.
    pub(super) fn open_catalogue(
        path: &Path,
        file: File,
        len: u64,
        password: Option<&str>,
        budget: &mut ScanBudget<'_>,
        damaged: DamagedInput,
    ) -> RarResult<Self> {
        let mut first = [0; SIGNATURE.len()];
        let used = len.min(SIGNATURE.len() as u64) as usize;
        budget.read(&file, path, &mut first[..used], 0)?;
        let (next, format) = if first == *SIGNATURE {
            (SIGNATURE.len() as u64, RarFormat::Rar5)
        } else if first.starts_with(SIGNATURE_V4) {
            (SIGNATURE_V4.len() as u64, RarFormat::Rar4)
        } else {
            Self::probe_signature(path, &file, len, (first, used), budget)?
        };
        Self::initialize_held(path, file, len, password, (Vec::new(), next, format), true, Some(budget), damaged)
    }

    /// The signature's end and the format, searched for in the volume's first bytes: `head` (read already, from the
    /// start of the file), and as much more of the window as the search needs. The bytes read are returned with it,
    /// for the volume's first piece, so nothing is read twice.
    fn probe_head(path: &Path, file: &File, len: u64, mut head: Vec<u8>) -> RarResult<(Vec<u8>, u64, RarFormat)> {
        head.truncate(usize::try_from(len).unwrap_or(usize::MAX));
        if let Ok((next, format)) = signature_location(&head) {
            return Ok((head, next, format));
        }
        let want = len.min(SIGNATURE_PROBE_BYTES) as usize;
        let have = head.len();
        if have < want {
            head.try_reserve_exact(want - have).map_err(|_| allocation())?;
            head.resize(want, 0);
            read_volume(file, &mut head[have..], have as u64)
                .map_err(|e| read_failure(e, Some(path.to_path_buf()), RarIntegrityReason::TruncatedHeader))?;
        }
        let (next, format) = signature_location(&head).map_err(signature_fault)?;
        Ok((head, next, format))
    }

    #[allow(clippy::too_many_arguments)] // Shared post-recognition initialization.
    fn initialize_held(
        path: &Path,
        file: File,
        len: u64,
        password: Option<&str>,
        (head, next, format): (Vec<u8>, u64, RarFormat),
        detailed: bool,
        budget: Option<&mut ScanBudget<'_>>,
        damaged: DamagedInput,
    ) -> RarResult<Volume> {
        let mut vol = Volume {
            path: path.to_path_buf(),
            src: Source::new(file, len, head),
            next,
            len,
            main: MainHeader::default(),
            password: password.filter(|s| !s.is_empty()).map(str::to_owned),
            header_key: None,
            legacy_keys: None,
            parser: None,
            format,
            end_record: None,
            damaged_input: damaged,
            damage: Vec::new(),
            damage_closed: false,
            held_block: None,
            resync_work: None,
            cancel: None,
            sfx: next.saturating_sub(match format {
                RarFormat::Rar5 => SIGNATURE.len(),
                RarFormat::Rar4 => SIGNATURE_V4.len(),
            } as u64),
        };
        match vol.next_block_impl(detailed, budget, true)? {
            Some((Block::Main(m), _, _)) => vol.main = m,
            Some((Block::Crypt, _, _)) => return Err(vol.password_required()),
            // Salvage: no readable main header. A RAR 4.x set reads on with an empty one (UnRAR lists such an
            // archive as "RAR 1.5" with nothing in it); a block a resync found is handed out first.
            other if damaged.salvages() && !vol.damage.is_empty() => {
                if vol.format == RarFormat::Rar4 {
                    vol.main.rar4_flags = Some(0);
                }
                vol.held_block = other;
            }
            _ => {
                return Err(vol.header_fault(
                    RarIntegrityReason::HeaderFraming("main archive header missing"),
                    Error::Corrupt("main archive header missing"),
                    true,
                ));
            }
        }
        Ok(vol)
    }

    /// The catalogue's search of the rest of the signature window, past the `first` bytes it read.
    fn probe_signature(
        path: &Path,
        file: &File,
        len: u64,
        (first, used): ([u8; SIGNATURE.len()], usize),
        budget: &mut ScanBudget<'_>,
    ) -> RarResult<(u64, RarFormat)> {
        let len = len.min(SIGNATURE_PROBE_BYTES) as usize;
        budget.check_read(len - used)?;
        let mut head = header_buffer(len)?;
        head[..used].copy_from_slice(&first[..used]);
        budget.read(file, path, &mut head[used..], used as u64)?;
        signature_location(&head).map_err(signature_fault)
    }

    /// The next block, or None at the physical end of the volume.
    pub fn next_block(&mut self) -> Result<Option<Block>> {
        self.next_block_impl(false, None, false)
            .map(|result| result.map(|(block, _, _)| block))
            .map_err(RarFault::into_legacy)
    }

    pub(crate) fn next_block_detailed(&mut self) -> RarResult<Option<(Block, MemberCrypt)>> {
        self.next_block_impl(true, None, false).map(|result| result.map(|(block, crypt, _)| (block, crypt)))
    }

    pub(super) fn next_catalogue(&mut self, budget: &mut ScanBudget<'_>) -> RarResult<Option<ParsedBlock>> {
        self.next_block_impl(true, Some(budget), false)
    }

    pub fn format(&self) -> RarFormat {
        self.format
    }

    /// Whether the headers are encrypted (`-hp`). RAR 5.0 knows it from its encryption header; a RAR 4.x main header
    /// stays in the clear and says so with `MHD_PASSWORD`, before any header has been decrypted.
    pub(super) fn encrypted_headers(&self) -> bool {
        self.header_key.is_some()
            || self.legacy_keys.is_some()
            || self.main.rar4_flags.is_some_and(|flags| flags & super::MHD_PASSWORD != 0)
    }

    pub(super) fn end_record(&self) -> Option<super::RarEndRecord> {
        self.end_record
    }

    pub(super) fn sfx_size(&self) -> u64 {
        self.sfx
    }

    pub(super) fn into_catalogue_file(self) -> File {
        self.src.file
    }

    fn scope(&self) -> RarScope {
        RarScope::Header { volume: self.path.clone() }
    }

    fn password_required(&self) -> RarFault {
        RarFault::new(RarFailure::PasswordRequired { scope: self.scope() }, Error::Encrypted)
    }

    fn header_fault(&self, reason: RarIntegrityReason, legacy: Error, plaintext_dependent: bool) -> RarFault {
        let password = match (&self.header_key, &self.legacy_keys) {
            (Some(keys), _) => keys.evidence,
            (None, Some(_)) => RarPasswordEvidence::VerifierUnavailable(crate::error::RarVerifierUnavailable::Absent),
            (None, None) => RarPasswordEvidence::NotEncrypted,
        };
        RarFault::new(RarFailure::integrity(self.scope(), reason, password, plaintext_dependent), legacy)
    }

    fn framing(&self, reason: &'static str, legacy: Error) -> RarFault {
        self.header_fault(RarIntegrityReason::HeaderFraming(reason), legacy, true)
    }

    /// Headers read past since this was last called ([`crate::extract::Options::damaged_input`]).
    pub fn take_damage(&mut self) -> Vec<HeaderDamage> {
        std::mem::take(&mut self.damage)
    }

    fn record_damage(&mut self, offset: u64, kind: HeaderDamageKind, name: Option<&str>, resumed_at: Option<u64>) {
        self.record_damage_of(offset, kind, name, resumed_at, kind != HeaderDamageKind::ChecksumMismatch);
    }

    fn record_damage_of(
        &mut self,
        offset: u64,
        kind: HeaderDamageKind,
        name: Option<&str>,
        resumed_at: Option<u64>,
        passed_over: bool,
    ) {
        if self.damage.len() >= crate::extract::MAX_HEADER_DAMAGE {
            return;
        }
        // a damaged header's name is kept for the message only: a copy of at most 1 KiB of it
        let name = name.map(|name| {
            let mut end = name.len().min(MAX_DAMAGE_NAME);
            while !name.is_char_boundary(end) {
                end -= 1;
            }
            name[..end].to_owned()
        });
        {
            self.damage.push(HeaderDamage { volume: self.path.clone(), offset, kind, name, resumed_at, passed_over });
        }
    }

    /// Whether a failure reading a header is damage [`DamagedInput::Salvage`] reads past: a header that fails its
    /// checksum, doesn't frame or parse, or runs (or whose data runs) past the end of the volume. Never with
    /// encrypted headers, where a failed checksum is how a wrong password shows.
    fn salvageable(&self, fault: &RarFault) -> Option<HeaderDamageKind> {
        if !self.damaged_input.salvages() || self.encrypted_headers() {
            return None;
        }
        match fault.failure.as_ref() {
            RarFailure::Integrity { scope: RarScope::Header { .. }, reason, .. } => match reason {
                RarIntegrityReason::TruncatedHeader | RarIntegrityReason::TruncatedData => {
                    Some(HeaderDamageKind::UnexpectedEnd)
                }
                RarIntegrityReason::HeaderCrc | RarIntegrityReason::HeaderFraming(_) => {
                    Some(HeaderDamageKind::Unreadable)
                }
                _ => None,
            },
            _ => None,
        }
    }

    fn next_block_impl(
        &mut self,
        detailed: bool,
        mut budget: Option<&mut ScanBudget<'_>>,
        catalogue_main: bool,
    ) -> RarResult<Option<ParsedBlock>> {
        if let Some(block) = self.held_block.take() {
            return Ok(Some(block));
        }
        loop {
            match self.next_block_raw(detailed, budget.as_deref_mut(), catalogue_main) {
                Ok(Some((Block::Main(_), ..))) if !catalogue_main && self.damaged_input.salvages() => {
                    // only a resync lands on a second main header: there is nothing in it to read
                    continue;
                }
                Ok(None) => {
                    if self.damaged_input.salvages()
                        && !self.damage_closed
                        && self.format == RarFormat::Rar5
                        && self.end_record.is_none()
                        && !self.encrypted_headers()
                    {
                        // 7-Zip 26.06: "Unexpected end of archive" for a RAR 5.0 volume without its end header
                        self.damage_closed = true;
                        self.record_damage(self.len, HeaderDamageKind::UnexpectedEnd, None, None);
                    }
                    return Ok(None);
                }
                Ok(block) => return Ok(block),
                Err(fault) => {
                    let Some(kind) = self.salvageable(&fault) else { return Err(fault) };
                    let at = self.parser.take().map_or(self.next, |parser| parser.header_offset());
                    let resumed = if self.damaged_input == DamagedInput::Resync {
                        self.resync(at.saturating_add(1), budget.as_deref_mut())?
                    } else {
                        None
                    };
                    self.record_damage(at, kind, None, resumed);
                    match resumed {
                        Some(next) => self.next = next,
                        None => {
                            self.next = self.len;
                            self.damage_closed = true;
                            return Ok(None);
                        }
                    }
                }
            }
        }
    }

    /// [`DamagedInput::Resync`]: the offset of the next header from `from` on that passes its checksum, found in one
    /// pass over the rest of the volume. Candidates are file, service and end headers (never a main header) of at
    /// most [`RESYNC_HEADER_MAX`] bytes. The checksum work of every resync in this volume together is bounded by
    /// [`RESYNC_WORK_PER_BYTE`] times the volume's length (plus 1 MiB), and each resync reads its window in chunks
    /// that start small, so the scan stays linear whatever the bytes are; past the bound it gives up.
    fn resync(&mut self, from: u64, mut budget: Option<&mut ScanBudget<'_>>) -> RarResult<Option<u64>> {
        let mut work =
            self.resync_work.unwrap_or_else(|| self.len.saturating_mul(RESYNC_WORK_PER_BYTE).saturating_add(1 << 20));
        let mut window = Vec::new();
        let mut header = Vec::new();
        let mut chunk = RESYNC_FIRST_CHUNK;
        let mut pos = from;
        let found = 'scan: loop {
            if pos >= self.len {
                break None;
            }
            let scan = (self.len - pos).min(chunk as u64) as usize;
            let want = (self.len - pos).min((scan + RESYNC_LOOKAHEAD) as u64) as usize;
            // the bytes read count as work too, so a run of resyncs close together stays linear
            let Some(left) = work.checked_sub(want as u64) else { break None };
            work = left;
            if !self.resync_read(&mut budget, &mut window, want, pos)? {
                break None;
            }
            for i in 0..scan {
                let Some(total) = resync_shape(&window[i..], self.format) else { continue };
                let at = pos + i as u64;
                if at.checked_add(total as u64).is_none_or(|end| end > self.len) {
                    continue;
                }
                let Some(left) = work.checked_sub(total as u64) else { break 'scan None };
                work = left;
                let checks = if let Some(h) = window.get(i..i + total) {
                    resync_checks(h, self.format)
                } else {
                    if !self.resync_read(&mut budget, &mut header, total, at)? {
                        break 'scan None;
                    }
                    resync_checks(&header, self.format)
                };
                if checks {
                    break 'scan Some(at);
                }
            }
            pos += scan as u64;
            chunk = chunk.saturating_mul(2).min(RESYNC_CHUNK);
        };
        self.resync_work = Some(work);
        Ok(found)
    }

    /// `len` bytes at `at` into `out`, for a resync; false when a catalogue's read budget has no room for them (the
    /// resync then gives up rather than fail the catalogue). Cancellation is checked before every read.
    fn resync_read(
        &mut self,
        budget: &mut Option<&mut ScanBudget<'_>>,
        out: &mut Vec<u8>,
        len: usize,
        at: u64,
    ) -> RarResult<bool> {
        if self.cancel.as_ref().is_some_and(crate::extract::Cancellation::is_canceled) {
            return Err(RarFault::new(RarFailure::Canceled, crate::extract::canceled_error()));
        }
        if let Some(budget) = budget.as_deref_mut() {
            budget.check()?;
            if budget.check_read(len).is_err() {
                return Ok(false);
            }
        }
        out.clear();
        out.try_reserve_exact(len).map_err(|_| allocation())?;
        out.resize(len, 0);
        match budget.as_deref_mut() {
            Some(budget) => budget.read(&self.src.file, &self.path, out, at)?,
            None => read_at_detailed(&self.src.file, out, at)
                .map_err(|e| read_failure(e, Some(self.path.clone()), RarIntegrityReason::TruncatedHeader))?,
        }
        Ok(true)
    }

    /// The run's cancellation, checked while a resync searches ([`DamagedInput::Resync`]).
    pub(crate) fn set_cancel(&mut self, cancel: Option<crate::extract::Cancellation>) {
        self.cancel = cancel;
    }

    fn next_block_raw(
        &mut self,
        detailed: bool,
        mut budget: Option<&mut ScanBudget<'_>>,
        catalogue_main: bool,
    ) -> RarResult<Option<ParsedBlock>> {
        use super::framing::{HeaderParser, ParserStep};
        let mut parser = self.parser.take().unwrap_or_else(|| {
            let mut parser = HeaderParser::new(self.path.clone(), self.next, Some(self.len), budget.is_some());
            parser.set_format(self.format);
            parser.set_salvage(self.damaged_input);
            parser
        });
        let result = (|| {
            loop {
                if self.next >= self.len {
                    return Ok(None);
                }
                if let Some(budget) = budget.as_deref_mut() {
                    budget.block()?;
                } else {
                    self.src.seek(self.next);
                }
                let (_, mut step) =
                    parser.advance_core_budget(&[], budget.as_deref()).map_err(super::framing::FramingError::legacy)?;
                let frame = loop {
                    match step {
                        ParserStep::LegacyKeyRequired { salt } => {
                            let pw = self.password.as_deref().ok_or_else(|| self.password_required())?;
                            if let Some(budget) = budget.as_deref_mut() {
                                budget.check()?;
                            }
                            let cancel = budget.as_deref().map(|budget| budget.cancel);
                            let (key, iv) =
                                match self.legacy_keys.get_or_insert_with(Default::default).keys(pw, &salt, cancel) {
                                    Ok(keys) => keys,
                                    Err(crate::crypto::KdfControlError::Canceled) => {
                                        return Err(RarFault::new(
                                            RarFailure::Canceled,
                                            std::io::Error::from(std::io::ErrorKind::Interrupted).into(),
                                        ));
                                    }
                                    Err(_) => return Err(self.framing("RAR4 header key", Error::Encrypted)),
                                };
                            parser.set_legacy_keys(&key, iv).map_err(|_| {
                                RarFault::new(
                                    RarFailure::Internal(RarInternal::Invariant("RAR4 header key out of turn")),
                                    Error::Encrypted,
                                )
                            })?;
                            step = parser
                                .advance_core_budget(&[], budget.as_deref())
                                .map_err(super::framing::FramingError::legacy)?
                                .1;
                        }
                        ParserStep::End => return Ok(None),
                        ParserStep::Frame(frame) => break frame,
                        ParserStep::Need { offset, len } => {
                            if let Some(budget) = &budget {
                                budget.check_read(len)?;
                            }
                            let mut bytes = header_buffer(len)?;
                            let mut at = offset;
                            self.read_header_exact(&mut budget, &mut at, &mut bytes)?;
                            let (used, next) = parser
                                .advance_core_budget(&bytes, budget.as_deref())
                                .map_err(super::framing::FramingError::legacy)?;
                            debug_assert_eq!(used, bytes.len());
                            step = next;
                        }
                    }
                };
                self.next = frame.data_end;
                if frame.damaged {
                    let name = match &frame.block {
                        Block::File(h) | Block::Service(h) => Some(h.name.as_str()),
                        _ => None,
                    };
                    let (offset, kind) = (frame.extent.start, HeaderDamageKind::ChecksumMismatch);
                    // A damaged header keeps the solid history only when its data, if any, is decoded into it in turn:
                    // it reads as a compressed file (not a folder, link or stored file). Read as anything else (a
                    // service, an unknown block, a folder, a main or end header that claims data) its data, which
                    // may be a member's compressed stream, is skipped unread.
                    let carries_data = frame.data_end > frame.extent.end;
                    let passed_over = match &frame.block {
                        Block::File(h) => carries_data && (h.method == 0 || h.is_dir() || h.redirection.is_some()),
                        Block::Main(_) | Block::End { .. } => carries_data,
                        _ => true,
                    };
                    self.record_damage_of(offset, kind, name, None, passed_over);
                }
                if matches!(frame.block, Block::Crypt) {
                    if budget.is_some() && (!catalogue_main || self.header_key.is_some()) {
                        return Err(self.framing("unexpected RAR header encryption block", Error::Encrypted));
                    }
                    if !detailed && self.password.is_none() {
                        return Ok(Some((Block::Crypt, None, None)));
                    }
                    let crypt_fault = |e| RarFault::new(RarFailure::crypt(e, self.scope()), Error::Encrypted);
                    let params = frame.header_crypt.expect("encryption frame has its record").map_err(crypt_fault)?;
                    let pw = self.password.as_deref().ok_or_else(|| self.password_required())?;
                    if let Some(budget) = budget.as_deref_mut() {
                        budget.check()?;
                    }
                    let keys = crate::crypto::derive_rar5_keys(pw, params.kdf_count, &params.salt, params.check)
                        .map_err(crypt_fault)?;
                    parser.set_encryption(&keys);
                    self.header_key = Some(keys);
                    continue;
                }
                if matches!(frame.block, Block::End { .. }) {
                    self.next = self.len;
                    self.end_record = frame.end_record;
                }
                if self.format == RarFormat::Rar4 && matches!(frame.block, Block::Unknown) {
                    continue;
                }
                return Ok(Some((frame.block, frame.crypt, frame.wire)));
            }
        })();
        self.parser = Some(parser);
        result
    }

    /// The bytes from `at` on (no more than `len`) that the volume holds already from its last read: a caller that
    /// reads the range itself can take these and start past them.
    pub(crate) fn held_at(&self, at: u64, len: u64) -> &[u8] {
        let bytes = self.src.piece.bytes();
        match at.checked_sub(self.src.at).and_then(|skip| usize::try_from(skip).ok()) {
            Some(skip) if skip < bytes.len() => {
                let n = usize::try_from(len).unwrap_or(usize::MAX).min(bytes.len() - skip);
                &bytes[skip..skip + n]
            }
            _ => &[],
        }
    }

    /// The open volume, for reads by position.
    pub fn file(&self) -> &File {
        &self.src.file
    }

    /// Whether the data read next is taken as fast as it can come (stored data, only checked and copied), so that
    /// two threads read ahead, or is decoded, for which one keeps up. It counts from when the reading ahead next
    /// starts (the first piece after the volume opens or after a move), so files that alternate don't restart it.
    pub fn read_fast(&mut self, fast: bool) {
        self.src.readers = if fast { FAST_READERS } else { 1 };
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> u64 {
        self.len
    }

    fn read_header_exact(
        &mut self,
        budget: &mut Option<&mut ScanBudget<'_>>,
        at: &mut u64,
        mut out: &mut [u8],
    ) -> RarResult<()> {
        if let Some(budget) = budget {
            budget.read(&self.src.file, &self.path, out, *at)?;
            *at += out.len() as u64;
            return Ok(());
        }
        while !out.is_empty() {
            if !self.src.fill().map_err(|e| e.detailed(&self.path, RarIntegrityReason::TruncatedHeader))? {
                return Err(self.header_fault(RarIntegrityReason::TruncatedHeader, Error::Truncated, false));
            }
            let held = self.src.held();
            let n = held.len().min(out.len());
            out[..n].copy_from_slice(&held[..n]);
            self.src.consume(n);
            out = &mut out[n..];
        }
        Ok(())
    }

    /// `len` bytes at `at`, appended to `out`.
    pub fn read_data_into(&mut self, at: u64, len: u64, out: &mut Vec<u8>) -> Result<()> {
        if at.checked_add(len).is_none_or(|end| end > self.len) {
            return Err(Error::Truncated);
        }
        out.reserve(len as usize);
        self.read_data(at, len, |piece| {
            out.extend_from_slice(piece);
            Ok(())
        })
    }

    /// Reads `len` bytes of a data area starting at `at`, in pieces, calling `sink` on each.
    pub fn read_data(&mut self, at: u64, len: u64, mut sink: impl FnMut(&[u8]) -> Result<()>) -> Result<()> {
        self.read_data_shared(at, len, |piece, range| sink(&piece.bytes()[range]))
    }

    /// [`Self::read_data`], handing `sink` each stretch as a range of the piece it lies in, which it may keep.
    pub fn read_data_shared(
        &mut self,
        at: u64,
        len: u64,
        sink: impl FnMut(&Arc<Piece>, Range<usize>) -> Result<()>,
    ) -> Result<()> {
        self.read_data_detailed(at, len, sink).map_err(|e| match e {
            ReadDataError::Input(e) => e.into_legacy(),
            ReadDataError::Sink(e) => e,
        })
    }

    pub(crate) fn read_data_detailed<E>(
        &mut self,
        at: u64,
        len: u64,
        mut sink: impl FnMut(&Arc<Piece>, Range<usize>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), ReadDataError<E>> {
        let truncated = |this: &Self| {
            ReadDataError::Input(this.header_fault(RarIntegrityReason::TruncatedData, Error::Truncated, false))
        };
        if at.checked_add(len).is_none_or(|end| end > self.len) {
            return Err(truncated(self));
        }
        self.src.seek(at);
        let mut left = len;
        while left > 0 {
            if !self
                .src
                .fill()
                .map_err(|e| ReadDataError::Input(e.detailed(&self.path, RarIntegrityReason::TruncatedData)))?
            {
                return Err(truncated(self));
            }
            let (piece, off) = self.src.held_shared();
            let n = ((piece.bytes.len() - off) as u64).min(left) as usize;
            let result = sink(piece, off..off + n);
            self.src.consume(n);
            result.map_err(ReadDataError::Sink)?;
            left -= n as u64;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn volume_metadata_retains_the_original_io_error() {
        let path = Path::new("volume");
        let fault = volume_length(path, || Err(std::io::Error::from_raw_os_error(libc::EACCES))).unwrap_err();
        assert!(matches!(fault.failure.as_ref(), RarFailure::Input {
            operation: IoOperation::Metadata, path: Some(actual), source, ..
        } if actual == path && source.raw_os_error() == Some(libc::EACCES)));
        assert!(matches!(fault.into_legacy(), Error::Io(e) if e.raw_os_error() == Some(libc::EACCES)));
    }

    #[test]
    fn transport_eof_keeps_its_original_cause_and_never_calls_the_sink() {
        #[derive(Debug)]
        struct Transport;
        impl std::fmt::Display for Transport {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("transport sentinel")
            }
        }
        impl std::error::Error for Transport {}

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("volume");
        std::fs::write(&path, b"data").unwrap();
        let file = File::open(&path).unwrap();
        let mut volume = Volume {
            path: path.clone(),
            src: Source::new(file, 1, Vec::new()),
            next: 0,
            len: 1,
            main: MainHeader::default(),
            password: None,
            header_key: None,
            legacy_keys: None,
            parser: None,
            format: RarFormat::Rar5,
            sfx: 0,
            end_record: None,
            damaged_input: DamagedInput::Refuse,
            damage: Vec::new(),
            damage_closed: false,
            held_block: None,
            resync_work: None,
            cancel: None,
        };
        let (send, recv) = sync_channel(1);
        let (spare, _) = channel();
        volume.src.ahead = Some(Ahead { pieces: vec![recv], turn: 0, spare, next: 0 });
        send.send(Err(PositionReadError::Io {
            offset: 0,
            source: std::io::Error::new(std::io::ErrorKind::UnexpectedEof, Transport),
        }))
        .unwrap();
        let result = volume.read_data_detailed::<()>(0, 1, |_, _| panic!("sink called after input failure"));
        let Err(ReadDataError::Input(fault)) = result else { panic!("expected input failure") };
        assert!(matches!(fault.failure.as_ref(), RarFailure::Input {
            operation: IoOperation::Read, path: Some(actual), offset: Some(0), ..
        } if actual == &path));
        use std::error::Error as _;
        let source = fault.failure.source().unwrap().downcast_ref::<std::io::Error>().unwrap();
        assert!(source.get_ref().unwrap().is::<Transport>());
        assert!(matches!(fault.into_legacy(), Error::Truncated));
    }

    #[cfg(unix)]
    #[test]
    fn data_read_distinguishes_synthetic_eof_from_sink_failure() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("piece");
        std::fs::write(&path, b"one byte").unwrap();
        let mut volume = Volume {
            path: path.clone(),
            src: Source::new(File::open(&path).unwrap(), 1, Vec::new()),
            next: 0,
            len: 1,
            main: MainHeader::default(),
            password: None,
            header_key: None,
            legacy_keys: None,
            parser: None,
            format: RarFormat::Rar5,
            sfx: 0,
            end_record: None,
            damaged_input: DamagedInput::Refuse,
            damage: Vec::new(),
            damage_closed: false,
            held_block: None,
            resync_work: None,
            cancel: None,
        };
        let Err(ReadDataError::Input(fault)) = volume.read_data_detailed::<()>(0, 2, |_, _| panic!("out of bounds"))
        else {
            panic!("expected structural failure")
        };
        assert!(matches!(
            fault.failure.as_ref(),
            RarFailure::Integrity { reason: RarIntegrityReason::TruncatedData, .. }
        ));
        assert!(std::error::Error::source(fault.failure.as_ref()).is_none());
        let sink_error = std::io::Error::from_raw_os_error(libc::ENOSPC);
        let Err(ReadDataError::Sink(e)) =
            volume.read_data_detailed(0, 1, |_, _| Err(std::io::Error::from_raw_os_error(libc::ENOSPC)))
        else {
            panic!("expected sink failure")
        };
        assert_eq!(e.raw_os_error(), sink_error.raw_os_error());
    }

    #[test]
    fn pieces_read_ahead_on_several_threads_come_in_order() {
        let dir = std::env::temp_dir().join(format!("zipfast-reader-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("data");
        let data: Vec<u8> =
            (0..(7 * READ + 12_345) as u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
        std::fs::write(&path, &data).unwrap();
        for readers in [1, 2, 3] {
            // from the start, from just past it (read on through), and from a far place (started again there)
            for start in [0, 13, 5 * READ + 77] {
                let mut src = Source::new(File::open(&path).unwrap(), data.len() as u64, Vec::new());
                src.readers = readers;
                src.seek(start as u64);
                let mut got = Vec::new();
                let mut moved = false;
                while src.fill().unwrap() {
                    let n = src.held().len().min(300_007);
                    got.extend_from_slice(&src.held()[..n]);
                    src.consume(n);
                    // a move back, from well into the reading ahead, starts it again
                    if start == 0 && !moved && got.len() > 3 * READ {
                        moved = true;
                        src.seek(0);
                        got.clear();
                    }
                }
                assert!(start != 0 || moved);
                assert!(got == data[start..], "{readers} readers from {start}");
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
