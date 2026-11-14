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

pub enum Block {
    Main(MainHeader),
    File(FileHeader),
    Service(FileHeader),
    End {
        more_volumes: bool,
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
        let read = read_at_detailed(file, &mut buf, at).map(|()| buf);
        let failed = read.is_err();
        if send.send(read).is_err() || failed {
            return;
        }
        at += (readers * READ) as u64;
    }
}

impl Source {
    fn new(file: File, len: u64) -> Source {
        Source {
            file,
            len,
            piece: Piece::new(Vec::new(), None),
            at: 0,
            off: 0,
            sequential: false,
            ahead: None,
            readers: 1,
        }
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
                    read_at_detailed(&self.file, &mut buf, from).map_err(SourceError::Read)?;
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
    parser: Option<super::framing::HeaderParser>,
    format: RarFormat,
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

#[cfg(all(test, unix))]
thread_local! {
    pub(crate) static VOLUME_OPENS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Recognition and its initial held data handle cannot become separated.
pub(crate) struct HeldSignature {
    file: File,
    len: u64,
    next: u64,
    format: RarFormat,
}
impl HeldSignature {
    pub(crate) fn recognize(file: File, len: u64, head: &[u8]) -> std::result::Result<Self, File> {
        match signature_location(head) {
            Ok((next, format)) => Ok(Self { file, len, next, format }),
            Err(_) => Err(file),
        }
    }
}
impl Volume {
    pub(crate) fn from_held_signature(path: &Path, signature: HeldSignature, password: Option<&str>) -> Result<Self> {
        let HeldSignature { file, len, next, format } = signature;
        Self::initialize_held(path, file, len, password, next, format, false, None).map_err(RarFault::into_legacy)
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    pub(crate) fn from_held_signature_detailed(
        path: &Path,
        signature: HeldSignature,
        password: Option<&str>,
    ) -> RarResult<Self> {
        let HeldSignature { file, len, next, format } = signature;
        Self::initialize_held(path, file, len, password, next, format, true, None)
    }
    pub fn open(path: &Path) -> Result<Volume> {
        Self::open_with_password(path, None)
    }

    pub fn open_with_password(path: &Path, password: Option<&str>) -> Result<Volume> {
        Self::open_impl(path, password, false).map_err(RarFault::into_legacy)
    }

    pub(crate) fn open_detailed(path: &Path, password: Option<&str>) -> RarResult<Volume> {
        Self::open_impl(path, password, true)
    }

    fn open_impl(path: &Path, password: Option<&str>, detailed: bool) -> RarResult<Volume> {
        let file =
            File::open(path).map_err(|e| RarFault::input(IoOperation::Open, Some(path.to_path_buf()), None, e))?;
        #[cfg(all(test, unix))]
        VOLUME_OPENS.set(VOLUME_OPENS.get() + 1);
        let len = volume_length(path, || file.metadata())?;
        Self::open_file(path, file, len, password, detailed, None)
    }

    pub(super) fn open_catalogue(
        path: &Path,
        file: File,
        len: u64,
        password: Option<&str>,
        budget: &mut ScanBudget<'_>,
    ) -> RarResult<Self> {
        Self::open_file(path, file, len, password, true, Some(budget))
    }

    fn open_file(
        path: &Path,
        file: File,
        len: u64,
        password: Option<&str>,
        detailed: bool,
        mut budget: Option<&mut ScanBudget<'_>>,
    ) -> RarResult<Volume> {
        let first = if let Some(budget) = budget.as_deref_mut() {
            let mut first = [0; SIGNATURE.len()];
            let used = len.min(SIGNATURE.len() as u64) as usize;
            budget.read(&file, path, &mut first[..used], 0)?;
            Some((first, used))
        } else {
            None
        };
        let (next, format) = if let Some((first, _)) = first
            && first == *SIGNATURE
        {
            (SIGNATURE.len() as u64, RarFormat::Rar5)
        } else if let Some((first, _)) = first
            && first.starts_with(SIGNATURE_V4)
        {
            (SIGNATURE_V4.len() as u64, RarFormat::Rar4)
        } else {
            Self::probe_signature(path, &file, len, first, budget.as_deref_mut())?
        };
        Self::initialize_held(path, file, len, password, next, format, detailed, budget)
    }
    #[allow(clippy::too_many_arguments)] // Shared post-recognition legacy initialization.
    fn initialize_held(
        path: &Path,
        file: File,
        len: u64,
        password: Option<&str>,
        next: u64,
        format: RarFormat,
        detailed: bool,
        budget: Option<&mut ScanBudget<'_>>,
    ) -> RarResult<Volume> {
        let mut vol = Volume {
            path: path.to_path_buf(),
            src: Source::new(file, len),
            next,
            len,
            main: MainHeader::default(),
            password: password.filter(|s| !s.is_empty()).map(str::to_owned),
            header_key: None,
            parser: None,
            format,
        };
        match vol.next_block_impl(detailed, budget, true)? {
            Some((Block::Main(m), _, _)) => vol.main = m,
            Some((Block::Crypt, _, _)) => return Err(vol.password_required()),
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

    fn probe_signature(
        path: &Path,
        file: &File,
        len: u64,
        first: Option<([u8; SIGNATURE.len()], usize)>,
        budget: Option<&mut ScanBudget<'_>>,
    ) -> RarResult<(u64, RarFormat)> {
        let len = len.min(SIGNATURE_PROBE_BYTES) as usize;
        if let (Some(budget), Some((_, used))) = (&budget, first) {
            budget.check_read(len - used)?;
        }
        let mut head = header_buffer(len)?;
        if let Some(budget) = budget {
            let (first, used) = first.expect("catalogue probe reads the signature prefix");
            head[..used].copy_from_slice(&first[..used]);
            budget.read(file, path, &mut head[used..], used as u64)?;
        } else {
            read_at_detailed(file, &mut head, 0)
                .map_err(|e| read_failure(e, Some(path.to_path_buf()), RarIntegrityReason::TruncatedHeader))?;
        }
        signature_location(&head).map_err(|e| {
            let failure = match e {
                Error::NotAnArchive => RarFailure::NotRar,
                _ => RarFailure::Unsupported(RarUnsupported::ArchiveVersion(4)),
            };
            RarFault::new(failure, e)
        })
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

    pub(super) fn encrypted_headers(&self) -> bool {
        self.header_key.is_some()
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
        let password = self.header_key.as_ref().map_or(RarPasswordEvidence::NotEncrypted, |keys| keys.evidence);
        RarFault::new(RarFailure::integrity(self.scope(), reason, password, plaintext_dependent), legacy)
    }

    fn framing(&self, reason: &'static str, legacy: Error) -> RarFault {
        self.header_fault(RarIntegrityReason::HeaderFraming(reason), legacy, true)
    }

    fn next_block_impl(
        &mut self,
        detailed: bool,
        mut budget: Option<&mut ScanBudget<'_>>,
        catalogue_main: bool,
    ) -> RarResult<Option<ParsedBlock>> {
        use super::framing::{HeaderParser, ParserStep};
        let mut parser = self.parser.take().unwrap_or_else(|| {
            let mut parser = HeaderParser::new(self.path.clone(), self.next, Some(self.len), budget.is_some());
            parser.set_format(self.format);
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
                        ParserStep::LegacyKeyRequired { .. } => {
                            return Err(RarFault::new(
                                RarFailure::Unsupported(crate::error::RarUnsupported::Rar4Feature("encrypted headers")),
                                Error::Encrypted,
                            ));
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

    /// The open volume, for reads by position.
    pub fn file(&mut self) -> &File {
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
            src: Source::new(file, 1),
            next: 0,
            len: 1,
            main: MainHeader::default(),
            password: None,
            header_key: None,
            parser: None,
            format: RarFormat::Rar5,
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
            src: Source::new(File::open(&path).unwrap(), 1),
            next: 0,
            len: 1,
            main: MainHeader::default(),
            password: None,
            header_key: None,
            parser: None,
            format: RarFormat::Rar5,
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
                let mut src = Source::new(File::open(&path).unwrap(), data.len() as u64);
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
