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

//! An LZMA2 stream decoded on several threads, one block per thread.
//!
//! 7-Zip with `-mmt` writes LZMA2 as independent blocks: each starts with a chunk that resets the dictionary
//! (control `0x01`, or `0xE0` and up), and a dictionary reset also forces new properties on the next LZMA chunk, so a
//! block decodes on its own exactly as it decodes inside the stream. [`Lzma2Blocks`] reads the packed stream on the
//! caller's thread and walks its chunk headers. Each dictionary reset at least [`MIN_PIECE`] decoded bytes after the
//! last cut starts a new piece. The caller's thread decodes the piece at the head of the stream itself, straight into
//! the caller's buffer, as the one-thread reader does; the pieces after it go to worker threads, which decode them as
//! their packed bytes arrive and hand back their output in segments. The caller's reads take the output in stream
//! order, so it is the one-thread output byte for byte. When the head piece is done the next one is handed out from
//! its worker, or decoded on the caller's thread if no worker has taken it yet.
//!
//! Every stream starts on the one-thread decoder ([`Single`]), with a walker that follows the chunk headers in each
//! block it reads (a few operations per chunk, no copies). The pipeline takes over at a chunk boundary only once it
//! can pay: at a second piece (a dictionary reset at least [`MIN_PIECE`] on), or once more than [`MIN_PIECE`] of
//! output has gone by and less than nine tenths of it came from stored chunks (LZMA decoding is slow enough that
//! reading ahead for the next piece is worth it), and never while the output so far is more than [`MAX_RATIO`] times
//! its packed bytes (such data decodes near memory speed on one thread, and the handoff costs more than it gains).
//! A stream of stored chunks in one piece, as one-thread 7-Zip writes
//! for data it cannot compress, never leaves the one-thread decoder and runs at its speed; worker threads start only
//! with a second piece. In the pipeline, packed bytes are read in blocks that are moved, not copied, to the decoder
//! that needs them.
//!
//! Memory is bounded. At most two pieces per worker are in the pipeline. The packed bytes waiting for decoders and
//! the decoded bytes waiting for the caller together stay within the budget
//! ([`super::SevenZipLimits::lzma2_parallel_bytes`]): a worker waits while it is spent (the head's only once the
//! caller has [`HEAD_SEGMENTS`] of its segments queued, so the caller always has output to take and the run moves),
//! and reading ahead stops, except for the head piece's next [`HEAD_INPUT`] bytes, which the run cannot move without.
//! Reading ahead also stops once the packed bytes waiting in the piece being read pass the larger of [`LOOKAHEAD`]
//! and the output handed out so far (at most the budget), or [`STORED_LOOKAHEAD`] in a piece of stored
//! chunks (which cost a copy to decode, so finding the next piece early gains little), so a one-block stream holds
//! little more than the one-thread reader does.
//!
//! A piece that fails gives the output it decoded before the failure and then the failure, in order, so the failure
//! lands on the member it lands on in one-thread decoding. Workers check the [`Cancellation`] every [`SEGMENT`] bytes
//! of output and while they wait, and dropping the reader stops and joins them.
use std::cell::Cell;
use std::collections::VecDeque;
use std::io::{self, Read};
use std::rc::Rc;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use super::coders::{Fault, data_error};
use crate::extract::Cancellation;

/// Dictionary resets closer together than this many decoded bytes are joined into one piece.
pub(crate) const MIN_PIECE: u64 = 1 << 20;
/// Decoded bytes a worker hands out at a time; it checks the cancellation between them.
const SEGMENT: usize = 1 << 20;
/// Dictionary bytes freed by finished pieces between two trims of glibc's arenas (see [`release_freed_memory`]).
const TRIM_EVERY: u64 = 4 << 20;
/// Streams whose output so far is more than this many times their packed bytes stay on one thread: they decode at
/// close to memory speed there, and passing blocks between threads costs more than it gains.
const MAX_RATIO: u64 = 64;
/// Packed bytes the head piece's decoder may have waiting that are read whatever the budget.
const HEAD_INPUT: u64 = 256 << 10;
/// Segments of the head's output the reader may have queued before its worker waits for the budget too.
const HEAD_SEGMENTS: usize = 2;
/// Spent packed blocks kept for reading into again.
const SPARE: usize = 64;
/// Packed bytes read from the stream at a time.
const READ: usize = 64 << 10;
/// Packed bytes that may wait for decoders before any output is handed out (see the module documentation).
const LOOKAHEAD: u64 = 8 << 20;
/// The lookahead in a piece of stored chunks (nine tenths or more of its output so far).
const STORED_LOOKAHEAD: u64 = 256 << 10;
/// Packed bytes read ahead at most before the caller's thread looks at its own work again.
const BURST: u64 = 4 << 20;
/// The smallest budget for bytes in flight.
pub(crate) const MIN_MEMORY: u64 = 4 * MIN_PIECE;
/// How long a waiting thread waits before it looks at the cancellation again.
const POLL: Duration = Duration::from_millis(20);

type Stream = Box<dyn Read>;

/// LZMA2's dictionary size for property byte `b` (at most 40).
pub(crate) fn dict_size(b: u8) -> u64 {
    if b >= 40 { u64::from(u32::MAX) } else { (2 | u64::from(b & 1)) << (b / 2 + 11) }
}

/// The smallest property byte at or under `b` whose dictionary holds `need` bytes.
pub(crate) fn shrink(b: u8, need: u64) -> u8 {
    (0..=b).find(|&s| dict_size(s) >= need.max(4096)).unwrap_or(b)
}

/// A raw LZMA2 decoder with dictionary property `b`.
pub(crate) fn raw_decoder(b: u8) -> io::Result<liblzma::stream::Stream> {
    let mut filters = liblzma::stream::Filters::new();
    filters.lzma2_properties(&[b]).map_err(|_| data_error("7z LZMA2 properties"))?;
    liblzma::stream::Stream::new_raw_decoder(&filters).map_err(|e| match e {
        liblzma::stream::Error::Mem | liblzma::stream::Error::MemLimit => io::Error::from(io::ErrorKind::OutOfMemory),
        _ => data_error("7z LZMA2 properties"),
    })
}

/// What the scanner found at a chunk boundary.
enum Next {
    /// A whole chunk, of this decoded size.
    Chunk { unpacked: u64 },
    /// The stream ends: an end marker (left out), the packed stream's end at a chunk boundary, or the coder's declared
    /// output size reached (the rest left unread).
    End,
    /// The bytes read end in damage: a bad control byte (taken), a chunk cut short, or a failed read. Decoding them
    /// gives their output and then the error, unless the decoder fails first (as it does on a bad control byte).
    Broken(io::Error),
}

/// The packed stream, read in blocks and walked chunk header by chunk header. The bytes walked over are handed to
/// `run` (the piece they belong to) in runs: a whole block is moved, only a block a piece boundary splits is copied.
struct Scanner {
    input: Stream,
    block: Vec<u8>,
    /// where the walk is in `block`
    at: usize,
    /// where the run not yet handed over starts in `block`
    from: usize,
    /// decoded bytes the chunks walked declare
    unpacked: u64,
    /// packed bytes walked
    packed: u64,
    /// the coder's declared output size: no chunk is read once `unpacked` reaches it
    size: u64,
    /// nothing more is walked: an end, damage or an error was met
    done: bool,
    eof: bool,
    /// blocks the decoders are done with, to read into again
    spare: Vec<Vec<u8>>,
}

impl Scanner {
    fn new(input: Stream, size: u64) -> Self {
        Self {
            input,
            block: Vec::new(),
            at: 0,
            from: 0,
            unpacked: 0,
            packed: 0,
            size,
            done: false,
            eof: false,
            spare: Vec::new(),
        }
    }

    /// Hands the bytes walked since the last run to `run`.
    fn flush(&mut self, run: &mut Vec<Vec<u8>>) {
        if self.from < self.at {
            if self.from == 0 && self.at == self.block.len() {
                run.push(std::mem::take(&mut self.block));
                self.at = 0;
            } else {
                run.push(self.block[self.from..self.at].to_vec());
            }
        }
        self.from = self.at;
    }

    /// Makes a byte available at `at`; false at the packed stream's end. A used-up block goes to `run` first.
    fn fill(&mut self, run: &mut Vec<Vec<u8>>) -> io::Result<bool> {
        while self.at == self.block.len() {
            self.flush(run);
            if self.eof {
                return Ok(false);
            }
            // a block a decoder is done with, or the last one when it was copied out: no new allocation to fill
            let mut block = std::mem::take(&mut self.block);
            if block.capacity() < READ {
                block = self.spare.pop().unwrap_or_default();
            }
            block.resize(READ, 0);
            loop {
                match self.input.read(&mut block) {
                    Ok(n) => {
                        block.truncate(n);
                        self.eof = n == 0;
                        break;
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => {
                        block.clear();
                        self.block = block;
                        (self.at, self.from) = (0, 0);
                        return Err(e);
                    }
                }
            }
            self.block = block;
            (self.at, self.from) = (0, 0);
        }
        Ok(true)
    }

    /// Walks over `n` bytes, copying the first of them into `header`; how many there were (fewer at the end).
    fn skip(&mut self, n: u64, header: &mut [u8], run: &mut Vec<Vec<u8>>) -> io::Result<u64> {
        let mut walked = 0u64;
        while walked < n && self.fill(run)? {
            let k = (n - walked).min((self.block.len() - self.at) as u64) as usize;
            let h = walked as usize;
            if h < header.len() {
                let m = (header.len() - h).min(k);
                header[h..h + m].copy_from_slice(&self.block[self.at..self.at + m]);
            }
            self.at += k;
            self.packed += k as u64;
            walked += k as u64;
        }
        Ok(walked)
    }

    /// The next chunk's control byte, made available without walking over it; None at the end. Errors end the walk.
    fn control(&mut self, run: &mut Vec<Vec<u8>>) -> Result<Option<u8>, io::Error> {
        if self.done || self.unpacked >= self.size {
            self.done = true;
            return Ok(None);
        }
        match self.fill(run) {
            Ok(true) => Ok(Some(self.block[self.at])),
            Ok(false) => {
                self.done = true;
                Ok(None)
            }
            Err(e) => {
                self.done = true;
                Err(e)
            }
        }
    }

    /// Walks over the chunk whose control byte [`Self::control`] gave, handing its bytes to `run`.
    fn chunk(&mut self, control: u8, run: &mut Vec<Vec<u8>>) -> Next {
        let next = self.walk(control, run);
        if !matches!(next, Next::Chunk { .. }) {
            self.done = true;
        }
        next
    }

    fn walk(&mut self, control: u8, run: &mut Vec<Vec<u8>>) -> Next {
        let header = match control {
            0x00 => return Next::End,
            0x01 | 0x02 => 3,
            0x80..=0xBF => 5,
            0xC0..=0xFF => 6,
            _ => {
                // The decoder fails on it, after everything before it.
                self.at += 1;
                self.packed += 1;
                return Next::Broken(data_error("LZMA data error"));
            }
        };
        let mut h = [0u8; 6];
        match self.skip(header, &mut h[..header as usize], run) {
            Err(e) => return Next::Broken(e),
            Ok(n) if n < header => return Next::Broken(Fault::Truncated.into()),
            Ok(_) => {}
        }
        let be16 = |i: usize| u64::from(u16::from_be_bytes([h[i], h[i + 1]]));
        let (payload, unpacked) = if control < 0x80 {
            let n = be16(1) + 1;
            (n, n)
        } else {
            (be16(3) + 1, ((u64::from(control & 0x1F) << 16) | be16(1)) + 1)
        };
        match self.skip(payload, &mut [], run) {
            Err(e) => return Next::Broken(e),
            Ok(n) if n < payload => return Next::Broken(Fault::Truncated.into()),
            Ok(_) => {}
        }
        self.unpacked += unpacked;
        Next::Chunk { unpacked }
    }
}

/// One piece's traffic between the reader and the thread decoding it.
#[derive(Default)]
struct Piece {
    /// packed bytes read for it, not yet taken by its decoder
    input: VecDeque<Vec<u8>>,
    /// bytes in `input`
    queued: u64,
    /// no more input comes: the piece is whole (its decoder closes it with an end marker) unless `tail` holds the
    /// error that follows its last bytes
    closed: bool,
    tail: Option<io::Error>,
    /// decoded bytes a worker made, not yet handed out
    output: VecDeque<Vec<u8>>,
    /// its worker is done; `fault` follows the output
    done: bool,
    fault: Option<io::Error>,
}

struct State {
    /// the pieces not yet handed out in full, in stream order: the first is the head
    pieces: VecDeque<Piece>,
    /// the head's number (pieces are numbered from 0 in stream order)
    head: u64,
    /// numbers of the pieces no thread has taken yet, in order
    jobs: VecDeque<u64>,
    /// packed bytes waiting for decoders and decoded bytes waiting for the reader
    held: u64,
    /// the most `held` has been, for the tests
    peak: u64,
    /// output buffers the workers hold, not yet handed out
    buffers: u64,
    /// the most `held` and `buffers` have been together, for the tests
    peak_total: u64,
    /// dictionary bytes freed since the arenas were last trimmed
    freed: u64,
    /// workers waiting for room in the budget
    budget_waiters: usize,
    /// packed blocks the decoders are done with, for the reader to read into again
    spare: Vec<Vec<u8>>,
    stop: bool,
}

impl State {
    fn piece(&mut self, number: u64) -> Option<&mut Piece> {
        let index = number.checked_sub(self.head)?;
        self.pieces.get_mut(usize::try_from(index).ok()?)
    }

    /// The next packed bytes for piece `number`: Some(bytes), or None when there are none yet. A closed piece with
    /// nothing left gives its end: an end marker, or nothing and its tail error.
    fn take(&mut self, number: u64) -> Option<Taken> {
        let piece = self.piece(number)?;
        if let Some(bytes) = piece.input.pop_front() {
            piece.queued -= bytes.capacity() as u64;
            self.held -= bytes.capacity() as u64;
            return Some(Taken::Bytes(bytes));
        }
        if piece.closed {
            return Some(Taken::End(piece.tail.take()));
        }
        None
    }

    /// Drops the head piece, once it is handed out; the bytes it never read leave the budget.
    fn pop(&mut self) -> Option<Piece> {
        let piece = self.pieces.pop_front()?;
        self.head += 1;
        self.held -= piece.queued;
        Some(piece)
    }
}

enum Taken {
    Bytes(Vec<u8>),
    /// the piece's input is over, with this error after it (None: a whole piece)
    End(Option<io::Error>),
}

struct Shared {
    state: Mutex<State>,
    /// idle workers wait here for a piece
    jobs: Condvar,
    /// busy workers wait here for packed bytes or for room in the budget
    work: Condvar,
    /// the reader waits here for output
    reader: Condvar,
    /// what `held` may reach before workers whose piece is not the head wait
    memory: u64,
    dict: u8,
    cancel: Cancellation,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Waits on `on` for a change, or a while (cancellation has no wake-up of its own).
    fn wait<'a>(&self, on: &Condvar, state: MutexGuard<'a, State>) -> MutexGuard<'a, State> {
        on.wait_timeout(state, POLL).unwrap_or_else(PoisonError::into_inner).0
    }

    /// Budget was freed: wakes the workers waiting for it (`waiters` of them) and the reader.
    fn freed(&self, waiters: usize) {
        if waiters > 0 {
            self.work.notify_all();
        }
        self.reader.notify_one();
    }

    fn halted(&self, state: &State) -> bool {
        state.stop || self.cancel.is_canceled()
    }
}

/// A piece's decoder and where it is in the piece's input.
struct Decoder {
    number: u64,
    stream: liblzma::stream::Stream,
    input: Vec<u8>,
    at: usize,
    /// all input is taken: for a whole piece the end marker is in `input`
    ended: bool,
    /// the error that follows the input
    tail: Option<io::Error>,
    /// the piece decoded to its end
    finished: bool,
}

/// What one step of a [`Decoder`] gave.
enum Step {
    /// `n` bytes of output (maybe 0), more to come
    Made(usize),
    /// the piece ended after `n` more bytes; the fault that follows them
    Ended(usize, Option<io::Error>),
    /// the decoder needs more input
    Hungry,
}

impl Decoder {
    fn new(number: u64, dict: u8) -> io::Result<Self> {
        Ok(Self {
            number,
            stream: raw_decoder(dict)?,
            input: Vec::new(),
            at: 0,
            ended: false,
            tail: None,
            finished: false,
        })
    }

    fn hungry(&self) -> bool {
        self.at == self.input.len() && !self.ended
    }

    /// Takes the next input; the block it is done with goes back to `spare`.
    fn feed(&mut self, taken: Taken, spare: &mut Vec<Vec<u8>>) {
        let spent = std::mem::take(&mut self.input);
        if spent.capacity() == READ && spare.len() < SPARE {
            spare.push(spent);
        }
        self.at = 0;
        match taken {
            Taken::Bytes(bytes) => self.input = bytes,
            Taken::End(tail) => {
                self.ended = true;
                self.input = if tail.is_none() { vec![0] } else { Vec::new() };
                self.tail = tail;
            }
        }
    }

    /// Decodes into `out` (which has room).
    fn step(&mut self, out: &mut [u8]) -> Step {
        if self.finished {
            return Step::Ended(0, None);
        }
        if self.hungry() {
            return Step::Hungry;
        }
        let action =
            if self.at == self.input.len() { liblzma::stream::Action::Finish } else { liblzma::stream::Action::Run };
        let (i0, o0) = (self.stream.total_in(), self.stream.total_out());
        let status = self.stream.process(&self.input[self.at..], out, action);
        let used = (self.stream.total_in() - i0) as usize;
        let made = (self.stream.total_out() - o0) as usize;
        self.at += used;
        let fault = match status {
            Err(liblzma::stream::Error::Mem | liblzma::stream::Error::MemLimit) => {
                io::Error::from(io::ErrorKind::OutOfMemory)
            }
            Err(_) => data_error("LZMA data error"),
            Ok(liblzma::stream::Status::StreamEnd) => {
                self.finished = true;
                return Step::Ended(made, None);
            }
            Ok(_) if self.ended && self.at == self.input.len() && used == 0 && made == 0 => {
                self.tail.take().unwrap_or_else(|| Fault::Truncated.into())
            }
            Ok(_) => return Step::Made(made),
        };
        self.finished = true;
        Step::Ended(made, Some(fault))
    }
}

fn work(shared: &Shared) {
    loop {
        let number = {
            let mut state = shared.lock();
            loop {
                if state.stop {
                    return;
                }
                if let Some(number) = state.jobs.pop_front() {
                    break number;
                }
                state = shared.wait(&shared.jobs, state);
            }
        };
        let fault = match Decoder::new(number, shared.dict) {
            Ok(decoder) => decode(shared, decoder),
            Err(e) => Some(e),
        };
        // The piece's decoder, and its dictionary, are freed by now.
        let mut state = shared.lock();
        if let Some(piece) = state.piece(number) {
            piece.done = true;
            piece.fault = fault;
        }
        state.freed += dict_size(shared.dict);
        let trim = state.freed >= TRIM_EVERY;
        if trim {
            state.freed = 0;
        }
        drop(state);
        shared.reader.notify_one();
        if trim {
            release_freed_memory();
        }
    }
}

/// Every piece's decoder allocates its dictionary afresh (liblzma has no way to reuse one), and glibc keeps freed
/// blocks of that size in the freeing thread's arena instead of handing them back, so with many workers the
/// process's resident memory grows past what is live. Asking glibc to trim its arenas every [`TRIM_EVERY`] bytes of
/// dictionaries freed hands that memory back.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn release_freed_memory() {
    // SAFETY: malloc_trim has no preconditions; it only returns free memory in glibc's arenas to the system and
    // never touches a live allocation.
    unsafe {
        libc::malloc_trim(0);
    }
}

/// Other allocators hand large blocks back themselves.
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn release_freed_memory() {}

/// Hands `out` to the reader; false once the reader is gone or the run is canceled. A worker waits while the budget
/// is spent, except the head's while the reader has fewer than [`HEAD_SEGMENTS`] of its segments queued: the reader
/// is waiting for those, so the run always moves, and a reader that stops reading (writing a member, a slow print
/// sink) stops the head as well, so nothing grows past the budget and those few segments.
fn hand_out(shared: &Shared, number: u64, out: Vec<u8>) -> bool {
    let mut state = shared.lock();
    // charged by what it holds, not by what it fills
    let len = out.capacity() as u64;
    loop {
        // `out` is the worker's buffer: it stays counted in `buffers` until it is handed out or dropped
        if shared.halted(&state) {
            state.buffers -= SEGMENT as u64;
            return false;
        }
        if out.is_empty() {
            state.buffers -= SEGMENT as u64;
            return true;
        }
        let head = number == state.head;
        let queued = state.piece(number).map_or(0, |p| p.output.len());
        if (head && queued < HEAD_SEGMENTS) || state.held + len <= shared.memory {
            break;
        }
        state.budget_waiters += 1;
        state = shared.wait(&shared.work, state);
        state.budget_waiters -= 1;
    }
    state.held += len;
    state.buffers -= SEGMENT as u64;
    state.peak = state.peak.max(state.held);
    state.peak_total = state.peak_total.max(state.held + state.buffers);
    if let Some(piece) = state.piece(number) {
        piece.output.push_back(out);
    }
    shared.reader.notify_one();
    true
}

/// Decodes a piece on a worker as its packed bytes arrive; the fault that follows its output.
fn decode(shared: &Shared, mut decoder: Decoder) -> Option<io::Error> {
    // The worker's one output buffer, made only when there is output to make: a worker holds at most one, counted
    // in its cost when the workers are chosen ([`plan`]), and gives it up as it hands it out.
    let mut out: Vec<u8> = Vec::new();
    let mut made = 0usize;
    loop {
        if out.is_empty() {
            let mut state = shared.lock();
            state.buffers += SEGMENT as u64;
            state.peak_total = state.peak_total.max(state.held + state.buffers);
            drop(state);
            out = vec![0u8; SEGMENT];
            made = 0;
        }
        if made == out.len() {
            if !hand_out(shared, decoder.number, std::mem::take(&mut out)) {
                return Some(Fault::Canceled.into());
            }
            continue;
        }
        match decoder.step(&mut out[made..]) {
            Step::Made(n) => made += n,
            Step::Ended(n, fault) => {
                // A short last segment goes out in a buffer of its own size, so a block just past a multiple of
                // the segment does not leave a near-empty segment-sized buffer queued.
                let last = if made + n == out.len() { out } else { out[..made + n].to_vec() };
                if !hand_out(shared, decoder.number, last) {
                    return Some(Fault::Canceled.into());
                }
                return fault;
            }
            Step::Hungry => {
                let mut state = shared.lock();
                let taken = loop {
                    if shared.halted(&state) {
                        state.buffers -= SEGMENT as u64;
                        return Some(Fault::Canceled.into());
                    }
                    match state.take(decoder.number) {
                        Some(taken) => break taken,
                        // the reader dropped the piece: it failed before
                        None if state.piece(decoder.number).is_none() => {
                            state.buffers -= SEGMENT as u64;
                            return Some(Fault::Canceled.into());
                        }
                        None => state = shared.wait(&shared.work, state),
                    }
                };
                decoder.feed(taken, &mut state.spare);
                let waiters = state.budget_waiters;
                drop(state);
                shared.freed(waiters);
            }
        }
    }
}

enum Mode {
    /// The one-thread decoder, walking the chunk headers as it reads (see [`Single`]).
    Single(Box<Single>),
    Parallel(Box<Parallel>),
    /// Taken while switching.
    Gone,
}

/// The piece being read.
#[derive(Clone, Copy)]
struct Feeding {
    number: u64,
    /// decoded bytes its chunks declare so far
    decoded: u64,
    /// those of them in stored chunks
    stored: u64,
}

/// The reader's side of the pipeline.
struct Parallel {
    shared: Arc<Shared>,
    /// the workers, started when the second piece is
    threads: Vec<JoinHandle<()>>,
    workers: usize,
    allowance: Option<Allowance>,
    scan: Scanner,
    /// the next piece's number
    next: u64,
    /// the piece being read
    feeding: Option<Feeding>,
    /// packed bytes walked for it, not yet handed over
    run: Vec<Vec<u8>>,
    /// the packed stream is read to its end (or its damage)
    finished: bool,
    /// pieces in the pipeline at most
    slots: usize,
    /// decoded bytes handed out so far
    produced: u64,
    /// the head piece, when it is decoded on this thread
    inline: Option<Decoder>,
    /// a worker's segment being handed out, and how far
    out: Vec<u8>,
    at: usize,
    /// the failure that follows the output already handed out
    after: Option<io::Error>,
}

impl Drop for Parallel {
    fn drop(&mut self) {
        self.shared.lock().stop = true;
        self.shared.jobs.notify_all();
        self.shared.work.notify_all();
        self.shared.reader.notify_all();
        for handle in self.threads.drain(..) {
            let _ = handle.join();
        }
    }
}

impl Parallel {
    /// Hands the walked bytes to piece `number`; `close` closes its input, with the error after its bytes.
    fn hand_over(&mut self, number: u64, close: Option<Option<io::Error>>) {
        let run = std::mem::take(&mut self.run);
        let mut state = self.shared.lock();
        // A piece whose decoder failed may be gone already: what it would have read is not needed.
        let Some(piece) = state.piece(number) else { return };
        let mut len = 0;
        for bytes in run {
            len += bytes.capacity() as u64;
            piece.input.push_back(bytes);
        }
        piece.queued += len;
        if let Some(tail) = close {
            piece.closed = true;
            piece.tail = tail;
        }
        state.held += len;
        state.peak = state.peak.max(state.held);
        state.peak_total = state.peak_total.max(state.held + state.buffers);
        self.shared.work.notify_all();
    }

    /// Starts a piece. The first is decoded on this thread; a worker takes each later one as soon as one is free.
    fn open(&mut self) -> io::Result<u64> {
        let number = self.next;
        self.next += 1;
        if number == 0 {
            self.inline = Some(Decoder::new(0, self.shared.dict)?);
        }
        if number == 1 {
            // A second piece: the stream has blocks, so the workers start. (If none can, this thread decodes
            // every piece, each as it reaches the head.)
            // Their dictionaries come out of what the folder's dictionary limit leaves once all its coders are
            // built, shared by its LZMA2 coders: the first to start workers takes what it needs.
            let mut workers = self.workers;
            if let Some(allowance) = &self.allowance {
                workers = workers.min(usize::try_from(allowance.spare.get() / allowance.window).unwrap_or(usize::MAX));
                allowance.spare.set(allowance.spare.get() - workers as u64 * allowance.window);
            }
            for _ in 0..workers {
                let shared = self.shared.clone();
                match std::thread::Builder::new().name("zipfast-lzma2".to_owned()).spawn(move || work(&shared)) {
                    Ok(handle) => self.threads.push(handle),
                    Err(_) => break,
                }
            }
        }
        let mut state = self.shared.lock();
        state.pieces.push_back(Piece::default());
        if number > 0 {
            state.jobs.push_back(number);
            self.shared.jobs.notify_one();
        }
        Ok(number)
    }

    /// Walks one chunk into the pipeline.
    fn scan(&mut self) -> io::Result<()> {
        if self.scan.spare.is_empty() {
            let mut state = self.shared.lock();
            let keep = state.spare.len().saturating_sub(SPARE / 2);
            self.scan.spare.extend(state.spare.drain(keep..));
        }
        let control = match self.scan.control(&mut self.run) {
            Ok(Some(control)) => control,
            Ok(None) => return self.close(None),
            Err(e) => return self.close(Some(e)),
        };
        let reset = control == 0x01 || control >= 0xE0;
        let feeding = match self.feeding {
            Some(feeding) if !(reset && feeding.decoded >= MIN_PIECE) => feeding,
            feeding => {
                // The first chunk, or a dictionary reset far enough on: the piece before is whole.
                if let Some(Feeding { number, .. }) = feeding {
                    self.scan.flush(&mut self.run);
                    self.hand_over(number, Some(None));
                }
                Feeding { number: self.open()?, decoded: 0, stored: 0 }
            }
        };
        self.feeding = Some(feeding);
        match self.scan.chunk(control, &mut self.run) {
            Next::Chunk { unpacked } => {
                let stored = if control < 0x80 { unpacked } else { 0 };
                self.feeding =
                    Some(Feeding { decoded: feeding.decoded + unpacked, stored: feeding.stored + stored, ..feeding });
                if !self.run.is_empty() {
                    self.hand_over(feeding.number, None);
                }
                Ok(())
            }
            Next::End => self.close(None),
            Next::Broken(e) => self.close(Some(e)),
        }
    }

    /// The packed stream ends (`tail`: in damage): the piece being read is closed.
    fn close(&mut self, tail: Option<io::Error>) -> io::Result<()> {
        self.finished = true;
        self.scan.flush(&mut self.run);
        let number = match self.feeding.take() {
            Some(feeding) => feeding.number,
            // nothing before the end: an empty piece carries it
            None => self.open()?,
        };
        self.hand_over(number, Some(tail));
        Ok(())
    }

    /// Whether reading ahead has room: pipeline slots, the budget, and a bounded lookahead in the piece being read.
    fn room(&self) -> bool {
        let mut state = self.shared.lock();
        let (lookahead, limit, head) = match self.feeding {
            Some(Feeding { number, decoded, stored }) => {
                // Stored chunks cost a copy to decode: finding the next piece early gains little, and a long
                // lookahead would leave the cache. Otherwise the lookahead grows with the output, up to the budget.
                let limit = if stored * 10 >= decoded * 9 {
                    STORED_LOOKAHEAD
                } else {
                    LOOKAHEAD.max(self.produced).min(self.shared.memory.max(HEAD_INPUT))
                };
                (state.piece(number).map_or(0, |p| p.queued), limit, number == state.head)
            }
            None => (0, LOOKAHEAD, true),
        };
        // The head piece's next bytes are read whatever the budget, while its decoder has less than HEAD_INPUT
        // waiting: the run cannot move without them. Reading further ahead is speculative and must fit the budget.
        let budget = (head && lookahead < HEAD_INPUT) || state.held < self.shared.memory;
        !self.finished && state.pieces.len() <= self.slots && budget && lookahead < limit
    }

    fn read_ahead(&mut self) -> io::Result<()> {
        let start = self.scan.packed;
        while self.scan.packed - start < BURST && self.room() {
            self.scan()?;
        }
        Ok(())
    }

    /// Decodes the head piece on this thread into `buf`; 0 once it has ended.
    fn read_inline(&mut self, decoder: &mut Decoder, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match decoder.step(buf) {
                Step::Made(0) => {}
                Step::Made(n) => return Ok(n),
                Step::Ended(n, fault) => {
                    if let Some(fault) = fault {
                        if n == 0 {
                            return Err(fault);
                        }
                        self.after = Some(fault);
                    }
                    return Ok(n);
                }
                Step::Hungry => {
                    let mut state = self.shared.lock();
                    let taken = state.take(decoder.number);
                    let waiters = state.budget_waiters;
                    let fed = taken.is_some();
                    if let Some(taken) = taken {
                        decoder.feed(taken, &mut state.spare);
                    }
                    drop(state);
                    match fed {
                        true => {
                            if waiters > 0 {
                                self.shared.work.notify_all();
                            }
                        }
                        // its bytes are not read yet: this thread reads them
                        false => self.scan()?,
                    }
                }
            }
        }
    }

    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.at < self.out.len() {
                let n = buf.len().min(self.out.len() - self.at);
                buf[..n].copy_from_slice(&self.out[self.at..self.at + n]);
                self.at += n;
                self.produced += n as u64;
                return Ok(n);
            }
            if let Some(fault) = self.after.take() {
                return Err(fault);
            }
            (self.out, self.at) = (Vec::new(), 0);
            self.read_ahead()?;
            if let Some(mut decoder) = self.inline.take() {
                let made = self.read_inline(&mut decoder, buf);
                match made {
                    Ok(0) if self.after.is_none() => {
                        // the head piece is done: the next one is the head
                        self.shared.lock().pop();
                        self.shared.work.notify_all();
                        continue;
                    }
                    Ok(n) => {
                        self.produced += n as u64;
                        self.inline = Some(decoder);
                        return Ok(n);
                    }
                    Err(e) => {
                        self.inline = Some(decoder);
                        return Err(e);
                    }
                }
            }
            let mut state = self.shared.lock();
            loop {
                let head = state.head;
                if let Some(piece) = state.pieces.front_mut() {
                    if let Some(bytes) = piece.output.pop_front() {
                        state.held -= bytes.capacity() as u64;
                        self.out = bytes;
                        break;
                    }
                    if piece.done {
                        // the next piece is the head: its worker may wait for the budget no longer
                        let fault = state.pop().and_then(|p| p.fault);
                        self.shared.work.notify_all();
                        if let Some(fault) = fault {
                            return Err(fault);
                        }
                        continue;
                    }
                    if state.jobs.front() == Some(&head) {
                        // no worker has taken the head: this thread decodes it
                        state.jobs.pop_front();
                        drop(state);
                        self.inline = Some(Decoder::new(head, self.shared.dict)?);
                        state = self.shared.lock();
                        break;
                    }
                } else if self.finished {
                    return Ok(0);
                }
                drop(state);
                if self.room() {
                    self.read_ahead()?;
                    state = self.shared.lock();
                    continue;
                }
                if self.shared.cancel.is_canceled() {
                    return Err(Fault::Canceled.into());
                }
                state = self.shared.wait(&self.shared.reader, self.shared.lock());
            }
            let waiters = state.budget_waiters;
            drop(state);
            if waiters > 0 {
                self.shared.work.notify_all();
            }
        }
    }
}

/// The dictionary bytes a folder's LZMA2 coders may still give their workers, and one worker's window.
pub(crate) struct Allowance {
    spare: Rc<Cell<u64>>,
    window: u64,
}

/// How many workers an LZMA2 coder with dictionary window `window` starts for `threads` and the parallel budget,
/// and the budget left for bytes in flight. Each worker costs its window and its one output buffer; together they
/// take at most a third of the budget, so the budget bounds all the memory the threads add, and the rest leaves
/// each worker about a 7-Zip block (four windows) of room in flight.
pub(crate) fn plan(threads: usize, budget: u64, window: u64) -> (usize, u64) {
    let budget = budget.max(MIN_MEMORY);
    let cost = window + SEGMENT as u64;
    let workers = usize::try_from(budget / 3 / cost).unwrap_or(usize::MAX).min(threads);
    (workers, budget - workers as u64 * cost)
}

/// The LZMA2 coder's output, its blocks decoded on several threads (see the module documentation).
pub(crate) struct Lzma2Blocks {
    mode: Mode,
    allowance: Option<Allowance>,
    size: u64,
    /// the dictionary property, already shrunk to the coder's output
    dict: u8,
    workers: usize,
    memory: u64,
    cancel: Cancellation,
}

impl Lzma2Blocks {
    /// `input` is the packed stream, `size` the coder's declared output size, `dict` its dictionary property
    /// (shrunk to `size`), `workers` the threads to decode on besides the caller's and `memory` the budget for
    /// bytes in flight.
    pub(crate) fn new(
        input: Stream,
        size: u64,
        dict: u8,
        workers: usize,
        memory: u64,
        cancel: &Cancellation,
    ) -> io::Result<Self> {
        let single = Single::new(input, size, dict)?;
        Ok(Self {
            mode: Mode::Single(Box::new(single)),
            size,
            dict,
            workers,
            memory,
            cancel: cancel.clone(),
            allowance: None,
        })
    }

    /// Takes the workers' dictionaries (`window` bytes each) out of `allowance` when they start.
    pub(crate) fn with_allowance(mut self, spare: Rc<Cell<u64>>, window: u64) -> Self {
        self.allowance = Some(Allowance { spare, window: window.max(1) });
        self
    }

    /// The pipeline, taking over from `single` at offset `cut` of its buffer, a chunk boundary.
    fn parallel(&mut self, single: Single, cut: usize) -> Mode {
        let Single { input, buf, len, stream, walker, eof, .. } = single;
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                pieces: VecDeque::new(),
                head: 0,
                jobs: VecDeque::new(),
                held: 0,
                peak: 0,
                buffers: 0,
                peak_total: 0,
                freed: 0,
                budget_waiters: 0,
                spare: Vec::new(),
                stop: false,
            }),
            jobs: Condvar::new(),
            work: Condvar::new(),
            reader: Condvar::new(),
            // the budget for bytes in flight, after the workers' own cost ([`plan`]); the head always moves
            memory: self.memory,
            dict: self.dict,
            cancel: self.cancel.clone(),
        });
        // Piece 0 is the stream so far: its decoder goes on, from the bytes before the cut it has not taken yet
        // (the cut is made in a block just read, so it has taken none of it).
        let mut piece = Piece::default();
        if cut > 0 {
            let first = buf[..cut].to_vec();
            piece.queued = first.capacity() as u64;
            piece.input.push_back(first);
        }
        {
            let mut state = shared.lock();
            state.held = piece.queued;
            state.pieces.push_back(piece);
        }
        let mut scan = Scanner::new(input, self.size);
        scan.block = buf[cut..len].to_vec();
        scan.unpacked = walker.decoded;
        // the walker stopped at the cut: it counts the packed bytes before it
        scan.packed = walker.walked;
        scan.eof = eof;
        let inline = Decoder { number: 0, stream, input: Vec::new(), at: 0, ended: false, tail: None, finished: false };
        Mode::Parallel(Box::new(Parallel {
            shared,
            threads: Vec::new(),
            workers: self.workers,
            allowance: self.allowance.take(),
            scan,
            next: 1,
            feeding: Some(Feeding { number: 0, decoded: walker.decoded, stored: walker.stored }),
            run: Vec::new(),
            finished: false,
            slots: (self.workers + 1) * 2,
            produced: walker.produced,
            inline: Some(inline),
            out: Vec::new(),
            at: 0,
            after: None,
        }))
    }
}

impl Read for Lzma2Blocks {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            match &mut self.mode {
                Mode::Single(single) => match single.read(out)? {
                    Single::BYTES => {}
                    cut => {
                        let Mode::Single(single) = std::mem::replace(&mut self.mode, Mode::Gone) else {
                            unreachable!()
                        };
                        self.mode = self.parallel(*single, cut);
                        continue;
                    }
                },
                Mode::Parallel(parallel) => return parallel.read(out),
                Mode::Gone => unreachable!("set again after a switch"),
            }
            let Mode::Single(single) = &mut self.mode else { unreachable!() };
            return Ok(single.made);
        }
    }
}

/// Where a [`Walker`] is in a chunk.
#[derive(Clone, Copy)]
enum At {
    /// at a chunk boundary: the next byte is a control byte
    Control,
    /// in a header: its control byte, how long it is and how much of it is read
    Header { len: usize, got: usize },
    /// in a payload, this many bytes to go
    Payload(u64),
    /// at the end marker, damage, or the coder's declared size: nothing more is walked
    Stopped,
}

/// Follows the chunk headers through the bytes the one-thread decoder reads, a few operations per chunk.
struct Walker {
    at: At,
    header: [u8; 6],
    /// decoded bytes the chunks walked declare, and those of them in stored chunks
    decoded: u64,
    stored: u64,
    /// packed bytes walked
    walked: u64,
    /// output handed out so far
    produced: u64,
    size: u64,
    /// the output-to-packed ratio past which the stream stays on one thread
    max_ratio: u64,
}

impl Walker {
    /// Walks `bytes`; the offset of the first chunk boundary where the pipeline should take over, if any: a
    /// dictionary reset at least [`MIN_PIECE`] on (a second piece), or a stream past [`MIN_PIECE`] of output that is
    /// mostly LZMA-coded (decoding is slow enough that reading ahead pays).
    fn walk(&mut self, bytes: &[u8]) -> Option<usize> {
        let mut i = 0;
        while i < bytes.len() {
            match self.at {
                At::Stopped => break,
                At::Control => {
                    let control = bytes[i];
                    let len = match control {
                        0x01 | 0x02 => 3,
                        0x80..=0xBF => 5,
                        0xC0..=0xFF => 6,
                        // the end marker or damage: the decoder deals with it
                        _ => {
                            self.at = At::Stopped;
                            break;
                        }
                    };
                    if self.decoded >= self.size {
                        self.at = At::Stopped;
                        break;
                    }
                    let reset = control == 0x01 || control >= 0xE0;
                    let coded = self.stored * 10 < self.decoded * 9;
                    // Output that comes out at more than MAX_RATIO times its packed size decodes near memory
                    // speed on one thread: handing it between threads would cost more than it gains.
                    let extreme = self.decoded > (self.walked + i as u64).saturating_mul(self.max_ratio);
                    if self.decoded >= MIN_PIECE && (reset || coded) && !extreme {
                        self.walked += i as u64;
                        return Some(i);
                    }
                    self.header[0] = control;
                    self.at = At::Header { len, got: 1 };
                    i += 1;
                }
                At::Header { len, got } => {
                    let k = (len - got).min(bytes.len() - i);
                    self.header[got..got + k].copy_from_slice(&bytes[i..i + k]);
                    i += k;
                    if got + k < len {
                        self.at = At::Header { len, got: got + k };
                        continue;
                    }
                    let h = &self.header;
                    let be16 = |j: usize| u64::from(u16::from_be_bytes([h[j], h[j + 1]]));
                    let (payload, unpacked) = if h[0] < 0x80 {
                        (be16(1) + 1, be16(1) + 1)
                    } else {
                        (be16(3) + 1, ((u64::from(h[0] & 0x1F) << 16) | be16(1)) + 1)
                    };
                    self.decoded += unpacked;
                    if h[0] < 0x80 {
                        self.stored += unpacked;
                    }
                    self.at = At::Payload(payload);
                }
                At::Payload(left) => {
                    let k = left.min((bytes.len() - i) as u64);
                    i += k as usize;
                    self.at = if k == left { At::Control } else { At::Payload(left - k) };
                }
            }
        }
        self.walked += bytes.len() as u64;
        None
    }
}

/// The one-thread decoder (the loop of [`super::coders::LzmaReader`], over a 64 KiB buffer), with a [`Walker`] on
/// every block it reads. A stream with no second piece and no long LZMA-coded stretch decodes here to its end, at
/// the one-thread speed; otherwise the pipeline takes over at a chunk boundary in a block just read.
struct Single {
    input: Stream,
    buf: Vec<u8>,
    /// the decoder has taken `buf[at..len]`... up to `at`
    at: usize,
    len: usize,
    eof: bool,
    stream: liblzma::stream::Stream,
    walker: Walker,
    /// what the last read made
    made: usize,
}

impl Single {
    /// [`Single::read`]'s answer when it made bytes (in `made`) rather than asking for the pipeline.
    const BYTES: usize = usize::MAX;

    fn new(input: Stream, size: u64, dict: u8) -> io::Result<Self> {
        Ok(Self {
            input,
            buf: vec![0; READ],
            at: 0,
            len: 0,
            eof: false,
            stream: raw_decoder(dict)?,
            walker: Walker {
                at: At::Control,
                header: [0; 6],
                decoded: 0,
                stored: 0,
                walked: 0,
                produced: 0,
                size,
                max_ratio: MAX_RATIO,
            },
            made: 0,
        })
    }

    /// Decodes into `out`: [`Self::BYTES`] with the count in `made`, or the offset in `buf` where the pipeline takes
    /// over.
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.at == self.len && !self.eof {
                let n = loop {
                    match self.input.read(&mut self.buf) {
                        Ok(n) => break n,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                        Err(e) => return Err(e),
                    }
                };
                (self.at, self.len, self.eof) = (0, n, n == 0);
                if let Some(cut) = self.walker.walk(&self.buf[..n]) {
                    return Ok(cut);
                }
            }
            let input = &self.buf[self.at..self.len];
            let action = if self.eof { liblzma::stream::Action::Finish } else { liblzma::stream::Action::Run };
            let (i0, o0) = (self.stream.total_in(), self.stream.total_out());
            let status = self.stream.process(input, out, action);
            let used = (self.stream.total_in() - i0) as usize;
            let made = (self.stream.total_out() - o0) as usize;
            self.at += used;
            match status {
                Err(liblzma::stream::Error::Mem | liblzma::stream::Error::MemLimit) => {
                    return Err(io::Error::from(io::ErrorKind::OutOfMemory));
                }
                Err(_) => return Err(data_error("LZMA data error")),
                Ok(_) if made > 0 => {
                    self.walker.produced += made as u64;
                    self.made = made;
                    return Ok(Self::BYTES);
                }
                Ok(liblzma::stream::Status::StreamEnd) => {
                    self.made = 0;
                    return Ok(Self::BYTES);
                }
                Ok(_) if self.eof && used == 0 => return Err(Fault::Truncated.into()),
                Ok(_) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use liblzma::stream::{Action, Filters, LzmaOptions, Status};

    /// Deterministic bytes: text-like (it compresses) or noise (it stays stored).
    fn bytes(len: usize, seed: u64, text: bool) -> Vec<u8> {
        let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let words = ["lzma ", "block ", "thread ", "chunk ", "reset ", "seven ", "zip ", "dictionary ", "\n"];
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            if text {
                out.extend_from_slice(words[(next() % words.len() as u64) as usize].as_bytes());
            } else {
                out.extend_from_slice(&next().to_le_bytes());
            }
        }
        out.truncate(len);
        out
    }

    /// One block: a raw LZMA2 stream for `data` (1 MiB dictionary), without its end marker.
    fn block(data: &[u8]) -> Vec<u8> {
        let mut options = LzmaOptions::new_preset(1).unwrap();
        options.dict_size(1 << 20);
        let mut filters = Filters::new();
        filters.lzma2(&options);
        let mut stream = liblzma::stream::Stream::new_raw_encoder(&filters).unwrap();
        let mut out = Vec::with_capacity(data.len() + (data.len() >> 4) + 4096);
        loop {
            if out.capacity() - out.len() < 4096 {
                out.reserve(1 << 20);
            }
            let at = stream.total_in() as usize;
            if stream.process_vec(&data[at..], &mut out, Action::Finish).unwrap() == Status::StreamEnd {
                break;
            }
        }
        assert_eq!(out.pop(), Some(0), "an end marker");
        out
    }

    /// A stream of independent blocks, one per `(len, seed, text)`, with an end marker; and its output.
    fn stream(blocks: &[(usize, u64, bool)]) -> (Vec<u8>, Vec<u8>) {
        let (mut packed, mut plain) = (Vec::new(), Vec::new());
        for &(len, seed, text) in blocks {
            let data = bytes(len, seed, text);
            packed.extend(block(&data));
            plain.extend(data);
        }
        packed.push(0);
        (packed, plain)
    }

    /// The 1 MiB dictionary's property byte.
    const DICT: u8 = 16;

    /// Reads `size` bytes as a folder does (a stream that ends early is cut short): the bytes and the failure.
    fn drain(mut reader: impl Read, size: u64) -> (Vec<u8>, Option<String>) {
        let mut out = Vec::new();
        let mut buf = vec![0u8; 256 << 10];
        while (out.len() as u64) < size {
            let n = buf.len().min((size - out.len() as u64) as usize);
            match reader.read(&mut buf[..n]) {
                Ok(0) => return (out, Some(Fault::Truncated.to_string())),
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(e) => return (out, Some(Fault::of(e).to_string())),
            }
        }
        (out, None)
    }

    fn one_thread(input: Stream, size: u64) -> (Vec<u8>, Option<String>) {
        drain(super::super::coders::LzmaReader::new(input, raw_decoder(DICT).unwrap()), size)
    }

    fn threads(input: Stream, size: u64, workers: usize, memory: u64) -> (Vec<u8>, Option<String>) {
        drain(Lzma2Blocks::new(input, size, DICT, workers, memory, &Cancellation::default()).unwrap(), size)
    }

    fn cursor(bytes: &[u8]) -> Stream {
        Box::new(io::Cursor::new(bytes.to_vec()))
    }

    /// Blocks of every shape: joined small ones, stored ones (noise), one larger than a small budget's cap.
    fn mixed() -> Vec<(usize, u64, bool)> {
        vec![
            (3 << 20, 1, true),
            (300 << 10, 2, true),
            (200 << 10, 3, false),
            (700 << 10, 4, true),
            (1_500_000, 5, false),
            (5 << 20, 6, true),
            (64 << 10, 7, true),
            (2 << 20, 8, false),
            (1, 9, true),
            (2_500_000, 10, true),
        ]
    }

    #[test]
    fn many_thread_counts_and_budgets_give_the_one_thread_bytes() {
        let (packed, plain) = stream(&mixed());
        let size = plain.len() as u64;
        let want = one_thread(cursor(&packed), size);
        assert!(want.1.is_none() && want.0 == plain);
        for workers in [2, 3, 4, 5, 8, 16] {
            for memory in [0, 6 << 20, 16 << 20, 1 << 30] {
                let got = threads(cursor(&packed), size, workers, memory);
                assert!(got.1.is_none(), "{workers} threads, {memory} bytes: {:?}", got.1);
                assert!(got.0 == plain, "{workers} threads, {memory} bytes: the output differs");
            }
        }
    }

    #[test]
    fn one_block_and_small_blocks_decode_alike() {
        for blocks in [
            vec![(6 << 20, 11, true)],
            vec![(100 << 10, 12, true); 40],
            vec![(4 << 20, 13, false)],
            vec![(10, 14, true), (10, 15, true)],
            // a stored first piece, then LZMA-coded ones: the switch at the second piece
            vec![(2_500_000, 16, false), (3 << 20, 17, true), (1 << 20, 18, false), (2 << 20, 19, true)],
            // one long stored block: no switch at all
            vec![(9 << 20, 20, false)],
        ] {
            let (packed, plain) = stream(&blocks);
            for workers in [2, 4] {
                let got = threads(cursor(&packed), plain.len() as u64, workers, 1 << 30);
                assert!(got.1.is_none() && got.0 == plain, "{workers} threads: {:?}", got.1);
            }
        }
    }

    #[test]
    fn the_declared_size_cuts_the_output() {
        let (packed, plain) = stream(&mixed());
        for size in [0, 1, 3 << 20, (3 << 20) + 5, plain.len() as u64 - 1] {
            let got = threads(cursor(&packed), size, 4, 1 << 30);
            assert_eq!(got.1, None, "{size}");
            assert!(got.0 == plain[..size as usize], "{size}");
        }
    }

    /// The one-thread failure, and its output a prefix of the threaded one's. The one-thread reader drops what the
    /// decoder made in the call that failed; a worker hands it out, so the threaded output may run a little further.
    fn same_failure(name: &str, got: &(Vec<u8>, Option<String>), want: &(Vec<u8>, Option<String>)) {
        assert_eq!(got.1, want.1, "{name}");
        assert!(got.0.starts_with(&want.0), "{name}: {} bytes vs {} one-thread", got.0.len(), want.0.len());
        assert!(
            got.0.len() - want.0.len() <= 256 << 10,
            "{name}: {} bytes vs {} one-thread",
            got.0.len(),
            want.0.len()
        );
    }

    /// Damage gives the bytes before it and then the same failure as one thread does.
    #[test]
    fn damage_fails_where_one_thread_fails() {
        let (packed, plain) = stream(&mixed());
        let size = plain.len() as u64;
        let mut cases: Vec<(String, Vec<u8>)> = Vec::new();
        // flipped payload bytes inside several blocks
        for at in [100, packed.len() / 3, packed.len() / 2, packed.len() - 1000] {
            let mut bad = packed.clone();
            bad[at] ^= 0x55;
            cases.push((format!("flip at {at}"), bad));
        }
        // cut short: mid-chunk, and with no end marker
        cases.push(("cut".into(), packed[..packed.len() * 2 / 3].to_vec()));
        cases.push(("no end marker".into(), packed[..packed.len() - 1].to_vec()));
        // a bad control byte at the start of the fourth block
        let fourth: usize = mixed()[..3].iter().map(|&(len, seed, text)| block(&bytes(len, seed, text)).len()).sum();
        let mut bad = packed.clone();
        bad[fourth] = 0x05;
        cases.push(("bad control".into(), bad));
        // a dictionary reset turned into a plain LZMA chunk: the block needs the dictionary before it
        let mut bad = packed.clone();
        assert!(bad[fourth] >= 0xE0 || bad[fourth] == 1);
        if bad[fourth] >= 0xE0 {
            bad[fourth] = 0x80 | (bad[fourth] & 0x1F);
        }
        cases.push(("reset dropped".into(), bad));
        for (name, bad) in cases {
            let want = one_thread(cursor(&bad), size);
            for workers in [2, 3, 8] {
                for memory in [0, 1 << 30] {
                    let got = threads(cursor(&bad), size, workers, memory);
                    same_failure(&format!("{name}: {workers} threads, {memory} bytes"), &got, &want);
                }
            }
        }
    }

    /// The packed stream fails after `ok` bytes.
    struct FailsAfter(io::Cursor<Vec<u8>>, u64);

    impl Read for FailsAfter {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.0.position() >= self.1 {
                return Err(Fault::Missing("volume.7z.002".into()).into());
            }
            let n = buf.len().min((self.1 - self.0.position()) as usize);
            self.0.read(&mut buf[..n])
        }
    }

    #[test]
    fn a_failed_read_comes_after_the_bytes_before_it() {
        let (packed, plain) = stream(&mixed());
        let size = plain.len() as u64;
        for ok in [0, 10, packed.len() as u64 / 2, packed.len() as u64 - 2, packed.len() as u64 - 1] {
            let want = one_thread(Box::new(FailsAfter(io::Cursor::new(packed.clone()), ok)), size);
            // the end marker alone missing is never read: the output is whole before it
            let whole = ok == packed.len() as u64 - 1;
            assert_eq!(want.1.is_none(), whole, "{ok}: {:?}", want.1);
            assert!(whole || want.1.as_deref().is_some_and(|f| f.contains("missing volume")), "{ok}: {:?}", want.1);
            let got = threads(Box::new(FailsAfter(io::Cursor::new(packed.clone()), ok)), size, 4, 1 << 30);
            same_failure(&format!("fails after {ok}"), &got, &want);
        }
    }

    #[test]
    fn cancellation_stops_the_workers_mid_stream() {
        let blocks: Vec<_> = (0..24).map(|i| (2 << 20, 100 + i, i % 3 != 0)).collect();
        let (packed, plain) = stream(&blocks);
        let cancel = Cancellation::default();
        let mut reader = Lzma2Blocks::new(cursor(&packed), plain.len() as u64, DICT, 4, 1 << 30, &cancel).unwrap();
        let mut buf = vec![0u8; 64 << 10];
        assert!(reader.read(&mut buf).unwrap() > 0);
        cancel.cancel();
        let started = std::time::Instant::now();
        let mut read = 0usize;
        let error = loop {
            match reader.read(&mut buf) {
                Ok(0) => panic!("ended after a cancel"),
                Ok(n) => read += n,
                Err(e) => break e,
            }
        };
        assert!(matches!(Fault::of(error), Fault::Canceled));
        assert!(read < plain.len() / 2, "{read} bytes after the cancel");
        drop(reader);
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
    }

    impl Lzma2Blocks {
        /// Lets even extremely compressible streams into the pipeline, for the tests that need them there.
        fn any_ratio(mut self) -> Self {
            if let Mode::Single(single) = &mut self.mode {
                single.walker.max_ratio = u64::MAX;
            }
            self
        }

        /// The most the pipeline's held bytes and the workers' output buffers have been together.
        fn peak_total(&self) -> Option<u64> {
            match &self.mode {
                Mode::Parallel(parallel) => Some(parallel.shared.lock().peak_total),
                _ => None,
            }
        }

        /// The bytes the queued buffers allocate right now (packed input and decoded output), counted directly.
        fn queued_capacity(&self) -> u64 {
            let Mode::Parallel(parallel) = &self.mode else { return 0 };
            let state = parallel.shared.lock();
            let input: usize = state.pieces.iter().flat_map(|p| p.input.iter()).map(Vec::capacity).sum();
            let output: usize = state.pieces.iter().flat_map(|p| p.output.iter()).map(Vec::capacity).sum();
            (input + output) as u64
        }

        /// The worker threads started, once the pipeline runs.
        fn started(&self) -> Option<usize> {
            match &self.mode {
                Mode::Parallel(parallel) => Some(parallel.threads.len()),
                _ => None,
            }
        }

        /// The most bytes the pipeline has held, once it runs.
        fn peak(&self) -> Option<u64> {
            match &self.mode {
                Mode::Parallel(parallel) => Some(parallel.shared.lock().peak),
                _ => None,
            }
        }
    }

    /// Blocks of zeros pack to a few KiB each, so all their input is read ahead at once and each decodes to 8 MiB:
    /// with the reader paused, or reading slowly, the queued output still stays within the budget and the few
    /// segments the head may run ahead, at every budget from one segment up, and nothing deadlocks.
    #[test]
    fn a_paused_reader_keeps_the_queued_output_within_the_budget() {
        let zeros = vec![0u8; 8 << 20];
        let one = block(&zeros);
        let blocks = 24;
        let mut packed = Vec::with_capacity(one.len() * blocks + 1);
        for _ in 0..blocks {
            packed.extend_from_slice(&one);
        }
        packed.push(0);
        let total = (zeros.len() * blocks) as u64;
        for memory in [0, SEGMENT as u64, 4 << 20, 16 << 20] {
            let mut reader = Lzma2Blocks::new(cursor(&packed), total, DICT, 4, memory, &Cancellation::default())
                .unwrap()
                .any_ratio();
            let mut buf = vec![0u8; 256 << 10];
            let mut read = 0u64;
            let mut take = |reader: &mut Lzma2Blocks, read: &mut u64| {
                let n = reader.read(&mut buf).unwrap();
                assert!(n > 0, "{memory}: ended at {read}");
                assert!(buf[..n].iter().all(|&b| b == 0));
                *read += n as u64;
            };
            while read < 10 << 20 {
                take(&mut reader, &mut read);
            }
            // paused, as while a member is written: the workers must stop, not fill memory
            std::thread::sleep(Duration::from_millis(300));
            let paused = reader.peak().expect("the pipeline runs");
            while read < total {
                take(&mut reader, &mut read);
                if read % (32 << 20) < (256 << 10) {
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
            assert_eq!(reader.read(&mut buf).unwrap(), 0);
            let bound = memory + (HEAD_SEGMENTS as u64 + 1) * SEGMENT as u64;
            let peak = reader.peak().unwrap();
            assert!(paused <= bound && peak <= bound, "{memory}: peak {paused} paused, {peak} in all, bound {bound}");
        }
    }

    /// Two LZMA2 coders of one folder share what the dictionary limit leaves for workers: the first to start them
    /// takes it, the second gets none and its caller's thread decodes every piece, with the same bytes.
    #[test]
    fn coders_of_one_folder_share_the_worker_dictionaries() {
        let (packed, plain) = stream(&mixed());
        let size = plain.len() as u64;
        let window = dict_size(DICT);
        let spare = Rc::new(Cell::new(2 * window + window / 2));
        let open = || {
            Lzma2Blocks::new(cursor(&packed), size, DICT, 8, 1 << 30, &Cancellation::default())
                .unwrap()
                .with_allowance(spare.clone(), window)
        };
        let (mut first, mut second) = (open(), open());
        let mut buf = vec![0u8; 256 << 10];
        let mut read = |reader: &mut Lzma2Blocks| {
            let mut out = Vec::new();
            loop {
                let n = reader.read(&mut buf).unwrap();
                if n == 0 || out.len() as u64 >= size {
                    return out;
                }
                out.extend_from_slice(&buf[..n]);
            }
        };
        assert!(read(&mut first) == plain);
        assert_eq!(first.started(), Some(2));
        assert_eq!(spare.get(), window / 2);
        assert!(read(&mut second) == plain);
        assert_eq!(second.started(), Some(0));
    }

    /// A tiny dictionary and many threads: the workers' output buffers count in their cost, so all the memory the
    /// threads add (dictionaries, buffers, bytes in flight) stays within the budget and the head's few segments,
    /// with the reader paused and reading slowly.
    #[test]
    fn many_workers_with_a_tiny_dictionary_stay_within_the_budget() {
        let mut options = LzmaOptions::new_preset(1).unwrap();
        options.dict_size(4096);
        let mut filters = Filters::new();
        filters.lzma2(&options);
        let mut packed = Vec::new();
        let mut plain = Vec::new();
        for i in 0..40 {
            let data = bytes(1 << 20, 300 + i, true);
            let mut stream = liblzma::stream::Stream::new_raw_encoder(&filters).unwrap();
            let mut out = Vec::with_capacity(data.len() + 4096);
            while stream.process_vec(&data[stream.total_in() as usize..], &mut out, Action::Finish).unwrap()
                != Status::StreamEnd
            {
                out.reserve(1 << 20);
            }
            assert_eq!(out.pop(), Some(0));
            packed.extend(out);
            plain.extend(data);
        }
        packed.push(0);
        let window = dict_size(0);
        for budget in [8 << 20, 16 << 20, 64 << 20] {
            let (workers, memory) = plan(16, budget, window);
            assert!(workers >= 1, "{budget}");
            let mut reader =
                Lzma2Blocks::new(cursor(&packed), plain.len() as u64, 0, workers, memory, &Cancellation::default())
                    .unwrap();
            let mut buf = vec![0u8; 256 << 10];
            let mut out = Vec::new();
            while out.len() < plain.len() {
                let n = reader.read(&mut buf).unwrap();
                assert!(n > 0);
                out.extend_from_slice(&buf[..n]);
                if out.len() == 4 << 20 || out.len() % (8 << 20) == 0 {
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
            assert!(out == plain, "{budget}");
            let threads = reader.started().unwrap() as u64;
            let total = reader.peak_total().unwrap() + threads * window;
            let bound = budget + HEAD_SEGMENTS as u64 * SEGMENT as u64;
            assert!(total <= bound, "{budget}: {workers} workers, {total} bytes, bound {bound}");
        }
    }

    /// One large block that compresses only partly, read under a small budget: the head piece's input read ahead
    /// stays within the budget (only its next few hundred KiB are read regardless), and the output is whole.
    #[test]
    fn a_large_block_reads_ahead_within_the_budget() {
        let mut plain = Vec::with_capacity(48 << 20);
        let mut unit = 0;
        while plain.len() < 48 << 20 {
            plain.extend(bytes(3072, 500 + unit, true));
            plain.extend(bytes(1024, 900 + unit, false));
            unit += 1;
        }
        let mut packed = block(&plain);
        packed.push(0);
        assert!(packed.len() > 10 << 20, "{} packed bytes", packed.len());
        for memory in [0u64, 1 << 20, 4 << 20] {
            let mut reader =
                Lzma2Blocks::new(cursor(&packed), plain.len() as u64, DICT, 4, memory, &Cancellation::default())
                    .unwrap();
            let got = drain(&mut reader, plain.len() as u64);
            assert!(got.1.is_none() && got.0 == plain, "{memory}: {:?}", got.1);
            let peak = reader.peak().expect("the pipeline runs");
            let bound = memory.max(HEAD_INPUT) + 2 * READ as u64 + (HEAD_SEGMENTS as u64 + 1) * SEGMENT as u64;
            assert!(peak <= bound, "{memory}: peak {peak}, bound {bound}");
        }
    }

    /// Blocks of zeros 1 MiB and one byte long: each ends in a one-byte segment. With the reader paused the queued
    /// buffers, counted by what they allocate, stay within the budget and the head's segments.
    #[test]
    fn short_last_segments_are_charged_by_what_they_hold() {
        let zeros = vec![0u8; (1 << 20) + 1];
        let one = block(&zeros);
        let blocks = 64;
        let mut packed = Vec::with_capacity(one.len() * blocks + 1);
        for _ in 0..blocks {
            packed.extend_from_slice(&one);
        }
        packed.push(0);
        let total = (zeros.len() * blocks) as u64;
        for memory in [4u64 << 20, 16 << 20] {
            let mut reader = Lzma2Blocks::new(cursor(&packed), total, DICT, 8, memory, &Cancellation::default())
                .unwrap()
                .any_ratio();
            let mut buf = vec![0u8; 256 << 10];
            let mut read = 0u64;
            let mut most = 0u64;
            while read < total {
                let n = reader.read(&mut buf).unwrap();
                assert!(n > 0 && buf[..n].iter().all(|&b| b == 0), "{memory}");
                read += n as u64;
                if (3 << 20..(3 << 20) + (256 << 10)).contains(&read) {
                    // paused, as while a member is written
                    std::thread::sleep(Duration::from_millis(300));
                }
                most = most.max(reader.queued_capacity());
            }
            let bound = memory + (HEAD_SEGMENTS as u64 + 1) * SEGMENT as u64 + 2 * READ as u64;
            assert!(most <= bound, "{memory}: {most} bytes queued, bound {bound}");
            assert!(reader.peak().unwrap() <= bound, "{memory}");
        }
    }

    /// An extremely compressible stream of many blocks (a repeated paragraph, as in a 1 GiB text archive) stays on
    /// one thread: it decodes near memory speed there.
    #[test]
    fn extremely_compressible_blocks_stay_on_one_thread() {
        let paragraph = bytes(4096, 77, true);
        let data: Vec<u8> = paragraph.iter().copied().cycle().take(4 << 20).collect();
        let one = block(&data);
        assert!(one.len() * 64 < data.len(), "{} packed for {}", one.len(), data.len());
        let mut packed = Vec::new();
        for _ in 0..8 {
            packed.extend_from_slice(&one);
        }
        packed.push(0);
        let total = (data.len() * 8) as u64;
        let mut reader = Lzma2Blocks::new(cursor(&packed), total, DICT, 8, 1 << 30, &Cancellation::default()).unwrap();
        let got = drain(&mut reader, total);
        assert!(got.1.is_none() && got.0.chunks(data.len()).all(|c| c == data));
        assert!(reader.peak().is_none(), "the pipeline started");
        // the same stream with the ratio lifted does go to the threads, with the same bytes
        let mut reader =
            Lzma2Blocks::new(cursor(&packed), total, DICT, 8, 1 << 30, &Cancellation::default()).unwrap().any_ratio();
        let again = drain(&mut reader, total);
        assert!(again == got);
        assert!(reader.started().unwrap() > 0);
    }

    #[test]
    fn dropping_the_reader_mid_stream_joins_the_workers() {
        let blocks: Vec<_> = (0..16).map(|i| (2 << 20, 200 + i, true)).collect();
        let (packed, plain) = stream(&blocks);
        let mut reader =
            Lzma2Blocks::new(cursor(&packed), plain.len() as u64, DICT, 8, 1 << 30, &Cancellation::default()).unwrap();
        let mut buf = vec![0u8; 1 << 20];
        reader.read_exact(&mut buf).unwrap();
        assert!(buf == plain[..buf.len()]);
        drop(reader);
    }
}
