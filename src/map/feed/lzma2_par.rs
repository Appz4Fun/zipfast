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

//! A 7z LZMA2 member's independent blocks decoded on worker threads ahead of the main decode
//! ([`super::super::FeedOptions::threads`]).
//!
//! 7-Zip with `-mmt` writes LZMA2 as blocks that each start with a chunk resetting the dictionary (a stored chunk
//! `0x01`, or an LZMA chunk `0xE0` and up), so a block decodes on its own exactly as it does inside the stream. The
//! decoder walks chunk headers ahead of the main decode as their packed bytes arrive; each dictionary reset past the
//! main decode's position starts a block a worker may take. The worker is fed the block's packed bytes as they
//! arrive (it never waits for the whole block), decodes them with its own decoder, and sends the output back; the
//! caller's thread writes it through the sink at its output offset and into the CRC runs, so the worker never
//! touches the source or the sink. The main decode stops at the first block a worker owns and, once that block's end
//! (the next dictionary reset) is known, goes on from that next reset, decoding nothing twice. A block a worker
//! cannot finish (a hole in its packed bytes, data that does not decode) is handed to the repair machinery as lost
//! output decoded from its own dictionary reset, which needs nothing held, so a failure costs only time.
//!
//! Only a plain member that no folder member follows uses workers; anything else decodes on the caller's thread as
//! before. Workers hold no state the snapshot needs: a decoder restored from one decodes the blocks again (output
//! already in the CRC runs is not written twice).

use super::*;
use std::sync::mpsc;

/// Output chunks a worker may have waiting for the caller's thread before it blocks: with [`CHUNK`]-sized chunks,
/// about 16 MiB per worker, so workers keep decoding while the caller's thread is busy.
const QUEUE: usize = 16;

/// A worker's output chunk.
const CHUNK: usize = 1 << 20;

/// Packed reads a worker may have queued before the caller's thread stops feeding it (each at most
/// [`super::FeedOptions::read_chunk`]): input is bounded by the read size, not by the block.
const INPUT_QUEUE: usize = 4;

/// How long the main decode, at a block it has not begun while every worker is busy, waits for one to free up before
/// decoding the block itself.
const WAIT: std::time::Duration = std::time::Duration::from_millis(20);

/// Workers from which the main decode waits ([`WAIT`]) for one to free up rather than decode a block itself: with
/// fewer, its own decoding adds more than the output it would write meanwhile (measured on Zen 3: one worker 113 MB/s
/// decoding vs 94 MB/s waiting; even at two; ahead from four).
const WAIT_FROM_THREADS: usize = 3;

/// How far ahead of the main decode (folder output) the header walk looks for blocks.
const LOOKAHEAD: u64 = 1 << 30;

/// The least folder output between the dictionary resets that start blocks: closer ones stay inside the block before
/// them (it decodes them as the main decode would), so a stream of tiny resets never starts a thread every few bytes.
const MIN_BLOCK: u64 = 128 << 10;

/// Workers for one member: decoding blocks ahead of the main decode.
pub(super) struct Par {
    /// worker threads that may run at once
    threads: usize,
    /// the next chunk header the walk ahead reads: plain packed offset and folder output offset
    ahead: Option<(u64, u64)>,
    /// dictionary resets the walk found, by folder output offset: their plain packed offset
    resets: BTreeMap<u64, u64>,
    /// blocks workers own, by their first folder output offset
    blocks: BTreeMap<u64, Block>,
    tx: mpsc::SyncSender<(u64, Msg)>,
    rx: mpsc::Receiver<(u64, Msg)>,
    /// packed (cipher) ranges running workers wait for, since the last round
    waiting: Vec<Range<u64>>,
    /// the end marker (plain packed, folder output), once walked
    stream_end: Option<(u64, u64)>,
    /// blocks given up while ahead of the main decode: it decodes them itself, so no worker takes them again
    given_up: std::collections::BTreeSet<u64>,
}

struct Block {
    /// plain packed offset of the block's first chunk header
    packed: u64,
    /// the next dictionary reset (plain packed offset, folder output offset), once the walk found it
    end: Option<(u64, u64)>,
    /// plain packed offset up to which the worker was fed
    sent: u64,
    /// the worker's input (bounded, [`INPUT_QUEUE`]); dropped once the block is fed whole (the worker then ends) or
    /// given up
    input: Option<mpsc::SyncSender<Vec<u8>>>,
    /// the last feed stopped at a full input queue: more is to come once the worker takes some
    backlog: bool,
    /// folder output offset written up to
    written: u64,
    state: State,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Running,
    Finished,
    /// given up: its output from `written` on is a repair's
    Failed,
}

enum Msg {
    Out(Vec<u8>),
    Done,
    Failed,
}

impl Par {
    pub(super) fn new(threads: usize) -> Option<Box<Self>> {
        (threads > 0).then(|| {
            let (tx, rx) = mpsc::sync_channel(QUEUE * threads);
            Box::new(Self {
                threads,
                ahead: None,
                resets: BTreeMap::new(),
                blocks: BTreeMap::new(),
                tx,
                rx,
                waiting: Vec::new(),
                stream_end: None,
                given_up: Default::default(),
            })
        })
    }

    /// The first block at or after `out` (folder output) a worker owns: where the main decode stops.
    pub(super) fn next_owned(&self, out: u64) -> Option<u64> {
        self.blocks.range(out..).next().map(|(&start, _)| start)
    }

    /// The block a worker owns starting at `out`, once its end is known: (plain packed, folder output) of that end.
    pub(super) fn owned_end(&self, out: u64) -> Option<(u64, u64)> {
        self.blocks.get(&out).and_then(|b| b.end)
    }

    /// Output before this (folder offset) is written as far as the workers go: the first block not finished.
    pub(super) fn written_floor(&self) -> Option<u64> {
        self.blocks.values().find(|b| b.state != State::Finished).map(|b| b.written)
    }

    /// The packed (cipher) ranges running workers waited for in the last round.
    pub(super) fn take_waiting(&mut self) -> Vec<Range<u64>> {
        std::mem::take(&mut self.waiting)
    }

    /// The plain packed ranges of the blocks not finished: kept by the source, all of each block (a block given up
    /// goes back to the main decode or to a repair, which read it from its start).
    pub(super) fn unfed(&self) -> Vec<Range<u64>> {
        self.blocks
            .values()
            .filter(|b| b.state != State::Finished)
            .map(|b| b.packed..b.end.map_or(u64::MAX, |(p, _)| p))
            .collect()
    }

    /// The blocks the main decode went past (it is at `main_out`) whose workers have not finished: (lost folder
    /// output from where the worker stopped, the block's dictionary reset to decode it from, the block's packed end).
    /// A snapshot keeps them as repairs, since it keeps no worker.
    pub(super) fn passed_unfinished(&self, main_out: u64) -> Vec<(Range<u64>, Cp, u64)> {
        self.blocks
            .range(..main_out)
            .filter(|(_, b)| b.state != State::Finished)
            .filter_map(|(&out, b)| {
                let (packed_end, out_end) = b.end?;
                let cp = Cp { packed: b.packed, out, props: None, seeded: false };
                (b.written < out_end).then_some((b.written..out_end, cp, packed_end))
            })
            .collect()
    }

    /// Every worker is busy, and there are enough of them ([`WAIT_FROM_THREADS`]) that the main decode should wait
    /// for one rather than decode the next block itself.
    pub(super) fn all_busy(&self) -> bool {
        self.threads >= WAIT_FROM_THREADS
            && self.blocks.values().filter(|b| b.state == State::Running).count() >= self.threads
    }

    /// No worker is running.
    pub(super) fn idle(&self) -> bool {
        self.blocks.values().all(|b| b.state != State::Running)
    }
}

/// A worker: decodes one block's chunks as they come and sends the output back.
fn worker(prop: u8, start: u64, input: mpsc::Receiver<Vec<u8>>, tx: mpsc::SyncSender<(u64, Msg)>) {
    let mut live = match Live::new(prop) {
        Ok(live) => live,
        Err(_) => {
            let _ = tx.send((start, Msg::Failed));
            return;
        }
    };
    let mut buf = vec![0u8; CHUNK];
    for bytes in input {
        let sent = live.feed(&bytes, &mut buf, start, &mut |out| {
            tx.send((start, Msg::Out(out.to_vec()))).map_err(|_| corrupt(start, "LZMA2 worker's caller is gone"))
        });
        if sent.is_err() {
            let _ = tx.send((start, Msg::Failed));
            return;
        }
    }
    let _ = tx.send((start, Msg::Done));
}

impl FeedDecoder {
    /// One round of the workers, on the caller's thread: writes what they decoded, walks headers ahead of the main
    /// decode for new blocks, starts workers on them and feeds every running worker the packed bytes that arrived.
    /// `wait`: block for the workers when there is nothing else to do (the main decode is done and every running
    /// block is fed whole).
    pub(super) fn par_round(
        &mut self,
        lz: &mut Lz,
        source: &mut dyn PackedSource,
        sink: &mut dyn FeedSink,
        wait: bool,
    ) -> Result<(), FeedError> {
        let Some(mut par) = lz.par.take() else { return Ok(()) };
        let result = (|| {
            self.par_collect(lz, &mut par, sink, false)?;
            self.par_walk(lz, &mut par, source)?;
            self.par_start(lz, &mut par);
            self.par_feed(lz, &mut par, source)?;
            self.par_fail(lz, &mut par);
            if wait {
                // every running block fed whole, or held back only by its input queue: the rest is decoding time
                // (fed on as the workers take their input), until the run's budget is spent
                while !self.par_over_budget()
                    && par.blocks.values().any(|b| b.state == State::Running && (b.input.is_none() || b.backlog))
                {
                    self.par_collect(lz, &mut par, sink, true)?;
                    self.par_feed(lz, &mut par, source)?;
                    self.par_fail(lz, &mut par);
                }
            }
            Ok(())
        })();
        lz.par = Some(par);
        result
    }

    /// At a block the main decode has not begun while every worker is busy: waits up to [`WAIT`] for a worker's
    /// message and writes what came. False when nothing came (workers short of input, say): the main decode then
    /// decodes the block itself.
    pub(super) fn par_wait(&mut self, lz: &mut Lz, sink: &mut dyn FeedSink) -> Result<bool, FeedError> {
        if self.par_over_budget() {
            return Ok(false);
        }
        let Some(mut par) = lz.par.take() else { return Ok(false) };
        let result = (|| {
            let Ok(msg) = par.rx.recv_timeout(WAIT) else { return Ok(false) };
            self.par_message(lz, &mut par, sink, msg)?;
            self.par_collect(lz, &mut par, sink, false)?;
            Ok(true)
        })();
        lz.par = Some(par);
        result
    }

    /// The run's write budget ([`super::FeedOptions::run_budget`]) is spent: worker output waits for the next run.
    fn par_over_budget(&self) -> bool {
        self.options.run_budget.is_some_and(|b| self.run_written >= b)
    }

    /// Workers still have work: a run stopped at its budget has more to do.
    pub(super) fn par_pending(&self, lz: &Lz) -> bool {
        lz.par.as_ref().is_some_and(|p| !p.idle())
    }

    /// Writes what the workers sent, until the run's budget is spent; `block`: wait (up to [`WAIT`]) for a message.
    fn par_collect(
        &mut self,
        lz: &mut Lz,
        par: &mut Par,
        sink: &mut dyn FeedSink,
        block: bool,
    ) -> Result<(), FeedError> {
        let mut first = block;
        loop {
            if self.par_over_budget() {
                return Ok(());
            }
            let msg = if first {
                first = false;
                // bounded: a worker that took its queued input without output yet (a few small reads inside one chunk)
                // waits for more, which the caller's thread feeds once this returns
                match par.rx.recv_timeout(WAIT) {
                    Ok(m) => m,
                    Err(_) => return Ok(()),
                }
            } else {
                match par.rx.try_recv() {
                    Ok(m) => m,
                    Err(_) => return Ok(()),
                }
            };
            self.par_message(lz, par, sink, msg)?;
        }
    }

    /// One message from a worker: its output written, or its end.
    fn par_message(
        &mut self,
        lz: &mut Lz,
        par: &mut Par,
        sink: &mut dyn FeedSink,
        (start, msg): (u64, Msg),
    ) -> Result<(), FeedError> {
        let Some(b) = par.blocks.get_mut(&start) else { return Ok(()) };
        if b.state != State::Running {
            return Ok(());
        }
        match msg {
            Msg::Out(bytes) => {
                let at = b.written;
                b.written += bytes.len() as u64;
                let (ss, end, write) = (lz.ss, lz.end, lz.write_from..lz.end);
                self.lz_emit((ss, end), end, &write, at, &bytes, sink)?;
            }
            Msg::Done => {
                // the worker ends once fed whole: its output must fill the block exactly
                b.state = match b.end {
                    Some((_, out_end)) if b.written == out_end => State::Finished,
                    _ => State::Failed,
                };
            }
            Msg::Failed => b.state = State::Failed,
        }
        Ok(())
    }

    /// Walks chunk headers ahead of the main decode, recording dictionary resets and the ends of owned blocks.
    fn par_walk(&mut self, lz: &mut Lz, par: &mut Par, source: &mut dyn PackedSource) -> Result<(), FeedError> {
        let Some(main) = lz.main.as_ref() else { return Ok(()) };
        // the walk starts at the main decode's next header (past the chunk it reads), never behind it
        let from = match main.chunk {
            Some(c) => (c.packed().end, c.unpacked().end),
            None => (main.pos, main.out),
        };
        let (mut pos, mut out) = match par.ahead {
            Some(a) if a.1 >= from.1 => a,
            _ => from,
        };
        // within the lookahead and the member, and on past them until every owned block's end is known
        let limit = from.1.saturating_add(LOOKAHEAD).min(lz.end);
        while out < limit || par.blocks.values().any(|b| b.end.is_none()) {
            let c = match self.lz_header(lz, source, pos, out)? {
                Hdr::Chunk(c) => c,
                // the end marker: the last block ends at it (the marker itself is never fed)
                Hdr::End => {
                    if let Some((_, b)) = par.blocks.range_mut(..out).next_back()
                        && b.end.is_none()
                    {
                        b.end = Some((pos, out));
                    }
                    par.stream_end = Some((pos, out));
                    break;
                }
                // a block whose end is not walked waits on this header: its bytes are needed (the main decode stops at
                // that block); a hole there gives the block up (the main decode reads it itself, with its own
                // fallback), since its end can never be walked
                Hdr::Missing { cipher, hole } => {
                    if let Some((_, b)) = par.blocks.range_mut(..=out).next_back()
                        && b.end.is_none()
                        && b.state == State::Running
                    {
                        if hole {
                            b.state = State::Failed;
                        } else {
                            par.waiting.push(cipher);
                        }
                    }
                    break;
                }
            };
            let spaced = par
                .resets
                .range(..c.unpacked_offset)
                .next_back()
                .is_none_or(|(&o, _)| c.unpacked_offset - o >= MIN_BLOCK);
            if matches!(c.reset, Lzma2Reset::Dict | Lzma2Reset::DictStateProps) && spaced {
                par.resets.insert(c.unpacked_offset, c.packed_offset);
                // the block before it ends here
                if let Some((_, b)) = par.blocks.range_mut(..c.unpacked_offset).next_back()
                    && b.end.is_none()
                {
                    b.end = Some((c.packed_offset, c.unpacked_offset));
                }
            }
            pos = c.packed().end;
            out = c.unpacked().end;
        }
        par.ahead = Some((pos, out));
        Ok(())
    }

    /// Starts workers on the resets past the main decode's current block, while threads are free.
    fn par_start(&mut self, lz: &Lz, par: &mut Par) {
        let Some(main) = lz.main.as_ref() else { return };
        // past the main decode's position; at a reset it has not begun to decode (between chunks, no decoder yet),
        // that block too: the caller's thread then only writes what the workers send
        let at_reset = main.chunk.is_none() && main.live.is_none() && par.resets.get(&main.out) == Some(&main.pos);
        let first = if at_reset { main.out } else { main.out + 1 };
        if first >= lz.end {
            return;
        }
        let running = par.blocks.values().filter(|b| b.state == State::Running).count();
        let free = par.threads.saturating_sub(running);
        let candidates: Vec<(u64, u64)> = par
            .resets
            .range(first..lz.end)
            .filter(|(out, _)| !par.blocks.contains_key(out) && !par.given_up.contains(out))
            .take(free)
            .map(|(&o, &p)| (o, p))
            .collect();
        for (out, packed) in candidates {
            let (input_tx, input_rx) = mpsc::sync_channel(INPUT_QUEUE);
            let tx = par.tx.clone();
            let prop = lz.dec_prop;
            let spawned =
                std::thread::Builder::new().name("zipfast-lzma2".into()).spawn(move || worker(prop, out, input_rx, tx));
            if spawned.is_err() {
                return;
            }
            // its end, if the walk already found the next reset (or the end marker)
            let end = par.resets.range(out + 1..).next().map(|(&o, &p)| (p, o)).or(par.stream_end);
            par.blocks.insert(
                out,
                Block {
                    packed,
                    end,
                    sent: packed,
                    input: Some(input_tx),
                    backlog: false,
                    written: out,
                    state: State::Running,
                },
            );
        }
    }

    /// Feeds every running worker the packed bytes of its block that arrived since.
    fn par_feed(&mut self, lz: &Lz, par: &mut Par, source: &mut dyn PackedSource) -> Result<(), FeedError> {
        let chunk = self.options.read_chunk.max(16);
        // a block whose end is not walked yet is fed only through the chunks whose headers were walked (all inside
        // it: no reset was met), never the end marker or a later block's bytes
        let walked = par.ahead.map_or(0, |(pos, _)| pos);
        for b in par.blocks.values_mut() {
            if b.state != State::Running || b.input.is_none() {
                continue;
            }
            b.backlog = false;
            loop {
                let stop = b.end.map_or(walked, |(p, _)| p).min(lz.plain_len);
                if b.sent >= stop {
                    // fed whole: the worker ends once it has decoded it
                    if b.end.is_some() {
                        b.input = None;
                    }
                    break;
                }
                let mut bytes = vec![0u8; (stop - b.sent).min(chunk as u64) as usize];
                match self.lz_read(lz, source, b.sent, &mut bytes)? {
                    Got::Data(n) => {
                        bytes.truncate(n);
                        let Some(tx) = b.input.as_ref() else { break };
                        match tx.try_send(bytes) {
                            Ok(()) => b.sent += n as u64,
                            // the worker has enough queued: fed on once it takes some (the bytes are read again then)
                            Err(mpsc::TrySendError::Full(_)) => {
                                b.backlog = true;
                                break;
                            }
                            Err(mpsc::TrySendError::Disconnected(_)) => {
                                b.state = State::Failed;
                                break;
                            }
                        }
                    }
                    Got::Missing { hole: false, cipher } => {
                        par.waiting.push(cipher);
                        break;
                    }
                    // a hole in its packed bytes: given up, its output is a repair's
                    Got::Missing { hole: true, .. } => {
                        b.state = State::Failed;
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    /// Gives up the blocks that failed: one the main decode has not reached goes back to it (it decodes the block,
    /// skipping what the worker already wrote); one it went past goes to the repairs once its end is known, decoded
    /// from the block's own dictionary reset from where the worker stopped.
    fn par_fail(&mut self, lz: &mut Lz, par: &mut Par) {
        let main_out = lz.main.as_ref().map(|l| l.out);
        let failed: Vec<u64> = par.blocks.iter().filter(|(_, b)| b.state == State::Failed).map(|(&o, _)| o).collect();
        for out in failed {
            // the block lies ahead of the main decode (not reached, or reached and stopped at)
            let ahead = main_out.is_some_and(|m| m <= out);
            let end = par.blocks[&out].end;
            if !ahead && end.is_none() {
                // past it, but its end not known yet: handed over once the walk finds it
                continue;
            }
            let b = par.blocks.remove(&out).expect("listed");
            if ahead {
                par.given_up.insert(out);
            }
            if let (false, Some((packed_end, out_end))) = (ahead, b.end)
                && b.written < out_end
            {
                let cp = Cp { packed: b.packed, out, props: None, seeded: false };
                self.lz_lose(lz, b.written..out_end, Kind::Decoded { cp, until: packed_end, seed: None });
            }
        }
    }
}
