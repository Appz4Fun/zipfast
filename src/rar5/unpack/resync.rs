//! Restarting the RAR 5.0 decoder after a hole in a compressed member, from plaintext known from another copy.
//!
//! RAR 5.0 packs a member as a series of byte-aligned blocks, each with its own header (and, in practice, its own
//! Huffman tables). After a run of lost packed bytes, [`resync`] finds the next block that decodes, works out which
//! output offset it starts at by matching what it decodes to (literals, and copies from the window) against the known
//! plaintext, and recovers the decoder's state the hole erased: the four last match distances and the last length. It
//! reads ahead block by block, checking each against the plaintext, until that state is known.
//! [`Unpacker::resume_at`] then starts a decoder at that block with the plaintext before it as its window, so decoding
//! goes on from the recipient's own packed bytes.

use super::parallel::{FilterFields, Packed, tokenize};
use super::{Bits, Huff, Lengths, PAD, Slot, Tables, Tok, Unpacker, Window, block_header, read_lengths};
use crate::error::Result;
use std::ops::Range;

/// The farthest back a match distance the hole erased is looked for in the plaintext.
const SEARCH: u64 = 4 << 20;
/// The most blocks read ahead to learn the decoder's state.
const MAX_BLOCKS: usize = 256;

/// Where and how decoding can restart after a hole: see [`resync`].
#[derive(Clone, Debug)]
pub struct Resync {
    /// Offset in the packed bytes given to [`resync`] of the block decoding restarts at (its header).
    pub packed_offset: usize,
    /// The member output offset that block starts at.
    pub output_offset: u64,
    /// Output the blocks read ahead decoded to, proven equal to the known plaintext (from the first block found after
    /// the hole up to `output_offset`).
    pub verified: Range<u64>,
    /// Whether the decoder's whole state was learned. When `false` some of the four last match distances never
    /// appeared before the packed bytes ran out; decoding still restarts, and a match that uses one of them decodes
    /// wrong (the member's CRC then fails).
    pub complete: bool,
    history: [u64; 4],
    last_len: u32,
    lens: Box<Lengths>,
}

/// Why [`resync`] found no restart point.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResyncError {
    /// No block in the packed bytes decodes to the known plaintext at an offset in the expected range: the plaintext
    /// differs, the range is wrong, or a filter that started before the hole covers the output.
    NotFound,
    /// A block after the hole starts a filter (at this output offset): its output differs from the plaintext until
    /// the filter runs, so look again from packed bytes after it.
    Filter { output_offset: u64 },
}

impl std::fmt::Display for ResyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => f.write_str("no RAR 5.0 block after the hole decodes to the known plaintext"),
            Self::Filter { output_offset } => write!(f, "a RAR 5.0 filter starts at output offset {output_offset}"),
        }
    }
}

impl std::error::Error for ResyncError {}

/// Known plaintext: member output offsets `base..base + bytes.len()`.
struct Known<'a> {
    base: u64,
    bytes: &'a [u8],
}

impl Known<'_> {
    fn get(&self, at: u64) -> Option<u8> {
        at.checked_sub(self.base).and_then(|i| usize::try_from(i).ok()).and_then(|i| self.bytes.get(i).copied())
    }
    /// Whether a copy of `len` bytes from `dist` back, at output offset `at`, reproduces the plaintext (byte by byte,
    /// so a copy may overlap its own output).
    fn copies(&self, at: u64, dist: u64, len: u32) -> bool {
        dist != 0
            && at.checked_sub(dist).is_some()
            && (0..u64::from(len)).all(|i| match (self.get(at + i), self.get(at + i - dist)) {
                (Some(a), Some(b)) => a == b,
                _ => false,
            })
    }
}

/// One block read without a window: its packed length (header and payload), its operations and literals, and its
/// code lengths.
struct Block {
    len: usize,
    toks: Vec<Tok>,
    lits: Vec<u8>,
    lens: Box<Lengths>,
    last: bool,
}

/// The block at `at`, if its header checks and its payload decodes to the end; `prev` are the code lengths a block
/// without tables is read with.
fn probe(packed: &[u8], at: usize, prev: Option<&Lengths>, pre: &mut Huff) -> Option<Block> {
    let (header, payload, flags) = block_header(packed.get(at..)?).ok()??;
    let end = at.checked_add(header)?.checked_add(payload)?;
    let mut buf = packed.get(at + header..end)?.to_vec();
    buf.resize(payload + PAD, 0);
    let valid_bits = usize::from(flags & 7) + 1;
    let end_bits = if payload == 0 { 0 } else { (payload - 1) * 8 + valid_bits };
    let mut bits = Bits::new(&buf);
    let lens = if flags & 0x80 != 0 { read_lengths(pre, &mut bits, end_bits).ok()? } else { *prev? };
    let mut tables = Tables::empty();
    tables.build(&lens).ok()?;
    let (mut packed_toks, mut filters, mut lits): (Vec<Packed>, Vec<FilterFields>, Vec<u8>) = Default::default();
    if tokenize(&buf, bits.pos(), end_bits, &tables, (&mut packed_toks, &mut filters, &mut lits), usize::MAX)
        .ok()?
        .is_some()
    {
        return None;
    }
    let toks = packed_toks.into_iter().map(|p| p.get(&filters)).collect();
    Some(Block { len: end - at, toks, lits, lens: Box::new(lens), last: flags & 0x40 != 0 })
}

/// The decoder state the hole erased, as far as it is known.
#[derive(Clone, Copy)]
struct State {
    hist: [Option<u64>; 4],
    last: Option<u32>,
}

impl State {
    fn complete(&self) -> bool {
        self.hist.iter().all(Option::is_some) && self.last.is_some()
    }
}

enum Sim {
    /// The block decodes to the plaintext; this much output.
    Matches(u64),
    Mismatch,
    Filter,
}

/// The one distance (up to `limit` back) whose copy reproduces the plaintext at `at`, if exactly one does.
fn infer(known: &Known<'_>, at: u64, len: u32, limit: u64) -> Option<u64> {
    let mut found = None;
    for d in 1..=limit.min(at.saturating_sub(known.base)) {
        if known.copies(at, d, len) {
            if found.is_some() {
                return None;
            }
            found = Some(d);
        }
    }
    found
}

/// Checks `block`, decoded at output offset `at` with state `st`, against the plaintext, learning the state it
/// uses. Distances the hole erased are taken from the plaintext when exactly one fits.
fn simulate(block: &Block, at: u64, known: &Known<'_>, st: &mut State, window: u64) -> Sim {
    let (mut p, mut li) = (at, 0usize);
    let limit = window.min(SEARCH);
    for tok in &block.toks {
        let (len, dist) = match *tok {
            Tok::Lits(n) => {
                let n = n as usize;
                let Some(lits) = block.lits.get(li..li + n) else { return Sim::Mismatch };
                if lits.iter().enumerate().any(|(i, &b)| known.get(p + i as u64) != Some(b)) {
                    return Sim::Mismatch;
                }
                li += n;
                p += n as u64;
                continue;
            }
            Tok::Filter { .. } => return Sim::Filter,
            Tok::Match { len, dist } => {
                st.hist.copy_within(0..3, 1);
                st.hist[0] = Some(dist);
                (len, dist)
            }
            Tok::Rep { k, len } => {
                let k = usize::from(k) & 3;
                let Some(d) = st.hist[k].or_else(|| infer(known, p, len, limit)) else { return Sim::Mismatch };
                st.hist.copy_within(0..k, 1);
                st.hist[0] = Some(d);
                (len, d)
            }
            Tok::Last => {
                let Some(len) = st.last else { return Sim::Mismatch };
                let Some(d) = st.hist[0].or_else(|| infer(known, p, len, limit)) else { return Sim::Mismatch };
                st.hist[0] = Some(d);
                (len, d)
            }
        };
        if !known.copies(p, dist, len) {
            return Sim::Mismatch;
        }
        st.last = Some(len);
        p += u64::from(len);
    }
    Sim::Matches(p - at)
}

/// Output offsets in `expected` the block's first literals fit at (every offset when it has none to anchor on).
fn candidates(block: &Block, known: &Known<'_>, expected: Range<u64>) -> Vec<u64> {
    // The first literal run, and how much output comes before it (unknown once a `Last` comes first).
    let mut before = 0u64;
    let mut anchor = None;
    for tok in &block.toks {
        match *tok {
            Tok::Lits(n) => {
                anchor = Some((before, &block.lits[..(n as usize).min(32)]));
                break;
            }
            Tok::Match { len, .. } | Tok::Rep { len, .. } => before += u64::from(len),
            _ => break,
        }
    }
    let Some((before, lits)) = anchor.filter(|(_, l)| !l.is_empty()) else { return expected.collect() };
    expected.filter(|&o| lits.iter().enumerate().all(|(i, &b)| known.get(o + before + i as u64) == Some(b))).collect()
}

/// Finds where decoding of a RAR 5.0 compressed member can restart after a hole.
///
/// * `packed`: the member's packed bytes after the hole (across volumes, in order). The first block header after the
///   hole is somewhere in it.
/// * `known_base`, `known`: plaintext of the member known from another copy, at output offsets
///   `known_base..known_base + known.len()`. It must cover the output the restart block starts at and, for the window,
///   as far back as the member's dictionary reaches (or the member's start).
/// * `window`: the member's window ([`super::window_for`]), which bounds match distances.
/// * `expected`: output offsets the first block after the hole may start at (from the hole's position and the
///   member's packing ratio: rar writes blocks of about 16 KB of output).
///
/// Each block found is checked against the plaintext: its literals must equal it, and every copy must reproduce it.
/// Distances and the last length the hole erased are taken from the plaintext when exactly one fits. Blocks are read
/// ahead until the decoder's state is known ([`Resync::complete`]); decoding restarts at the block after them.
pub fn resync(
    packed: &[u8],
    known_base: u64,
    known: &[u8],
    window: Window,
    expected: Range<u64>,
) -> std::result::Result<Resync, ResyncError> {
    let known = Known { base: known_base, bytes: known };
    let mut pre = Huff::new();
    for at in 0..packed.len() {
        // A block with its own tables (one without them needs the tables the hole erased).
        if packed[at] & 0x80 == 0 {
            continue;
        }
        let Some(first) = probe(packed, at, None, &mut pre) else { continue };
        for start in candidates(&first, &known, expected.clone()) {
            let mut st = State { hist: [None; 4], last: None };
            let (mut pos, mut out) = (at, start);
            let mut block = Some(first_clone(&first));
            for _ in 0..MAX_BLOCKS {
                let Some(b) = block.take() else { break };
                match simulate(&b, out, &known, &mut st, window.size) {
                    Sim::Matches(n) => {
                        out += n;
                        pos += b.len;
                    }
                    Sim::Filter => return Err(ResyncError::Filter { output_offset: out }),
                    Sim::Mismatch => break,
                }
                let next = if b.last { None } else { probe(packed, pos, Some(&b.lens), &mut pre) };
                if st.complete() || next.is_none() {
                    let complete = st.complete();
                    let lens = next.as_ref().map_or_else(|| b.lens.clone(), |n| n.lens.clone());
                    return Ok(Resync {
                        packed_offset: pos,
                        output_offset: out,
                        verified: start..out,
                        complete,
                        history: st.hist.map(|d| d.unwrap_or(0)),
                        last_len: st.last.unwrap_or(0),
                        lens,
                    });
                }
                block = next;
            }
        }
    }
    Err(ResyncError::NotFound)
}

fn first_clone(b: &Block) -> Block {
    Block { len: b.len, toks: b.toks.clone(), lits: b.lits.clone(), lens: b.lens.clone(), last: b.last }
}

impl Unpacker {
    /// A decoder that restarts a member at `resync`'s block: its window holds the known plaintext before
    /// [`Resync::output_offset`], and its state is what [`resync`] learned. Feed it the packed bytes from
    /// [`Resync::packed_offset`] on; it writes the member's output from `output_offset` on. `size` is the member's
    /// whole output size. The CRC32 a sink is given covers only that output, so check the member's CRC by combining
    /// it with the CRC of the plaintext before (`crate::crc32::combine`).
    pub fn resume_at(
        window: Window,
        resync: &Resync,
        known_base: u64,
        known: &[u8],
        size: Option<u64>,
    ) -> Result<Self> {
        let mut u = Unpacker::new(window)?;
        u.reset(size);
        let offset = resync.output_offset;
        let from = offset.saturating_sub(u.reach).max(known_base);
        for f in from..offset {
            if let Some(&b) = usize::try_from(f - known_base).ok().and_then(|i| known.get(i)) {
                u.window[(f & u.mask) as usize] = b;
            }
        }
        u.sp = offset;
        u.file_base = 0;
        u.emitted = offset;
        u.history = resync.history;
        u.last_len = resync.last_len;
        u.slot = Slot::filled(Some(*resync.lens));
        u.built = None;
        u.tables_ready = true;
        Ok(u)
    }
}
