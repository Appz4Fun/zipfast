//! Restarting the RAR 5.0 decoder after a hole in a compressed member, from plaintext known from another copy.
//!
//! RAR 5.0 packs a member as a series of byte-aligned blocks, each with its own header (and, in practice, its own
//! Huffman tables). After a run of lost packed bytes, [`resync`] finds the next block that decodes, works out which
//! output offset it starts at by matching what it decodes to (literals, and copies from the window) against the known
//! plaintext, and recovers the decoder's state the hole erased: the four last match distances and the last length. It
//! reads ahead block by block, checking each against the plaintext, until that state is known.
//! [`Unpacker::resume_at`] then starts a decoder at that block with the plaintext before it as its window, so decoding
//! goes on from the recipient's own packed bytes.

use super::parallel::{BUDGET, FilterFields, Packed, SLACK, tokenize};
use super::{Bits, Huff, Lengths, PAD, Slot, Tables, Tok, Unpacker, Window, block_header, read_lengths};
use crate::error::Result;
use std::ops::Range;

/// The farthest back a match distance the hole erased is looked for in the plaintext.
const SEARCH: u64 = 4 << 20;
/// The most blocks read ahead to learn the decoder's state, and the most blocks the scan probes.
const MAX_BLOCKS: usize = 256;
/// The most block steps all the read-aheads of one call take together.
const MAX_STEPS: usize = 4 * MAX_BLOCKS;
/// The most byte comparisons, and bytes probed, one call spends: about a second of work.
const WORK: u64 = 1 << 30;
/// The most literal runs of one block tried as anchors.
const MAX_RUNS: usize = 16;

/// What one [`resync`] call may still spend.
struct Work {
    left: u64,
    steps: usize,
}

impl Work {
    /// Spends `n`; false once the budget is gone.
    fn spend(&mut self, n: u64) -> bool {
        self.left = self.left.saturating_sub(n);
        self.left > 0
    }
}

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
    /// Whether the decoder's whole state was learned from the blocks read ahead (every one of the four last match
    /// distances set by a match in them, and the last length). When `false` the packed bytes, the known plaintext or
    /// the block budget ran out first; decoding still restarts at the first block past what was checked, and a match that uses an unknown distance fails (a distance of 0) or decodes wrong, which the
    /// member's size or CRC catches.
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
    /// A block after the hole (at `packed_offset` in the packed bytes, starting at output offset `output_offset`)
    /// starts a filter: its output differs from the plaintext until the filter runs. Look again from packed bytes
    /// after the filtered output.
    Filter { packed_offset: usize, output_offset: u64 },
    /// A block decodes to the plaintext at more than one offset in the expected range (repeated content): narrow
    /// `expected`.
    Ambiguous,
    /// The search spent its work budget (about a second: long runs of one byte, or literals that recur everywhere,
    /// make each check costly) before finding a restart: narrow `expected`, or look again from later packed bytes.
    Exhausted,
}

impl std::fmt::Display for ResyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => f.write_str("no RAR 5.0 block after the hole decodes to the known plaintext"),
            Self::Filter { packed_offset, output_offset } => {
                write!(f, "a RAR 5.0 block at packed offset {packed_offset} (output {output_offset}) starts a filter")
            }
            Self::Ambiguous => f.write_str("a RAR 5.0 block decodes to the plaintext at more than one offset"),
            Self::Exhausted => f.write_str("the RAR 5.0 resync spent its work budget"),
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
    /// The first output offset past the known plaintext.
    fn end(&self) -> u64 {
        self.base.saturating_add(self.bytes.len() as u64)
    }
    /// Whether a copy of `len` bytes from `dist` back, at output offset `at`, reproduces the plaintext (byte by byte,
    /// so a copy may overlap its own output). Both ends must be known.
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
fn probe(packed: &[u8], at: usize, prev: Option<&Lengths>, pre: &mut Huff, work: &mut Work) -> Option<Block> {
    let (header, payload, flags) = block_header(packed.get(at..)?).ok()??;
    if !work.spend(payload as u64) {
        return None;
    }
    let end = at.checked_add(header)?.checked_add(payload)?;
    // Read in place when the padding past the payload is there (a false header can claim megabytes: no copy for it).
    let copy;
    let buf: &[u8] = match packed.get(at + header..end.checked_add(PAD)?) {
        Some(slice) => slice,
        None => {
            let mut v = packed.get(at + header..end)?.to_vec();
            v.resize(payload + PAD, 0);
            copy = v;
            &copy
        }
    };
    let valid_bits = usize::from(flags & 7) + 1;
    let end_bits = if payload == 0 { 0 } else { (payload - 1) * 8 + valid_bits };
    let mut bits = Bits::new(buf);
    let lens = if flags & 0x80 != 0 { read_lengths(pre, &mut bits, end_bits).ok()? } else { *prev? };
    let mut tables = Tables::empty();
    tables.build(&lens).ok()?;
    let (mut packed_toks, mut filters, mut lits): (Vec<Packed>, Vec<FilterFields>, Vec<u8>) = Default::default();
    // The main decoder's bound on a block's tokens: a block that would take more is not one rar wrote.
    let budget = payload.saturating_mul(BUDGET).saturating_add(SLACK);
    if tokenize(buf, bits.pos(), end_bits, &tables, (&mut packed_toks, &mut filters, &mut lits), budget).ok()?.is_some()
    {
        return None;
    }
    let toks = packed_toks.into_iter().map(|p| p.get(&filters)).collect();
    Some(Block { len: end - at, toks, lits, lens: Box::new(lens), last: flags & 0x40 != 0 })
}

/// The decoder state the hole erased, as far as it is known. A distance taken from the plaintext (`inferred`) is
/// never trusted for the restart: the state is complete only once matches in the blocks read have set all four.
#[derive(Clone, Copy)]
struct State {
    hist: [Option<(u64, bool)>; 4],
    last: Option<u32>,
}

impl State {
    fn complete(&self) -> bool {
        self.hist.iter().all(|h| matches!(h, Some((_, false)))) && self.last.is_some()
    }
}

enum Sim {
    /// The block decodes to the plaintext; this much output.
    Matches(u64),
    /// The block contradicts the plaintext.
    Mismatch,
    /// The block's output runs past the known plaintext before contradicting it.
    Short,
    Filter,
}

/// The length an operation copies (a `Last` the last length, 0 while unknown).
fn len_of(tok: &Tok, st: &State) -> u32 {
    match *tok {
        Tok::Rep { len, .. } | Tok::Match { len, .. } => len,
        Tok::Last => st.last.unwrap_or(0),
        _ => 0,
    }
}

/// The one distance (up to `limit` back) whose copy reproduces the plaintext at `at`, if exactly one does.
fn infer(known: &Known<'_>, at: u64, len: u32, limit: u64, work: &mut Work) -> Option<u64> {
    let mut found = None;
    for d in 1..=limit.min(at.saturating_sub(known.base)) {
        // A cheap first-byte test before the full copy; every distance tried costs.
        if !work.spend(1) || known.get(at) != known.get(at - d) {
            if work.left == 0 {
                return None;
            }
            continue;
        }
        if !work.spend(u64::from(len)) {
            return None;
        }
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
fn simulate(block: &Block, at: u64, known: &Known<'_>, st: &mut State, window: u64, work: &mut Work) -> Sim {
    let (mut p, mut li) = (at, 0usize);
    let limit = window.min(SEARCH);
    for tok in &block.toks {
        let (len, dist) = match *tok {
            Tok::Lits(n) => {
                let n = n as usize;
                let Some(lits) = block.lits.get(li..li + n) else { return Sim::Mismatch };
                for (i, &b) in lits.iter().enumerate() {
                    match known.get(p + i as u64) {
                        Some(k) if k != b => return Sim::Mismatch,
                        Some(_) => {}
                        None => return Sim::Short,
                    }
                }
                li += n;
                p += n as u64;
                continue;
            }
            Tok::Filter { .. } => return Sim::Filter,
            Tok::Match { len, dist } => {
                st.hist.copy_within(0..3, 1);
                st.hist[0] = Some((dist, false));
                (len, dist)
            }
            Tok::Rep { .. } | Tok::Last if p + u64::from(len_of(tok, st)) > known.end() => return Sim::Short,
            Tok::Rep { k, len } => {
                let k = usize::from(k) & 3;
                let Some(h) = st.hist[k].or_else(|| infer(known, p, len, limit, work).map(|d| (d, true))) else {
                    return Sim::Mismatch;
                };
                st.hist.copy_within(0..k, 1);
                st.hist[0] = Some(h);
                (len, h.0)
            }
            Tok::Last => {
                let Some(len) = st.last else { return Sim::Mismatch };
                let Some(h) = st.hist[0].or_else(|| infer(known, p, len, limit, work).map(|d| (d, true))) else {
                    return Sim::Mismatch;
                };
                st.hist[0] = Some(h);
                (len, h.0)
            }
        };
        if p + u64::from(len) > known.end() {
            return Sim::Short;
        }
        if !work.spend(u64::from(len)) {
            return Sim::Short;
        }
        if !known.copies(p, dist, len) {
            return Sim::Mismatch;
        }
        st.last = Some(len);
        p += u64::from(len);
    }
    Sim::Matches(p - at)
}

/// The most offsets one block's first literals may fit at before it is skipped as uninformative.
const MAX_CANDIDATES: usize = 64;

/// The block's output length as far as it is known without the state (a `Last` copies the last length, unknown
/// here: each counts as up to `MAX_LEN` more), or None for a block that starts a filter.
fn known_len(block: &Block) -> Option<(u64, u64)> {
    let (mut len, mut slack) = (0u64, 0u64);
    for tok in &block.toks {
        match *tok {
            Tok::Lits(n) => len += u64::from(n),
            Tok::Match { len: l, .. } | Tok::Rep { len: l, .. } => len += u64::from(l),
            Tok::Last => slack += MAX_LEN,
            Tok::Filter { .. } => return None,
        }
    }
    Some((len, slack))
}

/// The longest copy RAR 5.0 makes.
const MAX_LEN: u64 = 0x1101;

/// Output offsets in `expected` the block fits at, found by searching the known plaintext for one of its literal runs
/// (the first of at least 8 bytes, or failing that 4, that fits no more than 64 places). None for a block whose
/// literals cannot pin its offset.
fn candidates(block: &Block, known: &Known<'_>, expected: &Range<u64>, work: &mut Work) -> Option<Vec<u64>> {
    let mut runs = Vec::new();
    let (mut before, mut li) = (0u64, 0usize);
    for tok in &block.toks {
        match *tok {
            Tok::Lits(n) => {
                let n = (n as usize).min(block.lits.len() - li);
                runs.push((before, &block.lits[li..li + n.min(32)]));
                li += n;
                before += n as u64;
            }
            Tok::Match { len, .. } | Tok::Rep { len, .. } => before += u64::from(len),
            _ => break,
        }
    }
    let long = runs.iter().filter(|(_, l)| l.len() >= 8);
    let short = runs.iter().filter(|(_, l)| (4..8).contains(&l.len()));
    for &(before, lits) in long.chain(short).take(MAX_RUNS) {
        let lo = expected.start.saturating_add(before).max(known.base);
        let hi = expected.end.saturating_add(before).min(known.end());
        if lo >= hi {
            return Some(Vec::new());
        }
        let from = (lo - known.base) as usize;
        let to = ((hi - known.base) as usize + lits.len() - 1).min(known.bytes.len());
        if !work.spend((to - from) as u64) {
            return None;
        }
        let mut found = Vec::new();
        let mut too_many = false;
        for (i, w) in known.bytes[from..to].windows(lits.len()).enumerate() {
            if w == lits {
                if found.len() == MAX_CANDIDATES {
                    too_many = true;
                    break;
                }
                found.push(lo + i as u64 - before);
            }
        }
        if !too_many {
            return Some(found);
        }
    }
    None
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
    let mut work = Work { left: WORK, steps: 0 };
    // Blocks found but not pinned move the expected range on by their output.
    let (mut shift, mut slack) = (0u64, 0u64);
    let mut blocks = 0;
    for at in 0..packed.len() {
        // A block with its own tables (one without them needs the tables the hole erased).
        if packed[at] & 0x80 == 0 {
            continue;
        }
        let Some(first) = probe(packed, at, None, &mut pre, &mut work) else {
            if work.left == 0 {
                return Err(ResyncError::Exhausted);
            }
            continue;
        };
        blocks += 1;
        if blocks > MAX_BLOCKS {
            break;
        }
        let range = expected.start.saturating_add(shift)..expected.end.saturating_add(shift + slack);
        let moved = |shift: &mut u64, slack: &mut u64| {
            if let Some((len, extra)) = known_len(&first) {
                *shift += len;
                *slack += extra;
            }
        };
        let Some(starts) = candidates(&first, &known, &range, &mut work) else {
            if work.left == 0 {
                return Err(ResyncError::Exhausted);
            }
            moved(&mut shift, &mut slack);
            continue;
        };
        // Every offset the block fits at is followed through the read-ahead; exactly one may hold.
        let mut found = None;
        for start in starts {
            let result = match follow(packed, at, &first, start, &known, window, &mut pre, &mut work) {
                Follow::Restart(r) => Ok(r),
                Follow::Filter { packed_offset, output_offset } => {
                    Err(ResyncError::Filter { packed_offset, output_offset })
                }
                Follow::Mismatch => continue,
                Follow::Exhausted => return Err(ResyncError::Exhausted),
            };
            if found.is_some() {
                return Err(ResyncError::Ambiguous);
            }
            found = Some(result);
        }
        if let Some(result) = found {
            return result;
        }
        // Pinned but contradicted everywhere: the block is passed, and so is its output.
        moved(&mut shift, &mut slack);
    }
    Err(ResyncError::NotFound)
}

enum Follow {
    Restart(Resync),
    Filter { packed_offset: usize, output_offset: u64 },
    Mismatch,
    Exhausted,
}

/// Follows blocks from `first` (at packed offset `at`, output offset `start`), checking each against the plaintext,
/// until the decoder's state is known or the blocks run out.
#[allow(clippy::too_many_arguments)]
fn follow(
    packed: &[u8],
    at: usize,
    first: &Block,
    start: u64,
    known: &Known<'_>,
    window: Window,
    pre: &mut Huff,
    work: &mut Work,
) -> Follow {
    let mut st = State { hist: [None; 4], last: None };
    let (mut pos, mut out) = (at, start);
    let mut owned;
    let mut block = first;
    for _ in 0..MAX_BLOCKS {
        work.steps += 1;
        if work.steps > MAX_STEPS || work.left == 0 {
            return Follow::Exhausted;
        }
        // On a copy of the state: a block that is not wholly checked teaches nothing.
        let mut trial = st;
        match simulate(block, out, known, &mut trial, window.size, work) {
            Sim::Matches(n) => {
                st = trial;
                out += n;
                pos += block.len;
            }
            // The block's offset is pinned by its literals before the filter, or by the blocks before it.
            Sim::Filter => return Follow::Filter { packed_offset: pos, output_offset: out },
            Sim::Mismatch => return Follow::Mismatch,
            // The plaintext ends first: restart at this block with what was learned, if a block was checked.
            Sim::Short if out > start => return restart(pos, start, out, &st, &block.lens),
            Sim::Short => return Follow::Mismatch,
        }
        let next = if block.last { None } else { probe(packed, pos, Some(&block.lens), pre, work) };
        if st.complete() || next.is_none() {
            let lens = next.as_ref().map_or_else(|| block.lens.clone(), |n| n.lens.clone());
            return restart(pos, start, out, &st, &lens);
        }
        owned = next.expect("checked above");
        block = &owned;
    }
    // The block budget ran out with the state still unknown: restart at the next block anyway.
    restart(pos, start, out, &st, &block.lens)
}

fn restart(pos: usize, start: u64, out: u64, st: &State, lens: &Lengths) -> Follow {
    Follow::Restart(Resync {
        packed_offset: pos,
        output_offset: out,
        verified: start..out,
        complete: st.complete(),
        history: st.hist.map(|h| h.filter(|&(_, inferred)| !inferred).map_or(0, |(d, _)| d)),
        last_len: st.last.unwrap_or(0),
        lens: Box::new(*lens),
    })
}

impl Unpacker {
    /// A decoder that restarts a member at `resync`'s block: its window holds the known plaintext before
    /// [`Resync::output_offset`], and its state is what [`resync`] learned. Feed it the packed bytes from
    /// [`Resync::packed_offset`] on; it writes the member's output from `output_offset` on. `size` is the member's
    /// whole output size. The CRC32 a sink is given covers only that output, so check the member's CRC by combining
    /// it with the CRC of the plaintext before ([`crate::crc32::combine`]).
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
