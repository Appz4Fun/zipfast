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
use super::{
    Bits, FilterKind, Huff, Lengths, MAX_FILTER_LEN, PAD, Slot, Tables, Tok, Unpacker, Verify, Window, block_header,
    read_lengths,
};
use crate::error::{Error, Result};
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
    /// The most block steps the read-aheads may take together.
    max_steps: usize,
    /// Checked now and then: a [`resync_near`] caller's deadline.
    deadline: Option<std::time::Instant>,
}

impl Work {
    /// Spends `n`; false once the budget is gone.
    fn spend(&mut self, n: u64) -> bool {
        self.left = self.left.saturating_sub(n);
        self.left > 0
    }

    fn new(left: u64, max_steps: usize, deadline: Option<std::time::Instant>) -> Self {
        Work { left, steps: 0, max_steps, deadline }
    }

    /// Whether the deadline passed: the budget is then gone.
    fn late(&mut self) -> bool {
        if self.deadline.is_some_and(|d| std::time::Instant::now() >= d) {
            self.left = 0;
        }
        self.left == 0
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
    /// Filters decoded past on the way to the restart whose output the restart's window still reaches: the decoder
    /// holds that output unfiltered, so [`Unpacker::resume_in_stream`] undoes them in the plaintext it copies there.
    filters: Vec<SeenFilter>,
    /// Every filter that can cover output after the restart was seen ([`resync_near`]): the restart lies a filter's
    /// longest length past the first block checked, so no filter declared before that block reaches it.
    guarded: bool,
    /// [`resync_near`]: output before this offset may have been changed by a filter declared before the first block
    /// checked, which the follow never saw (0 for [`resync`]). The resumed decoder refuses a match that copies from
    /// there into output no known plaintext checks.
    floor: u64,
    /// [`resync_near`] only: the follow covered the restart's whole match window ([`ResyncNear::window_checked`]).
    /// Never set by [`resync`], whose floor of 0 proves nothing.
    window_checked: bool,
}

/// A filter a [`resync_near`] follow decoded past: output offsets `start..start + len` (in the plaintext's
/// coordinates).
#[derive(Clone, Copy, Debug)]
struct SeenFilter {
    start: u64,
    len: u64,
    kind: FilterKind,
}

impl Resync {
    /// Whether every filter that can cover output after the restart was seen on the way to it, so a decoder resumed
    /// here needs no known plaintext past the restart to catch a filter it cannot see (see [`resync_near`]).
    pub fn guarded(&self) -> bool {
        self.guarded
    }
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
    Filter { packed_offset: usize, output_offset: u64, output_end: u64 },
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
            Self::Filter { packed_offset, output_offset, output_end } => {
                write!(
                    f,
                    "a RAR 5.0 block at packed offset {packed_offset} (output {output_offset}) starts a filter over output up to {output_end}"
                )
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
    /// The operations as the tokenizer packs them (8 bytes each, within its memory bound), and their filter fields.
    toks: Vec<Packed>,
    filters: Vec<FilterFields>,
    lits: Vec<u8>,
    lens: Box<Lengths>,
    last: bool,
}

/// The block at `at`, if its header checks and its payload decodes to the end; `prev` are the code lengths a block
/// without tables is read with.
fn probe(packed: &[u8], at: usize, prev: Option<&Lengths>, pre: &mut Huff, work: &mut Work) -> Option<Block> {
    let (header, payload, flags) = block_header(packed.get(at..)?).ok()??;
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
    // Decoding the symbols is the work that grows with the payload: charge the bytes that are there.
    if !work.spend(payload.min(packed.len() - at) as u64) {
        return None;
    }
    let (mut packed_toks, mut filters, mut lits): (Vec<Packed>, Vec<FilterFields>, Vec<u8>) = Default::default();
    // The main decoder's bound on a block's tokens: a block that would take more is not one rar wrote.
    let budget = payload.saturating_mul(BUDGET).saturating_add(SLACK);
    if tokenize(buf, bits.pos(), end_bits, &tables, (&mut packed_toks, &mut filters, &mut lits), budget).ok()?.is_some()
    {
        return None;
    }
    Some(Block { len: end - at, toks: packed_toks, filters, lits, lens: Box::new(lens), last: flags & 0x40 != 0 })
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
    /// The block starts a filter over output up to `output_end`.
    Filter(u64),
    /// The work budget ran out before the block was decided.
    Exhausted,
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
/// `Err` when the work budget runs out first.
fn infer(known: &Known<'_>, at: u64, len: u32, limit: u64, work: &mut Work) -> std::result::Result<Option<u64>, ()> {
    let mut found = None;
    for d in 1..=limit.min(at.saturating_sub(known.base)) {
        // A cheap first-byte test before the full copy; every distance tried costs.
        if !work.spend(1) {
            return Err(());
        }
        if known.get(at) != known.get(at - d) {
            continue;
        }
        if !work.spend(u64::from(len)) {
            return Err(());
        }
        if known.copies(at, d, len) {
            if found.is_some() {
                return Ok(None);
            }
            found = Some(d);
        }
    }
    Ok(found)
}

/// Checks `block`, decoded at output offset `at` with state `st`, against the plaintext, learning the state it
/// uses. Distances the hole erased are taken from the plaintext when exactly one fits.
fn simulate(
    block: &Block,
    at: u64,
    known: &Known<'_>,
    st: &mut State,
    window: u64,
    work: &mut Work,
    mut seen: Option<&mut Vec<SeenFilter>>,
) -> Sim {
    let (mut p, mut li) = (at, 0usize);
    // Output a filter seen changes: there the plaintext is the filtered bytes, and the decoder's window holds them
    // unfiltered, so what lies there is not compared.
    let touches = |seen: &Option<&mut Vec<SeenFilter>>, lo: u64, hi: u64| {
        seen.as_ref().is_some_and(|f| f.iter().any(|f| f.start < hi && f.start + f.len > lo))
    };
    let limit = window.min(SEARCH);
    for tok in block.toks.iter().map(|p| p.get(&block.filters)) {
        let tok = &tok;
        let (len, dist) = match *tok {
            Tok::Lits(n) => {
                let n = n as usize;
                let Some(lits) = block.lits.get(li..li + n) else { return Sim::Mismatch };
                if !work.spend(n as u64) {
                    return Sim::Exhausted;
                }
                if touches(&seen, p, p + n as u64) {
                    if p + n as u64 > known.end() {
                        return Sim::Short;
                    }
                    li += n;
                    p += n as u64;
                    continue;
                }
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
            Tok::Filter { offset, len, kind } => match seen.as_mut() {
                Some(seen) => {
                    seen.push(SeenFilter { start: p + offset, len, kind });
                    continue;
                }
                None => return Sim::Filter(p + offset + len),
            },
            Tok::Match { len, dist } => {
                st.hist.copy_within(0..3, 1);
                st.hist[0] = Some((dist, false));
                (len, dist)
            }
            Tok::Rep { .. } | Tok::Last if p + u64::from(len_of(tok, st)) > known.end() => return Sim::Short,
            Tok::Rep { k, len } => {
                let k = usize::from(k) & 3;
                let h = match st.hist[k] {
                    Some(h) => h,
                    None => match infer(known, p, len, limit, work) {
                        Ok(Some(d)) => (d, true),
                        Ok(None) => return Sim::Mismatch,
                        Err(()) => return Sim::Exhausted,
                    },
                };
                st.hist.copy_within(0..k, 1);
                st.hist[0] = Some(h);
                (len, h.0)
            }
            Tok::Last => {
                let Some(len) = st.last else { return Sim::Mismatch };
                let h = match st.hist[0] {
                    Some(h) => h,
                    None => match infer(known, p, len, limit, work) {
                        Ok(Some(d)) => (d, true),
                        Ok(None) => return Sim::Mismatch,
                        Err(()) => return Sim::Exhausted,
                    },
                };
                st.hist[0] = Some(h);
                (len, h.0)
            }
        };
        if p + u64::from(len) > known.end() {
            return Sim::Short;
        }
        if !work.spend(u64::from(len)) {
            return Sim::Exhausted;
        }
        let end = p + u64::from(len);
        let filtered =
            touches(&seen, p, end) || p.checked_sub(dist).is_some_and(|src| touches(&seen, src, src + u64::from(len)));
        if !filtered && !known.copies(p, dist, len) {
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
    for tok in block.toks.iter().map(|p| p.get(&block.filters)) {
        let tok = &tok;
        match *tok {
            Tok::Lits(n) => len += u64::from(n),
            Tok::Match { len: l, .. } | Tok::Rep { len: l, .. } => len += u64::from(l),
            Tok::Last => slack += MAX_LEN,
            Tok::Filter { .. } => return None,
        }
    }
    Some((len, slack))
}

/// How much plaintext one piece of a literal search covers between deadline checks.
const CHUNK: usize = 1 << 20;

/// The longest copy RAR 5.0 makes.
const MAX_LEN: u64 = 0x1101;

/// Output offsets in `expected` the block fits at, found by searching the known plaintext for one of its literal runs
/// (the first of at least 8 bytes, or failing that 4, that fits no more than 64 places). None for a block whose
/// literals cannot pin its offset.
fn candidates(block: &Block, known: &Known<'_>, expected: &Range<u64>, work: &mut Work) -> Option<Vec<u64>> {
    let mut runs = Vec::new();
    let (mut before, mut li) = (0u64, 0usize);
    for tok in block.toks.iter().map(|p| p.get(&block.filters)) {
        let tok = &tok;
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
        // In pieces of 1 MiB (overlapping by the run's length), so a deadline is noticed during a long scan.
        let mut piece = from;
        while piece < to && !too_many {
            if work.late() {
                return None;
            }
            let end = (piece + CHUNK + lits.len() - 1).min(to);
            find(&known.bytes[piece..end], lits, |i| {
                if found.len() == MAX_CANDIDATES {
                    too_many = true;
                    return false;
                }
                found.push(lo + (piece - from + i) as u64 - before);
                true
            });
            piece += CHUNK;
        }
        if !too_many {
            return Some(found);
        }
    }
    None
}

/// Calls `each` with every offset of `needle` in `hay`, in order, until it returns false. Looks for the needle's
/// first two bytes before comparing the rest.
fn find(hay: &[u8], needle: &[u8], mut each: impl FnMut(usize) -> bool) {
    let Some((&a, rest)) = needle.split_first() else { return };
    if hay.len() < needle.len() {
        return;
    }
    let last = hay.len() - needle.len();
    let mut i = 0;
    while i <= last {
        let Some(k) = hay[i..=last].iter().position(|&b| b == a) else { return };
        i += k;
        if hay[i + 1..i + needle.len()] == *rest && !each(i) {
            return;
        }
        i += 1;
    }
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
    let mut work = Work::new(WORK, MAX_STEPS, None);
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
                Follow::Filter { packed_offset, output_offset, output_end } => {
                    Err(ResyncError::Filter { packed_offset, output_offset, output_end })
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

/// Options for [`resync_near`].
#[derive(Clone, Debug)]
pub struct NearOptions {
    /// Where in `packed` the target's output is thought to lie, from the member's packing ratio or a map. The search
    /// starts just before it and moves back. `None` starts from the end of `packed`.
    pub estimate: Option<usize>,
    /// The most work (byte comparisons, and packed bytes decoded) the search may spend. The default, 2^30, is about
    /// a second.
    pub work: u64,
    /// Gives up after this long, whatever work is left.
    pub deadline: Option<std::time::Duration>,
    /// Look first for a guarded restart ([`Resync::guarded`]): one whose decoding was checked from a filter's
    /// longest length (4 MiB) before it, so it resumes with no plaintext past it, as a handover needs. When there is
    /// none (the target is within 4 MiB of the plaintext's start, or no anchor that far back pins), the closest
    /// restart is given instead. Default true.
    pub guard: bool,
}

impl Default for NearOptions {
    fn default() -> Self {
        NearOptions { estimate: None, work: WORK, deadline: None, guard: true }
    }
}

/// A restart [`resync_near`] found.
#[derive(Clone, Debug)]
pub struct ResyncNear {
    /// The restart, as [`resync`] gives it: start the decoder with [`Unpacker::resume_in_stream`].
    pub resync: Resync,
    /// How far before the target the restart lies: `target - resync.output_offset`.
    pub back: u64,
    /// The output offset of the block the search pinned first; every block from it up to the restart was decoded and
    /// checked against the plaintext (`resync.verified`).
    pub anchor: u64,
    /// The packed offset the successful search started from.
    pub searched_from: usize,
    /// Work spent, in the units of [`NearOptions::work`].
    pub work: u64,
    /// Time spent.
    pub elapsed: std::time::Duration,
    /// Whether the decoding checked from the anchor covers the restart's whole match window (or starts at the
    /// plaintext's start): no filter the follow did not see can have changed output a match after the restart copies
    /// from. When false, the resumed decoder refuses (as [`crate::Error::BadChecksum`]) a match that copies from
    /// before the anchor plus a filter's length into output no known plaintext checks, rather than risk wrong output.
    /// For a later member of a solid stream, a follow from that member's start covers only that member: when earlier
    /// members lie within the window, [`Unpacker::resume_in_stream`] refuses copies from before the member's start
    /// into unchecked output the same way.
    pub window_checked: bool,
}

/// Why [`resync_near`] found no restart.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NearError {
    /// No block from packed offset `lowest` on pins to the plaintext before the target (or every one that does is
    /// contradicted, ambiguous or in a filter's output).
    NotFound { lowest: usize },
    /// The work budget or the deadline ran out; the search had gone back to packed offset `lowest`.
    Exhausted { lowest: usize },
}

impl std::fmt::Display for NearError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound { lowest } => {
                write!(f, "no RAR 5.0 block from packed offset {lowest} on restarts before the target")
            }
            Self::Exhausted { lowest } => {
                write!(f, "the RAR 5.0 resync ran out of budget, having searched back to packed offset {lowest}")
            }
        }
    }
}

impl std::error::Error for NearError {}

/// The output a block found `margin` packed bytes before the estimate is looked for in: back from the target by
/// up to this many times the margin (rar compresses some content far more than 16:1), and at least 1 MiB.
const SPAN_PER_MARGIN: u64 = 32;
/// The most blocks one step of the search pins before it moves further back.
const NEAR_BLOCKS: usize = 64;
/// Blocks in a row whose literals are not in the plaintext before the target: the step is past the target.
const NEAR_MISSES: usize = 4;

/// Finds where decoding can restart as close as possible before output offset `target`, for a handover from one
/// copy of a member to another: the known plaintext usually ends at the target (what the old copy extracted).
///
/// The search starts a little before [`NearOptions::estimate`] in `packed` and moves back geometrically (16 KiB,
/// 64 KiB, ... before it) until a block's literals pin it to the plaintext shortly before the target. From that
/// block it decodes forward without a window, checking every block against the plaintext and learning the decoder's
/// state, and restarts at the last block that starts at or before the target (or at a block that starts a filter,
/// once the state is known, since a decoder starting there sees the filter). So the restart is within a block of
/// the target, whatever packing ratio the content between has, and the work grows with the distance searched, not
/// with the member's size.
///
/// Offsets are as in [`resync`]: `known_base` and `target` are output offsets in the same coordinates as `known`
/// (the solid stream's, for a later member of a solid archive; see [`Unpacker::resume_in_stream`]), and the result's
/// `packed_offset` is in `packed`.
pub fn resync_near(
    packed: &[u8],
    known_base: u64,
    known: &[u8],
    window: Window,
    target: u64,
    options: &NearOptions,
) -> std::result::Result<ResyncNear, NearError> {
    let started = std::time::Instant::now();
    let deadline = options.deadline.map(|d| started + d);
    let mut work = Work::new(options.work, usize::MAX, deadline);
    let known_end = known_base.saturating_add(known.len() as u64);
    let target = target.min(known_end);
    if target <= known_base {
        return Err(NearError::NotFound { lowest: packed.len() });
    }
    // Only the plaintext before the target counts: the block it falls in is where decoding restarts.
    let known = Known { base: known_base, bytes: &known[..(target - known_base) as usize] };
    let mut pre = Huff::new();
    let est = options.estimate.unwrap_or(packed.len()).min(packed.len());
    let checked =
        |r: &Resync, anchor: u64| anchor <= known_base || r.floor <= r.output_offset.saturating_sub(window.reach);
    let done = |(mut r, anchor, from): (Resync, u64, usize), work: &mut Work| {
        // A result found after the deadline is not given: the caller's time is up.
        if work.late() {
            return Err(NearError::Exhausted { lowest: from });
        }
        r.window_checked = checked(&r, anchor);
        Ok(ResyncNear {
            back: target - r.output_offset,
            anchor,
            searched_from: from,
            work: options.work - work.left,
            elapsed: started.elapsed(),
            window_checked: checked(&r, anchor),
            resync: r,
        })
    };
    let mut fallback: Option<(Resync, u64, usize)> = None;
    let keep = |found: (Resync, u64, usize), fallback: &mut Option<(Resync, u64, usize)>| {
        if fallback.as_ref().is_none_or(|f| found.0.output_offset > f.0.output_offset) {
            *fallback = Some(found);
        }
    };
    if options.guard {
        // Best: an anchor that covers the restart's whole match window, so nothing the decoder copies from can hold
        // output of a filter the follow did not see: the window's reach plus a filter's length before the target, or
        // the plaintext's start when the window reaches back that far (a member's start, where no filter can be
        // declared before).
        let cover = target.checked_sub(window.reach.saturating_add(MAX_FILTER_LEN)).filter(|&l| l > known_base);
        let found = match cover {
            Some(l) => search_near(packed, &known, window, l, est, &mut pre, &mut work),
            None => search_near(packed, &known, window, known_base + 1, 0, &mut pre, &mut work),
        };
        match found {
            Ok(found) if checked(&found.0, found.1) && (found.0.guarded || found.1 <= known_base) => {
                return done(found, &mut work);
            }
            Ok(found) => keep(found, &mut fallback),
            Err(NearError::NotFound { .. }) => {}
            Err(e) => return fallback.map_or(Err(e), |f| done(f, &mut work)),
        }
    }
    // Then a guarded restart: an anchor a filter's longest length before the target, followed to it.
    let mut limit = target.checked_sub(MAX_FILTER_LEN).filter(|_| options.guard);
    // A restart can only be at a block start: when one block covers much output, the restart falls before the
    // anchor plus a filter's length, so the anchor is looked for that much before the restart instead (twice).
    for _ in 0..3 {
        let Some(l) = limit.filter(|&l| l > known_base) else { break };
        match search_near(packed, &known, window, l, est, &mut pre, &mut work) {
            Ok(found) if found.0.guarded => return done(found, &mut work),
            Ok(found) => {
                limit = found.0.output_offset.checked_sub(MAX_FILTER_LEN).filter(|&next| next < l);
                keep(found, &mut fallback);
            }
            Err(NearError::NotFound { .. }) => break,
            Err(e) => return fallback.map_or(Err(e), |f| done(f, &mut work)),
        }
    }
    if let Some(f) = fallback.take_if(|f| f.0.guarded) {
        return done(f, &mut work);
    }
    match search_near(packed, &known, window, target, est, &mut pre, &mut work) {
        Ok(found) => {
            let better = fallback.as_ref().is_none_or(|f| found.0.output_offset >= f.0.output_offset);
            done(if better { found } else { fallback.expect("checked") }, &mut work)
        }
        Err(e) => fallback.map_or(Err(e), |f| done(f, &mut work)),
    }
}

/// The search of [`resync_near`]: back from `est` in `packed` until a block pins at an output offset at or before
/// `anchor_max`, then followed through the plaintext (which ends at the target). Returns the restart, the anchor's
/// output offset and the packed offset the successful step started from.
fn search_near(
    packed: &[u8],
    known: &Known<'_>,
    window: Window,
    anchor_max: u64,
    est: usize,
    pre: &mut Huff,
    work: &mut Work,
) -> std::result::Result<(Resync, u64, usize), NearError> {
    // Packed bytes from `scanned` on were searched already, but for the intervals in `pending`: a step that pinned
    // its share of blocks leaves the rest of its interval for after the steps back.
    let mut scanned = packed.len();
    let mut pending = Vec::new();
    let mut margin: usize = 16 << 10;
    let mut range;
    loop {
        let from = est.saturating_sub(margin);
        let span = (margin as u64).saturating_mul(SPAN_PER_MARGIN).max(1 << 20);
        range = anchor_max.saturating_sub(span).max(known.base)..anchor_max;
        match scan_blocks(packed, known, window, &range, from, from..scanned, NEAR_BLOCKS, NEAR_MISSES, pre, work)? {
            Scan::Found(found) => return Ok(found),
            Scan::Capped(at) => pending.push(at..scanned),
            Scan::Done => {}
        }
        scanned = from;
        if from == 0 {
            break;
        }
        margin = margin.saturating_mul(4);
    }
    // The intervals left over, with the widest range, every block of them, until the budget runs out: blocks
    // whose literals are not in the plaintext may be past the target, or inside output a filter declared before
    // them changed, so a run of them proves nothing here.
    while let Some(rest) = pending.pop() {
        let found = scan_blocks(packed, known, window, &range, rest.start, rest, usize::MAX, usize::MAX, pre, work)?;
        if let Scan::Found(found) = found {
            return Ok(found);
        }
    }
    Err(NearError::NotFound { lowest: 0 })
}

enum Scan {
    Found((Resync, u64, usize)),
    /// `cap` blocks were tried, or `misses` blocks in a row were not in the plaintext, without a restart; the
    /// interval's bytes from this offset on were not searched.
    Capped(usize),
    Done,
}

/// Looks through the blocks in `span` of `packed` for one that pins at an output offset in `range` (or before it)
/// and follows it to the target; stops after `cap` blocks are tried, or after `max_misses` blocks in a row whose
/// literals are not in the plaintext (most likely past the target, but possibly inside output a filter changed, so
/// the rest is kept for a later pass). `from` labels the result and errors.
#[allow(clippy::too_many_arguments)]
fn scan_blocks(
    packed: &[u8],
    known: &Known<'_>,
    window: Window,
    range: &Range<u64>,
    from: usize,
    span: Range<usize>,
    cap: usize,
    max_misses: usize,
    pre: &mut Huff,
    work: &mut Work,
) -> std::result::Result<Scan, NearError> {
    let exhausted = Err(NearError::Exhausted { lowest: from });
    let (mut at, mut pinned, mut misses) = (span.start, 0, 0);
    while at < span.end {
        if pinned >= cap || misses >= max_misses {
            return Ok(Scan::Capped(at));
        }
        if work.late() {
            return exhausted;
        }
        if packed[at] & 0x80 == 0 {
            at += 1;
            continue;
        }
        let Some(block) = probe(packed, at, None, pre, work) else {
            if work.left == 0 {
                return exhausted;
            }
            at += 1;
            continue;
        };
        pinned += 1;
        let starts = match candidates(&block, known, range, work) {
            None if work.late() => return exhausted,
            // Literals that recur too often to pin the block: the next block may do.
            None => Vec::new(),
            Some(v) if v.is_empty() => {
                // Not near the limit: earlier (the estimate was early, so follow it from there), or past it.
                match candidates(&block, known, &(known.base..range.start), work) {
                    None if work.late() => return exhausted,
                    Some(v) if !v.is_empty() => {
                        misses = 0;
                        v
                    }
                    // Past the limit, as every later block is then.
                    _ => {
                        misses += 1;
                        Vec::new()
                    }
                }
            }
            Some(v) => {
                misses = 0;
                v
            }
        };
        // Every offset the block fits at is followed to the target; exactly one may hold.
        let mut found = None;
        let mut ambiguous = false;
        for start in starts {
            match follow_near(packed, at, &block, start, known, window, pre, work) {
                Follow::Restart(r) => {
                    if found.is_some() {
                        ambiguous = true;
                        break;
                    }
                    found = Some((r, start, from));
                }
                Follow::Filter { .. } | Follow::Mismatch => {}
                Follow::Exhausted => return exhausted,
            }
        }
        match found {
            Some(found) if !ambiguous => return Ok(Scan::Found(found)),
            // Byte by byte, as `resync` scans: a false header that happens to decode must not hide a block.
            _ => at += 1,
        }
    }
    Ok(Scan::Done)
}

/// A place a [`follow_near`] may restart at: a block start past every filter seen, with the state there.
#[derive(Clone)]
struct Candidate {
    pos: usize,
    out: u64,
    st: State,
    lens: Box<Lengths>,
    seen: usize,
}

/// Follows blocks from `first` (at packed offset `at`, output offset `start`) through every block the plaintext
/// covers, checking each against it and decoding past filters (their output is not compared), and restarts at the
/// last block start that is past every filter seen with the state known. A restart a filter's longest length past
/// `start` is preferred (guarded: no filter declared before `start` reaches it); failing that, the last one.
#[allow(clippy::too_many_arguments)]
fn follow_near(
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
    let mut seen: Vec<SeenFilter> = Vec::new();
    let (mut any, mut guarded): (Option<Candidate>, Option<Candidate>) = (None, None);
    let reached_end;
    let mut owned;
    let mut block = first;
    let note = |pos: usize,
                out: u64,
                st: &State,
                lens: &Lengths,
                seen: &[SeenFilter],
                any: &mut Option<Candidate>,
                guarded: &mut Option<Candidate>| {
        if out > start && st.complete() && seen.iter().all(|f| f.start + f.len <= out) {
            let c = Candidate { pos, out, st: *st, lens: Box::new(*lens), seen: seen.len() };
            if out >= start.saturating_add(MAX_FILTER_LEN) {
                *guarded = Some(c.clone());
            }
            *any = Some(c);
        }
    };
    loop {
        work.steps += 1;
        if work.late() {
            return Follow::Exhausted;
        }
        note(pos, out, &st, &block.lens, &seen, &mut any, &mut guarded);
        let mut trial = st;
        let before = seen.len();
        match simulate(block, out, known, &mut trial, window.size, work, Some(&mut seen)) {
            Sim::Matches(n) => {
                st = trial;
                out += n;
                pos += block.len;
            }
            // The plaintext ends in this block (at the target): restart at the best place before it.
            Sim::Short => {
                seen.truncate(before);
                reached_end = true;
                break;
            }
            Sim::Mismatch | Sim::Filter(_) => return Follow::Mismatch,
            Sim::Exhausted => return Follow::Exhausted,
        }
        let next = if block.last { None } else { probe(packed, pos, Some(&block.lens), pre, work) };
        if work.left == 0 {
            return Follow::Exhausted;
        }
        let Some(next) = next else {
            // The member's last block ending exactly where the plaintext does reaches its end too.
            reached_end = block.last && out == known.end();
            note(pos, out, &st, &block.lens, &seen, &mut any, &mut guarded);
            break;
        };
        owned = next;
        block = &owned;
    }
    if work.late() {
        return Follow::Exhausted;
    }
    // A true anchor's blocks decode, checked, all the way to the plaintext's end (the target). A follow that runs out
    // of blocks first matched the plaintext only where its content repeats: packed bytes from past the target pinned
    // where the same bytes occur before it. Refused, however long the stretch it matched.
    if !reached_end {
        return Follow::Mismatch;
    }
    let is_guarded = guarded.is_some();
    let Some(c) = guarded.or(any) else { return Follow::Mismatch };
    // Only filters the restart's window reaches matter to it.
    let reach = c.out.saturating_sub(window.reach);
    let filters = seen[..c.seen].iter().filter(|f| f.start + f.len > reach).copied().collect();
    // A filter declared before the anchor (`start`) may have changed output up to a filter's longest length past it.
    let floor = start.saturating_add(MAX_FILTER_LEN).min(c.out);
    Follow::Restart(resync_at(c.pos, start, c.out, &c.st, &c.lens, filters, is_guarded, floor))
}

enum Follow {
    Restart(Resync),
    Filter { packed_offset: usize, output_offset: u64, output_end: u64 },
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
        if work.steps > work.max_steps || (work.steps.is_multiple_of(64) && work.late()) || work.left == 0 {
            return Follow::Exhausted;
        }
        // On a copy of the state: a block that is not wholly checked teaches nothing.
        let mut trial = st;
        match simulate(block, out, known, &mut trial, window.size, work, None) {
            Sim::Matches(n) => {
                st = trial;
                out += n;
                pos += block.len;
            }
            // A filter is seen whole by a decoder that starts at its block: restart there when the state is known.
            // The block's offset is pinned by its literals before the filter, or by the blocks before it.
            Sim::Filter(output_end) => return Follow::Filter { packed_offset: pos, output_offset: out, output_end },
            Sim::Mismatch => return Follow::Mismatch,
            // The plaintext ends first: restart at this block with what was learned, if a block was checked.
            Sim::Short if out > start => return restart(pos, start, out, &st, &block.lens),
            Sim::Short => return Follow::Mismatch,
            Sim::Exhausted => return Follow::Exhausted,
        }
        let next = if block.last { None } else { probe(packed, pos, Some(&block.lens), pre, work) };
        if work.left == 0 {
            return Follow::Exhausted;
        }
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
    Follow::Restart(resync_at(pos, start, out, st, lens, Vec::new(), false, 0))
}

#[allow(clippy::too_many_arguments)]
fn resync_at(
    pos: usize,
    start: u64,
    out: u64,
    st: &State,
    lens: &Lengths,
    filters: Vec<SeenFilter>,
    guarded: bool,
    floor: u64,
) -> Resync {
    {
        Resync {
            packed_offset: pos,
            output_offset: out,
            verified: start..out,
            complete: st.complete(),
            history: st.hist.map(|h| h.filter(|&(_, inferred)| !inferred).map_or(0, |(d, _)| d)),
            last_len: st.last.unwrap_or(0),
            lens: Box::new(*lens),
            filters,
            guarded,
            floor,
            window_checked: false,
        }
    }
}

impl Unpacker {
    /// A decoder that restarts a member at `resync`'s block: its window holds the known plaintext before
    /// [`Resync::output_offset`], and its state is what [`resync`] learned. Feed it the packed bytes from
    /// [`Resync::packed_offset`] on; it writes the member's output from `output_offset` on. `size` is the member's
    /// whole output size. The CRC32 a sink is given covers only that output, so check the member's CRC by combining
    /// it with the CRC of the plaintext before ([`crate::crc32::combine`]).
    ///
    /// A filter declared in a block the hole erased can cover output after the restart; this decoder cannot see it
    /// and would write that output unfiltered. So the output is checked against `known` until it is past the longest
    /// reach such a filter can have (a filter's 4 MiB length past the restart, or the member's end), and a difference
    /// is an error ([`crate::Error::BadChecksum`]) before those bytes reach the sink: resync again from packed bytes
    /// past it. After that window no plaintext is needed. `known` must cover the window, or this fails (with no
    /// `size`, the window ends where `known` does, at the latest).
    pub fn resume_at(
        window: Window,
        resync: &Resync,
        known_base: u64,
        known: &[u8],
        size: Option<u64>,
    ) -> Result<Self> {
        Self::resume_in_stream(window, resync, 0, known_base, known, size)
    }

    /// [`Self::resume_at`] for a member that starts at stream offset `member_start` of a solid stream, such as the
    /// second file of a solid archive.
    ///
    /// Every offset is in the solid stream's coordinates: [`Resync::output_offset`], `known_base` (and so the
    /// plaintext `known`, which may reach back into earlier members, as matches do), and the result's stream
    /// position. `size` is the member's own output size, and the sink gets the member's output from
    /// `output_offset - member_start` on. E8/E8E9/ARM filters address relative to the member's start, as RAR does
    /// for each file of a solid stream, so a member resumed with the wrong `member_start` decodes filtered data
    /// wrongly; the known-plaintext window catches that within its reach. `member_start` must not lie past
    /// `output_offset`; `resume_at` is this with `member_start` 0.
    pub fn resume_in_stream(
        window: Window,
        resync: &Resync,
        member_start: u64,
        known_base: u64,
        known: &[u8],
        size: Option<u64>,
    ) -> Result<Self> {
        let offset = resync.output_offset;
        if member_start > offset {
            return Err(Error::Unsupported(format!(
                "resuming RAR 5.0 output at stream offset {offset} inside a member that starts later, at {member_start}"
            )));
        }
        let known_end = known_base.saturating_add(known.len() as u64);
        // A member of unknown size may end where the known plaintext does.
        let member_end = size.map_or(known_end, |s| member_start.saturating_add(s));
        let mut check_end = offset.saturating_add(MAX_FILTER_LEN).min(member_end);
        // A guarded restart (every filter that can reach past it was seen) needs no plaintext past it; what there is
        // is still checked.
        // ... as is a restart followed from the member's start: a filter covers output of its own member only.
        let from_member_start = resync.floor > 0 && resync.verified.start <= member_start;
        if resync.guarded || from_member_start {
            check_end = check_end.min(known_end.max(offset));
        }
        if known_base > offset || known_end < check_end {
            return Err(Error::Unsupported(format!(
                "resuming RAR 5.0 output at {offset} needs known plaintext for {offset}..{check_end} to check it \
                 against filters declared before the restart; given {known_base}..{known_end}"
            )));
        }
        let mut u = Unpacker::new(window)?;
        u.reset(size);
        if check_end > offset {
            let bytes = known[(offset - known_base) as usize..(check_end - known_base) as usize].to_vec();
            // the window is checked in the member's output coordinates, as `emitted` counts them
            u.verify = Some(Box::new(Verify { end: check_end - member_start, bytes }));
        }
        let from = offset.saturating_sub(u.reach).max(known_base);
        for f in from..offset {
            if let Some(&b) = usize::try_from(f - known_base).ok().and_then(|i| known.get(i)) {
                u.window[(f & u.mask) as usize] = b;
            }
        }
        // The decoder's window holds filtered output as it was before the filter ran: undo the filters seen.
        for f in &resync.filters {
            let end = f.start + f.len;
            if end <= from || f.start < member_start {
                continue;
            }
            // Undoing it needs all of its output; a window holding part of it unfiltered-in-plaintext would decode a
            // later copy from there wrong.
            if f.start < known_base || end > known_end {
                return Err(Error::Unsupported(format!(
                    "resuming RAR 5.0 output at {offset} needs known plaintext for {}..{} to undo a filter whose output \
                     the window still holds; given {known_base}..{known_end}",
                    f.start.min(known_base),
                    end.max(known_end)
                )));
            }
            let mut bytes = known[(f.start - known_base) as usize..(end - known_base) as usize].to_vec();
            super::unapply_filter(f.kind, f.start - member_start, &mut bytes);
            for (i, &b) in bytes.iter().enumerate() {
                let at = f.start + i as u64;
                if at >= from && at < offset {
                    u.window[(at & u.mask) as usize] = b;
                }
            }
        }
        u.sp = offset;
        u.file_base = member_start;
        u.emitted = offset - member_start;
        // Matches into output nothing checks may not copy from before the floor (see `Resync::floor`). A follow from
        // the member's start saw every filter of this member; when earlier members of a solid stream lie within the
        // window, their filters were never seen (and the decoder held their output unfiltered), so the floor is
        // the member's start, unless it is the stream's start.
        if resync.floor > 0 {
            let floor = if !from_member_start {
                resync.floor.min(offset)
            } else if member_start > 0 && offset.saturating_sub(window.reach) < member_start {
                member_start
            } else {
                0
            };
            if floor > 0 {
                u.floor = floor;
                u.floor_from = check_end;
            }
        }
        u.history = resync.history;
        u.last_len = resync.last_len;
        u.slot = Slot::filled(Some(*resync.lens));
        u.built = None;
        u.tables_ready = true;
        // a resumed member's packed bytes run on to the encryption's block end: stop at the block flagged last
        u.stop_at_last = true;
        Ok(u)
    }
    /// [`Self::resume_in_stream`] for a handover that holds the output before the restart but not the packed bytes
    /// far before it: the window is seeded from `known` (the held plaintext, solid-stream offsets from
    /// `known_base`, ending at or past the restart), and no plaintext past the restart is needed.
    ///
    /// The output is **unverified** unless [`Self::seed_checked`] says otherwise. RAR's window holds output as it
    /// was before filters (E8, E8E9, ARM, delta) ran, while held plaintext is filtered output; a filter declared
    /// before the restart, which the follow to it did not see, may have changed bytes a later match copies, and then
    /// the copy writes wrong bytes. Filters the follow did see are undone where `known` holds all their output.
    /// Where the window is not proven, a match that copies from unproven output into output nothing checks is noted
    /// as a [`SeedSuspect`] ([`Self::seed_suspect`]) and decoded anyway, so the member's CRC32 or BLAKE2sp at its
    /// end decides; with `strict` it is refused instead ([`crate::Error::BadChecksum`]), as a checked decoder
    /// refuses it. A copy from before `known_base` (window bytes never seeded) is noted the same way. The first
    /// filter the decoder meets is noted too, as a weaker sign.
    ///
    /// A restart that is not guarded ([`Resync::guarded`]; a plain [`resync`] result never is) can have a filter
    /// declared before it cover output after it, which only held plaintext past the restart could catch: such a
    /// restart is noted as [`super::SeedReason::Unguarded`] at once, and refused with `strict` (as
    /// [`crate::Error::Unsupported`]).
    ///
    /// The window is proven (checked) when the follow to the restart covered it: [`ResyncNear::window_checked`] (a
    /// follow from the member's start, or from the dictionary plus a filter's reach before the restart), with
    /// `known` covering the window and every filter seen undone. Filter records sit inside Huffman-coded blocks, so
    /// no scan cheaper than that follow, over the packed bytes before the restart, can show there were none.
    pub fn resume_seeded(
        window: Window,
        resync: &Resync,
        member_start: u64,
        known_base: u64,
        known: &[u8],
        size: Option<u64>,
        strict: bool,
    ) -> Result<Self> {
        let offset = resync.output_offset;
        if member_start > offset {
            return Err(Error::Unsupported(format!(
                "resuming RAR 5.0 output at stream offset {offset} inside a member that starts later, at {member_start}"
            )));
        }
        let known_end = known_base.saturating_add(known.len() as u64);
        if known_base > offset || known_end < offset {
            return Err(Error::Unsupported(format!(
                "seeding a RAR 5.0 decoder at {offset} needs held plaintext reaching it; given {known_base}..{known_end}"
            )));
        }
        let member_end = size.map_or(known_end, |s| member_start.saturating_add(s));
        // what held plaintext there is past the restart is still checked
        let check_end = offset.saturating_add(MAX_FILTER_LEN).min(member_end).min(known_end.max(offset));
        let mut u = Unpacker::new(window)?;
        u.reset(size);
        if check_end > offset {
            let bytes = known[(offset - known_base) as usize..(check_end - known_base) as usize].to_vec();
            u.verify = Some(Box::new(Verify { end: check_end - member_start, bytes }));
        }
        let window_start = offset.saturating_sub(u.reach);
        let from = window_start.max(known_base);
        for f in from..offset {
            if let Some(&b) = usize::try_from(f - known_base).ok().and_then(|i| known.get(i)) {
                u.window[(f & u.mask) as usize] = b;
            }
        }
        // The lowest stream offset whose window bytes are proven: everything when the follow covered the window
        // (`resync_near` says so; a plain `resync` result never proves it), else the follow's floor, or the restart
        // itself when nothing before it was followed. Raised past seen filters whose output `known` lacks (they
        // cannot be undone) and to `known_base` when the window reaches before it (never seeded; nothing before the
        // stream's start exists).
        let from_member_start = resync.floor > 0 && resync.verified.start <= member_start;
        let mut floor = if resync.window_checked {
            0
        } else if from_member_start {
            if member_start > 0 && window_start < member_start { member_start } else { 0 }
        } else if resync.floor > 0 {
            resync.floor.min(offset)
        } else {
            offset
        };
        // A filter declared before the restart can cover output past it, up to a filter's longest length, unless
        // the restart is guarded; held plaintext past the restart is the only other check.
        // with the member's size unknown its end is too: a filter may reach its full length past the restart
        let reach_end =
            offset.saturating_add(MAX_FILTER_LEN).min(size.map_or(u64::MAX, |s| member_start.saturating_add(s)));
        let unguarded = !resync.guarded && !resync.window_checked && check_end < reach_end;
        if unguarded && strict {
            return Err(Error::Unsupported(format!(
                "seeding a RAR 5.0 decoder at {offset} strictly needs a guarded restart (resync_near) or held \
                 plaintext to {reach_end}, past any filter declared before it; given {known_base}..{known_end}"
            )));
        }
        for f in &resync.filters {
            let end = f.start + f.len;
            if end <= from || f.start < member_start {
                continue;
            }
            if f.start < known_base || end > known_end {
                floor = floor.max(end.min(offset));
                continue;
            }
            let mut bytes = known[(f.start - known_base) as usize..(end - known_base) as usize].to_vec();
            super::unapply_filter(f.kind, f.start - member_start, &mut bytes);
            for (i, &b) in bytes.iter().enumerate() {
                let at = f.start + i as u64;
                if at >= from && at < offset {
                    u.window[(at & u.mask) as usize] = b;
                }
            }
        }
        if known_base > window_start && known_base > 0 {
            floor = floor.max(known_base);
        }
        if floor > 0 {
            u.floor = floor;
            u.floor_from = check_end;
        }
        let mut seed = super::SeedState::new(strict, known_base, floor == 0 && !unguarded);
        if unguarded {
            seed.note_unguarded(offset - member_start);
        }
        u.seed = Some(Box::new(seed));
        u.sp = offset;
        u.file_base = member_start;
        u.emitted = offset - member_start;
        u.history = resync.history;
        u.last_len = resync.last_len;
        u.slot = Slot::filled(Some(*resync.lens));
        u.built = None;
        u.tables_ready = true;
        u.stop_at_last = true;
        Ok(u)
    }
}
