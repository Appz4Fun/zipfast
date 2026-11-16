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

//! Bounded, serial RAR4 version-29 LZ core, continuing across the parts of a split member and the members of a
//! solid stream.
//! Original implementation from the SDD factual worksheet and independent vectors.
//! No external decoder implementation was copied or translated.

use super::Sink;
use crate::extract::Cancellation;

mod filters;
mod legacy;
pub(crate) mod lifecycle;
mod ppm;
use lifecycle::Lifecycle;
pub(crate) use lifecycle::{CoreBinding, CoreFrame};

#[derive(Debug, PartialEq)]
pub(crate) enum Rar4FeedState {
    NeedInput,
    Complete,
}
#[derive(Debug, PartialEq)]
pub(crate) enum Rar4UnsupportedMode {
    VmFilter,
}
#[derive(Debug)]
pub(crate) enum Rar4DecodeError {
    Unsupported(Rar4UnsupportedMode),
    Malformed(&'static str),
    DecodedSize { expected: u64, actual: u64 },
    PackedSize { expected: u64, actual: u64 },
    InvalidDictionary { requested: u64 },
    WindowLimit { requested: u64, allowed: u64 },
    Allocation { requested: u64 },
    CounterOverflow,
    Canceled,
    Sink(crate::error::Error),
    State,
    Binding,
}

const CHUNK: usize = 65536;
const OUTPUT: usize = 32768;
/// PPM input decoded only while this much is buffered, until the member's data is all in: one character never
/// reads more (a model of order 64 escapes at most 64 times, each normalizing at most 4 bytes).
const PPM_LOOKAHEAD: usize = 4096;

impl Rar4DecodeError {
    pub(crate) fn detailed(self, scope: crate::error::RarScope) -> crate::error::RarFault {
        use crate::error::{
            Error, IoOperation, RarFailure, RarFault, RarIntegrityReason, RarPasswordEvidence, RarResource,
            RarUnsupported,
        };
        let integrity = |reason| RarFailure::integrity(scope.clone(), reason, RarPasswordEvidence::NotEncrypted, false);
        let (failure, legacy) = match self {
            Self::Unsupported(mode) => {
                let label = match mode {
                    Rar4UnsupportedMode::VmFilter => "VM/filter payload",
                };
                // This optional legacy label is bounded (at most 17 bytes) and
                // allocated only in the consumer adaptation, never core decoding.
                let mut message = String::new();
                let legacy = if message.try_reserve_exact(label.len()).is_ok() {
                    message.push_str(label);
                    Error::Unsupported(message)
                } else {
                    Error::Io(std::io::ErrorKind::OutOfMemory.into())
                };
                (RarFailure::Unsupported(RarUnsupported::Rar4Feature(label)), legacy)
            }
            Self::State | Self::Binding => (
                RarFailure::Internal(crate::error::RarInternal::Invariant("RAR4 completion/source binding")),
                Error::Corrupt("RAR4 completion/source binding"),
            ),
            Self::Malformed(reason) => (integrity(RarIntegrityReason::Decoder(reason)), Error::Corrupt(reason)),
            Self::DecodedSize { expected, actual } => {
                (integrity(RarIntegrityReason::DecodedSize { expected, actual }), Error::Corrupt("RAR4 decoded size"))
            }
            Self::PackedSize { expected, actual } if actual < expected => {
                (integrity(RarIntegrityReason::TruncatedData), Error::Truncated)
            }
            Self::PackedSize { .. } => (
                integrity(RarIntegrityReason::Decoder("RAR4 packed extent exceeded")),
                Error::Corrupt("RAR4 packed extent exceeded"),
            ),
            Self::InvalidDictionary { requested } => {
                (integrity(RarIntegrityReason::InvalidDictionary { requested }), Error::Corrupt("RAR4 dictionary"))
            }
            Self::WindowLimit { requested, allowed } => (
                RarFailure::Limit {
                    resource: RarResource::DictionarySize,
                    requested: Some(requested),
                    allowed: Some(allowed),
                },
                Error::Corrupt("RAR4 dictionary limit"),
            ),
            Self::Allocation { requested } => (
                RarFailure::Limit {
                    resource: RarResource::DictionaryAllocation,
                    requested: Some(requested),
                    allowed: None,
                },
                Error::Corrupt("RAR4 dictionary allocation"),
            ),
            Self::CounterOverflow => (
                RarFailure::Limit { resource: RarResource::Counter, requested: None, allowed: Some(u64::MAX) },
                Error::Corrupt("RAR4 work counter overflow"),
            ),
            Self::Canceled => (RarFailure::Canceled, Error::Io(std::io::Error::from(std::io::ErrorKind::Interrupted))),
            Self::Sink(Error::Io(source)) => return RarFault::output(IoOperation::Write, None, None, source, true),
            Self::Sink(error) => return crate::batch::decoder_failure(error, scope, RarPasswordEvidence::NotEncrypted),
        };
        RarFault::new(failure, legacy)
    }
}

type DecodeResult<T> = Result<T, Rar4DecodeError>;

struct Work {
    operations: u64,
    cancel: Option<Cancellation>,
    #[cfg(test)]
    cancel_at: Option<u64>,
}
impl Work {
    fn check(&self) -> DecodeResult<()> {
        if self.cancel.as_ref().is_some_and(Cancellation::is_canceled) {
            Err(Rar4DecodeError::Canceled)
        } else {
            Ok(())
        }
    }
    fn tick(&mut self, amount: u64) -> DecodeResult<()> {
        let before = self.operations;
        self.operations = self.operations.checked_add(amount).ok_or(Rar4DecodeError::CounterOverflow)?;
        #[cfg(test)]
        if self.cancel_at.is_some_and(|at| self.operations >= at) {
            if let Some(cancel) = &self.cancel {
                cancel.cancel();
            }
            self.cancel_at = None;
        }
        if self.operations / 256 != before / 256 {
            self.check()?;
        }
        Ok(())
    }
}

#[derive(Default)]
struct Bits {
    acc: u64,
    count: u8,
    #[cfg(test)]
    read_bytes: u64,
    #[cfg(test)]
    last_value: u32,
}
impl Bits {
    fn take(&mut self, n: u8, input: &mut &[u8]) -> Option<u32> {
        debug_assert!(n <= 18);
        while self.count < n {
            let (&byte, tail) = input.split_first()?;
            *input = tail;
            self.acc = (self.acc << 8) | u64::from(byte);
            self.count += 8;
            #[cfg(test)]
            {
                self.read_bytes += 1;
            }
        }
        self.count -= n;
        let value = (self.acc >> self.count) as u32;
        self.acc &= (1u64 << self.count) - 1;
        #[cfg(test)]
        {
            self.last_value = value;
        }
        Some(value)
    }
    fn align(&mut self) {
        let discard = self.count % 8;
        self.count -= discard;
        self.acc &= (1u64 << self.count) - 1;
    }
}

struct Huff {
    count: [u16; 16],
    first: [u32; 16],
    offset: [usize; 16],
    symbols: [u16; 299],
    used: usize,
}
impl Huff {
    fn empty() -> Self {
        Self { count: [0; 16], first: [0; 16], offset: [0; 16], symbols: [0; 299], used: 0 }
    }
    fn build(&mut self, lengths: &[u8], work: &mut Work) -> DecodeResult<()> {
        self.count = [0; 16];
        self.used = 0;
        for &length in lengths {
            work.tick(1)?;
            if length > 15 {
                return Err(Rar4DecodeError::Malformed("code length"));
            }
            if length != 0 {
                self.count[length as usize] += 1;
                self.used += 1;
            }
        }
        let mut offset = 0;
        let mut code = 0;
        for n in 1..16 {
            work.tick(1)?;
            code = (code + u32::from(self.count[n - 1])) << 1;
            if code + u32::from(self.count[n]) > 1 << n {
                return Err(Rar4DecodeError::Malformed("oversubscribed Huffman table"));
            }
            self.first[n] = code;
            self.offset[n] = offset;
            offset += self.count[n] as usize;
        }
        let mut next = self.offset;
        for (symbol, &length) in lengths.iter().enumerate() {
            work.tick(1)?;
            if length != 0 {
                self.symbols[next[length as usize]] = symbol as u16;
                next[length as usize] += 1;
            }
        }
        work.check()
    }
}

#[derive(Clone, Copy)]
enum Phase {
    Align,
    Mode,
    Retain,
    Bc {
        index: usize,
    },
    BcRun {
        index: usize,
    },
    BuildBc,
    Lengths {
        index: usize,
    },
    LengthRun {
        index: usize,
        kind: u16,
    },
    BuildTables,
    Token,
    End,
    EndHint,
    Length {
        index: usize,
        recent: Option<usize>,
    },
    LengthExtra {
        base: u64,
        bits: u8,
        recent: Option<usize>,
    },
    RecentLength {
        slot: usize,
    },
    Distance {
        length: u64,
    },
    DistanceBits {
        length: u64,
        index: usize,
    },
    Low {
        length: u64,
        base: u64,
    },
    Short {
        index: usize,
    },
    Copy {
        distance: u64,
        left: u64,
    },
    /// symbol 257: a filter record follows
    VmFirst,
    VmLength {
        first: u32,
        wide: bool,
    },
    VmCode {
        first: u32,
        left: usize,
    },
    /// a PPM block's header
    PpmInit,
    PpmChar,
    /// after the escape character
    PpmEscape,
    /// a filter record inside a PPM block
    PpmVmCode {
        first: u32,
        left: usize,
    },
    /// a RAR 1.5 or 2.0 engine's next code
    Legacy,
    Complete,
}

impl Phase {
    fn ppm(self) -> bool {
        matches!(self, Phase::PpmInit | Phase::PpmChar | Phase::PpmEscape | Phase::PpmVmCode { .. })
    }
}

pub(crate) struct Rar4Decoder {
    work: Work,
    dictionary: Vec<u8>,
    packed: u64,
    fed: u64,
    expected: u64,
    produced: u64,
    bits: Bits,
    phase: Phase,
    saved_phase: Phase,
    chain_base: u64,
    fetched: u64,
    binding: CoreBinding,
    lifecycle: Lifecycle,
    poisoned: bool,
    finished: bool,
    old: [u8; 404],
    lengths: [u8; 404],
    bc_lengths: [u8; 20],
    tables: [Huff; 5], // BC, LD, DD, LDD, RD
    prefix: u32,
    depth: usize,
    recent: [u64; 4], // zero explicitly means unavailable
    last_length: u64,
    low: u64,
    low_repeats: u8,
    output: [u8; OUTPUT],
    filled: usize,
    table_builds: u64,
    /// Solid chaining: past a member's last byte, read its end-of-file marker for the next member's start.
    track_boundary: bool,
    /// Reading the end-of-file marker after the member's output is complete.
    in_tail: bool,
    /// Where the next solid member starts: at a token, or at new tables.
    boundary: Option<Phase>,
    /// the PPMd model, once a PPM block has started one; a solid stream keeps it
    ppm: Option<Box<ppm::Ppm>>,
    /// in PPM blocks, the byte that says what follows isn't a literal
    esc: u8,
    /// PPM input not decoded yet, and how much of it is
    ppm_in: Vec<u8>,
    ppm_pos: usize,
    /// input a PPM block left when LZ blocks follow: read before any more is fed
    carry: Vec<u8>,
    /// the member's data is all in: PPM decodes to its end
    finishing: bool,
    /// the filters defined, and blocks waiting for their bytes
    filters: filters::Filters,
    /// a filter record's bytes as they arrive
    vm_code: Vec<u8>,
    /// decoded bytes held from the first waiting block's start until it can be filtered
    hold: Vec<u8>,
    hold_start: u64,
    /// the member's unpack version, and the RAR 1.5 or 2.0 engine that decodes it
    version: u8,
    legacy: Option<Box<legacy::Engine>>,
    /// the bit within the next buffered byte where the legacy engine reads on
    legacy_bit: u32,
    #[cfg(test)]
    first_cross: Option<(u64, u64, u64)>,
    #[cfg(test)]
    trace: Option<tests::BoundaryTrace>,
    #[cfg(test)]
    successor_trace: Option<tests::successor::SuccessorTrace>,
}

impl Rar4Decoder {
    pub(crate) fn new(
        dictionary: u64,
        packed: u64,
        unpacked: u64,
        window_limit: u64,
        cancel: Cancellation,
    ) -> DecodeResult<Self> {
        Self::new_with_cancel(dictionary, packed, unpacked, window_limit, Some(cancel))
    }
    pub(crate) fn new_with_cancel(
        dictionary: u64,
        packed: u64,
        unpacked: u64,
        window_limit: u64,
        cancel: Option<Cancellation>,
    ) -> DecodeResult<Self> {
        let mut work = Work {
            operations: 0,
            cancel,
            #[cfg(test)]
            cancel_at: tests::take_init_cancel(),
        };
        work.check()?;
        if !(65536..=4194304).contains(&dictionary) || !dictionary.is_power_of_two() {
            return Err(Rar4DecodeError::InvalidDictionary { requested: dictionary });
        }
        if dictionary > window_limit {
            return Err(Rar4DecodeError::WindowLimit { requested: dictionary, allowed: window_limit });
        }
        let mut history = Vec::new();
        work.check()?;
        history
            .try_reserve_exact(dictionary as usize)
            .map_err(|_| Rar4DecodeError::Allocation { requested: dictionary })?;
        let actual = history.capacity() as u64;
        if actual > window_limit.min(4194304) {
            return Err(Rar4DecodeError::WindowLimit { requested: actual, allowed: window_limit.min(4194304) });
        }
        while history.len() < dictionary as usize {
            work.check()?;
            let next = (history.len() + CHUNK).min(dictionary as usize);
            let work_bytes = next - history.len();
            history.resize(next, 0);
            work.tick(work_bytes as u64)?;
        }
        let binding =
            CoreBinding::new(CoreFrame { ordinal: 0, packed, unpacked, unpack_version: 29, method: 0x33, dictionary })?;
        let mut decoder = Self {
            work,
            dictionary: history,
            packed,
            fed: 0,
            expected: unpacked,
            produced: 0,
            bits: Bits::default(),
            phase: if unpacked == 0 { Phase::Complete } else { Phase::Align },
            saved_phase: Phase::Align,
            chain_base: 0,
            fetched: 0,
            binding,
            lifecycle: Lifecycle::Active,
            poisoned: false,
            finished: false,
            old: [0; 404],
            lengths: [0; 404],
            bc_lengths: [0; 20],
            tables: std::array::from_fn(|_| Huff::empty()),
            prefix: 0,
            depth: 0,
            recent: [0; 4],
            last_length: 0,
            low: 0,
            low_repeats: 0,
            output: [0; OUTPUT],
            filled: 0,
            table_builds: 0,
            track_boundary: false,
            in_tail: false,
            boundary: None,
            ppm: None,
            esc: 2,
            ppm_in: Vec::new(),
            ppm_pos: 0,
            carry: Vec::new(),
            finishing: false,
            filters: filters::Filters::default(),
            vm_code: Vec::new(),
            hold: Vec::new(),
            hold_start: 0,
            version: 29,
            legacy: None,
            legacy_bit: 0,
            #[cfg(test)]
            first_cross: None,
            #[cfg(test)]
            trace: None,
            #[cfg(test)]
            successor_trace: None,
        };
        decoder.work.tick(std::mem::size_of::<Self>() as u64)?;
        decoder.work.check()?;
        Ok(decoder)
    }
    pub(crate) fn feed(&mut self, bytes: &[u8], sink: &mut dyn Sink) -> DecodeResult<Rar4FeedState> {
        if self.poisoned || self.finished {
            return Err(Rar4DecodeError::Malformed("decoder is no longer usable"));
        }
        if self.lifecycle != Lifecycle::Active {
            return Err(Rar4DecodeError::State);
        }
        let result = (|| {
            self.work.check()?;
            self.fed = self.fed.checked_add(bytes.len() as u64).ok_or(Rar4DecodeError::CounterOverflow)?;
            if self.fed > self.packed {
                return Err(Rar4DecodeError::PackedSize { expected: self.packed, actual: self.fed });
            }
            self.pump(bytes, sink)?;
            self.work.check()?;
            Ok(if matches!(self.phase, Phase::Complete) { Rar4FeedState::Complete } else { Rar4FeedState::NeedInput })
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    /// Finishes a member and closes the decoder: no solid successor can follow.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn finish(&mut self, sink: &mut dyn Sink) -> DecodeResult<()> {
        if self.poisoned || self.finished {
            return Err(Rar4DecodeError::Malformed("decoder is no longer usable"));
        }
        self.finish_logical(sink)?;
        self.lifecycle = Lifecycle::Closed;
        self.finished = true;
        Ok(())
    }
    /// Decodes as far as `bytes` (after anything a PPM block left) allows.
    fn pump(&mut self, bytes: &[u8], sink: &mut dyn Sink) -> DecodeResult<()> {
        let mut input = bytes;
        loop {
            self.run(&mut input, sink)?;
            if self.carry.is_empty() || matches!(self.phase, Phase::Complete) {
                self.carry.clear();
                return Ok(());
            }
            // a PPM block ended: the LZ blocks after it read what it left, before anything fed later
            let carry = std::mem::take(&mut self.carry);
            let mut rest = carry.as_slice();
            self.run(&mut rest, sink)?;
            if !self.carry.is_empty() {
                continue;
            }
            if !rest.is_empty() && !matches!(self.phase, Phase::Complete) {
                return Err(Rar4DecodeError::State);
            }
            return Ok(());
        }
    }
    fn run(&mut self, input: &mut &[u8], sink: &mut dyn Sink) -> DecodeResult<()> {
        loop {
            match self.step_counted(input, sink) {
                Ok(true) => {}
                Ok(false) => return Ok(()),
                Err(error) if self.in_tail && Self::tail_tolerates(&error) => self.end_tail(),
                Err(error) => return Err(error),
            }
        }
    }
    /// The member's data is all in: decodes what PPM held back for lookahead.
    pub(super) fn drain_input(&mut self, sink: &mut dyn Sink) -> DecodeResult<()> {
        self.finishing = true;
        if self.phase.ppm() || matches!(self.phase, Phase::Legacy) || !self.carry.is_empty() {
            self.pump(&[], sink)?;
        }
        Ok(())
    }
    fn step_counted(&mut self, input: &mut &[u8], sink: &mut dyn Sink) -> DecodeResult<bool> {
        // Even a partly assembled field owns the bytes fetched into Bits.
        // Check the prospective cursor before any parser mutation.
        self.fetched
            .checked_add(input.len() as u64)
            .and_then(|n| n.checked_mul(8))
            .ok_or(Rar4DecodeError::CounterOverflow)?;
        let before = input.len();
        let result = self.step(input, sink);
        self.fetched =
            self.fetched.checked_add((before - input.len()) as u64).ok_or(Rar4DecodeError::CounterOverflow)?;
        result
    }
    fn flush(&mut self, sink: &mut dyn Sink) -> DecodeResult<()> {
        self.work.check()?;
        if self.filled != 0 {
            sink.put(&self.output[..self.filled]).map_err(Rar4DecodeError::Sink)?;
            self.filled = 0;
        }
        self.work.check()
    }
    fn emit(&mut self, byte: u8, sink: &mut dyn Sink) -> DecodeResult<()> {
        let next = self.produced.checked_add(1).ok_or(Rar4DecodeError::CounterOverflow)?;
        if next > self.expected {
            return Err(Rar4DecodeError::DecodedSize { expected: self.expected, actual: next });
        }
        let cursor = self.chain_base.checked_add(self.produced).ok_or(Rar4DecodeError::CounterOverflow)?;
        cursor.checked_add(1).ok_or(Rar4DecodeError::CounterOverflow)?;
        let index = (cursor & (self.dictionary.len() as u64 - 1)) as usize;
        self.dictionary[index] = byte;
        self.produced = next;
        if let Some(block) = self.filters.pending.front()
            && cursor >= block.start
        {
            // held until the block can be filtered
            if self.hold.is_empty() {
                self.hold_start = cursor;
            }
            self.hold.push(byte);
            if cursor + 1 >= block.end() {
                self.run_filters(sink)?;
            }
            return Ok(());
        }
        self.output[self.filled] = byte;
        self.filled += 1;
        if self.filled == OUTPUT {
            self.flush(sink)?;
        }
        Ok(())
    }
    /// Filters every waiting block whose bytes are all decoded and writes it, with what lies between blocks.
    fn run_filters(&mut self, sink: &mut dyn Sink) -> DecodeResult<()> {
        let held_end = self.hold_start + self.hold.len() as u64;
        while let Some(block) = self.filters.pending.front()
            && block.end() <= held_end
        {
            let block = block.clone();
            self.flush(sink)?;
            if block.start < self.hold_start {
                return Err(Rar4DecodeError::Malformed("RAR4 filter blocks overlap"));
            }
            let from = (block.start - self.hold_start) as usize;
            if from != 0 {
                sink.put(&self.hold[..from]).map_err(Rar4DecodeError::Sink)?;
            }
            let offset =
                block.start.checked_sub(self.chain_base).ok_or(Rar4DecodeError::Malformed("RAR4 filter block"))?;
            let mut data = self.hold[from..from + block.len].to_vec();
            self.work.tick(block.len as u64)?;
            data = filters::run(&block, data, offset).map_err(Rar4DecodeError::Malformed)?;
            self.filters.pending.pop_front();
            // a block filtered again in place runs the next filter on the first's output
            while let Some(next) = self.filters.pending.front()
                && next.start == block.start
                && next.len == data.len()
            {
                let next = next.clone();
                self.work.tick(next.len as u64)?;
                data = filters::run(&next, data, offset).map_err(Rar4DecodeError::Malformed)?;
                self.filters.pending.pop_front();
            }
            sink.put(&data).map_err(Rar4DecodeError::Sink)?;
            self.hold.drain(..from + block.len);
            self.hold_start = block.end();
        }
        // what is held before the next block (or all of it, when none waits) goes out plain
        let plain = match self.filters.pending.front() {
            Some(next) => next.start.saturating_sub(self.hold_start).min(self.hold.len() as u64) as usize,
            None => self.hold.len(),
        };
        if plain != 0 {
            self.flush(sink)?;
            sink.put(&self.hold[..plain]).map_err(Rar4DecodeError::Sink)?;
            self.hold.drain(..plain);
            self.hold_start += plain as u64;
        }
        Ok(())
    }
    fn add_filter(&mut self, first: u32) -> DecodeResult<()> {
        let at = self.chain_base.checked_add(self.produced).ok_or(Rar4DecodeError::CounterOverflow)?;
        let code = std::mem::take(&mut self.vm_code);
        self.work.tick(code.len() as u64)?;
        self.filters.add(first, &code, at).map_err(|reason| {
            if reason.contains("other than") {
                Rar4DecodeError::Unsupported(Rar4UnsupportedMode::VmFilter)
            } else {
                Rar4DecodeError::Malformed(reason)
            }
        })
    }
    /// Copies a match inside a PPM block, as far as the member's output goes.
    fn ppm_copy(&mut self, distance: u64, length: u64, sink: &mut dyn Sink) -> DecodeResult<()> {
        let history = self.chain_base.checked_add(self.produced).ok_or(Rar4DecodeError::CounterOverflow)?;
        if distance == 0 || distance > self.dictionary.len() as u64 || distance > history {
            return Err(Rar4DecodeError::Malformed("match distance outside initialized history"));
        }
        let length = length.min(self.expected - self.produced);
        self.work.tick(length)?;
        for _ in 0..length {
            let cursor = self.chain_base + self.produced;
            let index = ((cursor - distance) & (self.dictionary.len() as u64 - 1)) as usize;
            self.emit(self.dictionary[index], sink)?;
        }
        Ok(())
    }
    /// Past the member's last output byte in a PPM block.
    fn ppm_output_done(&mut self, sink: &mut dyn Sink) -> DecodeResult<()> {
        if self.produced == self.expected && !self.in_tail && self.lifecycle == Lifecycle::Active {
            self.flush(sink)?;
            if self.track_boundary {
                self.in_tail = true;
            } else {
                self.saved_phase = Phase::Align;
                self.phase = Phase::Complete;
            }
        }
        Ok(())
    }
    /// One PPM step: a character, an escape, or a filter byte. False: more input is needed first.
    /// Buffers `input` for a byte-reading engine. How much is buffered and not read yet.
    fn absorb(&mut self, input: &mut &[u8]) -> DecodeResult<usize> {
        if !input.is_empty() {
            if self.ppm_pos > CHUNK && self.ppm_pos <= self.ppm_in.len() {
                self.ppm_in.drain(..self.ppm_pos);
                self.ppm_pos = 0;
            }
            self.ppm_in
                .try_reserve(input.len())
                .map_err(|_| Rar4DecodeError::Allocation { requested: input.len() as u64 })?;
            self.ppm_in.extend_from_slice(input);
            *input = &[];
        }
        Ok(self.ppm_in.len() - self.ppm_pos.min(self.ppm_in.len()))
    }
    /// The unpack version decides the engine: RAR 1.5 and 2.0 decode with their own, 2.9 with this one.
    pub(crate) fn set_version(&mut self, version: u8) -> DecodeResult<()> {
        if !matches!(version, 15 | 20 | 26 | 29) {
            return Err(Rar4DecodeError::Binding);
        }
        self.version = version;
        self.legacy = legacy::Engine::new(version).map(Box::new);
        if let Some(engine) = &mut self.legacy {
            engine.start_member(self.expected);
            self.saved_phase = Phase::Legacy;
            if !matches!(self.phase, Phase::Complete) || self.in_tail {
                self.phase = Phase::Legacy;
            }
        }
        Ok(())
    }
    /// One code of a RAR 1.5 or 2.0 engine.
    fn legacy_step(&mut self, input: &mut &[u8], sink: &mut dyn Sink) -> DecodeResult<bool> {
        let available = self.absorb(input)?;
        if available < PPM_LOOKAHEAD && !self.finishing {
            return Ok(false);
        }
        if self.ppm_pos > self.ppm_in.len() + 8 {
            return Err(Rar4DecodeError::Malformed("RAR 1.5/2.0 data ends early"));
        }
        let mut engine = self.legacy.take().ok_or(Rar4DecodeError::State)?;
        let data = std::mem::take(&mut self.ppm_in);
        let mut bits = ppm::Bits { data: &data, addr: self.ppm_pos, bit: self.legacy_bit };
        let result = if self.in_tail {
            engine.member_end(&mut bits);
            Ok(())
        } else {
            self.work.tick(1).and_then(|()| engine.step(&mut bits, &mut LegacyOut { decoder: self, sink }))
        };
        let (addr, bit) = (bits.addr, bits.bit);
        self.ppm_in = data;
        self.ppm_pos = addr;
        self.legacy_bit = bit;
        self.legacy = Some(engine);
        result?;
        if self.in_tail {
            self.finish_tail(Phase::Legacy);
        } else if self.produced == self.expected && self.lifecycle == Lifecycle::Active {
            self.flush(sink)?;
            if self.track_boundary {
                self.in_tail = true;
            } else {
                self.saved_phase = Phase::Legacy;
                self.phase = Phase::Complete;
            }
        }
        Ok(true)
    }
    fn ppm_step(&mut self, input: &mut &[u8], sink: &mut dyn Sink) -> DecodeResult<bool> {
        let available = self.absorb(input)?;
        if available < PPM_LOOKAHEAD && !self.finishing {
            return Ok(false);
        }
        if self.ppm_pos > self.ppm_in.len() + 8 {
            return Err(Rar4DecodeError::Malformed("PPM data ends early"));
        }
        if available == 0 && self.in_tail {
            self.end_tail();
            return Ok(true);
        }
        let model = self.ppm.get_or_insert_with(Box::default);
        let mut bits = ppm::Bits { data: &self.ppm_in, addr: self.ppm_pos, bit: 0 };
        let mut esc = self.esc;
        let mut next = || model.decode_char(&mut bits).ok_or(Rar4DecodeError::Malformed("PPM data"));
        enum Then {
            Byte(u8),
            Escape,
            Copy(u64, u64),
            Vm(u32, usize),
            VmByte(u8),
            Tables,
            FileEnd,
            Nothing,
        }
        let then = match self.phase {
            Phase::PpmInit => {
                drop(next);
                if !model.init(&mut bits, &mut esc) {
                    return Err(Rar4DecodeError::Malformed("PPM block header"));
                }
                Then::Nothing
            }
            Phase::PpmChar => {
                let ch = next()?;
                if ch == esc { Then::Escape } else { Then::Byte(ch) }
            }
            Phase::PpmEscape => match next()? {
                0 => Then::Tables,
                2 => Then::FileEnd,
                3 => {
                    let first = u32::from(next()?);
                    let len = match (first & 7) + 1 {
                        7 => usize::from(next()?) + 7,
                        8 => usize::from(next()?) * 256 + usize::from(next()?),
                        n => n as usize,
                    };
                    Then::Vm(first, len)
                }
                4 => {
                    let mut distance = 0u64;
                    for _ in 0..3 {
                        distance = (distance << 8) | u64::from(next()?);
                    }
                    let length = u64::from(next()?);
                    Then::Copy(distance + 2, length + 32)
                }
                5 => Then::Copy(1, u64::from(next()?) + 4),
                _ => Then::Byte(esc),
            },
            Phase::PpmVmCode { .. } => Then::VmByte(next()?),
            _ => return Err(Rar4DecodeError::State),
        };
        self.ppm_pos = bits.addr;
        self.esc = esc;
        self.work.tick(1)?;
        if self.in_tail {
            // past the output only the end-of-file escape belongs to the member
            match then {
                Then::Escape => self.phase = Phase::PpmEscape,
                Then::Tables => self.leave_ppm(),
                Then::Nothing => self.phase = Phase::PpmChar,
                _ => self.finish_tail(Phase::Align),
            }
            return Ok(true);
        }
        match then {
            Then::Nothing => self.phase = Phase::PpmChar,
            Then::Byte(byte) => {
                self.emit(byte, sink)?;
                self.phase = Phase::PpmChar;
            }
            Then::Escape => self.phase = Phase::PpmEscape,
            Then::Copy(distance, length) => {
                self.ppm_copy(distance, length, sink)?;
                self.phase = Phase::PpmChar;
            }
            Then::Vm(first, len) => {
                self.vm_code.clear();
                self.vm_code
                    .try_reserve_exact(len)
                    .map_err(|_| Rar4DecodeError::Allocation { requested: len as u64 })?;
                self.phase = Phase::PpmVmCode { first, left: len };
                if len == 0 {
                    return Err(Rar4DecodeError::Malformed("empty RAR4 filter record"));
                }
            }
            Then::VmByte(byte) => {
                let Phase::PpmVmCode { first, left } = self.phase else { return Err(Rar4DecodeError::State) };
                self.vm_code.push(byte);
                if left == 1 {
                    self.add_filter(first)?;
                    self.phase = Phase::PpmChar;
                } else {
                    self.phase = Phase::PpmVmCode { first, left: left - 1 };
                }
            }
            Then::Tables => self.leave_ppm(),
            Then::FileEnd => {
                // the member ends in PPM: the next one starts on new tables (or a new PPM block)
                if self.produced != self.expected {
                    return Err(Rar4DecodeError::DecodedSize { expected: self.expected, actual: self.produced });
                }
            }
        }
        self.ppm_output_done(sink)?;
        if matches!(then, Then::FileEnd)
            && self.lifecycle == Lifecycle::Active
            && !matches!(self.phase, Phase::Complete)
        {
            self.finish_tail(Phase::Align);
        }
        Ok(true)
    }
    /// A PPM block ends: new LZ tables follow, read from where the PPM decoder stopped.
    fn leave_ppm(&mut self) {
        let start = self.ppm_pos.min(self.ppm_in.len());
        self.carry.clear();
        self.carry.extend_from_slice(&self.ppm_in[start..]);
        self.ppm_in.clear();
        self.ppm_pos = 0;
        self.bits = Bits::default();
        self.phase = Phase::Align;
    }
    fn symbol(&mut self, table: usize, input: &mut &[u8]) -> DecodeResult<Option<u16>> {
        if self.tables[table].used == 0 {
            return Err(Rar4DecodeError::Malformed("empty Huffman table"));
        }
        while self.depth < 15 {
            let Some(bit) = self.bits.take(1, input) else { return Ok(None) };
            self.work.tick(1)?;
            self.prefix = (self.prefix << 1) | bit;
            self.depth += 1;
            let h = &self.tables[table];
            if let Some(relative) = self.prefix.checked_sub(h.first[self.depth])
                && relative < u32::from(h.count[self.depth])
            {
                let symbol = h.symbols[h.offset[self.depth] + relative as usize];
                self.prefix = 0;
                self.depth = 0;
                return Ok(Some(symbol));
            }
        }
        Err(Rar4DecodeError::Malformed("undefined Huffman code"))
    }
    fn vm_record(&mut self, first: u32, len: usize) -> DecodeResult<Phase> {
        if len == 0 {
            return Err(Rar4DecodeError::Malformed("empty RAR4 filter record"));
        }
        self.vm_code.clear();
        self.vm_code.try_reserve_exact(len).map_err(|_| Rar4DecodeError::Allocation { requested: len as u64 })?;
        Ok(Phase::VmCode { first, left: len })
    }
    fn insert(&mut self, distance: u64) {
        self.recent.copy_within(0..3, 1);
        self.recent[0] = distance;
    }
    fn start_copy(&mut self, length: u64, distance: u64) -> DecodeResult<()> {
        let history = self.chain_base.checked_add(self.produced).ok_or(Rar4DecodeError::CounterOverflow)?;
        if distance == 0 || distance > self.binding.frame.dictionary || distance > history {
            return Err(Rar4DecodeError::Malformed("match distance outside initialized history"));
        }
        let end = self.produced.checked_add(length).ok_or(Rar4DecodeError::CounterOverflow)?;
        if end > self.expected {
            return Err(Rar4DecodeError::DecodedSize { expected: self.expected, actual: end });
        }
        #[cfg(test)]
        {
            if self.chain_base != 0 && distance > self.produced && self.first_cross.is_none() {
                self.first_cross = Some((self.produced, distance, length));
            }
            self.observe_successor_match(length, distance);
        }
        self.last_length = length;
        self.phase = Phase::Copy { distance, left: length };
        Ok(())
    }
    fn length(index: usize) -> (u64, u8) {
        if index < 8 {
            (index as u64, 0)
        } else {
            let bits = ((index - 4) / 4) as u8;
            (((4 + index % 4) as u64) << bits, bits)
        }
    }
    fn distance(index: usize) -> (u64, u8) {
        match index {
            0..=3 => (index as u64, 0),
            4..=33 => {
                let bits = ((index - 2) / 2) as u8;
                (((2 + index % 2) as u64) << bits, bits)
            }
            34..=47 => (((index - 32) as u64) << 16, 16),
            48..=59 => (((index - 44) as u64) << 18, 18),
            _ => unreachable!(),
        }
    }
    fn step(&mut self, input: &mut &[u8], sink: &mut dyn Sink) -> DecodeResult<bool> {
        if self.phase.ppm() {
            return self.ppm_step(input, sink);
        }
        if matches!(self.phase, Phase::Legacy) {
            return self.legacy_step(input, sink);
        }
        self.work.tick(1)?;
        macro_rules! take {
            ($bits:expr) => {
                match self.bits.take($bits, input) {
                    Some(n) => n,
                    None => return Ok(false),
                }
            };
        }
        macro_rules! symbol {
            ($table:expr) => {
                match self.symbol($table, input)? {
                    Some(n) => n,
                    None => return Ok(false),
                }
            };
        }
        match self.phase {
            Phase::Align => {
                self.bits.align();
                self.phase = Phase::Mode;
            }
            Phase::Mode => {
                // the block type bit belongs to a PPM block's own first byte: look, don't take
                if self.bits.count == 0 {
                    let Some((&byte, tail)) = input.split_first() else { return Ok(false) };
                    *input = tail;
                    self.bits.acc = u64::from(byte);
                    self.bits.count = 8;
                    #[cfg(test)]
                    {
                        self.bits.read_bytes += 1;
                    }
                }
                if (self.bits.acc >> (self.bits.count - 1)) & 1 != 0 {
                    #[cfg(test)]
                    self.observe(tests::TraceKind::Mode { ppm: true });
                    // the whole bytes the bit reader holds go back to the PPM decoder
                    self.ppm_in.clear();
                    self.ppm_pos = 0;
                    for k in (0..self.bits.count / 8).rev() {
                        self.ppm_in.push((self.bits.acc >> (8 * k)) as u8);
                    }
                    self.bits = Bits::default();
                    self.phase = Phase::PpmInit;
                    return Ok(true);
                }
                take!(1);
                #[cfg(test)]
                self.observe(tests::TraceKind::Mode { ppm: false });
                self.phase = Phase::Retain;
            }
            Phase::Retain => {
                if take!(1) == 0 {
                    self.old = [0; 404];
                }
                #[cfg(test)]
                self.observe(tests::TraceKind::Retain { delta: self.bits.last_value != 0 });
                self.phase = Phase::Bc { index: 0 };
            }
            Phase::Bc { index } => {
                let value = take!(4) as u8;
                if value == 15 {
                    self.phase = Phase::BcRun { index };
                } else {
                    self.bc_lengths[index] = value;
                    self.phase = if index + 1 == 20 { Phase::BuildBc } else { Phase::Bc { index: index + 1 } };
                }
            }
            Phase::BcRun { index } => {
                let value = take!(4) as usize;
                let count = if value == 0 { 1 } else { value + 2 };
                if index + count > 20 {
                    return Err(Rar4DecodeError::Malformed("BC run exceeds table"));
                }
                self.bc_lengths[index..index + count].fill(if value == 0 { 15 } else { 0 });
                self.phase = if index + count == 20 { Phase::BuildBc } else { Phase::Bc { index: index + count } };
            }
            Phase::BuildBc => {
                self.tables[0].build(&self.bc_lengths, &mut self.work)?;
                if self.tables[0].used == 0 {
                    return Err(Rar4DecodeError::Malformed("empty code-length table"));
                }
                self.phase = Phase::Lengths { index: 0 };
            }
            Phase::Lengths { index } => {
                let value = symbol!(0);
                if value < 16 {
                    self.lengths[index] = (value as u8 + self.old[index]) & 15;
                    self.phase =
                        if index + 1 == 404 { Phase::BuildTables } else { Phase::Lengths { index: index + 1 } };
                } else {
                    self.phase = Phase::LengthRun { index, kind: value };
                }
            }
            Phase::LengthRun { index, kind } => {
                let count = if kind == 16 || kind == 18 { take!(3) as usize + 3 } else { take!(7) as usize + 11 };
                if index + count > 404 || (kind < 18 && index == 0) {
                    return Err(Rar4DecodeError::Malformed("invalid code-length run"));
                }
                let value = if kind < 18 { self.lengths[index - 1] } else { 0 };
                self.lengths[index..index + count].fill(value);
                self.work.tick(count as u64)?;
                self.phase =
                    if index + count == 404 { Phase::BuildTables } else { Phase::Lengths { index: index + count } };
            }
            Phase::BuildTables => {
                for (table, range) in [0..299, 299..359, 359..376, 376..404].into_iter().enumerate() {
                    self.tables[table + 1].build(&self.lengths[range], &mut self.work)?;
                }
                if self.tables[1].used == 0 {
                    return Err(Rar4DecodeError::Malformed("empty literal table"));
                }
                self.old = self.lengths;
                self.low = 0;
                self.low_repeats = 0;
                self.table_builds = self.table_builds.checked_add(1).ok_or(Rar4DecodeError::CounterOverflow)?;
                #[cfg(test)]
                self.observe(tests::TraceKind::Tables);
                self.phase = Phase::Token;
            }
            Phase::Token => {
                let token = symbol!(1);
                if self.in_tail {
                    // Past the member's output only the end-of-file marker belongs to it. Anything else is
                    // read as UnRAR does: the next member goes on with the tables in force.
                    if token == 256 {
                        self.phase = Phase::End;
                    } else {
                        self.finish_tail(Phase::Token);
                    }
                    return Ok(true);
                }
                #[cfg(test)]
                match token {
                    256 => self.observe(tests::TraceKind::EndSymbol),
                    257 => self.observe(tests::TraceKind::VmFilter),
                    _ => {}
                }
                self.phase = match token {
                    0..=255 => {
                        self.emit(token as u8, sink)?;
                        Phase::Token
                    }
                    256 => Phase::End,
                    257 => Phase::VmFirst,
                    258 => {
                        if self.last_length == 0 {
                            return Err(Rar4DecodeError::Malformed("repeat before a match"));
                        }
                        self.start_copy(self.last_length, self.recent[0])?;
                        self.phase
                    }
                    259..=262 => Phase::RecentLength { slot: (token - 259) as usize },
                    263..=270 => Phase::Short { index: (token - 263) as usize },
                    271..=298 => Phase::Length { index: (token - 271) as usize, recent: None },
                    _ => return Err(Rar4DecodeError::Malformed("literal alphabet")),
                };
                if self.produced == self.expected
                    && matches!(self.phase, Phase::Token)
                    && self.lifecycle == Lifecycle::Active
                {
                    self.flush(sink)?;
                    if self.track_boundary {
                        self.in_tail = true;
                    } else {
                        self.saved_phase = self.phase;
                        self.phase = Phase::Complete;
                    }
                }
            }
            Phase::End => {
                self.phase = if take!(1) != 0 { Phase::Align } else { Phase::EndHint };
                #[cfg(test)]
                self.observe(tests::TraceKind::EndBit { same_file: self.bits.last_value != 0 });
            }
            Phase::EndHint => {
                let _hint = take!(1);
                #[cfg(test)]
                self.observe(tests::TraceKind::EndHint { read_tables_next: _hint != 0 });
                if self.in_tail {
                    self.finish_tail(if _hint == 0 { Phase::Token } else { Phase::Align });
                    return Ok(true);
                }
                if self.lifecycle == Lifecycle::Deferred {
                    self.lifecycle = Lifecycle::BoundaryReady;
                    self.saved_phase = if _hint == 0 { Phase::Token } else { Phase::Align };
                    return Ok(false);
                }
                return Err(Rar4DecodeError::DecodedSize { expected: self.expected, actual: self.produced });
            }
            Phase::Length { index, recent } => {
                let (base, bits) = Self::length(index);
                self.phase = Phase::LengthExtra { base, bits, recent };
            }
            Phase::RecentLength { slot } => {
                if self.recent[slot] == 0 {
                    return Err(Rar4DecodeError::Malformed("recent distance unavailable"));
                }
                self.phase = Phase::Length { index: symbol!(4) as usize, recent: Some(slot) };
            }
            Phase::LengthExtra { base, bits, recent } => {
                let length = base + u64::from(take!(bits)) + if recent.is_some() { 2 } else { 3 };
                if let Some(slot) = recent {
                    let distance = self.recent[slot];
                    self.recent.copy_within(0..slot, 1);
                    self.recent[0] = distance;
                    self.start_copy(length, distance)?;
                } else {
                    self.phase = Phase::Distance { length };
                }
            }
            Phase::Distance { length } => {
                self.phase = Phase::DistanceBits { length, index: symbol!(2) as usize };
            }
            Phase::DistanceBits { length, index } => {
                let (base, bits) = Self::distance(index);
                if index <= 9 {
                    let distance = base + 1 + u64::from(take!(bits));
                    self.insert(distance);
                    self.start_copy(length, distance)?;
                } else {
                    let high = u64::from(take!(bits - 4)) << 4;
                    self.phase = Phase::Low { length, base: base + 1 + high };
                }
            }
            Phase::Low { length, base } => {
                let low = if self.low_repeats != 0 {
                    self.low_repeats -= 1;
                    self.low
                } else {
                    let value = symbol!(3);
                    if value == 16 {
                        self.low_repeats = 15;
                        self.low
                    } else {
                        self.low = u64::from(value);
                        self.low
                    }
                };
                let distance = base + low;
                let length = length + u64::from(distance >= 0x2000) + u64::from(distance >= 0x40000);
                self.insert(distance);
                self.start_copy(length, distance)?;
            }
            Phase::Short { index } => {
                let (base, bits) = match index {
                    0 => (0, 2),
                    1 => (4, 2),
                    2 => (8, 3),
                    3 => (16, 4),
                    4 => (32, 5),
                    5 => (64, 6),
                    6 => (128, 6),
                    7 => (192, 6),
                    _ => unreachable!(),
                };
                let distance = base + 1 + u64::from(take!(bits));
                self.insert(distance);
                self.start_copy(2, distance)?;
            }
            Phase::Copy { distance, left } => {
                let cursor = self.chain_base.checked_add(self.produced).ok_or(Rar4DecodeError::CounterOverflow)?;
                let index = (cursor.checked_sub(distance).ok_or(Rar4DecodeError::CounterOverflow)?
                    & (self.dictionary.len() as u64 - 1)) as usize;
                self.emit(self.dictionary[index], sink)?;
                self.phase = if left == 1 { Phase::Token } else { Phase::Copy { distance, left: left - 1 } };
                if self.produced == self.expected && left == 1 && self.lifecycle == Lifecycle::Active {
                    self.flush(sink)?;
                    if self.track_boundary {
                        self.in_tail = true;
                    } else {
                        self.saved_phase = self.phase;
                        self.phase = Phase::Complete;
                    }
                }
            }
            Phase::VmFirst => {
                let first = take!(8);
                self.phase = match (first & 7) + 1 {
                    7 => Phase::VmLength { first, wide: false },
                    8 => Phase::VmLength { first, wide: true },
                    n => self.vm_record(first, n as usize)?,
                };
            }
            Phase::VmLength { first, wide } => {
                let len = if wide { take!(16) as usize } else { take!(8) as usize + 7 };
                self.phase = self.vm_record(first, len)?;
            }
            Phase::VmCode { first, left } => {
                self.vm_code.push(take!(8) as u8);
                self.phase = if left == 1 {
                    self.add_filter(first)?;
                    Phase::Token
                } else {
                    Phase::VmCode { first, left: left - 1 }
                };
            }
            Phase::PpmInit | Phase::PpmChar | Phase::PpmEscape | Phase::PpmVmCode { .. } | Phase::Legacy => {
                return Err(Rar4DecodeError::State);
            }
            Phase::Complete => return Ok(false),
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests;

/// A legacy engine's output: the decoder's window and sink, up to the member's end.
struct LegacyOut<'a> {
    decoder: &'a mut Rar4Decoder,
    sink: &'a mut dyn Sink,
}
impl legacy::Out for LegacyOut<'_> {
    fn put(&mut self, byte: u8) -> DecodeResult<()> {
        self.decoder.emit(byte, self.sink)
    }
    fn copy(&mut self, dist: u32, len: u32, lenient: bool) -> DecodeResult<()> {
        let d = &mut *self.decoder;
        let len = u64::from(len).min(d.expected - d.produced);
        let history = d.chain_base.checked_add(d.produced).ok_or(Rar4DecodeError::CounterOverflow)?;
        let dist = u64::from(dist);
        let reachable = dist != 0 && dist <= history && dist <= d.dictionary.len() as u64;
        if !reachable && !lenient {
            return Err(Rar4DecodeError::Malformed("match distance outside initialized history"));
        }
        d.work.tick(len)?;
        for _ in 0..len {
            let byte = if reachable {
                let cursor = d.chain_base + d.produced;
                d.dictionary[((cursor - dist) & (d.dictionary.len() as u64 - 1)) as usize]
            } else {
                0
            };
            d.emit(byte, self.sink)?;
        }
        Ok(())
    }
}

/// Wrap the immutable literal vector for source/output ownership unit tests.
/// This helper cannot compress data and is absent from normal builds.
#[cfg(test)]
pub(crate) fn fixed_fixture() -> Vec<u8> {
    fn block(kind: u8, flags: u16, body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0, 0, kind];
        bytes.extend(flags.to_le_bytes());
        bytes.extend(((body.len() + 7) as u16).to_le_bytes());
        bytes.extend(body);
        let crc = crate::crc32::hash(&bytes[2..]) as u16;
        bytes[..2].copy_from_slice(&crc.to_le_bytes());
        bytes
    }
    let packed = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rar4-lz/literal-a.packed"));
    let mut body = Vec::new();
    body.extend((packed.len() as u32).to_le_bytes());
    body.extend(1u32.to_le_bytes());
    body.push(3);
    body.extend(crate::crc32::hash(b"A").to_le_bytes());
    body.extend(0x50221884u32.to_le_bytes());
    body.extend([29, 0x33]);
    body.extend(1u16.to_le_bytes());
    body.extend(0o100644u32.to_le_bytes());
    body.push(b'x');
    [
        b"Rar!\x1a\x07\0".as_slice(),
        &block(0x73, 0, &[0; 6]),
        &block(0x74, 0x8000, &body),
        packed,
        &block(0x7b, 0x4000, &[]),
    ]
    .concat()
}

#[cfg(test)]
#[path = "rar4/deferred_tests.rs"]
mod deferred_tests;
