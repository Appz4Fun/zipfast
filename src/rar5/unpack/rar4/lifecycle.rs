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

//! Codec-only continuation. These capabilities prove no CRC, source or publication.
//! The future history adapter must validate the full FrameKey/Pending/source
//! envelope immediately before obtaining DeferGuard, with no callback in between.

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);

fn mint_owner(counter: &AtomicU64) -> DecodeResult<u64> {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        let next = current.checked_add(1).filter(|_| current != 0).ok_or(Rar4DecodeError::CounterOverflow)?;
        match counter.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(owner) => return Ok(owner),
            Err(actual) => current = actual,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CoreFrame {
    pub(crate) ordinal: u64,
    pub(crate) packed: u64,
    pub(crate) unpacked: u64,
    pub(crate) unpack_version: u8,
    pub(crate) method: u8,
    pub(crate) dictionary: u64,
}
impl CoreFrame {
    fn validate(self, retained: u64) -> DecodeResult<()> {
        if !matches!(self.unpack_version, 15 | 20 | 26 | 29) || !(0x31..=0x35).contains(&self.method) {
            return Err(Rar4DecodeError::Binding);
        }
        if !(65536..=4194304).contains(&self.dictionary) || !self.dictionary.is_power_of_two() {
            return Err(Rar4DecodeError::InvalidDictionary { requested: self.dictionary });
        }
        if self.dictionary > retained {
            return Err(Rar4DecodeError::Binding);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CoreBinding {
    pub(crate) owner: u64,
    pub(crate) epoch: u64,
    pub(crate) member_seq: u64,
    pub(crate) frame: CoreFrame,
}
impl CoreBinding {
    pub(super) fn new(frame: CoreFrame) -> DecodeResult<Self> {
        Ok(Self { owner: mint_owner(&NEXT_OWNER)?, epoch: 1, member_seq: 1, frame })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Lifecycle {
    Active,
    LogicalDone,
    Deferred,
    BoundaryReady,
    Unavailable,
    #[cfg_attr(not(test), allow(dead_code))]
    Closed,
}

#[derive(Debug)]
pub(crate) struct Completion {
    binding: CoreBinding,
}
impl Completion {
    // Used by the next adapter to match its external full frame envelope.
    #[allow(dead_code)]
    pub(crate) fn binding(&self) -> CoreBinding {
        self.binding
    }
}

#[derive(Debug)]
pub(crate) struct Boundary {
    binding: CoreBinding,
}
#[derive(Debug)]
pub(crate) enum BoundaryState {
    NeedInput,
    // The next private history consumer reads this single-use capability.
    Ready(#[allow(dead_code)] Boundary),
}

pub(crate) struct DeferGuard<'a> {
    decoder: &'a mut Rar4Decoder,
}
impl DeferGuard<'_> {
    #[allow(dead_code)]
    pub(crate) fn commit(self) {
        self.decoder.phase = self.decoder.saved_phase;
        self.decoder.lifecycle = Lifecycle::Deferred;
    }
}

impl Rar4Decoder {
    /// Exact parsed metadata constructor required by the future history adapter.
    /// Legacy constructors' synthetic frame is compatibility bookkeeping only.
    #[allow(dead_code)]
    pub(crate) fn new_frame(frame: CoreFrame, window_limit: u64, cancel: Option<Cancellation>) -> DecodeResult<Self> {
        frame.validate(4194304)?;
        let mut d = Self::new_with_cancel(frame.dictionary, frame.packed, frame.unpacked, window_limit, cancel)?;
        d.set_version(frame.unpack_version)?;
        // a progressive session's decoder window also bounds a PPM model and held filter blocks
        d.set_memory_limit(window_limit);
        d.binding.frame = frame;
        Ok(d)
    }
    /// Capture at member start for the future Pending/full-frame envelope.
    #[allow(dead_code)]
    pub(crate) fn active_binding(&self) -> DecodeResult<CoreBinding> {
        self.require(Lifecycle::Active)?;
        Ok(self.binding)
    }
    fn require(&self, state: Lifecycle) -> DecodeResult<()> {
        if self.poisoned || self.finished || self.lifecycle != state { Err(Rar4DecodeError::State) } else { Ok(()) }
    }
    pub(crate) fn finish_logical(&mut self, sink: &mut dyn Sink) -> DecodeResult<Completion> {
        self.require(Lifecycle::Active)?;
        let result = (|| {
            self.work.check()?;
            if self.fed != self.packed {
                return Err(Rar4DecodeError::PackedSize { expected: self.packed, actual: self.fed });
            }
            self.drain_input(sink)?;
            if !self.hold.is_empty() {
                // UnRAR keeps a block waiting into the next solid member, but its bytes are this member's output,
                // which must be complete and checked now; no archiver writes such a block.
                return Err(Rar4DecodeError::Malformed("RAR4 filter block runs past the member"));
            }
            if self.in_tail && self.produced == self.expected {
                // The member's data ends inside its end-of-file marker.
                self.end_tail();
            }
            if self.track_boundary && self.boundary.is_none() && matches!(self.phase, Phase::Complete) {
                // An empty member leaves the next one where this one started.
                self.boundary = Some(self.saved_phase);
            }
            if self.produced != self.expected || !matches!(self.phase, Phase::Complete) {
                return Err(Rar4DecodeError::DecodedSize { expected: self.expected, actual: self.produced });
            }
            self.consumed_bits()?;
            self.flush(sink)?;
            self.lifecycle = Lifecycle::LogicalDone;
            Ok(Completion { binding: self.binding })
        })();
        self.poison_on_error(result)
    }
    /// Validates ONLY codec identity/lifecycle. Caller must first validate its
    /// full source/Pending envelope; this is never a verification substitute.
    #[allow(dead_code)]
    pub(crate) fn validate_defer(&mut self, completion: Completion) -> DecodeResult<DeferGuard<'_>> {
        self.require(Lifecycle::LogicalDone)?;
        if completion.binding != self.binding {
            return Err(Rar4DecodeError::Binding);
        }
        self.check_transition()?;
        Ok(DeferGuard { decoder: self })
    }
    #[allow(dead_code)]
    pub(crate) fn abort(&mut self, completion: Completion) -> DecodeResult<()> {
        self.require(Lifecycle::LogicalDone)?;
        if completion.binding != self.binding {
            return Err(Rar4DecodeError::Binding);
        }
        self.lifecycle = Lifecycle::Unavailable;
        Ok(())
    }
    pub(crate) fn consumed_bits(&self) -> DecodeResult<u64> {
        self.fetched
            .checked_mul(8)
            .and_then(|n| n.checked_sub(u64::from(self.bits.count)))
            .ok_or(Rar4DecodeError::CounterOverflow)
    }
    #[allow(dead_code)]
    pub(crate) fn fetched(&self) -> u64 {
        self.fetched
    }

    /// Input must start at data_at + fetched(), after exhausting the saved
    /// accumulator with an empty call. No source or I/O accounting is performed.
    #[allow(dead_code)]
    pub(crate) fn resume_boundary(&mut self, bytes: &[u8]) -> DecodeResult<BoundaryState> {
        self.require(Lifecycle::Deferred)?;
        let remaining = self.packed.checked_sub(self.fetched).ok_or(Rar4DecodeError::CounterOverflow);
        let remaining = self.poison_on_error(remaining)?;
        if bytes.len() as u64 > remaining {
            return Err(Rar4DecodeError::Binding);
        }
        let result = (|| {
            self.work.check()?;
            let mut input = bytes;
            let mut no_output = |_: &[u8]| Err(crate::error::Error::Corrupt("RAR4 boundary output"));
            while self.step_counted(&mut input, &mut no_output)? {}
            self.work.check()?;
            if self.lifecycle == Lifecycle::BoundaryReady {
                Ok(BoundaryState::Ready(Boundary { binding: self.binding }))
            } else if self.fetched == self.packed {
                Err(Rar4DecodeError::Malformed("RAR4 missing real boundary bits"))
            } else {
                Ok(BoundaryState::NeedInput)
            }
        })();
        self.poison_on_error(result)
    }
    #[allow(dead_code)]
    pub(crate) fn begin_next(&mut self, boundary: Boundary, frame: CoreFrame) -> DecodeResult<()> {
        self.require(Lifecycle::BoundaryReady)?;
        if boundary.binding != self.binding {
            return Err(Rar4DecodeError::Binding);
        }
        frame.validate(self.dictionary.len() as u64)?;
        let counters = (|| {
            Ok((
                self.binding.member_seq.checked_add(1).ok_or(Rar4DecodeError::CounterOverflow)?,
                self.chain_base
                    .checked_add(self.produced)
                    .filter(|base| base.checked_add(frame.unpacked).is_some())
                    .ok_or(Rar4DecodeError::CounterOverflow)?,
            ))
        })();
        let (sequence, base) = self.poison_on_error(counters)?;
        self.check_transition()?;
        self.binding.member_seq = sequence;
        self.binding.frame = frame;
        self.chain_base = base;
        self.start_frame(frame);
        Ok(())
    }
    #[allow(dead_code)]
    pub(crate) fn reset_independent(&mut self, frame: CoreFrame) -> DecodeResult<()> {
        // A poisoned instance is never revived, even by reset.
        if self.poisoned {
            return Err(Rar4DecodeError::State);
        }
        frame.validate(self.dictionary.len() as u64)?;
        let epoch = self.binding.epoch.checked_add(1).ok_or(Rar4DecodeError::CounterOverflow);
        let epoch = self.poison_on_error(epoch)?;
        self.check_transition()?;
        self.binding.epoch = epoch;
        self.binding.member_seq = 1;
        self.binding.frame = frame;
        self.chain_base = 0;
        self.old = [0; 404];
        self.lengths = [0; 404];
        self.bc_lengths = [0; 20];
        self.tables = std::array::from_fn(|_| Huff::empty());
        self.recent = [0; 4];
        self.last_length = 0;
        self.low = 0;
        self.low_repeats = 0;
        self.saved_phase = Phase::Align;
        self.ppm = None;
        self.esc = 2;
        self.filters.reset();
        self.start_frame(frame);
        Ok(())
    }
    /// Read each member's end-of-file marker past its output, so a solid successor can start where it says.
    pub(crate) fn track_boundary(&mut self) {
        self.track_boundary = true;
        if self.lifecycle == Lifecycle::Active && self.produced == 0 && self.expected == 0 && self.packed != 0 {
            self.in_tail = true;
            self.phase = self.saved_phase;
        }
    }
    /// The member goes on in the next volume: its packed data grows by that part's size.
    pub(crate) fn extend_packed(&mut self, more: u64) -> DecodeResult<()> {
        self.require(Lifecycle::Active)?;
        let packed = self.packed.checked_add(more).ok_or(Rar4DecodeError::CounterOverflow);
        let packed = self.poison_on_error(packed)?;
        self.packed = packed;
        self.binding.frame.packed = packed;
        Ok(())
    }
    /// Whether a finished member left a start for a solid successor.
    pub(crate) fn has_boundary(&self) -> bool {
        !self.poisoned && self.lifecycle == Lifecycle::LogicalDone && self.boundary.is_some()
    }
    /// Starts the next member of a solid stream on the history, tables and distances the last one left.
    pub(crate) fn next_solid_member(&mut self, frame: CoreFrame) -> DecodeResult<()> {
        self.require(Lifecycle::LogicalDone)?;
        let Some(start) = self.boundary else { return Err(Rar4DecodeError::State) };
        let retained = self.dictionary.len() as u64;
        if frame.dictionary > retained {
            // the stream's window was sized for the members before
            return Err(Rar4DecodeError::WindowLimit { requested: frame.dictionary, allowed: retained });
        }
        frame.validate(retained)?;
        if frame.unpack_version != self.version
            && !(matches!(frame.unpack_version, 20 | 26) && matches!(self.version, 20 | 26))
        {
            return Err(Rar4DecodeError::Malformed("solid member changes unpack version"));
        }
        let base = self
            .chain_base
            .checked_add(self.produced)
            .filter(|base| base.checked_add(frame.unpacked).is_some())
            .ok_or(Rar4DecodeError::CounterOverflow);
        let base = self.poison_on_error(base)?;
        let sequence = self.binding.member_seq.checked_add(1).ok_or(Rar4DecodeError::CounterOverflow);
        let sequence = self.poison_on_error(sequence)?;
        self.check_transition()?;
        self.binding.member_seq = sequence;
        self.binding.frame = frame;
        self.chain_base = base;
        self.saved_phase = start;
        self.start_frame(frame);
        if let Some(engine) = &mut self.legacy {
            engine.start_member(frame.unpacked);
        }
        Ok(())
    }
    pub(super) fn tail_tolerates(error: &Rar4DecodeError) -> bool {
        matches!(
            error,
            Rar4DecodeError::Malformed(_) | Rar4DecodeError::Unsupported(_) | Rar4DecodeError::DecodedSize { .. }
        )
    }
    /// The end-of-file marker is cut short or isn't one: the next member starts as UnRAR would start it, on new
    /// tables when this stopped inside them, otherwise on the tables in force.
    pub(super) fn end_tail(&mut self) {
        let start = match self.phase {
            Phase::Align
            | Phase::Mode
            | Phase::Retain
            | Phase::Bc { .. }
            | Phase::BcRun { .. }
            | Phase::BuildBc
            | Phase::Lengths { .. }
            | Phase::LengthRun { .. }
            | Phase::BuildTables
            | Phase::PpmInit
            | Phase::PpmChar
            | Phase::PpmEscape
            | Phase::PpmVmCode { .. } => Phase::Align,
            Phase::Legacy => Phase::Legacy,
            _ => Phase::Token,
        };
        self.finish_tail(start);
    }
    pub(super) fn finish_tail(&mut self, start: Phase) {
        self.in_tail = false;
        self.boundary = Some(start);
        self.saved_phase = start;
        self.phase = Phase::Complete;
    }
    fn start_frame(&mut self, frame: CoreFrame) {
        self.packed = frame.packed;
        self.expected = frame.unpacked;
        self.fed = 0;
        self.fetched = 0;
        self.produced = 0;
        self.bits = Bits::default();
        self.prefix = 0;
        self.depth = 0;
        self.filled = 0;
        self.phase = if frame.unpacked == 0 { Phase::Complete } else { self.saved_phase };
        self.in_tail = false;
        self.boundary = None;
        self.ppm_in.clear();
        self.ppm_pos = 0;
        self.legacy_bit = 0;
        self.carry.clear();
        self.finishing = false;
        self.vm_code.clear();
        self.hold.clear();
        self.unfiltered = false;
        self.filters.next_member();
        if self.track_boundary && frame.unpacked == 0 && frame.packed != 0 {
            self.in_tail = true;
            self.phase = self.saved_phase;
        }
        self.finished = false;
        self.lifecycle = Lifecycle::Active;
        #[cfg(test)]
        {
            self.first_cross = None;
        }
    }
    fn check_transition(&mut self) -> DecodeResult<()> {
        let result = self.work.check();
        self.poison_on_error(result)
    }
    fn poison_on_error<T>(&mut self, result: DecodeResult<T>) -> DecodeResult<T> {
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}

#[cfg(test)]
mod identity_tests {
    use super::*;
    #[test]
    fn exhausted_owner_counter_never_wraps_or_reuses() {
        let counter = AtomicU64::new(u64::MAX - 1);
        assert_eq!(mint_owner(&counter).unwrap(), u64::MAX - 1);
        assert!(matches!(mint_owner(&counter), Err(Rar4DecodeError::CounterOverflow)));
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    }
}
