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

//! [`crate::extract::Options::damaged_input`] in a progressive session: damaged headers read past as the whole-archive
//! runners do, reported as [`ProgressiveEvent::HeaderDamaged`]. Only bytes the source delivered are judged: a header
//! the source has not delivered yet is waited on, and one inside a `Hole` answer stops the session with
//! `HeaderHole` as before (repair may still fill it); a resync never searches across a hole either.
use super::*;
use crate::extract::{HeaderDamage, HeaderDamageKind};
use crate::rar5::reader::{
    RESYNC_CHUNK, RESYNC_FIRST_CHUNK, RESYNC_LOOKAHEAD, RESYNC_WORK_PER_BYTE, resync_checks, resync_shape,
};

/// The longest member name a [`HeaderDamage`] keeps, as the whole-archive runners keep it.
const MAX_DAMAGE_NAME: usize = 1024;
/// The longest header a resync candidate can be ([`resync_shape`]): an 8 KiB RAR 5.0 header and its prefix.
const RESYNC_CANDIDATE_MAX: usize = (8 << 10) + 8;

/// A [`crate::extract::DamagedInput::Resync`] search for the next header that passes its checksum, held across
/// polls: the bytes read so far from `start`, and the next position to try.
pub(super) struct Resync {
    /// Where the unreadable header starts, and what was wrong with it.
    damage_at: u64,
    kind: HeaderDamageKind,
    /// The next candidate position.
    pos: u64,
    /// Bytes of the volume from `start` on, as read.
    window: Vec<u8>,
    start: u64,
    /// The source said the volume ends at `start + window.len()`.
    eof: bool,
    /// The next read's size: small first, so that resyncs close together read little.
    chunk: usize,
}

/// Per-volume resync work: bytes read and checksummed by every resync in the volume together, bounded by
/// [`RESYNC_WORK_PER_BYTE`] times the furthest offset read in the volume (plus 1 MiB), so the search stays linear in
/// the bytes the source delivered whatever they are.
#[derive(Default)]
pub(super) struct ResyncWork {
    spent: u64,
    furthest: u64,
}
impl ResyncWork {
    fn charge(&mut self, work: u64) -> bool {
        let bound = self.furthest.saturating_mul(RESYNC_WORK_PER_BYTE).saturating_add(1 << 20);
        match self.spent.checked_add(work).filter(|&spent| spent <= bound) {
            Some(spent) => {
                self.spent = spent;
                true
            }
            None => false,
        }
    }
}

impl ProgressiveSession {
    /// The damaged-input choice the parsers of this session take. A persistent session refuses damaged headers
    /// whatever the options say (its journal binds a member to the header bytes it was read from).
    pub(super) fn damaged_input(&self) -> crate::extract::DamagedInput {
        #[cfg(feature = "persistent-partials")]
        if self.partial.is_some() {
            return crate::extract::DamagedInput::Refuse;
        }
        self.options.extract.damaged_input
    }
    /// Queues the event for one damaged header of the current volume.
    pub(super) fn header_damage(
        &mut self,
        offset: u64,
        kind: HeaderDamageKind,
        name: Option<&str>,
        resumed_at: Option<u64>,
        passed_over: bool,
    ) -> ProgressiveResult<()> {
        let name = name.map(|name| {
            let mut end = name.len().min(MAX_DAMAGE_NAME);
            while !name.is_char_boundary(end) {
                end -= 1;
            }
            &name[..end]
        });
        let charge = std::mem::size_of::<HeaderDamage>()
            + self.expected.len()
            + name.map_or(0, str::len)
            + std::mem::size_of::<(u32, HeaderDamage)>();
        self.usage.charge(Resource::MetadataBytes, charge as u64)?;
        self.damage.try_reserve(1).map_err(|_| ProgressiveFailure::new(FailureKind::Malformed("damage allocation")))?;
        let damage = HeaderDamage {
            volume: std::path::PathBuf::from(self.expected.clone()),
            offset,
            kind,
            name: name.map(str::to_owned),
            resumed_at,
            passed_over,
        };
        if passed_over && self.member.is_none() {
            // Bytes that may hold a member's compressed stream were passed over: a solid member after the gap fails as
            // lacking its history instead of decoding against the history from before the gap. A member still being
            // continued keeps its decoder: its own checks decide.
            self.history.take();
            self.rar4_history.take();
            self.history_failure = None;
        }
        self.damage.push_back((self.volume, damage));
        Ok(())
    }
    /// A header that failed its checksum but parsed, read as it stands. False when the frame is to be dropped: a
    /// damaged main header past the first volume's (or a second one in a volume, which only damage produces), which
    /// holds nothing to read. The first volume's damaged main header describes the archive, as for a whole archive;
    /// a later volume's is taken as present without checking its now unreliable identity against the first.
    pub(super) fn damaged_frame(&mut self, frame: &PhysicalFrame) -> ProgressiveResult<bool> {
        let name = match &frame.block {
            Block::File(h) | Block::Service(h) => Some(h.name.as_str()),
            _ => None,
        };
        // As the whole-archive runners: the history survives only a header read as a compressed file, whose data is
        // decoded into it in turn. Read as anything else its data, which may be a member's compressed stream, is
        // skipped unread.
        let carries_data = frame.data_end > frame.extent.end;
        let passed_over = match &frame.block {
            Block::File(h) => carries_data && (h.method == 0 || h.is_dir() || h.redirection.is_some()),
            Block::Main(_) | Block::End { .. } => carries_data,
            _ => true,
        };
        self.header_damage(frame.extent.start, HeaderDamageKind::ChecksumMismatch, name, None, passed_over)?;
        if matches!(frame.block, Block::Main(_)) && (self.main_seen || self.volume > 0) {
            self.main_seen = true;
            return Ok(false);
        }
        Ok(true)
    }
    /// The header at the parser's offset is damage of `kind`: searched past under `Resync`, else the rest of the
    /// volume is passed over.
    pub(super) fn salvage_header(&mut self, kind: HeaderDamageKind) -> ProgressiveResult<()> {
        let at = self.parser.header_offset();
        if self.parser.resyncs() {
            let mut window = std::mem::take(&mut self.resync_window);
            window.clear();
            self.phase = Phase::Resync(Box::new(Resync {
                damage_at: at,
                kind,
                pos: at.saturating_add(1),
                window,
                start: at.saturating_add(1),
                eof: false,
                chunk: RESYNC_FIRST_CHUNK,
            }));
            return Ok(());
        }
        self.header_damage(at, kind, None, None, true)?;
        self.end_damaged_volume()
    }
    /// The volume ended at a block boundary without its end header. A RAR 5.0 volume is cut short there (7-Zip 26.06:
    /// "Unexpected end of archive"); a RAR 4.x one may end so (archives older than RAR 2.9 write no end block).
    pub(super) fn salvage_volume_end(&mut self) -> ProgressiveResult<()> {
        // a source that ends before a RAR signature was found is not a RAR volume, damaged or not
        if self.parser.scanning() {
            return Err(self.parser.truncated());
        }
        if !self.parser.at_block_start() {
            return self.salvage_header(HeaderDamageKind::UnexpectedEnd);
        }
        if self.parser.format() == crate::rar5::RarFormat::Rar5 {
            self.header_damage(self.parser.header_offset(), HeaderDamageKind::UnexpectedEnd, None, None, true)?;
        }
        self.end_damaged_volume()
    }
    /// The rest of the volume is passed over: a set goes on with its next volume, as the whole-archive runners do, and
    /// may end there when no next volume follows; otherwise the session is done.
    fn end_damaged_volume(&mut self) -> ProgressiveResult<()> {
        if self.volume_set == Some(true) {
            // a member split into the next volume needs it; between members the set may end here
            self.pre_29_open_end = self.member.is_none();
            self.phase = Phase::NextVolume;
            return Ok(());
        }
        if self.member.is_some() {
            return Err(ProgressiveFailure::new(FailureKind::Truncated));
        }
        if let Some(output) = &mut self.output {
            output.finish_directories(&mut self.driver)?;
        }
        self.phase = Phase::Done;
        Ok(())
    }
    /// One step of a resync: reads the volume on from where it got to and tries every position for a header that
    /// passes its checksum. `Ok(None)` to go on polling (the phase may have changed), or the poll result to return.
    pub(super) fn poll_resync(
        &mut self,
        cx: &mut Context<'_>,
        work: &mut u64,
    ) -> ProgressiveResult<Option<Poll<ProgressiveResult<Option<ProgressiveEvent>>>>> {
        let Phase::Resync(scan) = &mut self.phase else { unreachable!() };
        let format = self.parser.format();
        let end = self.parser.complete_len();
        // try the positions the window shows whole
        let mut found = None;
        let mut exhausted = false;
        loop {
            let held_end = scan.start + scan.window.len() as u64;
            let limit = if scan.eof { held_end } else { end.unwrap_or(u64::MAX) };
            if scan.pos >= limit {
                exhausted = true;
                break;
            }
            let i = (scan.pos - scan.start) as usize;
            let shown = &scan.window[i..];
            if !scan.eof && shown.len() < RESYNC_LOOKAHEAD && held_end < limit {
                break;
            }
            if let Some(total) = resync_shape(shown, format) {
                let fits = scan.pos.checked_add(total as u64).is_some_and(|candidate_end| candidate_end <= limit);
                if fits {
                    if shown.len() < total {
                        break;
                    }
                    if !self.resync_work.charge(total as u64) {
                        exhausted = true;
                        break;
                    }
                    if resync_checks(&shown[..total], format) {
                        found = Some(scan.pos);
                        break;
                    }
                }
            }
            scan.pos += 1;
        }
        if found.is_some() || exhausted {
            let Phase::Resync(scan) = std::mem::replace(&mut self.phase, Phase::Header) else { unreachable!() };
            let Resync { damage_at, kind, window, .. } = *scan;
            self.resync_window = window;
            self.header_damage(damage_at, kind, None, found, true)?;
            match found {
                Some(at) => {
                    self.parser.resume_at(at);
                    // a resync past an unreadable main header lands on a member: read on with an empty main header,
                    // as the whole-archive runners do
                    self.main_seen = true;
                }
                None => self.end_damaged_volume()?,
            }
            return Ok(None);
        }
        // more bytes: drop what no candidate needs any more, then read on
        let Phase::Resync(scan) = &mut self.phase else { unreachable!() };
        let drop = (scan.pos - scan.start) as usize;
        scan.window.drain(..drop);
        scan.start = scan.pos;
        let at = scan.start + scan.window.len() as u64;
        let full = scan.chunk.min(end.map_or(usize::MAX, |end| end.saturating_sub(at).min(usize::MAX as u64) as usize));
        if full == 0 {
            scan.eof = true;
            return Ok(None);
        }
        let budget = (self.options.limits.packed_work_per_poll.min(1 << 20) - *work) as usize;
        let n = match self.parked_read.take() {
            Some(parked) if parked <= full.min(self.buffer.len()) => parked,
            _ => full.min(self.buffer.len()).min(budget).max(1),
        };
        if at != self.cursor {
            self.driver.seek(at)?;
            self.cursor = at;
        }
        match self.driver.poll_step(cx, &mut self.buffer[..n]) {
            Poll::Pending => {
                self.parked_read = Some(n);
                Ok(Some(Poll::Pending))
            }
            Poll::Ready(Err(e)) => Err(e),
            Poll::Ready(Ok(SourceStep::VolumeOpened { .. })) => {
                Err(ProgressiveFailure::new(FailureKind::SourceContract))
            }
            Poll::Ready(Ok(SourceStep::EndOfVolume)) => {
                let Phase::Resync(scan) = &mut self.phase else { unreachable!() };
                scan.eof = true;
                Ok(None)
            }
            Poll::Ready(Ok(SourceStep::Hole { offset, .. })) => {
                // the next header may be in it, and repair may still fill it: never searched across
                let mut failure = ProgressiveFailure::new(FailureKind::HeaderHole);
                failure.context.packed_offset = Some(offset);
                Err(failure)
            }
            Poll::Ready(Ok(SourceStep::Filled { offset, count })) => {
                self.cursor = offset + count as u64;
                *work += count as u64;
                self.resync_work.furthest = self.resync_work.furthest.max(self.cursor);
                let Phase::Resync(scan) = &mut self.phase else { unreachable!() };
                if offset != scan.start + scan.window.len() as u64 {
                    return Err(ProgressiveFailure::new(FailureKind::SourceContract));
                }
                // only the bytes delivered count as work: a short read or a wait costs nothing
                if !self.resync_work.charge(count as u64) {
                    scan.eof = true;
                    self.driver.validate_step()?;
                    return Ok(None);
                }
                // the window holds at most a candidate's bytes and one chunk: its capacity is charged as it grows
                let before = scan.window.capacity();
                if scan.window.len() + count > before {
                    let wanted = (scan.window.len() + count).max(RESYNC_CANDIDATE_MAX + RESYNC_CHUNK.min(1 << 16));
                    self.usage.charge(Resource::MetadataBytes, (wanted - before) as u64)?;
                    scan.window
                        .try_reserve_exact(wanted - scan.window.len())
                        .map_err(|_| ProgressiveFailure::new(FailureKind::Malformed("resync allocation")))?;
                    self.usage.charge(Resource::MetadataBytes, scan.window.capacity().saturating_sub(wanted) as u64)?;
                }
                scan.window.extend_from_slice(&self.buffer[..count]);
                scan.chunk = scan.chunk.saturating_mul(2).min(RESYNC_CHUNK);
                self.driver.validate_step()?;
                Ok(None)
            }
        }
    }
}
