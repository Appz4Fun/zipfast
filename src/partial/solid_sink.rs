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

//! A [`FeedSink`] over the members of one solid stream (RAR) or folder (7z): the member being decoded writes to its
//! own direct partial, and [`FeedSink::read_earlier`] reads the durable output of the members before it at
//! offsets in the stream's output, which is what [`crate::map::FeedDecoder::resume_solid`] and a solid successor
//! restored from a snapshot need after a restart.
use super::*;
use crate::map::{FeedSink, FolderSlot, MapFormat, MapMethod, MemberMap};

/// One member's place in its solid stream's output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamSlot {
    /// Index into [`MemberMap::members`].
    pub member: usize,
    /// Where the member's output starts in the stream's output (`FeedDecoder::stream_start`).
    pub start: u64,
    /// The member's output size.
    pub size: u64,
}

/// The members that make up the solid stream (RAR 4.x and 5.0) or folder (7z) of member `index`, up to and
/// including it, in stream order, with their stream offsets. Members that produce no output through the stream
/// (directories, stored RAR members, empty members) are left out; another format gives the member alone at 0.
pub fn stream_slots(map: &MemberMap, index: usize) -> PartialResult<Vec<StreamSlot>> {
    let member = map.members.get(index).ok_or_else(|| err(PartialErrorKind::InvalidOptions))?;
    let size = |i: usize| map.members[i].unpacked_size.ok_or_else(|| err(PartialErrorKind::InvalidOptions));
    let mut slots = Vec::new();
    match map.format {
        MapFormat::Rar4 | MapFormat::Rar5 => {
            let decodes = |m: &crate::map::MapMember| !m.is_dir && matches!(m.method, MapMethod::Compressed { .. });
            let mut first = index;
            if member.solid {
                for i in (0..index).rev() {
                    if decodes(&map.members[i]) {
                        first = i;
                        if !map.members[i].solid {
                            break;
                        }
                    }
                }
            }
            let mut at = 0u64;
            for (i, m) in map.members.iter().enumerate().take(index + 1).skip(first) {
                if !decodes(m) {
                    continue;
                }
                let s = size(i)?;
                slots.push(StreamSlot { member: i, start: at, size: s });
                at = at.checked_add(s).ok_or_else(|| err(PartialErrorKind::InvalidOptions))?;
            }
        }
        MapFormat::SevenZip => {
            let FolderSlot { index: folder, offset } =
                member.folder.ok_or_else(|| err(PartialErrorKind::InvalidOptions))?;
            for (i, m) in map.members.iter().enumerate() {
                if let Some(f) = m.folder.filter(|f| f.index == folder && f.offset <= offset) {
                    let s = size(i)?;
                    if s > 0 || i == index {
                        slots.push(StreamSlot { member: i, start: f.offset, size: s });
                    }
                }
            }
            slots.sort_by_key(|s| s.start);
        }
        _ => slots.push(StreamSlot { member: index, start: 0, size: size(index)? }),
    }
    if slots.last().is_none_or(|s| s.member != index) {
        return Err(err(PartialErrorKind::InvalidOptions));
    }
    Ok(slots)
}

struct Slot {
    start: u64,
    size: u64,
    sink: DirectSink,
}

/// A [`FeedSink`] for the last member of a solid stream, over the direct partials of the members before it too.
///
/// [`FeedSink::write_at`] and [`FeedSink::read_held`] (member offsets) go to the current member's [`DirectSink`]
/// (the last one); [`FeedSink::read_earlier`] (stream offsets before the current member's start) reads the output
/// the earlier members' partials know, across member boundaries, stopping at the first byte not known. Bytes an
/// earlier member skipped over a hole and has not repaired are not known, so a decoder that needs them fails with
/// `FeedError::EarlierOutput` rather than reading a guess.
pub struct SolidStreamSink {
    slots: Vec<Slot>,
}

impl SolidStreamSink {
    /// A sink over `members` in stream order, each `(stream start, output size, partial)`; the last is the current
    /// member. Starts must not decrease and members must not overlap.
    pub fn new(members: Vec<(u64, u64, PartialFile)>) -> PartialResult<Self> {
        let mut end = 0u64;
        let mut slots = Vec::with_capacity(members.len());
        for (start, size, file) in members {
            if start < end || start.checked_add(size).is_none() {
                return Err(err(PartialErrorKind::InvalidOptions));
            }
            end = start + size;
            slots.push(Slot { start, size, sink: DirectSink::new(file) });
        }
        if slots.is_empty() {
            return Err(err(PartialErrorKind::InvalidOptions));
        }
        Ok(Self { slots })
    }

    /// Opens (or reopens after a restart) the partials of member `index`'s stream up to it ([`stream_slots`],
    /// [`DirectPartials::open`]) as a sink whose current member is `index`.
    pub fn open(partials: &DirectPartials, map: &MemberMap, index: usize) -> PartialResult<Self> {
        let layout = stream_slots(map, index)?;
        let mut members = Vec::with_capacity(layout.len());
        for s in layout {
            members.push((s.start, s.size, partials.open(map, s.member)?.file));
        }
        Self::new(members)
    }

    /// Makes a member of `size` output bytes, starting where the current one ends, the current member.
    pub fn push_member(&mut self, file: PartialFile, size: u64) {
        let last = self.slots.last().expect("a sink has a member");
        let start = last.start + last.size;
        self.slots.push(Slot { start, size, sink: DirectSink::new(file) });
    }

    /// Opens member `index`, the next member of the stream after the current one, and makes it the current member,
    /// keeping the handles of the members before it (which [`Self::open`] cannot reopen while they live). Use it
    /// when the decoder hands over in-session ([`crate::map::FeedDecoder::next_solid`]). `InvalidOptions` when
    /// `index` does not follow the current member in its stream (nothing changes).
    pub fn next_member(&mut self, partials: &DirectPartials, map: &MemberMap, index: usize) -> PartialResult<()> {
        let layout = stream_slots(map, index)?;
        let last = self.slots.last().expect("a sink has a member");
        let [.., before, this] = layout.as_slice() else { return Err(err(PartialErrorKind::InvalidOptions)) };
        if before.start != last.start || before.size != last.size || this.start != last.start + last.size {
            return Err(err(PartialErrorKind::InvalidOptions));
        }
        let file = partials.open(map, index)?.file;
        self.push_member(file, this.size);
        Ok(())
    }

    /// Where the current member's output starts in the stream (`FeedDecoder::stream_start` of its decoder).
    pub fn stream_start(&self) -> u64 {
        self.slots.last().expect("a sink has a member").start
    }
    /// The current member's sink.
    pub fn current(&self) -> &DirectSink {
        &self.slots.last().expect("a sink has a member").sink
    }
    pub fn current_mut(&mut self) -> &mut DirectSink {
        &mut self.slots.last_mut().expect("a sink has a member").sink
    }
    /// Sets the current member's cursor ([`DirectSink::set_cursor`]).
    pub fn set_cursor(&mut self, cursor: &[u8]) -> PartialResult<()> {
        self.current_mut().set_cursor(cursor)
    }
    /// Commits the current member's open group now ([`DirectSink::commit`]).
    pub fn commit(&mut self) -> PartialResult<PartialState> {
        self.current_mut().commit()
    }
    /// The sinks of the members of the stream, in order, the current member last.
    pub fn sinks(&self) -> impl Iterator<Item = &DirectSink> {
        self.slots.iter().map(|s| &s.sink)
    }
    /// The partials, in stream order, the current member's last.
    pub fn into_files(self) -> Vec<PartialFile> {
        self.slots.into_iter().map(|s| s.sink.into_file()).collect()
    }
}

impl FeedSink for SolidStreamSink {
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> std::io::Result<()> {
        self.current_mut().write_at(offset, bytes)
    }
    fn read_held(&mut self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        self.current_mut().read_held(offset, buf)
    }
    fn read_earlier(&mut self, stream_offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let current = self.slots.len() - 1;
        let limit = self.slots[current].start;
        let mut got = 0;
        while got < buf.len() {
            let at = stream_offset + got as u64;
            if at >= limit {
                break;
            }
            // the first member whose output reaches past `at`
            let j = self.slots.partition_point(|s| s.start + s.size <= at);
            let Some(s) = self.slots.get_mut(j).filter(|s| j < current && s.start <= at) else { break };
            let room = ((s.start + s.size - at) as usize).min(buf.len() - got);
            let n = s.sink.read_held(at - s.start, &mut buf[got..got + room])?;
            if n == 0 {
                break;
            }
            got += n;
        }
        Ok(got)
    }
}
