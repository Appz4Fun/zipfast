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

//! The split ZIP walker: an Info-ZIP spanned set `name.z01`, `name.z02`, ..., `name.zip`, whose disks are numbered
//! from 0 in that order.
//!
//! It finds the last volume (the one holding the end of central directory record), reads the central directory over
//! the volumes that hold it, then each entry's local header on its own disk and the volumes its data crosses.
use super::zip::{CHUNK, ZipPiece, directory, zip_limits, zip_member};
use super::{Got, MapEnd, MapError, MapFormat, MapInput, MapMember, MapOptions, MemberMap, Opened, read};
use crate::progressive::{FailureKind, ProgressiveFailure, Resource, Usage, VolumeRequest};
use crate::zip::ZipEntry;
use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::task::{Context, Poll};
use zip_container::{DirectoryError, DirectoryParser, LOCAL_HEADER_LEN, Limits, LocalHeader, ReducedCentralRecord};

const END_LEN: usize = 22;
const LOCATOR_LEN: usize = 20;
const END64_LEN: usize = 56;
/// The end record, a comment of up to 64 KiB, and the ZIP64 locator before it.
const TAIL_MAX: u64 = (END_LEN + u16::MAX as usize + LOCATOR_LEN) as u64;
/// How many indexes in a row may lack a volume, while looking for the last one through a source that keys on the
/// index, before the last volume is taken to be missing.
const MAX_GAP: u32 = 64;
/// Bytes of the smallest data descriptor (no signature, 32-bit sizes).
const DESCRIPTOR_MIN: u64 = 12;
/// The spanning signature an Info-ZIP split set's first volume starts with.
pub(super) const SPLIT_MARKER: &[u8; 4] = b"PK\x07\x08";

/// Whether `first_name` names the first volume of a split set (`.z01`, any case).
pub(super) fn is_split_name(first_name: &OsStr) -> bool {
    Path::new(first_name).extension().is_some_and(|ext| ext.eq_ignore_ascii_case("z01"))
}

/// The name of volume `index` of the split set whose first volume is `first`: the first name with its extension
/// replaced by `z01`, `z02`, ... (`z100` after `z99`), or by `zip` for the last volume. The extension is upper case
/// when the first name's is.
pub(crate) fn split_volume_name(first: &OsStr, index: u32, last: bool) -> OsString {
    let path = Path::new(first);
    let upper = path.extension().and_then(OsStr::to_str).is_some_and(|ext| ext.starts_with('Z'));
    let ext = if last { "zip".to_owned() } else { format!("z{:02}", u64::from(index) + 1) };
    path.with_extension(if upper { ext.to_ascii_uppercase() } else { ext }).into_os_string()
}

fn malformed(volume: u32, reason: &'static str) -> MapError {
    MapError::Malformed { volume, failure: Box::new(ProgressiveFailure::new(FailureKind::Malformed(reason))) }
}

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}
fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().expect("4 bytes"))
}
fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().expect("8 bytes"))
}

/// A directory entry and the disk its local header is on.
#[derive(Clone)]
struct SplitEntry {
    entry: ZipEntry,
    disk: u32,
}

fn project(record: ReducedCentralRecord<'_>) -> Result<SplitEntry, DirectoryError> {
    let disk = record.resolved().disk_start;
    Ok(SplitEntry { entry: crate::zip::project_record(record)?, disk })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Vol {
    /// Not asked for yet.
    Unknown,
    Present(u64),
    Missing,
}

/// A position in the set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Pos {
    vol: u32,
    off: u64,
}

/// What the end record says about the set.
#[derive(Clone, Copy, Debug)]
struct End {
    /// The disk holding the end record: the last one.
    last: u32,
    /// The classic end record's offset in that disk.
    at: u64,
    /// The disk the central directory starts on, when the classic record states it.
    directory_disk: Option<u32>,
    /// The ZIP64 end record's disk and offset, from the locator.
    zip64: Option<Pos>,
}

enum Avail {
    Ready(u64),
    Pending,
    Missing,
}

enum Gathered {
    Full,
    Pending,
    /// Volume `0` is missing.
    Missing(u32),
    /// The bytes ended at the end of the last volume allowed, or a source shrank.
    Eof,
}

enum Step {
    /// Opening the local header's disk.
    Open,
    /// Gathering the fixed local header.
    Header,
    /// Finding where the data starts.
    Data { header: LocalHeader },
    /// Placing the data on the volumes it crosses.
    Pieces { header: LocalHeader, data: Pos, cursor: Pos, remaining: u64, pieces: Vec<ZipPiece> },
    /// Checking the data descriptor after data that crosses a volume boundary.
    Descriptor { header: LocalHeader, data: Pos, pieces: Vec<ZipPiece>, lead: bool },
    /// Gathering the WinZip AES salt and verifier.
    Prefix { header: LocalHeader, data: Pos, pieces: Vec<ZipPiece> },
}

enum Phase {
    Start,
    /// Asking for volume `index` under its numbered name, then (`last_name`) under the last volume's name.
    Probe {
        index: u32,
        last_name: bool,
    },
    /// Looking for the end record at the end of volume `vol`. `named`: it answered to the last volume's name.
    /// `resume`: where probing goes on when the volume holds none.
    Tail {
        vol: u32,
        named: bool,
        resume: Option<u32>,
        wide: bool,
    },
    Zip64 {
        end: End,
    },
    Volumes {
        end: End,
        directory_disk: u32,
        next: u32,
    },
    Directory {
        parser: Box<DirectoryParser<SplitEntry>>,
        first: u32,
        bases: Vec<u64>,
        zip64: Option<Pos>,
    },
    Locals {
        entries: Vec<SplitEntry>,
        index: usize,
        step: Step,
    },
}

pub(super) struct ZipSplitWalker {
    usage: Usage,
    limits: Limits,
    first_name: OsString,
    phase: Phase,
    vols: Vec<Vol>,
    /// The last volume's index, once the end record was found.
    last: Option<u32>,
    parked: Option<usize>,
    buffer: Vec<u8>,
    /// Bytes gathered for the current step, and where the next one is read.
    scratch: Vec<u8>,
    at: Pos,
    members: Vec<MapMember>,
    /// The first availability problem met: the map's end.
    end: Option<MapEnd>,
    /// The volume count, when the input knows it (volumes in memory): the last one is then the `.zip`.
    count: Option<u32>,
    /// Indexes in a row without a volume while looking for the last one.
    gap: u32,
    /// Volumes held open, least recently used first, at most `handles` of them.
    kept: Vec<u32>,
    handles: u64,
    /// Where each local header and the central directory start, in order: a member's data must end before the next.
    starts: Vec<Pos>,
}

impl ZipSplitWalker {
    pub(super) fn new(usage: Usage, options: &MapOptions) -> Self {
        Self {
            usage,
            limits: zip_limits(&options.limits),
            first_name: options.first_name.clone(),
            phase: Phase::Start,
            vols: Vec::new(),
            last: None,
            parked: None,
            buffer: vec![0; CHUNK],
            scratch: Vec::new(),
            at: Pos { vol: 0, off: 0 },
            members: Vec::new(),
            end: None,
            count: None,
            gap: 0,
            kept: Vec::new(),
            handles: options.limits.volume_handles,
            starts: Vec::new(),
        }
    }

    pub(super) fn poll(
        &mut self,
        input: &mut dyn MapInput,
        cx: &mut Context<'_>,
        options: &MapOptions,
    ) -> Poll<Result<MemberMap, MapError>> {
        match self.poll_inner(input, cx, options) {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(map)) => Poll::Ready(Ok(map)),
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn vol(&self, index: u32) -> Vol {
        self.vols.get(index as usize).copied().unwrap_or(Vol::Unknown)
    }

    /// Records what volume `index` is. Growing the list is charged to the metadata budget, since a hostile end
    /// record can name any disk.
    fn set_vol(&mut self, index: u32, state: Vol) -> Result<(), MapError> {
        let i = index as usize;
        if self.vols.len() <= i {
            let grow = (u64::from(index) + 1 - self.vols.len() as u64) * std::mem::size_of::<Vol>() as u64;
            self.charge(Resource::MetadataBytes, grow, index)?;
            self.vols.resize(i + 1, Vol::Unknown);
        }
        self.vols[i] = state;
        Ok(())
    }

    fn charge(&self, resource: Resource, amount: u64, volume: u32) -> Result<(), MapError> {
        self.usage.charge(resource, amount).map_err(|e| MapError::from_failure(volume, e))
    }

    /// Asks the source for volume `index` under `name`. An empty volume counts as missing: no volume of a set is
    /// empty, and it lets a caller holding volumes in memory pass a missing one as an empty slice.
    ///
    /// The first name is never asked for again under another index: a first volume renamed to the last volume's name
    /// (a one-volume set named `name.zip`) would otherwise come back as a second volume.
    fn open(
        &mut self,
        input: &mut dyn MapInput,
        cx: &mut Context<'_>,
        index: u32,
        name: OsString,
    ) -> Result<Avail, MapError> {
        if index > 0 && name == self.first_name {
            return Ok(Avail::Missing);
        }
        self.charge(Resource::MetadataBytes, name.len() as u64, index)?;
        let request = VolumeRequest { index, expected: name };
        match input.open(&request, cx).map_err(|e| MapError::from_failure(index, e))? {
            Opened::Ready if input.len() > 0 => {
                let len = input.len();
                self.keep(input, index)?;
                Ok(Avail::Ready(len))
            }
            Opened::Ready | Opened::Missing => Ok(Avail::Missing),
            Opened::Wait => Ok(Avail::Pending),
            Opened::Abort => Err(MapError::Aborted { volume: index }),
        }
    }

    /// The name volume `index` is asked for under once the search for the last volume is over: the first name for
    /// volume 0 (whatever its pattern), the derived names otherwise.
    fn volume_name(&self, index: u32) -> OsString {
        if index == 0 {
            return self.first_name.clone();
        }
        split_volume_name(&self.first_name, index, self.last == Some(index))
    }

    /// Keeps the current volume open under `slot`. At most `volume_handles` volumes stay open: past that, the one
    /// used least recently is closed, and asked for again if it is needed later.
    fn keep(&mut self, input: &mut dyn MapInput, slot: u32) -> Result<(), MapError> {
        if let Some(i) = self.kept.iter().position(|&k| k == slot) {
            self.kept.remove(i);
        } else {
            if self.handles == 0 {
                return Err(MapError::Limit { resource: Resource::VolumeHandles, limit: 0, attempted: 1 });
            }
            while self.kept.len() as u64 >= self.handles {
                let oldest = self.kept.remove(0);
                input.release(oldest);
            }
        }
        self.kept.push(slot);
        input.keep(slot);
        Ok(())
    }

    /// Makes volume `index` current, asking for it under its name the first time, or again after it was closed.
    fn ensure(&mut self, input: &mut dyn MapInput, cx: &mut Context<'_>, index: u32) -> Result<Avail, MapError> {
        match self.vol(index) {
            Vol::Missing => Ok(Avail::Missing),
            Vol::Present(len) if self.kept.contains(&index) => {
                if !input.select(index) {
                    return Err(MapError::Source(Box::new(ProgressiveFailure::new(FailureKind::SourceContract))));
                }
                let i = self.kept.iter().position(|&k| k == index).expect("kept");
                self.kept.remove(i);
                self.kept.push(index);
                Ok(Avail::Ready(len))
            }
            Vol::Present(len) => {
                let name = self.volume_name(index);
                match self.open(input, cx, index, name)? {
                    Avail::Ready(again) if again != len => {
                        Err(MapError::Source(Box::new(ProgressiveFailure::new(FailureKind::SourceChanged))))
                    }
                    Avail::Missing => {
                        Err(MapError::Source(Box::new(ProgressiveFailure::new(FailureKind::SourceChanged))))
                    }
                    avail => Ok(avail),
                }
            }
            Vol::Unknown => {
                let name = self.volume_name(index);
                let avail = self.open(input, cx, index, name)?;
                match avail {
                    Avail::Ready(len) => self.set_vol(index, Vol::Present(len))?,
                    Avail::Missing => self.set_vol(index, Vol::Missing)?,
                    Avail::Pending => {}
                }
                Ok(avail)
            }
        }
    }

    /// Gathers bytes into `scratch` from `self.at` until it holds `want`, moving on to the next volume at the end of
    /// one while the volume is before `through`.
    fn gather(
        &mut self,
        input: &mut dyn MapInput,
        cx: &mut Context<'_>,
        want: usize,
        through: u32,
    ) -> Result<Gathered, MapError> {
        loop {
            if self.scratch.len() >= want {
                return Ok(Gathered::Full);
            }
            let Pos { vol, off } = self.at;
            let len = match self.ensure(input, cx, vol)? {
                Avail::Ready(len) => len,
                Avail::Pending => return Ok(Gathered::Pending),
                Avail::Missing => return Ok(Gathered::Missing(vol)),
            };
            if off >= len {
                if vol >= through {
                    return Ok(Gathered::Eof);
                }
                self.at = Pos { vol: vol + 1, off: 0 };
                continue;
            }
            let room = usize::try_from(len - off).unwrap_or(usize::MAX);
            let n = self.parked.take().unwrap_or_else(|| (want - self.scratch.len()).min(room).min(CHUNK));
            match read(input, &self.usage, off, &mut self.buffer[..n], cx)
                .map_err(|e| MapError::from_failure(vol, e))?
            {
                Got::NotYet => {
                    self.parked = Some(n);
                    return Ok(Gathered::Pending);
                }
                Got::Hole => return Err(MapError::HeaderHole { volume: vol, offset: off }),
                Got::Eof => return Ok(Gathered::Eof),
                Got::Filled(count) => {
                    let count = count.min(n);
                    self.charge(Resource::HeaderBytes, count as u64, vol)?;
                    self.scratch.extend_from_slice(&self.buffer[..count]);
                    self.at.off += count as u64;
                }
            }
        }
    }

    /// Starts gathering at `at`.
    fn start_gather(&mut self, at: Pos) {
        self.scratch.clear();
        self.at = at;
        self.parked = None;
    }

    fn poll_inner(
        &mut self,
        input: &mut dyn MapInput,
        cx: &mut Context<'_>,
        options: &MapOptions,
    ) -> Result<Poll<MemberMap>, MapError> {
        loop {
            if options.control.is_canceled() {
                return Err(MapError::Source(Box::new(ProgressiveFailure::new(FailureKind::Canceled))));
            }
            match &mut self.phase {
                Phase::Start => {
                    // The format detection left volume 0 open.
                    self.set_vol(0, Vol::Present(input.len()))?;
                    self.keep(input, 0)?;
                    self.count = input.count();
                    match self.count {
                        // Volumes in memory: the last one is the `.zip`.
                        Some(1) => self.enter_tail(0, true, None, false),
                        Some(count) => self.phase = Phase::Probe { index: count - 1, last_name: true },
                        None => self.phase = Phase::Probe { index: 1, last_name: false },
                    }
                }
                &mut Phase::Probe { index, last_name } => {
                    if let Some(poll) = self.probe(input, cx, index, last_name)? {
                        return Ok(poll);
                    }
                }
                &mut Phase::Tail { vol, named, resume, wide } => {
                    if let Some(poll) = self.tail(input, cx, vol, named, resume, wide)? {
                        return Ok(poll);
                    }
                }
                &mut Phase::Zip64 { end } => {
                    let at = end.zip64.expect("ZIP64 locator");
                    match self.gather(input, cx, END64_LEN, at.vol)? {
                        Gathered::Pending => return Ok(Poll::Pending),
                        Gathered::Missing(v) => return Err(MapError::MissingDirectory { volume: v }),
                        Gathered::Eof => return Err(malformed(at.vol, "ZIP64 end record")),
                        Gathered::Full => {}
                    }
                    let record = &self.scratch[..END64_LEN];
                    if &record[..4] != b"PK\x06\x06" || le32(record, 16) != end.last {
                        return Err(malformed(at.vol, "ZIP64 end record"));
                    }
                    let directory_disk = le32(record, 20);
                    self.scratch.clear();
                    self.begin_volumes(end, directory_disk)?;
                }
                &mut Phase::Volumes { end, directory_disk, next } => {
                    match self.ensure(input, cx, next)? {
                        Avail::Pending => return Ok(Poll::Pending),
                        Avail::Missing => return Err(MapError::MissingDirectory { volume: next }),
                        Avail::Ready(_) => {}
                    }
                    if next < end.last {
                        self.phase = Phase::Volumes { end, directory_disk, next: next + 1 };
                        continue;
                    }
                    self.begin_directory(end, directory_disk)?;
                }
                Phase::Directory { .. } => {
                    if let Some(poll) = self.directory(input, cx)? {
                        return Ok(poll);
                    }
                }
                Phase::Locals { .. } => {
                    if let Some(poll) = self.locals(input, cx)? {
                        return Ok(poll);
                    }
                }
            }
        }
    }

    /// Finds the last volume: volumes are asked for in order under their numbered names; a volume missing under its
    /// numbered name is asked for again under the last volume's name.
    fn probe(
        &mut self,
        input: &mut dyn MapInput,
        cx: &mut Context<'_>,
        index: u32,
        last_name: bool,
    ) -> Result<Option<Poll<MemberMap>>, MapError> {
        let name = split_volume_name(&self.first_name, index, last_name);
        match self.open(input, cx, index, name)? {
            Avail::Pending => Ok(Some(Poll::Pending)),
            Avail::Ready(len) => {
                self.set_vol(index, Vol::Present(len))?;
                self.gap = 0;
                if last_name {
                    self.enter_tail(index, true, None, false);
                } else {
                    let next = index.checked_add(1).ok_or_else(|| malformed(index, "split ZIP volume count"))?;
                    self.phase = Phase::Probe { index: next, last_name: false };
                }
                Ok(None)
            }
            Avail::Missing if !last_name => {
                self.phase = Phase::Probe { index, last_name: true };
                Ok(None)
            }
            Avail::Missing if self.count.is_some() => Err(MapError::MissingDirectory { volume: index }),
            Avail::Missing => {
                self.set_vol(index, Vol::Missing)?;
                self.gap += 1;
                let resume = index.checked_add(1).ok_or_else(|| malformed(index, "split ZIP volume count"))?;
                if self.gap == 1 && matches!(self.vol(index - 1), Vol::Present(_)) {
                    // A source that answers by index gives the last volume under its numbered name: it may be the one
                    // before the first index nothing answers. Its end record must say so.
                    self.enter_tail(index - 1, false, Some(resume), false);
                } else if self.gap > MAX_GAP {
                    return Err(MapError::MissingDirectory { volume: index + 1 - self.gap });
                } else {
                    // Middle volumes may be missing: look further.
                    self.phase = Phase::Probe { index: resume, last_name: false };
                }
                Ok(None)
            }
        }
    }

    fn enter_tail(&mut self, vol: u32, named: bool, resume: Option<u32>, wide: bool) {
        let Vol::Present(len) = self.vol(vol) else { unreachable!("tail of a present volume") };
        self.start_gather(Pos { vol, off: len - tail_span(len, wide) });
        self.phase = Phase::Tail { vol, named, resume, wide };
    }

    /// Looks for the end record at the end of volume `vol`: the last 42 bytes first, then the most a comment allows.
    fn tail(
        &mut self,
        input: &mut dyn MapInput,
        cx: &mut Context<'_>,
        vol: u32,
        named: bool,
        resume: Option<u32>,
        wide: bool,
    ) -> Result<Option<Poll<MemberMap>>, MapError> {
        let Vol::Present(len) = self.vol(vol) else { unreachable!("tail of a present volume") };
        let span = tail_span(len, wide);
        match self.gather(input, cx, span as usize, vol)? {
            Gathered::Pending => return Ok(Some(Poll::Pending)),
            Gathered::Missing(_) | Gathered::Eof => return Err(MapError::MissingDirectory { volume: vol }),
            Gathered::Full => {}
        }
        let tail = std::mem::take(&mut self.scratch);
        let found = find_end(&tail);
        let Some(at) = found else {
            if !wide && span < tail_span(len, true) {
                self.enter_tail(vol, named, resume, true);
                return Ok(None);
            }
            return match resume {
                Some(index) => {
                    self.phase = Phase::Probe { index, last_name: false };
                    Ok(None)
                }
                None => Err(MapError::MissingDirectory { volume: vol }),
            };
        };
        let record = &tail[at..at + END_LEN];
        let locator = at
            .checked_sub(LOCATOR_LEN)
            .map(|l| &tail[l..at])
            .filter(|l| l.starts_with(b"PK\x06\x07"))
            .map(|l| (Pos { vol: le32(l, 4), off: le64(l, 8) }, le32(l, 16)));
        let disk16 = le16(record, 4);
        let last = match (disk16, locator) {
            (0xffff, Some((_, total))) => {
                total.checked_sub(1).ok_or_else(|| malformed(vol, "ZIP64 end locator disk count"))?
            }
            (0xffff, None) => return Err(malformed(vol, "ZIP64 end locator")),
            (disk, _) => u32::from(disk),
        };
        if locator.is_some_and(|(record, total)| u64::from(total) != u64::from(last) + 1 || record.vol > last) {
            return Err(malformed(vol, "ZIP64 end locator disk count"));
        }
        let dd16 = le16(record, 6);
        let end = End {
            last,
            at: len - span + at as u64,
            directory_disk: (dd16 != 0xffff).then_some(u32::from(dd16)),
            zip64: locator.map(|(record, _)| record),
        };
        if !named && !plausible_end(record, &end, vol) {
            // Not this volume's own end record (member data can look like one): look further.
            let index = resume.expect("unnamed tails resume");
            self.phase = Phase::Probe { index, last_name: false };
            return Ok(None);
        }
        // Bind the volume to its disk number.
        if last != vol {
            if last < vol || self.count.is_some() {
                return Err(malformed(vol, "split ZIP volume count does not match its end record"));
            }
            // A source that answers by name gave the last volume at the first index missing its numbered volume.
            self.set_vol(vol, Vol::Missing)?;
            self.set_vol(last, Vol::Present(len))?;
            self.kept.retain(|&k| k != vol);
            self.keep(input, last)?;
        }
        self.vols.truncate(last as usize + 1);
        self.last = Some(last);
        match (end.directory_disk, end.zip64) {
            (Some(directory_disk), _) => self.begin_volumes(end, directory_disk)?,
            (None, Some(at)) => {
                self.start_gather(at);
                self.phase = Phase::Zip64 { end };
            }
            (None, None) => return Err(malformed(vol, "ZIP64 end locator")),
        }
        Ok(None)
    }

    fn begin_volumes(&mut self, end: End, directory_disk: u32) -> Result<(), MapError> {
        if directory_disk > end.last {
            return Err(malformed(end.last, "central directory disk"));
        }
        self.phase = Phase::Volumes { end, directory_disk, next: directory_disk };
        Ok(())
    }

    /// Starts the directory parser over the volumes from the directory's first disk through the last.
    fn begin_directory(&mut self, end: End, first: u32) -> Result<(), MapError> {
        let mut bases = Vec::new();
        let mut total = 0u64;
        for v in first..=end.last {
            let Vol::Present(len) = self.vol(v) else { unreachable!("directory volumes are present") };
            bases.push(total);
            total = total.checked_add(len).ok_or_else(|| malformed(v, "split ZIP size"))?;
        }
        let eocd = bases[(end.last - first) as usize] + end.at;
        let parser = DirectoryParser::spanned_at_eocd(total, eocd, self.limits, crate::crc32::hash, project)
            .map_err(|e| self.directory_error(e, end.last))?;
        self.parked = None;
        self.phase = Phase::Directory { parser: Box::new(parser), first, bases, zip64: end.zip64 };
        Ok(())
    }

    fn directory_error(&self, error: DirectoryError, volume: u32) -> MapError {
        directory_error(error, &self.limits, volume)
    }

    fn directory(
        &mut self,
        input: &mut dyn MapInput,
        cx: &mut Context<'_>,
    ) -> Result<Option<Poll<MemberMap>>, MapError> {
        let last = self.last.expect("last volume known");
        let Phase::Directory { parser, first, bases, .. } = &mut self.phase else { unreachable!() };
        let first = *first;
        let limits = self.limits;
        let range = parser.next_read().map_err(|e| directory_error(e, &limits, last))?;
        let Some(range) = range else {
            let Phase::Directory { parser, bases, zip64, .. } = std::mem::replace(&mut self.phase, Phase::Start) else {
                unreachable!()
            };
            let found = parser.finish().map_err(|e| self.directory_error(e, last))?;
            if found.prefix_shift != 0 {
                return Err(malformed(last, "central directory offset"));
            }
            // The parser looks for the ZIP64 end record in the concatenation, where the locator's offset (relative to
            // its own disk) does not apply: it must have taken the record the locator points at.
            if let Some(record) = &found.zip64_end {
                let at = zip64.filter(|at| at.vol >= first).map(|at| bases[(at.vol - first) as usize] + at.off);
                if at != Some(record.source.start) {
                    return Err(malformed(last, "ZIP64 end record"));
                }
            }
            let entries = found.entries;
            if entries.iter().any(|e| e.disk > last) {
                return Err(malformed(last, "ZIP local header disk"));
            }
            let mut starts: Vec<Pos> = entries.iter().map(|e| Pos { vol: e.disk, off: e.entry.local_at }).collect();
            starts.push(Pos { vol: first, off: found.declaration.offset });
            starts.sort_unstable_by_key(|p| (p.vol, p.off));
            starts.dedup();
            self.starts = starts;
            self.charge(Resource::Entries, entries.len() as u64, last)?;
            self.charge(Resource::Parts, entries.len() as u64, last)?;
            self.phase = Phase::Locals { entries, index: 0, step: Step::Open };
            return Ok(None);
        };
        // The volume holding the start of the range.
        let i = bases.partition_point(|&base| base <= range.start) - 1;
        let vol = first + i as u32;
        let off = range.start - bases[i];
        let len = match self.ensure(input, cx, vol)? {
            Avail::Ready(len) => len,
            Avail::Pending => return Ok(Some(Poll::Pending)),
            Avail::Missing => return Err(MapError::MissingDirectory { volume: vol }),
        };
        let want = (range.end - range.start).min(len - off).min(CHUNK as u64) as usize;
        let n = self.parked.take().unwrap_or(want);
        let count = match read(input, &self.usage, off, &mut self.buffer[..n], cx)
            .map_err(|e| MapError::from_failure(vol, e))?
        {
            Got::NotYet => {
                self.parked = Some(n);
                return Ok(Some(Poll::Pending));
            }
            Got::Hole => return Err(MapError::HeaderHole { volume: vol, offset: off }),
            Got::Eof => return Err(MapError::MissingDirectory { volume: vol }),
            Got::Filled(count) => count.min(n),
        };
        self.charge(Resource::HeaderBytes, count as u64, vol)?;
        let Phase::Directory { parser, .. } = &mut self.phase else { unreachable!() };
        parser.supply(range.start, &self.buffer[..count]).map_err(|e| directory_error(e, &limits, vol))?;
        Ok(None)
    }

    /// Records the first availability problem, which becomes the map's end.
    fn problem(&mut self, end: MapEnd) {
        self.end.get_or_insert(end);
    }

    fn finish(&mut self) -> MemberMap {
        let end = self.end.unwrap_or(MapEnd::Complete);
        MemberMap {
            format: MapFormat::Zip,
            header_encrypted: false,
            header_cipher: None,
            complete: end == MapEnd::Complete,
            end,
            volumes: self.last.map_or(0, |last| last + 1),
            members: std::mem::take(&mut self.members),
            folders: Vec::new(),
        }
    }

    /// Lists the current entry from what was read and moves on to the next one.
    fn push_member(
        &mut self,
        entry: &ZipEntry,
        local: Option<&LocalHeader>,
        prefix: Option<&[u8]>,
        pieces: Vec<ZipPiece>,
        complete: bool,
    ) -> Result<(), MapError> {
        let member = zip_member(&self.usage, self.members.len() as u64, entry, local, prefix, pieces, complete)?;
        self.members.push(member);
        self.scratch.clear();
        let Phase::Locals { index, step, .. } = &mut self.phase else { unreachable!() };
        *index += 1;
        *step = Step::Open;
        Ok(())
    }

    fn locals(&mut self, input: &mut dyn MapInput, cx: &mut Context<'_>) -> Result<Option<Poll<MemberMap>>, MapError> {
        let last = self.last.expect("last volume known");
        let Phase::Locals { entries, index, step } = &mut self.phase else { unreachable!() };
        let Some(SplitEntry { entry, disk }) = entries.get(*index).cloned() else {
            return Ok(Some(Poll::Ready(self.finish())));
        };
        let local_at = Pos { vol: disk, off: entry.local_at };
        match std::mem::replace(step, Step::Open) {
            Step::Open => match self.ensure(input, cx, disk)? {
                Avail::Pending => return Ok(Some(Poll::Pending)),
                Avail::Missing => {
                    self.problem(MapEnd::MissingVolume { volume: disk });
                    self.push_member(&entry, None, None, Vec::new(), false)?;
                }
                Avail::Ready(len) if entry.local_at >= len => {
                    // The last volume ends with the directory, so it cannot be cut: the offset is wrong. An earlier
                    // volume may be cut short.
                    if disk == last {
                        return Err(malformed(disk, "local header offset"));
                    }
                    self.problem(MapEnd::Truncated { volume: disk, offset: entry.local_at });
                    return Ok(Some(Poll::Ready(self.finish())));
                }
                Avail::Ready(_) => {
                    self.start_gather(local_at);
                    self.set_step(Step::Header);
                }
            },
            Step::Header => match self.gather(input, cx, LOCAL_HEADER_LEN, last)? {
                Gathered::Pending => {
                    self.set_step(Step::Header);
                    return Ok(Some(Poll::Pending));
                }
                Gathered::Missing(v) => {
                    self.problem(MapEnd::MissingVolume { volume: v });
                    self.push_member(&entry, None, None, Vec::new(), false)?;
                }
                Gathered::Eof => return self.cut(disk, entry.local_at, last),
                Gathered::Full => {
                    let header =
                        LocalHeader::parse(&self.scratch).map_err(|_| malformed(disk, "local header signature"))?;
                    self.scratch.clear();
                    self.set_step(Step::Data { header });
                }
            },
            Step::Data { header } => {
                let skip = (LOCAL_HEADER_LEN + usize::from(header.name_len) + usize::from(header.extra_len)) as u64;
                match self.advance(input, cx, local_at, skip, last)? {
                    Advanced::Pending => {
                        self.set_step(Step::Data { header });
                        return Ok(Some(Poll::Pending));
                    }
                    Advanced::Missing(v) => {
                        self.problem(MapEnd::MissingVolume { volume: v });
                        self.push_member(&entry, Some(&header), None, Vec::new(), false)?;
                    }
                    Advanced::PastEnd => return Err(malformed(disk, "local header size")),
                    Advanced::At(data) => self.set_step(Step::Pieces {
                        header,
                        data,
                        cursor: data,
                        remaining: entry.packed,
                        pieces: Vec::new(),
                    }),
                }
            }
            Step::Pieces { header, data, mut cursor, mut remaining, mut pieces } => loop {
                let len = match self.ensure(input, cx, cursor.vol)? {
                    Avail::Pending => {
                        self.set_step(Step::Pieces { header, data, cursor, remaining, pieces });
                        return Ok(Some(Poll::Pending));
                    }
                    Avail::Missing => {
                        self.problem(MapEnd::MissingVolume { volume: cursor.vol });
                        self.push_member(&entry, Some(&header), None, pieces, false)?;
                        break;
                    }
                    Avail::Ready(len) => len,
                };
                let take = remaining.min(len.saturating_sub(cursor.off));
                if take > 0 || (entry.packed == 0 && pieces.is_empty()) {
                    if !pieces.is_empty() {
                        self.charge(Resource::Parts, 1, cursor.vol)?;
                    }
                    let header_range = if cursor.vol != data.vol {
                        0..0
                    } else if local_at.vol == data.vol {
                        local_at.off..data.off
                    } else {
                        0..data.off
                    };
                    pieces.push(ZipPiece {
                        volume: cursor.vol,
                        packed: cursor.off..cursor.off + take,
                        header: header_range,
                    });
                }
                remaining -= take;
                if remaining == 0 {
                    // The data (and its descriptor) must end before the next local header or the directory. When it
                    // does not, a volume it crosses is shorter than when it was written, or the directory is wrong.
                    let data_end = pieces.last().map_or(data, |p| Pos { vol: p.volume, off: p.packed.end });
                    let described = entry.flags & 0x0008 != 0;
                    let end = Pos { vol: data_end.vol, off: data_end.off + if described { DESCRIPTOR_MIN } else { 0 } };
                    let next = self.starts.iter().copied().find(|s| (s.vol, s.off) > (local_at.vol, local_at.off));
                    if next.is_some_and(|next| self.after(end, next, last)) {
                        return self.overrun(&pieces, disk);
                    }
                    let crossed = pieces.len() > 1 || pieces.first().is_some_and(|p| p.volume != disk);
                    if described && crossed {
                        // A descriptor leaves a few bytes of slack before the next record; its CRC pins the end. The
                        // 4 bytes before it are read too: a descriptor's signature there means the data was placed 4
                        // bytes too late.
                        let lead = data_end.off >= 4;
                        let from = if lead { Pos { vol: data_end.vol, off: data_end.off - 4 } } else { data_end };
                        self.start_gather(from);
                        self.set_step(Step::Descriptor { header, data, pieces, lead });
                    } else {
                        self.data_placed(&entry, header, data, pieces)?;
                    }
                    break;
                }
                if cursor.vol >= last {
                    return self.overrun(&pieces, disk);
                }
                cursor = Pos { vol: cursor.vol + 1, off: 0 };
            },
            Step::Descriptor { header, data, pieces, lead } => {
                match self.gather(input, cx, if lead { 20 } else { 16 }, last)? {
                    Gathered::Pending => {
                        self.set_step(Step::Descriptor { header, data, pieces, lead });
                        return Ok(Some(Poll::Pending));
                    }
                    // Not there to check.
                    Gathered::Missing(_) | Gathered::Eof => self.data_placed(&entry, header, data, pieces)?,
                    Gathered::Full => {
                        let (before, descriptor) = self.scratch.split_at(if lead { 4 } else { 0 });
                        let signed = descriptor.starts_with(SPLIT_MARKER);
                        let early = !signed && before == SPLIT_MARKER;
                        if early || le32(descriptor, if signed { 4 } else { 0 }) != entry.crc32 {
                            return self.overrun(&pieces, disk);
                        }
                        self.data_placed(&entry, header, data, pieces)?;
                    }
                }
            }
            Step::Prefix { header, data, pieces } => {
                let prefix = super::zip::aes_prefix(&entry).expect("AES prefix");
                match self.gather(input, cx, prefix, last)? {
                    Gathered::Pending => {
                        self.set_step(Step::Prefix { header, data, pieces });
                        return Ok(Some(Poll::Pending));
                    }
                    // The data was placed on present volumes, so neither can happen; list it without the cipher.
                    Gathered::Missing(_) | Gathered::Eof => {
                        self.push_member(&entry, Some(&header), None, pieces, true)?;
                    }
                    Gathered::Full => {
                        let bytes = std::mem::take(&mut self.scratch);
                        self.push_member(&entry, Some(&header), Some(&bytes[..prefix]), pieces, true)?;
                    }
                }
            }
        }
        Ok(None)
    }

    /// Whether position `a` lies after `b`. Either may lie at or past the end of its volume, which is the start of
    /// the next one.
    fn after(&self, a: Pos, b: Pos, last: u32) -> bool {
        let canonical = |mut p: Pos| {
            while p.vol < last {
                match self.vol(p.vol) {
                    Vol::Present(len) if p.off >= len => p = Pos { vol: p.vol + 1, off: p.off - len },
                    _ => break,
                }
            }
            (p.vol, p.off)
        };
        canonical(a) > canonical(b)
    }

    /// A member's data runs past the next record, or past the end of the last volume. Data that crosses a volume
    /// boundary was placed by the volume lengths, so a volume it crosses was cut short: the map ends there, before
    /// the member. Data within one volume means a wrong directory.
    ///
    /// The volumes of a set before the last all have one length, so the cut one is the first volume the data runs
    /// to the end of that is shorter than the longest of them; when none is, the first volume the data crosses.
    fn overrun(&mut self, pieces: &[ZipPiece], disk: u32) -> Result<Option<Poll<MemberMap>>, MapError> {
        let Some(first) = pieces.first().filter(|first| pieces.len() > 1 || first.volume != disk) else {
            return Err(malformed(disk, "ZIP entry data runs past the next record"));
        };
        let last = self.last.expect("last volume known");
        let len = |v: u32| match self.vol(v) {
            Vol::Present(len) => len,
            _ => 0,
        };
        let full = self.vols.iter().take(last as usize).filter_map(|v| match v {
            Vol::Present(len) => Some(*len),
            _ => None,
        });
        let longest = full.max().unwrap_or(0);
        // Every piece but the final one runs to the end of its volume.
        let crossed = &pieces[..pieces.len() - 1];
        let volume = crossed.iter().map(|p| p.volume).find(|&v| v < last && len(v) < longest).unwrap_or(first.volume);
        self.problem(MapEnd::Truncated { volume, offset: len(volume) });
        Ok(Some(Poll::Ready(self.finish())))
    }

    /// Goes on once a member's data is placed: to its WinZip AES salt and verifier, or to the next member.
    fn data_placed(
        &mut self,
        entry: &ZipEntry,
        header: LocalHeader,
        data: Pos,
        pieces: Vec<ZipPiece>,
    ) -> Result<(), MapError> {
        match super::zip::aes_prefix(entry) {
            Some(prefix) if prefix as u64 <= entry.packed => {
                self.start_gather(data);
                self.set_step(Step::Prefix { header, data, pieces });
                Ok(())
            }
            _ => self.push_member(entry, Some(&header), None, pieces, true),
        }
    }

    fn set_step(&mut self, next: Step) {
        let Phase::Locals { step, .. } = &mut self.phase else { unreachable!() };
        *step = next;
    }

    /// A local header running past the end of the bytes: a cut volume, or past the end of the last one.
    fn cut(&mut self, disk: u32, offset: u64, last: u32) -> Result<Option<Poll<MemberMap>>, MapError> {
        if self.at.vol >= last {
            return Err(malformed(disk, "local header size"));
        }
        self.problem(MapEnd::Truncated { volume: disk, offset });
        Ok(Some(Poll::Ready(self.finish())))
    }

    /// The position `n` bytes after `from`, opening the volumes it crosses.
    fn advance(
        &mut self,
        input: &mut dyn MapInput,
        cx: &mut Context<'_>,
        from: Pos,
        mut n: u64,
        last: u32,
    ) -> Result<Advanced, MapError> {
        let mut pos = from;
        loop {
            let len = match self.ensure(input, cx, pos.vol)? {
                Avail::Ready(len) => len,
                Avail::Pending => return Ok(Advanced::Pending),
                Avail::Missing => return Ok(Advanced::Missing(pos.vol)),
            };
            let room = len.saturating_sub(pos.off);
            if n <= room {
                return Ok(Advanced::At(Pos { vol: pos.vol, off: pos.off + n }));
            }
            if pos.vol >= last {
                return Ok(Advanced::PastEnd);
            }
            n -= room;
            pos = Pos { vol: pos.vol + 1, off: 0 };
        }
    }
}

/// Whether the end record `record` found at the end of volume `vol`, which did not answer to the last volume's name,
/// is that volume's own: it states `vol` as its disk, and its directory (or ZIP64 end record) on that disk ends where
/// the next record starts.
fn plausible_end(record: &[u8], end: &End, vol: u32) -> bool {
    if end.last != vol || end.directory_disk.is_some_and(|d| d > vol) {
        return false;
    }
    match end.zip64 {
        Some(at) => {
            at.vol < vol || (at.vol == vol && at.off.checked_add(END64_LEN as u64 + LOCATOR_LEN as u64) <= Some(end.at))
        }
        None => {
            let (size, offset) = (u64::from(le32(record, 12)), u64::from(le32(record, 16)));
            end.directory_disk != Some(vol) || offset.checked_add(size) == Some(end.at)
        }
    }
}

/// A directory parser failure, pinned to `volume`.
fn directory_error(error: DirectoryError, limits: &Limits, volume: u32) -> MapError {
    match directory(error, limits) {
        MapError::Malformed { failure, .. } => MapError::Malformed { volume, failure },
        MapError::Unsupported { failure, .. } => MapError::Unsupported { volume, failure },
        other => other,
    }
}

/// How many bytes at the end of a volume of `len` bytes are searched for the end record.
fn tail_span(len: u64, wide: bool) -> u64 {
    len.min(if wide { TAIL_MAX } else { (END_LEN + LOCATOR_LEN) as u64 })
}

enum Advanced {
    At(Pos),
    Pending,
    Missing(u32),
    PastEnd,
}

/// The offset in `tail` (the last bytes of a volume) of an end record whose comment ends exactly at the end, the
/// latest one when several qualify.
pub(crate) fn find_end(tail: &[u8]) -> Option<usize> {
    (0..=tail.len().checked_sub(END_LEN)?).rev().find(|&at| {
        tail[at..].starts_with(b"PK\x05\x06") && usize::from(le16(tail, at + 20)) == tail.len() - at - END_LEN
    })
}
