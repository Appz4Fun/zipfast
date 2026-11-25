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

//! [`VolumeFiles`]: a packed source over volume files a downloader is still writing.

use super::{PackedRead, PackedSource, RangeSet};
use std::collections::BTreeMap;
use std::fs::File;
use std::ops::Range;

/// A [`PackedSource`] over volume files as a downloader writes them, article by article, in any order. The
/// decoder reads each article from disk as soon as it is written, so extraction keeps up with the download instead
/// of waiting for a finished volume and reading it back, and holds no article in memory.
///
/// Give each volume's file with [`Self::set_file`] (a handle that can read the file being written; the writer may
/// use another handle), then report every article the writer has written with [`Self::mark_written`] once its write
/// returned (a read sees the bytes from then on; no sync is needed for that). Articles that will not come are
/// [`Self::mark_lost`] (answered [`PackedRead::Hole`] until written). Bytes neither written nor lost are
/// [`PackedRead::NotYet`], and [`PackedSource::absent`] lists them, so the decoder names them as needs.
///
/// A read that fails, or finds the file shorter than reported, is answered as a hole: the bytes are damaged, not
/// late. Releases are ignored (the files stay).
#[derive(Debug, Default)]
pub struct VolumeFiles {
    volumes: BTreeMap<u32, Volume>,
}

#[derive(Debug, Default)]
struct Volume {
    file: Option<File>,
    written: RangeSet,
    lost: RangeSet,
}

impl VolumeFiles {
    pub fn new() -> Self {
        Self::default()
    }

    /// The file holding volume `volume` (as `MapPiece::volume` numbers them).
    pub fn set_file(&mut self, volume: u32, file: File) {
        self.volumes.entry(volume).or_default().file = Some(file);
    }

    /// Bytes `range` of volume `volume` are written to its file.
    pub fn mark_written(&mut self, volume: u32, range: Range<u64>) {
        let v = self.volumes.entry(volume).or_default();
        v.lost.remove(range.clone());
        v.written.insert(range);
    }

    /// Bytes `range` of volume `volume` will not come (until written).
    pub fn mark_lost(&mut self, volume: u32, range: Range<u64>) {
        let v = self.volumes.entry(volume).or_default();
        let mut at = range.start;
        // Written bytes stay readable: only the parts not written are lost.
        while at < range.end {
            let end = match v.written.containing(at) {
                Some(w) => {
                    at = w.end.min(range.end);
                    continue;
                }
                None => v.written.next_start(at).map_or(range.end, |s| s.min(range.end)),
            };
            v.lost.insert(at..end);
            at = end;
        }
    }

    /// The written ranges of volume `volume`, in order.
    pub fn written(&self, volume: u32) -> Vec<Range<u64>> {
        self.volumes.get(&volume).map(|v| v.written.ranges()).unwrap_or_default()
    }
}

impl PackedSource for VolumeFiles {
    fn read_packed(&mut self, volume: u32, offset: u64, buf: &mut [u8]) -> PackedRead {
        let Some(v) = self.volumes.get(&volume) else { return PackedRead::NotYet { len: u64::MAX } };
        if let Some(w) = v.written.containing(offset) {
            let n = (w.end - offset).min(buf.len() as u64) as usize;
            let Some(file) = &v.file else { return PackedRead::Hole { len: n as u64 } };
            return match crate::output::range::read_at(file, offset, &mut buf[..n]) {
                Ok(read) if read > 0 => PackedRead::Data(read),
                _ => PackedRead::Hole { len: n as u64 },
            };
        }
        let next = v.written.next_start(offset).unwrap_or(u64::MAX);
        if let Some(l) = v.lost.containing(offset) {
            return PackedRead::Hole { len: l.end.min(next) - offset };
        }
        let next = next.min(v.lost.next_start(offset).unwrap_or(u64::MAX));
        PackedRead::NotYet { len: if next == u64::MAX { u64::MAX } else { next - offset } }
    }

    fn absent(&self, volume: u32, range: Range<u64>) -> Option<Vec<Range<u64>>> {
        let mut gaps = Vec::new();
        let mut at = range.start;
        let written = self.volumes.get(&volume).map(|v| v.written.ranges()).unwrap_or_default();
        for w in written.iter().filter(|w| w.end > range.start && w.start < range.end) {
            if w.start > at {
                gaps.push(at..w.start);
            }
            at = at.max(w.end);
        }
        if at < range.end {
            gaps.push(at..range.end);
        }
        Some(gaps)
    }
}
