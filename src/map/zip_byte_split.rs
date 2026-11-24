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

//! The byte-split ZIP walker (`name.zip.001`, `name.zip.002`, ...): one ordinary ZIP cut at arbitrary offsets, with
//! no disk numbers. It learns the volume lengths by opening the pieces in order, then runs the single-volume
//! [`ZipWalker`] over a view that presents the pieces as one volume, and cuts every member's data at the piece
//! boundaries (`MapPiece::volume` and `MapPiece::packed` are per piece).
use super::zip::ZipWalker;
use super::{Got, MapError, MapInput, MapOptions, MemberMap, Opened};
use crate::progressive::{FailureKind, ProgressiveFailure, Resource, Usage, VolumeRequest};
use std::ffi::{OsStr, OsString};
use std::task::{Context, Poll};

/// Whether `name` is the first piece of a byte-split ZIP: `x.zip.001` (any digits count, value 1, any case).
pub(super) fn is_first_piece_name(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else { return false };
    let digits = name.bytes().rev().take_while(u8::is_ascii_digit).count();
    let stem = &name[..name.len() - digits];
    (2..=18).contains(&digits)
        && name[name.len() - digits..].parse::<u64>() == Ok(1)
        && stem.len() > 4
        && stem[stem.len() - 5..].eq_ignore_ascii_case(".zip.")
}

pub(super) struct ZipByteSplitWalker {
    usage: Usage,
    lens: Vec<u64>,
    names: Vec<OsString>,
    /// Volumes kept open on the input, least recently used first.
    kept: Vec<u32>,
    handles: u64,
    current: Option<u32>,
    walker: Option<ZipWalker>,
    limits: crate::progressive::ProgressiveLimits,
}

/// The pieces as one volume.
struct Joined<'a> {
    input: &'a mut dyn MapInput,
    set: &'a mut ZipByteSplitWalker,
}

impl ZipByteSplitWalker {
    pub(super) fn new(usage: Usage, options: &MapOptions) -> Self {
        Self {
            usage,
            lens: Vec::new(),
            names: vec![options.first_name.clone()],
            kept: Vec::new(),
            handles: options.limits.volume_handles,
            current: None,
            walker: None,
            limits: options.limits.clone(),
        }
    }

    fn name(&mut self, index: u32) -> Result<OsString, ProgressiveFailure> {
        while self.names.len() <= index as usize {
            let next = super::next_volume_name(self.names.last().expect("first name"));
            self.usage.charge(Resource::MetadataBytes, next.len() as u64)?;
            self.names.push(next);
        }
        Ok(self.names[index as usize].clone())
    }

    fn keep(&mut self, input: &mut dyn MapInput, index: u32) -> Result<(), ProgressiveFailure> {
        if let Some(i) = self.kept.iter().position(|&k| k == index) {
            self.kept.remove(i);
        } else {
            if self.handles == 0 {
                return Err(ProgressiveFailure::new(FailureKind::Limit {
                    resource: Resource::VolumeHandles,
                    limit: 0,
                    attempted: 1,
                }));
            }
            while self.kept.len() as u64 >= self.handles {
                input.release(self.kept.remove(0));
            }
        }
        self.kept.push(index);
        input.keep(index);
        Ok(())
    }

    /// Opens volume `index`; `Wait` means pending.
    fn open(
        &mut self,
        input: &mut dyn MapInput,
        cx: &mut Context<'_>,
        index: u32,
    ) -> Result<Opened, ProgressiveFailure> {
        let expected = self.name(index)?;
        self.usage.charge(Resource::SourceRequests, 1)?;
        self.current = None;
        let opened = input.open(&VolumeRequest { index, expected }, cx)?;
        match opened {
            Opened::Wait => self.usage.charge(Resource::ProviderWakes, 1)?,
            Opened::Ready => {
                self.current = Some(index);
                self.keep(input, index)?;
            }
            _ => {}
        }
        Ok(opened)
    }

    /// Makes volume `index` current. Ok(None) is pending, Ok(Some(false)) missing.
    fn select(
        &mut self,
        input: &mut dyn MapInput,
        cx: &mut Context<'_>,
        index: u32,
    ) -> Result<Option<bool>, ProgressiveFailure> {
        if self.current == Some(index) {
            return Ok(Some(true));
        }
        if let Some(i) = self.kept.iter().position(|&k| k == index) {
            if !input.select(index) {
                return Err(ProgressiveFailure::new(FailureKind::SourceContract));
            }
            self.kept.remove(i);
            self.kept.push(index);
            self.current = Some(index);
            return Ok(Some(true));
        }
        match self.open(input, cx, index)? {
            Opened::Wait => Ok(None),
            Opened::Ready if input.len() != self.lens[index as usize] => {
                Err(ProgressiveFailure::new(FailureKind::SourceChanged))
            }
            Opened::Ready => Ok(Some(true)),
            Opened::Missing => Ok(Some(false)),
            Opened::Abort => Err(ProgressiveFailure::new(FailureKind::Canceled)),
        }
    }

    pub(super) fn poll(
        &mut self,
        input: &mut dyn MapInput,
        cx: &mut Context<'_>,
        options: &MapOptions,
    ) -> Poll<Result<MemberMap, MapError>> {
        if self.walker.is_none() {
            if self.lens.is_empty() {
                // Format detection left volume 0 open.
                self.lens.push(input.len());
                self.current = Some(0);
                if let Err(e) = self.keep(input, 0) {
                    return Poll::Ready(Err(MapError::from_failure(0, e)));
                }
            }
            // The directory is at the end of the set: every piece's length is needed.
            loop {
                let index = self.lens.len() as u32;
                match self.open(input, cx, index) {
                    Err(e) => return Poll::Ready(Err(MapError::from_failure(index, e))),
                    Ok(Opened::Wait) => return Poll::Pending,
                    Ok(Opened::Ready) => self.lens.push(input.len()),
                    Ok(Opened::Missing) => break,
                    Ok(Opened::Abort) => return Poll::Ready(Err(MapError::Aborted { volume: index })),
                }
            }
            self.walker = Some(ZipWalker::new(self.usage.clone(), &self.limits).over_volumes(self.lens.clone()));
        }
        let mut walker = self.walker.take().expect("walker");
        let result = walker.poll(&mut Joined { input, set: self }, cx, options);
        self.walker = Some(walker);
        result
    }
}

impl MapInput for Joined<'_> {
    fn open(&mut self, _: &VolumeRequest, _: &mut Context<'_>) -> Result<Opened, ProgressiveFailure> {
        Ok(Opened::Ready)
    }
    fn len(&self) -> u64 {
        self.set.lens.iter().sum()
    }
    fn read(&mut self, offset: u64, buf: &mut [u8], cx: &mut Context<'_>) -> Result<Got, ProgressiveFailure> {
        let mut start = 0u64;
        let mut found = None;
        for (index, &len) in self.set.lens.iter().enumerate() {
            if offset < start + len {
                found = Some((index as u32, offset - start, start + len - offset));
                break;
            }
            start += len;
        }
        let Some((volume, at, left)) = found else { return Ok(Got::Eof) };
        match self.set.select(self.input, cx, volume)? {
            None => return Ok(Got::NotYet),
            Some(false) => return Ok(Got::Hole),
            Some(true) => {}
        }
        let n = buf.len().min(usize::try_from(left).unwrap_or(usize::MAX));
        self.input.read(at, &mut buf[..n], cx)
    }
}
