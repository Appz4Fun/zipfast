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

//! Restart points and handover plans: where decoding of a member can begin, and what a copy needs to start at an
//! output offset. See `docs/open-at.md`.
//!
//! [`member_restart`] says how a member restarts (its layer and the grain of its restart points). [`open_at`] plans
//! opening a member at an output offset from the map alone: for stored and encrypted-stored members it is the whole
//! answer; for RAR 5.0 compressed members and 7z LZMA2 folders it names the packed bytes to fetch and the known
//! plaintext to supply, and [`complete_rar5`] / [`complete_lzma2`] finish the job once those bytes are held.

use super::{
    CoderKind, Lzma2ChunkKind, Lzma2DecodeError, Lzma2DecodeOptions, Lzma2End, Lzma2Index, Lzma2IndexOptions,
    Lzma2Position, Lzma2Reset, Lzma2Start, MapFormat, MapMember, MapMethod, MemberMap, OutputMapping, PackedSpan,
};
use crate::rar5::unpack::{NearError, NearOptions, ResyncNear, Unpacker, Window, resync_near, window_for};
use std::ops::Range;

/// A filter's longest reach in RAR 5.0 output (4 MiB): plaintext this far before a restart lets
/// [`resync_near`] give a guarded restart.
const RAR5_FILTER_REACH: u64 = 0x40_0000;

/// How a member's packed bytes become its output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Layer {
    /// Stored as is: output byte `o` is packed byte `o` (RAR, ZIP, a 7z Copy folder).
    Stored,
    /// Stored and AES-CBC encrypted (RAR 5.0, RAR 4.x, a 7zAES-over-Copy folder's first member).
    StoredCbc,
    /// Stored and WinZip AES (counter mode) encrypted.
    StoredCounter,
    /// Stored and ZipCrypto encrypted: decrypting needs every earlier byte.
    StoredSequential,
    /// RAR 5.0 compressed (methods 1 to 5), possibly AES-CBC encrypted under the compression.
    Rar5Compressed,
    /// A 7z folder with an LZMA2 coder, possibly 7zAES encrypted under it, and no other coder.
    SevenZipLzma2,
    /// Anything else: RAR 4.x compressed, ZIP compressed, other 7z coder chains. No restart but the start.
    Other,
}

/// The grain of a member's restart points.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RestartGrain {
    /// Any output byte, from the map alone.
    AnyByte,
    /// Any 16-byte block, from the map alone; the ciphertext block before it is the IV (the member's IV for block 0).
    Block16,
    /// Only the member's start.
    StartOnly,
    /// RAR 5.0 block starts, found by [`crate::rar5::unpack::resync_near`] over held packed bytes and known
    /// plaintext; the map cannot list them.
    Rar5Blocks,
    /// LZMA2 chunks that reset the state (or store their bytes), found by walking the folder's packed bytes back from
    /// its end marker; the map cannot list them.
    Lzma2Chunks,
}

/// How a member restarts.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct MemberRestart {
    pub layer: Layer,
    pub grain: RestartGrain,
    /// Whether the packed bytes are encrypted under the layer (RAR AES-CBC under compression, 7zAES under LZMA2):
    /// they must be decrypted before [`complete_rar5`] / [`complete_lzma2`] reads them.
    pub encrypted: bool,
    /// RAR: the member's dictionary size. 7z LZMA2: the coder's dictionary size.
    pub dictionary: Option<u64>,
    /// Where the member's output starts in the decoder's output stream: for a RAR solid stream the sizes of the
    /// stream's earlier members (the `member_start` of [`Unpacker::resume_in_stream`]); for a 7z member its offset in
    /// the folder's output; otherwise 0.
    pub stream_start: u64,
    /// The member's output size.
    pub size: Option<u64>,
}

/// Why a member cannot be planned.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum OpenAtError {
    /// No member with this index.
    NoMember(usize),
    /// The member's size (or an earlier solid member's) is unknown.
    SizeUnknown,
    /// The offset is at or past the member's end.
    PastEnd { offset: u64, size: u64 },
    /// The map lacks what the plan needs (pieces, a folder, a dictionary size).
    Incomplete(&'static str),
    /// This layer restarts only at the member's start.
    StartOnly(Layer),
    /// The plan is not for this member's layer.
    WrongPlan,
    /// [`resync_near`] found no restart in the bytes held.
    Resync(NearError),
    /// The known plaintext does not cover what the restart needs: give plaintext from `needed.start` (or packed bytes
    /// from further back).
    NeedMore { needed: Range<u64> },
    /// No LZMA2 chunk chain running to the folder's end marker was found in the packed bytes held.
    NoChain,
    /// Decoding failed.
    Decode(String),
}

impl std::fmt::Display for OpenAtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoMember(i) => write!(f, "no member {i}"),
            Self::SizeUnknown => write!(f, "the member's size, or an earlier solid member's, is unknown"),
            Self::PastEnd { offset, size } => write!(f, "offset {offset} is not before the member's end ({size})"),
            Self::Incomplete(what) => write!(f, "the map lacks {what}"),
            Self::StartOnly(layer) => write!(f, "a {layer:?} member restarts only at its start"),
            Self::WrongPlan => write!(f, "the plan is for another kind of member"),
            Self::Resync(e) => write!(f, "{e}"),
            Self::NeedMore { needed } => write!(f, "known plaintext from output offset {} is needed", needed.start),
            Self::NoChain => write!(f, "no LZMA2 chunk chain to the folder's end in the packed bytes held"),
            Self::Decode(e) => write!(f, "decoding failed: {e}"),
        }
    }
}

impl std::error::Error for OpenAtError {}

/// How member `member` of `map` restarts: its layer, the grain of its restart points, its dictionary and where its
/// output starts in its decoder's stream.
pub fn member_restart(map: &MemberMap, member: usize) -> Result<MemberRestart, OpenAtError> {
    let m = map.members.get(member).ok_or(OpenAtError::NoMember(member))?;
    let stored = |layer, grain| MemberRestart {
        layer,
        grain,
        encrypted: false,
        dictionary: m.dictionary,
        stream_start: 0,
        size: m.unpacked_size,
    };
    let r = match (m.method, m.mapping) {
        (_, OutputMapping::Direct) => stored(Layer::Stored, RestartGrain::AnyByte),
        (_, OutputMapping::CbcBlocks) => stored(Layer::StoredCbc, RestartGrain::Block16),
        (_, OutputMapping::Counter { .. }) => stored(Layer::StoredCounter, RestartGrain::AnyByte),
        (_, OutputMapping::Sequential { .. }) => stored(Layer::StoredSequential, RestartGrain::StartOnly),
        (MapMethod::Compressed { .. }, _) if map.format == MapFormat::Rar5 => MemberRestart {
            layer: Layer::Rar5Compressed,
            grain: RestartGrain::Rar5Blocks,
            encrypted: m.encrypted,
            dictionary: m.dictionary,
            stream_start: rar_stream_start(map, member)?,
            size: m.unpacked_size,
        },
        (MapMethod::Coders, _) => match lzma2_folder(map, m) {
            Some((dict_prop, encrypted)) => MemberRestart {
                layer: Layer::SevenZipLzma2,
                grain: RestartGrain::Lzma2Chunks,
                encrypted,
                dictionary: Some(lzma2_dictionary(dict_prop)),
                stream_start: m.folder.map_or(0, |s| s.offset),
                size: m.unpacked_size,
            },
            None => stored(Layer::Other, RestartGrain::StartOnly),
        },
        _ => stored(Layer::Other, RestartGrain::StartOnly),
    };
    Ok(r)
}

/// The LZMA2 dictionary size a 7z property byte declares (40 and up: 4 GiB - 1).
fn lzma2_dictionary(prop: u8) -> u64 {
    if prop >= 40 { u64::from(u32::MAX) } else { (2 | u64::from(prop & 1)) << (prop / 2 + 11) }
}

/// The LZMA2 property byte and whether 7zAES sits under it, for a folder whose coders are LZMA2 alone or 7zAES
/// feeding LZMA2.
fn lzma2_folder(map: &MemberMap, m: &MapMember) -> Option<(u8, bool)> {
    let folder = map.folders.get(m.folder?.index as usize)?;
    let lzma2 = folder.coders.iter().find(|c| c.kind == CoderKind::Lzma2)?;
    let others = folder.coders.iter().filter(|c| c.kind != CoderKind::Lzma2).collect::<Vec<_>>();
    let encrypted = match others.as_slice() {
        [] => false,
        [aes] if aes.kind == CoderKind::Aes => true,
        _ => return None,
    };
    Some((*lzma2.properties.first()?, encrypted))
}

/// Where member `member`'s output starts in its RAR solid stream: the sizes of the members before it back to the
/// stream's first (the last member not marked solid).
fn rar_stream_start(map: &MemberMap, member: usize) -> Result<u64, OpenAtError> {
    let mut first = member;
    while first > 0 && map.members[first].solid {
        first -= 1;
    }
    map.members[first..member]
        .iter()
        .filter(|m| !m.is_dir)
        .try_fold(0u64, |sum, m| m.unpacked_size.and_then(|s| sum.checked_add(s)))
        .ok_or(OpenAtError::SizeUnknown)
}

/// Options for [`open_at`].
#[derive(Clone, Debug, Default)]
pub struct OpenAtOptions {
    /// Compressed members: where in the packed stream the target's output is thought to lie, when the caller knows
    /// better than the member's average packing ratio (an index, an earlier copy's ratio near the target).
    pub estimate: Option<u64>,
    /// Compressed members: how many packed bytes before the estimate to fetch, for the restart search.
    ///
    /// `None` (the default) picks it. For RAR 5.0 it covers the member's dictionary plus a filter's reach (4 MiB)
    /// before the target, scaled by the packing ratio with room to spare, or the whole packed stream before the
    /// target when the window reaches the member's start: the restart's whole match window is then checked against
    /// the known plaintext ([`ResyncNear::window_checked`]), so the resumed decoder can copy from anywhere in it. For
    /// LZMA2 it is 4 MiB.
    ///
    /// A smaller `Some(n)` fetches less. A RAR 5.0 restart whose window was not checked is still safe: the decoder
    /// refuses (as [`crate::Error::BadChecksum`]) a copy from output a filter it did not see may have changed,
    /// and the caller then fetches from further back.
    pub search: Option<u64>,
}

/// The LZMA2 search when [`OpenAtOptions::search`] is `None`.
const LZMA2_SEARCH: u64 = 4 << 20;

/// A plan for opening a member at an output offset; see [`open_at`].
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct OpenAt {
    pub member: usize,
    /// The output offset asked for, in the member's output.
    pub target: u64,
    pub restart: MemberRestart,
    /// How decoding starts.
    pub start: Start,
    /// Where in the packed stream (the member's; a 7z LZMA2 member's folder's) the bytes needed begin.
    pub fetch_from: u64,
    /// The packed bytes to fetch, from `fetch_from` to the end of the member's (or folder's) packed stream, per
    /// volume, in stream order. Pieces missing from the map are missing here too.
    pub spans: Vec<PackedSpan>,
}

/// How decoding starts in an [`OpenAt`] plan.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Start {
    /// Decoding starts at member output offset `output` (at or before the target; `target - output` bytes are
    /// decoded again). The spans begin with what that needs: for [`Layer::StoredCbc`] the ciphertext block before it,
    /// the IV, unless `output` is 0 (the member's IV).
    At { output: u64 },
    /// RAR 5.0 compressed: fetch `first` (packed stream offsets) and run [`complete_rar5`] with known plaintext
    /// covering `donor` (output offsets in the solid stream, ending at the target). The restart lands at a block
    /// start at or before the target.
    Rar5 {
        /// The target in the solid stream's output (`stream_start + target`).
        stream_target: u64,
        /// The estimated packed stream offset of the target.
        estimate: u64,
        /// The packed bytes to search first.
        first: Range<u64>,
        /// The known plaintext to supply: at least this range, ideally from the solid stream's start.
        donor: Range<u64>,
    },
    /// 7z LZMA2: fetch the folder's packed bytes from `fetch_from` to its end and run [`complete_lzma2`] with known
    /// folder output covering `donor`. The restart lands at a chunk start at or before the target.
    Lzma2 {
        folder: u32,
        /// The target in the folder's output (`stream_start + target`).
        folder_target: u64,
        dict_prop: u8,
        /// The known folder output to supply: at least this range.
        donor: Range<u64>,
    },
}

/// Plans opening member `member` of `map` at member output offset `offset`, from the map alone.
///
/// Stored members (plain, AES-CBC, WinZip AES) restart where [`Start::At`] says, and `spans` are exactly the packed
/// bytes from there to the member's end, as [`MapMember::packed_spans`] gives them. Compressed RAR 5.0 members and
/// 7z LZMA2 folders restart at points only their packed bytes show: the plan names the bytes to fetch and the known
/// plaintext to supply, and [`complete_rar5`] or [`complete_lzma2`] finds the restart once they are held.
pub fn open_at(map: &MemberMap, member: usize, offset: u64, options: &OpenAtOptions) -> Result<OpenAt, OpenAtError> {
    let restart = member_restart(map, member)?;
    let m = &map.members[member];
    let size = m.unpacked_size.ok_or(OpenAtError::SizeUnknown)?;
    if offset >= size {
        return Err(OpenAtError::PastEnd { offset, size });
    }
    let plan = |start, fetch_from, spans| {
        Ok(OpenAt { member, target: offset, restart: restart.clone(), start, fetch_from, spans })
    };
    match restart.grain {
        RestartGrain::AnyByte | RestartGrain::Block16 => {
            let output = if restart.grain == RestartGrain::Block16 { offset & !15 } else { offset };
            let spans = m.packed_spans(output..size).ok_or(OpenAtError::Incomplete("an output mapping"))?;
            let fetch_from = spans.first().map_or(0, |s| s.stream.start);
            plan(Start::At { output }, fetch_from, spans)
        }
        RestartGrain::Rar5Blocks => {
            let dictionary = restart.dictionary.ok_or(OpenAtError::Incomplete("the member's dictionary size"))?;
            let packed_len = m.packed_size;
            let estimate = options
                .estimate
                .unwrap_or_else(|| (offset as u128 * packed_len as u128 / size.max(1) as u128) as u64)
                .min(packed_len);
            let reach = dictionary.saturating_add(RAR5_FILTER_REACH);
            let search = options.search.unwrap_or_else(|| {
                if reach >= offset {
                    // the window reaches the member's start: search from there
                    estimate
                } else {
                    // the reach in packed bytes at the average ratio, doubled (rar's ratio swings widely), plus 4 MiB
                    let scaled = (reach as u128 * packed_len as u128 / size.max(1) as u128) as u64;
                    scaled.saturating_mul(2).saturating_add(4 << 20)
                }
            });
            let mut fetch_from = estimate.saturating_sub(search);
            if restart.encrypted {
                // the block before the first one fetched is its IV
                fetch_from = (fetch_from & !15).saturating_sub(16);
            }
            let stream_target = restart.stream_start + offset;
            let donor_from =
                stream_target.saturating_sub(dictionary.saturating_add(RAR5_FILTER_REACH).saturating_mul(2));
            let first = fetch_from..(estimate.saturating_add(1 << 20)).min(packed_len);
            plan(
                Start::Rar5 { stream_target, estimate, first, donor: donor_from..stream_target },
                fetch_from,
                stream_spans(m.pieces.iter().map(|p| (p.volume, p.packed.clone(), p.stream_offset)), fetch_from),
            )
        }
        RestartGrain::Lzma2Chunks => {
            let slot = m.folder.ok_or(OpenAtError::Incomplete("the member's folder"))?;
            let folder = map.folders.get(slot.index as usize).ok_or(OpenAtError::Incomplete("the member's folder"))?;
            let (dict_prop, _) = lzma2_folder(map, m).ok_or(OpenAtError::Incomplete("an LZMA2 coder"))?;
            let packed_len: u64 = folder.pack_sizes.iter().sum();
            let folder_target = slot.offset + offset;
            let estimate = options
                .estimate
                .unwrap_or_else(|| {
                    (folder_target as u128 * packed_len as u128 / folder.unpacked_size.max(1) as u128) as u64
                })
                .min(packed_len);
            let mut fetch_from = estimate.saturating_sub(options.search.unwrap_or(LZMA2_SEARCH));
            if restart.encrypted {
                fetch_from = (fetch_from & !15).saturating_sub(16);
            }
            let dictionary = lzma2_dictionary(dict_prop);
            let donor_from = folder_target.saturating_sub(dictionary.saturating_mul(2));
            plan(
                Start::Lzma2 { folder: slot.index, folder_target, dict_prop, donor: donor_from..folder_target },
                fetch_from,
                stream_spans(folder.packed.iter().map(|s| (s.volume, s.packed.clone(), s.stream.start)), fetch_from),
            )
        }
        RestartGrain::StartOnly => Err(OpenAtError::StartOnly(restart.layer)),
    }
}

/// The spans of a packed stream from stream offset `from` to its end.
fn stream_spans(pieces: impl Iterator<Item = (u32, Range<u64>, u64)>, from: u64) -> Vec<PackedSpan> {
    let mut spans = Vec::new();
    for (volume, packed, stream_offset) in pieces {
        let len = packed.end - packed.start;
        let end = stream_offset + len;
        if end <= from {
            continue;
        }
        let a = from.max(stream_offset);
        let at = packed.start + (a - stream_offset);
        spans.push(PackedSpan { volume, packed: at..packed.end, stream: a..end });
    }
    spans
}

/// A RAR 5.0 decoder restarted for a handover; see [`complete_rar5`].
#[non_exhaustive]
pub struct Rar5Resume {
    /// The decoder: feed it the member's packed bytes (decrypted, for an encrypted member) from `feed_from` to the
    /// member's end; it writes the member's output from `output` on.
    pub decoder: Unpacker,
    /// The packed stream offset to feed from.
    pub feed_from: u64,
    /// The member output offset the decoder starts writing at.
    pub output: u64,
    /// Output decoded again before the target: `target - output`.
    pub redecode: u64,
    /// The restart search's report.
    pub near: ResyncNear,
}

/// Finishes a [`Start::Rar5`] plan: finds the restart in the held packed bytes and starts a decoder there.
///
/// `packed` is the member's packed stream from offset `packed_from` (at most the plan's `fetch_from`), decrypted
/// when the member is encrypted; `known` is the solid stream's output from `known_base`, covering at least the
/// plan's `donor`. `near` bounds the search (its `estimate` is set from the plan).
pub fn complete_rar5(
    map: &MemberMap,
    plan: &OpenAt,
    packed_from: u64,
    packed: &[u8],
    known_base: u64,
    known: &[u8],
    near: &NearOptions,
) -> Result<Rar5Resume, OpenAtError> {
    let Start::Rar5 { stream_target, estimate, .. } = plan.start else { return Err(OpenAtError::WrongPlan) };
    let m = map.members.get(plan.member).ok_or(OpenAtError::NoMember(plan.member))?;
    let size = m.unpacked_size.ok_or(OpenAtError::SizeUnknown)?;
    let dictionary = plan.restart.dictionary.ok_or(OpenAtError::Incomplete("the member's dictionary size"))?;
    let window = rar5_window(dictionary, plan.restart.stream_start + size, m.solid || plan.restart.stream_start > 0)?;
    if known_base > stream_target || known_base.saturating_add(known.len() as u64) < stream_target {
        return Err(OpenAtError::NeedMore { needed: known_base.min(stream_target)..stream_target });
    }
    let options = NearOptions { estimate: Some(estimate.saturating_sub(packed_from) as usize), ..near.clone() };
    let found = resync_near(packed, known_base, known, window, stream_target, &options).map_err(OpenAtError::Resync)?;
    let member_start = plan.restart.stream_start;
    if found.resync.output_offset < member_start {
        return Err(OpenAtError::NeedMore { needed: known_base..stream_target });
    }
    let decoder = Unpacker::resume_in_stream(window, &found.resync, member_start, known_base, known, Some(size))
        .map_err(|e| match e {
            crate::Error::Unsupported(_) => OpenAtError::NeedMore { needed: 0..stream_target },
            e => OpenAtError::Decode(e.to_string()),
        })?;
    let output = found.resync.output_offset - member_start;
    Ok(Rar5Resume {
        decoder,
        feed_from: packed_from + found.resync.packed_offset as u64,
        output,
        redecode: plan.target - output,
        near: found,
    })
}

fn rar5_window(dictionary: u64, stream_size: u64, solid: bool) -> Result<Window, OpenAtError> {
    window_for(dictionary, Some(stream_size), solid).map_err(|e| OpenAtError::Decode(e.to_string()))
}

/// A 7z LZMA2 folder restarted for a handover; see [`complete_lzma2`].
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Lzma2Resume {
    /// The folder output offset the restart chunk starts at (at or before the plan's `folder_target`).
    pub output: u64,
    /// The packed folder stream offset of the restart chunk's header.
    pub feed_from: u64,
    /// The folder's output from `output` to its end, decoded.
    pub bytes: Vec<u8>,
    /// Folder output decoded again before the target: `folder_target - output`.
    pub redecode: u64,
}

/// Finishes a [`Start::Lzma2`] plan: finds the folder's chunk chain in the held packed bytes (it must run to the
/// end marker at the folder's end, which fixes every chunk's output offset), picks the last chunk at or before the
/// target that resets the LZMA state or stores its bytes, checks it against the known output, and decodes from it
/// to the folder's end with the known output before it as the dictionary.
///
/// `packed` is the folder's packed stream from offset `packed_from` (at most the plan's `fetch_from`) to its end,
/// decrypted when 7zAES sits under LZMA2 (padding after the end marker is allowed); `known` is the folder's output
/// from `known_base`, covering at least the plan's `donor`.
pub fn complete_lzma2(
    map: &MemberMap,
    plan: &OpenAt,
    packed_from: u64,
    packed: &[u8],
    known_base: u64,
    known: &[u8],
    options: &Lzma2DecodeOptions,
) -> Result<Lzma2Resume, OpenAtError> {
    let Start::Lzma2 { folder, folder_target, dict_prop, .. } = plan.start else { return Err(OpenAtError::WrongPlan) };
    let total = map.folders.get(folder as usize).ok_or(OpenAtError::Incomplete("the member's folder"))?.unpacked_size;
    let known_end = known_base.saturating_add(known.len() as u64);
    // The first chunk header chain that runs to the end marker at the end of the bytes.
    let mut found = None;
    for p in 0..packed.len() {
        let c = packed[p];
        if !(c == 1 || c == 2 || c >= 0x80) {
            continue;
        }
        let opts = Lzma2IndexOptions {
            start: Lzma2Start::Resume(Lzma2Position { packed: 0, unpacked: 0 }),
            ..Lzma2IndexOptions::default()
        };
        let idx = Lzma2Index::from_bytes(&packed[p..], opts);
        let Lzma2End::EndMarker { offset } = idx.end else { continue };
        if idx.chunks.len() < 2 || (packed.len() - p) as u64 - (offset + 1) >= 16 {
            continue;
        }
        let rest = idx.end_position().unpacked;
        if rest > total {
            continue;
        }
        found = Some((p, idx, total - rest));
        break;
    }
    let (p, idx, x) = found.ok_or(OpenAtError::NoChain)?;
    let bytes = &packed[p..];
    let chunks = &idx.chunks;
    let restartable = |k: usize| {
        let c = chunks[k];
        c.kind == Lzma2ChunkKind::Stored
            || matches!(c.reset, Lzma2Reset::State | Lzma2Reset::StateProps | Lzma2Reset::DictStateProps)
    };
    let known_at = |at: u64, len: u64| -> Option<&[u8]> {
        let s = usize::try_from(at.checked_sub(known_base)?).ok()?;
        known.get(s..s.checked_add(usize::try_from(len).ok()?)?)
    };
    // A false header before the true chain can lead into it: offsets counted back from the end are right for the
    // true chunks, so a restart must check out against the known output (a stored chunk's bytes, or the first
    // bytes of an LZMA chunk decoded with the known output before it).
    let checks_out = |k: usize| -> bool {
        let c = chunks[k];
        let at = x + c.unpacked_offset;
        if at > folder_target || at < known_base {
            return false;
        }
        if c.kind == Lzma2ChunkKind::Stored {
            let pl = c.payload();
            let len = c.unpacked_len.min(known_end.saturating_sub(at));
            len > 0 && known_at(at, len) == bytes.get(pl.start as usize..(pl.start + len) as usize)
        } else {
            let Some(dict) = known_at(known_base, at - known_base) else { return false };
            let len = c.unpacked_len.min(known_end.saturating_sub(at));
            len > 0
                && idx
                    .decode_with_dictionary(k..k + 1, bytes, 0, dict_prop, dict, options)
                    .is_ok_and(|b| known_at(at, len) == b.get(..len as usize))
        }
    };
    // The last restartable chunk at or before the target that checks out.
    let s = (0..chunks.len())
        .rev()
        .filter(|&k| x + chunks[k].unpacked_offset <= folder_target)
        .find(|&k| restartable(k) && checks_out(k))
        .ok_or(OpenAtError::NeedMore { needed: known_base..folder_target })?;
    let output = x + chunks[s].unpacked_offset;
    let dictionary = known_at(known_base, output - known_base).ok_or(OpenAtError::NeedMore { needed: 0..output })?;
    let decode_err = |e: Lzma2DecodeError| OpenAtError::Decode(format!("{e:?}"));
    let mut out = Vec::new();
    let mut i = s;
    while i < chunks.len() {
        let c = chunks[i];
        if c.kind == Lzma2ChunkKind::Stored {
            let pl = c.payload();
            out.extend_from_slice(&bytes[pl.start as usize..pl.end as usize]);
            i += 1;
        } else if restartable(i) {
            let dict = [dictionary, &out].concat();
            out.extend(
                idx.decode_with_dictionary(i..chunks.len(), bytes, 0, dict_prop, &dict, options).map_err(decode_err)?,
            );
            break;
        } else {
            return Err(OpenAtError::Decode(format!(
                "LZMA2 chunk at folder output {} continues the state of the chunk before it",
                x + c.unpacked_offset
            )));
        }
    }
    Ok(Lzma2Resume {
        output,
        feed_from: packed_from + p as u64 + chunks[s].packed_offset,
        bytes: out,
        redecode: folder_target - output,
    })
}
