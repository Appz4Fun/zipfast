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
    /// 7z LZMA2: the nearest restart the framing allows lies before the packed bytes held (a run of stored chunks the
    /// next LZMA chunk continues the state over is no restart): fetch the folder's packed stream from `packed` (that
    /// restart chunk's header) and supply known output from `output` less the dictionary, then complete again.
    FetchFrom { packed: u64, output: u64 },
    /// Decoding failed.
    Decode(String),
    /// The resumed output would exceed [`Lzma2DecodeOptions::max_output`].
    OutputLimit { limit: u64 },
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
            Self::FetchFrom { packed, output } => {
                write!(
                    f,
                    "the nearest LZMA2 restart is at packed offset {packed} (folder output {output}): fetch from there"
                )
            }
            Self::Decode(e) => write!(f, "decoding failed: {e}"),
            Self::OutputLimit { limit } => write!(f, "the resumed output would exceed {limit} bytes"),
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
    lzma2_coders(&map.folders.get(m.folder?.index as usize)?.coders)
}

/// [`lzma2_folder`] over a folder's coders: exactly one LZMA2 coder, and at most one 7zAES coder besides it.
pub(super) fn lzma2_coders(coders: &[super::MapCoder]) -> Option<(u8, bool)> {
    let (lzma2, others): (Vec<_>, Vec<_>) = coders.iter().partition(|c| c.kind == CoderKind::Lzma2);
    let [lzma2] = lzma2.as_slice() else { return None };
    let encrypted = match others.as_slice() {
        [] => false,
        [aes] if aes.kind == CoderKind::Aes => true,
        _ => return None,
    };
    Some((*lzma2.properties.first()?, encrypted))
}

/// Where member `member`'s output starts in its RAR solid stream: the sizes of the members before it back to the
/// stream's first (the last member not marked solid).
///
/// Only compressed files take part in the stream: directories and stored members (method 0) pass the decoder by,
/// whatever their solid flag, as extraction treats them. A compressed member without the solid flag starts a new
/// stream.
fn rar_stream_start(map: &MemberMap, member: usize) -> Result<u64, OpenAtError> {
    let decodes = |m: &MapMember| !m.is_dir && matches!(m.method, MapMethod::Compressed { .. });
    if !map.members[member].solid {
        return Ok(0);
    }
    let mut sum = 0u64;
    for m in map.members[..member].iter().rev().filter(|m| decodes(m)) {
        sum = m.unpacked_size.and_then(|s| sum.checked_add(s)).ok_or(OpenAtError::SizeUnknown)?;
        if !m.solid {
            break;
        }
    }
    Ok(sum)
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
    /// RAR 5.0 compressed members: how the resumed decoder's window is filled. See [`Seed`].
    pub seed: Seed,
}

/// How a RAR 5.0 handover fills the resumed decoder's window ([`OpenAtOptions::seed`]).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum Seed {
    /// The window is checked: the plan fetches packed bytes far enough back to follow the decoding over the whole
    /// match window (or a decoder floor refuses what was not followed), so the output is right or refused.
    #[default]
    Checked,
    /// The window is seeded from the caller's held plaintext (the output before the target, from an earlier copy),
    /// and the plan fetches packed bytes only from shortly before the target's estimated position
    /// ([`OpenAtOptions::search`]; by default enough for a guarded restart, see [`SEED_SEARCH`]). The output is unverified unless
    /// [`Rar5Resume::checked`] says otherwise: the member's CRC32 or BLAKE2sp at its end proves it, and the decoder
    /// reports early signs of trouble ([`Unpacker::seed_suspect`]). With `strict`, a suspect copy is refused instead
    /// of decoded. See [`Unpacker::resume_seeded`].
    HeldPlaintext { strict: bool },
}

/// The margin a [`Seed::HeldPlaintext`] plan fetches before the target's estimated position when
/// [`OpenAtOptions::search`] is `None`, on top of a filter's reach (4 MiB of output) at twice the member's average
/// packing ratio, so the restart can be guarded.
pub const SEED_SEARCH: u64 = 2 << 20;

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
    /// How a RAR 5.0 restart's window is filled, from [`OpenAtOptions::seed`].
    pub seed: Seed,
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
    /// 7z LZMA2: fetch the folder's packed bytes from `fetch_from` to its end, learn the chunk framing as `framing`
    /// says, and run [`complete_lzma2`] with known folder output covering `donor`. The restart lands at a chunk start
    /// at or before the target.
    Lzma2 {
        folder: u32,
        /// The target in the folder's output (`stream_start + target`).
        folder_target: u64,
        dict_prop: u8,
        /// The known folder output to supply: at least this range.
        donor: Range<u64>,
        /// How the chunk starts before the target become known.
        framing: Lzma2Framing,
    },
}

/// How a [`Start::Lzma2`] plan learns where the folder's LZMA2 chunks start. Only a walk of chunk headers from the
/// stream's first byte establishes that: no plaintext match can, since repeated plaintext can fake a chunk chain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Lzma2Framing {
    /// Walk the chunk headers from the folder's packed stream start up to past the target, reading each header's few
    /// bytes only ([`super::Lzma2IndexBuilder::for_folder`] does it, at most 6 bytes per chunk; each next header
    /// lies a header and a payload further on), and pass the index to [`complete_lzma2`]. The bulk fetch starts at
    /// `fetch_from`. LZMA2 chunks carry at most 64 KiB of packed bytes, so the headers are that close together: a
    /// download in larger pieces (Usenet articles) touches every piece before the target.
    HeaderWalk,
    /// The packed stream is 7zAES ciphertext: headers cannot be read on their own, so the plan fetches from the
    /// folder's start (`fetch_from` is 0) and [`complete_lzma2`] walks the decrypted bytes. A caller decrypting
    /// header blocks itself may pass an index instead.
    FromStart,
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
        Ok(OpenAt { member, target: offset, restart: restart.clone(), start, fetch_from, spans, seed: options.seed })
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
            let seeded = matches!(options.seed, Seed::HeldPlaintext { .. });
            let search = options.search.unwrap_or_else(|| {
                if seeded {
                    // enough for a guarded restart (followed from a filter's reach before it), at the average
                    // ratio doubled, plus the seed margin
                    let scaled = (RAR5_FILTER_REACH as u128 * packed_len as u128 / size.max(1) as u128) as u64;
                    scaled.saturating_mul(2).saturating_add(SEED_SEARCH)
                } else if reach >= offset {
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
            // A seeded window needs the plaintext it holds, the dictionary before the restart; a guarded restart is
            // checked from a filter's reach before it, whose window needs a dictionary before that too. So, as for a
            // checked plan: the dictionary and a filter's reach before the target, twice (the restart lands before it).
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
            let (framing, fetch_from) = if restart.encrypted {
                (Lzma2Framing::FromStart, 0)
            } else {
                (Lzma2Framing::HeaderWalk, estimate.saturating_sub(options.search.unwrap_or(LZMA2_SEARCH)))
            };
            let dictionary = lzma2_dictionary(dict_prop);
            let donor_from = folder_target.saturating_sub(dictionary.saturating_mul(2));
            plan(
                Start::Lzma2 {
                    folder: slot.index,
                    folder_target,
                    dict_prop,
                    donor: donor_from..folder_target,
                    framing,
                },
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
    /// The restart search's report; `None` when decoding starts at the stream's start, where no search is needed.
    pub near: Option<ResyncNear>,
    /// Whether decoding alone proves the output: always for a [`Seed::Checked`] plan (it decodes right or refuses);
    /// for [`Seed::HeldPlaintext`] only when the window was proven ([`Unpacker::seed_checked`]). When false, only
    /// the member's CRC32 or BLAKE2sp proves the output, and [`Unpacker::seed_suspect`] gives early signs.
    pub checked: bool,
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
    let member_start = plan.restart.stream_start;
    // At the stream's start (a member that is not a later member of a solid stream, with its packed bytes from 0)
    // a fresh decoder needs no search and no known plaintext: it is the restart for a target of 0, and the fallback
    // when the search finds none.
    let fresh = || -> Result<Rar5Resume, OpenAtError> {
        let mut decoder = Unpacker::new(window).map_err(|e| OpenAtError::Decode(e.to_string()))?;
        decoder.reset(Some(size));
        decoder.stop_at_last_block();
        Ok(Rar5Resume { decoder, feed_from: 0, output: 0, redecode: plan.target, near: None, checked: true })
    };
    let from_start = member_start == 0 && packed_from == 0;
    if stream_target == 0 {
        return if from_start { fresh() } else { Err(OpenAtError::NeedMore { needed: 0..0 }) };
    }
    let seed = plan.seed;
    let options = NearOptions { estimate: Some(estimate.saturating_sub(packed_from) as usize), ..near.clone() };
    // A seeded (not strict) plan takes the nearest unguarded restart when no guarded one is found: its output is
    // unverified anyway, and the decoder notes it (`SeedSuspect::Unguarded`) before decoding. Both searches share
    // the caller's work budget and deadline.
    let searched = if matches!(seed, Seed::HeldPlaintext { strict: false }) {
        crate::rar5::unpack::resync_near_or_unguarded(packed, known_base, known, window, stream_target, &options)
    } else {
        resync_near(packed, known_base, known, window, stream_target, &options)
    };
    let found = match searched {
        Ok(found) => found,
        Err(_) if from_start => return fresh(),
        Err(e) => return Err(OpenAtError::Resync(e)),
    };
    if found.resync.output_offset < member_start {
        return Err(OpenAtError::NeedMore { needed: known_base..stream_target });
    }
    let resumed = match seed {
        Seed::Checked => Unpacker::resume_in_stream(window, &found.resync, member_start, known_base, known, Some(size)),
        Seed::HeldPlaintext { strict } => {
            Unpacker::resume_seeded(window, &found.resync, member_start, known_base, known, Some(size), strict)
        }
    };
    let decoder = resumed.map_err(|e| match e {
        crate::Error::Unsupported(_) => OpenAtError::NeedMore { needed: 0..stream_target },
        e => OpenAtError::Decode(e.to_string()),
    })?;
    let checked = decoder.seed_checked().unwrap_or(true);
    let output = found.resync.output_offset - member_start;
    Ok(Rar5Resume {
        decoder,
        feed_from: packed_from + found.resync.packed_offset as u64,
        output,
        redecode: plan.target - output,
        near: Some(found),
        checked,
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

/// Finishes a [`Start::Lzma2`] plan: restarts at the last chunk at or before the target that resets the LZMA state
/// or stores its bytes, among chunk starts known from a walk of headers from the stream's first byte, and decodes
/// from it to the folder's end with the known output before it as the dictionary.
///
/// The chunk starts come from `framing`, an index walked from the stream's start (built over the header bytes with
/// [`super::Lzma2IndexBuilder::for_folder`], or over earlier bytes held from an earlier pass), or, when `packed`
/// itself starts at the stream's first byte (`packed_from` 0), from walking `packed`. A restart chunk's header must
/// lie in `packed`. Nothing else establishes the framing: header-like bytes in payloads form chains that can still
/// match the known output. Without a usable chunk start the result is `NeedMore`.
///
/// `packed` is the folder's packed stream from offset `packed_from` to its end, decrypted when 7zAES sits under
/// LZMA2 (the block padding after the stream's end is ignored: the AES coder's output size says where the stream
/// ends); `known` is the folder's output from `known_base`, covering at least the plan's `donor`. From the restart
/// the chunks must run to the end marker at the stream's last byte. The resumed output (stored and decoded) is
/// bounded by `options.max_output`.
#[allow(clippy::too_many_arguments)]
pub fn complete_lzma2(
    map: &MemberMap,
    plan: &OpenAt,
    packed_from: u64,
    packed: &[u8],
    known_base: u64,
    known: &[u8],
    framing: Option<&Lzma2Index>,
    options: &Lzma2DecodeOptions,
) -> Result<Lzma2Resume, OpenAtError> {
    let Start::Lzma2 { folder, folder_target, dict_prop, .. } = plan.start else { return Err(OpenAtError::WrongPlan) };
    let f = map.folders.get(folder as usize).ok_or(OpenAtError::Incomplete("the member's folder"))?;
    // Where the LZMA2 stream ends in the folder's packed stream: the packed size, or under 7zAES the AES coder's
    // output size (the ciphertext is padded to whole blocks; the stream ends inside the last one).
    let packed_len: u64 = f.pack_sizes.iter().sum();
    let stream_end = match f.coders.iter().position(|c| c.kind == CoderKind::Aes) {
        None => packed_len,
        Some(aes) => {
            let out: u64 = f.coders[..aes].iter().map(|c| u64::from(c.out_streams)).sum();
            *f.unpack_sizes.get(out as usize).ok_or(OpenAtError::Incomplete("the 7zAES coder's output size"))?
        }
    };
    resume_lzma2(
        &Lzma2Bounds { total: f.unpacked_size, stream_end, target: folder_target, dict_prop },
        packed_from,
        packed,
        known_base,
        known,
        framing,
        options,
    )
}

/// What [`resume_lzma2`] knows of the folder from the map.
struct Lzma2Bounds {
    /// The folder's output size.
    total: u64,
    /// The LZMA2 stream's length: its end marker is its last byte.
    stream_end: u64,
    /// The target in the folder's output.
    target: u64,
    dict_prop: u8,
}

fn resume_lzma2(
    b: &Lzma2Bounds,
    packed_from: u64,
    packed: &[u8],
    known_base: u64,
    known: &[u8],
    framing: Option<&Lzma2Index>,
    options: &Lzma2DecodeOptions,
) -> Result<Lzma2Resume, OpenAtError> {
    let (total, folder_target, dict_prop) = (b.total, b.target, b.dict_prop);
    let Some(end) = b.stream_end.checked_sub(packed_from).and_then(|e| usize::try_from(e).ok()) else {
        return Err(OpenAtError::Incomplete("packed bytes before the LZMA2 stream's end"));
    };
    if end > packed.len() {
        return Err(OpenAtError::NeedMore { needed: packed_from..b.stream_end });
    }
    let packed = &packed[..end];
    let need_framing = || OpenAtError::NeedMore { needed: 0..b.stream_end };
    // Chunk starts known from a walk from the stream's first byte.
    let walked: Vec<super::Lzma2Chunk>;
    let starts: &[super::Lzma2Chunk] = match framing {
        Some(index) => {
            if index.start != (Lzma2Position { packed: 0, unpacked: 0 }) {
                return Err(OpenAtError::Incomplete("an LZMA2 index walked from the stream's start"));
            }
            // An index walked only up to past the target (`Lzma2Framing::HeaderWalk`) ends before the next LZMA
            // chunk after a stored run: it is walked on over the held bytes when they go on from where it ends.
            let reach = index.end_position();
            match reach.packed.checked_sub(packed_from).and_then(|r| usize::try_from(r).ok()) {
                Some(rel) if reach.unpacked < total && rel < packed.len() => {
                    // (a walk's packed offsets count from the slice it is given)
                    let resume = Lzma2Position { packed: 0, unpacked: reach.unpacked };
                    let rest = Lzma2Index::from_bytes(
                        &packed[rel..],
                        Lzma2IndexOptions { start: Lzma2Start::Resume(resume), ..Lzma2IndexOptions::default() },
                    );
                    let shift = |c: &super::Lzma2Chunk| super::Lzma2Chunk {
                        packed_offset: c.packed_offset + reach.packed,
                        ..*c
                    };
                    walked = index.chunks.iter().copied().chain(rest.chunks.iter().map(shift)).collect();
                    &walked
                }
                _ => &index.chunks,
            }
        }
        None if packed_from == 0 => {
            walked = Lzma2Index::from_bytes(packed, Lzma2IndexOptions::default()).chunks;
            &walked
        }
        None => return Err(need_framing()),
    };
    let resets = |c: &super::Lzma2Chunk| {
        matches!(c.reset, Lzma2Reset::State | Lzma2Reset::StateProps | Lzma2Reset::DictStateProps)
    };
    let restartable = |c: &super::Lzma2Chunk| c.kind == Lzma2ChunkKind::Stored || resets(c);
    let reaches_end = matches!(starts.last(), Some(l) if l.unpacked_offset + l.unpacked_len == total);
    let attempt = |k: usize| -> Result<Result<Lzma2Resume, u64>, OpenAtError> {
        let start = starts[k];
        // The props in effect there, from the chunk that set them (the walk resumed below starts after it).
        let inherited = starts[..=k].iter().rev().find_map(|c| c.props);
        // Nothing before the last dictionary reset at or before the restart can be referenced.
        let reset_floor = starts[..=k]
            .iter()
            .rev()
            .find(|c| matches!(c.reset, Lzma2Reset::Dict | Lzma2Reset::DictStateProps))
            .map_or(0, |c| c.unpacked_offset);
        let rel = usize::try_from(start.packed_offset - packed_from).map_err(|_| need_framing())?;
        // From there the chunks run to the end marker at the stream's last byte and fill the folder's output.
        let idx = Lzma2Index::from_bytes(
            &packed[rel..],
            Lzma2IndexOptions {
                start: Lzma2Start::Resume(Lzma2Position { packed: 0, unpacked: start.unpacked_offset }),
                ..Lzma2IndexOptions::default()
            },
        );
        let ends_right =
            matches!(idx.end, Lzma2End::EndMarker { offset } if rel as u64 + offset + 1 == packed.len() as u64);
        if !ends_right || idx.chunks.is_empty() || idx.end_position().unpacked != total {
            return Err(OpenAtError::Decode(format!(
                "the LZMA2 chunks from folder output {} do not run to the stream's end marker",
                start.unpacked_offset
            )));
        }
        let bytes = &packed[rel..];
        let chunks = &idx.chunks;
        let known_at = |at: u64, len: u64| -> Option<&[u8]> {
            let s = usize::try_from(at.checked_sub(known_base)?).ok()?;
            known.get(s..s.checked_add(usize::try_from(len).ok()?)?)
        };
        let output = start.unpacked_offset;
        let decode_err = |e: Lzma2DecodeError| OpenAtError::Decode(format!("{e:?}"));
        let limit = options.max_output;
        let over = |n: u64| if n > limit { Err(OpenAtError::OutputLimit { limit }) } else { Ok(()) };
        let mut out = Vec::new();
        // where in `out` a stored chunk last reset the dictionary: nothing before it is reached
        let mut dict_reset_at = None;
        let mut i = 0;
        while i < chunks.len() {
            let c = chunks[i];
            if c.kind == Lzma2ChunkKind::Stored {
                if c.reset == Lzma2Reset::Dict {
                    dict_reset_at = Some(out.len());
                }
                let pl = c.payload();
                over(out.len() as u64 + (pl.end - pl.start))?;
                out.extend_from_slice(&bytes[pl.start as usize..pl.end as usize]);
                i += 1;
            } else if restartable(&c) {
                // Only the last dictionary-sized bytes can be reached: the known output's tail, then what was
                // resumed, unless a chunk since the restart reset the dictionary. The known output must cover its
                // part; a dictionary cut short would decode as corrupt data.
                let need = usize::try_from(lzma2_dictionary(dict_prop)).unwrap_or(usize::MAX);
                let (from_known, resumed_from) = match (c.reset, dict_reset_at) {
                    (Lzma2Reset::DictStateProps, _) => (0, out.len()),
                    (_, Some(at)) => (0, at.max(out.len().saturating_sub(need))),
                    (_, None) => (need.saturating_sub(out.len()), out.len().saturating_sub(need)),
                };
                let dict_from = output.saturating_sub(from_known as u64).max(reset_floor.min(output));
                let dictionary: &[u8] = match output - dict_from {
                    0 => &[],
                    n => known_at(dict_from, n).ok_or(OpenAtError::NeedMore { needed: dict_from..output })?,
                };
                let mut dict = Vec::with_capacity(dictionary.len() + out.len() - resumed_from);
                dict.extend_from_slice(dictionary);
                dict.extend_from_slice(&out[resumed_from..]);
                // the decoder's own bound is what is left of the limit
                let mut left = options.clone();
                left.max_output = limit - out.len() as u64;
                let decoded = idx
                    .decode_with_dictionary_props(i..chunks.len(), bytes, 0, dict_prop, &dict, inherited, &left)
                    .map_err(decode_err)?;
                over(out.len() as u64 + decoded.len() as u64)?;
                out.extend(decoded);
                break;
            } else {
                // an LZMA chunk that continues the state from before the restart
                return Ok(Err(c.unpacked_offset));
            }
        }
        Ok(Ok(Lzma2Resume { output, feed_from: start.packed_offset, bytes: out, redecode: folder_target - output }))
    };
    // The latest candidate at or before the target first, in one pass back over the index; one whose header lies
    // before the bytes held is fetched.
    //
    // A restart: an LZMA chunk that resets the state, or a stored chunk unless the next LZMA chunk after it continues
    // the state (a stored chunk resets nothing: 7-Zip -mmt goes on after a run of stored chunks with an LZMA chunk
    // that continues the state from before them). Proven by the index, or unproven when it ends before the next LZMA
    // chunk: then the candidate is tried and given up if decoding meets such a chunk. Every unproven candidate lies
    // in the index's last run of stored chunks, so what one meets they all would: one failure retires the run.
    let mut next_lzma: Option<super::Lzma2Chunk> = None;
    let mut unproven_failed = false;
    for k in (0..starts.len()).rev() {
        let c = starts[k];
        let proof = match (c.kind, next_lzma) {
            // the stream's start: everything is fresh there
            _ if c.packed_offset == 0 => Some(true),
            (Lzma2ChunkKind::Stored, Some(next)) => Some(resets(&next)),
            (Lzma2ChunkKind::Stored, None) => reaches_end.then_some(true),
            _ => Some(resets(&c)),
        };
        if c.kind != Lzma2ChunkKind::Stored {
            next_lzma = Some(c);
        }
        if c.unpacked_offset > folder_target || proof == Some(false) || (proof.is_none() && unproven_failed) {
            continue;
        }
        if c.packed_offset < packed_from {
            return Err(OpenAtError::FetchFrom { packed: c.packed_offset, output: c.unpacked_offset });
        }
        match attempt(k)? {
            Ok(resume) => return Ok(resume),
            Err(_) if proof.is_none() => unproven_failed = true,
            Err(at) => {
                return Err(OpenAtError::Decode(format!(
                    "LZMA2 chunk at folder output {at} continues the state of the chunk before it"
                )));
            }
        }
    }
    Err(need_framing())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> Lzma2DecodeOptions {
        Lzma2DecodeOptions::default()
    }

    fn bounds(stream: &[u8], total: u64, target: u64) -> Lzma2Bounds {
        Lzma2Bounds { total, stream_end: stream.len() as u64, target, dict_prop: 0 }
    }

    /// Codex's first stream: `01 00 19`, a 26-byte payload of `02 00 09` + ten `a` + `02 00 09` + ten `b`, then the
    /// end marker. Its payload holds a chunk chain that ends at the true end marker.
    fn stream_one() -> (Vec<u8>, Vec<u8>) {
        let payload = [&[0x02, 0x00, 0x09][..], &[b'a'; 10], &[0x02, 0x00, 0x09], &[b'b'; 10]].concat();
        ([&[0x01, 0x00, 0x19][..], &payload, &[0x00]].concat(), payload)
    }

    /// Codex's second stream: one stored chunk `01 04 72` of P = two repeats of (`02 02 02` + 515 `02`), then
    /// `02 00 63` + 100 `62`; the repeats let a fake chain match more than 515 bytes of known output.
    fn stream_two() -> (Vec<u8>, Vec<u8>) {
        let rep = [&[0x02, 0x02, 0x02][..], &[0x02; 515]].concat();
        let p = [&rep[..], &rep, &[0x02, 0x00, 0x63], &[0x62; 100]].concat();
        assert_eq!(p.len(), 0x473);
        ([&[0x01, 0x04, 0x72][..], &p, &[0x00]].concat(), p)
    }

    /// Fetched from inside the stored payload, no chunk start is known: refused, whatever the known output. With the
    /// framing walked from the stream's start the only chunk starts at 0, so a restart needs the bytes from 0.
    #[test]
    fn a_chain_inside_a_payload_is_never_taken() {
        for (stream, plain, from, target, known) in [
            {
                let (s, p) = stream_one();
                (s, p.clone(), 3usize, 7u64, p[..7].to_vec())
            },
            {
                let (s, p) = stream_two();
                (s, p.clone(), 3, 600, p[..600].to_vec())
            },
        ] {
            let b = bounds(&stream, plain.len() as u64, target);
            let r = resume_lzma2(&b, from as u64, &stream[from..], 0, &known, None, &opts());
            assert!(matches!(r, Err(OpenAtError::NeedMore { .. })), "{r:?}");
            let r = resume_lzma2(&b, from as u64, &stream[from..], 0, &plain, None, &opts());
            assert!(matches!(r, Err(OpenAtError::NeedMore { .. })), "{r:?}");
            // with the framing, the only real restart is the stream's start, before the bytes held: fetch from there
            let framing = Lzma2Index::from_bytes(&stream, Lzma2IndexOptions::default());
            let r = resume_lzma2(&b, from as u64, &stream[from..], 0, &known, Some(&framing), &opts());
            assert!(matches!(r, Err(OpenAtError::FetchFrom { packed: 0, output: 0 })), "{r:?}");
            // from the stream's start the framing is walked, and the output is right
            let r = resume_lzma2(&b, 0, &stream, 0, &known, None, &opts()).unwrap();
            assert_eq!((r.output, r.bytes), (0, plain));
        }
    }

    /// A framing index walked only up to past the target is walked on over the held bytes: the stored chunks after
    /// it run to the end, so a stored restart is proven (Codex's example: three stored 100-byte chunks, the index
    /// over the first two, target 150, bytes held from the second header).
    #[test]
    fn a_partial_framing_index_is_walked_on_over_the_held_bytes() {
        let part = |c: u8| -> Vec<u8> { (0..100u8).map(|i| c + i % 26).collect() };
        let (a, b, c) = (part(b'A'), part(b'a'), part(b'0'));
        let stream = [&[0x01, 0x00, 99][..], &a, &[0x02, 0x00, 99], &b, &[0x02, 0x00, 99], &c, &[0x00]].concat();
        let plain = [a.clone(), b.clone(), c.clone()].concat();
        let bounds = bounds(&stream, 300, 150);
        let framing = Lzma2Index::from_bytes(&stream[..206], Lzma2IndexOptions::default());
        assert_eq!(framing.chunks.len(), 2);
        let r = resume_lzma2(&bounds, 103, &stream[103..], 0, &plain[..150], Some(&framing), &opts()).unwrap();
        assert_eq!((r.output, r.feed_from), (100, 103));
        assert_eq!(r.bytes, plain[100..]);
    }

    /// A raw LZMA2 stream (2 MiB dictionary: prop 18) from liblzma, end marker included.
    fn lzma2_encode(input: &[u8]) -> Vec<u8> {
        use liblzma::stream::{Action, Filters, LzmaOptions, Status, Stream};
        let mut o = LzmaOptions::new_preset(6).unwrap();
        o.dict_size(2 << 20);
        let mut f = Filters::new();
        f.lzma2(&o);
        let mut st = Stream::new_raw_encoder(&f).unwrap();
        let mut out = Vec::with_capacity(input.len() + 4096);
        while st.process_vec(&input[st.total_in() as usize..], &mut out, Action::Finish).unwrap() != Status::StreamEnd {
            out.reserve(4096);
        }
        out
    }

    /// The known output must cover the dictionary before a restart that decodes an LZMA chunk: cut short, the
    /// answer is `NeedMore` for the missing part (it was a corrupt-data error); covered, the output is right.
    #[test]
    fn a_short_dictionary_is_need_more() {
        // text, incompressible bytes (stored chunks), the same text again: the LZMA chunk after the stored run
        // resets the state, and its matches reach back into the first text
        let text: Vec<u8> =
            (0..60_000u32).flat_map(|i| format!("line {} of {}\n", i % 977, i % 13).into_bytes()).collect();
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        let noise: Vec<u8> = (0..150_000)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect();
        let plain = [&text[..], &noise, &text].concat();
        let stream = lzma2_encode(&plain);
        let framing = Lzma2Index::from_bytes(&stream, Lzma2IndexOptions::default());
        let total = plain.len() as u64;
        let target = total - 1000;
        let b = Lzma2Bounds { total, stream_end: stream.len() as u64, target, dict_prop: 18 };
        let restart = framing
            .chunks
            .iter()
            .rev()
            .find(|c| c.unpacked_offset <= target && c.kind != Lzma2ChunkKind::Stored)
            .copied()
            .unwrap();
        assert_eq!(restart.reset, Lzma2Reset::State, "{:?}", framing.chunks);
        let (out, from) = (restart.unpacked_offset, restart.packed_offset);
        let held = &stream[from as usize..];
        // only the last 1000 bytes before the restart known: matches reach further back
        let short = resume_lzma2(
            &b,
            from,
            held,
            out - 1000,
            &plain[out as usize - 1000..target as usize],
            Some(&framing),
            &opts(),
        );
        assert!(matches!(short, Err(OpenAtError::NeedMore { ref needed }) if *needed == (0..out)), "{short:?}");
        let r = resume_lzma2(&b, from, held, 0, &plain[..target as usize], Some(&framing), &opts()).unwrap();
        assert_eq!((r.output, r.bytes.as_slice()), (out, &plain[out as usize..]));
    }

    /// Codex on #290: nothing before a dictionary reset can be referenced, so the known output needs to reach back
    /// only to the last reset before the restart, not a whole dictionary (here a stream whose first chunk resets the
    /// dictionary at output 5000, after another one).
    #[test]
    fn the_dictionary_needed_stops_at_an_earlier_dictionary_reset() {
        let prefix: Vec<u8> = (0..5000u32).map(|i| (i * 31 % 251) as u8).collect();
        let mut first = lzma2_encode(&prefix);
        assert_eq!(first.pop(), Some(0), "the end marker");
        let text: Vec<u8> =
            (0..60_000u32).flat_map(|i| format!("line {} of {}\n", i % 977, i % 13).into_bytes()).collect();
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        let noise: Vec<u8> = (0..150_000)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect();
        let tail = [&text[..], &noise, &text].concat();
        let stream = [first, lzma2_encode(&tail)].concat();
        let plain = [&prefix[..], &tail].concat();
        let framing = Lzma2Index::from_bytes(&stream, Lzma2IndexOptions::default());
        let total = plain.len() as u64;
        let target = total - 1000;
        let b = Lzma2Bounds { total, stream_end: stream.len() as u64, target, dict_prop: 18 };
        let restart = framing
            .chunks
            .iter()
            .rev()
            .find(|c| c.unpacked_offset <= target && c.kind != Lzma2ChunkKind::Stored)
            .copied()
            .unwrap();
        assert_eq!(restart.reset, Lzma2Reset::State, "{:?}", framing.chunks);
        let (out, from) = (restart.unpacked_offset, restart.packed_offset);
        // the known output from the reset at 5000 is the whole usable dictionary (2 MiB would reach back to 0)
        let r = resume_lzma2(
            &b,
            from,
            &stream[from as usize..],
            5000,
            &plain[5000..target as usize],
            Some(&framing),
            &opts(),
        )
        .unwrap();
        assert_eq!((r.output, r.bytes.as_slice()), (out, &plain[out as usize..]));
    }

    /// With a framing index from the start, a restart at a later chunk needs only the bytes from that chunk.
    #[test]
    fn a_framing_index_lets_a_later_chunk_restart() {
        let a: Vec<u8> = (0..100u8).map(|i| b'A' + i % 26).collect();
        let b: Vec<u8> = (0..100u8).map(|i| b'a' + i % 26).collect();
        let stream = [&[0x01, 0x00, 99][..], &a, &[0x02, 0x00, 99], &b, &[0x00]].concat();
        let plain = [a.clone(), b.clone()].concat();
        let bounds = bounds(&stream, 200, 150);
        let framing = Lzma2Index::from_bytes(&stream, Lzma2IndexOptions::default());
        let r = resume_lzma2(&bounds, 103, &stream[103..], 0, &plain[..150], Some(&framing), &opts()).unwrap();
        assert_eq!((r.output, r.bytes.as_slice(), r.feed_from), (100, &b[..], 103));
        // without it: refused
        let r = resume_lzma2(&bounds, 103, &stream[103..], 0, &plain[..150], None, &opts());
        assert!(matches!(r, Err(OpenAtError::NeedMore { .. })), "{r:?}");
        // an index that does not start at the stream's start is not framing
        let resumed = Lzma2Index::from_bytes(
            &stream[103..],
            Lzma2IndexOptions {
                start: Lzma2Start::Resume(Lzma2Position { packed: 103, unpacked: 100 }),
                ..Default::default()
            },
        );
        let r = resume_lzma2(&bounds, 103, &stream[103..], 0, &plain[..150], Some(&resumed), &opts());
        assert!(matches!(r, Err(OpenAtError::Incomplete(_))), "{r:?}");
        // bytes short of the stream's end are asked for, not guessed past
        let r = resume_lzma2(&bounds, 103, &stream[103..150], 0, &plain, Some(&framing), &opts());
        assert!(matches!(r, Err(OpenAtError::NeedMore { .. })), "{r:?}");
    }

    /// Stored payloads count toward `max_output` too.
    #[test]
    fn stored_output_is_bounded() {
        let (stream, plain) = stream_one();
        let b = bounds(&stream, plain.len() as u64, 0);
        let small = Lzma2DecodeOptions { max_output: 10, ..opts() };
        let r = resume_lzma2(&b, 0, &stream, 0, &plain, None, &small);
        assert!(matches!(r, Err(OpenAtError::OutputLimit { limit: 10 })), "{r:?}");
        let r = resume_lzma2(&b, 0, &stream, 0, &plain, None, &opts()).unwrap();
        assert_eq!((r.output, r.bytes), (0, plain));
    }

    /// Exactly one LZMA2 coder, alone or under 7zAES; two chained LZMA2 coders are not one stage.
    #[test]
    fn only_a_single_lzma2_coder_is_an_lzma2_folder() {
        let coder = |kind, properties: &[u8]| super::super::MapCoder {
            kind,
            id: 0,
            properties: properties.to_vec(),
            in_streams: 1,
            out_streams: 1,
        };
        assert_eq!(lzma2_coders(&[coder(CoderKind::Lzma2, &[16])]), Some((16, false)));
        assert_eq!(lzma2_coders(&[coder(CoderKind::Aes, &[]), coder(CoderKind::Lzma2, &[18])]), Some((18, true)));
        assert_eq!(lzma2_coders(&[coder(CoderKind::Lzma2, &[16]), coder(CoderKind::Lzma2, &[16])]), None);
        assert_eq!(lzma2_coders(&[coder(CoderKind::Bcj, &[]), coder(CoderKind::Lzma2, &[16])]), None);
    }

    /// A raw LZMA2 stream (2 MiB dictionary) of text and incompressible runs: liblzma stores the runs and resets
    /// the state (without props) for the LZMA chunk after each.
    fn mixed_stream() -> (Vec<u8>, Vec<u8>) {
        let mut x = 0x2545_F491_4F6C_DD1Du64;
        let mut noise = |n: usize| -> Vec<u8> {
            (0..n)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    x as u8
                })
                .collect()
        };
        let text = |n: usize, seed: usize| -> Vec<u8> {
            (0..n).map(|i| b"the quick brown fox jumps over the lazy dog "[(i * 7 + seed) % 44]).collect()
        };
        let plain = [text(300_000, 1), noise(400_000), text(150_000, 9), noise(130_000), text(90_000, 3)].concat();
        let mut opts = liblzma::stream::LzmaOptions::new_preset(6).unwrap();
        opts.dict_size(2 << 20);
        let mut filters = liblzma::stream::Filters::new();
        filters.lzma2(&opts);
        let mut stream = liblzma::stream::Stream::new_raw_encoder(&filters).unwrap();
        let mut out = Vec::with_capacity(plain.len() + (1 << 16));
        let mut consumed = 0;
        loop {
            out.reserve(1 << 16);
            let before = stream.total_in();
            let status = stream.process_vec(&plain[consumed..], &mut out, liblzma::stream::Action::Finish).unwrap();
            consumed += (stream.total_in() - before) as usize;
            if status == liblzma::stream::Status::StreamEnd {
                return (out, plain);
            }
        }
    }

    /// A restart at a state-only reset (or at a stored chunk before one) inherits the props from the chunk that set
    /// them, before the restart: the walk resumed at the restart does not see that chunk.
    #[test]
    fn a_state_only_reset_restarts_with_inherited_props() {
        let (stream, plain) = mixed_stream();
        let framing = Lzma2Index::from_bytes(&stream, Lzma2IndexOptions::default());
        let state_only = framing
            .chunks
            .iter()
            .position(|c| c.reset == Lzma2Reset::State && c.props.is_none())
            .expect("a state-only reset after stored chunks");
        let bounds =
            |target| Lzma2Bounds { total: plain.len() as u64, stream_end: stream.len() as u64, target, dict_prop: 18 };
        let stored = framing.chunks[..state_only].iter().rposition(|c| c.kind == Lzma2ChunkKind::Stored).unwrap();
        for k in [state_only, stored] {
            let c = framing.chunks[k];
            let target = c.unpacked_offset + 10;
            let from = c.packed_offset;
            let r = resume_lzma2(
                &bounds(target),
                from,
                &stream[from as usize..],
                0,
                &plain[..target as usize],
                Some(&framing),
                &opts(),
            )
            .unwrap_or_else(|e| panic!("chunk {k} ({:?}): {e}", c.reset));
            assert_eq!(r.output, c.unpacked_offset, "chunk {k}");
            assert_eq!(r.bytes, plain[r.output as usize..], "chunk {k}");
        }
    }
}
