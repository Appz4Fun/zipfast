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

//! Rebuilding a copy's volume bytes from output already held: see `docs/container-rebuild.md`.
//!
//! A downloader that switches from one copy of a file to another (the same file in another container) holds the
//! output the first copy produced. For a stored or AES-stored second copy, every volume byte carrying that output can
//! be computed locally: plain stored data is the output itself, AES-CBC ciphertext follows from the output, the key
//! and the ciphertext block before it ([`crate::crypto::rebuild_cbc`]), and WinZip AES ciphertext is the output XOR
//! its keystream. [`ContainerRebuilder::rebuild`] returns the bytes of a volume range with a report of what was
//! rebuilt and what was not, and why, so only the rest needs downloading. RAR 5.0 volume heads and tails are rebuilt
//! from the volume's surviving headers when asked ([`VolumeHeaders`]).

use super::{
    CipherParams, CoderKind, Layer, Lzma2Framing, MapFormat, MemberMap, OpenAt, OutputMapping, PackedSpan, Start,
    member_restart,
};
use crate::crypto::{AesKey, HmacSha1, aes_derive, derive_7z_key, derive_rar4_key_iv, derive_rar5_key};
use crate::rar5::{HeadDoubt, HeadOptions, QuickOpenMode, TailDoubt, rebuild_volume_head, rebuild_volume_tail_with};
use std::collections::{BTreeMap, HashMap};
use std::ops::Range;

/// How many plaintext bytes are read from a [`HeldOutput`] at a time.
const READ_CHUNK: usize = 1 << 20;
/// A CBC chain checkpoint is kept every this many blocks (64 KiB of stream), so later calls start close by.
const CHECKPOINT_EVERY: u64 = 4096;
/// WinZip AES authentication code length.
const AUTH_LEN: u64 = 10;

/// Output a downloader already holds, possibly with holes, read by member and output offset.
///
/// For a 7z member the offset is in the member's own output (its folder slot is added internally).
pub trait HeldOutput {
    /// Copies member `member`'s output from `offset` into `buf` and returns the ranges (absolute output offsets,
    /// within `offset..offset + buf.len()`) that are held. Bytes of `buf` outside them are ignored.
    fn read_held(&mut self, member: usize, offset: u64, buf: &mut [u8]) -> Vec<Range<u64>>;
}

impl<F: FnMut(usize, u64, &mut [u8]) -> Vec<Range<u64>>> HeldOutput for F {
    fn read_held(&mut self, member: usize, offset: u64, buf: &mut [u8]) -> Vec<Range<u64>> {
        self(member, offset, buf)
    }
}

/// One member of [`HeldMembers`]: its index, its output from offset 0, and the ranges held (all when `None`).
type HeldMember<'a> = (usize, &'a [u8], Option<Vec<Range<u64>>>);

/// [`HeldOutput`] over members' output in memory, each with the ranges known good (all of it when `None`).
#[derive(Clone, Debug, Default)]
pub struct HeldMembers<'a> {
    members: Vec<HeldMember<'a>>,
}

impl<'a> HeldMembers<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds member `member`'s output: `bytes` from offset 0, of which only `good` is held (all when `None`).
    pub fn with(mut self, member: usize, bytes: &'a [u8], good: Option<Vec<Range<u64>>>) -> Self {
        self.members.push((member, bytes, good));
        self
    }
}

impl HeldOutput for HeldMembers<'_> {
    fn read_held(&mut self, member: usize, offset: u64, buf: &mut [u8]) -> Vec<Range<u64>> {
        let Some((_, bytes, good)) = self.members.iter().find(|m| m.0 == member) else { return Vec::new() };
        let end = offset.saturating_add(buf.len() as u64).min(bytes.len() as u64);
        if offset >= end {
            return Vec::new();
        }
        buf[..(end - offset) as usize].copy_from_slice(&bytes[offset as usize..end as usize]);
        match good {
            None => std::iter::once(offset..end).collect(),
            Some(good) => good
                .iter()
                .filter_map(|g| {
                    let (a, b) = (g.start.max(offset), g.end.min(end));
                    (a < b).then_some(a..b)
                })
                .collect(),
        }
    }
}

/// Volume bytes the caller holds (downloaded articles). They are never reported as rebuilt; they give the CBC
/// ciphertext block before a range when the held output has a hole there, take part in [`Crc32Check`]s, and are
/// compared with what is rebuilt ([`RebuiltRange::conflicts`]).
#[derive(Clone, Copy, Debug)]
pub struct KnownBytes<'a> {
    pub volume: u32,
    pub offset: u64,
    pub bytes: &'a [u8],
}

/// A CRC32 over volume bytes (a Usenet article's, from its yEnc trailer), used to find a RAR final block's random
/// padding. Every byte of `range` other than the final block's must be rebuilt in the same call or be
/// [`KnownBytes`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Crc32Check {
    pub volume: u32,
    pub range: Range<u64>,
    pub crc32: u32,
}

/// A candidate final block offered to [`RebuildOptions::accept`].
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct FinalBlock {
    /// The member whose stream ends with this block.
    pub member: usize,
    /// The block's ciphertext as this padding gives it.
    pub block: [u8; 16],
    /// Where each of the block's 16 bytes lies: `(volume, offset)`, or None when its piece is not in the map.
    pub places: [Option<(u32, u64)>; 16],
    /// How many padding bytes the block has.
    pub pad: u8,
}

/// The RAR 5.0 headers of the volume being rebuilt, from the bytes the caller holds of it.
#[derive(Clone, Copy, Debug, Default)]
pub struct VolumeHeaders<'a> {
    /// The volume's exact length (from the par2 file description or the yEnc `=ybegin size=`).
    pub volume_len: u64,
    /// The volume's surviving start, through at least its last file header: rebuilds its tail
    /// ([`crate::rar5::rebuild_volume_tail_with`]).
    pub head: Option<&'a [u8]>,
    /// The volume's surviving last bytes (its quick open data and end header): rebuilds its start and every file
    /// header the quick open data caches ([`crate::rar5::rebuild_volume_head`]).
    pub tail: Option<&'a [u8]>,
    /// Whether volumes follow this one (for the tail's end header).
    pub more_volumes: Option<bool>,
    /// The set's quick open mode, from an intact volume ([`crate::rar5::quick_open_mode`]).
    pub quick_open: Option<QuickOpenMode>,
    /// The start of another intact volume of the set, through its main header (makes the rebuilt main header
    /// certain).
    pub sibling: Option<&'a [u8]>,
}

/// Options for [`ContainerRebuilder::rebuild`].
#[derive(Default)]
pub struct RebuildOptions<'a> {
    /// Only this member's bytes; other members' bytes are [`Missing::OtherMember`].
    pub member: Option<usize>,
    /// Volume bytes held, see [`KnownBytes`].
    pub known: Vec<KnownBytes<'a>>,
    /// Checks that find a RAR final block's random padding.
    pub checks: Vec<Crc32Check>,
    /// The caller's own test of a final block candidate (a par2 slice hash, say), tried when no [`Crc32Check`] can
    /// decide. It may be called up to 2^24 times.
    pub accept: Option<&'a mut dyn FnMut(&FinalBlock) -> bool>,
    /// Rebuild RAR 5.0 headers from these bytes of the volume.
    pub headers: Option<VolumeHeaders<'a>>,
    /// Handover plans ([`super::open_at`]) of compressed members: their packed bytes before the plan's restart are
    /// [`ByteState::Unneeded`].
    pub plans: &'a [OpenAt],
    /// The most stream bytes encrypted forward from a checkpoint (the IV, an earlier call's blocks or
    /// [`KnownBytes`]) to reach a CBC range's previous block. None: no limit.
    pub max_chain: Option<u64>,
    /// The largest range accepted (default 1 GiB).
    pub max_range: Option<u64>,
}

/// What became of a run of volume bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ByteState {
    /// The bytes in [`RebuiltRange::bytes`] are the volume's exactly.
    Rebuilt(Rebuilt),
    /// Compressed data before a handover plan's restart: not needed by the restarted decoder. With `chunk_headers`
    /// (a 7z LZMA2 plan with [`Lzma2Framing::HeaderWalk`]) the LZMA2 chunk headers in it are still read.
    Unneeded { chunk_headers: bool },
    /// Not rebuilt: download these bytes.
    Missing(Missing),
}

/// How rebuilt bytes were produced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Rebuilt {
    /// Stored data: the output itself.
    Plain,
    /// AES-CBC ciphertext of whole blocks.
    Cbc,
    /// The final CBC block, with `pad` padding bytes: zeros (7z) or found by a check (RAR).
    CbcFinal { pad: u8, searched: bool },
    /// WinZip AES ciphertext.
    Counter,
    /// WinZip AES salt and password verifier, from the map.
    CounterPrefix,
    /// WinZip AES authentication code, from the whole output.
    CounterAuth,
    /// A RAR 5.0 header, certain.
    Header(HeaderSource),
}

/// Which rebuild produced header bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum HeaderSource {
    /// The volume's tail from its start ([`VolumeHeaders::head`]).
    Tail,
    /// The volume's start from its tail ([`VolumeHeaders::tail`]).
    Head,
    /// A file header copied in the quick open data ([`VolumeHeaders::tail`]).
    Cached,
}

/// Why bytes were not rebuilt.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Missing {
    /// Archive structure (headers, padding, directories) not rebuilt.
    Header(HeaderGap),
    /// The output these bytes carry (the region's `output`) is not held.
    NotHeld,
    /// AES-CBC: the ciphertext block before these blocks is unknown: the held output has a hole between the last
    /// checkpoint and here, or reaching here would exceed [`RebuildOptions::max_chain`]. Supply the volume bytes
    /// of the block before as [`KnownBytes`].
    Chain,
    /// The final CBC block, whose `pad` padding bytes are random (RAR): no check decided it (`searched` false), or
    /// none of the at most 2^24 paddings passed (`searched` true). More than 3 padding bytes are never searched.
    FinalPadding { pad: u8, searched: bool },
    /// The final CBC block: `candidates` paddings pass every check given, and they differ in these bytes (the
    /// checks see too little of the block, an article boundary cutting through it, say). Bytes all passing
    /// candidates agree on are rebuilt. Give the CRC of the other article holding the block too.
    FinalPaddingAmbiguous { pad: u8, candidates: u32 },
    /// CBC padding blocks past the output.
    Padding,
    /// No key: no password was given, it is wrong (the format's check value refused it), or derivation failed.
    Key(KeyProblem),
    /// WinZip AES authentication code: it covers the whole output, which is not all held.
    AuthCode,
    /// Compressed data: not rebuildable from output. A handover plan ([`RebuildOptions::plans`]) says which bytes
    /// it does not need.
    Compressed(Layer),
    /// ZipCrypto: every byte depends on the encryption header's random bytes and all earlier output.
    Sequential,
    /// The map gives no output mapping (an unmapped cipher, an unknown size, a missing piece).
    Unmapped(&'static str),
    /// Another member's bytes, with [`RebuildOptions::member`] set.
    OtherMember,
}

/// Why header bytes were not rebuilt.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum HeaderGap {
    /// Only RAR 5.0 headers are rebuilt.
    NotRar5,
    /// Encrypted headers (`-hp`) start with random IVs.
    Encrypted,
    /// No [`RebuildOptions::headers`], or not the bytes this part needs (`head` for the tail, `tail` for the start).
    NoSource,
    /// The rebuild refused; the text says why.
    Refused(String),
    /// Neither rebuild covers these bytes (a header the quick open data does not cache, a service header).
    NotCovered,
    /// Rebuilt, but not certain: the bytes in [`RebuiltRange::bytes`] are a guess.
    Doubtful(HeaderDoubt),
}

/// Why rebuilt header bytes are not certain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum HeaderDoubt {
    Tail(TailDoubt),
    Head(HeadDoubt),
}

/// Why a key is not available.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum KeyProblem {
    NoPassword,
    /// The password check value (RAR 5.0, WinZip AES) refused the password.
    WrongPassword,
    /// The parameters cannot give a key (an unsupported KDF count, say).
    Derivation,
}

/// A run of volume bytes with one state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Region {
    /// Volume offsets.
    pub range: Range<u64>,
    /// The member whose data these bytes are, if any.
    pub member: Option<usize>,
    /// The member output offsets these bytes carry, where the mapping is exact (stored data, the ciphertext of
    /// output bytes); None for headers, prefixes, padding and compressed data.
    pub output: Option<Range<u64>>,
    pub state: ByteState,
}

/// The result of [`ContainerRebuilder::rebuild`].
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct RebuiltRange {
    pub volume: u32,
    pub range: Range<u64>,
    /// The range's bytes: exact where a region is [`ByteState::Rebuilt`], a guess where it is
    /// [`HeaderGap::Doubtful`], zero elsewhere.
    pub bytes: Vec<u8>,
    /// The range's regions, in order, back to back, covering it exactly.
    pub regions: Vec<Region>,
    /// Volume ranges where [`KnownBytes`] differ from what was rebuilt: the held output, the password or the known
    /// bytes are wrong.
    pub conflicts: Vec<Range<u64>>,
}

impl RebuiltRange {
    /// How many bytes were rebuilt exactly.
    pub fn rebuilt_len(&self) -> u64 {
        self.len_where(|s| matches!(s, ByteState::Rebuilt(_)))
    }

    /// How many bytes are not needed (compressed data before a restart).
    pub fn unneeded_len(&self) -> u64 {
        self.len_where(|s| matches!(s, ByteState::Unneeded { .. }))
    }

    /// The bytes matching `pred`.
    pub fn len_where(&self, mut pred: impl FnMut(&ByteState) -> bool) -> u64 {
        self.regions.iter().filter(|r| pred(&r.state)).map(|r| r.range.end - r.range.start).sum()
    }

    /// Whether every byte was rebuilt.
    pub fn complete(&self) -> bool {
        self.regions.iter().all(|r| matches!(r.state, ByteState::Rebuilt(_)))
    }

    /// The regions not rebuilt.
    pub fn missing(&self) -> impl Iterator<Item = &Region> {
        self.regions.iter().filter(|r| matches!(r.state, ByteState::Missing(_)))
    }
}

/// Why [`ContainerRebuilder::rebuild`] refused a request.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RebuildError {
    /// No member with this index.
    NoMember(usize),
    /// The range is empty, reversed, or larger than [`RebuildOptions::max_range`].
    BadRange,
}

impl std::fmt::Display for RebuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoMember(i) => write!(f, "no member {i}"),
            Self::BadRange => f.write_str("the range is empty, reversed or too large"),
        }
    }
}

impl std::error::Error for RebuildError {}

/// How a data stream's packed bytes relate to output.
#[derive(Clone, Debug)]
enum Kind {
    Plain,
    Cbc { cipher: CipherParams, zero_pad: bool },
    Counter { skip: u64, cipher: CipherParams },
    Sequential,
    Compressed(Layer),
    Unmapped(&'static str),
}

/// One data stream: a RAR or ZIP member's packed bytes, or a 7z folder's.
#[derive(Clone, Debug)]
struct Stream {
    spans: Vec<PackedSpan>,
    kind: Kind,
    /// The output (plaintext) length of the stream: the member's size, or the folder's.
    plain_len: Option<u64>,
    /// `(member, start of its output in the stream's plaintext, size)`, in order.
    members: Vec<(usize, u64, u64)>,
    folder: Option<u32>,
}

impl Stream {
    fn member_at(&self, plain: u64) -> Option<(usize, u64)> {
        self.members.iter().find(|m| plain >= m.1 && plain < m.1 + m.2).map(|m| (m.0, plain - m.1)).or_else(|| {
            // a stream byte past every member (CBC padding) belongs to the last member
            self.members.last().map(|m| (m.0, plain.saturating_sub(m.1)))
        })
    }

    fn holds(&self, member: usize) -> bool {
        self.members.iter().any(|m| m.0 == member)
    }

    fn first_member(&self) -> Option<usize> {
        self.members.first().map(|m| m.0)
    }

    /// Where stream byte `s` lies.
    fn place(&self, s: u64) -> Option<(u32, u64)> {
        self.spans
            .iter()
            .find(|p| s >= p.stream.start && s < p.stream.end)
            .map(|p| (p.volume, p.packed.start + (s - p.stream.start)))
    }
}

#[derive(Clone)]
enum Keys {
    Cbc { key: Vec<u8>, iv: Option<[u8; 16]> },
    Counter { key: Vec<u8>, mac_key: Vec<u8> },
}

/// Rebuilds volume bytes of a mapped copy from held output. Keeps derived keys and CBC checkpoints between calls,
/// so rebuilding a set's articles in order costs one key derivation per salt and no re-encryption.
pub struct ContainerRebuilder<'m> {
    map: &'m MemberMap,
    password: Option<String>,
    streams: Vec<Stream>,
    keys: HashMap<Vec<u8>, Result<Keys, KeyProblem>>,
    /// Per stream: block index -> its ciphertext.
    chain: HashMap<usize, BTreeMap<u64, [u8; 16]>>,
    /// Per stream: the WinZip AES authentication code, once computed.
    auth: HashMap<usize, [u8; 10]>,
}

impl std::fmt::Debug for ContainerRebuilder<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContainerRebuilder").field("streams", &self.streams.len()).finish_non_exhaustive()
    }
}

/// A RAR final block waiting for a check.
struct PendingFinal {
    stream: usize,
    member: usize,
    key: Vec<u8>,
    previous: [u8; 16],
    partial: Vec<u8>,
    places: [Option<(u32, u64)>; 16],
    output: Range<u64>,
}

impl<'m> ContainerRebuilder<'m> {
    /// A rebuilder for `map`, with the password of its encrypted members (never stored in the map).
    pub fn new(map: &'m MemberMap, password: Option<&str>) -> Self {
        Self {
            map,
            password: password.filter(|p| !p.is_empty()).map(str::to_owned),
            streams: streams_of(map),
            keys: HashMap::new(),
            chain: HashMap::new(),
            auth: HashMap::new(),
        }
    }

    /// The members with data in volume `volume`, in archive order.
    pub fn members_on(&self, volume: u32) -> Vec<usize> {
        let mut out: Vec<usize> = self
            .streams
            .iter()
            .filter(|s| s.spans.iter().any(|p| p.volume == volume))
            .flat_map(|s| s.members.iter().map(|m| m.0))
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    /// Rebuilds bytes `range` of volume `volume` from `held`, and reports what each byte is.
    ///
    /// Member data is rebuilt where its layer allows and the output it carries is held; header bytes when
    /// [`RebuildOptions::headers`] gives what a RAR 5.0 rebuild needs; a RAR final block when a check decides its
    /// padding. Everything else is reported [`ByteState::Missing`] with the reason, or [`ByteState::Unneeded`].
    pub fn rebuild(
        &mut self,
        volume: u32,
        range: Range<u64>,
        held: &mut dyn HeldOutput,
        options: &mut RebuildOptions<'_>,
    ) -> Result<RebuiltRange, RebuildError> {
        if let Some(m) = options.member
            && m >= self.map.members.len()
        {
            return Err(RebuildError::NoMember(m));
        }
        let len = range.end.checked_sub(range.start).filter(|&n| n > 0).ok_or(RebuildError::BadRange)?;
        if len > options.max_range.unwrap_or(1 << 30) || usize::try_from(len).is_err() {
            return Err(RebuildError::BadRange);
        }
        let mut out = Out {
            volume,
            range: range.clone(),
            bytes: vec![0; len as usize],
            regions: vec![Region { range: range.clone(), member: None, output: None, state: HEADER_PLACEHOLDER }],
            conflicts: Vec::new(),
        };
        let mut pending = Vec::new();
        for sid in 0..self.streams.len() {
            let overlaps: Vec<PackedSpan> = self.streams[sid]
                .spans
                .iter()
                .filter(|p| p.volume == volume && p.packed.start < range.end && p.packed.end > range.start)
                .map(|p| {
                    let a = p.packed.start.max(range.start);
                    let b = p.packed.end.min(range.end);
                    let s = p.stream.start + (a - p.packed.start);
                    PackedSpan { volume, packed: a..b, stream: s..s + (b - a) }
                })
                .collect();
            for part in overlaps {
                self.stream_part(sid, &part, held, options, &mut out, &mut pending);
            }
        }
        self.headers(&mut out, options);
        for p in pending {
            // another member's final block (a shared 7z folder) is masked below: not worth a search
            if options.member.is_none_or(|m| m == p.member) {
                self.finish_final(p, &mut out, options);
            }
        }
        if let Some(m) = options.member {
            // a shared 7z folder holds the member and others: their plaintext chains the CBC stream, but their
            // bytes are not this call's
            out.mask_other_members(m);
        }
        out.compare_known(&options.known);
        Ok(RebuiltRange { volume, range, bytes: out.bytes, regions: out.regions, conflicts: out.conflicts })
    }

    fn stream_part(
        &mut self,
        sid: usize,
        part: &PackedSpan,
        held: &mut dyn HeldOutput,
        options: &RebuildOptions<'_>,
        out: &mut Out,
        pending: &mut Vec<PendingFinal>,
    ) {
        let stream = &self.streams[sid];
        let first = stream.first_member();
        if let Some(m) = options.member
            && !stream.holds(m)
        {
            out.set(part.packed.clone(), first, None, ByteState::Missing(Missing::OtherMember));
            return;
        }
        match stream.kind.clone() {
            Kind::Plain => self.plain(sid, part, held, out),
            Kind::Cbc { cipher, zero_pad } => self.cbc(sid, part, &cipher, zero_pad, held, options, out, pending),
            Kind::Counter { skip, cipher } => self.counter(sid, part, skip, &cipher, held, out),
            Kind::Sequential => out.set(part.packed.clone(), first, None, ByteState::Missing(Missing::Sequential)),
            Kind::Unmapped(why) => {
                out.set(part.packed.clone(), first, None, ByteState::Missing(Missing::Unmapped(why)))
            }
            Kind::Compressed(layer) => {
                let stream = &self.streams[sid];
                // several plans on one stream (members of one 7z folder): the earliest restart decides what is unneeded
                let plan = options
                    .plans
                    .iter()
                    .filter(|p| match p.start {
                        Start::Lzma2 { folder, .. } => stream.folder == Some(folder),
                        _ => stream.folder.is_none() && stream.holds(p.member),
                    })
                    .min_by_key(|p| p.fetch_from);
                let compressed = ByteState::Missing(Missing::Compressed(layer));
                match plan {
                    Some(plan) if part.stream.start < plan.fetch_from => {
                        let chunk_headers =
                            matches!(plan.start, Start::Lzma2 { framing: Lzma2Framing::HeaderWalk, .. });
                        let cut = part.packed.start + (plan.fetch_from.min(part.stream.end) - part.stream.start);
                        out.set(part.packed.start..cut, first, None, ByteState::Unneeded { chunk_headers });
                        if cut < part.packed.end {
                            out.set(cut..part.packed.end, first, None, compressed);
                        }
                    }
                    _ => out.set(part.packed.clone(), first, None, compressed),
                }
            }
        }
    }

    /// Reads stream plaintext `range` from `held`, across the stream's members. Returns the bytes and the held
    /// sub-ranges (stream plaintext offsets).
    fn read_plain(&self, sid: usize, range: Range<u64>, held: &mut dyn HeldOutput) -> (Vec<u8>, Vec<Range<u64>>) {
        let stream = &self.streams[sid];
        let mut buf = vec![0u8; (range.end - range.start) as usize];
        let mut good = Vec::new();
        for &(member, start, size) in &stream.members {
            let a = range.start.max(start);
            let b = range.end.min(start + size);
            if a >= b {
                continue;
            }
            let slice = &mut buf[(a - range.start) as usize..(b - range.start) as usize];
            for g in held.read_held(member, a - start, slice) {
                let (ga, gb) = (g.start.max(a - start) + start, g.end.min(b - start) + start);
                if ga < gb {
                    good.push(ga..gb);
                }
            }
        }
        good.sort_by_key(|g| g.start);
        (buf, merge(good))
    }

    fn plain(&mut self, sid: usize, part: &PackedSpan, held: &mut dyn HeldOutput, out: &mut Out) {
        let stream = &self.streams[sid];
        let to_vol = |s: u64| part.packed.start + (s - part.stream.start);
        // stored data: stream offset = output offset (in the stream's plaintext)
        let mut at = part.stream.start;
        while at < part.stream.end {
            let end = (at + READ_CHUNK as u64).min(part.stream.end);
            let (buf, good) = self.read_plain(sid, at..end, held);
            let mut cursor = at;
            for g in good.iter().chain(std::iter::once(&(end..end))) {
                if cursor < g.start {
                    out.set_mapped(
                        stream,
                        to_vol(cursor)..to_vol(g.start),
                        cursor,
                        ByteState::Missing(Missing::NotHeld),
                    );
                }
                if g.start < g.end {
                    let v = to_vol(g.start);
                    out.write(v, &buf[(g.start - at) as usize..(g.end - at) as usize]);
                    out.set_mapped(stream, v..to_vol(g.end), g.start, ByteState::Rebuilt(Rebuilt::Plain));
                }
                cursor = cursor.max(g.end);
            }
            at = end;
        }
    }

    fn key(&mut self, cipher: &CipherParams) -> Result<Keys, KeyProblem> {
        let id = cipher_id(cipher);
        if let Some(k) = self.keys.get(&id) {
            return k.clone();
        }
        let derived = derive(cipher, self.password.as_deref());
        self.keys.insert(id, derived.clone());
        derived
    }

    #[allow(clippy::too_many_arguments)]
    fn cbc(
        &mut self,
        sid: usize,
        part: &PackedSpan,
        cipher: &CipherParams,
        zero_pad: bool,
        held: &mut dyn HeldOutput,
        options: &RebuildOptions<'_>,
        out: &mut Out,
        pending: &mut Vec<PendingFinal>,
    ) {
        let stream = self.streams[sid].clone();
        let first = stream.first_member();
        let Some(n) = stream.plain_len else {
            out.set(part.packed.clone(), first, None, ByteState::Missing(Missing::Unmapped("unknown size")));
            return;
        };
        let (key, iv) = match self.key(cipher) {
            Ok(Keys::Cbc { key, iv }) => match iv.or_else(|| stored_iv(cipher)) {
                Some(iv) => (key, iv),
                None => {
                    out.set(part.packed.clone(), first, None, ByteState::Missing(Missing::Unmapped("no data IV")));
                    return;
                }
            },
            Ok(_) => {
                out.set(part.packed.clone(), first, None, ByteState::Missing(Missing::Key(KeyProblem::Derivation)));
                return;
            }
            Err(problem) => {
                out.set(part.packed.clone(), first, None, ByteState::Missing(Missing::Key(problem)));
                return;
            }
        };
        let Some(aes) = AesKey::new(&key) else {
            out.set(part.packed.clone(), first, None, ByteState::Missing(Missing::Key(KeyProblem::Derivation)));
            return;
        };
        let to_vol = |s: u64| part.packed.start + (s - part.stream.start);
        let kb0 = part.stream.start / 16;
        let kb1 = part.stream.end.div_ceil(16);
        let full_blocks = n / 16; // blocks wholly inside the plaintext
        let last_partial = n % 16 != 0;

        // The known ciphertext of block `b`, from the caller's volume bytes.
        let known_block = |b: u64| -> Option<[u8; 16]> {
            let mut blk = [0u8; 16];
            for (i, slot) in blk.iter_mut().enumerate() {
                let (v, off) = stream.place(b * 16 + i as u64)?;
                *slot = known_byte(&options.known, v, off)?;
            }
            Some(blk)
        };

        // The starting checkpoint: the IV, a cached block, or a known block before kb0.
        let mut start: (i64, Option<[u8; 16]>) = (-1, Some(iv));
        if kb0 > 0 {
            if let Some((&c, &ct)) = self.chain.get(&sid).and_then(|m| m.range(..kb0).next_back()) {
                start = (c as i64, Some(ct));
            }
            if let Some((c, ct)) = latest_known_block(&stream, &options.known, kb0)
                && c as i64 > start.0
            {
                start = (c as i64, Some(ct));
            }
            let distance = (kb0 as i64 - 1 - start.0) as u64 * 16;
            if options.max_chain.is_some_and(|max| distance > max) {
                start = (kb0 as i64 - 1, None);
            }
        }
        let mut prev = start.1;
        let first_block = (start.0 + 1) as u64;

        // Walk blocks first_block..kb1, reading plaintext in chunks.
        let mut b = first_block;
        let mut last_computed: Option<(u64, [u8; 16])> = None;
        // consecutive blocks with one state are set as one region
        let mut run: Option<Run> = None;
        while b < kb1 {
            let chunk_end = (b + (READ_CHUNK as u64 / 16)).min(kb1);
            let p0 = b * 16;
            let p1 = (chunk_end * 16).min(n).max(p0);
            let (buf, good) = if p0 < p1 { self.read_plain(sid, p0..p1, held) } else { (Vec::new(), Vec::new()) };
            let held_all = |a: u64, z: u64| good.iter().any(|g| g.start <= a && g.end >= z);
            for blk_index in b..chunk_end {
                let bs = blk_index * 16;
                let emit = blk_index >= kb0;
                let out_range = bs.max(part.stream.start)..(bs + 16).min(part.stream.end);
                let in_range = emit && out_range.start < out_range.end;
                if blk_index < full_blocks || (blk_index == full_blocks && last_partial) {
                    let pend = (bs + 16).min(n);
                    let have = held_all(bs, pend);
                    let is_final = pend < bs + 16;
                    if is_final {
                        flush_run(&mut run, out, &stream);
                    }
                    if is_final && !zero_pad {
                        // RAR: random padding, decided later by a check
                        if let (Some(p), true, true) = (prev, have, in_range) {
                            let mut places = [None; 16];
                            for (i, slot) in places.iter_mut().enumerate() {
                                *slot = stream.place(bs + i as u64);
                            }
                            pending.push(PendingFinal {
                                stream: sid,
                                member: stream.member_at(bs).map_or(0, |m| m.0),
                                key: key.clone(),
                                previous: p,
                                partial: buf[(bs - p0) as usize..(pend - p0) as usize].to_vec(),
                                places,
                                output: bs..pend,
                            });
                        }
                        if in_range {
                            let state = if !have {
                                Missing::NotHeld
                            } else if prev.is_none() {
                                Missing::Chain
                            } else {
                                Missing::FinalPadding { pad: (bs + 16 - pend) as u8, searched: false }
                            };
                            out.set_mapped(
                                &stream,
                                to_vol(out_range.start)..to_vol(out_range.end),
                                out_range.start.min(n),
                                ByteState::Missing(state),
                            );
                            clip_output(out, to_vol(out_range.start)..to_vol(out_range.end), n, &stream);
                        }
                        prev = None;
                        continue;
                    }
                    let computed = match (prev, have) {
                        (Some(p), true) => {
                            let mut x = [0u8; 16];
                            x[..(pend - bs) as usize].copy_from_slice(&buf[(bs - p0) as usize..(pend - p0) as usize]);
                            for (xb, pb) in x.iter_mut().zip(p) {
                                *xb ^= pb;
                            }
                            Some(aes.encrypt_block(&x))
                        }
                        _ => None,
                    };
                    if in_range {
                        let v = to_vol(out_range.start)..to_vol(out_range.end);
                        match computed {
                            Some(ct) => {
                                out.write(v.start, &ct[(out_range.start - bs) as usize..(out_range.end - bs) as usize]);
                                let how = if is_final {
                                    Rebuilt::CbcFinal { pad: (bs + 16 - pend) as u8, searched: false }
                                } else {
                                    Rebuilt::Cbc
                                };
                                push_run(&mut run, out, &stream, v.clone(), out_range.start, ByteState::Rebuilt(how));
                            }
                            None => {
                                let why = if have { Missing::Chain } else { Missing::NotHeld };
                                push_run(&mut run, out, &stream, v.clone(), out_range.start, ByteState::Missing(why));
                            }
                        }
                        if is_final {
                            flush_run(&mut run, out, &stream);
                            clip_output(out, v, n, &stream);
                        }
                    }
                    if let Some(ct) = computed {
                        last_computed = Some((blk_index, ct));
                        if blk_index % CHECKPOINT_EVERY == CHECKPOINT_EVERY - 1 {
                            self.chain.entry(sid).or_default().insert(blk_index, ct);
                        }
                    }
                    prev = computed.or_else(|| known_block(blk_index));
                } else {
                    // a block wholly past the plaintext: padding rar may add
                    flush_run(&mut run, out, &stream);
                    if in_range {
                        out.set(
                            to_vol(out_range.start)..to_vol(out_range.end),
                            stream.member_at(bs).map(|m| m.0),
                            None,
                            ByteState::Missing(Missing::Padding),
                        );
                    }
                    prev = known_block(blk_index);
                }
            }
            b = chunk_end;
        }
        flush_run(&mut run, out, &stream);
        if let Some((blk, ct)) = last_computed {
            self.chain.entry(sid).or_default().insert(blk, ct);
        }
    }

    fn counter(
        &mut self,
        sid: usize,
        part: &PackedSpan,
        skip: u64,
        cipher: &CipherParams,
        held: &mut dyn HeldOutput,
        out: &mut Out,
    ) {
        let stream = self.streams[sid].clone();
        let first = stream.first_member();
        let to_vol = |s: u64| part.packed.start + (s - part.stream.start);
        let Some(n) = stream.plain_len else {
            out.set(part.packed.clone(), first, None, ByteState::Missing(Missing::Unmapped("unknown size")));
            return;
        };
        let CipherParams::WinZipAes { salt, verifier, .. } = cipher else {
            out.set(part.packed.clone(), first, None, ByteState::Missing(Missing::Unmapped("cipher")));
            return;
        };
        // salt and verifier
        let mut prefix = salt.clone();
        prefix.extend_from_slice(verifier);
        let s = &part.stream;
        if s.start < skip {
            let e = s.end.min(skip);
            if prefix.len() as u64 == skip {
                out.write(to_vol(s.start), &prefix[s.start as usize..e as usize]);
                out.set(to_vol(s.start)..to_vol(e), first, None, ByteState::Rebuilt(Rebuilt::CounterPrefix));
            } else {
                out.set(to_vol(s.start)..to_vol(e), first, None, ByteState::Missing(Missing::Unmapped("salt length")));
            }
        }
        let keys = self.key(cipher);
        let data = s.start.max(skip)..s.end.min(skip + n);
        if data.start < data.end {
            match &keys {
                Ok(Keys::Counter { key, .. }) => {
                    let aes = AesKey::new(key).expect("derived key length");
                    let mut at = data.start - skip;
                    let end = data.end - skip;
                    while at < end {
                        let chunk_end = (at + READ_CHUNK as u64).min(end);
                        let (mut buf, good) = self.read_plain(sid, at..chunk_end, held);
                        ctr_xor(&aes, at, &mut buf);
                        let mut cursor = at;
                        for g in good.iter().chain(std::iter::once(&(chunk_end..chunk_end))) {
                            if cursor < g.start {
                                let v = to_vol(cursor + skip)..to_vol(g.start + skip);
                                out.set(v, first, Some(cursor..g.start), ByteState::Missing(Missing::NotHeld));
                            }
                            if g.start < g.end {
                                let v = to_vol(g.start + skip);
                                out.write(v, &buf[(g.start - at) as usize..(g.end - at) as usize]);
                                out.set(
                                    v..to_vol(g.end + skip),
                                    first,
                                    Some(g.clone()),
                                    ByteState::Rebuilt(Rebuilt::Counter),
                                );
                            }
                            cursor = cursor.max(g.end);
                        }
                        at = chunk_end;
                    }
                }
                Ok(_) => out.set(
                    to_vol(data.start)..to_vol(data.end),
                    first,
                    None,
                    ByteState::Missing(Missing::Key(KeyProblem::Derivation)),
                ),
                Err(p) => {
                    out.set(to_vol(data.start)..to_vol(data.end), first, None, ByteState::Missing(Missing::Key(*p)))
                }
            }
        }
        let auth = s.start.max(skip + n)..s.end.min(skip + n + AUTH_LEN);
        if auth.start < auth.end {
            let v = to_vol(auth.start)..to_vol(auth.end);
            let tag = match &keys {
                Ok(Keys::Counter { key, mac_key }) => self.auth_code(sid, key, mac_key, n, held),
                _ => None,
            };
            match tag {
                Some(tag) => {
                    let o = (auth.start - skip - n) as usize;
                    out.write(v.start, &tag[o..o + (auth.end - auth.start) as usize]);
                    out.set(v, first, None, ByteState::Rebuilt(Rebuilt::CounterAuth));
                }
                None => {
                    let why = match &keys {
                        Err(p) => Missing::Key(*p),
                        _ => Missing::AuthCode,
                    };
                    out.set(v, first, None, ByteState::Missing(why));
                }
            }
        }
        let rest = s.start.max(skip + n + AUTH_LEN)..s.end;
        if rest.start < rest.end {
            out.set(
                to_vol(rest.start)..to_vol(rest.end),
                first,
                None,
                ByteState::Missing(Missing::Unmapped("past the data")),
            );
        }
    }

    /// The WinZip AES authentication code: HMAC-SHA1 over all the ciphertext, when the whole output is held.
    fn auth_code(
        &mut self,
        sid: usize,
        key: &[u8],
        mac_key: &[u8],
        n: u64,
        held: &mut dyn HeldOutput,
    ) -> Option<[u8; 10]> {
        if let Some(tag) = self.auth.get(&sid) {
            return Some(*tag);
        }
        let aes = AesKey::new(key)?;
        let mut mac = HmacSha1::new(mac_key);
        let mut at = 0;
        while at < n {
            let end = (at + READ_CHUNK as u64).min(n);
            let (mut buf, good) = self.read_plain(sid, at..end, held);
            if !(good.len() == 1 && good[0] == (at..end)) {
                return None;
            }
            ctr_xor(&aes, at, &mut buf);
            mac.update(&buf)?;
            at = end;
        }
        let tag: [u8; 10] = mac.finish()[..10].try_into().ok()?;
        self.auth.insert(sid, tag);
        Some(tag)
    }

    /// Fills the header regions: RAR 5.0 head and tail rebuilds where asked, a reason everywhere else.
    fn headers(&self, out: &mut Out, options: &RebuildOptions<'_>) {
        let gap = |why: HeaderGap| ByteState::Missing(Missing::Header(why));
        let base = if self.map.format != MapFormat::Rar5 {
            HeaderGap::NotRar5
        } else if self.map.header_encrypted {
            HeaderGap::Encrypted
        } else if options.headers.is_none() {
            HeaderGap::NoSource
        } else {
            HeaderGap::NotCovered
        };
        out.replace_placeholder(gap(base.clone()));
        let Some(h) = options.headers.filter(|_| base == HeaderGap::NotCovered) else { return };
        let mut refusals = Vec::new();
        // the start, and every cached file header, from the tail
        if let Some(tail) = h.tail {
            let head_options = HeadOptions { volume: Some(u64::from(out.volume)), sibling: h.sibling };
            match rebuild_volume_head(tail, h.volume_len, &head_options) {
                Ok(head) => {
                    let state = if head.exact {
                        ByteState::Rebuilt(Rebuilt::Header(HeaderSource::Head))
                    } else {
                        let doubt = head.doubt.unwrap_or(HeadDoubt::ArchiveFlagsInferred);
                        gap(HeaderGap::Doubtful(HeaderDoubt::Head(doubt)))
                    };
                    out.fill_headers(0, &head.bytes, &state);
                    let cached = ByteState::Rebuilt(Rebuilt::Header(HeaderSource::Cached));
                    for c in &head.headers {
                        out.fill_headers(c.offset, &c.bytes, &cached);
                    }
                }
                Err(e) => refusals.push(format!("start: {e}")),
            }
        }
        // the tail, from the start
        if let Some(head) = h.head {
            match rebuild_volume_tail_with(head, h.volume_len, h.more_volumes, h.quick_open) {
                Ok(tail) => {
                    let state = if tail.exact {
                        ByteState::Rebuilt(Rebuilt::Header(HeaderSource::Tail))
                    } else {
                        let doubt = tail.doubt.unwrap_or(TailDoubt::UnexpectedPadding);
                        gap(HeaderGap::Doubtful(HeaderDoubt::Tail(doubt)))
                    };
                    out.fill_headers(tail.offset, &tail.bytes, &state);
                    let pad_from = tail.offset.saturating_add(tail.bytes.len() as u64);
                    out.fill_zero_headers(pad_from..h.volume_len, &state);
                }
                Err(e) => refusals.push(format!("tail: {e}")),
            }
        }
        let rest = if !refusals.is_empty() {
            HeaderGap::Refused(refusals.join("; "))
        } else if h.head.is_none() || h.tail.is_none() {
            HeaderGap::NoSource
        } else {
            HeaderGap::NotCovered
        };
        out.replace_state(&gap(HeaderGap::NotCovered), gap(rest));
    }

    /// Decides a RAR final block's padding with a check, or leaves it missing.
    fn finish_final(&mut self, p: PendingFinal, out: &mut Out, options: &mut RebuildOptions<'_>) {
        let pad = 16 - p.partial.len();
        if pad > 3 {
            return;
        }
        // positions of the block inside the output range, and known bytes of the block
        let known: Vec<(usize, u8)> = (0..16)
            .filter_map(|i| p.places[i].and_then(|(v, o)| known_byte(&options.known, v, o)).map(|b| (i, b)))
            .collect();
        let filter = |blk: &[u8; 16]| known.iter().all(|&(i, b)| blk[i] == b);
        // every check that can judge the block, together: a check may see only a byte or two of it (an article
        // boundary inside the block), so one check alone can pass several paddings
        let checks: Vec<(CrcAffine, u32)> = options
            .checks
            .iter()
            .filter_map(|c| CrcAffine::new(c, &p, out, &options.known).map(|a| (a, c.crc32)))
            .collect();
        let mut accept = options.accept.as_deref_mut();
        let searched = !checks.is_empty() || accept.is_some();
        // every padding is tried; the bytes rebuilt are those all passing candidates agree on
        let mut first: Option<[u8; 16]> = None;
        let mut agree = [true; 16];
        let mut passing = 0u32;
        if searched && let Some(aes) = AesKey::new(&p.key) {
            let rem = p.partial.len();
            for v in 0..1u32 << (8 * pad) {
                let mut x = [0u8; 16];
                x[..rem].copy_from_slice(&p.partial);
                for (i, b) in x[rem..].iter_mut().enumerate() {
                    *b = (v >> (8 * (pad - 1 - i))) as u8;
                }
                for (xb, pb) in x.iter_mut().zip(p.previous) {
                    *xb ^= pb;
                }
                let blk = aes.encrypt_block(&x);
                if !filter(&blk) || !checks.iter().all(|(a, crc)| a.crc(&blk) == *crc) {
                    continue;
                }
                if let Some(accept) = accept.as_deref_mut()
                    && !accept(&FinalBlock { member: p.member, block: blk, places: p.places, pad: pad as u8 })
                {
                    continue;
                }
                passing = passing.saturating_add(1);
                match first {
                    None => first = Some(blk),
                    Some(f) => {
                        for i in 0..16 {
                            agree[i] &= f[i] == blk[i];
                        }
                    }
                }
            }
        }
        let found = first.filter(|_| passing == 1);
        let stream = &self.streams[p.stream];
        for i in 0..16 {
            let Some((v, o)) = p.places[i] else { continue };
            if v != out.volume || !out.range.contains(&o) {
                continue;
            }
            let s = p.output.start + i as u64;
            let output = (s < p.output.end).then(|| {
                let (_, mo) = stream.member_at(s).unwrap_or((p.member, s));
                mo..mo + 1
            });
            let state = match first {
                Some(blk) if passing == 1 || agree[i] => {
                    out.write(o, &blk[i..i + 1]);
                    ByteState::Rebuilt(Rebuilt::CbcFinal { pad: pad as u8, searched: true })
                }
                Some(_) => ByteState::Missing(Missing::FinalPaddingAmbiguous { pad: pad as u8, candidates: passing }),
                None => ByteState::Missing(Missing::FinalPadding { pad: pad as u8, searched }),
            };
            out.set(o..o + 1, Some(p.member), output, state);
        }
        if let Some(blk) = found {
            let b = p.output.start / 16;
            self.chain.entry(p.stream).or_default().insert(b, blk);
        }
    }
}

/// A run of consecutive CBC blocks with one state: volume range, stream plaintext offset at its start, state.
type Run = (Range<u64>, u64, ByteState);

fn push_run(run: &mut Option<Run>, out: &mut Out, stream: &Stream, v: Range<u64>, plain: u64, state: ByteState) {
    if let Some((rv, rp, rs)) = run.as_mut()
        && rv.end == v.start
        && *rp + (rv.end - rv.start) == plain
        && *rs == state
    {
        rv.end = v.end;
        return;
    }
    flush_run(run, out, stream);
    *run = Some((v, plain, state));
}

fn flush_run(run: &mut Option<Run>, out: &mut Out, stream: &Stream) {
    if let Some((v, plain, state)) = run.take() {
        out.set_mapped(stream, v, plain, state);
    }
}

/// Encrypts plaintext `buf` at output offset `at` with the WinZip AES counter keystream (counter `block + 1`,
/// little-endian).
fn ctr_xor(aes: &AesKey, at: u64, buf: &mut [u8]) {
    let mut pos = at;
    let mut i = 0;
    while i < buf.len() {
        let block = pos / 16;
        let within = (pos % 16) as usize;
        let counter = (u128::from(block) + 1).to_le_bytes();
        let ks = aes.encrypt_block(&counter);
        let take = (16 - within).min(buf.len() - i);
        for k in 0..take {
            buf[i + k] ^= ks[within + k];
        }
        i += take;
        pos += take as u64;
    }
}

/// Region bookkeeping for one call.
struct Out {
    volume: u32,
    range: Range<u64>,
    bytes: Vec<u8>,
    regions: Vec<Region>,
    conflicts: Vec<Range<u64>>,
}

/// Marks the bytes no data stream covers until [`ContainerRebuilder::headers`] says what they are.
const HEADER_PLACEHOLDER: ByteState = ByteState::Missing(Missing::Header(HeaderGap::NotRar5));

impl Out {
    fn write(&mut self, at: u64, bytes: &[u8]) {
        let a = at.max(self.range.start);
        let b = (at + bytes.len() as u64).min(self.range.end);
        if a < b {
            self.bytes[(a - self.range.start) as usize..(b - self.range.start) as usize]
                .copy_from_slice(&bytes[(a - at) as usize..(b - at) as usize]);
        }
    }

    /// Sets the state of volume range `range` (clipped to the call's range), splitting regions.
    fn set(&mut self, range: Range<u64>, member: Option<usize>, output: Option<Range<u64>>, state: ByteState) {
        let a = range.start.max(self.range.start);
        let b = range.end.min(self.range.end);
        if a >= b {
            return;
        }
        let output = output.map(|o| {
            let shift = a - range.start;
            let start = o.start + shift;
            start..start + (b - a).min(o.end.saturating_sub(start))
        });
        let mut next = Vec::with_capacity(self.regions.len() + 2);
        let mut placed = false;
        for r in self.regions.drain(..) {
            if r.range.end <= a || r.range.start >= b {
                if r.range.start >= b && !placed {
                    next.push(Region { range: a..b, member, output: output.clone(), state: state.clone() });
                    placed = true;
                }
                next.push(r);
                continue;
            }
            if r.range.start < a {
                next.push(Region { range: r.range.start..a, output: cut_output(&r, r.range.start..a), ..r.clone() });
            }
            if !placed {
                next.push(Region { range: a..b, member, output: output.clone(), state: state.clone() });
                placed = true;
            }
            if r.range.end > b {
                next.push(Region { range: b..r.range.end, output: cut_output(&r, b..r.range.end), ..r.clone() });
            }
        }
        if !placed {
            next.push(Region { range: a..b, member, output, state });
        }
        self.regions = coalesce(next);
    }

    /// [`Self::set`] for stream bytes whose output follows the stream: stream plaintext offset `plain` at `range.start`.
    fn set_mapped(&mut self, stream: &Stream, range: Range<u64>, plain: u64, state: ByteState) {
        // split at member boundaries within the stream's plaintext
        let mut v = range.start;
        let mut s = plain;
        while v < range.end {
            let (member, mo) = match stream.member_at(s) {
                Some(m) => m,
                None => {
                    self.set(v..range.end, None, None, state);
                    return;
                }
            };
            let m_end = stream.members.iter().find(|m| m.0 == member).map_or(u64::MAX, |m| m.1 + m.2);
            let n = if s < m_end { (m_end - s).min(range.end - v) } else { range.end - v };
            self.set(v..v + n, Some(member), Some(mo..mo + n), state.clone());
            v += n;
            s += n;
        }
    }

    /// Reports every byte of a member other than `member` as [`Missing::OtherMember`], zeroing it.
    fn mask_other_members(&mut self, member: usize) {
        let others: Vec<(Range<u64>, Option<usize>)> = self
            .regions
            .iter()
            .filter(|r| r.member.is_some_and(|x| x != member))
            .filter(|r| r.state != ByteState::Missing(Missing::OtherMember))
            .map(|r| (r.range.clone(), r.member))
            .collect();
        for (range, owner) in others {
            let len = (range.end - range.start) as usize;
            self.write(range.start, &vec![0; len]);
            self.set(range, owner, None, ByteState::Missing(Missing::OtherMember));
        }
    }

    fn replace_placeholder(&mut self, state: ByteState) {
        self.replace_state(&HEADER_PLACEHOLDER, state);
    }

    fn replace_state(&mut self, from: &ByteState, to: ByteState) {
        for r in &mut self.regions {
            if r.state == *from && r.member.is_none() {
                r.state = to.clone();
            }
        }
        self.regions = coalesce(std::mem::take(&mut self.regions));
    }

    /// The header gaps (bytes no data stream covers) within `at..at + bytes.len()`.
    fn header_gaps(&self, range: Range<u64>) -> Vec<Range<u64>> {
        self.regions
            .iter()
            .filter(|r| r.member.is_none() && matches!(r.state, ByteState::Missing(Missing::Header(_))))
            .filter_map(|r| {
                let (a, b) = (r.range.start.max(range.start), r.range.end.min(range.end));
                (a < b).then_some(a..b)
            })
            .collect()
    }

    fn fill_headers(&mut self, at: u64, bytes: &[u8], state: &ByteState) {
        for g in self.header_gaps(at..at + bytes.len() as u64) {
            self.write(g.start, &bytes[(g.start - at) as usize..(g.end - at) as usize]);
            self.set(g, None, None, state.clone());
        }
    }

    fn fill_zero_headers(&mut self, range: Range<u64>, state: &ByteState) {
        for g in self.header_gaps(range) {
            let len = (g.end - g.start) as usize;
            self.write(g.start, &vec![0; len]);
            self.set(g, None, None, state.clone());
        }
    }

    /// The volume byte at `o` when this call rebuilt it exactly.
    fn rebuilt_byte(&self, o: u64) -> Option<u8> {
        if !self.range.contains(&o) {
            return None;
        }
        let i = self.regions.partition_point(|r| r.range.end <= o);
        let r = self.regions.get(i)?;
        matches!(r.state, ByteState::Rebuilt(_)).then(|| self.bytes[(o - self.range.start) as usize])
    }

    fn compare_known(&mut self, known: &[KnownBytes<'_>]) {
        for k in known.iter().filter(|k| k.volume == self.volume) {
            let a = k.offset.max(self.range.start);
            let b = (k.offset + k.bytes.len() as u64).min(self.range.end);
            let mut run: Option<Range<u64>> = None;
            for o in a..b {
                let differs = self.rebuilt_byte(o).is_some_and(|x| x != k.bytes[(o - k.offset) as usize]);
                match (&mut run, differs) {
                    (Some(r), true) if r.end == o => r.end = o + 1,
                    (_, true) => {
                        if let Some(r) = run.take() {
                            self.conflicts.push(r);
                        }
                        run = Some(o..o + 1);
                    }
                    _ => {}
                }
            }
            if let Some(r) = run {
                self.conflicts.push(r);
            }
        }
    }
}

fn cut_output(r: &Region, part: Range<u64>) -> Option<Range<u64>> {
    r.output.as_ref().map(|o| {
        let start = o.start + (part.start - r.range.start);
        start..(start + (part.end - part.start)).min(o.end)
    })
}

fn coalesce(regions: Vec<Region>) -> Vec<Region> {
    let mut out: Vec<Region> = Vec::with_capacity(regions.len());
    for r in regions {
        if let Some(last) = out.last_mut()
            && last.range.end == r.range.start
            && last.member == r.member
            && last.state == r.state
        {
            let joined = match (&last.output, &r.output) {
                (None, None) => Some(None),
                (Some(a), Some(b)) if a.end == b.start => Some(Some(a.start..b.end)),
                _ => None,
            };
            if let Some(output) = joined {
                last.range.end = r.range.end;
                last.output = output;
                continue;
            }
        }
        out.push(r);
    }
    out
}

fn merge(sorted: Vec<Range<u64>>) -> Vec<Range<u64>> {
    let mut out: Vec<Range<u64>> = Vec::with_capacity(sorted.len());
    for r in sorted {
        match out.last_mut() {
            Some(last) if last.end >= r.start => last.end = last.end.max(r.end),
            _ => out.push(r),
        }
    }
    out
}

/// The final CBC block's output bytes stop at the plaintext's end: the padding carries no output.
fn clip_output(out: &mut Out, v: Range<u64>, n: u64, stream: &Stream) {
    let regions: Vec<Region> =
        out.regions.iter().filter(|r| r.range.start < v.end && r.range.end > v.start).cloned().collect();
    for r in regions {
        // each region's output stops at its own member's end: only the last member's region reaches the padding
        let member_end = r.member.and_then(|id| stream.members.iter().find(|m| m.0 == id)).map_or(n, |m| m.2);
        if let Some(o) = &r.output
            && o.end > member_end
        {
            let keep = member_end.saturating_sub(o.start);
            let split = r.range.start + keep;
            if keep > 0 {
                out.set(r.range.start..split, r.member, Some(o.start..member_end), r.state.clone());
            }
            out.set(split..r.range.end, r.member, None, r.state.clone());
        }
    }
}

fn known_byte(known: &[KnownBytes<'_>], volume: u32, offset: u64) -> Option<u8> {
    known.iter().find_map(|k| {
        (k.volume == volume && offset >= k.offset && offset < k.offset + k.bytes.len() as u64)
            .then(|| k.bytes[(offset - k.offset) as usize])
    })
}

/// The last block before `before` whose 16 bytes all lie in one known slice.
fn latest_known_block(stream: &Stream, known: &[KnownBytes<'_>], before: u64) -> Option<(u64, [u8; 16])> {
    let mut best: Option<(u64, [u8; 16])> = None;
    for k in known {
        for span in stream.spans.iter().filter(|p| p.volume == k.volume) {
            let a = span.packed.start.max(k.offset);
            let b = span.packed.end.min(k.offset + k.bytes.len() as u64);
            if a >= b {
                continue;
            }
            let s0 = span.stream.start + (a - span.packed.start);
            let s1 = span.stream.start + (b - span.packed.start);
            // last whole block inside s0..s1 and before `before`
            let last_end = (s1 / 16).min(before);
            if last_end == 0 || last_end * 16 < s0 + 16 {
                continue;
            }
            let blk = last_end - 1;
            if blk * 16 < s0 || best.is_some_and(|(c, _)| c >= blk) {
                continue;
            }
            let at = (span.packed.start + (blk * 16 - span.stream.start) - k.offset) as usize;
            best = Some((blk, k.bytes[at..at + 16].try_into().expect("16 bytes")));
        }
    }
    best
}

/// What a key depends on: RAR 5.0 and 7z members of one archive share a salt but not an IV.
fn cipher_id(cipher: &CipherParams) -> Vec<u8> {
    let text = match cipher {
        CipherParams::Rar5 { kdf_count, salt, check, .. } => format!("rar5 {kdf_count} {salt:?} {check:?}"),
        CipherParams::SevenZipAes { num_cycles_power, salt, .. } => format!("7z {num_cycles_power} {salt:?}"),
        other => format!("{other:?}"),
    };
    text.into_bytes()
}

/// The data IV a cipher's parameters store (RAR 5.0, 7zAES).
fn stored_iv(cipher: &CipherParams) -> Option<[u8; 16]> {
    match cipher {
        CipherParams::Rar5 { iv, .. } => *iv,
        CipherParams::SevenZipAes { iv, .. } => Some(*iv),
        _ => None,
    }
}

fn derive(cipher: &CipherParams, password: Option<&str>) -> Result<Keys, KeyProblem> {
    let password = password.ok_or(KeyProblem::NoPassword)?;
    match cipher {
        CipherParams::Rar5 { kdf_count, salt, iv: Some(_), check, .. } => {
            match derive_rar5_key(password, *kdf_count, salt, *check) {
                Some(key) => Ok(Keys::Cbc { key: key.to_vec(), iv: None }),
                None if check.is_some() && derive_rar5_key(password, *kdf_count, salt, None).is_some() => {
                    Err(KeyProblem::WrongPassword)
                }
                None => Err(KeyProblem::Derivation),
            }
        }
        CipherParams::Rar4 { salt } => {
            let (key, iv) = derive_rar4_key_iv(password, salt);
            Ok(Keys::Cbc { key: key.to_vec(), iv: Some(iv) })
        }
        CipherParams::SevenZipAes { num_cycles_power, salt, .. } => derive_7z_key(password, salt, *num_cycles_power)
            .map(|key| Keys::Cbc { key: key.to_vec(), iv: None })
            .ok_or(KeyProblem::Derivation),
        CipherParams::WinZipAes { strength, salt, verifier, .. } => {
            if !(1..=3).contains(strength) {
                return Err(KeyProblem::Derivation);
            }
            let key_len = (usize::from(*strength) + 1) * 8;
            let derived = aes_derive(password.as_bytes(), salt, key_len).ok_or(KeyProblem::Derivation)?;
            if derived[2 * key_len..2 * key_len + 2] != verifier[..] {
                return Err(KeyProblem::WrongPassword);
            }
            Ok(Keys::Counter { key: derived[..key_len].to_vec(), mac_key: derived[key_len..2 * key_len].to_vec() })
        }
        _ => Err(KeyProblem::Derivation),
    }
}

/// The data streams of a map.
fn streams_of(map: &MemberMap) -> Vec<Stream> {
    let mut streams = Vec::new();
    if map.format == MapFormat::SevenZip {
        for folder in &map.folders {
            let mut members: Vec<(usize, u64, u64)> = map
                .members
                .iter()
                .enumerate()
                .filter_map(|(i, m)| {
                    let slot = m.folder.filter(|s| s.index == folder.index)?;
                    Some((i, slot.offset, m.unpacked_size?))
                })
                .collect();
            members.sort_by_key(|m| m.1);
            let kinds: Vec<CoderKind> = folder.coders.iter().map(|c| c.kind).collect();
            let kind = if kinds.iter().all(|k| *k == CoderKind::Copy) && folder.pack_sizes.len() == 1 {
                Kind::Plain
            } else if kinds.iter().all(|k| matches!(k, CoderKind::Copy | CoderKind::Aes))
                && kinds.contains(&CoderKind::Aes)
                && folder.pack_sizes.len() == 1
                && let Some(cipher) = folder.cipher.clone()
            {
                Kind::Cbc { cipher, zero_pad: true }
            } else {
                let layer =
                    members.first().and_then(|m| member_restart(map, m.0).ok()).map_or(Layer::Other, |r| r.layer);
                Kind::Compressed(layer)
            };
            streams.push(Stream {
                spans: folder.packed.clone(),
                kind,
                plain_len: Some(folder.unpacked_size),
                members,
                folder: Some(folder.index),
            });
        }
        return streams;
    }
    for (i, m) in map.members.iter().enumerate() {
        if m.pieces.is_empty() {
            continue;
        }
        let spans = m
            .pieces
            .iter()
            .map(|p| PackedSpan {
                volume: p.volume,
                packed: p.packed.clone(),
                stream: p.stream_offset..p.stream_offset + (p.packed.end - p.packed.start),
            })
            .collect();
        let kind = match (m.mapping, &m.cipher) {
            (OutputMapping::Direct, _) => Kind::Plain,
            (OutputMapping::CbcBlocks, Some(c)) => Kind::Cbc { cipher: c.clone(), zero_pad: false },
            (OutputMapping::Counter { skip }, Some(c)) => Kind::Counter { skip, cipher: c.clone() },
            (OutputMapping::Sequential { .. }, _) => Kind::Sequential,
            (OutputMapping::None, _) if m.encrypted && matches!(m.cipher, Some(CipherParams::Rar4Legacy { .. })) => {
                Kind::Unmapped("legacy RAR encryption")
            }
            (OutputMapping::None, _) => Kind::Compressed(member_restart(map, i).map_or(Layer::Other, |r| r.layer)),
            _ => Kind::Unmapped("cipher parameters"),
        };
        let size = m.unpacked_size;
        streams.push(Stream {
            spans,
            kind,
            plain_len: size,
            members: vec![(i, 0, size.unwrap_or(u64::MAX))],
            folder: None,
        });
    }
    streams
}

/// The packed bytes of a handover plan's stream before its restart: what the plan never needs (for a 7z LZMA2
/// plan with [`Lzma2Framing::HeaderWalk`], except the chunk headers in them).
pub fn skipped_spans(map: &MemberMap, plan: &OpenAt) -> Vec<PackedSpan> {
    let spans: Vec<PackedSpan> = match plan.start {
        Start::Lzma2 { folder, .. } => map.folders.get(folder as usize).map(|f| f.packed.clone()).unwrap_or_default(),
        _ => map
            .members
            .get(plan.member)
            .map(|m| {
                m.pieces
                    .iter()
                    .map(|p| PackedSpan {
                        volume: p.volume,
                        packed: p.packed.clone(),
                        stream: p.stream_offset..p.stream_offset + (p.packed.end - p.packed.start),
                    })
                    .collect()
            })
            .unwrap_or_default(),
    };
    spans
        .into_iter()
        .filter(|s| s.stream.start < plan.fetch_from)
        .map(|s| {
            let end = s.stream.end.min(plan.fetch_from);
            PackedSpan {
                volume: s.volume,
                packed: s.packed.start..s.packed.start + (end - s.stream.start),
                stream: s.stream.start..end,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------------------------
// CRC32 as an affine function of a final block's bytes.

/// The CRC32 lookup table entry for `b` (reflected polynomial 0xEDB88320, register starting at 0).
fn crc_table(b: u8) -> u32 {
    let mut r = u32::from(b);
    for _ in 0..8 {
        r = if r & 1 != 0 { (r >> 1) ^ 0xEDB8_8320 } else { r >> 1 };
    }
    r
}

/// A 32x32 matrix over GF(2): column `i` is the image of bit `i`.
type Gf2 = [u32; 32];

fn gf2_apply(m: &Gf2, v: u32) -> u32 {
    let mut out = 0;
    let mut v = v;
    while v != 0 {
        let i = v.trailing_zeros() as usize;
        out ^= m[i];
        v &= v - 1;
    }
    out
}

fn gf2_mul(a: &Gf2, b: &Gf2) -> Gf2 {
    let mut out = [0; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = gf2_apply(a, b[i]);
    }
    out
}

/// The register change of one zero byte, raised to the power `n`.
fn zero_bytes(n: u64) -> Gf2 {
    let mut base = [0u32; 32];
    for (i, slot) in base.iter_mut().enumerate() {
        let r = 1u32 << i;
        *slot = crc_table((r & 0xff) as u8) ^ (r >> 8);
    }
    let mut result = [0u32; 32];
    for (i, slot) in result.iter_mut().enumerate() {
        *slot = 1 << i;
    }
    let mut n = n;
    while n > 0 {
        if n & 1 != 0 {
            result = gf2_mul(&base, &result);
        }
        base = gf2_mul(&base, &base);
        n >>= 1;
    }
    result
}

/// A check's CRC32 as `base ^ sum of contributions` of the final block's bytes in its range.
struct CrcAffine {
    base: u32,
    /// Per block byte index and bit: its effect on the CRC, or all zero when the byte is outside the range.
    effect: [[u32; 8]; 16],
}

impl CrcAffine {
    fn new(check: &Crc32Check, p: &PendingFinal, out: &Out, known: &[KnownBytes<'_>]) -> Option<Self> {
        let range = &check.range;
        if range.start >= range.end {
            return None;
        }
        let len = range.end - range.start;
        let inside: Vec<(usize, u64)> = (0..16)
            .filter_map(|i| {
                p.places[i].and_then(|(v, o)| (v == check.volume && range.contains(&o)).then(|| (i, o - range.start)))
            })
            .collect();
        if inside.is_empty() || usize::try_from(len).is_err() {
            return None;
        }
        // every other byte of the range must be rebuilt here or known
        let mut bytes = vec![0u8; len as usize];
        for (k, slot) in bytes.iter_mut().enumerate() {
            let o = range.start + k as u64;
            if inside.iter().any(|&(_, at)| at == k as u64) {
                continue;
            }
            let rebuilt = if check.volume == out.volume { out.rebuilt_byte(o) } else { None };
            *slot = rebuilt.or_else(|| known_byte(known, check.volume, o))?;
        }
        let base = crate::crc32::hash(&bytes);
        let mut effect = [[0u32; 8]; 16];
        // all inside positions are consecutive offsets of one volume; find the effect of each through the zeros after it
        for &(i, at) in &inside {
            let after = len - 1 - at;
            let m = zero_bytes(after);
            for (bit, slot) in effect[i].iter_mut().enumerate() {
                *slot = gf2_apply(&m, crc_table(1 << bit));
            }
        }
        Some(Self { base, effect })
    }

    fn crc(&self, blk: &[u8; 16]) -> u32 {
        let mut c = self.base;
        for (i, &byte) in blk.iter().enumerate() {
            let mut x = byte;
            while x != 0 {
                let bit = x.trailing_zeros() as usize;
                c ^= self.effect[i][bit];
                x &= x - 1;
            }
        }
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_affine_matches_direct_crc() {
        let mut data: Vec<u8> = (0..1000u32).map(|i| (i * 7 + 3) as u8).collect();
        let at = 600usize;
        let mut zeroed = data.clone();
        zeroed[at..at + 16].fill(0);
        let base = crate::crc32::hash(&zeroed);
        let mut effect = [[0u32; 8]; 16];
        for (i, row) in effect.iter_mut().enumerate() {
            let m = zero_bytes((data.len() - 1 - (at + i)) as u64);
            for (bit, slot) in row.iter_mut().enumerate() {
                *slot = gf2_apply(&m, crc_table(1 << bit));
            }
        }
        let affine = CrcAffine { base, effect };
        let blk: [u8; 16] = data[at..at + 16].try_into().unwrap();
        assert_eq!(affine.crc(&blk), crate::crc32::hash(&data));
        data[at + 5] ^= 0x41;
        let blk: [u8; 16] = data[at..at + 16].try_into().unwrap();
        assert_eq!(affine.crc(&blk), crate::crc32::hash(&data));
    }

    #[test]
    fn counter_keystream_matches_the_winzip_decryptor() {
        let key = [7u8; 16];
        let aes = AesKey::new(&key).unwrap();
        let plain: Vec<u8> = (0..100u8).collect();
        let mut whole = plain.clone();
        ctr_xor(&aes, 0, &mut whole);
        assert_eq!(crate::crypto::decrypt_winzip_ctr(&key, &whole).unwrap(), plain);
        let mut tail = plain[37..].to_vec();
        ctr_xor(&aes, 37, &mut tail);
        assert_eq!(tail, whole[37..]);
    }
}
