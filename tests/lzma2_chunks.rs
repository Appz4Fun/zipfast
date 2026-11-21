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

//! LZMA2 chunk indexes: raw LZMA2 streams written by liblzma (the encoder behind `xz --format=raw --lzma2`) and a
//! 7z archive written by 7-Zip, checked against full decodes.

use std::{
    fs::File,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};
use zipfast::map::*;
use zipfast::progressive::{
    ProgressiveResult, RangeRead, RangeSource, SourceId, SourceInfo, SourceLength, VolumeAnswer, VolumeRequest,
    VolumeSource,
};

/// Bytes that do not compress.
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

fn text(len: usize, seed: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 64);
    let mut i = seed;
    while out.len() < len {
        out.extend_from_slice(format!("line {i} of a compressible text, word {} again\n", i % 97).as_bytes());
        i += 1;
    }
    out.truncate(len);
    out
}

/// Text, noise and text again: LZMA chunks, stored chunks, and LZMA chunks after them.
fn mixed() -> Vec<u8> {
    let mut data = text(300_000, 1);
    data.extend(noise(400_000, 7));
    data.extend(text(150_000, 9));
    data.extend(noise(130_000, 8));
    data
}

const DICT_PROP: u8 = 18; // 2 MiB
const DICT: u32 = 2 << 20;

/// A raw LZMA2 stream with its end marker, as `xz --format=raw --lzma2=dict=2MiB` writes it.
fn encode(plain: &[u8]) -> Vec<u8> {
    let mut opts = liblzma::stream::LzmaOptions::new_preset(6).unwrap();
    opts.dict_size(DICT);
    let mut filters = liblzma::stream::Filters::new();
    filters.lzma2(&opts);
    let mut stream = liblzma::stream::Stream::new_raw_encoder(&filters).unwrap();
    let mut out = Vec::with_capacity(plain.len() + plain.len() / 16 + 1024);
    let mut consumed = 0;
    loop {
        if out.capacity() - out.len() < 4096 {
            out.reserve(1 << 16);
        }
        let before = stream.total_in();
        let status = stream.process_vec(&plain[consumed..], &mut out, liblzma::stream::Action::Finish).unwrap();
        consumed += (stream.total_in() - before) as usize;
        if status == liblzma::stream::Status::StreamEnd {
            return out;
        }
    }
}

/// Decodes a whole raw LZMA2 stream.
fn decode_all(packed: &[u8], prop: u8) -> Vec<u8> {
    let mut filters = liblzma::stream::Filters::new();
    filters.lzma2_properties(&[prop]).unwrap();
    let mut stream = liblzma::stream::Stream::new_raw_decoder(&filters).unwrap();
    let mut out = Vec::with_capacity(1 << 20);
    let mut consumed = 0;
    loop {
        if out.capacity() - out.len() < 4096 {
            out.reserve(1 << 20);
        }
        let before = stream.total_in();
        let status = stream.process_vec(&packed[consumed..], &mut out, liblzma::stream::Action::Run).unwrap();
        consumed += (stream.total_in() - before) as usize;
        if status == liblzma::stream::Status::StreamEnd {
            return out;
        }
    }
}

fn index(packed: &[u8]) -> Lzma2Index {
    Lzma2Index::from_bytes(packed, Lzma2IndexOptions::default())
}

fn assert_contiguous(index: &Lzma2Index) {
    let mut at = index.start;
    for c in &index.chunks {
        assert_eq!((c.packed_offset, c.unpacked_offset), (at.packed, at.unpacked));
        at = Lzma2Position { packed: c.packed().end, unpacked: c.unpacked().end };
    }
    assert_eq!(index.end_position(), at);
}

fn opts() -> Lzma2DecodeOptions {
    Lzma2DecodeOptions::default()
}

#[test]
fn index_of_mixed_data_matches_a_full_decode() {
    let data = mixed();
    let packed = encode(&data);
    let index = index(&packed);
    assert!(index.complete(), "{:?}", index.end);
    assert_eq!(index.end, Lzma2End::EndMarker { offset: packed.len() as u64 - 1 });
    assert_contiguous(&index);
    assert_eq!(index.end_position().unpacked, data.len() as u64);
    assert_eq!(decode_all(&packed, DICT_PROP), data);

    let kinds = |k| index.chunks.iter().filter(|c| c.kind == k).count();
    assert!(kinds(Lzma2ChunkKind::Stored) >= 4, "noise is stored");
    assert!(kinds(Lzma2ChunkKind::Lzma) >= 2, "text is compressed");
    assert_eq!(index.chunks[0].reset, Lzma2Reset::DictStateProps);
    // An LZMA chunk after stored ones resets the state.
    assert!(index.chunks.iter().skip(1).any(|c| matches!(c.reset, Lzma2Reset::State | Lzma2Reset::StateProps)));
    assert!(index.stored_bytes() >= 260_000);

    // Every stored payload is its output, byte for byte.
    for c in index.chunks.iter().filter(|c| c.kind == Lzma2ChunkKind::Stored) {
        let p = c.payload();
        let u = c.unpacked();
        assert_eq!(&packed[p.start as usize..p.end as usize], &data[u.start as usize..u.end as usize]);
        assert!(c.unpacked_len <= LZMA2_MAX_PAYLOAD);
    }

    // The whole stream decodes through the index, and every chunk on its own.
    let all = index.decode_chunks(0..index.chunks.len(), &packed, 0, DICT_PROP, &opts()).unwrap();
    assert_eq!(all, data);
    let mut joined = Vec::new();
    for i in 0..index.chunks.len() {
        let c = index.chunks[i];
        let out = index.decode_chunk(i, &packed, 0, DICT_PROP, &opts()).unwrap();
        assert_eq!(out.len() as u64, c.unpacked_len);
        joined.extend(out);
    }
    assert_eq!(joined, data);
}

#[test]
fn plans_and_reads_ranges_across_stored_and_lzma_chunks() {
    let data = mixed();
    let packed = encode(&data);
    let index = index(&packed);
    let len = data.len() as u64;
    let mut seed = 0x1234_5678u64;
    for _ in 0..40 {
        seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        let a = (seed >> 20) % len;
        let b = (a + (seed >> 40) % 150_000).min(len);
        let got = index.read_range(a..b, &packed, 0, DICT_PROP, &opts()).unwrap();
        assert_eq!(got, &data[a as usize..b as usize], "{a}..{b}");
        // Pieces tile the range, and stored ones point at the right bytes.
        let mut at = a;
        for piece in index.plan(a..b) {
            match piece {
                Lzma2Piece::Stored { unpacked, packed: p, chunk } => {
                    assert_eq!(unpacked.start, at);
                    assert_eq!(index.chunks[chunk].kind, Lzma2ChunkKind::Stored);
                    assert_eq!(
                        &packed[p.start as usize..p.end as usize],
                        &data[unpacked.start as usize..unpacked.end as usize]
                    );
                    at = unpacked.end;
                }
                Lzma2Piece::Decode { unpacked, chunks, from } => {
                    assert_eq!(unpacked.start, at);
                    assert!(from.unwrap() <= chunks.start);
                    at = unpacked.end;
                }
                Lzma2Piece::Unindexed { .. } => panic!("everything is indexed"),
            }
        }
        assert_eq!(at, b);
    }
    // Past the end is unindexed.
    assert_eq!(index.plan(len..len + 5), vec![Lzma2Piece::Unindexed { unpacked: len..len + 5 }]);
    assert!(matches!(
        index.read_range(len - 1..len + 1, &packed, 0, DICT_PROP, &opts()),
        Err(Lzma2DecodeError::Unindexed { unpacked }) if unpacked == len
    ));
    // Only the packed bytes a stored piece needs.
    let stored = index.chunks.iter().find(|c| c.kind == Lzma2ChunkKind::Stored).unwrap();
    let p = stored.payload();
    let window = &packed[p.start as usize..p.end as usize];
    let u = stored.unpacked();
    assert_eq!(
        index.read_range(u.clone(), window, p.start, DICT_PROP, &opts()).unwrap(),
        &data[u.start as usize..u.end as usize]
    );
    assert!(matches!(
        index.read_range(u.start..u.end + 1, window, p.start, DICT_PROP, &opts()),
        Err(Lzma2DecodeError::MissingPacked { .. })
    ));
}

/// Two streams back to back: the second starts with a dictionary reset mid-stream.
fn two_streams() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let a = mixed();
    let mut b = text(120_000, 50);
    b.extend(noise(80_000, 51));
    b.extend(text(90_000, 52));
    let mut packed = encode(&a);
    assert_eq!(packed.pop(), Some(0));
    packed.extend(encode(&b));
    (a, b, packed)
}

#[test]
fn decodes_from_a_mid_stream_dictionary_reset() {
    let (a, b, packed) = two_streams();
    let index = index(&packed);
    assert!(index.complete());
    let reset = index.chunk_at(a.len() as u64).unwrap();
    let c = index.chunks[reset];
    assert_eq!(c.unpacked_offset, a.len() as u64);
    assert!(c.reset.resets_dictionary());
    assert_eq!(index.chunks.iter().filter(|c| c.reset.resets_dictionary()).count(), 2);

    // The second run, decoded from its reset with only its own packed bytes.
    let run = &packed[c.packed_offset as usize..];
    let out = index.decode_chunks(reset..index.chunks.len(), run, c.packed_offset, DICT_PROP, &opts()).unwrap();
    assert_eq!(out, b);
    // A later chunk decodes from that reset, not from the stream start.
    let last = index.chunks.len() - 1;
    assert_eq!(index.decode_start(last), Some(reset));
    let l = index.chunks[last];
    let out = index.decode_chunk(last, run, c.packed_offset, DICT_PROP, &opts()).unwrap();
    assert_eq!(out, &b[(l.unpacked_offset - a.len() as u64) as usize..]);

    // Not from a chunk without a reset.
    assert!(matches!(
        index.decode_chunks(reset + 1..reset + 2, &packed, 0, DICT_PROP, &opts()),
        Err(Lzma2DecodeError::NotDictionaryReset { .. })
    ));

    // The streaming decoder, fed and drained a few bytes at a time.
    let chunks = &index.chunks[reset..];
    let mut decoder = Lzma2Decoder::new(chunks, DICT_PROP, &opts()).unwrap();
    let mut out = Vec::new();
    let mut fed = 0;
    let mut buf = [0u8; 7];
    while !decoder.is_finished() {
        let end = (fed + 5).min(run.len());
        let step = decoder.decode(&run[fed..end], &mut buf).unwrap();
        fed += step.consumed;
        out.extend_from_slice(&buf[..step.produced]);
    }
    assert_eq!(out, b);
    assert_eq!((decoder.packed_left(), decoder.output_left(), decoder.produced()), (0, 0, b.len() as u64));
    assert_eq!(fed, run.len() - 1, "the run's bytes, not the end marker");
}

#[test]
fn decoder_rejects_data_that_disagrees_with_the_headers() {
    let data = mixed();
    let packed = encode(&data);
    let index = index(&packed);
    let i = index.chunks.iter().position(|c| c.kind == Lzma2ChunkKind::Lzma && c.unpacked_offset > 0).unwrap();
    let c = index.chunks[i];
    let mut bad = packed.clone();
    for b in &mut bad[c.payload().start as usize + 8..c.payload().end as usize] {
        *b ^= 0x5A;
    }
    assert!(matches!(index.decode_chunk(i, &bad, 0, DICT_PROP, &opts()), Err(Lzma2DecodeError::Data { .. })));
    assert!(matches!(Lzma2Decoder::new(&index.chunks[..1], 41, &opts()), Err(Lzma2DecodeError::BadDictionaryProp(41))));
    let gap = [index.chunks[0], index.chunks[2]];
    assert!(matches!(Lzma2Decoder::new(&gap, DICT_PROP, &opts()), Err(Lzma2DecodeError::NotContiguous)));
}

#[test]
fn truncated_ranges_keep_the_chunks_before_the_cut() {
    let data = mixed();
    let packed = encode(&data);
    let full = index(&packed);
    let c = full.chunks[3];
    // Inside the header.
    let cut = index(&packed[..c.packed_offset as usize + 2]);
    assert_eq!(cut.chunks, full.chunks[..3]);
    assert_eq!(cut.end, Lzma2End::Truncated { offset: c.packed_offset, partial: None });
    // Inside the payload: the chunk is reported, not listed.
    let cut = index(&packed[..c.payload().start as usize + 10]);
    assert_eq!(cut.chunks, full.chunks[..3]);
    assert_eq!(cut.end, Lzma2End::Truncated { offset: c.packed_offset, partial: Some(c) });
    assert!(!cut.complete());
    // At a chunk boundary, without the end marker.
    let cut = index(&packed[..c.packed_offset as usize]);
    assert_eq!(cut.end, Lzma2End::RangeEnd { offset: c.packed_offset });
    // Every cut lists a prefix of the full index.
    for len in (0..packed.len()).step_by(997) {
        let cut = index(&packed[..len]);
        assert_eq!(cut.chunks, full.chunks[..cut.chunks.len()]);
        assert!(cut.end.offset() <= len as u64);
    }
    // An empty range and an empty stream.
    assert_eq!(index(&[]).end, Lzma2End::RangeEnd { offset: 0 });
    assert!(index(&[0]).complete());
}

#[test]
fn damaged_headers_end_the_index_with_typed_damage() {
    let data = mixed();
    let packed = encode(&data);
    let full = index(&packed);
    let c = full.chunks[4];
    let at = c.packed_offset as usize;

    let mut bad = packed.clone();
    bad[at] = 0x05;
    let damaged = index(&bad);
    assert_eq!(damaged.chunks, full.chunks[..4]);
    assert_eq!(damaged.end, Lzma2End::Damaged { offset: c.packed_offset, damage: Lzma2Damage::BadControl(0x05) });

    // The first chunk must reset the dictionary.
    let mut bad = packed.clone();
    bad[0] = 0xC0 | (bad[0] & 0x1F);
    assert_eq!(index(&bad).end, Lzma2End::Damaged { offset: 0, damage: Lzma2Damage::NoDictionaryReset });
    assert_eq!(index(&[0x02, 0, 0, 7]).end, Lzma2End::Damaged { offset: 0, damage: Lzma2Damage::NoDictionaryReset });

    // After a stored dictionary reset, the next LZMA chunk must set props.
    let stream = [0x01, 0x00, 0x00, b'x', 0xA0, 0x00, 0x00, 0x00, 0x00, 0x00];
    let damaged = index(&stream);
    assert_eq!(damaged.chunks.len(), 1);
    assert_eq!(damaged.end, Lzma2End::Damaged { offset: 4, damage: Lzma2Damage::MissingProps });

    // Props out of range, or lc + lp above 4.
    for p in [225u8, 4 + 9] {
        let mut bad = packed.clone();
        bad[5] = p;
        assert_eq!(index(&bad).end, Lzma2End::Damaged { offset: 0, damage: Lzma2Damage::BadProps(p) });
    }

    // Past the expected unpacked size.
    let options = Lzma2IndexOptions { expected_unpacked: Some(data.len() as u64 - 1), ..Default::default() };
    let damaged = Lzma2Index::from_bytes(&packed, options);
    assert_eq!(damaged.chunks, full.chunks[..full.chunks.len() - 1]);
    assert!(matches!(damaged.end, Lzma2End::Damaged { damage: Lzma2Damage::UnpackedOverflow, .. }));
}

#[test]
fn bounds_cap_chunks_offsets_dictionary_and_output() {
    let data = mixed();
    let packed = encode(&data);
    let full = index(&packed);
    let options = Lzma2IndexOptions { max_chunks: 3, ..Default::default() };
    let capped = Lzma2Index::from_bytes(&packed, options);
    assert_eq!(capped.chunks, full.chunks[..3]);
    assert_eq!(capped.end, Lzma2End::ChunkLimit { offset: full.chunks[3].packed_offset });
    let exact =
        Lzma2Index::from_bytes(&packed, Lzma2IndexOptions { max_chunks: full.chunks.len(), ..Default::default() });
    assert_eq!(exact, full);

    // Unpacked offsets never overflow.
    let resume = Lzma2Start::Resume(Lzma2Position { packed: 0, unpacked: u64::MAX - 10 });
    let stream = [0x02, 0x00, 0x20, 0u8];
    let mut bytes = stream.to_vec();
    bytes.resize(3 + 0x21, 1);
    let damaged = Lzma2Index::from_bytes(&bytes, Lzma2IndexOptions { start: resume, ..Default::default() });
    assert_eq!(damaged.end, Lzma2End::Damaged { offset: 0, damage: Lzma2Damage::UnpackedOverflow });

    // The dictionary is the coder's shrunk to the run: a 4 GiB prop decodes a 64 KiB run within a 64 KiB cap.
    let payload = noise(1 << 17, 4);
    let mut stored = vec![0x01, 0xFF, 0xFF];
    stored.extend_from_slice(&payload[..1 << 16]);
    stored.extend_from_slice(&[0x02, 0xFF, 0xFF]);
    stored.extend_from_slice(&payload[1 << 16..]);
    stored.push(0);
    let two = index(&stored);
    assert!(two.complete());
    let small = Lzma2DecodeOptions { max_dictionary: 1 << 16, ..opts() };
    assert_eq!(two.decode_chunks(0..1, &stored, 0, 40, &small).unwrap(), &payload[..1 << 16]);
    assert!(matches!(
        two.decode_chunks(0..2, &stored, 0, 40, &small),
        Err(Lzma2DecodeError::Limit { bound: Lzma2Bound::Dictionary, limit: 65536, attempted: 131072 })
    ));
    assert_eq!(two.decode_chunks(0..2, &stored, 0, 40, &opts()).unwrap(), payload);
    let tight = Lzma2DecodeOptions { max_output: 1000, ..opts() };
    assert!(matches!(
        full.decode_chunk(0, &packed, 0, DICT_PROP, &tight),
        Err(Lzma2DecodeError::Limit { bound: Lzma2Bound::Output, limit: 1000, .. })
    ));
    assert!(matches!(
        full.read_range(0..1001, &packed, 0, DICT_PROP, &tight),
        Err(Lzma2DecodeError::Limit { bound: Lzma2Bound::Output, .. })
    ));
}

#[test]
fn resumes_at_a_stored_chain_found_mid_stream() {
    let (_, _, packed) = two_streams();
    let full = index(&packed);
    // A window in the middle of the first noise run, at no known alignment.
    let first_stored = full.chunks.iter().position(|c| c.kind == Lzma2ChunkKind::Stored).unwrap();
    let from = full.chunks[first_stored].packed_offset as usize + 1000;
    let window = &packed[from..from + 300_000];
    let chains = find_stored_chunk_chains(window, 3);
    assert!(!chains.is_empty());
    let at = (from + chains[0]) as u64;
    let k = full.chunks.iter().position(|c| c.packed_offset == at).expect("a real chunk header");
    assert_eq!(full.chunks[k].kind, Lzma2ChunkKind::Stored);
    // Noise alone almost never chains.
    assert!(find_stored_chunk_chains(&noise(400_000, 3), 3).len() <= 2);

    // The caller knows the output offset (from matching the payload); the walk resumes there.
    let start = Lzma2Position { packed: at, unpacked: full.chunks[k].unpacked_offset };
    let resumed =
        Lzma2Index::from_bytes(&packed, Lzma2IndexOptions { start: Lzma2Start::Resume(start), ..Default::default() });
    assert!(resumed.complete());
    assert_eq!(resumed.start, start);
    assert_eq!(resumed.chunks, full.chunks[k..]);
    // Output before the resume point is not indexed; LZMA chunks before the next reset cannot be decoded.
    assert_eq!(resumed.plan(0..start.unpacked)[0], Lzma2Piece::Unindexed { unpacked: 0..start.unpacked });
    let lzma = resumed.chunks.iter().position(|c| c.kind == Lzma2ChunkKind::Lzma).unwrap();
    assert_eq!(resumed.chunks[lzma].reset, Lzma2Reset::State);
    assert_eq!(resumed.decode_start(lzma), None);
    let u = resumed.chunks[lzma].unpacked();
    assert!(matches!(resumed.plan(u.clone())[..], [Lzma2Piece::Decode { from: None, .. }]));
    assert!(matches!(
        resumed.read_range(u.clone(), &packed, 0, DICT_PROP, &opts()),
        Err(Lzma2DecodeError::Unindexed { unpacked }) if unpacked == u.start
    ));
    // Stored chunks after the resume point copy as usual, and the second stream's reset decodes.
    let s = resumed.chunks[0].unpacked();
    assert_eq!(
        resumed.read_range(s.clone(), &packed, 0, DICT_PROP, &opts()).unwrap(),
        decode_all(&packed, DICT_PROP)[s.start as usize..s.end as usize]
    );
    let last = resumed.chunks.len() - 1;
    assert!(resumed.decode_start(last).is_some());
}

// ---- Sources ----

#[derive(Default)]
struct Gate {
    ready: bool,
    waits: usize,
    reads: usize,
}

/// A range source that waits once before every read, fills at most `max` bytes, and reports holes.
struct Bytes {
    data: Vec<u8>,
    holes: Vec<std::ops::Range<u64>>,
    gate: Arc<Mutex<Gate>>,
    max: usize,
}

impl RangeSource for Bytes {
    fn info(&self) -> SourceInfo {
        let len = self.data.len() as u64;
        SourceInfo { id: SourceId(1), generation: 0, extent: len, length: SourceLength::Final(len) }
    }
    fn backing_files(&self) -> &[File] {
        &[]
    }
    fn read_at(&mut self, at: u64, buf: &mut [u8], cx: &mut Context<'_>) -> ProgressiveResult<RangeRead> {
        let mut g = self.gate.lock().unwrap();
        if !g.ready {
            g.waits += 1;
            g.ready = true;
            cx.waker().wake_by_ref();
            return Ok(RangeRead::NotYet);
        }
        g.ready = false;
        g.reads += 1;
        if let Some(h) = self.holes.iter().find(|h| h.contains(&at)) {
            return Ok(RangeRead::Hole { len: h.end - at });
        }
        let mut end = (at as usize + buf.len().min(self.max)).min(self.data.len());
        if let Some(h) = self.holes.iter().find(|h| h.start > at && (h.start as usize) < end) {
            end = h.start as usize;
        }
        let n = end - at as usize;
        buf[..n].copy_from_slice(&self.data[at as usize..end]);
        Ok(RangeRead::Filled { count: n })
    }
}

fn poll_builder(mut builder: Lzma2IndexBuilder) -> Lzma2Index {
    let mut cx = Context::from_waker(Waker::noop());
    let mut pending = 0;
    loop {
        match builder.poll_index(&mut cx) {
            Poll::Ready(result) => {
                assert!(matches!(builder.poll_index(&mut cx), Poll::Ready(Err(Lzma2Error::AlreadyFinished))));
                return result.unwrap();
            }
            Poll::Pending => pending += 1,
        }
        assert!(pending < 1_000_000);
    }
}

#[test]
fn builder_over_a_range_source_reads_only_headers_and_survives_payload_holes() {
    let data = mixed();
    let packed = encode(&data);
    let full = index(&packed);
    let lead = 777u64;
    let mut file = noise(lead as usize, 1);
    file.extend_from_slice(&packed);
    file.extend_from_slice(b"trailing bytes");
    // Holes over every payload but the first bytes of each: the walk never reads them.
    let holes = full.chunks.iter().map(|c| lead + c.payload().start + 1..lead + c.payload().end).collect();
    let gate = Arc::new(Mutex::new(Gate::default()));
    let source = Bytes { data: file.clone(), holes, gate: gate.clone(), max: usize::MAX };
    let builder =
        Lzma2IndexBuilder::new(Box::new(source), lead..lead + packed.len() as u64, Lzma2IndexOptions::default());
    let built = poll_builder(builder);
    assert_eq!(built, full);
    let g = gate.lock().unwrap();
    assert_eq!(g.reads, full.chunks.len() + 1, "one read per header and the end marker");
    assert_eq!(g.waits, g.reads);
    drop(g);

    // Short reads of one byte at a time give the same index.
    let gate = Arc::new(Mutex::new(Gate::default()));
    let source = Bytes { data: file.clone(), holes: Vec::new(), gate, max: 1 };
    let builder =
        Lzma2IndexBuilder::new(Box::new(source), lead..lead + packed.len() as u64, Lzma2IndexOptions::default());
    assert_eq!(poll_builder(builder), full);

    // A hole in a header ends the index there.
    let c = full.chunks[5];
    let hole = std::iter::once(lead + c.packed_offset + 1..lead + c.packed_offset + 2).collect();
    let gate = Arc::new(Mutex::new(Gate::default()));
    let source = Bytes { data: file.clone(), holes: hole, gate, max: usize::MAX };
    let builder =
        Lzma2IndexBuilder::new(Box::new(source), lead..lead + packed.len() as u64, Lzma2IndexOptions::default());
    let holed = poll_builder(builder);
    assert_eq!(holed.chunks, full.chunks[..5]);
    assert_eq!(holed.end, Lzma2End::Hole { chunk: c.packed_offset, offset: c.packed_offset + 1 });

    // A source shorter than the range is a truncation.
    let short = file[..(lead + c.payload().start + 3) as usize].to_vec();
    let gate = Arc::new(Mutex::new(Gate::default()));
    let source = Bytes { data: short, holes: Vec::new(), gate, max: usize::MAX };
    let builder =
        Lzma2IndexBuilder::new(Box::new(source), lead..lead + packed.len() as u64, Lzma2IndexOptions::default());
    let cut = poll_builder(builder);
    assert_eq!(cut.end, Lzma2End::Truncated { offset: c.packed_offset, partial: Some(c) });
}

// ---- 7z ----

fn fixture() -> Vec<u8> {
    std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/7z/lzma2_chunks.7z")).unwrap()
}

fn gather(volumes: &[&[u8]], spans: &[PackedSpan]) -> Vec<u8> {
    spans
        .iter()
        .flat_map(|s| volumes[s.volume as usize][s.packed.start as usize..s.packed.end as usize].to_vec())
        .collect()
}

#[test]
fn seven_zip_lzma2_folder_goes_straight_to_its_chunk_index() {
    let archive = fixture();
    let map = MemberMap::from_memory(&[&archive], "set.7z", None).unwrap();
    assert_eq!(map.folders.len(), 1);
    let folder = &map.folders[0];
    let stage = folder.lzma2_stage().unwrap();
    assert_eq!((stage.coder, stage.folder_output), (0, true));
    assert_eq!(stage.unpacked_size, folder.unpacked_size);
    assert_eq!(stage.packed, 0..folder.pack_sizes[0]);
    assert_eq!(stage.dict_prop, folder.coders[0].properties[0]);

    let index = map.lzma2_chunks(0, &[&archive], Lzma2IndexOptions::default()).unwrap();
    assert!(index.complete(), "{:?}", index.end);
    assert_contiguous(&index);
    assert_eq!(index.end_position().unpacked, folder.unpacked_size);
    assert_eq!(index.end_position().packed + 1, folder.pack_sizes[0]);
    // 64 KiB blocks: the second starts with a stored chunk that resets the dictionary, then an LZMA chunk that
    // sets props.
    let kinds: Vec<_> = index.chunks.iter().map(|c| (c.kind, c.reset)).collect();
    assert_eq!(
        kinds,
        [
            (Lzma2ChunkKind::Lzma, Lzma2Reset::DictStateProps),
            (Lzma2ChunkKind::Stored, Lzma2Reset::Dict),
            (Lzma2ChunkKind::Lzma, Lzma2Reset::StateProps),
        ]
    );
    assert_eq!(index.chunks[1].unpacked_offset, 65536);
    assert_eq!(index.decode_start(2), Some(1));
    assert!(index.stored_bytes() >= 40_000);

    // The packed stream, gathered from the folder's spans, decodes in full and through the index.
    let packed = gather(&[&archive], &stage.spans(folder, 0..stage.packed.end));
    let whole = decode_all(&packed, stage.dict_prop);
    assert_eq!(whole.len() as u64, folder.unpacked_size);

    // Each member's bytes, read through the index, match its CRC.
    for member in &map.members {
        let slot = member.folder.unwrap();
        let size = member.unpacked_size.unwrap();
        let bytes = index.read_range(slot.offset..slot.offset + size, &packed, 0, stage.dict_prop, &opts()).unwrap();
        assert_eq!(bytes, &whole[slot.offset as usize..(slot.offset + size) as usize]);
        assert_eq!(zipfast::crc32::hash(&bytes), member.checks.as_ref().unwrap().crc32.unwrap());
    }
    // The random member's stored pieces map to archive bytes directly.
    let b = map.members.iter().find(|m| m.name.as_deref() == Some("b.bin")).unwrap();
    let slot = b.folder.unwrap();
    let mut copied = 0;
    for piece in index.plan(slot.offset..slot.offset + b.unpacked_size.unwrap()) {
        if let Lzma2Piece::Stored { unpacked, packed: p, .. } = piece {
            let bytes = gather(&[&archive], &stage.spans(folder, p));
            assert_eq!(bytes, &whole[unpacked.start as usize..unpacked.end as usize]);
            copied += bytes.len();
        }
    }
    assert!(copied >= 40_000, "{copied}");
    // A folder index out of range.
    assert!(matches!(map.lzma2_chunks(1, &[&archive], Lzma2IndexOptions::default()), Err(Lzma2Error::NotLzma2Folder)));
}

struct Provider {
    volumes: Vec<Vec<u8>>,
    gate: Arc<Mutex<Gate>>,
    asked: Arc<Mutex<Vec<(u32, String)>>>,
}

impl VolumeSource for Provider {
    fn volume(&mut self, r: &VolumeRequest, cx: &mut Context<'_>) -> ProgressiveResult<VolumeAnswer> {
        self.asked.lock().unwrap().push((r.index, r.expected.to_string_lossy().into_owned()));
        cx.waker().wake_by_ref();
        Ok(match self.volumes.get(r.index as usize) {
            Some(data) if !data.is_empty() => VolumeAnswer::Ready(Box::new(Bytes {
                data: data.clone(),
                holes: Vec::new(),
                gate: self.gate.clone(),
                max: usize::MAX,
            })),
            _ => VolumeAnswer::Missing,
        })
    }
}

#[test]
fn seven_zip_split_set_indexes_through_a_volume_source() {
    let archive = fixture();
    let volumes: Vec<Vec<u8>> = archive.chunks(10_000).map(<[u8]>::to_vec).collect();
    let refs: Vec<&[u8]> = volumes.iter().map(Vec::as_slice).collect();
    let map = MemberMap::from_memory(&refs, "set.7z.001", None).unwrap();
    let in_memory = map.lzma2_chunks(0, &refs, Lzma2IndexOptions::default()).unwrap();
    assert!(in_memory.complete());
    assert_eq!(
        in_memory,
        MemberMap::from_memory(&[&archive], "set.7z", None)
            .unwrap()
            .lzma2_chunks(0, &[&archive], Lzma2IndexOptions::default())
            .unwrap()
    );

    let asked = Arc::new(Mutex::new(Vec::new()));
    let gate = Arc::new(Mutex::new(Gate::default()));
    let provider = Provider { volumes: volumes.clone(), gate: gate.clone(), asked: asked.clone() };
    let builder =
        Lzma2IndexBuilder::for_folder(Box::new(provider), &map.folders[0], "set.7z.001", Lzma2IndexOptions::default())
            .unwrap();
    assert_eq!(poll_builder(builder), in_memory);
    let asked = asked.lock().unwrap();
    assert_eq!(asked[0], (0, "set.7z.001".to_owned()));
    assert!(asked.len() >= 2);
    assert!(asked.iter().all(|(i, name)| *name == format!("set.7z.{:03}", i + 1)));

    // A missing volume ends the index at the first header it holds.
    let base = map.folders[0].packed[0].packed.start;
    let k = in_memory.chunks.iter().position(|c| (base + c.packed_offset) / 10_000 > 0).unwrap();
    let gap = ((base + in_memory.chunks[k].packed_offset) / 10_000) as u32;
    let mut gappy = volumes.clone();
    gappy[gap as usize].clear();
    let provider = Provider { volumes: gappy, gate, asked: Arc::new(Mutex::new(Vec::new())) };
    let builder =
        Lzma2IndexBuilder::for_folder(Box::new(provider), &map.folders[0], "set.7z.001", Lzma2IndexOptions::default())
            .unwrap();
    let cut = poll_builder(builder);
    assert_eq!(cut.end, Lzma2End::MissingVolume { offset: in_memory.chunks[k].packed_offset, volume: gap });
    assert_eq!(cut.chunks, in_memory.chunks[..k]);
}

// ---- Regressions from review ----

#[test]
fn max_output_caps_bytes_kept_not_the_run_decoded_before_them() {
    let data = mixed();
    let packed = encode(&data);
    let index = index(&packed);
    // Output 800_000 lies in an LZMA chunk whose run starts at the stream's only dictionary reset, 0.
    let i = index.chunk_at(800_000).unwrap();
    assert_eq!(index.chunks[i].kind, Lzma2ChunkKind::Lzma);
    assert_eq!(index.decode_start(i), Some(0));
    assert!(index.chunks[i].unpacked().end > 500_000);
    let small = Lzma2DecodeOptions { max_output: 500_000, ..opts() };
    let got = index.read_range(800_000..800_100, &packed, 0, DICT_PROP, &small).unwrap();
    assert_eq!(got, &data[800_000..800_100]);
    let c = index.chunks[i];
    if c.unpacked_len <= 500_000 {
        assert_eq!(
            index.decode_chunk(i, &packed, 0, DICT_PROP, &small).unwrap(),
            &data[c.unpacked_offset as usize..c.unpacked().end as usize]
        );
    }
    // The streamed bound is what caps the run.
    let streamed = Lzma2DecodeOptions { max_streamed: 500_000, ..opts() };
    assert!(matches!(
        index.read_range(800_000..800_100, &packed, 0, DICT_PROP, &streamed),
        Err(Lzma2DecodeError::Limit { bound: Lzma2Bound::Streamed, limit: 500_000, .. })
    ));
    assert_eq!(Lzma2DecodeOptions::default().max_streamed, 16 << 30);
    // And cancellation stops it.
    let canceled = opts();
    canceled.control.cancel();
    assert!(matches!(
        index.read_range(800_000..800_100, &packed, 0, DICT_PROP, &canceled),
        Err(Lzma2DecodeError::Canceled)
    ));
}

#[test]
fn a_volume_shorter_than_the_map_is_a_truncation_not_a_range_end() {
    let archive = fixture();
    let volumes: Vec<Vec<u8>> = archive.chunks(10_000).map(<[u8]>::to_vec).collect();
    let refs: Vec<&[u8]> = volumes.iter().map(Vec::as_slice).collect();
    let map = MemberMap::from_memory(&refs, "set.7z.001", None).unwrap();
    let full = map.lzma2_chunks(0, &refs, Lzma2IndexOptions::default()).unwrap();
    let base = map.folders[0].packed[0].packed.start;
    let k = full.chunks.iter().position(|c| (base + c.packed_offset) / 10_000 > 0).unwrap();
    let at = base + full.chunks[k].packed_offset;
    // The volume holding chunk k's header ends just before it.
    let mut short = volumes.clone();
    short[(at / 10_000) as usize].truncate((at % 10_000) as usize);
    let refs: Vec<&[u8]> = short.iter().map(Vec::as_slice).collect();
    let cut = map.lzma2_chunks(0, &refs, Lzma2IndexOptions::default()).unwrap();
    assert_eq!(cut.chunks, full.chunks[..k]);
    assert_eq!(cut.end, Lzma2End::Truncated { offset: full.chunks[k].packed_offset, partial: None });
}

#[test]
fn plan_starts_a_new_decode_piece_at_each_dictionary_reset() {
    // Two text streams back to back: an LZMA chunk directly before the second stream's dictionary reset.
    let a = text(2_500_000, 3);
    let b = text(200_000, 70);
    let mut packed = encode(&a);
    assert_eq!(packed.pop(), Some(0));
    packed.extend(encode(&b));
    let full = index(&packed);
    let reset = full.chunk_at(a.len() as u64).unwrap();
    assert!(reset >= 2 && full.chunks[reset].reset.resets_dictionary());
    assert_eq!(full.chunks[reset - 1].kind, Lzma2ChunkKind::Lzma);
    // Resume at the chunk before the reset: nothing before it is known.
    let r = &full.chunks[reset - 1];
    let start = Lzma2Position { packed: r.packed_offset, unpacked: r.unpacked_offset };
    let resumed =
        Lzma2Index::from_bytes(&packed, Lzma2IndexOptions { start: Lzma2Start::Resume(start), ..Default::default() });
    assert_eq!(resumed.chunks, full.chunks[reset - 1..]);
    let range = r.unpacked_offset..full.chunks[reset].unpacked().end;
    let pieces = resumed.plan(range.clone());
    assert_eq!(
        pieces,
        vec![
            Lzma2Piece::Decode { unpacked: r.unpacked(), chunks: 0..1, from: None },
            Lzma2Piece::Decode { unpacked: full.chunks[reset].unpacked(), chunks: 1..2, from: Some(1) },
        ]
    );
    // The part after the reset decodes; the part before it cannot.
    let after = full.chunks[reset].unpacked();
    assert_eq!(
        resumed.read_range(after.clone(), &packed, 0, DICT_PROP, &opts()).unwrap(),
        &b[..after.end as usize - a.len()]
    );
    assert!(matches!(
        resumed.read_range(range, &packed, 0, DICT_PROP, &opts()),
        Err(Lzma2DecodeError::Unindexed { unpacked }) if unpacked == r.unpacked_offset
    ));
}

/// RustyGet's restart: the chunks before a state reset are lost, but the plaintext before it is known (another copy
/// of the file). Decoding from that chunk with the known plaintext as the dictionary gives the same output as
/// decoding from the start, for every state reset in the stream, with or without its own props.
#[test]
fn a_state_reset_restarts_with_a_supplied_dictionary() {
    let plain = mixed();
    let packed = encode(&plain);
    let index = index(&packed);
    let restarts: Vec<usize> = (0..index.chunks.len())
        .filter(|&i| matches!(index.chunks[i].reset, Lzma2Reset::State | Lzma2Reset::StateProps))
        .collect();
    assert!(!restarts.is_empty(), "the mixed stream has state resets after its stored chunks");
    for &i in &restarts {
        let c = index.chunks[i];
        let end = (i + 3).min(index.chunks.len());
        let out_end = index.chunks[end - 1].unpacked().end;
        let dictionary = &plain[..c.unpacked_offset as usize];
        let out = index.decode_with_dictionary(i..end, &packed, 0, DICT_PROP, dictionary, &opts()).unwrap();
        assert_eq!(out, plain[c.unpacked_offset as usize..out_end as usize], "chunk {i} ({:?})", c.reset);
        // Only the packed bytes from that chunk on are needed.
        let from = &packed[c.packed_offset as usize..];
        let again =
            index.decode_with_dictionary(i..end, from, c.packed_offset, DICT_PROP, dictionary, &opts()).unwrap();
        assert_eq!(again, out);
    }
    // The same chunk with its own props (`0xC0`, as an encoder that changes props mid-stream writes it): rewrite its
    // header in the stream, index again and restart there.
    let i = restarts[0];
    let c = index.chunks[i];
    let props = index.props_for(i).unwrap();
    let at = c.packed_offset as usize;
    let mut with_props = packed[..at].to_vec();
    with_props.push(0xC0 | (packed[at] & 0x1F));
    with_props.extend_from_slice(&packed[at + 1..at + 5]);
    with_props.push(props);
    with_props.extend_from_slice(&packed[at + 5..]);
    let rewritten = self::index(&with_props);
    assert_eq!(rewritten.chunks[i].reset, Lzma2Reset::StateProps);
    let end = (i + 3).min(rewritten.chunks.len());
    let out_end = rewritten.chunks[end - 1].unpacked().end as usize;
    let out = rewritten
        .decode_with_dictionary(i..end, &with_props, 0, DICT_PROP, &plain[..c.unpacked_offset as usize], &opts())
        .unwrap();
    assert_eq!(out, plain[c.unpacked_offset as usize..out_end]);
    // A wrong dictionary does not give the file's bytes back.
    let c = index.chunks[i];
    let mut wrong = plain[..c.unpacked_offset as usize].to_vec();
    let at = wrong.len() - 1000;
    wrong[at..].iter_mut().for_each(|b| *b ^= 0x5a);
    let out = index.decode_with_dictionary(i..i + 1, &packed, 0, DICT_PROP, &wrong, &opts());
    assert!(out.map_or(true, |o| o != plain[c.unpacked().start as usize..c.unpacked().end as usize]));
}

#[test]
fn a_restart_needs_a_state_reset() {
    let plain = text(3_000_000, 4);
    let packed = encode(&plain);
    let index = index(&packed);
    // A chunk that continues the LZMA state cannot restart.
    let i = index.chunks.iter().position(|c| c.reset == Lzma2Reset::None && c.kind == Lzma2ChunkKind::Lzma);
    if let Some(i) = i {
        let c = index.chunks[i];
        let r = index.decode_with_dictionary(
            i..i + 1,
            &packed,
            0,
            DICT_PROP,
            &plain[..c.unpacked_offset as usize],
            &opts(),
        );
        assert!(matches!(r, Err(Lzma2DecodeError::NotStateReset { .. })), "{r:?}");
    }
    // The first chunk resets the dictionary: the supplied one is not needed.
    let c = index.chunks[0];
    let out = index.decode_with_dictionary(0..1, &packed, 0, DICT_PROP, b"ignored", &opts()).unwrap();
    assert_eq!(out, plain[..c.unpacked_len as usize]);
}
