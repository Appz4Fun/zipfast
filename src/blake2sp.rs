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

//! BLAKE2sp, the 8-way parallel form of BLAKE2s, as RAR 5.0 uses for its optional file hash. Written from RFC 7693
//! (BLAKE2s) and the BLAKE2 paper's description of the parallel modes: eight leaves take the input's 64-byte blocks
//! in turn, and a root hashes the leaves' digests.

use std::sync::atomic::{AtomicU8, Ordering};

const IV: [u32; 8] = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19];

const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

const BLOCK: usize = 64;
const LANES: usize = 8;
/// One round: a block for each leaf, in leaf order.
const ROUND: usize = LANES * BLOCK;

/// The initial chaining value of a tree node: 32-byte digest, no key, fanout 8, depth 2, inner length 32.
fn node_h(offset: u32, depth: u8) -> [u32; 8] {
    let mut h = IV;
    // parameter block words: digest length, key length, fanout, depth / leaf length / node offset /
    // node offset high, node depth, inner length / salt and personalisation (zero)
    h[0] ^= 32 | (u32::from(LANES as u8) << 16) | (2 << 24);
    h[2] ^= offset;
    h[3] ^= (u32::from(depth) << 16) | (32 << 24);
    h
}

/// The BLAKE2s compression function (RFC 7693 section 3.2) on one block; `t` counts the bytes hashed so far,
/// this block included.
fn compress(h: &mut [u32; 8], block: &[u8; BLOCK], t: u64, last: bool, last_node: bool) {
    let mut m = [0u32; 16];
    for (w, bytes) in m.iter_mut().zip(block.as_chunks::<4>().0) {
        *w = u32::from_le_bytes(*bytes);
    }
    let mut v = [0u32; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= t as u32;
    v[13] ^= (t >> 32) as u32;
    if last {
        v[14] = !v[14];
        if last_node {
            v[15] = !v[15];
        }
    }
    #[inline(always)]
    fn g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
        v[d] = (v[d] ^ v[a]).rotate_right(16);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(12);
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
        v[d] = (v[d] ^ v[a]).rotate_right(8);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(7);
    }
    for s in &SIGMA {
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

/// One BLAKE2s instance. The last block seen is held back until `finish`, since only then is it known to be last.
/// Used for the root, and in the RFC test.
#[derive(Clone)]
struct Blake2s {
    h: [u32; 8],
    t: u64,
    buf: [u8; BLOCK],
    buf_len: usize,
    last_node: bool,
}

impl Blake2s {
    fn node(offset: u32, depth: u8, last_node: bool) -> Self {
        Blake2s { h: node_h(offset, depth), t: 0, buf: [0; BLOCK], buf_len: 0, last_node }
    }

    fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            if self.buf_len == BLOCK {
                self.t += BLOCK as u64;
                let block = self.buf;
                compress(&mut self.h, &block, self.t, false, self.last_node);
                self.buf_len = 0;
            }
            let n = (BLOCK - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + n].copy_from_slice(&data[..n]);
            self.buf_len += n;
            data = &data[n..];
        }
    }

    fn finish(mut self) -> [u8; 32] {
        self.t += self.buf_len as u64;
        self.buf[self.buf_len..].fill(0);
        let block = self.buf;
        compress(&mut self.h, &block, self.t, true, self.last_node);
        digest(&self.h)
    }
}

fn digest(h: &[u32; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (bytes, w) in out.as_chunks_mut::<4>().0.iter_mut().zip(h) {
        *bytes = w.to_le_bytes();
    }
    out
}

/// A BLAKE2sp leaf-round implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Backend {
    /// Portable Rust, one leaf at a time.
    Scalar,
    /// AVX2: the eight leaves side by side, one per 32-bit lane. Only made once AVX2 has been found.
    #[cfg(target_arch = "x86_64")]
    Avx2,
    /// NEON: four leaves side by side, twice per round.
    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    Neon,
}

impl Backend {
    fn name(self) -> &'static str {
        match self {
            Backend::Scalar => "scalar",
            #[cfg(target_arch = "x86_64")]
            Backend::Avx2 => "avx2",
            #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
            Backend::Neon => "neon",
        }
    }

    /// Every backend this processor can run, the portable one first.
    #[cfg(test)]
    #[cfg_attr(not(any(target_arch = "aarch64", target_arch = "x86_64")), allow(unused_mut))]
    pub(crate) fn available() -> Vec<Backend> {
        let mut all = vec![Backend::Scalar];
        #[cfg(target_arch = "x86_64")]
        if std::arch::is_x86_feature_detected!("avx2") {
            all.push(Backend::Avx2);
        }
        #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
        if std::arch::is_aarch64_feature_detected!("neon") {
            all.push(Backend::Neon);
        }
        all
    }

    /// The fastest backend this processor can run, unless `ZIPFAST_BLAKE2SP=scalar` asks for the portable one.
    fn detect() -> Backend {
        if std::env::var_os("ZIPFAST_BLAKE2SP").is_some_and(|v| v == "scalar") {
            return Backend::Scalar;
        }
        #[cfg(target_arch = "x86_64")]
        if std::arch::is_x86_feature_detected!("avx2") {
            return Backend::Avx2;
        }
        #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
        if std::arch::is_aarch64_feature_detected!("neon") {
            return Backend::Neon;
        }
        Backend::Scalar
    }

    /// The backend picked for this process: detected once (the environment is read then), then cached.
    fn current() -> Backend {
        static PICKED: AtomicU8 = AtomicU8::new(0);
        match PICKED.load(Ordering::Relaxed) {
            1 => Backend::Scalar,
            #[cfg(target_arch = "x86_64")]
            2 => Backend::Avx2,
            #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
            3 => Backend::Neon,
            _ => {
                let b = Backend::detect();
                let code = match b {
                    Backend::Scalar => 1,
                    #[cfg(target_arch = "x86_64")]
                    Backend::Avx2 => 2,
                    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
                    Backend::Neon => 3,
                };
                PICKED.store(code, Ordering::Relaxed);
                b
            }
        }
    }

    /// Runs whole rounds of `data` (a multiple of [`ROUND`] bytes) through the eight leaves, none of them last.
    /// `t` is each leaf's byte count before the first round.
    fn rounds(self, h: &mut [[u32; 8]; LANES], t: u64, data: &[u8]) {
        debug_assert_eq!(data.len() % ROUND, 0);
        match self {
            Backend::Scalar => {
                for (r, round) in data.as_chunks::<ROUND>().0.iter().enumerate() {
                    let t = t + (r as u64 + 1) * BLOCK as u64;
                    for (leaf, block) in h.iter_mut().zip(round.as_chunks::<BLOCK>().0) {
                        compress(leaf, block, t, false, false);
                    }
                }
            }
            // SAFETY: an `Avx2` is only made once AVX2 has been found
            #[cfg(target_arch = "x86_64")]
            Backend::Avx2 => unsafe { avx2::rounds(h, t, data) },
            // SAFETY: a `Neon` is only made once NEON has been found
            #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
            Backend::Neon => unsafe { neon::rounds(h, t, data) },
        }
    }
}

/// The name of the BLAKE2sp implementation this process uses: `"avx2"`, `"neon"` or `"scalar"`.
/// `ZIPFAST_BLAKE2SP=scalar`, read once at the first hash, forces the portable one.
#[doc(hidden)]
pub fn blake2sp_backend() -> &'static str {
    Backend::current().name()
}

/// Streaming BLAKE2sp. Leaf `i` takes blocks `i`, `i + 8`, `i + 16`, ... of the input. A leaf's last block must be
/// compressed with the final flag, and which block that is shows only at the end, so up to two rounds (1 KiB) stay
/// buffered: a round is compressed only once more than a round follows it, which gives every leaf a later block.
#[derive(Clone)]
pub struct Blake2sp {
    h: [[u32; 8]; LANES],
    /// Bytes each leaf has compressed (all leaves alike until `finish`).
    t: u64,
    buf: Box<[u8; 2 * ROUND]>,
    buf_len: usize,
    backend: Backend,
}

impl Default for Blake2sp {
    fn default() -> Self {
        Self::new()
    }
}

impl Blake2sp {
    pub fn new() -> Self {
        Self::with(Backend::current())
    }

    fn with(backend: Backend) -> Self {
        Blake2sp {
            h: std::array::from_fn(|i| node_h(i as u32, 0)),
            t: 0,
            buf: Box::new([0; 2 * ROUND]),
            buf_len: 0,
            backend,
        }
    }

    /// The same hash run by `backend` (tests compare every backend the processor has).
    #[cfg(test)]
    pub(crate) fn with_backend(backend: Backend) -> Self {
        Self::with(backend)
    }

    fn run(&mut self, rounds: &[u8]) {
        self.backend.rounds(&mut self.h, self.t, rounds);
        self.t += (rounds.len() / LANES) as u64;
    }

    pub fn update(&mut self, mut data: &[u8]) {
        // A round is compressed only while more than two rounds of input remain after it (buffered or not), so
        // every leaf still has a later block for its final flag; at most two rounds stay buffered.
        while !data.is_empty() {
            if self.buf_len == 0 {
                if data.len() > 2 * ROUND {
                    // Straight from the input, leaving at most two rounds (and more than one) for the buffer.
                    let n = (data.len() - 2 * ROUND).div_ceil(ROUND) * ROUND;
                    self.run(&data[..n]);
                    data = &data[n..];
                }
                self.buf[..data.len()].copy_from_slice(data);
                self.buf_len = data.len();
                return;
            }
            if self.buf_len + data.len() <= 2 * ROUND {
                self.buf[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
                self.buf_len += data.len();
                return;
            }
            // More than two rounds remain: complete the buffered round, then flush buffered rounds while the
            // rule allows, so the buffer empties and the rest goes straight from the input.
            let take = ((ROUND - self.buf_len % ROUND) % ROUND).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            let mut flush = 0;
            while flush < self.buf_len && self.buf_len - flush + data.len() > 2 * ROUND {
                flush += ROUND;
            }
            if flush > 0 {
                self.backend.rounds(&mut self.h, self.t, &self.buf[..flush]);
                self.t += (flush / LANES) as u64;
                self.buf.copy_within(flush..self.buf_len, 0);
                self.buf_len -= flush;
            }
        }
    }

    pub fn finish(self) -> [u8; 32] {
        let held = &self.buf[..self.buf_len];
        let mut root = Blake2s::node(0, 1, true);
        for (i, mut h) in self.h.into_iter().enumerate() {
            let last_node = i == LANES - 1;
            let mut t = self.t;
            // This leaf's blocks among the held bytes: at most one per held round.
            let blocks: Vec<&[u8]> = (0..2)
                .map(|r| r * ROUND + i * BLOCK)
                .filter(|&at| at < held.len())
                .map(|at| &held[at..held.len().min(at + BLOCK)])
                .collect();
            if blocks.is_empty() {
                // No bytes at all for this leaf: one empty final block.
                compress(&mut h, &[0; BLOCK], t, true, last_node);
            }
            for (k, bytes) in blocks.iter().enumerate() {
                let mut block = [0u8; BLOCK];
                block[..bytes.len()].copy_from_slice(bytes);
                t += bytes.len() as u64;
                compress(&mut h, &block, t, k + 1 == blocks.len(), last_node);
            }
            root.update(&digest(&h));
        }
        root.finish()
    }
}

#[cfg(target_arch = "x86_64")]
mod avx2 {
    use super::{BLOCK, IV, LANES, ROUND, SIGMA};
    use std::arch::x86_64::*;

    /// Rotates each lane right by 16 or 8 bits with a byte shuffle.
    #[inline]
    #[target_feature(enable = "avx2")]
    fn ror16(x: __m256i) -> __m256i {
        let mask = _mm256_setr_epi8(
            2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13, 2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13,
        );
        _mm256_shuffle_epi8(x, mask)
    }

    #[inline]
    #[target_feature(enable = "avx2")]
    fn ror8(x: __m256i) -> __m256i {
        let mask = _mm256_setr_epi8(
            1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12, 1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12,
        );
        _mm256_shuffle_epi8(x, mask)
    }

    #[inline]
    #[target_feature(enable = "avx2")]
    fn ror12(x: __m256i) -> __m256i {
        _mm256_or_si256(_mm256_srli_epi32::<12>(x), _mm256_slli_epi32::<20>(x))
    }

    #[inline]
    #[target_feature(enable = "avx2")]
    fn ror7(x: __m256i) -> __m256i {
        _mm256_or_si256(_mm256_srli_epi32::<7>(x), _mm256_slli_epi32::<25>(x))
    }

    #[inline]
    #[target_feature(enable = "avx2")]
    fn g(v: &mut [__m256i; 16], a: usize, b: usize, c: usize, d: usize, x: __m256i, y: __m256i) {
        v[a] = _mm256_add_epi32(_mm256_add_epi32(v[a], v[b]), x);
        v[d] = ror16(_mm256_xor_si256(v[d], v[a]));
        v[c] = _mm256_add_epi32(v[c], v[d]);
        v[b] = ror12(_mm256_xor_si256(v[b], v[c]));
        v[a] = _mm256_add_epi32(_mm256_add_epi32(v[a], v[b]), y);
        v[d] = ror8(_mm256_xor_si256(v[d], v[a]));
        v[c] = _mm256_add_epi32(v[c], v[d]);
        v[b] = ror7(_mm256_xor_si256(v[b], v[c]));
    }

    /// Transposes eight rows of eight words: `out[j]` lane `i` is `rows[i]` word `j`.
    #[inline]
    #[target_feature(enable = "avx2")]
    fn transpose(r: [__m256i; 8]) -> [__m256i; 8] {
        let t0 = _mm256_unpacklo_epi32(r[0], r[1]);
        let t1 = _mm256_unpackhi_epi32(r[0], r[1]);
        let t2 = _mm256_unpacklo_epi32(r[2], r[3]);
        let t3 = _mm256_unpackhi_epi32(r[2], r[3]);
        let t4 = _mm256_unpacklo_epi32(r[4], r[5]);
        let t5 = _mm256_unpackhi_epi32(r[4], r[5]);
        let t6 = _mm256_unpacklo_epi32(r[6], r[7]);
        let t7 = _mm256_unpackhi_epi32(r[6], r[7]);
        let u0 = _mm256_unpacklo_epi64(t0, t2);
        let u1 = _mm256_unpackhi_epi64(t0, t2);
        let u2 = _mm256_unpacklo_epi64(t1, t3);
        let u3 = _mm256_unpackhi_epi64(t1, t3);
        let u4 = _mm256_unpacklo_epi64(t4, t6);
        let u5 = _mm256_unpackhi_epi64(t4, t6);
        let u6 = _mm256_unpacklo_epi64(t5, t7);
        let u7 = _mm256_unpackhi_epi64(t5, t7);
        [
            _mm256_permute2x128_si256::<0x20>(u0, u4),
            _mm256_permute2x128_si256::<0x20>(u1, u5),
            _mm256_permute2x128_si256::<0x20>(u2, u6),
            _mm256_permute2x128_si256::<0x20>(u3, u7),
            _mm256_permute2x128_si256::<0x31>(u0, u4),
            _mm256_permute2x128_si256::<0x31>(u1, u5),
            _mm256_permute2x128_si256::<0x31>(u2, u6),
            _mm256_permute2x128_si256::<0x31>(u3, u7),
        ]
    }

    /// See [`super::Backend::rounds`].
    ///
    /// # Safety
    ///
    /// The processor must have AVX2.
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn rounds(h: &mut [[u32; 8]; LANES], t: u64, data: &[u8]) {
        let mut hv = [_mm256_setzero_si256(); 8];
        for (j, x) in hv.iter_mut().enumerate() {
            let lanes: [u32; 8] = [h[0][j], h[1][j], h[2][j], h[3][j], h[4][j], h[5][j], h[6][j], h[7][j]];
            // SAFETY: an unaligned load of 32 bytes from an 8-word array
            *x = unsafe { _mm256_loadu_si256(lanes.as_ptr().cast()) };
        }
        let mut iv = [_mm256_setzero_si256(); 8];
        for (x, &w) in iv.iter_mut().zip(&IV) {
            *x = _mm256_set1_epi32(w as i32);
        }
        let mut t = t;
        for round in data.as_chunks::<ROUND>().0 {
            t += BLOCK as u64;
            let p = round.as_ptr();
            let mut m = [_mm256_setzero_si256(); 16];
            for half in 0..2 {
                let mut rows = [_mm256_setzero_si256(); 8];
                for (i, row) in rows.iter_mut().enumerate() {
                    // SAFETY: 32 bytes inside this 512-byte round
                    *row = unsafe { _mm256_loadu_si256(p.add(i * BLOCK + half * 32).cast()) };
                }
                m[half * 8..half * 8 + 8].copy_from_slice(&transpose(rows));
            }
            let mut v = [
                hv[0],
                hv[1],
                hv[2],
                hv[3],
                hv[4],
                hv[5],
                hv[6],
                hv[7],
                iv[0],
                iv[1],
                iv[2],
                iv[3],
                _mm256_xor_si256(iv[4], _mm256_set1_epi32(t as u32 as i32)),
                _mm256_xor_si256(iv[5], _mm256_set1_epi32((t >> 32) as u32 as i32)),
                iv[6],
                iv[7],
            ];
            macro_rules! round {
                ($r:expr) => {{
                    const S: [usize; 16] = SIGMA[$r];
                    g(&mut v, 0, 4, 8, 12, m[S[0]], m[S[1]]);
                    g(&mut v, 1, 5, 9, 13, m[S[2]], m[S[3]]);
                    g(&mut v, 2, 6, 10, 14, m[S[4]], m[S[5]]);
                    g(&mut v, 3, 7, 11, 15, m[S[6]], m[S[7]]);
                    g(&mut v, 0, 5, 10, 15, m[S[8]], m[S[9]]);
                    g(&mut v, 1, 6, 11, 12, m[S[10]], m[S[11]]);
                    g(&mut v, 2, 7, 8, 13, m[S[12]], m[S[13]]);
                    g(&mut v, 3, 4, 9, 14, m[S[14]], m[S[15]]);
                }};
            }
            round!(0);
            round!(1);
            round!(2);
            round!(3);
            round!(4);
            round!(5);
            round!(6);
            round!(7);
            round!(8);
            round!(9);
            for j in 0..8 {
                hv[j] = _mm256_xor_si256(hv[j], _mm256_xor_si256(v[j], v[j + 8]));
            }
        }
        for (j, x) in hv.iter().enumerate() {
            let mut lanes = [0u32; 8];
            // SAFETY: an unaligned store of 32 bytes into an 8-word array
            unsafe { _mm256_storeu_si256(lanes.as_mut_ptr().cast(), *x) };
            for (leaf, &w) in h.iter_mut().zip(&lanes) {
                leaf[j] = w;
            }
        }
    }
}

#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
mod neon {
    use super::{BLOCK, IV, LANES, ROUND, SIGMA};
    use std::arch::aarch64::*;

    #[inline]
    #[target_feature(enable = "neon")]
    fn ror16(x: uint32x4_t) -> uint32x4_t {
        vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(x)))
    }

    #[inline]
    #[target_feature(enable = "neon")]
    fn ror8(x: uint32x4_t, table: uint8x16_t) -> uint32x4_t {
        vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(x), table))
    }

    #[inline]
    #[target_feature(enable = "neon")]
    fn ror12(x: uint32x4_t) -> uint32x4_t {
        vsriq_n_u32::<12>(vshlq_n_u32::<20>(x), x)
    }

    #[inline]
    #[target_feature(enable = "neon")]
    fn ror7(x: uint32x4_t) -> uint32x4_t {
        vsriq_n_u32::<7>(vshlq_n_u32::<25>(x), x)
    }

    #[inline]
    #[target_feature(enable = "neon")]
    #[allow(clippy::too_many_arguments)]
    fn g(
        v: &mut [uint32x4_t; 16],
        a: usize,
        b: usize,
        c: usize,
        d: usize,
        x: uint32x4_t,
        y: uint32x4_t,
        table: uint8x16_t,
    ) {
        v[a] = vaddq_u32(vaddq_u32(v[a], v[b]), x);
        v[d] = ror16(veorq_u32(v[d], v[a]));
        v[c] = vaddq_u32(v[c], v[d]);
        v[b] = ror12(veorq_u32(v[b], v[c]));
        v[a] = vaddq_u32(vaddq_u32(v[a], v[b]), y);
        v[d] = ror8(veorq_u32(v[d], v[a]), table);
        v[c] = vaddq_u32(v[c], v[d]);
        v[b] = ror7(veorq_u32(v[b], v[c]));
    }

    /// Transposes four rows of four words: `out[j]` lane `i` is `rows[i]` word `j`.
    #[inline]
    #[target_feature(enable = "neon")]
    fn transpose(r: [uint32x4_t; 4]) -> [uint32x4_t; 4] {
        let t0 = vreinterpretq_u64_u32(vtrn1q_u32(r[0], r[1]));
        let t1 = vreinterpretq_u64_u32(vtrn2q_u32(r[0], r[1]));
        let t2 = vreinterpretq_u64_u32(vtrn1q_u32(r[2], r[3]));
        let t3 = vreinterpretq_u64_u32(vtrn2q_u32(r[2], r[3]));
        [
            vreinterpretq_u32_u64(vtrn1q_u64(t0, t2)),
            vreinterpretq_u32_u64(vtrn1q_u64(t1, t3)),
            vreinterpretq_u32_u64(vtrn2q_u64(t0, t2)),
            vreinterpretq_u32_u64(vtrn2q_u64(t1, t3)),
        ]
    }

    /// Loads leaves `first..first + 4`'s message words for one round, one leaf per lane.
    #[inline]
    #[target_feature(enable = "neon")]
    fn message(round: &[u8; ROUND], first: usize) -> [uint32x4_t; 16] {
        let p = round[first * BLOCK..].as_ptr().cast::<u32>();
        let mut m = [vdupq_n_u32(0); 16];
        for q in 0..4 {
            let mut rows = [vdupq_n_u32(0); 4];
            for (i, row) in rows.iter_mut().enumerate() {
                // SAFETY: 16 bytes inside this leaf group's four blocks of the round
                *row = unsafe { vld1q_u32(p.add(i * BLOCK / 4 + q * 4)) };
            }
            m[q * 4..q * 4 + 4].copy_from_slice(&transpose(rows));
        }
        m
    }

    /// Runs one round for all eight leaves: two groups of four, their G functions interleaved so the two
    /// independent dependency chains overlap.
    #[inline]
    #[target_feature(enable = "neon")]
    fn round8(hv: &mut [[uint32x4_t; 8]; 2], round: &[u8; ROUND], t: u64, table: uint8x16_t) {
        let ma = message(round, 0);
        let mb = message(round, 4);
        let init = |h: &[uint32x4_t; 8]| {
            [
                h[0],
                h[1],
                h[2],
                h[3],
                h[4],
                h[5],
                h[6],
                h[7],
                vdupq_n_u32(IV[0]),
                vdupq_n_u32(IV[1]),
                vdupq_n_u32(IV[2]),
                vdupq_n_u32(IV[3]),
                vdupq_n_u32(IV[4] ^ t as u32),
                vdupq_n_u32(IV[5] ^ (t >> 32) as u32),
                vdupq_n_u32(IV[6]),
                vdupq_n_u32(IV[7]),
            ]
        };
        let mut va = init(&hv[0]);
        let mut vb = init(&hv[1]);
        macro_rules! round {
            ($r:expr) => {{
                const S: [usize; 16] = SIGMA[$r];
                g(&mut va, 0, 4, 8, 12, ma[S[0]], ma[S[1]], table);
                g(&mut vb, 0, 4, 8, 12, mb[S[0]], mb[S[1]], table);
                g(&mut va, 1, 5, 9, 13, ma[S[2]], ma[S[3]], table);
                g(&mut vb, 1, 5, 9, 13, mb[S[2]], mb[S[3]], table);
                g(&mut va, 2, 6, 10, 14, ma[S[4]], ma[S[5]], table);
                g(&mut vb, 2, 6, 10, 14, mb[S[4]], mb[S[5]], table);
                g(&mut va, 3, 7, 11, 15, ma[S[6]], ma[S[7]], table);
                g(&mut vb, 3, 7, 11, 15, mb[S[6]], mb[S[7]], table);
                g(&mut va, 0, 5, 10, 15, ma[S[8]], ma[S[9]], table);
                g(&mut vb, 0, 5, 10, 15, mb[S[8]], mb[S[9]], table);
                g(&mut va, 1, 6, 11, 12, ma[S[10]], ma[S[11]], table);
                g(&mut vb, 1, 6, 11, 12, mb[S[10]], mb[S[11]], table);
                g(&mut va, 2, 7, 8, 13, ma[S[12]], ma[S[13]], table);
                g(&mut vb, 2, 7, 8, 13, mb[S[12]], mb[S[13]], table);
                g(&mut va, 3, 4, 9, 14, ma[S[14]], ma[S[15]], table);
                g(&mut vb, 3, 4, 9, 14, mb[S[14]], mb[S[15]], table);
            }};
        }
        round!(0);
        round!(1);
        round!(2);
        round!(3);
        round!(4);
        round!(5);
        round!(6);
        round!(7);
        round!(8);
        round!(9);
        for j in 0..8 {
            hv[0][j] = veorq_u32(hv[0][j], veorq_u32(va[j], va[j + 8]));
            hv[1][j] = veorq_u32(hv[1][j], veorq_u32(vb[j], vb[j + 8]));
        }
    }

    /// See [`super::Backend::rounds`].
    ///
    /// # Safety
    ///
    /// The processor must have NEON.
    #[target_feature(enable = "neon")]
    pub(super) unsafe fn rounds(h: &mut [[u32; 8]; LANES], t: u64, data: &[u8]) {
        // SAFETY: loads and stores of 16 bytes from or into 16-byte arrays
        unsafe {
            let table = vld1q_u8([1u8, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12].as_ptr());
            let mut hv = [[vdupq_n_u32(0); 8]; 2];
            for (g, set) in hv.iter_mut().enumerate() {
                for (j, x) in set.iter_mut().enumerate() {
                    let lanes = [h[g * 4][j], h[g * 4 + 1][j], h[g * 4 + 2][j], h[g * 4 + 3][j]];
                    *x = vld1q_u32(lanes.as_ptr());
                }
            }
            let mut t = t;
            for round in data.as_chunks::<ROUND>().0 {
                t += BLOCK as u64;
                round8(&mut hv, round, t, table);
            }
            for (g, set) in hv.iter().enumerate() {
                for (j, x) in set.iter().enumerate() {
                    let mut lanes = [0u32; 4];
                    vst1q_u32(lanes.as_mut_ptr(), *x);
                    for (k, &w) in lanes.iter().enumerate() {
                        h[g * 4 + k][j] = w;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn blake2s_matches_rfc_7693() {
        // the RFC's own example, with plain sequential parameters
        let mut s = Blake2s::node(0, 0, false);
        s.h = IV;
        s.h[0] ^= 0x0101_0020;
        s.update(b"abc");
        assert_eq!(hex(&s.finish()), "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
    }

    #[test]
    fn blake2sp_known_answers() {
        // computed with an independent construction from Python's hashlib tree parameters
        let cases = [
            (0, "dd0e891776933f43c7d032b08a917e25741f8aa9a12c12e1cac8801500f2ca4f"),
            (1, "a6b9eecc25227ad788c99d3f236debc8da408849e9a5178978727a81457f7239"),
            (64, "cc7a4d29e03634d99a2faa6812670672259183d47fc824eed98990045df1d4df"),
            (511, "eaf475c4cf2ef7466da52a56e0a7e2f8ae80047edf5ddbafacf995fd7821e88b"),
            (512, "36d2635a4853aa0ec5a6f246986a28f490129beac52c5ea047478a488c050f0a"),
            (513, "560d0aa2ffaeb39746112bd4f5b7d0bccef3efdf21be47e14dd9e33b782db88c"),
            (1024, "4fa7de206fb54150dd7a79b6d59c5c5739e9433c5437a9e6baef8ac1dc983e8f"),
            (5000, "9b79f268588cfaece26cfe812a4ca3c72c796bd82dcb81547469f8cf72e8b7ba"),
        ];
        for (n, want) in cases {
            let data: Vec<u8> = (0..n as u32).map(|i| (i * 31 % 251) as u8).collect();
            let mut h = Blake2sp::new();
            h.update(&data);
            assert_eq!(hex(&h.finish()), want, "length {n}");
        }
    }

    #[test]
    fn chunking_does_not_change_the_hash() {
        let data: Vec<u8> = (0..5000u32).map(|i| (i * 31 % 251) as u8).collect();
        let mut whole = Blake2sp::new();
        whole.update(&data);
        let mut pieces = Blake2sp::new();
        for c in data.chunks(77) {
            pieces.update(c);
        }
        assert_eq!(whole.finish(), pieces.finish());
    }

    fn hash_with(backend: Backend, data: &[u8], splits: &[usize]) -> [u8; 32] {
        let mut h = Blake2sp::with_backend(backend);
        let mut rest = data;
        for &n in splits {
            let n = n.min(rest.len());
            h.update(&rest[..n]);
            rest = &rest[n..];
        }
        h.update(rest);
        h.finish()
    }

    /// Every backend gives the portable hash for every length around the block and round boundaries.
    #[test]
    fn every_backend_matches_the_portable_one_on_every_short_length() {
        let data: Vec<u8> = (0..2100u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 11) as u8).collect();
        for backend in Backend::available() {
            for n in 0..=data.len() {
                assert_eq!(
                    hash_with(backend, &data[..n], &[]),
                    hash_with(Backend::Scalar, &data[..n], &[]),
                    "{backend:?} length {n}"
                );
            }
        }
    }

    /// Large inputs fed in uneven pieces, through the buffered and the direct paths.
    #[test]
    fn every_backend_matches_the_portable_one_on_large_split_inputs() {
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for case in 0..6 {
            let len = 100_000 + (next() % 300_000) as usize;
            let data: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            let splits: Vec<usize> = (0..40).map(|_| (next() % (case as u64 * 2000 + 700)) as usize).collect();
            let want = hash_with(Backend::Scalar, &data, &[]);
            for backend in Backend::available() {
                assert_eq!(hash_with(backend, &data, &[]), want, "{backend:?} case {case} whole");
                assert_eq!(hash_with(backend, &data, &splits), want, "{backend:?} case {case} split");
            }
        }
    }

    /// The known answers hold on every backend, not only the one this process picked.
    #[test]
    fn every_backend_gives_the_known_answers() {
        for backend in Backend::available() {
            for (n, want) in [
                (0usize, "dd0e891776933f43c7d032b08a917e25741f8aa9a12c12e1cac8801500f2ca4f"),
                (1024, "4fa7de206fb54150dd7a79b6d59c5c5739e9433c5437a9e6baef8ac1dc983e8f"),
                (5000, "9b79f268588cfaece26cfe812a4ca3c72c796bd82dcb81547469f8cf72e8b7ba"),
            ] {
                let data: Vec<u8> = (0..n as u32).map(|i| (i * 31 % 251) as u8).collect();
                assert_eq!(hex(&hash_with(backend, &data, &[])), want, "{backend:?} length {n}");
            }
        }
    }

    #[test]
    fn the_environment_can_force_the_portable_backend() {
        // Detection reads the variable once per process; check the decision function directly.
        let forced = std::env::var_os("ZIPFAST_BLAKE2SP").is_some_and(|v| v == "scalar");
        assert_eq!(Backend::detect() == Backend::Scalar, forced || Backend::available().len() == 1);
    }

    /// Large updates after a small one leave the buffer and go straight to the backend; the digest is the same
    /// however the input is cut, including cuts that leave exactly one or two rounds for the end.
    #[test]
    fn many_large_updates_hash_like_one() {
        let data: Vec<u8> = (0..3_000_000u32).map(|i| (i.wrapping_mul(2_246_822_519) >> 9) as u8).collect();
        let want = hash_with(Backend::Scalar, &data, &[]);
        for backend in Backend::available() {
            for (first, step) in
                [(1usize, 1 << 20), (100, 1 << 20), (511, 70_000), (513, 1024), (1024, 512), (1000, 1025)]
            {
                let mut h = Blake2sp::with_backend(backend);
                h.update(&data[..first]);
                for chunk in data[first..].chunks(step) {
                    h.update(chunk);
                }
                assert_eq!(h.finish(), want, "{backend:?} first {first} step {step}");
            }
            // ends that leave one round, two rounds, and a round and a byte after the last update
            for tail in [ROUND, 2 * ROUND, ROUND + 1, 2 * ROUND - 1] {
                let cut = data.len() - tail;
                assert_eq!(hash_with(backend, &data, &[37, cut - 37]), want, "{backend:?} tail {tail}");
            }
        }
    }
}
