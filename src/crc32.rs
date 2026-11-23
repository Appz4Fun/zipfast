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

//! CRC-32 (IEEE 802.3, reflected), as RAR, ZIP and gzip store it.
//!
//! Input of a few hundred bytes or more is folded with carry-less multiplies where the processor has them (PMULL
//! on 64-bit ARM, PCLMULQDQ on x86-64, both found at run time): eight 16-byte lanes take in 128 bytes a round, each
//! lane's value carried 1024 bits on by multiplying its halves by constants, so eight independent chains hide the
//! multiplier's latency. The lanes are then folded into one. On ARM the CRC instructions finish its 16 bytes; x86
//! has no CRC instruction for this polynomial (SSE4.2's is CRC-32C), so there the 128 bits are folded down to 64 and
//! a Barrett reduction gives the 32-bit remainder. Elsewhere, for short input, and when `ZIPFAST_CRC32=portable`
//! asks for it, `crc32fast` does the work.

use std::sync::atomic::{AtomicU8, Ordering};

/// The CRC-32 of bytes given in pieces.
#[derive(Clone, Default)]
pub struct Hasher {
    /// the CRC of the bytes so far (final form: not inverted)
    crc: u32,
    /// how many there were, for [`Hasher::combine`]
    len: u64,
}

impl Hasher {
    pub fn new() -> Self {
        Hasher::default()
    }

    pub fn update(&mut self, bytes: &[u8]) {
        self.crc = update(self.crc, bytes);
        self.len += bytes.len() as u64;
    }

    pub fn finalize(self) -> u32 {
        self.crc
    }

    /// A hasher that has already taken in `len` bytes whose CRC is `crc`.
    pub(crate) fn from_parts(crc: u32, len: u64) -> Self {
        Self { crc, len }
    }

    /// Takes in the bytes `other` was given, as if they had been given to this one after its own.
    pub fn combine(&mut self, other: &Hasher) {
        let mut a = crc32fast::Hasher::new_with_initial_len(self.crc, self.len);
        a.combine(&crc32fast::Hasher::new_with_initial_len(other.crc, other.len));
        self.crc = a.finalize();
        self.len += other.len;
    }
}

/// The CRC-32 of two byte strings one after the other, from the CRC of the first (`first`) and the CRC and length of
/// the second (`second`, `second_len`).
pub fn combine(first: u32, second: u32, second_len: u64) -> u32 {
    let mut a = Hasher::from_parts(first, 0);
    a.combine(&Hasher::from_parts(second, second_len));
    a.finalize()
}

/// The CRC-32 of `bytes`.
pub fn hash(bytes: &[u8]) -> u32 {
    update(0, bytes)
}

/// The CRC of what `crc` is the CRC of, with `bytes` after it.
fn update(crc: u32, bytes: &[u8]) -> u32 {
    if bytes.len() >= FOLD_MIN {
        return update_with(Backend::current(), crc, bytes);
    }
    portable(crc, bytes)
}

/// [`update`] on the given backend.
fn update_with(backend: Backend, crc: u32, bytes: &[u8]) -> u32 {
    match backend {
        #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
        // SAFETY: a `Fold` is only made once `fold::usable` has found the instructions `fold::run` needs
        Backend::Fold if bytes.len() >= FOLD_MIN => !unsafe { fold::run(!crc, bytes) },
        _ => portable(crc, bytes),
    }
}

fn portable(crc: u32, bytes: &[u8]) -> u32 {
    let mut h = crc32fast::Hasher::new_with_initial(crc);
    h.update(bytes);
    h.finalize()
}

/// The shortest input folded: below it, setting up and merging the lanes costs more than the other way. On x86 the
/// Barrett reduction and `crc32fast`'s own PCLMULQDQ loop move the break-even up (about 450 bytes on Coffee Lake).
#[cfg(not(target_arch = "x86_64"))]
const FOLD_MIN: usize = 256;
#[cfg(target_arch = "x86_64")]
const FOLD_MIN: usize = 512;

/// How the CRC is computed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Backend {
    /// the `crc32fast` crate
    Portable,
    /// carry-less multiply folding ([`fold`])
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    Fold,
}

impl Backend {
    /// Every backend this processor can run, the portable one first.
    #[cfg(test)]
    #[cfg_attr(not(any(target_arch = "aarch64", target_arch = "x86_64")), allow(unused_mut))]
    fn available() -> Vec<Backend> {
        let mut all = vec![Backend::Portable];
        #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
        if fold::usable() {
            all.push(Backend::Fold);
        }
        all
    }

    /// The fastest backend this processor can run, unless `ZIPFAST_CRC32=portable` asks for `crc32fast`.
    fn detect() -> Backend {
        if std::env::var_os("ZIPFAST_CRC32").is_some_and(|v| v == "portable") {
            return Backend::Portable;
        }
        #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
        if fold::usable() {
            return Backend::Fold;
        }
        Backend::Portable
    }

    /// The backend picked for this process: detected once (the environment is read then), then cached.
    fn current() -> Backend {
        static PICKED: AtomicU8 = AtomicU8::new(0);
        match PICKED.load(Ordering::Relaxed) {
            1 => Backend::Portable,
            #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
            2 => Backend::Fold,
            _ => {
                let b = Backend::detect();
                let code = match b {
                    Backend::Portable => 1,
                    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
                    Backend::Fold => 2,
                };
                PICKED.store(code, Ordering::Relaxed);
                b
            }
        }
    }

    fn name(self) -> &'static str {
        match self {
            Backend::Portable => "crc32fast",
            #[cfg(target_arch = "aarch64")]
            Backend::Fold => "pmull",
            #[cfg(target_arch = "x86_64")]
            Backend::Fold => "pclmulqdq",
        }
    }
}

/// The name of the CRC-32 implementation this process uses for long input: `"pmull"`, `"pclmulqdq"` or
/// `"crc32fast"`. `ZIPFAST_CRC32=portable`, read once at the first long input, forces `crc32fast`.
#[doc(hidden)]
pub fn crc32_backend() -> &'static str {
    Backend::current().name()
}

/// The polynomial, with its x^32 term, in normal order (bit i is the coefficient of x^i).
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
const POLY: u64 = 0x1_04c1_1db7;

/// x^n mod the polynomial, in normal order.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
const fn x_pow_mod(n: u32) -> u64 {
    let mut r: u64 = 1;
    let mut i = 0;
    while i < n {
        r <<= 1;
        if r & 1 << 32 != 0 {
            r ^= POLY;
        }
        i += 1;
    }
    r
}

/// What carries a 64-bit half `n` bits on: x^(n-1) mod the polynomial, bit-reflected like the data. A carry-less
/// product of two reflected values comes out one place short, which the missing factor of x makes up.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
const fn k(n: u32) -> u64 {
    x_pow_mod(n - 1).reverse_bits()
}

/// For a lane carried 1024 bits on (eight lanes) and 128 bits on (the next lane): the constants for its first half,
/// which stands 64 bits further from the end, and its second.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
const K1024: (u64, u64) = (k(1024 + 64), k(1024));
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
const K128: (u64, u64) = (k(128 + 64), k(128));

#[cfg(target_arch = "aarch64")]
mod fold {
    use std::arch::aarch64::*;

    use super::{K128, K1024};

    pub(super) fn usable() -> bool {
        std::arch::is_aarch64_feature_detected!("pmull") && std::arch::is_aarch64_feature_detected!("crc")
    }

    /// `acc` carried on by `k`'s distance, with `next` added.
    ///
    /// # Safety
    ///
    /// The processor must have PMULL.
    #[target_feature(enable = "aes")]
    #[inline]
    unsafe fn carry(acc: uint8x16_t, k: (u64, u64), next: uint8x16_t) -> uint8x16_t {
        let halves = vreinterpretq_u64_u8(acc);
        let a = vreinterpretq_u8_p128(vmull_p64(vgetq_lane_u64(halves, 0), k.0));
        let b = vreinterpretq_u8_p128(vmull_p64(vgetq_lane_u64(halves, 1), k.1));
        #[cfg(target_feature = "sha3")]
        // SAFETY: This build requires SHA3 support.
        let sum = unsafe { veor3q_u8(a, b, next) };
        #[cfg(not(target_feature = "sha3"))]
        let sum = veorq_u8(veorq_u8(a, b), next);
        sum
    }

    /// Chained CRC instructions over `bytes`, from the raw (inverted) register `c`.
    #[target_feature(enable = "crc")]
    unsafe fn chained(mut c: u32, bytes: &[u8]) -> u32 {
        let (words, rest) = bytes.as_chunks::<8>();
        for &w in words {
            c = __crc32d(c, u64::from_le_bytes(w));
        }
        for &b in rest {
            c = __crc32b(c, b);
        }
        c
    }

    /// The raw (inverted) CRC register after `bytes`, from `c`.
    ///
    /// # Safety
    ///
    /// The processor must have PMULL and the CRC instructions, and `bytes` must hold at least 128 bytes.
    #[target_feature(enable = "aes,crc")]
    pub(super) unsafe fn run(c: u32, bytes: &[u8]) -> u32 {
        debug_assert!(bytes.len() >= 128);
        // SAFETY: as the caller promises; every load is of 16 bytes inside `bytes`
        unsafe {
            let p = bytes.as_ptr();
            let mut lanes = [vdupq_n_u8(0); 8];
            for (i, lane) in lanes.iter_mut().enumerate() {
                *lane = vld1q_u8(p.add(16 * i));
            }
            // the register's starting value goes into the first four bytes
            lanes[0] = veorq_u8(lanes[0], vreinterpretq_u8_u32(vsetq_lane_u32(c, vdupq_n_u32(0), 0)));
            let mut at = 128;
            while at + 128 <= bytes.len() {
                for (i, lane) in lanes.iter_mut().enumerate() {
                    *lane = carry(*lane, K1024, vld1q_u8(p.add(at + 16 * i)));
                }
                at += 128;
            }
            let mut v = lanes[0];
            for &lane in &lanes[1..] {
                v = carry(v, K128, lane);
            }
            while at + 16 <= bytes.len() {
                v = carry(v, K128, vld1q_u8(p.add(at)));
                at += 16;
            }
            // what is left is congruent to the CRC of its own 16 bytes from a zero register
            let halves = vreinterpretq_u64_u8(v);
            let c = __crc32d(__crc32d(0, vgetq_lane_u64(halves, 0)), vgetq_lane_u64(halves, 1));
            chained(c, &bytes[at..])
        }
    }
}

#[cfg(target_arch = "x86_64")]
mod fold {
    //! Notation: a 128-bit register holding 16 data bytes stands for the polynomial whose coefficient of x^(127-j)
    //! is bit j (the first byte's low bit is the highest term), and a 64-bit half likewise with x^(63-j). The
    //! carry-less product of two such 64-bit values stands for the product of their polynomials times x.

    use std::arch::x86_64::*;

    use super::{K128, K1024, POLY, k};

    /// For a lane carried 512 and 256 bits on, while the eight lanes are merged.
    const K512: (u64, u64) = (k(512 + 64), k(512));
    const K256: (u64, u64) = (k(256 + 64), k(256));
    /// For the final reduction: x^96 and x^64 mod the polynomial (each less the factor of x a product adds).
    const K96: u64 = k(96);
    const K64: u64 = k(64);
    /// The Barrett constant: x^64 divided by the polynomial (33 bits), bit-reflected in 64.
    const MU: u64 = x64_div_poly().reverse_bits();
    /// The polynomial without its x^32 term, bit-reflected in 64.
    const P_LOW: u64 = (POLY & 0xffff_ffff).reverse_bits();

    /// The quotient of x^64 by the polynomial, in normal order.
    const fn x64_div_poly() -> u64 {
        let mut rem: u128 = 1 << 64;
        let mut q: u64 = 0;
        let mut d = 64;
        while d >= 32 {
            if rem & 1 << d != 0 {
                rem ^= (POLY as u128) << (d - 32);
                q |= 1 << (d - 32);
            }
            d -= 1;
        }
        q
    }

    pub(super) fn usable() -> bool {
        std::arch::is_x86_feature_detected!("pclmulqdq") && std::arch::is_x86_feature_detected!("sse4.1")
    }

    /// Two 64-bit constants as one register, the first in the low half.
    #[target_feature(enable = "sse2")]
    #[inline]
    fn pair(k: (u64, u64)) -> __m128i {
        _mm_set_epi64x(k.1 as i64, k.0 as i64)
    }

    /// `acc` carried on by the distance of `k` (made by [`pair`]), with `next` added.
    #[target_feature(enable = "pclmulqdq,sse4.1")]
    #[inline]
    fn carry(acc: __m128i, k: __m128i, next: __m128i) -> __m128i {
        let a = _mm_clmulepi64_si128::<0x00>(acc, k);
        let b = _mm_clmulepi64_si128::<0x11>(acc, k);
        _mm_xor_si128(_mm_xor_si128(a, b), next)
    }

    /// The raw CRC register after the 16 bytes of `v` from a zero register: `v`'s polynomial R times x^32, mod
    /// the polynomial, reflected in 32 bits.
    #[target_feature(enable = "pclmulqdq,sse4.1")]
    fn reduce(v: __m128i) -> u32 {
        // R = L x^64 + H, L and H the low and high halves. S = L (x^96 mod P) + H x^32 has degree under 96 and is
        // congruent to R x^32; it lands in bits 32..128.
        let s = _mm_xor_si128(
            _mm_clmulepi64_si128::<0x00>(v, _mm_cvtsi64_si128(K96 as i64)),
            _mm_slli_si128::<4>(_mm_srli_si128::<8>(v)),
        );
        // S = T x^64 + B, T (degree under 32) in the low half's bits 32..64, B in the high half. U = T (x^64 mod
        // P) + B has degree under 64 and is reflected in 64 bits by the high halves.
        let t = _mm_clmulepi64_si128::<0x00>(s, _mm_cvtsi64_si128(K64 as i64));
        let u = (_mm_extract_epi64::<1>(t) ^ _mm_extract_epi64::<1>(s)) as u64;
        // Barrett: with U = A x^32 + B', the quotient of U by P is that of A mu by x^32, mu = x^64 / P; the
        // product A mu x^33 holds it in bits 31..63.
        let a = _mm_cvtsi64_si128((u & 0xffff_ffff) as i64);
        let am = _mm_cvtsi128_si64(_mm_clmulepi64_si128::<0x00>(a, _mm_cvtsi64_si128(MU as i64))) as u64;
        let q = _mm_cvtsi64_si128((am >> 31 & 0xffff_ffff) as i64);
        // U mod P = B' + (q P mod x^32); q P_low x^33 holds the latter in bits 63..95.
        let qp = _mm_clmulepi64_si128::<0x00>(q, _mm_cvtsi64_si128(P_LOW as i64));
        let lo = _mm_cvtsi128_si64(qp) as u64;
        let hi = _mm_extract_epi64::<1>(qp) as u64;
        (u >> 32) as u32 ^ (lo >> 63 | hi << 1) as u32
    }

    /// The raw (inverted) CRC register after `bytes`, from `c`.
    ///
    /// # Safety
    ///
    /// The processor must have PCLMULQDQ and SSE4.1, and `bytes` must hold at least 128 bytes.
    #[target_feature(enable = "pclmulqdq,sse4.1")]
    pub(super) unsafe fn run(c: u32, bytes: &[u8]) -> u32 {
        debug_assert!(bytes.len() >= 128);
        let p = bytes.as_ptr().cast::<__m128i>();
        // SAFETY: every load is of 16 bytes inside `bytes`, unaligned loads allowed
        let load = |at: usize| unsafe { _mm_loadu_si128(p.byte_add(at)) };
        let mut lanes = [_mm_setzero_si128(); 8];
        for (i, lane) in lanes.iter_mut().enumerate() {
            *lane = load(16 * i);
        }
        // the register's starting value goes into the first four bytes
        lanes[0] = _mm_xor_si128(lanes[0], _mm_cvtsi32_si128(c as i32));
        let k1024 = pair(K1024);
        let mut at = 128;
        while at + 128 <= bytes.len() {
            for (i, lane) in lanes.iter_mut().enumerate() {
                *lane = carry(*lane, k1024, load(at + 16 * i));
            }
            at += 128;
        }
        // Up to seven whole 16-byte blocks remain: the first lanes take them, a round's worth further on, which leaves
        // the lanes in order of position once rotated.
        let extra = (bytes.len() - at) / 16;
        for (i, lane) in lanes[..extra].iter_mut().enumerate() {
            *lane = carry(*lane, k1024, load(at + 16 * i));
        }
        at += 16 * extra;
        lanes.rotate_left(extra);
        // the eight lanes into one, halving each step, so three multiplies deep rather than seven
        let k512 = pair(K512);
        let [a0, a1, a2, a3, a4, a5, a6, a7] = lanes;
        let (b0, b1, b2, b3) = (carry(a0, k512, a4), carry(a1, k512, a5), carry(a2, k512, a6), carry(a3, k512, a7));
        let k256 = pair(K256);
        let (c0, c1) = (carry(b0, k256, b2), carry(b1, k256, b3));
        let v = carry(c0, pair(K128), c1);
        // what is left is congruent to the CRC of its own 16 bytes from a zero register
        let c = reduce(v);
        if at == bytes.len() {
            return c;
        }
        let mut h = crc32fast::Hasher::new_with_initial(!c);
        h.update(&bytes[at..]);
        !h.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(n: usize) -> Vec<u8> {
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 32) as u8
            })
            .collect()
    }

    /// Every backend gives what `crc32fast` gives at every length to 4 KiB, from every offset within a 16-byte
    /// load, and however the input is split between two updates; `Hasher` and `combine` agree too.
    #[test]
    fn matches_crc32fast_at_every_length_offset_and_split() {
        let data = bytes(70_000);
        let backends = Backend::available();
        for len in (0..=4096).chain([65_537]) {
            for off in 0..16 {
                let d = &data[off..off + len];
                let want = crc32fast::hash(d);
                for &b in &backends {
                    assert_eq!(update_with(b, 0, d), want, "{b:?} len {len} off {off}");
                }
                // the folding itself, also below the length the dispatch hands it
                #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
                if (128..1024).contains(&len) && fold::usable() {
                    // SAFETY: `usable` found the instructions, and there are at least 128 bytes
                    assert_eq!(!unsafe { fold::run(!0x1234_5678, d) }, portable(0x1234_5678, d), "len {len} off {off}");
                }
                if off % 4 != 1 {
                    continue;
                }
                for cut in [1.min(len), len / 3, len.saturating_sub(129), len.saturating_sub(5)] {
                    for &b in &backends {
                        let split = update_with(b, update_with(b, 0, &d[..cut]), &d[cut..]);
                        assert_eq!(split, want, "{b:?} len {len} off {off} cut {cut}");
                    }
                }
                if len % 7 != 0 {
                    continue;
                }
                assert_eq!(hash(d), want, "len {len} off {off}");
                for cut in [0, 1.min(len), len / 3, len.saturating_sub(5), len] {
                    let mut h = Hasher::new();
                    h.update(&d[..cut]);
                    h.update(&d[cut..]);
                    assert_eq!(h.clone().finalize(), want, "len {len} off {off} cut {cut}");
                    let mut first = Hasher::new();
                    first.update(&d[..cut]);
                    let mut second = Hasher::new();
                    second.update(&d[cut..]);
                    first.combine(&second);
                    assert_eq!(first.finalize(), want, "combined: len {len} off {off} cut {cut}");
                }
            }
        }
    }

    /// Large inputs of odd lengths, whole and in uneven updates, from a nonzero starting CRC.
    #[test]
    fn matches_crc32fast_on_large_inputs() {
        let data = bytes(3 << 20);
        for &b in &Backend::available() {
            for len in [1 << 20, (1 << 20) + 13, 3_000_017, 3 << 20] {
                let d = &data[(3 << 20) - len..];
                let want = crc32fast::hash(d);
                assert_eq!(update_with(b, 0, d), want, "{b:?} len {len}");
                for step in [255, 4096 + 7, 65_521, 1 << 20] {
                    let crc = d.chunks(step).fold(0, |crc, chunk| update_with(b, crc, chunk));
                    assert_eq!(crc, want, "{b:?} len {len} step {step}");
                }
                let mut h = crc32fast::Hasher::new_with_initial(0xdead_beef);
                h.update(d);
                assert_eq!(update_with(b, 0xdead_beef, d), h.finalize(), "{b:?} len {len} seeded");
            }
        }
    }

    #[test]
    fn the_environment_can_force_the_portable_backend() {
        // Detection reads the variable once per process; check the decision function directly.
        let forced = std::env::var_os("ZIPFAST_CRC32").is_some_and(|v| v == "portable");
        assert_eq!(Backend::detect() == Backend::Portable, forced || Backend::available().len() == 1);
    }
}
