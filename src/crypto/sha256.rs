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

//! SHA-256 (FIPS 180-4), in one call or in pieces.
//!
//! Every compression goes through one function picked the first time it is needed and kept from then on: on 64-bit
//! ARM with the SHA2 instructions (every Apple M-series chip) and on x86-64 with SHA-NI (Intel Goldmont, Ice Lake and
//! later, every AMD Zen) the hardware rounds, elsewhere portable Rust. Setting `ZIPFAST_SHA256=scalar` in the
//! environment before the first hash forces the portable rounds, so tests can cover them on any machine. The SHA-NI
//! rounds are tested under Intel's Software Development Emulator in CI.

use std::sync::atomic::{AtomicU8, Ordering};

const SHA256_K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

pub(super) const SHA256_IV: [u32; 8] =
    [0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a, 0x510e_527f, 0x9b05_688c, 0x1f83_d9ab, 0x5be0_cd19];

#[cfg(test)]
thread_local! {
    /// Compressions run on this thread, for tests that check what a KDF charges.
    pub(super) static SHA256_COMPRESSIONS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// A SHA-256 compression function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Backend {
    /// Portable Rust.
    Scalar,
    /// The ARMv8 SHA2 instructions. Only made once they have been found on the processor.
    #[cfg(target_arch = "aarch64")]
    ArmSha2,
    /// The x86 SHA extensions (with SSSE3 and SSE4.1). Only made once they have been found on the processor.
    #[cfg(target_arch = "x86_64")]
    X86ShaNi,
}

impl Backend {
    /// Runs `blocks` through the compression function, in order.
    #[inline]
    fn compress(self, state: &mut [u32; 8], blocks: &[[u8; 64]]) {
        #[cfg(test)]
        SHA256_COMPRESSIONS.set(SHA256_COMPRESSIONS.get() + blocks.len() as u64);
        match self {
            Backend::Scalar => {
                for block in blocks {
                    compress_scalar(state, block);
                }
            }
            // SAFETY: an `ArmSha2` is only made once the instructions have been found
            #[cfg(target_arch = "aarch64")]
            Backend::ArmSha2 => {
                debug_assert!(std::arch::is_aarch64_feature_detected!("sha2"));
                unsafe { arm::compress(state, blocks) }
            }
            // SAFETY: an `X86ShaNi` is only made once the instructions have been found
            #[cfg(target_arch = "x86_64")]
            Backend::X86ShaNi => {
                debug_assert!(x86::usable());
                unsafe { x86::compress(state, blocks) }
            }
        }
    }

    fn name(self) -> &'static str {
        match self {
            Backend::Scalar => "scalar",
            #[cfg(target_arch = "aarch64")]
            Backend::ArmSha2 => "arm-sha2",
            #[cfg(target_arch = "x86_64")]
            Backend::X86ShaNi => "x86-sha-ni",
        }
    }

    /// Every backend this processor can run, the portable one first.
    #[cfg(test)]
    #[cfg_attr(not(any(target_arch = "aarch64", target_arch = "x86_64")), allow(unused_mut))]
    pub(super) fn available() -> Vec<Backend> {
        let mut all = vec![Backend::Scalar];
        #[cfg(target_arch = "aarch64")]
        if std::arch::is_aarch64_feature_detected!("sha2") {
            all.push(Backend::ArmSha2);
        }
        #[cfg(target_arch = "x86_64")]
        if x86::usable() {
            all.push(Backend::X86ShaNi);
        }
        all
    }

    /// The fastest backend this processor can run, unless the environment asks for the portable one.
    ///
    /// `ZIPFAST_SHA256=scalar` is read once, at the process's first hash; changing it later has no effect.
    fn detect() -> Backend {
        if std::env::var_os("ZIPFAST_SHA256").is_some_and(|v| v == "scalar") {
            return Backend::Scalar;
        }
        #[cfg(target_arch = "aarch64")]
        if std::arch::is_aarch64_feature_detected!("sha2") {
            return Backend::ArmSha2;
        }
        #[cfg(target_arch = "x86_64")]
        if x86::usable() {
            return Backend::X86ShaNi;
        }
        Backend::Scalar
    }

    /// The backend picked for this process: detected once, then cached.
    #[inline]
    fn current() -> Backend {
        static PICKED: AtomicU8 = AtomicU8::new(0);
        match PICKED.load(Ordering::Relaxed) {
            1 => Backend::Scalar,
            #[cfg(target_arch = "aarch64")]
            2 => Backend::ArmSha2,
            #[cfg(target_arch = "x86_64")]
            3 => Backend::X86ShaNi,
            _ => {
                let b = Backend::detect();
                let code = match b {
                    Backend::Scalar => 1,
                    #[cfg(target_arch = "aarch64")]
                    Backend::ArmSha2 => 2,
                    #[cfg(target_arch = "x86_64")]
                    Backend::X86ShaNi => 3,
                };
                PICKED.store(code, Ordering::Relaxed);
                b
            }
        }
    }
}

/// The name of the compression function this process uses: `"arm-sha2"`, `"x86-sha-ni"` or `"scalar"`.
#[doc(hidden)]
pub fn sha256_backend() -> &'static str {
    Backend::current().name()
}

/// Runs one block through the compression function this process uses.
#[inline]
pub(super) fn sha256_compress(state: &mut [u32; 8], block: &[u8; 64]) {
    Backend::current().compress(state, std::slice::from_ref(block));
}

fn compress_scalar(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for (i, chunk) in block.as_chunks::<4>().0.iter().enumerate() {
        w[i] = u32::from_be_bytes(*chunk);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(SHA256_K[i]).wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

#[cfg(target_arch = "aarch64")]
mod arm {
    use std::arch::aarch64::*;

    /// The round constants where the vector loads can reach them.
    static K: [u32; 64] = super::SHA256_K;

    /// Runs `blocks` through the compression function with the SHA2 instructions. `state` is held as ABCD and EFGH,
    /// the order they work in; each group of four rounds takes the next four schedule words plus their constants,
    /// and the schedule is extended four words at a time.
    ///
    /// # Safety
    ///
    /// The processor must have the SHA2 instructions.
    #[target_feature(enable = "sha2")]
    pub(super) unsafe fn compress(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
        // SAFETY: as the caller promises; every load and store is of 16 bytes inside `state`, `K` or a block
        unsafe {
            let mut abcd = vld1q_u32(state.as_ptr());
            let mut efgh = vld1q_u32(state.as_ptr().add(4));
            for block in blocks {
                let p = block.as_ptr();
                let mut m = [
                    vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p))),
                    vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p.add(16)))),
                    vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p.add(32)))),
                    vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p.add(48)))),
                ];
                let (abcd0, efgh0) = (abcd, efgh);
                for i in 0..16 {
                    let wk = vaddq_u32(m[i % 4], vld1q_u32(K.as_ptr().add(4 * i)));
                    let before = abcd;
                    abcd = vsha256hq_u32(abcd, efgh, wk);
                    efgh = vsha256h2q_u32(efgh, before, wk);
                    if i < 12 {
                        let partial = vsha256su0q_u32(m[i % 4], m[(i + 1) % 4]);
                        m[i % 4] = vsha256su1q_u32(partial, m[(i + 2) % 4], m[(i + 3) % 4]);
                    }
                }
                abcd = vaddq_u32(abcd, abcd0);
                efgh = vaddq_u32(efgh, efgh0);
            }
            vst1q_u32(state.as_mut_ptr(), abcd);
            vst1q_u32(state.as_mut_ptr().add(4), efgh);
        }
    }
}

#[cfg(target_arch = "x86_64")]
mod x86 {
    use std::arch::x86_64::*;

    /// The round constants where the vector loads can reach them.
    static K: [u32; 64] = super::SHA256_K;

    /// Whether the processor has the SHA extensions and the SSSE3 and SSE4.1 shuffles they are used with.
    pub(super) fn usable() -> bool {
        std::arch::is_x86_feature_detected!("sha")
            && std::arch::is_x86_feature_detected!("ssse3")
            && std::arch::is_x86_feature_detected!("sse4.1")
    }

    /// The next four schedule words from the previous sixteen, oldest first in `w`.
    #[inline]
    #[target_feature(enable = "sha,ssse3")]
    fn schedule(w: [__m128i; 4]) -> __m128i {
        let partial = _mm_sha256msg1_epu32(w[0], w[1]);
        // words t-7 .. t-4
        let middle = _mm_alignr_epi8::<4>(w[3], w[2]);
        _mm_sha256msg2_epu32(_mm_add_epi32(partial, middle), w[3])
    }

    /// Runs `blocks` through the compression function with SHA-NI. `sha256rnds2` works on the state as ABEF and
    /// CDGH and does two rounds per call, taking the two schedule-plus-constant words in the low half of its third
    /// operand; each group of four rounds takes the next four schedule words, extended four at a time.
    ///
    /// # Safety
    ///
    /// The processor must have the SHA extensions, SSSE3 and SSE4.1 (`usable`).
    #[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
    pub(super) unsafe fn compress(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
        // SAFETY: as the caller promises; every load and store is of 16 bytes inside `state`, `K` or a block
        unsafe {
            // big-endian words within each 32-bit lane
            let swap = _mm_set_epi64x(0x0c0d_0e0f_0809_0a0b, 0x0405_0607_0001_0203);
            let p = state.as_mut_ptr().cast::<__m128i>();
            let dcba = _mm_shuffle_epi32::<0xB1>(_mm_loadu_si128(p));
            let efgh = _mm_shuffle_epi32::<0x1B>(_mm_loadu_si128(p.add(1)));
            let mut abef = _mm_alignr_epi8::<8>(dcba, efgh);
            let mut cdgh = _mm_blend_epi16::<0xF0>(efgh, dcba);
            for block in blocks {
                let (abef0, cdgh0) = (abef, cdgh);
                let b = block.as_ptr().cast::<__m128i>();
                let mut w = [
                    _mm_shuffle_epi8(_mm_loadu_si128(b), swap),
                    _mm_shuffle_epi8(_mm_loadu_si128(b.add(1)), swap),
                    _mm_shuffle_epi8(_mm_loadu_si128(b.add(2)), swap),
                    _mm_shuffle_epi8(_mm_loadu_si128(b.add(3)), swap),
                ];
                for i in 0..16 {
                    if i >= 4 {
                        // `w[i % 4]` holds the oldest four words: replace them with the next four
                        let next = schedule([w[i % 4], w[(i + 1) % 4], w[(i + 2) % 4], w[(i + 3) % 4]]);
                        w[i % 4] = next;
                    }
                    let wk = _mm_add_epi32(w[i % 4], _mm_loadu_si128(K.as_ptr().add(4 * i).cast()));
                    cdgh = _mm_sha256rnds2_epu32(cdgh, abef, wk);
                    abef = _mm_sha256rnds2_epu32(abef, cdgh, _mm_shuffle_epi32::<0x0E>(wk));
                }
                abef = _mm_add_epi32(abef, abef0);
                cdgh = _mm_add_epi32(cdgh, cdgh0);
            }
            let feba = _mm_shuffle_epi32::<0x1B>(abef);
            let dchg = _mm_shuffle_epi32::<0xB1>(cdgh);
            _mm_storeu_si128(p, _mm_blend_epi16::<0xF0>(feba, dchg));
            _mm_storeu_si128(p.add(1), _mm_alignr_epi8::<8>(dchg, feba));
        }
    }
}

/// SHA-256 over bytes given in pieces.
///
/// ```
/// use std::io::Write;
/// use zipfast::crypto::{Sha256, sha256};
///
/// let mut h = Sha256::new();
/// h.update(b"ab");
/// h.write_all(b"c").unwrap();
/// assert_eq!(h.finalize(), sha256(b"abc"));
/// ```
#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    /// bytes taken in that do not yet fill a block
    buf: [u8; 64],
    buf_len: usize,
    /// how many bytes have been taken in, modulo 2^64
    len: u64,
    backend: Backend,
}

impl Default for Sha256 {
    fn default() -> Self {
        Sha256::new()
    }
}

impl std::fmt::Debug for Sha256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sha256").field("len", &self.len).finish_non_exhaustive()
    }
}

impl Sha256 {
    /// A hasher that has taken in nothing.
    pub fn new() -> Self {
        Sha256::with_backend(Backend::current())
    }

    pub(super) fn with_backend(backend: Backend) -> Self {
        Sha256 { state: SHA256_IV, buf: [0; 64], buf_len: 0, len: 0, backend }
    }

    /// Takes in `bytes` after everything taken in so far.
    pub fn update(&mut self, mut bytes: &[u8]) {
        self.len = self.len.wrapping_add(bytes.len() as u64);
        if self.buf_len > 0 {
            let take = (64 - self.buf_len).min(bytes.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&bytes[..take]);
            self.buf_len += take;
            bytes = &bytes[take..];
            if self.buf_len < 64 {
                return;
            }
            self.backend.compress(&mut self.state, std::slice::from_ref(&self.buf));
            self.buf_len = 0;
        }
        let (blocks, rest) = bytes.as_chunks::<64>();
        if !blocks.is_empty() {
            self.backend.compress(&mut self.state, blocks);
        }
        self.buf[..rest.len()].copy_from_slice(rest);
        self.buf_len = rest.len();
    }

    /// The digest of everything taken in.
    pub fn finalize(self) -> [u8; 32] {
        let mut state = self.state;
        let mut tail = [0u8; 128];
        tail[..self.buf_len].copy_from_slice(&self.buf[..self.buf_len]);
        tail[self.buf_len] = 0x80;
        let blocks = if self.buf_len < 56 { 1 } else { 2 };
        tail[blocks * 64 - 8..blocks * 64].copy_from_slice(&self.len.wrapping_mul(8).to_be_bytes());
        self.backend.compress(&mut state, &tail.as_chunks::<64>().0[..blocks]);
        let mut out = [0u8; 32];
        for (i, word) in state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

impl std::io::Write for Sha256 {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.update(bytes);
        Ok(bytes.len())
    }

    fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.update(bytes);
        Ok(())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Computes SHA-256 over `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn hex(d: [u8; 32]) -> String {
        d.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// FIPS 180-4 / NIST CAVP example messages and their digests.
    const NIST: [(&[u8], &str); 4] = [
        (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
        (
            b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
        ),
    ];
    const MILLION_A: &str = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";

    fn digest(backend: Backend, data: &[u8]) -> [u8; 32] {
        let mut h = Sha256::with_backend(backend);
        h.update(data);
        h.finalize()
    }

    fn bytes(n: usize, seed: u64) -> Vec<u8> {
        let mut x = seed | 1;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 32) as u8
            })
            .collect()
    }

    #[test]
    fn every_backend_matches_the_nist_vectors() {
        for backend in Backend::available() {
            for (msg, want) in NIST {
                assert_eq!(hex(digest(backend, msg)), want, "{backend:?} {msg:?}");
            }
            assert_eq!(hex(digest(backend, &vec![b'a'; 1_000_000])), MILLION_A, "{backend:?}");
            let mut h = Sha256::with_backend(backend);
            for _ in 0..1000 {
                h.update(&[b'a'; 1000]);
            }
            assert_eq!(hex(h.finalize()), MILLION_A, "{backend:?} in thousand-byte pieces");
            let mut h = Sha256::with_backend(backend);
            let mut left = 1_000_000;
            for step in [1usize, 63, 64, 65, 127, 4097].iter().cycle() {
                let n = (*step).min(left);
                h.update(&vec![b'a'; n]);
                left -= n;
                if left == 0 {
                    break;
                }
            }
            assert_eq!(hex(h.finalize()), MILLION_A, "{backend:?} in odd pieces");
        }
    }

    #[test]
    fn the_public_functions_match_the_nist_vectors() {
        for (msg, want) in NIST {
            assert_eq!(hex(sha256(msg)), want);
            let mut h = Sha256::default();
            h.write_all(msg).unwrap();
            h.flush().unwrap();
            assert_eq!(hex(h.finalize()), want);
        }
        let mut h = Sha256::new();
        std::io::copy(&mut std::io::repeat(b'a').take(1_000_000), &mut h).unwrap();
        assert_eq!(hex(h.finalize()), MILLION_A);
    }

    #[test]
    fn every_backend_agrees_with_the_scalar_one_at_random_splits() {
        let data = bytes(20_000, 0x9e37_79b9_7f4a_7c15);
        let mut rng = 0x2545_f491_4f6c_dd1du64;
        let mut next = |bound: usize| {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            (rng % (bound as u64 + 1)) as usize
        };
        let lengths = (0..300).chain([447, 448, 511, 512, 513, 4095, 4096, 4097, 20_000]);
        for len in lengths {
            let d = &data[..len];
            let want = digest(Backend::Scalar, d);
            for backend in Backend::available() {
                assert_eq!(digest(backend, d), want, "{backend:?} len {len}");
                for _ in 0..4 {
                    let mut h = Sha256::with_backend(backend);
                    let mut at = 0;
                    while at < len {
                        let n = next(len - at).min(next(200).max(1));
                        h.update(&d[at..at + n]);
                        h.update(&[]);
                        at += n;
                    }
                    let copy = h.clone();
                    assert_eq!(h.finalize(), want, "{backend:?} len {len}");
                    assert_eq!(copy.finalize(), want, "{backend:?} len {len} (clone)");
                }
            }
        }
    }

    #[test]
    fn every_backend_compresses_runs_of_blocks_like_the_scalar_one() {
        let data = bytes(64 * 9, 7);
        let blocks = data.as_chunks::<64>().0;
        for start in [SHA256_IV, [0; 8], [u32::MAX; 8], [1, 2, 3, 4, 5, 6, 7, 8]] {
            for n in 0..=blocks.len() {
                let mut want = start;
                Backend::Scalar.compress(&mut want, &blocks[..n]);
                for backend in Backend::available() {
                    let mut got = start;
                    backend.compress(&mut got, &blocks[..n]);
                    assert_eq!(got, want, "{backend:?} {n} blocks");
                }
            }
        }
    }

    #[test]
    fn a_clone_continues_independently() {
        let mut a = Sha256::new();
        a.update(b"ab");
        let mut b = a.clone();
        a.update(b"c");
        b.update(b"d");
        assert_eq!(a.finalize(), sha256(b"abc"));
        assert_eq!(b.finalize(), sha256(b"abd"));
    }

    #[test]
    fn the_hardware_backend_is_picked_where_the_processor_has_it() {
        let forced = std::env::var_os("ZIPFAST_SHA256").is_some_and(|v| v == "scalar");
        let want = if forced { Backend::Scalar } else { *Backend::available().last().unwrap() };
        assert_eq!(sha256_backend(), want.name());
    }
}
