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

//! AES rounds in hardware: the ARMv8 AES instructions or x86 AES-NI, picked at run time.
//!
//! Both take the encryption round keys `ek[0..=n]` and the equivalent-inverse-cipher keys `dk`, where `dk[0] = ek[n]`,
//! `dk[i] = InvMixColumns(ek[n - i])` for `0 < i < n` and `dk[n] = ek[0]` (FIPS 197 section 5.3.5). CBC decryption
//! has no chain between blocks, so it runs eight blocks at once to keep the AES units busy.

use std::sync::atomic::{AtomicU8, Ordering};

/// An AES round implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Backend {
    /// Portable Rust tables.
    Scalar,
    /// The ARMv8 AES instructions. Only made once they have been found on the processor.
    #[cfg(target_arch = "aarch64")]
    ArmAes,
    /// x86 AES-NI (with SSE2). Only made once it has been found on the processor.
    #[cfg(target_arch = "x86_64")]
    X86AesNi,
}

impl Backend {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Backend::Scalar => "scalar",
            #[cfg(target_arch = "aarch64")]
            Backend::ArmAes => "arm-aes",
            #[cfg(target_arch = "x86_64")]
            Backend::X86AesNi => "x86-aes-ni",
        }
    }

    /// Every backend this processor can run, the portable one first.
    #[cfg(test)]
    #[cfg_attr(not(any(target_arch = "aarch64", target_arch = "x86_64")), allow(unused_mut))]
    pub(crate) fn available() -> Vec<Backend> {
        let mut all = vec![Backend::Scalar];
        #[cfg(target_arch = "aarch64")]
        if std::arch::is_aarch64_feature_detected!("aes") {
            all.push(Backend::ArmAes);
        }
        #[cfg(target_arch = "x86_64")]
        if x86::usable() {
            all.push(Backend::X86AesNi);
        }
        all
    }

    /// The fastest backend this processor can run, unless `ZIPFAST_AES=scalar` asks for the portable one.
    fn detect() -> Backend {
        if std::env::var_os("ZIPFAST_AES").is_some_and(|v| v == "scalar") {
            return Backend::Scalar;
        }
        #[cfg(target_arch = "aarch64")]
        if std::arch::is_aarch64_feature_detected!("aes") {
            return Backend::ArmAes;
        }
        #[cfg(target_arch = "x86_64")]
        if x86::usable() {
            return Backend::X86AesNi;
        }
        Backend::Scalar
    }

    /// The backend picked for this process: detected once (the environment is read then), then cached.
    pub(crate) fn current() -> Backend {
        static PICKED: AtomicU8 = AtomicU8::new(0);
        match PICKED.load(Ordering::Relaxed) {
            1 => Backend::Scalar,
            #[cfg(target_arch = "aarch64")]
            2 => Backend::ArmAes,
            #[cfg(target_arch = "x86_64")]
            3 => Backend::X86AesNi,
            _ => {
                let b = Backend::detect();
                let code = match b {
                    Backend::Scalar => 1,
                    #[cfg(target_arch = "aarch64")]
                    Backend::ArmAes => 2,
                    #[cfg(target_arch = "x86_64")]
                    Backend::X86AesNi => 3,
                };
                PICKED.store(code, Ordering::Relaxed);
                b
            }
        }
    }
}

#[cfg(target_arch = "aarch64")]
pub(crate) mod arm {
    use std::arch::aarch64::*;

    /// Encrypts one block with the `rounds + 1` keys of `ek`.
    ///
    /// # Safety
    ///
    /// The processor must have the AES instructions.
    #[target_feature(enable = "aes")]
    pub(crate) unsafe fn encrypt(ek: &[[u8; 16]; 15], rounds: usize, block: &[u8; 16]) -> [u8; 16] {
        // SAFETY: as the caller promises; every load and store is of 16 bytes inside a key or block
        unsafe {
            let mut s = vld1q_u8(block.as_ptr());
            for k in &ek[..rounds - 1] {
                s = vaesmcq_u8(vaeseq_u8(s, vld1q_u8(k.as_ptr())));
            }
            s = vaeseq_u8(s, vld1q_u8(ek[rounds - 1].as_ptr()));
            s = veorq_u8(s, vld1q_u8(ek[rounds].as_ptr()));
            let mut out = [0u8; 16];
            vst1q_u8(out.as_mut_ptr(), s);
            out
        }
    }

    /// Decrypts one block with the equivalent-inverse-cipher keys `dk`.
    ///
    /// # Safety
    ///
    /// The processor must have the AES instructions.
    #[target_feature(enable = "aes")]
    pub(crate) unsafe fn decrypt(dk: &[[u8; 16]; 15], rounds: usize, block: &[u8; 16]) -> [u8; 16] {
        // SAFETY: as the caller promises; every load and store is of 16 bytes inside a key or block
        unsafe {
            let mut s = vld1q_u8(block.as_ptr());
            for k in &dk[..rounds - 1] {
                s = vaesimcq_u8(vaesdq_u8(s, vld1q_u8(k.as_ptr())));
            }
            s = vaesdq_u8(s, vld1q_u8(dk[rounds - 1].as_ptr()));
            s = veorq_u8(s, vld1q_u8(dk[rounds].as_ptr()));
            let mut out = [0u8; 16];
            vst1q_u8(out.as_mut_ptr(), s);
            out
        }
    }

    /// Decrypts whole 16-byte blocks of `data` in CBC mode in place; `iv` becomes the last ciphertext block.
    ///
    /// # Safety
    ///
    /// The processor must have the AES instructions.
    #[target_feature(enable = "aes")]
    pub(crate) unsafe fn decrypt_cbc(dk: &[[u8; 16]; 15], rounds: usize, iv: &mut [u8; 16], data: &mut [u8]) {
        const LANES: usize = 8;
        // SAFETY: as the caller promises; every load and store is of 16 bytes inside a key, `iv` or a whole block
        // of `data`, and each group's ciphertext is loaded before any of its plaintext is stored
        unsafe {
            let mut keys = [vdupq_n_u8(0); 15];
            for (k, bytes) in keys.iter_mut().zip(&dk[..=rounds]) {
                *k = vld1q_u8(bytes.as_ptr());
            }
            let mut prev = vld1q_u8(iv.as_ptr());
            let blocks = data.as_chunks_mut::<16>().0;
            let (groups, rest) = blocks.as_chunks_mut::<LANES>();
            for group in groups {
                let ct: [uint8x16_t; LANES] = std::array::from_fn(|i| vld1q_u8(group[i].as_ptr()));
                let mut s = ct;
                for k in &keys[..rounds - 1] {
                    for x in &mut s {
                        *x = vaesimcq_u8(vaesdq_u8(*x, *k));
                    }
                }
                for (i, x) in s.iter_mut().enumerate() {
                    let chain = if i == 0 { prev } else { ct[i - 1] };
                    *x = veorq_u8(veorq_u8(vaesdq_u8(*x, keys[rounds - 1]), keys[rounds]), chain);
                    vst1q_u8(group[i].as_mut_ptr(), *x);
                }
                prev = ct[LANES - 1];
            }
            for block in rest {
                let ct = vld1q_u8(block.as_ptr());
                let mut s = ct;
                for k in &keys[..rounds - 1] {
                    s = vaesimcq_u8(vaesdq_u8(s, *k));
                }
                s = veorq_u8(veorq_u8(vaesdq_u8(s, keys[rounds - 1]), keys[rounds]), prev);
                vst1q_u8(block.as_mut_ptr(), s);
                prev = ct;
            }
            vst1q_u8(iv.as_mut_ptr(), prev);
        }
    }
}

#[cfg(target_arch = "x86_64")]
pub(crate) mod x86 {
    use std::arch::x86_64::*;

    /// Whether the processor has AES-NI and the SSE2 loads it is used with.
    pub(crate) fn usable() -> bool {
        std::arch::is_x86_feature_detected!("aes") && std::arch::is_x86_feature_detected!("sse2")
    }

    #[inline]
    #[target_feature(enable = "sse2")]
    fn load(bytes: &[u8; 16]) -> __m128i {
        // SAFETY: an unaligned load of 16 bytes from a 16-byte array
        unsafe { _mm_loadu_si128(bytes.as_ptr().cast()) }
    }

    #[inline]
    #[target_feature(enable = "sse2")]
    fn store(bytes: &mut [u8; 16], v: __m128i) {
        // SAFETY: an unaligned store of 16 bytes into a 16-byte array
        unsafe { _mm_storeu_si128(bytes.as_mut_ptr().cast(), v) }
    }

    /// Encrypts one block with the `rounds + 1` keys of `ek`.
    ///
    /// # Safety
    ///
    /// The processor must have AES-NI and SSE2.
    #[target_feature(enable = "aes,sse2")]
    pub(crate) unsafe fn encrypt(ek: &[[u8; 16]; 15], rounds: usize, block: &[u8; 16]) -> [u8; 16] {
        let mut s = _mm_xor_si128(load(block), load(&ek[0]));
        for k in &ek[1..rounds] {
            s = _mm_aesenc_si128(s, load(k));
        }
        s = _mm_aesenclast_si128(s, load(&ek[rounds]));
        let mut out = [0u8; 16];
        store(&mut out, s);
        out
    }

    /// Decrypts one block with the equivalent-inverse-cipher keys `dk`.
    ///
    /// # Safety
    ///
    /// The processor must have AES-NI and SSE2.
    #[target_feature(enable = "aes,sse2")]
    pub(crate) unsafe fn decrypt(dk: &[[u8; 16]; 15], rounds: usize, block: &[u8; 16]) -> [u8; 16] {
        let mut s = _mm_xor_si128(load(block), load(&dk[0]));
        for k in &dk[1..rounds] {
            s = _mm_aesdec_si128(s, load(k));
        }
        s = _mm_aesdeclast_si128(s, load(&dk[rounds]));
        let mut out = [0u8; 16];
        store(&mut out, s);
        out
    }

    /// Decrypts whole 16-byte blocks of `data` in CBC mode in place; `iv` becomes the last ciphertext block.
    ///
    /// # Safety
    ///
    /// The processor must have AES-NI and SSE2.
    #[target_feature(enable = "aes,sse2")]
    pub(crate) unsafe fn decrypt_cbc(dk: &[[u8; 16]; 15], rounds: usize, iv: &mut [u8; 16], data: &mut [u8]) {
        const LANES: usize = 8;
        let keys: [__m128i; 15] = std::array::from_fn(|i| load(&dk[i]));
        let mut prev = load(iv);
        let blocks = data.as_chunks_mut::<16>().0;
        let (groups, rest) = blocks.as_chunks_mut::<LANES>();
        for group in groups {
            // every group's ciphertext is loaded before any of its plaintext is stored
            let ct: [__m128i; LANES] = std::array::from_fn(|i| load(&group[i]));
            let mut s: [__m128i; LANES] = std::array::from_fn(|i| _mm_xor_si128(ct[i], keys[0]));
            for k in &keys[1..rounds] {
                for x in &mut s {
                    *x = _mm_aesdec_si128(*x, *k);
                }
            }
            for (i, x) in s.iter_mut().enumerate() {
                let chain = if i == 0 { prev } else { ct[i - 1] };
                *x = _mm_xor_si128(_mm_aesdeclast_si128(*x, keys[rounds]), chain);
                store(&mut group[i], *x);
            }
            prev = ct[LANES - 1];
        }
        for block in rest {
            let ct = load(block);
            let mut s = _mm_xor_si128(ct, keys[0]);
            for k in &keys[1..rounds] {
                s = _mm_aesdec_si128(s, *k);
            }
            s = _mm_xor_si128(_mm_aesdeclast_si128(s, keys[rounds]), prev);
            store(block, s);
            prev = ct;
        }
        store(iv, prev);
    }
}
