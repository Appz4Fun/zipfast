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

//! Pure-Rust cryptographic primitives for archive password verification and decryption:
//! - FIPS 197 AES-128, AES-192, and AES-256 (CBC and WinZip CTR modes), with the ARMv8 AES instructions or x86
//!   AES-NI where the processor has them (picked at run time; `ZIPFAST_AES=scalar` forces the portable rounds)
//! - FIPS 180-4 SHA-256, one-shot ([`sha256`]) or incremental ([`Sha256`]), with the ARMv8 SHA2 instructions where
//!   the processor has them; the 7zAES and RAR 5.0 KDFs use the same rounds
//! - RAR 5.0 PBKDF2-HMAC-SHA256 key derivation, `PasswordCheck` verification, tweaked CRC32, and `-hp` header decryption
//! - RAR 4.x (`SetKey30`) SHA-1 key/IV derivation and `-hp` header decryption
//! - ZIP traditional PKWARE stream cipher (ZipCrypto) and WinZip AES (`0x9901`) PBKDF2-HMAC-SHA1 decryption

/// AES-128 (10 rounds), AES-192 (12 rounds), or AES-256 (14 rounds) expanded round keys.
#[derive(Clone, Copy)]
pub struct AesKey {
    enc_rk: [[u8; 16]; 15],
    /// The equivalent-inverse-cipher keys the hardware decryption rounds take (see [`aes_hw`]).
    dec_rk: [[u8; 16]; 15],
    rounds: usize,
    backend: aes_hw::Backend,
}

mod aes_hw;

/// The name of the AES implementation this process uses: `"arm-aes"`, `"x86-aes-ni"` or `"scalar"`.
/// `ZIPFAST_AES=scalar`, read once at the first key, forces the portable one.
#[doc(hidden)]
pub fn aes_backend() -> &'static str {
    aes_hw::Backend::current().name()
}

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9,
    0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f,
    0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07,
    0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3,
    0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58,
    0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3,
    0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f,
    0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac,
    0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a,
    0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
    0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42,
    0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39,
    0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2,
    0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76,
    0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc,
    0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d,
    0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c,
    0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f,
    0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
    0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62,
    0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd,
    0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60,
    0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6,
    0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

const RCON: [u32; 10] = [
    0x0100_0000,
    0x0200_0000,
    0x0400_0000,
    0x0800_0000,
    0x1000_0000,
    0x2000_0000,
    0x4000_0000,
    0x8000_0000,
    0x1b00_0000,
    0x3600_0000,
];

fn sub_word(w: u32) -> u32 {
    let [b0, b1, b2, b3] = w.to_be_bytes();
    u32::from_be_bytes([SBOX[usize::from(b0)], SBOX[usize::from(b1)], SBOX[usize::from(b2)], SBOX[usize::from(b3)]])
}

#[inline]
fn xtime(x: u8) -> u8 {
    (x << 1) ^ if x & 0x80 != 0 { 0x1b } else { 0 }
}

#[inline]
fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        a = xtime(a);
        b >>= 1;
    }
    p
}

fn inv_mix_columns(s: &mut [u8; 16]) {
    for col in s.as_chunks_mut::<4>().0 {
        let (s0, s1, s2, s3) = (col[0], col[1], col[2], col[3]);
        col[0] = gmul(s0, 0x0e) ^ gmul(s1, 0x0b) ^ gmul(s2, 0x0d) ^ gmul(s3, 0x09);
        col[1] = gmul(s0, 0x09) ^ gmul(s1, 0x0e) ^ gmul(s2, 0x0b) ^ gmul(s3, 0x0d);
        col[2] = gmul(s0, 0x0d) ^ gmul(s1, 0x09) ^ gmul(s2, 0x0e) ^ gmul(s3, 0x0b);
        col[3] = gmul(s0, 0x0b) ^ gmul(s1, 0x0d) ^ gmul(s2, 0x09) ^ gmul(s3, 0x0e);
    }
}

impl AesKey {
    pub fn new(key: &[u8]) -> Option<Self> {
        let (nk, nr) = match key.len() {
            16 => (4usize, 10usize),
            24 => (6usize, 12usize),
            32 => (8usize, 14usize),
            _ => return None,
        };
        let total_words = 4 * (nr + 1);
        let mut w = [0u32; 60];
        for (i, chunk) in key.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*chunk);
        }
        for i in nk..total_words {
            let mut temp = w[i - 1];
            if i % nk == 0 {
                temp = sub_word(temp.rotate_left(8)) ^ RCON[i / nk - 1];
            } else if nk > 6 && i % nk == 4 {
                temp = sub_word(temp);
            }
            w[i] = w[i - nk] ^ temp;
        }
        let mut enc_rk = [[0u8; 16]; 15];
        for r in 0..=nr {
            for c in 0..4 {
                enc_rk[r][c * 4..c * 4 + 4].copy_from_slice(&w[r * 4 + c].to_be_bytes());
            }
        }
        let mut dec_rk = [[0u8; 16]; 15];
        dec_rk[0] = enc_rk[nr];
        for i in 1..nr {
            dec_rk[i] = enc_rk[nr - i];
            inv_mix_columns(&mut dec_rk[i]);
        }
        dec_rk[nr] = enc_rk[0];
        Some(Self { enc_rk, dec_rk, rounds: nr, backend: aes_hw::Backend::current() })
    }

    /// The same key run by `backend` (tests compare every backend the processor has).
    #[cfg(test)]
    pub(crate) fn with_backend(mut self, backend: aes_hw::Backend) -> Self {
        self.backend = backend;
        self
    }

    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        match self.backend {
            aes_hw::Backend::Scalar => self.encrypt_scalar(block),
            // SAFETY: an `ArmAes` is only made once the instructions have been found
            #[cfg(target_arch = "aarch64")]
            aes_hw::Backend::ArmAes => unsafe { aes_hw::arm::encrypt(&self.enc_rk, self.rounds, block) },
            // SAFETY: an `X86AesNi` is only made once the instructions have been found
            #[cfg(target_arch = "x86_64")]
            aes_hw::Backend::X86AesNi => unsafe { aes_hw::x86::encrypt(&self.enc_rk, self.rounds, block) },
        }
    }

    pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        match self.backend {
            aes_hw::Backend::Scalar => self.decrypt_scalar(block),
            // SAFETY: an `ArmAes` is only made once the instructions have been found
            #[cfg(target_arch = "aarch64")]
            aes_hw::Backend::ArmAes => unsafe { aes_hw::arm::decrypt(&self.dec_rk, self.rounds, block) },
            // SAFETY: an `X86AesNi` is only made once the instructions have been found
            #[cfg(target_arch = "x86_64")]
            aes_hw::Backend::X86AesNi => unsafe { aes_hw::x86::decrypt(&self.dec_rk, self.rounds, block) },
        }
    }

    fn encrypt_scalar(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut s = *block;
        for (b, &k) in s.iter_mut().zip(&self.enc_rk[0]) {
            *b ^= k;
        }
        for round_key in self.enc_rk.iter().take(self.rounds).skip(1) {
            for b in &mut s {
                *b = SBOX[usize::from(*b)];
            }
            s = [s[0], s[5], s[10], s[15], s[4], s[9], s[14], s[3], s[8], s[13], s[2], s[7], s[12], s[1], s[6], s[11]];
            for col in s.as_chunks_mut::<4>().0 {
                let (s0, s1, s2, s3) = (col[0], col[1], col[2], col[3]);
                let t = s0 ^ s1 ^ s2 ^ s3;
                col[0] ^= t ^ xtime(s0 ^ s1);
                col[1] ^= t ^ xtime(s1 ^ s2);
                col[2] ^= t ^ xtime(s2 ^ s3);
                col[3] ^= t ^ xtime(s3 ^ s0);
            }
            for (b, &k) in s.iter_mut().zip(round_key) {
                *b ^= k;
            }
        }
        for b in &mut s {
            *b = SBOX[usize::from(*b)];
        }
        s = [s[0], s[5], s[10], s[15], s[4], s[9], s[14], s[3], s[8], s[13], s[2], s[7], s[12], s[1], s[6], s[11]];
        for (b, &k) in s.iter_mut().zip(&self.enc_rk[self.rounds]) {
            *b ^= k;
        }
        s
    }

    fn decrypt_scalar(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut s = *block;
        for (b, &k) in s.iter_mut().zip(&self.enc_rk[self.rounds]) {
            *b ^= k;
        }
        for round in (1..self.rounds).rev() {
            s = [s[0], s[13], s[10], s[7], s[4], s[1], s[14], s[11], s[8], s[5], s[2], s[15], s[12], s[9], s[6], s[3]];
            for b in &mut s {
                *b = INV_SBOX[usize::from(*b)];
            }
            for (b, &k) in s.iter_mut().zip(&self.enc_rk[round]) {
                *b ^= k;
            }
            inv_mix_columns(&mut s);
        }
        s = [s[0], s[13], s[10], s[7], s[4], s[1], s[14], s[11], s[8], s[5], s[2], s[15], s[12], s[9], s[6], s[3]];
        for b in &mut s {
            *b = INV_SBOX[usize::from(*b)];
        }
        for (b, &k) in s.iter_mut().zip(&self.enc_rk[0]) {
            *b ^= k;
        }
        s
    }

    /// Decrypts 16-byte aligned blocks in place using AES-CBC and updates `iv` to the last ciphertext block.
    pub fn decrypt_cbc_in_place(&self, iv: &mut [u8; 16], data: &mut [u8]) {
        match self.backend {
            aes_hw::Backend::Scalar => {}
            // SAFETY: an `ArmAes` is only made once the instructions have been found
            #[cfg(target_arch = "aarch64")]
            aes_hw::Backend::ArmAes => return unsafe { aes_hw::arm::decrypt_cbc(&self.dec_rk, self.rounds, iv, data) },
            // SAFETY: an `X86AesNi` is only made once the instructions have been found
            #[cfg(target_arch = "x86_64")]
            aes_hw::Backend::X86AesNi => {
                return unsafe { aes_hw::x86::decrypt_cbc(&self.dec_rk, self.rounds, iv, data) };
            }
        }
        for chunk in data.as_chunks_mut::<16>().0 {
            let ct = *chunk;
            let mut plain = self.decrypt_block(&ct);
            for (p, &iv_b) in plain.iter_mut().zip(&*iv) {
                *p ^= iv_b;
            }
            *chunk = plain;
            *iv = ct;
        }
    }
}

/// Decrypts AES-CBC ciphertext (`key` is 16, 24, or 32 bytes; `iv` is 16 bytes).
/// Trailing bytes that do not form a complete 16-byte block are ignored.
pub fn decrypt_cbc(key: &[u8], iv: &[u8; 16], data: &[u8]) -> Option<Vec<u8>> {
    let cipher = AesKey::new(key)?;
    let n = (data.len() / 16) * 16;
    if n == 0 {
        return Some(Vec::new());
    }
    let mut out = data.get(..n)?.to_vec();
    cipher.decrypt_cbc_in_place(&mut iv.clone(), &mut out);
    Some(out)
}

/// Why [`rebuild_cbc`] refused or rejected a rebuild.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CbcRebuildError {
    /// The key is not 16, 24 or 32 bytes.
    KeyLength,
    /// The plaintext is not a whole number of 16-byte blocks and does not end the stream.
    Unaligned,
    /// The intact ciphertext given to check against does not overlap the rebuilt range.
    NoOverlap,
    /// The rebuilt ciphertext differs from the intact ciphertext at this byte of the rebuilt range: the key, the
    /// plaintext or the previous ciphertext block is wrong.
    Mismatch { at: usize },
    /// The stream ends in a partial block whose padding is not known. RAR 5.0 fills it with random bytes, so zero
    /// padding would rebuild the wrong last block. Rebuild the whole blocks before it (pass them with `stream_end`
    /// false), then the last one with [`rebuild_final_block`] or from another source of its padding.
    FinalPadding { pad: usize },
}

impl std::fmt::Display for CbcRebuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyLength => f.write_str("AES key is not 16, 24 or 32 bytes"),
            Self::Unaligned => f.write_str("plaintext is not whole AES blocks and does not end the stream"),
            Self::NoOverlap => f.write_str("intact ciphertext does not overlap the rebuilt range"),
            Self::Mismatch { at } => write!(f, "rebuilt ciphertext differs from the intact ciphertext at byte {at}"),
            Self::FinalPadding { pad } => {
                write!(f, "the final block's {pad} padding bytes are not known (RAR 5.0 pads with random bytes)")
            }
        }
    }
}

impl std::error::Error for CbcRebuildError {}

/// Rebuilds the exact AES-CBC ciphertext of an encrypted stored member for a range of its plaintext, so a range
/// lost from the archive can be written back from plaintext supplied by another copy.
///
/// * `key`: the member's AES key: [`derive_rar5_key`] for RAR 5.0 (salt and count from [`rar5_record_params`] of
///   the file's encryption record), [`derive_7z_key`] for 7z AES, [`derive_rar4_key_iv`] for RAR 3.x/4.x.
/// * `previous`: the 16 ciphertext bytes just before the range, or the IV when the range starts the stream (RAR 5.0:
///   the file header's IV; 7z: the folder's IV, one per folder; RAR 3.x/4.x: the IV derived with the key).
/// * `plaintext`: the stream's plaintext from a 16-byte-aligned offset. The stream is a RAR member's packed data
///   across all its volumes' data areas taken together (a volume's part is rarely a multiple of 16 bytes, so blocks
///   and the previous 16 bytes can straddle a volume boundary), or a 7z folder's unpacked stream (several files in a
///   solid stored folder share one stream). For a stored member it is the output. [`cbc_rebuild_span`] turns a hole
///   into the aligned range to rebuild.
/// * `stream_end`: whether the range runs to the end of the stream (the RAR member, the 7z folder). Its last partial
///   block is then padded with zero bytes before encryption, as rar 7.30 (RAR 5.0) and 7-Zip write it; otherwise
///   `plaintext` must be whole blocks. (RAR 3.x/4.x padding could not be checked against rar, which no longer writes
///   that format.)
/// * `intact`: optionally `(offset, ciphertext)`: archive bytes that survive at `offset` within the rebuilt range.
///   The overlap must match. CBC makes a block depend only on the plaintext up to it, so a match proves the key, the
///   previous bytes and the plaintext up to the overlap: give bytes at or after the hole's end (the first intact
///   block after it), whose plaintext `plaintext` must include. A range that ends the stream has nothing after it to
///   check.
pub fn rebuild_cbc(
    key: &[u8],
    previous: &[u8; 16],
    plaintext: &[u8],
    stream_end: bool,
    intact: Option<(usize, &[u8])>,
) -> Result<Vec<u8>, CbcRebuildError> {
    let rem = plaintext.len() % 16;
    if rem != 0 && stream_end {
        // RAR 5.0 pads the last block with random bytes, which cannot be rebuilt from the plaintext.
        return Err(CbcRebuildError::FinalPadding { pad: 16 - rem });
    }
    rebuild_blocks(key, previous, plaintext, stream_end, intact)
}

/// [`rebuild_cbc`] for a stream whose final partial block is padded with zero bytes, as 7-Zip writes it (7z AES).
/// Do not use it for RAR 5.0: rar pads with random bytes.
pub fn rebuild_cbc_zero_padded(
    key: &[u8],
    previous: &[u8; 16],
    plaintext: &[u8],
    stream_end: bool,
    intact: Option<(usize, &[u8])>,
) -> Result<Vec<u8>, CbcRebuildError> {
    rebuild_blocks(key, previous, plaintext, stream_end, intact)
}

/// Rebuilds a stream's final partial block from its plaintext, when its padding is known to be one of `pad` bytes
/// chosen freely (RAR 5.0's random padding, up to 3 bytes), by trying every padding value until `accept` takes the
/// block's ciphertext (16 bytes). Use it with a check the rest of the stream gives, such as a CRC32 of the whole
/// article computed over the rebuilt blocks before it and this block. Returns the 16-byte block, or None when no
/// padding value is accepted or `pad` is 0 or more than 3 (2^24 tries is the most this is for).
pub fn rebuild_final_block(
    key: &[u8],
    previous: &[u8; 16],
    partial: &[u8],
    mut accept: impl FnMut(&[u8; 16]) -> bool,
) -> Option<[u8; 16]> {
    let rem = partial.len();
    if !(1..16).contains(&rem) {
        return None;
    }
    let pad = 16 - rem;
    if pad > 3 {
        return None;
    }
    let cipher = AesKey::new(key)?;
    let tries = 1u32 << (8 * pad);
    for v in 0..tries {
        let mut block = [0u8; 16];
        block[..rem].copy_from_slice(partial);
        // the padding counts up, most significant byte first
        for (i, b) in block[rem..].iter_mut().enumerate() {
            *b = (v >> (8 * (pad - 1 - i))) as u8;
        }
        let mut x = block;
        for (b, &p) in x.iter_mut().zip(previous) {
            *b ^= p;
        }
        let enc = cipher.encrypt_block(&x);
        if accept(&enc) {
            return Some(enc);
        }
    }
    None
}

fn rebuild_blocks(
    key: &[u8],
    previous: &[u8; 16],
    plaintext: &[u8],
    stream_end: bool,
    intact: Option<(usize, &[u8])>,
) -> Result<Vec<u8>, CbcRebuildError> {
    if !matches!(key.len(), 16 | 24 | 32) {
        return Err(CbcRebuildError::KeyLength);
    }
    let rem = plaintext.len() % 16;
    if rem != 0 && !stream_end {
        return Err(CbcRebuildError::Unaligned);
    }
    let mut padded = Vec::with_capacity(plaintext.len() + 16);
    padded.extend_from_slice(plaintext);
    if rem != 0 {
        padded.resize(plaintext.len() + 16 - rem, 0);
    }
    let rebuilt = encrypt_cbc(key, previous, &padded).ok_or(CbcRebuildError::KeyLength)?;
    if let Some((offset, bytes)) = intact {
        let end = offset.saturating_add(bytes.len()).min(rebuilt.len());
        if bytes.is_empty() || offset >= end {
            return Err(CbcRebuildError::NoOverlap);
        }
        if let Some(at) = rebuilt[offset..end].iter().zip(bytes).position(|(a, b)| a != b) {
            return Err(CbcRebuildError::Mismatch { at: offset + at });
        }
    }
    Ok(rebuilt)
}

/// What to rebuild with [`rebuild_cbc`] for a hole in a CBC stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CbcSpan {
    /// The stream range to rebuild: the hole widened to whole blocks, plus one intact block after it to check
    /// against when the stream has one. Pass the plaintext of this range.
    pub range: std::ops::Range<u64>,
    /// Where the previous 16 bytes start (`range.start - 16`), or None when the range starts the stream (use the IV).
    pub previous_at: Option<u64>,
    /// The intact bytes after the hole, as stream offsets: pass them as `intact`, at `check.start - range.start`.
    /// When `range` ends the stream on a partial block, the check runs to that block's end (the packed stream's
    /// end), so all 16 ciphertext bytes of the final block are compared. None when the hole reaches the stream's end.
    pub check: Option<std::ops::Range<u64>>,
    /// Whether `range` ends the stream (pass as `stream_end`).
    pub stream_end: bool,
}

/// The aligned range to rebuild for a hole (`hole`, stream offsets) in a CBC stream of `stream_len` bytes (its
/// plaintext length; the packed stream is that rounded up to 16).
pub fn cbc_rebuild_span(hole: std::ops::Range<u64>, stream_len: u64) -> CbcSpan {
    let end = hole.end.min(stream_len);
    let start = hole.start.min(end) / 16 * 16;
    let block_end = end.div_ceil(16) * 16;
    // One more block to check against, unless the hole reaches the end.
    let range_end = if block_end >= stream_len { stream_len } else { (block_end + 16).min(stream_len) };
    // The check runs through the last block's ciphertext, past the plaintext into its padding: a final block with
    // few plaintext bytes is still compared whole.
    let check_end = if range_end == stream_len { range_end.div_ceil(16) * 16 } else { range_end };
    let check = (end < stream_len).then_some(end..check_end);
    CbcSpan { range: start..range_end, previous_at: start.checked_sub(16), check, stream_end: range_end == stream_len }
}

/// Encrypts AES-CBC plaintext (`data` must be a multiple of 16 bytes).
pub fn encrypt_cbc(key: &[u8], iv: &[u8; 16], data: &[u8]) -> Option<Vec<u8>> {
    let cipher = AesKey::new(key)?;
    if !data.len().is_multiple_of(16) {
        return None;
    }
    let mut out = Vec::with_capacity(data.len());
    let mut prev = *iv;
    for chunk in data.as_chunks::<16>().0 {
        let mut x = *chunk;
        for (b, &p) in x.iter_mut().zip(&prev) {
            *b ^= p;
        }
        let enc = cipher.encrypt_block(&x);
        out.extend_from_slice(&enc);
        prev = enc;
    }
    Some(out)
}

/// Decrypts WinZip AES CTR-mode ciphertext (little-endian counter starting at 1).
pub fn decrypt_winzip_ctr(key: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
    let cipher = AesKey::new(key)?;
    let mut out = ciphertext.to_vec();
    winzip_ctr_xor(&cipher, &mut [0; 16], &mut out);
    Some(out)
}

// Calls before the last must end at a whole counter block.
fn winzip_ctr_xor(cipher: &AesKey, counter: &mut [u8; 16], bytes: &mut [u8]) {
    for chunk in bytes.chunks_mut(16) {
        for b in counter.iter_mut() {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
        let ks = cipher.encrypt_block(counter);
        for (byte, key) in chunk.iter_mut().zip(ks) {
            *byte ^= key;
        }
    }
}

// ---------------------------------------------------------------------------
// Pure-Rust SHA-256 + HMAC-SHA256 + RAR 5.0 key derivation & header decryption
// ---------------------------------------------------------------------------

mod sha256;

#[cfg(test)]
pub(crate) use sha256::SHA256_COMPRESSIONS;
#[doc(hidden)]
pub use sha256::sha256_backend;
use sha256::{SHA256_IV, sha256_compress};
pub use sha256::{Sha256, sha256};

/// The largest 7zAES `NumCyclesPower` 7-Zip itself accepts.
pub(crate) const SEVEN_ZIP_MAX_CYCLES_POWER: u8 = 24;

/// Derives the 7zAES AES-256 key: SHA-256 over `2^num_cycles_power` rounds of `salt`, the UTF-16LE password and
/// the round number as 8 little-endian bytes. A power of 0x3F means no hashing: the key is the salt followed by the
/// password, zero-padded to 32 bytes. Every SHA-256 compression is charged to `control`. Powers above
/// [`SEVEN_ZIP_MAX_CYCLES_POWER`] (other than 0x3F) and salts over 16 bytes are refused with None.
pub(crate) fn derive_7z_key_controlled(
    password: &str,
    salt: &[u8],
    num_cycles_power: u8,
    control: &mut dyn KdfControl,
) -> Option<std::result::Result<[u8; 32], KdfControlError>> {
    let units: Vec<u16> = password.encode_utf16().collect();
    derive_7z_key_units(&units, salt, num_cycles_power, control)
}

/// [`derive_7z_key_controlled`] over the password's UTF-16 code units as given.
fn derive_7z_key_units(
    units: &[u16],
    salt: &[u8],
    num_cycles_power: u8,
    control: &mut dyn KdfControl,
) -> Option<std::result::Result<[u8; 32], KdfControlError>> {
    if salt.len() > 16 {
        return None;
    }
    let mut raw = Vec::with_capacity(salt.len() + units.len() * 2 + 8);
    raw.extend_from_slice(salt);
    for unit in units {
        raw.extend_from_slice(&unit.to_le_bytes());
    }
    if num_cycles_power == 0x3F {
        let mut key = [0u8; 32];
        let n = raw.len().min(32);
        key[..n].copy_from_slice(&raw[..n]);
        return Some(Ok(key));
    }
    if num_cycles_power > SEVEN_ZIP_MAX_CYCLES_POWER {
        return None;
    }
    let fixed = raw.len();
    raw.extend_from_slice(&[0; 8]);
    let mut state = SHA256_IV;
    let mut block = [0u8; 64];
    let mut fill = 0usize;
    let mut total: u64 = 0;
    for round in 0..1u64 << num_cycles_power {
        raw[fixed..].copy_from_slice(&round.to_le_bytes());
        let mut bytes = raw.as_slice();
        total = total.wrapping_add(bytes.len() as u64);
        while !bytes.is_empty() {
            let take = (64 - fill).min(bytes.len());
            block[fill..fill + take].copy_from_slice(&bytes[..take]);
            fill += take;
            bytes = &bytes[take..];
            if fill == 64 {
                if let Err(e) = control.charge(1) {
                    return Some(Err(e));
                }
                sha256_compress(&mut state, &block);
                fill = 0;
            }
        }
    }
    let mut tail = [0u8; 128];
    tail[..fill].copy_from_slice(&block[..fill]);
    tail[fill] = 0x80;
    let bit_len = total.wrapping_mul(8);
    let blocks = if fill < 56 { 1 } else { 2 };
    tail[blocks * 64 - 8..blocks * 64].copy_from_slice(&bit_len.to_be_bytes());
    for chunk in tail[..blocks * 64].as_chunks::<64>().0 {
        if let Err(e) = control.charge(1) {
            return Some(Err(e));
        }
        sha256_compress(&mut state, chunk);
    }
    let mut key = [0u8; 32];
    for (i, word) in state.iter().enumerate() {
        key[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    Some(Ok(key))
}

/// Derives the 7zAES key without budgets; see `derive_7z_key_controlled`. None for an unsupported cycle power or
/// a salt over 16 bytes.
pub fn derive_7z_key(password: &str, salt: &[u8], num_cycles_power: u8) -> Option<[u8; 32]> {
    derive_7z_key_controlled(password, salt, num_cycles_power, &mut UnrestrictedKdf).map(|r| r.expect("unrestricted"))
}

/// [`derive_7z_key`] for a password given as UTF-16 code units, hashed exactly as given (little-endian, unpaired
/// surrogates included). For a password that is not valid UTF-8 the caller chooses how its bytes become units;
/// `derive_7z_key` is this over `password.encode_utf16()`.
pub fn derive_7z_key_utf16(password: &[u16], salt: &[u8], num_cycles_power: u8) -> Option<[u8; 32]> {
    derive_7z_key_units(password, salt, num_cycles_power, &mut UnrestrictedKdf).map(|r| r.expect("unrestricted"))
}

#[cfg(test)]
mod seven_zip_kdf_tests {
    #[test]
    fn matches_one_shot_sha256() {
        let (password, salt) = ("pässwörd", [7u8; 9]);
        for power in [0u8, 1, 3, 6] {
            let mut all = Vec::new();
            for round in 0..1u64 << power {
                all.extend_from_slice(&salt);
                for unit in password.encode_utf16() {
                    all.extend_from_slice(&unit.to_le_bytes());
                }
                all.extend_from_slice(&round.to_le_bytes());
            }
            assert_eq!(super::derive_7z_key(password, &salt, power), Some(super::sha256(&all)), "power {power}");
        }
        let mut raw = [0u8; 32];
        raw[..9].copy_from_slice(&salt);
        raw[9..11].copy_from_slice(&[b'p', 0]);
        assert_eq!(super::derive_7z_key("p", &salt, 0x3F), Some(raw));
        assert_eq!(super::derive_7z_key("p", &salt, 25), None);
    }
}

/// Precomputed inner/outer SHA-256 states after absorbing the 64-byte HMAC ipad and opad blocks.
#[derive(Clone, Copy)]
struct HmacSha256Key {
    inner: [u32; 8],
    outer: [u32; 8],
}

impl HmacSha256Key {
    fn new(key: &[u8]) -> Self {
        let mut k = [0u8; 64];
        if key.len() > 64 {
            k[..32].copy_from_slice(&sha256(key));
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0x36u8; 64];
        let mut opad = [0x5cu8; 64];
        for i in 0..64 {
            ipad[i] ^= k[i];
            opad[i] ^= k[i];
        }
        let mut inner = SHA256_IV;
        let mut outer = SHA256_IV;
        sha256_compress(&mut inner, &ipad);
        sha256_compress(&mut outer, &opad);
        Self { inner, outer }
    }

    /// Computes HMAC-SHA256 over a 32-byte digest (`u`), avoiding heap allocation inside PBKDF2 loops.
    #[inline]
    fn mac_32(&self, u: &[u8; 32]) -> [u8; 32] {
        let mut in_state = self.inner;
        let mut block = [0u8; 64];
        block[..32].copy_from_slice(u);
        block[32] = 0x80;
        // Total length = 64 (ipad) + 32 (u) = 96 bytes = 768 bits
        block[56..64].copy_from_slice(&768u64.to_be_bytes());
        sha256_compress(&mut in_state, &block);

        let mut out_block = [0u8; 64];
        for (i, &word) in in_state.iter().enumerate() {
            out_block[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out_block[32] = 0x80;
        out_block[56..64].copy_from_slice(&768u64.to_be_bytes());
        let mut out_state = self.outer;
        sha256_compress(&mut out_state, &out_block);

        let mut out = [0u8; 32];
        for (i, &word) in out_state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    fn mac_slice(&self, data: &[u8]) -> [u8; 32] {
        let mut in_state = self.inner;
        let (blocks, rem) = data.as_chunks::<64>();
        for b in blocks {
            sha256_compress(&mut in_state, b);
        }
        let bit_len = ((64 + data.len()) as u64) * 8;
        let mut tail = [0u8; 128];
        tail[..rem.len()].copy_from_slice(rem);
        tail[rem.len()] = 0x80;
        if rem.len() < 56 {
            tail[56..64].copy_from_slice(&bit_len.to_be_bytes());
            sha256_compress(&mut in_state, tail[..64].try_into().unwrap());
        } else {
            tail[120..128].copy_from_slice(&bit_len.to_be_bytes());
            sha256_compress(&mut in_state, tail[..64].try_into().unwrap());
            sha256_compress(&mut in_state, tail[64..128].try_into().unwrap());
        }
        let mut out_block = [0u8; 64];
        for (i, &word) in in_state.iter().enumerate() {
            out_block[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out_block[32] = 0x80;
        out_block[56..64].copy_from_slice(&768u64.to_be_bytes());
        let mut out_state = self.outer;
        sha256_compress(&mut out_state, &out_block);
        let mut out = [0u8; 32];
        for (i, &word) in out_state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

/// RAR5 encryption parameters from a file's encryption extra record (`0x01`) or archive encryption header (`HEAD_CRYPT`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rar5CryptParams {
    pub kdf_count: u8,
    pub salt: [u8; 16],
    pub iv: [u8; 16],
    pub check: Option<([u8; 8], [u8; 4])>,
    pub tweaked_crc: bool,
}

/// What a RAR5 header or extra record keeps to test a password: PBKDF2 count, salt, and 8-byte check value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rar5PasswordCheck {
    pub kdf_count: u8,
    pub salt: [u8; 16],
    pub check: [u8; 8],
}

impl Rar5PasswordCheck {
    pub fn to_bytes(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(25);
        out.push(self.kdf_count);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.check);
        out
    }

    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        Some(Self {
            kdf_count: *b.first()?,
            salt: b.get(1..17)?.try_into().ok()?,
            check: b.get(17..25)?.try_into().ok()?,
        })
    }

    pub fn accepts(&self, password: &str) -> bool {
        self.accepts_bytes(password.as_bytes())
    }

    /// [`accepts`](Self::accepts) for a password given as raw bytes, hashed exactly as given.
    pub fn accepts_bytes(&self, password: &[u8]) -> bool {
        if self.kdf_count > 24 {
            return false;
        }
        let keyed = HmacSha256Key::new(rar_password_prefix_utf8(password));
        let mut salt_block = [0u8; 20];
        salt_block[..16].copy_from_slice(&self.salt);
        salt_block[16..20].copy_from_slice(&1u32.to_be_bytes());
        let mut u = keyed.mac_slice(&salt_block);
        let mut fn_acc = u;
        let iterations = 1u32 << self.kdf_count;
        for _ in 1..iterations.saturating_add(32) {
            u = keyed.mac_32(&u);
            for (slot, b) in fn_acc.iter_mut().zip(u) {
                *slot ^= b;
            }
        }
        let mut folded = [0u8; 8];
        for (i, b) in fn_acc.iter().enumerate() {
            folded[i % 8] ^= *b;
        }
        folded == self.check
    }
}

fn vint(data: &[u8], pos: usize) -> Option<(u64, usize)> {
    let mut val = 0u64;
    for i in 0..10usize {
        let b = *data.get(pos + i)?;
        val |= u64::from(b & 0x7f) << (i * 7);
        if b & 0x80 == 0 {
            return Some((val, pos + i + 1));
        }
    }
    None
}

/// Parses a RAR5 encryption record body (`HEAD_CRYPT` fields or `FHEXTRA_CRYPT` after its record-type vint).
pub fn rar5_record_params(record: &[u8]) -> Option<Rar5CryptParams> {
    let (version, p) = vint(record, 0)?;
    if version != 0 {
        return None;
    }
    let (flags, p) = vint(record, p)?;
    let kdf_count = *record.get(p)?;
    if kdf_count > 24 {
        return None;
    }
    let salt: [u8; 16] = record.get(p + 1..p + 17)?.try_into().ok()?;
    let mut at = p + 17;
    let mut iv = [0u8; 16];
    if record.len() >= at + 16 {
        iv.copy_from_slice(record.get(at..at + 16)?);
        at += 16;
    }
    let check = if flags & 0x0001 != 0 && record.len() >= at + 12 {
        let chk: [u8; 8] = record.get(at..at + 8)?.try_into().ok()?;
        let csum: [u8; 4] = record.get(at + 8..at + 12)?.try_into().ok()?;
        Some((chk, csum))
    } else {
        None
    };
    Some(Rar5CryptParams { kdf_count, salt, iv, check, tweaked_crc: flags & 0x0002 != 0 })
}

#[derive(Clone, Copy)]
pub(crate) enum Rar5CryptLayout {
    Header,
    Member,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Rar5CryptError {
    Malformed,
    UnsupportedVersion(u64),
    KdfLimit(u8),
    WrongPassword,
}

pub(crate) fn parse_rar5_crypt(
    record: &[u8],
    layout: Rar5CryptLayout,
) -> std::result::Result<Rar5CryptParams, Rar5CryptError> {
    use Rar5CryptError::Malformed;
    let mut cursor = crate::rar5::Cursor::new(record);
    let version = cursor.vint().map_err(|_| Malformed)?;
    if version != 0 {
        return Err(Rar5CryptError::UnsupportedVersion(version));
    }
    let flags = cursor.vint().map_err(|_| Malformed)?;
    let p = cursor.pos();
    let kdf_count = *record.get(p).ok_or(Malformed)?;
    let salt = record.get(p + 1..p + 17).ok_or(Malformed)?.try_into().unwrap();
    let mut at = p + 17;
    let iv = match layout {
        Rar5CryptLayout::Header => [0; 16],
        Rar5CryptLayout::Member => {
            let iv = record.get(at..at + 16).ok_or(Malformed)?.try_into().unwrap();
            at += 16;
            iv
        }
    };
    let check = if flags & 1 == 0 {
        None
    } else {
        let bytes = record.get(at..at + 12).ok_or(Malformed)?;
        Some((bytes[..8].try_into().unwrap(), bytes[8..].try_into().unwrap()))
    };
    if kdf_count > 24 {
        return Err(Rar5CryptError::KdfLimit(kdf_count));
    }
    Ok(Rar5CryptParams { kdf_count, salt, iv, check, tweaked_crc: flags & 2 != 0 })
}

/// UnRAR and `rar` use at most this many characters of a RAR password and ignore the rest (`MAXPASSWORD` 128 with
/// a terminator). Measured by running the binaries: see `docs/rar-passwords.md`.
pub const RAR_MAX_PASSWORD_CHARS: usize = 127;

/// The first [`RAR_MAX_PASSWORD_CHARS`] Unicode characters of a RAR 5.0 password's UTF-8 bytes. Bytes that are not
/// valid UTF-8 are cut at that many bytes instead.
fn rar_password_prefix_utf8(password: &[u8]) -> &[u8] {
    match std::str::from_utf8(password) {
        Ok(text) => match text.char_indices().nth(RAR_MAX_PASSWORD_CHARS) {
            Some((end, _)) => &password[..end],
            None => password,
        },
        Err(_) => &password[..password.len().min(RAR_MAX_PASSWORD_CHARS)],
    }
}

/// The first [`RAR_MAX_PASSWORD_CHARS`] characters of a RAR 3.x/4.x password's UTF-16 units; a surrogate pair is
/// one character and an unpaired surrogate is one character.
fn rar_password_prefix_utf16(password: &[u16]) -> &[u16] {
    let mut chars = 0;
    let mut at = 0;
    while at < password.len() {
        if chars == RAR_MAX_PASSWORD_CHARS {
            return &password[..at];
        }
        let pair = (0xD800..0xDC00).contains(&password[at])
            && password.get(at + 1).is_some_and(|u| (0xDC00..0xE000).contains(u));
        at += if pair { 2 } else { 1 };
        chars += 1;
    }
    password
}

/// Derives the RAR5 32-byte AES-256 key and 32-byte `HashKey` (for keyed checksums) from `password`, `kdf_count`, and `salt`.
/// If `check` is `Some((chk, csum))` and `sha256(&chk)[..4] == csum`, verifies the password against `chk`.
pub fn derive_rar5_key_and_hash_key(
    password: &str,
    kdf_count: u8,
    salt: &[u8; 16],
    check: Option<([u8; 8], [u8; 4])>,
) -> Option<([u8; 32], [u8; 32])> {
    derive_rar5_keys(password, kdf_count, salt, check).ok().map(|keys| (keys.key, keys.hash_key))
}

pub(crate) struct Rar5Keys {
    pub(crate) key: [u8; 32],
    pub(crate) hash_key: [u8; 32],
    pub(crate) evidence: crate::error::RarPasswordEvidence,
}

/// A derivation calls this before every bounded group of SHA compression blocks.
pub(crate) trait KdfControl {
    fn charge(&mut self, blocks: u64) -> std::result::Result<(), KdfControlError>;
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[allow(dead_code, reason = "private progressive control producer")]
pub(crate) enum KdfControlError {
    Canceled,
    Limit { resource: crate::progressive::Resource, limit: u64, attempted: u64 },
}
#[derive(Debug)]
pub(crate) enum ControlledKdfError {
    Crypt(Rar5CryptError),
    Control(KdfControlError),
}

struct UnrestrictedKdf;
impl KdfControl for UnrestrictedKdf {
    fn charge(&mut self, _: u64) -> std::result::Result<(), KdfControlError> {
        Ok(())
    }
}

pub(crate) fn derive_rar5_keys(
    password: &str,
    kdf_count: u8,
    salt: &[u8; 16],
    check: Option<([u8; 8], [u8; 4])>,
) -> std::result::Result<Rar5Keys, Rar5CryptError> {
    derive_rar5_keys_impl(password.as_bytes(), kdf_count, salt, check, &mut UnrestrictedKdf).map_err(
        |error| match error {
            ControlledKdfError::Crypt(error) => error,
            ControlledKdfError::Control(_) => unreachable!("unrestricted legacy derivation"),
        },
    )
}

#[allow(dead_code, reason = "private progressive producer; legacy wrapper uses the same derivation core")]
pub(crate) fn derive_rar5_keys_controlled(
    password: &str,
    kdf_count: u8,
    salt: &[u8; 16],
    check: Option<([u8; 8], [u8; 4])>,
    control: &mut dyn KdfControl,
) -> std::result::Result<Rar5Keys, ControlledKdfError> {
    rar5_controlled(password, kdf_count, control, |control| {
        derive_rar5_keys_impl(password.as_bytes(), kdf_count, salt, check, control)
    })
}

/// [`rar5_material`] under the limits and metering of [`derive_rar5_keys_controlled`].
pub(crate) fn rar5_material_controlled(
    password: &str,
    kdf_count: u8,
    salt: &[u8; 16],
    check: Option<([u8; 8], [u8; 4])>,
    control: &mut dyn KdfControl,
) -> std::result::Result<Rar5Derived, ControlledKdfError> {
    rar5_controlled(password, kdf_count, control, |control| {
        rar5_material(password.as_bytes(), kdf_count, salt, check, control)
    })
}

/// Refuses a password or exponent past the progressive limits before any hashing, then runs `derive` with every
/// block charged to `control` and one derivation held to 2^22 blocks.
fn rar5_controlled<T>(
    password: &str,
    kdf_count: u8,
    control: &mut dyn KdfControl,
    derive: impl FnOnce(&mut dyn KdfControl) -> std::result::Result<T, ControlledKdfError>,
) -> std::result::Result<T, ControlledKdfError> {
    use crate::progressive::Resource;
    for (resource, attempted, limit) in [
        (Resource::KdfExponent, u64::from(kdf_count), 20),
        (Resource::PasswordUtf8Bytes, password.len() as u64, 4096),
        // RAR5 uses the supplied UTF-8 bytes directly.
        (Resource::PasswordEncodedBytes, password.len() as u64, 8192),
    ] {
        if attempted > limit {
            return Err(ControlledKdfError::Control(KdfControlError::Limit { resource, limit, attempted }));
        }
    }
    struct Derivation<'a> {
        control: &'a mut dyn KdfControl,
        blocks: u64,
    }
    impl KdfControl for Derivation<'_> {
        fn charge(&mut self, blocks: u64) -> std::result::Result<(), KdfControlError> {
            let attempted = self.blocks.checked_add(blocks).ok_or(crate::crypto::KdfControlError::Limit {
                resource: crate::progressive::Resource::KdfDerivationBlocks,
                limit: 1 << 22,
                attempted: u64::MAX,
            })?;
            if attempted > 1 << 22 {
                return Err(KdfControlError::Limit {
                    resource: Resource::KdfDerivationBlocks,
                    limit: 1 << 22,
                    attempted,
                });
            }
            self.control.charge(blocks)?;
            self.blocks = attempted;
            Ok(())
        }
    }
    derive(&mut Derivation { control, blocks: 0 })
}

fn derive_rar5_keys_impl<C: KdfControl + ?Sized>(
    password: &[u8],
    kdf_count: u8,
    salt: &[u8; 16],
    check: Option<([u8; 8], [u8; 4])>,
    control: &mut C,
) -> std::result::Result<Rar5Keys, ControlledKdfError> {
    let derived = rar5_pbkdf2(password, kdf_count, salt, check, control)?;
    // The check value was derived exactly when the record's checksum holds: no second hash.
    derived.keys_verified(check, derived.fold.is_some()).map_err(ControlledKdfError::Crypt)
}

/// What one RAR 5.0 PBKDF2-HMAC-SHA256 run gives: the AES key, the `HashKey`, and the folded password check value
/// when it was computed. A member's own check value is compared with `fold` by [`Rar5Derived::keys`].
#[derive(Clone)]
pub(crate) struct Rar5Derived {
    key: [u8; 32],
    hash_key: [u8; 32],
    fold: Option<[u8; 8]>,
}

impl Rar5Derived {
    /// The folded password check value, when it was derived.
    #[cfg(test)]
    pub(crate) fn check_value(&self) -> Option<[u8; 8]> {
        self.fold
    }

    /// The keys for a member whose encryption record carries `check`: its check value, when its checksum holds,
    /// must equal the derived one, or the password is wrong.
    /// Whether this material can give the keys for a member with `check`: material derived for a member without a
    /// verifiable check value has none to compare a later member's with (that member derives again).
    pub(crate) fn serves(&self, check: Option<([u8; 8], [u8; 4])>) -> bool {
        self.fold.is_some() || !matches!(check, Some((chk, csum)) if sha256(&chk)[..4] == csum)
    }

    pub(crate) fn keys(&self, check: Option<([u8; 8], [u8; 4])>) -> std::result::Result<Rar5Keys, Rar5CryptError> {
        let verifiable = matches!(check, Some((chk, csum)) if sha256(&chk)[..4] == csum);
        self.keys_verified(check, verifiable)
    }

    /// [`Self::keys`] where `verifiable` says whether the check value's checksum holds.
    fn keys_verified(
        &self,
        check: Option<([u8; 8], [u8; 4])>,
        verifiable: bool,
    ) -> std::result::Result<Rar5Keys, Rar5CryptError> {
        use crate::error::{RarPasswordEvidence, RarVerifierUnavailable};
        let evidence = match check {
            Some((chk, _)) if verifiable => match self.fold {
                Some(fold) if fold == chk => RarPasswordEvidence::VerifierMatched,
                _ => return Err(Rar5CryptError::WrongPassword),
            },
            Some(_) => RarPasswordEvidence::VerifierUnavailable(RarVerifierUnavailable::CheckChecksumMismatch),
            None => RarPasswordEvidence::VerifierUnavailable(RarVerifierUnavailable::Absent),
        };
        Ok(Rar5Keys { key: self.key, hash_key: self.hash_key, evidence })
    }
}

/// RAR 5.0 PBKDF2 runs started so far, by password (tests only: a test counts the runs for a password only it uses).
#[cfg(test)]
static RAR5_DERIVATIONS: std::sync::Mutex<Vec<(Vec<u8>, u64)>> = std::sync::Mutex::new(Vec::new());

/// RAR 5.0 key derivations started so far for `password` (tests only).
#[cfg(test)]
pub(crate) fn rar5_derivations(password: &str) -> u64 {
    let counts = RAR5_DERIVATIONS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    counts.iter().find(|(p, _)| p == password.as_bytes()).map_or(0, |(_, n)| *n)
}

/// The RAR 5.0 PBKDF2-HMAC-SHA256 run: `2^kdf_count` rounds for the key, 16 more for the `HashKey`, and 16 more for
/// the password check value when `check` can be verified.
fn rar5_pbkdf2<C: KdfControl + ?Sized>(
    password: &[u8],
    kdf_count: u8,
    salt: &[u8; 16],
    check: Option<([u8; 8], [u8; 4])>,
    control: &mut C,
) -> std::result::Result<Rar5Derived, ControlledKdfError> {
    if kdf_count > 24 {
        return Err(ControlledKdfError::Crypt(Rar5CryptError::KdfLimit(kdf_count)));
    }
    #[cfg(test)]
    {
        let mut counts = RAR5_DERIVATIONS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        match counts.iter_mut().find(|(p, _)| p == password) {
            Some((_, n)) => *n += 1,
            None => counts.push((password.to_vec(), 1)),
        }
    }
    // Normalizing a long HMAC key hashes ceil((bytes + 9) / 64) blocks.
    // Setup always hashes the two ipad/opad blocks. No password buffer is allocated.
    let password = rar_password_prefix_utf8(password);
    let normalization = if password.len() > 64 { (password.len() as u64 + 9).div_ceil(64) } else { 0 };
    control.charge(normalization + 2).map_err(ControlledKdfError::Control)?;
    let keyed = HmacSha256Key::new(password);
    let mut salt_block = [0u8; 20];
    salt_block[..16].copy_from_slice(salt);
    salt_block[16..20].copy_from_slice(&1u32.to_be_bytes());
    control.charge(2).map_err(ControlledKdfError::Control)?;
    let mut u = keyed.mac_slice(&salt_block);
    let mut fn_acc = u;
    let iterations = 1u32 << kdf_count;
    for _ in 1..iterations {
        control.charge(2).map_err(ControlledKdfError::Control)?;
        u = keyed.mac_32(&u);
        for (slot, b) in fn_acc.iter_mut().zip(u) {
            *slot ^= b;
        }
    }
    let key = fn_acc;
    for _ in 0..16 {
        control.charge(2).map_err(ControlledKdfError::Control)?;
        u = keyed.mac_32(&u);
        for (slot, b) in fn_acc.iter_mut().zip(u) {
            *slot ^= b;
        }
    }
    let hash_key = fn_acc;
    if check.is_some() {
        control.charge(1).map_err(ControlledKdfError::Control)?;
    }
    let verifiable = matches!(check, Some((chk, csum)) if sha256(&chk)[..4] == csum);
    let fold = if verifiable {
        for _ in 0..16 {
            control.charge(2).map_err(ControlledKdfError::Control)?;
            u = keyed.mac_32(&u);
            for (slot, b) in fn_acc.iter_mut().zip(u) {
                *slot ^= b;
            }
        }
        let mut folded = [0u8; 8];
        for (i, b) in fn_acc.iter().enumerate() {
            folded[i % 8] ^= *b;
        }
        Some(folded)
    } else {
        None
    };
    Ok(Rar5Derived { key, hash_key, fold })
}

/// Key material by key-derivation input (password and `K`: salt, count), for one run or session. In memory only;
/// at most [`KdfCache::KEPT`] inputs are kept, least recently used dropped first, so an archive with a new salt in
/// every header derives as it would without a cache.
pub(crate) struct KdfCache<K, V> {
    entries: Vec<(Box<[u8]>, K, V)>,
}

impl<K, V> Default for KdfCache<K, V> {
    fn default() -> Self {
        Self { entries: Vec::new() }
    }
}

impl<K: PartialEq, V: Clone> KdfCache<K, V> {
    /// Inputs kept at most.
    pub(crate) const KEPT: usize = 16;

    /// The material derived before for this input, now the most recently used.
    pub(crate) fn get(&mut self, password: &[u8], input: &K) -> Option<V> {
        let at = self.entries.iter().position(|(p, k, _)| k == input && **p == *password)?;
        let entry = self.entries.remove(at);
        let value = entry.2.clone();
        self.entries.push(entry);
        Some(value)
    }

    /// Keeps material derived for this input, dropping the least recently used past [`Self::KEPT`].
    pub(crate) fn insert(&mut self, password: &[u8], input: K, value: V) {
        self.entries.retain(|(p, k, _)| !(*k == input && **p == *password));
        if self.entries.len() >= Self::KEPT {
            self.entries.remove(0);
        }
        self.entries.push((password.into(), input, value));
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

/// RAR 5.0 key material by (count, salt): PBKDF2 runs once per input, since `rar` gives every file header of an
/// archive (and its encrypted headers) the same salt. Each member's password check value is still compared with
/// the derived one ([`Rar5Derived::keys`]).
pub(crate) type Rar5KeyCache = KdfCache<(u8, [u8; 16]), Rar5Derived>;

/// A [`Rar5KeyCache`] shared by the volumes of a set and the run or session reading them, so each volume's
/// encrypted headers and its members derive only inputs none of them derived before.
#[derive(Clone, Default)]
pub(crate) struct SharedRar5Keys(std::sync::Arc<std::sync::Mutex<Rar5KeyCache>>);

impl SharedRar5Keys {
    pub(crate) fn lock(&self) -> std::sync::MutexGuard<'_, Rar5KeyCache> {
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// RAR 3.x key and IV by salt, for a progressive session ([`crate::progressive::Usage`]).
pub(crate) type Rar4Keys = KdfCache<[u8; 8], ([u8; 16], [u8; 16])>;

impl Rar5KeyCache {
    /// [`derive_rar5_keys`] through the cache, stopping when `cancel` is set (only a derivation has work to stop).
    pub(crate) fn keys(
        &mut self,
        password: &str,
        params: &Rar5CryptParams,
        cancel: Option<&crate::extract::Cancellation>,
    ) -> std::result::Result<Rar5Keys, ControlledKdfError> {
        let input = (params.kdf_count, params.salt);
        let derived = match self.get(password.as_bytes(), &input).filter(|derived| derived.serves(params.check)) {
            Some(derived) => derived,
            None => {
                let control = &mut Cancelable(cancel);
                let derived =
                    rar5_material(password.as_bytes(), params.kdf_count, &params.salt, params.check, control)?;
                self.insert(password.as_bytes(), input, derived.clone());
                derived
            }
        };
        derived.keys(params.check).map_err(ControlledKdfError::Crypt)
    }
}

/// Stops a derivation once `cancel` is set.
struct Cancelable<'a>(Option<&'a crate::extract::Cancellation>);
impl KdfControl for Cancelable<'_> {
    fn charge(&mut self, _: u64) -> std::result::Result<(), KdfControlError> {
        if self.0.is_some_and(crate::extract::Cancellation::is_canceled) {
            Err(KdfControlError::Canceled)
        } else {
            Ok(())
        }
    }
}

/// RAR 5.0 key material for a [`Rar5KeyCache`], with the check value when `check` (the first member's) can be
/// verified: what [`derive_rar5_keys`] derives for it, at the same cost.
pub(crate) fn rar5_material(
    password: &[u8],
    kdf_count: u8,
    salt: &[u8; 16],
    check: Option<([u8; 8], [u8; 4])>,
    control: &mut dyn KdfControl,
) -> std::result::Result<Rar5Derived, ControlledKdfError> {
    rar5_pbkdf2(password, kdf_count, salt, check, control)
}

/// [`derive_rar5_key_and_hash_key`] for a password given as raw bytes, hashed exactly as given. RAR 5.0 keys
/// PBKDF2 with the password's UTF-8 bytes, so for a `&str` this is the same as `derive_rar5_key_and_hash_key`;
/// bytes that are not valid UTF-8 are used unchanged.
pub fn derive_rar5_key_and_hash_key_bytes(
    password: &[u8],
    kdf_count: u8,
    salt: &[u8; 16],
    check: Option<([u8; 8], [u8; 4])>,
) -> Option<([u8; 32], [u8; 32])> {
    derive_rar5_keys_impl(password, kdf_count, salt, check, &mut UnrestrictedKdf)
        .ok()
        .map(|keys| (keys.key, keys.hash_key))
}

/// [`derive_rar5_key`] for a password given as raw bytes; see [`derive_rar5_key_and_hash_key_bytes`].
pub fn derive_rar5_key_bytes(
    password: &[u8],
    kdf_count: u8,
    salt: &[u8; 16],
    check: Option<([u8; 8], [u8; 4])>,
) -> Option<[u8; 32]> {
    derive_rar5_key_and_hash_key_bytes(password, kdf_count, salt, check).map(|(k, _)| k)
}

/// Derives the RAR5 32-byte AES-256 key from `password`, `kdf_count`, and `salt`.
pub fn derive_rar5_key(
    password: &str,
    kdf_count: u8,
    salt: &[u8; 16],
    check: Option<([u8; 8], [u8; 4])>,
) -> Option<[u8; 32]> {
    derive_rar5_key_and_hash_key(password, kdf_count, salt, check).map(|(k, _)| k)
}

/// Computes the RAR5 tweaked CRC32 (`MAC` over the little-endian CRC32 using `hash_key`).
pub fn rar5_tweak_crc32(crc: u32, hash_key: &[u8; 32]) -> u32 {
    let keyed = HmacSha256Key::new(hash_key);
    let digest = keyed.mac_slice(&crc.to_le_bytes());
    let mut out = 0u32;
    for (i, &b) in digest.iter().enumerate() {
        out ^= u32::from(b) << ((i & 3) * 8);
    }
    out
}

/// Computes the RAR5 authentication code for a BLAKE2sp digest.
pub(crate) fn rar5_tweak_blake2sp(digest: &[u8; 32], hash_key: &[u8; 32]) -> [u8; 32] {
    HmacSha256Key::new(hash_key).mac_slice(digest)
}

/// Decrypts an encrypted RAR5 block header at `pos` (starts with 16-byte IV followed by AES-256-CBC blocks).
/// Returns `(decrypted_header_starting_at_crc, raw_encrypted_end_pos)` if the header CRC32 matches.
pub fn decrypt_rar5_header(data: &[u8], pos: usize, key: &[u8; 32]) -> Option<(Vec<u8>, usize)> {
    let iv: [u8; 16] = data.get(pos..pos.checked_add(16)?)?.try_into().ok()?;
    let ct_start = pos + 16;
    let first_block = data.get(ct_start..ct_start.checked_add(16)?)?;
    let first_dec = decrypt_cbc(key, &iv, first_block)?;
    let (hdr_size, size_after) = vint(&first_dec, 4)?;
    let hdr_size = usize::try_from(hdr_size).ok()?;
    if hdr_size == 0 || hdr_size > 2 * 1024 * 1024 {
        return None;
    }
    let plain_need = size_after.checked_add(hdr_size)?;
    let padded_len = plain_need.checked_next_multiple_of(16)?;
    let ct_end = ct_start.checked_add(padded_len)?;
    let ct = data.get(ct_start..ct_end)?;
    let dec = decrypt_cbc(key, &iv, ct)?;
    let stored_crc = u32::from_le_bytes(dec.get(..4)?.try_into().ok()?);
    let crc_slice = dec.get(4..plain_need)?;
    if crate::crc32::hash(crc_slice) != stored_crc {
        return None;
    }
    Some((dec, ct_end))
}

// ---------------------------------------------------------------------------
// Pure-Rust SHA-1 + RAR 4.x (`SetKey30`) key/IV derivation & header decryption
// ---------------------------------------------------------------------------

#[cfg(test)]
thread_local! { static SHA1_COMPRESSIONS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) }; }
#[derive(Clone)]
struct Sha1 {
    state: [u32; 5],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Sha1 {
    fn new() -> Self {
        Self {
            state: [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476, 0xc3d2_e1f0],
            buf: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    fn compress(state: &mut [u32; 5], chunk: &[u8; 64]) {
        Self::compress_tail(state, chunk);
    }

    /// One compression; returns the last 16 expanded message words (`w[64..80]`).
    fn compress_tail(state: &mut [u32; 5], chunk: &[u8; 64]) -> [u32; 16] {
        #[cfg(test)]
        SHA1_COMPRESSIONS.set(SHA1_COMPRESSIONS.get() + 1);
        let mut w = [0u32; 80];
        for (i, word) in chunk.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*word);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = *state;
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdcu32),
                _ => (b ^ c ^ d, 0xca62_c1d6u32),
            };
            let temp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        let mut tail = [0u32; 16];
        tail.copy_from_slice(&w[64..80]);
        tail
    }

    /// [`update_controlled`](Self::update_controlled) the way RAR 3.x's SHA-1 feeds its key derivation: a block
    /// hashed straight from `data` (every block after the first one that goes through the 64-byte buffer) is overwritten with the last 16 message words
    /// it expanded to, so the next round hashes different bytes there. Only passwords whose UTF-16 form plus
    /// salt (and the counter bytes) reach 64 bytes are affected.
    fn update_rar<C: KdfControl + ?Sized>(
        &mut self,
        mut data: &mut [u8],
        control: &mut C,
    ) -> std::result::Result<(), KdfControlError> {
        self.total_len += data.len() as u64;
        if self.buf_len + data.len() < 64 {
            self.buf[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
            self.buf_len += data.len();
            return Ok(());
        }
        {
            let take = (64 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &mut data[take..];
            if self.buf_len == 64 {
                control.charge(1)?;
                Self::compress(&mut self.state, &self.buf);
                self.buf_len = 0;
            }
        }
        let (blocks, rem) = data.as_chunks_mut::<64>();
        for b in blocks {
            control.charge(1)?;
            let tail = Self::compress_tail(&mut self.state, b);
            for (dst, word) in b.as_chunks_mut::<4>().0.iter_mut().zip(tail) {
                *dst = word.to_le_bytes();
            }
        }
        if !rem.is_empty() {
            self.buf[..rem.len()].copy_from_slice(rem);
            self.buf_len = rem.len();
        }
        Ok(())
    }

    fn update(&mut self, data: &[u8]) {
        self.update_controlled(data, &mut UnrestrictedKdf).expect("unrestricted SHA1");
    }
    fn update_controlled<C: KdfControl + ?Sized>(
        &mut self,
        mut data: &[u8],
        control: &mut C,
    ) -> std::result::Result<(), KdfControlError> {
        self.total_len += data.len() as u64;
        if self.buf_len > 0 {
            let take = (64 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                control.charge(1)?;
                Self::compress(&mut self.state, &self.buf);
                self.buf_len = 0;
            }
        }
        let (blocks, rem) = data.as_chunks::<64>();
        for b in blocks {
            control.charge(1)?;
            Self::compress(&mut self.state, b);
        }
        if !rem.is_empty() {
            self.buf[..rem.len()].copy_from_slice(rem);
            self.buf_len = rem.len();
        }
        Ok(())
    }

    fn finalize_words(&self) -> [u32; 5] {
        self.finalize_controlled(&mut UnrestrictedKdf).expect("unrestricted SHA1")
    }
    fn finalize_controlled<C: KdfControl + ?Sized>(
        &self,
        control: &mut C,
    ) -> std::result::Result<[u32; 5], KdfControlError> {
        let mut state = self.state;
        let bit_len = self.total_len * 8;
        let mut tail = [0u8; 128];
        tail[..self.buf_len].copy_from_slice(&self.buf[..self.buf_len]);
        tail[self.buf_len] = 0x80;
        if self.buf_len < 56 {
            tail[56..64].copy_from_slice(&bit_len.to_be_bytes());
            control.charge(1)?;
            Self::compress(&mut state, tail[..64].try_into().unwrap());
        } else {
            tail[120..128].copy_from_slice(&bit_len.to_be_bytes());
            control.charge(1)?;
            Self::compress(&mut state, tail[..64].try_into().unwrap());
            control.charge(1)?;
            Self::compress(&mut state, tail[64..128].try_into().unwrap());
        }
        Ok(state)
    }

    fn finalize_bytes(&self) -> [u8; 20] {
        let words = self.finalize_words();
        let mut out = [0u8; 20];
        for (i, &w) in words.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }
}

/// Derives the RAR4 (`SetKey30`) 16-byte AES-128 key and 16-byte IV from `password` and `salt`.
pub fn derive_rar4_key_iv(password: &str, salt: &[u8; 8]) -> ([u8; 16], [u8; 16]) {
    let units: Vec<u16> = password.encode_utf16().collect();
    derive_rar4_key_iv_impl(&units, salt, &mut UnrestrictedKdf).expect("unrestricted RAR4 derivation")
}

/// [`derive_rar4_key_iv`] for a password given as UTF-16 code units, hashed little-endian, unpaired surrogates
/// included; a surrogate pair counts as one character and hashes as its code point's low 16 bits, as UnRAR does. For a password that is not valid UTF-8 the caller chooses how its bytes become
/// units; `derive_rar4_key_iv` is this over `password.encode_utf16()`.
pub fn derive_rar4_key_iv_utf16(password: &[u16], salt: &[u8; 8]) -> ([u8; 16], [u8; 16]) {
    derive_rar4_key_iv_impl(password, salt, &mut UnrestrictedKdf).expect("unrestricted RAR4 derivation")
}

/// RAR 3.x keys by salt, for the one password of a run: the 2^18-round derivation runs once per salt (a solid or
/// split archive repeats one salt in every header). Derivation stops when `cancel` is set.
#[derive(Default)]
pub(crate) struct Rar4KeyCache {
    keys: Vec<([u8; 8], [u8; 16], [u8; 16])>,
}

impl Rar4KeyCache {
    /// Salts kept at most; an archive with more derives the oldest again.
    const KEPT: usize = 64;

    pub(crate) fn keys(
        &mut self,
        password: &str,
        salt: &[u8; 8],
        cancel: Option<&crate::extract::Cancellation>,
    ) -> std::result::Result<([u8; 16], [u8; 16]), KdfControlError> {
        if let Some(&(_, key, iv)) = self.keys.iter().find(|(s, ..)| s == salt) {
            return Ok((key, iv));
        }
        let units: Vec<u16> = password.encode_utf16().collect();
        let (key, iv) = derive_rar4_key_iv_impl(&units, salt, &mut Cancelable(cancel))?;
        if self.keys.len() == Self::KEPT {
            self.keys.remove(0);
        }
        self.keys.push((*salt, key, iv));
        Ok((key, iv))
    }
}

pub(crate) fn derive_rar4_key_iv_controlled(
    password: &str,
    salt: &[u8; 8],
    control: &mut dyn KdfControl,
) -> std::result::Result<([u8; 16], [u8; 16]), KdfControlError> {
    use crate::progressive::Resource;
    for (resource, attempted, limit) in [
        (Resource::PasswordUtf8Bytes, password.len() as u64, 4096),
        (Resource::PasswordEncodedBytes, password.encode_utf16().count() as u64 * 2, 8192),
    ] {
        if attempted > limit {
            return Err(KdfControlError::Limit { resource, limit, attempted });
        }
    }
    struct Derivation<'a> {
        control: &'a mut dyn KdfControl,
        blocks: u64,
    }
    impl KdfControl for Derivation<'_> {
        fn charge(&mut self, blocks: u64) -> std::result::Result<(), KdfControlError> {
            let attempted = self.blocks.saturating_add(blocks);
            if attempted > 1 << 22 {
                return Err(KdfControlError::Limit {
                    resource: Resource::KdfDerivationBlocks,
                    limit: 1 << 22,
                    attempted,
                });
            }
            self.control.charge(blocks)?;
            self.blocks = attempted;
            Ok(())
        }
    }
    let units: Vec<u16> = password.encode_utf16().collect();
    derive_rar4_key_iv_impl(&units, salt, &mut Derivation { control, blocks: 0 })
}

fn derive_rar4_key_iv_impl<C: KdfControl + ?Sized>(
    password: &[u16],
    salt: &[u8; 8],
    control: &mut C,
) -> std::result::Result<([u8; 16], [u8; 16]), KdfControlError> {
    let password = rar_password_prefix_utf16(password);
    let mut raw = Vec::with_capacity(password.len() * 2 + 8);
    // UnRAR and `rar` keep two bytes of each character: a character above U+FFFF (a surrogate pair here) is its
    // code point's low 16 bits, not the pair (measured with both binaries; see `docs/rar-passwords.md`).
    let mut units = password.iter().copied().peekable();
    while let Some(unit) = units.next() {
        let low = match (unit, units.peek()) {
            (0xD800..=0xDBFF, Some(&next @ 0xDC00..=0xDFFF)) => {
                units.next();
                let code = 0x1_0000 + ((u32::from(unit) - 0xD800) << 10) + (u32::from(next) - 0xDC00);
                code as u16
            }
            _ => unit,
        };
        raw.extend_from_slice(&low.to_le_bytes());
    }
    raw.extend_from_slice(salt);

    const ROUNDS: u32 = 0x40000;
    let mut sha = Sha1::new();
    let mut iv = [0u8; 16];
    for i in 0..ROUNDS {
        sha.update_rar(&mut raw, control)?;
        let idx = [i as u8, (i >> 8) as u8, (i >> 16) as u8];
        sha.update_controlled(&idx, control)?;
        if i % (ROUNDS / 16) == 0 {
            let words = sha.finalize_controlled(control)?;
            let pos = (i / (ROUNDS / 16)) as usize;
            if let Some(slot) = iv.get_mut(pos) {
                *slot = (words[4] & 0xff) as u8;
            }
        }
    }
    let words = sha.finalize_controlled(control)?;
    let mut key = [0u8; 16];
    for (i, &w) in words.iter().take(4).enumerate() {
        key[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    Ok((key, iv))
}

/// Decrypts an encrypted RAR4 block header at `pos` (starts with 8-byte salt followed by AES-128-CBC blocks).
pub fn decrypt_rar4_header(data: &[u8], pos: usize, key: &[u8; 16], iv: &[u8; 16]) -> Option<(Vec<u8>, usize)> {
    let first_block = data.get(pos..pos.checked_add(16)?)?;
    let first_dec = decrypt_cbc(key, iv, first_block)?;
    let head_type = *first_dec.get(2)?;
    if !(0x72..=0x7b).contains(&head_type) {
        return None;
    }
    let head_size = usize::from(u16::from_le_bytes(first_dec.get(5..7)?.try_into().ok()?));
    if !(7..=65536).contains(&head_size) {
        return None;
    }
    let padded = head_size.checked_next_multiple_of(16)?;
    let ct_end = pos.checked_add(padded)?;
    let ct = data.get(pos..ct_end)?;
    let dec = decrypt_cbc(key, iv, ct)?;
    let stored_crc = u16::from_le_bytes(dec.get(0..2)?.try_into().ok()?);
    let calc_crc = (crate::crc32::hash(dec.get(2..head_size)?) & 0xffff) as u16;
    if stored_crc != calc_crc {
        return None;
    }
    Some((dec, ct_end))
}

/// What a header-encrypted RAR4 (`-hp`) keeps at the start of its first encrypted block to test a password:
/// the 8-byte salt and the first 16-byte AES-128-CBC block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rar4HeaderCheck {
    pub salt: [u8; 8],
    pub block: [u8; 16],
}

impl Rar4HeaderCheck {
    pub fn to_bytes(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(24);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.block);
        out
    }

    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        Some(Self { salt: b.get(0..8)?.try_into().ok()?, block: b.get(8..24)?.try_into().ok()? })
    }

    pub fn accepts(&self, password: &str) -> bool {
        let (key, iv) = derive_rar4_key_iv(password, &self.salt);
        let Some(dec) = decrypt_cbc(&key, &iv, &self.block) else { return false };
        let Some(&head_type) = dec.get(2) else { return false };
        let Some(size_bytes) = dec.get(5..7) else { return false };
        let head_size = usize::from(u16::from_le_bytes([size_bytes[0], size_bytes[1]]));
        if !(0x74..=0x7b).contains(&head_type) || !(7..=16384).contains(&head_size) {
            return false;
        }
        if head_size <= 16 {
            let stored_crc = u16::from_le_bytes([dec[0], dec[1]]);
            let calc_crc = (crate::crc32::hash(&dec[2..head_size]) & 0xffff) as u16;
            return stored_crc == calc_crc;
        }
        true
    }
}

// ---------------------------------------------------------------------------
// ZIP Traditional Stream Cipher (ZipCrypto) & WinZip AES (`0x9901`)
// ---------------------------------------------------------------------------

fn crypto_keys(password: &[u8]) -> [u32; 3] {
    let mut keys = [0x1234_5678u32, 0x2345_6789, 0x3456_7890];
    for b in password {
        crypto_update(&mut keys, *b);
    }
    keys
}

fn crypto_update(keys: &mut [u32; 3], b: u8) {
    fn crc_byte(crc: u32, b: u8) -> u32 {
        let mut c = (crc ^ u32::from(b)) & 0xff;
        for _ in 0..8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0xedb8_8320 } else { c >> 1 };
        }
        (crc >> 8) ^ c
    }
    keys[0] = crc_byte(keys[0], b);
    keys[1] = keys[1].wrapping_add(keys[0] & 0xff).wrapping_mul(134_775_813).wrapping_add(1);
    keys[2] = crc_byte(keys[2], (keys[1] >> 24) as u8);
}

fn crypto_step(keys: &mut [u32; 3], cipher: u8) -> u8 {
    let plain = cipher ^ crypto_mask(keys);
    crypto_update(keys, plain);
    plain
}

fn crypto_mask(keys: &[u32; 3]) -> u8 {
    let t = keys[2] | 2;
    (t.wrapping_mul(t ^ 1) >> 8) as u8
}

pub(crate) struct ZipCrypto([u32; 3]);

impl ZipCrypto {
    pub(crate) fn new_cancellable<E>(password: &str, mut poll: impl FnMut() -> Result<(), E>) -> Result<Self, E> {
        let mut keys = [0x1234_5678, 0x2345_6789, 0x3456_7890];
        poll()?;
        for chunk in password.as_bytes().chunks(4096) {
            poll()?;
            for &byte in chunk {
                crypto_update(&mut keys, byte);
            }
        }
        Ok(Self(keys))
    }
    pub(crate) fn new(password: &str) -> Self {
        Self(crypto_keys(password.as_bytes()))
    }

    pub(crate) fn decrypt(&mut self, data: &mut [u8]) {
        for byte in data {
            *byte = crypto_step(&mut self.0, *byte);
        }
    }

    pub(crate) fn encrypt(&mut self, data: &mut [u8]) {
        for byte in data {
            let plaintext = *byte;
            *byte ^= crypto_mask(&self.0);
            crypto_update(&mut self.0, plaintext);
        }
    }
}

/// Decrypts a ZipCrypto entry starting at `data` (12-byte encryption header + payload) if `check` matches.
pub fn decrypt_zipcrypto(password: &str, check: u8, data: &[u8]) -> Option<Vec<u8>> {
    let header = data.get(..12)?;
    let payload = data.get(12..)?;
    let mut keys = crypto_keys(password.as_bytes());
    let mut last = 0u8;
    for b in header {
        last = crypto_step(&mut keys, *b);
    }
    if last != check {
        return None;
    }
    let mut out = Vec::with_capacity(payload.len());
    for b in payload {
        out.push(crypto_step(&mut keys, *b));
    }
    Some(out)
}

/// Reuses a complete owned member while retaining the encryption header.
pub(crate) fn decrypt_zipcrypto_in_place<E>(
    password: &str,
    expected: u8,
    data: &mut [u8],
    mut check: impl FnMut() -> Result<(), E>,
) -> Result<Option<std::ops::Range<usize>>, E> {
    check()?;
    let Some(header) = data.get(..12) else { return Ok(None) };
    let mut header: [u8; 12] = header.try_into().expect("fixed encryption header");
    let mut cipher = ZipCrypto::new(password);
    cipher.decrypt(&mut header);
    if header[11] != expected {
        return Ok(None);
    }
    for chunk in data[12..].chunks_mut(64 << 10) {
        check()?;
        cipher.decrypt(chunk);
    }
    Ok(Some(12..data.len()))
}

fn hmac_sha1(ipad: &[u8; 64], opad: &[u8; 64], data: &[u8]) -> [u8; 20] {
    let mut inner = Sha1::new();
    inner.update(ipad);
    inner.update(data);
    let inner_digest = inner.finalize_bytes();
    let mut outer = Sha1::new();
    outer.update(opad);
    outer.update(&inner_digest);
    outer.finalize_bytes()
}

pub(crate) struct HmacSha1 {
    inner: Sha1,
    outer: Sha1,
}

impl HmacSha1 {
    pub(crate) fn new(key: &[u8]) -> Self {
        let mut block = [0; 64];
        if key.len() > block.len() {
            let mut hash = Sha1::new();
            hash.update(key);
            block[..20].copy_from_slice(&hash.finalize_bytes());
        } else {
            block[..key.len()].copy_from_slice(key);
        }
        let mut inner_pad = [0x36; 64];
        let mut outer_pad = [0x5c; 64];
        for ((inside, outside), key) in inner_pad.iter_mut().zip(&mut outer_pad).zip(block) {
            *inside ^= key;
            *outside ^= key;
        }
        let mut inner = Sha1::new();
        inner.update(&inner_pad);
        let mut outer = Sha1::new();
        outer.update(&outer_pad);
        Self { inner, outer }
    }

    pub(crate) fn update(&mut self, bytes: &[u8]) -> Option<()> {
        self.inner.total_len.checked_add(bytes.len() as u64)?.checked_mul(8)?;
        self.inner.update(bytes);
        Some(())
    }

    pub(crate) fn finish(&self) -> [u8; 20] {
        let mut outer = self.outer.clone();
        outer.update(&self.inner.finalize_bytes());
        outer.finalize_bytes()
    }

    fn mac(&self, bytes: &[u8]) -> [u8; 20] {
        let mut inner = self.inner.clone();
        inner.update(bytes);
        let mut outer = self.outer.clone();
        outer.update(&inner.finalize_bytes());
        outer.finalize_bytes()
    }
}

// The fixed output covers all supported strengths. The buffered public reader
// helpers retain their existing allocation and return-value contracts.
fn derive_winzip_fixed(password: &[u8], salt: &[u8], key_len: usize) -> Option<[u8; 66]> {
    if ![16, 24, 32].contains(&key_len) || salt.len() != key_len / 2 {
        return None;
    }
    let keyed = HmacSha1::new(password);
    let wanted = 2 * key_len + 2;
    let mut result = [0; 66];
    let mut salt_block = [0; 20];
    salt_block[..salt.len()].copy_from_slice(salt);
    for (index, target) in result[..wanted].chunks_mut(20).enumerate() {
        salt_block[salt.len()..salt.len() + 4].copy_from_slice(&((index + 1) as u32).to_be_bytes());
        let mut u = keyed.mac(&salt_block[..salt.len() + 4]);
        let mut combined = u;
        for _ in 1..1000 {
            u = keyed.mac(&u);
            for (byte, next) in combined.iter_mut().zip(u) {
                *byte ^= next;
            }
        }
        target.copy_from_slice(&combined[..target.len()]);
    }
    Some(result)
}

/// Fixed PBKDF2-HMAC-SHA1; polling leaves the 1000-round result unchanged.
pub(crate) fn derive_winzip_cancellable<E>(
    password: &[u8],
    salt: &[u8],
    key_len: usize,
    mut poll: impl FnMut() -> Result<(), E>,
) -> Result<Option<[u8; 66]>, E> {
    if ![16, 24, 32].contains(&key_len) || salt.len() != key_len / 2 {
        return Ok(None);
    }
    poll()?;
    let mut digest = [0; 20];
    let key = if password.len() > 64 {
        let mut hash = Sha1::new();
        for chunk in password.chunks(4096) {
            poll()?;
            hash.update(chunk);
        }
        digest.copy_from_slice(&hash.finalize_bytes());
        &digest[..]
    } else {
        password
    };
    let keyed = HmacSha1::new(key);
    let mut result = [0; 66];
    let mut block = [0; 20];
    block[..salt.len()].copy_from_slice(salt);
    for (index, target) in result[..2 * key_len + 2].chunks_mut(20).enumerate() {
        poll()?;
        block[salt.len()..salt.len() + 4].copy_from_slice(&((index + 1) as u32).to_be_bytes());
        let mut u = keyed.mac(&block[..salt.len() + 4]);
        let mut combined = u;
        for round in 1..1000 {
            if round % 64 == 0 {
                poll()?;
            }
            u = keyed.mac(&u);
            for (byte, next) in combined.iter_mut().zip(u) {
                *byte ^= next;
            }
        }
        target.copy_from_slice(&combined[..target.len()]);
    }
    poll()?;
    Ok(Some(result))
}

/// Persistent byte-granular WinZip counter, including partial keystream blocks.
pub(crate) struct WinZipCtr {
    cipher: AesKey,
    counter: [u8; 16],
    block: [u8; 16],
    used: usize,
}
impl WinZipCtr {
    pub(crate) fn new(key: &[u8]) -> Option<Self> {
        Some(Self { cipher: AesKey::new(key)?, counter: [0; 16], block: [0; 16], used: 16 })
    }
    pub(crate) fn apply(&mut self, bytes: &mut [u8]) -> Option<()> {
        for byte in bytes {
            if self.used == 16 {
                if self.counter == [255; 16] {
                    return None;
                }
                for b in &mut self.counter {
                    *b = b.wrapping_add(1);
                    if *b != 0 {
                        break;
                    }
                }
                self.block = self.cipher.encrypt_block(&self.counter);
                self.used = 0;
            }
            *byte ^= self.block[self.used];
            self.used += 1;
        }
        Some(())
    }
}

pub(crate) struct WinZipAesEncryptor {
    key: AesKey,
    counter: [u8; 16],
    stream: [u8; 16],
    used: usize,
    hmac: HmacSha1,
    verifier: [u8; 2],
}

impl WinZipAesEncryptor {
    pub(crate) fn new(password: &[u8], salt: &[u8], key_len: usize) -> Option<Self> {
        let derived = derive_winzip_fixed(password, salt, key_len)?;
        Some(Self {
            key: AesKey::new(&derived[..key_len])?,
            counter: [0; 16],
            stream: [0; 16],
            used: 16,
            hmac: HmacSha1::new(&derived[key_len..2 * key_len]),
            verifier: derived[2 * key_len..2 * key_len + 2].try_into().ok()?,
        })
    }

    pub(crate) fn verifier(&self) -> [u8; 2] {
        self.verifier
    }

    pub(crate) fn encrypt(&mut self, bytes: &mut [u8]) -> Option<()> {
        self.hmac.inner.total_len.checked_add(bytes.len() as u64)?.checked_mul(8)?;
        self.xor(bytes)?;
        self.hmac.update(bytes)
    }

    pub(crate) fn decrypt(&mut self, bytes: &mut [u8]) -> Option<()> {
        self.hmac.update(bytes)?;
        self.xor(bytes)
    }

    fn xor(&mut self, bytes: &mut [u8]) -> Option<()> {
        for byte in bytes.iter_mut() {
            if self.used == self.stream.len() {
                let mut carry = true;
                for counter in &mut self.counter {
                    let (next, overflow) = counter.overflowing_add(1);
                    *counter = next;
                    if !overflow {
                        carry = false;
                        break;
                    }
                }
                if carry {
                    return None;
                }
                self.stream = self.key.encrypt_block(&self.counter);
                self.used = 0;
            }
            *byte ^= self.stream[self.used];
            self.used += 1;
        }
        Some(())
    }

    pub(crate) fn tag(&self) -> [u8; 10] {
        self.hmac.finish()[..10].try_into().expect("fixed tag length")
    }
}

/// PBKDF2-HMAC-SHA1 (1000 rounds) for WinZip AES: derives `2 * key_len + 2` bytes.
pub fn aes_derive(password: &[u8], salt: &[u8], key_len: usize) -> Option<Vec<u8>> {
    let mut k = [0u8; 64];
    if password.len() > 64 {
        let mut s = Sha1::new();
        s.update(password);
        k[..20].copy_from_slice(&s.finalize_bytes());
    } else {
        k[..password.len()].copy_from_slice(password);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let wanted = key_len * 2 + 2;
    let mut derived = Vec::with_capacity(wanted + 20);
    let mut block = 1u32;
    let mut salt_block = Vec::with_capacity(salt.len() + 4);
    while derived.len() < wanted {
        salt_block.clear();
        salt_block.extend_from_slice(salt);
        salt_block.extend_from_slice(&block.to_be_bytes());
        let mut u = hmac_sha1(&ipad, &opad, &salt_block);
        let mut out = u;
        for _ in 1..1000 {
            u = hmac_sha1(&ipad, &opad, &u);
            for (slot, b) in out.iter_mut().zip(u) {
                *slot ^= b;
            }
        }
        derived.extend_from_slice(&out);
        block += 1;
    }
    derived.truncate(wanted);
    Some(derived)
}

/// Decrypts WinZip AES (method 99) data starting with the salt and password verifier.
///
/// With `Some(packed)`, `data` must contain exactly `packed` bytes, including
/// the 10-byte authentication tag. The ciphertext is authenticated before decryption.
/// With `None`, the bytes after the verifier are treated as a ciphertext prefix
/// for preview and decrypted without authentication.
pub fn decrypt_winzip_aes(password: &str, strength: u8, data: &[u8], full_packed: Option<u64>) -> Option<Vec<u8>> {
    use subtle::ConstantTimeEq;

    const TAG_LEN: usize = 10;

    if !(1..=3).contains(&strength) {
        return None;
    }
    let salt_len = usize::from(strength) * 4 + 4;
    let key_len = (usize::from(strength) + 1) * 8;
    let ct_end = if let Some(packed) = full_packed {
        if usize::try_from(packed).ok()? != data.len() {
            return None;
        }
        data.len().checked_sub(TAG_LEN)?
    } else {
        data.len()
    };
    let salt = data.get(..salt_len)?;
    let verifier = data.get(salt_len..salt_len + 2)?;
    let ct = data.get(salt_len + 2..ct_end)?;
    let derived = aes_derive(password.as_bytes(), salt, key_len)?;
    if !bool::from(derived.get(key_len * 2..)?.ct_eq(verifier)) {
        return None;
    }
    if full_packed.is_some() {
        let mut ipad = [0x36; 64];
        let mut opad = [0x5c; 64];
        for (i, byte) in derived[key_len..key_len * 2].iter().enumerate() {
            ipad[i] ^= byte;
            opad[i] ^= byte;
        }
        let expected = hmac_sha1(&ipad, &opad, ct);
        if !bool::from(expected[..TAG_LEN].ct_eq(&data[ct_end..])) {
            return None;
        }
    }
    decrypt_winzip_ctr(&derived[..key_len], ct)
}

/// Authenticates a complete member before modifying its ciphertext in place.
/// The returned range excludes the salt, verifier and authentication tag.
pub(crate) fn decrypt_winzip_aes_in_place<E>(
    password: &str,
    strength: u8,
    data: &mut [u8],
    mut check: impl FnMut() -> Result<(), E>,
) -> Result<Option<std::ops::Range<usize>>, E> {
    use subtle::ConstantTimeEq;

    check()?;
    if !(1..=3).contains(&strength) {
        return Ok(None);
    }
    let key_len = (usize::from(strength) + 1) * 8;
    let salt_len = key_len / 2;
    if data.len() < salt_len + 12 {
        return Ok(None);
    }
    let range = salt_len + 2..data.len() - 10;
    let Some(derived) = derive_winzip_fixed(password.as_bytes(), &data[..salt_len], key_len) else {
        return Ok(None);
    };
    if !bool::from(derived[2 * key_len..2 * key_len + 2].ct_eq(&data[salt_len..salt_len + 2])) {
        return Ok(None);
    }
    let mut hmac = HmacSha1::new(&derived[key_len..2 * key_len]);
    for chunk in data[range.clone()].chunks(64 << 10) {
        check()?;
        if hmac.update(chunk).is_none() {
            return Ok(None);
        }
    }
    if !bool::from(hmac.finish()[..10].ct_eq(&data[range.end..])) {
        return Ok(None);
    }
    let Some(cipher) = AesKey::new(&derived[..key_len]) else { return Ok(None) };
    let mut counter = [0; 16];
    for chunk in data[range.clone()].chunks_mut(64 << 10) {
        check()?;
        winzip_ctr_xor(&cipher, &mut counter, chunk);
    }
    Ok(Some(range))
}

/// The salt and password verifier a WinZip AES member of `strength` starts with, in bytes (None for an unknown
/// strength).
pub(crate) fn winzip_aes_header_len(strength: u8) -> Option<usize> {
    (1..=3).contains(&strength).then(|| (usize::from(strength) + 1) * 4 + 2)
}

/// A WinZip AES member that a cut ends inside of, `data` being the bytes of it there and `packed` its declared size,
/// decrypted in place as 7-Zip 26.06 decrypts it: its password verifier is checked, and the ciphertext there (up to
/// where the authentication code would start) is decrypted without that code, which isn't there to check. The returned
/// range is the plaintext; None when the salt and verifier aren't all there or the verifier doesn't match.
pub(crate) fn decrypt_winzip_aes_cut_in_place<E>(
    password: &str,
    strength: u8,
    data: &mut [u8],
    packed: u64,
    mut check: impl FnMut() -> Result<(), E>,
) -> Result<Option<std::ops::Range<usize>>, E> {
    use subtle::ConstantTimeEq;

    check()?;
    let Some(header) = winzip_aes_header_len(strength) else { return Ok(None) };
    if data.len() < header {
        return Ok(None);
    }
    let key_len = (usize::from(strength) + 1) * 8;
    let salt_len = key_len / 2;
    let tag_at = usize::try_from(packed.saturating_sub(10)).unwrap_or(usize::MAX);
    let range = header..data.len().min(tag_at).max(header);
    let Some(derived) = derive_winzip_fixed(password.as_bytes(), &data[..salt_len], key_len) else {
        return Ok(None);
    };
    if !bool::from(derived[2 * key_len..2 * key_len + 2].ct_eq(&data[salt_len..header])) {
        return Ok(None);
    }
    let Some(cipher) = AesKey::new(&derived[..key_len]) else { return Ok(None) };
    let mut counter = [0; 16];
    for chunk in data[range.clone()].chunks_mut(64 << 10) {
        check()?;
        winzip_ctr_xor(&cipher, &mut counter, chunk);
    }
    Ok(Some(range))
}

/// Parses WinZip AES extra field `0x9901`: `(strength, actual_method)`.
pub fn aes_extra(extra: &[u8]) -> Option<(u8, u16)> {
    let (strength, _, method) = aes_extra_info(extra)?;
    Some((strength, method))
}

/// Parses WinZip AES extra field `0x9901`: `(strength, vendor_version, actual_method)`.
pub fn aes_extra_info(extra: &[u8]) -> Option<(u8, u16, u16)> {
    let mut p = 0usize;
    while p + 4 <= extra.len() {
        let id = u16::from_le_bytes([extra[p], extra[p + 1]]);
        let size = u16::from_le_bytes([extra[p + 2], extra[p + 3]]) as usize;
        if id == 0x9901 && size >= 7 {
            let vendor = u16::from_le_bytes(extra.get(p + 4..p + 6)?.try_into().ok()?);
            let strength = extra.get(p + 8).copied().filter(|s| (1..=3).contains(s))?;
            let method = u16::from_le_bytes(extra.get(p + 9..p + 11)?.try_into().ok()?);
            return Some((strength, vendor, method));
        }
        p = p.checked_add(4 + size)?;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    struct KdfMeter {
        blocks: u64,
        limit: u64,
        cancel_at: Option<u64>,
    }
    impl KdfControl for KdfMeter {
        fn charge(&mut self, blocks: u64) -> std::result::Result<(), KdfControlError> {
            if self.cancel_at.is_some_and(|at| self.blocks >= at) {
                return Err(KdfControlError::Canceled);
            }
            let attempted = self.blocks + blocks;
            if attempted > self.limit {
                return Err(KdfControlError::Limit {
                    resource: crate::progressive::Resource::KdfDerivationBlocks,
                    limit: self.limit,
                    attempted,
                });
            }
            self.blocks = attempted;
            Ok(())
        }
    }
    #[test]
    fn rar_password_prefixes_count_characters() {
        let long: String = "a".repeat(126) + "é😀x";
        assert_eq!(rar_password_prefix_utf8(long.as_bytes()), ("a".repeat(126) + "é").as_bytes());
        let units: Vec<u16> = long.encode_utf16().collect();
        assert_eq!(rar_password_prefix_utf16(&units), &units[..127]);
        let units: Vec<u16> = ("a".repeat(126) + "😀x").encode_utf16().collect();
        assert_eq!(rar_password_prefix_utf16(&units).len(), 128, "a pair is one character");
        assert_eq!(rar_password_prefix_utf16(&units[..127]), &units[..127]);
        let exact = "b".repeat(127);
        assert_eq!(rar_password_prefix_utf8(exact.as_bytes()).len(), 127);
        assert_eq!(rar_password_prefix_utf8(&[0xff; 200]).len(), 127);
    }

    fn kdf_meter(limit: u64) -> KdfMeter {
        KdfMeter { blocks: 0, limit, cancel_at: None }
    }

    #[test]
    fn controlled_rar4_counts_primitives_including_clone_padding_and_stops_before_work() {
        for password in ["", "pw", "é界😀", "abcdefghijklmnopqrstuvw", "abcdefghijklmnopqrstuvwx"] {
            SHA1_COMPRESSIONS.set(0);
            let mut meter = kdf_meter(u64::MAX);
            let actual = derive_rar4_key_iv_controlled(password, &[1; 8], &mut meter).unwrap();
            assert_eq!(meter.blocks, SHA1_COMPRESSIONS.get());
            // each character is two bytes of the hashed message, whatever its UTF-16 length
            let raw = password.chars().count() as u64 * 2 + 11;
            let expected = 0x40000 * raw / 64
                + (0..16).map(|i| 1 + u64::from(((i * 0x4000 + 1) * raw) % 64 >= 56)).sum::<u64>()
                + 1;
            assert_eq!(meter.blocks, expected);
            assert_eq!(actual, derive_rar4_key_iv(password, &[1; 8]));
            let known = match password {
                "pw" => Some(("77005689078b689864882b7665ede966", "510faeafff2ac0c52af181d88b5db8e3")),
                _ => None,
            };
            if let Some((key, iv)) = known {
                let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
                assert_eq!(hex(&actual.0), key);
                assert_eq!(hex(&actual.1), iv);
            }
        }
        for n in [55, 56, 63, 64] {
            let mut sha = Sha1::new();
            let mut meter = kdf_meter(u64::MAX);
            SHA1_COMPRESSIONS.set(0);
            sha.update_controlled(&vec![0; n], &mut meter).unwrap();
            sha.finalize_controlled(&mut meter).unwrap();
            assert_eq!(meter.blocks, (n as u64 + 9).div_ceil(64));
            assert_eq!(meter.blocks, SHA1_COMPRESSIONS.get());
        }
        for cancel in [false, true] {
            let mut meter = kdf_meter(if cancel { u64::MAX } else { 1024 });
            meter.cancel_at = cancel.then_some(1024);
            SHA1_COMPRESSIONS.set(0);
            let err = derive_rar4_key_iv_controlled("pw", &[1; 8], &mut meter).unwrap_err();
            assert_eq!(SHA1_COMPRESSIONS.get(), 1024);
            assert_eq!(meter.blocks, 1024);
            assert!(matches!(
                (cancel, err),
                (true, KdfControlError::Canceled) | (false, KdfControlError::Limit { attempted: 1025, .. })
            ));
        }
        SHA1_COMPRESSIONS.set(0);
        let mut meter = kdf_meter(u64::MAX);
        assert!(matches!(
            derive_rar4_key_iv_controlled(&"x".repeat(4097), &[0; 8], &mut meter),
            Err(KdfControlError::Limit { resource: crate::progressive::Resource::PasswordUtf8Bytes, .. })
        ));
        assert_eq!(SHA1_COMPRESSIONS.get(), 0);
        assert_eq!(meter.blocks, 0);
    }

    #[test]
    fn controlled_rar4_long_passwords_cost_what_the_127_character_prefix_costs() {
        // RAR keeps 127 characters, so the derivation of any longer password stays far under the hard ceiling.
        let mut long = kdf_meter(u64::MAX);
        let mut cut = kdf_meter(u64::MAX);
        let key = derive_rar4_key_iv_controlled(&"x".repeat(4096), &[0; 8], &mut long).unwrap();
        assert_eq!(key, derive_rar4_key_iv_controlled(&"x".repeat(127), &[0; 8], &mut cut).unwrap());
        assert_eq!(long.blocks, cut.blocks);
        assert!(long.blocks < 1 << 21, "{}", long.blocks);
    }

    #[test]
    fn controlled_rar5_stops_mid_derivation_and_hash_key_work() {
        let mut cancel = kdf_meter(u64::MAX);
        cancel.cancel_at = Some(1024);
        SHA256_COMPRESSIONS.set(0);
        assert!(matches!(
            derive_rar5_keys_controlled("secret", 12, &[0; 16], None, &mut cancel),
            Err(ControlledKdfError::Control(KdfControlError::Canceled))
        ));
        assert!(cancel.blocks >= 1024 && cancel.blocks <= 2048);
        assert_eq!(cancel.blocks, SHA256_COMPRESSIONS.get());
        let mut limited = kdf_meter(2 + 2 * (1 << 3) + 10);
        assert!(matches!(
            derive_rar5_keys_controlled("secret", 3, &[0; 16], None, &mut limited),
            Err(ControlledKdfError::Control(KdfControlError::Limit { .. }))
        ));
        assert_eq!(limited.blocks, limited.limit);
    }

    #[test]
    fn controlled_rar5_charges_actual_compressions_and_preserves_keys() {
        for n in [0, 64, 65, 119, 120, 4096] {
            let password = "x".repeat(n);
            let legacy = derive_rar5_keys(&password, 3, &[7; 16], None).unwrap();
            let mut meter = kdf_meter(u64::MAX);
            SHA256_COMPRESSIONS.set(0);
            let got = derive_rar5_keys_controlled(&password, 3, &[7; 16], None, &mut meter).unwrap();
            assert_eq!(meter.blocks, SHA256_COMPRESSIONS.get(), "password length {n}");
            assert_eq!(got.key, legacy.key);
            assert_eq!(got.hash_key, legacy.hash_key);
            assert_eq!(got.evidence, legacy.evidence);
        }
    }

    #[test]
    fn controlled_rar5_rejects_password_and_exponent_before_hashing() {
        for (password, exponent, resource) in [
            ("x".repeat(4097), 0, crate::progressive::Resource::PasswordUtf8Bytes),
            ("x".to_owned(), 21, crate::progressive::Resource::KdfExponent),
        ] {
            let mut meter = kdf_meter(u64::MAX);
            SHA256_COMPRESSIONS.set(0);
            assert!(matches!(derive_rar5_keys_controlled(&password, exponent, &[0;16], None, &mut meter),
                Err(ControlledKdfError::Control(KdfControlError::Limit { resource: actual, .. })) if actual == resource));
            assert_eq!(meter.blocks, 0);
            assert_eq!(SHA256_COMPRESSIONS.get(), 0);
        }
    }

    #[test]
    fn controlled_rar5_verifier_work_is_charged_and_corruption_is_not_wrong_password() {
        // Independent Python hashlib/hmac known answer for secret, salt [7;16], exponent3.
        let check = [0x3c, 0xb4, 0xa6, 0x01, 0x77, 0xb4, 0x1a, 0xe5];
        let sum = [0x16, 0xc9, 0x41, 0x3b];
        let mut meter = kdf_meter(u64::MAX);
        SHA256_COMPRESSIONS.set(0);
        let got = derive_rar5_keys_controlled("secret", 3, &[7; 16], Some((check, sum)), &mut meter).unwrap();
        assert_eq!(got.evidence, crate::error::RarPasswordEvidence::VerifierMatched);
        assert_eq!(meter.blocks, 2 + 2 * 8 + 32 + 1 + 32);
        assert_eq!(meter.blocks, SHA256_COMPRESSIONS.get());
        let mut limited = kdf_meter(2 + 2 * 8 + 32 + 1 + 10);
        assert!(matches!(
            derive_rar5_keys_controlled("secret", 3, &[7; 16], Some((check, sum)), &mut limited),
            Err(ControlledKdfError::Control(KdfControlError::Limit { .. }))
        ));
        assert_eq!(limited.blocks, limited.limit);
        assert!(matches!(
            derive_rar5_keys_controlled("wrong", 3, &[7; 16], Some((check, sum)), &mut kdf_meter(u64::MAX)),
            Err(ControlledKdfError::Crypt(Rar5CryptError::WrongPassword))
        ));
        let bad =
            derive_rar5_keys_controlled("wrong", 3, &[7; 16], Some((check, [0; 4])), &mut kdf_meter(u64::MAX)).unwrap();
        assert_eq!(
            bad.evidence,
            crate::error::RarPasswordEvidence::VerifierUnavailable(
                crate::error::RarVerifierUnavailable::CheckChecksumMismatch
            )
        );
    }

    // The AES-128 fixture comes from Prybar d3b8aa32a7c7214919b9c973588a9aa97a6a0e88.
    // Python hashlib and hmac and OpenSSL AES-ECB generated the fixtures independently.
    const AES_PASSWORD: &str = "prybar-fixture";
    const AES_FIXTURES: [(u8, &[u8], &[u8]); 3] = [
        (
            1,
            &[
                49, 50, 51, 52, 53, 54, 55, 56, 153, 191, 197, 64, 79, 101, 103, 92, 73, 178, 222, 207, 22, 192, 51,
                16, 127, 189, 76, 25, 140,
            ],
            b"hello pry",
        ),
        (
            2,
            &[
                49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 60, 136, 41, 180, 105, 28, 77, 228, 120, 155, 112, 7,
                174, 93, 111, 242, 148, 11, 66, 182, 93, 138, 189, 164, 33, 206, 162, 187, 170, 49, 127, 137, 243, 7,
                22, 15, 144, 85, 84, 98, 174, 19, 58, 225, 89, 169, 188, 217,
            ],
            b"WinZip AES fixture across CTR blocks",
        ),
        (
            3,
            &[
                49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102, 103, 55, 108, 59, 75, 78, 18, 73, 213,
                62, 53, 134, 241, 128, 148, 158, 57, 34, 200, 88, 19, 73, 163, 62, 13, 7, 115, 194, 62, 70, 21, 220,
                88, 175, 19, 146, 81, 98, 148, 247, 157, 137, 199, 148, 224, 5, 28, 238, 88,
            ],
            b"WinZip AES fixture across CTR blocks",
        ),
    ];

    #[test]
    fn rar4_key_cache_derives_once_per_salt_and_stops_when_canceled() {
        let mut cache = Rar4KeyCache::default();
        let canceled = crate::extract::Cancellation::default();
        canceled.cancel();
        // a salt never derived stops at the first block once canceled
        assert_eq!(cache.keys("pw", b"saltsalt", Some(&canceled)), Err(KdfControlError::Canceled));
        let keys = cache.keys("pw", b"saltsalt", None).unwrap();
        assert_eq!(keys, derive_rar4_key_iv("pw", b"saltsalt"));
        // a salt derived before comes from the cache: no work left to cancel
        assert_eq!(cache.keys("pw", b"saltsalt", Some(&canceled)), Ok(keys));
        assert_eq!(cache.keys("pw", b"pepper!!", Some(&canceled)), Err(KdfControlError::Canceled));
    }

    #[test]
    fn cancellable_derivation_and_persistent_ctr_match_legacy() {
        for key_len in [16, 24, 32] {
            let salt = [3; 16];
            let password = vec![b'p'; 65535];
            let reference = derive_winzip_fixed(&password, &salt[..key_len / 2], key_len).unwrap();
            let mut polls = 0;
            let actual = derive_winzip_cancellable(&password, &salt[..key_len / 2], key_len, || {
                polls += 1;
                Ok::<_, ()>(())
            })
            .unwrap()
            .unwrap();
            assert_eq!(actual, reference);
            for stop in 1..=polls {
                let mut current = 0;
                assert_eq!(
                    derive_winzip_cancellable(&password, &salt[..key_len / 2], key_len, || {
                        current += 1;
                        if current == stop { Err(()) } else { Ok(()) }
                    }),
                    Err(())
                );
                assert_eq!(current, stop);
            }
            let plain = (0..193).map(|i| i as u8).collect::<Vec<_>>();
            let expected = decrypt_winzip_ctr(&reference[..key_len], &plain).unwrap();
            for split in 0..=plain.len() {
                let mut actual = plain.clone();
                let mut ctr = WinZipCtr::new(&reference[..key_len]).unwrap();
                ctr.apply(&mut actual[..split]).unwrap();
                for chunk in actual[split..].chunks_mut(1) {
                    ctr.apply(chunk).unwrap();
                }
                assert_eq!(actual, expected);
            }
            let mut ctr = WinZipCtr::new(&reference[..key_len]).unwrap();
            ctr.counter = [255; 16];
            assert!(ctr.apply(&mut [0]).is_none());
        }
        let password = "p".repeat(65535);
        let mut expected = [0; 64];
        ZipCrypto::new(&password).decrypt(&mut expected);
        let mut actual = [0; 64];
        ZipCrypto::new_cancellable(&password, || Ok::<_, ()>(())).unwrap().decrypt(&mut actual);
        assert_eq!(actual, expected);
        for stop in 1..=17 {
            let mut polls = 0;
            assert!(
                ZipCrypto::new_cancellable(&password, || {
                    polls += 1;
                    if polls == stop { Err(()) } else { Ok(()) }
                })
                .is_err()
            );
        }
    }

    #[test]
    fn incremental_winzip_aes_matches_independent_vectors_at_chunk_boundaries() {
        let password = format!("a native AES fixture password with UTF-8 雪 {}", "p".repeat(67));
        let vectors = include_str!("../tests/fixtures/winzip-aes-stream.tsv");
        fn hex(bytes: &[u8]) -> String {
            bytes.iter().map(|byte| format!("{byte:02x}")).collect()
        }
        for line in vectors.lines().filter(|line| !line.starts_with('#')) {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            let strength = fields[0].parse::<usize>().unwrap();
            let len = fields[1].parse::<usize>().unwrap();
            let key_len = (strength + 1) * 8;
            let salt = (1..=strength * 4 + 4).map(|byte| byte as u8).collect::<Vec<_>>();
            let plain = (0..len).map(|i| (i * 73 + (i >> 8) + 19) as u8).collect::<Vec<_>>();
            for chunk in [1, 15, 16, 17, 63, 64, 65, 65536] {
                let mut cipher = WinZipAesEncryptor::new(password.as_bytes(), &salt, key_len).unwrap();
                assert_eq!(hex(&cipher.verifier()), fields[2]);
                let mut ciphertext = plain.clone();
                for block in ciphertext.chunks_mut(chunk) {
                    cipher.encrypt(block).unwrap();
                }
                let mut sha = Sha1::new();
                sha.update(&ciphertext);
                assert_eq!(hex(&sha.finalize_bytes()), fields[3], "{strength} {len} {chunk}");
                assert_eq!(hex(&cipher.tag()), fields[4], "{strength} {len} {chunk}");
            }
        }
    }

    #[test]
    fn incremental_winzip_aes_reproduces_original_ciphertext_and_tags() {
        for (strength, expected, plaintext) in AES_FIXTURES {
            let key_len = (usize::from(strength) + 1) * 8;
            let salt_len = key_len / 2;
            let mut cipher = WinZipAesEncryptor::new(AES_PASSWORD.as_bytes(), &expected[..salt_len], key_len).unwrap();
            assert_eq!(cipher.verifier(), expected[salt_len..salt_len + 2]);
            let mut bytes = plaintext.to_vec();
            for chunk in bytes.chunks_mut(3) {
                cipher.encrypt(chunk).unwrap();
            }
            assert_eq!(bytes, &expected[salt_len + 2..expected.len() - 10]);
            assert_eq!(cipher.tag(), expected[expected.len() - 10..]);
        }
    }

    #[test]
    fn incremental_winzip_aes_decrypts_and_authenticates_original_vectors() {
        for (strength, expected, plaintext) in AES_FIXTURES {
            let key_len = (usize::from(strength) + 1) * 8;
            let salt_len = key_len / 2;
            for chunk in [1, 15, 16, 17, 63, 64, 65, 65536] {
                let mut cipher =
                    WinZipAesEncryptor::new(AES_PASSWORD.as_bytes(), &expected[..salt_len], key_len).unwrap();
                let mut bytes = expected[salt_len + 2..expected.len() - 10].to_vec();
                for block in bytes.chunks_mut(chunk) {
                    cipher.decrypt(block).unwrap();
                }
                assert_eq!(bytes, plaintext);
                assert_eq!(cipher.tag(), expected[expected.len() - 10..]);
            }
        }
    }

    #[test]
    fn incremental_winzip_aes_rejects_counter_and_hmac_length_overflow() {
        let mut cipher = WinZipAesEncryptor::new(b"password", &[1; 8], 16).unwrap();
        cipher.counter = [255; 16];
        assert!(cipher.encrypt(&mut [1]).is_none());
        let mut cipher = WinZipAesEncryptor::new(b"password", &[1; 8], 16).unwrap();
        cipher.hmac.inner.total_len = u64::MAX / 8;
        assert!(cipher.encrypt(&mut [1]).is_none());
    }

    #[test]
    fn in_place_aes_authenticates_before_modifying_independent_vectors() {
        for (strength, encrypted, plaintext) in AES_FIXTURES {
            let mut data = encrypted.to_vec();
            let range =
                decrypt_winzip_aes_in_place(AES_PASSWORD, strength, &mut data, || Ok::<_, ()>(())).unwrap().unwrap();
            assert_eq!(&data[range.clone()], plaintext);
            assert_eq!(&data[..range.start], &encrypted[..range.start]);
            assert_eq!(&data[range.end..], &encrypted[range.end..]);
            for password in [AES_PASSWORD, "wrong password"] {
                let mut damaged = encrypted.to_vec();
                if password == AES_PASSWORD {
                    *damaged.last_mut().unwrap() ^= 1;
                }
                let before = damaged.clone();
                assert!(
                    decrypt_winzip_aes_in_place(password, strength, &mut damaged, || Ok::<_, ()>(()))
                        .unwrap()
                        .is_none()
                );
                assert_eq!(damaged, before);
            }
            for len in [0, range.start - 1, range.start, encrypted.len() - 1] {
                let mut truncated = encrypted[..len].to_vec();
                let before = truncated.clone();
                assert!(
                    decrypt_winzip_aes_in_place(AES_PASSWORD, strength, &mut truncated, || Ok::<_, ()>(()))
                        .unwrap()
                        .is_none()
                );
                assert_eq!(truncated, before);
            }
        }
    }

    #[test]
    fn in_place_crypto_checks_cancellation_during_authentication_and_decryption() {
        let plain = vec![7; (64 << 10) + 17];
        let mut cipher = WinZipAesEncryptor::new(b"password", &[3; 16], 32).unwrap();
        let mut encrypted = vec![3; 16];
        encrypted.extend(cipher.verifier());
        let mut payload = plain.clone();
        cipher.encrypt(&mut payload).unwrap();
        encrypted.extend(payload);
        encrypted.extend(cipher.tag());
        for stop in 1..=5 {
            let mut data = encrypted.clone();
            let mut checks = 0;
            let result = decrypt_winzip_aes_in_place("password", 3, &mut data, || {
                checks += 1;
                if checks == stop { Err("cancelled") } else { Ok(()) }
            });
            assert_eq!(result, Err("cancelled"));
            assert_eq!(checks, stop);
            if stop <= 4 {
                assert_eq!(data, encrypted);
            }
        }
        let mut data = encrypted;
        let range = decrypt_winzip_aes_in_place("password", 3, &mut data, || Ok::<_, ()>(())).unwrap().unwrap();
        assert_eq!(data[range], plain);

        let mut data = vec![0; 12];
        data[11] = 0x5b;
        data.extend(&plain);
        ZipCrypto::new("password").encrypt(&mut data);
        for stop in 1..=3 {
            let mut encrypted = data.clone();
            let mut checks = 0;
            assert_eq!(
                decrypt_zipcrypto_in_place("password", 0x5b, &mut encrypted, || {
                    checks += 1;
                    if checks == stop { Err("cancelled") } else { Ok(()) }
                }),
                Err("cancelled")
            );
            assert_eq!(checks, stop);
        }
        let range = decrypt_zipcrypto_in_place("password", 0x5b, &mut data, || Ok::<_, ()>(())).unwrap().unwrap();
        assert_eq!(data[range], plain);
    }

    #[test]
    fn authenticates_full_winzip_aes_payload() {
        for (strength, data, plaintext) in AES_FIXTURES {
            let packed = Some(data.len() as u64);
            assert_eq!(decrypt_winzip_aes(AES_PASSWORD, strength, data, packed).as_deref(), Some(plaintext));
            assert!(decrypt_winzip_aes("wrong password", strength, data, packed).is_none());
        }
    }

    #[test]
    fn rejects_winzip_aes_ciphertext_tampering() {
        for (strength, data, plaintext) in AES_FIXTURES {
            let mut damaged = data.to_vec();
            damaged[data.len() - 10 - plaintext.len()] ^= 1;
            assert!(decrypt_winzip_aes(AES_PASSWORD, strength, &damaged, Some(data.len() as u64)).is_none());
        }
    }

    #[test]
    fn rejects_winzip_aes_tag_tampering() {
        for (strength, data, _) in AES_FIXTURES {
            let mut damaged = data.to_vec();
            damaged[data.len() - 1] ^= 1;
            assert!(decrypt_winzip_aes(AES_PASSWORD, strength, &damaged, Some(data.len() as u64)).is_none());
        }
    }

    #[test]
    fn requires_exact_winzip_aes_packed_size() {
        for (strength, data, plaintext) in AES_FIXTURES {
            let packed = data.len() as u64;
            assert!(decrypt_winzip_aes(AES_PASSWORD, strength, &data[..data.len() - 1], Some(packed)).is_none());
            assert!(decrypt_winzip_aes(AES_PASSWORD, strength, data, Some(packed - 1)).is_none());

            let short = &data[..data.len() - 10 - plaintext.len() + 9];
            assert!(decrypt_winzip_aes(AES_PASSWORD, strength, short, Some(short.len() as u64)).is_none());
        }
    }

    #[test]
    fn previews_winzip_aes_ciphertext_prefix_without_tag() {
        for (strength, data, plaintext) in AES_FIXTURES {
            let end = data.len() - 10 - plaintext.len() + 4;
            assert_eq!(
                decrypt_winzip_aes(AES_PASSWORD, strength, &data[..end], None).as_deref(),
                Some(&plaintext[..4])
            );
            assert!(decrypt_winzip_aes("wrong password", strength, &data[..end], None).is_none());
        }
    }

    #[test]
    fn fips_197_and_cbc_round_trip() {
        let pt: [u8; 16] =
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let k256: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
            0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let c256: [u8; 16] =
            [0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89];
        let aes = AesKey::new(&k256).unwrap();
        let enc = aes.encrypt_block(&pt);
        assert_eq!(enc, c256);
        assert_eq!(aes.decrypt_block(&enc), pt);

        let iv = [0x42u8; 16];
        let msg = b"0123456789abcdeffedcba9876543210";
        let ct = encrypt_cbc(&k256, &iv, msg).unwrap();
        assert_eq!(decrypt_cbc(&k256, &iv, &ct).unwrap(), msg);
    }
}

/// SHA-1 for checking stored digests (xar's per-file checksums), not for keys.
#[derive(Clone)]
pub(crate) struct Sha1Digest(Sha1);

impl Sha1Digest {
    pub(crate) fn new() -> Self {
        Self(Sha1::new())
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    pub(crate) fn finalize(&self) -> [u8; 20] {
        self.0.finalize_bytes()
    }
}

/// MD5 (RFC 1321), for checking stored digests (xar's per-file checksums), not for anything secret.
#[derive(Clone)]
pub(crate) struct Md5 {
    state: [u32; 4],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Md5 {
    pub(crate) fn new() -> Self {
        Self { state: [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476], buf: [0; 64], buf_len: 0, total_len: 0 }
    }

    fn compress(state: &mut [u32; 4], chunk: &[u8; 64]) {
        const S: [u32; 64] = [
            7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
            14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10,
            15, 21, 6, 10, 15, 21,
        ];
        let mut m = [0u32; 16];
        for (i, word) in chunk.as_chunks::<4>().0.iter().enumerate() {
            m[i] = u32::from_le_bytes(*word);
        }
        let [mut a, mut b, mut c, mut d] = *state;
        for (i, &shift) in S.iter().enumerate() {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            // K[i] = floor(abs(sin(i + 1)) * 2^32)
            let k = ((i as f64 + 1.0).sin().abs() * 4_294_967_296.0) as u32;
            let rotated = a.wrapping_add(f).wrapping_add(k).wrapping_add(m[g]).rotate_left(shift);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(rotated);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
    }

    pub(crate) fn update(&mut self, mut data: &[u8]) {
        self.total_len += data.len() as u64;
        if self.buf_len > 0 {
            let take = (64 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len < 64 {
                return;
            }
            let buf = self.buf;
            Self::compress(&mut self.state, &buf);
            self.buf_len = 0;
        }
        let (blocks, rest) = data.as_chunks::<64>();
        for block in blocks {
            Self::compress(&mut self.state, block);
        }
        self.buf[..rest.len()].copy_from_slice(rest);
        self.buf_len = rest.len();
    }

    pub(crate) fn finalize(&self) -> [u8; 16] {
        let mut state = self.state;
        let mut tail = [0u8; 128];
        tail[..self.buf_len].copy_from_slice(&self.buf[..self.buf_len]);
        tail[self.buf_len] = 0x80;
        let len = if self.buf_len < 56 { 64 } else { 128 };
        tail[len - 8..len].copy_from_slice(&(self.total_len * 8).to_le_bytes());
        for block in tail[..len].as_chunks::<64>().0 {
            Self::compress(&mut state, block);
        }
        let mut out = [0u8; 16];
        for (i, w) in state.iter().enumerate() {
            out[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
        }
        out
    }
}

/// SHA-512 (FIPS 180-4), for checking stored digests (xar's per-file checksums), not for keys.
#[derive(Clone)]
pub(crate) struct Sha512 {
    state: [u64; 8],
    buf: [u8; 128],
    buf_len: usize,
    total_len: u128,
}

const SHA512_K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

impl Sha512 {
    pub(crate) fn new() -> Self {
        Self {
            state: [
                0x6a09e667f3bcc908,
                0xbb67ae8584caa73b,
                0x3c6ef372fe94f82b,
                0xa54ff53a5f1d36f1,
                0x510e527fade682d1,
                0x9b05688c2b3e6c1f,
                0x1f83d9abfb41bd6b,
                0x5be0cd19137e2179,
            ],
            buf: [0; 128],
            buf_len: 0,
            total_len: 0,
        }
    }

    fn compress(state: &mut [u64; 8], chunk: &[u8; 128]) {
        let mut w = [0u64; 80];
        for (i, word) in chunk.as_chunks::<8>().0.iter().enumerate() {
            w[i] = u64::from_be_bytes(*word);
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        for (&k, &wi) in SHA512_K.iter().zip(w.iter()) {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ (!e & g);
            let t1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(k).wrapping_add(wi);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *s = s.wrapping_add(v);
        }
    }

    pub(crate) fn update(&mut self, mut data: &[u8]) {
        self.total_len += data.len() as u128;
        if self.buf_len > 0 {
            let take = (128 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len < 128 {
                return;
            }
            let buf = self.buf;
            Self::compress(&mut self.state, &buf);
            self.buf_len = 0;
        }
        let (blocks, rest) = data.as_chunks::<128>();
        for block in blocks {
            Self::compress(&mut self.state, block);
        }
        self.buf[..rest.len()].copy_from_slice(rest);
        self.buf_len = rest.len();
    }

    pub(crate) fn finalize(&self) -> [u8; 64] {
        let mut state = self.state;
        let mut tail = [0u8; 256];
        tail[..self.buf_len].copy_from_slice(&self.buf[..self.buf_len]);
        tail[self.buf_len] = 0x80;
        let len = if self.buf_len < 112 { 128 } else { 256 };
        tail[len - 16..len].copy_from_slice(&(self.total_len * 8).to_be_bytes());
        for block in tail[..len].as_chunks::<128>().0 {
            Self::compress(&mut state, block);
        }
        let mut out = [0u8; 64];
        for (i, w) in state.iter().enumerate() {
            out[8 * i..8 * i + 8].copy_from_slice(&w.to_be_bytes());
        }
        out
    }
}

#[cfg(test)]
mod digest_tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn md5_and_sha1_match_their_references_in_any_pieces() {
        let md5 = |d: &[u8]| {
            let mut h = Md5::new();
            h.update(d);
            hex(&h.finalize())
        };
        assert_eq!(md5(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            md5(b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"),
            "57edf4a22be3c955ac49da2e2107b67a"
        );
        let sha512 = |d: &[u8]| {
            let mut h = Sha512::new();
            h.update(d);
            hex(&h.finalize())
        };
        assert_eq!(
            sha512(b"abc"),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        let long: Vec<u8> = (0..1000u32).map(|i| (i * 13 + 1) as u8).collect();
        let whole = sha512(&long);
        // references from Python's hashlib: 1000 bytes, and 120 (whose padding takes a second block)
        assert_eq!(
            whole,
            "d14270cf0199a09f200decb1cc9643a4479147d5ddfd709fcb47fa63bef7341196595d4a2087168fde35d1a7cf60db53b0d1dec5e1a890cccee921f77e117ebc"
        );
        assert_eq!(
            sha512(&long[..120]),
            "08412141eebec8088927c599d00d23adfadac2358c5ca18c44cfb6f55fb5e5b6ae14b353a779c0352ec2f0a99960256f6a322d2485c50e4b0321c420d13ff6bb"
        );
        for cut in [1, 111, 112, 127, 128, 129, 300] {
            let mut h = Sha512::new();
            for piece in long.chunks(cut) {
                h.update(piece);
            }
            assert_eq!(hex(&h.finalize()), whole, "{cut}");
        }
        let mut sha = Sha1Digest::new();
        sha.update(b"abc");
        assert_eq!(hex(&sha.finalize()), "a9993e364706816aba3e25717850c26c9cd0d89d");
        let long: Vec<u8> = (0..1000u32).map(|i| (i * 31 + 7) as u8).collect();
        let whole = md5(&long);
        for cut in [1, 63, 64, 65, 200] {
            let mut h = Md5::new();
            for piece in long.chunks(cut) {
                h.update(piece);
            }
            assert_eq!(hex(&h.finalize()), whole, "{cut}");
        }
    }
}

#[cfg(test)]
mod aes_backend_tests {
    use super::aes_hw::Backend;
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// FIPS 197 appendix C, on every backend this processor has.
    #[test]
    fn every_backend_matches_the_fips_197_vectors() {
        let plain: [u8; 16] = hex("00112233445566778899aabbccddeeff").try_into().unwrap();
        let cases = [
            ("000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"),
            ("000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191"),
            ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "8ea2b7ca516745bfeafc49904b496089"),
        ];
        for backend in Backend::available() {
            for (key, ct) in cases {
                let k = AesKey::new(&hex(key)).unwrap().with_backend(backend);
                let ct: [u8; 16] = hex(ct).try_into().unwrap();
                assert_eq!(k.encrypt_block(&plain), ct, "{backend:?} encrypt, key {key}");
                assert_eq!(k.decrypt_block(&ct), plain, "{backend:?} decrypt, key {key}");
            }
        }
    }

    /// CBC over lengths that cover the eight-block groups and every remainder, against the portable rounds.
    #[test]
    fn every_backend_decrypts_cbc_like_the_portable_one() {
        let data: Vec<u8> = (0..16 * 37u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
        for key_len in [16, 24, 32] {
            let key: Vec<u8> = (0..key_len as u8).map(|i| i.wrapping_mul(37) ^ 0x5a).collect();
            let scalar = AesKey::new(&key).unwrap().with_backend(Backend::Scalar);
            for backend in Backend::available() {
                let k = AesKey::new(&key).unwrap().with_backend(backend);
                for blocks in [0usize, 1, 7, 8, 9, 16, 17, 37] {
                    let (mut want_iv, mut got_iv) = ([0x11u8; 16], [0x11u8; 16]);
                    let mut want = data[..blocks * 16].to_vec();
                    let mut got = want.clone();
                    scalar.decrypt_cbc_in_place(&mut want_iv, &mut want);
                    k.decrypt_cbc_in_place(&mut got_iv, &mut got);
                    assert_eq!(got, want, "{backend:?} key {key_len} blocks {blocks}");
                    assert_eq!(got_iv, want_iv, "{backend:?} key {key_len} blocks {blocks}: chained IV");
                    // decrypting what encrypt_cbc made gives the plaintext back
                    let ct = encrypt_cbc(&key, &[3; 16], &data[..blocks * 16]).unwrap();
                    let mut back = ct.clone();
                    k.decrypt_cbc_in_place(&mut [3; 16], &mut back);
                    assert_eq!(back, &data[..blocks * 16], "{backend:?} key {key_len} blocks {blocks}: round trip");
                }
            }
        }
    }

    /// A trailing partial block is left alone, as the portable loop leaves it.
    #[test]
    fn every_backend_leaves_a_partial_tail_block_alone() {
        for backend in Backend::available() {
            let k = AesKey::new(&[9; 32]).unwrap().with_backend(backend);
            let mut data = vec![0xabu8; 16 * 9 + 5];
            k.decrypt_cbc_in_place(&mut [0; 16], &mut data);
            assert_eq!(&data[16 * 9..], &[0xab; 5], "{backend:?}");
        }
    }
}
