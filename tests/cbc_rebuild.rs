//! Rebuilding the AES-CBC ciphertext of an encrypted stored member from its plaintext (`zipfast::crypto::rebuild_cbc`).

use zipfast::crypto::{
    CbcRebuildError, CbcSpan, cbc_rebuild_span, derive_7z_key, derive_rar5_key, encrypt_cbc, rebuild_cbc,
    rebuild_cbc_zero_padded, rebuild_final_block,
};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

const PLAIN: &[u8] = b"The quick brown fox jumps over the lazy dog 0123456789!";

/// `rar a -ma5 -m0 -psecret` (rar 7.30) of the 55-byte `PLAIN`: the file header's encryption record and the data.
const RAR5_SALT: &str = "f953ac2028e7da629113b19ac0983559";
const RAR5_IV: &str = "c106d84e041d92773ab3a72aeb0fe41a";
const RAR5_KDF: u8 = 15;
const RAR5_DATA: &str = "2ef276b039efbcca928d083cbd7b5d8522634e97a3c779bb81ea448db80ea47322574615a67b41bec7c9fb5f79dc36db45bdef1dbf2ea64ad364f7b40a0a27e4";

/// `7zz a -mx0 -psecret` (7-Zip) of the same file: the folder's IV and its packed stream (empty salt, 2^19 rounds).
const SEVEN_IV: &str = "a25b7b3ab70f7b031af4b6b30fc30ed8";
const SEVEN_DATA: &str = "7ad348069c47cc067fcfa6c54afc39861d65e3c00b3b470c89b6cf82ca74519e2ec94cf7fb37086950b219519e17c53b9c6d6451e61a805e937cb6aa35b52047";

fn rar5_key() -> [u8; 32] {
    derive_rar5_key("secret", RAR5_KDF, &unhex(RAR5_SALT).try_into().unwrap(), None).unwrap()
}

/// A RAR 5.0 member whose last block is partial has unknown padding (random in rar): `rebuild_cbc` refuses rather
/// than zero-padding. Its whole blocks rebuild byte for byte from the header IV.
#[test]
fn a_rar5_member_refuses_an_unknown_final_padding_and_rebuilds_its_whole_blocks() {
    let iv: [u8; 16] = unhex(RAR5_IV).try_into().unwrap();
    assert_eq!(rebuild_cbc(&rar5_key(), &iv, PLAIN, true, None), Err(CbcRebuildError::FinalPadding { pad: 9 }));
    let data = unhex(RAR5_DATA);
    assert_eq!(rebuild_cbc(&rar5_key(), &iv, &PLAIN[..48], false, None).unwrap(), data[..48]);
}

/// The final partial block with 2 padding bytes (14 plaintext bytes in it) is found by trying padding values
/// until the block's ciphertext is the one the check accepts; a wrong accept finds nothing; 9 bytes is refused.
#[test]
fn a_final_block_with_two_padding_bytes_is_found_by_trying_the_padding() {
    let key = rar5_key();
    let iv: [u8; 16] = unhex(RAR5_IV).try_into().unwrap();
    let plain = &PLAIN[..30];
    // Encrypt with padding 0x9c 0xee (not zero), as rar's random padding would be.
    let mut padded = plain.to_vec();
    padded.extend_from_slice(&[0x9c, 0xee]);
    let truth = encrypt_cbc(&key, &iv, &padded).unwrap();
    let prefix = rebuild_cbc(&key, &iv, &PLAIN[..16], false, None).unwrap();
    let found = rebuild_final_block(&key, prefix[..16].try_into().unwrap(), &plain[16..], |b| b[..] == truth[16..32])
        .expect("the padding is one of 2^24 values");
    assert_eq!(found[..], truth[16..32]);
    assert!(rebuild_final_block(&key, prefix[..16].try_into().unwrap(), &plain[16..], |_| false).is_none());
    // 9 padding bytes: too many to try.
    assert!(rebuild_final_block(&key, &iv, &PLAIN[48..], |_| true).is_none());
}

#[test]
fn a_7z_aes_folder_rebuilds_byte_for_byte_from_its_plaintext() {
    let key = derive_7z_key("secret", &[], 19).unwrap();
    let iv: [u8; 16] = unhex(SEVEN_IV).try_into().unwrap();
    assert_eq!(rebuild_cbc_zero_padded(&key, &iv, PLAIN, true, None).unwrap(), unhex(SEVEN_DATA));
}

/// A lost middle block (bytes 16..32) rebuilt from the plaintext and the ciphertext block before it, checked
/// against the intact block after it.
#[test]
fn a_lost_middle_range_rebuilds_from_the_previous_block_and_checks_the_next() {
    let data = unhex(RAR5_DATA);
    let previous: [u8; 16] = data[..16].try_into().unwrap();
    let rebuilt = rebuild_cbc(&rar5_key(), &previous, &PLAIN[16..48], false, Some((16, &data[32..48]))).unwrap();
    assert_eq!(rebuilt, data[16..48]);
    // The last block of the member is partial: its padding is unknown, so it is refused.
    let previous: [u8; 16] = data[32..48].try_into().unwrap();
    assert_eq!(
        rebuild_cbc(&rar5_key(), &previous, &PLAIN[48..], true, None),
        Err(CbcRebuildError::FinalPadding { pad: 9 })
    );
}

#[test]
fn a_wrong_key_plaintext_or_block_is_caught_by_the_intact_overlap() {
    let data = unhex(RAR5_DATA);
    let previous: [u8; 16] = data[..16].try_into().unwrap();
    let mut wrong = PLAIN[16..48].to_vec();
    wrong[20] ^= 1;
    let result = rebuild_cbc(&rar5_key(), &previous, &wrong, false, Some((16, &data[32..48])));
    assert_eq!(result, Err(CbcRebuildError::Mismatch { at: 16 }));
    assert_eq!(
        rebuild_cbc(&rar5_key(), &previous, &PLAIN[16..48], false, Some((32, &data[32..48]))),
        Err(CbcRebuildError::NoOverlap)
    );
    assert_eq!(rebuild_cbc(&rar5_key(), &previous, &PLAIN[16..40], false, None), Err(CbcRebuildError::Unaligned));
    assert_eq!(rebuild_cbc(&[0; 20], &previous, &PLAIN[16..48], false, None), Err(CbcRebuildError::KeyLength));
}

/// An arbitrary hole (bytes 20..37 of the 55-byte stream, as a lost article would be) rebuilt through
/// `cbc_rebuild_span`: widened to 16..55 (to the stream's end) from the previous 16 bytes, and checked against the
/// intact bytes 37..55 after the hole.
#[test]
fn a_hole_widens_to_blocks_with_a_check_after_it() {
    let data = unhex(RAR5_DATA);
    let span = cbc_rebuild_span(20..37, PLAIN.len() as u64);
    assert_eq!(span, CbcSpan { range: 16..55, previous_at: Some(0), check: Some(37..55), stream_end: true });
    let previous: [u8; 16] = data[..16].try_into().unwrap();
    let check = span.check.clone().unwrap();
    let intact = &data[check.start as usize..check.end as usize];
    // The range reaches the stream's end on a partial block: the rebuild before the final block is what this checks.
    let rebuilt = rebuild_cbc(
        &rar5_key(),
        &previous,
        &PLAIN[span.range.start as usize..span.range.end as usize],
        false,
        Some(((check.start - span.range.start) as usize, intact)),
    );
    assert_eq!(rebuilt, Err(CbcRebuildError::Unaligned));
    // With the partial block left to its padding: the rebuild of the whole blocks before it.
    let whole = rebuild_cbc(&rar5_key(), &previous, &PLAIN[16..48], false, None).unwrap();
    assert_eq!(whole, data[16..48]);
    // A hole in the first block uses the IV; one reaching the end has nothing to check.
    assert_eq!(
        cbc_rebuild_span(3..9, 55),
        CbcSpan { range: 0..32, previous_at: None, check: Some(9..32), stream_end: false }
    );
    assert_eq!(
        cbc_rebuild_span(40..55, 55),
        CbcSpan { range: 32..55, previous_at: Some(16), check: None, stream_end: true }
    );
    // A stream ending on a block boundary, a hole of exactly one block, and a hole in the padding past the plaintext.
    assert_eq!(
        cbc_rebuild_span(20..37, 48),
        CbcSpan { range: 16..48, previous_at: Some(0), check: Some(37..48), stream_end: true }
    );
    assert_eq!(
        cbc_rebuild_span(0..16, 64),
        CbcSpan { range: 0..32, previous_at: None, check: Some(16..32), stream_end: false }
    );
    assert_eq!(
        cbc_rebuild_span(60..64, 55),
        CbcSpan { range: 48..55, previous_at: Some(32), check: None, stream_end: true }
    );
}

/// Edges: an intact slice overlapping part of the range, longer than it, or not block-aligned; a stream that ends
/// on a block boundary gets no extra block; empty plaintext at the end is empty; a 7z range in the middle of a
/// folder's stream.
#[test]
fn overlap_and_padding_edges() {
    let data = unhex(RAR5_DATA);
    let previous: [u8; 16] = data[..16].try_into().unwrap();
    let key = rar5_key();
    // Overlap only the last 5 bytes of the range, from an unaligned offset, with a slice running past it.
    assert!(rebuild_cbc(&key, &previous, &PLAIN[16..48], false, Some((27, &data[43..64]))).is_ok());
    let mut bad = data[43..64].to_vec();
    bad[2] ^= 1;
    assert_eq!(
        rebuild_cbc(&key, &previous, &PLAIN[16..48], false, Some((27, &bad))),
        Err(CbcRebuildError::Mismatch { at: 29 })
    );
    // 32 bytes ending the stream: two blocks, no padding block.
    assert_eq!(rebuild_cbc(&key, &previous, &PLAIN[16..48], true, None).unwrap().len(), 32);
    assert_eq!(rebuild_cbc(&key, &previous, &[], true, None).unwrap(), Vec::<u8>::new());
    // 7z, the folder's second and third blocks from its first.
    let seven = unhex(SEVEN_DATA);
    let key7 = derive_7z_key("secret", &[], 19).unwrap();
    let prev7: [u8; 16] = seven[..16].try_into().unwrap();
    assert_eq!(rebuild_cbc(&key7, &prev7, &PLAIN[16..48], false, Some((16, &seven[32..48]))).unwrap(), seven[16..48]);
}
