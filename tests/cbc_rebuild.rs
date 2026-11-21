//! Rebuilding the AES-CBC ciphertext of an encrypted stored member from its plaintext (`zipfast::crypto::rebuild_cbc`).

use zipfast::crypto::{CbcRebuildError, CbcSpan, cbc_rebuild_span, derive_7z_key, derive_rar5_key, rebuild_cbc};

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

/// The whole member, from the header IV, with its zero-padded last block: rar's bytes exactly.
#[test]
fn a_rar5_member_rebuilds_byte_for_byte_from_its_plaintext() {
    let iv: [u8; 16] = unhex(RAR5_IV).try_into().unwrap();
    let rebuilt = rebuild_cbc(&rar5_key(), &iv, PLAIN, true, None).unwrap();
    assert_eq!(rebuilt, unhex(RAR5_DATA));
}

#[test]
fn a_7z_aes_folder_rebuilds_byte_for_byte_from_its_plaintext() {
    let key = derive_7z_key("secret", &[], 19).unwrap();
    let iv: [u8; 16] = unhex(SEVEN_IV).try_into().unwrap();
    assert_eq!(rebuild_cbc(&key, &iv, PLAIN, true, None).unwrap(), unhex(SEVEN_DATA));
}

/// A lost middle block (bytes 16..32) rebuilt from the plaintext and the ciphertext block before it, checked
/// against the intact block after it.
#[test]
fn a_lost_middle_range_rebuilds_from_the_previous_block_and_checks_the_next() {
    let data = unhex(RAR5_DATA);
    let previous: [u8; 16] = data[..16].try_into().unwrap();
    let rebuilt = rebuild_cbc(&rar5_key(), &previous, &PLAIN[16..48], false, Some((16, &data[32..48]))).unwrap();
    assert_eq!(rebuilt, data[16..48]);
    // The last block of the member, reaching the end: zero padding.
    let previous: [u8; 16] = data[32..48].try_into().unwrap();
    assert_eq!(rebuild_cbc(&rar5_key(), &previous, &PLAIN[48..], true, None).unwrap(), data[48..]);
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
/// `cbc_rebuild_span`: widened to blocks 16..48 plus the check bytes up to 64, from the previous 16 bytes, and
/// checked against the intact bytes after the hole.
#[test]
fn a_hole_widens_to_blocks_with_a_check_after_it() {
    let data = unhex(RAR5_DATA);
    let span = cbc_rebuild_span(20..37, PLAIN.len() as u64);
    assert_eq!(span, CbcSpan { range: 16..55, previous_at: Some(0), check: Some(37..55), stream_end: true });
    let previous: [u8; 16] = data[..16].try_into().unwrap();
    let check = span.check.clone().unwrap();
    let intact = &data[check.start as usize..check.end as usize];
    let rebuilt = rebuild_cbc(
        &rar5_key(),
        &previous,
        &PLAIN[span.range.start as usize..span.range.end as usize],
        span.stream_end,
        Some(((check.start - span.range.start) as usize, intact)),
    )
    .unwrap();
    assert_eq!(rebuilt, data[16..]);
    // A hole in the first block uses the IV; one reaching the end has nothing to check.
    assert_eq!(
        cbc_rebuild_span(3..9, 55),
        CbcSpan { range: 0..32, previous_at: None, check: Some(9..32), stream_end: false }
    );
    assert_eq!(
        cbc_rebuild_span(40..55, 55),
        CbcSpan { range: 32..55, previous_at: Some(16), check: None, stream_end: true }
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
