//! Rebuilding the AES-CBC ciphertext of an encrypted stored member from its plaintext (`zipfast::crypto::rebuild_cbc`).

use zipfast::crypto::{CbcRebuildError, derive_7z_key, derive_rar5_key, rebuild_cbc};

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
