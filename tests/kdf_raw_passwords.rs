//! Key derivations for passwords that are not valid UTF-8: RAR 5.0 takes raw bytes, RAR 3.x/4.x and 7z take UTF-16
//! code units. Each agrees with its `&str` form on valid strings and accepts what a string cannot hold.

use zipfast::crypto::{
    Rar5PasswordCheck, derive_7z_key, derive_7z_key_utf16, derive_rar4_key_iv, derive_rar4_key_iv_utf16,
    derive_rar5_key, derive_rar5_key_and_hash_key, derive_rar5_key_and_hash_key_bytes, derive_rar5_key_bytes,
};

const PASSWORDS: [&str; 4] = ["", "password", "pässwörd ✓", "emoji 𝄞 pair"];

#[test]
fn byte_and_unit_forms_agree_with_the_string_forms() {
    let salt16 = [7u8; 16];
    let salt8 = [3u8; 8];
    for p in PASSWORDS {
        assert_eq!(derive_rar5_key_bytes(p.as_bytes(), 4, &salt16, None), derive_rar5_key(p, 4, &salt16, None), "{p}");
        assert_eq!(
            derive_rar5_key_and_hash_key_bytes(p.as_bytes(), 4, &salt16, None),
            derive_rar5_key_and_hash_key(p, 4, &salt16, None),
            "{p}"
        );
        let units: Vec<u16> = p.encode_utf16().collect();
        assert_eq!(derive_rar4_key_iv_utf16(&units, &salt8), derive_rar4_key_iv(p, &salt8), "{p}");
        assert_eq!(derive_7z_key_utf16(&units, &salt8, 6), derive_7z_key(p, &salt8, 6), "{p}");
        assert_eq!(derive_7z_key_utf16(&units, &salt8, 0x3F), derive_7z_key(p, &salt8, 0x3F), "{p}");
    }
}

#[test]
fn raw_bytes_and_unpaired_surrogates_get_their_own_keys() {
    let salt16 = [9u8; 16];
    // Latin-1 "pässwörd": not UTF-8, and different from both the UTF-8 spelling and the lossy decoding.
    let raw = b"p\xe4ssw\xf6rd";
    let key = derive_rar5_key_bytes(raw, 4, &salt16, None).expect("a key for any bytes");
    assert_ne!(Some(key), derive_rar5_key("pässwörd", 4, &salt16, None));
    assert_ne!(Some(key), derive_rar5_key(&String::from_utf8_lossy(raw), 4, &salt16, None));
    // Widening each byte to a unit (one mapping a caller may choose) gives the Latin-1 string's UTF-16.
    let widened: Vec<u16> = raw.iter().map(|&b| u16::from(b)).collect();
    assert_eq!(derive_rar4_key_iv_utf16(&widened, &[1; 8]), derive_rar4_key_iv("pässwörd", &[1; 8]));
    assert_eq!(derive_7z_key_utf16(&widened, &[], 6), derive_7z_key("pässwörd", &[], 6));
    // A lone surrogate cannot be in a &str, but it is hashed as given.
    let lone = [0x0070, 0xd800, 0x0071];
    assert_ne!(derive_rar4_key_iv_utf16(&lone, &[1; 8]), derive_rar4_key_iv("p\u{fffd}q", &[1; 8]));
    assert!(derive_7z_key_utf16(&lone, &[], 6).is_some());
}

#[test]
fn the_rar5_password_check_takes_raw_bytes_like_strings() {
    let raw = b"\xff\xfe raw";
    let salt = [5u8; 16];
    // A check record with an all-zero check value: no password matches it, and the byte and string forms agree.
    let check_bytes = {
        let mut probe = Vec::with_capacity(25);
        probe.push(4u8);
        probe.extend_from_slice(&salt);
        probe.extend_from_slice(&[0; 8]);
        probe
    };
    let zero = Rar5PasswordCheck::from_bytes(&check_bytes).unwrap();
    assert!(!zero.accepts_bytes(raw), "an all-zero check value is not this password's");
    assert_eq!(zero.accepts_bytes(b"ascii"), zero.accepts("ascii"));
}
