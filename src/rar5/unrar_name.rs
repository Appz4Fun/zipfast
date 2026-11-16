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

//! RAR 5.0 member names decoded the way UnRAR decodes them on Unix.

/// UnRAR's `NM`: the longest name, in wide characters, including the terminating zero.
///
/// This models UnRAR 6.x's fixed `wchar FileName[NM]`. If UnRAR 7.x decodes header names into a growable
/// string without this cap, names longer than 2047 units are the only ones that would differ; the decoding
/// rules themselves are the same.
const NM: usize = 2048;

/// The name UnRAR on Unix reads from a RAR 5.0 header's name bytes `raw`, as the 32-bit `wchar_t` units it
/// holds.
///
/// A RAR 5.0 header stores the name as UTF-8. zipfast's own decoding replaces each malformed sequence with U+FFFD,
/// but UnRAR (`UtfToWide` in `unicode.cpp`, called from `Archive::ReadHeader50`) is looser in some ways and
/// stricter in others, and on Unix its `wchar_t` holds 32-bit units:
///
/// - It reads the name as a C string: the header's bytes, cut to `NM * 4 - 1` (8191), up to the first zero byte. (The
///   cut never matters: at four bytes or fewer a place, the output fills first.)
/// - A lead byte `0xxxxxxx`, `110xxxxx`, `1110xxxx` or `11110xxx` takes 0, 1, 2 or 3 continuation bytes
///   (`10xxxxxx`), and the unit is the payload bits put together. Nothing else is checked: overlong forms (`C0 80`,
///   `E0 80 80`, ...) and encoded surrogates (`ED A0 80` is 0xD800) are kept as whatever value they spell.
/// - The first byte that is neither (a stray continuation byte, or `F8`..`FF`) or a lead byte without all its
///   continuation bytes ends the name there, whether mid-name or at a truncated end; what came before is kept and
///   the rest dropped. So `c\xffd` is `c`.
/// - A 4-byte form above 0x10FFFF is dropped and decoding carries on after it.
/// - The output buffer holds `NM` (2048) units including the terminating zero. Every unit costs one place and one
///   above 0xFFFF a second (room for a UTF-16 surrogate pair, though Unix stores it as one unit), dropped ones
///   included; the name ends at the first unit that no longer fits.
/// - A unit of 0 (from an overlong form) is written like any other, so the wide string, and the name UnRAR uses,
///   ends there.
///
/// What UnRAR does to the name after that (path separator and case conversion, for example) is not modelled.
///
/// ```
/// use zipfast::rar5::unrar_name;
///
/// assert_eq!(unrar_name(b"c\xffd"), [u32::from('c')]);
/// assert_eq!(unrar_name(b"\xed\xa0\x80"), [0xd800]);
/// ```
pub fn unrar_name(raw: &[u8]) -> Vec<u32> {
    let raw = &raw[..raw.len().min(NM * 4 - 1)];
    let src = raw.split(|&b| b == 0).next().unwrap_or_default();
    let tail = |at: usize| u32::from(src[at] & 0x3f);
    let continues = |at: usize, n: usize| (at..at + n).all(|i| src.get(i).is_some_and(|&b| b & 0xc0 == 0x80));
    let mut out = Vec::new();
    // places left in the output buffer, the terminating zero's taken already
    let mut room = NM - 1;
    let mut at = 0;
    while let Some(&lead) = src.get(at) {
        let c = u32::from(lead);
        at += 1;
        let (unit, more) = match lead {
            0x00..=0x7f => (c, 0),
            0xc0..=0xdf if continues(at, 1) => ((c & 0x1f) << 6 | tail(at), 1),
            0xe0..=0xef if continues(at, 2) => ((c & 0x0f) << 12 | tail(at) << 6 | tail(at + 1), 2),
            0xf0..=0xf7 if continues(at, 3) => {
                ((c & 0x07) << 18 | tail(at) << 12 | tail(at + 1) << 6 | tail(at + 2), 3)
            }
            _ => break,
        };
        at += more;
        let places = if unit > 0xffff { 2 } else { 1 };
        if room < places {
            break;
        }
        room -= places;
        if unit > 0x10_ffff {
            continue;
        }
        if unit == 0 {
            break;
        }
        out.push(unit);
    }
    out
}

/// `units` as text when every one is a Unicode scalar value (so not a surrogate); None otherwise.
///
/// ```
/// use zipfast::rar5::{unrar_name, unrar_name_to_string};
///
/// assert_eq!(unrar_name_to_string(&unrar_name(b"a\xc1\x81")).as_deref(), Some("aA"));
/// assert_eq!(unrar_name_to_string(&unrar_name(b"\xed\xa0\x80")), None);
/// ```
pub fn unrar_name_to_string(units: &[u32]) -> Option<String> {
    units.iter().map(|&u| char::from_u32(u)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn units(s: &str) -> Vec<u32> {
        s.chars().map(u32::from).collect()
    }

    #[test]
    fn valid_utf8_decodes_as_usual() {
        assert_eq!(unrar_name(b""), Vec::<u32>::new());
        assert_eq!(unrar_name(b"dir/file.txt"), units("dir/file.txt"));
        let text = "caf\u{e9}/\u{20ac}\u{4e2d}/\u{1f600}\u{10ffff}";
        assert_eq!(unrar_name(text.as_bytes()), units(text));
        assert_eq!(unrar_name_to_string(&unrar_name(text.as_bytes())).as_deref(), Some(text));
    }

    #[test]
    fn a_malformed_byte_ends_the_name() {
        assert_eq!(unrar_name(b"c\xffd"), units("c"));
        // a stray continuation byte, and the other lead bytes that start nothing
        for bad in [0x80u8, 0xbf, 0xf8, 0xfb, 0xfc, 0xfe, 0xff] {
            assert_eq!(unrar_name(&[b'a', bad, b'b']), units("a"), "{bad:#x}");
            assert_eq!(unrar_name(&[bad, b'b']), Vec::<u32>::new(), "{bad:#x}");
        }
        // a lead byte whose continuation is missing, mid-name: the lead and everything after it go
        assert_eq!(unrar_name(b"x\xc3yz"), units("x"));
        assert_eq!(unrar_name(b"x\xe2\x82yz"), units("x"));
        assert_eq!(unrar_name(b"x\xf0\x9f\x98yz"), units("x"));
        assert_eq!(unrar_name(b"x\xe2\x82\xac\xe2\x28\xa1"), [u32::from('x'), 0x20ac]);
    }

    #[test]
    fn a_truncated_sequence_at_the_end_is_dropped() {
        assert_eq!(unrar_name(b"ab\xc3"), units("ab"));
        assert_eq!(unrar_name(b"ab\xe2\x82"), units("ab"));
        assert_eq!(unrar_name(b"ab\xf0\x9f\x98"), units("ab"));
        assert_eq!(unrar_name(b"\xf0"), Vec::<u32>::new());
    }

    #[test]
    fn overlong_forms_are_kept_as_what_they_spell() {
        assert_eq!(unrar_name(b"\xc1\x81"), units("A"));
        assert_eq!(unrar_name(b"\xe0\x81\x81"), units("A"));
        assert_eq!(unrar_name(b"\xf0\x80\x81\x81"), units("A"));
        assert_eq!(unrar_name(b"\xc0\xaf"), units("/"));
        assert_eq!(unrar_name(b"\xe0\x82\xa9"), units("\u{a9}"));
        assert_eq!(unrar_name(b"\xf0\x82\x82\xac"), units("\u{20ac}"));
        // an overlong zero writes a zero unit, which ends the name
        assert_eq!(unrar_name(b"a\xc0\x80b"), units("a"));
        assert_eq!(unrar_name(b"a\xe0\x80\x80b"), units("a"));
    }

    #[test]
    fn encoded_surrogates_are_kept_as_code_units() {
        assert_eq!(unrar_name(b"\xed\xa0\x80"), [0xd800]);
        assert_eq!(unrar_name(b"a\xed\xbf\xbfb"), [u32::from('a'), 0xdfff, u32::from('b')]);
        assert_eq!(unrar_name(b"\xed\xa0\xbd\xed\xb8\x80"), [0xd83d, 0xde00]);
        assert_eq!(unrar_name_to_string(&unrar_name(b"\xed\xa0\x80")), None);
    }

    #[test]
    fn four_byte_forms_above_the_unicode_range_are_skipped() {
        assert_eq!(unrar_name(b"\xf0\x9f\x98\x80"), [0x1f600]);
        assert_eq!(unrar_name(b"\xf4\x8f\xbf\xbf"), [0x10ffff]);
        assert_eq!(unrar_name(b"a\xf4\x90\x80\x80b"), units("ab"));
        assert_eq!(unrar_name(b"a\xf7\xbf\xbf\xbfb"), units("ab"));
    }

    #[test]
    fn a_zero_byte_ends_the_name() {
        assert_eq!(unrar_name(b"ab\0cd"), units("ab"));
        assert_eq!(unrar_name(b"\0cd"), Vec::<u32>::new());
    }

    #[test]
    fn the_name_is_bounded_like_the_buffers() {
        assert_eq!(unrar_name(&[b'a'; 5000]).len(), NM - 1);
        // a unit above 0xFFFF takes two places: 1023 of them fill 2046, and the next needs two of the one left
        let mut raw = "\u{1f600}".repeat(1024).into_bytes();
        assert_eq!(unrar_name(&raw).len(), 1023);
        raw.splice(0..0, *b"a");
        assert_eq!(unrar_name(&raw).len(), 1 + 1023);
        // dropped units take their places too
        let mut raw = b"\xf4\x90\x80\x80".repeat(1023);
        raw.extend_from_slice(b"ab");
        assert_eq!(unrar_name(&raw), units("a"));
        let raw = "\u{20ac}".repeat(3000).into_bytes();
        assert_eq!(unrar_name(&raw).len(), NM - 1);
    }
}
