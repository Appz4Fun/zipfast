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

//! Names of the volumes after the first in a multi-volume set.

use std::path::{Path, PathBuf};

/// The volume after `path`: `name.part01.rar` becomes `name.part02.rar` (keeping the width, growing it when the
/// number overflows), and `name.rar` becomes `name.r00`, then `name.r01` and so on.
pub fn next_volume(path: &Path) -> Option<PathBuf> {
    let name = path.file_name()?.to_str()?;
    let lower = name.to_ascii_lowercase();
    let next = if let Some(stem) = lower.strip_suffix(".rar") {
        match part_digits_at(stem) {
            Some(digits_at) => {
                let suffix = &stem[digits_at..];
                let n: u64 = suffix.parse().ok()?;
                let digits = format!("{:0width$}", n.checked_add(1)?, width = suffix.len());
                format!("{}{}{}", &name[..digits_at], digits, &name[stem.len()..])
            }
            // keep the extension's case: set.RAR goes on in set.R00
            None => {
                let r = if name.ends_with(".RAR") || name.ends_with(".Rar") { 'R' } else { 'r' };
                format!("{}.{r}00", &name[..name.len() - 4])
            }
        }
    } else {
        // .r00 .. .r99, then .s00 and onwards
        let (base, ext) = name.rsplit_once('.')?;
        let mut chars = ext.chars();
        let letter = chars.next()?;
        let digits = chars.as_str();
        if !letter.is_ascii_alphabetic() || digits.len() < 2 || !digits.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        let n: u32 = digits.parse().ok()?;
        let limit = 10u32.checked_pow(digits.len().try_into().ok()?)?;
        let next_number = n.checked_add(1)?;
        if next_number < limit {
            format!("{base}.{letter}{next_number:0w$}", w = digits.len())
        } else {
            let next_letter = (letter as u8 + 1) as char;
            if !next_letter.is_ascii_alphabetic() {
                return None;
            }
            format!("{base}.{next_letter}{:0w$}", 0, w = digits.len())
        }
    };
    Some(path.with_file_name(next))
}

/// The volume before `path`, the inverse of [`next_volume`]: `name.part02.rar` becomes `name.part01.rar`, `name.r00`
/// becomes `name.rar`, `name.s00` becomes `name.r99`. None for a first name (`name.rar`, `name.part1.rar`) and for a
/// name that is no volume name.
pub fn previous_volume(path: &Path) -> Option<PathBuf> {
    let name = path.file_name()?.to_str()?;
    let lower = name.to_ascii_lowercase();
    let previous = if let Some(stem) = lower.strip_suffix(".rar") {
        let digits_at = part_digits_at(stem)?;
        let suffix = &stem[digits_at..];
        let n: u64 = suffix.parse().ok()?;
        if n <= 1 {
            return None;
        }
        // The width the set was named with, unless that name is absent and a narrower one is there: a set numbered
        // without padding (`part9`, `part10`) grows its width where `next_volume` does, so `part10`'s predecessor
        // is `part9`, not `part09`.
        let name_at =
            |width: usize| format!("{}{:0width$}{}", &name[..digits_at], n - 1, &name[stem.len()..], width = width);
        let narrowest = (n - 1).to_string().len();
        let padded = name_at(suffix.len());
        (narrowest..suffix.len())
            .rev()
            .map(name_at)
            .find(|candidate| !path.with_file_name(&padded).exists() && path.with_file_name(candidate).exists())
            .unwrap_or(padded)
    } else {
        let (base, ext) = name.rsplit_once('.')?;
        let mut chars = ext.chars();
        let letter = chars.next()?;
        let digits = chars.as_str();
        if !letter.is_ascii_alphabetic() || digits.len() < 2 || !digits.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        let n: u32 = digits.parse().ok()?;
        let width = digits.len();
        if n > 0 {
            format!("{base}.{letter}{:0width$}", n - 1)
        } else if letter.eq_ignore_ascii_case(&'r') {
            let r = if letter == 'R' { "RAR" } else { "rar" };
            format!("{base}.{r}")
        } else {
            let before = (letter as u8 - 1) as char;
            format!("{base}.{before}{:0width$}", 10u32.checked_pow(width.try_into().ok()?)? - 1)
        }
    };
    Some(path.with_file_name(previous))
}

/// In `name.partNN`, where the digits start.
fn part_digits_at(stem: &str) -> Option<usize> {
    let digits_len = stem.bytes().rev().take_while(u8::is_ascii_digit).count();
    if digits_len == 0 {
        return None;
    }
    let digits_at = stem.len() - digits_len;
    stem[..digits_at].ends_with(".part").then_some(digits_at)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn next(s: &str) -> String {
        next_volume(Path::new(s)).unwrap().to_string_lossy().into_owned()
    }

    #[test]
    fn rejects_an_overflowing_part_number() {
        assert_eq!(next_volume(Path::new("a.part18446744073709551615.rar")), None);
        assert_eq!(next_volume(Path::new("a.part18446744073709551616.rar")), None);
    }

    #[test]
    fn rejects_an_overflowing_old_style_suffix() {
        assert_eq!(next_volume(Path::new("a.r0000000001")), None);
        assert_eq!(next_volume(Path::new("a.r4294967295")), None);
    }

    #[test]
    fn rejects_suffixes_without_an_ascii_letter_successor() {
        for name in ["a.é00", "a.100", "a.z99", "a.Z99"] {
            assert_eq!(next_volume(Path::new(name)), None, "{name}");
        }
    }

    #[test]
    fn previous_names() {
        let prev = |s: &str| previous_volume(Path::new(s)).map(|p| p.to_string_lossy().into_owned());
        assert_eq!(prev("a.part02.rar").as_deref(), Some("a.part01.rar"));
        assert_eq!(prev("a.part10.rar").as_deref(), Some("a.part09.rar"));
        assert_eq!(prev("a.part1.rar"), None);
        assert_eq!(prev("a.rar"), None);
        assert_eq!(prev("a.r00").as_deref(), Some("a.rar"));
        assert_eq!(prev("A.R00").as_deref(), Some("A.RAR"));
        assert_eq!(prev("a.r05").as_deref(), Some("a.r04"));
        assert_eq!(prev("a.s00").as_deref(), Some("a.r99"));
        assert_eq!(prev("a.txt"), None);
    }

    /// Y5: an unpadded set's predecessor of `part10` is `part9`, found by the file that is there.
    #[test]
    fn previous_of_an_unpadded_set_takes_the_narrower_width() {
        let dir = tempfile::tempdir().unwrap();
        let at = |name: &str| dir.path().join(name);
        std::fs::write(at("s.part9.rar"), b"").unwrap();
        assert_eq!(previous_volume(&at("s.part10.rar")), Some(at("s.part9.rar")));
        // the padded name wins when it exists
        std::fs::write(at("s.part09.rar"), b"").unwrap();
        assert_eq!(previous_volume(&at("s.part10.rar")), Some(at("s.part09.rar")));
        // and with neither there, the set's own width is kept
        assert_eq!(previous_volume(&at("t.part10.rar")), Some(at("t.part09.rar")));
        std::fs::write(at("u.part99.rar"), b"").unwrap();
        assert_eq!(previous_volume(&at("u.part100.rar")), Some(at("u.part99.rar")));
    }

    #[test]
    fn numbering() {
        assert_eq!(next("a.part1.rar"), "a.part2.rar");
        assert_eq!(next("a.part09.rar"), "a.part10.rar");
        assert_eq!(next("a.part99.rar"), "a.part100.rar");
        assert_eq!(next("dir/Movie.2026.PART001.RAR"), "dir/Movie.2026.PART002.RAR");
        assert_eq!(next("a.rar"), "a.r00");
        assert_eq!(next("a.r00"), "a.r01");
        assert_eq!(next("SET.RAR"), "SET.R00");
        assert_eq!(next("SET.R00"), "SET.R01");
        assert_eq!(next("a.r99"), "a.s00");
    }
}

/// Native-name variant of [`next_volume`], preserving non-ASCII path units.
/// Suffix arithmetic uses the same checked numeric limits as `next_volume`.
pub fn next_volume_os(path: &std::ffi::OsStr) -> Option<std::ffi::OsString> {
    let path = Path::new(path);
    let name = path.file_name()?;
    #[cfg(unix)]
    let units: Vec<u16> = {
        use std::os::unix::ffi::OsStrExt;
        name.as_bytes().iter().map(|&b| u16::from(b)).collect()
    };
    #[cfg(windows)]
    let units: Vec<u16> = {
        use std::os::windows::ffi::OsStrExt;
        name.encode_wide().collect()
    };
    #[cfg(not(any(unix, windows)))]
    return next_volume(path).map(PathBuf::into_os_string);
    #[cfg(any(unix, windows))]
    {
        let next = next_ascii_units(&units)?;
        #[cfg(unix)]
        let name = {
            use std::os::unix::ffi::OsStringExt;
            std::ffi::OsString::from_vec(next.into_iter().map(|n| n as u8).collect())
        };
        #[cfg(windows)]
        let name = {
            use std::os::windows::ffi::OsStringExt;
            std::ffi::OsString::from_wide(&next)
        };
        Some(path.with_file_name(name).into_os_string())
    }
}

#[cfg(any(unix, windows))]
fn next_ascii_units(name: &[u16]) -> Option<Vec<u16>> {
    fn lower(c: u16) -> u16 {
        if (65..=90).contains(&c) { c + 32 } else { c }
    }
    fn digits(s: &[u16]) -> Option<u64> {
        s.iter().try_fold(0u64, |n, &c| {
            if !(48..=57).contains(&c) {
                return None;
            }
            n.checked_mul(10)?.checked_add(u64::from(c - 48))
        })
    }
    let dot = name.iter().rposition(|&c| c == 46)?;
    let ext = &name[dot + 1..];
    let mut out = name.to_vec();
    if ext.iter().copied().map(lower).eq("rar".encode_utf16()) {
        let stem = &name[..dot];
        let start = stem.iter().rposition(|c| !(48..=57).contains(c)).map_or(0, |i| i + 1);
        if start < dot && start >= 5 && stem[start - 5..start].iter().copied().map(lower).eq(".part".encode_utf16()) {
            let n = digits(&stem[start..])?.checked_add(1)?;
            let next = format!("{n:0width$}", width = dot - start);
            out.splice(start..dot, next.encode_utf16());
        } else {
            let uppercase = ext == [82, 65, 82] || ext == [82, 97, 114];
            out.truncate(dot + 1);
            out.extend(if uppercase { "R00" } else { "r00" }.encode_utf16());
        }
    } else {
        if ext.len() < 3 || !matches!(ext[0],65..=90|97..=122) {
            return None;
        }
        let n: u32 = digits(&ext[1..])?.try_into().ok()?;
        let limit = 10u32.checked_pow((ext.len() - 1).try_into().ok()?)?;
        let next = n.checked_add(1)?;
        let (letter, number) = if next < limit {
            (ext[0], next)
        } else {
            let letter = ext[0] + 1;
            if !matches!(letter,65..=90|97..=122) {
                return None;
            }
            (letter, 0)
        };
        out.truncate(dot + 1);
        out.push(letter);
        out.extend(format!("{number:0width$}", width = ext.len() - 1).encode_utf16());
    }
    Some(out)
}

#[cfg(test)]
mod native_tests {
    use super::*;
    #[test]
    fn ascii_matches_legacy_including_overflows() {
        for name in [
            "dir/Movie.2026.PART001.RAR",
            "a.part99.rar",
            "a.rar",
            "SET.RAR",
            "a.r99",
            "a.z99",
            "a.part18446744073709551615.rar",
            "a.part18446744073709551616.rar",
            "a.r0000000001",
            "a.r4294967295",
            "a.100",
            "a",
        ] {
            assert_eq!(
                next_volume_os(std::ffi::OsStr::new(name)),
                next_volume(Path::new(name)).map(PathBuf::into_os_string),
                "{name}"
            );
        }
    }
    #[cfg(unix)]
    #[test]
    fn raw_non_utf8_paths_survive() {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        for (input, output) in [
            (b"dir\xff/a\xfe.part09.rar".as_slice(), b"dir\xff/a\xfe.part10.rar".as_slice()),
            (b"a\xff.rar", b"a\xff.r00"),
            (b"a\xff.r99", b"a\xff.s00"),
        ] {
            let name = std::ffi::OsString::from_vec(input.to_vec());
            assert_eq!(next_volume_os(&name).unwrap().as_os_str().as_bytes(), output);
        }
    }
    #[cfg(windows)]
    #[test]
    fn unpaired_surrogate_survives() {
        use std::os::windows::ffi::{OsStrExt, OsStringExt};
        let input = std::ffi::OsString::from_wide(&[0xd800, 46, 114, 97, 114]);
        assert_eq!(next_volume_os(&input).unwrap().encode_wide().collect::<Vec<_>>(), vec![0xd800, 46, 114, 48, 48]);
    }
}
