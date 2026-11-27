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

//! Turns a name stored in an archive into a path under the destination, refusing anything that would escape it.

use std::path::{Component, Path, PathBuf};

use crate::error::{Error, Result};

/// The name a RAR member is written under, from its decoded name; None when it can't be written.
///
/// A RAR 4.x legacy name holding bytes that aren't UTF-8 decodes as UnRAR decodes it: U+FFFE marks the name and
/// each such byte becomes U+E000 plus its value, always U+E080 to U+E0FF. It is written with those private-use
/// characters and without the mark: valid UTF-8 on every file system, never a `/`, `\` or `.`, and distinct for
/// distinct raw bytes. The decoder maps every U+E080..U+E0FF character of a marked name from a byte, so the
/// written name gives the raw name back. To keep the mapping one to one, an unmarked name holding U+E080..U+E0FF
/// is refused (it would collide with a mapped one), and so is any marked RAR 5.0 name. A RAR 4.x name that stored
/// U+FFFE itself decodes with U+FFFF in its place (it would pass for the mark otherwise) and is refused.
pub(crate) fn rar_output_name(name: &str, rar4: bool) -> Option<std::borrow::Cow<'_, str>> {
    let mapped = |c: char| ('\u{E080}'..='\u{E0FF}').contains(&c);
    match name.find('\u{FFFE}') {
        Some(_) if !rar4 => None,
        Some(mark) => {
            let (before, after) = name.split_at(mark);
            let after = &after['\u{FFFE}'.len_utf8()..];
            (!before.contains(mapped) && !after.contains('\u{FFFE}'))
                .then(|| std::borrow::Cow::Owned(format!("{before}{after}")))
        }
        _ if rar4 && name.contains('\u{FFFF}') => None,
        None if rar4 && name.contains(mapped) => None,
        None => Some(std::borrow::Cow::Borrowed(name)),
    }
}

/// `Options::rar4_raw_names`: `rel`, a RAR 4.x member's checked output path (from [`rar_output_name`] and
/// [`sanitize`]), with each U+E080..U+E0FF character turned back into the byte 0x80..0xFF it stands for, as UnRAR
/// and 7-Zip write such a name on Unix. None when `rel` holds no such character.
///
/// The bytes are all 0x80 or above, never a `/`, a NUL or a `.`, so every component stays the one that was checked;
/// that is verified again here, and a path that would change shape is refused (None, keep `rel`).
#[cfg(unix)]
pub(crate) fn rar4_raw_path(rel: &Path) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    let text = rel.to_str()?;
    if !text.chars().any(|c| ('\u{E080}'..='\u{E0FF}').contains(&c)) {
        return None;
    }
    let bytes = rar4_raw_bytes(text.as_bytes().to_vec());
    if bytes.contains(&0) {
        return None;
    }
    let raw = PathBuf::from(std::ffi::OsString::from_vec(bytes));
    let normal = |path: &Path| path.components().all(|part| matches!(part, Component::Normal(_)));
    (normal(rel) && normal(&raw) && raw.components().count() == rel.components().count()).then_some(raw)
}

/// `Options::rar4_raw_names` for a RAR 4.x symbolic link's target, mapped as member names are
/// (`crate::extract::link::rar4_target`): each U+E080..U+E0FF character back to its byte 0x80..0xFF, so the link
/// points at the member written under its raw bytes. The bytes are never a `/`, a NUL or a `.`, so the target's
/// components stay the ones that are checked. A target that isn't UTF-8 is returned as it is.
pub(crate) fn rar4_raw_bytes(target: Vec<u8>) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(&target) else { return target };
    if !text.chars().any(|c| ('\u{E080}'..='\u{E0FF}').contains(&c)) {
        return target;
    }
    let mut bytes = Vec::with_capacity(text.len());
    for c in text.chars() {
        match u32::from(c).checked_sub(0xE000).filter(|b| (0x80..=0xFF).contains(b)).and_then(|b| u8::try_from(b).ok())
        {
            Some(byte) => bytes.push(byte),
            None => bytes.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes()),
        }
    }
    bytes
}

/// Whether a folder member's name is only `.` and separators, as in the `./` that bsdtar and Windows `tar.exe`
/// write first when archiving the current directory: it stands for the destination itself, so it is passed over.
#[cfg(test)]
pub(crate) fn names_root(name: &str) -> bool {
    names_root_with(name, true)
}

/// [`names_root`], with `\\` a separator only when `backslash_separates` (not under `Options::backslashes` literal,
/// where `\\` or `.\\` is a folder's own name).
pub(crate) fn names_root_with(name: &str, backslash_separates: bool) -> bool {
    let separator = |c: char| c == '/' || backslash_separates && c == '\\';
    !name.is_empty() && name.split(separator).all(|part| part.is_empty() || part == ".")
}

/// `windows_names`: the archive was made on Windows, so a backslash is a separator there and a drive letter or
/// a reserved character means nothing on this side.
pub fn sanitize(name: &str, windows_names: bool) -> Result<PathBuf> {
    sanitize_with(name, windows_names, false)
}

/// [`sanitize`], also mapping the characters Windows refuses in a name to `_` when `windows_safe` is set, whatever
/// system made the archive (`Options::windows_safe_names`).
pub(crate) fn sanitize_with(name: &str, windows_names: bool, windows_safe: bool) -> Result<PathBuf> {
    sanitize_fallible_with(name, windows_names, windows_safe).map_err(|_| Error::UnsafePath(name.to_string()))
}

/// Whether Windows refuses `c` in a file name.
fn windows_reserved(c: char) -> bool {
    matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*')
}

/// `name` with the characters Windows refuses in a file name mapped to `_`, separators and all else kept.
pub(crate) fn windows_safe_name(name: &str) -> std::borrow::Cow<'_, str> {
    if name.contains(windows_reserved) {
        name.chars().map(|c| if windows_reserved(c) { '_' } else { c }).collect::<String>().into()
    } else {
        name.into()
    }
}

pub(crate) enum ProjectionError {
    Unsafe,
    Allocation(std::collections::TryReserveError),
}

// A single component traversal serves both the legacy and bounded RAR paths.
// A normalized UTF-8 name never grows: replacement characters are all ASCII.
pub(crate) fn sanitize_fallible(name: &str, windows_names: bool) -> std::result::Result<PathBuf, ProjectionError> {
    sanitize_fallible_with(name, windows_names, false)
}

fn sanitize_fallible_with(
    name: &str,
    windows_names: bool,
    windows_safe: bool,
) -> std::result::Result<PathBuf, ProjectionError> {
    let mut out = String::new();
    out.try_reserve_exact(name.len()).map_err(ProjectionError::Allocation)?;
    for (i, part) in name.split(|c| c == '/' || (windows_names && c == '\\')).enumerate() {
        match part {
            "" if i == 0 && !name.is_empty() => return Err(ProjectionError::Unsafe),
            "" | "." => continue,
            ".." => return Err(ProjectionError::Unsafe),
            _ => {}
        }
        if part.contains('\0') || (windows_names && i == 0 && part.len() == 2 && part.ends_with(':')) {
            return Err(ProjectionError::Unsafe);
        }
        if !out.is_empty() {
            out.push('/');
        }
        for c in part.chars() {
            out.push(if (cfg!(windows) || windows_names || windows_safe) && windows_reserved(c) { '_' } else { c });
        }
    }
    let path = PathBuf::from(out);
    if path.as_os_str().is_empty() || path.components().any(|c| !matches!(c, Component::Normal(_))) {
        return Err(ProjectionError::Unsafe);
    }
    Ok(path)
}

/// Whether `target` resolves inside `root` once joined to `link_dir`, without touching the file system.
pub fn link_stays_inside(link_dir: &Path, target: &str) -> bool {
    if target.starts_with('/') || target.starts_with('\\') || target.contains(':') {
        return false;
    }
    let mut depth: i64 = link_dir.components().count() as i64;
    for part in target.split(['/', '\\']) {
        match part {
            "" | "." => {}
            ".." => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            _ => depth += 1,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_escapes() {
        for bad in ["../x", "a/../../x", "/etc/passwd", "a/..", "", "a/\0b"] {
            assert!(sanitize(bad, false).is_err(), "{bad:?}");
        }
        assert!(sanitize("C:/x", true).is_err());
        assert!(sanitize("..\\x", true).is_err());
    }

    #[test]
    fn root_names() {
        for root in [".", "./", ".\\", "./.", "././"] {
            assert!(names_root(root), "{root:?}");
        }
        for other in ["", "./a", "..", "../", "a/."] {
            assert!(!names_root(other), "{other:?}");
        }
    }

    #[test]
    fn keeps_normal_names() {
        assert_eq!(sanitize("a/b/c.mkv", false).unwrap(), Path::new("a/b/c.mkv"));
        assert_eq!(sanitize("./a//b", false).unwrap(), Path::new("a/b"));
        assert_eq!(sanitize("a\\b.txt", true).unwrap(), Path::new("a/b.txt"));
    }

    #[test]
    #[cfg(unix)]
    fn rar4_raw_paths_map_private_use_back_to_bytes() {
        use std::os::unix::ffi::OsStrExt;
        let raw = |name: &str| rar4_raw_path(Path::new(name)).map(|p| p.as_os_str().as_bytes().to_vec());
        assert_eq!(raw("test/C\u{E085}:5\u{E0E5}\u{E0CB}B'").as_deref(), Some(&b"test/C\x85:5\xe5\xcbB'"[..]));
        assert_eq!(raw("d\u{E0FF}/\u{E080}").as_deref(), Some(&b"d\xff/\x80"[..]));
        // nothing mapped: the path stays as it is
        assert_eq!(raw("test/caf\u{E9}.txt"), None);
        assert_eq!(raw("test/\u{E07F}\u{E100}"), None);
        // never a separator, NUL or dot component out of a mapped byte; a path that isn't plain is left alone
        assert_eq!(raw("../\u{E085}"), None);
        assert_eq!(raw("/abs/\u{E085}"), None);
    }

    #[test]
    fn rar_output_names_are_one_to_one() {
        let out = |name: &str, rar4: bool| rar_output_name(name, rar4).map(|n| n.into_owned());
        assert_eq!(out("caf\u{FFFE}\u{E0E9}.txt", true).as_deref(), Some("caf\u{E0E9}.txt"));
        assert_eq!(out("plain/name.txt", true).as_deref(), Some("plain/name.txt"));
        // an unmarked private-use character would collide with a mapped byte
        assert_eq!(out("caf\u{E0E9}.txt", true), None);
        assert_eq!(out("\u{E0E9}\u{FFFE}\u{E0E8}", true), None);
        assert_eq!(out("a\u{FFFE}\u{E0E9}\u{FFFE}", true), None);
        // a stored U+FFFE (decoded as U+FFFF) is refused; U+FFFD is ordinary text
        assert_eq!(out("a\u{FFFF}", true), None);
        assert_eq!(out("a\u{FFFD}", true).as_deref(), Some("a\u{FFFD}"));
        // RAR 5.0 names are UTF-8: a mark there is refused, other private-use characters are only text
        assert_eq!(out("caf\u{FFFE}\u{E0E9}.txt", false), None);
        assert_eq!(out("caf\u{E0E9}.txt", false).as_deref(), Some("caf\u{E0E9}.txt"));
    }

    #[test]
    fn links() {
        assert!(link_stays_inside(Path::new("a/b"), "../c"));
        assert!(!link_stays_inside(Path::new("a"), "../../c"));
        assert!(!link_stays_inside(Path::new(""), "/etc"));
    }
}

#[cfg(test)]
mod windows_safe_tests {
    use super::*;

    #[test]
    fn windows_safe_maps_reserved_characters_on_any_host() {
        let name = "dir/a<b>c:d\"e|f?g*h.txt";
        assert_eq!(sanitize_with(name, false, true).unwrap(), PathBuf::from("dir/a_b_c_d_e_f_g_h.txt"));
        if !cfg!(windows) {
            assert_eq!(sanitize_with(name, false, false).unwrap(), PathBuf::from(name));
        }
        assert_eq!(windows_safe_name(name), "dir/a_b_c_d_e_f_g_h.txt");
        assert!(matches!(windows_safe_name("plain/name"), std::borrow::Cow::Borrowed(_)));
    }
}
