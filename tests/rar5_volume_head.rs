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

//! `rar5::rebuild_volume_head`: a RAR 5.0 volume's start rebuilt from its quick open record.

use zipfast::Error;
use zipfast::rar5::{HeadDoubt, HeadOptions, rebuild_volume_head};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// A rar 7.30 volume (from the `rar5_volume_tail` vectors): its headers in place, its length, where its tail starts
/// and the tail.
struct Vector {
    headers: &'static [(usize, &'static str)],
    len: u64,
    tail_at: usize,
    tail: &'static str,
    volume: u64,
}

impl Vector {
    /// The volume's last bytes: the tail, then zeros up to its length.
    fn tail(&self) -> Vec<u8> {
        let mut tail = unhex(self.tail);
        tail.resize(self.len as usize - self.tail_at, 0);
        tail
    }
    /// The volume's first bytes: the signature, then each header that follows directly.
    fn head(&self) -> Vec<u8> {
        let mut head = b"Rar!\x1a\x07\x01\x00".to_vec();
        for (at, hex) in self.headers {
            if *at == head.len() {
                head.extend(unhex(hex));
            }
        }
        head
    }
    /// The start of a sibling volume of the same set: here the volume's own main header, which a sibling shares
    /// but for the volume number and the locator offset.
    fn sibling(&self) -> Vec<u8> {
        let mut s = b"Rar!\x1a\x07\x01\x00".to_vec();
        s.extend(unhex(self.headers[0].1));
        s
    }
}

/// `qo-plus/set.part2.rar`: one file continuing through the volume.
const QO_MIDDLE: Vector = Vector {
    headers: &[
        (8, "2ed59b100d01050803010701019d9f868000"),
        (26, "34315c3129021b0bdd9e0604e0dc2aa48302678d1d8d800001096d6f7669652e6d6b760a03137f09016b014b372a"),
    ],
    len: 102400,
    tail_at: 102309,
    tail: "cc3b31870e0306b80000b8000080000102514fd96e78d933008b9f062e34315c3129021b0bdd9e0604e0dc2aa48302678d1d8d800001096d6f7669652e6d6b760a03137f09016b014b372a8b475126030504010000000000000000",
    volume: 1,
};
/// `multi/set.part07.rar`: a file ending and another starting in the volume.
const QO_TWO_FILES: Vector = Vector {
    headers: &[
        (8, "abd475ee0d0105080306070101df9e868000"),
        (26, "f9c8e8bd29020b0bb1a40504e0dc2aa48302bb1aa2f3800001096d6f7669652e6d6b760a03137f09016b014b372a"),
        (86649, "94867e422902130bc0f90004f09309a48302fe5278768000010965787472612e62696e0a03137f09016bad3e7b2a"),
    ],
    len: 102400,
    tail_at: 102247,
    tail: "f0a4e1d90e0306ef0000ef000080000102514f2631008f3300cd9e062ef9c8e8bd29020b0bb1a40504e0dc2aa48302bb1aa2f3800001096d6f7669652e6d6b760a03137f09016b014b372a709600413200ee792e94867e422902130bc0f90004f09309a48302fe5278768000010965787472612e62696e0a03137f09016bad3e7b2a8b47512603050401000000000000000000000000000000",
    volume: 6,
};
/// `password/set.part7.rar`: the last volume of a `-p` set.
const QO_PASSWORD_LAST: Vector = Vector {
    headers: &[
        (8, "dc3b8e1d0d0105080306070101eea9858000"),
        (
            26,
            "910415f05a020b3cfda80504e0dc2aa48302b7ad9c1d800001096d6f7669652e6d6b76300100030fa8986d2d90111c91c645be02a721325ba32580af85446e807ddec291ca24715f7b21d7fde7b0767c02821caa0a03137f09016b014b372a",
        ),
    ],
    len: 87418,
    tail_at: 87286,
    tail: "9a78c6450e0306e90000e9000080000102514f59a32fc66400dca9055f910415f05a020b3cfda80504e0dc2aa48302b7ad9c1d800001096d6f7669652e6d6b76300100030fa8986d2d90111c91c645be02a721325ba32580af85446e807ddec291ca24715f7b21d7fde7b0767c02821caa0a03137f09016b014b372a1d77565103050400",
    volume: 6,
};
/// `small-piece-qoplus/set.part2.rar`: two files, both cached (`-qo+`).
const SMALL_PIECE_QO_PLUS: Vector = Vector {
    headers: &[
        (8, "254a451b0d0105080301070101e79e868000"),
        (26, "ae21770725020b0bc5820604aba10ca48302c9d1b1ba80000105612e6d6b760a03134c13016b203d5406"),
        (98697, "76f74cfa2502130bbc9b0004f09309a4830267b116de80000105622e6d6b760a03134c13016b4c82ab06"),
    ],
    len: 102400,
    tail_at: 102255,
    tail: "167035640e0306e70000e7000080000102514f441dda942f00d59e062aae21770725020b0bc5820604aba10ca48302c9d1b1ba80000105612e6d6b760a03134c13016b203d540616514e8b2e00e61b2a76f74cfa2502130bbc9b0004f09309a4830267b116de80000105622e6d6b760a03134c13016b4c82ab068b47512603050401000000000000000000000000000000",
    volume: 1,
};
/// `small-piece-default/set.part2.rar`: the same volume in rar's default mode, the small second file not cached.
const SMALL_PIECE_DEFAULT: Vector = Vector {
    headers: &[
        (8, "254a451b0d0105080301070101e79e868000"),
        (26, "ae21770725020b0bc5820604aba10ca48302c9d1b1ba80000105612e6d6b760a03134c13016b203d5406"),
        (98697, "76f74cfa2502130bbc9b0004f09309a4830267b116de80000105622e6d6b760a03134c13016b4c82ab06"),
    ],
    len: 102400,
    tail_at: 102255,
    tail: "59850f640e0306b40000b4000080000102514f441dda942f00d59e062aae21770725020b0bc5820604aba10ca48302c9d1b1ba80000105612e6d6b760a03134c13016b203d54068b47512603050401000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    volume: 1,
};
/// `qo-minus/set.part2.rar`: no quick open data.
const NO_QO_MIDDLE: Vector =
    Vector { headers: &[(8, "31fd3dd00401040301")], len: 102400, tail_at: 102392, tail: "8b47512603050401", volume: 1 };

#[test]
fn rar_made_volume_heads_rebuild_byte_for_byte() {
    for (name, v) in [
        ("one file", QO_MIDDLE),
        ("two files", QO_TWO_FILES),
        ("password, last volume", QO_PASSWORD_LAST),
        ("small piece, -qo+", SMALL_PIECE_QO_PLUS),
    ] {
        let sibling = v.sibling();
        let options = HeadOptions { volume: Some(v.volume), sibling: Some(&sibling) };
        let head = rebuild_volume_head(&v.tail(), v.len, &options).unwrap();
        assert_eq!(head.bytes, v.head(), "{name}");
        assert!(head.exact, "{name}: {:?}", head.doubt);
        assert_eq!(head.quick_open_offset, v.tail_at as u64, "{name}");
        // Every header the record copies is placed where it is in the volume.
        for h in &head.headers {
            let (_, hex) = v.headers.iter().find(|(at, _)| *at as u64 == h.offset).expect("a cached header");
            assert_eq!(h.bytes, unhex(hex), "{name}");
        }
        // A longer tail (with packed data in front) gives the same.
        let mut longer = vec![0x5a; 5000];
        longer.extend(v.tail());
        assert_eq!(rebuild_volume_head(&longer, v.len, &options).unwrap(), head, "{name}");
    }
}

#[test]
fn without_a_sibling_the_main_header_is_inferred() {
    // Two files, the second not solid: the archive is not solid, and the bytes are certain.
    let v = QO_TWO_FILES;
    let head = rebuild_volume_head(&v.tail(), v.len, &HeadOptions { volume: Some(v.volume), sibling: None }).unwrap();
    assert_eq!(head.bytes, v.head());
    assert!(head.exact, "{:?}", head.doubt);
    // One file: whether the archive is solid does not show. The bytes are rar's, but not claimed certain.
    let v = QO_MIDDLE;
    let head = rebuild_volume_head(&v.tail(), v.len, &HeadOptions { volume: Some(v.volume), sibling: None }).unwrap();
    assert_eq!(head.bytes, v.head());
    assert_eq!(head.doubt, Some(HeadDoubt::ArchiveFlagsInferred));
}

#[test]
fn what_cannot_be_certain_is_said() {
    // rar's default quick open mode skipped the small second file: the headers listed are exact, the gap is said.
    let v = SMALL_PIECE_DEFAULT;
    let sibling = v.sibling();
    let head =
        rebuild_volume_head(&v.tail(), v.len, &HeadOptions { volume: Some(1), sibling: Some(&sibling) }).unwrap();
    assert_eq!(head.doubt, Some(HeadDoubt::UncachedHeaders));
    assert_eq!(head.bytes, v.head()[..head.bytes.len()]);
    assert_eq!(head.headers.len(), 1);
    // The first volume's number would be 0, but its first file continues from a previous volume.
    let v = QO_MIDDLE;
    let head =
        rebuild_volume_head(&v.tail(), v.len, &HeadOptions { volume: Some(0), sibling: Some(&sibling) }).unwrap();
    assert_eq!(head.doubt, Some(HeadDoubt::VolumeNumberContradicted));
    // A volume that starts inside a file needs its number.
    assert!(matches!(rebuild_volume_head(&v.tail(), v.len, &HeadOptions::default()), Err(Error::Unsupported(_))));
}

#[test]
fn volumes_without_a_sound_quick_open_record_are_refused() {
    let v = NO_QO_MIDDLE;
    assert!(matches!(rebuild_volume_head(&v.tail(), v.len, &HeadOptions::default()), Err(Error::Unsupported(_))));
    assert!(matches!(rebuild_volume_head(&[0; 64], 64, &HeadOptions::default()), Err(Error::NotAnArchive)));
    assert!(matches!(rebuild_volume_head(b"junk", 2, &HeadOptions::default()), Err(Error::Corrupt(_))));
    // A record whose checksum fails.
    let v = QO_MIDDLE;
    let mut tail = v.tail();
    tail[30] ^= 1;
    assert!(matches!(
        rebuild_volume_head(&tail, v.len, &HeadOptions { volume: Some(1), sibling: None }),
        Err(Error::Corrupt(_))
    ));
    // A sibling that is not RAR 5.0.
    assert!(matches!(
        rebuild_volume_head(&v.tail(), v.len, &HeadOptions { volume: Some(1), sibling: Some(b"Rar!\x1a\x07\x00") }),
        Err(Error::NotAnArchive)
    ));
}

#[test]
fn hostile_tails_never_panic() {
    let mut state = 0x9e37_79b9u32;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        state
    };
    for v in [QO_MIDDLE, QO_TWO_FILES, QO_PASSWORD_LAST, SMALL_PIECE_DEFAULT] {
        let tail = v.tail();
        for _ in 0..3000 {
            let mut t = tail.clone();
            for _ in 0..(next() % 4 + 1) {
                let at = next() as usize % t.len();
                t[at] = next() as u8;
            }
            let cut = next() as usize % (t.len() + 1);
            let t = &t[cut.min(t.len() / 2)..];
            let len = v.len.wrapping_add(u64::from(next() % 3)).wrapping_sub(1);
            let sibling = v.sibling();
            let _ = rebuild_volume_head(
                t,
                len,
                &HeadOptions { volume: Some(u64::from(next() % 3)), sibling: Some(&sibling) },
            );
            let _ = rebuild_volume_head(t, len, &HeadOptions::default());
        }
    }
}

/// Every volume of rar-made sets outside the repository (`ZIPFAST_RAR5_TAIL_SETS`, or the default fixtures path,
/// and `ZIPFAST_Z_FIXTURES`, RustyGet's sets): rebuilt from its last 128 KiB with a sibling, a result claimed exact
/// is the volume's start byte for byte, and every set made with quick open data rebuilds exactly.
#[test]
fn every_volume_of_the_rar_made_sets_rebuilds_its_head() {
    let mut dirs = Vec::new();
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    if let Some(d) = std::env::var_os("ZIPFAST_RAR5_TAIL_SETS")
        .map(std::path::PathBuf::from)
        .or_else(|| home.as_ref().map(|h| h.join("git.xbmc4lyfe/zipfast-test-fixtures/rar5-tail")))
        .filter(|d| d.is_dir())
    {
        dirs.extend(std::fs::read_dir(d).unwrap().map(|e| e.unwrap().path()));
    }
    if let Some(d) = std::env::var_os("ZIPFAST_Z_FIXTURES").map(std::path::PathBuf::from).filter(|d| d.is_dir()) {
        dirs.extend(std::fs::read_dir(d).unwrap().map(|e| e.unwrap().path()).filter(|p| p.is_dir()));
    }
    if dirs.is_empty() {
        eprintln!("skipped: no rar-made sets (set ZIPFAST_RAR5_TAIL_SETS or ZIPFAST_Z_FIXTURES)");
        return;
    }
    dirs.sort();
    let (mut exact, mut checked) = (0, 0);
    for set in dirs {
        let name = set.file_name().unwrap().to_string_lossy().into_owned();
        let mut volumes: Vec<_> = std::fs::read_dir(&set)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "rar"))
            .collect();
        volumes.sort();
        if volumes.is_empty() {
            continue;
        }
        let first = std::fs::read(&volumes[0]).unwrap();
        if !first.starts_with(b"Rar!\x1a\x07\x01\x00") {
            continue;
        }
        for (index, path) in volumes.iter().enumerate() {
            let bytes = std::fs::read(path).unwrap();
            let sibling_path = &volumes[(index + 1) % volumes.len()];
            let sibling = std::fs::read(sibling_path).unwrap();
            let sibling = &sibling[..sibling.len().min(4096)];
            let tail = &bytes[bytes.len().saturating_sub(128 << 10)..];
            let options = HeadOptions { volume: Some(index as u64), sibling: Some(sibling) };
            checked += 1;
            if index == 0 {
                // The first volume starts with a whole file: without its number it is taken for the first, and said so.
                if let Ok(head) =
                    rebuild_volume_head(tail, bytes.len() as u64, &HeadOptions { volume: None, ..options })
                {
                    assert_eq!(head.bytes, bytes[..head.bytes.len()], "{name}");
                    assert_eq!(head.doubt, Some(HeadDoubt::VolumeNumberInferred), "{name}");
                }
            }
            match rebuild_volume_head(tail, bytes.len() as u64, &options) {
                Ok(head) => {
                    assert_eq!(head.bytes, bytes[..head.bytes.len()], "{name} volume {index}: {:?}", head.doubt);
                    for h in &head.headers {
                        let at = h.offset as usize;
                        assert_eq!(h.bytes, bytes[at..at + h.bytes.len()], "{name} volume {index}");
                    }
                    if head.exact {
                        exact += 1;
                    } else {
                        assert!(
                            name.contains("default") || name.contains("nfo"),
                            "{name} volume {index}: {:?}",
                            head.doubt
                        );
                    }
                }
                Err(e) => assert!(
                    // No quick open data: `-qo-`, encrypted headers, or rar's default mode with nothing to cache.
                    name.contains("hp")
                        || name == "rr"
                        || name.contains("minus")
                        || name.contains("noqo")
                        || name.contains("default") && matches!(e, Error::Unsupported(_)),
                    "{name} volume {index}: {e}"
                ),
            }
        }
    }
    eprintln!("{exact} of {checked} volumes rebuilt exactly");
    assert!(exact > 0);
}
