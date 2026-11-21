//! Rebuilding the end of a RAR 5.0 volume byte for byte (`zipfast::rar5::rebuild_volume_tail`).

use zipfast::rar5::{
    QuickOpenMode, RebuiltTail, TailDoubt, quick_open_mode, rebuild_volume_tail, rebuild_volume_tail_with,
};

/// The rebuilt bytes from the tail's offset to the volume's end: headers, then the padding zeros.
fn whole(tail: &RebuiltTail) -> Vec<u8> {
    let mut out = tail.bytes.clone();
    out.resize(out.len() + tail.padding as usize, 0);
    out
}

/// Volume sets made by rar 7.30, outside the repository: `ZIPFAST_RAR5_TAIL_SETS`, or the default fixtures path.
fn sets() -> Option<std::path::PathBuf> {
    let dir = std::env::var_os("ZIPFAST_RAR5_TAIL_SETS").map(std::path::PathBuf::from).or_else(|| {
        std::env::var_os("HOME").map(|h| std::path::Path::new(&h).join("git.xbmc4lyfe/zipfast-test-fixtures/rar5-tail"))
    })?;
    dir.is_dir().then_some(dir)
}

/// Where a volume's tail starts, as the rebuild finds it from the whole volume.
fn rebuild_offset(bytes: &[u8]) -> usize {
    rebuild_volume_tail_with(bytes, bytes.len() as u64, None, Some(QuickOpenMode::All))
        .map_or(bytes.len(), |t| t.offset as usize)
}

/// Every volume of every rar-made set: cut after the last file's data and rebuilt, it matches the original byte for
/// byte, and the result says when it cannot be certain.
#[test]
fn every_volume_of_the_rar_made_sets_rebuilds_byte_for_byte() {
    let Some(dir) = sets() else {
        eprintln!("skipped: no rar-made sets (set ZIPFAST_RAR5_TAIL_SETS)");
        return;
    };
    let (mut checked, mut unsure) = (0, 0);
    let mut sets: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().path()).collect();
    sets.sort();
    for set in sets {
        let name = set.file_name().unwrap().to_string_lossy().into_owned();
        let mut volumes: Vec<_> = std::fs::read_dir(&set).unwrap().map(|e| e.unwrap().path()).collect();
        volumes.sort();
        let count = volumes.len();
        // The set's quick open mode, as a caller learns it from any intact volume of the set.
        let mode = volumes.iter().find_map(|v| quick_open_mode(&std::fs::read(v).unwrap()));
        if name.contains("default") && name.starts_with("small") || name == "nfo-first-default" {
            assert_eq!(mode, Some(QuickOpenMode::LargeFiles), "{name}");
        }
        if name.ends_with("qoplus") && (name.starts_with("small") || name.starts_with("nfo")) {
            assert_eq!(mode, Some(QuickOpenMode::All), "{name}");
        }
        for (index, path) in volumes.iter().enumerate() {
            let bytes = std::fs::read(path).unwrap();
            let more = Some(index + 1 < count);
            // Without the mode the rebuild may doubt, but never claims exact bytes that are wrong.
            if let Ok(guess) =
                rebuild_volume_tail(&bytes[..bytes.len().min(rebuild_offset(&bytes))], bytes.len() as u64, more)
            {
                if guess.exact {
                    assert_eq!(
                        whole(&guess),
                        bytes[guess.offset as usize..],
                        "{}: exact without the mode",
                        path.display()
                    );
                } else if guess.doubt == Some(TailDoubt::QuickOpenMode) {
                    unsure += 1;
                }
            }
            let rebuilt = rebuild_volume_tail_with(&bytes, bytes.len() as u64, more, mode);
            if name == "hp" || name == "rr" {
                assert!(rebuilt.is_err(), "{}: {rebuilt:?}", path.display());
                continue;
            }
            let rebuilt = rebuilt.unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            let offset = rebuilt.offset as usize;
            assert_eq!(whole(&rebuilt), bytes[offset..], "{}", path.display());
            assert!(rebuilt.exact, "{}: {:?}", path.display(), rebuilt.doubt);
            // Lost from the end of the last file's data: the same bytes from the surviving start.
            let cut = rebuild_volume_tail_with(&bytes[..offset], bytes.len() as u64, more, mode).unwrap();
            assert_eq!(cut, rebuilt, "{}", path.display());
            checked += 1;
        }
    }
    // Volumes of a 3 GB member, kept as their first and last 4 KiB: rar's default quick open mode still caches the
    // header of a member this large, and its file header's padded fields are copied as they are.
    let slices = dir.with_file_name("rar5-tail-big").join("slices");
    if slices.is_dir() {
        for name in
            ["big-default-01", "big-default-08", "big-default-16", "big-qoplus-01", "big-qoplus-08", "big-qoplus-16"]
        {
            let head = std::fs::read(slices.join(format!("{name}.head"))).unwrap();
            let end = std::fs::read(slices.join(format!("{name}.tail"))).unwrap();
            let len: u64 = std::fs::read_to_string(slices.join(format!("{name}.len"))).unwrap().trim().parse().unwrap();
            let more = Some(!name.ends_with("-16"));
            let rebuilt = rebuild_volume_tail(&head, len, more).unwrap();
            assert!(rebuilt.exact, "{name}: {:?}", rebuilt.doubt);
            let tail = whole(&rebuilt);
            assert_eq!(tail, end[end.len() - tail.len()..], "{name}");
            assert_eq!(rebuilt.offset + tail.len() as u64, len, "{name}");
            checked += 1;
        }
    }
    eprintln!("{checked} volumes rebuilt; {unsure} needed the quick open mode");
    assert!(checked > 0);
}

/// A volume's headers and expected tail, taken from a rar-made set: enough to rebuild without the packed data.
struct Vector {
    headers: &'static [(usize, &'static str)],
    len: u64,
    tail_at: usize,
    tail: &'static str,
    more: bool,
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

impl Vector {
    /// The surviving start of the volume up to the end of the last file's data: signature and headers in place,
    /// zeros for the packed data (the rebuild does not read it).
    fn head(&self) -> Vec<u8> {
        let mut head = vec![0; self.tail_at];
        head[..8].copy_from_slice(b"Rar!\x1a\x07\x01\x00");
        for (at, hex) in self.headers {
            let bytes = unhex(hex);
            head[*at..*at + bytes.len()].copy_from_slice(&bytes);
        }
        head
    }
}

/// `qo-plus/set.part2.rar` (rar 7.30): header (offset, bytes), the volume length, the tail offset and the tail.
const QO_MIDDLE: Vector = Vector {
    headers: &[
        (8, "2ed59b100d01050803010701019d9f868000"),
        (26, "34315c3129021b0bdd9e0604e0dc2aa48302678d1d8d800001096d6f7669652e6d6b760a03137f09016b014b372a"),
    ],
    len: 102400,
    tail_at: 102309,
    tail: "cc3b31870e0306b80000b8000080000102514fd96e78d933008b9f062e34315c3129021b0bdd9e0604e0dc2aa48302678d1d8d800001096d6f7669652e6d6b760a03137f09016b014b372a8b475126030504010000000000000000",
    more: true,
};
/// `qo-minus/set.part2.rar` (rar 7.30): header (offset, bytes), the volume length, the tail offset and the tail.
const NO_QO_MIDDLE: Vector = Vector {
    headers: &[
        (8, "31fd3dd00401040301"),
        (17, "0635bb2b29021b0bb99f0604e0dc2aa483023bdbff89800001096d6f7669652e6d6b760a03137f09016b014b372a"),
    ],
    len: 102400,
    tail_at: 102392,
    tail: "8b47512603050401",
    more: true,
};
/// `multi/set.part07.rar` (rar 7.30): header (offset, bytes), the volume length, the tail offset and the tail.
const QO_TWO_FILES: Vector = Vector {
    headers: &[
        (8, "abd475ee0d0105080306070101df9e868000"),
        (26, "f9c8e8bd29020b0bb1a40504e0dc2aa48302bb1aa2f3800001096d6f7669652e6d6b760a03137f09016b014b372a"),
        (86649, "94867e422902130bc0f90004f09309a48302fe5278768000010965787472612e62696e0a03137f09016bad3e7b2a"),
    ],
    len: 102400,
    tail_at: 102247,
    tail: "f0a4e1d90e0306ef0000ef000080000102514f2631008f3300cd9e062ef9c8e8bd29020b0bb1a40504e0dc2aa48302bb1aa2f3800001096d6f7669652e6d6b760a03137f09016b014b372a709600413200ee792e94867e422902130bc0f90004f09309a48302fe5278768000010965787472612e62696e0a03137f09016bad3e7b2a8b47512603050401000000000000000000000000000000",
    more: true,
};
/// `password/set.part7.rar` (rar 7.30): header (offset, bytes), the volume length, the tail offset and the tail.
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
    more: false,
};

/// `small-piece-default/set.part2.rar` (rar 7.30).
const SMALL_PIECE_DEFAULT: Vector = Vector {
    headers: &[
        (8, "254a451b0d0105080301070101e79e868000"),
        (26, "ae21770725020b0bc5820604aba10ca48302c9d1b1ba80000105612e6d6b760a03134c13016b203d5406"),
        (98697, "76f74cfa2502130bbc9b0004f09309a4830267b116de80000105622e6d6b760a03134c13016b4c82ab06"),
    ],
    len: 102400,
    tail_at: 102255,
    tail: "59850f640e0306b40000b4000080000102514f441dda942f00d59e062aae21770725020b0bc5820604aba10ca48302c9d1b1ba80000105612e6d6b760a03134c13016b203d54068b47512603050401000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    more: true,
};
/// `small-piece-qoplus/set.part2.rar` (rar 7.30).
const SMALL_PIECE_QO_PLUS: Vector = Vector {
    headers: &[
        (8, "254a451b0d0105080301070101e79e868000"),
        (26, "ae21770725020b0bc5820604aba10ca48302c9d1b1ba80000105612e6d6b760a03134c13016b203d5406"),
        (98697, "76f74cfa2502130bbc9b0004f09309a4830267b116de80000105622e6d6b760a03134c13016b4c82ab06"),
    ],
    len: 102400,
    tail_at: 102255,
    tail: "167035640e0306e70000e7000080000102514f441dda942f00d59e062aae21770725020b0bc5820604aba10ca48302c9d1b1ba80000105612e6d6b760a03134c13016b203d540616514e8b2e00e61b2a76f74cfa2502130bbc9b0004f09309a4830267b116de80000105622e6d6b760a03134c13016b4c82ab068b47512603050401000000000000000000000000000000",
    more: true,
};
/// `small-last-default/set.part3.rar` (rar 7.30).
const SMALL_LAST_DEFAULT: Vector = Vector {
    headers: &[
        (8, "a38191bd0d01050803020701018080808000"),
        (26, "8fee97552e020b0be48f00048bcd0ca48302d8faad548000010e73686f72742d7461696c2e6d6b760a03134c13016b985c7607"),
    ],
    len: 2105,
    tail_at: 2097,
    tail: "1d77565103050400",
    more: false,
};

#[test]
fn rar_made_volume_ends_rebuild_byte_for_byte() {
    for (name, v) in [
        ("quick open, middle volume", QO_MIDDLE),
        ("no quick open, middle volume", NO_QO_MIDDLE),
        ("quick open, two files in the volume", QO_TWO_FILES),
        ("quick open, password, last volume", QO_PASSWORD_LAST),
    ] {
        let rebuilt = rebuild_volume_tail(&v.head(), v.len, Some(v.more)).unwrap();
        assert_eq!(rebuilt.offset, v.tail_at as u64, "{name}");
        assert_eq!(whole(&rebuilt), unhex(v.tail), "{name}");
        assert!(rebuilt.exact, "{name}: {:?}", rebuilt.doubt);
        // The usual loss: the surviving bytes end inside the last file's packed data.
        let cut = rebuild_volume_tail(&v.head()[..v.tail_at - 1000], v.len, Some(v.more)).unwrap();
        assert_eq!(cut, rebuilt, "{name}");
        // A file that continues in the next volume says more volumes follow without being told.
        if v.more {
            assert_eq!(rebuild_volume_tail(&v.head(), v.len, None).unwrap(), rebuilt, "{name}");
        }
    }
}

/// The last volume's file ends in it, so without `more_volumes` the flag is inferred and the result not certain.
#[test]
fn an_inferred_last_volume_is_not_claimed_exact() {
    let v = QO_PASSWORD_LAST;
    let rebuilt = rebuild_volume_tail(&v.head(), v.len, None).unwrap();
    assert_eq!(whole(&rebuilt), unhex(v.tail));
    assert!(!rebuilt.exact);
    assert_eq!(rebuilt.doubt, Some(TailDoubt::MoreVolumesInferred));
}

/// Doubts: supplied tail bytes that differ, padding where none is expected, a quick open header the locator puts
/// elsewhere (a length that leaves room for an unseen header), and the wrong "more volumes" flag.
#[test]
fn a_rebuild_that_cannot_be_certain_says_why() {
    let v = QO_MIDDLE;
    let mut head = v.head();
    let mut tail = unhex(v.tail);
    tail[3] ^= 1;
    head.extend(&tail);
    let rebuilt = rebuild_volume_tail(&head, v.len, Some(true)).unwrap();
    assert_eq!(rebuilt.doubt, Some(TailDoubt::DiffersFromSupplied));
    assert_eq!(whole(&rebuilt), unhex(v.tail), "the rebuilt bytes are still rar's");

    // A wrong length: padding after the last volume's end header, or far more than rar reserves after a middle one.
    let v = QO_PASSWORD_LAST;
    let rebuilt = rebuild_volume_tail(&v.head(), v.len + 3, Some(false)).unwrap();
    assert_eq!(rebuilt.doubt, Some(TailDoubt::UnexpectedPadding));
    let v = QO_MIDDLE;
    let rebuilt = rebuild_volume_tail(&v.head(), v.len + 100, Some(true)).unwrap();
    assert_eq!(rebuilt.doubt, Some(TailDoubt::UnexpectedPadding));
    // An untrusted length as large as it gets: the padding is a count, never allocated.
    let rebuilt = rebuild_volume_tail(&v.head(), u64::MAX, Some(true)).unwrap();
    assert_eq!(rebuilt.doubt, Some(TailDoubt::UnexpectedPadding));
    assert_eq!(rebuilt.padding, u64::MAX - v.tail_at as u64 - rebuilt.bytes.len() as u64);

    // Told no volumes follow, although the last file continues in the next one.
    let rebuilt = rebuild_volume_tail(&v.head(), v.len, Some(false)).unwrap();
    assert_eq!(rebuilt.doubt, Some(TailDoubt::MoreVolumesContradicted));

    let v = NO_QO_MIDDLE;
    let rebuilt = rebuild_volume_tail(&v.head(), v.len + 100, Some(true)).unwrap();
    assert_eq!(rebuilt.doubt, Some(TailDoubt::UnexpectedPadding));

    // The volume's second file header is lost too (zeros where it was): the locator puts the quick open header
    // after a file the surviving bytes do not show.
    let v = QO_TWO_FILES;
    let mut head = v.head();
    let (second, bytes) = v.headers[2];
    head[second..second + bytes.len() / 2].fill(0);
    let rebuilt = rebuild_volume_tail(&head[..second + 64], v.len, Some(true)).unwrap();
    assert_eq!(rebuilt.offset, second as u64);
    assert_eq!(rebuilt.doubt, Some(TailDoubt::QuickOpenElsewhere));
}

#[test]
fn volumes_that_cannot_be_rebuilt_are_refused() {
    // Encrypted headers (`-hp`): every header has a random IV.
    let mut hp = b"Rar!\x1a\x07\x01\x00".to_vec();
    hp.extend(unhex("22f50b0021040000010f0d1933453e3f07bad92638ed6933ec931f9b198eff33e9e397ab44c7"));
    hp.resize(4096, 0);
    assert!(matches!(rebuild_volume_tail(&hp, 102_400, Some(true)), Err(zipfast::Error::Unsupported(_))));
    // A recovery record (`-rr`): its data covers the whole volume.
    let mut rr = b"Rar!\x1a\x07\x01\x00".to_vec();
    rr.extend(unhex("39a3ee891201050d0b010c0103c7e585800092e6858000"));
    rr.resize(4096, 0);
    assert!(matches!(rebuild_volume_tail(&rr, 102_400, Some(true)), Err(zipfast::Error::Unsupported(_))));
    // Not RAR 5.0, and a start that ends inside the first file header.
    assert!(matches!(rebuild_volume_tail(b"Rar!\x1a\x07\x00", 100, None), Err(zipfast::Error::NotAnArchive)));
    let v = QO_MIDDLE;
    assert!(matches!(rebuild_volume_tail(&v.head()[..40], v.len, None), Err(zipfast::Error::Truncated)));
}

/// rar's default quick open mode skips the header of a file with 4096 bytes of packed data or less in the volume,
/// and `-qo+` caches it: a volume ending with such a piece (here b.mkv's first 3516 bytes) has two possible tails.
/// Without the set's mode the rebuild doubts; with it, both are exact. A last volume holding only a small piece has
/// no quick open data in default mode, and its zero locator offset says so.
#[test]
fn a_small_piece_depends_on_the_quick_open_mode() {
    for (v, mode) in [(SMALL_PIECE_DEFAULT, QuickOpenMode::LargeFiles), (SMALL_PIECE_QO_PLUS, QuickOpenMode::All)] {
        let guess = rebuild_volume_tail(&v.head(), v.len, Some(v.more)).unwrap();
        assert_eq!(guess.doubt, Some(TailDoubt::QuickOpenMode), "{mode:?}");
        let rebuilt = rebuild_volume_tail_with(&v.head(), v.len, Some(v.more), Some(mode)).unwrap();
        assert!(rebuilt.exact, "{mode:?}: {:?}", rebuilt.doubt);
        assert_eq!(whole(&rebuilt), unhex(v.tail), "{mode:?}");
        // The other mode's bytes differ, and the volume's length cannot always tell: a supplied mode is trusted, so
        // take it from the set (`quick_open_mode`), never guess it.
        let other = if mode == QuickOpenMode::All { QuickOpenMode::LargeFiles } else { QuickOpenMode::All };
        let wrong = rebuild_volume_tail_with(&v.head(), v.len, Some(v.more), Some(other)).unwrap();
        assert_ne!(whole(&wrong), unhex(v.tail), "{mode:?}");
    }
    let v = SMALL_LAST_DEFAULT;
    let rebuilt = rebuild_volume_tail(&v.head(), v.len, Some(false)).unwrap();
    assert!(rebuilt.exact, "{:?}", rebuilt.doubt);
    assert_eq!(whole(&rebuilt), unhex(v.tail));
}

/// A middle volume whose last surviving file ends in it may have lost a later file header with the tail: rebuilt from
/// a start that stops after that file, the result is doubted, and from the whole volume it is exact.
#[test]
fn a_middle_volume_ending_with_a_whole_file_is_doubted_from_its_start_alone() {
    let v = QO_TWO_FILES;
    let first_end = v.headers[2].0;
    let rebuilt = rebuild_volume_tail(&v.head()[..first_end], v.len, Some(true)).unwrap();
    assert!(!rebuilt.exact);
    assert_eq!(rebuilt.offset, first_end as u64);
}
