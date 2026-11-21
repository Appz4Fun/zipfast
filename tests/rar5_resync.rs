//! Restarting the RAR 5.0 decoder after a hole in a compressed member (`zipfast::rar5::unpack::resync`).

use zipfast::rar5::unpack::{ResyncError, Sink, Unpacker, resync, window_for};

fn vint(b: &[u8], mut i: usize) -> (u64, usize) {
    let (mut v, mut s) = (0u64, 0);
    loop {
        let c = b[i];
        i += 1;
        v |= u64::from(c & 0x7f) << s;
        s += 7;
        if c < 0x80 {
            return (v, i);
        }
    }
}

/// The first file's packed data, unpacked size and dictionary size in a single-volume RAR 5.0 archive.
fn member(archive: &[u8]) -> (Vec<u8>, u64, u64) {
    let mut i = 8;
    loop {
        let (size, h) = vint(archive, i + 4);
        let (kind, j) = vint(archive, h);
        let (flags, mut j) = vint(archive, j);
        if flags & 1 != 0 {
            j = vint(archive, j).1;
        }
        let mut data = 0;
        if flags & 2 != 0 {
            (data, j) = vint(archive, j);
        }
        let end = h + size as usize;
        if kind == 2 {
            let (file_flags, k) = vint(archive, j);
            let (unpacked, mut k) = vint(archive, k);
            k = vint(archive, k).1; // attributes
            if file_flags & 2 != 0 {
                k += 4;
            }
            if file_flags & 4 != 0 {
                k += 4;
            }
            let (info, _) = vint(archive, k);
            let power = (info >> 10) & 0x1f;
            let fraction = (info >> 15) & 0x1f;
            let mut dict = (128u64 << 10) << power;
            dict += dict / 32 * fraction;
            return (archive[end..end + data as usize].to_vec(), unpacked, dict);
        }
        i = end + data as usize;
    }
}

struct Collect(Vec<u8>);
impl Sink for Collect {
    fn put(&mut self, bytes: &[u8]) -> zipfast::Result<()> {
        self.0.extend_from_slice(bytes);
        Ok(())
    }
}

fn fixtures() -> Option<std::path::PathBuf> {
    let dir = std::env::var_os("ZIPFAST_RAR5_RESYNC_SETS").map(std::path::PathBuf::from).or_else(|| {
        std::env::var_os("HOME")
            .map(|h| std::path::Path::new(&h).join("git.xbmc4lyfe/zipfast-test-fixtures/rar5-resync"))
    })?;
    dir.is_dir().then_some(dir)
}

/// A rar-made compressed member loses packed bytes in the middle; decoding restarts after the hole from the known
/// plaintext and produces the rest of the member exactly.
#[test]
fn a_rar_made_member_restarts_after_a_hole() {
    let Some(dir) = fixtures() else {
        eprintln!("skipped: no rar-made sets (set ZIPFAST_RAR5_RESYNC_SETS)");
        return;
    };
    let joined = || {
        let parts: Vec<_> =
            (1..=4).map(|i| member(&std::fs::read(dir.join(format!("textvol.part{i}.rar"))).unwrap())).collect();
        (parts.iter().flat_map(|p| p.0.clone()).collect::<Vec<u8>>(), parts[0].1, parts[0].2)
    };
    for (archive, plain) in [("text.rar", "text.txt"), ("video.rar", "video.mkv"), ("textvol", "text.txt")] {
        let plain = std::fs::read(dir.join(plain)).unwrap();
        let (packed, size, dict) =
            if archive == "textvol" { joined() } else { member(&std::fs::read(dir.join(archive)).unwrap()) };
        assert_eq!(size as usize, plain.len());
        let window = window_for(dict, Some(size), false).unwrap();
        for hole in [100_000usize, 400_000, 900_000] {
            let after = &packed[hole + 30_000..];
            // A narrow estimate from the packing ratio (64 KiB either side), as a caller would make it.
            let est = ((hole + 30_000) as u64 * size) / packed.len() as u64;
            let expected = est.saturating_sub(64 << 10)..(est + (64 << 10)).min(size);
            let r = resync(after, 0, &plain, window, expected).unwrap();
            eprintln!(
                "hole {hole}: restart at packed +{} output {} verified {:?} complete {}",
                r.packed_offset, r.output_offset, r.verified, r.complete
            );
            let mut u = Unpacker::resume_at(window, &r, 0, &plain, Some(size)).unwrap();
            let mut out = Collect(Vec::new());
            u.feed(&after[r.packed_offset..], &mut out).unwrap();
            u.finish(&mut out).unwrap();
            assert_eq!(out.0, plain[r.output_offset as usize..], "hole {hole}");
        }
    }
}

/// Text-like data that compresses: literals, matches and repeats over a 128 KiB window.
fn sample(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 64);
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    while out.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        if x.is_multiple_of(7) {
            out.extend((0..40).map(|i| (x >> (i % 8)) as u8));
        } else {
            out.extend_from_slice(format!("word{} of line {} again ", x % 300, x % 50).as_bytes());
        }
    }
    out.truncate(len);
    out
}

fn decode(window: zipfast::rar5::unpack::Window, packed: &[u8], size: u64) -> Vec<u8> {
    let mut u = Unpacker::new(window).unwrap();
    u.reset(Some(size));
    let mut out = Collect(Vec::new());
    u.feed(packed, &mut out).unwrap();
    u.finish(&mut out).unwrap();
    out.0
}

/// A stream made by the test encoder (every block with its own tables) loses packed bytes at several places;
/// decoding restarts after each hole and produces the rest exactly, having learned the last distances and length.
#[test]
fn decoding_restarts_after_a_hole_with_the_state_learned_from_the_plaintext() {
    use zipfast::rar5::testenc;
    let plain = sample(600_000);
    let packed = testenc::tuned_stream(&testenc::lz(&plain, 1 << 17, 16), 2_000);
    let window = window_for(128 << 10, Some(plain.len() as u64), false).unwrap();
    assert_eq!(decode(window, &packed, plain.len() as u64), plain, "the encoder's stream decodes");
    for hole in [5_000usize, packed.len() / 3, packed.len() / 2] {
        let after = &packed[hole + 1_000..];
        let r = resync(after, 0, &plain, window, 0..plain.len() as u64).unwrap();
        assert!(r.complete, "hole {hole}");
        assert!(r.verified.end == r.output_offset && r.verified.start < r.output_offset, "{:?}", r.verified);
        let mut u = Unpacker::resume_at(window, &r, 0, &plain, Some(plain.len() as u64)).unwrap();
        let mut out = Collect(Vec::new());
        u.feed(&after[r.packed_offset..], &mut out).unwrap();
        u.finish(&mut out).unwrap();
        assert_eq!(out.0, plain[r.output_offset as usize..], "hole {hole}");
    }
}

/// Plaintext that differs from what the blocks decode to (another file) finds no restart point; a known plaintext
/// given only from an offset still works when it covers the window before the restart.
#[test]
fn the_restart_point_must_decode_to_the_known_plaintext() {
    use zipfast::rar5::testenc;
    let plain = sample(300_000);
    let packed = testenc::tuned_stream(&testenc::lz(&plain, 1 << 17, 16), 2_000);
    let window = window_for(128 << 10, Some(plain.len() as u64), false).unwrap();
    let after = &packed[packed.len() / 2..];
    let other: Vec<u8> = plain.iter().map(|b| b ^ 0x20).collect();
    assert!(resync(after, 0, &other, window, 0..plain.len() as u64).is_err());
    // Only the plaintext from 10,000 on is given: it still covers the 128 KiB window before the restart.
    let base = 10_000u64;
    let r = resync(after, base, &plain[base as usize..], window, base..plain.len() as u64).unwrap();
    let mut u = Unpacker::resume_at(window, &r, base, &plain[base as usize..], Some(plain.len() as u64)).unwrap();
    let mut out = Collect(Vec::new());
    u.feed(&after[r.packed_offset..], &mut out).unwrap();
    u.finish(&mut out).unwrap();
    assert_eq!(out.0, plain[r.output_offset as usize..]);
}

/// A block after the hole that starts a filter, once its literals have pinned its offset, is reported with its packed
/// and output offsets: its output differs from the plaintext until the filter runs.
#[test]
fn a_filter_after_the_hole_is_reported() {
    use zipfast::rar5::testenc::{self, Op};
    let plain = sample(200_000);
    let mut ops = testenc::lz(&plain[..150_000], 1 << 17, 16);
    let first = testenc::tuned_block(&ops, false).len();
    let split = ops.len();
    // The second block: 64 literals, then the filter, then the rest as literals.
    ops.extend(plain[150_000..150_064].iter().map(|&b| Op::Lit(b)));
    ops.push(Op::Filter { start: 0, len: 1_000, kind: 0, channels: 1 });
    ops.extend(plain[150_064..].iter().map(|&b| Op::Lit(b)));
    let packed = testenc::tuned_stream(&ops, split);
    let window = window_for(128 << 10, Some(plain.len() as u64), false).unwrap();
    let r = resync(&packed[first..], 0, &plain, window, 140_000..160_000);
    assert_eq!(r.unwrap_err(), ResyncError::Filter { packed_offset: 0, output_offset: 150_000 });
}

/// Repeated content: the hole falls in the second of two copies of a stretch longer than the window, so a block in
/// it decodes to the plaintext at both copies. The restart is refused until `expected` says which.
#[test]
fn a_block_that_fits_two_places_is_ambiguous() {
    use zipfast::rar5::testenc;
    let a = sample(60_000);
    let b: Vec<u8> = sample(400_000).iter().map(|x| x.rotate_left(3)).collect();
    let c = sample(30_000);
    let plain = [a.as_slice(), &b, &b, &c].concat();
    let packed = testenc::tuned_stream(&testenc::lz(&plain, 1 << 17, 16), 2_000);
    let window = window_for(128 << 10, Some(plain.len() as u64), false).unwrap();
    // A hole well inside the second copy: more than a window past its start, so nothing it reads back from leaves it.
    let hole = packed.len() * 7 / 10;
    let after = &packed[hole..];
    assert_eq!(resync(after, 0, &plain, window, 0..plain.len() as u64).unwrap_err(), ResyncError::Ambiguous);
    let second = (60_000 + 400_000) as u64..plain.len() as u64;
    let r = resync(after, 0, &plain, window, second).unwrap();
    let mut u = Unpacker::resume_at(window, &r, 0, &plain, Some(plain.len() as u64)).unwrap();
    let mut out = Collect(Vec::new());
    u.feed(&after[r.packed_offset..], &mut out).unwrap();
    u.finish(&mut out).unwrap();
    assert_eq!(out.0, plain[r.output_offset as usize..]);
}

#[test]
fn crc32_combine_joins_a_prefix_and_a_resumed_part() {
    let data = sample(10_000);
    let (a, b) = data.split_at(3_333);
    let joined = zipfast::crc32::combine(zipfast::crc32::hash(a), zipfast::crc32::hash(b), b.len() as u64);
    assert_eq!(joined, zipfast::crc32::hash(&data));
}

/// Plaintext that ends soon after the hole still gives a restart: the blocks it covers are checked, and decoding
/// restarts at the first one past it with what they taught (possibly not the whole state).
#[test]
fn plaintext_that_ends_soon_after_the_hole_still_restarts() {
    use zipfast::rar5::testenc;
    let plain = sample(600_000);
    let packed = testenc::tuned_stream(&testenc::lz(&plain, 1 << 17, 16), 2_000);
    let window = window_for(128 << 10, Some(plain.len() as u64), false).unwrap();
    let after = &packed[packed.len() / 2..];
    let full = resync(after, 0, &plain, window, 0..plain.len() as u64).unwrap();
    // Only up to 60,000 bytes past the first block found (about one block more).
    let known = &plain[..(full.verified.start + 60_000) as usize];
    let r = resync(after, 0, known, window, 0..known.len() as u64).unwrap();
    assert_eq!(r.verified.start, full.verified.start);
    assert!(r.output_offset <= known.len() as u64 + 70_000, "{r:?}");
    let mut u = Unpacker::resume_at(window, &r, 0, known, Some(plain.len() as u64)).unwrap();
    let mut out = Collect(Vec::new());
    u.feed(&after[r.packed_offset..], &mut out).unwrap();
    if r.complete {
        u.finish(&mut out).unwrap();
        assert_eq!(out.0, plain[r.output_offset as usize..]);
    }
}

/// A block that the known plaintext ends inside teaches nothing: restarting at it with the state its first tokens
/// would have set would apply them twice. Block A sets three distances; block B's first match sets the fourth and a
/// later repeat uses the oldest. With the plaintext ending inside B, the restart at B must decode B right.
#[test]
fn a_block_cut_by_the_end_of_the_plaintext_leaves_the_state_alone() {
    use zipfast::rar5::testenc::{self, Op};
    let lits = |n: usize, seed: u8| (0..n).map(move |i| Op::Lit(seed.wrapping_add((i * 37) as u8)));
    let p: Vec<Op> = lits(200, 1).collect();
    let a: Vec<Op> = lits(32, 90).chain([Op::Match(4, 1), Op::Match(4, 2), Op::Match(4, 3)]).collect();
    let b: Vec<Op> =
        [Op::Match(4, 5)].into_iter().chain(lits(20, 170)).chain([Op::Rep(3, 4)]).chain(lits(40, 30)).collect();
    let blocks = [testenc::tuned_block(&p, false), testenc::tuned_block(&a, false), testenc::tuned_block(&b, true)];
    let packed = blocks.concat();
    let window = window_for(128 << 10, None, false).unwrap();
    let plain = decode_unsized(window, &packed);
    let b_start = 200 + 32 + 12;
    let after = &packed[blocks[0].len()..];
    let r = resync(after, 0, &plain[..b_start + 9], window, 200..201).unwrap();
    assert_eq!(r.output_offset, b_start as u64, "{r:?}");
    let mut u = Unpacker::resume_at(window, &r, 0, &plain, None).unwrap();
    let mut out = Collect(Vec::new());
    u.feed(&after[r.packed_offset..], &mut out).unwrap();
    u.finish(&mut out).unwrap();
    assert_eq!(out.0, plain[b_start..]);
}

fn decode_unsized(window: zipfast::rar5::unpack::Window, packed: &[u8]) -> Vec<u8> {
    let mut u = Unpacker::new(window).unwrap();
    u.reset(None);
    let mut out = Collect(Vec::new());
    u.feed(packed, &mut out).unwrap();
    u.finish(&mut out).unwrap();
    out.0
}

/// Megabytes of junk before the first block (a hole answered with garbage, or false block headers claiming large
/// payloads) do not use up the work budget: only bytes actually decoded count.
#[test]
fn junk_before_the_first_block_does_not_exhaust_the_budget() {
    use zipfast::rar5::testenc;
    let plain = sample(300_000);
    let packed = testenc::tuned_stream(&testenc::lz(&plain, 1 << 17, 16), 2_000);
    let window = window_for(128 << 10, Some(plain.len() as u64), false).unwrap();
    let mut x = 0x2545_F491_4F6C_DD1Du64;
    let mut input: Vec<u8> = (0..2_000_000)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect();
    let junk = input.len();
    input.extend_from_slice(&packed[packed.len() / 2..]);
    let r = resync(&input, 0, &plain, window, 0..plain.len() as u64).unwrap();
    assert!(r.packed_offset > junk);
    let mut u = Unpacker::resume_at(window, &r, 0, &plain, Some(plain.len() as u64)).unwrap();
    let mut out = Collect(Vec::new());
    u.feed(&input[r.packed_offset..], &mut out).unwrap();
    u.finish(&mut out).unwrap();
    assert_eq!(out.0, plain[r.output_offset as usize..]);
}
