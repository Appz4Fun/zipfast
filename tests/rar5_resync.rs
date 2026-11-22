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
    assert_eq!(r.unwrap_err(), ResyncError::Filter { packed_offset: 0, output_offset: 150_000, output_end: 151_064 });
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
    // Resuming needs the plaintext past the restart to check it against filters the hole may have erased.
    assert!(Unpacker::resume_at(window, &r, 0, known, Some(plain.len() as u64)).is_err());
    let mut u = Unpacker::resume_at(window, &r, 0, &plain, Some(plain.len() as u64)).unwrap();
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

/// A resumed member's packed bytes run on past its last block to the encryption's block end (CBC padding, up to 15
/// bytes): decoding stops at the block flagged last and ignores them, as a normal extraction trims them.
#[test]
fn a_resumed_member_ignores_the_encryption_padding_after_its_last_block() {
    use zipfast::rar5::testenc;
    let plain = sample(300_000);
    let packed = testenc::tuned_stream(&testenc::lz(&plain, 1 << 17, 16), 2_000);
    let window = window_for(128 << 10, Some(plain.len() as u64), false).unwrap();
    let hole = packed.len() / 2;
    let after = &packed[hole + 1_000..];
    let r = resync(after, 0, &plain, window, 0..plain.len() as u64).unwrap();
    let mut padded = after[r.packed_offset..].to_vec();
    padded.extend_from_slice(&[0xa5; 13]);
    let mut u = Unpacker::resume_at(window, &r, 0, &plain, Some(plain.len() as u64)).unwrap();
    let mut out = Collect(Vec::new());
    u.feed(&padded, &mut out).unwrap();
    u.finish(&mut out).unwrap();
    assert_eq!(out.0, plain[r.output_offset as usize..]);
}

/// A filter declared in the block the hole erased covers output past the restart. The resumed decoder cannot see it
/// and writes that output unfiltered; the check against the known plaintext turns that into an error before the
/// bytes reach the sink. Here an x86 (E8) filter changes 4 bytes 150 KB after the restart, after blocks that match.
#[test]
fn a_filter_declared_in_the_lost_block_is_an_error_after_the_restart() {
    use zipfast::rar5::testenc::{self, Op};
    let mut plain = sample(400_000);
    for b in plain.iter_mut().filter(|b| **b == 0xe8) {
        *b = 0xe9;
    }
    plain[250_000..250_005].copy_from_slice(&[0xe8, 0x10, 0, 0, 0]);
    let mut ops = testenc::lz(&plain[..100_000], 1 << 17, 16);
    let at = ops.len();
    ops.push(Op::Filter { start: 0, len: 200_000, kind: 1, channels: 0 });
    ops.extend(testenc::lz(&plain[100_000..], 1 << 17, 16));
    const PER: usize = 2_000;
    let packed = testenc::tuned_stream(&ops, PER);
    let window = window_for(1 << 20, Some(plain.len() as u64), false).unwrap();
    // What the member decodes to, with the filter applied: the plaintext a donor would supply.
    let truth = decode(window, &packed, plain.len() as u64);
    assert_ne!(truth[250_001..250_005], plain[250_001..250_005], "the filter changes the operand");
    // Lose exactly the block holding the filter record.
    let chunks: Vec<&[Op]> = ops.chunks(PER).collect();
    let block = at / PER;
    let start: usize = chunks[..block].iter().map(|c| testenc::tuned_block(c, false).len()).sum();
    let end = start + testenc::tuned_block(chunks[block], false).len();
    let after = &packed[end..];
    let r = resync(after, 0, &truth, window, 0..truth.len() as u64).unwrap();
    assert!(r.output_offset < 250_000, "the restart is inside the filter, before the changed bytes: {r:?}");
    let mut u = Unpacker::resume_at(window, &r, 0, &truth, Some(truth.len() as u64)).unwrap();
    let mut out = Collect(Vec::new());
    let result = u.feed(&after[r.packed_offset..], &mut out).and_then(|()| u.finish(&mut out));
    let err = result.expect_err("the unfiltered output must not pass").to_string();
    assert!(err.contains("output offset 25000"), "{err}");
    assert!(out.0.len() as u64 + r.output_offset <= 250_001, "no wrong byte reached the sink");
}

/// A resumed file of a solid stream goes on into the next file: after the earlier file's last block (and its AES
/// padding) the decoder takes the next file's blocks with its window and state.
#[test]
fn a_resumed_solid_file_continues_into_the_next() {
    use zipfast::rar5::testenc::{self, Op};
    let plain = sample(300_000);
    let (a, b) = plain.split_at(200_000);
    let first = testenc::tuned_stream(&testenc::lz(a, 1 << 17, 16), 2_000);
    // The second file as literals: its blocks need nothing from the first but the decoder carrying on.
    let second = testenc::tuned_stream(&b.iter().map(|&x| Op::Lit(x)).collect::<Vec<_>>(), 2_000);
    let window = window_for(128 << 10, Some(a.len() as u64), true).unwrap();
    let after = &first[first.len() / 2..];
    let r = resync(after, 0, a, window, 0..a.len() as u64).unwrap();
    let mut u = Unpacker::resume_at(window, &r, 0, a, Some(a.len() as u64)).unwrap();
    let mut out = Collect(Vec::new());
    let padded = |bytes: &[u8]| [bytes, &[0x5a; 11][..]].concat();
    u.feed(&padded(&after[r.packed_offset..]), &mut out).unwrap();
    u.finish(&mut out).unwrap();
    assert_eq!(out.0, a[r.output_offset as usize..]);
    let mut out = Collect(Vec::new());
    u.next_file(Some(b.len() as u64));
    u.feed(&padded(&second), &mut out).unwrap();
    u.finish(&mut out).unwrap();
    assert_eq!(out.0, b, "the next file decodes after the resumed one");
}

/// The same through the workers: a resumed file whose next file is queued (`queue_file`) before the first is done.
#[test]
fn a_resumed_solid_file_continues_into_a_queued_next_file() {
    use zipfast::rar5::testenc::{self, Op};
    let plain = sample(300_000);
    let (a, b) = plain.split_at(200_000);
    let first = testenc::tuned_stream(&testenc::lz(a, 1 << 17, 16), 2_000);
    let second = testenc::tuned_stream(&b.iter().map(|&x| Op::Lit(x)).collect::<Vec<_>>(), 2_000);
    let window = window_for(128 << 10, Some(a.len() as u64), true).unwrap();
    let after = &first[first.len() / 2..];
    let r = resync(after, 0, a, window, 0..a.len() as u64).unwrap();
    let mut u = Unpacker::resume_at(window, &r, 0, a, Some(a.len() as u64)).unwrap();
    u.force_parallel();
    // The files' outputs, split at the empty slice the decoder puts where they meet.
    struct Files(Vec<Vec<u8>>);
    impl Sink for Files {
        fn put(&mut self, bytes: &[u8]) -> zipfast::Result<()> {
            if bytes.is_empty() {
                self.0.push(Vec::new());
            } else {
                self.0.last_mut().unwrap().extend_from_slice(bytes);
            }
            Ok(())
        }
    }
    let mut out = Files(vec![Vec::new()]);
    let padded = |bytes: &[u8]| [bytes, &[0x5a; 11][..]].concat();
    u.feed(&padded(&after[r.packed_offset..]), &mut out).unwrap();
    u.queue_file(Some(b.len() as u64));
    u.feed(&padded(&second), &mut out).unwrap();
    u.finish(&mut out).unwrap();
    assert_eq!(out.0.len(), 2, "two files");
    assert_eq!(out.0[0], a[r.output_offset as usize..]);
    assert_eq!(out.0[1], b, "the queued file decodes after the resumed one");
}

/// A decoder that resumed a member and is then reset for a file of its own decodes it as usual: the resumed
/// member's stop at its last block and its known plaintext do not carry over.
#[test]
fn a_reset_after_a_resume_decodes_ordinarily() {
    use zipfast::rar5::testenc;
    let plain = sample(200_000);
    let packed = testenc::tuned_stream(&testenc::lz(&plain, 1 << 17, 16), 2_000);
    let window = window_for(128 << 10, Some(plain.len() as u64), false).unwrap();
    let after = &packed[packed.len() / 2..];
    let r = resync(after, 0, &plain, window, 0..plain.len() as u64).unwrap();
    let mut u = Unpacker::resume_at(window, &r, 0, &plain, Some(plain.len() as u64)).unwrap();
    let mut out = Collect(Vec::new());
    u.feed(&after[r.packed_offset..], &mut out).unwrap();
    u.finish(&mut out).unwrap();
    // Another member, from its start, then bytes past its last block: the reset decoder treats them as a fresh one
    // does (it does not keep the resumed member's stop at the last block).
    let other = sample(150_000).into_iter().map(|b| b ^ 0x55).collect::<Vec<u8>>();
    let packed2 = [testenc::tuned_stream(&testenc::lz(&other, 1 << 17, 16), 2_000), vec![0x5a; 11]].concat();
    let run = |u: &mut Unpacker| {
        let mut out = Collect(Vec::new());
        let r = u.feed(&packed2, &mut out).and_then(|()| u.finish(&mut out));
        (r.is_ok(), out.0)
    };
    u.reset(Some(other.len() as u64));
    let mut fresh = Unpacker::new(window).unwrap();
    fresh.reset(Some(other.len() as u64));
    let (reset_ok, reset_out) = run(&mut u);
    let (fresh_ok, fresh_out) = run(&mut fresh);
    assert_eq!((reset_ok, reset_out), (fresh_ok, fresh_out));
    assert!(!fresh_ok, "a fresh decoder rejects bytes past the last block");
}

/// A second file of a solid stream resumes with its filters addressed from its own start: an E8 filter after the
/// restart decodes exactly with `resume_in_stream`, while treating the stream as one member from 0 gets the
/// operands wrong and is caught before a wrong byte reaches the sink.
#[test]
fn a_solid_second_member_resumes_with_filters_based_at_its_start() {
    use zipfast::rar5::testenc::{self, Op};
    let a = sample(100_000);
    let mut b = sample(300_000);
    for x in b.iter_mut().filter(|x| **x == 0xe8) {
        *x = 0xe9;
    }
    for at in (160_000..240_000).step_by(997) {
        b[at..at + 5].copy_from_slice(&[0xe8, (at % 251) as u8, 0x10, 0, 0]);
    }
    const PER: usize = 2_000;
    let first = testenc::tuned_stream(&testenc::lz(&a, 1 << 17, 16), PER);
    let mut ops = testenc::lz(&b[..150_000], 1 << 17, 16);
    ops.push(Op::Filter { start: 0, len: 100_000, kind: 1, channels: 0 });
    ops.extend(testenc::lz(&b[150_000..], 1 << 17, 16));
    let second = testenc::tuned_stream(&ops, PER);
    let window = window_for(1 << 20, Some((a.len() + b.len()) as u64), true).unwrap();
    // The solid stream's output: the first file, then the second with its filter applied.
    let mut u = Unpacker::new(window).unwrap();
    u.reset(Some(a.len() as u64));
    let mut out = Collect(Vec::new());
    u.feed(&first, &mut out).unwrap();
    u.finish(&mut out).unwrap();
    u.next_file(Some(b.len() as u64));
    u.feed(&second, &mut out).unwrap();
    u.finish(&mut out).unwrap();
    let stream = out.0;
    assert_eq!(&stream[..a.len()], &a[..]);
    let truth_b = &stream[a.len()..];
    assert_ne!(truth_b[160_001..160_005], b[160_001..160_005], "the filter changes the operands");
    // Lose packed bytes early in the second file, well before the filter's block.
    let after = &second[second.len() / 5..];
    let start = a.len() as u64;
    let r = resync(after, 0, &stream, window, start..stream.len() as u64).unwrap();
    assert!(r.output_offset > start && r.output_offset < start + 150_000, "{r:?}");
    let resumed = |member_start: u64, size: u64| {
        let mut u = Unpacker::resume_in_stream(window, &r, member_start, 0, &stream, Some(size)).unwrap();
        let mut out = Collect(Vec::new());
        let result = u.feed(&after[r.packed_offset..], &mut out).and_then(|()| u.finish(&mut out));
        (result, out.0)
    };
    let (result, out) = resumed(start, b.len() as u64);
    result.unwrap();
    assert_eq!(out, truth_b[(r.output_offset - start) as usize..], "filters are addressed from the member's start");
    // As one member from the stream's start (resume_at's view), the E8 operands come out wrong; the
    // known-plaintext window stops them.
    let (result, out) = resumed(0, stream.len() as u64);
    let err = result.expect_err("a filter based at the stream's start must not pass").to_string();
    assert!(err.contains("differs from the known plaintext"), "{err}");
    assert!(r.output_offset + out.len() as u64 <= start + 160_001, "no wrong byte reached the sink");
    // A member start past the restart is refused.
    assert!(Unpacker::resume_in_stream(window, &r, r.output_offset + 1, 0, &stream, Some(b.len() as u64)).is_err());
}
