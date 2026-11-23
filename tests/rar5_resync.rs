//! Restarting the RAR 5.0 decoder after a hole in a compressed member (`zipfast::rar5::unpack::resync`).

use zipfast::rar5::unpack::{NearError, NearOptions, ResyncError, Sink, Unpacker, resync, resync_near, window_for};

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

// ---- resync_near: restarting as close as possible before a target, for a handover ----

fn near(
    packed: &[u8],
    known: &[u8],
    window: zipfast::rar5::unpack::Window,
    target: u64,
    guard: bool,
) -> zipfast::rar5::unpack::ResyncNear {
    let options = NearOptions { estimate: Some(packed.len() / 2), guard, ..Default::default() };
    resync_near(packed, 0, known, window, target, &options).unwrap()
}

fn resumed(
    window: zipfast::rar5::unpack::Window,
    r: &zipfast::rar5::unpack::Resync,
    member_start: u64,
    known: &[u8],
    size: u64,
    packed: &[u8],
) -> Vec<u8> {
    let mut u = Unpacker::resume_in_stream(window, r, member_start, 0, known, Some(size)).unwrap();
    let mut out = Collect(Vec::new());
    u.feed(&packed[r.packed_offset..], &mut out).unwrap();
    u.finish(&mut out).unwrap();
    out.0
}

/// The plaintext ends at the target, as a handover's does: the restart is the last block start at or before it,
/// found from an estimate far off, and the decoder resumed there produces the rest exactly.
#[test]
fn resync_near_restarts_at_the_last_block_before_the_target() {
    use zipfast::rar5::testenc;
    let plain = sample(400_000);
    let packed = testenc::tuned_stream(&testenc::lz(&plain, 1 << 17, 16), 2_000);
    let window = window_for(1 << 20, Some(plain.len() as u64), false).unwrap();
    let target = 333_333u64;
    let n = near(&packed, &plain[..target as usize], window, target, false);
    assert!(n.resync.output_offset <= target && n.back == target - n.resync.output_offset, "{n:?}");
    assert!(n.back < 40_000, "within a block of the target: {n:?}");
    assert!(n.anchor < n.resync.output_offset && n.resync.verified.end == n.resync.output_offset);
    assert_eq!(
        resumed(window, &n.resync, 0, &plain, plain.len() as u64, &packed),
        plain[n.resync.output_offset as usize..]
    );
    // A target exactly at that block start, or one byte past it, restarts there too.
    let block = n.resync.output_offset;
    for (t, back) in [(block, 0), (block + 1, 1)] {
        let m = near(&packed, &plain[..t as usize], window, t, false);
        assert_eq!((m.resync.output_offset, m.back), (block, back));
    }
}

#[test]
fn resync_near_reports_a_spent_budget() {
    use zipfast::rar5::testenc;
    let plain = sample(400_000);
    let packed = testenc::tuned_stream(&testenc::lz(&plain, 1 << 17, 16), 2_000);
    let window = window_for(1 << 20, Some(plain.len() as u64), false).unwrap();
    let options = NearOptions { estimate: Some(packed.len()), work: 1_000, guard: false, ..Default::default() };
    match resync_near(&packed, 0, &plain[..300_000], window, 300_000, &options) {
        Err(NearError::Exhausted { lowest }) => assert!(lowest < packed.len()),
        other => panic!("{other:?}"),
    }
    // Plaintext that is not this member's: nothing pins.
    let other: Vec<u8> = sample(500_000).iter().map(|b| b ^ 0x5a).collect();
    let options = NearOptions { guard: false, ..Default::default() };
    let r = resync_near(&packed, 0, &other[100_000..400_000], window, 300_000, &options);
    assert!(matches!(r, Err(NearError::NotFound { lowest: 0 })), "{r:?}");
}

/// A filter before the target is decoded past: the restart lies after its output, and the decoder resumed there
/// copies from it exactly, although its window holds that output unfiltered and the plaintext holds it filtered.
#[test]
fn resync_near_decodes_past_a_filter_and_undoes_it_in_the_window() {
    use zipfast::rar5::testenc::{self, Op};
    let mut plain = sample(500_000);
    for x in plain.iter_mut().filter(|x| **x == 0xe8) {
        *x = 0xe9;
    }
    for at in (60_000..140_000).step_by(499) {
        plain[at..at + 5].copy_from_slice(&[0xe8, (at % 251) as u8, 0x10, 0, 0]);
    }
    let mut ops = testenc::lz(&plain[..50_000], 1 << 17, 16);
    ops.push(Op::Filter { start: 0, len: 100_000, kind: 1, channels: 0 });
    ops.extend(testenc::lz(&plain[50_000..390_000], 1 << 17, 16));
    // A copy from the filtered output, after the restart.
    ops.push(Op::Match(2_000, 390_000 - 70_000));
    ops.extend(testenc::lz(&plain[392_000..], 1 << 17, 16));
    let packed = testenc::tuned_stream(&ops, 2_000);
    let window = window_for(1 << 20, Some(plain.len() as u64), false).unwrap();
    let truth = decode(window, &packed, plain.len() as u64);
    assert_ne!(truth[70_000..72_000], plain[70_000..72_000], "the filter changes its output");
    assert_eq!(truth[390_000..392_000], plain[70_000..72_000], "the copy reads the window's unfiltered bytes");
    let target = 385_000u64;
    // From the stream's start, so the blocks followed include the filter's.
    let options = NearOptions { estimate: Some(0), guard: false, ..Default::default() };
    let n = resync_near(&packed, 0, &truth[..target as usize], window, target, &options).unwrap();
    assert!(n.anchor < 50_000 && n.resync.output_offset > 150_000, "decoded past the filter: {n:?}");
    // The whole plaintext is given, so the known-plaintext check runs over the copy too.
    assert_eq!(
        resumed(window, &n.resync, 0, &truth, truth.len() as u64, &packed),
        truth[n.resync.output_offset as usize..]
    );
}

/// A target in a solid stream's second member, in stream offsets: the restart resumes with the member's start.
#[test]
fn resync_near_finds_a_restart_in_a_solid_second_member() {
    use zipfast::rar5::testenc;
    let a = sample(100_000);
    let b = sample(300_000).into_iter().rev().collect::<Vec<u8>>();
    // The second member's own blocks: its copies stay within it, and the first member is only window.
    let second = testenc::tuned_stream(&testenc::lz(&b, 1 << 17, 16), 2_000);
    let window = window_for(1 << 20, Some((a.len() + b.len()) as u64), true).unwrap();
    let stream = [a.as_slice(), b.as_slice()].concat();
    let start = a.len() as u64;
    let target = start + 250_000;
    let n = near(&second, &stream[..target as usize], window, target, false);
    assert!(n.resync.output_offset > start && n.back < 40_000, "{n:?}");
    let out = resumed(window, &n.resync, start, &stream, b.len() as u64, &second);
    assert_eq!(out, b[(n.resync.output_offset - start) as usize..]);
}

/// Ops for `len` bytes of output: unique literal runs (which pin blocks) between copies at varying distances (which
/// teach the decoder's state).
fn spread(len: usize) -> Vec<zipfast::rar5::testenc::Op> {
    use zipfast::rar5::testenc::Op;
    let (mut ops, mut out, mut x) = (Vec::new(), 0usize, 0x2545_F491_4F6C_DD1Du64);
    while out < len {
        for _ in 0..48 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            ops.push(Op::Lit(x as u8));
        }
        out += 48;
        if out > 70_000 {
            let dist = 1_000 + (x >> 20) % 60_000;
            ops.push(Op::Match(1_500, dist));
            out += 1_500;
        }
    }
    ops
}

/// The handover case: a guarded restart (checked from 4 MiB before it) resumes with the plaintext only up to the
/// target, with no known plaintext past it.
#[test]
fn a_guarded_resync_near_resumes_without_plaintext_past_the_target() {
    use zipfast::rar5::testenc;
    let ops = spread(5_200_000);
    let plain = testenc::model(&ops);
    let packed = testenc::tuned_stream(&ops, 4_000);
    let window = window_for(1 << 20, Some(plain.len() as u64), false).unwrap();
    let target = 5_000_000u64;
    let known = &plain[..target as usize];
    let n = near(&packed, known, window, target, true);
    assert!(n.resync.guarded() && n.back < 200_000, "{n:?}");
    assert!(n.anchor + (4 << 20) <= n.resync.output_offset);
    assert_eq!(
        resumed(window, &n.resync, 0, known, plain.len() as u64, &packed),
        plain[n.resync.output_offset as usize..]
    );
    // Within 4 MiB of the plaintext's start the follow starts at the member's start, before which no filter can be
    // declared: that restart resumes with plaintext only up to the target too.
    let early = &plain[..1_000_000];
    let e = near(&packed, early, window, 1_000_000, true);
    assert!(e.anchor == 0 && e.window_checked && e.back < 200_000, "{e:?}");
    assert_eq!(
        resumed(window, &e.resync, 0, early, plain.len() as u64, &packed),
        plain[e.resync.output_offset as usize..]
    );
    // Without the member's first blocks such a restart is not guarded: it needs plaintext past it.
    let cut = &packed[packed.len() / 40..];
    let options = NearOptions { estimate: Some(cut.len() / 10), ..Default::default() };
    let e = resync_near(cut, 0, early, window, 1_000_000, &options).unwrap();
    assert!(!e.resync.guarded() && !e.window_checked && e.anchor > 0, "{e:?}");
    assert!(Unpacker::resume_in_stream(window, &e.resync, 0, 0, early, Some(plain.len() as u64)).is_err());
}

/// RustyGet's z-fixtures (set ZIPFAST_Z_FIXTURES to the sets directory): a handover at several targets of the
/// RAR 5.0 sets restarts within a block of the target, guarded, resumes exactly with the plaintext only up to the
/// target, and (in release builds) takes well under a second.
#[test]
fn resync_near_on_the_z_fixtures() {
    use zipfast::crypto::{decrypt_cbc, derive_rar5_key};
    use zipfast::map::{CipherParams, MemberMap};
    let Some(dir) = std::env::var_os("ZIPFAST_Z_FIXTURES").map(std::path::PathBuf::from) else {
        eprintln!("skipped: set ZIPFAST_Z_FIXTURES to the z-fixtures sets directory");
        return;
    };
    let manifest = String::from_utf8(std::fs::read(dir.join("MANIFEST.json")).unwrap()).unwrap();
    let at = manifest.find("\"password\"").unwrap();
    let password = manifest[at..].split('"').nth(3).unwrap().to_owned();
    for (set, payload, max_back) in [
        ("F03_rar5_m3_video", "cabac.mkv", 64u64 << 10),
        ("F05_rar5_m5_mixed", "mixed.mkv", 8 << 20),
        ("F06_rar5_m3_mixed_hp", "mixed.mkv", 8 << 20),
    ] {
        let plain = std::fs::read(dir.join(payload)).unwrap();
        let set_dir = dir.join(set);
        let mut names: Vec<String> = std::fs::read_dir(&set_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.ends_with(".rar"))
            .collect();
        names.sort();
        let vols: Vec<Vec<u8>> = names.iter().map(|n| std::fs::read(set_dir.join(n)).unwrap()).collect();
        let refs: Vec<&[u8]> = vols.iter().map(Vec::as_slice).collect();
        let map = MemberMap::from_memory(&refs, &names[0], Some(&password)).unwrap();
        let m = map.members.iter().find(|m| m.unpacked_size == Some(plain.len() as u64)).unwrap();
        let mut packed: Vec<u8> = m
            .pieces
            .iter()
            .flat_map(|p| vols[p.volume as usize][p.packed.start as usize..p.packed.end as usize].to_vec())
            .collect();
        if let Some(CipherParams::Rar5 { kdf_count, salt, iv: Some(iv), check, .. }) = m.cipher.clone() {
            let key = derive_rar5_key(&password, kdf_count, &salt, check).unwrap();
            packed = decrypt_cbc(&key, &iv, &packed[..packed.len() / 16 * 16]).unwrap();
        }
        let size = plain.len() as u64;
        let window = window_for(m.dictionary.unwrap(), Some(size), false).unwrap();
        let ratio = size as f64 / packed.len() as f64;
        for (target, estimate) in [5_000_000u64, 12_000_000, 20_000_000, 25_000_000]
            .into_iter()
            .map(|t| (t, Some((t as f64 / ratio) as usize)))
            .chain([(20_000_000, None)])
        {
            let known = &plain[..target as usize];
            let options = NearOptions { estimate, ..Default::default() };
            let n = resync_near(&packed, 0, known, window, target, &options)
                .unwrap_or_else(|e| panic!("{set} target {target}: {e}"));
            eprintln!(
                "{set} target {target} (estimate {estimate:?}): restart {} ({} back), anchor {}, {} ms",
                n.resync.output_offset,
                n.back,
                n.anchor,
                n.elapsed.as_millis()
            );
            assert!(n.resync.guarded() && n.back <= max_back, "{set} target {target}: {n:?}");
            if !cfg!(debug_assertions) {
                assert!(n.elapsed < std::time::Duration::from_secs(1), "{set} target {target}: {:?}", n.elapsed);
            }
            assert_eq!(
                resumed(window, &n.resync, 0, known, size, &packed),
                plain[n.resync.output_offset as usize..],
                "{set} {target}"
            );
        }
    }
}

/// A stream with a 16 MiB dictionary: an E8 filter's output at about 2 MiB, then 9 MiB more, then (at
/// `before_copy`) a 3,000-byte copy from inside the filter's output, starting at a call's opcode. Returns the packed
/// stream, its decoded output, the window, the filter's start and `before_copy`.
fn unseen_filter_stream() -> (Vec<u8>, Vec<u8>, zipfast::rar5::unpack::Window, u64, u64) {
    use zipfast::rar5::testenc::{self, Op};
    let mut ops = spread(2 << 20);
    let filter_at = testenc::model(&ops).len() as u64;
    ops.push(Op::Filter { start: 0, len: 20_000, kind: 1, channels: 0 });
    // Calls whose operands the E8 filter rewrites.
    for k in 0..4_000u32 {
        ops.extend([0xe8, (k % 251) as u8, 0x10, 0, 0].map(Op::Lit));
    }
    ops.extend(spread(9 << 20));
    let before_copy = testenc::model(&ops).len() as u64;
    ops.push(Op::Match(3_000, before_copy - (filter_at + 10_000)));
    ops.extend(spread(200_000));
    let packed = testenc::tuned_stream(&ops, 4_000);
    let unfiltered = testenc::model(&ops);
    let window = window_for(16 << 20, Some(unfiltered.len() as u64), false).unwrap();
    let truth = decode(window, &packed, unfiltered.len() as u64);
    let (lo, hi) = (filter_at as usize + 10_000, filter_at as usize + 13_000);
    assert_eq!(
        truth[before_copy as usize..before_copy as usize + 3_000],
        unfiltered[lo..hi],
        "the copy reads unfiltered bytes"
    );
    assert_ne!(truth[lo..hi], unfiltered[lo..hi], "which the filter changed in the output");
    assert_eq!(truth[lo], 0xe8, "the copy starts at a call's opcode, which the filter leaves");
    (packed, truth, window, filter_at, before_copy)
}

/// Resumes `resync_near` at `target` from packed bytes that start at about 4 MiB of output (the member's first
/// blocks and the filter's are not given), with the plaintext only up to the target. Returns the result and the
/// restart's output offset.
fn resume_past_unseen_filter(
    packed: &[u8],
    truth: &[u8],
    window: zipfast::rar5::unpack::Window,
    filter_at: u64,
    target: u64,
) -> (zipfast::Result<()>, Vec<u8>, u64) {
    let cut = packed.len() * 4 / 11;
    let known = &truth[..target as usize];
    let options = NearOptions { estimate: Some((packed.len() - cut) * 6 / 10), ..Default::default() };
    let n = resync_near(&packed[cut..], 0, known, window, target, &options).unwrap();
    assert!(n.resync.guarded() && !n.window_checked, "{n:?}");
    assert!(n.anchor > filter_at + 20_000, "the filter is before the anchor: {n:?}");
    let mut u = Unpacker::resume_in_stream(window, &n.resync, 0, 0, known, Some(truth.len() as u64)).unwrap();
    let mut out = Collect(Vec::new());
    let result = u.feed(&packed[cut + n.resync.packed_offset..], &mut out).and_then(|()| u.finish(&mut out));
    (result, out.0, n.resync.output_offset)
}

/// A dictionary over 4 MiB: a filter's output lies before the anchor (unseen by the follow) but inside the restart's
/// match window, and a copy after the target reads it. The resumed decoder must refuse that copy rather than write
/// the filtered bytes where the window held them unfiltered.
#[test]
fn a_resumed_decoder_refuses_a_copy_from_output_an_unseen_filter_changed() {
    let (packed, truth, window, filter_at, before_copy) = unseen_filter_stream();
    let (result, out, restart) = resume_past_unseen_filter(&packed, &truth, window, filter_at, before_copy - 50_000);
    let err = result.expect_err("a copy from output an unseen filter changed must not pass").to_string();
    assert!(err.contains("before the window checked"), "{err}");
    let good = (before_copy - restart) as usize;
    assert!(out.len() <= good && out == truth[restart as usize..][..out.len()], "no wrong byte reached the sink");
}

/// The same copy starting one byte before the target: its first byte (the call's opcode, which the filter leaves)
/// is the only one known plaintext checks, and the rest would land past the target unchecked. Refused too.
#[test]
fn a_resumed_decoder_refuses_such_a_copy_across_the_end_of_the_known_plaintext() {
    let (packed, truth, window, filter_at, before_copy) = unseen_filter_stream();
    let (result, out, restart) = resume_past_unseen_filter(&packed, &truth, window, filter_at, before_copy + 1);
    let err = result.expect_err("a copy straddling the end of the known plaintext must not pass").to_string();
    assert!(err.contains("before the window checked"), "{err}");
    let good = (before_copy - restart) as usize;
    assert!(out.len() <= good && out == truth[restart as usize..][..out.len()], "no wrong byte reached the sink");
}

/// Blocks inside output a filter declared before the packed bytes given changed: their literals are not in the
/// plaintext, though they lie before the target. The search goes on past them to a block that pins.
#[test]
fn resync_near_searches_on_past_blocks_inside_filtered_output() {
    use zipfast::rar5::testenc::{self, Op};
    let mut ops = testenc::lz(&sample(20_000), 1 << 17, 16);
    ops.push(Op::Filter { start: 0, len: 300_000, kind: 0, channels: 3 });
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    for _ in 0..300_000 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        ops.push(Op::Lit(x as u8));
    }
    let tail: Vec<u8> = sample(200_000).into_iter().rev().collect();
    ops.extend(testenc::lz(&tail, 1 << 17, 16));
    let packed = testenc::tuned_stream(&ops, 500);
    let size = testenc::model(&ops).len() as u64;
    let window = window_for(1 << 20, Some(size), false).unwrap();
    let truth = decode(window, &packed, size);
    // From inside the filtered output: the filter's block is not given.
    let cut = packed.len() / 10;
    let target = size - 20_000;
    let options = NearOptions { estimate: Some(0), guard: false, ..Default::default() };
    let n = resync_near(&packed[cut..], 0, &truth[..target as usize], window, target, &options).unwrap();
    assert!(n.anchor >= 320_000 && n.back < 40_000, "pinned past the filtered output: {n:?}");
    assert_eq!(resumed(window, &n.resync, 0, &truth, size, &packed[cut..]), truth[n.resync.output_offset as usize..]);
}

/// More than a step's share of blocks that cannot pin, right at the estimate: the rest of the interval is still
/// searched, and a later block pins.
#[test]
fn resync_near_searches_past_many_unpinnable_blocks() {
    use zipfast::rar5::testenc::{self, Op};
    let pattern = b"abcdefghijklmnop";
    let mut ops: Vec<Op> = (0..70 * 500).map(|i| Op::Lit(pattern[i % 16])).collect();
    let tail = sample(200_000);
    ops.extend(testenc::lz(&tail, 1 << 17, 16));
    let packed = testenc::tuned_stream(&ops, 500);
    let plain = testenc::model(&ops);
    let window = window_for(1 << 20, Some(plain.len() as u64), false).unwrap();
    let target = plain.len() as u64 - 20_000;
    let options = NearOptions { estimate: Some(0), guard: false, ..Default::default() };
    let n = resync_near(&packed, 0, &plain[..target as usize], window, target, &options).unwrap();
    assert!(n.resync.output_offset <= target && n.back < 40_000, "{n:?}");
    assert_eq!(
        resumed(window, &n.resync, 0, &plain, plain.len() as u64, &packed),
        plain[n.resync.output_offset as usize..]
    );
}

/// A deadline that passes while the follow decodes a long way is honoured: no result is given after it.
#[test]
fn resync_near_gives_no_result_after_its_deadline() {
    use zipfast::rar5::testenc::{self, Op};
    let mut ops = testenc::lz(&sample(100_000), 1 << 17, 16);
    for _ in 0..10_000 {
        ops.push(Op::Lit(b'A'));
        ops.push(Op::Match(4_000, 1));
    }
    let tail: Vec<u8> = sample(100_000).into_iter().rev().collect();
    ops.extend(testenc::lz(&tail, 1 << 17, 16));
    let packed = testenc::tuned_stream(&ops, 2_000);
    let plain = testenc::model(&ops);
    let window = window_for(1 << 20, Some(plain.len() as u64), false).unwrap();
    let target = plain.len() as u64 - 20_000;
    let known = &plain[..target as usize];
    let options = NearOptions { estimate: Some(0), guard: false, ..Default::default() };
    let n = resync_near(&packed, 0, known, window, target, &options).unwrap();
    assert!(n.anchor < 100_000, "the follow covers the long run: {n:?}");
    let options = NearOptions { estimate: Some(0), guard: false, deadline: Some(n.elapsed / 8), ..Default::default() };
    let late = resync_near(&packed, 0, known, window, target, &options);
    assert!(matches!(late, Err(NearError::Exhausted { .. })), "{late:?}");
}

/// A solid stream: the first member has an E8 filter near its end, and the second copies from that filtered output
/// after the target. Resumed from the second member's start, the follow saw none of the first member's filters, so
/// the copy (which the decoder makes from the unfiltered window) must be refused rather than written from the
/// filtered plaintext.
#[test]
fn a_later_solid_member_resumed_from_its_start_refuses_a_copy_from_an_earlier_members_filtered_output() {
    use zipfast::rar5::testenc::{self, Op};
    let mut ops_a = testenc::lz(&sample(200_000), 1 << 17, 16);
    let filter_at = testenc::model(&ops_a).len() as u64;
    ops_a.push(Op::Filter { start: 0, len: 20_000, kind: 1, channels: 0 });
    for k in 0..4_000u32 {
        ops_a.extend([0xe8, (k % 251) as u8, 0x10, 0, 0].map(Op::Lit));
    }
    ops_a.extend(testenc::lz(&sample(300_000)[250_000..], 1 << 17, 16));
    let a_len = testenc::model(&ops_a).len() as u64;
    let b_head: Vec<u8> = sample(150_000).into_iter().rev().collect();
    let mut ops_b = testenc::lz(&b_head, 1 << 17, 16);
    let copy_at = a_len + b_head.len() as u64;
    // A copy from the first member's filtered output, starting at a call's opcode.
    ops_b.push(Op::Match(3_000, copy_at - (filter_at + 10_000)));
    ops_b.extend(testenc::lz(&sample(400_000)[300_000..], 1 << 17, 16));
    let first = testenc::tuned_stream(&ops_a, 2_000);
    let second = testenc::tuned_stream(&ops_b, 2_000);
    let window = window_for(1 << 20, Some(1 << 20), true).unwrap();
    // The stream's output: the first member, then the second.
    let mut u = Unpacker::new(window).unwrap();
    u.reset(Some(a_len));
    let mut out = Collect(Vec::new());
    u.feed(&first, &mut out).unwrap();
    u.finish(&mut out).unwrap();
    // (The second member's copy reaches into the first, so its length is counted, not modelled.)
    let b_len = b_head.len() as u64 + 3_000 + 100_000;
    u.next_file(Some(b_len));
    u.feed(&second, &mut out).unwrap();
    u.finish(&mut out).unwrap();
    let stream = out.0;
    let (lo, at) = ((filter_at + 10_000) as usize, copy_at as usize);
    assert_ne!(stream[at..at + 3_000], stream[lo..lo + 3_000], "the copy reads the window's unfiltered bytes");
    assert_eq!(stream[lo], 0xe8);
    // Resumed from the second member's start (estimate 0 on its packed bytes), the target just before the copy.
    let target = copy_at - 20_000;
    let known = &stream[..target as usize];
    let options = NearOptions { estimate: Some(0), guard: false, ..Default::default() };
    let n = resync_near(&second, 0, known, window, target, &options).unwrap();
    assert_eq!(n.anchor, a_len, "followed from the second member's start: {n:?}");
    let mut u = Unpacker::resume_in_stream(window, &n.resync, a_len, 0, known, Some(b_len)).unwrap();
    let mut out = Collect(Vec::new());
    let result = u.feed(&second[n.resync.packed_offset..], &mut out).and_then(|()| u.finish(&mut out));
    let err = result.expect_err("a copy from an earlier member's filtered output must not pass").to_string();
    assert!(err.contains("before the window checked"), "{err}");
    let good = (copy_at - n.resync.output_offset) as usize;
    assert!(out.0.len() <= good && out.0 == stream[n.resync.output_offset as usize..][..out.0.len()]);
}

/// The search had the whole plaintext, but the decoder is resumed with only a suffix of it that starts inside a
/// filter's output the window still holds: that filter cannot be undone, so resuming is refused, saying what
/// plaintext it needs, rather than leaving filtered bytes in the window for a later copy to read.
#[test]
fn resuming_without_the_plaintext_to_undo_a_retained_filter_is_refused() {
    use zipfast::rar5::testenc::{self, Op};
    let mut plain = sample(500_000);
    for x in plain.iter_mut().filter(|x| **x == 0xe8) {
        *x = 0xe9;
    }
    for at in (60_000..140_000).step_by(499) {
        plain[at..at + 5].copy_from_slice(&[0xe8, (at % 251) as u8, 0x10, 0, 0]);
    }
    let mut ops = testenc::lz(&plain[..50_000], 1 << 17, 16);
    ops.push(Op::Filter { start: 0, len: 100_000, kind: 1, channels: 0 });
    ops.extend(testenc::lz(&plain[50_000..], 1 << 17, 16));
    let packed = testenc::tuned_stream(&ops, 2_000);
    let window = window_for(1 << 20, Some(plain.len() as u64), false).unwrap();
    let truth = decode(window, &packed, plain.len() as u64);
    let target = 385_000u64;
    let options = NearOptions { estimate: Some(0), guard: false, ..Default::default() };
    let n = resync_near(&packed, 0, &truth[..target as usize], window, target, &options).unwrap();
    assert!(n.anchor == 0 && n.resync.output_offset > 150_000, "{n:?}");
    // The whole plaintext resumes exactly.
    assert_eq!(
        resumed(window, &n.resync, 0, &truth, truth.len() as u64, &packed),
        truth[n.resync.output_offset as usize..]
    );
    // A suffix from inside the filter's output (still within the window) does not.
    let base = 100_000usize;
    let err = Unpacker::resume_in_stream(window, &n.resync, 0, base as u64, &truth[base..], Some(truth.len() as u64))
        .err()
        .expect("the filter's output before the plaintext cannot be undone")
        .to_string();
    assert!(err.contains("to undo a filter") && err.contains("50000.."), "{err}");
    // A suffix that starts after the filter's output resumes (its window holds no part of it).
    let after = 160_000usize;
    if n.resync.output_offset > after as u64 {
        assert!(
            Unpacker::resume_in_stream(window, &n.resync, 0, after as u64, &truth[after..], Some(truth.len() as u64))
                .is_ok()
        );
    }
}

/// Checks a `resync_near` result on the unseen-filter stream: a restart must resume to the stream's exact output
/// (given the whole plaintext) up to `before_copy`, where the stream copies from output of a filter the follow did
/// not see (the resumed decoder may stop there); anything else must be a typed `NotFound` or `Exhausted`.
fn assert_restart_or_typed_failure(
    packed: &[u8],
    truth: &[u8],
    window: zipfast::rar5::unpack::Window,
    before_copy: u64,
    result: Result<zipfast::rar5::unpack::ResyncNear, NearError>,
    what: &str,
) {
    match result {
        Ok(n) => {
            let r = &n.resync;
            let mut u = Unpacker::resume_in_stream(window, r, 0, 0, truth, Some(truth.len() as u64))
                .unwrap_or_else(|e| panic!("{what}: resume: {e} ({n:?})"));
            let mut out = Collect(Vec::new());
            let result = u.feed(&packed[r.packed_offset..], &mut out).and_then(|()| u.finish(&mut out));
            let rest = &truth[r.output_offset as usize..];
            assert!(
                out.0.len() <= rest.len() && out.0 == rest[..out.0.len()],
                "{what}: restart at {} decodes wrong",
                r.output_offset
            );
            // The only error a right restart may stop with: the known-plaintext check (or the floor) at the copy.
            if let Err(e) = result {
                let msg = e.to_string();
                let at = msg
                    .split("output offset ")
                    .nth(1)
                    .and_then(|t| t.split(' ').next())
                    .and_then(|t| t.parse::<u64>().ok());
                let at_copy = at.is_some_and(|at| at >= before_copy) || msg.contains("before the window checked");
                assert!(
                    at_copy && r.output_offset < before_copy,
                    "{what}: a wrong restart at {}: {msg}",
                    r.output_offset
                );
            }
        }
        Err(NearError::NotFound { .. } | NearError::Exhausted { .. }) => {}
    }
}

/// Packed bytes from past the target repeat plaintext from before it (each `spread` starts with the same bytes).
/// With the known plaintext starting just after the filter, those bytes occur in it only once, so a block from past
/// the target pinned there, and its blocks matched the repeat until the packed bytes ran out, short of the target.
/// A true anchor's blocks reach the target: that follow is refused, and the true restart found.
#[test]
fn resync_near_refuses_a_pin_in_content_that_repeats_past_the_target() {
    let (packed, truth, window, filter_at, before_copy) = unseen_filter_stream();
    let target = before_copy - 50_000;
    let cut = packed.len() * 8 / 11;
    let estimate = (target as u128 * packed.len() as u128 / truth.len() as u128) as usize - cut;
    let options = NearOptions { estimate: Some(estimate), guard: false, ..Default::default() };
    let mut restarts = Vec::new();
    for known_base in [0, filter_at + 20_000, target - (6 << 20)] {
        let known = &truth[known_base as usize..target as usize];
        let n = resync_near(&packed[cut..], known_base, known, window, target, &options).unwrap();
        assert!(n.resync.output_offset <= target && n.back < 1 << 20, "base {known_base}: {n:?}");
        restarts.push((n.resync.packed_offset, n.resync.output_offset));
        assert_restart_or_typed_failure(
            &packed[cut..],
            &truth,
            window,
            before_copy,
            Ok(n),
            &format!("base {known_base}"),
        );
    }
    assert!(restarts.windows(2).all(|w| w[0] == w[1]), "every base finds the same restart: {restarts:?}");
}

/// The same stream with the known plaintext starting at many offsets: every result is a correct restart or a typed
/// failure, never a wrong pin.
#[test]
fn resync_near_never_pins_wrong_whatever_the_plaintext_start() {
    let (packed, truth, window, filter_at, before_copy) = unseen_filter_stream();
    let target = before_copy - 50_000;
    let cut = packed.len() * 8 / 11;
    let estimate = (target as u128 * packed.len() as u128 / truth.len() as u128) as usize - cut;
    let mut bases: Vec<u64> = (0..6).map(|i| i * (target - (1 << 20)) / 6).collect();
    bases.extend([
        filter_at,
        filter_at + 1,
        filter_at + 10_000,
        filter_at + 20_000,
        filter_at + 20_001,
        filter_at + 70_000,
    ]);
    bases.extend([target - (3 << 20), target - (1 << 20), target - 100_000]);
    for (i, &known_base) in bases.iter().enumerate() {
        let known = &truth[known_base as usize..target as usize];
        let guard = i % 2 == 0;
        let options = NearOptions { estimate: Some(estimate), guard, ..Default::default() };
        let result = resync_near(&packed[cut..], known_base, known, window, target, &options);
        assert_restart_or_typed_failure(
            &packed[cut..],
            &truth,
            window,
            before_copy,
            result,
            &format!("base {known_base} guard {guard}"),
        );
    }
// ---- Seeding the window from held plaintext (Unpacker::resume_seeded) ----

/// The unseen-filter stream resumed `back` bytes before its copy, seeded from the plaintext before that target, from
/// packed bytes that start well after the filter (as a handover that fetches only near the target holds them).
struct Seeded {
    result: zipfast::Result<()>,
    out: Vec<u8>,
    truth: Vec<u8>,
    restart: u64,
    before_copy: u64,
    decoder: Unpacker,
}

fn resume_seeded_past_unseen_filter(strict: bool, back: u64) -> Seeded {
    let (packed, truth, window, filter_at, before_copy) = unseen_filter_stream();
    let target = before_copy - back;
    // packed bytes from well after the filter, early enough for a guarded restart (followed from 4 MiB before it)
    let cut = packed.len() * 5 / 11;
    let known = &truth[..target as usize];
    let estimate = (target as u128 * packed.len() as u128 / truth.len() as u128) as usize - cut;
    let options = NearOptions { estimate: Some(estimate), ..Default::default() };
    let n = resync_near(&packed[cut..], 0, known, window, target, &options).unwrap();
    assert!(n.anchor > filter_at + 20_000 && !n.window_checked, "the follow never saw the filter: {n:?}");
    assert!(n.resync.guarded(), "{n:?}");
    let mut decoder =
        Unpacker::resume_seeded(window, &n.resync, 0, 0, known, Some(truth.len() as u64), strict).unwrap();
    assert_eq!(decoder.seed_checked(), Some(false), "the window is not proven");
    let mut out = Collect(Vec::new());
    let result =
        decoder.feed(&packed[cut + n.resync.packed_offset..], &mut out).and_then(|()| decoder.finish(&mut out));
    Seeded { result, out: out.0, truth, restart: n.resync.output_offset, before_copy, decoder }
}

/// A seeded decoder past a filter it never saw: the copy from the filtered output writes wrong bytes, but decoding
/// goes on to the end, the suspect is noted where the copy is, and the output is flagged unverified, for the
/// member's checksum to decide.
#[test]
fn a_seeded_decoder_notes_a_copy_from_output_an_unseen_filter_changed() {
    use zipfast::rar5::unpack::SeedReason;
    let s = resume_seeded_past_unseen_filter(false, 50_000);
    s.result.expect("a seeded decoder goes on");
    let from = s.restart as usize;
    assert_eq!(s.out.len(), s.truth.len() - from, "the whole rest of the member came out");
    let at = s.before_copy as usize - from;
    assert_ne!(s.out[at..at + 3_000], s.truth[s.before_copy as usize..][..3_000], "the copy came out wrong");
    let suspect = s.decoder.seed_suspect().expect("the copy is noted");
    assert!(matches!(suspect.reason, SeedReason::UncheckedCopy { .. }), "{suspect:?}");
    assert!(suspect.at <= s.before_copy, "noted at or before the wrong bytes: {suspect:?}");
}

/// The same with `strict`: the suspect copy is refused, as a checked decoder refuses it, before a wrong byte reaches
/// the sink.
#[test]
fn a_strict_seeded_decoder_refuses_that_copy() {
    let s = resume_seeded_past_unseen_filter(true, 50_000);
    let err = s.result.expect_err("strict refuses the copy").to_string();
    assert!(err.contains("before the window checked"), "{err}");
    let good = (s.before_copy - s.restart) as usize;
    assert!(
        s.out.len() <= good && s.out == s.truth[s.restart as usize..][..s.out.len()],
        "no wrong byte reached the sink"
    );
}

/// Filter-free content: a decoder seeded from the plaintext before the target, from packed bytes near it only,
/// decodes the rest exactly; copies from before the follow may still be noted (they cannot be told apart from
/// unfiltered ones without the earlier packed bytes), and the output stays flagged unverified.
#[test]
fn a_seeded_decoder_on_filter_free_content_is_exact() {
    use zipfast::rar5::testenc;
    let ops = spread(12 << 20);
    let packed = testenc::tuned_stream(&ops, 4_000);
    let plain = testenc::model(&ops);
    let window = window_for(16 << 20, Some(plain.len() as u64), false).unwrap();
    let target = plain.len() as u64 * 3 / 4;
    let cut = packed.len() / 3;
    let known = &plain[..target as usize];
    let estimate = (target as u128 * packed.len() as u128 / plain.len() as u128) as usize - cut;
    let options = NearOptions { estimate: Some(estimate), ..Default::default() };
    let n = resync_near(&packed[cut..], 0, known, window, target, &options).unwrap();
    assert!(target - n.resync.output_offset < 1 << 20, "the restart is near the target: {n:?}");
    let mut u = Unpacker::resume_seeded(window, &n.resync, 0, 0, known, Some(plain.len() as u64), false).unwrap();
    let mut out = Collect(Vec::new());
    u.feed(&packed[cut + n.resync.packed_offset..], &mut out).unwrap();
    u.finish(&mut out).unwrap();
    assert_eq!(out.0, plain[n.resync.output_offset as usize..], "exact");
    assert_eq!(u.seed_checked(), Some(false));
}

/// A seeded decoder whose held plaintext starts after the window's start notes a copy from before it (bytes never
/// seeded) as `BeforeSeed`.
#[test]
fn a_seeded_decoder_notes_a_copy_from_before_the_held_plaintext() {
    use zipfast::rar5::unpack::SeedReason;
    let (packed, truth, window, filter_at, before_copy) = unseen_filter_stream();
    let target = before_copy - 50_000;
    // held plaintext only from 6 MiB before the target: the copy's source (in the filter's output) was never seeded
    let known_base = target - (6 << 20);
    assert!(known_base > filter_at + 20_000);
    let known = &truth[known_base as usize..target as usize];
    let cut = packed.len() * 5 / 11;
    let estimate = (target as u128 * packed.len() as u128 / truth.len() as u128) as usize - cut;
    let options = NearOptions { estimate: Some(estimate), ..Default::default() };
    let n = resync_near(&packed[cut..], known_base, known, window, target, &options).unwrap();
    let mut u =
        Unpacker::resume_seeded(window, &n.resync, 0, known_base, known, Some(truth.len() as u64), false).unwrap();
    let mut out = Collect(Vec::new());
    u.feed(&packed[cut + n.resync.packed_offset..], &mut out).unwrap();
    u.finish(&mut out).unwrap();
    let suspect = u.seed_suspect().expect("noted");
    assert!(matches!(suspect.reason, SeedReason::BeforeSeed { source } if source < known_base), "{suspect:?}");
}

/// A plain `resync` result proves nothing about the window (its floor of 0 is no proof) and is never guarded: a
/// decoder seeded from it is unverified, notes the unguarded restart at once, and with `strict` is refused, so an
/// unseen filter covering output after the restart cannot pass as checked.
#[test]
fn a_decoder_seeded_from_a_plain_resync_is_unverified_and_strict_refuses_it() {
    use zipfast::rar5::testenc::{self, Op};
    use zipfast::rar5::unpack::SeedReason;
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
    let truth = decode(window, &packed, plain.len() as u64);
    // lose exactly the block holding the filter record, and restart inside the filter's output
    let chunks: Vec<&[Op]> = ops.chunks(PER).collect();
    let block = at / PER;
    let start: usize = chunks[..block].iter().map(|c| testenc::tuned_block(c, false).len()).sum();
    let end = start + testenc::tuned_block(chunks[block], false).len();
    let after = &packed[end..];
    let r = resync(after, 0, &truth, window, 0..truth.len() as u64).unwrap();
    assert!(r.output_offset < 250_000 && !r.guarded(), "{r:?}");
    // held plaintext up to the restart only, as a seeded handover holds it
    let known = &truth[..r.output_offset as usize];
    let mut u = Unpacker::resume_seeded(window, &r, 0, 0, known, Some(truth.len() as u64), false).unwrap();
    assert_eq!(u.seed_checked(), Some(false), "a plain resync proves no window");
    assert!(u.seed_suspects().iter().any(|s| s.reason == SeedReason::Unguarded), "{:?}", u.seed_suspects());
    let mut out = Collect(Vec::new());
    u.feed(&after[r.packed_offset..], &mut out).and_then(|()| u.finish(&mut out)).unwrap();
    assert_ne!(out.0, truth[r.output_offset as usize..], "the unseen filter's output came out unfiltered");
    let strict = Unpacker::resume_seeded(window, &r, 0, 0, known, Some(truth.len() as u64), true);
    assert!(matches!(strict, Err(zipfast::Error::Unsupported(_))), "strict refuses an unguarded restart");
}
