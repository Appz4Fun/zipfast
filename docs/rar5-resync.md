# Restarting RAR 5.0 decoding after a hole

A RAR 5.0 compressed member is a series of byte-aligned blocks, and rar writes each with its own Huffman tables (about 16 KB of output per block for video). When packed bytes of such a member are lost, but another copy of the file supplies the plaintext, `zipfast::rar5::unpack::resync` finds where decoding can restart after the hole. `Unpacker::resume_at` then decodes the rest of the member from the recipient's own packed bytes:

```rust
use zipfast::rar5::unpack::{resync, Unpacker, window_for};
let window = window_for(dictionary, Some(size), false)?;
let r = resync(&packed_after_hole, known_base, &known_plaintext, window, expected_offsets)?;
let mut u = Unpacker::resume_at(window, &r, known_base, &known_plaintext, Some(size))?;
u.feed(&packed_after_hole[r.packed_offset..], &mut sink)?;
u.finish(&mut sink)?;
```

## How it finds the restart

1. **Find a block.** It scans the packed bytes after the hole for a block header whose checksum holds and whose tables and symbols decode to the block's end. A block that reuses the previous block's tables can't be the first, because the hole erased them.
2. **Find its output offset.** It decodes that block without a window, then searches the known plaintext within `expected` for one of the block's literal runs: the first of at least 8 bytes, or failing that 4, that fits no more than 64 places. That gives the candidate offsets. At each candidate, every literal and every copy must reproduce the plaintext.
   - **When a block is passed:** either its literals can't pin it (it has no such run among its first 16, or they fit too many places), or every candidate contradicts the plaintext. The block is skipped, and the expected range moves on by its output (widened for operations of unknown length), so `expected` keeps describing where the next block starts.
   - **Limits:** the scan stops after 256 blocks. One call also has a work budget of about a second of comparisons and probed bytes, and runs out with `ResyncError::Exhausted`. Long runs of one byte, or literals that recur everywhere, make each check costly.
   - **Partial checks:** each block is checked on a copy of the learned state, and only a block checked to its end changes it.
3. **Recover the erased state.** The hole erased the decoder's state: the four last match distances and the last length.
   - **While checking:** a repeat that uses an erased distance takes the one distance, up to 4 MiB back, whose copy reproduces the plaintext.
   - **For the restart:** such an inferred distance is never trusted. The state counts as known only once matches in the blocks read have set all four distances, plus the last length.
4. **Read ahead until the state is known.** Each block read is checked the same way. Decoding restarts at the block after the last one read.
   - **`Resync::verified`:** the output those read-ahead blocks decoded to, proven equal to the plaintext.
   - **`complete`:** false when the packed bytes, the known plaintext or the 256-block budget ran out first. In that case decoding restarts at the first block past what was checked. Decoding still restarts. A later match that uses an unknown distance fails (as a distance of 0) or decodes wrong, and the member's size or CRC catches it.
5. **Rule out other offsets.** Every candidate offset is followed through the read-ahead, and exactly one must hold. Content that repeats beyond the window can fit two places; that gives `ResyncError::Ambiguous`.

## Inputs

- **`packed`:** the member's packed bytes after the hole, across volumes and in order.
- **`known_base`, `known`:** the known plaintext, at member output offsets `known_base..`. It must cover at least the first block after the hole and, for the window, as far back as the member's dictionary reaches (or the member's start). The more it covers past the hole, the more blocks can be checked.
- **`window`:** from `window_for(dictionary, size, false)`. The dictionary comes from the file header.
- **`expected`:** where the first block after the hole may start in the output, estimated from the hole's position and the packing ratio. A ±64 KiB estimate works on rar's output. Keep it as narrow as the estimate allows: the scan costs time in proportion to its width, and a wide range over content that repeats can make a block fit twice (`Ambiguous`).

## Output and errors

- **`resume_at`:** gives a decoder that writes the member's output from `Resync::output_offset` on. The CRC32 it hands a sink covers only that output. Combine it with the CRC of the plaintext before it, using `zipfast::crc32::combine(prefix_crc, resumed_crc, resumed_len)`, and check the result against the member's CRC.
- **`ResyncError::NotFound`:** no block decodes to the plaintext in the range. Either the plaintext or the range is wrong, or a filter that started before the hole covers the output.
- **`ResyncError::Filter { packed_offset, output_offset }`:** a block after the hole starts a filter (E8, ARM or delta) once its offset is pinned. `packed_offset` and `output_offset` are where that block starts. Its output differs from the plaintext until the filter runs, so look again from packed bytes after the filtered output. Filters are for executables and rarely occur in video.
- **`ResyncError::Ambiguous`:** a block fits the plaintext at more than one offset. Narrow `expected`.
- **`ResyncError::Exhausted`:** the work budget ran out first. Narrow `expected`, or look again from later packed bytes.

## Checked against

- **rar 7.30 output (`-ma5 -m3`):**
  - 3 MB of text with a 128 KiB dictionary;
  - 4 MB of video-like data, which rar compressed by 0.3%, so the blocks are mostly literals.
  - the text again, split into 400 KB volumes, with the parts' data areas joined.

  Holes at three places in each restart and decode the rest exactly. The test reads those sets when present (`ZIPFAST_RAR5_RESYNC_SETS`).
- **Committed tests:**
  - the test encoder's streams restart after holes, from full or partial plaintext;
  - wrong plaintext finds nothing;
  - a filter after the hole is reported with its offsets;
  - repeated content is `Ambiguous` until `expected` is narrowed.

RAR 4.x is not covered.
