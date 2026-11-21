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
2. **Find its output offset.** It decodes that block without a window, then matches the result against the known plaintext at the offsets in `expected`. The block's first literals pick the candidates, and every literal and every copy must reproduce the plaintext.
3. **Recover the erased state.** The hole erased the decoder's state: the four last match distances and the last length. A repeat that uses an erased distance takes the one distance, up to 4 MiB back, whose copy reproduces the plaintext. The last length comes from the operations that follow.
4. **Read ahead until the state is known.** Each block read is checked the same way. Decoding restarts at the block after the last one read.
   - **`Resync::verified`:** the output those read-ahead blocks decoded to, proven equal to the plaintext.
   - **`complete`:** false when a distance never appeared before the packed bytes ran out. Decoding still restarts; a later match that uses that distance decodes wrong, and the member's CRC catches it.

## Inputs

- **`packed`:** the member's packed bytes after the hole, across volumes and in order.
- **`known_base`, `known`:** the known plaintext, at member output offsets `known_base..`. It must cover the restart block and, for the window, as far back as the member's dictionary reaches (or the member's start).
- **`window`:** from `window_for(dictionary, size, false)`. The dictionary comes from the file header.
- **`expected`:** where the first block after the hole may start in the output, estimated from the hole's position and the packing ratio. A wide range only costs scanning time.

## Output and errors

- **`resume_at`:** gives a decoder that writes the member's output from `Resync::output_offset` on. The CRC32 it hands a sink covers only that output, so combine it with the CRC of the plaintext before it to check the member's CRC.
- **`ResyncError::NotFound`:** no block decodes to the plaintext in the range. Either the plaintext or the range is wrong, or a filter that started before the hole covers the output.
- **`ResyncError::Filter { output_offset }`:** a block after the hole starts a filter (E8, ARM or delta). Its output differs from the plaintext until the filter runs, so look again from packed bytes after it. Filters are for executables and rarely occur in video.

## Checked against

- **rar 7.30 output (`-ma5 -m3`):**
  - 3 MB of text with a 128 KiB dictionary;
  - 4 MB of video-like data, which rar compressed by 0.3%, so the blocks are mostly literals.

  Holes at three places in each restart and decode the rest exactly. The test reads those sets when present (`ZIPFAST_RAR5_RESYNC_SETS`).
- **Committed tests:** the test encoder's streams restart after holes, from full or partial plaintext. Wrong plaintext finds nothing, and a filter after the hole is reported.

RAR 4.x is not covered.
