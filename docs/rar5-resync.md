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
   - **Limits:** the scan stops after 256 blocks. One call also has a work budget of about a second of comparisons and decoded bytes. Running out, even in the middle of checking a candidate, gives `ResyncError::Exhausted`, never a guess. Long runs of one byte, or literals that recur everywhere, make each check costly. Junk before the first block costs little: a false header is charged only once its tables decode, and only for bytes that are there.
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
- **`expected`:** where the first block after the hole may start in the output, estimated from the hole's position and the packing ratio. A ±64 KiB estimate works on rar's output (about 50-90 ms per call on video). Keep it as narrow as the estimate allows: the scan costs time in proportion to its width, and a wide range over content that repeats can make a block fit twice (`Ambiguous`). Over repetitive text or binaries a wide range spends the work budget (`Exhausted`) call after call: RustyGet measured 12 retries and 20 s for a 1.5 MB hole with a wide range, restarting about 20 MB of output later. Estimate the restart from the packed position (hole end × unpacked size / packed size) and keep ±64 KiB around it; after `Exhausted`, move the packed start on by a block or two (16 KiB) and the range with it.

## Output and errors

- **`resume_at`:** gives a decoder that writes the member's output from `Resync::output_offset` on. The CRC32 it hands a sink covers only that output. Combine it with the CRC of the plaintext before it, using `zipfast::crc32::combine(prefix_crc, resumed_crc, resumed_len)`, and check the result against the member's CRC.
  - **Solid streams:** `Unpacker::resume_in_stream(window, &r, member_start, known_base, &known, size)` resumes a
    member that starts at stream offset `member_start` of a solid stream, such as a solid archive's second file.
    Every offset is then a stream offset (the known plaintext may reach back into earlier members, as matches do),
    `size` is the member's own size, and filters are addressed from the member's start, as RAR does per file.
    `resume_at` is this with `member_start` 0; using it inside a later solid member decodes E8/E8E9/ARM-filtered
    output wrongly (the known-plaintext window below catches that within its reach).
  - **Filters the hole erased:** a filter declared in a lost block can cover output after the restart, and the resumed decoder cannot see it. So it checks its output against the known plaintext until it is 4 MiB (a filter's longest length) past the restart, or at the member's end, and reports a difference as `Error::BadChecksum` before the bytes reach the sink. Resync again from packed bytes past that point. `known` must cover that window, or `resume_at` fails; past it no plaintext is needed.
  - **Encrypted members:** the decrypted packed bytes run on past the last block to the AES block end. The resumed decoder stops at the block flagged last and ignores them, as a normal extraction does.
- **`ResyncError::NotFound`:** no block decodes to the plaintext in the range. Either the plaintext or the range is wrong, or a filter that started before the hole covers the output.
- **`ResyncError::Filter { packed_offset, output_offset, output_end }`:** a block after the hole starts a filter (E8, ARM or delta) once its offset is pinned. `packed_offset` and `output_offset` are where that block starts, and `output_end` is where the filter's output ends. Its output differs from the plaintext until the filter runs, so look again with `expected` past `output_end`, from packed bytes after that block. Filters are for executables and rarely occur in video.
- **`ResyncError::Ambiguous`:** a block fits the plaintext at more than one offset. Narrow `expected`.
- **`ResyncError::Exhausted`:** the work budget ran out first. Narrow `expected`, or look again from later packed bytes.

## Restarting near a target (handover)

`resync_near(packed, known_base, &known, window, target, &NearOptions { estimate, work, deadline, guard })` finds
the restart closest before output offset `target`, for a handover from one copy of a member to another: the known
plaintext is what the old copy extracted, so it usually ends at the target.

```rust,ignore
let est = (target as f64 * packed_len as f64 / size as f64) as usize; // or a map's estimate
let n = resync_near(&packed, 0, &known[..target as usize], window, target,
                    &NearOptions { estimate: Some(est), ..Default::default() })?;
// n.back = target - n.resync.output_offset; n.resync.guarded(): resumes with no plaintext past the restart
let mut u = Unpacker::resume_in_stream(window, &n.resync, member_start, 0, &known, Some(size))?;
u.feed(&packed[n.resync.packed_offset..], &mut sink)?;
```

- **How:** starting a little before `estimate` and moving back geometrically (16 KiB, 64 KiB, ... before it), it
  looks for a block whose literals pin it to the plaintext before the target. A few blocks in a row found nowhere
  in it are most likely past the target, so the step moves back. Blocks inside output a filter changed miss too, so
  the rest of such a step is searched after the steps back, as is the rest of a step that tried its share of blocks. From that anchor it decodes forward without a window, checking every block against the plaintext and
  learning the decoder's state. It does not stop when the state is known; it goes on to the last block that starts
  at or before the target and restarts there. So the restart is within one block of the target, whatever packing
  ratio the content between has (rar's ratio varies from 1:1 to over 15:1 inside one mixed member, which makes a
  ratio estimate land megabytes off), and the work grows with the distance searched, not the member's size.
- **Filters:** blocks that start a filter are decoded past. Their output is not compared, since the plaintext
  holds it filtered, and a restart is only placed past every filter seen. The decoder's window holds filtered output
  as it was before the filter ran, so `resume_in_stream` undoes the filters seen (E8, E8E9, ARM, delta) in the
  plaintext it copies into the window. Without that, a match after the restart that copies from filtered output
  decodes wrong.
- **Guarded restarts (`NearOptions::guard`, default true):** a restart checked from a filter's longest length
  (4 MiB) before it is `guarded()`. No filter declared before the anchor can cover output after it, assuming rar
  declares a filter in the block its output starts in, as it does. `resume_in_stream` then needs no plaintext past
  the restart, which a handover does not have. It still checks what plaintext there is. A restart followed from the
  member's start counts as guarded too.
- **The match window (`ResyncNear::window_checked`):** a match after the restart may copy from anywhere in the
  window, up to the dictionary size back. Output a filter changed there must be undone before the decoder copies
  from it, and only filters the follow saw can be undone. So the search first looks for an anchor that covers the
  restart's whole window: the window's reach plus 4 MiB before the target, or the plaintext's start when the window
  reaches back that far. The plaintext's start is a member's start in a handover, where nothing can be declared
  before. Following from there is cheap, since decoding without a window is a byte comparison. Failing that, it
  falls back to a guarded anchor with `window_checked: false`. The resumed decoder then refuses, as
  `Error::BadChecksum`, a match that copies from before the anchor plus 4 MiB and writes any byte where no known
  plaintext checks it (one that starts just before that boundary and runs past it included).
  That is an error, never silently wrong output. Failing that too, it gives the closest restart, which needs
  plaintext past it to resume.
- **Block granularity:** a restart is a block start. One rar block can cover megabytes of very compressible output:
  in `mixed.mkv` (z-fixtures F05/F06) a single block covers output 14.2 MB to 22.0 MB, so every target in it
  restarts at 14.2 MB.
- **Result:** `ResyncNear { resync, back, anchor, searched_from, work, elapsed, window_checked }`.
- **Errors:** `NearError::NotFound { lowest }` means no block pinned before the target from packed offset `lowest`
  on. `NearError::Exhausted { lowest }` means the work budget (default 2^30, about a second) or the deadline ran out.
  The deadline is checked during long literal searches, on every block followed, and before a result is given, so
  no result comes after it.
- **Solid streams:** offsets are in the plaintext's coordinates, the solid stream's for a later member. Resume
  with that member's start (`resume_in_stream`). A follow from a later member's start covers that member only: the
  decoder held earlier members' output unfiltered, and their filters were never seen. So when the window reaches
  before the member's start, the resumed decoder refuses a copy from there into output no known plaintext checks,
  unless the member's start is the stream's start (offset 0).

Measured on z-fixtures (release, one thread, M4; plaintext only up to the target; every restart followed from the
member's start, window checked, guarded and resumed exactly):

| set | target | restart (back) | time |
|---|---|---|---|
| F03 video (-m3) | 5 / 12 / 20 / 25 MB | 13 / 9 / 4.4 / 1.1 KB back | 4 / 10 / 17 / 27 ms |
| F05 mixed (-m5) | 5 / 12 / 20 / 25 MB | 13 KB / 127 KB / 5.75 MB (block) / 11 KB back | 4 / 30 / 61 / 66 ms |
| F06 mixed -hp (-m3) | 5 / 12 / 20 / 25 MB | 13 KB / 127 KB / 5.80 MB (block) / 14 KB back | 4 / 30 / 62 / 65 ms |

Before (`resync` with a packing-ratio estimate at the F06 20 MB target), every width up to the whole member was
`NotFound` or `Exhausted` (22 ms to 1.6 s per call). The estimate (packed 10.78 MB) decodes to output about 22.8 MB,
past the target. Prybar's layered search over `resync` took about 25 s and landed about 4 MB back. The example
`cargo run --release --example resync_near -- <set dir> <password> <plaintext> <target>...` reproduces the table.

## Checked against

- **rar 7.30 output (`-ma5 -m3`):**
  - 3 MB of text with a 128 KiB dictionary;
  - 4 MB of video-like data, which rar compressed by 0.3%, so the blocks are mostly literals.
  - the text again, split into 400 KB volumes, with the parts' data areas joined.

  Holes at three places in each restart and decode the rest exactly. The test reads those sets when present (`ZIPFAST_RAR5_RESYNC_SETS`).
- **Committed tests:**
  - the test encoder's streams restart after holes, from full or partial plaintext;
  - wrong plaintext finds nothing;
  - a filter after the hole is reported with its offsets and its output end;
  - a filter declared in the lost block, covering output after the restart, is an error rather than wrong output;
  - the AES padding after a resumed member's last block is ignored;
  - repeated content is `Ambiguous` until `expected` is narrowed;
  - `resync_near` restarts at the last block before the target (and at a target exactly at or just past a block
    start), reports a spent budget and plaintext that is not the member's, decodes past a filter and undoes it in
    the resumed window (a later copy from the filtered output decodes exactly), finds a restart in a solid second
    member, and a guarded restart resumes with plaintext only up to the target;
  - with a 16 MiB dictionary, a copy after the target from output a filter before the anchor changed is refused by
    the resumed decoder, as is the same copy starting one byte before the end of the known plaintext; more than a
    step's share of unpinnable blocks at the estimate is searched past, as are blocks inside output a delta filter
    declared before the given packed bytes changed; a deadline that passes during a long follow gives `Exhausted`;
    a later solid member resumed from its start refuses a copy, after the target, from an earlier member's filtered
    output;
  - with `ZIPFAST_Z_FIXTURES`, `resync_near` on F03/F05/F06 at several targets (guarded, exact, under 1 s in release).

RAR 4.x is not covered.
