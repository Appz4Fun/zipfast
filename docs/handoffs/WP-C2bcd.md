# WP-C2b/c/d RAR5 build, window literal writes, fixed per-run cost

Status: merging (docs-only: nothing measurable to gain)
Branch: rar5-decode-speed. Worktree: /Users/allen/git.xbmc4lyfe/zipfast-c2. PR: see GitHub.

## Method
Archives made on the server with rar 7.23 (`zipfast-handoffs/c2-gen-archives.sh`): tree (cargo sources, ~219 MB, 17k files),
text (155 MB), video-like (300 MB skewed random bytes, ~6 bits entropy so the Huffman path runs), mixed (all three, 688 MB),
each at -m3 and -m5 (-ma5 -mt1). Bench: `zipfast-handoffs/c2-bench.sh <bin>`: `t -q -mt1`, best of 5 wall.
Files: ~/zf-bench-data (Mac), ~/zf-bench/c2 (server). The big archives were deleted afterwards.

## Throughput (unpacked MB/s, best of 5; -m3 and -m5 equal within 1%, so one number)
| archive | M4 s | M4 MB/s | i7 s | i7 MB/s |
|---|---|---|---|---|
| mixed 688 MB | 1.345 | 512 | 2.37 | 291 |
| text 155 MB | 0.148 | 1043 | 0.299 | 519 |
| tree 219 MB | 0.320 | 684 | 0.555 | 394 |
| video 314 MB | 0.924 | 340 | 1.546 | 203 |

## Profile (M4, `sample`, decode thread only; perf is blocked on the server)
| function | video_m3 | mixed_m5 | tree_m3 |
|---|---|---|---|
| `Unpacker::decode_rest` (Huffman decode, LZ copy, `put_from` literal writes, all inlined) | 94% | 96% | ~97% |
| `Huff::build` | 3.4% | 2.0% | below sample floor |
| `read_lengths` | 2.0% | - | - |
| crc32 | - | 1.7% | - |
| memcpy / munmap / memset / thread spawn | not visible | not visible | not visible |
Fixed per-run cost: `t -mt1` on a one-file 6-byte archive takes 1.87 ms vs 1.22 ms for `/usr/bin/true`, so 0.65 ms.

## Decisions
- C2b: `Huff::build` is already incremental (tracks the dirty range of the LUT, specialised `fill::<N>` loops, counts once).
  Its whole share is 2 to 3.4%; even a free build would be at the edge of the 1% noise floor. Not changed.
- C2c: literals already go through `put_from`, which for runs up to 32 bytes is two 16-byte word stores (no memcpy call);
  `Win::write` is only the long/wrapping fallback. A literal-straight-into-window decoder would be an invasive change to the
  resync/spill invariants for no visible share. Not changed.
- C2d: 0.65 ms fixed cost against runs of 25 ms and up; nothing to reuse. Not changed.
- The M5 profile of the earlier plan (Build 10.9% on Coffee Lake F03) is not reproducible on the M4 with larger data; the
  i7 could not be profiled (perf blocked), only timed.

## Next
Remaining speed is inside `decode_rest` (Huffman decode + match copy). A line-level profile on the i7 (needs perf or
VTune access) would be the prerequisite for any further work; nothing in the build/window/fixed-cost parts is worth a PR.
