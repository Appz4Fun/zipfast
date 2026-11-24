# TODO bugs: waves 3 to 7 (2026-11-24)

Codex review findings on PRs merged in waves 3 to 7 of `docs/implementation-plan.md`, all merged before review.
Three fix groups run in parallel, split by file so they never collide. Each item gets a test that fails without
its fix; then reply on its thread naming the fix PR, and resolve the thread.
Clean PRs (no findings): #262, #264, #267, #271, #272, #273. #269: review pending (added to group Z when it arrives).

## Group X: tar writer and tar extraction (src/tar/write.rs, src/tar.rs). Branch bugs-tar.

| # | PR | Thread | Where | Sev | Status |
|---|---|---|---|---|---|
| X1 | #261 | PRRT_kwDOVi_ME867Tjpf | src/tar/write.rs:430 | P2 | fixed (bugs-tar) |
| X2 | #261 | PRRT_kwDOVi_ME867Tjpp | src/tar/write.rs:582 | P2 | fixed (bugs-tar) |
| X3 | #261 | PRRT_kwDOVi_ME867Tjpy | src/tar/write.rs:205 | P2 | fixed (bugs-tar) |
| X4 | #268 | PRRT_kwDOVi_ME867U_2O | src/tar/write.rs:653 | P1 | fixed (bugs-tar) |
| X5 | #270 | PRRT_kwDOVi_ME867Vpgb | src/tar.rs:1792 | P2 | fixed (bugs-tar) |

- **X1** Negative fractional pax times: `mtime=-1, nanos=500_000_000` is -0.5 s but is written as `mtime=-1.5`
  (read back as (-2, 500000000)). Emit the normalized signed decimal (-0.5). Test: round trip of pre-epoch fractional
  times through zipfast's reader; compare with GNU tar's encoding of a -0.5 s mtime if possible.
- **X2** Eight-byte base-256 fields (uid, gid, devmajor/devminor): setting `field[0] = 0x80` overwrites the top value
  byte; `uid = 1 << 56` writes UID 0. Keep representable high bits with the marker, refuse values that don't fit.
  Test: uid 1<<56 and the largest representable value round-trip; a value too large is refused.
- **X3** `append` fails on `io::ErrorKind::Interrupted` from the reader after the header is written. Retry
  Interrupted like `src/tar.rs::read_full`. Test: a reader that returns Interrupted once.
- **X4 (P1)** Sparse: a non-final data segment whose length is not a multiple of 512 is accepted, but the writer
  concatenates segments without the per-segment block padding GNU tar expects, so GNU tar 1.35 extraction reads the
  next member's header as data ("Skipping to next header"). Example: size 8192, segments [(0,100),(4096,100)], then a
  regular member. Determine GNU's layout for unaligned middle segments by experiment in docker (GNU tar 1.35 with a
  sparse file whose segments are unaligned; on tmpfs segments are 4096-aligned, so build the archive with
  `--sparse` from a file on a filesystem with smaller blocks, or craft it by hand and check with `tar -tvf`/`-xf`).
  Implement GNU's layout (with stored-size accounting) or refuse such layouts before writing any header. Test with
  GNU tar extraction in docker (both gnu and pax 1.0 formats).
- **X5** Compressed-tar staged publication (`StagedTar::publish`, src/tar.rs ~1805) still calls `replace(temporary,
  &place.path)`, which rejects every symlink: with `Overwrite::Always`, a .tar.gz with a symlink then a regular file of
  the same name now aborts extraction and drops the remaining staged members (before #270 it reported the member and
  continued). Use the identity-aware replacement (`replace_over` with `place.link`) as on the 7z route. Test: that
  case on a compressed tar.

## Group Y: extraction runs and RAR volumes (src/extract.rs, src/volume.rs). Branch bugs-extract.

| # | PR | Thread | Where | Sev | Status |
|---|---|---|---|---|---|
| Y1 | #266 | PRRT_kwDOVi_ME867UlDM | src/extract.rs:797 | P1 | PR open (cleanroom review) |
| Y2 | #266 | PRRT_kwDOVi_ME867UlDU | src/extract.rs:819 | P2 | PR open (cleanroom review) |
| Y3 | #266 | PRRT_kwDOVi_ME867UlDY | src/extract.rs:819 | P2 | PR open (cleanroom review) |
| Y4 | #275 | PRRT_kwDOVi_ME867WvWO | src/extract.rs:3608 | P2 | PR open (cleanroom review) |
| Y5 | #275 | PRRT_kwDOVi_ME867WvWY | src/volume.rs:79 | P2 | PR open (cleanroom review) |

- **Y1 (P1)** Multithreaded whole-archive RAR runs: `StartDecision::RenameTo` redirecting member `a` to `b` leaves
  the pending-output bookkeeping (`batch_paths`/`queued_paths` in `start_file`) keyed by `a`, so a later member `b`
  skips the drain that serializes conflicting writes; both get non-replacing placements and the second creation
  becomes `Outcome::Fatal` in src/batch.rs, aborting the run even under `Overwrite::Always`. Key the collision checks by
  the hook-selected destination before placement and worker submission. Test: 4 threads, small batched members,
  rename `a`->`b` then a member `b`, under Always and Skip.
- **Y2** Rename paths like `a//b` or `a/./b` pass validation, but the raw PathBuf goes to `place_target`, and
  `Extracted::record` asserts a normalized spelling (src/extract/link.rs:309-310): debug-build panic. Normalize the
  accepted path (rebuild from its normal components). Test: both spellings land at `a/b`, no panic.
- **Y3** Rename names with an embedded NUL are accepted and then fail in the filesystem with InvalidInput, which is
  a terminal output fault that stops the run. Reject NUL in any component as `UnsafePath` (member-local). Test.
- **Y4** Restart from a later volume changes ordinal meaning: `Options::select` by `MemberRef::ordinal` refers to
  `list` positions for the given volume (which start at that volume and omit orphan continuations), but the restarted
  run counts from the earlier volume, so ordinal 0 on multi.part2.rar selects file1.txt instead of file3.txt. Map the
  listing's identities onto the restarted run (or do not restart when a selection is given; prefer mapping). Test with
  multi.part2.rar.
- **Y5** `previous_volume` for unpadded sets: the predecessor of `set.part10.rar` is formatted `set.part09.rar`,
  but the file is `set.part9.rar`. Try the narrower width when the padded name is absent (mirror `next_volume`'s width
  growth). Test: part1..part10 unpadded, start at part10, restart works.

## Group Z: LZMA2 feed and ZIP rewrite (src/map/feed/lzma2.rs, src/zip/rewrite/**). Branch bugs-feed-rewrite.

| # | PR | Thread | Where | Sev | Status |
|---|---|---|---|---|---|
| Z1 | #265 | PRRT_kwDOVi_ME867UXRe | src/map/feed/lzma2.rs:570 | P2 | fixed (PR pending) |
| Z2 | #274 | PRRT_kwDOVi_ME867Wqp0 | src/zip/rewrite/native/rename.rs:221 | P2 | fixed (PR pending) |
| Z3+ | #269 | (pending) | src/map/feed/zip.rs | | #269 reviewed: no findings |

- **Z1** Snapshot reconstruction sets `base` to None when the main lane and all repairs advanced to seeded
  checkpoints, so the dictionary-reset fallback is lost; restoring with a sink that keeps the member's output but not
  earlier members then fails with `FeedError::HeldOutput`. Serialize the dictionary-reset fallback independently of the
  active checkpoints. Test: snapshot in that state, restore with a sink lacking `read_earlier`, repair completes.
- **Z2** Rename rebuilds local and central records without charging `limits.common.plan_capacity` or updating
  `usage.common.plan.capacity` (also the ordinal-indexed `result` allocation and temporary record buffers). Charge them
  before reserving. Test: large extras/comments with a tight plan_capacity fail with the limit error; usage reports the
  retained capacity.

## Follow-ups noted by cleanroom reviews (not yet fixed)
- **F1 (from #277 review, non-blocking):** in a restarted later-volume RAR run with an ordinal selection, if `members_before`
  returns None (an earlier volume becomes unreadable partway), `run.members_before` becomes `u64::MAX` and the
  selection silently selects nothing. Fall back to a run without restart, or report the error.
