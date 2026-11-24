# TODO bugs: round 2 (2026-11-24)

Late Codex findings that arrived after the earlier sweeps, on already-merged PRs. Two fix groups split by file.
Each item: a test that fails without its fix; reply on the thread naming the fix PR; resolve the thread.

## Group R1: tar writer, 7z placeholder, ZIP listing budget, test isolation. Branch bugs-round2-a.

| # | PR | Thread | Where | Sev | Status |
|---|---|---|---|---|---|
| A1 | #276 | PRRT_kwDOVi_ME867YJ8a | src/tar/write.rs:721 | P2 | open |
| A2 | #252 | PRRT_kwDOVi_ME867Lncl | src/sevenzip/run.rs:703 | P2 | open |
| A3 | #246 | PRRT_kwDOVi_ME867PMnB | src/zip.rs:1041 | P2 | open |
| A4 | #257 | PRRT_kwDOVi_ME867S4tH | tests/persistent_partials.rs:4652 | P2 (flaky test) | open |

- **A1** Eight-byte base-256 fields: values 2^62 .. 2^63-1 set the base-256 sign bit (0x40 of the first byte after the
  0x80 marker), so `(1 << 63) - 1` encodes as eight 0xff bytes = -1, which src/tar.rs::number sign-extends and member
  parsing discards. Reject values >= 2^62 for eight-byte unsigned fields (and the matching bound for 12-byte fields),
  and fix the boundary test (it currently asserts the wrong value succeeds).
- **A2** 7z with `refused_link_placeholder: true`: in a multi-member folder with a folder CRC (deferred publication),
  `place` calls `check_target` while staging later members and creates directory `s` before the refused link
  `s -> ../outside` is published; `stand_in`'s `create_new` then fails because `s` exists, and `publish` returns a
  terminal `SevenZipError::Io`, so remaining members are not extracted. Preserve archive order: create the placeholder
  (or reserve the path) before later members create parents under it, so only the member beneath it fails. Test: a 7z
  folder (one solid folder, CRC) with link `s -> ../outside` then `s/new.txt` then `other.txt`, placeholder on: `s` is
  an empty file, `s/new.txt` fails, `other.txt` extracts.
- **A3** ZIP listing budget charges a symlink target's raw byte length, but the listing keeps
  `String::from_utf8_lossy(&target)`, which expands each invalid byte to 3 bytes (U+FFFD). Charge the decoded string's
  length (and keep that decoded value). Test: many 0xff-byte targets with a budget that the raw length fits but the
  decoded length does not: listing fails with the budget error.
- **A4** `grouped encrypted refill` sync-count test reads the process-global `SYNCS` atomic, so parallel tests can
  make `grouped_syncs >= plain_syncs`. Use an operation-scoped count (e.g. a thread-local counter like src/work.rs,
  or the fixture's own anchor-store call count) so the assertion is isolated. Verify by running the file with
  `--test-threads=8` several times.

## Group R2: RAR4 solid replay in the feed decoder (src/map/feed/rar4.rs, examples/live_feed). Branch bugs-round2-b.

| # | PR | Thread | Where | Sev | Status |
|---|---|---|---|---|---|
| B1 | #240 | PRRT_kwDOVi_ME867MAvE | src/map/feed/rar4.rs:385 | P2 | open |
| B2 | #240 | PRRT_kwDOVi_ME867MAvH | src/map/feed/rar4.rs:388 | P2 | open |
| B3 | #240 | PRRT_kwDOVi_ME867MAvO | src/map/feed/rar4.rs:146 + examples/live_feed/sim.rs:921-978 | P2 | open |

- **B1** Standalone/restored RAR4 successor replaying earlier solid members: prefix output uses `write: 0..0`, so the
  earlier member's CRC is never accumulated or checked, and no suspect range is recorded; a corrupt earlier member
  yields `unproven: false` for derived output. Accumulate and check prefix members' CRCs and propagate suspect stream
  offsets with the same window-reach rules as the `next_solid` hand-off (`carried_suspect()`/`inherit()`). Test: corrupt
  a byte of an earlier member's packed data so it decodes to size but fails CRC; the successor reports unproven.
- **B2** Replay of an earlier member larger than the `ArticleBuffer` limit never finishes: prefix bytes are released
  only at `Stop::Reached`, and `FeedDecoder::release()` uses the requested member's geometry, so the buffer fills
  (`BufferFull`) and nothing advances. Release consumed ranges of the active prefix member on partial runs too,
  keeping bytes its lane still needs. Test: a buffer limit smaller than the earlier member, articles in order: the
  successor completes.
- **B3** `examples/live_feed` with several members of one RAR4 solid stream: standalone successors replay their
  predecessors' packed bytes, but the release-safety overlap check in sim.rs (921-935) only looks at each member's own
  pieces and folder spans, so releases stay on, the predecessor's bytes are dropped before the successor replays them,
  and the run ends "every article delivered, members not done". Include replayed prefix spans in the overlap check
  (or disable releases for overlapping solid decoders, or use the next_solid hand-off). Test in tests/live_feed.rs
  with a multi-member solid RAR4 set.
