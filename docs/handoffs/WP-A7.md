# WP-A7: Deflate stored-block resync

Status: merging. Branch: deflate-stored-resync. Worktree: /Users/allen/git.xbmc4lyfe/zipfast-a7. PR: see below.

## Done
- `src/map/feed/zip.rs`: `Resync` (Edge, Scan, Count, Ahead phases), main decode confirms or refutes at the restart's output offset.
- `src/inflate64.rs`: `Inflater::unflushed`. `src/map/feed.rs`: `CrcRuns::add_run`.
- docs/feed-decoder.md ZIP section. Tests: tests/feed_decoder_zip_resync.rs.

## Decisions
- Output offset of a restart = member size - count of a window-less decode of the candidate to the data end (exact, since match lengths do not depend on the window); false candidates mostly die there before any write.
- Ahead output is unproven and its CRC runs are kept apart until the main decode confirms (block boundary at exactly that output offset whose stored header ends at the candidate byte). Refuted: the range is `lost` again and rewritten (sink gets those bytes twice, documented).
- ZipCrypto: no restart. One restart open at a time. Snapshots do not keep a restart.

## Tests
cargo test --test feed_decoder_zip_resync --test feed_decoder_zip (debug and release; also --features persistent-partials)
