# WP-A2 handoff
Status: merging. Branch feed-7z-hole-cost, worktree /Users/allen/git.xbmc4lyfe/zipfast-a2.
Finding: no avoidable cost. Per-hole time (live_feed repair_ms) is the decode of the output held behind the hole,
95% liblzma; redecoded 0, packed read once. Before numbers = after (no code change): F07 1.6-5 ms, F08 36-66 ms,
F10 37-67 ms per hole at drop 0.05 (seeds 1-4).
Done: profile, docs note in docs/feed-decoder.md, test an_article_sized_hole_waits_and_resumes_without_decoding_twice.
Left / idea: chunk-parallel decode of independent blocks after a repair (large, conflicts with WP-A4).
Tests: cargo test --test feed_decoder_7z --test feed_decoder_z (debug and --release).
