# WP-A6: byte-split ZIP in MemberMap

- Status: merging
- Branch: zip-byte-split-map; worktree /Users/allen/git.xbmc4lyfe/zipfast-a6; PR: #259
- Done: `src/map/zip_byte_split.rs` (walker: learns piece lengths, runs `ZipWalker` over a joined view), `ZipWalker::over_volumes`
  cuts member pieces at piece boundaries; detection in `Core` (`PK\x03\x04` + `*.zip.001`); live_feed concatenation removed;
  docs (member-map.md, feed-decoder.md); tests `tests/member_map_zip_bytesplit.rs`, `byte_split_volumes` in
  feed_decoder_zip, live_feed fixture case.
- Left: nothing. Not done: first piece under 4 bytes is NotArchive; last_volume identity for `.zip.00N` not touched.
- Tests: `cargo test --test member_map_zip_bytesplit --test feed_decoder_zip --test live_feed` (debug and --release).
- Decisions: reuse ZipWalker unchanged through an adapter instead of a new walker; middle gap = end of set.
