# BUGS group Z: LZMA2 feed and ZIP rewrite

Status: PR open, awaiting cleanroom review (not merged). Branch bugs-feed-rewrite, worktree /Users/allen/git.xbmc4lyfe/zipfast-bugsz.

## Done
- Z1 (src/map/feed/lzma2.rs): the dictionary-reset fallback (`Lz::base`) is serialized as its own trailing section
  (tag 2, only when set; old snapshots still restore) and preferred over the value derived from active checkpoints.
  A restored main lane that restarts at a seeded checkpoint whose dictionary the sink no longer gives now falls back
  to `base` instead of failing with `HeldOutput` (the packed bytes from `base` are asked for again as `Next`).
  Test: tests/feed_decoder_7z.rs a_snapshot_keeps_the_dictionary_reset_fallback_past_seeded_restart_points
  (fails without the fix: "restoring needs held output 0..271502").
- Z2 (src/zip/rewrite/native/rename.rs `build`): the ordinal-indexed result, each member's temporary source records and
  rebuilt records are charged to `plan_capacity` before allocation and reported in `usage.common.plan.capacity`
  (upper bound: source record sizes plus twice the new name plus the Arc).
  Test: tests/zip_rewrite_rename.rs rename_charges_the_rebuilt_records_to_plan_capacity (fails without the fix).
- Z3+: PR #269 Codex review completed with no findings (no comments, no threads), so no items.

## Run
cargo test --test feed_decoder_7z --test zip_rewrite_rename (debug and --release); also feed_decoder_zip,
feed_decoder_zip_resync, zip_rewrite.

## Decisions
- Z2 charges an upper bound, not exact capacities, because the charge must precede the allocation.
