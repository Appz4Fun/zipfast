# BUGS round 2, group R2: RAR4 solid replay

Status: in review (PR opened, not merged; a cleanroom reviewer reviews it first).
Branch: bugs-round2-b. Worktree: /Users/allen/git.xbmc4lyfe/zipfast-r2b.

## Done
- B1 (src/map/feed/rar4.rs, rar5.rs OutSink::hashing): the replay hashes each earlier member's output, checks the
  header CRC32, and carries the suspect end offset with the `carried_suspect()` reach rule; the successor becomes
  `unproven`. Test: `a_replayed_earlier_member_that_fails_its_crc_makes_the_successor_unproven`
  (tests/feed_decoder_solid_rar4.rs; damages a packed byte of member 0 in the solid fixtures).
- B2: consumed packed bytes of the active replay member are released on Budget/Missing stops too
  (`pre_released`). Test: `a_replayed_earlier_member_larger_than_the_buffer_limit_completes`.
- B3 (examples/live_feed/sim.rs): the release-safety overlap check includes the replayed earlier members' pieces of
  each solid member (releases off when they overlap). Test: `members_of_one_solid_rar4_stream_replay_their_predecessors`
  (tests/live_feed.rs).

## Decisions
- B3: chose disabling releases for overlapping solid decoders (simplest, matches 7z folder handling).
- Each test was confirmed failing with the src/example fix reverted.

## Run
cargo test --test feed_decoder_solid_rar4 --test feed_decoder_rar4 --test feed_decoder --test live_feed
(live_feed also with --features persistent-partials), debug and release.
