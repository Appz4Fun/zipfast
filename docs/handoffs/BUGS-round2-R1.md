# BUGS round 2, group R1

Status: PR #280 open, awaiting cleanroom review (not merged).
Branch: bugs-round2-a. Worktree: /Users/allen/git.xbmc4lyfe/zipfast-r2a.

## Done
- A1 src/tar/write.rs `num`: an eight-byte base-256 field keeps 62 value bits (marker 0x80, sign 0x40); values >= 2^62
  are refused. Test: tests/tar_writer.rs `eight_byte_base256_ids_keep_their_high_bits` (boundary corrected: 2^62-1
  encodes as 0xbf ff.., 2^62 and 2^63-1 are errors). 12-byte fields were already correct (value bits 64 < 94).
- A2 src/sevenzip/run.rs: `Run::pending_links` records links staged for the folder CRC; `place` fails a later member
  whose path lies under one, so no parent is created before the link/placeholder takes its path. Test:
  tests/sevenzip_extract.rs `a_member_under_a_deferred_refused_link_fails_alone` (Built gained a `symlinks` field).
- A3 src/zip.rs `list_detailed`: the target is lossy-decoded before the budget charge, and that decoded value is kept.
  Test: tests/zip.rs `listing_budget_charges_the_decoded_link_target` (8000 x 4000 bytes of 0xff).
- A4 src/partial/mod.rs: `durable_sync_count_this_thread()` (thread-local, bumped with the global one);
  tests/persistent_partials.rs `encrypted_grouped_refills_share_one_commit_and_survive_a_reopen` uses it.

## Verified
- Each test fails with its fix reverted (touch, rebuild).
- A4: with a sibling thread running a persistent extract inside the measured window, the old global-counter assertion
  fails ("grouped 88 syncs, ungrouped 20"), the thread-local one passes. (That experiment is not committed.)

## Decisions
- A2 chose to fail the member beneath a pending link (as under a published link) rather than publish links early.
- A4 thread-local is sound because the refills run on the calling thread.

## Left
- Cleanroom review, then merge.

## Run
`cargo test --test tar_writer --test sevenzip_extract --test zip`; `cargo test --features persistent-partials --test persistent_partials`
