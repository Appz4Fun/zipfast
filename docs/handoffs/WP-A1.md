# WP-A1: Linux per-hole cost in persistent partials

Status: merging (PR number and merge sha added after merge). Branch hole-cost-linux, worktree ../zipfast-holecost.

## Done
- Rebased the earlier WIP onto main (src/partial/durable.rs no longer exists upstream; sync is `sync_file` in mod.rs).
- Measured on `ssh server` (fsync about 5 ms; scripts in ~/zf-bench/holecost/bench.sh). Time per hole is syncs x fsync latency:
  plain mode is about 9 syncs and 2 CAS per hole (and about 5 syncs per refill step).
- Kept: encrypted members refill in the open group (`fill_encrypted_grouped`), `refill_targets` no longer flushes the
  group for encrypted members when `group_refills`, empty-range refill joins the group. Test:
  `encrypted_grouped_refills_share_one_commit_and_survive_a_reopen` (fails without the change).
- Dropped: committing a hole with the open group when `group_holes` is off: session -30% but later refills +60% syncs.
- Bench: `persistent_holes_bench` takes ZF_SET, ZF_PASSWORD, ZF_HOLES. Profiling hooks removed.

## Numbers (Linux server, ms)
Per-refill figures corrected in bugs-wave1 (bug 4): the first version divided refill time by the injected hole ranges instead of
the refill calls made; re-run with the fixed bench on F01/F11 (the 'before' rows keep the old ratio, scaled).
| set | mode | session per hole | refill per refill |
| F01 5 holes (16 refills) | default before/after | 214 / 215 | 55 (was reported as 179 / 177: divided by 5 holes) |
| F01 5 holes | group_holes+group_refills before | -0.1 | not re-run (about 178 reported, divided by 5 holes) |
| F01 5 holes | group both after | -0.1 | 4.3 (was reported as 14.0) |
| F01 18 holes (54 refills) | group both after | -0.2 | 2.3 (was reported as 6.7) |
| F11 33 holes (99 refills) | group both after | -0.1 | 2.4 (was reported as 7.0) |
| 1 GiB stored, 64 holes | default | 103 | 60 |
| 1 GiB stored, 64 holes | group both | 0.4 | 2.2 |
Target under 3 ms per hole is met with both group limits on; with them off the floor is syncs x fsync (see docs/persistent-partials.md).

## Left / next ideas
- Make the group limits the default for RustyGet (crash loss is the open group; documented). Decision for the owner.
- Fewer syncs per ungrouped transaction: file fsync plus directory fsync per put (journal.rs put_batch); a directory sync only
  for newly created names would save about 2 per transaction but changes the retry policy there. Not done.
- No new abort()-at-sync-point crash test: grouped writes add no new sync point (they use the existing group commit);
  the existing crash-point suites (`encrypted_restart_resumes_at_every_crash_point`, state tests) pass.
- macOS bench not re-run (grouped paths only change when group_refills is on).

## Tests
`cargo test --features persistent-partials --lib partial` and the persistent_* integration tests, debug and release.
