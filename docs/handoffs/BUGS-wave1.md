# BUGS-wave1: Codex findings on wave 1 (TODO_BUGS_2026-11-24.md)

Status: in review (a separate cleanroom reviewer reviews before merge; do not merge from this worker). Branch bugs-wave1,
worktree ../zipfast-bugs1. PR number: see the PR for branch bugs-wave1.

## Done
| # | Fix | Test (fails without the fix) | Commit |
| 1 | Hole moved to the second article (nonempty decoded prefix); asserts `before > 0` | tests/feed_decoder_7z.rs `an_article_sized_hole_waits_and_resumes_without_decoding_twice` (hole at 0 fails the prefix assertion) | ec3f0e06 |
| 2 | `stream_slots` 7z: layout by member index up to the requested one, zero-length predecessors kept | tests/persistent_solid_sink_7z.rs `empty_folder_members_keep_their_place_in_the_stream_layout` (panics in open/layout without the fix) | 98267462 |
| 3 | `fill_encrypted_grouped`: errors after a group write carry `packed_progress` (applied, state) | tests/persistent_partials.rs `a_grouped_encrypted_refill_reports_progress_when_retaining_ciphertext_fails` (fault: `hole_intervals` limit fails ciphertext retention after the group commit) | ec3f0e06 |
| 4 | Bench `run` returns the refill count, per-refill time divides by it; docs corrected | example, re-run once on F01 (server): 16 refills; default 55.4 ms/refill, grouped 4.31 (F01 18 holes: 54 refills, 2.28; F11: 99, 2.36) | 5547b8be |

## Decisions
- Item 3 test fault: a `ProgressiveLimits::hole_intervals` of 4 lets the reopen and refill planning pass and fails the
  merge of kept ciphertext after the plaintext was written (group_commit_bytes 1 commits it at once). Added
  `reopen_limited` (limits as parameters) beside `reopen_with`.
- Item 3 reports applied ranges only when the error carries no progress already.
- Item 2: ordering relies on member indices being in folder order (a 7z header lists a folder's substreams in order).
- Item 4 re-run on `ssh server` with the F01 fixture of ~/zf-bench/holecost (built in ~/zf-bench/bugs1, target removed).

## How to run
`cargo test --features persistent-partials --test persistent_solid_sink_7z --test persistent_partials --test feed_decoder_7z`
(debug and release); `cargo clippy --workspace --all-targets --locked -- -D warnings` with and without
`--features persistent-partials`.

## Left
Nothing. Merge after the cleanroom review; then remove the worktree.
