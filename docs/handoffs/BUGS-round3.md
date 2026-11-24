# BUGS round 3

Status: PR open, awaiting cleanroom review (not merged).
Branch: bugs-round3. Worktree: /Users/allen/git.xbmc4lyfe/zipfast-r3.

## Done (src/sevenzip/run.rs, where a deferred link is staged)
- C1: `pending_links` holds the destination-relative output path chosen by `check_target` (`place.path` minus
  `opts.dest`), not the archive name. Test: tests/sevenzip_extract.rs
  `a_renamed_pending_link_does_not_block_members_under_its_archive_name` (existing dir `s`, RenameNew: link at `s_1`,
  `s/new.txt` extracts).
- C2: a staged link is added only when `refusal_before_place` (as `publish` uses it) does not refuse it, i.e. it will
  be placed or a placeholder will stand in. Test: `a_refused_link_without_a_placeholder_does_not_block_members_under_it`.
  The #280 test `a_member_under_a_deferred_refused_link_fails_alone` (placeholder on) still passes.

## Verified
Each new test fails with only its own fix reverted (touch, rebuild).

## Decisions
- Refusal is judged at staging time from the link's verified-so-far data file; a link that later fails to publish for
  another reason still blocks members under it (conservative).

## Left
- Cleanroom review, then merge.

## Run
`cargo test --test sevenzip_extract --test links --test compat_options` (debug and release)
