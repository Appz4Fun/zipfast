# WP-A4 handoff
Status: merging. Branch lzma2-repair-checkpoints, worktree /Users/allen/git.xbmc4lyfe/zipfast-a4. PR: see report.

## Finding
A checkpoint at a chunk that resets nothing cannot exist (liblzma does not expose its state), so no "every N MiB"
checkpoints. Usable restart points: dictionary reset, state-reset chunk (>= 0xA0) with held dictionary. A 7-Zip
single-block folder has neither after its start: repairs there still decode from the start (documented).

## Done (src/map/feed/lzma2.rs)
- State-reset restart points whose dictionary reaches before the member (earlier members, via read_earlier) are now
  recorded (probe at 3 offsets, once per CP_INTERVAL = 1 MiB), with `Lz::base` (dictionary reset) as fallback.
- Fresh repair lanes wait when another repair is blocked on missing packed bytes inside their packed range
  (`lz_shared_block`) instead of decoding up to them again. This was the main cost (each of N repairs sharing a restart
  point decoded ~1 MB up to the same missing bytes every round).
- Test repairs_in_a_single_reset_folder_restart_at_the_nearest_state_reset (plain and 7zAES, sink with read_earlier):
  member 1 (state resets): 20 repairs 13.0-19.7 MB -> 1.0 MB (<= 1 MiB + one run); member 2 (one text stretch, no
  restart point): bounded by (holes+1) x 3 MB, documented.

## Run
cargo test --test feed_decoder_7z (debug and --release); also feed_decoder, feed_decoder_solid, persistent_solid_sink*.

## Left / ideas
- Start a later member's main decode at a state reset before its start (needs read_earlier) instead of the folder's dict reset.
- Share one decoder across repairs with the same restart point.
