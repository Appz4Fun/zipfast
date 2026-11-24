# WP-A3: multi-member held-output sink for resume_solid

Status: merging. Branch: solid-stream-sink. Worktree: /Users/allen/git.xbmc4lyfe/zipfast-a3. PR: pending.

## Done
- src/partial/solid_sink.rs: `SolidStreamSink` (new, open, next_member, push_member, current/current_mut, set_cursor,
  commit, sinks, into_files, stream_start), `stream_slots(map, index)`, `StreamSlot`. mod.rs: `mod` line and re-export only.
- tests/persistent_solid_sink.rs (RAR5, plain and AES): layout, read_earlier spans/stops, resume_solid after restart
  (redecoded 0, CRC ok), hole in member 1 (member 2 unproven until CRC, repair after restart).
- tests/persistent_solid_sink_7z.rs: layout, three-member folder decode after restart, repair after restart.
- docs: persistent-partials.md ("Solid streams"), feed-decoder.md.

## Left
- Nothing for the WP.

## Run
cargo test --features persistent-partials --test persistent_solid_sink --test persistent_solid_sink_7z (debug and --release)

## Decisions and dead ends
- `DirectPartials::open` is Busy for a member with a live handle, so `open` suits restart; in-session use `next_member`.
- Hole test: member 1's hole skipped over output known from elsewhere, modelled by filling member 1's partial with
  the plaintext first (the decoder rewrites matching bytes, no-ops).
- 7z: a fresh member decodes from the folder's last state reset (redecoded > 0, existing behaviour), so read_earlier
  is not asked in the 7z tests; the sink path is covered by the RAR5 tests and the unit test.
