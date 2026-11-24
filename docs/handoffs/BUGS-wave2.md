# BUGS-wave2

Status: PR open, awaiting cleanroom review (not merged by design).
Branch: bugs-wave2. Worktree: /Users/allen/git.xbmc4lyfe/zipfast-bugs2. PR: see below.

Done (all in 66bb6bc5):
1. last_volume.rs: SetIdentitySteps now counts every Key comparison (Key::eq), so a linear scan is visible.
   Test: tests/set_identity.rs many_members_match_in_linear_time. Mutation check: replacing firsts.get with
   firsts.iter().find(..) made it fail (128,008,886 steps against 8,002,233), then reverted.
2. zip_byte_split.rs is_first_piece_name compares bytes. Test: byte_split_names_with_multibyte_characters_do_not_panic.
3. zip.rs cut charges Resource::Parts per extra piece. Test: extra_pieces_are_charged_against_the_parts_budget.
4. zip_byte_split.rs poll translates HeaderHole to piece and local offset. Test: a_header_hole_names_the_piece_and_the_local_offset.
5. zip_byte_split.rs discovery loop checks options.control. Test: cancellation_stops_piece_discovery (immediate provider).
Tests 2-5 are in tests/member_map_zip_bytesplit.rs; each was confirmed failing with its fix reverted.

Run: cargo test --test member_map_zip_bytesplit --test set_identity (debug and --release, also --features persistent-partials).
Left: review, then merge. Clippy x2 and fmt clean.
