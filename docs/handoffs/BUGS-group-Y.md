# BUGS group Y: extraction runs and RAR volumes
Status: PR open, awaiting cleanroom review (not merged). Branch bugs-extract. Worktree /Users/allen/git.xbmc4lyfe/zipfast-bugsy.

| Item | Fix | Test (fails without the fix) |
|---|---|---|
| Y1 | `start_file` keys `batch_paths`/`queued_paths` by the place the hook chose; a renamed name that is busy drains and is placed again (no rename mode) | tests/start_hook_rename.rs `a_renamed_member_and_a_later_member_at_its_new_name_are_serialized`, `a_member_renamed_onto_an_earlier_pending_name_waits_for_it` (4 threads, Always and Skip) |
| Y2 | `check_target_detailed` rebuilds the accepted rename from its components | `a_new_name_with_empty_or_dot_components_is_normalized` |
| Y3 | `start_rename_is_safe` rejects NUL (UnsafePath, member-local) | `a_new_name_with_a_nul_fails_only_its_member` |
| Y4 | restarted run counts `members_before` (members starting in the volumes before the given one); those are unselected under a selection, ordinals shift | tests/rar_later_volume.rs `a_selection_by_ordinal_from_a_later_volume_follows_that_volumes_listing` |
| Y5 | `previous_volume` tries narrower widths when the padded name is absent | `volume::tests::previous_of_an_unpadded_set_takes_the_narrower_width`, `rar5_unpadded_set_restarts_from_part10` |

Decisions: members in the earlier volumes (including one continued into the given volume) are not in the given
volume's listing, so a selection leaves them out; without a selection they are extracted as before. Y1 re-placement
is skipped under rename modes (the file is reserved with O_EXCL at placement, so naming is already safe).
Run: cargo test --test start_hook_rename --test rar_later_volume --test links --test rar5_links --test member_start_hook; cargo test --lib volume
Checked: fmt, clippy x2, those tests debug+release, both feature sets.
