# WP-B2: start extraction from a later RAR volume (Z6)

Status: merging
Branch: rar-later-volume; worktree: /Users/allen/git.xbmc4lyfe/zipfast-b2; PR: see GitHub (branch rar-later-volume)

## Done
- `extract` RAR runs (extract and test; legacy, typed and held-signature routes share `rar_run_shared_open`) now
  start over at an earlier volume as UnRAR 7.30 does: if the first member in the given volume has the split-before
  flag, walk back by name (`volume::previous_volume`) through volumes whose first member also continues, until one
  that does not; every one must exist and open. Otherwise (a volume missing, no earlier name, or the volume starts
  with a fresh member) no restart.
- No restart: members continued from before are reported once as `Skipped(MissingStart)` (UnRAR warns once per
  member; later parts of the same orphan stay quiet via `Run::orphan`). Prybar maps this to exit 6 ("No files to
  extract" / "Total errors: 1") as UnRAR does.
- Listing (`l`) is unchanged: UnRAR lists only the given volume.

## Facts learned by running UnRAR 7.30 (docker debian + ~/prybar-refs/compat/bin/unrar)
- rarinfo multi.part2 with part1/part3: restart, all 3 files, exit 0; part2+part3 only: file3 extracted,
  "need to start from a previous volume to unpack file2.txt", exit 6; part1+part3 (part2 missing), start part3: no restart.
- multivol_oldnaming .r00 + .rar: restart, exit 0; .r00 alone: nothing, exit 6. The fixture .r00 main header carries
  MHD_FIRSTVOLUME (0x0101) like the .rar, so the first-volume flag is NOT the criterion; the continuation flag is.
- RAR5 volume starting with a new member: no restart (exit 0, only that member).

## Tests
`cargo test --test rar_later_volume` (8 tests; fail without the change: restart ones). Unit test
`volume::tests::previous_names`. RAR5 sets are synthesized with tests/common (no rar binary here), and UnRAR was run
on the same bytes to record the expectations.

## Not done / notes
- No real WinRAR-made RAR5 multi-volume fixture exists in the repo.
- Progressive/feed sessions are untouched (they take volumes as given).
