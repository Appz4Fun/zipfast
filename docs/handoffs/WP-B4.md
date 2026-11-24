# WP-B4: RewritePlan::rename for ZIP

- Status: merging
- Branch: zip-rewrite-rename
- Worktree: /Users/allen/git.xbmc4lyfe/zipfast-b4
- PR: see GitHub (branch zip-rewrite-rename)

## Done
- `RewritePlan::rename(&EntryId, EntryName)` in src/zip/rewrite/native/rename.rs (`Action::Rename`).
- Writer: `PreparedRaw.rename` + `Renamed` (src/zip/write/raw.rs) rebuild local header and central record in memory; payload and
  descriptor are still copied from the source; ZIP64 relocation applied to the rebuilt central by `relocated_central`.
- Verify: `verify_renamed` compares headers with the rebuilt records and the payload with the source.
- Tests: tests/zip_rewrite_rename.rs (14), raw.rs unit test (relocation equals the raw-copy path, including >4 GiB offsets).
- Fixtures: tests/fixtures/zip-rename (sources made with python zipfile, `*.7z.zip` made by `7z rn` 26.06 in docker).

## 7-Zip behaviour (observed by running 7z rn)
- Local and central names replaced, later offsets shift, 0x7075 dropped from both records, bit 11 set iff the new name is non-ASCII.
- 7-Zip also adds an NTFS timestamp extra (0x000a) to the central record; we do not (documented). The tests compare local bytes
  exactly and central records modulo that extra.

## Decisions
- Rename needs CollisionPolicy::Exact (RenameUnsupported otherwise).
- Names must keep the old trailing slash. Rename to an existing live name, including its own, is NameConflict.
- Comment with non-ASCII bytes keeps the flag (RenameEncoding when the name cannot live with it).
- No write receipts for renamed members; they verify as retained (Full verifies the payload).

## Run
cargo test --test zip_rewrite_rename; cargo test --test zip_rewrite; cargo test --lib renamed_records
(7zz and unzip are used when on PATH.)

## Left
- Nothing known. A rename that pushes a later member over 4 GiB is covered by the unit test only.
