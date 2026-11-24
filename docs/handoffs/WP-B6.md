# WP-B6 handoff
Status: merging. Branch listing-followups, worktree /Users/allen/git.xbmc4lyfe/zipfast-b6.

Finding: all three follow-ups were already implemented by #164 (Entry::tar, partial .zip.001 listing, crypt record
doc). This WP adds tests against recorded 7zz 26.06 output and fixtures:
1. RAR5 crypt record: tests/rar5_encrypted.rs, real rar5-psw.rar (7zz: `AES:15:3`). Doc already says flags print even when 0.
2. .zip.001 gap: tests/zip_bytesplit.rs on the 7zz fixture minus piece 2 (7zz lists noise.bin, 1 error).
3. pax .tgz: tests/tar_listing_meta.rs, GNU tar 1.35 gpax.tgz/gpax.tar (owner, ids, pax name, records, ns times).
Decision: MemberMap is a different path (needs the directory; a gap gives MissingDirectory, correctly an incomplete
map), not changed. Remaining -slt corpus mismatches need the Prybar list (not available).
Run: cargo test --test zip_bytesplit --test rar5_encrypted --test tar_listing_meta
