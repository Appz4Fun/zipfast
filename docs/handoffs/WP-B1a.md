# WP-B1a handoff
Status: merging
Branch: tar-writer-core; worktree /Users/allen/git.xbmc4lyfe/zipfast-b1a
Done: src/tar/write.rs (public `zipfast::tar::write`), tests/tar_writer.rs, tests/fixtures/tar-writer/*, docs/tar-writer.md.
Left: B1b sparse, B1c compressors; optionally make repack use the new writer.
Tests: `cargo test --test tar_writer` (debug and release), `cargo test --lib tar::write`.
Decisions: pax ext header name pinned to `%d/PaxHeaders/%f`; pax records order linkpath, path, uid, gid, size, mtime,
uname, gname (verified for linkpath+path, others singly); repack left untouched (different dialect).
