# WP-B1b handoff
Status: merging
Branch: tar-writer-sparse; worktree /Users/allen/git.xbmc4lyfe/zipfast-b1b
Done: sparse GNU `S` and pax 1.0 writer in src/tar/write.rs; TarEntry.sparse, TarWriterOptions.sparse_pid;
tests/tar_writer_sparse.rs; fixtures sparse-gnu.tar, sparse-pax10.tar, make-sparse.sh, README.md; docs/tar-writer.md.
Left: pax sparse 0.0/0.1 (not requested).
Tests: `cargo test --test tar_writer_sparse --test tar_writer` (debug and release).
Decisions: GNU tar 1.35 default pax sparse version is 1.0 (verified by cmp); final (realsize,0) map entry always;
pax data member pid via sparse_pid (references made with unshare -fp so pid 1); no `path` record for sparse pax.
