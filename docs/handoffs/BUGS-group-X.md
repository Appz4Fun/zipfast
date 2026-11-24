# BUGS group X handoff
Status: PR open, awaiting cleanroom review (not merged)
Branch: bugs-tar; worktree /Users/allen/git.xbmc4lyfe/zipfast-bugsx

Fixes and tests (all verified to fail with the src changes reverted):
- X1 src/tar/write.rs pax mtime: signed decimal of the normalized value (-0.5, matches GNU tar 1.35 for `touch -d @-0.5`).
  Test tests/tar_writer.rs::negative_fractional_pax_time_is_the_signed_decimal.
- X2 base-256 `num`: `field[0] |= 0x80`, values not fitting (8-byte field: >= 2^63) are refused.
  Test tests/tar_writer.rs::eight_byte_base256_ids_keep_their_high_bits.
- X3 `append` retries Interrupted. Test tests/tar_writer.rs::append_retries_an_interrupted_reader.
- X4 sparse: decision = refuse (before any header) a non-final segment whose length is not a multiple of 512;
  GNU pads each segment but counts stored size unpadded, so no consistent layout exists for it. Documented in
  docs/tar-writer.md. Test tests/tar_writer_sparse.rs::unaligned_middle_segment_is_refused_before_any_header.
- X5 src/tar.rs StagedTar::publish uses replace_link(temporary, path, place.link).
  Test tests/tar.rs::compressed_tar_symlink_then_file_of_same_name_continues.
Run: cargo test --test tar --test tar_writer --test tar_writer_sparse (debug and release).
