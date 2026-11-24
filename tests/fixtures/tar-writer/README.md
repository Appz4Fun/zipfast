Reference archives written by GNU tar 1.35 (debian:trixie); the tests in tests/tar_writer*.rs rebuild the same
trees from explicit metadata and compare bytes.

- `make-reference.sh`: gnu, gnu-numeric, gnu-override, pax, ustar (`docker run --rm -v "$PWD":/w debian:trixie sh /w/make-reference.sh`)
- `make-sparse.sh`: sparse-gnu.tar and sparse-pax10.tar (`docker run --rm --privileged -v "$PWD":/w debian:trixie sh /w/make-sparse.sh`;
  `--privileged` only so `unshare -fp` makes tar pid 1, which pax puts in the `GNUSparseFile.<pid>` name)
- `gnu.tar.{1,6,9}.gz`: the compressor tests' references
