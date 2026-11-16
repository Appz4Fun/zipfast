# UnRAR reference output

For each first volume, the SHA-256 of every file `unrar x -y` (UnRAR 7.30 beta 1, `ubuntu:24.04`, `LANG=C.UTF-8`,
`-p-`, or `-ptestpw123` for `win-enc*`) extracted, as `sha256sum` prints it. The name is the archive's path in
Prybar's RAR4 corpus with `/` replaced by `_`. `tests/rar4_split_solid.rs` extracts the archives through every route
and compares.
