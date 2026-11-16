# UnRAR reference output

For each first volume, the SHA-256 of every file `unrar x -y` (UnRAR 7.30 beta 1, `ubuntu:24.04`, `LANG=C.UTF-8`,
`-p-`, or `-ptestpw123` for `win-enc*`) extracted, as `sha256sum` prints it. The name is the archive's path in
Prybar's RAR4 corpus with `/` replaced by `_`. `tests/rar4_split_solid.rs` extracts the archives through every route
and compares.

`rars_*.sha256` are the SHA-256 of the expected payloads the `rars` crate ships beside those fixtures
(`ppmd/solid_lorem_{a,b}.txt`, `rarvm/solid_e8_filter_{lead.txt,payload.exe}`), named as the archive lists them.
