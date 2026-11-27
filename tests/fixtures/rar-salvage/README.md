# Damaged RAR fixtures for `Options::damaged_input`

Repro archives from Prybar's differential fuzzing (2026-11-26; references UnRAR 7.30 beta 1 and 7-Zip 26.06 for
Linux). Each is the fuzzer's damaged archive, unchanged. `tests/rar_salvage.rs` checks zipfast against what the
reference did.

| file | bucket / signature | damage | reference behaviour |
|---|---|---|---|
| `salvage-rar5-dir-crc.rar` | N-UNRAR-SALVAGE `rustyget-x86-4-967e04cb975d` (`unrar x -y`, `rar a -ma5 -m4`) | one byte of folder `t`'s header CRC and its data size changed | UnRAR: "Corrupt header is found", "t - the file header is corrupt" (twice), creates folder `t`, exit 3 |
| `salvage-rar5-main-and-dir-crc.rar` | N-UNRAR-SALVAGE `rustyget-arm-1-88760c70a27d` (`unrar x -y`, `-p` data encryption) | main header flags and folder header (attributes, mtime, name `t` to `p`) changed, CRCs fail | UnRAR: "Main archive header is corrupt", "p - the file header is corrupt", creates folder `p` with the damaged mtime, exit 3 |
| `list-rar4-cut-in-main.rar` | N-UNRAR-LIST-STOPS `rustyget-arm-1-c2cf9ab2f10e` (`unrar l -pwhatever`, seed `rar4-legacy/rars-solid.rar`) | cut to 11 bytes, inside the main header | UnRAR: "Main archive header is corrupt", "Unexpected end of archive", lists `Details: RAR 1.5`, `0 files`, exit 3 |
| `list-rar4-cut-at-main.rar` | N-UNRAR-LIST-STOPS `rustyget-x86-4-e23f3bf86488` (`unrar vt`, seed `rar4-legacy/rars-compressed.rar`) | cut to 8 bytes, one byte into the main header | UnRAR: as above, `Details: RAR 1.5`, exit 3 |
| `hdrerr-rar5-no-end.rar` | N-7Z-HDRERR-SILENT `rustyget-x86-4-2ccc53506c3f` (`7zz x -y`, `rar a -ma5`) | cut to 24 bytes, right after the main header | 7-Zip: "ERRORS: Unexpected end of archive", no files, exit 2 |
| `hdrerr-rar4-cut-in-file.rar` | N-7Z-HDRERR-SILENT `rustyget-arm-1-d7da3a805ffb` (`7zz l -slt`, seed `rar4/latest_winrar.rar`) | cut to 31 bytes, inside the first file header | 7-Zip: "ERRORS: Unexpected end of archive", `Blocks = 0`, exit 2 |
