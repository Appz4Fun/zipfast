# Solid, encrypted RAR 5.0 with an empty member

Made by prybar-fc's compat fuzzing with RAR 7.x: `rar a -mt1 -ma5 -s -ppw esppw.rar t/a t/b t/c` (`t/a` and `t/c`:
1000 random bytes each; `t/b`: 0 bytes; password `pw`). `eshppw.rar` is the same with `-hppw` (encrypted headers).
UnRAR 7.30 and 7-Zip 26.06 extract all three; used by `tests/rar5_solid_encrypted_empty.rs`.
