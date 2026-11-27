# RAR 5.0 archives for the key derivation cache

Made with RAR 7.00 (Linux) for `src/kdf_cache_tests.rs`, password `kdfcache`; each member is a few bytes of text
(`a1.txt`..`a3.txt`: `alpha N`, `b1.txt`: `beta 1`, `c.txt`: 1500 × `z`). UnRAR 7.30 tests all of them OK.

- `hp3.rar`: `rar a -hpkdfcache -ma5 -mt1 hp3.rar a1.txt a2.txt a3.txt` (encrypted headers, three members).
- `p3.rar`: `rar a -pkdfcache -ma5 -mt1 p3.rar a1.txt a2.txt a3.txt` (encrypted data, plain headers).
- `vols.part1.rar`..`vols.part4.rar`: `rar a -hpkdfcache -ma5 -mt1 -m0 -v1k vols.rar a1.txt c.txt b1.txt`
  (encrypted headers in four volumes, `c.txt` split across them).

`rar` uses one salt for the encrypted headers and every file record of an archive and of every volume of a set, so
each archive needs exactly one key derivation. The test builds its own archive with three salts for the mixed case.
