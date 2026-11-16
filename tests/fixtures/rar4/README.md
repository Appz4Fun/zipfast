# RAR 4.x fixtures

Archives written by WinRAR and rar, copied unchanged from the test fixtures of the `dariusiii/rarinfo` PHP library
(`tests/fixtures/rar/`, exercised by its `RarInfoTest.php`), which is distributed under the BSD-3-Clause license.
`tests/rar4_legacy_fixtures.rs` checks them against `unrar lb` listings.

| file | contents |
|---|---|
| `rar_unicode.rar` | `file1À۞.txt` (18 bytes, stored), a Unicode-encoded name after its legacy `file1·?.txt` |
| `latest_winrar.rar` | `1.txt` and `2.txt` (5 bytes each), solid, compressed, with a recovery record (an `RR` service header carrying `Protect+` SubData) |
| `solid.rar` | `tese.txt` and `unrardll.txt`, one solid LZ stream |
| `dirlink_unix.rar` | made on Unix: symbolic links `emptydir\link` and `link`, `file` (8 bytes, stored), directories `emptydir`, `nopermdir` (mode 000), `setuiddir` (04000) and `stickydir` (01700), each followed by a `UOW` owner service header with SubData |
| `commented.rar` | `file.txt` (12 bytes) and an archive comment in a `CMT` service header compressed by RAR 2.9 (`-m3`); `tests/rar_comments.rs` checks it against `unrar l` |
| `encrypted_headers.rar`, `secret-crypted-none.rar` | encrypted headers (`-hp`), password unknown: UnRAR lists and extracts nothing without it |

Copyright (c) 2010-2016 Hecks. Redistributed under the BSD-3-Clause license; the full notice and conditions are in [../LICENSE-rarinfo](../LICENSE-rarinfo).
