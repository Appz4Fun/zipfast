# 7z fixtures

Archives written by 7-Zip, copied unchanged from the test fixtures of the `dariusiii/rarinfo` PHP library
(`tests/fixtures/szip/`, exercised by its `SzipInfoTest.php`), which is distributed under the BSD-3-Clause
license. The password of the encrypted ones is `password`.

| file | contents |
|---|---|
| `empty_file.7z` | one empty file, no streams |
| `store_method.7z` | `7zFormat.txt` (7573 bytes) and `foo.txt` (15), Copy, one folder each |
| `store_method_enc_headers.7z` | the same, with an LZMA-encoded header |
| `store_with_directories.7z` | four stored files under `testdir/` and `testdir/testdir2/`, and both directories |
| `store_with_empty.7z` | two stored files, an empty file and the directory `testdir3` |
| `multi_volume.7z.001`, `.002` | `7zFormat.txt` and `foo.txt`, Copy, split at 4096 bytes |
| `solid_lzma_single.7z` | `7zFormat.txt`, LZMA |
| `solid_lzma_multi.7z` | three files in one solid LZMA folder |
| `encrypted_files.7z` | Copy, LZMA, 7zAES+LZMA and 7zAES+Copy folders, plain header |
| `multi_substreams_encrypted.7z` | a two-file LZMA folder and a 7zAES+LZMA folder |
| `encrypted_headers.7z` | `7zFormat.txt` in a 7zAES+Copy folder, header encrypted (`-mhe`) |

`lzma2_chunks.7z` is not from rarinfo: it was written for this project by 7-Zip 26.06 (`7zz a -m0=lzma2:d=256k:c=64k
-mmt=2 -ms=on`) from `a.txt` (1500 lines of text), `b.bin` (70000 random bytes) and `c.txt` (120 short lines). One
solid LZMA2 folder, cut into 64 KiB blocks that each reset the dictionary, with stored chunks for the random member.

Copyright (c) 2010-2016 Hecks. Redistributed under the BSD-3-Clause license; the full notice and conditions are in [../LICENSE-rarinfo](../LICENSE-rarinfo).
