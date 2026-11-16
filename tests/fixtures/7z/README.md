# 7z fixtures

Archives written by 7-Zip, copied unchanged from the test fixtures of the `dariusiii/rarinfo` PHP library
(`tests/fixtures/szip/`, exercised by its `SzipInfoTest.php`). The password of the encrypted ones is `password`.

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
