# 7z extraction fixtures

Archives written by 7-Zip (7zz) 26.06 for macOS arm64 from the inputs `gen_inputs.py` writes, by `gen.sh`:

```sh
tests/fixtures/7z-extract/gen.sh /path/to/7zz tests/fixtures/7z-extract
```

`gen.sh` holds every 7zz command line. `expected.txt` lists each input file's size and SHA-256; the tests compare
extracted files against it, so regenerating with another 7-Zip version changes the archives but not the expectations.
The password of the encrypted ones is `password`.

| file | contents |
|---|---|
| `copy.7z` | `text/a.txt`, `text/b.txt`, `text/tiny.txt`, Copy |
| `lzma.7z`, `lzma2.7z`, `deflate.7z`, `bzip2.7z` | `text/a.txt`, `text/b.txt`, one coder each, not solid |
| `bcj_x86.7z`, `bcj_arm.7z`, `bcj_armt.7z`, `bcj_arm64.7z`, `bcj_ppc.7z`, `bcj_sparc.7z`, `bcj_ia64.7z` | `code/<arch>.bin` (generated code-like bytes full of branches), the branch converter over LZMA |
| `bcj2.7z` | `code/x86.bin`, BCJ2 over three LZMA coders and a raw range coder stream |
| `delta.7z` | `delta/samples.raw`, Delta:4 over LZMA2 |
| `ppmd.7z` | `text/a.txt`, PPMd (order 6, 16 MiB) |
| `ppmd_solid.7z` | `text` and `big` in one solid PPMd folder, order 32 with a 2 MiB model |
| `solid.7z` | the folders `big` and `text` and their six files in one solid LZMA2 block |
| `tree.7z` | directories (one empty), an empty file, a file in a subfolder and the executable `text/run.sh` (mode 0755) |
| `aes.7z` | `text/a.txt`, `text/b.txt`, 7zAES over LZMA2, plain header |
| `aes_hdr.7z` | the same with the header encrypted (`-mhe=on`) |
| `aes_copy.7z` | `text/tiny.txt`, 7zAES over Copy |
| `split.7z.001` to `.003` | `noise/noise.bin` (10000 random bytes) and `text/tiny.txt`, LZMA2, split at 4 KiB (`-v4k`) |
| `times.7z` | `a.txt`, made by hand (not by `gen.sh`) with `7zz a -mtc=on -mta=on -mx=1`: stores creation and access times |
| `solid_wrongpw.7z` | `a.txt`, `b.txt`, `c.txt` in one solid LZMA2 + 7zAES folder, plain header, password `pw` |
| `nonsolid_wrongpw.7z` | `a.txt`, `b.txt`, one LZMA2 + 7zAES folder each, plain header, password `pw` |
| `mixed_wrongpw.7z` | `p.txt` in a plain LZMA2 folder, then `a.txt` in an LZMA2 + 7zAES folder (password `pw`) |

The three `*_wrongpw.7z` archives were made by hand with 7-Zip 26.06 for Linux x86-64 (`7z a -mx5 -ms=on|off -ppw
-mhe=off`; `mixed_wrongpw.7z` by two `7z a` calls, the second with `-ppw`) from small text files, for the wrong-password
tests. `7z x -pwrong` on them prints `ERROR: Data Error in encrypted file. Wrong password? : <name>` once per
encrypted member (all three of the solid folder), writes no encrypted member, extracts `p.txt`, and exits 2.

All entries carry the mtime 2020-01-02 03:04:05 (local time of the generating machine).
