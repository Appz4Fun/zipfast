# Declared-size fixtures

Used by `tests/declared_size.rs`. Each archive holds one member whose header declares fewer bytes than its data
gives. The expected bytes are what the reference tools write, 7-Zip 26.06 (x64) and UnRAR 7.30 beta 1 for Linux x86-64,
run in `docker run --platform linux/amd64 --network none -e TZ=UTC ubuntu:24.04` with the archives mounted read-only.

| file | made with `make_declared_size.py` | member | declared | carried |
| --- | --- | --- | --- | --- |
| `r5-stored.rar` | `stored5` | `big.bin`, RAR 5.0, stored | 1 | 60,000 bytes |
| `r4-stored.rar` | `stored4` | `big.bin`, RAR 4.x, stored | 1 | 60,000 bytes |
| `r5-lz.rar` | `patch c5.rar r5-lz.rar 1000` | `words.txt`, RAR 5.0, `-m3` | 1,000 | 211,990 bytes |
| `r4-lz.rar` | `patch ../rar4/solid.rar r4-lz.rar 100` | `tese.txt`, RAR 2.9 LZ | 100 | 787 bytes |
| `r4-ppmd.rar` | `patch ../rar4-rar300/ppmd_solid_rar300.rar r4-ppmd.rar 1000` | `solid_lorem_a.txt`, RAR 2.9 PPMd | 1,000 | 98,304 bytes |
| `7z-copy.7z` | `patch7z copy.7z 7z-copy.7z 1000` | `part.txt`, Copy | 1,000 | 12,000 bytes |
| `7z-lzma.7z` | `patch7z lzma.7z 7z-lzma.7z 1000` | `part.txt`, LZMA | 1,000 | 12,000 bytes |
| `7z-lzma2.7z` | `patch7z lzma2.7z 7z-lzma2.7z 1000` | `part.txt`, LZMA2 | 1,000 | 12,000 bytes |
| `zip-stored.zip` | `zipstored` | `big.bin`, stored | 1 | 60,000 bytes |
| `zip-deflate.zip` | `zipdeflate` | `words.txt`, Deflate | 1,000 | 211,990 bytes |

`c5.rar` is `rar a -ep -m3 -ma5` (RAR 7.00) of `words.txt`: 5,000 lines of eight words drawn by Python's
`random.Random(5)` from `alpha beta gamma delta eps zeta eta theta iota kappa`. `patch` rewrites the first member's
declared size (fixing the header checksum) and drops the members after it. `part.txt` is the first 12,000 bytes of
`words.txt`; `copy.7z`, `lzma.7z` and `lzma2.7z` are `7zz a -mhc=off -m0=Copy` (`LZMA`, `LZMA2`) of it, and `patch7z`
rewrites the folder's unpack size (fixing both header CRCs). The ZIP members keep the whole data's CRC.

Every mode of both tools stops at the declared size (UnRAR exit 3, "checksum error"; 7-Zip exit 2, "CRC Failed" or
"Data Error"):

| file | `unrar x -kb`, `unrar p`, `7z x`, `7z x -so` | SHA-256 |
| --- | --- | --- |
| `r5-stored.rar`, `r4-stored.rar`, `zip-stored.zip` | 1 byte | `6e340b9c…17afa01d` |
| `r5-lz.rar`, `7z-*.7z`, `zip-deflate.zip` | 1,000 bytes | `58ae25d1…015dbdc5` |
| `r4-lz.rar` | 100 bytes | `214bd299…91efba05` |
| `r4-ppmd.rar` | 1,000 bytes | `9c458d03…db8c936e` |

For the 7z and ZIP files only 7-Zip's modes apply (`7z x` and `7z x -so`): "CRC Failed" for the 7z files and
`zip-stored.zip`, "Data Error" for `zip-deflate.zip` (Info-ZIP `unzip`, not imitated, writes all 211,990 bytes of it
and exits 0).
