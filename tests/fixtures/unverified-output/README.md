# Unverified-output fixtures

Used by `tests/unverified_output.rs` (`extract::UnverifiedOutput::Emit`). The expected bytes are what the reference
tools write, 7-Zip 26.06 (x64) and UnRAR 7.30 beta 1 for Linux x86-64, run in
`docker run --platform linux/amd64 --network none -e TZ=UTC ubuntu:24.04` with the archives mounted read-only. The
test files hold the length and SHA-256 of each output.

## RAR 5.0 first volumes cut off from the rest of their set

`r5-partial.part1.rar` and `r5-edge.part1.rar` are `rar5-resync/text.rar` of the zipfast-test-fixtures repository
(SHA-256 `9904462e…8ed613`: a 3,000,000-byte text file, `-m3 -md=128k`, blocks of about 24.7 KB packed) made into the
first volume of a set whose later volumes are missing, by `forge_rar5_volume.py`:

```sh
python3 forge_rar5_volume.py text.rar 24709 r5-partial.part1.rar  # 1,500 bytes into the second block
python3 forge_rar5_volume.py text.rar 23215 r5-edge.part1.rar     # 6 bytes into it (10 with its header)
```

| file | `unrar p -inul` (exit 6) | `7z x -so` (exit 2, "Data Error") |
| --- | --- | --- |
| `r5-partial.part1.rar` | 55,043 bytes, `11c38a4d…d7a06e` | 55,084 bytes |
| `r5-edge.part1.rar` | 51,611 bytes, `9e56b78c…6d2a64` | 51,620 bytes |

UnRAR leaves out the symbols that start in the last 128 bits of the data there, and decodes nothing of a block of
which fewer than 1,024 bytes are there (`r5-edge`: the second block is skipped and the last symbols of the first
are left out). The same rule matched `textvol.part1.rar` of `rar5-resync` (968,316 bytes) and `text.rar` cut at 45
other places, including on both sides of three block starts.

The RAR 4.x cases use the existing `rar4/multi_broken.part1.rar` (`unrar p`: `file2.txt` 6,198 bytes, `08d18923…402895`)
and the first volumes of `rar4-rar300/multivol_newnaming_rar300.part01.rar` (53,664 bytes, `7a7bc1f0…7af513`) and
`rar4-rar300/compressed_multivol_prng_rar300.rar` (819 bytes, `2f016dfe…28f8e3`), each copied alone into a temporary
directory. UnRAR leaves out an LZ token that starts in the last 30 bytes of the data there. `7z x -so` writes none of
those three members ("Data Error").

## 7z members that fail

Made with 7-Zip 26.06 from three files (`a.txt`: 400 lines of eight words from a ten-word list, 20,484 bytes;
`b.bin`: 6,000 random bytes; `c.txt`: `hello c\n` 250 times), then damaged:

| file | made with | damage |
| --- | --- | --- |
| `copy_crc.7z` | `-mx=0` `a.txt c.txt` | byte 1,032 (in `a.txt`) XOR `0x20` |
| `lzma_bad.7z` | `-m0=lzma -ms=off` `a.txt c.txt` | byte 332 XOR `0x01` |
| `solid_bad.7z` | `-ms=on` `a.txt b.bin c.txt` (LZMA2) | byte 632 XOR `0x01` |
| `lzma_trunc.7z` | `-m0=lzma -mhc=off` `a.txt` | the folder's pack size changed from 2,803 to 2,000 in the header (both header CRCs fixed) |
| `enc.7z` | `-psecret -ms=on` `a.txt c.txt` | none: read with `-pwrong` |
| `enc_copy.7z` | `-psecret -mx=0` `a.txt c.txt` | none: read with `-pwrong` |

What `7z x -so` writes (exit 2 for each):

| command | bytes | SHA-256 | error |
| --- | --- | --- | --- |
| `copy_crc.7z a.txt` | 20,484 | `9597f306…c9ee35` | CRC Failed : a.txt |
| `lzma_bad.7z a.txt` | 1,392 | `d54f2246…3ce438` | Data Error : a.txt |
| `solid_bad.7z a.txt` | 3,281 | `296d3f40…78f600` | Data Error : a.txt |
| `solid_bad.7z b.bin` | 0 | | Data Error : a.txt, b.bin |
| `lzma_trunc.7z` | 13,904 | `b0e0070e…31e793` | Data Error : a.txt |
| `-pwrong enc.7z` | 0 | | Data Error in encrypted file. Wrong password? |
| `-pwrong enc_copy.7z` | 22,484 | `b37305f9…6b0a7d` | CRC Failed in encrypted file. Wrong password? (both) |

The RAR filter case uses `rar4-rar300/generic_delta_padding_mutation.rar`: `7z x -so` writes 1,048,576 bytes
(`aff2543c…9e76c5`) and "ERROR: Unsupported Method : itanium_synthetic_bundles.bin", exit 2.
