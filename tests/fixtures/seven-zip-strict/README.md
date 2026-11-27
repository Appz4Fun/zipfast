# `seven_zip_strict` fixtures

Small archives that 7-Zip 26.06 wrote, then altered where 7-Zip's extra end checks look: a range coder's last bytes,
bytes after a stream's end, or a ZIP local header field. `gen.py` writes them all deterministically:

    python3 -I gen.py /path/to/7z OUT_DIR

It uses 7-Zip 26.06 for Linux x86-64 (`~/prybar-refs/compat/bin/7z`). Run it in Docker with `--network none`. Where
several byte changes would do, `gen.py` keeps the first one 7-Zip reports exactly as listed below.
`tests/seven_zip_strict.rs` checks zipfast against each verdict.

7z archives hold `a.txt` and `b.txt` (or `a.bin` and `b.bin`) in one folder, `#0`. `two-folders-last-tail.7z` has two
folders.

| fixture | change | 7-Zip 26.06 `t` |
| --- | --- | --- |
| `lzma.7z`, `ppmd.7z`, `bcj2.7z` | none | OK |
| `lzma2-no-end-marker.7z` | the LZMA2 end marker dropped | OK |
| `lzma-eos.7z` | LZMA with an end marker after the data | OK |
| `lzma-code.7z` | the range coder's last byte | Data Error : #0 |
| `lzma-tail.7z` | a byte after the LZMA data | Data Error : #0 |
| `lzma2-tail.7z` | a byte after the end marker | Data Error : #0 |
| `lzma2-chunk-start.7z` | the end marker byte made `0xB3`, a chunk's control byte | Data Error : #0 |
| `ppmd-code.7z` | the range coder's last byte | Data Error : #0 |
| `ppmd-tail.7z` | a byte after the PPMd data | Data Error : #0 |
| `ppmd-first-byte.7z` | the first byte is not 0 | Data Error : a.txt, b.txt |
| `bcj2-call-tail.7z` | a byte after the call stream's data | Data Error : #0 |
| `bcj2-rc-code.7z` | the range coder's last byte | Data Error : #0 |
| `bcj2-rc-first-byte.7z` | the range coder's first byte is not 0 | Data Error : a.bin, b.bin |
| `deflate-past-size.7z` | the Deflate stream goes on with more output past the folder's size | Data Error : #0 |
| `deflate-tail.7z`, `deflate64-tail.7z` | a byte after the end block | There are some data after the end of the payload data : #0 |
| `deflate64-copy-last-block-empty.7z` | Copy feeding Deflate64 (one folder, two coders); the output in a block that isn't the last, then an empty last block | Data Error : #0 |
| `bzip2-second-stream.7z` | a second BZip2 stream after the first | There are some data after the end of the payload data : #0 |
| `bzip2-two-streams.7z` | `a.txt` and `b.txt` written as two BZip2 streams | Data Error : b.txt |
| `copy-tail.7z` | a packed byte beyond the unpacked size | There are some data after the end of the payload data : #0 |
| `two-folders-last-tail.7z` | a byte after the second folder's LZMA data | Data Error : #1 |
| `local.zip` | none (`f0.txt`, `f1.txt`, `f2.txt`) | OK |
| `local-streamed-crc.zip` | `f1.txt` flagged for a data descriptor in both headers, its local CRC-32 changed | OK (not compared) |
| `local-crc.zip` | `f1.txt`'s local CRC-32 | Headers Error : f1.txt (`x` leaves it empty) |
| `local-size.zip` | `f1.txt`'s local size | Headers Error : f1.txt (`x` leaves it empty) |
| `local-method.zip` | `f1.txt`'s local method | Headers Error : f1.txt (`x` leaves it empty) |
| `local-descriptor-flag.zip` | `f1.txt`'s local data descriptor flag | Headers Error : f1.txt (`x` writes its data) |
| `local-link-crc.zip` | the symbolic link `l1` (to `f0.txt`) with its local CRC-32 changed | Headers Error : l1 (`x` leaves an empty regular file and also reports Unknown reparse stream : l1) |
| `local-link-flag.zip` | the same link with only its local data descriptor flag set | Headers Error : l1 (`x` places the link) |
| `central-descriptor-flag.zip` | `f1.txt` flagged for a data descriptor in its central record only | Headers Error : f1.txt (`x` writes its data) |
