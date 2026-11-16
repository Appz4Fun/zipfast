# Deflate64 fixtures

Archives written by 7-Zip (7zz) 26.06 for macOS arm64 from the inputs `gen_inputs.py` writes, by `gen.sh`:

```sh
tests/fixtures/deflate64/gen.sh /path/to/7zz tests/fixtures/deflate64
```

`expected.txt` lists each input's size and SHA-256; the tests compare decoded output against it. The password of
the encrypted archives is `password`.

| file | contents |
|---|---|
| `d64.zip` | `far.bin`, `runs.bin`, `small.txt`, `text.txt`, ZIP method 9 |
| `d64_zipcrypto.zip` | `small.txt`, `text.txt`, method 9 under ZipCrypto |
| `d64_aes.zip` | `small.txt`, `text.txt`, WinZip AES-256 (method 99) over method 9 |
| `d64.7z` | the four inputs in one solid Deflate64 folder (coder `040109`) |

What the inputs exercise:

- `far.bin`: a 40000-byte random block twice. The first copy is stored blocks, the second a match 40000 bytes back
  (distance code 30, beyond Deflate's 32 KiB).
- `runs.bin`: long runs, matches of 7-Zip's longest Deflate64 length (257). 7-Zip never writes length code 285 with
  its 16 extra bits, nor distance code 31; the unit tests in `src/inflate64/tests.rs` build those streams by hand.
- `small.txt`: a fixed-Huffman block.
- `text.txt`: dynamic-Huffman blocks.
