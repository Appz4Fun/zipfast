# Archives cut short inside a member's data

Used by `tests/emit_cut_archive.rs`, which cuts these archives (and `rar4/solid.rar`,
`rar4-rar300/ppmd_solid_rar300.rar`, `rar4-legacy/BIGLZ.RAR`) at a byte offset and compares what zipfast prints of the
member cut short with what `unrar p` prints. The expected bytes are UnRAR 7.30 beta 1 for Linux x86-64, run as
`unrar p -inul -y -p- <cut>` in `docker run --platform linux/amd64 --network none ubuntu:24.04` with the cuts mounted
read-only; the test lists each cut's length and SHA-256.

| file | made with `../declared-size/make_declared_size.py` | member |
| --- | --- | --- |
| `r5-lz.rar` | `patch ../declared-size/r5-lz.rar r5-lz.rar 211990` | `words.txt`, RAR 5.0, `-m3`, 211,990 bytes |
| `r5-stored.rar` | `patch ../declared-size/r5-stored.rar r5-stored.rar 60000` | `big.bin`, RAR 5.0, stored, 60,000 bytes |
| `r4-stored.rar` | `patch ../declared-size/r4-stored.rar r4-stored.rar 60000` | `big.bin`, RAR 4.x, stored, 60,000 bytes |

That is, the declared-size fixtures with each member's true size declared again.

What the tools do with an archive that ends inside a member's data ("Unexpected end of archive", UnRAR exit 3, 7-Zip
exit 2):

- `unrar p` prints every member before it, then what it decodes of the member cut short: it reads on past the end as
  though zeros followed, decoding each code (LZ token, PPMd symbol, RAR 1.5/2.0 code, RAR 5.0 symbol) that starts
  before the byte after the data; a code straddling the end decodes over that fill. `unrar x -kb` keeps the same bytes
  in the member's file. For RAR 5.0 the bytes a straddling symbol yields differ from what zeros give (the length
  matches) and zipfast's tail can differ there, so the test uses RAR 5.0 cuts where the bytes agree.
- `7z x` and `7z x -so` keep or print the stored data that is there and what 7-Zip decodes of a RAR 5.0 member (the same
  length as UnRAR, with different bytes at the end), and nothing of a compressed RAR 4.x member.
