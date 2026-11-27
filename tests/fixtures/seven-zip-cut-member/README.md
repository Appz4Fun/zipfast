# ZIP archives cut short, as 7-Zip reads them

Used by `tests/seven_zip_cut_member.rs`, which cuts these files shorter (and the RAR fixtures `rar4/solid.rar`,
`rar4-rar300/ppmd_solid_rar300.rar`, `rar4-legacy/BIGLZ.RAR`, `emit-cut-archive/*.rar`, `rar5-solid-enc/esppw.rar`,
and the volume sets `rar4-volumes/multi.part*.rar` and `rar4-archiver/win-encvol.*` with a volume left out). It
compares what zipfast keeps, prints and reads of each with what 7-Zip 26.06 does.

Each `zs-<method>.cut.zip` is an archive made by 7-Zip 26.06 for Linux x86-64, cut at the longest point the test uses:

    7z a -tzip -mm=<method> [-ppw [-mem=AES256]] zs-<method>.zip a.txt b.bin c.txt

| file | `-mm` | encryption |
| --- | --- | --- |
| `zs-deflate.cut.zip` | `deflate` | none |
| `zs-store.cut.zip` | `copy` | none |
| `zs-lzma.cut.zip` | `lzma` | none |
| `zs-bzip2.cut.zip` | `bzip2` | none |
| `zs-zc-deflate.cut.zip`, `zs-zc-store.cut.zip` | `deflate`, `copy` | ZipCrypto, `-ppw` |
| `zs-aes-deflate.cut.zip`, `zs-aes-store.cut.zip` | `deflate`, `copy` | WinZip AES-256, `-ppw -mem=AES256` |

`a.txt` is 55,581 bytes of text, `b.bin` 20,000 random bytes and `c.txt` text, all dated 2020-01-02 03:04:05. The
test's cut points are named for where they fall: `a0` just past `a.txt`'s local header, `a4k` 4,000 bytes into its
data, `b100` 100 bytes into `b.bin`'s, `c3k` 3,000 bytes into `c.txt`'s, `chdr` 20 bytes into `c.txt`'s local header.

The expected output is 7-Zip 26.06's, from `docker run --platform linux/amd64 --network none` with the cut files
mounted read-only:

    7z x -y -bd -p<pw or -> -o<dir> <cut>          # and 7z e: the same files
    7z x -so -y -bd -p<pw or -> <cut> [<member>]   # the same bytes

Every cut exits 2 with "Unexpected end of archive". The test lists each file's size and SHA-256, and the error 7-Zip
gives. `docs/compat-options.md` ("Cut members in 7z mode") sums up what 7-Zip keeps for each kind of member.
