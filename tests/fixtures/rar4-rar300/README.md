# RAR 3.x split, solid and encrypted fixtures

Copied unchanged from the test fixtures of the `rars` crate (github.com/bitplane/rars,
`crates/rars/tests/fixtures/rar15_40/`), which is distributed under the MIT OR Apache-2.0 license. Prybar's
RAR4 compatibility corpus carries the same files.

| file | contents |
|---|---|
| `compressed_multivol_prng_rar300.{rar,r00,r01,r02,r03}` | `cvolume.bin`, LZ compressed (v29) and split over five old-style named volumes |
| `multivol_oldnaming_rar300.{rar,r00}` | `bigtext_64k.bin`, compressed and split over `.rar`/`.r00` volumes |
| `multivol_newnaming_rar300.part0{1,2}.rar` | the same file over `.partNN.rar` volumes |
| `solid_simple_rar300.rar` | `one.txt` and `two.txt`, solid LZ |
| `solid_rar300.rar` | four files in one solid LZ stream |
| `per_file_rar300_password.rar` | `hello.txt`, AES-128 encrypted and compressed; password `password` |
| `rar4_junrar_password.rar` | `file1.txt` (`file1\n`), encrypted and compressed; password `junrar` |

`../rar4-unrar/` holds the SHA-256 of every file UnRAR 7.30 extracts from them.
