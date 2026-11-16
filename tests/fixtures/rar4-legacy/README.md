# RAR 1.5 and 2.0 compressed fixtures

Copied unchanged from the test fixtures of the `rars` crate (github.com/bitplane/rars,
`crates/rars/tests/fixtures/rar15_40/`), which is distributed under the MIT OR Apache-2.0 license. The
`rars-*` files are that crate's `rars_generated/` set, renamed with the prefix.

| file | unpack version | contents |
|---|---|---|
| `readme_154_normal.rar` | 15 | `README.md` (CRC32 `0x509e5e3c`), RAR 1.54 compressed |
| `readme_154_store_solid.rar` | 15 | the same in a solid archive |
| `rars-compressed.rar`, `rars-solid.rar` | 15 | one compressed member; two solid members |
| `rars-split-store.{rar,r00,r01}` | 15 | a stored member over old-style volumes, whose non-final parts carry no packed-data CRC |
| `SOLID.RAR` | 20 | two members, the second going on from the first's history |
| `AUDIO.RAR`, `AUTOREJ.RAR` | 20 | RAR 2.50 `-mm`, which chose LZ blocks |
| `BIGLZ.RAR`, `unpack20_multiblock.rar` | 20 | long LZ history; several table blocks |

No archive written by a real RAR 2.x encoder with a true audio block is known; the audio engine follows UnRAR.
