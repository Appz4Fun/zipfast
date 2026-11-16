# RAR 4.x volume sets written by RARLAB rar 6.24

Written with RARLAB `rar` 6.24 (`-ma4`), from our own 2800-byte payload `split.bin`, and validated with
`unrar t`. They are the `nzbkit-base` RAR4 archiver fixtures that Prybar's corpus also carries.

| file | switches | contents |
|---|---|---|
| `mac-oldvol.{rar,r00,r01,r02}` | `-m0 -v1000b -vn` (macOS host) | stored `split.bin` over old-style `.rar`/`.r00`/`.r01`/`.r02` volumes |
| `win-encvol.{rar,r00,r01,r02}` | `-m0 -ptestpw123 -v1000b -vn` (Windows host) | the same, AES-128 encrypted; password `testpw123` |

`../rar4-unrar/` holds the SHA-256 of the files UnRAR 7.30 extracts from them.
