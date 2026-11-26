# RAR 3.x split, solid and encrypted fixtures

Copied unchanged from the test fixtures of the `rars` crate (github.com/bitplane/rars,
`crates/rars/tests/fixtures/rar15_40/`), which is distributed under the MIT OR Apache-2.0 license. Prybar's
RAR4 compatibility corpus carries the same files.

| file | contents |
|---|---|
| `compressed_multivol_prng_rar300.{rar,r00,r01,r02,r03}` | `cvolume.bin`, LZ compressed (v29) and split over five old-style named volumes |
| `multivol_oldnaming_rar300.{rar,r00}` | `bigtext_64k.bin`, compressed and split over `.rar`/`.r00` volumes |
| `multivol_newnaming_rar300.part0{1,2}.rar` | the same file over `.partNN.rar` volumes |
| `header_encrypted_multivol_rar300.{rar,r00}`, `header_encrypted_newnaming_rar300.part0{1,2}.rar` | the same file behind encrypted headers (`-hp`); password `password` |
| `solid_simple_rar300.rar` | `one.txt` and `two.txt`, solid LZ |
| `solid_rar300.rar` | four files in one solid LZ stream |
| `per_file_rar300_password.rar` | `hello.txt`, AES-128 encrypted and compressed; password `password` |
| `rar4_junrar_password.rar` | `file1.txt` (`file1\n`), encrypted and compressed; password `junrar` |
| `rarvm_{x86_e8,x86_e8e9,itanium_synthetic,delta_4ch,rgb_gradient,audio_stereo}_rar300.rar` | one file each through a VM standard filter |
| `ppmd_solid_rar300.rar` | `solid_lorem_a.txt` and `solid_lorem_b.txt`, one solid PPMd stream |
| `ppmd_embedded_vm_filter.rar` | a filter record inside a PPMd block |
| `solid_e8_filter_member_offset.rar` | `lead.txt` then `tiny_e8e9.exe` through an E8E9 filter, solid |
| `generic_delta_padding_mutation.rar` | a VM program that is none of the standard filters (refused; written unfiltered with `UnsupportedFilters::WriteUnfiltered`) |
| `with_comment_rar300.rar` | stored `hello.txt` and a RAR 3.x archive comment (a compressed `CMT` service header) |

Made here from `solid_simple_rar300.rar` by patching file headers and recomputing each header CRC (CRC-32 of the
header from its type byte on, low 16 bits):

| file | patch |
|---|---|
| `hosts_macos_beos_rar300.rar` | host OS of `one.txt` set to 4 (MacOS) and of `two.txt` to 5 (BeOS) |
| `old_revision_rar300.rar` | `one.txt` flagged as an old file revision (`LHD_VERSION`, 0x800) and renamed `one.txt;1` |

No UnRAR manifest exists for these two: the tests expect the output in `solid_simple_rar300.rar`'s manifest
(`../rar4-unrar/in_rar300_solid_simple_rar300.rar.sha256`), with `one.txt` named `one.txt;1` for the old revision.

`../rar4-unrar/` holds the SHA-256 of every file UnRAR 7.30 extracts from the copied fixtures.
