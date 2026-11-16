# RAR 4.x volume fixtures

`multi.part1.rar`, `multi.part2.rar` and `multi.part3.rar` are a three-volume RAR 4.x set written by WinRAR with
`NAME.partN.rar` naming. They are copied unchanged from the test fixtures of the `dariusiii/rarinfo` PHP library
(`tests/fixtures/rar/`, exercised by its `RarInfoTest.php`), which is distributed under the BSD-3-Clause license.

Their main headers set `MHD_VOLUME | MHD_NEWNUMBERING` (0x0011), plus `MHD_FIRSTVOLUME` (0x0100) on the first
volume. `tests/entry_metadata.rs` reads them for `RarVolumeMetadata::new_numbering()` and `rar4_flags()`; the
old-style `.rNN` set it compares them with is built by the test.
