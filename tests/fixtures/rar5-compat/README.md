# RAR 5.0 compatibility fixtures

- `r5extra.rar` (159 bytes, from Prybar's 7-Zip listing corpus, `seven-list/in/seven-list/r5extra.rar`): a RAR 5.0
  archive whose main header carries an original-name record, a locator record with a quick open offset of 100 and a
  recovery record offset of 200, and an unknown extra record. At main header start + 100 there is no valid block
  header, so UnRAR 7.30 reports "Corrupt header is found" and "Main archive header is corrupt" and exits 3 for
  `l`/`lb`/`vt`/`t`/`x`/`e`/`p`, while still listing and extracting both files. `tests/rar_headers.rs` derives
  variants from it (other quick open offsets, the header CRC recomputed) and checks `RarVolumeMetadata::quick_open`
  against UnRAR's outcomes for each.
