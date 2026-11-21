# Rebuilding encrypted stored data from plaintext

An encrypted stored member is the plaintext encrypted with AES in CBC mode. When an article of such a member is lost but another copy supplies the plaintext, `zipfast::crypto::rebuild_cbc` produces the exact ciphertext for that range, so the archive volume becomes byte-identical again (and passes par2):

```rust
let key = zipfast::crypto::derive_rar5_key(password, params.kdf_count, &params.salt, None).unwrap();
let ciphertext = zipfast::crypto::rebuild_cbc(&key, &previous_block, &plaintext, stream_end, Some((offset, &intact)))?;
```

## Inputs

- **The key.**
  - **RAR 5.0:** `derive_rar5_key`, with the salt and count from `rar5_record_params` of the file header's encryption record.
  - **7z AES:** `derive_7z_key`.
  - **RAR 3.x/4.x:** `derive_rar4_key_iv`.
- **The previous ciphertext block,** or the IV when the range starts the stream.
  - **RAR 5.0:** the file header's IV.
  - **7z:** the folder's IV. There is one IV per folder.
  - **RAR 3.x/4.x:** the IV derived with the key.
  - **Across volumes:** CBC runs on across a RAR volume boundary, so the previous block can be the last block of the previous volume.
- **The plaintext,** starting at a 16-byte-aligned offset of the member's stream. For a stored member, the stream is the output.
- **`stream_end`:** whether the range reaches the end of the member. If it does, its last partial block is padded with zero bytes, as rar and 7-Zip write it. Otherwise the plaintext must be whole blocks.
- **`intact`:** optional. Archive bytes that survive within the range, given as `(offset, ciphertext)`, for example the first intact block after the hole. The overlap must match: that proves the key, the plaintext and the previous block, and a mismatch is reported with its position.

## Checked against

- rar 7.30 (`-ma5 -m0 -p`): a member's whole ciphertext, including the zero-padded final block, and a lost middle range, rebuilt from the plaintext.
- 7-Zip (`-mx0 -p`): a folder's whole packed stream.

The test vectors are in `tests/cbc_rebuild.rs`.

RAR 3.x/4.x ciphertext is the same AES-CBC, so whole blocks rebuild the same way. Its final-block padding could not be checked, because rar no longer writes that format.
