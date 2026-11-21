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
- **The previous 16 ciphertext bytes,** or the IV when the range starts the stream.
  - **RAR 5.0:** the file header's IV.
  - **7z:** the folder's IV. There is one IV per folder.
  - **RAR 3.x/4.x:** the IV derived with the key.
- **The plaintext,** starting at a 16-byte-aligned offset of the stream. For a stored member, the stream is the output. The stream is:
  - **RAR:** the member's packed data across all its volumes' data areas taken together. A volume's part is rarely a multiple of 16 bytes (rar 7.30 split a 100,000-byte member into 19,753-byte parts), so offsets count from the member's start, and blocks and the previous 16 bytes can straddle a volume boundary.
  - **7z:** the folder's unpacked stream. Several files in a solid stored folder share one stream.
- **`stream_end`:** whether the range reaches the end of the stream (the RAR member, or the 7z folder). If it does, its last partial block is padded with zero bytes, as rar and 7-Zip write it. Otherwise the plaintext must be whole blocks.
- **`intact`:** optional. Archive bytes that survive within the range, given as `(offset, ciphertext)`. The overlap must match, and a mismatch is reported with its position. In CBC a block depends only on the plaintext up to it, so a match proves the key, the previous bytes and the plaintext only up to the overlap.
  - **Where to take it from:** at or after the hole's end, for example the first intact block after the hole. Its plaintext must be inside `plaintext`.
  - **At the stream's end:** a range that ends the stream has nothing after it to check.

## From a hole to the call

`cbc_rebuild_span(hole, stream_len)` turns an article hole (stream offsets) into what to pass:

- **`range`:** the hole widened to whole blocks, plus one intact block after it.
- **`previous_at`:** where the previous 16 bytes start, or None to use the IV.
- **`check`:** the intact bytes to compare.
- **`stream_end`**

```rust
let span = zipfast::crypto::cbc_rebuild_span(hole, member_len);
let previous = match span.previous_at { Some(at) => stream_bytes(at..at + 16), None => iv };
let check = span.check.clone().map(|c| ((c.start - span.range.start) as usize, stream_bytes(c)));
let ciphertext = zipfast::crypto::rebuild_cbc(&key, &previous, &plaintext(span.range.clone()), span.stream_end, check.as_ref().map(|(o, b)| (*o, b.as_slice())))?;
```

## Checked against

- rar 7.30 (`-ma5 -m0 -p`): a member's whole ciphertext, including the zero-padded final block, and a lost middle range, rebuilt from the plaintext.
- 7-Zip (`-mx0 -p`): a folder's whole packed stream.

The test vectors are in `tests/cbc_rebuild.rs`.

RAR 3.x/4.x ciphertext is the same AES-CBC, so whole blocks rebuild the same way. Its final-block padding could not be checked, because rar no longer writes that format.
