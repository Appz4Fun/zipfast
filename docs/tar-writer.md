# Tar writer (`zipfast::tar::write`)

A streaming tar writer to any `std::io::Write` sink, byte-exact with GNU tar 1.35.

```rust
let mut w = TarWriter::new(sink, TarWriterOptions::default()); // --format=gnu -b 20
w.append(&entry, &mut reader)?;          // header, then entry.size bytes from reader
// or: w.begin(&entry)?; w.write_data(chunk)?; ...
let sink = w.finish()?;                  // two zero blocks, padded to the record
```

- `TarEntry` is a stat-like description (path bytes, kind, mode, uid/gid, names, mtime and nanoseconds, size, link
  target, device numbers). Kinds: file, dir, symlink, hard link, char/block device, FIFO, and a reserved `Sparse`
  (appending it is an error until the sparse writer exists).
- `TarWriterOptions`: `format` (`Gnu` default, `Ustar`, `Pax`), `blocking_factor` (`-b`, default 20),
  `owner`/`group` (`--owner`/`--group` NAME:ID), `mtime` (`--mtime`), `numeric_owner`.
- Gnu: `ustar  \0` magic, `././@LongLink` `L`/`K` members for names and link targets over 100 bytes (K first),
  base-256 for uid, gid, size, device numbers and mtimes that do not fit octal, sub-seconds dropped.
- Ustar: names split at the last slash within 156 bytes as GNU does; anything that does not fit is an error.
- Pax: an `x` header (named `<dir>/PaxHeaders/<base>`, GNU's `exthdr.name=%d/PaxHeaders/%f`) carries `linkpath`,
  `path` (over 100 bytes or non-ASCII), `uid`, `gid`, `size` (too big for octal), `mtime` (fractional or out of
  range), `uname`, `gname`. No atime or ctime records (GNU tar's `delete=atime,delete=ctime`).
- Directories get a trailing slash when missing. Overrides apply to every member including links.

## Compressors (`CompressedWriter`)

```rust
let f = CompressedWriter::new(file, Compression::Gzip { level: 6 })?;   // tar -z
let mut w = TarWriter::new(f, TarWriterOptions::default());
// ... append entries ...
w.finish()?.finish()?;                                                    // tar trailer, then compressor trailer
```

`Compression` is `None`, `Gzip{level 0-9}`, `Bzip2{level 1-9}`, `Xz{level 0-9}`, `Zstd{level 1-22}` (out of range is an
InvalidInput error). Encoders are flate2, bzip2, liblzma and zstd (all existing dependencies). Dropping a
`CompressedWriter` without `finish()` leaves a truncated stream.

Gzip writes the header gzip 1.13 writes for piped input (mtime 0, no name, OS 3, XFL 2/4/0 by level) and the same
CRC32/ISIZE trailer; the deflate body is zlib's, not gzip's own, so the bytes are not identical to `tar -z` output
(tests compare header and trailer, and that the system gzip decodes to the exact tar). bzip2, xz and zstd are checked
by decoding with the system tool and with `tar::list`; their byte streams are not claimed to match any CLI.

Design for later work: the writer is generic over the sink, so compressors (B1c) wrap the sink; sparse members
(B1b) add a `Sparse` entry path in `begin`.

Proof: `tests/tar_writer.rs` compares against archives made by GNU tar 1.35 in docker
(`tests/fixtures/tar-writer/`, with `make-reference.sh` and a README), and round-trips through `tar::list`.

Not done: sparse files, `repack` still uses its own private writer (a different, pax/ustar
dialect with fixed ownership), and pax overflow of device numbers (an error).
