# Growing native volumes

`zipfast::progressive::GrowingFileVolumes` is a library-owned `VolumeSource` for RAR sets that another process,
such as a downloader, is still creating and appending. It backs commands like
`pry extract ARCHIVE --output DIR --follow`. `GrowingFileSource` is the matching `RangeSource` for one such file.
It is format-neutral, so ZIP and 7z progressive sessions can use it once they exist.

```rust,ignore
let volumes = GrowingFileVolumes::new("/downloads/show.part01.rar", GrowingOptions::default())?;
let notifier = volumes.notifier(); // optional: call notifier.notify() from a file-system watcher
let options = ProgressiveOptions::new(extract_options, volumes.first_name().to_owned());
let mut session = ProgressiveSession::new(Box::new(volumes), options)?;
// poll_event with your task's waker until Ready(Ok(None)), as for any progressive session
```

## Volume paths and absent volumes

The first volume's path fixes the directory. Every volume's path is that directory joined with the session's
`VolumeRequest::expected` name. The session derives that name from `ProgressiveOptions::first_name`, so the
first name must equal `GrowingFileVolumes::first_name()`. A name that is not exactly one plain path component
(for example one containing a separator or `..`) is a `SourceContract` failure. Files are opened with
`O_NOFOLLOW | O_NONBLOCK` and must be regular files.

- **Absent volume (including volume 0):** the provider answers `Wait` and schedules a wake.
- **Still absent after `idle_timeout`, measured from the first `Wait` for that volume:** it answers `Missing`,
  which the session reports as `FailureKind::MissingVolume` with the volume index in the failure context.
- **Volume present but not declared yet:** it wakes the session at once and answers `Wait`. The session reads
  the declaration again before it asks for the volume a second time, and by then the declaration names it.

## Reads past the current end

`GrowingFileSource::info` reports `extent` as the length observed so far and the length as
`SourceLength::Advertised(u64::MAX)`. That length is the documented open-ended exception to "both variants promise
the same exact logical EOF". The provider cannot know a volume's final length on its own, and the session does not
need it. A RAR session leaves a volume when it parses the end-of-archive block (with `more_volumes` set, or at
the end of the set), never by reaching the source's EOF. The driver never reaches `u64::MAX`, so it never reports
`EndOfVolume` for a growing source, and `extent` may grow, as the driver allows.

A read at or past the observed length answers `NotYet`. The source then parks the read's waker until whichever
comes first:

- `poll_interval` after the read (default 250 ms);
- the idle deadline;
- a `GrowthNotifier::notify()`.

The read then runs again. After `idle_timeout` (default 10 minutes) with no growth and no successful read, the
read fails with `FailureKind::IdleTimeout { idle }`. That error is typed and terminal, so the session does not
hang.

## Waking without a runtime

Each provider owns one timer thread (`zipfast-growing-wake`), spawned lazily at the first timed park. It sleeps on
a condition variable until the earliest deadline, wakes each due waker outside its lock, and exits when the
provider and every source it opened are dropped. A waker that parks again replaces its own deadline rather than
queueing a second wake. Nothing busy-polls:

- the driver never retries a parked provider without a wake;
- each timed park produces at most one wake;
- a notification wakes everything that is parked.

Setting `poll_interval: None` leaves waking to a `GrowthNotifier`, for example one driven by fs-notify. Even then
the idle deadline still wakes the session once, so a stall is reported rather than hanging.

### Per-wake cost and limits for long follows

Every wake, whether from the timer or a notification, is charged to the session's cumulative budgets:

| Wait | `provider_wakes` | `source_requests` | `source_bookkeeping` |
|---|---|---|---|
| Absent volume | 1 | 2 | 1 |
| Read past the current end | 1 | 3 | 0 |

These costs do not depend on how many volumes are declared. When the provider repeats its declaration unchanged
(same epoch, same size), the session accepts the repeat in O(1). That is safe because the library provider never
changes an entry without raising the epoch, and because the next admission and every publication still re-prove
all bindings. Each protection query re-checks one declared volume, in rotation.

With the defaults, `provider_wakes` (1,048,576) is the first limit a pure wait reaches. That is about 72 hours of
waiting at the 250 ms interval, fewer if notifications add wakes. `source_requests` (4,194,304) and
`source_bookkeeping` (64 Mi) also pay for the actual reading. For a follow of duration *T*, size the limits as:

- `provider_wakes ≥ T / poll_interval`, plus the number of notifications you expect;
- `source_requests ≥ 3 × provider_wakes`, plus what the archive itself needs.

Alternatively, lengthen `poll_interval` and rely on a `GrowthNotifier` for prompt wakes.

## Strict publication: a growing native inventory

`protection()` returns `ProtectionDeclaration::Complete`. It names every volume that exists so far, each as
`VolumeBacking::Native` with one `ProtectedPath` carrying the handle the provider opened, under an epoch that
rises whenever volumes are appended. Each call first re-checks every declared volume (see below). It then looks
for further volume names (with the same `next_volume_os` the session uses) and declares each one that now exists.
Until volume 0 exists, the declaration is `Opaque`; the switch from `Opaque` to `Complete` is an ordinary
upgrade.

Why this grows, rather than reserving names for volumes that do not exist yet: the session keeps a declared path
that is absent on disk *unbound*. `NativeProtection::resolved_for_publication` refuses Strict publication while
any binding is unbound, because a case-folded or Unicode-normalised spelling of an absent name cannot be compared
by identity. A declaration that reserved future names would leave every member provisional until the last volume
arrived. A custom provider that reserved names up front, as prybar first proposed, would therefore not get Strict
publication for early members. Declaring only existing, bound volumes keeps every binding resolved, so a verified
member publishes Strict as soon as it is verified, even while later volumes are still absent.

Ordinary sessions keep frozen declarations for custom providers. A declaration grows in an ordinary session only
when the boxed provider's concrete type is `GrowingFileVolumes`. The session checks this through
`VolumeSource: Any`, the same way it recognises `ImmutableFileSource`. A wrapper that forwards every method of a
`GrowingFileVolumes` is still a custom provider, and its growth is refused with `SourceChanged`. Persistent
sessions (`new_partial`) accept the same growth through their existing opt-in and exclusions. A persistent session
needs a Complete declaration when it starts, so create volume 0 (it may be empty) before calling `new_partial`.

### Guards

Volumes that exist are bound by the same machinery as `ImmutableFileSource` volumes:

- an output whose path, or whose existing target's identity, matches a bound volume fails with `UnsafePath`;
- a canonical-parent filename match does too;
- every authority point (volume admission, member boundaries, publication) re-proves each binding's path
  identity against its held handle.

The publication check asks the provider for its declaration immediately before it checks the target. Any volume
that exists by then is declared and bound before the output can replace it.

The names of volumes that do not exist yet are not reserved. An ordinary session growing a library-owned
declaration therefore records the native identity of every output file it creates (the stage file, which
publication renames into place). It refuses, with `UnsafePath`, any newly declared path whose declared handle, or
whatever the path now resolves to, is one of those files. Identities are compared, so a case-folded, normalised or
hard-linked alias is caught too. If an output is published at a name where a later volume will appear, the
session fails closed when it reaches that volume; it never reads its own output as input. A volume created in the
moment between the publication check and the rename is replaced by the output, and is refused the same way when it
is requested.

To keep a downloader and the extractor apart entirely, extract to a directory that is not the download directory.

Recorded output identities are never retired, even after the library discards a stage file. If the file system
reuses such an inode for a volume created later, that volume is refused with `UnsafePath`. This fails closed and
is rare. A separate output directory on another file system avoids it entirely.

## Writer requirements

The provider assumes an **append-only writer**: every byte below the current file size is final when it becomes
visible. Writers that break this fail closed: a read sees bytes that are not yet the volume's, and the session
reports `SourceChanged` (from the block checks or the length check), a RAR header or data checksum failure, or a
malformed header. Writers known to break it:

- **Preallocation.** For example aria2's default `--file-allocation=prealloc` (or `falloc`/`trunc`), or a
  downloader that sizes the file first. The file reaches its final size at once, full of zeros.
- **Out-of-order or segmented writes into the final file.** For example NZBGet with `DirectWrite=yes`, aria2 with
  several connections per file, or BitTorrent clients, which write pieces wherever they land.
- **Network file systems that report a size before the data is readable.** For example NFS or SMB clients with
  attribute caching, or FUSE file systems that extend first and fill later.

Settings that work:

- NZBGet with `DirectWrite=no`, which assembles each file in order (or renames complete files; see below);
- SABnzbd's normal in-order assembly;
- aria2 with `--file-allocation=none` and one connection per file (`-x1 -s1`), or with completed files renamed in;
- `curl` or `wget` writing sequentially;
- any writer that only appends.

Torrents should finish (or download to a staging directory) before extraction.

**Writers that use a temporary name and rename on completion** are supported, but each volume only appears when it
is complete. Until then the provider sees it as absent, and after `idle_timeout` it answers `Missing`
(`MissingVolume`). Set `idle_timeout` comfortably longer than the slowest single volume takes to download. Use a
`GrowthNotifier` (driven by a watcher on the directory) so each rename is noticed at once rather than at the next
poll.

## Prefix stability: what is guaranteed

Bytes already read must not change. The source checks this cheaply. It never rehashes everything on every read.

- **Identity.** Before and after every read, the held handle must still be a regular file with the
  `(device, inode)` it was opened with. The path, checked with `lstat`, must still resolve to that identity. A
  deletion, a replacement by rename (new inode, even with identical bytes) or a symlink swap is `SourceChanged`.
  The driver's native bindings repeat the path check at its own authority points.
- **Length.** The length must never decrease. A truncation, or a read that ends before the observed length, is
  `SourceChanged`. Volumes the session has already left are re-checked too:
  - each protection query re-checks the identity, path and length of one declared volume, in rotation;
  - all declared volumes are re-checked whenever a new one is declared.
- **Content.** The source remembers a CRC-32 for every complete `check_block`-byte block (default 64 KiB) of what
  it has served. Bytes never served that fall in a gap are hashed from the file. That costs 4 bytes of memory per
  block, about 64 KiB per GiB.
  - Any later read that overlaps remembered blocks is compared with them.
  - Sampling re-reads one remembered block for every `check_every` blocks served (default 8, so about 12% extra
    reads), at most two per read. It works in sweeps. Each sweep covers the blocks remembered when it began and
    finishes even while the file keeps growing; the next sweep starts again at block 0. Each protection query
    re-reads one more block, rotating across volumes.
  - A difference is `SourceChanged`. `check_every: 0` turns sampling off, but overlap comparison stays on.

The guarantee has three tiers.

| Change | When it is caught |
|---|---|
| Replacement, deletion or truncation | Always, at the next read or authority point |
| In-place rewrite of served bytes | Eventually, while the stream continues (the sweep reaches it); immediately, if the bytes are read again |
| Rewrite of the trailing partial block | Once that block completes and is swept |

A rewrite that happens after the session has finished the set, or before the sweep reaches it, is not detected
by the source. RAR's own header and data checksums still refuse corrupted members, and a published member's
bytes are the ones that were verified. CRC-32 detects accidental changes; it is not a defence against a writer
who forges collisions. Such a writer could forge the archive itself.

## Not covered

- Non-Unix platforms: native identity is unavailable, and opening or reading reports `Unsupported`, as for
  `ImmutableFileSource`.
- Final-length proof: the source keeps reporting `Advertised(u64::MAX)`. The end block, parsed by the session,
  is what proves where a volume ends.
- Volumes past the end of the set that happen to exist with the next names are declared and protected too. A
  symlink or non-regular file at such a name fails the session closed.
