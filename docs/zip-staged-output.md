# Checked ZIP staged output: native and portable backends

`zip::run_with_policy`, `zip::run_with_context` and `ZipReadStage::prepare_file` write each regular member to a
staged file and publish it only after the member is fully decoded and verified and the source has been checked
again. The stage is written through one of two backends.

## Choosing the backend

`StagedStorage` (set with `EncryptedReadOverrides::staged_storage` or `EncryptedReadOptions::with_staged_storage`):

| Value | Behaviour |
| --- | --- |
| `Auto` (default) | Native where the destination parent's filesystem is on the allow-list, portable everywhere else. |
| `NativeOnly` | The old behaviour: a destination outside the allow-list fails with `ReadFault::UnsupportedStorage`. |
| `PortableOnly` | Portable everywhere, even on an allow-listed filesystem. |

The choice is made per member, from the member's own held parent directory, so one run can mix backends (for
example a bind mount inside the destination). The run reports it: `ZipRunReport::portable_files()` and
`native_files()`, and `ZipReadStage::backend()` returns `StagedBackend::Native` or `StagedBackend::Portable`.

The native allow-list is unchanged: local APFS on macOS; ext4, XFS, Btrfs and tmpfs on Linux. Anything else
takes the portable path under `Auto`: ZFS, NFS, SMB/CIFS, FUSE (mergerfs, shfs, sshfs), overlayfs, exFAT,
HFS+, and so on. HFS+ and exFAT were exercised directly (macOS disk images); the rest are covered by the test
control that makes every filesystem look unsupported.

## What both backends keep

- Member names are normalized and refused when unsafe (absolute, `..`, NUL, drive prefixes).
- The destination parent is opened step by step without following symlinks and held by descriptor; every create,
  rename and unlink is relative to that descriptor, so output cannot escape the destination.
- The target is inspected before the stage is created and again just before publication: the overwrite mode
  (`Skip`, `Always`, `RenameNew`, `RenameExisting`) and protected paths apply in the same way, and a directory or
  symlink at the target is never replaced.
- The source archive is observed again at both final boundaries; a changed source stops publication.
- Nothing is published until the member is completely decoded and its CRC or WinZip AES HMAC matches. On any
  failure the stage is removed.
- The same run budgets, descriptor accounting and cancellation.

## What the portable backend gives up

The portable backend is a 0600 temporary file named `.zipfast<32 hex>` (or `~zipfast...`) in the target directory,
the payload, best-effort time and mode, a flush where supported, then one rename. Compared with native it loses:

1. **Private birth.** Native creates the stage with an empty ACL and an ownership check, inside a fresh 0700 private
   directory, so no other user can open it even with inherited ACLs. Portable creates it 0600 with `O_EXCL` and
   `O_NOFOLLOW` only: an inherited ACL on the parent (NFSv4, SMB, ZFS with `aclinherit`), or a server that ignores
   modes (SMB without Unix extensions, exFAT), can make the stage readable by others while it is written. The stage
   name is visible in the target directory while it is written.
2. **Ownership and ACL reconstruction.** Native probes what an ordinary creation would get (owner, group, mode, ACL)
   and reproduces it exactly, then checks it. Portable sets the mode `0666 & !umask` and then the archived mode,
   best effort, and does not touch ACLs, owner or group; a filesystem may refuse or ignore the mode.
3. **Identity proofs.** Native checks device and inode of the stage after every step, and that the stage stays on
   the parent's device. Portable checks only that the descriptor holds a regular file of the expected size: exFAT,
   SMB and several FUSE filesystems do not keep inode numbers stable across a rename, and mergerfs reports a
   different device per branch.
4. **Atomic no-replace publication on every filesystem.** Native always uses `renameat2(RENAME_NOREPLACE)` or
   `renameatx_np(RENAME_EXCL)`. Portable uses that when the filesystem supports it, otherwise a hard link plus unlink
   of the stage name (still atomic), and where neither exists (exFAT, many SMB and FUSE mounts) it checks that the
   target is absent and then renames. Only in that last case can a name created by another process between the check
   and the rename be replaced. `Overwrite::Always` is one plain `renameat` on both backends.
5. **Stage substitution in shared directories.** Native stages live in a private 0700 directory nobody else can
   enter. The portable stage name sits in the target directory, so in a shared writable directory without a sticky
   bit (common on SMB and NFS) another user could rename their own file over it after our descriptor is closed.
   Before every rename or link the portable path checks that the name still holds the device and inode our
   descriptor had just before closing, and refuses with `ESTALE` otherwise. The check and the rename are separate
   calls, so a swap inside that window stays possible; and on a filesystem whose inode numbers are not stable this
   check is only as good as those numbers.
6. **Cleanup by identity.** Native removes a stage only when its identity still matches. Portable removes the stage
   name when it is still a regular file on the same device; the 128-bit random name is what keeps that to our own
   file.

Portable adds one thing native does not do: an `fdatasync` (Linux) or `fsync` (macOS) before the rename, skipped
without error where the filesystem has none (EINVAL, ENOTSUP, EROFS).

## WinZip AES without a spool

A checked run no longer copies a WinZip AES member larger than 64 KiB to a private spool file before
authenticating it. The run streams it: ciphertext is read once, HMAC-SHA1 is updated over it and the decrypted,
decompressed plaintext goes straight to the member's stage. After the last byte the tag is compared; only a match lets
the stage be published, and a mismatch removes it and fails the member with `ReadFault::AuthenticationFailed`. When
the codec fails first on tampered input, the rest of the ciphertext is hashed so the failure still reports
`AuthenticationFailed` when the tag disagrees.

So a checked extraction needs no temporary directory at all, and `TMPDIR` on overlayfs or NFS no longer matters. The
unauthenticated plaintext only ever reaches the stage (a 0600 file that is never published unauthenticated); no
caller callback sees it. Contexts built by callers (`EncryptedReadContext::for_projected`, `for_session`) with a
callback or stdout output keep the spool, because there the caller's sink would see the bytes.

## The WinZip AES spool on a portable temp directory

Reads that still spool a WinZip AES member (a caller callback or stdout sink, where unauthenticated bytes must not
reach the caller) use the same `StagedStorage` choice for the spool directory (`EncryptedReadOverrides::temp_dir`,
`EncryptedReadOptions::with_temp_dir`, else `TMPDIR`). Under `Auto` a temp directory outside the native allow-list
(ZFS, NFS, overlayfs, exFAT, ...) gets a portable spool instead of `UnsupportedStorage`; `NativeOnly` still refuses it.

The spool is a 0600 file created with `O_EXCL | O_NOFOLLOW`, checked, and unlinked at once, so it is anonymous while
it holds ciphertext. On the portable path it loses:

1. **Private directory checks.** Native requires the temp directory to be owned by the process user (or root) and
   not group- or world-writable unless sticky, and the spool file to be owned by us with mode exactly 0600 and no ACL.
   Portable only requires a directory and a regular file: NFS with squashed owners, SMB and shared FUSE mounts report
   owners and modes that cannot be checked, and an inherited ACL may let others open the file before it is unlinked.
   Only ciphertext is spooled, so what could leak is ciphertext that is already in the archive.
2. **The unlink race.** In a shared writable directory without a sticky bit another user can move the spool away
   and put their own file under its name between our identity check and our `unlinkat`; we then remove their file.
   After the unlink the portable path requires the spool name to be gone (`ENOENT`) and our descriptor to have no
   links left, so the read fails with `UnsupportedIdentity` instead of continuing; the only exceptions, detected with
   `fstatfs`, are NFS, where an unlinked open file keeps one `.nfsXXXX` silly-rename link until it is closed, and
   FAT/exFAT, which have no link counts (always 1); there the absent spool name is the only evidence, so a spool moved
   away under another name goes unnoticed.
   What portability cannot prevent: the other user's file is gone, and our ciphertext stays under whatever name it
   was moved to.
3. **Inode identity of the held descriptor.** exFAT renumbers an inode once its name is unlinked, so after the unlink
   portable checks of our own descriptor compare the device only.

## Bulk publication for many small files

`Publication::Bulk` (`EncryptedReadOverrides::publication`, `EncryptedReadOptions::with_publication`) is for archives
of many small files, where per-member staging dominates: native staging creates and removes a probe file and a
private directory and makes two renames per member, and the portable stage flushes every file.

Under `Bulk` every member takes the portable stage (a 0600 temp file in its target directory, one rename) **without**
the per-file flush, and when the run ends every directory it published into (and each directory between it and the
destination root) is flushed once with `fsync`/`fdatasync`. `StagedStorage::NativeOnly` takes precedence and keeps
native staging. Everything listed under "What both backends keep" still holds: containment, held parents, target and
overwrite checks, source checks, and publication only after full verification (CRC or AES HMAC).

What `Bulk` gives up, beyond the portable list above:

1. **File data durability.** No file is flushed before or after its rename. After a power loss or kernel crash a
   published name can point at an empty or partly written file, on any filesystem; a process crash loses nothing.
   Callers that need per-file durability keep the default `Publication::Staged`.
2. **Ordering until the run ends.** Directory entries are flushed only at the end of the run, so after a crash a
   name may be missing, or present while an earlier name is not.
3. **macOS strength.** `fsync` on macOS flushes to the drive, not through its cache (`F_FULLFSYNC` is not used), so
   even the final directory flush is weaker than on Linux.
4. A directory flush that fails ends the run with a `ReadFault::Io { operation: Flush }` after the files are already
   published.
