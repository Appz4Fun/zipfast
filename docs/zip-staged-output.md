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
5. **Cleanup by identity.** Native removes a stage only when its identity still matches. Portable removes the stage
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
