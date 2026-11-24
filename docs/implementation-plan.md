# zipfast: remaining work, spec and execution plan

Status as of 2026-11-24 (main `b6d9a0b`). This document is written to be handed to an orchestrator model
that splits the work across worker models. Every work package (WP) below is self-contained: goal, spec,
files it may touch, dependencies, acceptance tests, definition of done and an estimate.

Consumers, in priority order:

1. **RustyGet** (Usenet/NZB downloader; live extraction and repair speed). Highest priority.
2. **Prybar** (7-Zip / UnRAR / GNU tar / unzip compatible CLI built on zipfast). Second priority.
3. Internal quality: flaky tests, performance, portability.

---

## 1. What is already done (do not redo)

| Area | State | Where |
|---|---|---|
| Feed decoder (bytes arrive out of order, `NeedBytes`, holes, repairs, snapshots) | Stored, AES, RAR5, RAR4, 7z LZMA2, ZIP stored/Deflate/Deflate64/ZipCrypto/WinZip AES | `src/map/feed*`, `docs/feed-decoder.md` |
| Solid members after the first | RAR5 (`next_solid`, `SolidCarry`/`resume_solid`), RAR4, 7z folders | #239, #240, #241 |
| Persistent partials | Session path, direct path (`DirectPartials`, `DirectSink`), restart cursor for every feed container, `PartialLimits::for_members` | `src/partial/`, `docs/persistent-partials.md` |
| Partial-path speed | Exclusion lstat cache (#250), macOS deferred `F_FULLFSYNC` (#248), group holes/refills (#228) | |
| Parallel LZMA2 decode | Memory-bounded, `malloc_trim` on glibc, worker panic surfaces as an error | `src/sevenzip/lzma2_par.rs` |
| Container rebuild, open_at, RAR5 resync/handover, CBC rebuild | Done | `docs/container-rebuild.md`, `docs/open-at.md`, `docs/rar5-resync.md`, `docs/cbc-rebuild.md` |
| Link safety and compat | `PreexistingLinks::{FollowInside, Refuse}`, `refused_link_placeholder` | `docs/compat-options.md` |
| Review hygiene | Every Codex review thread on merged PRs replied to and resolved | |
| Reference integration | `examples/live_feed` (RustyGet live path simulator, TSV output) | `docs/feed-decoder.md` |

---

## 2. Ground rules for every worker (non-negotiable)

These come from the user and from incidents in earlier sessions. The orchestrator must paste this section into
every worker prompt.

1. **One git worktree per WP**, created from `origin/main`: `git worktree add -b <branch> ../zipfast-<wp> origin/main`.
   Work only there. Set `CARGO_TARGET_DIR=<worktree>/target` and **delete it when done**. The Mac disk is often
   above 95% full; check `df -h /` before large builds, and stop if under 20 GB free.
2. **Never use `git stash`.** The stash list is shared by all worktrees; workers have popped each other's work.
   Commit work in progress to the WP branch instead.
3. **License:** RPL-1.5. Write code from scratch unless the source is MIT. Never copy or derive from unrar source,
   LGPL or Apache-only code (UnRAR/7-Zip behaviour may be observed by running the binaries in
   `~/prybar-refs/compat/bin`, never by reading their source).
4. **Build hosts:** `ssh server` (Linux i7-8700K, Coffee Lake): build only under `~/zf-bench/<wp>`; wrap builds in
   `flock -w 120 -x /tmp/i7-heavy.lock` with `CARGO_BUILD_JOBS=3`, and every timing run in
   `flock -w 120 -x /tmp/nzbget-rust-benchmark.lock`. Never touch port 6789. `ssh m5air`: never touch the live
   RustyGet process on port 6791; keep runs bounded.
5. **Tests prove fixes:** every bug fix gets a regression test that fails without the fix. Check this by
   reverting the fix, `touch`ing the file, rebuilding, and running the test (a stale build once hid a failure).
   Run feed and decoder tests in **debug and release** (debug catches integer overflow).
6. **Avoid wall-clock assertions** in tests; count work instead (several flaky tests came from timing under load).
7. **Commit message** ends with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. PR body ends with
   `🤖 Generated with [Claude Code](https://claude.com/claude-code)`.
8. **Workers never merge.** They open a PR against `main`, comment `@codex review`, and handle review rounds.
9. **Review threads:** for each Codex thread: fix it (with a test) or explain why not, reply on the thread, then
   resolve it (`gh api graphql -f query='mutation{resolveReviewThread(input:{threadId:"ID"}){thread{isResolved}}}'`).
   Target: zero unresolved threads on the repo (`python3 ~/git.xbmc4lyfe/review-sweep/unresolved.py Appz4Fun zipfast`).
10. **Public API changes:** adding a field to `extract::Options` breaks full struct literals for consumers. Update
    every in-repo literal and say so in the PR body. Prefer builder or `Default`-based additions where possible.

### 2.1 Merge gate (orchestrator or senior model only)

A PR merges only when all hold, on the **exact head** being merged:

- Codex review shows no unresolved findings (re-anchored, already resolved threads are fine).
- Zero unresolved review threads on the PR.
- Branch is current with `origin/main` (rebase, then re-review if the rebase was not trivial).
- Full local CI passes 7/7 (GitHub Actions are offline): `fmt --check`; `clippy -D warnings` with and without
  `--features persistent-partials`; `cargo test --workspace --all-targets --locked` with and without the feature;
  doc tests with and without the feature. Scripts: `scratchpad/localci.sh` and `scratchpad/ci-pair.sh`
  (rebases onto main in a scratch worktree, then runs CI).
- Merge with `gh pr merge <n> --squash --delete-branch --admin`.
- For compat-affecting PRs (links, names, overwrite, exit behaviour), Prybar runs its comparison harness
  (`linkdiff` / `check-compatibility.py`) on the head and signs off.
- After merge, notify the consumer (RustyGet or Prybar) with the merge hash.

Because `main` moves often, merge in the order given by the lanes below. When two PRs touch the same module,
merge the smaller first and rebase the other.

---

## 3. Work packages

Estimate key: **S** = up to 4 worker-hours, **M** = 4 to 12, **L** = 12 to 30, **XL** = over 30.
Review and CI add roughly 1 to 3 hours of wall clock per PR on this machine (full CI is 35 to 40 minutes under load).

### Lane A: RustyGet (highest priority)

#### WP-A1: Linux per-hole cost in persistent partials (RustyGet item 4) — M
- **State:** a worker started on branch `hole-cost-linux` (worktree `../zipfast-holecost`); it stopped at a usage limit
  while extending `examples/persistent_holes_bench.rs` to take an existing set, a password, explicit holes and
  several members. Resume from that branch.
- **Goal:** cut the per-hole cost on Linux (Prybar measured about 12 ms/hole, mostly the session write path plus
  refill) for both the session path (`refill_from_packed`, as RustyGet uses it) and `DirectSink`.
- **Spec:** measure first on `ssh server` (ms per hole, ms per refill, `durable_sync_count`, `ordering_sync_count`,
  `exclusion_lstat_count`, MetadataBytes per hole). Then remove per-hole syncs and ledger rewrites that are not
  needed for crash safety. Candidates: `fdatasync` where file metadata is unchanged; holes recorded inside the
  open group commit; avoiding a full ledger rewrite per hole; cheaper refill verification. Crash-loss guarantees
  must not get worse; document any change.
- **Files:** `src/partial/**`, `examples/persistent_holes_bench.rs`, `docs/persistent-partials.md`.
- **Acceptance tests:**
  - Bench numbers before and after on Linux, for F01 and F11 (z-fixtures `~/rustyget-requests/z-fixtures/sets`)
    and a generated 1 GiB stored set with 64 holes. Target: under 3 ms per hole, or a written explanation of the floor.
  - Crash test: kill the process (`abort()` in a child) at each new sync point; reopen; durable state is
    consistent; loss is at most the open group.
  - The existing suites `tests/persistent_partials*.rs` and `tests/persistent_direct.rs` pass.
  - macOS numbers not worse (re-run `persistent_holes_bench` locally).
- **Depends on:** nothing. **Conflicts with:** WP-A3, WP-A5 (both touch `src/partial/`): run A1 first, or keep
  A3 and A5 out of `src/partial/mod.rs` until A1 merges.

#### WP-A2: 7z (LZMA2) per-hole cost (36 to 156 ms per hole) — M
- **Goal:** Prybar's `live_feed` bench shows each 7z hole costing 36 to 156 ms, and compressed sets stalling on
  every hole until its repair arrives. Find and cut the avoidable part.
- **Spec:** profile `examples/live_feed` on F07, F08, F10 with `--drop 0.02/0.05`. Likely costs: re-walking chunk
  headers from the folder start after each stall, rebuilding the decoder or dictionary from held output on resume,
  re-reading released bytes. A whole lost 750 KB article always hides LZMA2 chunk headers, so waiting is correct;
  the cost of resuming after the repair is the target. Keep the framing rule: chunk boundaries only from a
  header walk, never from plaintext matches.
- **Files:** `src/map/feed/lzma2.rs`, `src/map/lzma2*` (index), `examples/live_feed`.
- **Acceptance tests:**
  - `live_feed` on F07/F08/F10, drop 2% and 5%, lateness 8: ms per hole before and after, output exact, CRC ok,
    each byte written once (existing harness checks these).
  - `stats.redecoded` does not grow; `tests/feed_decoder_7z.rs` and `tests/feed_decoder_z.rs` pass in debug and release.
- **Depends on:** nothing. **Conflicts with:** WP-A4 (same file). Run before A4.

#### WP-A3: Multi-member held-output sink for `resume_solid` — S/M
- **Goal:** `FeedDecoder::resume_solid` (RAR5 solid member started from a `SolidCarry` in a later process) needs a
  sink whose `read_earlier(stream_offset, buf)` returns earlier members' output at solid-stream offsets.
  `DirectSink` covers one member only, so RustyGet cannot restart a solid RAR5 member from persistent output today.
- **Spec:** add a `SolidStreamSink` (name open) that wraps the `DirectPartials` members of one solid stream and
  maps stream offsets to (member, offset) via `MapMember` sizes and `stream_start()`. `write_at` goes to the
  current member; `read_held` and `read_earlier` read durable output of any earlier member. Also usable for
  7z folders (folder offsets).
- **Files:** new `src/partial/solid_sink.rs` (or in `src/partial/direct.rs`), `docs/persistent-partials.md`,
  `docs/feed-decoder.md`.
- **Acceptance tests:**
  - Three-member solid RAR5 (plain and AES), persistent: decode member 0 and 1, drop all handles (simulated
    restart), reopen, `resume_solid` member 2 from a serialized `SolidCarry` using the new sink: exact output, CRC
    ok, `stats.redecoded == 0`.
  - The same with a hole in member 1 repaired after restart: member 2 stays `unproven` until proven.
  - 7z three-member folder through the same sink.
- **Depends on:** nothing (uses merged #239 to #243). **Conflicts with:** WP-A1 (`src/partial/`): keep to a new file.

#### WP-A4: 7z repair re-decode in single-reset folders — M
- **Goal:** in a 7z folder whose dictionary resets only at its start, each repair re-decodes from the restart
  point before its hole, possibly in an earlier member (up to about 1.1 MB per repair in tests).
- **Spec:** keep checkpoints (chunk start plus dictionary, using held output) at bounded intervals while decoding
  (for example every 1 to 4 MiB of output, only where the sink holds the dictionary), so a repair restarts from
  the nearest checkpoint before its hole. Bound the checkpoint memory.
- **Files:** `src/map/feed/lzma2.rs`.
- **Acceptance tests:** `tests/feed_decoder_7z.rs` single-reset folder case: per-repair `stats.redecoded` at most one
  checkpoint interval (currently up to 1.1 MB); snapshot/restore still works; debug and release.
- **Depends on:** WP-A2 merged (same file).

#### WP-A5: One commit (CAS) covering several members — M/L (optional, ask RustyGet first)
- **Goal:** at about 100 syncs per member, a member boundary still costs about 4 flushes and a group about 2.
  One anchor CAS covering several members' group commits would cut this further on macOS.
- **Spec:** split `flush_group` around the CAS in `src/partial/mod.rs` so a session-level group flushes all dirty
  members' data and pages, then issues one barrier and one CAS. Keep per-member recovery semantics.
- **Acceptance tests:** 2 GiB / 40-volume bench: durable syncs per member drop; crash tests at each barrier lose at
  most the open group across all members; all persistent suites pass.
- **Depends on:** WP-A1 merged. Confirm RustyGet still wants it (its own `DurableAnchors` store costs 2
  `F_FULLFSYNC` per CAS, more than zipfast now; that fix is on RustyGet's side and documented).

#### WP-A6: Split ZIP by bytes (`.zip.001`) in `MemberMap` — S/M
- **Goal:** the feed decoder handles ZIP, but `MemberMap` does not map byte-split `.zip.001` sets; callers must
  concatenate the pieces first.
- **Spec:** map a byte-split set as one logical volume made of pieces, giving per-piece `(volume, range)` in
  `NeedBytes` and member parts. Reuse `src/zip/byte_split.rs` detection.
- **Files:** `src/map/**` (ZIP mapping), `examples/live_feed` (drop the concatenation workaround), `docs/member-map.md`.
- **Acceptance tests:** `tests/feed_decoder_zip.rs` byte-split case without concatenation: needs name the right
  piece; exact output; `live_feed` per-piece article cutting.

#### WP-A7: Deflate stored-block resync (optional) — M
- **Goal:** after a hole in a Deflate member, restart at a later stored block when one can be proven
  (LEN/NLEN check plus the member CRC at the end), instead of always waiting.
- **Spec:** output after a heuristic restart is `unproven` until the CRC passes; never claim verified early.
  Only stored blocks (no Huffman resync).
- **Files:** `src/map/feed/zip*.rs`, `src/inflate64/`.
- **Acceptance tests:** a Deflate member made with stored blocks (zlib level 0 sections) with a hole: decoding
  continues after the hole, lost range reported exactly, repair fills it, CRC ok; a crafted false LEN/NLEN match
  is rejected or marked unproven and then fails over to waiting.

#### WP-A8: RustyGet integration feedback (H-series) — open-ended
- RustyGet is wiring `next_solid`, `SolidCarry`, `DirectPartials` and the feed decoder into its download
  priority loop and will report API changes. Reserve one worker for quick follow-up PRs when that arrives.

### Lane B: Prybar compatibility

Baseline (last reported by Prybar, before today's merges): UnRAR-reference run cases 863/981 (88%), password cases
78/102 (76%), UnRAR `lt` 43/46, UnRAR `slt` 492/492, 7-Zip `l -slt` 410/420, GNU tar 351/351, 7-Zip-mode link
cases 136/246 (55%; the rest are mostly deliberate refusals). Target: 100% on everything that is not a documented,
deliberate safety difference.

#### WP-B0: Compat triage (do first; feeds B-lane sizing) — S
- **Goal:** get the current failing cases from Prybar on current main and group them by zipfast cause.
- **Spec:** ask the Prybar session (agent relay) for `check-compatibility.py` output on zipfast main; read
  `~/rustyget-requests/prybar-mismatch-list-20261122.md` (groups Z1 to Z7) and mark which are fixed (Z1 7z `-so`,
  Z3 tar devices, P3 fallback mtime, P4, P6 were done in #232 and earlier). Produce
  `docs/validation/compat-gaps.md`: one line per remaining case group, cause, owning module, size.
- **Output:** a list the orchestrator turns into WP-B9.x packages.

#### WP-B1: Public streaming tar writer, GNU tar 1.35 byte-exact — L/XL
- **Goal:** Prybar's GNU tar mode refuses `-c` until zipfast has a public tar writer.
- **Spec:** streaming writer (`Write` sink) with ustar, GNU `././@LongLink`, pax headers, hard and symbolic links,
  devices and FIFOs, sparse files (GNU and pax 1.0), behind streaming gzip, bzip2, xz and zstd encoders. Defaults
  byte-exact with GNU tar 1.35: `--format=gnu`, mtime/uid/gid/uname/gname from stat, `--owner/--group/--mtime/
  --numeric-owner`, `-b 20` (10240-byte records). Optional: public block-level tar walker. The only writer today is
  private in `src/repack/tarball.rs`; reuse its pieces, keep repack working.
- **Files:** new `src/tar/write*.rs` (or `src/tar_write.rs`), encoders under `src/stream/`, `docs/tar-writer.md`.
- **Acceptance tests:** for a fixture tree (long names, links, devices if root is not needed via fakeroot-free
  synthetic stat, sparse file, unicode names): archive bytes identical to `gtar --format=gnu -b20` output with the
  same options (generate references once with GNU tar 1.35 in docker and commit them); round-trip through
  zipfast's own tar reader; each compressor's output decompresses with the system tool. Parallelism: split into
  B1a (core ustar/GNU/pax writer), B1b (sparse), B1c (encoders: gzip/bzip2/xz/zstd, each independent).

#### WP-B2: Start extraction from a later RAR volume (mismatch Z6) — M
- **Goal:** UnRAR can start from `.part3.rar` and extract members that begin there; zipfast refuses or needs vol 1.
- **Spec:** open a set from a later volume: catalogue members whose headers start in the given and later volumes;
  report continued members (split from earlier volumes) as UnRAR does. Match UnRAR 7.30 output and exit code on
  the reference corpus.
- **Files:** `src/rar5/session*`, `src/progressive/*` (volume admission), RAR4 equivalents.
- **Acceptance tests:** the two Z6 cases from the mismatch list match UnRAR exactly (tree, messages Prybar maps,
  exit code); RAR4 and RAR5.

#### WP-B3: Long RAR passwords (127-char limit) — S
- **Goal:** UnRAR 7.30 refuses RAR5 passwords over 127 characters (MAXPASSWORD 128) and likely truncates;
  zipfast hashes the whole password.
- **Spec:** determine behaviour by running the binaries only (rar/unrar in docker, `~/prybar-refs/compat/bin`):
  make archives with 127-, 128- and 200-character passwords and see which passwords open them; RAR4 too. Match it.
- **Acceptance tests:** fixtures for each length (generated, committed); open/refuse matches UnRAR for RAR4 and RAR5.

#### WP-B4: `RewritePlan::rename` for ZIP (`7z rn` parity) — M
- **Spec:** rename an entry keeping member data byte-for-byte: rewrite local and central names, keep CRC and
  sizes, handle the Info-ZIP Unicode path extra (0x7075) and the UTF-8 flag, data descriptors, ZIP64.
- **Files:** `src/zip/rewrite.rs`, `docs/zip-rewrite.md`.
- **Acceptance tests:** rename in plain, ZIP64, data-descriptor and Unicode-extra archives; `7z t` and `unzip -t`
  accept the result; untouched members byte-identical (compare raw data ranges); `7z rn` output byte comparison
  where 7-Zip is deterministic.

#### WP-B5: Rename the output inside a run (mid-run "Auto rename") — M
- **Goal:** when a 7-Zip "Auto rename" answer arrives mid-run, Prybar restarts extraction, so hard links and RAR5
  file copies cannot reach targets written before the restart.
- **Spec (preferred option a):** let the start hook return a decision that renames this member's output path
  within the current run (e.g. `StartDecision::RenameTo(path)`), validated like any output path; the run's own
  link records then resolve naturally. Fallback (b), only if (a) cannot cover a case: accept earlier target records
  (name → path, dev/ino) carried into a new run.
- **Files:** `src/extract.rs`, `src/extract/rename.rs`, `src/extract/link.rs`, RAR session selection paths.
- **Acceptance tests:** tar hard link and RAR5 file copy whose target was renamed by the hook mid-run resolve to
  the renamed file; protected-path and escaping rules still apply; Prybar comparison harness unchanged elsewhere.

#### WP-B6: 7-Zip `l -slt` remaining fields (10 of 420 left) and listing follow-ups — S/M
- **Spec:** finish the remaining `-slt` mismatches (ask Prybar for the current list). Known follow-ups:
  `rar5_crypt_record` doc (7-Zip prints flags even when 0); `.zip.001` with a missing middle piece should list
  members before the gap (7-Zip does) instead of failing open; pax `.tgz` compressed-tar listing metadata
  (uid/gid/user/group/pax/magic).
- **Acceptance tests:** Prybar `-slt` corpus 420/420 or documented exceptions.

#### WP-B7: Remaining old Prybar items to verify — S each
- **P8:** inspect_target accepts a symlink whose (dev, ino) matches a link this run placed, and replaces it by
  rename (RAR4 too). Verify whether #247/#252 already cover it; if not, implement.
- **Flatten quirk:** on the checked ZIP route with flatten (`e`), `MemberFilter::on_start` reports the stored path,
  not the flattened one, so skip-existing may test the wrong path (repro: existing `./b.txt` plus a ZIP with
  `dir/b.txt`, `e` with skip-existing should skip). Verify, fix with a test.
- **Temp cleanup after SIGKILL (low):** optional helper that removes `.zipfast-*` temps whose dev/ino the caller saw
  zipfast create (from `RunObserver` events), never by name alone.

#### WP-B8: WIM LZMS and split `.swm` — L (low)
- LZMS has no public specification; only do this from clean-room behaviour (decompress outputs of real tools to
  derive the format) if the user approves. Split `.swm` sets without LZMS are smaller (M).

#### WP-B9.x: Cases from WP-B0 triage — sized after B0.

### Lane C: Quality, performance, portability

#### WP-C1: Replace wall-clock test assertions with work counters — S
- **Targets:** `tests/set_identity.rs::many_members_match_in_linear_time` (ratio of times; failed under load),
  `seven_zip_stdout_reads_many_members_from_one_session` (60 s limit), `tests/repack.rs` bsd symbol test (relaxed
  to 600 s in #221). Count operations through an internal counter instead.
- **Acceptance:** tests pass under `stress-ng`-style load (run 3 copies of the suite at once) without timing flakes.

#### WP-C2: RAR5 decode speed (Prybar profile on Coffee Lake) — M/L
- **Profile** (F05 `-m5` about 763 MB/s, F03 `-m3` about 1030 MB/s): Huffman decode about 35% (F05), `Huff::build`
  10.9% (F03), `Win::write` memcpy 6.5 to 9% (decode literals straight into the window), per-run fixed cost 3 to 5%
  (munmap/memset/thread spawn/probe). The x86 CRC32 change gave little; do not repeat it.
- **Rules:** SIMD allowed with runtime dispatch; floor is Coffee Lake (AVX2, no AVX-512) and Apple M4; forced-path
  tests for each code path; AVX-512 paths need Intel SDE correctness tests; bench-proven only.
- **Acceptance:** byte-identical output on all RAR5 fixtures and z-fixtures; MB/s before and after on `ssh server`
  (under the bench lock) and the M4; no regression on any fixture.
- Parallel split: C2a Huffman decode table, C2b `Huff::build`, C2c window literal writes, C2d fixed per-run cost.

#### WP-C3: 32-bit build (low) — S
- `libc::stat` time fields are `i32` on i686; `src/guard.rs:64..67` and `src/zip/session.rs:1066..1067` assume i64.
  Only if a consumer needs 32-bit. Acceptance: `cargo check --target i686-unknown-linux-gnu` in docker.

#### WP-C4: External PR #227 (7z map edge-case tests from another contributor) — S
- Review it, run CI, ask the author for changes or merge. It only adds tests.

---

## 4. Dependency graph and parallel lanes

```
Lane A (RustyGet)          Lane B (Prybar)              Lane C (quality)
-----------------          ---------------              ----------------
A1 Linux hole cost  ─┐     B0 triage ──► B9.x           C1 flaky tests
A3 solid sink (new  │     B1a tar core ─┐              C2a..d RAR5 speed (4 parallel)
   file, parallel)  │     B1b sparse  ──┤► B1 merge    C3 32-bit (low)
A2 7z hole cost ──► A4    B1c encoders ─┘              C4 PR #227
A6 .zip.001 map            B2 later volume
A7 deflate resync          B3 long password
A1 ──► A5 (optional)       B4 zip rename
A8 (on demand)             B5 in-run rename ──► B7 P8 check
                           B6 -slt fields
```

**File-ownership conflicts** (do not run these in parallel without care):

| Module | WPs |
|---|---|
| `src/partial/` | A1, A3, A5 (A3 in a new file is fine) |
| `src/map/feed/lzma2.rs` | A2, A4 (serial) |
| `src/map/feed/zip*.rs`, `src/inflate64/` | A7 |
| `src/map/` ZIP mapping | A6 |
| `src/extract.rs`, `src/extract/link.rs`, `src/extract/rename.rs` | B5, B7 (serial), and any B9.x touching links |
| `src/rar5/session*`, `src/progressive/` | B2, possibly B9.x |
| `src/zip/rewrite.rs` | B4 |
| `src/tar/`, `src/repack/` | B1, B6 (pax listing part) |
| RAR5 decoder (`src/rar5/unpack*`) | C2a..d (split by function; rebase often) |

**Suggested waves** (each wave runs in parallel; up to about 6 workers is what this machine handles, given the
35 to 40 minute full CI and the disk):

- **Wave 1:** A1, A2, A3, B0, B1a, C1.
- **Wave 2:** A6, B1b, B1c, B2, B3, C4 (start as wave-1 PRs move into review).
- **Wave 3:** A4 (after A2), A7, B4, B5, B6, C2a/C2b.
- **Wave 4:** A5 (if RustyGet wants it), B7, B9.x, C2c/C2d, B8 (only if approved), C3 (only if needed).

---

## 5. ETA

Assumes about 6 workers in parallel, one orchestrator doing reviews and merges, Codex review rounds averaging 2 to 3
per PR, and full local CI at about 40 minutes per PR (CI is the serial bottleneck: plan for about 10 PR merges per
day at most).

| Group | Worker effort | Wall clock |
|---|---|---|
| Lane A must-haves (A1, A2, A3, A6) | 2 to 4 days | 2 to 3 days |
| Lane A follow-ups (A4, A7, A5 optional) | 3 to 5 days | 2 to 3 days after A2/A1 |
| Lane B tar writer (B1a to B1c) | 4 to 6 days | 3 to 4 days |
| Lane B other (B0, B2 to B7) | 4 to 6 days | 3 to 4 days |
| Lane B triage cases (B9.x) | unknown until B0; estimate 2 to 5 days | |
| Lane C (C1, C2, C4; C3 if needed) | 3 to 5 days | 2 to 3 days |
| **Total** | **about 18 to 30 worker-days** | **about 1.5 to 2.5 weeks** |

RustyGet's must-haves (A1 to A3, A6) can land within the first 3 days if they start in wave 1.
B8 (LZMS) is excluded from the total: it needs a decision first.

---

## 6. Worker prompt template (for the orchestrator)

```
You are implementing WP-<id> in zipfast (Rust archive library, repo Appz4Fun/zipfast, gh is authenticated).
<paste section 2 "Ground rules">
Create worktree: git worktree add -b <branch> /Users/allen/git.xbmc4lyfe/zipfast-<id> origin/main
Spec: <paste the WP section>
When done: cargo fmt --all; cargo clippy --workspace --all-targets --locked -- -D warnings (also with
--features persistent-partials); the WP's acceptance tests in debug and release; the touched test files.
Commit, push, open a PR against main, comment "@codex review". Handle every review round: fix with a test,
reply, resolve each thread. Do NOT merge. Delete your target dir when done.
Report: PR number, head sha, what changed, test results (with numbers), anything not done and why.
```

Review prompt for a second, independent worker (optional, catches what Codex misses): give it the diff and the WP
spec only, not the implementer's report, and ask for correctness bugs with a failing test sketch for each.
