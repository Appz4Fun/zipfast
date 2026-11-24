# Orchestrator tracker: executing docs/implementation-plan.md

Mode (user, 2026-11-24): at most 3 parallel agents, conservative model (sonnet, low effort). Each WP agent opens a PR
with `@codex review`, then squash-merges itself (no CI, no review gate). After a whole wave merges: collect every Codex
comment on that wave's PRs into `TODO_BUGS_<date>.md` (repo root on a branch), fix them all in one batch, and the
bug-fix PR gets a cleanroom review (independent fresh-context agent given only the diff + TODO list) before merge.
Worker rules: WORKER-RULES.md in this folder. Per-WP notes: WP-<id>.md in this folder and docs/handoffs/ on each branch.

Main at start: 67b0a9d (plan merged in #254, #246 merged).

## Waves (3 agents each)

| Wave | WPs | State |
|---|---|---|
| 1 | A1 (Linux hole cost, branch hole-cost-linux exists with WIP commit 12f8c89), A2 (7z hole cost), A3 (solid stream sink) | started 2026-11-24 |
| 1-bugs | TODO_BUGS from wave 1 PRs | |
| 2 | A6 (.zip.001 map), B0 (compat triage), C1 (flaky tests) | |
| 2-bugs | | |
| 3 | B1a (tar writer core), B2 (later RAR volume), B3 (long passwords) | |
| 3-bugs | | |
| 4 | A4 (7z checkpoints, after A2), B4 (ZIP rename), B5 (in-run rename) | |
| 4-bugs | | |
| 5 | B1b (sparse tar write), B1c (encoders), B6 (-slt fields) | |
| 5-bugs | | |
| 6 | A7 (deflate resync), B7 (old items), C4 (PR #227) | |
| 6-bugs | | |
| 7 | C2a, C2b (RAR5 speed), B9.x from B0 | |
| 8 | C2c, C2d, A5 (only if RustyGet wants it) | |
| skipped unless approved | B8 (WIM LZMS), C3 (32-bit) | |

## Log
- 2026-11-24: wave 1 launched (A1 branch hole-cost-linux, A2 branch feed-7z-hole-cost, A3 branch solid-stream-sink), sonnet/low.
- WP-A2 merged #255 00c31bb: no decoder change (catch-up decode is inherent: liblzma loop on stalled tail, redecoded 0); docs + count-based test. Idea left: decode independent blocks in parallel after a repair.
- WP-A3 merged #256 7d74fe3: SolidStreamSink (src/partial/solid_sink.rs). 7z path proven for output but read_earlier unused there (7z re-decodes from last state reset; WP-A4 territory).
- WP-A1 merged #257 7dc9f93: grouped encrypted refills; ~2-7 ms/refill with group_holes+group_refills on Linux, ungrouped floor ~100-200 ms/hole (syncs x 5ms fsync). Idea left: dir sync only for new journal files. Wave 1 complete.
- Wave 1 bug sweep: 4 Codex findings -> zipfast-bugs1/TODO_BUGS_2026-11-24.md (branch bugs-wave1); fix agent launched; cleanroom review before merge.
- Wave 2 started early in the free slots (no file overlap with bugs-wave1): A6 (zip-byte-split-map), C1 (test-work-counters). B0 next when a slot frees.
- WP-C1 merged #258 4210373: src/work.rs thread-local counters; set_identity, repack, iso9660, cpio tests count work. seven_zip_stdout test not found on main. B0 launched (compat-triage).
- WP-A6 merged #259 64a4ec7: MemberMap maps .zip.001 per piece (src/map/zip_byte_split.rs); live_feed workaround removed. Gaps: missing middle piece read as end of set; first piece <4 bytes NotArchive.
- bugs-wave1 PR #260 (b051cf7) fixes all 4; all 4 threads replied+resolved. Cleanroom review agent launched.
- WP-B1a merged #261 94f3854: zipfast::tar::write TarWriter (gnu/ustar/pax), 5 fixtures byte-identical to GNU tar 1.35. Wave 3 = B1a, B2, B3. B2 launched.
- WP-B0 merged #262 3f23215: docs/validation/compat-gaps.md (Prybar no reply; based on 11-22 list). Most groups fixed (Z1-5,7 via #222/#224/#232). Proposed B9.1 Prybar re-run (S, Prybar-side), B9.2 opt-in keep partial output on failed member (M, deliberate diff, confirm), B9.3 confirm .z01/.zip.001 -so + P8 (S). Wave 2 complete.
- bugs-wave1 #260 cleanroom APPROVE; merged 60a16a5 (+ doc nit). Wave 1 closed. Wave 2 bugs: 5 findings (#258 x1, #259 x4) -> zipfast-bugs2/TODO_BUGS_2026-11-24-wave2.md, fix agent running. B3 launched.
- bugs-wave2 PR #263 (27187b5) fixes all 5; threads replied+resolved. Cleanroom review launched.
- bugs-wave2 #263 cleanroom APPROVE; merged. Wave 2 closed. A4 launched (wave 4).
- WP-A4 merged #265 e9a467c: restart points at state resets with read_earlier-backed dictionary; later repairs wait on shared missing bytes. 13-20 MB -> 1 MB redecoded (20 repairs). Single-block folders still decode from start (liblzma state not exposed). Wave 4 = A4, B4, B5. B4 launched.
- WP-B3 merged #264 4b2ff51: RAR passwords truncated to 127 chars (RAR4+5, -p/-hp, verified with rar 6.24/7.20 + unrar 7.30). Also fixed: RAR4 KDF SHA-1 quirk for passwords >= 29 chars (Sha1::update_rar), RAR4 astral chars hashed as low 16 bits (may break WinRAR-on-Windows astral RAR4 passwords; decision documented in docs/rar-passwords.md). Flake seen once: zip_checked_cli actual_binary_socket_write_failure_has_no_listing_fallback. B5 launched.
- WP-B5 merged #266 7f31f56: StartDecision::RenameTo (tar, lone compressed, legacy ZIP, 7z, RAR runs). Checked ZIP route fails the member (not supported); RarSession selection has no start hook. StartDecision no longer Copy (breaking). Mutation check NOT done (cover in wave-4 bug sweep). B1c launched (wave 5).
- WP-B1c merged #267 f076965: Compression enum + CompressedWriter (gzip/bzip2/xz/zstd, existing deps). gzip header/trailer byte-exact vs gzip 1.13, deflate body differs (zlib vs GNU deflate); all decode to exact tar. B1b launched.
- WP-B1b merged #268 849ec2a: sparse entries (GNU 'S' + pax 1.0), byte-identical vs GNU tar 1.35; sparse_pid option. A7 launched (wave 6).
- WP-A7 merged #269 4e045ac: deflate stored-block restart after a lost hole (count pass, unproven until CRC/AES, refute -> fallback; refuted case writes bytes twice, documented). One restart at a time; snapshot drops open restart. B7 launched.
- WP-C4: external PR #227 (7z map missing middle volume tests) verified on main and squash-merged.
- WP-B7 merged #270 be51e0d: P8 fixed for tar/legacy ZIP/7z/RAR4 (checked ZIP route still refuses; documented); flatten quirk not reproducible (tests+docs); temp-cleanup helper not done (RunObserver lacks staged dev/ino). Wave 6 complete (A7, B7, C4). Wave 5 complete minus B6 (moved to wave 7). Sweeping waves 5+6 now.
- B6 launched (listing follow-ups: rar5 crypt flags, .zip.001 missing middle piece listing, pax .tgz listing metadata) as wave 7 start.
- WP-B6 merged #271 e17481b: all 3 follow-ups already in #164; tests pinned to 7zz 26.06 output. Remaining -slt mismatches need Prybar's list. C2a launched.
- WP-C2a #272 53b0808 docs-only: Huffman decode already has 11-bit LUT, bulk refills, SIMD literals; 10/12-bit within noise or slower. Next: C2b-d combined measurement agent with larger data.
- B2 merged #275 32df9d3, B4 merged #274 d07f5dd, C2bcd #273 docs-only (decode_rest 94-97%, nothing else >3.4%). All planned WPs done; A5/B8/C3/B9.x need decisions. Final sweep of waves 3-7.
- Final sweep (waves 3-7): 12 findings + #269 pending -> zipfast-handoffs/TODO_BUGS_2026-11-24-waves3-7.md. 3 fix agents: X tar (bugs-tar), Y extract/volumes (bugs-extract), Z lzma2+rewrite+#269 (bugs-feed-rewrite). Each PR gets a cleanroom review before merge.
- Group X #276 cleanroom APPROVE; merged.
- Group Y #277 (c6350d7) fixes Y1-Y5; cleanroom review launched.
- Group Y #277 cleanroom APPROVE; merged. Follow-up F1 recorded in TODO file.
- Group Z #278 (1181baf) fixes Z1, Z2; #269 reviewed by Codex: no findings. Cleanroom review launched.
- Group Z #278 cleanroom APPROVE; merged. All waves and sweeps done.
- Round 2 sweep: 7 late Codex findings (#240 x3, #246, #252, #257, #276) -> TODO_BUGS_2026-11-24-round2.md; groups R1 (bugs-round2-a) and R2 (bugs-round2-b) launched.
- R2 #279 (67e2aa2) fixes B1-B3; threads resolved; cleanroom launched.
- R2 #279 cleanroom APPROVE; merged.
- R1 #280 (433578c) fixes A1-A4; threads resolved; cleanroom launched.
- R1 #280 cleanroom APPROVE; merged. Follow-up F2 recorded. Round 2 done.
- Round 3: 2 Codex findings on #280 (7z pending-link check; C2 = F2) -> TODO_BUGS_2026-11-24-round3.md; fix agent launched (bugs-round3).
- Round 3 #281 (3ecd247) fixes C1, C2; threads resolved; cleanroom launched.
- Round 3 #281 cleanroom APPROVE; merged. F2 resolved by C2.
