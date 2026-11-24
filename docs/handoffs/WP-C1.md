# WP-C1 handoff
Status: merging. Branch test-work-counters, worktree /Users/allen/git.xbmc4lyfe/zipfast-c1.
Done: src/work.rs (#[doc(hidden)] thread-local counters: SetIdentitySteps, ArNameBytes, CpioWaitingLinks, IsoFolders);
converted set_identity many_members, repack bsd symbol, iso9660 loop-back folder, cpio waiting links tests to counts.
Mutation-checked set_identity (quadratic loop) and repack (no name cache): both fail.
Not changed: `seven_zip_stdout_reads_many_members_from_one_session` does not exist on main (not found in tests/ or src/).
Remaining Instant uses are liveness guards (poll/wake deadlines in progressive/rar4 drive loops, lzma2 thread
deadlocks guards, cancel promptness) or timing-only prints; they bound hangs, not ratios, so left alone.
Tests: cargo test --test set_identity --test repack --test iso9660 --test cpio (debug + release).
