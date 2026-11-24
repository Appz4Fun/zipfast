# WP-B5: start-hook rename (StartDecision::RenameTo)
Status: merging. Branch: start-hook-rename. Worktree: /Users/allen/git.xbmc4lyfe/zipfast-b5.
Done: `StartDecision::RenameTo(PathBuf)` (relative to dest, plain components); applied in `check_target_detailed`
(tar, lone files, legacy ZIP, 7z, RAR whole-archive). Link records stay keyed by archive name and land at the new path,
so hard links / RAR5 copies resolve. Tests: tests/start_hook_rename.rs (8).
Decisions: the hook is not re-asked for the new name; unsafe name -> member fails (RarPolicyReason::UnsafePath);
checked ZIP route (bound to the entry name) fails the member with a clear reason; RarSession selection has no start
hook, so nothing to do there. StartDecision lost `Copy` (still Clone/Eq).
Run: cargo test --test start_hook_rename --test member_start_hook
