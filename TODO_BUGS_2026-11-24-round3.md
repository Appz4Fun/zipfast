# TODO bugs: round 3 (2026-11-24)

Codex findings on the round-2 fix PR #280 (src/sevenzip/run.rs, the pending-link check added for A2). One group,
branch bugs-round3. Each item: a test that fails without its fix; reply on the thread naming the fix PR; resolve.

| # | PR | Thread | Where | Sev | Status |
|---|---|---|---|---|---|
| C1 | #280 | PRRT_kwDOVi_ME867Zspn | src/sevenzip/run.rs:1057 | P2 | fixed (this PR) |
| C2 | #280 | PRRT_kwDOVi_ME867Zspv | src/sevenzip/run.rs:1057 | P2 (= follow-up F2) | fixed (this PR) |

- **C1** Pending links are tracked by archive name (`staged.link`), not by output path (`staged.place.path`). With
  `Overwrite::RenameNew` and an existing destination directory `s`, a solid folder with link `s` then `s/new.txt` renames
  the link to `s_1`, yet `s/new.txt` is rejected although its parent is still a real directory (this extracted before
  #280). Record the destination-relative output path chosen by `check_target` when reserving pending link paths.
  Test: exactly that case; `s/new.txt` extracts, the link lands at `s_1`.
- **C2** With the default `refused_link_placeholder: false`, link `s -> ../outside` then `s/new.txt` now rejects the
  file only because `s` was staged, but `publish` refuses that link via `refusal_before_place` without creating
  anything at `s`. Only add a staged link to `pending_links` when it will actually occupy its path (it will be placed, or
  it is refused and a placeholder will be written). Test: placeholder off: the link fails alone and `s/new.txt`
  extracts into a real directory `s` (pre-#280 behaviour); placeholder on: unchanged from #280 (`s` is an empty file and
  `s/new.txt` fails alone).
