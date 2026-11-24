# Prybar compatibility gaps by zipfast cause (WP-B0 triage, 2026-11-24)

## How this was produced

- The Prybar session (`claude:cecef017...@m4air`) was asked through the agent relay for fresh
  `check-compatibility.py` results and waited on for 15 minutes. It was busy and did not reply, so there is
  **no fresh Prybar run** behind this file.
- Fallback: `~/rustyget-requests/prybar-mismatch-list-20261122.md` (Prybar 800ce03 against zipfast f9a892b,
  groups Z1 to Z7, P1 to P8, A1 to A4, Q1), checked against zipfast main `42103731` by `git log` and the tests.
- A local Prybar build was not attempted. Prybar pins zipfast at 1381746 (after #224), and main has since added
  `extract::Options` fields (#232, #252), so Prybar would not compile against main without Prybar-side changes.
  Also, `check-compatibility.py` stops at its first failing assert and is not the 981-case differential used
  for the list (`run-cases.sh`, `run-pw.sh` live in Prybar's scratchpad).
- Baseline numbers (plan, Lane B): UnRAR cases 863/981, password cases 78/102, `lt` 43/46, `slt` 492/492,
  7-Zip `l -slt` 410/420, GNU tar 351/351, 7-Zip link cases 136/246. The list itself reported 729/981 and 67/102
  at 800ce03, so the plan baseline already includes some fixes.

## 1. Mismatch-list groups owned by zipfast

| Group | Cases | Mode | Expected vs actual | Cause | Owning module | Status | Fixing PR |
|---|---|---|---|---|---|---|---|
| Z1 | 51 | 7z `x -so` on .7z / .7z.001 | 7-Zip exit 0; pry exit 2 "reading one 7z entry on its own" | no 7z single-member read | `src/extract.rs`, 7z session | FIXED | #222 |
| Z2 | 7 | 7z `x -so` on byte-split `.zip.001`, `.z01` sets | 7-Zip exit 0; pry "not a supported archive" | split ZIP not reachable through the projected inspect path | `src/zip` split sets | FIXED (split ZIP entry via SelectedEntry; `.z01` listing/extract in #179, #186). Needs Prybar confirmation on the `.z01` `-so` case | #222 |
| Z3 | 4 | 7z mode, tar device node | 7-Zip writes an empty file, exit 0; pry exit 2 | devices refused | `src/tar.rs` | FIXED, option `Options::special_entries`; Prybar must adopt | #232 |
| Z4 | 9 | UnRAR `lt`, RAR4 `-hp` | `, encrypted headers` missing in Details | `encrypted_headers()` false for RAR4 | RAR4 headers | FIXED | #224 |
| Z5 | 7 | UnRAR l/t/x/e/p on r5extra.rar | UnRAR exit 3 "Main archive header is corrupt"; pry 0 or 10 | RAR5 quick open locator not validated | RAR5 open | FIXED | #224 |
| Z6 | 2 | UnRAR `x` from a later volume | UnRAR restarts from volume 1 (all files); pry extracts only that volume's members | later-volume start not supported | `src/rar5/session*`, `src/progressive/*` | OPEN | planned B2 |
| Z7 | 1 | UnRAR `lt`, RAR 1.5 split-store | `Pack-CRC32` line missing | split piece CRC not exposed | RAR4 headers | FIXED | #224 |

## 2. Groups marked PRYBAR in the list that needed zipfast hooks

| Group | Cases | Expected vs actual | Status | Fixing PR / note |
|---|---|---|---|---|
| P3 | 14 | member with no mtime gets extraction time; 7-Zip/UnRAR use the archive's mtime | FIXED in zipfast: `Options::fallback_mtime`; Prybar must pass it | #232 |
| P4 | 6 | 7z mode on `.tgz` extracts inner members; 7-Zip writes the single `.tar` | FIXED in zipfast: `Options::compressed_tar = Whole`; Prybar must pass it | #232 |
| P6 | 2 | RAR5 versioned files: 7-Zip writes `[VER]/3/name` | FIXED in zipfast: `Options::version_naming = SevenZipDir`; Prybar must pass it | #232 (and #183) |
| P8 | 2 | RAR4 symlink: `e -y` replaces the first link; `p` prints only regular files | UNVERIFIED; zipfast part (accept a link this run placed) may be covered by #180/#252 | planned B7 |
| P2 | 15 | 7z `x`/`e`: 7-Zip keeps the partial or empty file of a failed member; pry removes it | unknown; Prybar says Prybar-owned. Possibly needs a zipfast option to keep a failed member's partial output | see B9.2 |
| P7 | 12 | UnRAR `-u` / `-f` refused by pry | Prybar-owned (switch parsing); filter hooks exist (`MemberFilter::on_start`) | none in zipfast expected |
| P1, P5 | 98 | password prompt and overwrite prompt behaviour | Prybar-owned, no zipfast cause | none |

## 3. Accepted or reference quirks (no work)

A1 (4, RAR4 `-hp` with `-p-` prints nothing), A2 (7, `p` withholds failed bytes), A3 (16, control-character escaping
and non-UTF-8 names on APFS), A4 (4, `-so` stops at a failed member), Q1 (3, 7-Zip reports a CRC failure on the RAR 1.5
old-style split; UnRAR and pry extract the correct bytes).

## 4. Remaining zipfast-side work and proposed packages

Other open items from the plan's Lane B (B2 Z6, B3 long passwords, B4 ZIP rename, B5 in-run rename, B6 `-slt`
10 of 420, B7 P8) are already in the plan. New proposals from this triage:

| Proposed WP | Title | Mode / cases | Owning module | Deliberate difference | Size |
|---|---|---|---|---|---|
| B9.1 | Prybar re-run against zipfast main and adoption of the #222/#224/#232 options | all modes; the Z1 to Z5, Z7, P3, P4, P6 cases (about 100 cases) should turn green once Prybar bumps and passes the new options | Prybar side, no zipfast change expected | no | S |
| B9.2 | Optional keep-partial-output on a failed member (7-Zip `x`/`e` leaves the partial or empty file) | P2, 15 cases (CRC, missing volume, unsupported method, wrong password) | `src/extract.rs`, staged output | maybe: zipfast removes failed output as a safety choice, so this must be opt-in; confirm with Prybar before starting | M |
| B9.3 | Confirm `.z01` and `.zip.001` `-so` and verify P8 link replacement against the Prybar corpus, add missing tests | Z2 (7 cases), P8 (2 cases) | `src/zip` split sets, `src/extract/link.rs` | no | S |

B9.2 is the only item that may need new zipfast code, and only if Prybar confirms it cannot do it with hooks.
B9.1 and B9.3 need a fresh Prybar differential, which this triage could not obtain (Prybar session busy).
Next step for the orchestrator: ask Prybar for `run-cases.sh` and `run-pw.sh` totals after bumping to current main,
then resize B9.x from the failures that remain.
