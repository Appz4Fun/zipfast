# WP-B7: remaining old Prybar items
Status: merging. Branch: prybar-old-items. Worktree: /Users/allen/git.xbmc4lyfe/zipfast-b7.
## P8 (done except checked-ZIP file over link)
Not covered by #247/#252: a tar file over a link the run placed failed `a symlink is in the way`. Fix: `RenameLog.placed`
(the run's `link::Extracted`) lets `place_target`/`place_renamed` treat a symlink whose (dev, ino) is in the run's link set
as replaceable; `Place.link` carries that identity to publication (`output::replace_over` accepts exactly that link).
Wired on tar, legacy ZIP, 7z, RAR4 whole-archive (both link and file sites) and checked-ZIP link members.
Tests: tests/prybar_old_items.rs (tar file/link over own link, earlier-run link still refused, ZIP both routes, Skip).
Not covered by test: 7z and RAR4 (no tool here to build an archive with a duplicate name over a link); they share
`place_target`/`replace_link`. Not done: checked ZIP route (`run_with_policy`) file over a link it placed is still
refused (native fd-based `zip/read/output/target.rs::inspect` is called at three sites without the run's link set);
a test pins the current refusal. Rename modes with a placed link: handled in `place_renamed` (not separately tested).
## Flatten quirk: not reproducible on main
Hook sees `dest/b.txt` and Skip skips before the hook on checked ZIP, legacy ZIP, tar; 7z and RAR paths are flat.
Tests added; docs of `on_start` now say it. No code change.
## Temp cleanup helper: not done
`RunEvent`/`RunObserver` carry no stage (dev, ino); a helper would first need a new `#[non_exhaustive]` event on every route.
Run: cargo test --test prybar_old_items --test links
