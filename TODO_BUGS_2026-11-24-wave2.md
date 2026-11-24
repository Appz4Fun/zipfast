# TODO bugs: wave 2 (2026-11-24)

Codex review findings on the wave 2 PRs of `docs/implementation-plan.md` (WP-C1 #258, WP-A6 #259; WP-B0 #262 is
docs-only and had no findings), all merged before review. Fix every item in one PR (branch `bugs-wave2`), each with a
test that fails without its fix, then reply on and resolve each thread.

| # | PR | Thread | Where | Severity | Status |
|---|---|---|---|---|---|
| 1 | #258 | PRRT_kwDOVi_ME867TEEG | src/map/last_volume.rs:632 | P2 (test no longer guards the regression) | fixed in 66bb6bc5 |
| 2 | #259 | PRRT_kwDOVi_ME867TLcy | src/map/zip_byte_split.rs:35 | P2 (panic on UTF-8 names) | fixed in 66bb6bc5 |
| 3 | #259 | PRRT_kwDOVi_ME867TLc5 | src/map/zip.rs:300 | P2 (parts budget bypass) | fixed in 66bb6bc5 |
| 4 | #259 | PRRT_kwDOVi_ME867TLc_ | src/map/zip_byte_split.rs:182 | P2 (wrong error coordinates) | fixed in 66bb6bc5 |
| 5 | #259 | PRRT_kwDOVi_ME867TLdH | src/map/zip_byte_split.rs:169 | P2 (cancellation ignored) | fixed in 66bb6bc5 |

## 1. The set_identity work counter adds a fixed cost (#258)
`SetIdentitySteps` is bumped by a constant 3 per last-volume member, regardless of the matching work. Replacing
`firsts.get(...)` with a linear search leaves the count unchanged, so the 4,000/16,000-member test still reports a
ratio of 4 while the matching is quadratic. The timing assert is gone, so nothing guards the regression.
**Fix:** count the actual lookup/comparison operations (each map probe, each candidate compared, each fallback scan
step). **Test:** the existing `many_members_match_in_linear_time` must fail when the lookup is temporarily replaced by
a linear scan (do that mutation check, then revert).

## 2. UTF-8 slicing panic in byte-split detection (#259)
`stem.len() - 5` can land inside a multi-byte character: a ZIP named `éabc.001` gives stem `éabc.` and slicing at
byte 1 panics (and release builds use `panic = "abort"`). **Fix:** compare the suffix as bytes (or use checked
`get`). **Test:** map ZIPs named `éabc.001`, `é.zip.001`, `ab.001` and a normal `x.zip.001`: no panic; byte-split
detection only for `*.zip.NNN`.

## 3. Extra pieces are not charged against the parts budget (#259)
When a member crosses piece boundaries, `src/map/zip.rs:300` pushes additional `MapPiece`s without charging
`Resource::Parts`; a one-entry archive spanning many pieces succeeds with `limits.parts = 1`. The split-ZIP walker
charges continuation pieces separately. **Fix:** charge each additional part before allocating it and propagate the
limit error. **Test:** a one-member ZIP cut into 10 pieces with `limits.parts = 2` fails with the parts limit error;
with enough parts it maps.

## 4. Header-hole errors use concatenated coordinates (#259)
When a `RangeSource` reports a hole while reading a header or the directory in a later piece, `Joined::read` returns
`Got::Hole` and the single-volume walker builds `HeaderHole { volume: 0, offset }` with the concatenated offset.
**Fix:** translate to `{ volume: piece index, offset: offset within that piece }` before returning from the
byte-split walker. **Test:** a byte-split set whose central directory sits in piece 3, with a hole there: the error
names piece 3 and a local offset inside its length.

## 5. Cancellation not checked during piece discovery (#259)
The discovery loop (`src/map/zip_byte_split.rs:169`) keeps opening pieces while the provider answers `Ready`
synchronously, without checking `options.control`. **Fix:** check cancellation on each discovery iteration, like
the other walkers' phase loops. **Test:** a provider that cancels the control after piece 2 of 20: the map returns the
canceled error and opens no more than one further piece.
