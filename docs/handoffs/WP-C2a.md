# WP-C2a Huffman decode speed

Status: merging (docs-only; no code change kept)
Branch: rar5-huffman-speed. Worktree: /Users/allen/git.xbmc4lyfe/zipfast-c2a.

## Findings
The RAR5 `Huff` decoder in src/rar5/unpack.rs already has: an 11-bit first-level LUT (symbol<<4|len in u16),
a 64-bit MSB-first accumulator refilled in bulk to >=56 bits (`Bits::refill`/`refill_inside`, unchecked inside the
block), three literals per refill without limit checks, multi-literal "quick" runs for a common code length, and AVX2/NEON
`run8` for length-8 literals. The wider-table / bulk-refill ideas in the WP are therefore already in.

## Experiment (M4, `zipfast t -mt1`, best of 15 wall, F03 = 35 MB set, F05 = 14 MB set)
Bench script: zipfast-handoffs/c2a-bench.sh (run on each binary).
| LUT_BITS | F03 s | F05 s |
|---|---|---|
| 11 (current) | 0.02427 | 0.02607 |
| 10 | 0.02394 (-1.4%) | 0.02607 (+0.0%, other run 0.02583) |
| 12 | 0.02489 (+2.6%) | 0.02658 (+2.0%) |
Run-to-run noise about 1%. No setting beats 11 outside noise; 12 regresses (bigger `build` fill, more cache).
10 is within noise and would risk the i7 (more slow-path hits), so it is not kept.
Not tried: fusing length+distance decode into one lookup. The distance-slot code is 6 to 8 bits typically and the
extra bits between length and distance are variable, so a fused table needs per-(len-slot,dist-slot) entries;
judged unlikely to pay for the added table-build cost (C2b territory) and the exactness risk on resync paths.
The i7 was not benchmarked since there was no M4 gain to confirm.

## Next
Further Huffman gains likely need a profile showing where the 35% goes (build vs decode); coordinate with C2b.
Tests: not run beyond build (no code change).
