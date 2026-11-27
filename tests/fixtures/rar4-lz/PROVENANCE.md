# Fixed RAR4 LZ vectors

These packed bytes are hand-transcribed fixed test vectors specified in
`phase5-rar4-compressed-bitstream-worksheet.md` and its companion
`phase5-rar4-compressed-vectors/vectors.json` in the shared SDD folder.
No external decoder implementation or general compressor produced them.
Nine positive vectors were independently replayed with checksummed UnRAR
at source pin `160dcb5c9c1babbbdd3f0f1fc78cf48a7f8150cf`.
The three negative prefixes are boundary controls, not valid complete
PPM/VM streams. Their exact status/output is recorded in `reference.json`.

The test harness wraps only these immutable bytes with ordinary RAR4
container headers and a known expected CRC. It cannot encode input data.
The original checkpoint kept the public tests RED. The connected branch
now uses these same vectors through normal selected and ordinary consumers.
Full connected qualification is recorded separately in the shared SDD report.

`official-lz-m3.packed` is the payload region of the locally generated
RARLAB 6.24 `-ma4 -m3 -mc- -s- -md64k` archive documented in
`phase5-rar4-compressed-evidence/observations.json`.
Archive SHA-256 is 66128c817b5134fe504b6bd959332429298b142962e8a8b1cb135d5eb5994712.
Packed SHA-256 is d8fc14b15e1f597e722342623c466e6f561b0b24dff92cbd3bbde1f0cc0aeef1.
The source is our deterministic 302,400-byte control, not third-party data.

The additional official-lz-m1/m2/m4/m5 packed fixtures use the same
recorded writer controls, sources and source timestamps as level3.
The six DD/threshold fixtures and three low/recent fixtures are fixed
hand-specified codebooks and token topologies from the worksheet. Exact
bytes, expected output lengths/hashes, and pinned independent replay are
recorded in `branch-vectors.json` and `branch-reference.json`.
No general compression API or third-party decoder code is included.

`zipf-m3.rar` is a RARLAB 6.24 archive made with
`rar a -ma4 -m3 -s- -mt1 -tsm- -tsc- -tsa- zipf-m3.rar zipf.txt code.exe` from the two inputs
`zipf-m3.gen.py` writes (Zipf-distributed words, so the literal table has codes up to 15 bits, and
x86-like bytes; both deterministic, mtime 2026-01-01). Members: `zipf.txt` 98,304 bytes
(sha256 d2a80a5fb0675d25d7ad22f1a3ca621cddc709fb842ed7f9492f276e135a5db2) and `code.exe` 49,152 bytes
(cab01a0827e8359dfb02aecbe9f8c3dce50283d85aa78d18c9884f8a6fbaa114), both LZ. Archive SHA-256 is
53c0b3eef8919f422875e58417966104630fb7ed1175afb85ff197b9c7682fe2. The RAR4 decoder's golden tests
(`src/rar5/unpack/rar4/golden_tests.rs`) decode its two packed streams as is and mutated.
