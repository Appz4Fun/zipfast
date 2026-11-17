# Streamed byte-split ZIP with a missing piece

`s.zip.001` and `s.zip.003`: three members written by Python's `zipfile` to an unseekable stream (flag bit 3, sizes in
signed data descriptors), the archive cut into 12000-byte pieces, and `s.zip.002` deleted. 7-Zip 26.06 lists
`a.txt` (800, packed 26), `b.txt` (5) and `c.bin` (size unknown, packed 11832) and reports an unexpected end.
