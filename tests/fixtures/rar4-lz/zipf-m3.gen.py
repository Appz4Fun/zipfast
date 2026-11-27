# Copyright (C) 2026 xbmc4lyfe
# SPDX-License-Identifier: RPL-1.5
#
# Unless explicitly acquired and licensed from Licensor under another license,
# the contents of this file are subject to the Reciprocal Public License
# ("RPL") Version 1.5, or subsequent versions as allowed by the RPL, and You
# may not copy or use this file in either source code or executable form,
# except in compliance with the terms and conditions of the RPL.
#
# All software distributed under the RPL is provided strictly on an "AS IS"
# basis, WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR
# HEREBY DISCLAIMS ALL SUCH WARRANTIES, INCLUDING WITHOUT LIMITATION, ANY
# WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, QUIET
# ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing
# rights and limitations under the RPL.

# Deterministic inputs for the zipf RAR4 fixture: Zipf-distributed words (long Huffman codes) and x86-like code.
import random, struct
r = random.Random(20261126)
vocab = ["".join(r.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(r.randint(2, 11))) for _ in range(3000)]
weights = [1.0 / (i + 1) for i in range(len(vocab))]
out = []
size = 0
while size < 96 * 1024:
    line = " ".join(r.choices(vocab, weights, k=r.randint(4, 14))) + r.choice([".\n", ",\n", "!\n", "?\n", ";\n"])
    out.append(line); size += len(line)
open("zipf.txt", "w").write("".join(out)[: 96 * 1024])
b = bytearray()
while len(b) < 48 * 1024:
    k = r.random()
    if k < 0.15:
        b += b"\xe8" + struct.pack("<i", r.randint(-50000, 50000))
    elif k < 0.25:
        b += b"\xe9" + struct.pack("<i", r.randint(-50000, 50000))
    else:
        b += bytes(r.choice([0x8b, 0x89, 0x48, 0x0f, 0x00, 0xff, 0xc3, r.randrange(256)]) for _ in range(r.randint(1, 6)))
open("code.exe", "wb").write(bytes(b[: 48 * 1024]))
