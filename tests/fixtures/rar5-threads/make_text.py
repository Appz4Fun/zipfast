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

"""Writes the text files of the rar5-threads fixtures.

usage: python3 make_text.py OUT SIZE SEED CHANGES
"""
import sys
# deterministic, very compressible text: a 48 KiB passage of words, repeated with a few words changed each time
WORDS = "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima mike november oscar papa".split()
def make(path, size, seed):
    x = seed
    def rnd():
        nonlocal x
        x = (x * 6364136223846793005 + 1442695040888963407) & (2**64 - 1)
        return x >> 33
    base = bytearray()
    while len(base) < 48 << 10:
        base += (WORDS[rnd() & 15] + (" " if rnd() & 7 else "\n")).encode()
    out = bytearray()
    while len(out) < size:
        for _ in range(int(sys.argv[4])):
            at = rnd() % (len(base) - 8)
            base[at:at + 5] = WORDS[rnd() & 15][:5].encode().ljust(5)
        out += base
    open(path, "wb").write(bytes(out[:size]))
make(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]))
