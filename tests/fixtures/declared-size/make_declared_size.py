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

"""Makes the declared-size fixtures: a RAR 5.0 or RAR 4.x member whose header declares fewer bytes than it carries.

stored: python3 make_declared_size.py stored5|stored4 OUT   (60,000 bytes stored, 1 declared)
patch:  python3 make_declared_size.py patch IN OUT SIZE   (the first member of IN declared SIZE, later ones dropped)
zip:    python3 make_declared_size.py zipstored|zipdeflate OUT   (60,000 bytes stored with 1 declared, or words.txt
        deflated with 1,000 declared; the CRC is the whole data's)
7z:     python3 make_declared_size.py patch7z IN OUT SIZE   (IN made with `7zz a -mhc=off`, one member in one folder:
        the folder's unpack size set to SIZE, both header CRCs fixed)
"""
import sys, zlib, struct, random

def vint(v):
    out = bytearray()
    while True:
        b = v & 0x7f; v >>= 7
        if v: out.append(b | 0x80)
        else: out.append(b); return bytes(out)

def r5_block(kind, flags, fields, data_size=None):
    body = vint(kind) + vint(flags | (0x02 if data_size is not None else 0))
    if data_size is not None: body += vint(data_size)
    body += fields
    size = vint(len(body))
    return struct.pack('<I', zlib.crc32(size + body)) + size + body

def rar5_stored(name, data, declared, crc_of=None):
    crc = zlib.crc32(data if crc_of is None else crc_of)
    sig = b'Rar!\x1a\x07\x01\x00'
    main = r5_block(1, 0, vint(0))
    n = name.encode()
    fields = vint(0x04) + vint(declared) + vint(0x20) + struct.pack('<I', crc) + vint(0) + vint(0) + vint(len(n)) + n
    fh = r5_block(2, 0, fields, len(data))
    end = r5_block(5, 0, vint(0))
    return sig + main + fh + data + end

def r4_hdr(typ, flags, rest):
    body = bytes([typ]) + struct.pack('<HH', flags, 7 + len(rest)) + rest
    return struct.pack('<H', zlib.crc32(body) & 0xffff) + body

def rar4_stored(name, data, declared, crc_of=None):
    crc = zlib.crc32(data if crc_of is None else crc_of)
    n = name.encode()
    marker = b'Rar!\x1a\x07\x00'
    main = r4_hdr(0x73, 0, b'\0' * 6)
    rest = struct.pack('<IIBIIBBHI', len(data), declared, 3, crc, 0x5a000000, 29, 0x30, len(n), 0x81a4) + n
    fh = r4_hdr(0x74, 0x8000, rest)
    end = r4_hdr(0x7b, 0x4000, b'')
    return marker + main + fh + data + end


def rvint(b, i):
    v = s = 0
    while True:
        c = b[i]; i += 1; v |= (c & 0x7f) << s; s += 7
        if not c & 0x80: return v, i

def rar5(a, new):
    out = bytearray(a[:8]); i = 8
    while i < len(a):
        start = i
        size, j = rvint(a, i + 4); hstart = j; hend = j + size
        typ, j = rvint(a, j); flags, j = rvint(a, j)
        extra = data = 0
        if flags & 1: extra, j = rvint(a, j)
        if flags & 2: data, j = rvint(a, j)
        if typ == 2:
            ff, k = rvint(a, j); unp, k2 = rvint(a, k)
            body = vint(typ) + vint(flags) + (vint(extra) if flags & 1 else b'') + (vint(data) if flags & 2 else b'') + vint(ff) + vint(new) + a[k2:hend]
            sz = vint(len(body))
            out += struct.pack('<I', zlib.crc32(sz + body)) + sz + body + a[hend:hend + data]
            end = b'\x00\x00\x00\x00' ; eb = vint(5) + vint(0) + vint(0); es = vint(len(eb))
            out += struct.pack('<I', zlib.crc32(es + eb)) + es + eb
            return bytes(out)
        out += a[start:hend + data]; i = hend + data
    raise SystemExit('no file')

def rar4(a, new):
    out = bytearray(a[:7]); i = 7
    while i < len(a):
        crc, typ, flags, size = struct.unpack_from('<HBHH', a, i)
        add = struct.unpack_from('<I', a, i + 7)[0] if (flags & 0x8000 or typ == 0x74) else 0
        if typ == 0x74:
            h = bytearray(a[i:i + size]); struct.pack_into('<I', h, 11, new)
            struct.pack_into('<H', h, 0, zlib.crc32(h[2:]) & 0xffff)
            out += h + a[i + size:i + size + add]
            body = bytes([0x7b]) + struct.pack('<HH', 0x4000, 7)
            out += struct.pack('<H', zlib.crc32(body) & 0xffff) + body
            return bytes(out)
        out += a[i:i + size + add]; i += size + add
    raise SystemExit('no file')

def words():
    r = random.Random(5); w = 'alpha beta gamma delta eps zeta eta theta iota kappa'.split()
    return ''.join(' '.join(r.choice(w) for _ in range(8)) + '\n' for _ in range(5000)).encode()

def zip_member(name, data, packed, method, declared):
    n = name.encode(); crc = zlib.crc32(data)
    common = struct.pack('<HHHHHIII', 20, 0, method, 0x6000, 0x5a21, crc, len(packed), declared)
    local = b'PK\x03\x04' + common + struct.pack('<HH', len(n), 0) + n
    central = b'PK\x01\x02' + struct.pack('<H', 0x0314) + common + struct.pack('<HHHHHII', len(n), 0, 0, 0, 0, 0x81a40000, 0) + n
    eocd = b'PK\x05\x06' + struct.pack('<HHHHIIH', 0, 0, 1, 1, len(central), len(local) + len(packed), 0)
    return local + packed + central + eocd

def patch7z(a, new):
    off, size = struct.unpack_from('<QQ', a, 12)
    start = 32 + off
    h = bytearray(a[start:start + size])
    def num(v):
        if v < 0x80: return bytes([v])
        assert v < 0x4000; return bytes([0x80 | (v >> 8), v & 0xff])
    i = h.index(b'\x0c') + 1
    old = h[i:i + 2]; repl = num(new)
    assert len(repl) == 2 and old[0] & 0xc0 == 0x80, (old, repl)
    h[i:i + 2] = repl
    out = bytearray(a[:start]) + h
    struct.pack_into('<I', out, 28, zlib.crc32(h))
    struct.pack_into('<I', out, 8, zlib.crc32(out[12:32]))
    return bytes(out)

if __name__ == '__main__':
    if sys.argv[1] == 'zipstored':
        data = bytes((i * 7 + (i >> 8)) & 0xff for i in range(60000))
        open(sys.argv[2], 'wb').write(zip_member('big.bin', data, data, 0, 1)); raise SystemExit
    if sys.argv[1] == 'zipdeflate':
        data = words(); c = zlib.compressobj(9, zlib.DEFLATED, -15)
        open(sys.argv[2], 'wb').write(zip_member('words.txt', data, c.compress(data) + c.flush(), 8, 1000)); raise SystemExit
    if sys.argv[1] == 'patch7z':
        open(sys.argv[3], 'wb').write(patch7z(open(sys.argv[2], 'rb').read(), int(sys.argv[4]))); raise SystemExit
    if sys.argv[1] in ('stored5', 'stored4'):
        data = bytes((i * 7 + (i >> 8)) & 0xff for i in range(60000))
        make = rar5_stored if sys.argv[1] == 'stored5' else rar4_stored
        open(sys.argv[2], 'wb').write(make('big.bin', data, 1))
    else:
        a = open(sys.argv[2], 'rb').read()
        new = int(sys.argv[4])
        open(sys.argv[3], 'wb').write(rar5(a, new) if a[6] == 1 else rar4(a, new))
