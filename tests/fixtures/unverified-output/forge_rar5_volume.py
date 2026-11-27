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

"""Makes a first volume of a RAR 5.0 set from a one-volume archive: its one file header says the data goes on in
the next volume, the data is cut after CUT bytes, and the end header says more volumes follow.

usage: python3 forge_rar5_volume.py ARCHIVE.rar CUT OUT.part1.rar
"""
import sys, zlib, struct
def rv(b, i):
    v=0; s=0
    while True:
        c=b[i]; i+=1; v|=(c&0x7f)<<s; s+=7
        if not c&0x80: return v,i
def wv(v, n=None):
    out=[]
    while True:
        c=v&0x7f; v>>=7
        out.append(c)
        if v==0: break
    if n is not None:
        while len(out)<n: out.append(0)
    for k in range(len(out)-1): out[k]|=0x80
    return bytes(out)
src, cut, dst = sys.argv[1], int(sys.argv[2]), sys.argv[3]
d=open(src,'rb').read()
assert d[:8]==b'Rar!\x1a\x07\x01\x00'
i=8; out=bytearray(d[:8])
done=False
while i<len(d) and not done:
    start=i
    crc=struct.unpack('<I',d[i:i+4])[0]; i+=4
    hsize,j=rv(d,i); body_start=i; hend=j+hsize
    htype,k=rv(d,j); hflags,k2=rv(d,k)
    hdr=bytearray(d[body_start:hend])
    if htype==1:
        # archive flags after optional extra size
        p=k2-body_start
        if hflags&1: _,q=rv(d,k2); p=q-body_start
        af,q=rv(d,body_start+p); assert af==0, af
        hdr[p]=1
        out+=struct.pack('<I',zlib.crc32(hdr)&0xffffffff)+hdr
        i=hend
    elif htype==2:
        p=k2
        if hflags&1: _,p=rv(d,p)
        assert hflags&2
        dsize,p2=rv(d,p)
        n=p2-p
        # rebuild header bytes: replace hflags and data size
        newflags=wv(hflags|0x10, k2-k)
        rel_k=k-body_start; rel_p=p-body_start
        hdr[rel_k:rel_k+(k2-k)]=newflags
        hdr[rel_p:rel_p+n]=wv(cut,n)
        # file CRC field: after file flags, unpacked size, attributes, mtime?
        q=p2; ff,q=rv(d,q); _,q=rv(d,q); _,q=rv(d,q)
        if ff&2: q+=4
        data=d[hend:hend+cut]
        if ff&4:
            rq=q-body_start
            hdr[rq:rq+4]=struct.pack('<I',zlib.crc32(data)&0xffffffff)
        out+=struct.pack('<I',zlib.crc32(hdr)&0xffffffff)+hdr+data
        i=hend+dsize
        done=True
    else:
        raise SystemExit('unexpected header %d'%htype)
end=bytearray([3,5,0,1])  # size 3: type 5, flags 0, end flags 1
out+=struct.pack('<I',zlib.crc32(end)&0xffffffff)+end
open(dst,'wb').write(out)
