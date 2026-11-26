// Copyright (C) 2026 xbmc4lyfe
// SPDX-License-Identifier: RPL-1.5
//
// Unless explicitly acquired and licensed from Licensor under another license,
// the contents of this file are subject to the Reciprocal Public License
// ("RPL") Version 1.5, or subsequent versions as allowed by the RPL, and You
// may not copy or use this file in either source code or executable form,
// except in compliance with the terms and conditions of the RPL.
//
// All software distributed under the RPL is provided strictly on an "AS IS"
// basis, WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR
// HEREBY DISCLAIMS ALL SUCH WARRANTIES, INCLUDING WITHOUT LIMITATION, ANY
// WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, QUIET
// ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing
// rights and limitations under the RPL.

//! RustyGet's stored-data speed: a source that holds packed bytes in memory lends them
//! ([`PackedSource::borrow_packed`]) and a stored member's output is written straight from them, with no copy into
//! the decoder; [`ArticleBuffer::insert_owned`] keeps an article without copying it.

use std::io;
use zipfast::map::{
    ArticleBuffer, BufferFull, FeedDecoder, FeedOptions, FeedSink, MemberMap, PackedRead, PackedSource,
};

/// One stored member as a single-file ZIP.
fn stored_zip(name: &str, data: &[u8]) -> Vec<u8> {
    let crc = crc32fast::hash(data);
    let mut out = Vec::new();
    out.extend_from_slice(b"PK\x03\x04");
    out.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0x21, 0x50]);
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(data);
    let at = out.len() as u32;
    let mut central = Vec::new();
    central.extend_from_slice(b"PK\x01\x02");
    central.extend_from_slice(&[20, 3, 20, 0, 0, 0, 0, 0, 0, 0, 0x21, 0x50]);
    central.extend_from_slice(&crc.to_le_bytes());
    central.extend_from_slice(&(data.len() as u32).to_le_bytes());
    central.extend_from_slice(&(data.len() as u32).to_le_bytes());
    central.extend_from_slice(&(name.len() as u16).to_le_bytes());
    central.extend_from_slice(&[0; 8]);
    central.extend_from_slice(&(0o100644u32 << 16).to_le_bytes());
    central.extend_from_slice(&0u32.to_le_bytes());
    central.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&central);
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&[0, 0, 0, 0, 1, 0, 1, 0]);
    out.extend_from_slice(&(central.len() as u32).to_le_bytes());
    out.extend_from_slice(&at.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

/// An [`ArticleBuffer`] that counts how bytes were taken from it; `lend` off turns lending off.
struct Counting {
    inner: ArticleBuffer,
    lend: bool,
    lent: u64,
    copied: u64,
}

impl PackedSource for Counting {
    fn read_packed(&mut self, volume: u32, offset: u64, buf: &mut [u8]) -> PackedRead {
        let r = self.inner.read_packed(volume, offset, buf);
        if let PackedRead::Data(n) = r {
            self.copied += n as u64;
        }
        r
    }
    fn borrow_packed(&mut self, volume: u32, offset: u64, max: usize) -> Option<&[u8]> {
        if !self.lend {
            return None;
        }
        let bytes = self.inner.borrow_packed(volume, offset, max)?;
        self.lent += bytes.len() as u64;
        Some(bytes)
    }
}

struct Out(Vec<u8>);
impl FeedSink for Out {
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> io::Result<()> {
        let end = offset as usize + bytes.len();
        if self.0.len() < end {
            self.0.resize(end, 0);
        }
        self.0[offset as usize..end].copy_from_slice(bytes);
        Ok(())
    }
    fn read_held(&mut self, _: u64, _: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }
}

#[test]
fn stored_output_is_written_from_lent_bytes() {
    let data: Vec<u8> = (0..3_000_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
    let zip = stored_zip("movie.mkv", &data);
    let map = MemberMap::from_memory(&[&zip], "set.zip", None).unwrap();
    for lend in [true, false] {
        let mut source = Counting { inner: ArticleBuffer::new(usize::MAX), lend, lent: 0, copied: 0 };
        // articles in order, owned: kept without a copy
        for (i, article) in zip.chunks(750_000).enumerate() {
            source.inner.insert_owned(0, (i * 750_000) as u64, article.to_vec()).unwrap();
        }
        let mut d = FeedDecoder::new(&map, 0, FeedOptions::default()).unwrap();
        let mut out = Out(Vec::new());
        let s = d.run(&mut source, &mut out).unwrap().clone();
        assert!(s.done && s.crc_ok == Some(true), "lend {lend}: {s:?}");
        assert!(out.0 == data, "lend {lend}: output differs");
        if lend {
            assert_eq!((source.lent, source.copied), (data.len() as u64, 0), "every stored byte lent, none copied");
        } else {
            assert_eq!(source.lent, 0);
            assert!(source.copied >= data.len() as u64);
        }
    }
}

#[test]
fn insert_owned_keeps_bytes_and_falls_back_on_overlap() {
    let mut b = ArticleBuffer::new(100);
    b.insert_owned(0, 10, vec![1; 20]).unwrap();
    assert_eq!(b.held(), 20);
    // overlapping the held bytes: only the new ones are kept (as `insert`)
    b.insert_owned(0, 20, vec![2; 20]).unwrap();
    assert_eq!(b.held(), 30);
    let mut buf = [0u8; 30];
    assert!(matches!(b.read_packed(0, 10, &mut buf), PackedRead::Data(20)));
    assert_eq!(&buf[..20], &[1; 20]);
    assert!(matches!(b.read_packed(0, 30, &mut buf), PackedRead::Data(10)));
    assert_eq!(&buf[..10], &[2; 10]);
    assert_eq!(b.borrow_packed(0, 15, 3), Some(&[1u8; 3][..]));
    assert_eq!(b.borrow_packed(0, 5, 3), None, "nothing held there");
    // past the limit: nothing kept
    assert!(matches!(b.insert_owned(0, 100, vec![3; 71]), Err(BufferFull { .. })));
    assert_eq!(b.held(), 30);
    // an empty article is nothing
    b.insert_owned(1, 0, Vec::new()).unwrap();
    assert_eq!(b.held(), 30);
}
