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

//! `zipfast::codec::lzma_decode`: raw LZMA and LZMA2 as 7z stores them.

use std::path::Path;

use liblzma::stream::{Action, Filters, LzmaOptions, Status, Stream};
use zipfast::codec::{LzmaError, lzma_decode};

fn sample(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 % 251) as u8 ^ (i / 97) as u8).collect()
}

/// Raw-encode `data`; LZMA1 output carries an end marker so that it decodes without a stated size.
fn encode(lzma2: bool, data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut options = LzmaOptions::new_preset(6).unwrap();
    options.dict_size(1 << 16);
    let mut filters = Filters::new();
    let props = if lzma2 {
        filters.lzma2(&options);
        vec![8] // 2 << (8 / 2 + 11) = 64 KiB
    } else {
        filters.lzma1(&options);
        let mut props = vec![0x5d];
        props.extend((1u32 << 16).to_le_bytes());
        props
    };
    let mut stream = Stream::new_raw_encoder(&filters).unwrap();
    let mut out = Vec::with_capacity(data.len() + 1024);
    let mut consumed = 0;
    loop {
        let before = stream.total_in();
        let status = stream.process_vec(&data[consumed..], &mut out, Action::Finish).unwrap();
        consumed += (stream.total_in() - before) as usize;
        if status == Status::StreamEnd {
            break;
        }
        out.reserve(4096);
    }
    (props, out)
}

#[test]
fn decodes_a_real_7z_encoded_header() {
    // copy.7z's end header is a kEncodedHeader: one LZMA folder (props 5d 00 10 00 00) packing 110 bytes at offset
    // 32 + 9007 into the 186-byte header, whose CRC is 8fdddd4a.
    let bytes = std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/7z-extract/copy.7z")).unwrap();
    let next = 32 + u64::from_le_bytes(bytes[12..20].try_into().unwrap()) as usize;
    let encoded = &bytes[next..];
    assert_eq!(&encoded[..6], &[0x17, 0x06, 0xa3, 0x2f, 0x01, 0x09]);
    assert_eq!(&encoded[17..23], &[0x05, 0x5d, 0x00, 0x10, 0x00, 0x00]);
    let packed = &bytes[32 + 0x232f..32 + 0x232f + 110];
    let header = lzma_decode(&encoded[18..23], packed, Some(186), 1 << 20).unwrap();
    assert_eq!(header.len(), 186);
    assert_eq!(header[0], 0x01, "kHeader");
    assert_eq!(crc32fast::hash(&header), 0x8fdd_dd4a);
    // A cap under the stated size is refused before decoding.
    assert_eq!(lzma_decode(&encoded[18..23], packed, Some(186), 185), Err(LzmaError::OutputLimit { limit: 185 }));
}

#[test]
fn decodes_lzma2_and_lzma_with_and_without_a_size() {
    let data = sample(300_000);
    for lzma2 in [true, false] {
        let (props, packed) = encode(lzma2, &data);
        assert_eq!(lzma_decode(&props, &packed, Some(data.len() as u64), 1 << 20).unwrap(), data);
        assert_eq!(lzma_decode(&props, &packed, None, 1 << 20).unwrap(), data, "lzma2 {lzma2}");
        // A prefix by size.
        assert_eq!(lzma_decode(&props, &packed, Some(1000), 1 << 20).unwrap(), &data[..1000]);
        // Truncated input.
        let cut = &packed[..packed.len() / 2];
        assert_eq!(lzma_decode(&props, cut, Some(data.len() as u64), 1 << 20), Err(LzmaError::Truncated));
        assert_eq!(lzma_decode(&props, cut, None, 1 << 20), Err(LzmaError::Truncated));
    }
}

#[test]
fn output_cap_is_enforced_without_a_size() {
    let data = sample(200_000);
    for lzma2 in [true, false] {
        let (props, packed) = encode(lzma2, &data);
        assert_eq!(lzma_decode(&props, &packed, None, 199_999), Err(LzmaError::OutputLimit { limit: 199_999 }));
        assert_eq!(lzma_decode(&props, &packed, None, 200_000).unwrap().len(), 200_000);
        assert_eq!(
            lzma_decode(&props, &packed, Some(200_001), 200_000),
            Err(LzmaError::OutputLimit { limit: 200_000 })
        );
    }
}

#[test]
fn garbage_fails_typed() {
    let mut state = 0x9e37_79b9u32;
    let garbage: Vec<u8> = (0..4096)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect();
    for props in [&[0x5d, 0, 0, 1, 0][..], &[16]] {
        for size in [Some(100_000), None] {
            let result = lzma_decode(props, &garbage, size, 1 << 20);
            assert!(
                matches!(result, Err(LzmaError::Corrupt | LzmaError::Truncated | LzmaError::OutputLimit { .. })),
                "{props:?} {size:?}: {result:?}"
            );
        }
    }
    // An LZMA2 control byte that is no chunk type.
    assert_eq!(lzma_decode(&[16], &[0x03, 0, 0], None, 1 << 20), Err(LzmaError::Corrupt));
}

#[test]
fn properties_are_bounded() {
    // LZMA2 dictionary codes stop at 40 (4 GiB - 1); 41 and up are invalid.
    for bad in [41u8, 0xff] {
        assert_eq!(lzma_decode(&[bad], &[0], None, 1 << 20), Err(LzmaError::Properties));
    }
    // lc + lp + pb past the LZMA range (props byte >= 225), and wrong lengths.
    assert_eq!(lzma_decode(&[225, 0, 0, 1, 0], &[0; 8], Some(1), 1 << 20), Err(LzmaError::Properties));
    for props in [&[][..], &[0x5d, 0, 0, 1], &[0x5d, 0, 0, 1, 0, 0]] {
        assert_eq!(lzma_decode(props, &[0], None, 1 << 20), Err(LzmaError::Properties));
    }
    // A 4 GiB dictionary stated for a small output decodes with a window the output can use.
    let data = sample(5_000);
    let (_, packed) = encode(true, &data);
    assert_eq!(lzma_decode(&[40], &packed, Some(data.len() as u64), 1 << 16).unwrap(), data);
    let (_, packed) = encode(false, &data);
    assert_eq!(lzma_decode(&[0x5d, 0xff, 0xff, 0xff, 0xff], &packed, None, 1 << 16).unwrap(), data);
}

#[test]
fn large_stated_dictionaries_are_not_refused() {
    use zipfast::codec::MAX_DICTIONARY;
    // Every dictionary LZMA or LZMA2 can state fits the bound: 7-Zip writes LZMA1 dictionaries past 1.5 GiB.
    assert_eq!(MAX_DICTIONARY, u64::from(u32::MAX));
    let data = sample(10_000);
    let (_, packed) = encode(false, &data);
    for dict in [(1536u32 << 20) + 1, 3 << 30, u32::MAX] {
        let mut props = vec![0x5d];
        props.extend(dict.to_le_bytes());
        // Shrunk to the output, so nothing near the stated size is allocated.
        assert_eq!(lzma_decode(&props, &packed, None, 1 << 20).unwrap(), data, "{dict}");
    }
    let (_, packed) = encode(true, &data);
    for code in [37u8, 38, 39, 40] {
        assert_eq!(lzma_decode(&[code], &packed, Some(data.len() as u64), 1 << 20).unwrap(), data, "{code}");
    }
    // A modest stated dictionary under a huge cap decodes.
    let (props, packed) = encode(true, &data);
    assert_eq!(lzma_decode(&props, &packed, None, 1 << 40).unwrap(), data);
}

/// A stated size is not reserved up front: a stream that stops short of a huge stated size is truncated, not an
/// allocation failure.
#[test]
fn a_huge_stated_size_grows_output_as_it_is_produced() {
    let data = sample(1000);
    let (props, packed) = encode(true, &data);
    assert_eq!(lzma_decode(&props, &packed, Some(1 << 62), u64::MAX), Err(LzmaError::Truncated));
}
