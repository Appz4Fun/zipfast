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

//! Shared by the archive fuzz targets: an input becomes a multi-volume RAR, 7z or ZIP set (the first byte picks the
//! format and how many volumes the rest is cut into), mapped and fed member by member through `FeedDecoder`. Every
//! step must return an error or a result, never panic, and stay within its bounds.

use zipfast::map::{ArticleBuffer, FeedDecoder, FeedOptions, MemberMap};

pub fn run(data: &[u8], holes: bool) {
    let Some((&head, rest)) = data.split_first() else { return };
    let name = match head % 3 {
        0 => "set.part1.rar",
        1 => "set.7z.001",
        _ => "set.zip",
    };
    // one to four volumes of the rest
    let n = usize::from(head >> 6) + 1;
    let size = rest.len().div_ceil(n).max(1);
    let volumes: Vec<&[u8]> = rest.chunks(size).collect();
    let Ok(map) = MemberMap::from_memory(&volumes, name, Some("password")) else { return };
    for index in 0..map.members.len().min(4) {
        let Ok(mut decoder) = FeedDecoder::new(&map, index, FeedOptions::new(Some("password"))) else { continue };
        let mut source = ArticleBuffer::new(1 << 26);
        for (v, bytes) in volumes.iter().enumerate() {
            let mut at = 0usize;
            // holes: every few hundred bytes a small range is lost, chosen by the data itself
            while at < bytes.len() {
                let step = 256 + usize::from(bytes[at]) * 4;
                let end = (at + step).min(bytes.len());
                if holes && bytes[at] % 7 == 0 {
                    source.mark_lost(v as u32, at as u64..end as u64);
                } else if source.insert(v as u32, at as u64, &bytes[at..end]).is_err() {
                    return;
                }
                at = end;
            }
        }
        let mut sink: Vec<u8> = Vec::new();
        for _ in 0..64 {
            match decoder.run(&mut source, &mut sink) {
                Ok(status) if status.done || (!status.more && status.needs.is_empty()) => break,
                Ok(_) => {}
                Err(_) => break,
            }
            // the decoder may only ask for bounded output
            if sink.len() > 1 << 28 {
                break;
            }
        }
        let _ = decoder.snapshot().to_bytes();
    }
}
