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

#![no_main]
#[path = "drive.rs"]
mod drive;
use libfuzzer_sys::fuzz_target;
use std::task::{Context, Poll, Waker};
use zipfast::progressive::{ProgressiveOptions, ProgressiveSession};

// Sealed in-memory volumes (RAR4 or RAR5, one or two volumes) through the progressive session: poll to the end.
fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let (bits, flags) = (data[0], data[1]);
    let magic: &[u8] = if flags & 4 != 0 { b"Rar!\x1a\x07\x00" } else { b"Rar!\x1a\x07\x01\x00" };
    let mut body = data[2..].to_vec();
    if !body.starts_with(magic) {
        let mut v = magic.to_vec();
        v.extend_from_slice(&body);
        body = v;
    }
    let mut vols: Vec<(std::ffi::OsString, Box<[u8]>)> = vec![("a.part1.rar".into(), body.clone().into())];
    if flags & 2 != 0 && body.len() > 8 {
        let cut = body.len() / 2;
        vols = vec![
            ("a.part1.rar".into(), body[..cut].to_vec().into()),
            ("a.part2.rar".into(), body[cut..].to_vec().into()),
        ];
    }
    let dir = drive::scratch().join("prog");
    let mut opts = ProgressiveOptions::new(
        drive::options(dir.clone(), zipfast::extract::Mode::Extract, bits),
        "a.part1.rar".into(),
    );
    if flags & 1 != 0 {
        let _ = opts.set_password(Some("pw".into()));
    }
    if let Ok(mut s) = ProgressiveSession::from_sealed_memory(vols, opts) {
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..100_000 {
            match s.poll_event(&mut cx) {
                Poll::Ready(Ok(Some(_))) => {}
                _ => break,
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
});
