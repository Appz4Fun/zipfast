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
use libfuzzer_sys::fuzz_target;
// A RAR 5 encryption record with arbitrary KDF parameters: parsing never panics, and a derivation through the
// archive paths (budgeted) finishes quickly whatever the count byte says.
fuzz_target!(|data: &[u8]| {
    let _ = zipfast::crypto::rar5_record_params(data);
    // archive: signature + sealed HEAD_CRYPT block (type 4) + end block, password supplied
    let mut fields = vec![4u8, 0]; // type, flags
    fields.extend_from_slice(&data[..data.len().min(64)]);
    let block = zipfast::rar5::frame::seal_header(&fields);
    let mut arch = b"Rar!\x1a\x07\x01\x00".to_vec();
    arch.extend_from_slice(&block);
    arch.extend_from_slice(&data[data.len().min(64)..]);
    let dir = std::env::temp_dir().join(format!("zf-kdf-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let p = dir.join("a.rar");
    let _ = std::fs::write(&p, &arch);
    let _ = zipfast::extract::list_detailed(&p, Some("pw"));
    let _ = zipfast::extract::inspect_with_password(&p, Some("pw"));
    let _ = std::fs::remove_file(&p);
});
