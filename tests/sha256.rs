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

//! `ZIPFAST_SHA256=scalar` forces the portable SHA-256 rounds for the whole process.

use std::process::Command;

const CHILD: &str = "ZIPFAST_SHA256_TEST_CHILD";

fn hex(d: [u8; 32]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn the_environment_forces_the_scalar_backend() {
    if std::env::var_os(CHILD).is_some() {
        assert_eq!(zipfast::crypto::sha256_backend(), "scalar");
        assert_eq!(
            hex(zipfast::crypto::sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let mut h = zipfast::crypto::Sha256::new();
        for _ in 0..1000 {
            h.update(&[b'a'; 1000]);
        }
        assert_eq!(hex(h.finalize()), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
        return;
    }
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "the_environment_forces_the_scalar_backend", "--test-threads=1"])
        .env(CHILD, "1")
        .env("ZIPFAST_SHA256", "scalar")
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn the_default_backend_uses_the_hardware_where_it_can() {
    if std::env::var_os("ZIPFAST_SHA256").is_some() {
        return;
    }
    #[cfg(target_arch = "aarch64")]
    if std::arch::is_aarch64_feature_detected!("sha2") {
        assert_eq!(zipfast::crypto::sha256_backend(), "arm-sha2");
        return;
    }
    #[cfg(target_arch = "x86_64")]
    if std::arch::is_x86_feature_detected!("sha")
        && std::arch::is_x86_feature_detected!("ssse3")
        && std::arch::is_x86_feature_detected!("sse4.1")
    {
        assert_eq!(zipfast::crypto::sha256_backend(), "x86-sha-ni");
        return;
    }
    assert_eq!(zipfast::crypto::sha256_backend(), "scalar");
}
