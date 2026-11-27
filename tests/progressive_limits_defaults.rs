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

//! RustyGet production (John.Wick.Chapter.4 UHD REMUX): a 70-100 GB RAR set hit the old 64 GiB default
//! `SourceBytes` cap. Byte totals are not where a hostile archive is stopped, so their defaults exceed real sets.

use zipfast::progressive::{DEFAULT_BYTE_TOTAL, ProgressiveLimits};

#[test]
fn byte_total_defaults_exceed_uhd_remux_sets() {
    let limits = ProgressiveLimits::default();
    let hundred_gb = 100_000_000_000u64;
    assert_eq!(DEFAULT_BYTE_TOTAL, 1 << 40);
    for (name, value) in [
        ("source_bytes", limits.source_bytes),
        ("logical_output_bytes", limits.logical_output_bytes),
        ("temp_bytes", limits.temp_bytes),
        ("output_write_bytes", limits.output_write_bytes),
        ("verify_bytes", limits.verify_bytes),
        ("verify_work_bytes", limits.verify_work_bytes),
    ] {
        assert!(value >= hundred_gb, "{name} default {value} below a 100 GB set");
        assert_eq!(value, DEFAULT_BYTE_TOTAL, "{name}");
    }
}
