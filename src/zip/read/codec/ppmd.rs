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

//! PPMd (method 98) slice progress adapter.
use super::{EncryptedReadOptions, IntegrityReason, Progress};
pub(in crate::zip::read::codecs) struct Decoder(crate::ppmd8::Decoder);
impl Decoder {
    /// The model's memory, which the stream's header asks for, is held to the LZMA memory limit.
    pub(in crate::zip::read::codecs) fn new(options: &EncryptedReadOptions) -> Result<Self, IntegrityReason> {
        Ok(Self(crate::ppmd8::Decoder::new(options.lzma_memory_bytes)))
    }
    pub(in crate::zip::read::codecs) fn step(&mut self, input: &[u8], output: &mut [u8], last: bool) -> Progress {
        match self.0.step(input, output, last) {
            Ok((consumed, produced)) => {
                let fault = self.0.trailing().then_some(IntegrityReason::TrailingData);
                Progress { consumed, produced, fault, end: self.0.ended() }
            }
            Err(_) => Progress { consumed: 0, produced: 0, fault: Some(IntegrityReason::Decoder), end: false },
        }
    }
}
