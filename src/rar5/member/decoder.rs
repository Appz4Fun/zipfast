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

//! Private format ownership. Independent RAR4 state never becomes RAR5 history.
use super::*;
use crate::rar5::unpack::rar4::{CoreBinding, CoreFrame, Rar4Decoder};
#[allow(clippy::large_enum_variant, reason = "fixed inline codec storage avoids a second fallible allocation")]
pub(crate) enum MemberDecoder {
    Rar5(Unpacker),
    Rar4(Rar4Decoder),
}
impl MemberDecoder {
    pub(super) fn rar5_mut(&mut self) -> Result<&mut Unpacker> {
        match self {
            Self::Rar5(d) => Ok(d),
            Self::Rar4(_) => Err(Error::Corrupt("RAR4 routed through RAR5 codec")),
        }
    }
}
impl MemberMachine {
    pub(crate) fn check_rar4_binding(&self, expected: CoreBinding) -> crate::progressive::ProgressiveResult<()> {
        let Some(MemberDecoder::Rar4(d)) = &self.decoder else {
            return Err(crate::progressive::ProgressiveFailure::new(
                crate::progressive::FailureKind::InvalidCapability,
            ));
        };
        let got = d
            .active_binding()
            .map_err(|e| crate::rar5::framing::progressive_fault(e.detailed(self.context.scope())))?;
        if got != expected {
            return Err(crate::progressive::ProgressiveFailure::new(
                crate::progressive::FailureKind::InvalidCapability,
            ));
        }
        Ok(())
    }
    pub(crate) fn take_rar5_decoder(&mut self) -> crate::error::RarResult<Option<Unpacker>> {
        match self.decoder.take() {
            Some(MemberDecoder::Rar5(d)) => Ok(Some(d)),
            None => Ok(None),
            Some(MemberDecoder::Rar4(_)) => Err(crate::error::RarFault::new(
                crate::error::RarFailure::Internal(crate::error::RarInternal::Invariant(
                    "RAR4 cannot provide RAR5 history",
                )),
                Error::Corrupt("RAR4 cannot provide RAR5 history"),
            )),
        }
    }
    pub(crate) fn new_rar4(
        header: &crate::rar5::FileHeader,
        context: EntryContext,
        frame: CoreFrame,
        window_limit: u64,
        usage: &crate::progressive::Usage,
        control: &crate::progressive::SessionControl,
    ) -> crate::progressive::ProgressiveResult<(Self, CoreBinding)> {
        use crate::progressive::Resource;
        usage.check(Resource::DecoderWindow, frame.dictionary)?;
        usage.charge(Resource::MetadataBytes, std::mem::size_of::<Rar4Decoder>() as u64)?;
        let decoder = Rar4Decoder::new_frame(frame, window_limit, Some(control.cancellation_token()))
            .map_err(|e| crate::rar5::framing::progressive_fault(e.detailed(context.scope())))?;
        let binding = decoder
            .active_binding()
            .map_err(|e| crate::rar5::framing::progressive_fault(e.detailed(context.scope())))?;
        let mut machine = Self::from_state(header, context, None, None, 0);
        machine.decoder = Some(MemberDecoder::Rar4(decoder));
        machine.inner = Some(InnerChecks::new(header));
        Ok((machine, binding))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn c1_session_token_cancels_inside_expanding_lz_feed() {
        let packed =
            include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rar4-lz/official-lz-m3.packed"));
        let control = crate::progressive::SessionControl::default();
        let usage = crate::progressive::Usage::new(crate::progressive::ProgressiveLimits::default());
        let header = crate::rar5::FileHeader {
            format: crate::rar5::RarFormat::Rar4,
            method: 3,
            unpacked_size: 302400,
            ..Default::default()
        };
        let context = EntryContext {
            entry: crate::extract::RarEntryIdentity { index: Some(0), order: 0, name: String::new() },
            method: 3,
            password: crate::error::RarPasswordEvidence::NotEncrypted,
        };
        let frame = CoreFrame {
            ordinal: 0,
            packed: packed.len() as u64,
            unpacked: 302400,
            unpack_version: 29,
            method: 0x33,
            dictionary: 65536,
        };
        let (mut machine, _) = MemberMachine::new_rar4(&header, context, frame, 65536, &usage, &control).unwrap();
        let mut produced = 0;
        let e = machine
            .feed(packed, &mut |bytes: &[u8]| {
                produced += bytes.len();
                control.cancel();
                Ok(())
            })
            .unwrap_err();
        assert_eq!(produced, 32768);
        assert!(
            matches!(e.kind,crate::progressive::FailureKind::Rar(ref f) if matches!(f.as_ref(),crate::error::RarFailure::Canceled))
                || matches!(e.kind, crate::progressive::FailureKind::Canceled)
        );
        assert!(machine.feed(&[], &mut |_: &[u8]| Ok(())).is_err());
    }
}
