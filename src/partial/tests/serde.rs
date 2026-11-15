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

use crate::partial::*;
use ::serde::de::value::{BytesDeserializer, Error, SeqDeserializer};
use ::serde::{Deserialize, Serialize};
#[path = "../../../tests/common/partial_state.rs"]
mod byte_adapter;
use byte_adapter::Bytes;
// Catches serde dispatch bypassing the canonical byte codec or losing binding fields.
#[test]
fn state_serde_roundtrip_reopens_actual_output() {
    let fixture = super::state::Fixture::new();
    let file = fixture.create().unwrap();
    let state = file.close().unwrap();
    let bytes = state.serialize(Bytes).unwrap();
    let decoded = PartialState::deserialize(BytesDeserializer::<Error>::new(&bytes)).unwrap();
    assert_eq!(decoded.anchor(), state.anchor());
    assert_eq!(fixture.open(decoded).unwrap().remaining().unwrap(), vec![0..16]);
    let decoded = PartialState::deserialize(SeqDeserializer::<_, Error>::new(bytes.into_iter())).unwrap();
    assert_eq!(decoded.anchor(), state.anchor());
}
struct Endless {
    hint: Option<usize>,
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}
impl<'de> ::serde::de::SeqAccess<'de> for Endless {
    type Error = Error;
    fn size_hint(&self) -> Option<usize> {
        self.hint
    }
    fn next_element_seed<T: ::serde::de::DeserializeSeed<'de>>(&mut self, seed: T) -> Result<Option<T::Value>, Error> {
        use ::serde::de::IntoDeserializer;
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        seed.deserialize(0u8.into_deserializer()).map(Some)
    }
}
// Catches trusting a misleading/absent size hint and allocating an unbounded sequence.
#[test]
fn state_serde_bytes_and_sequence_are_bounded() {
    assert!(PartialState::deserialize(BytesDeserializer::<Error>::new(&vec![0; 65_537])).is_err());
    for hint in [None, Some(1), Some(usize::MAX)] {
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let access = Endless { hint, calls: calls.clone() };
        let deserializer = ::serde::de::value::SeqAccessDeserializer::new(access);
        assert!(PartialState::deserialize(deserializer).is_err());
        assert!(calls.load(std::sync::atomic::Ordering::SeqCst) <= 65_537);
    }
}

// A well-formed byte stream is not authority, and a head cannot replace missing pages.
#[test]
fn forged_canonical_state_and_missing_pages_cannot_authorize_output() {
    let f = super::state::Fixture::new();
    let original = f.create().unwrap().close().unwrap();
    let limits = PartialLimits::default();
    let (kind, transaction, _, mut head) = crate::partial::state::decode_record(&original.wire, &limits).unwrap();
    head.revision += 1;
    let forged =
        crate::partial::state::encode_record(kind, transaction, Some(original.anchor()), &head, &limits).unwrap();
    let bytes = forged.serialize(Bytes).unwrap();
    let decoded = PartialState::deserialize(BytesDeserializer::<Error>::new(&bytes)).unwrap();
    assert!(matches!(f.open(decoded).err().unwrap().kind, PartialErrorKind::StateStale { .. }));
    let bundle = f.dir.path().join("state").join(crate::partial::native::bundle_name(&f.member));
    std::fs::remove_file(bundle.join(format!("p-{}", crate::partial::native::hex(&head.pages[0].digest)))).unwrap();
    assert!(matches!(f.open(original).err().unwrap().kind, PartialErrorKind::StateUnavailable));
    assert_eq!(std::fs::read(f.output()).unwrap(), vec![0; 16]);
    let f = super::state::Fixture::new();
    let state = f.create().unwrap().close().unwrap();
    let bundle = f.dir.path().join("state").join(crate::partial::native::bundle_name(&f.member));
    std::fs::rename(&bundle, f.dir.path().join("retained-bundle")).unwrap();
    assert!(matches!(
        PartialState::load(&f.dir.path().join("state"), state.anchor(), &limits).unwrap_err().kind,
        PartialErrorKind::StateUnavailable
    ));
    assert_eq!(std::fs::read(f.output()).unwrap(), vec![0; 16]);
}
