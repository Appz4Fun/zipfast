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

use super::*;
use std::sync::Arc;
pub(crate) struct AnchorBinding {
    member: MemberKey,
    store: Arc<dyn StateAnchorStore>,
}
/// Runtime acknowledgement; neither serialized nor constructible outside this module.
pub(crate) struct AnchorAck {
    anchor: StateAnchor,
}
impl AnchorAck {
    pub(super) fn anchor(&self) -> &StateAnchor {
        &self.anchor
    }
    pub(super) fn matches(&self, anchor: &StateAnchor) -> bool {
        &self.anchor == anchor
    }
}
impl AnchorBinding {
    pub(super) fn new(member: MemberKey, store: Arc<dyn StateAnchorStore>) -> Self {
        Self { member, store }
    }
    pub(crate) fn current(&self) -> PartialResult<Option<StateAnchor>> {
        let value = self.store.current(&self.member)?;
        if value.as_ref().is_some_and(|a| a.member() != &self.member) {
            return Err(err(PartialErrorKind::BindingMismatch(BindingField::Anchor)));
        }
        Ok(value)
    }
    pub(super) fn current_ack(&self) -> PartialResult<Option<AnchorAck>> {
        Ok(self.current()?.map(|anchor| AnchorAck { anchor }))
    }
    pub(crate) fn advance(&self, expected: Option<&StateAnchor>, next: &StateAnchor) -> PartialResult<AnchorAck> {
        if next.member() != &self.member || expected.is_some_and(|a| a.member() != &self.member) {
            return Err(err(PartialErrorKind::BindingMismatch(BindingField::Anchor)));
        }
        self.store
            .compare_exchange(&self.member, expected, next)
            .map_err(|_| err(PartialErrorKind::AnchorCommitUncertain))?;
        Ok(AnchorAck { anchor: next.clone() })
    }
    pub(crate) fn confirm_current(&self, expected: &StateAnchor) -> PartialResult<AnchorAck> {
        match self.current()? {
            Some(a) if &a == expected => Ok(AnchorAck { anchor: a }),
            Some(latest) => Err(err(PartialErrorKind::StateStale { latest })),
            None => Err(err(PartialErrorKind::AnchorConflict)),
        }
    }
}
