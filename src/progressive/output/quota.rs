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

use super::super::{FailureKind, ProgressiveFailure, ProgressiveResult, Resource};
use std::{
    sync::{Arc, Mutex},
    task::{Context, Waker},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Capacity {
    Ready,
    Needed { retained: u64 },
    Pending,
}
struct State {
    retained: u64,
    active: bool,
    announced: bool,
    task: Option<Waker>,
}
#[derive(Clone)]
pub(super) struct Quota {
    state: Arc<Mutex<State>>,
    limit: u64,
    active_limit: u64,
}
pub(super) struct Lease {
    quota: Quota,
    active: bool,
}
impl Quota {
    pub(super) fn new(limit: u64, active_limit: u64) -> Self {
        Self {
            state: Arc::new(Mutex::new(State { retained: 0, active: false, announced: false, task: None })),
            limit,
            active_limit: active_limit.min(1),
        }
    }
    pub(super) fn clear_registration(&self) {
        let previous = { self.state.lock().unwrap().task.take() };
        // A task's final destructor may reenter cancellation or release artifacts.
        drop(previous);
    }
    pub(super) fn acquire(&self) -> ProgressiveResult<Lease> {
        let mut s = self.state.lock().unwrap();
        if s.active || self.active_limit == 0 {
            return Err(ProgressiveFailure::new(FailureKind::Limit {
                resource: Resource::ActiveOutputs,
                limit: self.active_limit,
                attempted: 1 + u64::from(s.active),
            }));
        }
        if s.retained >= self.limit {
            return Err(ProgressiveFailure::new(FailureKind::Limit {
                resource: Resource::RetainedArtifacts,
                limit: self.limit,
                attempted: s.retained.saturating_add(1),
            }));
        }
        s.retained += 1;
        s.active = true;
        Ok(Lease { quota: self.clone(), active: true })
    }
    pub(super) fn poll(&self, cx: &mut Context<'_>) -> Capacity {
        let incoming = cx.waker().clone();
        let (old, result) = {
            let mut s = self.state.lock().unwrap();
            let old = s.task.replace(incoming);
            let result = if s.retained < self.limit {
                s.announced = false;
                Capacity::Ready
            } else if !s.announced {
                s.announced = true;
                Capacity::Needed { retained: s.retained }
            } else {
                Capacity::Pending
            };
            (old, result)
        };
        drop(old);
        result
    }
}
impl Lease {
    pub(super) fn deliver(&mut self) {
        if self.active {
            self.quota.state.lock().unwrap().active = false;
            self.active = false;
        }
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        let task = {
            let mut s = self.quota.state.lock().unwrap();
            s.retained -= 1;
            if self.active {
                s.active = false;
            }
            s.announced = false;
            s.task.take()
        };
        if let Some(w) = task {
            w.wake();
        }
    }
}
