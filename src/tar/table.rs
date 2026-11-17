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

//! What the archives read from a table (xar's TOC, an ISO 9660 image's folders) share: names kept once each, with
//! the folder they sit in, so a full path is built only as its member is handed out (a long folder name is not
//! copied into every path below it); and checks that the data ranges members declare don't overlap or add up past
//! what the archive could hold.

use crate::error::{Error, Result};

/// The longest full path a member may have, its folders' names included.
pub(super) const MAX_PATH: usize = 64 << 10;

/// Every member's own name and folder.
#[derive(Default)]
pub(super) struct Names {
    names: Vec<Name>,
}

/// A name, its stored bytes when they aren't UTF-8, and the folder it sits in.
type Name = (String, Option<Vec<u8>>, Option<usize>);

impl Names {
    /// Adds a name in `parent` (added before it); returns its index.
    pub(super) fn push(&mut self, name: String, raw: Option<Vec<u8>>, parent: Option<usize>) -> usize {
        debug_assert!(parent.is_none_or(|p| p < self.names.len()));
        self.names.push((name, raw, parent));
        self.names.len() - 1
    }

    /// Bytes of names kept, for tests of the bound.
    #[cfg(test)]
    pub(super) fn bytes(&self) -> usize {
        self.names.iter().map(|(n, r, _)| n.len() + r.as_ref().map_or(0, Vec::len)).sum()
    }

    /// The full path of name `i`, and its stored bytes when some part isn't UTF-8; too long a path is refused.
    pub(super) fn path(&self, i: usize, too_long: &'static str) -> Result<(String, Option<Vec<u8>>)> {
        let mut chain = vec![i];
        let mut len = self.names[i].0.len();
        while let Some(p) = self.names[*chain.last().expect("one")].2 {
            len += self.names[p].0.len() + 1;
            if len > MAX_PATH {
                return Err(Error::Corrupt(too_long));
            }
            chain.push(p);
        }
        let parts: Vec<&Name> = chain.iter().rev().map(|&j| &self.names[j]).collect();
        let path = parts.iter().map(|(n, ..)| n.as_str()).collect::<Vec<_>>().join("/");
        let raw = parts.iter().any(|(_, r, _)| r.is_some()).then(|| {
            let bytes: Vec<&[u8]> = parts.iter().map(|(n, r, _)| r.as_deref().unwrap_or(n.as_bytes())).collect();
            bytes.join(&b'/')
        });
        Ok((path, raw))
    }
}

/// Refuses `ranges` (start, length) that overlap one another; empty ranges are passed over.
pub(super) fn disjoint(ranges: &mut [(u64, u64)], why: &'static str) -> Result<()> {
    ranges.sort_unstable();
    let mut end = 0u64;
    let mut first = true;
    for &(start, len) in ranges.iter().filter(|r| r.1 > 0) {
        if !first && start < end {
            return Err(Error::Corrupt(why));
        }
        end = start.checked_add(len).ok_or(Error::Corrupt(why))?;
        first = false;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_join_their_folders() {
        let mut n = Names::default();
        let a = n.push("a".into(), None, None);
        let b = n.push("b".into(), Some(b"b\xff".to_vec()), Some(a));
        let c = n.push("c".into(), None, Some(b));
        assert_eq!(n.path(c, "long").unwrap(), ("a/b/c".to_owned(), Some(b"a/b\xff/c".to_vec())));
        assert_eq!(n.path(a, "long").unwrap(), ("a".to_owned(), None));
        let deep = n.push("x".repeat(MAX_PATH), None, Some(c));
        assert!(n.path(deep, "long").is_err());
    }

    #[test]
    fn overlapping_ranges_are_refused() {
        assert!(disjoint(&mut [(10, 5), (0, 10), (15, 0), (15, 1)], "x").is_ok());
        assert!(disjoint(&mut [(0, 10), (9, 2)], "x").is_err());
        assert!(disjoint(&mut [(5, 5), (5, 5)], "x").is_err());
        assert!(disjoint(&mut [(5, 0), (5, 0), (0, 1)], "x").is_ok());
        assert!(disjoint(&mut [(u64::MAX, 2)], "x").is_err());
    }
}
