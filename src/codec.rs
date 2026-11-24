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

//! Raw codecs for callers that hold a coder's properties and packed bytes themselves, such as a 7z header found by
//! a repair tool.

use std::fmt;

/// Why [`lzma_decode`] failed.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum LzmaError {
    /// The properties are neither 5 valid LZMA bytes nor one LZMA2 dictionary byte of at most 40.
    Properties,
    /// The dictionary, after shrinking to the output, would pass [`MAX_DICTIONARY`]. No valid property reaches it at
    /// the current bound; it is kept so the bound can tighten without an API change.
    DictionaryLimit { requested: u64, allowed: u64 },
    /// The output would pass `max_output` (or the stated unpacked size does).
    OutputLimit { limit: u64 },
    /// The data does not decode.
    Corrupt,
    /// The data ended before the stated size, or before the end marker when no size is stated.
    Truncated,
    /// Memory for the output or the decoder could not be had.
    Allocation,
}

impl fmt::Display for LzmaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Properties => f.write_str("invalid LZMA or LZMA2 properties"),
            Self::DictionaryLimit { requested, allowed } => {
                write!(f, "LZMA dictionary of {requested} bytes passes the {allowed}-byte limit")
            }
            Self::OutputLimit { limit } => write!(f, "LZMA output passes the {limit}-byte limit"),
            Self::Corrupt => f.write_str("corrupt LZMA data"),
            Self::Truncated => f.write_str("truncated LZMA data"),
            Self::Allocation => f.write_str("LZMA allocation failed"),
        }
    }
}

impl std::error::Error for LzmaError {}

/// Decode raw LZMA or LZMA2 data, as a 7z coder stores it.
///
/// `props` is the coder's properties: 5 bytes for LZMA (`lc/lp/pb` and the dictionary size) or 1 byte for LZMA2
/// (the dictionary size code, at most 40). With `unpacked_size` the output is exactly that long and decoding stops
/// there; without it, decoding runs to the end marker (LZMA's optional one, LZMA2's end chunk).
///
/// At most `max_output` bytes are produced: a larger stated size, or more output before the end marker, fails with
/// [`LzmaError::OutputLimit`]. The dictionary is allocated up front, shrunk to what the output can use (the stated
/// size, else `max_output`; at least 4 KiB), and refused with [`LzmaError::DictionaryLimit`] past
/// [`MAX_DICTIONARY`]. The output grows as it is produced, never past `max_output` plus one byte.
///
/// ```
/// let err = zipfast::codec::lzma_decode(&[41], &[], None, 1 << 20).unwrap_err();
/// assert_eq!(err, zipfast::codec::LzmaError::Properties);
/// ```
pub fn lzma_decode(
    props: &[u8],
    packed: &[u8],
    unpacked_size: Option<u64>,
    max_output: u64,
) -> Result<Vec<u8>, LzmaError> {
    if let Some(size) = unpacked_size
        && size > max_output
    {
        return Err(LzmaError::OutputLimit { limit: max_output });
    }
    let (filters, window) = filters(props, unpacked_size.unwrap_or(max_output))?;
    if window > MAX_DICTIONARY {
        return Err(LzmaError::DictionaryLimit { requested: window, allowed: MAX_DICTIONARY });
    }
    decode(&filters, packed, unpacked_size, max_output)
}

/// The largest dictionary [`lzma_decode`] allocates: 4 GiB - 1, the largest LZMA and LZMA2 can state (and the 7z
/// default). Every valid property therefore fits; the dictionary is still allocated up front, so a caller with no
/// stated size bounds it through `max_output`.
pub const MAX_DICTIONARY: u64 = u32::MAX as u64;

/// LZMA2's dictionary size for property byte `b` (at most 40).
pub(crate) fn lzma2_dict(b: u8) -> u64 {
    if b >= 40 { u64::from(u32::MAX) } else { (2 | u64::from(b & 1)) << (b / 2 + 11) }
}

/// Raw decoder filters for LZMA (5 property bytes) or LZMA2 (1), with the dictionary shrunk to what `output`
/// bytes can use, and the window that leaves.
pub(crate) fn filters(props: &[u8], output: u64) -> Result<(liblzma::stream::Filters, u64), LzmaError> {
    let need = output.max(4096);
    let mut filters = liblzma::stream::Filters::new();
    let window = match *props {
        [_, _, _, _, _] => {
            let mut props: [u8; 5] = props.try_into().expect("five bytes");
            let dict = u64::from(u32::from_le_bytes(props[1..].try_into().expect("four bytes"))).clamp(4096, need);
            props[1..].copy_from_slice(&(dict as u32).to_le_bytes());
            filters.lzma1_properties(&props).map_err(|_| LzmaError::Properties)?;
            dict
        }
        [b] if b <= 40 => {
            let b = (0..=b).find(|&s| lzma2_dict(s) >= need).unwrap_or(b);
            filters.lzma2_properties(&[b]).map_err(|_| LzmaError::Properties)?;
            lzma2_dict(b)
        }
        _ => return Err(LzmaError::Properties),
    };
    Ok((filters, window))
}

const STEP: usize = 64 << 10;

/// Run a raw decoder over `input`: to exactly `size` bytes, or to the end marker within `max_output`.
pub(crate) fn decode(
    filters: &liblzma::stream::Filters,
    input: &[u8],
    size: Option<u64>,
    max_output: u64,
) -> Result<Vec<u8>, LzmaError> {
    use liblzma::stream::{Action, Status, Stream};
    let mut stream = Stream::new_raw_decoder(filters).map_err(|_| LzmaError::Allocation)?;
    let target = size.unwrap_or(max_output);
    // Output grows as it is produced, even with a stated size: a corrupt stream may state one it never reaches.
    let mut out = Vec::new();
    let mut chunk = Vec::new();
    chunk.try_reserve_exact(STEP).map_err(|_| LzmaError::Allocation)?;
    chunk.resize(STEP, 0);
    let mut consumed = 0usize;
    loop {
        let produced = out.len() as u64;
        if size.is_some() && produced == target {
            return Ok(out);
        }
        // Room for the next piece, one byte past the cap when no size is stated so that overflow shows.
        let room = (target - produced).saturating_add(u64::from(size.is_none())).min(STEP as u64) as usize;
        let (i, o) = (stream.total_in(), stream.total_out());
        let status = stream.process(&input[consumed..], &mut chunk[..room], Action::Run);
        consumed += (stream.total_in() - i) as usize;
        let written = &chunk[..(stream.total_out() - o) as usize];
        if out.len() + written.len() > out.capacity() {
            // Grow geometrically, but never past the stated size or one byte over the cap.
            let limit = usize::try_from(target.saturating_add(u64::from(size.is_none()))).unwrap_or(usize::MAX);
            let want = out.capacity().saturating_mul(2).max(out.len() + written.len()).min(limit);
            out.try_reserve_exact(want.max(out.len() + written.len()) - out.len())
                .map_err(|_| LzmaError::Allocation)?;
        }
        out.extend_from_slice(written);
        if out.len() as u64 > target {
            return Err(LzmaError::OutputLimit { limit: max_output });
        }
        match status {
            Err(liblzma::stream::Error::Mem) => return Err(LzmaError::Allocation),
            Err(_) => return Err(LzmaError::Corrupt),
            Ok(Status::StreamEnd) if size.is_none() || out.len() as u64 == target => return Ok(out),
            Ok(Status::StreamEnd) => return Err(LzmaError::Truncated),
            Ok(_) if stream.total_in() == i && stream.total_out() == o => {
                // No progress with room to write: the input is used up.
                return Err(if consumed == input.len() { LzmaError::Truncated } else { LzmaError::Corrupt });
            }
            Ok(_) => {}
        }
    }
}
