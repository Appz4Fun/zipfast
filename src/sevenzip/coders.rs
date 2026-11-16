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

//! A folder's coders wired up as a chain of readers. The graph follows the folder's bind pairs from the output stream
//! no bind pair consumes back to the packed streams, so any arrangement 7-Zip writes decodes, including BCJ2's four
//! inputs. Every coder's output is cut to the size the header gives it, and a stream that ends early is an error.
use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read};
use std::path::PathBuf;
use std::{cell::RefCell, rc::Rc};

use super::bcj::{Arch, BranchReader, DeltaReader, SwapReader};
use super::bcj2::Bcj2Reader;
use super::source::{PackReader, VolumeSet};
use super::{SevenZipError, SevenZipLimit, SevenZipLimits};
use crate::extract::Cancellation;
use crate::map::{CipherParams, CoderKind, MapCoder, MapFolder};

const BUF: usize = 64 << 10;

/// Why a folder stream stopped, carried inside an `io::Error` through the readers.
#[derive(Debug)]
pub(crate) enum Fault {
    /// The packed data does not decode.
    Data(&'static str),
    /// The packed data ends before the header says it does.
    Truncated,
    Canceled,
    /// A volume holding packed data is not there.
    Missing(PathBuf),
    /// Reading the archive failed.
    Input(io::Error),
}

impl std::fmt::Display for Fault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Data(what) => f.write_str(what),
            Self::Truncated => f.write_str("the packed data ends early"),
            Self::Canceled => f.write_str("canceled"),
            Self::Missing(path) => write!(f, "missing volume {}", path.display()),
            Self::Input(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Fault {}

impl From<Fault> for io::Error {
    fn from(fault: Fault) -> Self {
        io::Error::other(fault)
    }
}

/// An `io::Error` for data that does not decode.
pub(crate) fn data_error(what: &'static str) -> io::Error {
    Fault::Data(what).into()
}

impl Fault {
    /// The fault inside an error a reader returned. Errors from a decoding library that are not ours are bad data.
    pub(crate) fn of(error: io::Error) -> Self {
        if error.get_ref().is_some_and(|inner| inner.is::<Fault>()) {
            return *error.into_inner().expect("checked").downcast::<Fault>().expect("checked");
        }
        match error.kind() {
            io::ErrorKind::UnexpectedEof => Fault::Truncated,
            _ => Fault::Data("the packed data does not decode"),
        }
    }
}

/// Bytes a stream passes between cancellation checks.
const CANCEL_EVERY: u64 = 1 << 20;

/// A coder's output (or a packed stream), cut to its declared size; ending early is [`Fault::Truncated`]. Every
/// stream of a folder goes through one, so cancellation is seen every [`CANCEL_EVERY`] bytes at every stage, even
/// inside a decoder that loops on its input without producing output (empty Deflate blocks).
struct Exact<R> {
    inner: R,
    left: u64,
    cancel: Cancellation,
    /// Bytes passed since cancellation was last checked.
    unchecked: u64,
}

impl<R> Exact<R> {
    fn new(inner: R, left: u64, cancel: &Cancellation) -> Self {
        Self { inner, left, cancel: cancel.clone(), unchecked: CANCEL_EVERY }
    }
}

impl<R: Read> Read for Exact<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.left == 0 || buf.is_empty() {
            return Ok(0);
        }
        if self.unchecked >= CANCEL_EVERY {
            if self.cancel.is_canceled() {
                return Err(Fault::Canceled.into());
            }
            self.unchecked = 0;
        }
        let n = (self.left.min(buf.len() as u64)) as usize;
        let got = self.inner.read(&mut buf[..n])?;
        if got == 0 {
            return Err(Fault::Truncated.into());
        }
        self.left -= got as u64;
        self.unchecked += got as u64;
        Ok(got)
    }
}

type Stream = Box<dyn Read>;

/// LZMA or LZMA2 through liblzma's raw decoder.
struct LzmaReader {
    input: BufReader<Stream>,
    stream: liblzma::stream::Stream,
}

impl Read for LzmaReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            let input = self.input.fill_buf()?;
            let eof = input.is_empty();
            let (i, o) = (self.stream.total_in(), self.stream.total_out());
            let action = if eof { liblzma::stream::Action::Finish } else { liblzma::stream::Action::Run };
            let status = self.stream.process(input, out, action);
            let used = (self.stream.total_in() - i) as usize;
            let made = (self.stream.total_out() - o) as usize;
            self.input.consume(used);
            match status {
                Err(liblzma::stream::Error::Mem | liblzma::stream::Error::MemLimit) => {
                    return Err(io::Error::from(io::ErrorKind::OutOfMemory));
                }
                Err(_) => return Err(data_error("LZMA data error")),
                Ok(_) if made > 0 => return Ok(made),
                Ok(liblzma::stream::Status::StreamEnd) => return Ok(0),
                Ok(_) if eof && used == 0 => return Err(Fault::Truncated.into()),
                Ok(_) => {}
            }
        }
    }
}

/// LZMA2's dictionary size for property byte `b` (at most 40).
fn lzma2_dict(b: u8) -> u64 {
    if b >= 40 { u64::from(u32::MAX) } else { (2 | u64::from(b & 1)) << (b / 2 + 11) }
}

/// `dictionaries` is what the folder's earlier LZMA coders allocated; this one's window is added to it.
fn lzma(
    kind: CoderKind,
    properties: &[u8],
    input: Stream,
    size: u64,
    limits: &SevenZipLimits,
    dictionaries: &mut u64,
) -> Built {
    // The dictionary never needs to be larger than the output, so a stated dictionary never allocates more.
    let need = size.max(4096);
    let mut filters = liblzma::stream::Filters::new();
    let window = if kind == CoderKind::Lzma {
        let mut props: [u8; 5] = properties.try_into().map_err(|_| SevenZipError::Corrupt("7z LZMA properties"))?;
        let stated = u64::from(u32::from_le_bytes(props[1..].try_into().expect("four bytes")));
        let dict = stated.clamp(4096, need.min(u64::from(u32::MAX)));
        props[1..].copy_from_slice(&(dict as u32).to_le_bytes());
        filters.lzma1_properties(&props).map_err(|_| SevenZipError::Corrupt("7z LZMA properties"))?;
        dict
    } else {
        let &[b] = properties else { return Err(SevenZipError::Corrupt("7z LZMA2 properties")) };
        if b > 40 {
            return Err(SevenZipError::Corrupt("7z LZMA2 properties"));
        }
        let b = (0..=b).find(|&s| lzma2_dict(s) >= need).unwrap_or(b);
        filters.lzma2_properties(&[b]).map_err(|_| SevenZipError::Corrupt("7z LZMA2 properties"))?;
        lzma2_dict(b)
    };
    let total = dictionaries.saturating_add(window);
    if total > limits.dictionary_bytes {
        return Err(SevenZipError::Limit {
            limit: SevenZipLimit::DictionaryBytes,
            max: limits.dictionary_bytes,
            attempted: total,
        });
    }
    *dictionaries = total;
    let stream = liblzma::stream::Stream::new_raw_decoder(&filters).map_err(|e| match e {
        liblzma::stream::Error::Mem | liblzma::stream::Error::MemLimit => {
            SevenZipError::Io(io::Error::from(io::ErrorKind::OutOfMemory))
        }
        _ => SevenZipError::Corrupt("7z LZMA properties"),
    })?;
    Ok(Box::new(LzmaReader { input: BufReader::with_capacity(BUF, input), stream }))
}

/// 7zAES: AES-256-CBC over whole blocks.
struct AesReader {
    input: Stream,
    key: crate::crypto::AesKey,
    iv: [u8; 16],
    buf: Box<[u8]>,
    at: usize,
    len: usize,
}

impl Read for AesReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.at == self.len {
            // Gather whole blocks.
            let mut have = 0;
            loop {
                let n = self.input.read(&mut self.buf[have..])?;
                have += n;
                if n == 0 || have == self.buf.len() || (have >= 16 && have.is_multiple_of(16)) {
                    break;
                }
            }
            if have == 0 {
                return Ok(0);
            }
            if !have.is_multiple_of(16) {
                return Err(data_error("7zAES data is not a whole number of blocks"));
            }
            self.key.decrypt_cbc_in_place(&mut self.iv, &mut self.buf[..have]);
            self.at = 0;
            self.len = have;
        }
        let n = (self.len - self.at).min(out.len());
        out[..n].copy_from_slice(&self.buf[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}

/// The password and the 7zAES keys derived from it, by cycle power and salt.
pub(crate) struct Keys {
    password: Option<String>,
    cache: HashMap<(u8, Vec<u8>), [u8; 32]>,
}

struct KdfCancel<'a>(&'a Cancellation);

impl crate::crypto::KdfControl for KdfCancel<'_> {
    fn charge(&mut self, _: u64) -> Result<(), crate::crypto::KdfControlError> {
        if self.0.is_canceled() { Err(crate::crypto::KdfControlError::Canceled) } else { Ok(()) }
    }
}

impl Keys {
    pub(crate) fn new(password: Option<&str>) -> Self {
        Self { password: password.filter(|p| !p.is_empty()).map(str::to_owned), cache: HashMap::new() }
    }

    fn key(&mut self, cycles: u8, salt: &[u8], cancel: &Cancellation) -> Result<[u8; 32], SevenZipError> {
        if let Some(key) = self.cache.get(&(cycles, salt.to_vec())) {
            return Ok(*key);
        }
        let password = self.password.as_deref().ok_or(SevenZipError::PasswordRequired)?;
        let key = match crate::crypto::derive_7z_key_controlled(password, salt, cycles, &mut KdfCancel(cancel)) {
            None => return Err(SevenZipError::Unsupported("7zAES cycle count or salt")),
            Some(Err(_)) => return Err(SevenZipError::Canceled),
            Some(Ok(key)) => key,
        };
        self.cache.insert((cycles, salt.to_vec()), key);
        Ok(key)
    }
}

type Built = Result<Stream, SevenZipError>;

/// The 4-byte start offset some branch converters take.
fn branch_start(properties: &[u8]) -> Result<u32, SevenZipError> {
    match properties {
        [] => Ok(0),
        [a, b, c, d] => Ok(u32::from_le_bytes([*a, *b, *c, *d])),
        _ => Err(SevenZipError::Corrupt("7z branch converter properties")),
    }
}

/// Whether this build decodes coder `kind`; the rest are refused before anything is written.
pub(crate) fn supported(kind: CoderKind) -> bool {
    matches!(
        kind,
        CoderKind::Copy
            | CoderKind::Lzma
            | CoderKind::Lzma2
            | CoderKind::Bzip2
            | CoderKind::Deflate
            | CoderKind::Aes
            | CoderKind::Bcj
            | CoderKind::Bcj2
            | CoderKind::Delta
            | CoderKind::PowerPc
            | CoderKind::Ia64
            | CoderKind::Arm
            | CoderKind::ArmThumb
            | CoderKind::Arm64
            | CoderKind::Sparc
    ) || matches!(kind, CoderKind::Other(SWAP2 | SWAP4 | ZSTD))
}

const SWAP2: u64 = 0x02_0302;
const SWAP4: u64 = 0x02_0304;
/// Zstandard as the 7-Zip ZS fork and its plugins write it.
const ZSTD: u64 = 0x04F7_1101;

/// What building a folder needs besides the folder.
pub(crate) struct Context<'a> {
    pub(crate) set: &'a Rc<RefCell<VolumeSet>>,
    pub(crate) keys: &'a mut Keys,
    pub(crate) limits: &'a SevenZipLimits,
    pub(crate) cancel: &'a Cancellation,
    /// LZMA dictionary bytes the folder being built has allocated so far.
    pub(crate) dictionaries: u64,
}

/// The folder's output stream, exactly `folder.unpacked_size` bytes.
pub(crate) fn folder_reader(folder: &MapFolder, cx: &mut Context<'_>) -> Built {
    let coders = &folder.coders;
    let mut in_base = Vec::with_capacity(coders.len());
    let mut out_base = Vec::with_capacity(coders.len());
    let (mut ins, mut outs) = (0u64, 0u64);
    for coder in coders {
        in_base.push(ins);
        out_base.push(outs);
        ins += u64::from(coder.in_streams);
        outs += u64::from(coder.out_streams);
    }
    if folder.unpack_sizes.len() as u64 != outs || folder.pack_sizes.len() != folder.packed_streams.len() {
        return Err(SevenZipError::Corrupt("7z folder stream counts"));
    }
    let main = (0..outs)
        .find(|o| folder.bind_pairs.iter().all(|&(_, out)| out != *o))
        .ok_or(SevenZipError::Corrupt("7z folder output stream"))?;
    let graph = Graph { folder, in_base, out_base };
    let mut used = vec![false; coders.len()];
    let reader = graph.output(main, &mut used, cx)?;
    if used.iter().any(|u| !u) {
        return Err(SevenZipError::Corrupt("7z folder has a coder nothing reads"));
    }
    Ok(reader)
}

struct Graph<'f> {
    folder: &'f MapFolder,
    in_base: Vec<u64>,
    out_base: Vec<u64>,
}

impl Graph<'_> {
    /// The reader for folder output stream `out`.
    fn output(&self, out: u64, used: &mut [bool], cx: &mut Context<'_>) -> Built {
        let coders = &self.folder.coders;
        let index = (0..coders.len())
            .find(|&c| (self.out_base[c]..self.out_base[c] + u64::from(coders[c].out_streams)).contains(&out))
            .ok_or(SevenZipError::Corrupt("7z folder bind pair"))?;
        if used[index] {
            return Err(SevenZipError::Corrupt("7z folder coders form a cycle"));
        }
        used[index] = true;
        let coder = &coders[index];
        if coder.out_streams != 1 {
            return Err(SevenZipError::Unsupported("7z coder with several outputs"));
        }
        let mut inputs = Vec::with_capacity(coder.in_streams as usize);
        for j in 0..u64::from(coder.in_streams) {
            let input = self.in_base[index] + j;
            let reader = if let Some(&(_, bound)) = self.folder.bind_pairs.iter().find(|&&(i, _)| i == input) {
                self.output(bound, used, cx)?
            } else if let Some(k) = self.folder.packed_streams.iter().position(|&p| p == input) {
                let start: u64 = self.folder.pack_sizes[..k].iter().sum();
                let range = start..start + self.folder.pack_sizes[k];
                let pack = PackReader::new(cx.set.clone(), &self.folder.packed, range, cx.cancel.clone());
                Box::new(Exact::new(pack, self.folder.pack_sizes[k], cx.cancel)) as Stream
            } else {
                return Err(SevenZipError::Corrupt("7z coder input bound to nothing"));
            };
            inputs.push(reader);
        }
        let size = self.folder.unpack_sizes[out as usize];
        let reader = coder_reader(coder, inputs, size, cx)?;
        Ok(Box::new(Exact::new(reader, size, cx.cancel)))
    }
}

fn one(mut inputs: Vec<Stream>) -> Result<Stream, SevenZipError> {
    if inputs.len() != 1 {
        return Err(SevenZipError::Corrupt("7z coder stream count"));
    }
    Ok(inputs.pop().expect("one input"))
}

fn coder_reader(coder: &MapCoder, inputs: Vec<Stream>, size: u64, cx: &mut Context<'_>) -> Built {
    let props = coder.properties.as_slice();
    let branch = |inputs: Vec<Stream>, arch: Arch| -> Built {
        Ok(Box::new(BranchReader::new(one(inputs)?, arch, branch_start(props)?)))
    };
    match coder.kind {
        CoderKind::Copy => one(inputs),
        kind @ (CoderKind::Lzma | CoderKind::Lzma2) => {
            lzma(kind, props, one(inputs)?, size, cx.limits, &mut cx.dictionaries)
        }
        CoderKind::Deflate => {
            Ok(Box::new(flate2::bufread::DeflateDecoder::new(BufReader::with_capacity(BUF, one(inputs)?))))
        }
        CoderKind::Bzip2 => {
            Ok(Box::new(bzip2::bufread::MultiBzDecoder::new(BufReader::with_capacity(BUF, one(inputs)?))))
        }
        CoderKind::Aes => {
            let Some(CipherParams::SevenZipAes { num_cycles_power, salt, iv }) =
                crate::map::sevenzip::aes_params(props)
            else {
                return Err(SevenZipError::Corrupt("7zAES properties"));
            };
            let input = one(inputs)?;
            let key = cx.keys.key(num_cycles_power, &salt, cx.cancel)?;
            let key = crate::crypto::AesKey::new(&key).expect("AES-256 key");
            Ok(Box::new(AesReader { input, key, iv, buf: vec![0; BUF].into_boxed_slice(), at: 0, len: 0 }))
        }
        CoderKind::Delta => {
            let dist = match props {
                [d] => usize::from(*d) + 1,
                _ => return Err(SevenZipError::Corrupt("7z Delta properties")),
            };
            Ok(Box::new(DeltaReader::new(one(inputs)?, dist)))
        }
        CoderKind::Bcj => branch(inputs, Arch::X86),
        CoderKind::PowerPc => branch(inputs, Arch::PowerPc),
        CoderKind::Ia64 => branch(inputs, Arch::Ia64),
        CoderKind::Arm => branch(inputs, Arch::Arm),
        CoderKind::ArmThumb => branch(inputs, Arch::ArmThumb),
        CoderKind::Sparc => branch(inputs, Arch::Sparc),
        CoderKind::Arm64 => branch(inputs, Arch::Arm64),
        CoderKind::Bcj2 => {
            let [main, call, jump, rc]: [Stream; 4] =
                inputs.try_into().map_err(|_| SevenZipError::Corrupt("7z BCJ2 stream count"))?;
            let buffered = |s: Stream| BufReader::with_capacity(BUF, s);
            Ok(Box::new(Bcj2Reader::new(buffered(main), buffered(call), buffered(jump), buffered(rc))))
        }
        CoderKind::Other(SWAP2) => Ok(Box::new(SwapReader::new(one(inputs)?, 2))),
        CoderKind::Other(SWAP4) => Ok(Box::new(SwapReader::new(one(inputs)?, 4))),
        CoderKind::Other(ZSTD) => {
            let decoder = zstd::stream::read::Decoder::with_buffer(BufReader::with_capacity(BUF, one(inputs)?))
                .map_err(SevenZipError::Io)?;
            Ok(Box::new(decoder))
        }
        CoderKind::Ppmd => Err(SevenZipError::UnsupportedCoder { id: coder.id }),
        _ => Err(SevenZipError::UnsupportedCoder { id: coder.id }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Empty stored Deflate blocks, forever.
    struct EmptyBlocks;

    impl Read for EmptyBlocks {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = [0u8, 0, 0, 0xFF, 0xFF][i % 5];
            }
            Ok(buf.len() / 5 * 5)
        }
    }

    #[test]
    fn a_decoder_looping_on_its_input_still_sees_cancellation() {
        let cancel = Cancellation::default();
        cancel.cancel();
        // Deflate makes no output from empty blocks, so it keeps reading; the stream it reads checks the token.
        let input = Exact::new(EmptyBlocks, u64::MAX, &cancel);
        let mut deflate = flate2::bufread::DeflateDecoder::new(BufReader::new(input));
        let error = deflate.read(&mut [0u8; 16]).unwrap_err();
        assert!(matches!(Fault::of(error), Fault::Canceled));
    }

    #[test]
    fn exact_checks_cancellation_every_mebibyte() {
        let cancel = Cancellation::default();
        let mut exact = Exact::new(io::repeat(0), u64::MAX, &cancel);
        let mut buf = vec![0u8; 64 << 10];
        assert!(exact.read(&mut buf).unwrap() > 0);
        cancel.cancel();
        let mut read = 0u64;
        let error = loop {
            match exact.read(&mut buf) {
                Ok(n) => read += n as u64,
                Err(e) => break e,
            }
        };
        assert!(matches!(Fault::of(error), Fault::Canceled));
        assert!(read <= CANCEL_EVERY);
    }
}
