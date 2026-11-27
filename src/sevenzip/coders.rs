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
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

use super::bcj::{Arch, BranchReader, DeltaReader, SwapReader};
use super::bcj2::Bcj2Reader;
use super::lzma2_par::{self, Lzma2Blocks};
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
pub(crate) struct LzmaReader {
    input: BufReader<Stream>,
    stream: liblzma::stream::Stream,
    /// the data turned out bad after the bytes last returned: the next read says so
    failed: bool,
}

impl LzmaReader {
    pub(crate) fn new(input: Stream, stream: liblzma::stream::Stream) -> Self {
        Self { input: BufReader::with_capacity(BUF, input), stream, failed: false }
    }
}

impl Read for LzmaReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.failed {
            return Err(data_error("LZMA data error"));
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
                // what decoded before the bad data goes out first (7-Zip's `x -so` streams it), the error after
                // (only when the caller still wants more: one asking for exactly the bytes made would never ask
                // again, and the failure would be lost)
                Err(_) if made > 0 && made < out.len() => {
                    self.failed = true;
                    return Ok(made);
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

/// `dictionaries` is what the folder's earlier LZMA coders allocated; this one's window is added to it. An LZMA2
/// coder with `threads` above one decodes its blocks on that many worker threads besides the caller's
/// ([`Lzma2Blocks`]); each worker's window comes out of what `dictionary_bytes` has left.
fn lzma(kind: CoderKind, properties: &[u8], input: Stream, size: u64, cx: &mut Context<'_>) -> Built {
    let (limits, dictionaries) = (cx.limits, &mut cx.dictionaries);
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
        let b = lzma2_par::shrink(b, need);
        filters.lzma2_properties(&[b]).map_err(|_| SevenZipError::Corrupt("7z LZMA2 properties"))?;
        lzma2_par::dict_size(b)
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
    if kind == CoderKind::Lzma2 && cx.threads > 1 && size >= 2 * lzma2_par::MIN_PIECE {
        // The caller's thread reads the stream, hands out the output and decodes the head piece in the window
        // counted above; up to `threads` workers decode the pieces after it, as many as the parallel budget pays
        // for, dictionaries and buffers included ([`lzma2_par::plan`]). Their windows also come out of what
        // `dictionary_bytes` leaves once the whole folder is built (`cx.spare`), shared by all its LZMA2 coders,
        // taken when the workers start.
        let (workers, memory) = lzma2_par::plan(cx.threads, limits.lzma2_parallel_bytes, window);
        if workers > 0 {
            let b = lzma2_par::shrink(properties[0], need);
            let blocks = Lzma2Blocks::new(input, size, b, workers, memory, cx.cancel).map_err(|e| {
                if e.kind() == io::ErrorKind::OutOfMemory {
                    SevenZipError::Io(e)
                } else {
                    SevenZipError::Corrupt("7z LZMA properties")
                }
            })?;
            return Ok(Box::new(blocks.with_allowance(cx.spare.clone(), window)));
        }
    }
    let stream = liblzma::stream::Stream::new_raw_decoder(&filters).map_err(|e| match e {
        liblzma::stream::Error::Mem | liblzma::stream::Error::MemLimit => {
            SevenZipError::Io(io::Error::from(io::ErrorKind::OutOfMemory))
        }
        _ => SevenZipError::Corrupt("7z LZMA properties"),
    })?;
    Ok(Box::new(LzmaReader::new(input, stream)))
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

    /// Remembers a key derived elsewhere (the encrypted header's) for folders with the same parameters.
    pub(crate) fn seed(&mut self, cycles: u8, salt: Vec<u8>, key: [u8; 32]) {
        if self.password.is_some() {
            self.cache.insert((cycles, salt), key);
        }
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
            | CoderKind::Deflate64
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
            | CoderKind::Ppmd
    ) || matches!(kind, CoderKind::Other(SWAP2 | SWAP4 | ZSTD))
}

const SWAP2: u64 = 0x02_0302;
const SWAP4: u64 = 0x02_0304;
/// Zstandard as the 7-Zip ZS fork and its plugins write it.
const ZSTD: u64 = 0x04F7_1101;

/// 7-Zip PPMd (PPMd variant H with 7-Zip's range coder): an order byte and the model's memory in bytes. The
/// model's memory counts against the folder's dictionary budget.
fn ppmd(props: &[u8], input: Stream, size: u64, cx: &mut Context<'_>) -> Built {
    let &[order, m0, m1, m2, m3] = props else { return Err(SevenZipError::Corrupt("7z PPMd properties")) };
    let memory = u32::from_le_bytes([m0, m1, m2, m3]);
    if !(2..=64).contains(&order) || !((1 << 11)..=(256 << 20)).contains(&memory) {
        return Err(SevenZipError::Corrupt("7z PPMd properties"));
    }
    let total = cx.dictionaries.saturating_add(u64::from(memory));
    if total > cx.limits.dictionary_bytes {
        return Err(SevenZipError::Limit {
            limit: SevenZipLimit::DictionaryBytes,
            max: cx.limits.dictionary_bytes,
            attempted: total,
        });
    }
    cx.dictionaries = total;
    Ok(Box::new(PpmdReader {
        input,
        buf: Vec::with_capacity(PPMD_LOOKAHEAD * 2),
        pos: 0,
        eof: false,
        model: None,
        order,
        memory,
        left: size,
    }))
}

/// One PPMd character never reads more than this much input.
const PPMD_LOOKAHEAD: usize = 4096;

struct PpmdReader {
    input: Stream,
    buf: Vec<u8>,
    pos: usize,
    eof: bool,
    /// started at the first read
    model: Option<Box<crate::rar5::unpack::rar4::ppm::Ppm>>,
    order: u8,
    memory: u32,
    left: u64,
}

impl PpmdReader {
    /// Buffers at least the lookahead, unless the input ends first.
    fn fill(&mut self) -> io::Result<()> {
        while !self.eof && self.buf.len() - self.pos < PPMD_LOOKAHEAD {
            if self.pos > 0 {
                self.buf.drain(..self.pos);
                self.pos = 0;
            }
            let at = self.buf.len();
            self.buf.resize(at + PPMD_LOOKAHEAD, 0);
            let n = self.input.read(&mut self.buf[at..])?;
            self.buf.truncate(at + n);
            self.eof = n == 0;
        }
        Ok(())
    }
}

impl Read for PpmdReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        use crate::rar5::unpack::rar4::ppm::{Bits, Ppm};
        let bad = || io::Error::new(io::ErrorKind::InvalidData, "7z PPMd data");
        let mut n = 0;
        while n < out.len() && self.left > 0 {
            self.fill()?;
            let mut bits = Bits { data: &self.buf, addr: self.pos, bit: 0 };
            let model = match &mut self.model {
                Some(model) => model,
                None => {
                    let mut model = Box::<Ppm>::default();
                    if !model.init_7z(&mut bits, self.order, self.memory) {
                        return Err(bad());
                    }
                    self.model.insert(model)
                }
            };
            // decode while a whole character's lookahead is buffered, or the input has ended: true at first, as
            // `fill` buffered it
            let want = out.len().min(n.saturating_add(usize::try_from(self.left).unwrap_or(usize::MAX)));
            let start = n;
            while n < want && (self.eof || self.buf.len().saturating_sub(bits.addr) >= PPMD_LOOKAHEAD) {
                out[n] = model.decode_char(&mut bits).ok_or_else(bad)?;
                // past the input's end the decoder reads zeros; more than a few is damage
                if bits.addr > self.buf.len() + 8 {
                    return Err(bad());
                }
                n += 1;
            }
            self.pos = bits.addr;
            self.left -= (n - start) as u64;
        }
        Ok(n)
    }
}

/// What building a folder needs besides the folder.
pub(crate) struct Context<'a> {
    pub(crate) set: &'a Rc<RefCell<VolumeSet>>,
    pub(crate) keys: &'a mut Keys,
    pub(crate) limits: &'a SevenZipLimits,
    pub(crate) cancel: &'a Cancellation,
    /// LZMA dictionary bytes the folder being built has allocated so far.
    pub(crate) dictionaries: u64,
    /// Threads an LZMA2 coder may decode its blocks on; 1 for the one-thread decoder.
    pub(crate) threads: usize,
    /// What `dictionary_bytes` leaves for LZMA2 workers once the folder is built, shared by its coders.
    pub(crate) spare: Rc<Cell<u64>>,
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
    // Every coder's own window is counted now: the LZMA2 workers may have what is left.
    cx.spare.set(cx.limits.dictionary_bytes.saturating_sub(cx.dictionaries));
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
        kind @ (CoderKind::Lzma | CoderKind::Lzma2) => lzma(kind, props, one(inputs)?, size, cx),
        CoderKind::Deflate => {
            Ok(Box::new(flate2::bufread::DeflateDecoder::new(BufReader::with_capacity(BUF, one(inputs)?))))
        }
        CoderKind::Deflate64 => {
            Ok(Box::new(crate::inflate64::Inflate64Reader::new(BufReader::with_capacity(BUF, one(inputs)?))))
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
        CoderKind::Ppmd => ppmd(props, one(inputs)?, size, cx),
        _ => Err(SevenZipError::UnsupportedCoder { id: coder.id }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Codex on #317: a data error liblzma reports in the call that also made the last bytes the caller asked for is
    /// not put off to a later read (a caller asking for exactly what is left never reads again): the read fails.
    #[test]
    fn a_data_error_with_the_last_bytes_asked_for_fails_the_read() {
        let data: Vec<u8> =
            (0..10_000u32).map(|i| b"lzma end marker test "[(i % 21) as usize] ^ (i / 997) as u8).collect();
        let options = liblzma::stream::LzmaOptions::new_preset(6).unwrap();
        let mut filters = liblzma::stream::Filters::new();
        filters.lzma1(&options);
        let mut encoder = liblzma::stream::Stream::new_raw_encoder(&filters).unwrap();
        let mut packed = Vec::with_capacity(data.len() + 1024);
        encoder.process_vec(&data, &mut packed, liblzma::stream::Action::Finish).unwrap();
        let mut cases = 0;
        for back in 1..=8.min(packed.len()) {
            for bit in 0..8 {
                let mut bad = packed.clone();
                let at = bad.len() - back;
                bad[at] ^= 1 << bit;
                // what liblzma does with an output buffer of exactly the data's length
                let mut direct = liblzma::stream::Stream::new_raw_decoder(&filters).unwrap();
                let mut out = vec![0u8; data.len()];
                let status = direct.process(&bad, &mut out, liblzma::stream::Action::Finish);
                if status.is_ok() || direct.total_out() != data.len() as u64 {
                    continue;
                }
                cases += 1;
                let stream = liblzma::stream::Stream::new_raw_decoder(&filters).unwrap();
                let mut reader = LzmaReader::new(Box::new(io::Cursor::new(bad)), stream);
                let mut out = vec![0u8; data.len()];
                assert!(reader.read(&mut out).is_err(), "byte {back} from the end, bit {bit}");
            }
        }
        assert!(cases > 0, "no damage made the decoder fail with the last byte");
    }

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
    fn deflate64_looping_on_empty_blocks_still_sees_cancellation() {
        let cancel = Cancellation::default();
        cancel.cancel();
        let input = Exact::new(EmptyBlocks, u64::MAX, &cancel);
        let mut deflate64 = crate::inflate64::Inflate64Reader::new(BufReader::new(input));
        let error = deflate64.read(&mut [0u8; 16]).unwrap_err();
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
