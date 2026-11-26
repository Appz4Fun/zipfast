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

//! Testing and extracting 7z archives, single files and split sets (`.7z.001`, `.7z.002`, ...).
//!
//! The headers come from the member map ([`crate::map`]); this module decodes the folders. Each folder's coders are
//! wired up from its bind pairs, and its output is streamed in order: a solid folder is never held in memory, and
//! members are cut from it by their sizes. Every member's CRC (and a folder's own CRC where one is stored) is checked
//! before its file is published: data goes to a temporary file beside the target, which takes the target's name only
//! once it checks out. See `docs/7z-extract.md`.
//!
//! [`crate::extract::run`], [`crate::extract::run_with_password`] and [`crate::extract::run_with_zip_policy`] find a
//! 7z archive by its signature and come here, with the default [`SevenZipLimits`].

mod bcj;
mod bcj2;
mod coders;
mod lzma2_par;
mod run;
mod source;

use std::path::Path;
use std::task::{Context, Poll, Waker};

use crate::error::{Error, Result};
use crate::extract::{Cancellation, Entry, MtimeOrigin, Options, Summary};
use crate::map::{CoderKind, MapBuilder, MapEnd, MapError, MapFolder, MapFormat, MapOptions, MemberMap};

/// Bounds on what a 7z archive may ask for. The defaults open every archive 7-Zip writes with its own settings,
/// including solid folders of many gigabytes and 7-Zip's largest dictionaries; a caller that must bound a hostile
/// archive's work or memory lowers them.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct SevenZipLimits {
    /// Decoded bytes per folder (a solid block, or one file): no limit by default (`u64::MAX`). It bounds every
    /// coder's output in the folder, not only the last one, and the outputs of all a folder's coders together may
    /// total at most four times this, so a lowered limit keeps any stage of a coder chain from expanding a little
    /// packed data without bound. What it protects is work and output size, not memory: every coder streams, and
    /// each stops at the size its folder declares. Decoding checks for cancellation at least once per MiB whatever
    /// the limit.
    pub folder_bytes: u64,
    /// Folders in the archive: 4096.
    pub folders: u64,
    /// Packed streams in the archive: 4096.
    pub pack_streams: u64,
    /// Coders in one folder: 32.
    pub coders: u64,
    /// Property bytes of one coder: 64.
    pub coder_properties: u64,
    /// Entries (files, folders, empty files and anti items): 65536.
    pub entries: u64,
    /// Memory one folder's decoders may allocate up front: LZMA and LZMA2 dictionaries, each first shrunk to its
    /// coder's declared output size, summed over the folder's coders (a BCJ2 folder has three): 4 GiB, the largest
    /// LZMA dictionary there is (7-Zip offers up to 1536 MiB, `-md=1536m`). This is the memory-bomb guard: a small
    /// archive can declare a large dictionary and a large output, and this caps what that makes the decoder
    /// allocate. An allocation the system refuses up front is an `OutOfMemory` I/O error, but Linux and macOS usually
    /// overcommit, so memory may only run short as a dictionary fills, where the system (Linux's OOM killer, say) may
    /// end the process instead. The Zstandard coder's window, at most what its frame header asks for, isn't counted
    /// here. Lower it on a machine with less memory to spare.
    pub dictionary_bytes: u64,
    /// [`print_selected`] (and reading one member through `extract::SelectedEntry`): the most plaintext one member
    /// may hold back until its CRC checks out: 8 GiB. A larger member fails with
    /// [`SevenZipLimit::SpoolBytes`] as soon as it goes past this, prints nothing, and the run goes on.
    pub spool_member_bytes: u64,
    /// Plaintext all held-back members keep in memory together: 1 MiB, so short members never touch the disk.
    /// Past it a member moves to the run's temporary file. A folder that holds its members back for its own CRC
    /// counts them all against this, however many there are.
    pub spool_memory_bytes: u64,
    /// The folder for the run's temporary file: the system's temporary folder by default. The run keeps one such
    /// file, each held member a range of it, and it is unlinked as it is made (it has no name in the folder), so
    /// nothing is left behind however the process ends, and the run uses one descriptor however many members it
    /// holds back.
    pub spool_dir: Option<std::path::PathBuf>,
    /// Memory an LZMA2 coder decoding its blocks on several threads may add: 256 MiB (at least 4 MiB is used). A
    /// stream 7-Zip wrote with `-mmt` is a run of independent blocks; with more than one thread they are decoded
    /// side by side. Each worker thread costs its dictionary and a 1 MiB output buffer; the workers take at most a
    /// third of this (fewer start when they would take more; their dictionaries count against `dictionary_bytes`
    /// too), and the packed and decoded bytes in flight the rest: a worker waits while that is spent. Large blocks
    /// (7-Zip's are four times the dictionary: 64 MiB to 256 MiB at `-mx5` to `-mx9`) then decode only partly side
    /// by side; a caller that wants the most speed and has the memory raises it. See `docs/7z-extract.md`.
    pub lzma2_parallel_bytes: u64,
    /// Threads [`print_selected`] (and reading one member through `extract::SelectedEntry`) decode a folder's
    /// LZMA2 blocks on: None for one per core, `Some(1)` for the calling thread alone. [`run`] takes
    /// [`Options::threads`] instead.
    pub decode_threads: Option<usize>,
}

impl Default for SevenZipLimits {
    fn default() -> Self {
        Self {
            folder_bytes: u64::MAX,
            folders: 4096,
            pack_streams: 4096,
            coders: 32,
            coder_properties: 64,
            entries: 65536,
            dictionary_bytes: 4 << 30,
            spool_member_bytes: 8 << 30,
            spool_memory_bytes: 1 << 20,
            spool_dir: None,
            lzma2_parallel_bytes: 256 << 20,
            decode_threads: None,
        }
    }
}

/// Which of [`SevenZipLimits`] an archive went past.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SevenZipLimit {
    /// A folder's output, or any one coder's output in it, is larger than `folder_bytes`.
    FolderBytes,
    /// The outputs of all a folder's coders total more than four times `folder_bytes`.
    FolderCoderBytes,
    Folders,
    PackStreams,
    Coders,
    CoderProperties,
    Entries,
    DictionaryBytes,
    /// A printed member held back more plaintext than `spool_member_bytes` before its CRC could check it.
    SpoolBytes,
}

/// How a member of an encrypted 7z folder failed under a password that was never proven right: the evidence that
/// the password is wrong, which 7-Zip words differently.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum EncryptedFailure {
    /// The decrypted data did not decode (a compressed folder: LZMA, LZMA2, PPMd, BZip2, Deflate): 7-Zip's
    /// "Data Error in encrypted file. Wrong password?".
    DataError,
    /// The decrypted data decoded (a Copy folder, or a coder that took the garbage) but failed the member's or the
    /// folder's CRC: 7-Zip's "CRC Failed in encrypted file. Wrong password?".
    CrcFailed,
}

impl EncryptedFailure {
    /// 7-Zip 26.06's message for it, as it prints it after `ERROR: ` and before ` : <name>`.
    pub fn seven_zip_message(self) -> &'static str {
        match self {
            Self::DataError => "Data Error in encrypted file. Wrong password?",
            Self::CrcFailed => "CRC Failed in encrypted file. Wrong password?",
        }
    }

    /// The text of a member's line in [`Summary::errors`] after `<name>: `.
    pub(crate) fn line(self) -> &'static str {
        match self {
            Self::DataError => "data error in encrypted file: wrong password?",
            Self::CrcFailed => "CRC failed in encrypted file: wrong password?",
        }
    }
}

/// Why a 7z run stopped.
///
/// Through [`crate::extract::run`] and friends it arrives inside the crate [`Error`]: see [`SevenZipError::of`].
/// Through [`crate::extract::run_with_zip_policy`] a missing password is `ReadFault::PasswordRequired`, a wrong one
/// `ReadFault::PasswordCheckFailed` (for the run with encrypted headers, for each member with encrypted data only)
/// and cancellation `ReadFault::Cancelled`; the rest is `ReadFault::Legacy`.
#[derive(Debug)]
#[non_exhaustive]
pub enum SevenZipError {
    /// Encrypted data or headers, and no password.
    PasswordRequired,
    /// The password does not decrypt the headers, which stops the run (`failure: None`); or, as a member's error, the
    /// member's encrypted folder does not decode or fails its CRC before the password is proven (7z has no password
    /// check value), and `failure` says which, as 7-Zip's wording does: [`EncryptedFailure::DataError`] ("Data Error
    /// in encrypted file. Wrong password?") or [`EncryptedFailure::CrcFailed`] ("CRC Failed in encrypted file. Wrong
    /// password?").
    WrongPassword { failure: Option<EncryptedFailure> },
    /// The [`Cancellation`] was triggered. Nothing in progress is published.
    Canceled,
    /// The archive asks for more than [`SevenZipLimits`] allows.
    Limit { limit: SevenZipLimit, max: u64, attempted: u64 },
    /// A coder this build does not decode (PPMd, RISC-V, or an unknown method id), found before anything
    /// is written. `id` is the method id as stored.
    UnsupportedCoder { id: u64 },
    /// A header feature this build does not handle.
    Unsupported(&'static str),
    /// The headers are corrupt or inconsistent.
    Corrupt(&'static str),
    /// The member map failed (damaged headers, header limits).
    Map(MapError),
    /// A volume of a split set is not there.
    MissingVolume(std::path::PathBuf),
    /// The archive cannot be read, or the output cannot be written.
    Io(std::io::Error),
}

impl std::fmt::Display for SevenZipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PasswordRequired => f.write_str("7z: a password is required"),
            Self::WrongPassword { failure: None } => f.write_str("7z: wrong password"),
            Self::WrongPassword { failure: Some(failure) } => write!(f, "7z: {}", failure.line()),
            Self::Canceled => f.write_str("7z: canceled"),
            Self::Limit { limit, max, attempted } => write!(f, "7z limit {limit:?} exceeded ({attempted} > {max})"),
            Self::UnsupportedCoder { id } => write!(f, "7z coder {id:#x} is not supported"),
            Self::Unsupported(what) => write!(f, "7z: unsupported {what}"),
            Self::Corrupt(what) => write!(f, "7z: corrupt archive: {what}"),
            Self::Map(e) => write!(f, "7z: {e}"),
            Self::MissingVolume(path) => write!(f, "7z: missing volume {}", path.display()),
            Self::Io(e) => write!(f, "7z: {e}"),
        }
    }
}

impl std::error::Error for SevenZipError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Map(e) => Some(e),
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl SevenZipError {
    /// The 7z failure inside a crate [`Error`] a 7z run returned, if it is one.
    ///
    /// The legacy `Error` keeps its variants, so a 7z failure arrives as the variant that already means it
    /// ([`Error::Encrypted`] for a missing password, [`Error::MissingVolume`], [`Error::Io`] for I/O) or else as an
    /// [`Error::Io`] carrying the `SevenZipError`, whose kind is `PermissionDenied` for a wrong password,
    /// `ConnectionAborted` for cancellation (as [`Cancellation`] reports it elsewhere), `Unsupported` for an
    /// unsupported coder or feature, `InvalidInput` for a limit and `InvalidData` for corrupt headers.
    pub fn of(error: &Error) -> Option<&SevenZipError> {
        match error {
            Error::Io(e) => e.get_ref().and_then(|inner| inner.downcast_ref::<SevenZipError>()),
            _ => None,
        }
    }
}

impl From<SevenZipError> for Error {
    fn from(e: SevenZipError) -> Self {
        use std::io::{Error as IoError, ErrorKind};
        let kind = match &e {
            SevenZipError::PasswordRequired => return Error::Encrypted,
            SevenZipError::MissingVolume(path) => return Error::MissingVolume(path.clone()),
            SevenZipError::Io(_) => {
                let SevenZipError::Io(io) = e else { unreachable!() };
                return Error::Io(io);
            }
            SevenZipError::WrongPassword { .. } => ErrorKind::PermissionDenied,
            SevenZipError::Canceled => ErrorKind::ConnectionAborted,
            SevenZipError::UnsupportedCoder { .. } | SevenZipError::Unsupported(_) => ErrorKind::Unsupported,
            SevenZipError::Limit { .. } => ErrorKind::InvalidInput,
            SevenZipError::Corrupt(_) | SevenZipError::Map(_) => ErrorKind::InvalidData,
        };
        Error::Io(IoError::new(kind, e))
    }
}

/// Whether `head`, a file's first bytes, starts a 7z archive.
pub(crate) fn sniff(head: &[u8]) -> bool {
    head.starts_with(&crate::map::sevenzip::MAGIC)
}

/// Tests or extracts the 7z archive whose first volume is `first`, decrypting with `password` when encrypted.
///
/// Options, member selection, overwrite choices (including the rename modes), protected paths and the per-file report
/// lines work as for the other formats' whole-archive runs; a rename is a report line as it is made and an entry in
/// [`Summary::renames`]. A member that fails (a CRC mismatch, data that does not decode, an unsafe name) is a
/// line in [`Summary::errors`] and is not published; the run goes on. So is a member whose encrypted folder the
/// password does not decrypt (`<name>: data error in encrypted file: wrong password?` when its folder's data does not
/// decode, `<name>: CRC failed in encrypted file: wrong password?` when it decodes but fails a CRC; each member of a
/// solid folder, with [`SevenZipError::WrongPassword`] carrying the matching [`EncryptedFailure`] as its error), as
/// 7-Zip reports each one. The run itself fails on a missing
/// password, a wrong one for encrypted headers, a limit, an unsupported coder, cancellation, unreadable headers or
/// volumes and output errors.
pub fn run(
    first: &Path,
    options: &Options,
    password: Option<&str>,
    cancel: &Cancellation,
    limits: &SevenZipLimits,
    mut report: impl FnMut(&str),
) -> Result<Summary> {
    run_reporting(first, options, password, cancel, limits, &mut report).map_err(|e| e.error)
}

/// Prints the members `select` takes to `output` in archive order, as `7z x -so` does: their data only, one after
/// another.
///
/// `select` gets each member's listing index (as [`list`] numbers them) and name; directories are never offered.
/// Each folder is decoded once, front to back, also when several of its members are taken (the members before and
/// between them are decoded and dropped), so printing a whole solid archive costs one decode. Each member is spooled
/// to a private temporary file until its CRC checks out (and, for a folder of several members that stores its own
/// CRC, until the folder's does, which prints the folder's members together at its end), so a member that fails
/// prints nothing. Such a member is a line in [`Summary::errors`] and the run goes on, as in [`run`]; `files` and
/// `bytes` count what was printed. The run itself fails as [`run`] does (a missing or wrong password, a limit, an
/// unsupported coder, cancellation, unreadable headers or volumes) and on an error writing to `output`, after which
/// `output` may hold the members printed before.
pub fn print_selected(
    first: &Path,
    password: Option<&str>,
    mut select: impl FnMut(u64, &str) -> bool,
    output: &mut dyn std::io::Write,
    cancel: &Cancellation,
    limits: &SevenZipLimits,
) -> Result<Summary> {
    print_selected_with(first, password, &mut select, &mut |_, bytes| output.write_all(bytes), cancel, limits)
}

/// [`print_selected`] handing each chunk to `on_bytes` with the listing index of the member it belongs to, so a
/// caller can tell where one member ends and the next begins.
pub fn print_selected_with(
    first: &Path,
    password: Option<&str>,
    select: &mut dyn FnMut(u64, &str) -> bool,
    on_bytes: &mut dyn FnMut(u64, &[u8]) -> std::io::Result<()>,
    cancel: &Cancellation,
    limits: &SevenZipLimits,
) -> Result<Summary> {
    run::print(first, password, select, on_bytes, cancel, limits).map_err(Error::from)
}

/// [`run`], reporting a rename mode's renames to `report` as they happen; a terminal error keeps them too.
pub(crate) fn run_reporting(
    first: &Path,
    options: &Options,
    password: Option<&str>,
    cancel: &Cancellation,
    limits: &SevenZipLimits,
    report: &mut impl crate::extract::LegacyReport,
) -> std::result::Result<Summary, crate::extract::RunError> {
    run::run(first, options, password, cancel, limits, report)
        .map_err(|(error, renames)| crate::extract::RunError::new(Error::from(error), renames))
}

/// The entries of a 7z archive, in archive order. Anti items are left out. Listing reads only the headers, so the
/// header limits of [`SevenZipLimits::default`] apply and the decoding ones (`folder_bytes`, the coder-output total
/// and `dictionary_bytes`) don't.
pub fn list(first: &Path, password: Option<&str>) -> Result<Vec<Entry>> {
    list_with_limits(first, password, &SevenZipLimits::default())
}

/// [`list`] under the caller's limits: of them, the header limits (folders, pack streams, coders, coder
/// properties and entries) apply, since listing never decodes.
pub fn list_with_limits(first: &Path, password: Option<&str>, limits: &SevenZipLimits) -> Result<Vec<Entry>> {
    list_entries(first, password, limits, false)
}

/// [`list`], naming each entry as [`run`] with the same `options` would: with
/// [`Options::windows_safe_names`](crate::extract::Options::windows_safe_names) the characters Windows refuses in a
/// name (`<>:"|?*`) read as `_`.
pub fn list_with_options(first: &Path, password: Option<&str>, options: &Options) -> Result<Vec<Entry>> {
    list_entries(first, password, &SevenZipLimits::default(), options.windows_safe_names)
}

fn list_entries(
    first: &Path,
    password: Option<&str>,
    limits: &SevenZipLimits,
    windows_safe: bool,
) -> Result<Vec<Entry>> {
    let map = open_map(first, password, &Cancellation::default(), limits)?;
    check_header_bounds(&map, limits)?;
    Ok(map
        .members
        .iter()
        .map(|m| {
            let folder = m.folder.map(|slot| &map.folders[slot.index as usize]);
            let first_in_folder = m.folder.is_some_and(|slot| slot.offset == 0);
            Entry {
                mode: m.unix_mode,
                name: {
                    let name = member_name(m);
                    if windows_safe { crate::path::windows_safe_name(&name).into_owned() } else { name }
                },
                size: m.unpacked_size.unwrap_or(0),
                size_unknown: false,
                // A folder's packed bytes are counted once, on its first member.
                packed: match folder {
                    Some(f) if first_in_folder => f.pack_sizes.iter().sum(),
                    _ => 0,
                },
                mtime: m.mtime.map(|t| t.0),
                mtime_origin: m.mtime.map(|_| MtimeOrigin::Utc),
                ctime: m.ctime,
                atime: m.atime,
                tar: None,
                attributes: (m.attributes != 0).then_some(m.attributes as u32 & 0xFFFF),
                crc32: m.checks.and_then(|c| c.crc32),
                method: folder.map_or(0, method_number),
                method_name: folder.map(method_name),
                dir: m.is_dir,
                encrypted: m.encrypted,
                solid: folder.is_some_and(|f| f.members > 1),
                // A Unix symbolic link (S_IFLNK): its target is in the member's data, which a listing does not
                // decode, so it is left empty here.
                link: m
                    .unix_mode
                    .is_some_and(|mode| mode & 0o170000 == 0o120000)
                    .then(|| crate::rar5::Redirection::UnixSymlink(String::new())),
                version: None,
            }
        })
        .collect())
}

/// A ZIP-style method number for listings: the folder's compressor (Copy 0, Deflate 8, Deflate64 9, BZip2 12, LZMA
/// 14, LZMA2 33, Zstandard 93, PPMd 98, other 255).
fn method_number(folder: &MapFolder) -> u8 {
    let filter = |k: &CoderKind| {
        !matches!(
            k,
            CoderKind::Aes
                | CoderKind::Bcj
                | CoderKind::Bcj2
                | CoderKind::Delta
                | CoderKind::PowerPc
                | CoderKind::Ia64
                | CoderKind::Arm
                | CoderKind::ArmThumb
                | CoderKind::Arm64
                | CoderKind::Sparc
                | CoderKind::RiscV
        )
    };
    let compressors: Vec<CoderKind> = folder.coders.iter().map(|c| c.kind).filter(filter).collect();
    match compressors.iter().find(|k| **k != CoderKind::Copy).or(compressors.first()) {
        None | Some(CoderKind::Copy) => 0,
        Some(CoderKind::Deflate) => 8,
        Some(CoderKind::Deflate64) => 9,
        Some(CoderKind::Bzip2) => 12,
        Some(CoderKind::Lzma) => 14,
        Some(CoderKind::Lzma2) => 33,
        Some(CoderKind::Other(0x04F7_1101)) => 93,
        Some(CoderKind::Ppmd) => 98,
        Some(_) => 255,
    }
}

/// The folder's method as 7-Zip's listing prints it: each coder's name and properties, last stored coder first,
/// separated by spaces (`LZMA2:24 BCJ`, `LZMA:16 7zAES:19`), following 7-Zip's `CHandler::SetMethodToProp`.
pub(crate) fn method_name(folder: &MapFolder) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(folder.coders.len());
    for coder in folder.coders.iter().rev() {
        let p = &coder.properties;
        let mut s = String::from(match coder.kind {
            CoderKind::Copy => "Copy",
            CoderKind::Lzma => "LZMA",
            CoderKind::Lzma2 => "LZMA2",
            CoderKind::Ppmd => "PPMD",
            CoderKind::Bzip2 => "BZip2",
            CoderKind::Deflate => "Deflate",
            CoderKind::Deflate64 => "Deflate64",
            CoderKind::Aes => "7zAES",
            CoderKind::Bcj => "BCJ",
            CoderKind::Bcj2 => "BCJ2",
            CoderKind::Delta => "Delta",
            CoderKind::PowerPc => "PPC",
            CoderKind::Ia64 => "IA64",
            CoderKind::Arm => "ARM",
            CoderKind::ArmThumb => "ARMT",
            CoderKind::Arm64 => "ARM64",
            CoderKind::Sparc => "SPARC",
            CoderKind::RiscV => "RISCV",
            CoderKind::Other(0x04F7_1101) => "ZSTD",
            CoderKind::Other(_) => "",
        });
        match coder.kind {
            CoderKind::Other(id) if id != 0x04F7_1101 => s = format!("{id:X}"),
            CoderKind::Lzma if p.len() == 5 => {
                let dict = u32::from_le_bytes([p[1], p[2], p[3], p[4]]);
                s.push(':');
                s.push_str(&size_value(dict));
                let d = u32::from(p[0]);
                if d != 0x5D {
                    let (lc, lp, pb) = (d % 9, (d / 9) % 5, d / 45);
                    if lc != 3 {
                        s.push_str(&format!(":lc{lc}"));
                    }
                    if lp != 0 {
                        s.push_str(&format!(":lp{lp}"));
                    }
                    if pb != 2 {
                        s.push_str(&format!(":pb{pb}"));
                    }
                }
            }
            CoderKind::Lzma2 if p.len() == 1 => {
                let d = u32::from(p[0]);
                s.push(':');
                if d & 1 == 0 {
                    s.push_str(&((d >> 1) + 12).to_string());
                } else {
                    s.push_str(&size_value(3u32.wrapping_shl((d >> 1) + 11)));
                }
            }
            CoderKind::Ppmd if p.len() == 5 => {
                let mem = u32::from_le_bytes([p[1], p[2], p[3], p[4]]);
                s.push_str(&format!(":o{}:mem{}", p[0], size_value(mem)));
            }
            CoderKind::Aes if !p.is_empty() => s.push_str(&format!(":{}", p[0] & 0x3F)),
            CoderKind::Delta if p.len() == 1 => s.push_str(&format!(":{}", u32::from(p[0]) + 1)),
            _ => {}
        }
        parts.push(s);
    }
    parts.join(" ")
}

/// 7-Zip's `GetStringForSizeValue`: a power of two as its exponent, else the size with an `m`, `k` or `b` suffix.
fn size_value(val: u32) -> String {
    if val.is_power_of_two() {
        return val.trailing_zeros().to_string();
    }
    if val.is_multiple_of(1 << 20) {
        format!("{}m", val >> 20)
    } else if val.is_multiple_of(1 << 10) {
        format!("{}k", val >> 10)
    } else {
        format!("{val}b")
    }
}

/// The member's name as a filter and the report see it: decoded, or with each bad UTF-16 unit replaced.
pub(crate) fn member_name(m: &crate::map::MapMember) -> String {
    m.name.clone().unwrap_or_else(|| {
        let units: Vec<u16> = m.raw_name.as_chunks::<2>().0.iter().map(|u| u16::from_le_bytes(*u)).collect();
        String::from_utf16_lossy(&units)
    })
}

pub(crate) fn limit(limit: SevenZipLimit, max: u64, attempted: u64) -> SevenZipError {
    SevenZipError::Limit { limit, max, attempted }
}

/// Reads the headers of the archive at `first`.
pub(crate) fn open_map(
    first: &Path,
    password: Option<&str>,
    cancel: &Cancellation,
    limits: &SevenZipLimits,
) -> std::result::Result<MemberMap, SevenZipError> {
    open_map_keyed(first, password, cancel, limits).map(|(map, _)| map)
}

/// A 7z header key: (cycle power, salt, key).
pub(crate) type HeaderKey = (u8, Vec<u8>, [u8; 32]);

/// [`open_map`], also returning the key an encrypted header was decrypted with, so that folders with the same
/// key parameters need no second derivation (up to 2^24 SHA-256 rounds).
pub(crate) fn open_map_keyed(
    first: &Path,
    password: Option<&str>,
    cancel: &Cancellation,
    limits: &SevenZipLimits,
) -> std::result::Result<(MemberMap, Option<HeaderKey>), SevenZipError> {
    if cancel.is_canceled() {
        return Err(SevenZipError::Canceled);
    }
    let mut options = MapOptions::new(first.as_os_str()).password(password);
    options.limits.entries = limits.entries;
    // Encrypted headers take the same key derivations as data: up to 2^24 rounds, as 7-Zip accepts; the work is
    // bounded by the password length limit and stopped by cancellation.
    options.limits.kdf_exponent = 24;
    options.limits.kdf_derivation_blocks = 1 << 40;
    options.limits.kdf_session_blocks = 1 << 40;
    options.control = crate::progressive::SessionControl::from_cancellation(cancel.clone());
    let source = source::FileVolumes { first: first.to_path_buf() };
    let mut builder = MapBuilder::new(Box::new(source), options);
    let mut cx = Context::from_waker(Waker::noop());
    let map = match builder.poll_map(&mut cx) {
        Poll::Ready(result) => result,
        Poll::Pending => unreachable!("files never wait"),
    };
    let key = builder.seven_zip_header_key().cloned();
    let map = map.map_err(|e| match e {
        MapError::PasswordRequired => SevenZipError::PasswordRequired,
        MapError::WrongPassword => SevenZipError::WrongPassword { failure: None },
        MapError::Limit { resource: crate::progressive::Resource::Entries, limit: _, attempted } => {
            limit(SevenZipLimit::Entries, limits.entries, attempted)
        }
        MapError::Source(failure) if matches!(failure.kind, crate::progressive::FailureKind::Canceled) => {
            SevenZipError::Canceled
        }
        MapError::Source(failure) => match failure.kind {
            crate::progressive::FailureKind::Input { cause, .. } => SevenZipError::Io(cause),
            kind => SevenZipError::Map(MapError::Source(Box::new(crate::progressive::ProgressiveFailure::new(kind)))),
        },
        other => SevenZipError::Map(other),
    })?;
    if map.format != MapFormat::SevenZip {
        return Err(SevenZipError::Map(MapError::NotArchive));
    }
    match map.end {
        MapEnd::Complete => Ok((map, key)),
        MapEnd::HeaderUnavailable { volume, .. } => {
            let set = source::VolumeSet::new(first, volume + 1);
            let path = set.paths()[volume as usize].clone();
            if path.exists() {
                Err(SevenZipError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)))
            } else {
                Err(SevenZipError::MissingVolume(path))
            }
        }
        MapEnd::Truncated { .. } => Err(SevenZipError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))),
        _ => Err(SevenZipError::Corrupt("7z headers")),
    }
}

/// Applies all of [`SevenZipLimits`] that the headers decide, decoding ones included.
pub(crate) fn check_bounds(map: &MemberMap, limits: &SevenZipLimits) -> std::result::Result<(), SevenZipError> {
    check_header_bounds(map, limits)?;
    for folder in &map.folders {
        if let Some(&largest) = folder.unpack_sizes.iter().chain([&folder.unpacked_size]).max()
            && largest > limits.folder_bytes
        {
            return Err(limit(SevenZipLimit::FolderBytes, limits.folder_bytes, largest));
        }
        let total = folder.unpack_sizes.iter().fold(0u64, |a, &s| a.saturating_add(s));
        let work = limits.folder_bytes.saturating_mul(4);
        if total > work {
            return Err(limit(SevenZipLimit::FolderCoderBytes, work, total));
        }
    }
    Ok(())
}

/// The limits on the headers themselves, which listing applies too.
fn check_header_bounds(map: &MemberMap, limits: &SevenZipLimits) -> std::result::Result<(), SevenZipError> {
    let folders = map.folders.len() as u64;
    if folders > limits.folders {
        return Err(limit(SevenZipLimit::Folders, limits.folders, folders));
    }
    let packs: u64 = map.folders.iter().map(|f| f.pack_sizes.len() as u64).sum();
    if packs > limits.pack_streams {
        return Err(limit(SevenZipLimit::PackStreams, limits.pack_streams, packs));
    }
    let entries = map.members.len() as u64;
    if entries > limits.entries {
        return Err(limit(SevenZipLimit::Entries, limits.entries, entries));
    }
    for folder in &map.folders {
        let coders = folder.coders.len() as u64;
        if coders > limits.coders {
            return Err(limit(SevenZipLimit::Coders, limits.coders, coders));
        }
        if let Some(props) = folder.coders.iter().map(|c| c.properties.len() as u64).max()
            && props > limits.coder_properties
        {
            return Err(limit(SevenZipLimit::CoderProperties, limits.coder_properties, props));
        }
    }
    Ok(())
}
#[cfg(test)]
mod method_name_tests {
    use super::size_value;

    #[test]
    fn sizes_follow_7zip() {
        assert_eq!(size_value(1 << 24), "24");
        assert_eq!(size_value(3 << 20), "3m");
        assert_eq!(size_value(6 << 10), "6k");
        assert_eq!(size_value(1000), "1000b");
        assert_eq!(size_value(0), "0m");
    }
}

#[cfg(test)]
mod header_key_tests {
    use super::*;
    use crate::crypto::SHA256_COMPRESSIONS;
    use crate::extract::{Mode, Options, Overwrite};

    fn compressions(f: impl FnOnce()) -> u64 {
        SHA256_COMPRESSIONS.with(|c| c.set(0));
        f();
        SHA256_COMPRESSIONS.with(|c| c.get())
    }

    /// An archive with encrypted headers and data derives its key once: the folders reuse the header's key.
    #[test]
    fn an_encrypted_header_key_is_derived_once_per_run() {
        let first = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/7z-extract/aes_hdr.7z"));
        let limits = SevenZipLimits::default();
        let cancel = Cancellation::default();
        let map_only = compressions(|| {
            let (_, key) = open_map_keyed(first, Some("password"), &cancel, &limits).unwrap();
            assert!(key.is_some(), "the header key is handed on");
        });
        let dir = tempfile::tempdir().unwrap();
        let options = Options {
            mode: Mode::Test,
            dest: dir.path().to_path_buf(),
            overwrite: Overwrite::Skip,
            flatten: false,
            threads: None,
            protected_paths: Default::default(),
            parallel_min: None,
            select: None,
            windows_safe_names: false,
            special_entries: Default::default(),
            fallback_mtime: None,
            compressed_tar: Default::default(),
            version_naming: Default::default(),
            preexisting_links: Default::default(),
            refused_link_placeholder: false,
            restart_from_first_volume: false,
            replace_placed_links: false,
            keep_broken: false,
            attempt_continued_members: false,
            damaged_input: Default::default(),
            unsupported_filters: Default::default(),
            salvage_truncated_zip: false,
            unix_modes: Default::default(),
            backslashes: Default::default(),
        };
        let whole = compressions(|| {
            let summary = run(first, &options, Some("password"), &cancel, &limits, |_| {}).unwrap();
            assert!(summary.errors.is_empty(), "{:?}", summary.errors);
        });
        // One derivation is 2^cycles rounds of a few blocks each; the run adds only a few blocks of its own.
        assert!(map_only > 1 << 16, "{map_only}");
        assert!(whole < map_only + map_only / 4, "the run derived the key again: {whole} vs {map_only}");
    }
}
