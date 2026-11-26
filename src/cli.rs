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

//! `zipfast <command> [switches] <archive> [destination]`

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use crate::extract::{self, Mode, Options, Overwrite};

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod fd;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use fd::FdWriter;

const USAGE: &str = "usage: zipfast <command> [switches] <archive> [destination/]

commands:
  l   list the archive's contents
  t   test: read every file and check its checksum
  x   extract with full paths
  e   extract every file into the destination, without folders
  repack [--mtime=N] [--level=N] [--nested] <archive> <output>
      rewrite an ar archive as ar, or a tarball as a .tar.gz, byte-for-byte reproducibly:
      sorted members, owner 0, normalised modes, every time N (default $SOURCE_DATE_EPOCH,
      else 0), gzip level N (default 9); --nested also repacks .tar.gz members

switches:
  -o+ overwrite files that already exist
  -o- skip files that already exist (default)
  -y  same as -o+
  -q  quiet: report only errors
  -p<pw>  decrypt encrypted archives with password
  -mt<n>  use up to n threads (default: one per core)
  --salvage  read a RAR archive with damaged headers as UnRAR does: use a header that fails its
             checksum, stop a volume at one that can't be read, and warn
  --resync   as --salvage, and look past an unreadable header for the next valid one
";

pub(crate) fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = args.first() else {
        early(format_args!("{USAGE}"));
        return ExitCode::from(2);
    };
    if command == "repack" {
        return repack(&args[1..]);
    }
    let mut overwrite = Overwrite::Skip;
    let mut quiet = false;
    let mut threads = None;
    let mut password: Option<String> = None;
    let mut damaged = extract::DamagedInput::Refuse;
    let mut paths = Vec::new();
    for arg in &args[1..] {
        match arg.as_str() {
            "--salvage" => damaged = extract::DamagedInput::Salvage,
            "--resync" => damaged = extract::DamagedInput::Resync,
            "-o+" | "-y" => overwrite = Overwrite::Always,
            "-o-" => overwrite = Overwrite::Skip,
            "-q" | "-idq" => quiet = true,
            "--" => {}
            s if s.starts_with("-p") && s.len() > 2 => password = Some(s[2..].to_string()),
            s if s.starts_with("-mt") => match s[3..].parse::<usize>() {
                Ok(n) if n >= 1 => threads = Some(n),
                _ => {
                    early(format_args!("bad switch {s}: give a thread count of at least 1, like -mt4\n"));
                    return ExitCode::from(2);
                }
            },
            s if s.starts_with('-') && s.len() > 1 => {
                early(format_args!("unknown switch {s}\n"));
                return ExitCode::from(2);
            }
            s => paths.push(PathBuf::from(s)),
        }
    }
    let Some(archive) = paths.first().cloned() else {
        early(format_args!("{USAGE}"));
        return ExitCode::from(2);
    };
    let dest = paths.get(1).cloned().unwrap_or_else(|| PathBuf::from("."));
    match command.as_str() {
        "l" | "v" if damaged != extract::DamagedInput::Refuse => salvage_list(&archive, password.as_deref(), damaged),
        "l" | "v" => list(&archive, password.as_deref()),
        "t" | "x" | "e" => {
            let mode = if command == "t" { Mode::Test } else { Mode::Extract };
            let opts = Options {
                mode,
                dest,
                overwrite,
                flatten: command == "e",
                threads,
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
                damaged_input: damaged,
                unsupported_filters: Default::default(),
                salvage_truncated_zip: false,
                unix_modes: Default::default(),
                backslashes: Default::default(),
            };
            run(&archive, &opts, password.as_deref(), quiet)
        }
        other => {
            early(format_args!("unknown command {other}\n{USAGE}"));
            ExitCode::from(2)
        }
    }
}

fn repack(args: &[String]) -> ExitCode {
    let mut opts = crate::repack::RepackOptions::default();
    let epoch = std::env::var("SOURCE_DATE_EPOCH").ok().filter(|v| !v.is_empty());
    let mut mtime = epoch.as_deref().map(|v| ("SOURCE_DATE_EPOCH", v.to_string()));
    let mut quiet = false;
    let mut paths = Vec::new();
    for arg in args {
        match arg.as_str() {
            "--nested" => opts.nested = true,
            "-q" => quiet = true,
            s if s.starts_with("--mtime=") => {
                mtime = Some(("--mtime", s["--mtime=".len()..].trim_start_matches('@').to_string()))
            }
            s if s.starts_with("--level=") => match s["--level=".len()..].parse::<u32>() {
                Ok(n) if n <= 9 => opts.level = n,
                _ => {
                    early(format_args!("bad switch {s}: give a deflate level from 0 to 9\n"));
                    return ExitCode::from(2);
                }
            },
            s if s.starts_with('-') && s.len() > 1 => {
                early(format_args!("unknown switch {s}\n"));
                return ExitCode::from(2);
            }
            s => paths.push(PathBuf::from(s)),
        }
    }
    if let Some((from, value)) = mtime {
        match value.parse::<u64>() {
            Ok(t) => opts.mtime = t,
            Err(_) => {
                early(format_args!("bad {from} {value:?}: give whole seconds since 1970\n"));
                return ExitCode::from(2);
            }
        }
    }
    let [input, output] = paths.as_slice() else {
        early(format_args!("{USAGE}"));
        return ExitCode::from(2);
    };
    match crate::repack::repack(input, output, &opts) {
        Ok(summary) => {
            if !quiet {
                let format = match summary.format {
                    crate::repack::RepackFormat::Ar => "ar",
                    crate::repack::RepackFormat::TarGz => "tar.gz",
                };
                let nested = if summary.nested > 0 {
                    format!(", {} nested tarballs repacked", summary.nested)
                } else {
                    String::new()
                };
                println!("{}: {} members written as {format}{nested}", output.display(), summary.members);
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{}: {e}", input.display());
            ExitCode::from(2)
        }
    }
}

/// `l --salvage` / `l --resync`: the listing, then a warning for every damaged header read past.
fn salvage_list(archive: &Path, password: Option<&str>, damaged: extract::DamagedInput) -> ExitCode {
    // Only a RAR archive lists differently under salvage: anything else keeps its own listing, a ZIP's checked one
    // (which refuses an output that aliases the archive) included.
    let route = extract::checked_route(archive, &extract::Cancellation::default());
    if !matches!(route, Ok(extract::CheckedRoute::Legacy(extract::LegacyRoute::Rar { .. }))) {
        drop(route);
        return list(archive, password);
    }
    drop(route);
    let options = Options { damaged_input: damaged, ..listing_options() };
    match extract::list_detailed_with_options(archive, password, &options) {
        Ok(listing) => {
            let code = legacy_list_result(archive, Ok(listing.entries.clone()));
            damage_warning(&listing.damaged_headers, listing.damaged_headers.len() as u64);
            if listing.headers_damaged() { ExitCode::from(1) } else { code }
        }
        Err(e) => legacy_list_result(archive, Err(e)),
    }
}

/// Options for a listing: only `damaged_input` matters there.
fn listing_options() -> Options {
    Options {
        mode: Mode::Test,
        dest: PathBuf::new(),
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
    }
}

/// The warning for a run or listing that read past damaged headers; `lines` are printed (a run has already sent
/// them as diagnostics, so it passes none).
fn damage_warning(lines: &[extract::HeaderDamage], count: u64) {
    for damage in lines {
        eprintln!("{damage}");
    }
    if count > 0 {
        eprintln!(
            "warning: the archive's headers are damaged ({count} read past); what is listed or extracted may be incomplete"
        );
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn legacy_list(archive: &Path, password: Option<&str>) -> ExitCode {
    legacy_list_result(archive, extract::list_with_password(archive, password))
}
fn legacy_list_result(archive: &Path, result: crate::Result<Vec<extract::Entry>>) -> ExitCode {
    match result {
        Ok(entries) => {
            println!("{:>14} {:>14} {:>8} {:>6}  name", "size", "packed", "crc32", "method");
            for e in &entries {
                let crc = e.crc32.map_or("-".to_string(), |c| format!("{c:08x}"));
                let method = if e.dir { "dir".to_string() } else { format!("m{}", e.method) };
                let flags = if e.encrypted { " *" } else { "" };
                println!("{:>14} {:>14} {crc:>8} {method:>6}  {}{flags}", e.size, e.packed, e.name);
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{}: {e}", archive.display());
            ExitCode::from(2)
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn legacy_run(archive: &Path, opts: &Options, password: Option<&str>, quiet: bool) -> ExitCode {
    let started = Instant::now();
    let result = extract::run_with_password(archive, opts, password, |line| eprintln!("{line}"));
    legacy_run_result(archive, quiet, started, result)
}
fn legacy_run_result(
    archive: &Path,
    quiet: bool,
    started: Instant,
    result: crate::Result<extract::Summary>,
) -> ExitCode {
    match result {
        Ok(s) => {
            if !quiet {
                let secs = started.elapsed().as_secs_f64();
                let mb = s.bytes as f64 / 1e6;
                eprintln!(
                    "{} files, {} folders, {:.1} MB from {} volume(s) in {:.2}s ({:.0} MB/s){}",
                    s.files,
                    s.dirs,
                    mb,
                    s.volumes,
                    secs,
                    if secs > 0.0 { mb / secs } else { 0.0 },
                    if s.skipped > 0 { format!(", {} skipped", s.skipped) } else { String::new() }
                );
            }
            damage_warning(&[], s.damaged_headers.len() as u64);
            if s.errors.is_empty() && s.damaged_headers.is_empty() { ExitCode::SUCCESS } else { ExitCode::from(1) }
        }
        Err(e) => {
            eprintln!("{}: {e}", archive.display());
            ExitCode::from(2)
        }
    }
}

fn early(text: std::fmt::Arguments<'_>) {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let mut stderr = FdWriter::new(std::io::stderr().lock());
        let result = crate::zip::read::diagnostic::terminal(&mut stderr, &extract::Cancellation::default(), text);
        if let Err(error) = result {
            let _ = (error.boundary, error.diagnostic, error.usage);
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    eprint!("{text}");
}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn list(archive: &Path, password: Option<&str>) -> ExitCode {
    if ["ZIPFAST_ZIP_ENCRYPTED_MAX_BYTES", "ZIPFAST_ZIP_TEMP_BYTES", "ZIPFAST_ZIP_TEMP_DIR"]
        .iter()
        .any(|k| std::env::var_os(k).is_some())
    {
        early(format_args!("checked ZIP overrides are unsupported on this platform\n"));
        return ExitCode::from(2);
    }
    legacy_list(archive, password)
}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn run(archive: &Path, opts: &Options, password: Option<&str>, quiet: bool) -> ExitCode {
    if ["ZIPFAST_ZIP_ENCRYPTED_MAX_BYTES", "ZIPFAST_ZIP_TEMP_BYTES", "ZIPFAST_ZIP_TEMP_DIR"]
        .iter()
        .any(|k| std::env::var_os(k).is_some())
    {
        early(format_args!("checked ZIP overrides are unsupported on this platform\n"));
        return ExitCode::from(2);
    }
    legacy_run(archive, opts, password, quiet)
}
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn overrides() -> Result<crate::zip::EncryptedReadOverrides, &'static str> {
    fn value<T: std::str::FromStr>(key: &str) -> Result<Option<T>, &'static str> {
        let Some(raw) = std::env::var_os(key) else { return Ok(None) };
        let text = raw.to_str().ok_or("invalid ZIP override")?;
        if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
            return Err("ZIP overrides require unsigned decimal integers");
        }
        text.parse().map(Some).map_err(|_| "ZIP override overflows its integer type")
    }
    let max = value::<u64>("ZIPFAST_ZIP_ENCRYPTED_MAX_BYTES")?;
    Ok(crate::zip::EncryptedReadOverrides {
        member_packed_bytes: max,
        member_decoded_bytes: max,
        live_spool_bytes: value::<u128>("ZIPFAST_ZIP_TEMP_BYTES")?,
        temp_dir: std::env::var_os("ZIPFAST_ZIP_TEMP_DIR").map(PathBuf::from),
        ..Default::default()
    })
}
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[allow(clippy::result_large_err)] // Borrowed checked failures remain fixed-size, never boxed.
fn run(archive: &Path, opts: &Options, password: Option<&str>, quiet: bool) -> ExitCode {
    use crate::zip::read::with_opened_policy;
    let started = Instant::now();
    let cancel = extract::Cancellation::default();
    let overrides = match overrides() {
        Ok(v) => v,
        Err(error) => {
            early(format_args!("{error}\n"));
            return ExitCode::from(2);
        }
    };
    let opened = match extract::checked_route(archive, &cancel) {
        Ok(extract::CheckedRoute::Zip(opened)) => opened,
        Ok(extract::CheckedRoute::Legacy(route)) => {
            return legacy_run_result(
                archive,
                quiet,
                started,
                route.run(archive, opts, password, &mut |line: &str| eprintln!("{line}")).map_err(|e| e.error),
            );
        }
        Err(error) => {
            early(format_args!("{}: {error}\n", archive.display()));
            return ExitCode::from(2);
        }
    };
    let session = match opened.into_zip_projected(&cancel) {
        Ok(v) => v,
        Err(error) => {
            early(format_args!("{}: {error}\n", archive.display()));
            return ExitCode::from(2);
        }
    };
    let mut prepared = false;
    let renderer = Renderer {
        stderr: FdWriter::new(std::io::stderr().lock()),
        archive,
        quiet,
        started,
        prepared: &mut prepared,
        fatal_rendered: false,
    };
    let result = with_opened_policy(session, opts, password, &cancel, &overrides, renderer);
    if !prepared && let Err(error) = &result {
        early(format_args!("{}: {}\n", archive.display(), ErrorText(error, None)));
    }
    if let Ok(report) = &result {
        damage_warning(&[], report.damaged_headers());
    }
    match result {
        Ok(report) if report.failed() == 0 && report.damaged_headers() == 0 => ExitCode::SUCCESS,
        Ok(_) => ExitCode::from(1),
        Err(_) => ExitCode::from(2),
    }
}
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[allow(clippy::result_large_err)] // Borrowed checked failures remain fixed-size, never boxed.
fn list(archive: &Path, password: Option<&str>) -> ExitCode {
    let cancel = extract::Cancellation::default();
    if let Err(error) = overrides() {
        early(format_args!("{error}\n"));
        return ExitCode::from(2);
    }
    let opened = match extract::checked_route(archive, &cancel) {
        Ok(extract::CheckedRoute::Zip(opened)) => opened,
        Ok(extract::CheckedRoute::Legacy(route)) => {
            return legacy_list_result(archive, route.list(archive, password));
        }
        Err(error) => {
            early(format_args!("{}: {error}\n", archive.display()));
            return ExitCode::from(2);
        }
    };
    let session = match opened.into_zip_projected(&cancel) {
        Ok(v) => v,
        Err(error) => {
            early(format_args!("{}: {error}\n", archive.display()));
            return ExitCode::from(2);
        }
    };
    let mut stdout = FdWriter::new(std::io::stdout().lock());
    let result = session.render_listing_owned(&mut stdout, &cancel, |entries, writer| {
        writer.write_fmt(format_args!("{:>14} {:>14} {:>8} {:>6}  name\n", "size", "packed", "crc32", "method"))?;
        for e in entries {
            writer.write_fmt(format_args!(
                "{:>14} {:>14} {:>8} {:>6}  {}{}\n",
                e.size,
                e.packed,
                Crc((!e.is_dir()).then_some(e.crc32)),
                Method(e.is_dir(), e.method.min(255)),
                Escaped(&e.name),
                if e.encrypted() { " *" } else { "" }
            ))?;
        }
        Ok(())
    });
    match result {
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => {
            if error.prewrite {
                early(format_args!("{}: {}\n", archive.display(), error.error));
            }
            let _ = error.usage;
            ExitCode::from(2)
        }
    }
}
#[cfg(any(target_os = "macos", target_os = "linux"))]
struct Renderer<'a> {
    stderr: FdWriter<std::io::StderrLock<'a>>,
    archive: &'a Path,
    quiet: bool,
    started: Instant,
    prepared: &'a mut bool,
    fatal_rendered: bool,
}
#[cfg(any(target_os = "macos", target_os = "linux"))]
impl crate::zip::ZipRunObserver for Renderer<'_> {
    fn prepare(&mut self, io: &mut crate::zip::ZipDiagnosticScope<'_>) -> crate::zip::ZipObserverResult<()> {
        *self.prepared = true;
        io.admit_sinks(None, Some(&self.stderr))?;
        Ok(())
    }
    fn observe(
        &mut self,
        event: crate::zip::ZipRunEvent<'_>,
        io: &mut crate::zip::ZipDiagnosticScope<'_>,
    ) -> crate::zip::ZipObserverResult<()> {
        use crate::zip::ZipRunEvent;
        if self.fatal_rendered && matches!(event, ZipRunEvent::RunEnded { error: Some(_), .. }) {
            return Ok(());
        }
        if matches!(event, ZipRunEvent::MemberSucceeded { .. } | ZipRunEvent::LegacyError { .. })
            || self.quiet && matches!(event, ZipRunEvent::RunEnded { error: None, .. })
        {
            return Ok(());
        }
        io.emit(crate::zip::ZipDiagnosticSink::Stderr, &mut self.stderr, |status, writer| {
            if status.is_fatal() {
                let result = match event {
                    ZipRunEvent::MemberFailed { name, error, .. } => writer.write_fmt(format_args!(
                        "{}: {}; ZIP source or diagnostic admission changed\n",
                        Escaped(name),
                        ErrorText(error, Some(name))
                    )),
                    _ => writer.write_fmt(format_args!(
                        "{}: ZIP source or diagnostic admission changed\n",
                        self.archive.display()
                    )),
                };
                if result.is_ok() {
                    self.fatal_rendered = true;
                }
                return result;
            }
            let fatal = matches!(&event,ZipRunEvent::MemberFailed{error,..}if !error.member_local())
                || matches!(&event, ZipRunEvent::RunEnded { error: Some(_), .. });
            let result = match event {
                ZipRunEvent::MemberFailed { name, error, .. } => {
                    writer.write_fmt(format_args!("{}: {}\n", Escaped(name), ErrorText(error, Some(name))))
                }
                ZipRunEvent::MemberSkipped { name, .. } => {
                    writer.write_fmt(format_args!("{}: exists, skipped\n", Escaped(name)))
                }
                ZipRunEvent::RunEnded { error: Some(error), .. } => {
                    writer.write_fmt(format_args!("{}: {}\n", self.archive.display(), ErrorText(error, None)))
                }
                ZipRunEvent::RunEnded { report, error: None } => {
                    let secs = self.started.elapsed().as_secs_f64();
                    let mb = report.decoded_bytes() as f64 / 1e6;
                    writer.write_fmt(format_args!(
                        "{} files, {} folders, {:.1} MB from {} volume(s) in {:.2}s ({:.0} MB/s){}\n",
                        report.files(),
                        report.dirs(),
                        mb,
                        report.volumes(),
                        secs,
                        if secs > 0.0 { mb / secs } else { 0.0 },
                        Skipped(report.skipped())
                    ))
                }
                ZipRunEvent::LegacyDiagnostic { message } => writer.write_fmt(format_args!("{message}\n")),
                _ => Ok(()),
            };
            if fatal && result.is_ok() {
                self.fatal_rendered = true;
            }
            result
        })?;
        Ok(())
    }
}
struct Escaped<'a>(&'a str);
impl std::fmt::Display for Escaped<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for c in self.0.chars() {
            if c.is_control() {
                for escaped in c.escape_default() {
                    write!(f, "{escaped}")?;
                }
            } else {
                write!(f, "{c}")?;
            }
        }
        Ok(())
    }
}
struct Method(bool, u16);
impl std::fmt::Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0 {
            f.pad("dir")
        } else {
            let mut bytes = [0u8; 6];
            let mut n = self.1;
            let mut at = bytes.len();
            loop {
                at -= 1;
                bytes[at] = b'0' + (n % 10) as u8;
                n /= 10;
                if n == 0 {
                    break;
                }
            }
            at -= 1;
            bytes[at] = b'm';
            f.pad(std::str::from_utf8(&bytes[at..]).map_err(|_| std::fmt::Error)?)
        }
    }
}
struct Skipped(u64);
impl std::fmt::Display for Skipped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0 > 0 { write!(f, ", {} skipped", self.0) } else { Ok(()) }
    }
}
struct ErrorText<'a>(&'a crate::zip::ZipReadError, Option<&'a str>);
impl std::fmt::Display for ErrorText<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use crate::zip::{IntegrityReason, ReadFault};
        if self.0.source_change().is_some() && self.0.operation().is_none() {
            return f.write_str("ZIP source changed");
        }
        match self.0.operation() {
            Some(ReadFault::PasswordRequired) => f.write_str("encrypted (password required)"),
            Some(ReadFault::PasswordCheckFailed { cipher: crate::zip::CipherKind::ZipCrypto, .. }) => {
                f.write_str("corrupt archive: wrong password")
            }
            Some(ReadFault::PasswordCheckFailed { .. } | ReadFault::AuthenticationFailed) => {
                f.write_str("corrupt archive: wrong password or damaged AES stream")
            }
            Some(ReadFault::Integrity { reason: IntegrityReason::Checksum, .. }) => match self.1 {
                Some(name) => write!(f, "checksum error in {}", Escaped(name)),
                None => f.write_str("checksum error"),
            },
            Some(ReadFault::Integrity { reason: IntegrityReason::DecodedSize, .. }) => {
                f.write_str("corrupt archive: decoded size differs from directory")
            }
            Some(ReadFault::Integrity { reason, .. }) => write!(f, "corrupt archive: ZIP {reason:?}"),
            Some(ReadFault::UnsupportedMethod { method }) => {
                write!(f, "compression method {method} is not supported yet")
            }
            Some(ReadFault::CheckedFormat { reason }) => f.write_str(reason),
            Some(ReadFault::Limit { resource, limit, attempted }) => {
                write!(f, "ZIP {resource:?} limit {limit} exceeded by {attempted}")
            }
            Some(ReadFault::Io { error, .. }) => write!(f, "{error}"),
            Some(ReadFault::Legacy(error)) => write!(f, "{error}"),
            Some(ReadFault::Cancelled) => f.write_str("operation cancelled"),
            // name the directory (encrypted data spools in the temporary one) and why it was refused
            Some(ReadFault::UntrustedDirectory { object: crate::zip::OwnedObject::CiphertextDirectory, reason }) => {
                let dir = std::env::var_os("ZIPFAST_ZIP_TEMP_DIR").map_or_else(std::env::temp_dir, PathBuf::from);
                write!(
                    f,
                    "temporary directory {} refused: {reason} (set ZIPFAST_ZIP_TEMP_DIR or TMPDIR to a private one)",
                    dir.display()
                )
            }
            Some(ReadFault::UntrustedDirectory { reason, .. }) => write!(f, "output directory refused: {reason}"),
            Some(ReadFault::Allocation { capacity }) => {
                write!(f, "could not allocate {capacity} bytes for ZIP processing")
            }
            _ => write!(f, "{}", self.0),
        }
    }
}

struct Crc(Option<u32>);
impl std::fmt::Display for Crc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Some(mut n) = self.0 else { return f.pad("-") };
        let mut hex = [b'0'; 8];
        for c in hex.iter_mut().rev() {
            *c = b"0123456789abcdef"[(n & 15) as usize];
            n >>= 4;
        }
        f.pad(std::str::from_utf8(&hex).map_err(|_| std::fmt::Error)?)
    }
}
