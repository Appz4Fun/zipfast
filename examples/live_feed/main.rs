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

//! Live extraction of a multi-volume RAR 5.0, RAR 4.x or 7z set from simulated Usenet articles, through
//! `ArticleBuffer` -> `FeedDecoder` -> `FeedSink` (a persistent partial with `--features persistent-partials`).
//! A reference integration for downloaders; see `docs/feed-decoder.md` ("Live feed example") and `sim.rs`.
//!
//! Prints one tab-separated summary line per run on stdout (`--header` adds the column names first) and a short
//! human summary on stderr.

mod sim;

use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "usage: live_feed [--password PW] [--article BYTES] [--seed N] [--lateness N|all] [--window N] \
[--drop FRACTION] [--drop-articles I,J,..] [--repair-delay N] [--sink auto|file|partial] [--group-holes] [--group-refills] \
[--group-commit-mib N] [--max-needs N] [--buffer-mib N] [--work DIR] [--keep] [--no-verify] [--runs N] \
[--label NAME] [--header] <set dir | volume...>";

fn main() -> ExitCode {
    match real_main() {
        Ok(ok) => {
            if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(e) => {
            eprintln!("live_feed: {e}\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn real_main() -> Result<bool, String> {
    let mut config = sim::Config::new(Vec::new(), PathBuf::new());
    let mut work = None;
    let mut keep = false;
    let mut runs = 1usize;
    let mut label = None;
    let mut header = false;
    let mut inputs = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = |name: &str| args.next().ok_or_else(|| format!("{name} needs a value"));
        fn num<T: std::str::FromStr>(name: &str, v: String) -> Result<T, String> {
            v.parse().map_err(|_| format!("{name}: not a number: {v}"))
        }
        match arg.as_str() {
            "--password" => config.password = Some(value(&arg)?),
            "--article" => config.article = num(&arg, value(&arg)?)?,
            "--seed" => config.seed = num(&arg, value(&arg)?)?,
            "--lateness" => {
                let v = value(&arg)?;
                config.lateness = if v == "all" { None } else { Some(num(&arg, v)?) };
            }
            "--window" => config.window = num(&arg, value(&arg)?)?,
            "--drop" => config.drop = num(&arg, value(&arg)?)?,
            "--drop-articles" => {
                let list = value(&arg)?;
                config.drop_articles =
                    Some(list.split(',').map(|i| num(&arg, i.to_owned())).collect::<Result<_, _>>()?);
            }
            "--repair-delay" => config.repair_delay = Some(num(&arg, value(&arg)?)?),
            "--sink" => {
                config.sink = match value(&arg)?.as_str() {
                    "auto" => sim::SinkKind::Auto,
                    "file" => sim::SinkKind::File,
                    "partial" => sim::SinkKind::Partial,
                    other => return Err(format!("--sink: unknown sink {other}")),
                }
            }
            "--group-holes" => config.group_holes = true,
            "--group-refills" => config.group_refills = true,
            "--group-commit-mib" => config.group_commit_mib = Some(num(&arg, value(&arg)?)?),
            "--max-needs" => config.max_needs = num(&arg, value(&arg)?)?,
            "--buffer-mib" => config.buffer_limit = num::<usize>(&arg, value(&arg)?)?.saturating_mul(1 << 20),
            "--work" => work = Some(PathBuf::from(value(&arg)?)),
            "--keep" => keep = true,
            "--no-verify" => config.verify = false,
            "--runs" => runs = num(&arg, value(&arg)?)?,
            "--label" => label = Some(value(&arg)?),
            "--header" => header = true,
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(true);
            }
            flag if flag.starts_with("--") => return Err(format!("unknown option {flag}")),
            _ => inputs.push(PathBuf::from(arg)),
        }
    }
    config.volumes = match inputs.as_slice() {
        [] => return Err("no set given".into()),
        [dir] if dir.is_dir() => sim::volumes_in(dir).map_err(|e| format!("{}: {e}", dir.display()))?,
        files => files.to_vec(),
    };
    if config.volumes.is_empty() {
        return Err("no volumes found".into());
    }
    let label = label.unwrap_or_else(|| {
        let first = &inputs[0];
        let named = if first.is_dir() { first.as_path() } else { first.parent().unwrap_or(first) };
        named.file_name().map_or_else(|| "set".into(), |n| n.to_string_lossy().into_owned())
    });
    let base = match work {
        Some(dir) => dir,
        None => std::env::temp_dir().join(format!("live_feed-{}", std::process::id())),
    };
    if header {
        println!("{}", sim::Report::HEADER);
    }
    let mut all_ok = true;
    for run in 0..runs.max(1) {
        // every run starts from an empty work directory: a persistent partial never overwrites output
        config.work = base.join(format!("run{run}"));
        let _ = std::fs::remove_dir_all(&config.work);
        let report = sim::run(&config)?;
        println!("{}", report.tsv(&label));
        eprintln!(
            "{label}: {} {} member(s) via {} sink, {:.1} MB in {:.0} ms ({:.0} MB/s); {} of {} articles dropped, {} holes, \
             {} refills, {} redecoded, {} syncs; crc {}, verify {:?}",
            report.format,
            report.fed,
            report.sink,
            report.output_bytes as f64 / 1e6,
            report.wall.as_secs_f64() * 1e3,
            report.output_bytes as f64 / 1e6 / report.wall.as_secs_f64().max(1e-9),
            report.dropped,
            report.articles,
            report.holes,
            report.refills,
            report.redecoded,
            report.syncs,
            if report.crc_ok { "ok" } else { "FAIL" },
            report.verified,
        );
        all_ok &= report.crc_ok && report.verified != Some(false);
        if !keep {
            let _ = std::fs::remove_dir_all(&config.work);
        }
    }
    if !keep {
        let _ = std::fs::remove_dir(&base);
    }
    Ok(all_ok)
}
