#![forbid(unsafe_code)]

//! `openvibes-agent <config.toml>`: runs the platform lifecycle every minute.
//! `openvibes-agent export <config.toml> <dir>`: writes a local-only agent's
//! queued findings to export files in `dir`.

use std::{
    ffi::OsString,
    path::Path,
    process::ExitCode,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use openvibes_agent::{AgentError, Service, load_config};

// ponytail: fixed interval and no signal handling; the process is simply
// stopped (SQLite state is crash-safe). Make it configurable if operators ask.
const TICK: Duration = Duration::from_secs(60);

const USAGE: &str = "usage: openvibes-agent <config.toml> | export <config.toml> <dir>";

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let path = match args.as_slice() {
        [path] => path,
        [command, path, dir] if command == "export" => return export(path, dir),
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    let service = load_config(Path::new(path)).and_then(Service::open);
    let mut service = match service {
        Ok(service) => service,
        Err(error) => {
            eprintln!("openvibes-agent: cannot start: {error}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!("openvibes-agent {} started", env!("CARGO_PKG_VERSION"));
    loop {
        match service.scan_if_due(unix_ms()) {
            Ok(Some(report)) => {
                for (rule_set, error) in &report.rule_set_errors {
                    eprintln!("openvibes-agent: rule set {}: {error}", rule_set.as_str());
                }
                eprintln!(
                    "openvibes-agent: scan queued {} findings ({} rules unavailable, {} failed{})",
                    report.queued,
                    report.unavailable_rules,
                    report.failed_rules,
                    if report.partial_collection {
                        ", partial facts"
                    } else {
                        ""
                    },
                );
            }
            Ok(None) => {}
            Err(error) => eprintln!("openvibes-agent: scan failed: {error}"),
        }
        match service.tick(unix_ms()) {
            Ok(report) => {
                if let Some(error) = report.renewal_error {
                    eprintln!("openvibes-agent: renewal failed, retrying: {error}");
                }
            }
            Err(AgentError::NotEnrolled) => {
                eprintln!("openvibes-agent: waiting for an enrollment token");
            }
            Err(error) => eprintln!("openvibes-agent: {error}"),
        }
        thread::sleep(TICK);
    }
}

fn export(path: &OsString, dir: &OsString) -> ExitCode {
    let exported = load_config(Path::new(path))
        .and_then(Service::open)
        .and_then(|mut service| service.export(Path::new(dir), unix_ms()));
    match exported {
        Ok(report) => {
            match report.packages {
                Ok(count) => {
                    eprintln!("openvibes-agent: exported an inventory of {count} packages")
                }
                Err(error) => eprintln!("openvibes-agent: no inventory: {}", error.message),
            }
            eprintln!("openvibes-agent: exported {} findings", report.findings);
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("openvibes-agent: export failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        })
}
