#![forbid(unsafe_code)]

//! `openvibes-agent <config.toml>`: runs the platform lifecycle every minute.
//! `openvibes-agent export <config.toml> <dir>`: writes a local-only agent's
//! queued findings to export files in `dir`.
//! `openvibes-agent service <config.toml>` (Windows): the same lifecycle under
//! the Service Control Manager, logging to the Windows Event Log.
//! `windows-setup` and `windows-remove-data` (Windows): run by the MSI, see
//! `winsetup.rs`.

use std::{
    ffi::OsString,
    path::Path,
    process::ExitCode,
    sync::mpsc::{self, Receiver, RecvTimeoutError},
    time::{SystemTime, UNIX_EPOCH},
};

use openvibes_agent::{AgentError, Service, load_config};

// ponytail: no Unix signal handling; the process is simply stopped (SQLite
// state is crash-safe). The Windows service stops between two ticks.

const USAGE: &str = "usage: openvibes-agent <config.toml> | export <config.toml> <dir> | service <config.toml> (Windows)";

/// One log line: to stderr (the systemd journal, or a console), and to the
/// Windows Event Log once the service has set it as the logger. The record
/// goes to the logger directly: the facade's max level stays Off, so the
/// `log` lines of rustls, ureq and aya stay silent as before.
macro_rules! say {
    ($level:ident, $($arg:tt)+) => {{
        let line = format!($($arg)+);
        eprintln!("{line}");
        log::logger().log(
            &log::Record::builder()
                .level(log::Level::$level)
                .args(format_args!("{line}"))
                .build(),
        );
    }};
}

// After `say!`, which they use.
#[cfg(any(windows, test))]
mod winsetup;
#[cfg(windows)]
mod winsvc;

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    match args.as_slice() {
        [path] => {
            // Never sent: the console agent runs until it is stopped.
            let (_stop, stopped) = mpsc::channel();
            run(Path::new(path), &stopped)
        }
        [command, path, dir] if command == "export" => export(path, dir),
        #[cfg(windows)]
        [command, path] if command == "service" => winsvc::start(path),
        #[cfg(windows)]
        [command, dir, url, ca, token] if command == "windows-setup" => {
            installer(|| winsetup::setup(Path::new(dir), utf8(url)?, utf8(ca)?, utf8(token)?))
        }
        #[cfg(windows)]
        [command, dir] if command == "windows-remove-data" => {
            installer(|| winsetup::remove_data(Path::new(dir)))
        }
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

/// An MSI custom action: its stderr goes nowhere, so a failure also goes to
/// the Event Log (the MSI has registered the source by then), and the
/// non-zero exit makes Windows Installer roll the install back.
#[cfg(windows)]
fn installer(action: impl FnOnce() -> Result<(), String>) -> ExitCode {
    let _ = winlog2::init("openvibes-agent");
    log::set_max_level(log::LevelFilter::Off);
    match action() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            say!(Error, "openvibes-agent installer: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(windows)]
fn utf8(value: &OsString) -> Result<&str, String> {
    value
        .to_str()
        .ok_or_else(|| "a setting is not valid Unicode".to_string())
}

/// The agent lifecycle, until `stop` receives (or its sender is dropped).
fn run(path: &Path, stop: &Receiver<()>) -> ExitCode {
    let service = load_config(path).and_then(Service::open);
    let mut service = match service {
        Ok(service) => service,
        Err(error) => {
            say!(Error, "openvibes-agent: cannot start: {error}");
            return ExitCode::FAILURE;
        }
    };
    say!(
        Info,
        "openvibes-agent {} started; collectors: {}",
        env!("CARGO_PKG_VERSION"),
        service.config().scan.collectors.capabilities().join(", ")
    );
    if let Some(moved) = service.recovered_queue() {
        say!(
            Warn,
            "openvibes-agent: the queue was corrupt; moved aside in the state directory as {} and replaced (its findings are lost)",
            moved
                .file_name()
                .map_or_else(Default::default, |name| name.to_string_lossy())
        );
    }
    loop {
        match service.scan_if_due(unix_ms()) {
            Ok(Some(report)) => {
                if report.not_queued > 0 {
                    say!(
                        Warn,
                        "openvibes-agent: queue full: {} findings not queued (delivery or export frees space)",
                        report.not_queued
                    );
                }
                for rule_set in &report.newly_not_assigned {
                    say!(
                        Warn,
                        "openvibes-agent: rule set {} is not assigned to this host (410); its rules stop running",
                        rule_set.as_str()
                    );
                }
                for (rule_set, error) in &report.rule_set_errors {
                    say!(
                        Warn,
                        "openvibes-agent: rule set {}: {error}",
                        rule_set.as_str()
                    );
                }
                if let Some(seconds) = report.rules_retry_in_s {
                    say!(
                        Warn,
                        "openvibes-agent: no rules loaded yet for some rule sets (the platform is not answering); fetching again in {seconds} s"
                    );
                }
                say!(
                    Info,
                    "openvibes-agent: scan matched {} rules, queued {} findings ({} rules unavailable, {} failed{})",
                    report.matched,
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
            Err(error) => say!(Error, "openvibes-agent: scan failed: {error}"),
        }
        match service.tick(unix_ms()) {
            Ok(report) => {
                if let Some(agent_id) = &report.enrolled_as {
                    say!(Info, "openvibes-agent: enrolled as {agent_id}");
                }
                if let Some(error) = report.renewal_error {
                    say!(Warn, "openvibes-agent: renewal failed, retrying: {error}");
                }
                match &report.health_left_out {
                    Some(left_out) if left_out.is_empty() => {
                        say!(Info, "openvibes-agent: the health report is complete again");
                    }
                    Some(left_out) => say!(
                        Warn,
                        "openvibes-agent: the health report leaves out: {}",
                        left_out.join("; ")
                    ),
                    None => {}
                }
                if let Some(jump) = report.clock_jump_ms {
                    say!(
                        Warn,
                        "openvibes-agent: the system clock jumped {} s; pruning and certificate expiry ignore the jump",
                        jump / 1_000
                    );
                }
                match report.services_truncated {
                    Some(true) => say!(
                        Warn,
                        "openvibes-agent: the services report is cut to the protocol limits (truncated)"
                    ),
                    Some(false) => {
                        say!(
                            Info,
                            "openvibes-agent: the services report is complete again"
                        )
                    }
                    None => {}
                }
                match report.services_error {
                    // Names are checked as they are read, so an invalid
                    // report is an agent bug; it is not sent until the
                    // lists change.
                    Some(AgentError::Transport(
                        openvibes_transport::TransportError::InvalidRequest,
                    )) => say!(
                        Error,
                        "openvibes-agent: BUG: the services report is invalid and was not sent; please report this"
                    ),
                    Some(error) => say!(Warn, "openvibes-agent: sending services failed: {error}"),
                    None => {}
                }
                if let Some(error) = report.heartbeat_error {
                    say!(
                        Warn,
                        "openvibes-agent: heartbeat failed, delivery continued: {error}"
                    );
                }
                for (reason, count) in &report.rejected {
                    say!(
                        Warn,
                        "openvibes-agent: platform refused {count} findings permanently ({reason})"
                    );
                }
            }
            Err(AgentError::NotEnrolled) => {
                say!(Info, "openvibes-agent: waiting for an enrollment token");
            }
            Err(error) => say!(Error, "openvibes-agent: {error}"),
        }
        match stop.recv_timeout(service.wake_in(unix_ms())) {
            Err(RecvTimeoutError::Timeout) => {}
            Ok(()) | Err(RecvTimeoutError::Disconnected) => return ExitCode::SUCCESS,
        }
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
