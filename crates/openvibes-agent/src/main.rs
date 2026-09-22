#![forbid(unsafe_code)]

//! `openvibes-agent <config.toml>`: runs the platform lifecycle every minute.

use std::{
    path::Path,
    process::ExitCode,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use openvibes_agent::{AgentError, Service, load_config};

// ponytail: fixed interval and no signal handling; the process is simply
// stopped (SQLite state is crash-safe). Make it configurable if operators ask.
const TICK: Duration = Duration::from_secs(60);

fn main() -> ExitCode {
    let Some(path) = std::env::args_os().nth(1) else {
        eprintln!("usage: openvibes-agent <config.toml>");
        return ExitCode::from(2);
    };
    let service = load_config(Path::new(&path)).and_then(Service::open);
    let mut service = match service {
        Ok(service) => service,
        Err(error) => {
            eprintln!("openvibes-agent: cannot start: {error}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!("openvibes-agent {} started", env!("CARGO_PKG_VERSION"));
    loop {
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

fn unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        })
}
