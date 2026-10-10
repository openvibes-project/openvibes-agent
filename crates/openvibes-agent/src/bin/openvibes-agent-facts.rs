#![forbid(unsafe_code)]

//! `openvibes-agent-facts`: the root helper (platform spec
//! `2026-10-09-hardening-rules-design.md` §4). Run by the package-enabled
//! `openvibes-agent-facts.timer` as root, with only `CAP_DAC_READ_SEARCH`
//! and `CAP_SYS_PTRACE` and no network; reads the host once (services with exact port owners, and the
//! hardening facts of protocol P19) and writes
//! `root_facts::PATH` for the unprivileged agent. It takes no input: no
//! arguments, no configuration, no rules.

use std::{
    path::Path,
    process::ExitCode,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use openvibes_agent::root_facts::{self, HardeningScan, RootFacts, ServicesScan};
use openvibes_core::ResourceLimits;

fn main() -> ExitCode {
    if std::env::args_os().len() > 1 {
        eprintln!("openvibes-agent-facts: takes no arguments");
        return ExitCode::from(2);
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or_default();
    let deadline = Instant::now() + Duration::from_secs(ResourceLimits::V1.scan_seconds);
    // As root with both capabilities, the collector's fd walk names the
    // process holding each listener.
    let services = openvibes_collectors::collect_services(deadline)
        .ok()
        .map(|s| ServicesScan {
            owners: s.owners,
            listeners: s.listeners,
            services: s.services,
        });
    // Hardening facts (P19): read-only, from files under `/`.
    let hardening = openvibes_collectors::collect_hardening(Path::new("/"));
    let facts = RootFacts {
        schema_version: 1,
        collected_at_unix_ms: now,
        services,
        hardening: Some(HardeningScan {
            facts: hardening.facts,
            errors: hardening.errors,
        }),
    };
    match root_facts::write(Path::new(root_facts::PATH), &facts) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!(
                "openvibes-agent-facts: writing {}: {error}",
                root_facts::PATH
            );
            ExitCode::FAILURE
        }
    }
}
