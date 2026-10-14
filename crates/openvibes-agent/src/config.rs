use std::{
    io::Read,
    path::{Path, PathBuf},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openvibes_core::{EnrollmentToken, Identifier, ResourceLimits};
use openvibes_rules::TrustedRuleKey;
use openvibes_storage::{StorageError, open_input_file};
use openvibes_transport::{DEFAULT_DISTRIBUTION_PORT, DEFAULT_PLATFORM_PORT, TransportConfig};
use serde::Deserialize;

use crate::AgentError;

/// Largest accepted configuration file.
const CONFIG_BYTES: u64 = 64 * 1024;

/// On-disk TOML layout. Unknown keys are errors, so a typo fails loudly
/// instead of silently falling back to a default. Without `platform_url` the
/// agent is local-only.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    platform_url: Option<String>,
    platform_ca_file: Option<PathBuf>,
    state_dir: PathBuf,
    proxy_url: Option<String>,
    enrollment_token_file: Option<PathBuf>,
    distribution_url: Option<String>,
    scan_interval_seconds: Option<u64>,
    collectors: Option<Vec<String>>,
    /// Read by the package's audit-setup script, not by the agent (which
    /// never changes audit rules): `false` keeps the package from changing
    /// /etc/audit/rules.d at all (no exec rule, no `-a task,never` edit).
    #[allow(dead_code)]
    manage_audit_rules: Option<bool>,
    /// For tests only: `"audit"` skips eBPF and reads kernel audit.
    process_events_source: Option<String>,
    #[serde(default)]
    rule_sets: Vec<RuleSetFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleSetFile {
    id: Identifier,
    bundle_file: Option<PathBuf>,
    trusted_keys: Vec<TrustedKeyFile>,
    /// Absent: restricted, except `baseline-alarms` (fail closed).
    restricted: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedKeyFile {
    issuer_key_id: Identifier,
    /// Unpadded base64url of the 32-byte Ed25519 public key.
    public_key: String,
}

/// The project's offline-signed alarm rule set: unrestricted unless its
/// line says otherwise.
pub(crate) const BASELINE_ALARMS: &str = "baseline-alarms";

/// Default time between scans.
const DEFAULT_SCAN_INTERVAL_SECONDS: u64 = 3_600;
/// Allowed scan intervals. Every scan re-reports its matches as new findings,
/// so the lower bound also bounds the finding rate.
const SCAN_INTERVAL_SECONDS: std::ops::RangeInclusive<u64> = 60..=86_400;

/// Where a rule set's entry came from (rule-set assignment, P20).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleSetSource {
    /// A `[[rule_sets]]` entry in the configuration file. A 404 or 410
    /// for it is a refused answer.
    Configured,
    /// Added from the agent's own table of project sets
    /// (`project_sets.rs`). `assignable`: the platform may switch it off
    /// for this host with a 410.
    Project {
        /// Hardening sets are; the baseline and the alarms are not.
        assignable: bool,
    },
}

/// A locally provisioned, signed rule bundle and the keys trusted for it.
#[derive(Clone, Debug)]
pub struct RuleSetConfig {
    /// Rule-set identity the bundle must carry.
    pub id: Identifier,
    /// Signed envelope file, read on every scan; `None` when the rule set
    /// comes only from the distribution service.
    pub bundle_file: Option<PathBuf>,
    /// Restricted (contract, P14): its `process_event` rules share one CEL
    /// budget per start with the other restricted sets and run after the
    /// unrestricted ones. Set in this file only, out of any signing key's
    /// reach: `restricted = true|false`, absent meaning restricted except
    /// for `baseline-alarms`.
    pub restricted: bool,
    /// The configuration file, or the project-set table.
    pub source: RuleSetSource,
}

/// Which host collectors a scan runs: `collectors` in the configuration,
/// all of them by default. A rule whose facts come from a disabled
/// collector is unavailable, never compliant. `process_events` (P14:
/// threat alarms from process starts) runs beside the scans and is always
/// on (#247, user): listed or not, so no host needs an agent.toml edit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Collectors {
    /// Running processes (`process.*`).
    pub processes: bool,
    /// Installed packages (`package.*`), also the local-only inventory.
    pub packages: bool,
    /// Listening ports (`port.*`).
    pub ports: bool,
    /// Process starts for `process_event` rules (P14).
    pub process_events: bool,
    /// Listening sockets and systemd services sent to the platform (P15);
    /// no facts.
    pub services: bool,
}

impl Default for Collectors {
    fn default() -> Self {
        Self {
            processes: true,
            packages: true,
            ports: true,
            process_events: true,
            services: true,
        }
    }
}

impl Collectors {
    /// The heartbeat capabilities of the enabled collectors (protocol P7),
    /// in a fixed order.
    #[must_use]
    pub fn capabilities(&self) -> Vec<&'static str> {
        [
            (self.processes, "collector.processes"),
            (self.packages, "collector.packages"),
            (self.ports, "collector.ports"),
            (self.services, "collector.services"),
        ]
        .into_iter()
        .filter_map(|(enabled, name)| enabled.then_some(name))
        .collect()
    }
}

/// Parses `collectors`: known names, each once, at least one; `ports`
/// also turns on `services`, and `process_events` is always on.
fn collectors(list: Option<Vec<String>>) -> Result<Collectors, AgentError> {
    let Some(list) = list else {
        return Ok(Collectors::default());
    };
    let mut chosen = Collectors {
        processes: false,
        packages: false,
        ports: false,
        process_events: false,
        services: false,
    };
    for name in &list {
        let slot = match name.as_str() {
            "processes" => &mut chosen.processes,
            "packages" => &mut chosen.packages,
            "ports" => &mut chosen.ports,
            "process_events" => &mut chosen.process_events,
            "services" => &mut chosen.services,
            _ => return Err(AgentError::Config),
        };
        if *slot {
            return Err(AgentError::Config);
        }
        *slot = true;
    }
    if list.is_empty() {
        return Err(AgentError::Config);
    }
    // `ports` brings `services` (#67): lists written before services
    // existed report them with no edit.
    chosen.services |= chosen.ports;
    // Threat alarms are on in every list (#247).
    chosen.process_events = true;
    Ok(chosen)
}

/// What to scan, how often, and which rules to evaluate.
#[derive(Clone, Debug)]
pub struct ScanConfig {
    /// Time between scans, in milliseconds.
    pub interval_ms: i64,
    /// Provisioned rule sets; with none, the agent never scans.
    pub rule_sets: Vec<RuleSetConfig>,
    /// Keys trusted for those rule sets, each scoped to one of them.
    pub trusted_keys: Vec<TrustedRuleKey>,
    /// Collectors each scan runs.
    pub collectors: Collectors,
}

/// Validated agent configuration.
#[derive(Clone, Debug)]
pub struct AgentConfig {
    /// How to reach and authenticate the platform; `None` when local-only,
    /// in which case the agent never uses the network.
    pub transport: Option<TransportConfig>,
    /// The rule distribution service, reached with the platform's CA, proxy,
    /// and client identity. Only with a platform.
    pub distribution: Option<TransportConfig>,
    /// `distribution` was derived from `platform_url` (no
    /// `distribution_url`): unreachable, it is quiet for project sets
    /// never stored (spec 2026-10-14 §3).
    pub distribution_derived: bool,
    /// Private agent-owned state directory.
    pub state_dir: PathBuf,
    /// File holding a single-use enrollment token, read only while the agent
    /// has no identity. The agent never modifies or deletes it.
    pub enrollment_token_file: Option<PathBuf>,
    /// Scanning and locally provisioned rules.
    pub scan: ScanConfig,
    /// For tests only (`process_events_source = "audit"`): process starts
    /// come from kernel audit without trying eBPF first.
    pub force_audit: bool,
}

/// Loads a TOML configuration and the platform CA bundle it names.
///
/// Every path must be absolute. `platform_url` and `platform_ca_file` come
/// together; a local-only configuration may not name a proxy or token. Files
/// are size-checked before parsing, and failures report
/// [`AgentError::Config`] without echoing content or paths. A file another
/// user could change, or that is not a regular file, is
/// [`AgentError::InsecureFile`] (see [`openvibes_storage::open_input_file`]).
pub fn load_config(path: &Path) -> Result<AgentConfig, AgentError> {
    let bytes = read_bounded(path, CONFIG_BYTES, false)?.ok_or(AgentError::Config)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| AgentError::Config)?;
    let file: ConfigFile = toml::from_str(text).map_err(|_| AgentError::Config)?;
    let absolute = file
        .platform_ca_file
        .as_ref()
        .is_none_or(|path| path.is_absolute())
        && file.state_dir.is_absolute()
        && file
            .enrollment_token_file
            .as_ref()
            .is_none_or(|path| path.is_absolute())
        && file.rule_sets.iter().all(|set| {
            set.bundle_file
                .as_ref()
                .is_none_or(|path| path.is_absolute())
        });
    if !absolute {
        return Err(AgentError::Config);
    }
    let fetched = file.distribution_url.is_some();
    if !fetched && file.rule_sets.iter().any(|set| set.bundle_file.is_none()) {
        return Err(AgentError::Config);
    }
    let force_audit = match file.process_events_source.as_deref() {
        None => false,
        Some("audit") => true,
        Some(_) => return Err(AgentError::Config),
    };
    let mut scan = scan_config(file.scan_interval_seconds, file.rule_sets)?;
    scan.collectors = collectors(file.collectors)?;
    let transport = match (file.platform_url, file.platform_ca_file) {
        (Some(base_url), Some(ca_file)) => {
            let limits = ResourceLimits::V1;
            let ca_bytes = u64::try_from(limits.document_bytes).unwrap_or(u64::MAX);
            let server_roots_pem =
                read_bounded(&ca_file, ca_bytes, false)?.ok_or(AgentError::Config)?;
            Some(TransportConfig {
                base_url,
                default_port: DEFAULT_PLATFORM_PORT,
                server_roots_pem,
                proxy_url: file.proxy_url,
                limits,
            })
        }
        (None, None) if file.proxy_url.is_none() && file.enrollment_token_file.is_none() => None,
        _ => return Err(AgentError::Config),
    };
    // Without `distribution_url`, the platform's host on Setup's
    // distribution port (spec 2026-10-14 §3), for the project sets only.
    let distribution = match (file.distribution_url, &transport) {
        (Some(_), None) => return Err(AgentError::Config),
        (url, Some(platform)) => url
            .or_else(|| derived_distribution_url(&platform.base_url))
            .map(|base_url| TransportConfig {
                base_url,
                default_port: DEFAULT_DISTRIBUTION_PORT,
                ..platform.clone()
            }),
        (None, None) => None,
    };
    // The project's own sets reach every agent that has a distribution
    // service, with no line here (P20); local-only agents keep exactly
    // their configuration.
    if distribution.is_some() {
        crate::project_sets::add(&mut scan, cfg!(target_os = "linux"))?;
    }
    Ok(AgentConfig {
        transport,
        distribution_derived: !fetched && distribution.is_some(),
        distribution,
        state_dir: file.state_dir,
        enrollment_token_file: file.enrollment_token_file,
        scan,
        force_audit,
    })
}

/// `https://<platform host>:18424`; `None` when `platform_url` is not a
/// valid base URL (the platform client refuses it anyway).
fn derived_distribution_url(platform_url: &str) -> Option<String> {
    let rest = platform_url.strip_prefix("https://")?;
    let authority = rest.split('/').next()?;
    // No user info, query or fragment: a base URL has none.
    if authority.contains(['@', '?', '#']) {
        return None;
    }
    let host = match authority.strip_prefix('[') {
        Some(v6) => authority.get(..v6.find(']')? + 2)?,
        None => authority.split(':').next()?,
    };
    (!host.is_empty()).then(|| format!("https://{host}:{DEFAULT_DISTRIBUTION_PORT}"))
}

/// Validates the scan settings: a bounded interval, distinct rule sets, and
/// well-formed, non-weak keys, each rule set with at least one.
fn scan_config(
    interval_seconds: Option<u64>,
    rule_sets: Vec<RuleSetFile>,
) -> Result<ScanConfig, AgentError> {
    let interval = interval_seconds.unwrap_or(DEFAULT_SCAN_INTERVAL_SECONDS);
    let limits = ResourceLimits::V1;
    if !SCAN_INTERVAL_SECONDS.contains(&interval) || rule_sets.len() > limits.list_items {
        return Err(AgentError::Config);
    }
    let mut sets = Vec::new();
    let mut trusted_keys = Vec::new();
    for set in rule_sets {
        // The agent's own alarms use a reserved rule set id (P14).
        if set.trusted_keys.is_empty()
            || set.id.as_str() == crate::alarms::engine::AGENT_RULE_SET
            || sets.iter().any(|seen: &RuleSetConfig| seen.id == set.id)
        {
            return Err(AgentError::Config);
        }
        for key in set.trusted_keys {
            let bytes: [u8; 32] = URL_SAFE_NO_PAD
                .decode(key.public_key.as_bytes())
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or(AgentError::Config)?;
            trusted_keys.push(
                TrustedRuleKey::new(set.id.clone(), key.issuer_key_id, bytes)
                    .map_err(|_| AgentError::Config)?,
            );
        }
        let restricted = set.restricted.unwrap_or(set.id.as_str() != BASELINE_ALARMS);
        sets.push(RuleSetConfig {
            id: set.id,
            bundle_file: set.bundle_file,
            restricted,
            source: RuleSetSource::Configured,
        });
    }
    Ok(ScanConfig {
        interval_ms: i64::try_from(interval * 1_000).unwrap_or(i64::MAX),
        rule_sets: sets,
        trusted_keys,
        collectors: Collectors::default(),
    })
}

/// Reads the enrollment token, trimming surrounding whitespace. A missing file
/// is `None`, since operators remove it once the agent has enrolled. The file
/// is a secret: readable by others, it is [`AgentError::InsecureFile`].
pub fn read_enrollment_token(path: &Path) -> Result<Option<EnrollmentToken>, AgentError> {
    let limit = u64::try_from(ResourceLimits::V1.string_bytes).unwrap_or(u64::MAX);
    let Some(bytes) = read_bounded(path, limit, true)? else {
        return Ok(None);
    };
    let text = std::str::from_utf8(&bytes).map_err(|_| AgentError::Config)?;
    EnrollmentToken::new(text.trim())
        .map(Some)
        .map_err(|_| AgentError::Config)
}

/// Reads at most `limit` bytes of a trusted input file (`secret`: also
/// unreadable by others); `None` if the file does not exist.
pub(crate) fn read_bounded(
    path: &Path,
    limit: u64,
    secret: bool,
) -> Result<Option<Vec<u8>>, AgentError> {
    let file = match open_input_file(path, secret) {
        Ok(Some(file)) => file,
        Ok(None) => return Ok(None),
        Err(StorageError::InsecurePath) => return Err(AgentError::InsecureFile),
        Err(_) => return Err(AgentError::Config),
    };
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| AgentError::Config)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(AgentError::Config);
    }
    Ok(Some(bytes))
}

#[cfg(test)]
mod tests {
    use super::derived_distribution_url as derived;

    #[test]
    fn a_derived_url_keeps_only_the_host() {
        assert_eq!(
            derived("https://p.example:18423/x").as_deref(),
            Some("https://p.example:18424")
        );
        assert_eq!(
            derived("https://[::1]:18423").as_deref(),
            Some("https://[::1]:18424")
        );
    }

    #[test]
    fn nothing_is_derived_from_a_bad_platform_url() {
        for url in [
            "https://user@p.example",
            "https://user:pw@p.example:18423",
            "https://p.example?x=1",
            "https://p.example:18423?x=1",
            "https://p.example#frag",
            "https://[::1]#frag",
            "http://p.example",
            "https://",
            "https://:18423",
            "https://[::1",
            "p.example",
            "",
        ] {
            assert_eq!(derived(url), None, "{url}");
        }
    }
}
