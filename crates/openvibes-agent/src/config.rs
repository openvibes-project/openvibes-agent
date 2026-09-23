use std::{
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openvibes_core::{EnrollmentToken, Identifier, ResourceLimits};
use openvibes_rules::TrustedRuleKey;
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
    #[serde(default)]
    rule_sets: Vec<RuleSetFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleSetFile {
    id: Identifier,
    bundle_file: Option<PathBuf>,
    trusted_keys: Vec<TrustedKeyFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedKeyFile {
    issuer_key_id: Identifier,
    /// Unpadded base64url of the 32-byte Ed25519 public key.
    public_key: String,
}

/// Default time between scans.
const DEFAULT_SCAN_INTERVAL_SECONDS: u64 = 3_600;
/// Allowed scan intervals. Every scan re-reports its matches as new findings,
/// so the lower bound also bounds the finding rate.
const SCAN_INTERVAL_SECONDS: std::ops::RangeInclusive<u64> = 60..=86_400;

/// A locally provisioned, signed rule bundle and the keys trusted for it.
#[derive(Clone, Debug)]
pub struct RuleSetConfig {
    /// Rule-set identity the bundle must carry.
    pub id: Identifier,
    /// Signed envelope file, read on every scan; `None` when the rule set
    /// comes only from the distribution service.
    pub bundle_file: Option<PathBuf>,
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
    /// Private agent-owned state directory.
    pub state_dir: PathBuf,
    /// File holding a single-use enrollment token, read only while the agent
    /// has no identity. The agent never modifies or deletes it.
    pub enrollment_token_file: Option<PathBuf>,
    /// Scanning and locally provisioned rules.
    pub scan: ScanConfig,
}

/// Loads a TOML configuration and the platform CA bundle it names.
///
/// Every path must be absolute. `platform_url` and `platform_ca_file` come
/// together; a local-only configuration may not name a proxy or token. Files
/// are size-checked before parsing, and failures report
/// [`AgentError::Config`] without echoing content or paths.
pub fn load_config(path: &Path) -> Result<AgentConfig, AgentError> {
    let bytes = read_bounded(path, CONFIG_BYTES)?.ok_or(AgentError::Config)?;
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
    let scan = scan_config(file.scan_interval_seconds, file.rule_sets)?;
    let transport = match (file.platform_url, file.platform_ca_file) {
        (Some(base_url), Some(ca_file)) => {
            let limits = ResourceLimits::V1;
            let ca_bytes = u64::try_from(limits.document_bytes).unwrap_or(u64::MAX);
            let server_roots_pem = read_bounded(&ca_file, ca_bytes)?.ok_or(AgentError::Config)?;
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
    let distribution = match (file.distribution_url, &transport) {
        (Some(base_url), Some(platform)) => Some(TransportConfig {
            base_url,
            default_port: DEFAULT_DISTRIBUTION_PORT,
            ..platform.clone()
        }),
        (None, _) => None,
        (Some(_), None) => return Err(AgentError::Config),
    };
    Ok(AgentConfig {
        transport,
        distribution,
        state_dir: file.state_dir,
        enrollment_token_file: file.enrollment_token_file,
        scan,
    })
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
        if set.trusted_keys.is_empty() || sets.iter().any(|seen: &RuleSetConfig| seen.id == set.id)
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
        sets.push(RuleSetConfig {
            id: set.id,
            bundle_file: set.bundle_file,
        });
    }
    Ok(ScanConfig {
        interval_ms: i64::try_from(interval * 1_000).unwrap_or(i64::MAX),
        rule_sets: sets,
        trusted_keys,
    })
}

/// Reads the enrollment token, trimming surrounding whitespace. A missing file
/// is `None`, since operators remove it once the agent has enrolled.
pub fn read_enrollment_token(path: &Path) -> Result<Option<EnrollmentToken>, AgentError> {
    let limit = u64::try_from(ResourceLimits::V1.string_bytes).unwrap_or(u64::MAX);
    let Some(bytes) = read_bounded(path, limit)? else {
        return Ok(None);
    };
    let text = std::str::from_utf8(&bytes).map_err(|_| AgentError::Config)?;
    EnrollmentToken::new(text.trim())
        .map(Some)
        .map_err(|_| AgentError::Config)
}

/// Reads at most `limit` bytes; `None` if the file does not exist.
pub(crate) fn read_bounded(path: &Path, limit: u64) -> Result<Option<Vec<u8>>, AgentError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
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
