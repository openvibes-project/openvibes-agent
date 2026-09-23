use std::{
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
};

use openvibes_core::{EnrollmentToken, ResourceLimits};
use openvibes_transport::TransportConfig;
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
}

/// Validated agent configuration.
#[derive(Clone, Debug)]
pub struct AgentConfig {
    /// How to reach and authenticate the platform; `None` when local-only,
    /// in which case the agent never uses the network.
    pub transport: Option<TransportConfig>,
    /// Private agent-owned state directory.
    pub state_dir: PathBuf,
    /// File holding a single-use enrollment token, read only while the agent
    /// has no identity. The agent never modifies or deletes it.
    pub enrollment_token_file: Option<PathBuf>,
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
            .is_none_or(|path| path.is_absolute());
    if !absolute {
        return Err(AgentError::Config);
    }
    let transport = match (file.platform_url, file.platform_ca_file) {
        (Some(base_url), Some(ca_file)) => {
            let limits = ResourceLimits::V1;
            let ca_bytes = u64::try_from(limits.document_bytes).unwrap_or(u64::MAX);
            let server_roots_pem = read_bounded(&ca_file, ca_bytes)?.ok_or(AgentError::Config)?;
            Some(TransportConfig {
                base_url,
                server_roots_pem,
                proxy_url: file.proxy_url,
                limits,
            })
        }
        (None, None) if file.proxy_url.is_none() && file.enrollment_token_file.is_none() => None,
        _ => return Err(AgentError::Config),
    };
    Ok(AgentConfig {
        transport,
        state_dir: file.state_dir,
        enrollment_token_file: file.enrollment_token_file,
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
fn read_bounded(path: &Path, limit: u64) -> Result<Option<Vec<u8>>, AgentError> {
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
