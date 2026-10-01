//! Host services wire types (protocol P15, `POST /v1/services`): the
//! host's listening sockets and running systemd services.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    Identifier, ResourceLimits, SchemaVersion, Validate, ValidationError,
    contracts::{validate_identifier, validate_unix_ms, validate_version},
    export::validate_sha256,
};

/// Listeners in one report.
pub const SERVICES_MAX_LISTENERS: usize = 4_096;
/// Services in one report.
pub const SERVICES_MAX_SERVICES: usize = 2_048;
/// Distinct program names per service.
pub const SERVICE_MAX_PROGRAMS: usize = 16;
/// One report, serialized, uncompressed.
pub const HOST_SERVICES_BYTES: usize = 524_288;
/// Longest unit, program or user name.
const NAME_BYTES: usize = 255;

/// Transport protocol of a listener.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ListenerProtocol {
    /// A TCP socket in `LISTEN`.
    Tcp,
    /// An unconnected UDP socket below the ephemeral range.
    Udp,
}

/// One listening socket.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ServiceListener {
    /// `tcp` or `udp`.
    pub protocol: ListenerProtocol,
    /// The bound address (`0.0.0.0` and `::` for any).
    pub address: IpAddr,
    /// 1 to 65535.
    pub port: u16,
    /// Bound to a non-loopback address.
    pub exposed: bool,
    /// The owning systemd unit, when visible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// The owning process's short name, when visible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
}

/// One running systemd service.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HostService {
    /// The unit, e.g. `nginx.service`.
    pub unit: String,
    /// Distinct short names of its processes, sorted, at most 16.
    pub programs: Vec<String>,
    /// Number of processes.
    pub processes: u32,
    /// The main process's user: a name, or the decimal uid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
}

/// How far an absent listener owner can be trusted.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Owners {
    /// Every process's sockets were read: an absent owner means none.
    Complete,
    /// Some owners are not visible.
    Partial,
}

/// Body of `POST /v1/services`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HostServices {
    /// Wire schema version.
    pub schema_version: SchemaVersion,
    /// The authenticated agent.
    pub agent_id: Identifier,
    /// When the lists were read.
    pub collected_at_unix_ms: i64,
    /// [`services_digest`] of the lists, lowercase hex.
    pub sha256: String,
    /// Whether every owner was visible.
    pub owners: Owners,
    /// A list was cut to the limits.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
    /// Listening sockets, servers only.
    pub listeners: Vec<ServiceListener>,
    /// Running systemd services.
    pub services: Vec<HostService>,
}

/// One listener's digest row; also the order lists are cut in.
#[must_use]
pub fn listener_row(listener: &ServiceListener) -> String {
    let protocol = match listener.protocol {
        ListenerProtocol::Tcp => "tcp",
        ListenerProtocol::Udp => "udp",
    };
    serde_json::to_string(&(
        protocol,
        listener.address.to_string(),
        listener.port,
        listener.exposed,
        &listener.service,
        &listener.program,
    ))
    .unwrap_or_default()
}

/// One service's digest row; also the order lists are cut in.
#[must_use]
pub fn service_row(service: &HostService) -> String {
    let mut programs: Vec<&str> = service.programs.iter().map(String::as_str).collect();
    programs.sort_unstable();
    programs.dedup();
    serde_json::to_string(&(&service.unit, programs, service.processes, &service.user))
        .unwrap_or_default()
}

/// SHA-256 of `[[listeners…],[services…]]`, each list deduplicated and
/// sorted by its rows' compact JSON (contracts-v1, "Services digest (P15)").
#[must_use]
pub fn services_digest(listeners: &[ServiceListener], services: &[HostService]) -> [u8; 32] {
    let sorted = |mut rows: Vec<String>| {
        rows.sort_unstable();
        rows.dedup();
        rows.join(",")
    };
    let text = format!(
        "[[{}],[{}]]",
        sorted(listeners.iter().map(listener_row).collect()),
        sorted(services.iter().map(service_row).collect()),
    );
    Sha256::digest(text.as_bytes()).into()
}

/// A unit, program or user name: 1 to 255 bytes, no control characters.
fn validate_name(field: &'static str, value: &str) -> Result<(), ValidationError> {
    if value.is_empty() || value.len() > NAME_BYTES || value.chars().any(|c| c < ' ' || c == '\x7f')
    {
        return Err(ValidationError::new(
            field,
            "must be 1 to 255 bytes without control characters",
        ));
    }
    Ok(())
}

fn validate_unit(value: &str) -> Result<(), ValidationError> {
    validate_name("unit", value)?;
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b":_.@\\-".contains(&b))
    {
        return Err(ValidationError::new("unit", "is not a systemd unit name"));
    }
    Ok(())
}

impl Validate for HostServices {
    fn validate(&self, limits: ResourceLimits) -> Result<(), ValidationError> {
        validate_version(self.schema_version)?;
        validate_identifier("agent_id", self.agent_id.as_str(), limits)?;
        validate_unix_ms("collected_at_unix_ms", self.collected_at_unix_ms)?;
        validate_sha256("sha256", &self.sha256)?;
        if self.listeners.len() > SERVICES_MAX_LISTENERS {
            return Err(ValidationError::new("listeners", "more than 4096"));
        }
        if self.services.len() > SERVICES_MAX_SERVICES {
            return Err(ValidationError::new("services", "more than 2048"));
        }
        for listener in &self.listeners {
            if listener.port == 0 {
                return Err(ValidationError::new("port", "must be 1 to 65535"));
            }
            if let Some(unit) = &listener.service {
                validate_unit(unit)?;
            }
            if let Some(program) = &listener.program {
                validate_name("program", program)?;
            }
        }
        for service in &self.services {
            validate_unit(&service.unit)?;
            if service.programs.len() > SERVICE_MAX_PROGRAMS {
                return Err(ValidationError::new("programs", "more than 16"));
            }
            let mut seen = std::collections::BTreeSet::new();
            for program in &service.programs {
                validate_name("program", program)?;
                if !seen.insert(program) {
                    return Err(ValidationError::new(
                        "programs",
                        "a program is listed twice",
                    ));
                }
            }
            if service.processes > i32::MAX as u32 {
                return Err(ValidationError::new("processes", "exceeds 2^31-1"));
            }
            if let Some(user) = &service.user {
                validate_name("user", user)?;
            }
        }
        let bytes = serde_json::to_vec(self)
            .map_err(|_| ValidationError::new("services", "does not serialize"))?;
        if bytes.len() > HOST_SERVICES_BYTES {
            return Err(ValidationError::new("services", "exceeds 512 KiB"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct Vector {
        name: String,
        listeners: Vec<ServiceListener>,
        services: Vec<HostService>,
        sha256: String,
    }

    #[test]
    fn the_digest_matches_the_protocol_vectors() {
        let text = include_str!("../../../protocol/vectors/services-digest.json");
        let vectors: Vec<Vector> = serde_json::from_str(text).unwrap();
        assert_eq!(vectors.len(), 3);
        for vector in vectors {
            assert_eq!(
                crate::hex(&services_digest(&vector.listeners, &vector.services)),
                vector.sha256,
                "{}",
                vector.name
            );
        }
    }

    #[test]
    fn absent_owner_and_user_are_left_out_of_the_body() {
        let report: HostServices = serde_json::from_str(include_str!(
            "../../../protocol/fixtures/v1/host-services/valid.json"
        ))
        .unwrap();
        let json = serde_json::to_string(&report.listeners[1]).unwrap();
        assert!(
            !json.contains("service") && !json.contains("program"),
            "{json}"
        );
        let json = serde_json::to_string(&report.services[2]).unwrap();
        assert!(!json.contains("user"), "{json}");
    }
}
