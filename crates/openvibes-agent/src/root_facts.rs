//! Root facts (platform spec `2026-10-09-hardening-rules-design.md` §4):
//! what the package-installed helper `openvibes-agent-facts` reads as root,
//! handed to the unprivileged agent in one file. Nobody types a command:
//! the package enables the helper's timer, and the agent uses the file when
//! it is fresh, its own unprivileged scan otherwise.
//!
//! It carries the services scan with exact port owners (protocol P15;
//! replaces the opt-in `owners.conf` drop-in) and the hardening facts
//! (P19). The helper takes no input: no network, no rules, no arguments.

use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::Path,
};

use openvibes_core::{
    CollectorError, CollectorErrorCode, Fact, FactSet, HostService, HostServices, Identifier,
    Owners, ResourceLimits, SchemaVersion, ServiceListener, Validate,
};
use serde::{Deserialize, Serialize};

/// Where the helper writes and the agent reads. The directory is the
/// helper unit's `RuntimeDirectory` (`0750 root:openvibes_agent`).
pub const PATH: &str = "/run/openvibes-agent-facts/root-facts.json";
/// Largest file read; a full services scan is well under 1 MiB.
const MAX_BYTES: u64 = 4 * 1024 * 1024;
/// Older than this, the agent scans itself: three of the helper's
/// 5-minute runs missed.
const FRESH_MS: i64 = 15 * 60 * 1000;
/// Clock skew tolerated for a file dated slightly ahead.
const AHEAD_MS: i64 = 60 * 1000;

/// The file. Unknown fields are refused: helper and agent ship together.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootFacts {
    /// Format version, 1.
    pub schema_version: u32,
    /// When the helper read the host.
    pub collected_at_unix_ms: i64,
    /// The services scan with exact owners; absent when it failed.
    pub services: Option<ServicesScan>,
    /// The hardening facts and the sources that could not be read (P19).
    #[serde(default)]
    pub hardening: Option<HardeningScan>,
}

/// The hardening collector's result (P19).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HardeningScan {
    /// Facts, source `hardening`.
    pub facts: Vec<Fact>,
    /// One error per unreadable source (`hardening.<source>`).
    pub errors: Vec<CollectorError>,
}

/// The services collector's result, as the agent sends it (P15).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServicesScan {
    /// `complete` when every listener's holder was found.
    pub owners: Owners,
    /// Listening sockets, servers only.
    pub listeners: Vec<ServiceListener>,
    /// Running systemd services.
    pub services: Vec<HostService>,
}

/// Writes `facts` atomically: a temporary file in the same directory, then
/// a rename, so the agent never reads half a file. `0640`: the group
/// (the unit's `Group=openvibes_agent`) may read it.
pub fn write(path: &Path, facts: &RootFacts) -> io::Result<()> {
    let bytes = serde_json::to_vec(facts).map_err(io::Error::other)?;
    let tmp = path.with_extension("json.tmp");
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o640);
    let mut file = options.open(&tmp)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(&tmp, path)
}

/// The file, when it is present, well-formed and fresh.
fn fresh(path: &Path, now_unix_ms: i64) -> Option<RootFacts> {
    // The same checks as every file the agent reads but does not own: a
    // regular file, on a path no other user can redirect.
    let file = openvibes_storage::open_input_file(path, false).ok()??;
    let mut text = String::new();
    file.take(MAX_BYTES + 1).read_to_string(&mut text).ok()?;
    if u64::try_from(text.len()).ok()? > MAX_BYTES {
        return None;
    }
    let facts: RootFacts = serde_json::from_str(&text).ok()?;
    let age = now_unix_ms - facts.collected_at_unix_ms;
    (facts.schema_version == 1 && (-AHEAD_MS..=FRESH_MS).contains(&age)).then_some(facts)
}

/// The services scan from a fresh, well-formed file, or `None` (missing,
/// unreadable, too big, stale, dated ahead, malformed, or refused by the
/// P15 validation): the agent then scans itself.
#[must_use]
pub fn fresh_services(path: &Path, now_unix_ms: i64) -> Option<ServicesScan> {
    let facts = fresh(path, now_unix_ms)?;
    let scan = facts.services?;
    valid(&scan, facts.collected_at_unix_ms).then_some(scan)
}

/// The hardening facts for a scan (P19); `Ok(None)` without the helper's
/// file (no helper on this OS, or not run yet: like a disabled collector);
/// or the one error that makes them all unavailable: the file is stale or
/// malformed, or its facts do not pass validation on their own (so a bad
/// file can never invalidate the rest of the scan).
pub fn fresh_hardening(
    path: &Path,
    now_unix_ms: i64,
) -> Result<Option<HardeningScan>, CollectorError> {
    if fs::symlink_metadata(path).is_err() {
        return Ok(None);
    }
    let unavailable = |code, message: &str| CollectorError {
        collector: Identifier::new("hardening").expect("static collector id"),
        code,
        message: message.to_owned(),
        retryable: true,
    };
    let Some(facts) = fresh(path, now_unix_ms) else {
        return Err(unavailable(
            CollectorErrorCode::NotFound,
            "the root-facts helper's file is unreadable, malformed or stale",
        ));
    };
    let Some(scan) = facts.hardening else {
        return Err(unavailable(
            CollectorErrorCode::NotFound,
            "the root-facts helper sent no hardening facts",
        ));
    };
    let alone = FactSet {
        schema_version: SchemaVersion::V1,
        scan_id: Identifier::new("hardening").expect("static id"),
        collected_at_unix_ms: facts.collected_at_unix_ms,
        facts: scan.facts.clone(),
        errors: scan.errors.clone(),
    };
    let ours = scan.facts.iter().all(|f| f.source.as_str() == "hardening")
        && scan
            .errors
            .iter()
            .all(|e| e.collector.as_str().starts_with("hardening."));
    if !ours || alone.validate(ResourceLimits::V1).is_err() {
        return Err(unavailable(
            CollectorErrorCode::InvalidData,
            "the root-facts helper's hardening facts are invalid",
        ));
    }
    Ok(Some(scan))
}

/// Whether the scan, as the agent would send it, passes P15 validation.
fn valid(scan: &ServicesScan, collected_at_unix_ms: i64) -> bool {
    let snapshot = crate::services::Snapshot::new(
        scan.owners,
        scan.listeners.clone(),
        scan.services.clone(),
        collected_at_unix_ms,
    );
    let Ok(agent_id) = Identifier::new("root-facts") else {
        return false;
    };
    HostServices {
        schema_version: SchemaVersion::V1,
        agent_id,
        collected_at_unix_ms,
        sha256: snapshot.sha256,
        owners: snapshot.owners,
        truncated: snapshot.truncated,
        listeners: snapshot.listeners,
        services: snapshot.services,
    }
    .validate(ResourceLimits::V1)
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::{FRESH_MS, PATH, RootFacts, ServicesScan, fresh_services, write};
    use openvibes_core::Owners;

    fn facts(at: i64) -> RootFacts {
        RootFacts {
            schema_version: 1,
            collected_at_unix_ms: at,
            services: Some(ServicesScan {
                owners: Owners::Complete,
                listeners: Vec::new(),
                services: Vec::new(),
            }),
            hardening: None,
        }
    }

    #[test]
    fn hardening_facts_pass_alone_or_not_at_all() {
        use super::{HardeningScan, fresh_hardening};
        use openvibes_core::{Fact, FactValue, Identifier};
        let path = scratch("hardening");
        let now = 1_800_000_000_000;
        let fact = |key: &str, source: &str, value| Fact {
            key: Identifier::new(key).unwrap(),
            source: Identifier::new(source).unwrap(),
            value,
        };
        let mut file = facts(now - 60_000);
        assert_eq!(
            fresh_hardening(&path, now),
            Ok(None),
            "no file: no helper here"
        );
        write(&path, &file).unwrap();
        assert!(fresh_hardening(&path, now).is_err(), "no hardening section");
        file.hardening = Some(HardeningScan {
            facts: vec![fact(
                "sshd.permitrootlogin",
                "hardening",
                FactValue::String(String::new()),
            )],
            errors: Vec::new(),
        });
        write(&path, &file).unwrap();
        assert_eq!(
            fresh_hardening(&path, now).unwrap().unwrap().facts.len(),
            1,
            "an empty string is the unset value"
        );
        file.hardening = Some(HardeningScan {
            facts: vec![fact(
                "process.names",
                "processes",
                FactValue::StringList(Vec::new()),
            )],
            errors: Vec::new(),
        });
        write(&path, &file).unwrap();
        assert!(
            fresh_hardening(&path, now).is_err(),
            "another collector's fact"
        );
        file.hardening = Some(HardeningScan {
            facts: vec![fact(
                "mount.tmp.options",
                "hardening",
                FactValue::StringList(vec!["b".into(), "a".into()]),
            )],
            errors: Vec::new(),
        });
        write(&path, &file).unwrap();
        assert!(fresh_hardening(&path, now).is_err(), "an unsorted list");
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("root-facts-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .unwrap();
        dir.join("root-facts.json")
    }

    #[test]
    fn a_fresh_file_is_used_and_a_stale_or_future_one_is_not() {
        let path = scratch("fresh");
        let now = 1_800_000_000_000;
        write(&path, &facts(now - 60_000)).unwrap();
        let scan = fresh_services(&path, now).expect("fresh");
        assert_eq!(scan.owners, Owners::Complete);
        write(&path, &facts(now - FRESH_MS - 1)).unwrap();
        assert_eq!(fresh_services(&path, now), None, "stale");
        write(&path, &facts(now + 5 * 60_000)).unwrap();
        assert_eq!(fresh_services(&path, now), None, "dated ahead");
    }

    #[test]
    fn missing_malformed_or_unknown_fields_fall_back() {
        let path = scratch("bad");
        let now = 1_800_000_000_000;
        assert_eq!(fresh_services(&path, now), None, "missing");
        std::fs::write(&path, b"{not json").unwrap();
        assert_eq!(fresh_services(&path, now), None, "malformed");
        let extra = format!(
            r#"{{"schema_version":1,"collected_at_unix_ms":{now},"services":null,"other":1}}"#
        );
        std::fs::write(&path, extra).unwrap();
        assert_eq!(fresh_services(&path, now), None, "unknown field");
        let mut v2 = facts(now);
        v2.schema_version = 2;
        write(&path, &v2).unwrap();
        assert_eq!(fresh_services(&path, now), None, "other version");
    }

    #[test]
    fn the_path_is_the_one_the_unit_and_install_sh_expect() {
        assert_eq!(PATH, "/run/openvibes-agent-facts/root-facts.json");
    }
}
