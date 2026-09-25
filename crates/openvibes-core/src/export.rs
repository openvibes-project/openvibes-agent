use serde::{Deserialize, Serialize};

use crate::{
    Finding, Identifier, ResourceLimits, SchemaVersion, Validate, ValidationError,
    contracts::{validate_string, validate_unix_ms, validate_version},
};

/// One local-only export file: a delivery batch of findings plus the host it
/// came from. Unsigned in version 1; the ingest service stores imports as
/// unauthenticated.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FindingExport {
    /// Wire schema version.
    pub schema_version: SchemaVersion,
    /// Random identifier generated once per agent installation.
    pub install_id: Identifier,
    /// Platform identity, present only while the agent is enrolled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<Identifier>,
    /// Host name as reported by the OS, for operators only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Scanner software version.
    pub scanner_version: String,
    /// Export time as milliseconds since the Unix epoch.
    pub exported_at_unix_ms: i64,
    /// Findings in queue order.
    pub findings: Vec<Finding>,
}

impl Validate for FindingExport {
    fn validate(&self, limits: ResourceLimits) -> Result<(), ValidationError> {
        validate_version(self.schema_version)?;
        if let Some(hostname) = &self.hostname {
            validate_string("hostname", hostname, limits)?;
        }
        validate_string("scanner_version", &self.scanner_version, limits)?;
        validate_unix_ms("exported_at_unix_ms", self.exported_at_unix_ms)?;
        if self.findings.is_empty() || self.findings.len() > limits.delivery_batch_items {
            return Err(ValidationError::new(
                "findings",
                "must contain between one and one delivery batch of findings",
            ));
        }
        self.findings
            .iter()
            .try_for_each(|finding| finding.validate(limits))
    }
}

/// Package database an [`InstalledPackage`] was read from.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageManager {
    /// RPM database (Fedora, RHEL, SUSE, ...).
    Rpm,
    /// dpkg status database (Debian, Ubuntu, ...).
    Dpkg,
}

/// One installed package as its database records it; neither verified nor
/// normalised to CPE names.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InstalledPackage {
    /// Database the record came from.
    pub manager: PackageManager,
    /// Package name.
    pub name: String,
    /// Upstream version, without epoch or distribution release.
    pub version: String,
    /// Distribution release or Debian revision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release: Option<String>,
    /// Version epoch, when the package sets one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u32>,
    /// Architecture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    /// Vendor as the database records it (RPM only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    /// dpkg only: source package, when it differs from the binary's name
    /// (protocol P10).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// dpkg only: the source's full version, when it differs from the
    /// binary's (a binNMU).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_version: Option<String>,
}

/// One local-only snapshot of the host's installed packages. Unsigned in
/// version 1, like [`FindingExport`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InventoryExport {
    /// Wire schema version.
    pub schema_version: SchemaVersion,
    /// Random identifier generated once per agent installation.
    pub install_id: Identifier,
    /// Platform identity, present only while the agent is enrolled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<Identifier>,
    /// Host name as reported by the OS, for operators only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Scanner software version.
    pub scanner_version: String,
    /// Collection time as milliseconds since the Unix epoch.
    pub collected_at_unix_ms: i64,
    /// Installed packages.
    pub packages: Vec<InstalledPackage>,
}

impl Validate for InstalledPackage {
    fn validate(&self, limits: ResourceLimits) -> Result<(), ValidationError> {
        validate_string("packages.name", &self.name, limits)?;
        validate_string("packages.version", &self.version, limits)?;
        for value in [
            &self.release,
            &self.arch,
            &self.vendor,
            &self.source,
            &self.source_version,
        ]
        .into_iter()
        .flatten()
        {
            validate_string("packages", value, limits)?;
        }
        Ok(())
    }
}

impl Validate for InventoryExport {
    fn validate(&self, limits: ResourceLimits) -> Result<(), ValidationError> {
        validate_version(self.schema_version)?;
        if let Some(hostname) = &self.hostname {
            validate_string("hostname", hostname, limits)?;
        }
        validate_string("scanner_version", &self.scanner_version, limits)?;
        validate_unix_ms("collected_at_unix_ms", self.collected_at_unix_ms)?;
        if self.packages.len() > limits.fact_list_items {
            return Err(ValidationError::new(
                "packages",
                "contains too many packages",
            ));
        }
        self.packages
            .iter()
            .try_for_each(|package| package.validate(limits))
    }
}

/// The host's operating system, from os-release (`ID`, `VERSION_ID`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OsRelease {
    /// Distribution id, e.g. `fedora`.
    pub id: Identifier,
    /// Release, e.g. `44`.
    pub version_id: Identifier,
}

/// Online route (protocol P8): the host's operating system and installed
/// packages, sent to `/v1/inventory` when they change.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InventoryReport {
    /// Wire schema version.
    pub schema_version: SchemaVersion,
    /// The authenticated agent's own id.
    pub agent_id: Identifier,
    /// Operating system.
    pub os: OsRelease,
    /// The running kernel's release as `uname -r` reports it (protocol P9).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub running_kernel: Option<String>,
    /// Collection time as milliseconds since the Unix epoch.
    pub collected_at_unix_ms: i64,
    /// Installed packages.
    pub packages: Vec<InstalledPackage>,
}

impl Validate for InventoryReport {
    fn validate(&self, limits: ResourceLimits) -> Result<(), ValidationError> {
        validate_version(self.schema_version)?;
        validate_unix_ms("collected_at_unix_ms", self.collected_at_unix_ms)?;
        if let Some(kernel) = &self.running_kernel
            && !is_kernel_release(kernel)
        {
            return Err(ValidationError::new(
                "running_kernel",
                "must be 1 to 128 characters from A-Z a-z 0-9 . _ + ~ ^ -",
            ));
        }
        if self.packages.len() > limits.fact_list_items {
            return Err(ValidationError::new(
                "packages",
                "contains too many packages",
            ));
        }
        self.packages
            .iter()
            .try_for_each(|package| package.validate(limits))
    }
}

/// Whether `value` is a kernel release as the schema allows it.
#[must_use]
pub fn is_kernel_release(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+~^-".contains(&b))
}
