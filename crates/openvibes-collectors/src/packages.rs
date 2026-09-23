//! Installed packages: `package.names`, `package.count`, and the inventory.
//!
//! - `package.names` (string list): sorted, de-duplicated package names from
//!   every supported package database on the host.
//! - `package.count` (integer): the number of installed package records.
//!
//! The same records form the host inventory ([`InstalledPackage`]), copied
//! from the database without verification or CPE normalisation. RPM's
//! `gpg-pubkey` pseudo-packages (imported signing keys) are skipped.
//!
//! All or nothing, like the processes collector: an unreadable or malformed
//! database, more packages than the fact list limit, or a passed deadline
//! yields no facts and one [`CollectorError`].
//!
//! Sources and privileges (Linux): the RPM database
//! `/var/lib/rpm/rpmdb.sqlite` (RPM 4.16 and later), opened read-only, and
//! dpkg's `/var/lib/dpkg/status`. Both are world-readable by default, so no
//! privilege is needed. Older Berkeley DB RPM databases, Windows, and macOS
//! report `unsupported`.

use std::time::Instant;

use openvibes_core::{
    CollectorError, CollectorErrorCode, Fact, FactValue, Identifier, InstalledPackage,
    ResourceLimits,
};

/// Collector identifier reported as the source of every fact and error.
const SOURCE: &str = "packages";

/// Reads every supported package database, or one error if the result would
/// be incomplete. Never writes to any database.
pub fn collect_packages(
    deadline: Instant,
    limits: ResourceLimits,
) -> Result<Vec<InstalledPackage>, CollectorError> {
    let packages = platform::packages(deadline)?;
    if Instant::now() > deadline {
        return Err(error(
            CollectorErrorCode::TimedOut,
            "package scan exceeded its deadline",
            true,
        ));
    }
    if packages.len() > limits.fact_list_items {
        return Err(error(
            CollectorErrorCode::InvalidData,
            "more packages than the fact list limit",
            true,
        ));
    }
    Ok(packages)
}

/// The `package.*` facts for a collected inventory.
#[must_use]
pub fn package_facts(packages: &[InstalledPackage]) -> Vec<Fact> {
    let mut names: Vec<String> = packages
        .iter()
        .map(|package| package.name.clone())
        .collect();
    names.sort_unstable();
    names.dedup();
    let count = i64::try_from(packages.len()).unwrap_or(i64::MAX);
    vec![
        fact("package.names", FactValue::StringList(names)),
        fact("package.count", FactValue::Integer(count)),
    ]
}

fn fact(key: &str, value: FactValue) -> Fact {
    Fact {
        key: Identifier::new(key).expect("static fact key"),
        source: Identifier::new(SOURCE).expect("static collector id"),
        value,
    }
}

fn error(code: CollectorErrorCode, message: &str, retryable: bool) -> CollectorError {
    CollectorError {
        collector: Identifier::new(SOURCE).expect("static collector id"),
        code,
        message: message.to_owned(),
        retryable,
    }
}

#[cfg(target_os = "linux")]
mod dpkg;
#[cfg(target_os = "linux")]
mod rpm;

#[cfg(target_os = "linux")]
mod platform {
    use std::{path::Path, time::Instant};

    use openvibes_core::{CollectorError, CollectorErrorCode, InstalledPackage};

    use super::{dpkg, error, rpm};

    const RPM_DB: &str = "/var/lib/rpm/rpmdb.sqlite";
    const RPM_BDB: &str = "/var/lib/rpm/Packages";
    const DPKG_STATUS: &str = "/var/lib/dpkg/status";

    pub(super) fn packages(deadline: Instant) -> Result<Vec<InstalledPackage>, CollectorError> {
        let mut packages = Vec::new();
        let mut found = false;
        if Path::new(RPM_DB).exists() {
            packages.extend(rpm::read(Path::new(RPM_DB), deadline)?);
            found = true;
        } else if Path::new(RPM_BDB).exists() {
            return Err(error(
                CollectorErrorCode::Unsupported,
                "Berkeley DB RPM databases are not supported",
                false,
            ));
        }
        if Path::new(DPKG_STATUS).exists() {
            packages.extend(dpkg::read(Path::new(DPKG_STATUS))?);
            found = true;
        }
        if !found {
            return Err(error(
                CollectorErrorCode::NotFound,
                "no supported package database",
                false,
            ));
        }
        Ok(packages)
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use std::time::Instant;

    use openvibes_core::{CollectorError, CollectorErrorCode, InstalledPackage};

    pub(super) fn packages(_deadline: Instant) -> Result<Vec<InstalledPackage>, CollectorError> {
        Err(super::error(
            CollectorErrorCode::Unsupported,
            "package collection is not supported on this OS yet",
            false,
        ))
    }
}

#[cfg(test)]
mod tests;
