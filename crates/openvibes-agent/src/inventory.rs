//! Inventory changes (protocol P11): the last inventory the platform
//! acknowledged is kept as the base, and a change set is sent against it
//! when that is worth it; otherwise the full report.

use std::{fs, io::Read, path::Path};

use openvibes_core::{
    InstalledPackage, InventoryChanges, InventoryReport, NormalizedPackage, OsRelease,
    ResourceLimits, hex, inventory_changes, inventory_fingerprint,
};
use serde::{Deserialize, Serialize};

/// An inventory ready to report, with the fingerprint that decides whether
/// the platform already has it.
pub(crate) struct PendingInventory {
    pub(crate) os: OsRelease,
    pub(crate) running_kernel: Option<String>,
    pub(crate) packages: Vec<InstalledPackage>,
    pub(crate) collected_at_unix_ms: i64,
    pub(crate) sha256: String,
}

/// The last inventory the platform acknowledged, kept in the state
/// directory (`inventory-base.json`, 0600).
#[derive(Deserialize, Serialize)]
pub(crate) struct InventoryBase {
    pub(crate) os: OsRelease,
    pub(crate) running_kernel: Option<String>,
    pub(crate) packages: Vec<InstalledPackage>,
}

impl From<&PendingInventory> for InventoryBase {
    fn from(pending: &PendingInventory) -> Self {
        Self {
            os: pending.os.clone(),
            running_kernel: pending.running_kernel.clone(),
            packages: pending.packages.clone(),
        }
    }
}

/// The contract fingerprint, as lowercase hex.
pub(crate) fn fingerprint(
    os: &OsRelease,
    running_kernel: Option<&str>,
    packages: &[InstalledPackage],
) -> String {
    hex(&inventory_fingerprint(
        os,
        running_kernel,
        packages.iter().map(NormalizedPackage::from),
    ))
}

/// The stored base, only if it reads back whole, within the limits, and its
/// fingerprint is the acknowledged one; anything else means a full report.
pub(crate) fn read_inventory_base(path: &Path, acked: Option<&str>) -> Option<InventoryBase> {
    let acked = acked?;
    let limits = ResourceLimits::V1;
    let max = u64::try_from(limits.inventory_document_bytes).ok()?;
    let mut bytes = Vec::new();
    fs::File::open(path)
        .ok()?
        .take(max + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if u64::try_from(bytes.len()).ok()? > max {
        return None;
    }
    let base: InventoryBase = serde_json::from_slice(&bytes).ok()?;
    (base.packages.len() <= limits.inventory_items
        && fingerprint(&base.os, base.running_kernel.as_deref(), &base.packages) == acked)
        .then_some(base)
}

/// The change set to send instead of `report`, or `None` for the full
/// report: after a 404 (`unsupported`, until restart), without a base whose
/// fingerprint is the acknowledged one, or when the changes are larger than
/// half the full report.
pub(crate) fn changes_to_send(
    unsupported: bool,
    base: Option<&InventoryBase>,
    acked: Option<&str>,
    pending: &PendingInventory,
    report: &InventoryReport,
) -> Option<InventoryChanges> {
    if unsupported {
        return None;
    }
    let (base, acked) = (base?, acked?);
    if fingerprint(&base.os, base.running_kernel.as_deref(), &base.packages) != acked {
        return None;
    }
    let (added, removed) = inventory_changes(&base.packages, &pending.packages);
    let changes = InventoryChanges {
        schema_version: report.schema_version,
        agent_id: report.agent_id.clone(),
        base_sha256: acked.to_owned(),
        sha256: pending.sha256.clone(),
        os: report.os.clone(),
        running_kernel: report.running_kernel.clone(),
        collected_at_unix_ms: report.collected_at_unix_ms,
        added,
        removed,
    };
    let changes_bytes = serde_json::to_vec(&changes).ok()?.len();
    let full_bytes = serde_json::to_vec(report).ok()?.len();
    (changes_bytes * 2 <= full_bytes).then_some(changes)
}

#[cfg(test)]
mod tests {
    use openvibes_core::{Identifier, SchemaVersion};

    use super::*;

    fn package(name: &str) -> InstalledPackage {
        serde_json::from_value(serde_json::json!(
            {"manager": "rpm", "name": name, "version": "1", "release": "1.fc44"}
        ))
        .unwrap()
    }

    fn setup() -> (InventoryBase, String, PendingInventory, InventoryReport) {
        let os: OsRelease = serde_json::from_str(r#"{"id":"fedora","version_id":"44"}"#).unwrap();
        let old: Vec<InstalledPackage> = (0..20).map(|i| package(&format!("p{i}"))).collect();
        let mut new = old.clone();
        new[0] = package("updated");
        let base = InventoryBase {
            os: os.clone(),
            running_kernel: None,
            packages: old,
        };
        let acked = fingerprint(&os, None, &base.packages);
        let pending = PendingInventory {
            sha256: fingerprint(&os, None, &new),
            os: os.clone(),
            running_kernel: None,
            packages: new.clone(),
            collected_at_unix_ms: 1,
        };
        let report = InventoryReport {
            schema_version: SchemaVersion::V1,
            agent_id: Identifier::new("agent.1").unwrap(),
            os,
            running_kernel: None,
            collected_at_unix_ms: 1,
            packages: new,
        };
        (base, acked, pending, report)
    }

    #[test]
    fn a_404_means_full_reports_until_restart() {
        let (base, acked, pending, report) = setup();
        let changes = changes_to_send(false, Some(&base), Some(&acked), &pending, &report)
            .expect("one package changed: a change set");
        assert_eq!((changes.added.len(), changes.removed.len()), (1, 1));
        assert!(changes_to_send(true, Some(&base), Some(&acked), &pending, &report).is_none());
    }

    #[test]
    fn a_base_that_is_not_the_acknowledged_one_is_not_used() {
        let (base, _, pending, report) = setup();
        let other = "0".repeat(64);
        assert!(changes_to_send(false, Some(&base), Some(&other), &pending, &report).is_none());
        assert!(changes_to_send(false, None, Some(&other), &pending, &report).is_none());
    }
}
