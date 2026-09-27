//! The inventory fingerprint and change sets (protocol P11). Both sides
//! compute the fingerprint over the normalised package record the platform
//! stores, so the platform can check a change set against what it holds.

use std::collections::BTreeMap;

use serde::{Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::{InstalledPackage, OsRelease, PackageManager};

/// A package as the fingerprint and the platform see it: `vendor` dropped,
/// absent epoch 0, absent release and arch empty.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NormalizedPackage {
    /// `rpm` or `dpkg`.
    pub manager: String,
    /// Package name.
    pub name: String,
    /// Epoch; 0 when the package sets none.
    pub epoch: u32,
    /// Upstream version.
    pub version: String,
    /// Distribution release; empty when absent.
    pub release: String,
    /// Architecture; empty when absent.
    pub arch: String,
    /// Source package, when it differs from the binary's name.
    pub source: Option<String>,
    /// dpkg: the source's full version, when it differs.
    pub source_version: Option<String>,
}

impl From<&InstalledPackage> for NormalizedPackage {
    fn from(package: &InstalledPackage) -> Self {
        Self {
            manager: match package.manager {
                PackageManager::Rpm => "rpm",
                PackageManager::Dpkg => "dpkg",
            }
            .to_owned(),
            name: package.name.clone(),
            epoch: package.epoch.unwrap_or(0),
            version: package.version.clone(),
            release: package.release.clone().unwrap_or_default(),
            arch: package.arch.clone().unwrap_or_default(),
            source: package.source.clone(),
            source_version: package.source_version.clone(),
        }
    }
}

/// The contract's record: an eight-element JSON array.
impl Serialize for NormalizedPackage {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        (
            &self.manager,
            &self.name,
            self.epoch,
            &self.version,
            &self.release,
            &self.arch,
            &self.source,
            &self.source_version,
        )
            .serialize(serializer)
    }
}

/// SHA-256 of `[[os.id, os.version_id], running_kernel, [record, …]]` in
/// compact JSON, records deduplicated and sorted by their JSON text
/// (contracts-v1, "Inventory fingerprint").
#[must_use]
pub fn inventory_fingerprint(
    os: &OsRelease,
    running_kernel: Option<&str>,
    packages: impl IntoIterator<Item = NormalizedPackage>,
) -> [u8; 32] {
    // Strings, integers and nulls always serialize.
    let mut records: Vec<String> = packages
        .into_iter()
        .map(|package| serde_json::to_string(&package).unwrap_or_default())
        .collect();
    records.sort_unstable();
    records.dedup();
    let head = serde_json::to_string(&(os.id.as_str(), os.version_id.as_str())).unwrap_or_default();
    let kernel = serde_json::to_string(&running_kernel).unwrap_or_default();
    let text = format!("[{head},{kernel},[{}]]", records.join(","));
    Sha256::digest(text.as_bytes()).into()
}

/// Lowercase hex.
#[must_use]
pub fn hex(digest: &[u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The digest `hex` wrote; `None` for anything but 64 lowercase hex digits.
#[must_use]
pub fn digest_from_hex(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut digest = [0; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(digest)
}

/// `(added, removed)` from `base` to `current`, compared by normalised
/// record: an update is one removed and one added.
#[must_use]
pub fn inventory_changes(
    base: &[InstalledPackage],
    current: &[InstalledPackage],
) -> (Vec<InstalledPackage>, Vec<InstalledPackage>) {
    let index = |list: &[InstalledPackage]| -> BTreeMap<NormalizedPackage, InstalledPackage> {
        list.iter()
            .map(|package| (NormalizedPackage::from(package), package.clone()))
            .collect()
    };
    let (old, new) = (index(base), index(current));
    let only = |from: &BTreeMap<NormalizedPackage, InstalledPackage>,
                other: &BTreeMap<NormalizedPackage, InstalledPackage>| {
        from.iter()
            .filter(|(key, _)| !other.contains_key(*key))
            .map(|(_, package)| package.clone())
            .collect()
    };
    (only(&new, &old), only(&old, &new))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize)]
    struct Vector {
        name: String,
        inventory: Inventory,
        sha256: String,
    }
    #[derive(serde::Deserialize)]
    struct Inventory {
        os: OsRelease,
        running_kernel: Option<String>,
        packages: Vec<InstalledPackage>,
    }

    #[test]
    fn the_fingerprint_matches_the_protocol_vectors() {
        let text = include_str!("../../../protocol/vectors/inventory-fingerprint.json");
        let vectors: Vec<Vector> = serde_json::from_str(text).unwrap();
        assert_eq!(vectors.len(), 3);
        for vector in vectors {
            let inventory = vector.inventory;
            let digest = inventory_fingerprint(
                &inventory.os,
                inventory.running_kernel.as_deref(),
                inventory.packages.iter().map(NormalizedPackage::from),
            );
            assert_eq!(hex(&digest), vector.sha256, "{}", vector.name);
            assert_eq!(digest_from_hex(&vector.sha256), Some(digest));
        }
        assert_eq!(digest_from_hex(&"A".repeat(64)), None, "lowercase only");
        assert_eq!(digest_from_hex("00"), None);
    }

    fn package(name: &str, version: &str) -> InstalledPackage {
        serde_json::from_value(serde_json::json!({
            "manager": "rpm", "name": name, "version": version, "release": "1.fc44", "arch": "x86_64"
        }))
        .unwrap()
    }

    #[test]
    fn changes_are_whole_records() {
        let base = [
            package("bash", "5.2.37"),
            package("gone", "1"),
            package("same", "1"),
        ];
        let mut vendor = package("same", "1");
        vendor.vendor = Some("Fedora Project".into()); // not part of the record
        let current = [package("bash", "5.2.38"), vendor, package("new", "2")];
        let (added, removed) = inventory_changes(&base, &current);
        let names = |list: &[InstalledPackage]| {
            list.iter()
                .map(|p| format!("{}-{}", p.name, p.version))
                .collect::<Vec<_>>()
        };
        assert_eq!(names(&added), ["bash-5.2.38", "new-2"]);
        assert_eq!(names(&removed), ["bash-5.2.37", "gone-1"]);
        assert_eq!(inventory_changes(&current, &current), (vec![], vec![]));
    }
}
