//! Windows programs (protocol P22): the entries Apps and Features lists,
//! from `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` in the
//! 64-bit and the 32-bit registry view. Readable by every account, so the
//! service's virtual account needs no privilege. Per-user installs (HKCU)
//! are not listed: the service cannot see other users' hives.

use openvibes_core::{InstalledPackage, PackageManager, ResourceLimits};

/// One Uninstall subkey's values.
#[derive(Default)]
pub(crate) struct Entry {
    pub(crate) name: Option<String>,
    pub(crate) version: Option<String>,
    pub(crate) publisher: Option<String>,
    pub(crate) system_component: bool,
    /// Set on updates and patches, which Apps and Features nests under
    /// their program.
    pub(crate) has_parent: bool,
}

/// The package for an entry Apps and Features would show, or `None`. Values
/// over the string limit or with a NUL are dropped (the program, or only
/// its publisher), never cut.
pub(crate) fn program(
    entry: Entry,
    arch: &str,
    limits: ResourceLimits,
) -> Option<InstalledPackage> {
    let valid = |value: Option<String>| {
        value.map(|value| value.trim().to_owned()).filter(|value| {
            !value.is_empty() && value.len() <= limits.string_bytes && !value.contains('\0')
        })
    };
    if entry.system_component || entry.has_parent {
        return None;
    }
    Some(InstalledPackage {
        manager: PackageManager::Windows,
        name: valid(entry.name)?,
        version: valid(entry.version)?,
        release: None,
        epoch: None,
        arch: Some(arch.to_owned()),
        vendor: valid(entry.publisher),
        source: None,
        source_version: None,
    })
}

#[cfg(windows)]
pub(super) fn read(
    deadline: std::time::Instant,
) -> Result<Vec<InstalledPackage>, openvibes_core::CollectorError> {
    use openvibes_core::CollectorErrorCode;
    use winreg::{
        RegKey,
        enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY},
    };

    const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    let limits = ResourceLimits::V1;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let mut packages = Vec::new();
    for (view, arch) in [(KEY_WOW64_64KEY, "x86_64"), (KEY_WOW64_32KEY, "x86")] {
        let flags = KEY_READ | view;
        let uninstall = hklm.open_subkey_with_flags(UNINSTALL, flags).map_err(|_| {
            super::error(
                CollectorErrorCode::NotFound,
                "cannot open the Uninstall registry key",
                true,
            )
        })?;
        for name in uninstall.enum_keys() {
            if std::time::Instant::now() > deadline {
                break; // collect_packages reports the timeout
            }
            // An entry that vanished or cannot be read is skipped, as Apps
            // and Features does.
            let Ok(key) = name.and_then(|name| uninstall.open_subkey_with_flags(name, flags))
            else {
                continue;
            };
            let entry = Entry {
                name: key.get_value("DisplayName").ok(),
                version: key.get_value("DisplayVersion").ok(),
                publisher: key.get_value("Publisher").ok(),
                system_component: key
                    .get_value::<u32, _>("SystemComponent")
                    .is_ok_and(|v| v == 1),
                has_parent: key.get_value::<String, _>("ParentKeyName").is_ok(),
            };
            packages.extend(program(entry, arch, limits));
            super::check_count(packages.len(), limits)?;
        }
    }
    Ok(packages)
}

/// The Windows version as `os` (P22): `windows` and
/// `<major>.<minor>.<build>.<UBR>`, e.g. `10.0.26100.2894`.
#[must_use]
pub(crate) fn os(
    major: u32,
    minor: u32,
    build: &str,
    ubr: u32,
) -> Option<openvibes_core::OsRelease> {
    let build: u32 = build.trim().parse().ok()?;
    Some(openvibes_core::OsRelease {
        id: openvibes_core::Identifier::new("windows").ok()?,
        version_id: openvibes_core::Identifier::new(format!("{major}.{minor}.{build}.{ubr}"))
            .ok()?,
    })
}

#[cfg(windows)]
pub(crate) fn os_release() -> Option<openvibes_core::OsRelease> {
    use winreg::{RegKey, enums::HKEY_LOCAL_MACHINE};
    let key = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        .ok()?;
    os(
        key.get_value("CurrentMajorVersionNumber").ok()?,
        key.get_value("CurrentMinorVersionNumber").ok()?,
        &key.get_value::<String, _>("CurrentBuildNumber").ok()?,
        key.get_value("UBR").unwrap_or(0),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, version: &str) -> Entry {
        Entry {
            name: Some(name.into()),
            version: Some(version.into()),
            publisher: Some(" Igor Pavlov ".into()),
            ..Entry::default()
        }
    }

    #[test]
    fn lists_what_apps_and_features_shows() {
        let limits = ResourceLimits::V1;
        let p = program(entry("7-Zip 24.08 (x64)", "24.08"), "x86_64", limits).unwrap();
        assert_eq!(
            (p.name.as_str(), p.version.as_str()),
            ("7-Zip 24.08 (x64)", "24.08")
        );
        assert_eq!(
            (p.vendor.as_deref(), p.arch.as_deref()),
            (Some("Igor Pavlov"), Some("x86_64"))
        );
        assert_eq!(p.manager, PackageManager::Windows);

        let hidden = Entry {
            system_component: true,
            ..entry("a", "1")
        };
        let update = Entry {
            has_parent: true,
            ..entry("a", "1")
        };
        for skipped in [
            hidden,
            update,
            entry("", "1"),
            entry("a", " "),
            Entry::default(),
        ] {
            assert!(program(skipped, "x86", limits).is_none());
        }
        let long = "x".repeat(limits.string_bytes + 1);
        assert!(program(entry(&long, "1"), "x86", limits).is_none());
        assert!(program(entry("a\0b", "1"), "x86", limits).is_none());
        let bad_publisher = Entry {
            publisher: Some(long),
            ..entry("a", "1")
        };
        assert_eq!(program(bad_publisher, "x86", limits).unwrap().vendor, None);
    }

    #[test]
    fn windows_version() {
        let os = os(10, 0, "26100", 2894).unwrap();
        assert_eq!(
            (os.id.as_str(), os.version_id.as_str()),
            ("windows", "10.0.26100.2894")
        );
        assert!(super::os(10, 0, "not a build", 1).is_none());
    }
}
