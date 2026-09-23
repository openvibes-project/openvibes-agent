use openvibes_core::{FactValue, InstalledPackage, PackageManager};

use super::package_facts;

fn package(name: &str) -> InstalledPackage {
    InstalledPackage {
        manager: PackageManager::Rpm,
        name: name.into(),
        version: "1".into(),
        release: None,
        epoch: None,
        arch: None,
        vendor: None,
    }
}

#[test]
fn facts_are_sorted_unique_names_and_a_record_count() {
    let facts = package_facts(&[package("zlib"), package("bash"), package("zlib")]);
    assert_eq!(facts[0].key.as_str(), "package.names");
    assert_eq!(
        facts[0].value,
        FactValue::StringList(vec!["bash".into(), "zlib".into()])
    );
    assert_eq!(facts[1].value, FactValue::Integer(3));
    assert!(facts.iter().all(|fact| fact.source.as_str() == "packages"));
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        path::Path,
        time::{Duration, Instant},
    };

    use openvibes_core::{CollectorErrorCode, PackageManager, ResourceLimits};

    use super::super::{collect_packages, dpkg::parse_status, rpm};

    const STRING: u32 = 6;
    const INT32: u32 = 4;

    /// An RPM header with `fields` of (tag, type, value bytes).
    fn header(fields: &[(u32, u32, Vec<u8>)]) -> Vec<u8> {
        let mut index = Vec::new();
        let mut data = Vec::new();
        for (tag, kind, value) in fields {
            if *kind == INT32 {
                while data.len() % 4 != 0 {
                    data.push(0);
                }
            }
            for word in [*tag, *kind, data.len() as u32, 1] {
                index.extend_from_slice(&word.to_be_bytes());
            }
            data.extend_from_slice(value);
        }
        let mut blob = Vec::new();
        blob.extend_from_slice(&(fields.len() as u32).to_be_bytes());
        blob.extend_from_slice(&(data.len() as u32).to_be_bytes());
        blob.extend(index);
        blob.extend(data);
        blob
    }

    fn text(value: &str) -> Vec<u8> {
        let mut bytes = value.as_bytes().to_vec();
        bytes.push(0);
        bytes
    }

    fn openssl() -> Vec<(u32, u32, Vec<u8>)> {
        vec![
            (1000, STRING, text("openssl")),
            (1001, STRING, text("3.2.2")),
            (1002, STRING, text("1.fc44")),
            (1003, INT32, 1u32.to_be_bytes().to_vec()),
            (1011, STRING, text("Fedora Project")),
            (1022, STRING, text("x86_64")),
        ]
    }

    #[test]
    fn rpm_headers_are_parsed_with_every_field() {
        let package = rpm::parse_header(&header(&openssl())).unwrap();
        assert_eq!(package.manager, PackageManager::Rpm);
        assert_eq!(
            (package.name.as_str(), package.version.as_str()),
            ("openssl", "3.2.2")
        );
        assert_eq!(package.release.as_deref(), Some("1.fc44"));
        assert_eq!(package.epoch, Some(1));
        assert_eq!(package.vendor.as_deref(), Some("Fedora Project"));
        assert_eq!(package.arch.as_deref(), Some("x86_64"));

        let minimal = header(&openssl()[..2]);
        let package = rpm::parse_header(&minimal).unwrap();
        assert_eq!(
            (package.release, package.epoch, package.vendor),
            (None, None, None)
        );
    }

    #[test]
    fn malformed_rpm_headers_are_refused() {
        let good = header(&openssl());
        let mut no_version = openssl();
        no_version.remove(1);
        let mut wrong_type = openssl();
        wrong_type[0].1 = INT32;
        let mut unterminated = openssl();
        let last = unterminated.len() - 1;
        unterminated[last].2.pop();
        let mut out_of_bounds = good.clone();
        out_of_bounds[8 + 8..8 + 12].copy_from_slice(&u32::MAX.to_be_bytes());
        let mut bad_epoch = openssl();
        bad_epoch[3].1 = STRING;
        let mut huge_index = good.clone();
        huge_index[..4].copy_from_slice(&0x0010_0000u32.to_be_bytes());
        for (name, blob) in [
            ("empty", Vec::new()),
            ("truncated", good[..good.len() - 1].to_vec()),
            ("trailing", [good.clone(), vec![0]].concat()),
            ("no version", header(&no_version)),
            ("wrong type", header(&wrong_type)),
            ("unterminated", header(&unterminated)),
            ("bad epoch", header(&bad_epoch)),
            ("out of bounds", out_of_bounds),
            ("huge index", huge_index),
        ] {
            assert_eq!(rpm::parse_header(&blob), None, "{name}");
        }
    }

    fn database(test: &str, blobs: &[Vec<u8>]) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "openvibes-rpmdb-{}-{test}.sqlite",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute_batch("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL)")
            .unwrap();
        for blob in blobs {
            connection
                .execute("INSERT INTO Packages (blob) VALUES (?1)", [blob])
                .unwrap();
        }
        path
    }

    fn later() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    #[test]
    fn rpm_database_is_read_without_signing_keys() {
        let key = header(&[
            (1000, STRING, text("gpg-pubkey")),
            (1001, STRING, text("abc")),
        ]);
        let path = database("good", &[header(&openssl()), key]);
        let packages = rpm::read(&path, later()).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "openssl");
    }

    #[test]
    fn one_malformed_rpm_header_fails_the_whole_read() {
        let path = database("bad", &[header(&openssl()), vec![1, 2, 3]]);
        assert_eq!(
            rpm::read(&path, later()).unwrap_err().code,
            CollectorErrorCode::InvalidData
        );
        let missing = Path::new("/nonexistent/rpmdb.sqlite");
        assert!(rpm::read(missing, later()).is_err());
    }

    #[test]
    fn dpkg_status_keeps_installed_packages_and_splits_versions() {
        let status = "\
Package: openssh-server
Status: install ok installed
Architecture: amd64
Description: secure shell (SSH) server
 continuation line: not a field
Version: 1:9.6p1-3ubuntu13.5

Package: removed-tool
Status: deinstall ok config-files
Version: 2.0-1

Package: libfoo
Status: install ok installed
Version: 1.2.3

Package: no-version
Status: install ok installed
";
        let packages = parse_status(status);
        assert_eq!(packages.len(), 2);
        let ssh = &packages[0];
        assert_eq!(
            (
                ssh.name.as_str(),
                ssh.version.as_str(),
                ssh.release.as_deref(),
                ssh.epoch
            ),
            ("openssh-server", "9.6p1", Some("3ubuntu13.5"), Some(1))
        );
        assert_eq!(ssh.arch.as_deref(), Some("amd64"));
        assert_eq!(ssh.manager, PackageManager::Dpkg);
        assert_eq!(
            (packages[1].version.as_str(), packages[1].release.as_deref()),
            ("1.2.3", None)
        );
    }

    /// Runs on every Linux CI host: Fedora-like hosts read RPM, Ubuntu dpkg.
    #[test]
    fn the_live_host_reports_packages() {
        let packages = collect_packages(later(), ResourceLimits::V1).unwrap();
        assert!(!packages.is_empty());
        assert!(packages.iter().all(|package| package.name != "gpg-pubkey"));
    }

    #[test]
    fn a_passed_deadline_emits_nothing() {
        let Some(past) = Instant::now().checked_sub(Duration::from_secs(1)) else {
            return;
        };
        let error = collect_packages(past, ResourceLimits::V1).unwrap_err();
        assert_eq!(error.code, CollectorErrorCode::TimedOut);
    }
}
