//! What the Windows installer (MSI) runs as SYSTEM, from its custom actions:
//!
//! - `windows-setup <data dir> <platform url> <CA file> <CA SHA-256> <token>
//!   <MSI file>` writes `agent.toml` (and copies the CA, writes the token)
//!   from the install properties `PLATFORM_URL`, `PLATFORM_CA`,
//!   `PLATFORM_CA_SHA256` and `ENROLLMENT_TOKEN`; an empty argument is a
//!   property that was not given. With `PLATFORM_CA_SHA256` the CA must
//!   match it (the SHA-256 of its DER, as the Linux install line's
//!   `--ca-sha256`), and without `PLATFORM_CA` the CA is then
//!   `openvibes-platform-ca.crt` beside the MSI (`OriginalDatabase`), so the
//!   console's install line needs no path (#136). A file beside the MSI is
//!   never used without the fingerprint: anyone who can write to that folder
//!   could have put it there. Without a URL it keeps
//!   an existing `agent.toml` (upgrade, repair) or writes a local-only one.
//!   The result is checked with `load_config`, so a bad value fails the
//!   install, which Windows Installer then rolls back.
//! - `windows-remove-data <data dir>` deletes the data directory (config,
//!   token, identity, queue) on a real uninstall, never on an upgrade.
//!
//! The files inherit the data directory's SYSTEM/Administrators/service ACL,
//! which the MSI sets (`MsiLockPermissionsEx`).

use std::{fs, path::Path};

use openvibes_agent::load_config;
use openvibes_core::EnrollmentToken;

const CONFIG: &str = "agent.toml";
const CA: &str = "platform-ca.crt";
const TOKEN: &str = "token";
/// The CA's file name beside the MSI, as the console's download names it.
const CA_BESIDE_MSI: &str = "openvibes-platform-ca.crt";

pub(crate) fn setup(
    dir: &Path,
    url: &str,
    ca: &str,
    ca_sha256: &str,
    token: &str,
    msi: &str,
) -> Result<(), String> {
    data_dir(dir)?;
    let config = dir.join(CONFIG);
    let mut text = format!(
        "# Written by the installer; reinstall with new PLATFORM_URL,\n\
         # PLATFORM_CA and ENROLLMENT_TOKEN to change it.\n\
         state_dir = {}\n\
         collectors = [\"processes\", \"packages\"]\n",
        quoted(&dir.join("state").to_string_lossy())?
    );
    if url.is_empty() {
        if !ca.is_empty() || !ca_sha256.is_empty() || !token.is_empty() {
            return Err(
                "PLATFORM_CA, PLATFORM_CA_SHA256 and ENROLLMENT_TOKEN need PLATFORM_URL".into(),
            );
        }
        if config.exists() {
            return check(&config);
        }
    }
    // Everything is checked before anything is written: a failed install is
    // rolled back by Windows Installer, which does not know these files.
    let mut files = Vec::new();
    if !url.is_empty() {
        if !url.starts_with("https://") {
            return Err("PLATFORM_URL must start with https://".into());
        }
        let pinned = if ca_sha256.is_empty() {
            None
        } else {
            Some(fingerprint_hex(ca_sha256)?)
        };
        let beside = Path::new(msi)
            .parent()
            .map(|folder| folder.join(CA_BESIDE_MSI));
        let ca = match beside {
            Some(path) if ca.is_empty() && pinned.is_some() && path.is_file() => {
                path.to_string_lossy().into_owned()
            }
            _ if ca.is_empty() => {
                return Err(format!(
                    "PLATFORM_URL needs PLATFORM_CA (the platform's root.crt), or \
                     PLATFORM_CA_SHA256 with {CA_BESIDE_MSI} beside the MSI"
                ));
            }
            _ => ca.to_owned(),
        };
        let ca = ca.as_str();
        let pem = fs::read(ca).map_err(|error| format!("cannot read PLATFORM_CA {ca}: {error}"))?;
        if pem.len() > CA_BYTES || !pem.starts_with(b"-----BEGIN CERTIFICATE-----") {
            return Err(format!("PLATFORM_CA {ca} is not a PEM certificate"));
        }
        if let Some(want) = pinned
            && der_sha256(&pem).as_deref() != Some(want.as_str())
        {
            return Err(format!(
                "PLATFORM_CA {ca} does not match PLATFORM_CA_SHA256 (not this platform's CA)"
            ));
        }
        text.push_str(&format!(
            "platform_url = {}\nplatform_ca_file = {}\nenrollment_token_file = {}\n",
            quoted(url)?,
            quoted(&dir.join(CA).to_string_lossy())?,
            quoted(&dir.join(TOKEN).to_string_lossy())?,
        ));
        files.push((dir.join(CA), pem));
        if !token.is_empty() {
            // Never echoed: it is a secret.
            if token.chars().any(char::is_control) || EnrollmentToken::new(token.trim()).is_err() {
                return Err("ENROLLMENT_TOKEN is not a valid token".into());
            }
            files.push((dir.join(TOKEN), token.trim().as_bytes().to_vec()));
        }
    }
    files.push((config.clone(), text.into_bytes()));
    let written = files.iter().try_for_each(|(path, bytes)| {
        fs::write(path, bytes).map_err(|error| format!("cannot write {}: {error}", path.display()))
    });
    let result = written.and_then(|()| check(&config));
    if result.is_err() {
        for (path, _) in &files {
            let _ = fs::remove_file(path);
        }
    }
    result
}

/// `AB:CD:…` or `abcd…`: 64 lower-case hex digits, or an error.
fn fingerprint_hex(value: &str) -> Result<String, String> {
    let hex: String = value
        .chars()
        .filter(|c| *c != ':')
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(hex)
    } else {
        Err("PLATFORM_CA_SHA256 is not a SHA-256 fingerprint".into())
    }
}

/// The SHA-256 (lower-case hex) of the one certificate in `pem`, as
/// `install.sh` computes it; `None` unless it holds exactly one.
fn der_sha256(pem: &[u8]) -> Option<String> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use sha2::{Digest, Sha256};
    let text = std::str::from_utf8(pem).ok()?;
    if text.matches("-----BEGIN ").count() != 1 {
        return None;
    }
    let body: String = text
        .split("-----BEGIN CERTIFICATE-----")
        .nth(1)?
        .split("-----END CERTIFICATE-----")
        .next()?
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let der = STANDARD.decode(body).ok()?;
    Some(
        Sha256::digest(der)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    )
}

/// The platform's root certificate is a few kB; more is the wrong file.
const CA_BYTES: usize = 64 * 1024;

pub(crate) fn remove_data(dir: &Path) -> Result<(), String> {
    data_dir(dir)?;
    match fs::remove_dir_all(dir) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("cannot remove {}: {error}", dir.display())),
    }
    // The `OpenVIBES` folder too, unless something else of ours is in it.
    if let Some(parent) = dir.parent() {
        let _ = fs::remove_dir(parent);
    }
    Ok(())
}

/// Only ever `...\OpenVIBES\Agent`: a wrong property must never make the
/// installer write or delete somewhere else.
fn data_dir(dir: &Path) -> Result<(), String> {
    let named = |path: Option<&Path>, name: &str| {
        path.and_then(Path::file_name)
            .is_some_and(|found| found.eq_ignore_ascii_case(name))
    };
    if dir.is_absolute() && named(Some(dir), "Agent") && named(dir.parent(), "OpenVIBES") {
        Ok(())
    } else {
        Err(format!("not the agent's data directory: {}", dir.display()))
    }
}

fn check(config: &Path) -> Result<(), String> {
    load_config(config)
        .map(drop)
        .map_err(|error| format!("{} is not valid: {error}", config.display()))
}

/// A TOML basic string; control characters are refused, not escaped.
fn quoted(value: &str) -> Result<String, String> {
    if value.chars().any(char::is_control) {
        return Err("a setting contains a control character".into());
    }
    Ok(format!(
        "\"{}\"",
        value.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(test: &str) -> (std::path::PathBuf, impl Drop) {
        struct Gone(std::path::PathBuf);
        impl Drop for Gone {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let root = std::env::temp_dir().join(format!("ov-winsetup-{test}-{}", std::process::id()));
        let dir = root.join("OpenVIBES").join("Agent");
        fs::create_dir_all(&dir).unwrap();
        (dir, Gone(root))
    }

    #[test]
    fn writes_keeps_and_removes() {
        let (dir, _gone) = data("writes");
        // Local-only, then kept as it is by an upgrade without properties.
        setup(&dir, "", "", "", "", "").unwrap();
        fs::write(
            dir.join(CONFIG),
            fs::read_to_string(dir.join(CONFIG)).unwrap() + "# edited\n",
        )
        .unwrap();
        setup(&dir, "", "", "", "", "").unwrap();
        assert!(
            fs::read_to_string(dir.join(CONFIG))
                .unwrap()
                .ends_with("# edited\n")
        );

        // A platform: CA copied, token written, and the config loads.
        let ca = dir.parent().unwrap().parent().unwrap().join("root.crt");
        fs::write(&ca, "-----BEGIN CERTIFICATE-----\n").unwrap();
        setup(
            &dir,
            "https://platform.example",
            &ca.to_string_lossy(),
            "",
            "token-123",
            "",
        )
        .unwrap();
        assert!(dir.join(CA).exists() && dir.join(TOKEN).exists());
        let config = load_config(&dir.join(CONFIG)).unwrap();
        assert!(config.transport.is_some());

        remove_data(&dir).unwrap();
        assert!(!dir.exists() && !dir.parent().unwrap().exists());
        remove_data(&dir).unwrap();
    }

    #[test]
    fn takes_the_ca_from_beside_the_msi_only_with_its_fingerprint() {
        // #136: no PLATFORM_CA, the console's download beside the MSI, and
        // only with PLATFORM_CA_SHA256: anyone who can write to the folder
        // could have put a CA there.
        let (dir, _gone) = data("beside");
        let folder = dir
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("Downloads folder");
        fs::create_dir_all(&folder).unwrap();
        let msi = folder.join("openvibes-agent-0.3.0-x64.msi");
        let msi = msi.to_string_lossy();
        let url = "https://platform.example";
        // The SHA-256 of the DER bytes 00 00 00, as the console prints it.
        let fp = "70:9E:80:C8:84:87:A2:41:1E:1E:E4:DF:B9:F2:2A:86:14:92:D2:0C:47:65:15:0C:0C:79:4A:BD:70:F8:14:7C";
        assert!(
            setup(&dir, url, "", fp, "token-123", &msi).is_err(),
            "no CA beside it"
        );
        fs::write(
            folder.join(CA_BESIDE_MSI),
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        assert!(
            setup(&dir, url, "", "", "token-123", &msi).is_err(),
            "never beside the MSI without the fingerprint"
        );
        let other = format!("{}00", &fp[..fp.len() - 2]);
        assert!(
            setup(&dir, url, "", &other, "token-123", &msi).is_err(),
            "another CA"
        );
        assert!(setup(&dir, url, "", "not-a-fingerprint", "token-123", &msi).is_err());
        setup(
            &dir,
            url,
            "",
            &fp.to_lowercase().replace(':', ""),
            "token-123",
            &msi,
        )
        .unwrap();
        setup(&dir, url, "", fp, "token-123", &msi).unwrap();
        assert!(dir.join(CA).exists());
    }

    #[test]
    fn refuses_bad_input() {
        let (dir, _gone) = data("refuses");
        assert!(setup(&dir, "", "", "", "token-123", "").is_err());
        assert!(setup(&dir, "https://platform.example", "", "", "", "").is_err());
        let ca = dir.parent().unwrap().join("root.crt");
        fs::write(&ca, "-----BEGIN CERTIFICATE-----\n").unwrap();
        let ca = ca.to_string_lossy();
        assert!(setup(&dir, "https://platform.example\n", &ca, "", "", "").is_err());
        assert!(setup(&dir, "https://platform.example", &ca, "", "to\nken", "").is_err());
        assert!(setup(&dir, "http://platform.example", &ca, "", "", "").is_err());
        let not_pem = dir.parent().unwrap().join("not.pem");
        fs::write(&not_pem, "hello").unwrap();
        assert!(
            setup(
                &dir,
                "https://platform.example",
                &not_pem.to_string_lossy(),
                "",
                "",
                ""
            )
            .is_err()
        );
        // Nothing was written by any of them.
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
        assert!(remove_data(&dir.parent().unwrap().join("Other")).is_err());
        assert!(remove_data(Path::new("relative/OpenVIBES/Agent")).is_err());
        assert!(dir.exists());
    }
}
