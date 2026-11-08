//! What the Windows installer (MSI) runs as SYSTEM, from its custom actions:
//!
//! - `windows-setup <data dir> <platform url> <CA file> <token>` writes
//!   `agent.toml` (and copies the CA, writes the token) from the install
//!   properties `PLATFORM_URL`, `PLATFORM_CA` and `ENROLLMENT_TOKEN`; an
//!   empty argument is a property that was not given. Without a URL it keeps
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

pub(crate) fn setup(dir: &Path, url: &str, ca: &str, token: &str) -> Result<(), String> {
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
        if !ca.is_empty() || !token.is_empty() {
            return Err("PLATFORM_CA and ENROLLMENT_TOKEN need PLATFORM_URL".into());
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
        if ca.is_empty() {
            return Err("PLATFORM_URL needs PLATFORM_CA, the platform's root.crt".into());
        }
        let pem = fs::read(ca).map_err(|error| format!("cannot read PLATFORM_CA {ca}: {error}"))?;
        if pem.len() > CA_BYTES || !pem.starts_with(b"-----BEGIN CERTIFICATE-----") {
            return Err(format!("PLATFORM_CA {ca} is not a PEM certificate"));
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
        setup(&dir, "", "", "").unwrap();
        fs::write(
            dir.join(CONFIG),
            fs::read_to_string(dir.join(CONFIG)).unwrap() + "# edited\n",
        )
        .unwrap();
        setup(&dir, "", "", "").unwrap();
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
            "token-123",
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
    fn refuses_bad_input() {
        let (dir, _gone) = data("refuses");
        assert!(setup(&dir, "", "", "token-123").is_err());
        assert!(setup(&dir, "https://platform.example", "", "").is_err());
        let ca = dir.parent().unwrap().join("root.crt");
        fs::write(&ca, "-----BEGIN CERTIFICATE-----\n").unwrap();
        let ca = ca.to_string_lossy();
        assert!(setup(&dir, "https://platform.example\n", &ca, "").is_err());
        assert!(setup(&dir, "https://platform.example", &ca, "to\nken").is_err());
        assert!(setup(&dir, "http://platform.example", &ca, "").is_err());
        let not_pem = dir.parent().unwrap().join("not.pem");
        fs::write(&not_pem, "hello").unwrap();
        assert!(
            setup(
                &dir,
                "https://platform.example",
                &not_pem.to_string_lossy(),
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
