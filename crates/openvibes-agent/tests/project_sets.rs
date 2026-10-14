//! The project's own rule sets (protocol P20): which ones an agent adds,
//! a quiet 404 for an added set, and 410 for an assignable one.

use std::{fs, path::PathBuf};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use openvibes_agent::{AgentConfig, RuleSetSource, load_config};

#[cfg(target_os = "linux")]
mod support;

// Test-only seed. No signing credentials are provisioned to the scanner.
fn organization_key() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

fn trusted_keys() -> String {
    let public = URL_SAFE_NO_PAD.encode(organization_key().verifying_key().to_bytes());
    format!("trusted_keys = [{{ issuer_key_id = \"org.rules\", public_key = \"{public}\" }}]")
}

fn dir(test: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("agent-project-sets")
        .join(test);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Loads `top` (top-level keys; `CA` names a CA file) and `sets`
/// (`[[rule_sets]]` tables; `BUNDLE` names a bundle file).
fn load(test: &str, top: &str, sets: &str) -> AgentConfig {
    try_load(test, top, sets).unwrap()
}

fn try_load(test: &str, top: &str, sets: &str) -> Result<AgentConfig, openvibes_agent::AgentError> {
    let dir = dir(test);
    fs::write(dir.join("ca.pem"), "read, not parsed, at load\n").unwrap();
    let top = top.replace("CA", &format!("{:?}", dir.join("ca.pem")));
    let sets = sets.replace("BUNDLE", &format!("{:?}", dir.join("baseline.json")));
    let path = dir.join("agent.toml");
    fs::write(
        &path,
        format!("state_dir = {:?}\n{top}\n{sets}", dir.join("state")),
    )
    .unwrap();
    load_config(&path)
}

fn listed(config: &AgentConfig) -> Vec<(String, RuleSetSource)> {
    config
        .scan
        .rule_sets
        .iter()
        .map(|set| (set.id.as_str().to_owned(), set.source))
        .collect()
}

const PLATFORM: &str = "platform_url = \"https://p.example\"\nplatform_ca_file = CA";
const ONLINE: &str = "platform_url = \"https://p.example\"\nplatform_ca_file = CA\n\
                      distribution_url = \"https://p.example\"";

#[test]
fn project_sets_are_added_only_with_a_distribution_service() {
    let baseline = format!(
        "[[rule_sets]]\nid = \"baseline\"\nbundle_file = BUNDLE\n{}\n",
        trusted_keys()
    );
    let configured = RuleSetSource::Configured;
    let fixed = RuleSetSource::Project { assignable: false };
    let switched = RuleSetSource::Project { assignable: true };
    let only_baseline = vec![("baseline".to_owned(), configured)];
    assert_eq!(
        listed(&load("local", "", &baseline)),
        only_baseline,
        "local-only"
    );

    let linux = [
        ("baseline-alarms".to_owned(), fixed),
        ("hardening-linux-l1".to_owned(), switched),
        ("hardening-linux-l2".to_owned(), switched),
    ];
    let mut expected = only_baseline.clone();
    if cfg!(target_os = "linux") {
        expected.extend(linux.clone());
    }
    assert_eq!(listed(&load("online", ONLINE, &baseline)), expected);
    assert_eq!(
        listed(&load("platform", PLATFORM, &baseline)),
        expected,
        "no distribution_url: the derived one adds them too"
    );

    // Nothing configured: Windows and macOS get only the baseline.
    let mut expected = vec![("baseline".to_owned(), fixed)];
    if cfg!(target_os = "linux") {
        expected.extend(linux);
    }
    assert_eq!(listed(&load("online-empty", ONLINE, "")), expected);
}

/// The distribution URL `platform_url` gives, and whether it was derived.
fn distribution(test: &str, top: &str) -> Option<(String, bool)> {
    let config = load(test, top, "");
    config
        .distribution
        .map(|distribution| (distribution.base_url, config.distribution_derived))
}

#[test]
fn without_distribution_url_the_platform_host_on_18424_is_used() {
    let derived = |url: &str| Some((url.to_owned(), true));
    let platform = |url: &str| format!("platform_url = \"{url}\"\nplatform_ca_file = CA");
    assert_eq!(
        distribution("derived", PLATFORM),
        derived("https://p.example:18424")
    );
    assert_eq!(
        distribution("derived-port", &platform("https://p.example:9443")),
        derived("https://p.example:18424"),
        "the platform's own port is replaced"
    );
    assert_eq!(
        distribution("derived-v6", &platform("https://[2001:db8::1]")),
        derived("https://[2001:db8::1]:18424")
    );
    assert_eq!(
        distribution("derived-v6-port", &platform("https://[2001:db8::1]:18423")),
        derived("https://[2001:db8::1]:18424")
    );
    assert_eq!(
        distribution("explicit", ONLINE),
        Some(("https://p.example".to_owned(), false)),
        "an explicit distribution_url wins"
    );
    assert_eq!(distribution("no-platform", ""), None, "local-only");
}

#[test]
fn a_configured_set_without_a_file_still_needs_an_explicit_distribution_url() {
    let fetched = format!("[[rule_sets]]\nid = \"site.web\"\n{}\n", trusted_keys());
    assert!(try_load("configured-derived", PLATFORM, &fetched).is_err());
    assert!(try_load("configured-explicit", ONLINE, &fetched).is_ok());
}

#[test]
fn a_configured_project_set_keeps_its_own_keys_and_restricted() {
    let l1 = format!(
        "[[rule_sets]]\nid = \"hardening-linux-l1\"\n{}\nrestricted = false\n",
        trusted_keys()
    );
    let config = load("configured-l1", ONLINE, &l1);
    let l1: Vec<_> = config
        .scan
        .rule_sets
        .iter()
        .filter(|set| set.id.as_str() == "hardening-linux-l1")
        .collect();
    assert_eq!(l1.len(), 1, "never merged with the project's entry");
    assert_eq!(
        (l1[0].source, l1[0].restricted),
        (RuleSetSource::Configured, false)
    );
}

/// Scans against a mock distribution service. Linux only: elsewhere the
/// only project set is the baseline, configured here.
#[cfg(target_os = "linux")]
#[path = "project_sets/scans.rs"]
mod scans;
