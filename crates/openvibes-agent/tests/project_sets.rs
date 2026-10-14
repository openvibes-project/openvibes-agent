//! The project's own rule sets (protocol P20): which ones an agent adds,
//! a quiet 404 for an added set, and 410 for an assignable one.

use std::{fs, path::PathBuf};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use openvibes_agent::{AgentConfig, RuleSetSource, load_config};

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
    load_config(&path).unwrap()
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
    assert_eq!(
        listed(&load("platform", PLATFORM, &baseline)),
        only_baseline,
        "no distribution_url: nothing added"
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

    // Nothing configured: Windows and macOS get only the baseline.
    let mut expected = vec![("baseline".to_owned(), fixed)];
    if cfg!(target_os = "linux") {
        expected.extend(linux);
    }
    assert_eq!(listed(&load("online-empty", ONLINE, "")), expected);
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
mod scans {
    use std::{
        fs,
        sync::{Arc, mpsc},
    };

    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::Signer;
    use openvibes_agent::{AgentError, ScanReport, Service, load_config};
    use openvibes_core::{
        Confidence, EnrollmentResponse, PayloadEncoding, ResourceLimits, Rule, RuleBundleRequest,
        RuleSet, RuleSetState, SchemaVersion, Severity, SignedRuleEnvelope,
    };
    use openvibes_rules::{TrustedRuleKey, signing_preimage};
    use openvibes_testkit::{Handler, Pki, Reply, Seen, json, serve, status};
    use openvibes_transport::TransportError;
    use sha2::{Digest, Sha256};

    use super::{dir, organization_key, support::id, trusted_keys};

    const NOW: i64 = 1_800_000_000_000;
    const HOUR: i64 = 3_600_000;
    const L1: &str = "hardening-linux-l1";

    /// A `set` bundle signed with the test key; its one rule always matches.
    fn bundle(set: &str, version: u64) -> Vec<u8> {
        let payload = serde_json::to_string(&RuleSet {
            schema_version: SchemaVersion::V1,
            rules: vec![Rule {
                id: id("host.has.processes"),
                version: 1,
                title: "Processes are running".into(),
                severity: Severity::Info,
                confidence: Confidence::new(100).unwrap(),
                expression: "facts['process.count'] >= 1".into(),
                finding_message: "The host runs processes".into(),
                kind: openvibes_core::RuleKind::Snapshot,
                programs: None,
                attack: None,
            }],
        })
        .unwrap();
        let mut envelope = SignedRuleEnvelope {
            schema_version: SchemaVersion::V1,
            rule_set_id: id(set),
            rule_set_version: version,
            issuer_key_id: id("org.rules"),
            created_at_unix_ms: NOW - HOUR,
            expires_at_unix_ms: NOW + 100 * HOUR,
            payload_encoding: PayloadEncoding::Json,
            payload_sha256_hex: Sha256::digest(payload.as_bytes())
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            payload,
            signature_base64url: String::new(),
        };
        let preimage = signing_preimage(&envelope, ResourceLimits::V1).unwrap();
        envelope.signature_base64url =
            URL_SAFE_NO_PAD.encode(organization_key().sign(&preimage).to_bytes());
        serde_json::to_vec(&envelope).unwrap()
    }

    fn raw(status: u16, body: Vec<u8>) -> Handler {
        Box::new(move |_: &Seen| Reply {
            status,
            headers: "",
            body,
            stall: false,
        })
    }

    fn not_found() -> Handler {
        raw(404, Vec::new())
    }

    fn gone() -> Handler {
        raw(410, Vec::new())
    }

    fn unchanged() -> Handler {
        raw(204, Vec::new())
    }

    /// Per scan, in request order: baseline (configured), then the added
    /// baseline-alarms, hardening-linux-l1, hardening-linux-l2.
    fn scans(answers: Vec<[Handler; 4]>) -> Vec<Handler> {
        answers.into_iter().flatten().collect()
    }

    /// Enrollment, then one heartbeat.
    fn ingest(pki: &Arc<Pki>) -> Vec<Handler> {
        let issuer = pki.clone();
        vec![
            Box::new(move |seen: &Seen| {
                let request: serde_json::Value = serde_json::from_slice(&seen.body).unwrap();
                json(&EnrollmentResponse {
                    schema_version: SchemaVersion::V1,
                    agent_id: id("agent.1"),
                    certificate_chain_pem: vec![
                        issuer.issue_client(request["csr_pem"].as_str().unwrap()),
                    ],
                    expires_at_unix_ms: NOW + 1_000 * HOUR,
                })
            }),
            Box::new(|_: &Seen| status(204)),
        ]
    }

    /// An enrolled agent: `baseline` configured with the test key, the
    /// project sets added. The project key's private half is offline, so
    /// L1 also trusts the test key, under its own issuer id.
    fn enrolled(test: &str, pki: &Arc<Pki>, distribution_url: &str) -> Service {
        let dir = dir(test);
        fs::write(dir.join("ca.pem"), pki.roots_pem()).unwrap();
        fs::write(dir.join("token"), "one-time\n").unwrap();
        fs::set_permissions(
            dir.join("token"),
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();
        let (ingest_url, _) = serve(pki.server_config(false, false), ingest(pki));
        let path = dir.join("agent.toml");
        fs::write(
            &path,
            format!(
                "platform_url = {ingest_url:?}\nplatform_ca_file = {:?}\nstate_dir = {:?}\n\
                 enrollment_token_file = {:?}\ndistribution_url = {distribution_url:?}\n\
                 [[rule_sets]]\nid = \"baseline\"\n{}\n",
                dir.join("ca.pem"),
                dir.join("state"),
                dir.join("token"),
                trusted_keys(),
            ),
        )
        .unwrap();
        let mut config = load_config(&path).unwrap();
        let public = organization_key().verifying_key().to_bytes();
        config
            .scan
            .trusted_keys
            .push(TrustedRuleKey::new(id(L1), id("org.rules"), public).unwrap());
        let mut service = Service::open(config).unwrap();
        service.tick(NOW).unwrap();
        service
    }

    /// Each fetch: the set asked for and the version the agent held.
    fn asked(seen: &mpsc::Receiver<Seen>) -> Vec<(String, Option<u64>)> {
        seen.try_iter()
            .map(|seen| {
                let request: RuleBundleRequest = serde_json::from_slice(&seen.body).unwrap();
                (
                    request.rule_set_id.as_str().to_owned(),
                    request.current_version,
                )
            })
            .collect()
    }

    fn versions(asked: &[(String, Option<u64>)], set: &str) -> Vec<Option<u64>> {
        asked
            .iter()
            .filter(|(name, _)| name == set)
            .map(|(_, version)| *version)
            .collect()
    }

    /// A set's health: (version, state); `None` when not listed.
    fn health(report: &ScanReport, set: &str) -> Option<(Option<u64>, Option<RuleSetState>)> {
        report
            .rule_sets
            .iter()
            .find(|health| health.id.as_str() == set)
            .map(|health| (health.version, health.state))
    }

    #[test]
    fn an_older_platform_without_the_project_sets_sees_no_change() {
        let pki = Arc::new(Pki::new());
        let (url, seen) = serve(
            pki.server_config(true, false),
            scans(vec![[
                raw(200, bundle("baseline", 1)),
                not_found(),
                not_found(),
                not_found(),
            ]]),
        );
        let mut service = enrolled("older-platform", &pki, &url);
        let report = service.scan_if_due(NOW).unwrap().unwrap();
        assert_eq!(report.matched, 1);
        assert!(
            report.rule_set_errors.is_empty(),
            "{:?}",
            report.rule_set_errors
        );
        assert_eq!(
            report.rules_retry_in_s, None,
            "nothing to fetch again early"
        );
        let listed: Vec<&str> = report.rule_sets.iter().map(|set| set.id.as_str()).collect();
        assert_eq!(listed, ["baseline"], "a set not offered is not in health");
        let sets: Vec<String> = asked(&seen).into_iter().map(|(set, _)| set).collect();
        assert_eq!(
            sets,
            ["baseline", "baseline-alarms", L1, "hardening-linux-l2"]
        );
    }

    #[test]
    fn an_unassigned_set_stops_and_comes_back() {
        let pki = Arc::new(Pki::new());
        let (url, seen) = serve(
            pki.server_config(true, false),
            scans(vec![
                [
                    raw(200, bundle("baseline", 1)),
                    not_found(),
                    raw(200, bundle(L1, 1)),
                    not_found(),
                ],
                [unchanged(), not_found(), gone(), not_found()],
                [
                    unchanged(),
                    not_found(),
                    raw(200, bundle(L1, 1)),
                    not_found(),
                ],
            ]),
        );
        let mut service = enrolled("not-assigned", &pki, &url);
        let first = service.scan_if_due(NOW).unwrap().unwrap();
        assert_eq!(first.matched, 2, "baseline and L1");
        assert_eq!(health(&first, L1), Some((Some(1), None)));

        let off = service.scan_if_due(NOW + HOUR).unwrap().unwrap();
        assert_eq!(off.matched, 1, "L1 no longer runs");
        assert!(off.rule_set_errors.is_empty(), "{:?}", off.rule_set_errors);
        assert_eq!(
            health(&off, L1),
            Some((None, Some(RuleSetState::NotAssigned)))
        );

        let on = service.scan_if_due(NOW + 2 * HOUR).unwrap().unwrap();
        assert_eq!(on.matched, 2, "switched back on: the next scan runs it");
        assert_eq!(health(&on, L1), Some((Some(1), None)));
        assert_eq!(
            versions(&asked(&seen), L1),
            [None, Some(1), None],
            "withdrawn: asked without current_version, so the same v1 comes back as 200"
        );
    }

    #[test]
    fn a_reassigned_set_keeps_its_rollback_floor() {
        let pki = Arc::new(Pki::new());
        let (url, _) = serve(
            pki.server_config(true, false),
            scans(vec![
                [
                    raw(200, bundle("baseline", 1)),
                    not_found(),
                    raw(200, bundle(L1, 2)),
                    not_found(),
                ],
                [unchanged(), not_found(), gone(), not_found()],
                [unchanged(), not_found(), raw(503, Vec::new()), not_found()],
                [
                    unchanged(),
                    not_found(),
                    raw(200, bundle(L1, 1)),
                    not_found(),
                ],
                [
                    unchanged(),
                    not_found(),
                    raw(200, bundle(L1, 2)),
                    not_found(),
                ],
            ]),
        );
        let mut service = enrolled("reassigned-floor", &pki, &url);
        assert_eq!(service.scan_if_due(NOW).unwrap().unwrap().matched, 2);
        assert_eq!(service.scan_if_due(NOW + HOUR).unwrap().unwrap().matched, 1);

        // Platform unreachable: a withdrawn set never falls back to its
        // stored bundle.
        let outage = service.scan_if_due(NOW + 2 * HOUR).unwrap().unwrap();
        assert_eq!(outage.matched, 1, "L1 stays off");
        assert_eq!(health(&outage, L1), Some((None, None)));

        // Switched on again with an older bundle: refused against the kept
        // floor, and still nothing runs.
        let older = service.scan_if_due(NOW + 3 * HOUR).unwrap().unwrap();
        assert_eq!(older.matched, 1, "a switch-off/on cannot roll L1 back");
        assert!(
            older.rule_set_errors.contains(&(
                id(L1),
                AgentError::Rules(openvibes_rules::LoadError::Rollback)
            )),
            "{:?}",
            older.rule_set_errors
        );

        // The version it had (or newer) is accepted and runs again.
        let back = service.scan_if_due(NOW + 4 * HOUR).unwrap().unwrap();
        assert_eq!(back.matched, 2);
        assert_eq!(health(&back, L1), Some((Some(2), None)));
    }

    #[test]
    fn a_410_for_a_set_that_is_not_assignable_is_refused() {
        let pki = Arc::new(Pki::new());
        let (url, seen) = serve(
            pki.server_config(true, false),
            scans(vec![
                [
                    raw(200, bundle("baseline", 1)),
                    not_found(),
                    not_found(),
                    not_found(),
                ],
                [gone(), gone(), not_found(), not_found()],
                [unchanged(), not_found(), not_found(), not_found()],
            ]),
        );
        let mut service = enrolled("not-assignable", &pki, &url);
        service.scan_if_due(NOW).unwrap().unwrap();

        let refused = service.scan_if_due(NOW + HOUR).unwrap().unwrap();
        assert_eq!(refused.matched, 1, "the stored baseline keeps running");
        assert_eq!(
            refused.rule_set_errors,
            [
                (
                    id("baseline"),
                    AgentError::Transport(TransportError::Rejected)
                ),
                (
                    id("baseline-alarms"),
                    AgentError::Transport(TransportError::Rejected)
                ),
            ]
        );
        assert_eq!(health(&refused, "baseline"), Some((Some(1), None)));

        service.scan_if_due(NOW + 2 * HOUR).unwrap().unwrap();
        assert_eq!(
            versions(&asked(&seen), "baseline"),
            [None, Some(1), Some(1)],
            "its bundle and floor were kept"
        );
    }
}
