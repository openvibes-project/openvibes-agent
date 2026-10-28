use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, mpsc},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::Signer;
use openvibes_agent::{AgentError, RuleSetSource, ScanReport, Service, load_config};
use openvibes_core::{
    BundleRefusal, Confidence, EnrollmentResponse, PayloadEncoding, ResourceLimits, Rule,
    RuleBundleRequest, RuleSet, RuleSetState, SchemaVersion, Severity, SignedRuleEnvelope,
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
/// project sets added.
fn enrolled(test: &str, pki: &Arc<Pki>, distribution_url: &str) -> Service {
    let baseline = format!("[[rule_sets]]\nid = \"baseline\"\n{}\n", trusted_keys());
    agent(test, pki, distribution_url, &baseline)
}

/// An enrolled agent configured with `sets` (`[[rule_sets]]` tables).
fn agent(test: &str, pki: &Arc<Pki>, distribution_url: &str, sets: &str) -> Service {
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
             enrollment_token_file = {:?}\ndistribution_url = {distribution_url:?}\n{sets}",
            dir.join("ca.pem"),
            dir.join("state"),
            dir.join("token"),
        ),
    )
    .unwrap();
    let mut service = open(&path);
    service.tick(NOW).unwrap();
    service
}

/// Opens the agent at `path`. The project key's private half is offline,
/// so each added set also trusts the test key, under its own issuer id.
fn open(path: &Path) -> Service {
    open_with(path, false)
}

/// [`open`], with `distribution_url` taken as derived from `platform_url`
/// when `derived` (the tests' platform is not on the distribution port).
fn open_with(path: &Path, derived: bool) -> Service {
    let mut config = load_config(path).unwrap();
    config.distribution_derived = derived;
    let public = organization_key().verifying_key().to_bytes();
    let added: Vec<_> = config
        .scan
        .rule_sets
        .iter()
        .filter(|set| set.source != RuleSetSource::Configured)
        .map(|set| set.id.clone())
        .collect();
    for set in added {
        config
            .scan
            .trusted_keys
            .push(TrustedRuleKey::new(set, id("org.rules"), public).unwrap());
    }
    Service::open(config).unwrap()
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
            [unchanged(), not_found(), not_found(), not_found()],
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
    assert_eq!(off.newly_not_assigned, [id(L1)], "logged when it changes");
    assert!(off.rule_set_errors.is_empty(), "{:?}", off.rule_set_errors);
    assert_eq!(
        health(&off, L1),
        Some((None, Some(RuleSetState::NotAssigned)))
    );

    // A 404 never withdraws, but neither does it bring a withdrawn set back.
    let still = service.scan_if_due(NOW + 2 * HOUR).unwrap().unwrap();
    assert_eq!(still.matched, 1);
    assert!(still.newly_not_assigned.is_empty(), "not logged again");
    assert!(
        still.rule_set_errors.is_empty(),
        "{:?}",
        still.rule_set_errors
    );
    assert_eq!(
        health(&still, L1),
        Some((None, Some(RuleSetState::NotAssigned)))
    );

    let on = service.scan_if_due(NOW + 3 * HOUR).unwrap().unwrap();
    assert_eq!(on.matched, 2, "switched back on: the next scan runs it");
    assert_eq!(health(&on, L1), Some((Some(1), None)));
    assert_eq!(
        versions(&asked(&seen), L1),
        [None, Some(1), None, None],
        "withdrawn: asked without current_version, so the same v1 comes back as 200"
    );
}

#[test]
fn a_reassigned_set_keeps_its_rollback_floor() {
    let pki = Arc::new(Pki::new());
    // L2, never stored, is answered 410, then 404, then 503: remembered as
    // not assigned for the process lifetime (nothing stored to mark).
    let (url, _) = serve(
        pki.server_config(true, false),
        scans(vec![
            [
                raw(200, bundle("baseline", 1)),
                not_found(),
                raw(200, bundle(L1, 2)),
                gone(),
            ],
            [unchanged(), not_found(), gone(), not_found()],
            [
                unchanged(),
                not_found(),
                raw(503, Vec::new()),
                raw(503, Vec::new()),
            ],
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
    let off = service.scan_if_due(NOW + HOUR).unwrap().unwrap();
    assert_eq!(off.matched, 1);
    let not_assigned = Some((None, Some(RuleSetState::NotAssigned)));
    assert_eq!(health(&off, "hardening-linux-l2"), not_assigned);

    // Platform unreachable: a withdrawn set never falls back to its
    // stored bundle, and neither set waits for an early retry.
    let outage = service.scan_if_due(NOW + 2 * HOUR).unwrap().unwrap();
    assert_eq!(outage.matched, 1, "L1 stays off");
    assert_eq!(health(&outage, L1), not_assigned);
    assert_eq!(health(&outage, "hardening-linux-l2"), not_assigned);
    assert_eq!(outage.rules_retry_in_s, None, "nothing to wait for");

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
    let refused = older.rule_sets.iter().find(|set| set.id == id(L1)).unwrap();
    assert_eq!(refused.state, Some(RuleSetState::NotAssigned));
    assert_eq!(refused.refused, Some(BundleRefusal::RolledBack));

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
            [not_found(), not_found(), not_found(), not_found()],
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

    let missing = service.scan_if_due(NOW + 2 * HOUR).unwrap().unwrap();
    assert_eq!(missing.matched, 1, "a 404 does not stop a configured set");
    assert_eq!(
        missing.rule_set_errors,
        [(
            id("baseline"),
            AgentError::Transport(TransportError::Rejected)
        )]
    );
    assert_eq!(
        versions(&asked(&seen), "baseline"),
        [None, Some(1), Some(1)],
        "its bundle and floor were kept"
    );
}

#[test]
fn an_added_baseline_with_rules_is_never_stopped_by_a_404() {
    let pki = Arc::new(Pki::new());
    let (url, _) = serve(
        pki.server_config(true, false),
        scans(vec![
            [
                raw(200, bundle("baseline", 1)),
                not_found(),
                not_found(),
                not_found(),
            ],
            [not_found(), not_found(), not_found(), not_found()],
        ]),
    );
    // No `[[rule_sets]]`: the baseline is added, as on a host installed
    // without rules.
    let mut service = agent("added-baseline-404", &pki, &url, "");
    assert_eq!(service.scan_if_due(NOW).unwrap().unwrap().matched, 1);

    let missing = service.scan_if_due(NOW + HOUR).unwrap().unwrap();
    assert_eq!(missing.matched, 1, "the stored baseline keeps running");
    assert_eq!(
        missing.rule_set_errors,
        [(
            id("baseline"),
            AgentError::Transport(TransportError::Rejected)
        )]
    );
    assert_eq!(health(&missing, "baseline"), Some((Some(1), None)));
}

#[test]
fn a_withdrawn_set_named_in_the_configuration_uses_its_stored_bundle() {
    let pki = Arc::new(Pki::new());
    let (url, _) = serve(
        pki.server_config(true, false),
        scans(vec![
            [
                raw(200, bundle("baseline", 1)),
                not_found(),
                raw(200, bundle(L1, 1)),
                not_found(),
            ],
            [unchanged(), not_found(), gone(), not_found()],
            // Configured now: baseline, L1, then the added alarms and L2.
            [unchanged(), raw(503, Vec::new()), not_found(), not_found()],
        ]),
    );
    let test = "withdrawn-then-configured";
    let mut service = enrolled(test, &pki, &url);
    service.scan_if_due(NOW).unwrap().unwrap();
    assert_eq!(service.scan_if_due(NOW + HOUR).unwrap().unwrap().matched, 1);
    drop(service);

    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("agent-project-sets")
        .join(test)
        .join("agent.toml");
    let mut toml = fs::read_to_string(&path).unwrap();
    toml.push_str(&format!(
        "[[rule_sets]]\nid = \"{L1}\"\n{}\n",
        trusted_keys()
    ));
    fs::write(&path, toml).unwrap();
    let mut service = open(&path);
    let configured = service.scan_if_due(NOW + 2 * HOUR).unwrap().unwrap();
    assert_eq!(
        configured.matched, 2,
        "a configured set falls back as always"
    );
    assert_eq!(health(&configured, L1), Some((Some(1), None)));
}

/// A distribution URL derived from `platform_url` that does not answer.
#[path = "derived.rs"]
mod derived;
