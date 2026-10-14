use std::{fs, net::TcpListener, path::PathBuf, sync::Arc};

use openvibes_agent::AgentError;
use openvibes_testkit::{Pki, serve};
use openvibes_transport::TransportError;

use super::{HOUR, NOW, agent, bundle, health, not_found, open_with, raw, scans};
use crate::support::id;

/// A URL on a port nobody listens on.
fn closed() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    format!("https://{}", listener.local_addr().unwrap())
}

/// Points the agent of `test` at `url` and reopens it, its URL derived.
fn reopen_derived(test: &str, url: &str) -> openvibes_agent::Service {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("agent-project-sets")
        .join(test)
        .join("agent.toml");
    let toml = fs::read_to_string(&path).unwrap();
    let toml = toml
        .lines()
        .map(|line| {
            if line.starts_with("distribution_url") {
                format!("distribution_url = {url:?}")
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&path, toml).unwrap();
    open_with(&path, true)
}

#[test]
fn an_unreachable_derived_url_is_quiet_for_sets_never_stored() {
    let pki = Arc::new(Pki::new());
    let test = "derived-unreachable";
    let url = closed();
    drop(agent(test, &pki, &url, ""));
    let mut service = reopen_derived(test, &url);
    let report = service.scan_if_due(NOW).unwrap().unwrap();
    assert!(
        report.rule_set_errors.is_empty(),
        "{:?}",
        report.rule_set_errors
    );
    assert!(report.rule_sets.is_empty(), "{:?}", report.rule_sets);
    assert_eq!(report.rules_retry_in_s, None, "no early retries");
    assert_eq!(
        service.rules_retry_in(NOW),
        None,
        "asked again at the scan interval"
    );
}

#[test]
fn after_a_bundle_a_derived_url_outage_is_reported_as_today() {
    let pki = Arc::new(Pki::new());
    let (url, _) = serve(
        pki.server_config(true, false),
        scans(vec![[
            raw(200, bundle("baseline", 1)),
            not_found(),
            not_found(),
            not_found(),
        ]]),
    );
    let test = "derived-outage";
    drop(agent(test, &pki, &url, ""));
    let mut service = reopen_derived(test, &url);
    assert_eq!(service.scan_if_due(NOW).unwrap().unwrap().matched, 1);
    drop(service);

    let mut service = reopen_derived(test, &closed());
    let report = service.scan_if_due(NOW + HOUR).unwrap().unwrap();
    assert_eq!(report.matched, 1, "the stored baseline keeps running");
    assert_eq!(
        report.rule_set_errors,
        [(
            id("baseline"),
            AgentError::Transport(TransportError::Connect)
        )],
        "only the set with a bundle reports the outage"
    );
    assert_eq!(health(&report, "baseline"), Some((Some(1), None)));
}

#[test]
fn a_configured_set_is_never_fetched_from_a_derived_url() {
    let pki = Arc::new(Pki::new());
    let test = "derived-configured";
    let file = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("agent-project-sets")
        .join(format!("{test}.json"));
    fs::write(&file, bundle("site.web", 1)).unwrap();
    let sets = format!(
        "[[rule_sets]]\nid = \"site.web\"\nbundle_file = {file:?}\n{}\n",
        super::trusted_keys()
    );
    let url = closed();
    drop(agent(test, &pki, &url, &sets));
    let mut service = reopen_derived(test, &url);
    let report = service.scan_if_due(NOW).unwrap().unwrap();
    assert_eq!(report.matched, 1, "read from its file, as without a URL");
    assert!(
        report.rule_set_errors.is_empty(),
        "{:?}",
        report.rule_set_errors
    );
    assert_eq!(health(&report, "site.web"), Some((Some(1), None)));
}

/// No health entry, no error, no early retry.
fn assert_quiet(service: &openvibes_agent::Service, report: &openvibes_agent::ScanReport) {
    assert!(
        report.rule_set_errors.is_empty(),
        "{:?}",
        report.rule_set_errors
    );
    assert!(report.rule_sets.is_empty(), "{:?}", report.rule_sets);
    assert_eq!(report.rules_retry_in_s, None, "no early retries");
    assert_eq!(service.rules_retry_in(NOW), None);
}

#[test]
fn a_derived_url_the_platform_ca_does_not_trust_is_quiet() {
    let pki = Arc::new(Pki::new());
    let stranger = Pki::new();
    let (url, _) = serve(
        stranger.server_config(false, false),
        scans(vec![
            [not_found(), not_found(), not_found(), not_found()],
            [not_found(), not_found(), not_found(), not_found()],
        ]),
    );
    let test = "derived-untrusted";
    let mut explicit = agent(test, &pki, &url, "");
    let report = explicit.scan_if_due(NOW).unwrap().unwrap();
    assert_eq!(
        report.rule_set_errors.first().map(|(_, error)| error),
        Some(&AgentError::Transport(TransportError::Tls)),
        "an explicit URL reports the TLS failure"
    );
    drop(explicit);
    let mut service = reopen_derived(test, &url);
    let report = service.scan_if_due(NOW).unwrap().unwrap();
    assert_quiet(&service, &report);
}

#[test]
fn before_enrolling_a_derived_url_is_quiet() {
    let pki = Pki::new();
    let dir = super::dir("derived-not-enrolled");
    fs::write(dir.join("ca.pem"), pki.roots_pem()).unwrap();
    let path = dir.join("agent.toml");
    // No token and no identity: never enrolled, so no distribution client.
    fs::write(
        &path,
        format!(
            "platform_url = {:?}\nplatform_ca_file = {:?}\nstate_dir = {:?}\n\
             distribution_url = {:?}\n",
            closed(),
            dir.join("ca.pem"),
            dir.join("state"),
            closed(),
        ),
    )
    .unwrap();
    let mut service = open_with(&path, true);
    let report = service.scan_if_due(NOW).unwrap().unwrap();
    assert_quiet(&service, &report);
    drop(service);

    // With an explicit URL, unchanged: each set waits for its rules.
    let mut service = open_with(&path, false);
    let report = service.scan_if_due(NOW).unwrap().unwrap();
    assert_eq!(report.rule_sets.len(), 4, "{:?}", report.rule_sets);
    assert!(
        report
            .rule_set_errors
            .iter()
            .all(|(_, error)| *error == AgentError::NoRuleBundle),
        "{:?}",
        report.rule_set_errors
    );
}
