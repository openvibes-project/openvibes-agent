//! The rule-bundle answers (protocol P20): 404 is `NotFound` (not
//! published), 410 is `NotAssigned` (not assigned to this host); any
//! other 4xx stays `Rejected`, and a 410 elsewhere is a plain refusal.

use openvibes_core::{Identifier, ResourceLimits, RuleBundleRequest, SchemaVersion};
use openvibes_testkit::{Pki, Seen, serve, status};
use openvibes_transport::{
    DEFAULT_DISTRIBUTION_PORT, PlatformClient, TransportConfig, TransportError,
};

#[test]
fn rule_bundle_answers_404_and_410_by_name() {
    let pki = Pki::new();
    let (url, _) = serve(
        pki.server_config(false, false),
        vec![
            Box::new(|_: &Seen| status(404)),
            Box::new(|_: &Seen| status(410)),
            Box::new(|_: &Seen| status(400)),
            Box::new(|_: &Seen| status(204)),
        ],
    );
    let config = TransportConfig {
        base_url: url,
        default_port: DEFAULT_DISTRIBUTION_PORT,
        server_roots_pem: pki.roots_pem(),
        proxy_url: None,
        limits: ResourceLimits::V1,
    };
    let client = PlatformClient::new(&config, None).unwrap();
    let request = RuleBundleRequest {
        schema_version: SchemaVersion::V1,
        rule_set_id: Identifier::new("hardening-linux-l1").unwrap(),
        current_version: None,
    };
    assert_eq!(
        client.fetch_rule_bundle(&request),
        Err(TransportError::NotFound)
    );
    assert_eq!(
        client.fetch_rule_bundle(&request),
        Err(TransportError::NotAssigned)
    );
    assert_eq!(
        client.fetch_rule_bundle(&request),
        Err(TransportError::Rejected)
    );
    assert_eq!(client.fetch_rule_bundle(&request), Ok(None));
}

#[test]
fn a_410_on_another_endpoint_is_rejected() {
    let pki = Pki::new();
    let (url, _) = serve(
        pki.server_config(false, false),
        vec![Box::new(|_: &Seen| status(410))],
    );
    let config = TransportConfig {
        base_url: url,
        default_port: DEFAULT_DISTRIBUTION_PORT,
        server_roots_pem: pki.roots_pem(),
        proxy_url: None,
        limits: ResourceLimits::V1,
    };
    let client = PlatformClient::new(&config, None).unwrap();
    let heartbeat: openvibes_core::Heartbeat = serde_json::from_str(include_str!(
        "../../../protocol/fixtures/v1/heartbeat/valid.json"
    ))
    .unwrap();
    assert_eq!(client.heartbeat(&heartbeat), Err(TransportError::Rejected));
}
