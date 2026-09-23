//! Local-only route: no platform configured, findings kept across restarts,
//! and exported to files that consume them from the queue.

use std::{
    fs,
    path::{Path, PathBuf},
};

use openvibes_agent::{AgentError, Service, TickReport, load_config};
use openvibes_core::{
    Confidence, Finding, FindingExport, Identifier, ResourceLimits, SchemaVersion, Severity,
    Validate,
};

fn finding(index: usize) -> Finding {
    Finding {
        schema_version: SchemaVersion::V1,
        finding_id: Identifier::new(format!("finding.{index}")).unwrap(),
        scan_id: Identifier::new("scan.1").unwrap(),
        rule_id: Identifier::new("rule.1").unwrap(),
        rule_version: 1,
        observed_at_unix_ms: 1,
        severity: Severity::Low,
        confidence: Confidence::new(90).unwrap(),
        message: "synthetic".into(),
        evidence: Vec::new(),
    }
}

/// Fresh scratch directory holding a local-only config with `extra` lines.
fn scratch(test: &str, extra: &str) -> (PathBuf, PathBuf) {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("agent-local-only")
        .join(test);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("out")).unwrap();
    let config = dir.join("agent.toml");
    fs::write(
        &config,
        format!("state_dir = {:?}\n{extra}", dir.join("state")),
    )
    .unwrap();
    (dir, config)
}

fn open(config: &Path) -> Service {
    Service::open(load_config(config).unwrap()).unwrap()
}

fn exports(dir: &Path) -> Vec<FindingExport> {
    let mut names: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    names.sort();
    names
        .iter()
        .map(|path| serde_json::from_slice(&fs::read(path).unwrap()).unwrap())
        .collect()
}

#[test]
fn platform_settings_come_together_or_not_at_all() {
    let (dir, config) = scratch("config", "");
    assert!(load_config(&config).unwrap().transport.is_none());
    let lines = [
        "platform_url = \"https://platform.example\"\n".to_owned(),
        format!("platform_ca_file = {:?}\n", dir.join("ca.pem")),
        format!("enrollment_token_file = {:?}\n", dir.join("token")),
        "proxy_url = \"http://proxy.example:3128\"\n".to_owned(),
    ];
    for line in lines {
        let (_, config) = scratch("config-partial", &line);
        assert_eq!(
            load_config(&config).err(),
            Some(AgentError::Config),
            "{line}"
        );
    }
}

#[test]
fn local_only_keeps_findings_across_restart_and_exports_each_once() {
    let (dir, config) = scratch("export", "");
    let out = dir.join("out");
    let mut service = open(&config);
    assert_eq!(service.tick(10).unwrap(), TickReport::default());
    for index in 0..501 {
        assert!(service.queue().enqueue(&finding(index), 10).unwrap());
    }
    drop(service);

    let mut service = open(&config);
    assert_eq!(service.tick(20).unwrap(), TickReport::default());
    assert_eq!(service.queue().len().unwrap(), 501);
    assert_eq!(service.export(&out, 30).unwrap(), 501);
    assert!(service.queue().is_empty().unwrap());

    let files = exports(&out);
    assert_eq!(files.len(), 2);
    assert_eq!(files[0].findings.len(), 500);
    assert_eq!(files[1].findings, vec![finding(500)]);
    let install_id = files[0].install_id.clone();
    for file in &files {
        file.validate(ResourceLimits::V1).unwrap();
        assert_eq!(file.install_id, install_id);
        assert_eq!(file.agent_id, None);
        assert_eq!(file.exported_at_unix_ms, 30);
    }

    // Exported findings are consumed: not exported again, not re-queued.
    assert_eq!(service.export(&out, 40).unwrap(), 0);
    assert_eq!(exports(&out).len(), 2);
    assert!(!service.queue().enqueue(&finding(3), 50).unwrap());
    drop(service);
    assert_eq!(open(&config).export(&out, 60).unwrap(), 0);
}

#[test]
fn failed_export_keeps_findings_queued() {
    let (dir, config) = scratch("export-fails", "");
    let mut service = open(&config);
    service.queue().enqueue(&finding(1), 10).unwrap();
    assert_eq!(
        service.export(&dir.join("missing"), 20).err(),
        Some(AgentError::Export)
    );
    assert_eq!(service.queue().len().unwrap(), 1);
}
