use openvibes_core::{Confidence, Finding, Identifier, ResourceLimits, SchemaVersion, Severity};
use openvibes_storage::SqliteQueue;

use super::{ScanReport, enqueue_finding};

fn finding(n: usize) -> Finding {
    Finding {
        detection: None,
        schema_version: SchemaVersion::V1,
        rule_set_id: None,
        finding_id: Identifier::new(format!("f.{n}")).unwrap(),
        scan_id: Identifier::new("scan.1").unwrap(),
        rule_id: Identifier::new("rule.1").unwrap(),
        rule_version: 1,
        observed_at_unix_ms: 0,
        severity: Severity::Info,
        confidence: Confidence::new(100).unwrap(),
        message: "x".repeat(4_000),
        evidence: Vec::new(),
    }
}

#[test]
fn load_errors_map_to_refusal_codes() {
    use openvibes_core::BundleRefusal as R;
    use openvibes_rules::LoadError as L;
    assert_eq!(super::refusal(&L::InvalidSignature), R::Signature);
    assert_eq!(super::refusal(&L::UntrustedIssuer), R::Signature);
    assert_eq!(super::refusal(&L::DigestMismatch), R::Signature);
    assert_eq!(super::refusal(&L::Expired), R::Expired);
    assert_eq!(super::refusal(&L::NotYetValid), R::Expired);
    assert_eq!(super::refusal(&L::Rollback), R::RolledBack);
    assert_eq!(super::refusal(&L::VersionConflict), R::RolledBack);
    assert_eq!(super::refusal(&L::InvalidRules), R::Invalid);
}

#[test]
fn a_full_queue_keeps_the_newest_findings() {
    // Under the workspace's target directory, owned by the test user: the
    // system temp directory can sit behind a symlink (macOS), which the
    // queue's path checks refuse.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/unit-tmp")
        .join(format!("scan-full-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let small = ResourceLimits {
        queue_bytes: 64 * 1024,
        ..ResourceLimits::V1
    };
    let mut queue = SqliteQueue::open(&dir.join("queue.sqlite"), small).unwrap();
    let mut report = ScanReport::default();
    for n in 0..40 {
        enqueue_finding(&mut queue, &finding(n), 0, &mut report).unwrap();
    }
    // P12: the queue drops its oldest findings instead of refusing
    // new ones, and counts what it dropped.
    assert_eq!((report.queued, report.not_queued), (40, 0));
    assert!(queue.stats().unwrap().dropped_total > 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_set_no_longer_assigned_is_not_running() {
    use openvibes_core::{RuleSetHealth, RuleSetState};
    let set = |name: &str, state| RuleSetHealth {
        id: Identifier::new(name).unwrap(),
        version: None,
        expires_at_unix_ms: None,
        refused: None,
        state,
    };
    let report = ScanReport {
        rule_sets: vec![
            set("baseline", None),
            set("hardening-linux-l1", Some(RuleSetState::NotAssigned)),
        ],
        ..ScanReport::default()
    };
    // Its matches end (P13), so switching it back on starts them again.
    let running: Vec<String> = report
        .running_sets()
        .into_iter()
        .map(|id| id.as_str().to_owned())
        .collect();
    assert_eq!(running, ["baseline"]);
}
