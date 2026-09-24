use std::time::{Duration, Instant};

use openvibes_core::{
    FactSet, Finding, Identifier, ResourceLimits, RuleBundleRequest, SchemaVersion,
};
use openvibes_rules::{
    AcceptedVersion, EvaluationClock, Evaluator, LoadContext, LoadError, RuleLoader, RuleOutcome,
    VerifiedRuleSet,
};
use openvibes_storage::{RuleStore, SqliteQueue, StorageError, StoredRuleBundle};
use openvibes_transport::PlatformClient;

use crate::{AgentError, RuleSetConfig, config::read_bounded};

/// What one scan did. Failures of single rule sets or rules never stop the
/// others; they are counted here so the operator sees them.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ScanReport {
    /// Findings newly queued by this scan.
    pub queued: usize,
    /// Matches not queued because the queue was full (ADR-0003
    /// backpressure); the scan went on and reports them here.
    pub not_queued: usize,
    /// Rule sets whose provisioned bundle was refused, with the reason. A set
    /// listed here was still evaluated if its last accepted bundle was usable.
    pub rule_set_errors: Vec<(Identifier, AgentError)>,
    /// Rules not evaluated because a fact was unavailable.
    pub unavailable_rules: usize,
    /// Rules that failed to evaluate.
    pub failed_rules: usize,
    /// Whether a collector reported an error, so some facts were missing.
    pub partial_collection: bool,
}

/// Evaluation clock: monotonic time for budgets, wall time for bundle validity.
struct HostClock {
    origin: Instant,
    unix_ms: i64,
}

impl EvaluationClock for HostClock {
    fn elapsed(&self) -> Duration {
        self.origin.elapsed()
    }
    fn unix_ms(&self) -> i64 {
        self.unix_ms
    }
}

/// Refreshes every provisioned rule set (from the distribution service when
/// `client` is given, and from its file), collects host facts once, evaluates
/// every usable rule set against them, and queues the matches. Finding IDs derive from `install_id`, so
/// scanning does not depend on enrollment.
pub(crate) fn scan(
    rule_sets: &[RuleSetConfig],
    client: Option<&PlatformClient>,
    loader: &RuleLoader,
    store: &mut RuleStore,
    queue: &mut SqliteQueue,
    install_id: &Identifier,
    now_unix_ms: i64,
) -> Result<ScanReport, AgentError> {
    let limits = ResourceLimits::V1;
    let mut report = ScanReport::default();
    let mut verified = Vec::new();
    for set in rule_sets {
        let (bundle, errors) = current_bundle(set, client, loader, store, now_unix_ms);
        let unusable = bundle.is_none() && errors.is_empty();
        verified.extend(bundle);
        report
            .rule_set_errors
            .extend(errors.into_iter().map(|error| (set.id.clone(), error)));
        if unusable {
            // Nothing new was offered and nothing was ever accepted.
            report
                .rule_set_errors
                .push((set.id.clone(), AgentError::NoRuleBundle));
        }
    }
    if verified.is_empty() {
        return Ok(report);
    }

    let deadline = Instant::now() + Duration::from_secs(limits.scan_seconds);
    let mut facts = Vec::new();
    let mut errors = Vec::new();
    match openvibes_collectors::collect_processes(deadline, limits) {
        Ok(collected) => facts.extend(collected),
        Err(error) => errors.push(error),
    }
    match openvibes_collectors::collect_ports(deadline, limits) {
        Ok(collected) => facts.extend(collected),
        Err(error) => errors.push(error),
    }
    match openvibes_collectors::collect_packages(deadline, limits) {
        Ok(packages) => facts.extend(openvibes_collectors::package_facts(&packages)),
        Err(error) => errors.push(error),
    }
    let facts = FactSet {
        schema_version: SchemaVersion::V1,
        scan_id: Identifier::new(format!("scan.{now_unix_ms}")).map_err(|_| AgentError::Config)?,
        collected_at_unix_ms: now_unix_ms,
        facts,
        errors,
    };
    report.partial_collection = !facts.errors.is_empty();
    let clock = HostClock {
        origin: Instant::now(),
        unix_ms: now_unix_ms,
    };
    let evaluator = Evaluator::new(limits).map_err(AgentError::Evaluation)?;
    for bundle in &verified {
        let evaluated = match evaluator.evaluate(bundle, &facts, install_id, &clock) {
            Ok(evaluated) => evaluated,
            Err(error) => {
                let id = bundle.accepted_version().rule_set_id().clone();
                report
                    .rule_set_errors
                    .push((id, AgentError::Evaluation(error)));
                continue;
            }
        };
        for result in evaluated.results {
            match result.outcome {
                RuleOutcome::Match(finding) => {
                    enqueue_finding(queue, &finding, now_unix_ms, &mut report)?;
                }
                RuleOutcome::NoMatch => {}
                RuleOutcome::Unavailable => report.unavailable_rules += 1,
                RuleOutcome::Failed(_) => report.failed_rules += 1,
            }
        }
    }
    Ok(report)
}

/// Queues one match. A full queue is counted in `report` instead of failing
/// the scan, so the rest of the report (including a revocation signalled by
/// the distribution service) still reaches the caller.
fn enqueue_finding(
    queue: &mut SqliteQueue,
    finding: &Finding,
    now_unix_ms: i64,
    report: &mut ScanReport,
) -> Result<(), AgentError> {
    match queue.enqueue(finding, now_unix_ms) {
        Ok(true) => report.queued += 1,
        Ok(false) => {}
        Err(StorageError::Full) => report.not_queued += 1,
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

/// Where one candidate envelope for a rule set came from this scan: `Ok(None)`
/// means the source had nothing (no file configured, or nothing newer).
type Candidate = Result<Option<Vec<u8>>, AgentError>;

/// This scan's candidates for `set`, each marked `true` when it is the
/// provisioned file: the distribution service's newer envelope, if a client
/// is given, then the provisioned file.
fn candidates(
    set: &RuleSetConfig,
    client: Option<&PlatformClient>,
    current_version: Option<u64>,
) -> Vec<(bool, Candidate)> {
    let mut candidates = Vec::new();
    if let Some(client) = client {
        let request = RuleBundleRequest {
            schema_version: SchemaVersion::V1,
            rule_set_id: set.id.clone(),
            current_version,
        };
        candidates.push((
            false,
            client
                .fetch_rule_bundle(&request)
                .map_err(AgentError::Transport),
        ));
    }
    if let Some(path) = &set.bundle_file {
        let limit = u64::try_from(ResourceLimits::V1.document_bytes).unwrap_or(u64::MAX);
        candidates.push((
            true,
            match read_bounded(path, limit) {
                Ok(Some(bytes)) => Ok(Some(bytes)),
                Ok(None) | Err(_) => Err(AgentError::Config),
            },
        ));
    }
    candidates
}

/// The bundle to evaluate for `set`, and why candidates were refused. Each
/// valid candidate is accepted into `store` and raises the floor for the next;
/// if none is accepted, the last accepted bundle is re-verified and used, so a
/// bad or rolled-back candidate never replaces good rules. A damaged store
/// record is an error, never first use.
fn current_bundle(
    set: &RuleSetConfig,
    client: Option<&PlatformClient>,
    loader: &RuleLoader,
    store: &mut RuleStore,
    now_unix_ms: i64,
) -> (Option<VerifiedRuleSet>, Vec<AgentError>) {
    let stored = match store.get(&set.id) {
        Ok(stored) => stored,
        Err(error) => return (None, vec![AgentError::Storage(error)]),
    };
    let mut floor = match &stored {
        Some(stored) => {
            match AcceptedVersion::restore(set.id.clone(), stored.version, stored.preimage_sha256) {
                Ok(floor) => Some(floor),
                Err(_) => return (None, vec![AgentError::Storage(StorageError::Corrupt)]),
            }
        }
        None => None,
    };
    let mut errors = Vec::new();
    let mut accepted = None;
    let current_version = floor.as_ref().map(AcceptedVersion::version);
    for (from_file, candidate) in candidates(set, client, current_version) {
        let bytes = match candidate {
            Ok(Some(bytes)) => bytes,
            Ok(None) => continue,
            Err(error) => {
                errors.push(error);
                continue;
            }
        };
        let context = LoadContext {
            expected_rule_set_id: &set.id,
            now_unix_ms,
            last_accepted: floor.as_ref(),
        };
        let bundle = match loader.load_json(&bytes, context) {
            Ok(bundle) => bundle,
            // With a distribution service, an older provisioned file is
            // expected once a newer bundle was fetched: not a rollback
            // attempt worth reporting on every scan.
            Err(LoadError::Rollback) if from_file && client.is_some() => continue,
            Err(error) => {
                errors.push(AgentError::Rules(error));
                continue;
            }
        };
        let version = bundle.accepted_version().clone();
        let record = StoredRuleBundle {
            version: version.version(),
            preimage_sha256: *version.preimage_sha256(),
            envelope: bytes,
        };
        match store.accept(&set.id, &record) {
            Ok(()) => {
                floor = Some(version);
                accepted = Some(bundle);
            }
            Err(error) => errors.push(AgentError::Storage(error)),
        }
    }
    if accepted.is_none() {
        let context = LoadContext {
            expected_rule_set_id: &set.id,
            now_unix_ms,
            last_accepted: floor.as_ref(),
        };
        accepted = stored.and_then(|stored| loader.load_json(&stored.envelope, context).ok());
    }
    (accepted, errors)
}

#[cfg(test)]
mod tests {
    use openvibes_core::{
        Confidence, Finding, Identifier, ResourceLimits, SchemaVersion, Severity,
    };
    use openvibes_storage::SqliteQueue;

    use super::{ScanReport, enqueue_finding};

    fn finding(n: usize) -> Finding {
        Finding {
            schema_version: SchemaVersion::V1,
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
    fn a_full_queue_counts_findings_instead_of_failing_the_scan() {
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
        assert!(report.queued > 0);
        assert!(report.not_queued > 0, "the rest counted, not an error");
        assert_eq!(report.queued + report.not_queued, 40);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
