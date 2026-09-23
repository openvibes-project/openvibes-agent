use std::time::{Duration, Instant};

use openvibes_core::{FactSet, Identifier, ResourceLimits, SchemaVersion};
use openvibes_rules::{
    AcceptedVersion, EvaluationClock, Evaluator, LoadContext, RuleLoader, RuleOutcome,
    VerifiedRuleSet,
};
use openvibes_storage::{RuleStore, SqliteQueue, StorageError, StoredRuleBundle};

use crate::{AgentError, RuleSetConfig, config::read_bounded};

/// What one scan did. Failures of single rule sets or rules never stop the
/// others; they are counted here so the operator sees them.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ScanReport {
    /// Findings newly queued by this scan.
    pub queued: usize,
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

/// Collects host facts once, evaluates every provisioned rule set against
/// them, and queues the matches. Finding IDs derive from `install_id`, so
/// scanning does not depend on enrollment.
pub(crate) fn scan(
    rule_sets: &[RuleSetConfig],
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
        match current_bundle(set, loader, store, now_unix_ms) {
            (Some(bundle), error) => {
                verified.push(bundle);
                report
                    .rule_set_errors
                    .extend(error.map(|e| (set.id.clone(), e)));
            }
            (None, error) => {
                let error = error.unwrap_or(AgentError::Config);
                report.rule_set_errors.push((set.id.clone(), error));
            }
        }
    }
    if verified.is_empty() {
        return Ok(report);
    }

    let deadline = Instant::now() + Duration::from_secs(limits.scan_seconds);
    let (facts, errors) = match openvibes_collectors::collect_processes(deadline, limits) {
        Ok(facts) => (facts, Vec::new()),
        Err(error) => (Vec::new(), vec![error]),
    };
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
                    if queue.enqueue(&finding, now_unix_ms)? {
                        report.queued += 1;
                    }
                }
                RuleOutcome::NoMatch => {}
                RuleOutcome::Unavailable => report.unavailable_rules += 1,
                RuleOutcome::Failed(_) => report.failed_rules += 1,
            }
        }
    }
    Ok(report)
}

/// The bundle to evaluate for `set`, and why the provisioned file was refused
/// if it was. A newer valid file is accepted into `store`; otherwise the last
/// accepted bundle is re-verified and used, so a bad or rolled-back file never
/// replaces good rules. A damaged store record is an error, never first use.
fn current_bundle(
    set: &RuleSetConfig,
    loader: &RuleLoader,
    store: &mut RuleStore,
    now_unix_ms: i64,
) -> (Option<VerifiedRuleSet>, Option<AgentError>) {
    let stored = match store.get(&set.id) {
        Ok(stored) => stored,
        Err(error) => return (None, Some(AgentError::Storage(error))),
    };
    let floor = match &stored {
        Some(stored) => {
            match AcceptedVersion::restore(set.id.clone(), stored.version, stored.preimage_sha256) {
                Ok(floor) => Some(floor),
                Err(_) => return (None, Some(AgentError::Storage(StorageError::Corrupt))),
            }
        }
        None => None,
    };
    let context = || LoadContext {
        expected_rule_set_id: &set.id,
        now_unix_ms,
        last_accepted: floor.as_ref(),
    };
    let bytes_limit = u64::try_from(ResourceLimits::V1.document_bytes).unwrap_or(u64::MAX);
    let file_error = match read_bounded(&set.bundle_file, bytes_limit) {
        Ok(Some(bytes)) => match loader.load_json(&bytes, context()) {
            Ok(bundle) => {
                let accepted = bundle.accepted_version();
                let record = StoredRuleBundle {
                    version: accepted.version(),
                    preimage_sha256: *accepted.preimage_sha256(),
                    envelope: bytes,
                };
                match store.accept(&set.id, &record) {
                    Ok(()) => return (Some(bundle), None),
                    Err(error) => AgentError::Storage(error),
                }
            }
            Err(error) => AgentError::Rules(error),
        },
        Ok(None) | Err(_) => AgentError::Config,
    };
    let cached = stored.and_then(|stored| loader.load_json(&stored.envelope, context()).ok());
    (cached, Some(file_error))
}
