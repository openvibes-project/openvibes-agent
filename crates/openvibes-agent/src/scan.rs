use std::time::{Duration, Instant};

use openvibes_core::{FactSet, Identifier, ResourceLimits, RuleBundleRequest, SchemaVersion};
use openvibes_rules::{
    AcceptedVersion, EvaluationClock, Evaluator, LoadContext, RuleLoader, RuleOutcome,
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
                .push((set.id.clone(), AgentError::Config));
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

/// Where one candidate envelope for a rule set came from this scan: `Ok(None)`
/// means the source had nothing (no file configured, or nothing newer).
type Candidate = Result<Option<Vec<u8>>, AgentError>;

/// This scan's candidates for `set`: the distribution service's newer
/// envelope, if a client is given, then the provisioned file.
fn candidates(
    set: &RuleSetConfig,
    client: Option<&PlatformClient>,
    current_version: Option<u64>,
) -> Vec<Candidate> {
    let mut candidates = Vec::new();
    if let Some(client) = client {
        let request = RuleBundleRequest {
            schema_version: SchemaVersion::V1,
            rule_set_id: set.id.clone(),
            current_version,
        };
        candidates.push(
            client
                .fetch_rule_bundle(&request)
                .map_err(AgentError::Transport),
        );
    }
    if let Some(path) = &set.bundle_file {
        let limit = u64::try_from(ResourceLimits::V1.document_bytes).unwrap_or(u64::MAX);
        candidates.push(match read_bounded(path, limit) {
            Ok(Some(bytes)) => Ok(Some(bytes)),
            Ok(None) | Err(_) => Err(AgentError::Config),
        });
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
    for candidate in candidates(set, client, current_version) {
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
