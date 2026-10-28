use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};

use openvibes_core::{
    BundleRefusal, CollectorOutcome, FactSet, Finding, Identifier, ResourceLimits, RuleSetHealth,
    RuleSetState, SchemaVersion,
};
use openvibes_rules::{
    EvaluationClock, Evaluator, LoadError, RuleLoader, RuleOutcome, VerifiedRuleSet,
};
use openvibes_storage::{RuleStore, SqliteQueue, StorageError};
use openvibes_transport::PlatformClient;

use crate::{AgentError, RuleSetSource, ScanConfig, matches::Outcome, project_sets::Withdrawn};

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
    /// Rules that matched or did not (P12).
    pub rules_evaluated: usize,
    /// Each enabled collector that ran, by name: `Ok` or its error (P12).
    pub collectors: BTreeMap<String, CollectorOutcome>,
    /// Every configured rule set: the version and expiry in use, and why
    /// this scan's bundle was refused, if it was (P12).
    pub rule_sets: Vec<RuleSetHealth>,
    /// Project sets that turned not assigned (410) in this scan, for one
    /// log line each (agent #93).
    pub newly_not_assigned: Vec<Identifier>,
    /// Rules that matched (queued or not).
    pub matched: usize,
    /// Some set has no rules because the platform didn't answer; it is
    /// fetched again in this many seconds (board #111).
    pub rules_retry_in_s: Option<u64>,
    /// Each rule set evaluated without error, with every rule's outcome,
    /// for finding changes (P13).
    pub(crate) evaluated: Vec<(Identifier, Vec<(Identifier, Outcome)>)>,
}

impl ScanReport {
    /// The rule sets running on this host after this scan: every listed
    /// set except one the platform no longer assigns (P20). The others'
    /// matches end (P13), so switching a set back on starts them again.
    pub(crate) fn running_sets(&self) -> BTreeSet<Identifier> {
        self.rule_sets
            .iter()
            .filter(|set| set.state != Some(RuleSetState::NotAssigned))
            .map(|set| set.id.clone())
            .collect()
    }
}

/// The health report's code for a refused bundle (P12).
pub(crate) fn refusal(error: &LoadError) -> BundleRefusal {
    match error {
        LoadError::InvalidSignature
        | LoadError::UntrustedIssuer
        | LoadError::InvalidTrustKey
        | LoadError::DigestMismatch => BundleRefusal::Signature,
        LoadError::Expired | LoadError::NotYetValid => BundleRefusal::Expired,
        LoadError::Rollback | LoadError::VersionConflict => BundleRefusal::RolledBack,
        _ => BundleRefusal::Invalid,
    }
}

/// The health code of the first refused bundle among `errors`.
fn first_refusal(errors: &[AgentError]) -> Option<BundleRefusal> {
    errors.iter().find_map(|error| match error {
        AgentError::Rules(error) => Some(refusal(error)),
        _ => None,
    })
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
/// every usable rule set against them, and queues the matches in `queue`
/// when one is given (without P13 finding changes). Finding IDs derive from
/// `install_id`, so scanning does not depend on enrollment. Also returns
/// the usable bundles, for their `process_event` rules (P14). `gone` holds
/// the project sets last answered 410 (P20) in this process, so one never
/// stored (no withdrawn mark) stays not assigned through an outage.
/// `derived`: `client` reaches a distribution URL derived from
/// `platform_url` (spec 2026-10-14 §3), used for project sets only, and
/// quiet while unreachable for those never stored.
#[expect(clippy::too_many_arguments, reason = "one call site")]
pub(crate) fn scan(
    config: &ScanConfig,
    client: Option<&PlatformClient>,
    derived: bool,
    loader: &RuleLoader,
    store: &mut RuleStore,
    gone: &mut BTreeSet<Identifier>,
    mut queue: Option<&mut SqliteQueue>,
    install_id: &Identifier,
    now_unix_ms: i64,
) -> Result<(ScanReport, Vec<VerifiedRuleSet>), AgentError> {
    let limits = ResourceLimits::V1;
    let mut report = ScanReport::default();
    let mut verified = Vec::new();
    let collectors = config.collectors;
    for set in &config.rule_sets {
        // A configured set needs an explicit distribution_url, as before.
        let client = client.filter(|_| !(derived && set.source == RuleSetSource::Configured));
        let current =
            bundle::current_bundle(set, client, derived, loader, store, gone, now_unix_ms);
        match &current {
            Err((Withdrawn::NotAssigned, _)) => {
                if gone.insert(set.id.clone()) {
                    report.newly_not_assigned.push(set.id.clone());
                }
            }
            _ => {
                gone.remove(&set.id);
            }
        }
        let (bundle, errors) = match current {
            Ok(current) => current,
            // Not published here (an older platform, or no rules package):
            // nothing runs, nothing is reported.
            Err((Withdrawn::NotOffered, _)) => continue,
            Err((Withdrawn::NotAssigned, errors)) => {
                // Stop using the stored bundle, so neither its expiry nor
                // a platform outage keeps it running; its row stays, so
                // the rollback floor holds when the set is switched back on.
                if let Err(error) = store.withdraw(&set.id) {
                    report
                        .rule_set_errors
                        .push((set.id.clone(), AgentError::Storage(error)));
                }
                report.rule_sets.push(RuleSetHealth {
                    id: set.id.clone(),
                    version: None,
                    expires_at_unix_ms: None,
                    refused: first_refusal(&errors),
                    state: Some(RuleSetState::NotAssigned),
                });
                report
                    .rule_set_errors
                    .extend(errors.into_iter().map(|error| (set.id.clone(), error)));
                continue;
            }
        };
        report.rule_sets.push(RuleSetHealth {
            id: set.id.clone(),
            version: bundle.as_ref().map(|b| b.accepted_version().version()),
            expires_at_unix_ms: bundle.as_ref().map(VerifiedRuleSet::expires_at_unix_ms),
            refused: first_refusal(&errors),
            state: None,
        });
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
        return Ok((report, verified));
    }

    let deadline = Instant::now() + Duration::from_secs(limits.scan_seconds);
    let mut facts = Vec::new();
    let mut errors = Vec::new();
    // A disabled collector contributes no facts and no error: its rules are
    // unavailable, and the scan is not partial.
    let mut outcome = |name: &str, error: Option<&openvibes_core::CollectorError>| {
        report.collectors.insert(
            name.to_owned(),
            error.map_or(CollectorOutcome::Ok, |error| error.code.into()),
        );
    };
    if collectors.processes {
        match openvibes_collectors::collect_processes(deadline, limits) {
            Ok(collected) => {
                facts.extend(collected);
                outcome("processes", None);
            }
            Err(error) => {
                outcome("processes", Some(&error));
                errors.push(error);
            }
        }
    }
    if collectors.ports {
        match openvibes_collectors::collect_ports(deadline, limits) {
            Ok(collected) => {
                facts.extend(collected);
                outcome("ports", None);
            }
            Err(error) => {
                outcome("ports", Some(&error));
                errors.push(error);
            }
        }
    }
    if collectors.packages {
        match openvibes_collectors::collect_packages(deadline, limits) {
            Ok(packages) => {
                facts.extend(openvibes_collectors::package_facts(&packages));
                outcome("packages", None);
            }
            Err(error) => {
                outcome("packages", Some(&error));
                errors.push(error);
            }
        }
    }
    // Hardening facts (P19) come from the root-facts helper, which every
    // package enables; nobody switches them on. Without its file (no helper
    // on this OS) they are absent, as from a disabled collector. Which hardening rules a host
    // runs is the platform's choice (the rule sets it is given).
    match crate::root_facts::fresh_hardening(
        std::path::Path::new(crate::root_facts::PATH),
        now_unix_ms,
    ) {
        Ok(None) => {}
        Ok(Some(hardening)) => {
            facts.extend(hardening.facts);
            // A source the host does not have (no auditd, no sshd) is not
            // a partial scan: its rules are unavailable either way. Read
            // failures are.
            errors.extend(
                hardening
                    .errors
                    .into_iter()
                    .filter(|e| e.code != openvibes_core::CollectorErrorCode::NotFound),
            );
            outcome("hardening", None);
        }
        Err(error) => {
            outcome("hardening", Some(&error));
            errors.push(error);
        }
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
        let mut outcomes = Vec::with_capacity(evaluated.results.len());
        for result in evaluated.results {
            let outcome = match result.outcome {
                RuleOutcome::Match(finding) => {
                    report.rules_evaluated += 1;
                    report.matched += 1;
                    if let Some(queue) = queue.as_deref_mut() {
                        enqueue_finding(queue, &finding, now_unix_ms, &mut report)?;
                    }
                    Outcome::Match(*finding)
                }
                RuleOutcome::NoMatch => {
                    report.rules_evaluated += 1;
                    Outcome::NoMatch
                }
                RuleOutcome::Unavailable => {
                    report.unavailable_rules += 1;
                    Outcome::Kept
                }
                RuleOutcome::Failed(_) => {
                    report.failed_rules += 1;
                    Outcome::Kept
                }
            };
            outcomes.push((result.rule_id, outcome));
        }
        report
            .evaluated
            .push((bundle.accepted_version().rule_set_id().clone(), outcomes));
    }
    Ok((report, verified))
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

mod bundle;

#[cfg(test)]
mod tests;
