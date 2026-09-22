use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    time::Duration,
};

use ovsvms_core::{
    Fact, FactSet, FactValue, Finding, Identifier, ResourceLimits, Rule, SchemaVersion, Validate,
};
use sha2::{Digest, Sha256};

use crate::{VerifiedRuleSet, subset};

/// Host-supplied clocks, inaccessible to CEL expressions.
/// Implementations must be fast and return a nondecreasing monotonic duration.
pub trait EvaluationClock {
    /// Monotonic elapsed time since an arbitrary host-selected origin.
    fn elapsed(&self) -> Duration;
    /// Trusted current Unix time in milliseconds for bundle validity checks.
    fn unix_ms(&self) -> i64;
}

/// Fixed failure codes; no expression or collected value is included in errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvaluationError {
    /// Configured limits exceed supported ceilings or are zero.
    InvalidLimits,
    /// Fact contracts are invalid or have a future observation time.
    InvalidFacts,
    /// Logical fact input exceeds the aggregate byte budget.
    FactBudgetExceeded,
    /// A supplied clock is negative or moves backwards.
    InvalidClock,
    /// The bundle is outside its authenticated validity interval.
    BundleNotValid,
    /// CEL parsing failed.
    InvalidExpression,
    /// The expression uses a construct outside the supported subset.
    UnsupportedExpression,
    /// Expression bytes, tokens, or nodes exceed the configured budget.
    ExpressionLimit,
    /// Parentheses or AST nesting exceed the configured depth.
    DepthLimit,
    /// Rule processing exhausted its deterministic cost budget.
    OperationLimit,
    /// Rule processing exceeded its cooperative deadline.
    DeadlineExceeded,
    /// Operands do not have the required types.
    TypeMismatch,
    /// The complete expression does not produce a Boolean.
    NonBoolean,
    /// A referenced fact is missing or its collector reported an error.
    UnavailableFact,
    /// Too many distinct facts were referenced by one rule.
    EvidenceLimit,
}

impl fmt::Display for EvaluationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rule evaluation failed: {self:?}")
    }
}
impl std::error::Error for EvaluationError {}

/// Distinguishes a evaluated non-match from unavailable data and rule failures.
#[derive(Debug)]
pub enum RuleOutcome {
    /// A rule matched and produced a deliverable finding.
    Match(Box<Finding>),
    /// The well-typed rule successfully evaluated to false.
    NoMatch,
    /// A required fact is missing or came from a failed/partial collector.
    Unavailable,
    /// The rule could not be compiled or evaluated safely.
    Failed(EvaluationError),
}

/// One result, preserving authenticated rule order and identity.
#[derive(Debug)]
pub struct RuleResult {
    /// Rule that was evaluated.
    pub rule_id: Identifier,
    /// Outcome, including explicit failure or unavailable-data status.
    pub outcome: RuleOutcome,
    /// Deterministic charged operations, including type checking and comparisons.
    pub operations: u64,
}

/// Results from a single immutable fact snapshot.
#[derive(Debug)]
pub struct EvaluationReport {
    /// Scan used for this report.
    pub scan_id: Identifier,
    /// Whether any collector reported an error in this snapshot.
    pub partial_collection: bool,
    /// One result per authenticated rule; one failure does not discard others.
    pub results: Vec<RuleResult>,
}

/// Evaluates the documented CEL subset against immutable, typed facts.
pub struct Evaluator {
    limits: ResourceLimits,
}

impl Evaluator {
    /// Constructs an evaluator. Limits may tighten, but never exceed, V1 ceilings.
    pub fn new(limits: ResourceLimits) -> Result<Self, EvaluationError> {
        crate::parsing::validate_limits(limits).map_err(|_| EvaluationError::InvalidLimits)?;
        let ceiling = ResourceLimits::V1;
        for (actual, maximum) in [
            (
                limits.expression_depth as u64,
                ceiling.expression_depth as u64,
            ),
            (
                limits.expression_nodes as u64,
                ceiling.expression_nodes as u64,
            ),
            (
                limits.fact_input_bytes as u64,
                ceiling.fact_input_bytes as u64,
            ),
            (limits.facts_per_scan as u64, ceiling.facts_per_scan as u64),
            (
                limits.evidence_per_finding as u64,
                ceiling.evidence_per_finding as u64,
            ),
            (limits.evaluation_operations, ceiling.evaluation_operations),
            (
                limits.evaluation_milliseconds,
                ceiling.evaluation_milliseconds,
            ),
        ] {
            if actual == 0 || actual > maximum {
                return Err(EvaluationError::InvalidLimits);
            }
        }
        Ok(Self { limits })
    }

    /// Evaluates only loader-created verified rules. The clocks are host policy,
    /// never CEL variables. Each rule gets an independent cost/time budget.
    /// Fact validation failures reject the scan; individual rule failures remain
    /// visible in the report without preventing unrelated rules from running.
    pub fn evaluate(
        &self,
        verified: &VerifiedRuleSet,
        facts: &FactSet,
        agent_id: &Identifier,
        clock: &impl EvaluationClock,
    ) -> Result<EvaluationReport, EvaluationError> {
        let now = clock.unix_ms();
        check_validity(verified, now)?;
        if facts.collected_at_unix_ms > now {
            return Err(EvaluationError::InvalidFacts);
        }
        let view = Facts::new(facts, self.limits)?;
        // A bundle loaded under looser limits must still satisfy this evaluator's limits.
        verified
            .rules()
            .validate(self.limits)
            .map_err(|_| EvaluationError::InvalidExpression)?;
        let mut results = Vec::new();
        for rule in &verified.rules().rules {
            let mut budget = Meter::new(clock, verified, self.limits);
            let evaluated = subset::evaluate(&rule.expression, &view, &mut budget);
            let outcome = match evaluated {
                Ok((true, evidence)) => {
                    let finding = make_finding(verified, facts, agent_id, rule, evidence);
                    match budget.charge(0) {
                        Ok(()) => RuleOutcome::Match(Box::new(finding)),
                        Err(error) => RuleOutcome::Failed(error),
                    }
                }
                Ok((false, _)) => RuleOutcome::NoMatch,
                Err(EvaluationError::UnavailableFact) => RuleOutcome::Unavailable,
                Err(error) => RuleOutcome::Failed(error),
            };
            results.push(RuleResult {
                rule_id: rule.id.clone(),
                outcome,
                operations: budget.used,
            });
        }
        Ok(EvaluationReport {
            scan_id: facts.scan_id.clone(),
            partial_collection: !facts.errors.is_empty(),
            results,
        })
    }
}

pub(crate) struct Facts<'a> {
    values: BTreeMap<&'a str, &'a Fact>,
    failed_sources: BTreeSet<&'a str>,
}

impl<'a> Facts<'a> {
    fn new(facts: &'a FactSet, limits: ResourceLimits) -> Result<Self, EvaluationError> {
        // Check logical allocation sizes before creating indexes or validating with
        // the contracts' duplicate-key set. No input values are cloned.
        if facts.facts.len() > limits.facts_per_scan || facts.errors.len() > limits.list_items {
            return Err(EvaluationError::InvalidFacts);
        }
        let mut remaining = limits.fact_input_bytes;
        let mut charge = |length: usize| -> Result<(), EvaluationError> {
            remaining = remaining
                .checked_sub(length)
                .ok_or(EvaluationError::FactBudgetExceeded)?;
            Ok(())
        };
        charge(facts.scan_id.as_str().len())?;
        for fact in &facts.facts {
            charge(fact.key.as_str().len())?;
            charge(fact.source.as_str().len())?;
            match &fact.value {
                FactValue::Boolean(_) => charge(1)?,
                FactValue::Integer(_) => charge(8)?,
                FactValue::String(value) => charge(value.len())?,
                FactValue::StringList(values) => {
                    if values.len() > limits.list_items {
                        return Err(EvaluationError::InvalidFacts);
                    }
                    for value in values {
                        charge(value.len())?;
                    }
                }
            }
        }
        for error in &facts.errors {
            charge(error.collector.as_str().len())?;
            charge(error.message.len())?;
        }
        facts
            .validate(limits)
            .map_err(|_| EvaluationError::InvalidFacts)?;
        Ok(Self {
            values: facts
                .facts
                .iter()
                .map(|fact| (fact.key.as_str(), fact))
                .collect(),
            failed_sources: facts
                .errors
                .iter()
                .map(|error| error.collector.as_str())
                .collect(),
        })
    }

    pub(crate) fn get(&self, key: &str) -> Result<&'a Fact, EvaluationError> {
        let fact = self
            .values
            .get(key)
            .ok_or(EvaluationError::UnavailableFact)?;
        if self.failed_sources.contains(fact.source.as_str()) {
            return Err(EvaluationError::UnavailableFact);
        }
        Ok(fact)
    }
}

pub(crate) struct Meter<'a, C> {
    clock: &'a C,
    bundle: &'a VerifiedRuleSet,
    start: Duration,
    last: Duration,
    last_unix_ms: i64,
    pub(crate) limits: ResourceLimits,
    used: u64,
}

impl<'a, C: EvaluationClock> Meter<'a, C> {
    fn new(clock: &'a C, bundle: &'a VerifiedRuleSet, limits: ResourceLimits) -> Self {
        let start = clock.elapsed();
        Self {
            clock,
            bundle,
            start,
            last: start,
            last_unix_ms: clock.unix_ms(),
            limits,
            used: 0,
        }
    }

    pub(crate) fn charge(&mut self, operations: u64) -> Result<(), EvaluationError> {
        let elapsed = self.clock.elapsed();
        let unix_ms = self.clock.unix_ms();
        if elapsed < self.last || unix_ms < self.last_unix_ms {
            return Err(EvaluationError::InvalidClock);
        }
        self.last = elapsed;
        self.last_unix_ms = unix_ms;
        check_validity(self.bundle, unix_ms)?;
        if elapsed.saturating_sub(self.start)
            >= Duration::from_millis(self.limits.evaluation_milliseconds)
        {
            return Err(EvaluationError::DeadlineExceeded);
        }
        if operations > self.limits.evaluation_operations - self.used {
            return Err(EvaluationError::OperationLimit);
        }
        self.used += operations;
        Ok(())
    }
}

fn check_validity(bundle: &VerifiedRuleSet, now: i64) -> Result<(), EvaluationError> {
    if now < 0 {
        return Err(EvaluationError::InvalidClock);
    }
    if now < bundle.created_at_unix_ms() || now >= bundle.expires_at_unix_ms() {
        return Err(EvaluationError::BundleNotValid);
    }
    Ok(())
}

fn make_finding(
    bundle: &VerifiedRuleSet,
    facts: &FactSet,
    agent_id: &Identifier,
    rule: &Rule,
    evidence: Vec<Identifier>,
) -> Finding {
    let mut digest = Sha256::new();
    digest.update(b"OVSVMS-FINDING-V1\0");
    for field in [
        agent_id.as_str(),
        facts.scan_id.as_str(),
        bundle.accepted_version().rule_set_id().as_str(),
        rule.id.as_str(),
    ] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field.as_bytes());
    }
    digest.update(bundle.accepted_version().preimage_sha256());
    digest.update(rule.version.to_be_bytes());
    let hex: String = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Finding {
        schema_version: SchemaVersion::V1,
        finding_id: Identifier::new(format!("finding.{hex}"))
            .expect("fixed ASCII hash fits identifier contract"),
        scan_id: facts.scan_id.clone(),
        rule_id: rule.id.clone(),
        rule_version: rule.version,
        observed_at_unix_ms: facts.collected_at_unix_ms,
        severity: rule.severity,
        confidence: rule.confidence,
        message: rule.finding_message.clone(),
        evidence,
    }
}
