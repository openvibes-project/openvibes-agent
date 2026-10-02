//! Evaluate, collapse and build alarms (pure).
//!
//! Order per event: evaluate on unmasked values (masked for restricted
//! rule sets) → mask → cap → collapse.

use std::{collections::HashMap, sync::Arc, time::Instant};

use openvibes_collectors::process_events::{ProcessStart, Seeded};
use openvibes_core::{
    ALARM_BYTES, Alarm, AlarmProcess, Confidence, EVENT_OPERATIONS, Identifier, Severity, mask_args,
};
use openvibes_rules::{
    CompiledEventRules, EvaluationClock, EventValue, ProcessEvent, VerifiedRuleSet,
};
use sha2::{Digest, Sha256};

use super::table::{CMDLINE_BYTES, Lineage, ProcessTable};

/// A verified bundle and its compiled `process_event` rules, kept together
/// so they cannot drift, and whether its rule set is restricted (the
/// agent's own setting: restricted sets share one budget per start and run
/// after the unrestricted ones).
pub type RulePair = (Arc<VerifiedRuleSet>, Arc<CompiledEventRules>, bool);

/// The rule set of alarms the agent raises itself (contract, P14).
pub const AGENT_RULE_SET: &str = "openvibes-agent";
/// Its rule for a start whose restricted-set budget ran out.
const EVALUATION_CUT: &str = "evaluation.cut";
const EVALUATION_CUT_MESSAGE: &str = "Not every alarm rule was evaluated for this process start; its budget ran out (an unusually long command line can cause this).";

/// Repeats within this long of an alarm's first match collapse into it.
pub const COLLAPSE_WINDOW_MS: i64 = 600_000;
/// Alarms remembered for collapsing; the oldest go first.
pub const COLLAPSE_ENTRIES: usize = 4_096;

struct Collapsed {
    alarm_id: Identifier,
    first_seen: i64,
    count: u32,
}

/// The process table, the collapse state and the rule counters.
#[derive(Default)]
pub struct Engine {
    table: ProcessTable,
    collapse: HashMap<[u8; 32], Collapsed>,
    /// Rule runs that failed (budget, deadline); never an alarm.
    pub failures: u64,
    /// Rule runs a missing value made unavailable.
    pub unavailable: u64,
    /// Matches lost because no alarm id could be made; the caller counts
    /// them as dropped alarms.
    pub lost: u64,
    /// Starts whose restricted rules stopped at the per-start budget
    /// (contract, P14; health `events_budget_cut_total`).
    pub budget_cuts: u64,
    /// Log each start's lineage to stderr (`OPENVIBES_TRACE_STARTS`), to
    /// explain a rule that did not match.
    pub trace: bool,
}

impl Engine {
    /// Records `start` and runs every rule on it. Returns the alarms to
    /// queue: new ones, and repeats carrying their alarm's id with the
    /// grown count. `lookup` reads a missing parent from `/proc`;
    /// `new_id` makes an alarm id; `None` loses the match (counted in
    /// `lost`), since a shared id would merge unrelated alarms.
    pub fn on_start(
        &mut self,
        start: &ProcessStart,
        rules: &[RulePair],
        clock: &impl EvaluationClock,
        now: Instant,
        lookup: impl FnMut(u32) -> Option<Seeded>,
        mut new_id: impl FnMut() -> Option<Identifier>,
    ) -> Vec<Alarm> {
        let (event, lineage) = self.table.start(start, now, lookup);
        if self.trace {
            let parent = lineage.ancestors.first().map_or_else(
                || "none".to_owned(),
                |p| format!("{} ({}, seeded {})", p.name, p.exe, p.seeded),
            );
            eprintln!(
                "openvibes-agent: start pid {} ppid {} exe {} parent {parent}",
                start.pid, start.ppid, lineage.process.exe
            );
        }
        let mut alarms = Vec::new();
        let masked_cmdline = std::cell::OnceCell::new();
        let cmdline = || {
            masked_cmdline
                .get_or_init(|| {
                    let args: Vec<String> = start
                        .args
                        .iter()
                        .map(|arg| String::from_utf8_lossy(arg).into_owned())
                        .collect();
                    mask_args(&lineage.process.exe, &args).join(" ")
                })
                .clone()
        };
        // Unrestricted sets keep each rule's own limit only; the restricted
        // ones (after them) share one budget for this start.
        let mut budget = EVENT_OPERATIONS;
        let mut cut = false;
        let ordered = rules
            .iter()
            .filter(|pair| !pair.2)
            .chain(rules.iter().filter(|pair| pair.2));
        // Restricted sets see the command lines masked (contract P14), built
        // once and only when a restricted rule's prefilter names the start.
        let masked_event = std::cell::OnceCell::new();
        for (bundle, compiled, restricted) in ordered {
            if cut {
                break;
            }
            let outcomes = if *restricted {
                if !compiled.names(&event) {
                    continue;
                }
                let masked = masked_event.get_or_init(|| masked(&event, &cmdline(), &lineage));
                let (outcomes, spent) =
                    compiled.evaluate_within(bundle, masked, clock, &mut budget);
                cut = spent;
                outcomes
            } else {
                compiled.evaluate(bundle, &event, clock)
            };
            for outcome in outcomes {
                if outcome.failure.is_some() {
                    self.failures += 1;
                }
                if outcome.unavailable {
                    self.unavailable += 1;
                }
                if !outcome.matched {
                    continue;
                }
                let Some(rule) = bundle
                    .rules()
                    .rules
                    .iter()
                    .find(|rule| rule.id == outcome.rule_id)
                else {
                    continue;
                };
                let set = bundle.accepted_version();
                let key = collapse_key(set.rule_set_id(), &rule.id, &lineage, &cmdline());
                let raised = self.raise(
                    key,
                    start.at_unix_ms,
                    &lineage,
                    &mut new_id,
                    Template {
                        rule_set_id: set.rule_set_id().clone(),
                        rule_set_version: set.version(),
                        rule_id: rule.id.clone(),
                        rule_version: rule.version,
                        severity: rule.severity,
                        confidence: rule.confidence,
                        message: rule.finding_message.clone(),
                    },
                );
                alarms.extend(raised);
            }
        }
        if cut {
            self.budget_cuts += 1;
            // A signal, not only a counter: the start that spent the budget
            // is the one worth a look. Collapsed without the command line,
            // so a loop that varies its padding is one counted alarm.
            let rule_set = Identifier::new(AGENT_RULE_SET).expect("static id");
            let rule = Identifier::new(EVALUATION_CUT).expect("static id");
            let key = collapse_key(&rule_set, &rule, &lineage, "");
            let raised = self.raise(
                key,
                start.at_unix_ms,
                &lineage,
                &mut new_id,
                Template {
                    rule_set_id: rule_set,
                    rule_set_version: 1,
                    rule_id: rule,
                    rule_version: 1,
                    severity: Severity::Low,
                    confidence: Confidence::new(50).expect("in range"),
                    message: EVALUATION_CUT_MESSAGE.to_owned(),
                },
            );
            alarms.extend(raised);
        }
        alarms
    }

    /// Collapses a match into an alarm: a new one, or the earlier one with a
    /// grown count. `None` when no alarm id could be made (counted in
    /// `lost`).
    fn raise(
        &mut self,
        key: [u8; 32],
        at: i64,
        lineage: &Lineage,
        new_id: &mut impl FnMut() -> Option<Identifier>,
        template: Template,
    ) -> Option<Alarm> {
        let Some((alarm_id, first_seen, count)) = self.collapse(key, at, new_id) else {
            self.lost += 1;
            return None;
        };
        let (process, ancestors) = lineage.to_alarm_processes();
        let mut alarm = Alarm {
            alarm_id,
            rule_set_id: template.rule_set_id,
            rule_set_version: template.rule_set_version,
            rule_id: template.rule_id,
            rule_version: template.rule_version,
            severity: template.severity,
            confidence: template.confidence,
            message: template.message,
            first_seen_unix_ms: first_seen,
            last_seen_unix_ms: at.max(first_seen),
            count,
            process,
            ancestors,
        };
        fit(&mut alarm);
        Some(alarm)
    }

    /// Marks exited processes; see [`ProcessTable::reap`].
    pub fn reap(&mut self, alive: impl Fn(u32) -> bool, now: Instant) {
        self.table.reap(alive, now);
    }

    fn collapse(
        &mut self,
        key: [u8; 32],
        at: i64,
        new_id: &mut impl FnMut() -> Option<Identifier>,
    ) -> Option<(Identifier, i64, u32)> {
        if let Some(seen) = self.collapse.get_mut(&key)
            && (0..=COLLAPSE_WINDOW_MS).contains(&at.saturating_sub(seen.first_seen))
        {
            seen.count = seen.count.saturating_add(1).min(i32::MAX.unsigned_abs());
            return Some((seen.alarm_id.clone(), seen.first_seen, seen.count));
        }
        if self.collapse.len() >= COLLAPSE_ENTRIES {
            self.collapse
                .retain(|_, seen| at.saturating_sub(seen.first_seen) <= COLLAPSE_WINDOW_MS);
        }
        if self.collapse.len() >= COLLAPSE_ENTRIES
            && let Some(oldest) = self
                .collapse
                .iter()
                .min_by_key(|(_, seen)| seen.first_seen)
                .map(|(key, _)| *key)
        {
            self.collapse.remove(&oldest);
        }
        let alarm_id = new_id()?;
        self.collapse.insert(
            key,
            Collapsed {
                alarm_id: alarm_id.clone(),
                first_seen: at,
                count: 1,
            },
        );
        Some((alarm_id, at, 1))
    }
}

/// SHA-256 over the length-prefixed collapse key fields: rule set, rule,
/// `process.exe`, `parent.exe` ("" without a parent), masked command line.
/// What an alarm takes from its rule (or the agent's own rule).
struct Template {
    rule_set_id: Identifier,
    rule_set_version: u64,
    rule_id: Identifier,
    rule_version: u64,
    severity: Severity,
    confidence: Confidence,
    message: String,
}

/// `event` with `process.cmdline` and `parent.cmdline` masked: `cmdline`
/// is the start's own, masked from all its arguments; the parent's is
/// masked from the arguments its entry keeps, as the event's own is built.
fn masked(event: &ProcessEvent, cmdline: &str, lineage: &Lineage) -> ProcessEvent {
    let mut event = event.clone();
    // Masking replaces a secret by a fixed mark, so a line can grow a
    // little; one over the binding's bound is cut like an unmasked one.
    let mut set = |key: &str, mut text: String| {
        if text.len() > CMDLINE_BYTES {
            let mut end = CMDLINE_BYTES;
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            text.truncate(end);
        }
        let _ = event.set(key, EventValue::String(text));
    };
    set("process.cmdline", cmdline.to_owned());
    if let Some(parent) = lineage.ancestors.first() {
        set("parent.cmdline", parent.masked_args().join(" "));
    }
    event
}

fn collapse_key(
    rule_set: &Identifier,
    rule: &Identifier,
    lineage: &Lineage,
    cmdline: &str,
) -> [u8; 32] {
    let parent = lineage.ancestors.first().map_or("", |p| p.exe.as_str());
    let mut hash = Sha256::new();
    for field in [
        rule_set.as_str(),
        rule.as_str(),
        &lineage.process.exe,
        parent,
        cmdline,
    ] {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field.as_bytes());
    }
    hash.finalize().into()
}

fn serialized_len(alarm: &Alarm) -> usize {
    serde_json::to_vec(alarm).map_or(usize::MAX, |bytes| bytes.len())
}

/// Cuts an alarm to [`ALARM_BYTES`] serialized: the farthest ancestor's
/// arguments first, then nearer ones, then the process's own, then whole
/// ancestors from the farthest.
fn fit(alarm: &mut Alarm) {
    let clear = |process: &mut AlarmProcess| {
        process.args.clear();
        process.truncated = true;
    };
    for i in (0..alarm.ancestors.len()).rev() {
        if serialized_len(alarm) <= ALARM_BYTES {
            return;
        }
        clear(&mut alarm.ancestors[i]);
    }
    if serialized_len(alarm) > ALARM_BYTES {
        clear(&mut alarm.process);
    }
    while serialized_len(alarm) > ALARM_BYTES && alarm.ancestors.pop().is_some() {}
}
