//! Evaluate, collapse and build alarms (pure).
//!
//! Order per event: evaluate on unmasked values → mask → cap → collapse.

use std::{collections::HashMap, sync::Arc, time::Instant};

use openvibes_collectors::process_events::{ProcessStart, Seeded};
use openvibes_core::{ALARM_BYTES, Alarm, AlarmProcess, Identifier, mask_args};
use openvibes_rules::{CompiledEventRules, EvaluationClock, VerifiedRuleSet};
use sha2::{Digest, Sha256};

use super::table::{Lineage, ProcessTable};

/// A verified bundle and its compiled `process_event` rules, kept together
/// so they cannot drift.
pub type RulePair = (Arc<VerifiedRuleSet>, Arc<CompiledEventRules>);

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
        let mut masked_cmdline = None;
        for (bundle, compiled) in rules {
            for outcome in compiled.evaluate(bundle, &event, clock) {
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
                let cmdline = masked_cmdline.get_or_insert_with(|| {
                    let args: Vec<String> = start
                        .args
                        .iter()
                        .map(|arg| String::from_utf8_lossy(arg).into_owned())
                        .collect();
                    mask_args(&lineage.process.exe, &args).join(" ")
                });
                let key = collapse_key(
                    bundle.accepted_version().rule_set_id(),
                    &rule.id,
                    &lineage,
                    cmdline,
                );
                let at = start.at_unix_ms;
                let Some((alarm_id, first_seen, count)) = self.collapse(key, at, &mut new_id)
                else {
                    self.lost += 1;
                    continue;
                };
                let (process, ancestors) = lineage.to_alarm_processes();
                let mut alarm = Alarm {
                    alarm_id,
                    rule_set_id: bundle.accepted_version().rule_set_id().clone(),
                    rule_set_version: bundle.accepted_version().version(),
                    rule_id: rule.id.clone(),
                    rule_version: rule.version,
                    severity: rule.severity,
                    confidence: rule.confidence,
                    message: rule.finding_message.clone(),
                    first_seen_unix_ms: first_seen,
                    last_seen_unix_ms: at.max(first_seen),
                    count,
                    process,
                    ancestors,
                };
                fit(&mut alarm);
                alarms.push(alarm);
            }
        }
        alarms
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
