//! Threat alarms (protocol P14): process starts from kernel audit, their
//! lineage, `process_event` rules, and delivery of collapsed, masked
//! alarms.

pub mod engine;
pub mod table;
#[cfg(target_os = "linux")]
pub mod thread;

use std::sync::Arc;

use openvibes_core::{ResourceLimits, RuleKind};
use openvibes_rules::{VerifiedRuleSet, compile_event_rules};

use engine::RulePair;

/// Compiled `process_event` rules of `bundles`, and the counts for health:
/// (rules in use, accepted, refused, accepted without a `programs`
/// prefilter).
#[must_use]
pub fn compile(
    bundles: Vec<VerifiedRuleSet>,
    restricted: impl Fn(&openvibes_core::Identifier) -> bool,
) -> (Vec<RulePair>, u64, u64, u64) {
    let (mut pairs, mut accepted, mut refused, mut unfiltered) = (Vec::new(), 0, 0, 0);
    for bundle in bundles {
        let compiled = compile_event_rules(&bundle, ResourceLimits::V1);
        accepted += compiled.rules() as u64;
        refused += compiled.refused.len() as u64;
        unfiltered += bundle
            .rules()
            .rules
            .iter()
            .filter(|rule| rule.kind == RuleKind::ProcessEvent && rule.programs.is_none())
            .filter(|rule| !compiled.refused.iter().any(|(id, _)| *id == rule.id))
            .count() as u64;
        if compiled.rules() > 0 {
            let restricted = restricted(bundle.accepted_version().rule_set_id());
            pairs.push((Arc::new(bundle), Arc::new(compiled), restricted));
        }
    }
    (pairs, accepted, refused, unfiltered)
}

#[cfg(test)]
mod engine_tests;
#[cfg(test)]
mod table_tests;
