//! The health report each heartbeat carries (protocol P12): assembled from
//! the queue, the last scan, the rule sets, and the service's own counts.

use openvibes_core::{
    HEALTH_MAX_COLLECTORS, HEALTH_MAX_REASONS, HEALTH_MAX_RULE_SETS, Health, Identifier,
    QueueHealth, ResourceLimits, RuleSetHealth, ScanHealth, Validate,
};
use openvibes_storage::QueueStats;

/// How long a detected clock jump stays in the report.
const CLOCK_JUMP_REPORT_MS: i64 = 3_600_000;

/// The report, with each part that would make it invalid left out, and
/// what was left out (for the log). One bad field no longer drops the whole
/// report, which left the platform showing an old one without a word (#66).
/// `None` only if it is still invalid after that; the heartbeat then goes
/// without it rather than be refused.
pub(crate) fn assemble(
    stats: &QueueStats,
    max_bytes: u64,
    last_scan: Option<&ScanHealth>,
    rule_sets: &[RuleSetHealth],
    storage_errors: u64,
    clock_jump: Option<(i64, i64)>,
    now_unix_ms: i64,
) -> (Option<Health>, Vec<String>) {
    // A jump is reported for an hour after it was seen (jump, seen at), so
    // one correction at boot or after a resume does not flag the agent for
    // as long as it runs.
    let clock_jump_s = clock_jump
        .filter(|(_, seen)| now_unix_ms.saturating_sub(*seen) <= CLOCK_JUMP_REPORT_MS)
        .map(|(jump, _)| jump / 1000);
    let health = Health {
        queue: QueueHealth {
            pending: stats.pending,
            oldest_pending_age_s: stats.oldest_enqueued_at_ms.map(|oldest| {
                (now_unix_ms.saturating_sub(oldest) / 1000)
                    .max(0)
                    .unsigned_abs()
            }),
            bytes: stats.bytes,
            max_bytes,
            dropped_total: stats.dropped_total,
            rejected_total: stats
                .rejected_total
                .iter()
                .filter_map(|(reason, count)| Some((Identifier::new(reason).ok()?, *count)))
                .collect(),
        },
        last_scan: last_scan.cloned(),
        rule_sets: rule_sets.to_vec(),
        storage_errors,
        clock_jump_s,
        matches_truncated: None,
        alarms: None,
    };
    let mut health = health;
    let left_out = fit(&mut health);
    match health.validate(ResourceLimits::V1) {
        Ok(()) => (Some(health), left_out),
        Err(error) => {
            let mut left_out = left_out;
            left_out.push(format!("the whole report ({error})"));
            (None, left_out)
        }
    }
}

/// Leaves out what `Health::validate` would refuse: extra list entries, a
/// timestamp out of range, a version 0. Returns what it left out.
fn fit(health: &mut Health) -> Vec<String> {
    let mut left_out = Vec::new();
    if health.queue.rejected_total.len() > HEALTH_MAX_REASONS {
        health.queue.rejected_total = std::mem::take(&mut health.queue.rejected_total)
            .into_iter()
            .take(HEALTH_MAX_REASONS)
            .collect();
        left_out.push(format!("rejection reasons beyond {HEALTH_MAX_REASONS}"));
    }
    if health.rule_sets.len() > HEALTH_MAX_RULE_SETS {
        health.rule_sets.truncate(HEALTH_MAX_RULE_SETS);
        left_out.push(format!("rule sets beyond {HEALTH_MAX_RULE_SETS}"));
    }
    if let Some(scan) = &mut health.last_scan {
        if scan.collectors.len() > HEALTH_MAX_COLLECTORS {
            scan.collectors = std::mem::take(&mut scan.collectors)
                .into_iter()
                .take(HEALTH_MAX_COLLECTORS)
                .collect();
            left_out.push(format!("collectors beyond {HEALTH_MAX_COLLECTORS}"));
        }
        // Timestamps are non-negative Unix milliseconds (the contract's rule).
        if scan.finished_at_unix_ms < 0 {
            health.last_scan = None;
            left_out.push("the last scan (its time)".into());
        }
    }
    for set in &mut health.rule_sets {
        if set.version == Some(0) {
            set.version = None;
            left_out.push(format!("rule set {}: version 0", set.id.as_str()));
        }
        if set.expires_at_unix_ms.is_some_and(|at| at < 0) {
            set.expires_at_unix_ms = None;
            left_out.push(format!("rule set {}: expiry", set.id.as_str()));
        }
    }
    left_out
}

#[cfg(test)]
mod tests {
    use openvibes_core::{BundleRefusal, Identifier, RuleSetHealth};
    use openvibes_storage::QueueStats;

    use super::assemble;

    fn stats() -> QueueStats {
        QueueStats {
            pending: 2,
            oldest_enqueued_at_ms: Some(1_000),
            bytes: 4_096,
            dropped_total: 3,
            ..QueueStats::default()
        }
    }

    #[test]
    fn the_report_reflects_the_queue_and_clock() {
        let health = assemble(
            &stats(),
            1 << 28,
            None,
            &[],
            1,
            Some((-400_000, 60_000)),
            61_000,
        )
        .0
        .unwrap();
        assert_eq!(health.queue.oldest_pending_age_s, Some(60));
        assert_eq!(health.queue.dropped_total, 3);
        assert_eq!(health.storage_errors, 1);
        assert_eq!(health.clock_jump_s, Some(-400));
    }

    #[test]
    fn a_clock_jump_is_reported_for_an_hour() {
        let seen = 1_000_000;
        let jump = Some((-400_000, seen));
        let at = |now| {
            assemble(&stats(), 1 << 28, None, &[], 0, jump, now)
                .0
                .unwrap()
                .clock_jump_s
        };
        assert_eq!(at(seen + 3_599_000), Some(-400));
        assert_eq!(at(seen + 3_600_001), None, "an old jump ages out");
    }

    #[test]
    fn an_invalid_part_is_left_out_and_the_rest_is_sent() {
        // Board #66: one bad field used to drop the whole report, so the
        // platform kept an old one forever without a word.
        let sets: Vec<RuleSetHealth> = (0..70)
            .map(|n| RuleSetHealth {
                id: Identifier::new(format!("set-{n}")).unwrap(),
                version: Some(if n == 0 { 0 } else { 1 }),
                expires_at_unix_ms: Some(if n == 1 { -5 } else { 1 }),
                refused: Some(BundleRefusal::Invalid),
            })
            .collect();
        let (health, left_out) = assemble(&stats(), 1 << 28, None, &sets, 2, None, 0);
        let health = health.expect("the rest is still sent");
        assert_eq!(health.rule_sets.len(), 64, "only the first 64 rule sets");
        assert_eq!(health.rule_sets[0].version, None, "a version 0 is left out");
        assert_eq!(
            health.rule_sets[1].expires_at_unix_ms, None,
            "a bad expiry is left out"
        );
        assert_eq!(health.storage_errors, 2, "the rest is kept");
        assert_eq!(
            left_out,
            [
                "rule sets beyond 64",
                "rule set set-0: version 0",
                "rule set set-1: expiry"
            ]
        );
    }

    #[test]
    fn a_valid_report_leaves_nothing_out() {
        let (health, left_out) = assemble(&stats(), 1 << 28, None, &[], 0, None, 0);
        assert!(health.is_some());
        assert!(left_out.is_empty());
    }
}
