//! The health report each heartbeat carries (protocol P12): assembled from
//! the queue, the last scan, the rule sets, and the service's own counts.

use openvibes_core::{
    Health, Identifier, QueueHealth, ResourceLimits, RuleSetHealth, ScanHealth, Validate,
};
use openvibes_storage::QueueStats;

/// The report, or `None` when it would be invalid: the heartbeat then goes
/// without it rather than be refused.
pub(crate) fn assemble(
    stats: &QueueStats,
    max_bytes: u64,
    last_scan: Option<&ScanHealth>,
    rule_sets: &[RuleSetHealth],
    storage_errors: u64,
    clock_jump_ms: Option<i64>,
    now_unix_ms: i64,
) -> Option<Health> {
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
        clock_jump_s: clock_jump_ms.map(|jump| jump / 1000),
    };
    health
        .validate(ResourceLimits::V1)
        .is_ok()
        .then_some(health)
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
        let health = assemble(&stats(), 1 << 28, None, &[], 1, Some(-400_000), 61_000).unwrap();
        assert_eq!(health.queue.oldest_pending_age_s, Some(60));
        assert_eq!(health.queue.dropped_total, 3);
        assert_eq!(health.storage_errors, 1);
        assert_eq!(health.clock_jump_s, Some(-400));
    }

    #[test]
    fn an_invalid_health_report_is_left_out() {
        let sets: Vec<RuleSetHealth> = (0..70)
            .map(|n| RuleSetHealth {
                id: Identifier::new(format!("set-{n}")).unwrap(),
                version: Some(1),
                expires_at_unix_ms: Some(1),
                refused: Some(BundleRefusal::Invalid),
            })
            .collect();
        assert!(assemble(&stats(), 1 << 28, None, &sets, 0, None, 0).is_none());
    }
}
