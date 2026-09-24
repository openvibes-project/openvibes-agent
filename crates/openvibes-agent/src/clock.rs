//! Clock-jump detection. All times are UTC (Unix milliseconds), so a timezone
//! or daylight-saving change never moves them; only setting the system clock
//! does. The monotonic clock cannot be set, so a wall-clock move that the
//! monotonic clock did not witness is a jump.

use std::time::Instant;

/// Wall and monotonic progress may differ by this much before it counts as
/// a jump; NTP corrections are seconds.
pub(crate) const JUMP_TOLERANCE_MS: i64 = 5 * 60 * 1_000;

/// Tracks how far the wall clock has jumped ahead of the time the agent
/// actually witnessed.
#[derive(Debug, Default)]
pub(crate) struct ClockGuard {
    last: Option<(i64, Instant)>,
    skew_ms: i64,
}

impl ClockGuard {
    /// Observes wall time `now_ms` at monotonic instant `at`. Returns the
    /// jump (positive: forward) when wall and monotonic progress differ by
    /// more than [`JUMP_TOLERANCE_MS`].
    pub(crate) fn observe(&mut self, now_ms: i64, at: Instant) -> Option<i64> {
        let jump = self
            .last
            .map(|(wall, monotonic)| {
                let witnessed = i64::try_from(at.saturating_duration_since(monotonic).as_millis())
                    .unwrap_or(i64::MAX);
                now_ms.saturating_sub(wall).saturating_sub(witnessed)
            })
            .filter(|jump| jump.abs() > JUMP_TOLERANCE_MS);
        if let Some(jump) = jump {
            self.skew_ms = self.skew_ms.saturating_add(jump).max(0);
        }
        self.last = Some((now_ms, at));
        jump
    }

    /// Accumulated forward skew, never negative: data-losing decisions
    /// (pruning, dropping an expired identity) subtract it from wall time.
    pub(crate) fn skew_ms(&self) -> i64 {
        self.skew_ms
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::{ClockGuard, JUMP_TOLERANCE_MS};

    const MINUTE: i64 = 60_000;
    const DAY: i64 = 86_400_000;

    #[test]
    fn steady_time_and_small_corrections_are_not_jumps() {
        let start = Instant::now();
        let mut guard = ClockGuard::default();
        assert_eq!(guard.observe(1_000_000, start), None, "first observation");
        let later = start + Duration::from_secs(60);
        assert_eq!(guard.observe(1_000_000 + MINUTE, later), None);
        // NTP nudges the wall clock 30 s ahead: well inside the tolerance.
        let later = later + Duration::from_secs(60);
        assert_eq!(guard.observe(1_000_000 + 2 * MINUTE + 30_000, later), None);
        assert_eq!(guard.skew_ms(), 0);
    }

    #[test]
    fn a_forward_jump_accumulates_skew_and_a_backward_one_undoes_it() {
        let start = Instant::now();
        let mut guard = ClockGuard::default();
        guard.observe(0, start);
        let jump = guard
            .observe(40 * DAY, start + Duration::from_secs(60))
            .unwrap();
        assert!((jump - (40 * DAY - MINUTE)).abs() < 1_000, "{jump}");
        assert!((guard.skew_ms() - jump).abs() == 0);
        // The operator sets the clock back: the skew returns to zero, never
        // below (a backward jump must not prune new findings early).
        guard.observe(2 * MINUTE, start + Duration::from_secs(120));
        assert_eq!(guard.skew_ms(), 0);
        guard.observe(-50 * DAY, start + Duration::from_secs(180));
        assert_eq!(guard.skew_ms(), 0);
    }

    #[test]
    fn the_tolerance_is_five_minutes() {
        let start = Instant::now();
        let mut guard = ClockGuard::default();
        guard.observe(0, start);
        assert_eq!(
            guard.observe(4 * MINUTE, start),
            None,
            "4 minutes: tolerated"
        );
        let jump = guard.observe(10 * MINUTE, start);
        assert_eq!(jump, Some(6 * MINUTE), "6 more minutes: a jump");
        assert_eq!(JUMP_TOLERANCE_MS, 5 * MINUTE);
    }
}
