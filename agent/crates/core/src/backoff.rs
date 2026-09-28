//! Retry delays: exponential backoff with full jitter, `Retry-After`
//! handling, and the heartbeat interval clamp (protocol types review gate).

use std::time::Duration;

/// Uniform random fraction in `[0, 1)` from the OS generator. Falls back to
/// `0.5` if it is unavailable (jitter is not a security property).
pub(crate) fn random_fraction() -> f64 {
    #[allow(
        clippy::cast_precision_loss,
        reason = "53 random bits fit exactly in an f64 mantissa"
    )]
    getrandom::u64().map_or(0.5, |r| (r >> 11) as f64 / (1u64 << 53) as f64)
}

/// Exponential backoff policy.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Backoff {
    pub(crate) base: Duration,
    pub(crate) max: Duration,
}

impl Backoff {
    /// Default policy for console requests: 1 s doubling up to 5 min.
    pub(crate) const CONSOLE: Self = Self {
        base: Duration::from_secs(1),
        max: Duration::from_secs(300),
    };

    /// Upper bound of the delay before retry number `attempt` (0-based).
    pub(crate) fn ceiling(&self, attempt: u32) -> Duration {
        let factor = 1u32.checked_shl(attempt.min(30)).unwrap_or(u32::MAX);
        self.base.saturating_mul(factor).min(self.max)
    }

    /// Full jitter: uniform in `[0, ceiling(attempt)]`, at least 100 ms.
    /// `fraction` is in `[0, 1)`.
    pub(crate) fn delay(&self, attempt: u32, fraction: f64) -> Duration {
        self.ceiling(attempt)
            .mul_f64(fraction.clamp(0.0, 1.0))
            .max(Duration::from_millis(100))
    }
}

/// Bounds of `Retry-After` (contract: 1..=3600 s).
const RETRY_AFTER_MAX_S: u64 = 3600;

/// Parses a `Retry-After` header value in seconds (the contract only uses
/// the delta-seconds form). Out-of-range values are clamped to `1..=3600`.
pub(crate) fn parse_retry_after(value: &str) -> Option<Duration> {
    let secs: u64 = value.trim().parse().ok()?;
    Some(Duration::from_secs(secs.clamp(1, RETRY_AFTER_MAX_S)))
}

/// Delay honoring `Retry-After` plus up to 20 % jitter (at most 30 s), so
/// that agents told the same delay do not retry in lockstep.
pub(crate) fn retry_after_delay(retry_after: Duration, fraction: f64) -> Duration {
    let jitter = retry_after
        .mul_f64(0.2)
        .min(Duration::from_secs(30))
        .mul_f64(fraction.clamp(0.0, 1.0));
    retry_after + jitter
}

/// Heartbeat interval bounds (contract `HeartbeatIntervalSeconds`).
pub(crate) const HEARTBEAT_MIN_S: i64 = 10;
/// Upper bound: a longer interval would make the agent look silent.
pub(crate) const HEARTBEAT_MAX_S: i64 = 300;
/// Interval used before the console provides one.
pub(crate) const HEARTBEAT_DEFAULT_S: u64 = 30;

/// Gate: a console-provided `heartbeat_interval_s` is clamped to
/// `[10, 300]`; a value `<= 0` is rejected (`None`: keep the previous
/// interval), so the console can cause neither a hot loop nor a silent
/// agent.
pub(crate) fn clamp_heartbeat_interval(value: i64) -> Option<u64> {
    if value <= 0 {
        return None;
    }
    u64::try_from(value.clamp(HEARTBEAT_MIN_S, HEARTBEAT_MAX_S)).ok()
}

/// Interval of the slow retry after a fatal `401` (15 min, 0 to 60 s jitter).
pub(crate) fn unauthorized_retry_delay(fraction: f64) -> Duration {
    Duration::from_secs(15 * 60) + Duration::from_secs(60).mul_f64(fraction.clamp(0.0, 1.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ceiling_doubles_and_caps() {
        let b = Backoff::CONSOLE;
        assert_eq!(b.ceiling(0), Duration::from_secs(1));
        assert_eq!(b.ceiling(1), Duration::from_secs(2));
        assert_eq!(b.ceiling(5), Duration::from_secs(32));
        assert_eq!(b.ceiling(9), Duration::from_secs(300));
        assert_eq!(b.ceiling(u32::MAX), Duration::from_secs(300));
    }

    #[test]
    fn jittered_delay_stays_within_bounds() {
        let b = Backoff::CONSOLE;
        for attempt in 0..40 {
            for _ in 0..50 {
                let d = b.delay(attempt, random_fraction());
                assert!(d >= Duration::from_millis(100));
                assert!(d <= b.ceiling(attempt).max(Duration::from_millis(100)));
            }
        }
        assert_eq!(b.delay(3, 0.0), Duration::from_millis(100));
        assert_eq!(b.delay(3, 1.0), Duration::from_secs(8));
        assert_eq!(b.delay(3, 7.0), Duration::from_secs(8));
    }

    #[test]
    fn random_fraction_is_in_unit_interval() {
        for _ in 0..1000 {
            let f = random_fraction();
            assert!((0.0..1.0).contains(&f));
        }
    }

    #[test]
    fn retry_after_is_parsed_and_clamped() {
        assert_eq!(parse_retry_after("7"), Some(Duration::from_secs(7)));
        assert_eq!(parse_retry_after(" 0 "), Some(Duration::from_secs(1)));
        assert_eq!(parse_retry_after("999999"), Some(Duration::from_secs(3600)));
        assert_eq!(parse_retry_after("-1"), None);
        assert_eq!(parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT"), None);
    }

    #[test]
    fn retry_after_delay_adds_bounded_jitter() {
        let ra = Duration::from_secs(10);
        assert_eq!(retry_after_delay(ra, 0.0), ra);
        assert_eq!(retry_after_delay(ra, 1.0), Duration::from_secs(12));
        let big = Duration::from_secs(3600);
        assert_eq!(retry_after_delay(big, 1.0), big + Duration::from_secs(30));
        for _ in 0..100 {
            let d = retry_after_delay(ra, random_fraction());
            assert!(d >= ra && d <= Duration::from_secs(12));
        }
    }

    #[test]
    fn heartbeat_interval_gate() {
        assert_eq!(clamp_heartbeat_interval(0), None);
        assert_eq!(clamp_heartbeat_interval(-5), None);
        assert_eq!(clamp_heartbeat_interval(i64::MIN), None);
        assert_eq!(clamp_heartbeat_interval(1), Some(10));
        assert_eq!(clamp_heartbeat_interval(9), Some(10));
        assert_eq!(clamp_heartbeat_interval(30), Some(30));
        assert_eq!(clamp_heartbeat_interval(301), Some(300));
        assert_eq!(clamp_heartbeat_interval(i64::MAX), Some(300));
    }

    #[test]
    fn unauthorized_retry_is_slow() {
        assert_eq!(unauthorized_retry_delay(0.0), Duration::from_secs(900));
        assert_eq!(unauthorized_retry_delay(1.0), Duration::from_secs(960));
    }
}
