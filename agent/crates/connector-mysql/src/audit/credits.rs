//! Credits for the extra sampling statements of a Discovery scan
//! (security review of 914c9d2, N3).
//!
//! Discovery samples a wide table in several column batches, one statement
//! each, so that every statement stays under the audit logs' text limits
//! (`sql::sample_statements`). The own-account budget charges each
//! statement of the agent: on the file sources, without row counts, every
//! statement is charged the whole per-object budget, so the second batch
//! of a table was reported as a read by the agent at every scan.
//!
//! The first batch of a table is charged as usual. Before sending each
//! further batch, Discovery grants a credit holding its **exact text** and
//! its table; the Audit stream of the same target consumes a credit, once,
//! for a statement record with that exact, uncut text, the agent's
//! identity, and no table record other than a read of that table, and
//! leaves it out without a charge. Credits are granted only while the
//! target's Audit stream runs, and a credit expires after two poll
//! intervals plus the scan's statement timeout, within
//! [`MIN_CREDIT_TTL`] and [`MAX_CREDIT_TTL`] (security review of 09e93da,
//! L1: a statement the source never logs leaves a credit that a replay of
//! its exact text from the agent's identity can use until then); at most
//! [`MAX_CREDITS`] are held per target (the oldest are dropped: their
//! statements are then reported, fail closed).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Shortest and longest lifetime of a credit.
pub(crate) const MIN_CREDIT_TTL: Duration = Duration::from_secs(30);
pub(crate) const MAX_CREDIT_TTL: Duration = Duration::from_secs(900);
/// Poll interval assumed before the Audit stream sets it.
const DEFAULT_POLL: Duration = Duration::from_secs(60);
/// Credits held per target at most.
pub(crate) const MAX_CREDITS: usize = 4096;

struct Credit {
    text: Vec<u8>,
    schema: String,
    table: String,
    until: Instant,
}

/// The credits of one target (see the module documentation).
#[derive(Default)]
pub(crate) struct SampleCredits {
    entries: VecDeque<Credit>,
    /// The Audit stream's poll interval (`None`: not set yet).
    poll: Option<Duration>,
}

/// Shared between the target's Discovery scans and its Audit stream.
pub(crate) type SharedCredits = Arc<Mutex<SampleCredits>>;

impl SampleCredits {
    fn expire(&mut self, now: Instant) {
        while self.entries.front().is_some_and(|c| c.until <= now) {
            self.entries.pop_front();
        }
    }

    /// The Audit stream's poll interval.
    pub(crate) fn set_poll_interval(&mut self, poll: Duration) {
        self.poll = Some(poll);
    }

    /// Lifetime of a credit for a statement under `statement_timeout`.
    pub(crate) fn ttl(&self, statement_timeout: Duration) -> Duration {
        (self.poll.unwrap_or(DEFAULT_POLL) * 2 + statement_timeout)
            .clamp(MIN_CREDIT_TTL, MAX_CREDIT_TTL)
    }

    /// Grants one credit for `text`, a sampling statement of
    /// `schema`.`table` under `statement_timeout`, sent at `now`.
    pub(crate) fn grant(
        &mut self,
        text: &str,
        schema: &str,
        table: &str,
        statement_timeout: Duration,
        now: Instant,
    ) {
        let ttl = self.ttl(statement_timeout);
        self.expire(now);
        while self.entries.len() >= MAX_CREDITS {
            self.entries.pop_front();
        }
        self.entries.push_back(Credit {
            text: text.as_bytes().to_vec(),
            schema: schema.to_owned(),
            table: table.to_owned(),
            until: now + ttl,
        });
    }

    /// The table of the oldest live credit for exactly `text`, if any.
    pub(crate) fn peek(&mut self, text: &[u8], now: Instant) -> Option<(String, String)> {
        self.expire(now);
        self.entries
            .iter()
            .find(|c| c.text == text)
            .map(|c| (c.schema.clone(), c.table.clone()))
    }

    /// Consumes the oldest live credit for exactly `text`.
    pub(crate) fn take(&mut self, text: &[u8], now: Instant) -> bool {
        self.expire(now);
        match self.entries.iter().position(|c| c.text == text) {
            Some(i) => {
                self.entries.remove(i);
                true
            }
            None => false,
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credits_are_exact_single_use_bounded_and_expire() {
        let now = Instant::now();
        let mut c = SampleCredits::default();
        let t = Duration::from_secs(30);
        c.grant("SELECT `b` FROM `s`.`t` LIMIT 10", "s", "t", t, now);
        assert_eq!(c.peek(b"SELECT `b` FROM `s`.`t` LIMIT 10 ", now), None);
        assert_eq!(
            c.peek(b"SELECT `b` FROM `s`.`t` LIMIT 10", now),
            Some(("s".to_owned(), "t".to_owned()))
        );
        assert!(c.take(b"SELECT `b` FROM `s`.`t` LIMIT 10", now));
        assert!(!c.take(b"SELECT `b` FROM `s`.`t` LIMIT 10", now));
        c.grant("x", "s", "t", t, now);
        assert!(c.peek(b"x", now + c.ttl(t)).is_none());
        assert_eq!(c.len(), 0);
        for i in 0..MAX_CREDITS + 10 {
            c.grant(&format!("q{i}"), "s", "t", t, now);
        }
        assert_eq!(c.len(), MAX_CREDITS);
        assert!(c.peek(b"q0", now).is_none());
        assert!(
            c.peek(format!("q{}", MAX_CREDITS + 9).as_bytes(), now)
                .is_some()
        );
    }
}
