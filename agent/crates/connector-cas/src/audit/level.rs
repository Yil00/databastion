//! The audit level of a `cas` target (ADR-0041 decision 10). `check()` and
//! the stream share this one rule, fed with the times of the records they
//! parsed (record times, clamped to the agent clock, so re-reading the same
//! tail never makes the evidence fresher).
//!
//! - **Never Full**: the trail covers authentications and ticket issuance,
//!   not reads through the management endpoints nor of the stores, the
//!   action filters live in the CAS configuration the agent must not read,
//!   and `what` is dropped.
//! - **Partial**: an `AUTHENTICATION_SUCCESS` record **and** a
//!   service-ticket issuance record in the last 24 h; with
//!   `audit.auth_failures_not_seen` when no `AUTHENTICATION_FAILED` was
//!   parsed in the last 7 days.
//! - **Limited**: a valid record in the last 24 h, but not both kinds
//!   (`audit.auth_records_not_seen`, `audit.service_ticket_records_not_seen`).
//! - **None**: before any record (`audit.limited_pending_first_record`), and
//!   when no valid record was parsed in the last 24 h (both "not seen"
//!   notes); the unreadable, unsupported-format and stopped cases are
//!   decided by the caller.

use std::time::{Duration, SystemTime};

use databastion_core::AuditLevel;

use crate::notes::{CasNote, CasNoteCode};
use crate::parse::record::{Action, AuditRecord};

/// Freshness of the records that prove a level.
pub const FRESH: Duration = Duration::from_secs(24 * 3600);
/// Freshness of the failed authentication proof.
pub const FAILURES_FRESH: Duration = Duration::from_secs(7 * 24 * 3600);

/// Times of the last records of each kind (record times, clamped).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Evidence {
    /// Any valid record.
    pub last_valid: Option<SystemTime>,
    /// `AUTHENTICATION_SUCCESS`.
    pub last_auth_success: Option<SystemTime>,
    /// Service-ticket (or token) issuance.
    pub last_issuance: Option<SystemTime>,
    /// `AUTHENTICATION_FAILED`.
    pub last_auth_failed: Option<SystemTime>,
}

fn later(slot: &mut Option<SystemTime>, t: SystemTime) {
    if slot.is_none_or(|s| s < t) {
        *slot = Some(t);
    }
}

fn fresh(t: Option<SystemTime>, now: SystemTime, within: Duration) -> bool {
    t.is_some_and(|t| now.duration_since(t).map_or(true, |age| age <= within))
}

impl Evidence {
    /// Notes a parsed record.
    pub fn note(&mut self, r: &AuditRecord, now: SystemTime) {
        let t = r.when.min(now);
        later(&mut self.last_valid, t);
        match r.action {
            Action::AuthSuccess => later(&mut self.last_auth_success, t),
            Action::AuthFailed => later(&mut self.last_auth_failed, t),
            ref a if a.issues_for_service() => later(&mut self.last_issuance, t),
            _ => {}
        }
    }

    /// Merges another source of evidence (the check's tail and the
    /// stream).
    pub fn merge(&mut self, o: &Self) {
        for (slot, t) in [
            (&mut self.last_valid, o.last_valid),
            (&mut self.last_auth_success, o.last_auth_success),
            (&mut self.last_issuance, o.last_issuance),
            (&mut self.last_auth_failed, o.last_auth_failed),
        ] {
            if let Some(t) = t {
                later(slot, t);
            }
        }
    }

    /// The level these records prove at `now`, and its notes.
    #[must_use]
    pub fn level(&self, now: SystemTime) -> (AuditLevel, Vec<CasNote>) {
        if self.last_valid.is_none() {
            return (
                AuditLevel::None,
                vec![CasNote::flag(CasNoteCode::AuditLimitedPendingFirstRecord)],
            );
        }
        let success = fresh(self.last_auth_success, now, FRESH);
        let issuance = fresh(self.last_issuance, now, FRESH);
        let mut notes = Vec::new();
        if !success {
            notes.push(CasNote::flag(CasNoteCode::AuditAuthRecordsNotSeen));
        }
        if !issuance {
            notes.push(CasNote::flag(CasNoteCode::AuditServiceTicketRecordsNotSeen));
        }
        if !fresh(self.last_valid, now, FRESH) {
            return (AuditLevel::None, notes);
        }
        if success && issuance {
            if !fresh(self.last_auth_failed, now, FAILURES_FRESH) {
                notes.push(CasNote::flag(CasNoteCode::AuditAuthFailuresNotSeen));
            }
            return (AuditLevel::Partial, notes);
        }
        (AuditLevel::Limited, notes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::UtcOffset;
    use crate::parse::record::parse_record;

    const H: u64 = 3600;

    fn rec(action: &str, at: SystemTime) -> AuditRecord {
        let ms = at
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        parse_record(
            format!(r#"{{"action": "{action}", "when": {ms}}}"#).as_bytes(),
            UtcOffset(0),
        )
        .unwrap()
    }

    fn codes(n: &[CasNote]) -> Vec<CasNoteCode> {
        n.iter().map(|n| n.code).collect()
    }

    #[test]
    fn levels_follow_the_records_never_full() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let ago = |h: u64| now - Duration::from_secs(h * H);
        let mut e = Evidence::default();
        assert_eq!(
            e.level(now),
            (
                AuditLevel::None,
                vec![CasNote::flag(CasNoteCode::AuditLimitedPendingFirstRecord)]
            )
        );
        e.note(&rec("TICKET_GRANTING_TICKET_CREATED", ago(1)), now);
        let (l, n) = e.level(now);
        assert_eq!(l, AuditLevel::Limited);
        assert_eq!(
            codes(&n),
            [
                CasNoteCode::AuditAuthRecordsNotSeen,
                CasNoteCode::AuditServiceTicketRecordsNotSeen
            ]
        );
        e.note(&rec("AUTHENTICATION_SUCCESS", ago(2)), now);
        assert_eq!(
            codes(&e.level(now).1),
            [CasNoteCode::AuditServiceTicketRecordsNotSeen]
        );
        e.note(&rec("SERVICE_TICKET_CREATED", ago(3)), now);
        let (l, n) = e.level(now);
        assert_eq!(l, AuditLevel::Partial);
        assert_eq!(codes(&n), [CasNoteCode::AuditAuthFailuresNotSeen]);
        e.note(&rec("AUTHENTICATION_FAILED", ago(24 * 6)), now);
        assert_eq!(e.level(now), (AuditLevel::Partial, vec![]));
        // A day later, nothing new: the proofs are stale.
        let later = now + Duration::from_secs(25 * H);
        let (l, n) = e.level(later);
        assert_eq!(l, AuditLevel::None);
        assert_eq!(
            codes(&n),
            [
                CasNoteCode::AuditAuthRecordsNotSeen,
                CasNoteCode::AuditServiceTicketRecordsNotSeen
            ]
        );
    }

    #[test]
    fn future_records_count_as_now() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let mut e = Evidence::default();
        e.note(
            &rec(
                "AUTHENTICATION_SUCCESS",
                now + Duration::from_secs(1000 * H),
            ),
            now,
        );
        assert_eq!(e.last_auth_success, Some(now));
        let mut m = Evidence::default();
        m.merge(&e);
        assert_eq!(m, e);
    }
}
