//! What the Discovery scans and the audit stream of one `cas` target found,
//! for its `check()` (counts and times only, never a value or a name).

use std::sync::{Arc, Mutex, PoisonError};

use crate::audit::level::Evidence;
use crate::registry::ServiceIndex;

/// Registry facts from the last Discovery scan.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RegistryFacts {
    /// Files skipped (unreadable, refused, too large, beyond the cap, not
    /// a definition, unparsable).
    pub skipped: u64,
    /// Services whose `clientSecret` is stored in clear.
    pub clear_secrets: u64,
    /// Files refused because the agent could write them (counted in
    /// `skipped` too).
    pub writable: u64,
}

#[derive(Debug, Default)]
struct Inner {
    evidence: Evidence,
    registry: Option<RegistryFacts>,
    services: Option<Arc<ServiceIndex>>,
    dropped: u64,
    json_records: u64,
    non_json_records: u64,
    headers_logged: bool,
    stream_stopped: bool,
}

/// Shared state of one `cas` target.
#[derive(Debug, Default)]
pub struct CasState {
    inner: Mutex<Inner>,
}

impl CasState {
    fn with<T>(&self, f: impl FnOnce(&mut Inner) -> T) -> T {
        f(&mut self.inner.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// Records evidence of parsed records.
    pub fn note_evidence(&self, e: &Evidence) {
        self.with(|i| i.evidence.merge(e));
    }

    /// Records parsed and dropped lines: `json` valid records, `non_json`
    /// lines that are not one JSON object, `dropped` lines dropped for any
    /// reason (non-JSON included).
    pub fn note_lines(&self, json: u64, non_json: u64, dropped: u64, headers: bool) {
        self.with(|i| {
            i.json_records = i.json_records.saturating_add(json);
            i.non_json_records = i.non_json_records.saturating_add(non_json);
            i.dropped = i.dropped.saturating_add(dropped);
            i.headers_logged |= headers;
        });
    }

    /// Records the facts of a Discovery scan and its service index.
    pub fn note_registry(&self, facts: RegistryFacts, services: Option<Arc<ServiceIndex>>) {
        self.with(|i| {
            i.registry = Some(facts);
            if services.is_some() {
                i.services = services;
            }
        });
    }

    /// Marks the stream stopped (or restarted).
    pub fn set_stream_stopped(&self, stopped: bool) {
        self.with(|i| i.stream_stopped = stopped);
    }

    /// The service index of the last scan.
    #[must_use]
    pub fn services(&self) -> Option<Arc<ServiceIndex>> {
        self.with(|i| i.services.clone())
    }

    pub(crate) fn snapshot(&self) -> Snapshot {
        self.with(|i| Snapshot {
            evidence: i.evidence,
            registry: i.registry,
            dropped: i.dropped,
            format_unsupported: i.json_records == 0 && i.non_json_records > 0,
            headers_logged: i.headers_logged,
            stream_stopped: i.stream_stopped,
        })
    }
}

/// A copy of the state, for one check.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Snapshot {
    pub(crate) evidence: Evidence,
    pub(crate) registry: Option<RegistryFacts>,
    pub(crate) dropped: u64,
    pub(crate) format_unsupported: bool,
    pub(crate) headers_logged: bool,
    pub(crate) stream_stopped: bool,
}
