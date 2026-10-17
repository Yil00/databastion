//! The objects of one access event (end-of-phase-9 review, gates G1 and
//! G7).
//!
//! The bound is the core's rule ([`MaskedEvent::with_object`]): an event
//! keeps at most 15 named objects and a slot for `*`; an object past that
//! makes the event name `*` (covering it, widened to `(*, -, *)` across
//! databases) and always reported, never lost without a sign. This list
//! only collects the distinct objects of a statement (bounded upstream:
//! the grouping's 64 record objects, the analyzer's relation bound) and
//! the databases of objects lost upstream, and hands them all to the core.

use databastion_classifiers::masking::{EventObject, MaskedEvent};
use databastion_classifiers::names::NormalizedName;

/// The distinct objects of one event, and the databases of objects lost
/// before reaching it.
#[derive(Debug, Default)]
pub(crate) struct Objects {
    list: Vec<EventObject>,
    unlisted: Vec<NormalizedName>,
}

impl Objects {
    /// Adds an object (duplicates ignored).
    pub(crate) fn push(&mut self, o: EventObject) {
        if !self.list.contains(&o) {
            self.list.push(o);
        }
    }

    /// Records that objects of `database` (`*`: several or unknown) were
    /// lost before they reached this list (a bound upstream): the event
    /// gets the core's overflow ([`MaskedEvent::with_unlisted_objects`]).
    pub(crate) fn mark_unlisted(&mut self, database: NormalizedName) {
        if !self.unlisted.contains(&database) {
            self.unlisted.push(database);
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.list.is_empty() && self.unlisted.is_empty()
    }

    /// Adds the objects to `ev`, through the core's bound.
    pub(crate) fn apply(self, mut ev: MaskedEvent) -> MaskedEvent {
        for o in self.list {
            ev = ev.with_object(o);
        }
        for db in self.unlisted {
            ev = ev.with_unlisted_objects(db);
        }
        ev
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::time::SystemTime;

    use databastion_classifiers::masking::{
        EventAction, EventPrincipal, EventSource, MAX_EVENT_OBJECTS, MaskedEvent,
    };

    use super::*;
    use crate::discover::normalize;

    fn obj(db: &str, name: &str) -> EventObject {
        EventObject::new(normalize(db), None, normalize(name))
    }

    fn event() -> MaskedEvent {
        MaskedEvent::new(
            EventSource::SqlserverXevents,
            EventAction::Read,
            EventPrincipal::unidentified(),
            SystemTime::UNIX_EPOCH,
        )
    }

    fn stars(ev: &MaskedEvent) -> Vec<&str> {
        ev.objects()
            .iter()
            .filter(|o| o.object().as_str() == "*")
            .map(|o| o.database().as_str())
            .collect()
    }

    #[test]
    fn the_core_rule_applies() {
        let name = |i: usize| format!("t{}", char::from(b'a' + u8::try_from(i).unwrap()));
        // 15 named objects: no overflow.
        let mut o = Objects::default();
        for i in 0..15 {
            o.push(obj("db", &name(i)));
            o.push(obj("db", "ta"));
        }
        let ev = o.apply(event());
        assert_eq!(ev.objects().len(), 15);
        assert!(!ev.objects_overflowed() && !ev.always_report());
        // 16: `*` of that database, always reported.
        let mut o = Objects::default();
        for i in 0..16 {
            o.push(obj("db", &name(i)));
        }
        let ev = o.apply(event());
        assert_eq!(ev.objects().len(), MAX_EVENT_OBJECTS);
        assert!(ev.objects_overflowed() && ev.always_report());
        assert_eq!(stars(&ev), ["db"]);
        // Then one of another database: widened.
        let mut o = Objects::default();
        for i in 0..16 {
            o.push(obj("db", &name(i)));
        }
        o.push(obj("crm", "customers"));
        assert_eq!(stars(&o.apply(event())), ["*"]);
        // Objects lost upstream: the overflow too, even with room.
        let mut o = Objects::default();
        o.push(obj("db", "t"));
        o.mark_unlisted(normalize("crm"));
        let ev = o.apply(event());
        assert!(ev.objects_overflowed() && ev.always_report());
        assert_eq!(stars(&ev), ["crm"]);
    }
}
