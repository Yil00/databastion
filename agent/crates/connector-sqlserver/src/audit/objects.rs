//! The objects of one access event, bounded fail closed (end-of-phase-9
//! review, gate G1).
//!
//! An event holds at most [`MAX_EVENT_OBJECTS`] objects (contract
//! `AccessEvent.objects.maxItems`), and [`MaskedEvent::with_object`]
//! ignores the ones past that bound. A statement that names more objects
//! than fit would otherwise lose some of them without a sign: the
//! statement is then a read of what fits and of `*`, always reported (the
//! rule of the MySQL / MariaDB connector for its 16 table names). One slot
//! is kept for `*`, so that `*` always fits.

use databastion_classifiers::masking::{EventObject, MAX_EVENT_OBJECTS, MaskedEvent};

/// Distinct objects kept besides `*`.
const KEPT: usize = MAX_EVENT_OBJECTS - 1;

/// The distinct objects of one event, at most [`KEPT`], and whether some
/// did not fit.
#[derive(Debug, Default)]
pub(crate) struct Objects {
    list: Vec<EventObject>,
    overflow: bool,
}

impl Objects {
    /// Adds an object (duplicates ignored); one past the bound marks the
    /// list as overflowed instead.
    pub(crate) fn push(&mut self, o: EventObject) {
        if self.list.contains(&o) {
            return;
        }
        if self.list.len() < KEPT {
            self.list.push(o);
        } else {
            self.overflow = true;
        }
    }

    /// Records that objects were lost before they reached this list (a
    /// bound upstream).
    pub(crate) fn mark_overflow(&mut self) {
        self.overflow = true;
    }

    /// Whether some object did not fit: the event must name `*` and be
    /// always reported.
    pub(crate) fn overflow(&self) -> bool {
        self.overflow
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// Adds the objects to `ev`. A caller that names `*` adds it to `ev`
    /// first: one slot is always left for it.
    pub(crate) fn apply(self, mut ev: MaskedEvent) -> MaskedEvent {
        for o in self.list {
            ev = ev.with_object(o);
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
    use databastion_classifiers::names::NormalizedName;

    use super::*;
    use crate::discover::normalize;

    fn obj(name: &str) -> EventObject {
        EventObject::new(normalize("db"), None, normalize(name))
    }

    fn event() -> MaskedEvent {
        MaskedEvent::new(
            EventSource::SqlserverXevents,
            EventAction::Read,
            EventPrincipal::unidentified(),
            SystemTime::UNIX_EPOCH,
        )
    }

    #[test]
    fn star_always_fits_and_overflow_is_marked() {
        let star = || EventObject::new(normalize("db"), None, NormalizedName::wildcard());
        let mut o = Objects::default();
        for i in 0..KEPT {
            o.push(obj(&format!(
                "t{}",
                char::from(b'a' + u8::try_from(i).unwrap())
            )));
            o.push(obj("ta"));
        }
        assert!(!o.overflow());
        let ev = std::mem::take(&mut o).apply(event());
        assert_eq!(ev.objects().len(), KEPT);
        for i in 0..MAX_EVENT_OBJECTS {
            o.push(obj(&format!(
                "t{}",
                char::from(b'a' + u8::try_from(i).unwrap())
            )));
        }
        assert!(o.overflow());
        let ev = o.apply(event().with_object(star()));
        assert_eq!(ev.objects().len(), MAX_EVENT_OBJECTS);
        assert!(ev.objects().contains(&star()));
    }
}
