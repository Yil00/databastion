//! Property tests on the access event object bound (end-of-phase-9
//! security review, G7): an event fed more objects than it can list
//! names `*`, is always reported, and loses no object silently.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use databastion_classifiers::masking::{
    EventAction, EventObject, EventPrincipal, EventSource, MAX_EVENT_OBJECTS, MaskedEvent,
};
use databastion_classifiers::names::{NormalizedName, normalize_path};
use proptest::prelude::*;

fn object(db: u8, schema: Option<u8>, name: Option<u8>) -> EventObject {
    EventObject::new(
        normalize_path(&format!("db_{}", char::from(b'a' + db))),
        schema.map(|s| normalize_path(&format!("s_{}", char::from(b'a' + s)))),
        name.map_or_else(NormalizedName::wildcard, |n| {
            normalize_path(&format!(
                "t_{}{}",
                char::from(b'a' + n / 26),
                char::from(b'a' + n % 26)
            ))
        }),
    )
}

/// Whether `o` is listed or covered by a `*` object of `e`.
fn covered(e: &MaskedEvent, o: &EventObject) -> bool {
    e.objects().contains(o)
        || e.objects().iter().any(|s| {
            s.object().as_str() == "*"
                && (s.database().as_str() == "*" || s.database() == o.database())
                && s.schema().is_none_or(|x| o.schema() == Some(x))
        })
}

fn objects() -> impl Strategy<Value = Vec<EventObject>> {
    prop::collection::vec(
        (
            0u8..3,
            prop::option::of(0u8..3),
            prop::option::weighted(0.9, 0u8..200),
        )
            .prop_map(|(d, s, n)| object(d, s, n)),
        0..60,
    )
}

proptest! {
    #[test]
    fn no_object_is_lost_silently(objs in objects()) {
        let mut e = MaskedEvent::new(
            EventSource::Pgaudit,
            EventAction::Read,
            EventPrincipal::account("report"),
            std::time::SystemTime::UNIX_EPOCH,
        );
        for o in &objs {
            e = e.with_object(o.clone());
        }
        let mut distinct: Vec<&EventObject> = Vec::new();
        for o in &objs {
            if !distinct.contains(&o) {
                distinct.push(o);
            }
        }
        let distinct_named = distinct.iter().filter(|o| o.object().as_str() != "*").count();
        prop_assert!(e.objects().len() <= MAX_EVENT_OBJECTS);
        let named = e.objects().iter().filter(|o| o.object().as_str() != "*").count();
        prop_assert!(named < MAX_EVENT_OBJECTS);
        // Sorted, no duplicate.
        for w in e.objects().windows(2) {
            prop_assert!(w[0] != w[1]);
        }
        let stars = e.objects().iter().filter(|o| o.object().as_str() == "*").count();
        if distinct_named >= MAX_EVENT_OBJECTS {
            // More than 15 distinct named objects: `*`, always reported.
            prop_assert!(e.objects_overflowed());
            prop_assert!(e.always_report());
            prop_assert!(stars >= 1);
        }
        if e.objects_overflowed() {
            prop_assert!(e.always_report());
            prop_assert!(stars >= 1);
        } else {
            prop_assert!(!e.always_report());
            prop_assert_eq!(e.objects().len(), distinct.len());
        }
        for o in &objs {
            prop_assert!(covered(&e, o), "{:?} lost", o);
        }
    }
}
