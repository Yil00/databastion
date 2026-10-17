//! Property tests on the access event object bound (end-of-phase-9
//! security review, G7): an event fed more objects than it can list
//! names `*`, is always reported, and loses no object silently; objects
//! lost upstream (`with_unlisted_objects`) and merges keep the rule; the
//! objects stay sorted and without duplicates.

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

/// One step fed to an event: an object, objects lost upstream (of a
/// database), or a merge with an event built from other steps.
#[derive(Debug, Clone)]
enum Step {
    Object(EventObject),
    Unlisted(u8),
    Merge(Vec<EventObject>),
}

fn steps() -> impl Strategy<Value = Vec<Step>> {
    let object = (
        0u8..3,
        prop::option::of(0u8..3),
        prop::option::weighted(0.9, 0u8..200),
    )
        .prop_map(|(d, s, n)| object(d, s, n));
    prop::collection::vec(
        prop_oneof![
            8 => object.clone().prop_map(Step::Object),
            1 => (0u8..4).prop_map(Step::Unlisted),
            1 => prop::collection::vec(object, 0..20).prop_map(Step::Merge),
        ],
        0..60,
    )
}

fn database(d: u8) -> NormalizedName {
    if d == 3 {
        NormalizedName::wildcard()
    } else {
        normalize_path(&format!("db_{}", char::from(b'a' + d)))
    }
}

fn event() -> MaskedEvent {
    MaskedEvent::new(
        EventSource::Pgaudit,
        EventAction::Read,
        EventPrincipal::account("report"),
        std::time::SystemTime::UNIX_EPOCH,
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
        // Sorted by (database, schema, object), no duplicate.
        let key = |o: &EventObject| {
            (
                o.database().as_str().to_owned(),
                o.schema().map_or(String::new(), |s| s.as_str().to_owned()),
                o.object().as_str().to_owned(),
            )
        };
        for w in e.objects().windows(2) {
            prop_assert!(key(&w[0]) < key(&w[1]), "{:?} then {:?}", w[0], w[1]);
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

    /// With objects lost upstream (`with_unlisted_objects`) and merges:
    /// sorted, no duplicate, within the bound; an unlisted database is
    /// always covered by a `*` and the event is always reported; every
    /// object fed is listed or covered.
    #[test]
    fn unlisted_objects_and_merges_lose_nothing(steps in steps()) {
        let mut e = event();
        let mut fed: Vec<EventObject> = Vec::new();
        let mut unlisted = false;
        for step in &steps {
            match step {
                Step::Object(o) => {
                    e = e.with_object(o.clone());
                    fed.push(o.clone());
                }
                Step::Unlisted(d) => {
                    e = e.with_unlisted_objects(database(*d));
                    fed.push(EventObject::new(database(*d), None, NormalizedName::wildcard()));
                    unlisted = true;
                }
                Step::Merge(objs) => {
                    // Merge needs the same group: the other event is fed
                    // the same objects as `e`, plus its own; only the
                    // flags and counts merge.
                    let mut other = event();
                    for o in e.objects() {
                        other = other.with_object(o.clone());
                    }
                    for o in objs {
                        other = other.with_object(o.clone());
                    }
                    if other.group_key() == e.group_key() {
                        let overflowed = other.objects_overflowed();
                        e.merge(other);
                        if overflowed {
                            prop_assert!(e.objects_overflowed() && e.always_report());
                        }
                    }
                }
            }
        }
        let objects = e.objects();
        prop_assert!(objects.len() <= MAX_EVENT_OBJECTS);
        prop_assert!(objects.iter().filter(|o| o.object().as_str() != "*").count() < MAX_EVENT_OBJECTS);
        // Sorted by (database, schema, object), no duplicate.
        let key = |o: &EventObject| {
            (
                o.database().as_str().to_owned(),
                o.schema().map_or(String::new(), |s| s.as_str().to_owned()),
                o.object().as_str().to_owned(),
            )
        };
        for w in objects.windows(2) {
            prop_assert!(key(&w[0]) < key(&w[1]), "{:?} then {:?}", w[0], w[1]);
        }
        if unlisted {
            prop_assert!(e.objects_overflowed() && e.always_report());
        }
        for o in &fed {
            prop_assert!(covered(&e, o), "{:?} lost", o);
        }
    }
}
