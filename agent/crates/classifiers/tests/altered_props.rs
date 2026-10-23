//! Property tests of the ADR-0056 marker (decision 2 item 5): a name is
//! marked altered if and only if the first normalization step (control and
//! format characters stripped, NFKC) changed it and the result is not `*`,
//! for `names.rs`; for `keys.rs`, if and only if NFKC changed a segment the
//! pattern keeps (a segment turned into `*` is not altered).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use databastion_classifiers::keys::{self, LearnedPatterns, PatternBuilder, pattern_tokens};
use databastion_classifiers::names::{
    PathPart, is_forbidden_char, normalize_field_path, normalize_ldap_dn, normalize_path,
};
use proptest::prelude::*;
use unicode_normalization::UnicodeNormalization;

/// The first step, written independently of `names.rs`: strip, NFKC,
/// strip again.
fn first_step(raw: &str) -> String {
    let stripped: String = raw.chars().filter(|c| !is_forbidden_char(*c)).collect();
    let folded: String = stripped.nfkc().collect();
    folded.chars().filter(|c| !is_forbidden_char(*c)).collect()
}

/// Pieces of names: plain ASCII, characters the first step strips (U+200B,
/// U+00AD, U+202E, U+FEFF), compatibility forms it maps (fullwidth letters
/// and digits, the `ﬁ` ligature, `ſ`, a combining acute that composes),
/// and characters it keeps (`é` precomposed, Greek, CJK).
fn piece() -> impl Strategy<Value = &'static str> {
    prop::sample::select(vec![
        "a",
        "b",
        "c",
        "x",
        "_",
        ".",
        ".",
        "-",
        "1",
        "42",
        "customers",
        "orders",
        "\u{200B}",
        "\u{00AD}",
        "\u{202E}",
        "\u{FEFF}",
        "\u{FF43}",
        "\u{FF55}",
        "\u{FF14}",
        "\u{FB01}",
        "\u{017F}",
        "e\u{0301}",
        "\u{00E9}",
        "\u{03C3}",
        "\u{5BA2}",
        "@",
        "jane",
        "=",
    ])
}

fn name() -> impl Strategy<Value = String> {
    prop::collection::vec(piece(), 1..10).prop_map(|p| p.concat())
}

/// Lowercase words the key normalizer keeps as literals.
fn word() -> impl Strategy<Value = &'static str> {
    prop::sample::select(vec![
        "cart", "items", "profile", "orders", "color", "settings", "cache", "page", "about",
    ])
}

/// The fullwidth form of an ASCII lowercase word (NFKC maps it back).
fn fullwidth(w: &str) -> String {
    w.chars()
        .map(|c| char::from_u32(u32::from(c) - u32::from('a') + 0xFF41).unwrap())
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    #[test]
    fn paths_are_marked_iff_the_first_step_changed_them(raw in name()) {
        let n = normalize_path(&raw);
        let want = first_step(&raw) != raw && n.as_str() != "*";
        prop_assert_eq!(n.altered(), want, "{:?} -> {:?}", raw, n.as_str());
    }

    #[test]
    fn field_paths_are_marked_iff_the_first_step_changed_a_key(
        keys in prop::collection::vec(prop::option::of(name()), 1..5),
    ) {
        let parts: Vec<PathPart<'_>> = keys
            .iter()
            .map(|k| k.as_deref().map_or(PathPart::Index, PathPart::Key))
            .collect();
        let n = normalize_field_path(&parts);
        let changed = keys.iter().flatten().any(|k| first_step(k) != *k);
        prop_assert_eq!(n.altered(), changed && n.as_str() != "*", "{:?} -> {:?}", keys, n.as_str());
    }

    #[test]
    fn ldap_dns_are_marked_iff_the_first_step_changed_them(
        entry in name(),
        ou in name(),
    ) {
        let raw = format!("uid={entry},ou={ou},dc=example,dc=org");
        let n = normalize_ldap_dn(&raw);
        let want = first_step(&raw) != raw && n.as_str() != "*";
        prop_assert_eq!(n.altered(), want, "{:?} -> {:?}", raw, n.as_str());
    }

    /// The marker never changes the name, and equal names compare equal
    /// whatever their markers.
    #[test]
    fn the_marker_is_not_part_of_the_name(raw in name()) {
        let n = normalize_path(&raw);
        let again = normalize_path(&first_step(&raw));
        prop_assert!(!again.altered());
        if n.as_str() == again.as_str() {
            prop_assert_eq!(&n, &again);
        }
    }

    /// Keys: a name NFKC leaves as it is is never marked; a marked one was
    /// changed by NFKC and is not `*`.
    #[test]
    fn keys_are_marked_only_when_nfkc_changed_them(raw in name()) {
        let p = keys::split_key(raw.as_bytes()).pattern();
        let nfkc: String = raw.nfkc().collect();
        if nfkc == raw {
            prop_assert!(!p.altered(), "{:?}", raw);
        }
        if p.altered() {
            prop_assert!(nfkc != raw && p.as_str() != "*");
        }
    }

    /// Keys: one word written in fullwidth gives the pattern of the plain
    /// key, marked if and only if that word is kept as a literal in it; the
    /// plain key is never marked.
    #[test]
    fn a_fullwidth_segment_is_marked_iff_kept(
        words in prop::collection::vec(word(), 1..5),
        at in any::<prop::sample::Index>(),
        digits in any::<bool>(),
    ) {
        let i = at.index(words.len());
        let plain = words.join(":");
        let mut variant: Vec<String> = words.iter().map(|w| (*w).to_owned()).collect();
        // A fullwidth word, or fullwidth digits (a record id: always `*`).
        let (plain, variant_word) = if digits {
            let mut p: Vec<String> = variant.clone();
            p[i] = "42".to_owned();
            (p.join(":"), "\u{FF14}\u{FF12}".to_owned())
        } else {
            (plain, fullwidth(words[i]))
        };
        variant[i] = variant_word;
        let variant = variant.join(":");
        let p = keys::split_key(plain.as_bytes()).pattern();
        let v = keys::split_key(variant.as_bytes()).pattern();
        prop_assert_eq!(p.as_str(), v.as_str());
        prop_assert!(!p.altered());
        let tokens = pattern_tokens(p.as_str());
        let kept = !digits && tokens.get(i).is_some_and(|t| *t == words[i]);
        prop_assert_eq!(v.altered(), kept, "{:?} -> {:?}", variant, v.as_str());
    }
}

/// Discovery: a walk whose keys include a fullwidth spelling of a kept
/// segment emits that pattern altered; the other patterns stay plain; a
/// fullwidth segment that the walk turns into `*` (record-id rule) does
/// not mark its pattern.
#[test]
fn walks_mark_patterns_learned_from_altered_keys() {
    let mut b = PatternBuilder::new(4);
    for k in [
        "cart:items".to_owned(),
        format!("cart:{}", fullwidth("items")),
        "cache:page:about".to_owned(),
        "session:jdupont".to_owned(),
        format!("session:{}", fullwidth("amartin")),
    ] {
        b.add(k.as_bytes(), keys::split_key(k.as_bytes()), 0);
    }
    let emitted: Vec<(String, bool)> = b
        .finish()
        .into_iter()
        .map(|p| (p.pattern.as_str().to_owned(), p.pattern.altered()))
        .collect();
    assert!(
        emitted.contains(&("cart:items".to_owned(), true)),
        "{emitted:?}"
    );
    assert!(
        emitted.contains(&("cache:page:about".to_owned(), false)),
        "{emitted:?}"
    );
    assert!(
        emitted.contains(&("session:*".to_owned(), false)),
        "{emitted:?}"
    );
    // One key alone: marked when a kept segment was fullwidth; a segment
    // holding a character the normalizer refuses is `*`, not altered.
    let one = |k: &str| {
        let p = keys::split_key(k.as_bytes()).pattern();
        (p.as_str().to_owned(), p.altered())
    };
    assert_eq!(
        one(&format!("{}:items", fullwidth("cart"))),
        ("cart:items".to_owned(), true)
    );
    assert_eq!(one("cart\u{200B}:items"), ("*:items".to_owned(), false));
    // Without the fullwidth key, the same pattern is plain.
    let mut b = PatternBuilder::new(4);
    b.add(b"cart:items", keys::split_key(b"cart:items"), 0);
    let p = b.finish().remove(0).pattern;
    assert_eq!((p.as_str(), p.altered()), ("cart:items", false));
}

/// Audit: a key mapped to a learned pattern carries the pattern's marker,
/// or its own when NFKC changed the key name; a key mapped to `*` (no
/// learned pattern) is never marked; the marker survives an intersection
/// (altered when altered in any set).
#[test]
fn audit_objects_carry_the_learned_or_their_own_marker() {
    let l = LearnedPatterns::with_markers([
        ("cart:items", true),
        ("session:*", false),
        ("cache:page:about", false),
    ]);
    let obj = |k: &str| {
        let o = l.object(k.as_bytes(), false);
        (o.as_str().to_owned(), o.altered())
    };
    assert_eq!(obj("cart:items"), ("cart:items".to_owned(), true));
    assert_eq!(obj("session:abc"), ("session:*".to_owned(), false));
    // The key's own fullwidth segment.
    assert_eq!(
        obj(&format!("{}:abc", fullwidth("session"))),
        ("session:*".to_owned(), true)
    );
    // A literal prefix of an altered pattern, then `*`.
    assert_eq!(obj("cart:other"), ("cart:*".to_owned(), true));
    assert_eq!(obj("cache:page:x"), ("cache:page:*".to_owned(), false));
    // Nothing learned for it: `*`, never marked, even when NFKC changed it.
    assert_eq!(obj(&fullwidth("unknown")), ("*".to_owned(), false));
    let other = LearnedPatterns::with_markers([("cart:items", false), ("session:*", true)]);
    let both = LearnedPatterns::intersection(&[&l, &other]);
    assert_eq!(
        both.marked().collect::<Vec<_>>(),
        [("cart:items", true), ("session:*", true)]
    );
    // A pattern listed twice is altered when either is.
    let twice = LearnedPatterns::with_markers([("cart:items", false), ("cart:items", true)]);
    assert_eq!(twice.marked().collect::<Vec<_>>(), [("cart:items", true)]);
}
