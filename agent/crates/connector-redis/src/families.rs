//! Round-robin sampling across the key families merged into one pattern
//! (#237 review; ADR-0052 decision 6, implementation note "Over-masking
//! cascade").
//!
//! The record-id and cardinality rules of decision 7 can merge unrelated
//! families into one pattern (`phone:1` and `addressbook:2` give `*:*`).
//! The pattern builder keeps the first `n` keys met by the walk, so a
//! family met late in the walk could never be sampled. This module keeps,
//! next to the builder and during one database walk, a few sample keys
//! per **family**, and after the walk gives each pattern that merged two
//! or more families its `n` sample keys taken in turn from each family.
//!
//! - A family is the key's own pattern (the per-key rules alone, no walk
//!   rule) reduced to its first segment, its segment count and its Redis
//!   type: `phone:1` and `phone:2` are one family, `addressbook:2`
//!   another. Only a keyed hash of it is kept, never its text.
//! - Bounded: at most [`MAX_FAMILIES`] families (beyond, a new family is
//!   not tracked and the builder's samples stand), at most `n` keys per
//!   family, and at most `2n + MAX_FAMILIES` keys in all, where every
//!   family always gets its first key. The keys are raw names in zeroized
//!   buffers, like the builder's samples, and are never logged nor sent.
//! - A kept key is given to a pattern only when the pattern is the one
//!   the key matches as a whole among the patterns of the walk
//!   ([`LearnedPatterns::pattern_of`]), with the same type: the pattern
//!   Audit charges the agent's own read of that key to (ADR-0052
//!   refinement of 2026-10-16). Other keys stay with the builder's choice.
//!   The `*` pattern (not a learned pattern) keeps the builder's samples.
//! - The values found in names (`#key`) follow the chosen keys first, then
//!   the builder's, still at most `n`.

use std::collections::HashMap;
use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;

use databastion_classifiers::keys::{self, EmittedPattern, LearnedPatterns, SecretBytes};

/// Most families tracked per database walk (the builder's template bound).
pub(crate) const MAX_FAMILIES: usize = keys::MAX_TEMPLATES;

struct Family {
    kind: u8,
    keys: Vec<SecretBytes>,
}

/// The sample keys kept per family during one database walk.
pub(crate) struct Families {
    state: RandomState,
    /// `n`: the sample keys per pattern (and per family).
    cap: usize,
    index: HashMap<u64, usize>,
    /// In the order the walk met them.
    list: Vec<Family>,
    held: usize,
    /// Keys held beyond each family's first (at most `2n`).
    extra: usize,
}

impl std::fmt::Debug for Families {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Families")
            .field("families", &self.list.len())
            .field("held", &self.held)
            .finish_non_exhaustive()
    }
}

/// The first segment and the segment count of a key's own pattern.
fn family_of(own: &str) -> (&str, usize) {
    let mut parts = own.split([':', '/', '|', '.']);
    let first = parts.next().unwrap_or_default();
    (first, 1 + parts.count())
}

impl Families {
    /// Families keeping at most `n` sample keys each.
    pub(crate) fn new(n: usize) -> Self {
        Self {
            state: RandomState::new(),
            cap: n,
            index: HashMap::new(),
            list: Vec::new(),
            held: 0,
            extra: 0,
        }
    }

    /// The most keys held beyond each family's first.
    fn extra_budget(&self) -> usize {
        self.cap.saturating_mul(2)
    }

    /// Families tracked so far.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.list.len()
    }

    /// Keys held so far.
    #[cfg(test)]
    pub(crate) fn held(&self) -> usize {
        self.held
    }

    /// One key of the walk: `raw` its name, `own` its own pattern
    /// ([`keys::KeyUnits::pattern`]), `kind` its type code.
    pub(crate) fn add(&mut self, raw: &[u8], own: &str, kind: u8) {
        if self.cap == 0 {
            return;
        }
        let (first, count) = family_of(own);
        let id = self.state.hash_one((first, count, kind));
        let idx = match self.index.get(&id) {
            Some(i) => *i,
            None => {
                if self.list.len() >= MAX_FAMILIES {
                    return;
                }
                self.index.insert(id, self.list.len());
                self.list.push(Family {
                    kind,
                    keys: Vec::new(),
                });
                self.list.len() - 1
            }
        };
        let extra_budget = self.extra_budget();
        let Some(family) = self.list.get_mut(idx) else {
            return;
        };
        let first = family.keys.is_empty();
        if family.keys.len() >= self.cap || (!first && self.extra >= extra_budget) {
            return;
        }
        family.keys.push(SecretBytes::new(raw));
        self.held = self.held.saturating_add(1);
        if !first {
            self.extra = self.extra.saturating_add(1);
        }
    }

    /// After the walk: each emitted pattern that holds keys of two or more
    /// families gets its sample keys in turn from each family (in the order
    /// the walk met them), filled up with the builder's own samples, at
    /// most `n`.
    pub(crate) fn rebalance(self, emitted: &mut [EmittedPattern]) {
        let cap = self.cap;
        if cap == 0 || self.list.len() < 2 {
            return;
        }
        let learned = LearnedPatterns::new(emitted.iter().map(|p| p.pattern.as_str()));
        let slots: HashMap<(String, u8), usize> = emitted
            .iter()
            .enumerate()
            .map(|(i, p)| ((p.pattern.as_str().to_owned(), p.kind), i))
            .collect();
        // Per emitted pattern: the keys of each family, families in walk
        // order.
        let mut per: Vec<Vec<Vec<SecretBytes>>> = Vec::new();
        per.resize_with(emitted.len(), Vec::new);
        for family in self.list {
            // This family's bucket in each pattern it feeds.
            let mut buckets: HashMap<usize, usize> = HashMap::new();
            for key in family.keys {
                let Some(p) = learned.pattern_of(key.expose()) else {
                    continue;
                };
                let Some(&slot) = slots.get(&(p.as_str().to_owned(), family.kind)) else {
                    continue;
                };
                let Some(lists) = per.get_mut(slot) else {
                    continue;
                };
                let b = *buckets.entry(slot).or_insert_with(|| {
                    lists.push(Vec::new());
                    lists.len() - 1
                });
                if let Some(list) = lists.get_mut(b) {
                    list.push(key);
                }
            }
        }
        for (pattern, lists) in emitted.iter_mut().zip(per) {
            if lists.len() < 2 {
                continue;
            }
            let chosen = round_robin(lists, cap);
            let group = &mut pattern.group;
            let mut names = Vec::new();
            for k in &chosen {
                names.extend(keys::split_key(k.expose()).name_values);
            }
            let mut samples = chosen;
            for s in std::mem::take(&mut group.samples) {
                if samples.len() >= cap {
                    break;
                }
                if !samples.contains(&s) {
                    samples.push(s);
                }
            }
            for v in std::mem::take(&mut group.name_values) {
                if !names.contains(&v) {
                    names.push(v);
                }
            }
            names.truncate(cap);
            group.samples = samples;
            group.name_values = names;
        }
    }
}

/// At most `cap` items, one from each list in turn.
fn round_robin<T>(lists: Vec<Vec<T>>, cap: usize) -> Vec<T> {
    let mut iters: Vec<std::vec::IntoIter<T>> = lists.into_iter().map(Vec::into_iter).collect();
    let mut out = Vec::new();
    while out.len() < cap {
        let mut any = false;
        for it in &mut iters {
            if out.len() >= cap {
                break;
            }
            if let Some(v) = it.next() {
                out.push(v);
                any = true;
            }
        }
        if !any {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use databastion_classifiers::keys::PatternBuilder;

    /// A walk as `discover::walk` runs it.
    fn walk(n: usize, names: &[String]) -> Vec<EmittedPattern> {
        let mut builder = PatternBuilder::new(n);
        let mut families = Families::new(n);
        for name in names {
            let units = keys::split_key(name.as_bytes());
            families.add(name.as_bytes(), units.pattern().as_str(), 0);
            builder.add(name.as_bytes(), units, 0);
        }
        let mut emitted = builder.finish();
        families.rebalance(&mut emitted);
        emitted
    }

    fn sampled(p: &EmittedPattern) -> Vec<String> {
        p.group
            .samples
            .iter()
            .map(|s| String::from_utf8(s.expose().to_vec()).unwrap())
            .collect()
    }

    #[test]
    fn a_family_met_late_in_the_walk_is_sampled() {
        // 40 `phone:<n>` keys first, then 3 `addressbook:<n>`: merged into
        // `*:*` (implementation note "Over-masking cascade").
        let mut names: Vec<String> = (1..=40).map(|i| format!("phone:{i}")).collect();
        names.extend((1..=3).map(|i| format!("addressbook:{i}")));
        let emitted = walk(4, &names);
        assert_eq!(emitted.len(), 1);
        let p = &emitted[0];
        assert_eq!(p.pattern.as_str(), "*:*");
        assert_eq!(p.group.count, 43);
        let s = sampled(p);
        assert_eq!(s.len(), 4);
        assert_eq!(s.iter().filter(|k| k.starts_with("phone:")).count(), 2);
        assert_eq!(
            s.iter().filter(|k| k.starts_with("addressbook:")).count(),
            2
        );
        // In turn, in walk order.
        assert_eq!(s, ["phone:1", "addressbook:1", "phone:2", "addressbook:2"]);
    }

    #[test]
    fn without_a_late_family_the_builders_samples_stand() {
        let names: Vec<String> = (1..=10).map(|i| format!("phone:{i}")).collect();
        let emitted = walk(3, &names);
        assert_eq!(emitted.len(), 1);
        assert_eq!(sampled(&emitted[0]), ["phone:1", "phone:2", "phone:3"]);
    }

    #[test]
    fn a_short_family_is_filled_up_with_the_others() {
        let mut names: Vec<String> = (1..=20).map(|i| format!("phone:{i}")).collect();
        names.push("addressbook:1".to_owned());
        let emitted = walk(5, &names);
        let s = sampled(&emitted[0]);
        assert_eq!(s.len(), 5);
        assert!(s.contains(&"addressbook:1".to_owned()));
        let mut dedup = s.clone();
        dedup.sort();
        dedup.dedup();
        assert_eq!(dedup.len(), 5, "no key sampled twice");
    }

    #[test]
    fn many_families_each_get_a_key_before_any_gets_two() {
        let mut names = Vec::new();
        for fam in ["a", "b", "c", "d", "e", "f"] {
            for i in 1..=30 {
                names.push(format!("{fam}x:{i}"));
            }
        }
        let emitted = walk(6, &names);
        assert_eq!(emitted.len(), 1);
        let firsts: std::collections::BTreeSet<String> = sampled(&emitted[0])
            .iter()
            .map(|k| k.split(':').next().unwrap().to_owned())
            .collect();
        assert_eq!(firsts.len(), 6);
    }

    #[test]
    fn patterns_that_did_not_merge_are_unchanged() {
        // Two families that stay apart (different shapes).
        let mut names: Vec<String> = (1..=5).map(|i| format!("user:{i}:email")).collect();
        names.extend((1..=5).map(|i| format!("cart:{i}")));
        let emitted = walk(2, &names);
        assert_eq!(emitted.len(), 2);
        for p in &emitted {
            let s = sampled(p);
            assert_eq!(s.len(), 2);
            let first = s[0].split(':').next().unwrap().to_owned();
            assert!(s.iter().all(|k| k.starts_with(&first)));
        }
    }

    #[test]
    fn values_in_names_follow_the_chosen_keys() {
        let mut names: Vec<String> = (1..=30).map(|i| format!("phone:{i}")).collect();
        names.extend((1..=3).map(|i| format!("mail:jane{i}@example.com")));
        let emitted = walk(4, &names);
        let p = emitted
            .iter()
            .find(|p| p.pattern.as_str() == "*:*")
            .expect("merged");
        let s = sampled(p);
        assert!(s.iter().any(|k| k.starts_with("mail:")), "{s:?}");
        assert!(
            p.group
                .name_values
                .iter()
                .any(|v| v.expose().contains("@example.com"))
        );
        assert!(p.group.name_values.len() <= 4);
    }

    #[test]
    fn bounds() {
        let mut f = Families::new(3);
        for i in 0..(MAX_FAMILIES + 50) {
            for j in 0..5 {
                f.add(format!("f{i}:{j}").as_bytes(), &format!("f{i}:*"), 0);
            }
        }
        assert_eq!(f.len(), MAX_FAMILIES);
        assert!(f.held() <= 2 * 3 + MAX_FAMILIES);
        // Every tracked family got its first key.
        assert!(f.list.iter().all(|fam| !fam.keys.is_empty()));
        assert!(f.list.iter().all(|fam| fam.keys.len() <= 3));
        let mut none = Families::new(0);
        none.add(b"a:1", "a:*", 0);
        assert_eq!(none.len(), 0);
        assert_eq!(family_of("user:*:email"), ("user", 3));
        assert_eq!(family_of("*"), ("*", 1));
    }

    #[test]
    fn round_robin_order_and_cap() {
        let r = round_robin(vec![vec![1, 2, 3], vec![10], vec![20, 21]], 5);
        assert_eq!(r, [1, 10, 20, 2, 21]);
        assert_eq!(round_robin(vec![vec![1], vec![2]], 10), [1, 2]);
        assert!(round_robin::<u8>(vec![], 3).is_empty());
    }
}
