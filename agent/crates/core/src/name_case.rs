//! Name case semantics of a target (`TargetStatus.name_case`, ADR-0055).
//!
//! The MySQL / MariaDB and SQL Server connectors read, at each `check()`,
//! whether names that differ only by case are one name on the server
//! (`lower_case_table_names`, collations) and keep the last value read
//! ([`crate::Connector::name_case`]). The core turns it into the protocol
//! type here ([`to_protocol`]): database names are already normalized by
//! the connector (`classifiers::names`, ADR-0009); entries of one name are
//! merged with the stricter value, entries equal to `objects` dropped, the
//! rest sorted by the byte order of the name, and past [`MAX_EXCEPT`]
//! entries or [`MAX_EXCEPT_BYTES`] serialized, `objects` becomes `unknown`
//! without `except` (decision 4, security review L4).
//!
//! The field is sent only for `mysql`, `mariadb` and `sqlserver` targets,
//! only when the console lists `target_status.name_case`, and then in
//! every status of such a target, also when `check()` failed or timed out
//! (decision 2, security review M1): the connector's last value, else
//! `unknown` for both parts. Closed values and normalized names only (I2).

use std::collections::BTreeMap;

use databastion_classifiers::names::{NormalizedName, violates_numeric_rule};
use databastion_protocol::{Identifier, TargetNameCase, TargetNameCaseException};

/// Contract `TargetNameCase.except.maxItems`.
pub const MAX_EXCEPT: usize = 32;
/// Agent-side bound on `except` serialized as compact JSON (ADR-0055
/// decision 4, security review L4; contract text).
pub const MAX_EXCEPT_BYTES: usize = 8192;

/// How names compare on the server (contract `NameCase`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NameCase {
    /// Names that differ only by case are distinct.
    Sensitive,
    /// Names that differ only by case are one name.
    Insensitive,
    /// Not known (the console reads it as `Sensitive`).
    Unknown,
}

impl NameCase {
    /// Rank in the stricter-first order of ADR-0055 decision 4:
    /// `sensitive`, then `unknown`, then `insensitive`.
    const fn rank(self) -> u8 {
        match self {
            Self::Sensitive => 2,
            Self::Unknown => 1,
            Self::Insensitive => 0,
        }
    }

    /// The stricter of two values.
    #[must_use]
    pub const fn stricter(self, other: Self) -> Self {
        if other.rank() > self.rank() {
            other
        } else {
            self
        }
    }

    const fn to_protocol(self) -> databastion_protocol::NameCase {
        match self {
            Self::Sensitive => databastion_protocol::NameCase::Sensitive,
            Self::Insensitive => databastion_protocol::NameCase::Insensitive,
            Self::Unknown => databastion_protocol::NameCase::Unknown,
        }
    }
}

/// What a connector read: how database names compare, the default for
/// schema, object and column names, and the databases that differ from
/// it, by normalized name (several may share one name; the core merges
/// them).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameCaseReport {
    /// How database names compare.
    pub databases: NameCase,
    /// Default for schema, object and column names.
    pub objects: NameCase,
    /// Databases whose object names compare otherwise, by normalized name.
    pub except: Vec<(NormalizedName, NameCase)>,
}

impl NameCaseReport {
    /// `unknown` for both parts, no `except`: nothing read on this server
    /// run.
    #[must_use]
    pub fn unknown() -> Self {
        Self::uniform(NameCase::Unknown)
    }

    /// One value for database and object names, no `except`.
    #[must_use]
    pub fn uniform(value: NameCase) -> Self {
        Self {
            databases: value,
            objects: value,
            except: Vec::new(),
        }
    }
}

/// A normalized name as a contract `Identifier`; `*` when it does not
/// conform (a Redis key pattern, the `not` rule): fail closed, it then
/// merges into the `*` entry.
fn identifier(name: &NormalizedName) -> Option<Identifier> {
    let s = name.as_str();
    if !violates_numeric_rule(s)
        && let Ok(id) = Identifier::try_from(s)
    {
        return Some(id);
    }
    Identifier::try_from("*").ok()
}

/// The protocol value of `report` (see the module documentation).
#[must_use]
pub fn to_protocol(report: &NameCaseReport) -> TargetNameCase {
    // One entry per name as sent, the stricter value; sorted by the byte
    // order of the UTF-8 name (`String`'s `Ord`).
    let mut merged: BTreeMap<String, NameCase> = BTreeMap::new();
    let mut lost = false;
    for (name, value) in &report.except {
        let Some(id) = identifier(name) else {
            lost = true;
            continue;
        };
        merged
            .entry(id.as_str().to_owned())
            .and_modify(|v| *v = v.stricter(*value))
            .or_insert(*value);
    }
    let except: Vec<TargetNameCaseException> = merged
        .into_iter()
        .filter(|(_, v)| *v != report.objects)
        .filter_map(|(name, v)| {
            Some(TargetNameCaseException {
                database: Identifier::try_from(name.as_str()).ok()?,
                objects: v.to_protocol(),
            })
        })
        .collect();
    let fits = !lost
        && except.len() <= MAX_EXCEPT
        && serde_json::to_vec(&except).is_ok_and(|b| b.len() <= MAX_EXCEPT_BYTES);
    if fits {
        TargetNameCase {
            databases: report.databases.to_protocol(),
            except,
            objects: report.objects.to_protocol(),
        }
    } else {
        TargetNameCase {
            databases: report.databases.to_protocol(),
            except: Vec::new(),
            objects: databastion_protocol::NameCase::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use databastion_classifiers::names::{PathPart, normalize_field_path};
    use databastion_protocol::NameCase as P;

    fn n(raw: &str) -> NormalizedName {
        normalize_field_path(&[PathPart::Key(raw)])
    }

    fn names(t: &TargetNameCase) -> Vec<(&str, P)> {
        t.except
            .iter()
            .map(|e| (e.database.as_str(), e.objects))
            .collect()
    }

    #[test]
    fn stricter_is_sensitive_then_unknown_then_insensitive() {
        use NameCase::{Insensitive as I, Sensitive as S, Unknown as U};
        for (a, b, want) in [
            (S, U, S),
            (U, S, S),
            (S, I, S),
            (I, S, S),
            (U, I, U),
            (I, U, U),
            (I, I, I),
            (U, U, U),
            (S, S, S),
        ] {
            assert_eq!(a.stricter(b), want, "{a:?} {b:?}");
        }
    }

    #[test]
    fn unknown_report_has_both_parts_unknown_and_no_except() {
        let t = to_protocol(&NameCaseReport::unknown());
        assert_eq!((t.databases, t.objects), (P::Unknown, P::Unknown));
        assert!(t.except.is_empty());
        let json = serde_json::to_value(&t).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"databases": "unknown", "objects": "unknown"})
        );
    }

    /// Entries are sorted by byte order, merged per name with the stricter
    /// value, and those equal to `objects` dropped (security review L2).
    #[test]
    fn entries_are_sorted_merged_and_minimal() {
        let r = NameCaseReport {
            databases: NameCase::Insensitive,
            objects: NameCase::Insensitive,
            except: vec![
                (n("zeta"), NameCase::Sensitive),
                (n("Alpha"), NameCase::Unknown),
                (n("alpha"), NameCase::Sensitive),
                (n("Alpha"), NameCase::Sensitive),
                (n("beta"), NameCase::Insensitive),
                (n("émile_db"), NameCase::Unknown),
            ],
        };
        let t = to_protocol(&r);
        assert_eq!(
            names(&t),
            [
                ("Alpha", P::Sensitive),
                ("alpha", P::Sensitive),
                ("zeta", P::Sensitive),
                ("émile_db", P::Unknown),
            ]
        );
        assert_eq!(t.objects, P::Insensitive);
    }

    /// ADR-0055 decision 4 (security review L3): two databases whose names
    /// a classifier matches reach the console as one `*` entry, with the
    /// stricter value; the value never leaves the agent (I2).
    #[test]
    fn a_classifier_matched_database_name_is_sent_as_the_wildcard() {
        let r = NameCaseReport {
            databases: NameCase::Insensitive,
            objects: NameCase::Insensitive,
            except: vec![
                (n("jane.doe@example.com"), NameCase::Unknown),
                (n("FR7630006000011234567890189"), NameCase::Sensitive),
                (n("crm"), NameCase::Sensitive),
            ],
        };
        let t = to_protocol(&r);
        assert_eq!(names(&t), [("*", P::Sensitive), ("crm", P::Sensitive)]);
        let text = serde_json::to_string(&t).unwrap();
        assert!(!text.contains("jane") && !text.contains("FR76"), "{text}");
    }

    #[test]
    fn bounds_turn_objects_unknown_without_except() {
        let entries = |count: usize, len: usize| NameCaseReport {
            databases: NameCase::Insensitive,
            objects: NameCase::Insensitive,
            except: (0..count)
                .map(|i| {
                    let name = format!("{}{}", char::from(b'a' + (i % 26) as u8), "x".repeat(len));
                    (n(&format!("{name}{}", i / 26)), NameCase::Sensitive)
                })
                .collect(),
        };
        // 32 short entries fit.
        let t = to_protocol(&entries(32, 3));
        assert_eq!(t.except.len(), 32);
        assert_eq!(t.objects, P::Insensitive);
        // 33 do not.
        let t = to_protocol(&entries(33, 3));
        assert!(t.except.is_empty());
        assert_eq!((t.databases, t.objects), (P::Insensitive, P::Unknown));
        // 32 long names pass 8 KiB.
        let t = to_protocol(&entries(32, 250));
        assert!(t.except.is_empty());
        assert_eq!(t.objects, P::Unknown);
        // Just under the byte bound: kept, and serialized within it.
        let r = entries(30, 230);
        let t = to_protocol(&r);
        let bytes = serde_json::to_vec(&t.except).unwrap().len();
        assert!(bytes <= MAX_EXCEPT_BYTES, "{bytes}");
        assert_eq!(t.except.len(), 30);
        // Merged entries count once, and dropped ones (equal to `objects`)
        // not at all.
        let mut r = entries(32, 3);
        r.except.extend(entries(32, 3).except);
        r.except
            .extend((0..40).map(|i| (n(&format!("same{i}")), NameCase::Insensitive)));
        assert_eq!(to_protocol(&r).except.len(), 32);
    }

    /// The fixtures' shapes: every value the schema allows, built from the
    /// agent's own report.
    #[test]
    fn reports_serialize_to_the_contract() {
        let r = NameCaseReport {
            databases: NameCase::Insensitive,
            objects: NameCase::Insensitive,
            except: vec![
                (n("crm_cs"), NameCase::Sensitive),
                (n("offline_db"), NameCase::Unknown),
            ],
        };
        let json = serde_json::to_value(to_protocol(&r)).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "databases": "insensitive",
                "objects": "insensitive",
                "except": [
                    {"database": "crm_cs", "objects": "sensitive"},
                    {"database": "offline_db", "objects": "unknown"}
                ]
            })
        );
        let _: TargetNameCase = serde_json::from_value(json).unwrap();
        let s = to_protocol(&NameCaseReport::uniform(NameCase::Sensitive));
        assert_eq!(
            serde_json::to_value(s).unwrap(),
            serde_json::json!({"databases": "sensitive", "objects": "sensitive"})
        );
    }
}
