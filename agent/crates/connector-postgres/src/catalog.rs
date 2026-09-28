//! Schema introspection and sampling scope (ADR-0012 obligations 1 and 2).
//!
//! Sampled: tables (`r`) and materialized views (`m`) the role can read, in
//! schemas it has `USAGE` on, outside the system schemas and extensions.
//! Never sampled: foreign tables (`f`), partitioned tables (`p`, read
//! through their leaves), relations whose row-level security policies
//! depend on anything but `pg_catalog` and the relation itself, and leaf
//! partitions / inheritance children with a row-level security ancestor
//! (reading them directly would bypass the ancestor's policies). The
//! skipped relations are the "not covered" part of `check()`.
//!
//! A leaf partition is reported under its partitioned root: the leaves of
//! one root form one [`Unit`], sampled leaf by leaf (`FROM ONLY`) within the
//! job's `sample_rows` budget, and classified together.

use std::collections::BTreeMap;

use tokio_postgres::types::Type;

use crate::conn::ReadTx;
use crate::error::{PgError, Stage};
use crate::sql;
use crate::wire::catalog_text;

/// Most relations introspected per database.
pub(crate) const MAX_RELATIONS: i64 = 100_000;
/// Most leaves sampled per partitioned root (the largest ones).
pub(crate) const MAX_LEAVES: usize = 64;

/// One relation from the catalogs (names are raw: never sent or logged
/// without normalization; `Debug` shows neither).
#[derive(Clone, PartialEq)]
pub(crate) struct Relation {
    pub(crate) oid: u32,
    pub(crate) schema: String,
    pub(crate) name: String,
    pub(crate) kind: u8,
    pub(crate) is_partition: bool,
    pub(crate) reltuples: f32,
    pub(crate) rls: bool,
    pub(crate) readable: bool,
    pub(crate) ancestor_rls: bool,
    pub(crate) root: u32,
    pub(crate) rls_blocked: bool,
}

impl std::fmt::Debug for Relation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Relation")
            .field("oid", &self.oid)
            .field("kind", &char::from(self.kind))
            .finish_non_exhaustive()
    }
}

/// Reads the relations in scope of obligation 1, then checks the policy
/// expressions of the row-level security tables not already blocked by
/// `pg_depend` (H1). Rows whose names are not UTF-8 are skipped (L1).
pub(crate) async fn introspect(tx: &ReadTx<'_>) -> Result<Vec<Relation>, PgError> {
    let rows = tx
        .query(
            Stage::Introspection,
            sql::INTROSPECT,
            &[(&MAX_RELATIONS, Type::INT8)],
        )
        .await?;
    let get = |e: tokio_postgres::Error| PgError::from_driver(&e, Stage::Introspection);
    let mut out = Vec::with_capacity(rows.len());
    let mut undecodable = 0usize;
    for row in &rows {
        let (Some(schema), Some(name)) = (
            catalog_text(row, 1).map_err(get)?,
            catalog_text(row, 2).map_err(get)?,
        ) else {
            undecodable += 1;
            continue;
        };
        let kind: i8 = row.try_get(3).map_err(get)?;
        out.push(Relation {
            oid: row.try_get(0).map_err(get)?,
            schema,
            name,
            kind: kind.to_ne_bytes()[0],
            is_partition: row.try_get(4).map_err(get)?,
            reltuples: row.try_get(5).map_err(get)?,
            rls: row.try_get(6).map_err(get)?,
            readable: row.try_get(7).map_err(get)?,
            ancestor_rls: row.try_get(8).map_err(get)?,
            root: row.try_get(9).map_err(get)?,
            rls_blocked: row.try_get(10).map_err(get)?,
        });
    }
    if undecodable > 0 {
        tracing::warn!(
            count = undecodable,
            "relations with names that are not valid UTF-8 are not covered"
        );
    }
    if rows.len() >= usize::try_from(MAX_RELATIONS).unwrap_or(usize::MAX) {
        tracing::warn!(
            limit = MAX_RELATIONS,
            "introspection reached its relation limit; later relations are not covered"
        );
    }
    check_policies(tx, &mut out).await?;
    Ok(out)
}

/// Marks as blocked the row-level security relations whose `SELECT`
/// policies use a node type, function, operator or I/O coercion outside
/// the allow-lists (`policy`, `sql::POLICY_REFS_REJECTED`).
async fn check_policies(tx: &ReadTx<'_>, relations: &mut [Relation]) -> Result<(), PgError> {
    let candidates: Vec<u32> = relations
        .iter()
        .filter(|r| r.rls && !r.rls_blocked)
        .map(|r| r.oid)
        .collect();
    if candidates.is_empty() {
        return Ok(());
    }
    let get = |e: tokio_postgres::Error| PgError::from_driver(&e, Stage::Introspection);
    let rows = tx
        .query(
            Stage::Introspection,
            sql::POLICY_TREES,
            &[(&candidates, Type::OID_ARRAY)],
        )
        .await?;
    let mut trees: BTreeMap<u32, Vec<Option<String>>> = BTreeMap::new();
    for row in &rows {
        let rel: u32 = row.try_get(0).map_err(get)?;
        let entry = trees.entry(rel).or_default();
        for i in [1, 2] {
            if row
                .try_get::<_, Option<crate::wire::WireBytes<'_>>>(i)
                .map_err(get)?
                .is_some()
            {
                // Present but not UTF-8: unsupported (None).
                entry.push(catalog_text(row, i).map_err(get)?);
            }
        }
    }
    for rel in relations.iter_mut().filter(|r| r.rls && !r.rls_blocked) {
        let Some(exprs) = trees.get(&rel.oid) else {
            continue; // no SELECT policy: default deny, nothing runs
        };
        let texts: Option<Vec<&str>> = exprs.iter().map(Option::as_deref).collect();
        let Some(refs) = texts.and_then(|t| crate::policy::scan(&t, rel.oid)) else {
            rel.rls_blocked = true;
            continue;
        };
        let as_vec = |s: &std::collections::BTreeSet<u32>| s.iter().copied().collect::<Vec<u32>>();
        let (f, o, t) = (
            as_vec(&refs.functions),
            as_vec(&refs.operators),
            as_vec(&refs.io_types),
        );
        let rejected: i64 = tx
            .query(
                Stage::Introspection,
                sql::POLICY_REFS_REJECTED,
                &[
                    (&f, Type::OID_ARRAY),
                    (&o, Type::OID_ARRAY),
                    (&t, Type::OID_ARRAY),
                ],
            )
            .await?
            .first()
            .map(|r| r.try_get(0))
            .transpose()
            .map_err(get)?
            .unwrap_or(1);
        rel.rls_blocked = rejected > 0;
    }
    Ok(())
}

/// A relation read directly (a table, a materialized view, or a leaf of a
/// partitioned root).
#[derive(Clone, PartialEq)]
pub(crate) struct Member {
    pub(crate) oid: u32,
    pub(crate) schema: String,
    pub(crate) name: String,
    pub(crate) reltuples: f32,
}

/// What is reported as one object: a table / materialized view, or a
/// partitioned root with its readable leaves.
#[derive(Clone, PartialEq)]
pub(crate) struct Unit {
    pub(crate) schema: String,
    pub(crate) name: String,
    /// Sampled in this order (ascending `reltuples`: small leaves take
    /// little of the budget, the rest goes to the larger ones).
    pub(crate) members: Vec<Member>,
    /// A sampled member has row-level security: the sample may be
    /// incomplete (policies apply to the agent role).
    pub(crate) rls: bool,
}

impl Unit {
    /// Sum of the members' `reltuples` estimates, when known.
    pub(crate) fn estimated_rows(&self) -> Option<u64> {
        let known: Vec<f64> = self
            .members
            .iter()
            .map(|m| f64::from(m.reltuples))
            .filter(|r| *r >= 0.0)
            .collect();
        if known.is_empty() {
            return None;
        }
        let sum: f64 = known.iter().sum();
        // Estimates are non-negative and far below 2^53.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        Some(sum.round() as u64)
    }
}

/// Relations in the job's scope that are not sampled, by reason (raw names:
/// normalize before logging).
#[derive(Clone, Default, PartialEq, Eq)]
pub(crate) struct Coverage {
    /// No `SELECT` on any column.
    pub(crate) not_readable: Vec<(String, String)>,
    /// Row-level security policy depending on user code or another
    /// relation (obligation 2).
    pub(crate) rls_policy: Vec<(String, String)>,
    /// Leaf partition or inheritance child with a row-level security
    /// ancestor (obligation 1).
    pub(crate) rls_ancestor: Vec<(String, String)>,
    /// Foreign tables and foreign leaves (never read, I5).
    pub(crate) foreign: usize,
    /// Leaves beyond [`MAX_LEAVES`] of a partitioned root.
    pub(crate) leaves_over_limit: usize,
}

impl Coverage {
    pub(crate) fn not_covered(&self) -> usize {
        self.not_readable.len() + self.rls_policy.len() + self.rls_ancestor.len()
    }
}

impl std::fmt::Debug for Member {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Member")
            .field("oid", &self.oid)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Unit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Unit")
            .field("members", &self.members)
            .field("rls", &self.rls)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Coverage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Coverage")
            .field("not_readable", &self.not_readable.len())
            .field("rls_policy", &self.rls_policy.len())
            .field("rls_ancestor", &self.rls_ancestor.len())
            .field("foreign", &self.foreign)
            .field("leaves_over_limit", &self.leaves_over_limit)
            .finish()
    }
}

const KIND_TABLE: u8 = b'r';
const KIND_MATVIEW: u8 = b'm';
const KIND_FOREIGN: u8 = b'f';

/// Groups the sampled relations into [`Unit`]s. `include(schema, name)` is
/// the job filter, applied to the reported (root) names.
pub(crate) fn plan(
    relations: &[Relation],
    include: impl Fn(&str, &str) -> bool,
) -> (Vec<Unit>, Coverage) {
    let by_oid: std::collections::HashMap<u32, &Relation> =
        relations.iter().map(|r| (r.oid, r)).collect();
    let mut units: Vec<Unit> = Vec::new();
    let mut index: std::collections::HashMap<u32, usize> = std::collections::HashMap::new();
    let mut coverage = Coverage::default();
    for rel in relations {
        // Reported under the partitioned root when it is visible;
        // otherwise under its own name.
        let report = if rel.is_partition {
            by_oid.get(&rel.root).copied().unwrap_or(rel)
        } else {
            rel
        };
        if !include(&report.schema, &report.name) {
            continue;
        }
        let names = || (rel.schema.clone(), rel.name.clone());
        match rel.kind {
            KIND_FOREIGN => {
                coverage.foreign += 1;
                continue;
            }
            KIND_TABLE | KIND_MATVIEW => {}
            _ => continue,
        }
        if !rel.readable {
            coverage.not_readable.push(names());
            continue;
        }
        if rel.ancestor_rls {
            coverage.rls_ancestor.push(names());
            continue;
        }
        if rel.rls_blocked {
            coverage.rls_policy.push(names());
            continue;
        }
        let member = Member {
            oid: rel.oid,
            schema: rel.schema.clone(),
            name: rel.name.clone(),
            reltuples: rel.reltuples,
        };
        let i = *index.entry(report.oid).or_insert_with(|| {
            units.push(Unit {
                schema: report.schema.clone(),
                name: report.name.clone(),
                members: Vec::new(),
                rls: false,
            });
            units.len() - 1
        });
        units[i].rls |= rel.rls;
        units[i].members.push(member);
    }
    for unit in &mut units {
        if unit.members.len() > MAX_LEAVES {
            unit.members
                .sort_by(|a, b| b.reltuples.total_cmp(&a.reltuples).then(a.oid.cmp(&b.oid)));
            coverage.leaves_over_limit += unit.members.len() - MAX_LEAVES;
            unit.members.truncate(MAX_LEAVES);
        }
        unit.members
            .sort_by(|a, b| a.reltuples.total_cmp(&b.reltuples).then(a.oid.cmp(&b.oid)));
    }
    (units, coverage)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rel(oid: u32, name: &str, kind: u8) -> Relation {
        Relation {
            oid,
            schema: "s".to_owned(),
            name: name.to_owned(),
            kind,
            is_partition: false,
            reltuples: 10.0,
            rls: false,
            readable: true,
            ancestor_rls: false,
            root: oid,
            rls_blocked: false,
        }
    }

    fn leaf(oid: u32, name: &str, root: u32, reltuples: f32) -> Relation {
        Relation {
            is_partition: true,
            root,
            reltuples,
            ..rel(oid, name, b'r')
        }
    }

    #[test]
    fn leaves_are_reported_under_their_root() {
        let rels = vec![
            rel(1, "events", b'p'),
            leaf(2, "events_2025", 1, 500.0),
            leaf(3, "events_2026", 1, 0.0),
            Relation {
                kind: b'f',
                ..leaf(4, "events_remote", 1, -1.0)
            },
            rel(5, "customers", b'r'),
            rel(6, "report", b'm'),
            rel(7, "remote", b'f'),
        ];
        let (units, cov) = plan(&rels, |_, _| true);
        let names: Vec<&str> = units.iter().map(|u| u.name.as_str()).collect();
        assert_eq!(names, ["events", "customers", "report"]);
        let leaves: Vec<&str> = units[0].members.iter().map(|m| m.name.as_str()).collect();
        // Ascending reltuples; the foreign leaf is never a member.
        assert_eq!(leaves, ["events_2026", "events_2025"]);
        assert_eq!(units[0].estimated_rows(), Some(500));
        assert_eq!(cov.foreign, 2);
        assert_eq!(cov.not_covered(), 0);
    }

    #[test]
    fn rls_rules_skip_and_report() {
        let rels = vec![
            Relation {
                rls: true,
                ..rel(1, "root", b'p')
            },
            Relation {
                ancestor_rls: true,
                ..leaf(2, "root_leaf", 1, 5.0)
            },
            Relation {
                rls: true,
                rls_blocked: true,
                ..rel(3, "user_function_policy", b'r')
            },
            Relation {
                rls: true,
                ..rel(4, "builtin_policy", b'r')
            },
            Relation {
                readable: false,
                ..rel(5, "no_grant", b'r')
            },
            Relation {
                ancestor_rls: true,
                ..rel(6, "inheritance_child", b'r')
            },
        ];
        let (units, cov) = plan(&rels, |_, _| true);
        assert_eq!(units.len(), 1);
        assert_eq!(units[0].name, "builtin_policy");
        assert!(units[0].rls);
        let n = |v: &[(String, String)]| v.iter().map(|x| x.1.clone()).collect::<Vec<_>>();
        assert_eq!(n(&cov.rls_ancestor), ["root_leaf", "inheritance_child"]);
        assert_eq!(n(&cov.rls_policy), ["user_function_policy"]);
        assert_eq!(n(&cov.not_readable), ["no_grant"]);
    }

    #[test]
    fn filters_apply_to_reported_names() {
        let rels = vec![
            rel(1, "events", b'p'),
            leaf(2, "events_2025", 1, 5.0),
            rel(3, "customers", b'r'),
        ];
        let (units, _) = plan(&rels, |_, n| n != "events");
        assert_eq!(units.len(), 1);
        assert_eq!(units[0].name, "customers");
        let (units, _) = plan(&rels, |_, n| n == "events");
        assert_eq!(units.len(), 1);
        assert_eq!(units[0].members[0].name, "events_2025");
    }

    #[test]
    fn leaves_are_capped() {
        let mut rels = vec![rel(1, "big", b'p')];
        for i in 0..(MAX_LEAVES as u32 + 10) {
            #[allow(clippy::cast_precision_loss)]
            rels.push(leaf(100 + i, &format!("big_{i}"), 1, i as f32));
        }
        let (units, cov) = plan(&rels, |_, _| true);
        assert_eq!(units[0].members.len(), MAX_LEAVES);
        assert_eq!(cov.leaves_over_limit, 10);
        // The largest leaves are kept.
        assert!(units[0].members.iter().all(|m| m.reltuples >= 10.0));
    }
}
