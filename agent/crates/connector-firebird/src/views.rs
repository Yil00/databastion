//! The dependent set (ADR-0060 R41, replacing R12 item 5's view-only
//! set): at every re-evaluation, `check()` reads `RDB$VIEW_RELATIONS`,
//! `RDB$DEPENDENCIES` (views 1, triggers 2, computed columns 3, domain
//! checks 4, procedures 5, functions 15, packages 18 and 19), every
//! column's field source (`RDB$RELATION_FIELDS`) and every routine,
//! package and trigger name, and computes the objects that depend,
//! directly or transitively, on a relation of the statement-text or
//! credential-bearing always-reported lists
//! ([`crate::trace_events::always_listed`]): views, procedures, functions,
//! packages, triggers, and tables with a dependent computed column, a
//! dependent domain check (R41 item 1: writes would be enough; the whole
//! table counts, over-reporting until the tracing of domain checks is
//! measured) or a dependent check-constraint trigger.
//!
//! - **Nodes** are keyed by namespace (R41 item 1, review L2): relations
//!   (tables and views), procedures, functions, packages, triggers and
//!   fields (domains); a dependency row of a packaged routine resolves to
//!   its package's node, so a standalone `P` and a packaged `PKG.P` are
//!   distinct.
//! - **Strongly connected components** (iterative Tarjan): each member of
//!   a component is dependent when any member is or a component it
//!   depends on is (recursive routines, packages calling each other).
//! - **Bounds, fail closed** (R41 item 2): at most [`MAX_ROWS`] rows per
//!   read and [`MAX_DEPENDENT`] dependent objects; no depth bound. A
//!   failed or cut read, a name that is not UTF-8, a computed-column row
//!   that maps to no table, or more dependent objects than the bound make
//!   the set incomplete: every view, routine, package and trigger, every
//!   table with a computed column, and every unknown name then count as
//!   dependent ([`crate::audit::Classes`]).
//!
//! No view is block-blind (R28 item 3 is not implemented): a block-less
//! view read that returned rows stays ambiguous.

use std::collections::{HashMap, HashSet};

use tokio::time::Instant;

use crate::conn::Session;
use crate::error::FbError;
use crate::sql::{self, Col, Value};
use crate::trace_events::always_listed;

/// Rows read from each catalog relation at most (R41 item 2).
pub(crate) const MAX_ROWS: usize = 65_536;
/// Dependent objects at most (R41 item 2).
pub(crate) const MAX_DEPENDENT: usize = 16_384;

/// The dependent set of one database (R41).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ViewDeps {
    /// Names of the dependent objects, every kind (matched without regard
    /// to kind, R41 item 6).
    pub(crate) dependent: HashSet<String>,
    /// Tables with a computed column (counted dependent when incomplete).
    pub(crate) computed: HashSet<String>,
    /// The columns were read (`computed` is meaningful).
    pub(crate) computed_known: bool,
    /// Every routine, package and trigger name the read gave (a name in an
    /// object position unknown to the catalog is dependent, R41 item 3).
    pub(crate) routines: HashSet<String>,
    /// The reads were complete and within the bounds.
    pub(crate) complete: bool,
}

/// A catalog object, by namespace (R41 item 1).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Node {
    /// A table or a view (one namespace).
    Relation(String),
    Procedure(String),
    Function(String),
    Package(String),
    Trigger(String),
    /// A domain (field source): computed columns and domain checks.
    Field(String),
}

impl Node {
    /// `RDB$DEPENDENCIES` object types; others are not followed.
    fn of(kind: i64, name: String) -> Option<Self> {
        match kind {
            0 | 1 => Some(Self::Relation(name)),
            2 => Some(Self::Trigger(name)),
            3 | 4 | 9 => Some(Self::Field(name)),
            5 => Some(Self::Procedure(name)),
            15 => Some(Self::Function(name)),
            18 | 19 => Some(Self::Package(name)),
            _ => None,
        }
    }

    /// The object's name, `None` for a domain (not an object a record names).
    fn name(&self) -> Option<&str> {
        match self {
            Self::Relation(n)
            | Self::Procedure(n)
            | Self::Function(n)
            | Self::Package(n)
            | Self::Trigger(n) => Some(n),
            Self::Field(_) => None,
        }
    }
}

/// One row of [`sql::VIEW_RELATIONS`]: view, base, context type.
pub(crate) type ViewRow = (String, String, i64);
/// One row of [`sql::DEPENDENCIES`]: dependent, its type, depended-on, its
/// type, the dependent's package.
pub(crate) type DepRow = (String, i64, String, i64, Option<String>);
/// One row of [`sql::FIELD_SOURCES`]: relation, field source, computed.
pub(crate) type FieldRow = (String, String, bool);
/// One row of [`sql::ROUTINES`]: name, package, type, a trigger's
/// relation, system flag.
pub(crate) type RoutineRow = (String, Option<String>, i64, Option<String>, i64);

/// The reads of one database (`None`: failed, cut, or a row dropped).
#[derive(Debug, Default)]
pub(crate) struct Reads {
    pub(crate) views: Option<Vec<ViewRow>>,
    pub(crate) deps: Option<Vec<DepRow>>,
    pub(crate) fields: Option<Vec<FieldRow>>,
    pub(crate) routines: Option<Vec<RoutineRow>>,
}

/// The dependent set from the reads.
pub(crate) fn compute(r: Reads) -> ViewDeps {
    let mut out = ViewDeps::default();
    if let Some(fields) = &r.fields {
        out.computed_known = true;
        out.computed = fields.iter().filter(|f| f.2).map(|f| f.0.clone()).collect();
    }
    if let Some(routines) = &r.routines {
        for (name, package, _, _, _) in routines {
            out.routines.insert(name.clone());
            if let Some(p) = package {
                out.routines.insert(p.clone());
            }
        }
    }
    let (Some(views), Some(deps), Some(fields), Some(routines)) =
        (r.views, r.deps, r.fields, r.routines)
    else {
        return out;
    };
    let mut edges: HashMap<Node, Vec<Node>> = HashMap::new();
    for (view, base, context) in views {
        // Context type 2: a selectable procedure in the view's `FROM`.
        let to = if context == 2 {
            Node::Procedure(base)
        } else {
            Node::Relation(base)
        };
        edges.entry(Node::Relation(view)).or_default().push(to);
    }
    let computed_sources: HashSet<&str> = fields
        .iter()
        .filter(|f| f.2)
        .map(|f| f.1.as_str())
        .collect();
    for (dependent, dtype, on, otype, package) in &deps {
        // A computed column that maps to no table (R41 item 2).
        if *dtype == 3 && !computed_sources.contains(dependent.as_str()) {
            return out;
        }
        // `RDB$PACKAGE_NAME` is the depended-on object's package (measured
        // on 5.0.4: a view column calling `PKG.F` is recorded as depending
        // on `F`, type 15, package `PKG`); a packaged routine's own
        // dependencies are its package body's (type 19). A packaged routine
        // resolves to its package's node (L2).
        let to = match package {
            Some(p) if matches!(otype, 5 | 15) => Some(Node::Package(p.clone())),
            _ => Node::of(*otype, on.clone()),
        };
        if let (Some(from), Some(to)) = (Node::of(*dtype, dependent.clone()), to) {
            edges.entry(from).or_default().push(to);
        }
    }
    // A table depends on its columns' domains (computed columns, domain
    // checks) and on its check-constraint triggers (system flag set).
    for (relation, source, _) in fields {
        edges
            .entry(Node::Relation(relation))
            .or_default()
            .push(Node::Field(source));
    }
    // A table with an expression index: its dependency is not recorded
    // (measured), so the table counts as dependent (R41 item 9).
    let mut indexed: HashSet<String> = HashSet::new();
    for (name, _, kind, relation, system) in routines {
        match (kind, relation) {
            (2, Some(rel)) if system != 0 => {
                edges
                    .entry(Node::Relation(rel))
                    .or_default()
                    .push(Node::Trigger(name));
            }
            (6, Some(rel)) => {
                indexed.insert(rel);
            }
            _ => {}
        }
    }
    let dep = dependent_nodes(&edges);
    let mut names: HashSet<String> = dep
        .iter()
        .filter_map(|n| n.name())
        .filter(|n| !always_listed(n))
        .map(str::to_owned)
        .collect();
    names.extend(indexed);
    if names.len() > MAX_DEPENDENT {
        return out;
    }
    out.dependent = names;
    out.complete = true;
    out
}

/// The nodes that depend on an always-reported relation, through the
/// strongly connected components of the graph (review M2: mutually
/// recursive routines share what any of them reaches, whatever the order
/// of the walk). Iterative (Tarjan), so a long chain cannot exhaust the
/// stack; no depth bound (R41 item 2).
fn dependent_nodes(edges: &HashMap<Node, Vec<Node>>) -> HashSet<Node> {
    const UNSEEN: usize = usize::MAX;
    let mut ids: HashMap<&Node, usize> = HashMap::new();
    let mut nodes: Vec<&Node> = Vec::new();
    for (from, tos) in edges {
        for n in std::iter::once(from).chain(tos) {
            ids.entry(n).or_insert_with(|| {
                nodes.push(n);
                nodes.len() - 1
            });
        }
    }
    let succ: Vec<Vec<usize>> = nodes
        .iter()
        .map(|n| {
            edges
                .get(*n)
                .map(|v| v.iter().map(|t| ids[t]).collect())
                .unwrap_or_default()
        })
        .collect();
    let n = nodes.len();
    let (mut index, mut low, mut comp) = (vec![UNSEEN; n], vec![0; n], vec![UNSEEN; n]);
    let mut on_stack = vec![false; n];
    let (mut stack, mut next) = (Vec::new(), 0usize);
    // Component facts in Tarjan's emission order (successors first).
    let (mut dep, mut height): (Vec<bool>, Vec<usize>) = (Vec::new(), Vec::new());
    for root in 0..n {
        if index[root] != UNSEEN {
            continue;
        }
        let mut work: Vec<(usize, usize)> = vec![(root, 0)];
        while let Some(top) = work.last_mut() {
            let (v, i) = *top;
            if i == 0 && index[v] == UNSEEN {
                index[v] = next;
                low[v] = next;
                next += 1;
                stack.push(v);
                on_stack[v] = true;
            }
            if let Some(&w) = succ[v].get(i) {
                top.1 += 1;
                if index[w] == UNSEEN {
                    work.push((w, 0));
                } else if on_stack[w] {
                    low[v] = low[v].min(index[w]);
                }
                continue;
            }
            work.pop();
            if let Some(&(u, _)) = work.last() {
                low[u] = low[u].min(low[v]);
            }
            if low[v] == index[v] {
                let c = dep.len();
                let mut members = Vec::new();
                while let Some(w) = stack.pop() {
                    on_stack[w] = false;
                    comp[w] = c;
                    members.push(w);
                    if w == v {
                        break;
                    }
                }
                let mut d = false;
                let mut h = 0usize;
                for &m in &members {
                    if let Node::Relation(r) = nodes[m]
                        && always_listed(r)
                    {
                        d = true;
                    }
                    for &t in &succ[m] {
                        let tc = comp[t];
                        if tc != c && tc != UNSEEN {
                            d |= dep[tc];
                            h = h.max(height[tc] + 1);
                        }
                    }
                }
                dep.push(d);
                height.push(h);
            }
        }
    }
    (0..n)
        .filter(|&v| dep[comp[v]])
        .map(|v| nodes[v].clone())
        .collect()
}

/// A catalog name as the `OCTETS` cast sends it: UTF-8, padding dropped.
fn name(v: Option<&Value>) -> Option<String> {
    let b = v?.as_bytes()?;
    let t = std::str::from_utf8(b).ok()?;
    Some(t.trim_end_matches(' ').to_owned())
}

/// The optional package column of a read (NULL: none).
fn opt_name(v: Option<&Value>) -> Option<Option<String>> {
    match v {
        Some(Value::Null) | None => Some(None),
        v => Some(Some(name(v)?)),
    }
}

/// A read whose rows all convert; `None` when it failed, was cut, or a
/// row did not convert (fail closed). A fatal error ends the check.
async fn rows<T>(
    s: &mut Session,
    text: &'static str,
    shape: &[Col],
    deadline: Instant,
    f: impl Fn(&[Value]) -> Option<T>,
) -> Result<Option<Vec<T>>, FbError> {
    match s.query(text, shape, MAX_ROWS, deadline).await {
        Ok(r) if !r.cut => Ok(r.rows.iter().map(|row| f(row)).collect::<Option<Vec<_>>>()),
        Ok(_) => Ok(None),
        Err(e) if !e.fatal => Ok(None),
        Err(e) => Err(e),
    }
}

/// Reads the dependent set on the agent's attachment (R41). A failed or
/// cut read gives the incomplete set (logged); a fatal error ends the
/// check.
pub(crate) async fn read(s: &mut Session, deadline: Instant) -> Result<ViewDeps, FbError> {
    let o = Col::Octets(252);
    let views = rows(s, sql::VIEW_RELATIONS, &[o, o, Col::Int], deadline, |row| {
        Some((name(row.first())?, name(row.get(1))?, row.get(2)?.as_int()?))
    })
    .await?;
    let deps = rows(
        s,
        sql::DEPENDENCIES,
        &[o, Col::Int, o, Col::Int, o],
        deadline,
        |row| {
            Some((
                name(row.first())?,
                row.get(1)?.as_int()?,
                name(row.get(2))?,
                row.get(3)?.as_int()?,
                opt_name(row.get(4))?,
            ))
        },
    )
    .await?;
    let fields = rows(s, sql::FIELD_SOURCES, &[o, o, Col::Bool], deadline, |row| {
        Some((
            name(row.first())?,
            name(row.get(1))?,
            row.get(2)?.as_bool()?,
        ))
    })
    .await?;
    let routines = rows(
        s,
        sql::ROUTINES,
        &[o, o, Col::Int, o, Col::Int],
        deadline,
        |row| {
            Some((
                name(row.first())?,
                opt_name(row.get(1))?,
                row.get(2)?.as_int()?,
                opt_name(row.get(3))?,
                row.get(4)?.as_int()?,
            ))
        },
    )
    .await?;
    s.commit(deadline).await?;
    let out = compute(Reads {
        views,
        deps,
        fields,
        routines,
    });
    if !out.complete {
        tracing::warn!(
            "Firebird dependent-set read cut or failed: every view, routine, package, trigger and \
             computed-column table counts as dependent until the next complete read (ADR-0060 R41 \
             item 2)"
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(view: &str, base: &str) -> ViewRow {
        (view.to_owned(), base.to_owned(), 0)
    }

    fn d(dep: &str, dt: i64, on: &str, ot: i64) -> DepRow {
        (dep.to_owned(), dt, on.to_owned(), ot, None)
    }

    fn reads(views: Vec<ViewRow>, deps: Vec<DepRow>) -> Reads {
        Reads {
            views: Some(views),
            deps: Some(deps),
            fields: Some(Vec::new()),
            routines: Some(Vec::new()),
        }
    }

    fn sorted(d: &ViewDeps) -> Vec<&str> {
        let mut v: Vec<&str> = d.dependent.iter().map(String::as_str).collect();
        v.sort_unstable();
        v
    }

    #[test]
    fn views_and_code_over_always_reported_relations_transitively() {
        let deps = compute(reads(
            vec![
                v("V_MIX", "CUSTOMERS"),
                v("V_MIX", "MON$STATEMENTS"),
                v("V_TOP", "V_MIX"),
                v("V_PLAIN", "CUSTOMERS"),
                ("V_PROC".to_owned(), "P_SECRETS".to_owned(), 2),
            ],
            vec![
                d("P_SECRETS", 5, "SEC$USERS", 0),
                d("V_FUNC", 1, "F_CFG", 15),
                d("F_CFG", 15, "RDB$CONFIG", 0),
                d("V_PKG", 1, "PK", 18),
                // A packaged routine's reads are its package body's.
                d("PK", 19, "MON$CONTEXT_VARIABLES", 0),
                d("V_OK", 1, "F_OK", 15),
                d("F_OK", 15, "CUSTOMERS", 0),
            ],
        ));
        assert!(deps.complete);
        assert_eq!(
            sorted(&deps),
            [
                "F_CFG",
                "PK",
                "P_SECRETS",
                "V_FUNC",
                "V_MIX",
                "V_PKG",
                "V_PROC",
                "V_TOP"
            ]
        );
    }

    /// R41 item 1: a computed column (dependent type 3) maps its table; a
    /// domain check (4) and a check-constraint trigger (2, system flag)
    /// map theirs; a table trigger reading a virtual relation is dependent
    /// by name; a computed column row that maps to no table fails closed.
    #[test]
    fn computed_columns_domains_and_triggers() {
        let r = Reads {
            views: Some(Vec::new()),
            deps: Some(vec![
                d("RDB$123", 3, "MON$STATEMENTS", 0),
                d("D_CHECK", 4, "SEC$USERS", 0),
                d("CHECK_7", 2, "MON$CALL_STACK", 0),
                d("TR_AUDIT", 2, "MON$CONTEXT_VARIABLES", 0),
            ]),
            fields: Some(vec![
                ("T_COMP".to_owned(), "RDB$123".to_owned(), true),
                ("T_DOM".to_owned(), "D_CHECK".to_owned(), false),
                ("T_PLAIN".to_owned(), "RDB$9".to_owned(), false),
            ]),
            routines: Some(vec![
                ("CHECK_7".to_owned(), None, 2, Some("T_CHK".to_owned()), 3),
                (
                    "TR_AUDIT".to_owned(),
                    None,
                    2,
                    Some("T_PLAIN".to_owned()),
                    0,
                ),
            ]),
        };
        let deps = compute(r);
        assert!(deps.complete);
        assert_eq!(
            sorted(&deps),
            ["CHECK_7", "TR_AUDIT", "T_CHK", "T_COMP", "T_DOM"]
        );
        assert!(deps.computed.contains("T_COMP"));
        // A computed column that maps to no table.
        let mut r = reads(Vec::new(), vec![d("RDB$999", 3, "MON$STATEMENTS", 0)]);
        r.fields = Some(Vec::new());
        assert!(!compute(r).complete);
    }

    /// Review L2, measured on 5.0.4: a standalone `P` and a packaged
    /// `PKG.P` are distinct; the package column names the depended-on
    /// object's package; a table with an expression index is dependent.
    #[test]
    fn packaged_and_standalone_routines_are_distinct() {
        let mut r = reads(
            vec![],
            vec![
                d("PKG", 19, "MON$STATEMENTS", 0),
                (
                    "RDB$21".to_owned(),
                    3,
                    "P".to_owned(),
                    15,
                    Some("PKG".to_owned()),
                ),
                d("P", 5, "CUSTOMERS", 0),
                d("V_STANDALONE", 1, "P", 5),
            ],
        );
        r.fields = Some(vec![("V_PKG".to_owned(), "RDB$21".to_owned(), true)]);
        r.routines = Some(vec![(
            "IX_EXPR".to_owned(),
            None,
            6,
            Some("T_IX".to_owned()),
            0,
        )]);
        let deps = compute(r);
        assert_eq!(sorted(&deps), ["PKG", "T_IX", "V_PKG"]);
    }

    #[test]
    fn a_failed_or_cut_read_is_incomplete_and_no_depth_bound() {
        assert!(
            !compute(Reads {
                views: None,
                ..reads(vec![], vec![])
            })
            .complete
        );
        assert!(
            !compute(Reads {
                deps: None,
                ..reads(vec![], vec![])
            })
            .complete
        );
        assert!(
            !compute(Reads {
                fields: None,
                ..reads(vec![], vec![])
            })
            .complete
        );
        assert!(
            !compute(Reads {
                routines: None,
                ..reads(vec![], vec![])
            })
            .complete
        );
        // A chain of 100 views: no depth bound (R41 item 2).
        let chain: Vec<ViewRow> = (0..100)
            .map(|i| v(&format!("V{i}"), &format!("V{}", i + 1)))
            .chain([v("V100", "MON$STATEMENTS")])
            .collect();
        let deps = compute(reads(chain, vec![]));
        assert!(deps.complete && deps.dependent.contains("V0"));
        // More dependent objects than the bound.
        let many: Vec<ViewRow> = (0..=MAX_DEPENDENT)
            .map(|i| v(&format!("V{i}"), "MON$STATEMENTS"))
            .collect();
        assert!(!compute(reads(many, vec![])).complete);
        let deps = compute(reads(vec![v("A", "B"), v("B", "A")], vec![]));
        assert!(deps.complete && deps.dependent.is_empty());
    }

    /// Review M2: mutually recursive procedures share what either reaches,
    /// whatever the order of the walk (repeated: the map order varies).
    #[test]
    fn mutually_recursive_code_shares_its_dependencies() {
        for _ in 0..50 {
            let deps = compute(reads(
                vec![
                    ("V1".to_owned(), "P1".to_owned(), 2),
                    ("W".to_owned(), "P2".to_owned(), 2),
                ],
                vec![
                    d("P1", 5, "P2", 5),
                    d("P1", 5, "SEC$USERS", 0),
                    d("P2", 5, "P1", 5),
                ],
            ));
            assert!(deps.complete);
            assert_eq!(sorted(&deps), ["P1", "P2", "V1", "W"]);
        }
    }

    #[test]
    fn octets_names() {
        let mut b = b"V_MIX".to_vec();
        b.resize(63, b' ');
        assert_eq!(
            name(Some(&Value::Bytes(zeroize::Zeroizing::new(b)))).as_deref(),
            Some("V_MIX")
        );
        assert_eq!(
            name(Some(&Value::Bytes(zeroize::Zeroizing::new(vec![0xff])))),
            None
        );
    }
}
