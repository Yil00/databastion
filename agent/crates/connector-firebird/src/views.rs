//! Views over always-reported relations (ADR-0060 R12 item 5, R28 items 3
//! and 4): at every re-evaluation, `check()` reads `RDB$VIEW_RELATIONS`
//! (every view's base relations and procedure contexts) and
//! `RDB$DEPENDENCIES` (what views and code depend on) and computes,
//! transitively and bounded, the views that depend on a relation of the
//! statement-text or credential-bearing always-reported lists
//! ([`crate::trace_events::always_listed`]). A read whose text or block
//! names such a view gets `*` and the always-reported mark.
//!
//! Fail closed: a failed or cut read, a name that is not UTF-8, more than
//! [`MAX_VIEWS`] views or a chain deeper than [`MAX_DEPTH`] make every
//! view of the database count as dependent ([`ViewDeps::complete`] false).
//! Dependencies through code are followed (a view that calls a procedure
//! or function that reads an always-reported relation, at any depth within
//! the bound); a code dependency the read does not show (an external
//! routine) adds nothing, its own queries being statement records of
//! their own (R18).
//!
//! No view is block-blind (R28 item 3 is not implemented): a block-less
//! view read that returned rows stays ambiguous, whatever the view's
//! dependencies, so a view that depends on code is never block-blind.

use std::collections::{HashMap, HashSet};

use tokio::time::Instant;

use crate::conn::Session;
use crate::error::FbError;
use crate::sql::{self, Col, Value};
use crate::trace_events::always_listed;

/// Rows read from each catalog relation at most.
pub(crate) const MAX_ROWS: usize = 65_536;
/// Views considered at most (R12 item 5).
pub(crate) const MAX_VIEWS: usize = 16_384;
/// Dependency depth followed at most (R12 item 5).
pub(crate) const MAX_DEPTH: usize = 16;

/// The views of one database that depend on an always-reported relation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ViewDeps {
    pub(crate) dependent: HashSet<String>,
    /// The reads were complete and within the bounds; otherwise every view
    /// counts as dependent.
    pub(crate) complete: bool,
}

/// A catalog object, by namespace.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Node {
    /// A table or a view (one namespace).
    Relation(String),
    Procedure(String),
    Function(String),
    Package(String),
}

impl Node {
    /// `RDB$DEPENDENCIES` object types (0 relation, 1 view, 5 procedure,
    /// 15 function, 18 and 19 package header and body); others are not
    /// followed.
    fn of(kind: i64, name: String) -> Option<Self> {
        match kind {
            0 | 1 => Some(Self::Relation(name)),
            5 => Some(Self::Procedure(name)),
            15 => Some(Self::Function(name)),
            18 | 19 => Some(Self::Package(name)),
            _ => None,
        }
    }
}

/// One row of [`sql::VIEW_RELATIONS`]: view, base, context type.
pub(crate) type ViewRow = (String, String, i64);
/// One row of [`sql::DEPENDENCIES`]: dependent, its type, depended-on, its
/// type, the dependent's package.
pub(crate) type DepRow = (String, i64, String, i64, Option<String>);

/// The dependency set from the two reads (`None`: failed, cut, or a row
/// dropped).
pub(crate) fn compute(views: Option<Vec<ViewRow>>, deps: Option<Vec<DepRow>>) -> ViewDeps {
    let (Some(views), Some(deps)) = (views, deps) else {
        return ViewDeps::default();
    };
    let mut edges: HashMap<Node, Vec<Node>> = HashMap::new();
    let mut view_names: HashSet<String> = HashSet::new();
    for (view, base, context) in views {
        view_names.insert(view.clone());
        // Context type 2: a selectable procedure in the view's `FROM`.
        let to = if context == 2 {
            Node::Procedure(base)
        } else {
            Node::Relation(base)
        };
        edges.entry(Node::Relation(view)).or_default().push(to);
    }
    for (dependent, dtype, on, otype, package) in deps {
        if dtype == 1 {
            view_names.insert(dependent.clone());
        }
        // A packaged routine's dependencies are its package's.
        let from = match package {
            Some(p) if dtype != 1 => Some(Node::Package(p)),
            _ => Node::of(dtype, dependent),
        };
        if let (Some(from), Some(to)) = (from, Node::of(otype, on)) {
            edges.entry(from).or_default().push(to);
        }
    }
    if view_names.len() > MAX_VIEWS {
        return ViewDeps::default();
    }
    let mut memo: HashMap<Node, (bool, usize)> = HashMap::new();
    let mut dependent = HashSet::new();
    for v in &view_names {
        match depends(
            &Node::Relation(v.clone()),
            &edges,
            &mut memo,
            &mut Vec::new(),
        ) {
            Some((true, _)) => {
                dependent.insert(v.clone());
            }
            Some((false, _)) => {}
            // Deeper than the bound: fail closed.
            None => return ViewDeps::default(),
        }
    }
    ViewDeps {
        dependent,
        complete: true,
    }
}

/// Whether `n` depends on an always-reported relation, with the height of
/// its dependency chain; `None` past the depth bound (wherever the walk
/// enters the chain: heights are memoized with the results). A cycle (not
/// possible in a valid catalog) counts as no dependency through itself.
fn depends(
    n: &Node,
    edges: &HashMap<Node, Vec<Node>>,
    memo: &mut HashMap<Node, (bool, usize)>,
    path: &mut Vec<Node>,
) -> Option<(bool, usize)> {
    if let Node::Relation(r) = n
        && always_listed(r)
    {
        return Some((true, 0));
    }
    if let Some(d) = memo.get(n) {
        return Some(*d);
    }
    if path.contains(n) || path.len() > MAX_DEPTH {
        return if path.contains(n) {
            Some((false, 0))
        } else {
            None
        };
    }
    path.push(n.clone());
    let mut out = (false, 0usize);
    for next in edges.get(n).map(Vec::as_slice).unwrap_or_default() {
        let Some((dep, h)) = depends(next, edges, memo, path) else {
            path.pop();
            return None;
        };
        out = (out.0 || dep, out.1.max(h + 1));
    }
    path.pop();
    if out.1 > MAX_DEPTH {
        return None;
    }
    memo.insert(n.clone(), out);
    Some(out)
}

/// A catalog name as the `OCTETS` cast sends it: UTF-8, padding dropped.
fn name(v: Option<&Value>) -> Option<String> {
    let b = v?.as_bytes()?;
    let t = std::str::from_utf8(b).ok()?;
    Some(t.trim_end_matches(' ').to_owned())
}

/// Reads the dependency set on the agent's attachment (R12 item 5). A
/// failed or cut read gives the incomplete set; a fatal error ends the
/// check.
pub(crate) async fn read(s: &mut Session, deadline: Instant) -> Result<ViewDeps, FbError> {
    let views = match s
        .query(
            sql::VIEW_RELATIONS,
            &[Col::Octets(252), Col::Octets(252), Col::Int],
            MAX_ROWS,
            deadline,
        )
        .await
    {
        Ok(r) if !r.cut => r
            .rows
            .iter()
            .map(|row| Some((name(row.first())?, name(row.get(1))?, row.get(2)?.as_int()?)))
            .collect::<Option<Vec<_>>>(),
        Ok(_) => None,
        Err(e) if !e.fatal => None,
        Err(e) => return Err(e),
    };
    let deps = match s
        .query(
            sql::DEPENDENCIES,
            &[
                Col::Octets(252),
                Col::Int,
                Col::Octets(252),
                Col::Int,
                Col::Octets(252),
            ],
            MAX_ROWS,
            deadline,
        )
        .await
    {
        Ok(r) if !r.cut => r
            .rows
            .iter()
            .map(|row| {
                let package = match row.get(4) {
                    Some(Value::Null) | None => None,
                    v => Some(name(v)?),
                };
                Some((
                    name(row.first())?,
                    row.get(1)?.as_int()?,
                    name(row.get(2))?,
                    row.get(3)?.as_int()?,
                    package,
                ))
            })
            .collect::<Option<Vec<_>>>(),
        Ok(_) => None,
        Err(e) if !e.fatal => None,
        Err(e) => return Err(e),
    };
    s.commit(deadline).await?;
    Ok(compute(views, deps))
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

    #[test]
    fn views_over_always_reported_relations_transitively() {
        let deps = compute(
            Some(vec![
                // A view mixing a table and a statement-text relation.
                v("V_MIX", "CUSTOMERS"),
                v("V_MIX", "MON$STATEMENTS"),
                // A view over that view.
                v("V_TOP", "V_MIX"),
                // A plain view.
                v("V_PLAIN", "CUSTOMERS"),
                // A view over a selectable procedure.
                ("V_PROC".to_owned(), "P_SECRETS".to_owned(), 2),
            ]),
            Some(vec![
                // The procedure reads a credential relation.
                d("P_SECRETS", 5, "SEC$USERS", 0),
                // A view calling a function that reads `RDB$CONFIG`.
                d("V_FUNC", 1, "F_CFG", 15),
                d("F_CFG", 15, "RDB$CONFIG", 0),
                // A packaged function, through its package.
                d("V_PKG", 1, "PK", 18),
                (
                    "F_IN".to_owned(),
                    15,
                    "MON$CONTEXT_VARIABLES".to_owned(),
                    0,
                    Some("PK".to_owned()),
                ),
                // A view calling a harmless function.
                d("V_OK", 1, "F_OK", 15),
                d("F_OK", 15, "CUSTOMERS", 0),
            ]),
        );
        assert!(deps.complete);
        let mut got: Vec<&str> = deps.dependent.iter().map(String::as_str).collect();
        got.sort_unstable();
        assert_eq!(got, ["V_FUNC", "V_MIX", "V_PKG", "V_PROC", "V_TOP"]);
    }

    #[test]
    fn a_failed_cut_or_too_deep_read_counts_every_view() {
        assert!(!compute(None, Some(vec![])).complete);
        assert!(!compute(Some(vec![]), None).complete);
        // A chain deeper than the bound.
        let chain: Vec<ViewRow> = (0..=MAX_DEPTH + 1)
            .map(|i| v(&format!("V{i}"), &format!("V{}", i + 1)))
            .collect();
        assert!(!compute(Some(chain), Some(vec![])).complete);
        // Within the bound.
        let chain: Vec<ViewRow> = (0..MAX_DEPTH - 1)
            .map(|i| v(&format!("V{i}"), &format!("V{}", i + 1)))
            .chain([v(&format!("V{}", MAX_DEPTH - 1), "MON$STATEMENTS")])
            .collect();
        let deps = compute(Some(chain), Some(vec![]));
        assert!(deps.complete);
        assert!(deps.dependent.contains("V0"));
        // Too many views.
        let many: Vec<ViewRow> = (0..=MAX_VIEWS).map(|i| v(&format!("V{i}"), "T")).collect();
        assert!(!compute(Some(many), Some(vec![])).complete);
        // A cycle (an invalid catalog) terminates.
        let deps = compute(Some(vec![v("A", "B"), v("B", "A")]), Some(vec![]));
        assert!(deps.complete && deps.dependent.is_empty());
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
