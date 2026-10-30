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
    let Some(dep) = dependent_nodes(&edges) else {
        // Deeper than the bound: fail closed.
        return ViewDeps::default();
    };
    let dependent = view_names
        .into_iter()
        .filter(|v| dep.contains(&Node::Relation(v.clone())))
        .collect();
    ViewDeps {
        dependent,
        complete: true,
    }
}

/// The nodes that depend on an always-reported relation, through the
/// strongly connected components of the graph (review M2: mutually
/// recursive routines share what any of them reaches, whatever the order
/// of the walk); `None` when the condensed graph is deeper than
/// [`MAX_DEPTH`]. Iterative (Tarjan), so a long chain cannot exhaust the
/// stack.
fn dependent_nodes(edges: &HashMap<Node, Vec<Node>>) -> Option<HashSet<Node>> {
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
                if h > MAX_DEPTH {
                    return None;
                }
                dep.push(d);
                height.push(h);
            }
        }
    }
    Some(
        (0..n)
            .filter(|&v| dep[comp[v]])
            .map(|v| nodes[v].clone())
            .collect(),
    )
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

    /// Review M2: mutually recursive procedures share what either reaches,
    /// whatever the order of the walk (repeated: the map order varies).
    #[test]
    fn mutually_recursive_code_shares_its_dependencies() {
        let mk = |a: &str, at: i64, b: &str, bt: i64| (a.to_owned(), at, b.to_owned(), bt, None);
        for _ in 0..50 {
            let d = compute(
                Some(vec![
                    ("V1".to_owned(), "P1".to_owned(), 2),
                    ("W".to_owned(), "P2".to_owned(), 2),
                ]),
                Some(vec![
                    mk("P1", 5, "P2", 5),
                    mk("P1", 5, "SEC$USERS", 0),
                    mk("P2", 5, "P1", 5),
                ]),
            );
            assert!(d.complete);
            let mut got: Vec<&str> = d.dependent.iter().map(String::as_str).collect();
            got.sort_unstable();
            assert_eq!(got, ["V1", "W"]);
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
