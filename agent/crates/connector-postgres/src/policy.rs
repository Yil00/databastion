//! Row-level security policy expressions (ADR-0012 obligation 2, security
//! review H1).
//!
//! `pg_depend` does not record dependencies on pinned built-in objects, so
//! a policy calling `pg_catalog.query_to_xml('select evil()', …)` has no
//! dependency row: checking `pg_depend` alone lets such a table be sampled,
//! and the policy then runs arbitrary SQL in the agent's session. The
//! stored expression (`pg_policy.polqual`, a `pg_node_tree`) is therefore
//! scanned here, locally, for every function, operator and I/O coercion it
//! uses:
//!
//! - node types outside a fixed allow-list make the policy unsupported
//!   (fail closed);
//! - function oids (`:funcid`, `:aggfnoid`, …), operator oids (`:opno`,
//!   `:opnos`, `:eqop`, `:sortop`) and the result types of I/O coercions
//!   are collected and checked on the server by
//!   [`crate::sql::POLICY_REFS_REJECTED`]: only immutable `pg_catalog`
//!   functions outside a denylist, plus a short list of stable ones.
//!
//! The expression text is read only for this: it is never logged, stored
//! or sent (it may hold literals). Only oids are extracted.

use std::collections::BTreeSet;

/// Largest expression scanned; a larger one is unsupported.
const MAX_TREE_BYTES: usize = 1024 * 1024;

/// Node types whose evaluation only calls the functions / operators they
/// name (collected below) or none at all.
const ALLOWED_NODES: &[&str] = &[
    "ALIAS",
    "ARRAYCOERCEEXPR",
    "ARRAYEXPR",
    "BOOLEANTEST",
    "BOOLEXPR",
    "CASEEXPR",
    "CASETESTEXPR",
    "CASEWHEN",
    "COALESCEEXPR",
    "COERCEVIAIO",
    "COLLATEEXPR",
    "CONST",
    "DISTINCTEXPR",
    "FROMEXPR",
    "FUNCEXPR",
    "MINMAXEXPR",
    "NULLIFEXPR",
    "NULLTEST",
    "OPEXPR",
    "QUERY",
    "RANGETBLENTRY",
    "RANGETBLREF",
    "RELABELTYPE",
    "ROWCOMPAREEXPR",
    "ROWEXPR",
    "RTEPERMISSIONINFO",
    "SCALARARRAYOPEXPR",
    "SORTGROUPCLAUSE",
    "SQLVALUEFUNCTION",
    "SUBLINK",
    "TARGETENTRY",
    "VAR",
    "AGGREF",
];

const FUNCTION_KEYS: &[&str] = &[
    ":funcid",
    ":opfuncid",
    ":aggfnoid",
    ":winfnoid",
    ":hashfuncid",
    ":negfuncid",
];
const OPERATOR_KEYS: &[&str] = &[":opno", ":eqop", ":sortop"];

/// Objects a policy expression uses.
#[derive(Default, Clone, PartialEq, Eq)]
pub(crate) struct PolicyRefs {
    pub(crate) functions: BTreeSet<u32>,
    pub(crate) operators: BTreeSet<u32>,
    /// Result types of I/O coercions (their input function runs).
    pub(crate) io_types: BTreeSet<u32>,
}

impl std::fmt::Debug for PolicyRefs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyRefs")
            .field("functions", &self.functions.len())
            .field("operators", &self.operators.len())
            .field("io_types", &self.io_types.len())
            .finish()
    }
}

/// Splits a `pg_node_tree` into tokens: `{ } ( )` alone, other tokens
/// separated by whitespace; a backslash escapes the next character.
fn tokens(tree: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = tree.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            '{' | '}' | '(' | ')' => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
                out.push(c.to_string());
            }
            c if c.is_whitespace() => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn oid(token: Option<&String>) -> Option<u32> {
    token?.parse().ok()
}

/// Scans policy expressions. `None`: unsupported (too large, unknown node
/// type, malformed): the relation is not sampled.
pub(crate) fn scan(trees: &[&str]) -> Option<PolicyRefs> {
    let mut refs = PolicyRefs::default();
    for tree in trees {
        if tree.len() > MAX_TREE_BYTES {
            return None;
        }
        let t = tokens(tree);
        let mut stack: Vec<&str> = Vec::new();
        let mut i = 0;
        while i < t.len() {
            let tok = t[i].as_str();
            match tok {
                "{" => {
                    let name = t.get(i + 1)?.as_str();
                    if !ALLOWED_NODES.contains(&name) {
                        return None;
                    }
                    stack.push(name);
                    i += 2;
                    continue;
                }
                "}" => {
                    stack.pop()?;
                }
                k if FUNCTION_KEYS.contains(&k) => {
                    let v = oid(t.get(i + 1))?;
                    if v != 0 {
                        refs.functions.insert(v);
                    }
                    i += 2;
                    continue;
                }
                k if OPERATOR_KEYS.contains(&k) => {
                    let v = oid(t.get(i + 1))?;
                    if v != 0 {
                        refs.operators.insert(v);
                    }
                    i += 2;
                    continue;
                }
                ":opnos" => {
                    // `(o 96 97)`
                    if t.get(i + 1).map(String::as_str) != Some("(")
                        || t.get(i + 2).map(String::as_str) != Some("o")
                    {
                        return None;
                    }
                    i += 3;
                    while t.get(i).map(String::as_str) != Some(")") {
                        refs.operators.insert(oid(t.get(i))?);
                        i += 1;
                    }
                }
                ":resulttype" if stack.last() == Some(&"COERCEVIAIO") => {
                    refs.io_types.insert(oid(t.get(i + 1))?);
                    i += 2;
                    continue;
                }
                _ => {}
            }
            i += 1;
        }
        if !stack.is_empty() {
            return None;
        }
    }
    Some(refs)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Trees printed by PostgreSQL 16 (literal bytes shortened).
    const BUILTINS: &str = "{BOOLEXPR :boolop and :args ({OPEXPR :opno 98 :opfuncid 67 \
        :opresulttype 16 :args ({VAR :varno 1 :varattno 1} {FUNCEXPR :funcid 2077 \
        :args ({CONST :consttype 25 :constvalue 4 [ 80 0 0 0 ]}) :location 44})} \
        {OPEXPR :opno 96 :opfuncid 65 :args ({COERCEVIAIO :arg {FUNCEXPR :funcid 2077 \
        :funcresulttype 25 :args ()} :resulttype 23 :resultcollid 0} {VAR :varno 1})} \
        {SCALARARRAYOPEXPR :opno 96 :opfuncid 65 :hashfuncid 0 :negfuncid 0 :args ()} \
        {ROWCOMPAREEXPR :rctype 1 :opnos (o 664 97) :opfamilies (o 1994 1976) :largs ()})}";

    #[test]
    fn collects_functions_operators_and_io_types() {
        let r = scan(&[BUILTINS]).unwrap();
        assert_eq!(r.functions.into_iter().collect::<Vec<_>>(), [65, 67, 2077]);
        assert_eq!(
            r.operators.into_iter().collect::<Vec<_>>(),
            [96, 97, 98, 664]
        );
        assert_eq!(r.io_types.into_iter().collect::<Vec<_>>(), [23]);
    }

    #[test]
    fn query_to_xml_is_seen_although_pg_depend_has_no_row() {
        // USING (pg_catalog.query_to_xml('select evil()', true, false, '') IS NOT NULL)
        let tree = "{NULLTEST :arg {FUNCEXPR :funcid 2925 :funcresulttype 142 :args \
            ({CONST :consttype 25 :constvalue 17 [ 68 0 0 0 115 ]})} :nulltesttype 1}";
        assert!(scan(&[tree]).unwrap().functions.contains(&2925));
    }

    #[test]
    fn unknown_or_malformed_trees_fail_closed() {
        assert!(scan(&["{WINDOWFUNC :winfnoid 3100}"]).is_none());
        assert!(scan(&["{JSONEXPR :op 1}"]).is_none());
        assert!(scan(&["{FUNCEXPR :funcid x}"]).is_none());
        assert!(scan(&["{FUNCEXPR :funcid 1"]).is_none());
        assert!(scan(&["{FUNCEXPR :funcid 1}}"]).is_none());
        assert!(scan(&["{ROWCOMPAREEXPR :opnos (96)}"]).is_none());
        assert!(scan(&[&"{CONST}".repeat(MAX_TREE_BYTES)]).is_none());
    }

    #[test]
    fn escaped_text_does_not_inject_keys() {
        // An alias `x :funcid 99` is printed with escaped spaces.
        let r = scan(&["{ALIAS :aliasname x\\ :funcid\\ 99 :colnames <>}"]).unwrap();
        assert!(r.functions.is_empty());
    }
}
