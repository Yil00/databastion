//! Server-side JavaScript in command documents (ADR-0027 refinement of
//! 2026-10-12, security review of #207, M3): `$where`, `$function` and
//! `$accumulator`, found **by key name** at any depth of a record's
//! command documents up to [`MAX_JS_DEPTH`], on the file sources (the
//! server log, the `auditLog`). The profiler computes the same fact on the
//! server (`profiler::projection`, field `js`), with the same bound.
//!
//! A conditional sleep under `maxTimeMS` is a one-bit oracle per operation
//! whose two outcomes (a quiet `MaxTimeMSExpired`, a success with no
//! document) both read 0 documents; an operation that runs JavaScript is
//! therefore always reported and never left out as the agent's own
//! (`events`), whatever it returned.
//!
//! - **Keys only.** The scanner reads the record's bytes once, without
//!   decoding values: a string is skipped from quote to quote (escapes
//!   stepped over), so the JavaScript code itself (a string value) and
//!   every literal are never copied, decoded nor logged. A key is compared
//!   in place with the three names, its JSON escapes decoded into an
//!   18-byte buffer at most (a longer key cannot match).
//! - **Depth bound, fail closed.** The command document is depth 0; an
//!   object or array at depth [`MAX_JS_DEPTH`] or deeper that is not empty
//!   counts as JavaScript (its keys are not examined). The scanner keeps
//!   one bit per open container, so at most [`MAX_JS_DEPTH`] bits.
//! - **Truncated server-log lines** (`maxLogSizeKB`): the server cuts an
//!   attribute and describes the cut in a top-level `truncated` report
//!   (`{"truncated": {"command": {"truncated": {...}, "omitted": n}}}`).
//!   The command counts as JavaScript when a key could have been cut: the
//!   report names an omitted element (`omitted`) or a cut element that is
//!   not a string (`type` other than `"string"`) under `command`,
//!   `originatingCommand` or `resolvedViews`. A cut string value hides no
//!   key.
//! - Malformed input (an unterminated string or container) counts as
//!   JavaScript; a record the JSON parser refuses is dropped anyway.

/// Deepest level of a command document whose keys are examined (the same
/// bound as the crate's other walks of server-controlled documents).
pub(crate) const MAX_JS_DEPTH: usize = 64;

/// The operators that run server-side JavaScript.
pub(crate) const JS_KEYS: [&str; 3] = ["$where", "$function", "$accumulator"];

/// Longest name compared, in bytes (`originatingCommand`; a longer key
/// matches no name and is not decoded further).
const LONGEST: usize = 18;

/// Where the command documents are in a server log line.
const LOG_COMMANDS: [&[&str]; 3] = [
    &["attr", "command"],
    &["attr", "originatingCommand"],
    &["attr", "resolvedViews"],
];
/// Their truncation reports.
const LOG_REPORTS: [&[&str]; 3] = [
    &["truncated", "command"],
    &["truncated", "originatingCommand"],
    &["truncated", "resolvedViews"],
];
/// The command an `explain` runs, in a server log line.
const LOG_EXPLAINED: &[&str] = &["attr", "command", "explain"];
/// Where the command document is in an `auditLog` record.
const AUDIT_ARGS: &[&str] = &["param", "args"];
/// The command an `explain` runs, in an `auditLog` record.
const AUDIT_EXPLAINED: &[&str] = &["param", "args", "explain"];

fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r')
}

fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while b.get(i).copied().is_some_and(is_ws) {
        i += 1;
    }
    i
}

/// The index of the closing quote of the string opening at `start`.
fn string_end(b: &[u8], start: usize) -> Option<usize> {
    let mut i = start + 1;
    loop {
        match *b.get(i)? {
            b'\\' => i += 2,
            b'"' => return Some(i),
            _ => i += 1,
        }
    }
}

fn hex(b: u8) -> Option<u32> {
    char::from(b).to_digit(16)
}

/// Whether the body of a JSON string (between its quotes) is `name`,
/// escapes decoded on the fly (never into a buffer longer than
/// [`LONGEST`]).
fn key_is(raw: &[u8], names: &[&str]) -> bool {
    let mut buf = [0u8; LONGEST];
    let mut n = 0;
    let mut i = 0;
    while i < raw.len() {
        let c = if raw[i] == b'\\' {
            let Some(&e) = raw.get(i + 1) else {
                return false;
            };
            match e {
                b'"' | b'\\' | b'/' => {
                    i += 2;
                    e
                }
                b'u' => {
                    let Some(v) = raw
                        .get(i + 2..i + 6)
                        .and_then(|h| h.iter().try_fold(0u32, |acc, d| Some(acc * 16 + hex(*d)?)))
                    else {
                        return false;
                    };
                    // The names are ASCII: anything else cannot match.
                    let Ok(c) = u8::try_from(v) else {
                        return false;
                    };
                    if !c.is_ascii() {
                        return false;
                    }
                    i += 6;
                    c
                }
                // Control characters: never in the names.
                _ => return false,
            }
        } else {
            i += 1;
            raw[i - 1]
        };
        if n == LONGEST {
            return false;
        }
        buf[n] = c;
        n += 1;
    }
    names.iter().any(|k| k.as_bytes() == &buf[..n])
}

/// The index just after the JSON value starting at `i` (whitespace before
/// it skipped); `None` when it is not terminated.
fn skip_value(b: &[u8], i: usize) -> Option<usize> {
    let i = skip_ws(b, i);
    match *b.get(i)? {
        b'"' => Some(string_end(b, i)? + 1),
        b'{' | b'[' => {
            let mut open = 0usize;
            let mut j = i;
            loop {
                match *b.get(j)? {
                    b'"' => j = string_end(b, j)? + 1,
                    b'{' | b'[' => {
                        open += 1;
                        j += 1;
                    }
                    b'}' | b']' => {
                        open -= 1;
                        j += 1;
                        if open == 0 {
                            return Some(j);
                        }
                    }
                    _ => j += 1,
                }
            }
        }
        _ => {
            let mut j = i;
            while let Some(&c) = b.get(j) {
                if matches!(c, b',' | b'}' | b']') || is_ws(c) {
                    break;
                }
                j += 1;
            }
            (j > i).then_some(j)
        }
    }
}

/// The values at `path` (object keys from the top-level value of `b`),
/// as byte slices of `b`. Every member with a matching key counts (a
/// duplicate key included). `Err(())`: not well formed.
fn values_at<'a>(b: &'a [u8], path: &[&str], out: &mut Vec<&'a [u8]>) -> Result<(), ()> {
    let Some((first, rest)) = path.split_first() else {
        let end = skip_value(b, 0).ok_or(())?;
        out.push(&b[skip_ws(b, 0)..end]);
        return Ok(());
    };
    let mut i = skip_ws(b, 0);
    if b.get(i) != Some(&b'{') {
        // Not an object: nothing at the path.
        return Ok(());
    }
    i += 1;
    loop {
        i = skip_ws(b, i);
        match b.get(i) {
            Some(b'}') => return Ok(()),
            Some(b',') => {
                i += 1;
                continue;
            }
            Some(b'"') => {}
            _ => return Err(()),
        }
        let key_end = string_end(b, i).ok_or(())?;
        let matched = key_is(&b[i + 1..key_end], &[first]);
        i = skip_ws(b, key_end + 1);
        if b.get(i) != Some(&b':') {
            return Err(());
        }
        let start = skip_ws(b, i + 1);
        let end = skip_value(b, start).ok_or(())?;
        if matched {
            values_at(&b[start..end], rest, out)?;
        }
        i = end;
    }
}

/// Whether a JSON value runs server-side JavaScript: a key of [`JS_KEYS`]
/// at a depth below [`MAX_JS_DEPTH`], or a non-empty object or array at
/// that depth or deeper (fail closed). Values are skipped, never decoded.
pub(crate) fn value_runs_js(b: &[u8]) -> bool {
    // One bit per open container: an object (`true`) or an array.
    let mut stack: Vec<bool> = Vec::new();
    let mut expect_key = false;
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        match c {
            b'"' => {
                let Some(end) = string_end(b, i) else {
                    return true;
                };
                if expect_key && key_is(&b[i + 1..end], &JS_KEYS) {
                    return true;
                }
                expect_key = false;
                i = end + 1;
            }
            b'{' | b'[' => {
                if stack.len() >= MAX_JS_DEPTH {
                    let close = if c == b'{' { b'}' } else { b']' };
                    let j = skip_ws(b, i + 1);
                    if b.get(j) != Some(&close) {
                        // Keys not examined: fail closed.
                        return true;
                    }
                    i = j + 1;
                    expect_key = false;
                    continue;
                }
                stack.push(c == b'{');
                expect_key = c == b'{';
                i += 1;
            }
            b'}' | b']' => {
                if stack.pop().is_none() {
                    return true;
                }
                expect_key = false;
                i += 1;
            }
            b',' => {
                expect_key = stack.last() == Some(&true);
                i += 1;
            }
            _ => i += 1,
        }
    }
    // Unterminated: fail closed.
    !stack.is_empty()
}

/// Whether a server-log truncation report says a key could have been cut:
/// it names an omitted element, or a cut element that is not a string.
pub(crate) fn report_cuts_keys(b: &[u8]) -> bool {
    let mut depth = 0usize;
    let mut expect_key = false;
    // The previous key was `type`: its value is read (a type name the
    // server writes, never a value of the command).
    let mut type_value = false;
    let mut i = 0;
    let mut seen = false;
    while let Some(&c) = b.get(i) {
        match c {
            b'"' => {
                let Some(end) = string_end(b, i) else {
                    return true;
                };
                let raw = &b[i + 1..end];
                if expect_key {
                    if key_is(raw, &["omitted"]) {
                        return true;
                    }
                    type_value = key_is(raw, &["type"]);
                } else if type_value {
                    if raw != b"string" {
                        return true;
                    }
                    type_value = false;
                }
                expect_key = false;
                i = end + 1;
            }
            b'{' => {
                if type_value {
                    return true;
                }
                seen = true;
                depth += 1;
                expect_key = true;
                i += 1;
            }
            b'[' => return true,
            b'}' => {
                let Some(d) = depth.checked_sub(1) else {
                    return true;
                };
                depth = d;
                expect_key = false;
                i += 1;
            }
            b',' => {
                expect_key = true;
                i += 1;
            }
            b':' => i += 1,
            c if is_ws(c) => i += 1,
            // A scalar that is not a string: a `size` is fine, a `type`
            // that is not a string is not understood.
            _ => {
                if type_value {
                    return true;
                }
                i += 1;
            }
        }
    }
    // Not an object, or unterminated: fail closed.
    !seen || depth != 0
}

/// Whether the object at `path` of `b` starts with one of `names` (an
/// `explain` of `mapReduce`).
fn first_key_in(b: &[u8], path: &[&str], names: &[&str]) -> bool {
    let mut found = Vec::new();
    if values_at(b, path, &mut found).is_err() {
        return true;
    }
    found.iter().any(|v| {
        let i = skip_ws(v, 0);
        if v.get(i) != Some(&b'{') {
            return false;
        }
        let i = skip_ws(v, i + 1);
        v.get(i) == Some(&b'"') && string_end(v, i).is_some_and(|end| key_is(&v[i + 1..end], names))
    })
}

const MAP_REDUCE: [&str; 2] = ["mapReduce", "mapreduce"];

/// Whether a server log line's command documents (`command`,
/// `originatingCommand`, `resolvedViews`) run server-side JavaScript, or a
/// key of them could have been cut by the server.
pub(crate) fn server_log_runs_js(line: &[u8]) -> bool {
    let mut found = Vec::new();
    for path in LOG_COMMANDS {
        if values_at(line, path, &mut found).is_err() {
            return true;
        }
    }
    if found.iter().any(|v| value_runs_js(v)) {
        return true;
    }
    found.clear();
    for path in LOG_REPORTS {
        if values_at(line, path, &mut found).is_err() {
            return true;
        }
    }
    found.iter().any(|v| report_cuts_keys(v)) || first_key_in(line, LOG_EXPLAINED, &MAP_REDUCE)
}

/// Whether an `auditLog` record's command document (`param.args`) runs
/// server-side JavaScript.
pub(crate) fn audit_log_runs_js(record: &[u8]) -> bool {
    let mut found = Vec::new();
    if values_at(record, AUDIT_ARGS, &mut found).is_err() {
        return true;
    }
    found.iter().any(|v| value_runs_js(v)) || first_key_in(record, AUDIT_EXPLAINED, &MAP_REDUCE)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    const BACKSLASH: u8 = 0x5c;

    fn js(s: &str) -> bool {
        value_runs_js(s.as_bytes())
    }

    /// `{"a": <inner>}` nested `n` times (objects), or `[<inner>]` (arrays).
    fn nest(n: usize, inner: &str, arrays: bool) -> String {
        let mut s = inner.to_owned();
        for _ in 0..n {
            s = if arrays {
                format!("[{s}]")
            } else {
                format!("{{\"a\":{s}}}")
            };
        }
        s
    }

    #[test]
    fn every_form_is_found_by_key() {
        let forms = [
            r#"{"find":"c","filter":{"$where":"sleep(100)"}}"#,
            r#"{"find":"c","filter":{"$expr":{"$function":{"body":"f","args":[],"lang":"js"}}}}"#,
            r#"{"aggregate":"c","pipeline":[{"$group":{"_id":null,"n":{"$accumulator":{}}}}]}"#,
            r#"{"aggregate":"c","pipeline":[{"$lookup":{"from":"d","pipeline":[{"$match":{"$expr":{"$function":{}}}}],"as":"x"}}]}"#,
            r#"{"aggregate":"c","pipeline":[{"$facet":{"a":[{"$match":{"$expr":{"$function":{}}}}]}}]}"#,
            r#"{"aggregate":"c","pipeline":[{"$unionWith":{"coll":"d","pipeline":[{"$match":{"$where":"1"}}]}},{"$out":"o"}]}"#,
            r#"{"aggregate":"c","pipeline":[{"$match":{"$where":"1"}},{"$merge":{"into":"o"}}]}"#,
            r#"{"update":"c","updates":[{"q":{},"u":[{"$set":{"y":{"$function":{}}}}]}]}"#,
            r#"{"findAndModify":"c","query":{"$where":"1"},"update":{"$set":{"x":1}}}"#,
            r#"{"count":"c","query":{"$where":"1"}}"#,
            r#"{"distinct":"c","key":"k","query":{"$expr":{"$function":{}}}}"#,
            r#"{"delete":"c","deletes":[{"q":{"$where":"1"},"limit":0}]}"#,
            r#"{"find":"c","filter":{},"projection":{"e":{"$function":{}}}}"#,
            r#"{"explain":{"find":"c","filter":{"$where":"1"}},"verbosity":"executionStats"}"#,
            // Escaped key (the server never writes one; a JSON parser
            // would still read `$where`).
            r#"{"find":"c","filter":{"\u0024where":"1"}}"#,
            r#"{"find":"c","filter":{"$wh\u0065re":"1"}}"#,
        ];
        for f in forms {
            assert!(js(f), "{f}");
        }
    }

    #[test]
    fn values_and_other_keys_are_not_javascript() {
        let plain = [
            r#"{"find":"c","filter":{"email":"$where"}}"#,
            r#"{"find":"c","filter":{"note":"{\"$where\": 1}"}}"#,
            r#"{"find":"c","filter":{"$expr":{"$eq":["$function","$accumulator"]}}}"#,
            r#"{"find":"c","filter":{"$wherever":1,"where":1,"$Where":1,"function":1}}"#,
            r#"{"aggregate":"c","pipeline":[{"$group":{"_id":"$k","n":{"$sum":1}}}]}"#,
            r#"{"find":"c","filter":{"a":["$where",{"b":"$function"}]}}"#,
            r#"{"find":"c","filter":{"\u0024wher":1,"\\$where":1,"$where\u0000":1}}"#,
            r#"{}"#,
            r#""$where""#,
            r#"42"#,
        ];
        for f in plain {
            assert!(!js(f), "{f}");
        }
    }

    /// The bound: keys at depth MAX_JS_DEPTH - 1 are examined; a non-empty
    /// container at MAX_JS_DEPTH fails closed; an empty one does not.
    #[test]
    fn the_depth_bound_fails_closed() {
        // `inner` at depth n (the outermost object is depth 0).
        let at = |n: usize, inner: &str| nest(n, inner, false);
        let last = MAX_JS_DEPTH - 1;
        assert!(js(&at(last, r#"{"$where":"1"}"#)));
        assert!(!js(&at(last, r#"{"x":"1"}"#)));
        assert!(!js(&at(last, r#"{"x":{}}"#)));
        assert!(!js(&at(last, r#"{"x":[ ]}"#)));
        // One level deeper: not examined, fail closed.
        assert!(js(&at(last, r#"{"x":{"y":1}}"#)));
        assert!(js(&at(last, r#"{"x":[1]}"#)));
        assert!(js(&at(MAX_JS_DEPTH, r#"{"x":1}"#)));
        assert!(js(&at(MAX_JS_DEPTH + 10, r#"{"x":1}"#)));
        // Arrays count as levels too.
        assert!(!js(&nest(MAX_JS_DEPTH, "1", true)));
        assert!(js(&nest(MAX_JS_DEPTH + 1, "1", true)));
        assert!(js(&nest(MAX_JS_DEPTH - 1, r#"{"$function":{}}"#, true)));
        // Very deep input is scanned without recursion.
        assert!(js(&nest(100_000, "1", true)));
    }

    #[test]
    fn malformed_input_fails_closed() {
        for bad in [r#"{"find":"c"#, r#"{"a":[1,2"#, r#"{"a":"x}"#, "]"] {
            assert!(js(bad), "{bad}");
        }
    }

    fn line(attr: &str, extra: &str) -> String {
        format!(
            r#"{{"t":{{"$date":"2026-10-12T10:00:00.000+00:00"}},"id":51803,"ctx":"conn1","attr":{attr}{extra}}}"#
        )
    }

    #[test]
    fn server_log_lines() {
        let l = line(
            r#"{"type":"command","ns":"app.c","command":{"find":"c","filter":{"$where":"1"}}}"#,
            "",
        );
        assert!(server_log_runs_js(l.as_bytes()));
        // A getMore whose cursor runs JavaScript.
        let l = line(
            r#"{"type":"command","command":{"getMore":1,"collection":"c"},"originatingCommand":{"find":"c","filter":{"$where":"1"}}}"#,
            "",
        );
        assert!(server_log_runs_js(l.as_bytes()));
        // A view whose pipeline runs JavaScript.
        let l = line(
            r#"{"type":"command","command":{"find":"v","filter":{}},"resolvedViews":[{"viewNamespace":"app.v","resolvedPipeline":[{"$match":{"$expr":{"$function":{}}}}]}]}"#,
            "",
        );
        assert!(server_log_runs_js(l.as_bytes()));
        // An explain of mapReduce.
        let l = line(
            r#"{"type":"command","command":{"explain":{"mapReduce":"c","map":"f","reduce":"g"},"verbosity":"executionStats"}}"#,
            "",
        );
        assert!(server_log_runs_js(l.as_bytes()));
        // Keys elsewhere in the line do not count.
        let l = line(
            r#"{"type":"command","command":{"find":"c","filter":{"a":1}},"planSummary":{"$where":1},"errMsg":"$function"}"#,
            r#","other":{"$accumulator":1}"#,
        );
        assert!(!server_log_runs_js(l.as_bytes()));
        let l = line(
            r#"{"type":"command","command":{"explain":{"find":"c","mapReduce":1}}}"#,
            "",
        );
        assert!(!server_log_runs_js(l.as_bytes()));
    }

    /// The server's truncation report (`maxLogSizeKB`), as MongoDB 8.0
    /// writes it.
    #[test]
    fn truncated_log_lines_count_when_a_key_could_be_cut() {
        let cmd = r#"{"type":"command","command":{"find":"c","filter":{"email":{"$nin":["x0"]}}}}"#;
        // Elements omitted after the cut: a key could have been cut.
        let omitted = r#","truncated":{"command":{"truncated":{"filter":{"truncated":{"email":{"truncated":{"$nin":{"truncated":{"1413":{"type":"string","size":10}},"omitted":1587}}}}},"omitted":1}},"omitted":3}},"size":{"command":45933}"#;
        assert!(server_log_runs_js(line(cmd, omitted).as_bytes()));
        // Only a string value cut, nothing omitted: no key lost.
        let string_only = r#","truncated":{"command":{"truncated":{"filter":{"truncated":{"note":{"type":"string","size":20000}}}}}},"size":{"command":21000}"#;
        assert!(!server_log_runs_js(line(cmd, string_only).as_bytes()));
        // A cut element of another type: fail closed.
        let object =
            r#","truncated":{"command":{"truncated":{"filter":{"type":"object","size":20000}}}}"#;
        assert!(server_log_runs_js(line(cmd, object).as_bytes()));
        // A report of another attribute does not count.
        let other = r#","truncated":{"planSummary":{"omitted":3}}"#;
        assert!(!server_log_runs_js(line(cmd, other).as_bytes()));
        // A report that is not understood fails closed.
        for odd in [
            r#","truncated":{"command":[1]}"#,
            r#","truncated":{"command":"cut"}"#,
            r#","truncated":{"command":{"x":{"type":3}}}"#,
        ] {
            assert!(server_log_runs_js(line(cmd, odd).as_bytes()), "{odd}");
        }
    }

    #[test]
    fn audit_log_records() {
        let rec = |args: &str| {
            format!(
                r#"{{"atype":"authCheck","param":{{"command":"find","ns":"app.c","args":{args}}},"result":0}}"#
            )
        };
        assert!(audit_log_runs_js(
            rec(r#"{"find":"c","filter":{"$where":"1"}}"#).as_bytes()
        ));
        assert!(audit_log_runs_js(
            rec(r#"{"explain":{"mapreduce":"c"}}"#).as_bytes()
        ));
        assert!(!audit_log_runs_js(
            rec(r#"{"find":"c","filter":{"a":"$where"}}"#).as_bytes()
        ));
        // Keys outside `param.args` do not count.
        assert!(!audit_log_runs_js(
            br#"{"atype":"createView","param":{"ns":"app.v","pipeline":[{"$match":{"$where":"1"}}]}}"#
        ));
    }

    #[test]
    fn keys_are_compared_whole() {
        // `\uXXXX` escapes, built here.
        let esc = |before: &str, hex: &str, after: &str| {
            format!("{before}{}u{hex}{after}", char::from(BACKSLASH)).into_bytes()
        };
        assert!(key_is(b"originatingCommand", &["originatingCommand"]));
        assert!(key_is(
            &esc("origin", "0061", "tingCommand"),
            &["originatingCommand"]
        ));
        assert!(key_is(&esc("", "0024", "where"), &["$where"]));
        assert!(!key_is(b"originatingCommandX", &["originatingCommand"]));
        assert!(!key_is(b"$where", &["$wher"]));
        assert!(!key_is(
            &esc("", "00e9", ""),
            &[std::str::from_utf8(&[0xc3, 0xa9]).unwrap()]
        ));
        assert!(!key_is(&esc("", "00", ""), &["$where"]));
        assert!(!key_is(&[BACKSLASH], &["$where"]));
    }

    #[test]
    fn values_at_finds_paths_and_duplicates() {
        let b = br#"{"a":{"b":1,"b":[2]},"c":"x","a":{"b":{"d":3}}}"#;
        let mut out = Vec::new();
        values_at(b, &["a", "b"], &mut out).unwrap();
        let got: Vec<&str> = out
            .iter()
            .map(|v| std::str::from_utf8(v).unwrap())
            .collect();
        assert_eq!(got, ["1", "[2]", r#"{"d":3}"#]);
        let mut out = Vec::new();
        assert!(values_at(br#"{"a":"#, &["a"], &mut out).is_err());
        let mut out = Vec::new();
        values_at(b"[1]", &["a"], &mut out).unwrap();
        assert!(out.is_empty());
    }
}
