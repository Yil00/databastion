//! The closed list of statements (ADR-0059 decision 5): constant templates
//! in which only identifiers are inserted, each through [`quote`]; numbers
//! are bound parameters. [`statement_allow_list`] lists every template for
//! the architecture test `sqlite_connector_statements_are_closed`.
//!
//! `PRAGMA table_list` and the `pragma_*` table-valued functions are never
//! used: `table_list` compiles every view and connects every virtual table.

use crate::ipc::{MAX_NAME, RowidAlias, SampleRange};

/// The catalog: `table` and `view` rows of `sqlite_schema` (the `sql`
/// column is never read).
pub const CATALOG: &str =
    "SELECT type, name, rootpage FROM main.sqlite_schema WHERE type IN ('table', 'view')";
/// `sqlite_stat1` row counts (the table's own row, not an index's).
pub const STATS: &str = "SELECT tbl, stat FROM main.sqlite_stat1 WHERE idx IS NULL OR idx = tbl";
/// The check pragmas, without an argument.
pub const PRAGMA_JOURNAL_MODE: &str = "PRAGMA main.journal_mode";
/// See [`PRAGMA_JOURNAL_MODE`].
pub const PRAGMA_SCHEMA_VERSION: &str = "PRAGMA main.schema_version";
/// See [`PRAGMA_JOURNAL_MODE`].
pub const PRAGMA_PAGE_SIZE: &str = "PRAGMA main.page_size";
/// See [`PRAGMA_JOURNAL_MODE`].
pub const PRAGMA_ENCODING: &str = "PRAGMA main.encoding";
/// The self-check, on a fresh in-memory connection (decision 1).
pub const SELF_COMPILE_OPTIONS: &str = "PRAGMA compile_options";
/// See [`SELF_COMPILE_OPTIONS`].
pub const SELF_TRUSTED_SCHEMA: &str = "PRAGMA trusted_schema";
/// See [`SELF_COMPILE_OPTIONS`].
pub const SELF_VERSION: &str = "SELECT sqlite_version(), sqlite_source_id()";

/// Template texts, `{t}` for the quoted table, `{r}` for the rowid alias,
/// `{c}` for the guarded column list.
const COLUMNS_T: &str = "PRAGMA main.table_xinfo({t})";
const BOUNDS_T: &str = "SELECT min({r}), max({r}) FROM main.{t} NOT INDEXED";
const SAMPLE_FROM_T: &str =
    "SELECT {r}, {c} FROM main.{t} NOT INDEXED WHERE {r} >= ?1 ORDER BY {r} LIMIT ?2";
const SAMPLE_BELOW_T: &str =
    "SELECT {r}, {c} FROM main.{t} NOT INDEXED WHERE {r} < ?1 ORDER BY {r} LIMIT ?2";
const SAMPLE_BETWEEN_T: &str =
    "SELECT {r}, {c} FROM main.{t} NOT INDEXED WHERE {r} >= ?1 AND {r} < ?2 ORDER BY {r} LIMIT ?3";
const SAMPLE_PLAIN_T: &str = "SELECT {c} FROM main.{t} NOT INDEXED LIMIT ?1";
/// One guarded column: only `TEXT` and `INTEGER` values of at most 64 KiB,
/// cut to 4 096 characters by SQLite (then to 4 096 bytes by the reader).
/// `typeof` and `octet_length` read only the record header.
const GUARDED_T: &str = "CASE WHEN typeof({q}) IN ('text', 'integer') AND octet_length({q}) <= 65536 THEN substr({q}, 1, 4096) END";

/// Every statement template of the crate, by name (architecture test).
#[must_use]
pub fn statement_allow_list() -> &'static [(&'static str, &'static str)] {
    &[
        ("catalog", CATALOG),
        ("stats", STATS),
        ("journal_mode", PRAGMA_JOURNAL_MODE),
        ("schema_version", PRAGMA_SCHEMA_VERSION),
        ("page_size", PRAGMA_PAGE_SIZE),
        ("encoding", PRAGMA_ENCODING),
        ("self_compile_options", SELF_COMPILE_OPTIONS),
        ("self_trusted_schema", SELF_TRUSTED_SCHEMA),
        ("self_version", SELF_VERSION),
        ("columns", COLUMNS_T),
        ("bounds", BOUNDS_T),
        ("sample_from", SAMPLE_FROM_T),
        ("sample_below", SAMPLE_BELOW_T),
        ("sample_between", SAMPLE_BETWEEN_T),
        ("sample_plain", SAMPLE_PLAIN_T),
        ("guarded_column", GUARDED_T),
    ]
}

/// The templates that read sampled rows (each contains `NOT INDEXED`).
#[must_use]
pub fn sampling_templates() -> &'static [&'static str] {
    &[
        BOUNDS_T,
        SAMPLE_FROM_T,
        SAMPLE_BELOW_T,
        SAMPLE_BETWEEN_T,
        SAMPLE_PLAIN_T,
    ]
}

/// The one quoting function: `"` + the name with `"` doubled + `"`. A name
/// with a NUL byte, more than [`MAX_NAME`] bytes, or invalid UTF-8 is never
/// quoted (`None`: its object is counted `skipped_unsupported`).
#[must_use]
pub fn quote(name: &[u8]) -> Option<String> {
    if name.is_empty() || name.len() > MAX_NAME || name.contains(&0) {
        return None;
    }
    let text = std::str::from_utf8(name).ok()?;
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        if c == '"' {
            out.push('"');
        }
        out.push(c);
    }
    out.push('"');
    Some(out)
}

/// `PRAGMA main.table_xinfo(<table>)`.
#[must_use]
pub fn columns(table: &[u8]) -> Option<String> {
    Some(COLUMNS_T.replace("{t}", &quote(table)?))
}

/// `min` / `max` of the rowid.
#[must_use]
pub fn bounds(table: &[u8], alias: RowidAlias) -> Option<String> {
    Some(
        BOUNDS_T
            .replace("{t}", &quote(table)?)
            .replace("{r}", alias.as_str()),
    )
}

/// One sampling statement and its parameter count.
#[must_use]
pub fn sample(
    table: &[u8],
    alias: Option<RowidAlias>,
    columns: &[impl AsRef<[u8]>],
    range: SampleRange,
) -> Option<String> {
    if columns.is_empty() {
        return None;
    }
    let mut guarded = Vec::with_capacity(columns.len());
    for c in columns {
        guarded.push(GUARDED_T.replace("{q}", &quote(c.as_ref())?));
    }
    let list = guarded.join(", ");
    let template = match (range, alias) {
        (SampleRange::From(_), Some(_)) => SAMPLE_FROM_T,
        (SampleRange::Below(_), Some(_)) => SAMPLE_BELOW_T,
        (SampleRange::Between(..), Some(_)) => SAMPLE_BETWEEN_T,
        (SampleRange::Plain { .. }, None) => SAMPLE_PLAIN_T,
        _ => return None,
    };
    let text = template
        .replace("{t}", &quote(table)?)
        .replace("{c}", &list);
    Some(match alias {
        Some(a) => text.replace("{r}", a.as_str()),
        None => text,
    })
}

/// Percent-encodes `path` for the `file:` URI (decision 3): every byte
/// outside the RFC 3986 unreserved set and `/` is encoded, so `?`, `#`, `&`,
/// `=` and `%` cannot reach SQLite's URI parser.
#[must_use]
pub fn uri(path: &[u8]) -> String {
    let mut out = String::with_capacity(path.len() + 40);
    out.push_str("file:");
    for b in path {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'/') {
            out.push(char::from(*b));
        } else {
            out.push('%');
            for nibble in [b >> 4, b & 0x0f] {
                out.push(char::from(*HEX.get(usize::from(nibble)).unwrap_or(&b'0')));
            }
        }
    }
    out.push_str("?mode=ro&readonly_shm=1");
    out
}

const HEX: [u8; 16] = *b"0123456789ABCDEF";

/// An integer value as its decimal text (sampled `INTEGER` values, decision
/// 6).
#[must_use]
pub fn decimal(v: i64) -> String {
    format!("{v}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn names_are_quoted_or_refused() {
        assert_eq!(quote(b"t").unwrap(), "\"t\"");
        assert_eq!(quote(b"a\"b").unwrap(), "\"a\"\"b\"");
        assert_eq!(quote("é x".as_bytes()).unwrap(), "\"é x\"");
        assert_eq!(quote(b""), None);
        assert_eq!(quote(b"a\0b"), None);
        assert_eq!(quote(&[0xff, 0xfe]), None);
        assert_eq!(quote(&[b'a'; MAX_NAME + 1]), None);
        assert!(quote(&[b'a'; MAX_NAME]).is_some());
    }

    #[test]
    fn templates_build_closed_statements() {
        let s = sample(
            b"t\"x",
            Some(RowidAlias::Oid),
            &[b"c".as_slice()],
            SampleRange::From(3),
        )
        .unwrap();
        assert!(s.starts_with("SELECT oid, CASE WHEN typeof(\"c\")"));
        assert!(
            s.contains("FROM main.\"t\"\"x\" NOT INDEXED WHERE oid >= ?1 ORDER BY oid LIMIT ?2")
        );
        assert!(sample(b"t", None, &[b"c".as_slice()], SampleRange::From(3)).is_none());
        assert!(
            sample(
                b"t",
                Some(RowidAlias::Rowid),
                &[b"c".as_slice()],
                SampleRange::Plain { reverse: false }
            )
            .is_none()
        );
        assert_eq!(
            bounds(b"t", RowidAlias::Rowid).unwrap(),
            "SELECT min(rowid), max(rowid) FROM main.\"t\" NOT INDEXED"
        );
        for t in sampling_templates() {
            assert!(t.contains("NOT INDEXED"), "{t}");
        }
    }

    #[test]
    fn uri_encodes_every_special_byte() {
        assert_eq!(
            uri(b"/srv/a b/x?y#z&w=%.db"),
            "file:/srv/a%20b/x%3Fy%23z%26w%3D%25.db?mode=ro&readonly_shm=1"
        );
    }

    proptest! {
        /// The quoted name, unquoted as SQLite does, is the name; it never
        /// ends the identifier early.
        #[test]
        fn quoting_round_trips(name in "\\PC{1,40}") {
            let q = quote(name.as_bytes()).unwrap();
            let inner = &q[1..q.len() - 1];
            prop_assert_eq!(inner.replace("\"\"", "\""), name);
            // Every quote inside is doubled.
            let mut chars = inner.chars().peekable();
            while let Some(c) = chars.next() {
                if c == '"' {
                    prop_assert_eq!(chars.next(), Some('"'));
                }
            }
        }

        /// The encoded path holds no URI delimiter.
        #[test]
        fn uri_has_no_delimiter(path in proptest::collection::vec(any::<u8>(), 1..80)) {
            let u = uri(&path);
            let body = u.strip_prefix("file:").unwrap().strip_suffix("?mode=ro&readonly_shm=1").unwrap();
            prop_assert!(!body.contains(['?', '#', '&', '=']));
            prop_assert!(body.bytes().all(|b| b.is_ascii_graphic()));
        }
    }
}
