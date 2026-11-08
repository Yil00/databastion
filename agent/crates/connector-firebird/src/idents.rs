//! Identifier tokens of a statement text (ADR-0060 R41 item 6): every
//! identifier outside literals and comments, in both dialect readings
//! (an unquoted identifier upper-cased; a quoted one as written, `""`
//! unescaped; dialect 1 reads `"…"` as a literal, so the union of the two
//! readings is every token), trailing U+0020 removed; and every packaged
//! name `PKG . P` (an identifier, a `.` and an identifier, whitespace or
//! comments allowed between them). The tokens are matched against the
//! dependent set and never kept or sent: they are names, not values.

/// Most tokens read from one text (the trace cuts texts at
/// `max_sql_length`; past this, the rest is not read and the text counts
/// as matching, fail closed).
const MAX_TOKENS: usize = 65_536;

/// Re-review L-2: words reserved on both Firebird 4.0 and 5.0, sorted
/// (an unquoted one cannot name an object). Checked on the pinned servers
/// by the engine-matrix drift test: each is reserved in `RDB$KEYWORDS`
/// (5.0) and refused as a relation name (4.0 and 5.0). A word missing
/// here is only matched (fail closed).
pub(crate) const RESERVED: &[&str] = &[
    "ADD",
    "ALL",
    "ALTER",
    "AND",
    "ANY",
    "AS",
    "AT",
    "AVG",
    "BEGIN",
    "BETWEEN",
    "BIGINT",
    "BLOB",
    "BOOLEAN",
    "BOTH",
    "BY",
    "CASE",
    "CAST",
    "CHAR",
    "CHARACTER",
    "CHECK",
    "CLOSE",
    "COLLATE",
    "COLUMN",
    "COMMIT",
    "CONNECT",
    "CONSTRAINT",
    "COUNT",
    "CREATE",
    "CROSS",
    "CURRENT",
    "CURRENT_DATE",
    "CURRENT_ROLE",
    "CURRENT_TIME",
    "CURRENT_TIMESTAMP",
    "CURRENT_USER",
    "CURSOR",
    "DATE",
    "DAY",
    "DEC",
    "DECIMAL",
    "DECLARE",
    "DEFAULT",
    "DELETE",
    "DISTINCT",
    "DOUBLE",
    "DROP",
    "ELSE",
    "END",
    "ESCAPE",
    "EXECUTE",
    "EXISTS",
    "EXTERNAL",
    "EXTRACT",
    "FALSE",
    "FETCH",
    "FILTER",
    "FLOAT",
    "FOR",
    "FOREIGN",
    "FROM",
    "FULL",
    "FUNCTION",
    "GLOBAL",
    "GRANT",
    "GROUP",
    "HAVING",
    "HOUR",
    "IN",
    "INDEX",
    "INNER",
    "INSERT",
    "INT",
    "INTEGER",
    "INTO",
    "IS",
    "JOIN",
    "LEADING",
    "LEFT",
    "LIKE",
    "LOWER",
    "MAX",
    "MERGE",
    "MIN",
    "MINUTE",
    "MONTH",
    "NATURAL",
    "NOT",
    "NULL",
    "NUMERIC",
    "OF",
    "ON",
    "ONLY",
    "OPEN",
    "OR",
    "ORDER",
    "OUTER",
    "PLAN",
    "PRIMARY",
    "PROCEDURE",
    "REAL",
    "RECREATE",
    "REFERENCES",
    "RETURNS",
    "REVOKE",
    "RIGHT",
    "ROLLBACK",
    "ROW",
    "ROWS",
    "SECOND",
    "SELECT",
    "SET",
    "SMALLINT",
    "SOME",
    "SUM",
    "TABLE",
    "THEN",
    "TIME",
    "TIMESTAMP",
    "TO",
    "TRAILING",
    "TRIGGER",
    "TRIM",
    "TRUE",
    "UNION",
    "UNIQUE",
    "UPDATE",
    "UPPER",
    "USER",
    "USING",
    "VALUE",
    "VALUES",
    "VARCHAR",
    "VARIABLE",
    "VARYING",
    "VIEW",
    "WHEN",
    "WHERE",
    "WHILE",
    "WITH",
    "YEAR",
];

/// The identifiers of one text.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Idents {
    pub(crate) names: Vec<String>,
    /// `(package, name)` pairs.
    pub(crate) packaged: Vec<(String, String)>,
    /// A quoted identifier holds a non-ASCII character (R41 item 6: from an
    /// attachment whose character set is not `UTF8`, the printed form may
    /// not compare, so it counts as dependent).
    pub(crate) non_ascii_quoted: bool,
    /// More tokens than the bound.
    pub(crate) cut: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum Token {
    Ident(String),
    Dot,
    Other,
}

fn trimmed(mut s: String) -> String {
    while s.ends_with(' ') {
        s.pop();
    }
    s
}

/// The identifier tokens of `text`.
pub(crate) fn idents(text: &str) -> Idents {
    let mut out = Idents::default();
    let mut tokens: Vec<Token> = Vec::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if tokens.len() >= MAX_TOKENS {
            out.cut = true;
            break;
        }
        match c {
            '-' if chars.peek() == Some(&'-') => {
                for c in chars.by_ref() {
                    if c == '\n' {
                        break;
                    }
                }
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                let mut prev = ' ';
                for c in chars.by_ref() {
                    if prev == '*' && c == '/' {
                        break;
                    }
                    prev = c;
                }
            }
            '\'' => {
                while let Some(c) = chars.next() {
                    if c == '\'' {
                        if chars.peek() == Some(&'\'') {
                            chars.next();
                        } else {
                            break;
                        }
                    }
                }
                tokens.push(Token::Other);
            }
            '"' => {
                let mut name = String::new();
                while let Some(c) = chars.next() {
                    if c == '"' {
                        if chars.peek() == Some(&'"') {
                            chars.next();
                            name.push('"');
                        } else {
                            break;
                        }
                    } else {
                        name.push(c);
                    }
                }
                if !name.is_ascii() {
                    out.non_ascii_quoted = true;
                }
                tokens.push(Token::Ident(trimmed(name)));
            }
            '.' => tokens.push(Token::Dot),
            // The alternate quoting `q'<c>…<c>'` (`(`, `{`, `[`, `<` closed
            // by their pair): a literal, its `'` inside never ends it. Not
            // closed: the text counts as matching (fail closed).
            'q' | 'Q' if chars.peek() == Some(&'\'') => {
                chars.next();
                let Some(open) = chars.next() else {
                    out.cut = true;
                    break;
                };
                let close = match open {
                    '(' => ')',
                    '{' => '}',
                    '[' => ']',
                    '<' => '>',
                    c => c,
                };
                let mut prev = None;
                let mut closed = false;
                for c in chars.by_ref() {
                    if prev == Some(close) && c == '\'' {
                        closed = true;
                        break;
                    }
                    prev = Some(c);
                }
                if !closed {
                    out.cut = true;
                    break;
                }
                tokens.push(Token::Other);
            }
            c if c.is_ascii_alphabetic() => {
                let mut name = String::new();
                name.push(c.to_ascii_uppercase());
                while let Some(&n) = chars.peek() {
                    if n.is_ascii_alphanumeric() || n == '_' || n == '$' {
                        name.push(n.to_ascii_uppercase());
                        chars.next();
                    } else {
                        break;
                    }
                }
                // Re-review L-2: an unquoted reserved word is the keyword,
                // never an object's name (a quoted `"COUNT"` is).
                if RESERVED.binary_search(&name.as_str()).is_ok() {
                    tokens.push(Token::Other);
                } else {
                    tokens.push(Token::Ident(name));
                }
            }
            c if c.is_whitespace() => {}
            _ => tokens.push(Token::Other),
        }
    }
    for (i, t) in tokens.iter().enumerate() {
        if let Token::Ident(n) = t {
            out.names.push(n.clone());
            if let (Some(Token::Dot), Some(Token::Ident(m))) =
                (tokens.get(i + 1), tokens.get(i + 2))
            {
                out.packaged.push((n.clone(), m.clone()));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(t: &str) -> Vec<String> {
        idents(t).names
    }

    /// R41 item 9: identifiers at every position, the package part after
    /// lexing, literals and comments left out.
    #[test]
    fn every_identifier_token() {
        for (text, want) in [
            (
                "MERGE INTO T USING P_MON ON 1 = 1 WHEN MATCHED THEN DELETE",
                "P_MON",
            ),
            ("SELECT * FROM T WHERE A IN (SELECT B FROM v_mon)", "V_MON"),
            ("WITH C AS (SELECT * FROM P_MON) SELECT * FROM C", "P_MON"),
            (
                "SELECT * FROM T CROSS JOIN LATERAL (SELECT * FROM P_MON(T.ID)) X",
                "P_MON",
            ),
            ("INSERT INTO T SELECT * FROM \"Mon View \"", "Mon View"),
        ] {
            assert!(
                names(text).iter().any(|n| n == want),
                "{text}: {:?}",
                names(text)
            );
        }
        let i = idents("SELECT PKG . F(1), Q/**/.G(2) FROM RDB$DATABASE");
        assert!(i.packaged.contains(&("PKG".to_owned(), "F".to_owned())));
        assert!(i.packaged.contains(&("Q".to_owned(), "G".to_owned())));
        let i = idents("SELECT 'P_MON' FROM T -- P_MON\n/* P_MON */");
        assert!(!i.names.iter().any(|n| n == "P_MON"), "{:?}", i.names);
        assert!(idents("SELECT * FROM \"Tabelle_ä\"").non_ascii_quoted);
        assert!(!idents("SELECT * FROM T").non_ascii_quoted);
    }

    /// Re-review note: `q'<c>…<c>'` is a literal whose inner `'` does not
    /// end it, so the tokens after it are read; not closed, the text
    /// counts as matching.
    #[test]
    fn alternate_quoted_literals() {
        for t in [
            "SELECT q'{it's P_LIT}', F_MON(1) FROM T",
            "SELECT Q'!it's P_LIT!', F_MON(1) FROM T",
            "SELECT q'(a')', F_MON(1) FROM T",
        ] {
            let i = idents(t);
            assert!(i.names.iter().any(|n| n == "F_MON"), "{t}: {:?}", i.names);
            assert!(
                !i.names.iter().any(|n| n == "P_LIT" || n == "S"),
                "{t}: {:?}",
                i.names
            );
            assert!(!i.cut, "{t}");
        }
        assert!(idents("SELECT q'{open FROM T").cut);
        assert!(idents("SELECT q'").cut);
        // An identifier starting with Q is not a literal.
        assert!(names("SELECT QTY FROM T").iter().any(|n| n == "QTY"));
    }

    /// Re-review L-2: unquoted reserved words are not tokens; quoted, they
    /// are; the list is sorted for the binary search.
    #[test]
    fn reserved_words_are_keywords_unless_quoted() {
        assert!(RESERVED.windows(2).all(|w| w[0] < w[1]));
        let n = names("SELECT COUNT(*) FROM RDB$DATABASE");
        assert!(!n.iter().any(|n| n == "COUNT" || n == "SELECT"), "{n:?}");
        assert!(n.iter().any(|n| n == "RDB$DATABASE"), "{n:?}");
        let n = names("SELECT * FROM \"COUNT\"");
        assert!(n.iter().any(|n| n == "COUNT"), "{n:?}");
        // A non-reserved keyword can name an object unquoted.
        assert!(names("SELECT * FROM NAME").iter().any(|n| n == "NAME"));
    }
}
