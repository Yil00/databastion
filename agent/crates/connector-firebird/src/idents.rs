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
                tokens.push(Token::Ident(name));
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
}
