//! Parser of `SHOW GRANTS` output lines, used by `check()` to evaluate the
//! privileges the account holds through roles (P4-D).
//!
//! `information_schema` lists the privileges granted to the account itself,
//! never those of its roles without a grant on the `mysql` database: the
//! only role-aware source readable by a least-privilege account is
//! `SHOW GRANTS` (MySQL: `FOR CURRENT_USER() USING <roles>`; MariaDB: `FOR
//! <role>` for a role granted to the account).
//!
//! The parser works on server text and fails closed: a line it does not
//! fully understand is `None`, and the caller then counts the roles as not
//! evaluated. Nothing parsed here is logged: database names only feed the
//! `mysql` / `sys` / `performance_schema` comparisons of
//! `check::evaluate_privileges`, privilege names become closed labels.
//!
//! Handled forms (MySQL 8.0+ and MariaDB 10.6+):
//! - `GRANT <privileges> ON <target> TO <grantee> [<options>]`, where a
//!   privilege may carry a column list (`SELECT (`a`, `b`)`) and the target
//!   is `*.*`, `*`, `db.*`, `db.tbl` or `tbl`, optionally after `TABLE`,
//!   `PROCEDURE`, `FUNCTION` or `PACKAGE [BODY]`;
//! - `GRANT PROXY ON <user> TO …`;
//! - `GRANT <role>[, <role>…] TO <grantee> [WITH ADMIN OPTION]`;
//! - `REVOKE …` (MySQL partial revokes) and `SET DEFAULT ROLE …` (MariaDB)
//!   are ignored: ignoring a revoke over-reports, never under-reports.
//!
//! `WITH GRANT OPTION` and `WITH ADMIN OPTION` make the line grantable.

/// Longest line parsed (a longer one is not understood).
const MAX_LINE_BYTES: usize = 64 * 1024;

/// A token of a grant line.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    /// An unquoted word (keyword or name).
    Word(String),
    /// A quoted name or string (backticks, single or double quotes).
    Quoted(String),
    /// `,` `(` `)` `.` `@` `*`
    Punct(char),
}

impl Tok {
    fn is_word(&self, w: &str) -> bool {
        matches!(self, Self::Word(x) if x.eq_ignore_ascii_case(w))
    }

    /// A name: a word or a quoted identifier.
    fn name(&self) -> Option<&str> {
        match self {
            Self::Word(x) | Self::Quoted(x) => Some(x),
            Self::Punct(_) => None,
        }
    }
}

const PUNCT: &[char] = &[',', '(', ')', '.', '@', '*'];

/// Splits a line into tokens; `None` for an unterminated quote, a `;` or a
/// line over [`MAX_LINE_BYTES`].
fn tokens(line: &str) -> Option<Vec<Tok>> {
    if line.len() > MAX_LINE_BYTES {
        return None;
    }
    let mut out = Vec::new();
    let mut chars = line.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
        } else if c == ';' {
            return None;
        } else if PUNCT.contains(&c) {
            chars.next();
            out.push(Tok::Punct(c));
        } else if matches!(c, '`' | '\'' | '"') {
            chars.next();
            let mut s = String::new();
            loop {
                match chars.next()? {
                    q if q == c => {
                        // A doubled quote is the quote itself.
                        if chars.peek() == Some(&c) {
                            chars.next();
                            s.push(c);
                        } else {
                            break;
                        }
                    }
                    // Backslash escapes in strings (never in identifiers).
                    '\\' if c != '`' => s.push(chars.next()?),
                    other => s.push(other),
                }
            }
            out.push(Tok::Quoted(s));
        } else {
            let mut s = String::new();
            while let Some(&w) = chars.peek() {
                if w.is_whitespace() || PUNCT.contains(&w) || matches!(w, '`' | '\'' | '"' | ';') {
                    break;
                }
                s.push(w);
                chars.next();
            }
            out.push(Tok::Word(s));
        }
    }
    Some(out)
}

/// What a grant is on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Scope {
    /// `*.*`.
    Global,
    /// A database, table, column or routine privilege: the database name
    /// (empty when the line names none, i.e. the default database).
    Database(String),
    /// `PROXY ON <user>`: the account may act as another account.
    Proxy,
}

/// A parsed `SHOW GRANTS` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Line {
    /// Privileges (upper case, e.g. `SELECT`, `SHOW VIEW`) on a scope.
    Privileges {
        privileges: Vec<String>,
        scope: Scope,
        grantable: bool,
    },
    /// Roles granted to the grantee (`WITH ADMIN OPTION`: grantable), and
    /// how many the line names.
    Roles { grantable: bool, count: u64 },
    /// `REVOKE` or `SET DEFAULT ROLE`: not a grant.
    Ignored,
}

/// Parses one `SHOW GRANTS` line; `None` when it is not fully understood.
pub(crate) fn parse_line(line: &str) -> Option<Line> {
    let toks = tokens(line)?;
    let first = toks.first()?;
    if first.is_word("REVOKE") || (first.is_word("SET") && toks.get(1)?.is_word("DEFAULT")) {
        return Some(Line::Ignored);
    }
    if !first.is_word("GRANT") {
        return None;
    }
    // Top-level `ON` and `TO` (outside a column list).
    let mut depth = 0usize;
    let (mut on, mut to) = (None, None);
    for (i, t) in toks.iter().enumerate().skip(1) {
        match t {
            Tok::Punct('(') => depth += 1,
            Tok::Punct(')') => depth = depth.checked_sub(1)?,
            _ if depth == 0 && on.is_none() && to.is_none() && t.is_word("ON") => on = Some(i),
            _ if depth == 0 && t.is_word("TO") => {
                to = Some(i);
                break;
            }
            _ => {}
        }
    }
    let to = to?;
    let tail = &toks[to + 1..];
    // The grantee must be there.
    tail.first()?.name()?;
    let grantable = tail
        .windows(2)
        .any(|w| (w[0].is_word("GRANT") || w[0].is_word("ADMIN")) && w[1].is_word("OPTION"));
    let Some(on) = on else {
        // Role grant: a list of quoted role names (the servers always
        // quote them; an unquoted word here is a privilege without `ON`).
        let roles = &toks[1..to];
        if !roles.iter().any(|t| matches!(t, Tok::Quoted(_)))
            || !roles
                .iter()
                .all(|t| matches!(t, Tok::Quoted(_) | Tok::Punct(',' | '@')))
        {
            return None;
        }
        let count = 1 + roles
            .iter()
            .filter(|t| matches!(t, Tok::Punct(',')))
            .count() as u64;
        return Some(Line::Roles { grantable, count });
    };
    let privileges = privilege_list(&toks[1..on])?;
    let target = &toks[on + 1..to];
    let scope = if privileges == ["PROXY"] {
        // `ON user@host`, `ON ''@''`.
        target.first()?.name()?;
        Scope::Proxy
    } else {
        scope(target)?
    };
    Some(Line::Privileges {
        privileges,
        scope,
        grantable,
    })
}

/// `SELECT, INSERT (`a`, `b`), SHOW VIEW` → `["SELECT", "INSERT", "SHOW
/// VIEW"]`.
fn privilege_list(toks: &[Tok]) -> Option<Vec<String>> {
    let mut out = Vec::new();
    let mut words: Vec<&str> = Vec::new();
    let mut i = 0;
    let mut columns_done = false;
    loop {
        match toks.get(i) {
            None | Some(Tok::Punct(',')) => {
                if words.is_empty() {
                    return None;
                }
                out.push(words.join(" ").to_ascii_uppercase());
                words.clear();
                columns_done = false;
                if i >= toks.len() {
                    return Some(out);
                }
            }
            Some(Tok::Word(w)) if !columns_done => words.push(w),
            Some(Tok::Punct('(')) if !words.is_empty() && !columns_done => {
                // Column list: names separated by commas, up to `)`.
                i += 1;
                loop {
                    toks.get(i)?.name()?;
                    i += 1;
                    match toks.get(i)? {
                        Tok::Punct(',') => i += 1,
                        Tok::Punct(')') => break,
                        _ => return None,
                    }
                }
                columns_done = true;
            }
            Some(_) => return None,
        }
        i += 1;
    }
}

/// The scope of a grant target.
fn scope(target: &[Tok]) -> Option<Scope> {
    let mut t = target;
    // Object type keywords.
    if t.first()
        .is_some_and(|x| x.is_word("TABLE") || x.is_word("PROCEDURE") || x.is_word("FUNCTION"))
    {
        t = &t[1..];
    } else if t.first().is_some_and(|x| x.is_word("PACKAGE")) {
        t = &t[1..];
        if t.first().is_some_and(|x| x.is_word("BODY")) {
            t = &t[1..];
        }
    }
    match t {
        [Tok::Punct('*'), Tok::Punct('.'), Tok::Punct('*')] => Some(Scope::Global),
        [Tok::Punct('*')] => Some(Scope::Database(String::new())),
        [db, Tok::Punct('.'), Tok::Punct('*')] => Some(Scope::Database(db.name()?.to_owned())),
        [db, Tok::Punct('.'), object] => {
            object.name()?;
            Some(Scope::Database(db.name()?.to_owned()))
        }
        [object] => {
            object.name()?;
            Some(Scope::Database(String::new()))
        }
        _ => None,
    }
}

/// A `SELECT` (or `ALL [PRIVILEGES]`) grant of a `SHOW GRANTS` line, with
/// what it covers, for the CAS store guard's credential column check
/// (ADR-0041 decision 6). Names are only compared, never logged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SelectGrant {
    /// `None`: every database (`*.*`); `Some("")`: the default database.
    pub(crate) db: Option<String>,
    /// `None`: every table of the database.
    pub(crate) table: Option<String>,
    /// `None`: every column of the table.
    pub(crate) columns: Option<Vec<String>>,
}

/// The `SELECT` grants of one `SHOW GRANTS` line (empty for a line that
/// grants no `SELECT`); `None` when the line is not understood.
pub(crate) fn select_grants(line: &str) -> Option<Vec<SelectGrant>> {
    if !matches!(parse_line(line)?, Line::Privileges { .. }) {
        return Some(Vec::new());
    }
    let toks = tokens(line)?;
    let mut depth = 0usize;
    let (mut on, mut to) = (None, None);
    for (i, t) in toks.iter().enumerate().skip(1) {
        match t {
            Tok::Punct('(') => depth += 1,
            Tok::Punct(')') => depth = depth.checked_sub(1)?,
            _ if depth == 0 && on.is_none() && t.is_word("ON") => on = Some(i),
            _ if depth == 0 && t.is_word("TO") => {
                to = Some(i);
                break;
            }
            _ => {}
        }
    }
    let (on, to) = (on?, to?);
    let mut target = toks.get(on + 1..to)?;
    if target.first().is_some_and(|x| x.is_word("TABLE")) {
        target = target.get(1..)?;
    } else if target
        .first()
        .is_some_and(|x| x.is_word("PROCEDURE") || x.is_word("FUNCTION") || x.is_word("PACKAGE"))
    {
        return Some(Vec::new());
    }
    let (db, table) = match target {
        [Tok::Punct('*'), Tok::Punct('.'), Tok::Punct('*')] => (None, None),
        [Tok::Punct('*')] => (Some(String::new()), None),
        [d, Tok::Punct('.'), Tok::Punct('*')] => (Some(d.name()?.to_owned()), None),
        [d, Tok::Punct('.'), t] => (Some(d.name()?.to_owned()), Some(t.name()?.to_owned())),
        [t] => (Some(String::new()), Some(t.name()?.to_owned())),
        _ => return None,
    };
    // Privileges with their column lists.
    let mut out = Vec::new();
    let list = toks.get(1..on)?;
    let mut i = 0;
    while i < list.len() {
        let mut words: Vec<&str> = Vec::new();
        let mut columns: Option<Vec<String>> = None;
        while let Some(t) = list.get(i) {
            match t {
                Tok::Word(w) => words.push(w),
                Tok::Punct('(') => {
                    let mut cols = Vec::new();
                    i += 1;
                    loop {
                        cols.push(list.get(i)?.name()?.to_owned());
                        i += 1;
                        match list.get(i)? {
                            Tok::Punct(',') => i += 1,
                            Tok::Punct(')') => break,
                            _ => return None,
                        }
                    }
                    columns = Some(cols);
                }
                Tok::Punct(',') => break,
                _ => return None,
            }
            i += 1;
        }
        i += 1;
        let p = words.join(" ").to_ascii_uppercase();
        if p == "SELECT" || p == "ALL" || p == "ALL PRIVILEGES" {
            out.push(SelectGrant {
                db: db.clone(),
                table: table.clone(),
                columns,
            });
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_grants_keep_tables_and_columns() {
        let g = |db: Option<&str>, t: Option<&str>, c: Option<&[&str]>| SelectGrant {
            db: db.map(str::to_owned),
            table: t.map(str::to_owned),
            columns: c.map(|c| c.iter().map(|x| (*x).to_owned()).collect()),
        };
        assert_eq!(
            select_grants("GRANT SELECT ON *.* TO `r`@`%`"),
            Some(vec![g(None, None, None)])
        );
        assert_eq!(
            select_grants("GRANT SELECT, INSERT ON `cas`.* TO `r`@`%`"),
            Some(vec![g(Some("cas"), None, None)])
        );
        assert_eq!(
            select_grants(
                "GRANT SELECT (`type`, `creation_time`), INSERT (`id`) ON `cas`.`cas_tickets` \
                 TO `u`@`%`"
            ),
            Some(vec![g(
                Some("cas"),
                Some("cas_tickets"),
                Some(&["type", "creation_time"])
            )])
        );
        assert_eq!(
            select_grants("GRANT ALL PRIVILEGES ON TABLE `cas`.`t` TO `r`"),
            Some(vec![g(Some("cas"), Some("t"), None)])
        );
        assert_eq!(
            select_grants("GRANT INSERT ON `cas`.* TO `r`"),
            Some(vec![])
        );
        assert_eq!(
            select_grants("GRANT EXECUTE ON PROCEDURE `cas`.`p` TO `r`"),
            Some(vec![])
        );
        assert_eq!(select_grants("GRANT `role1` TO `u`@`%`"), Some(vec![]));
        assert_eq!(select_grants("GRANT SELECT ON `a`.`b`.`c` TO `u`"), None);
    }

    fn privs(line: &str) -> (Vec<String>, Scope, bool) {
        match parse_line(line) {
            Some(Line::Privileges {
                privileges,
                scope,
                grantable,
            }) => (privileges, scope, grantable),
            other => panic!("{line}: {other:?}"),
        }
    }

    fn db(name: &str) -> Scope {
        Scope::Database(name.to_owned())
    }

    #[test]
    fn mysql_lines_are_parsed() {
        assert_eq!(
            privs("GRANT USAGE ON *.* TO `databastion`@`%`"),
            (vec!["USAGE".to_owned()], Scope::Global, false)
        );
        assert_eq!(
            privs("GRANT SELECT, INSERT, SHOW VIEW ON `hr`.* TO `u`@`%` WITH GRANT OPTION"),
            (
                vec!["SELECT".into(), "INSERT".into(), "SHOW VIEW".into()],
                db("hr"),
                true
            )
        );
        // Dynamic privileges, no space after the commas.
        assert_eq!(
            privs("GRANT BACKUP_ADMIN,SYSTEM_VARIABLES_ADMIN ON *.* TO `r`@`%`"),
            (
                vec!["BACKUP_ADMIN".into(), "SYSTEM_VARIABLES_ADMIN".into()],
                Scope::Global,
                false
            )
        );
        // Column privileges, a table, names with quotes and keywords.
        assert_eq!(
            privs("GRANT SELECT (`id`, `to`), UPDATE (`on`) ON `a``b`.`t.x` TO `u`@`localhost`"),
            (vec!["SELECT".into(), "UPDATE".into()], db("a`b"), false)
        );
        assert_eq!(
            privs("GRANT EXECUTE, ALTER ROUTINE ON PROCEDURE `hr`.`p` TO `u`@`%`"),
            (
                vec!["EXECUTE".into(), "ALTER ROUTINE".into()],
                db("hr"),
                false
            )
        );
        assert_eq!(
            privs("GRANT SELECT ON `mysql`.`user` TO `r`@`%`"),
            (vec!["SELECT".into()], db("mysql"), false)
        );
        assert_eq!(
            privs("GRANT PROXY ON ``@`` TO `u`@`%` WITH GRANT OPTION"),
            (vec!["PROXY".into()], Scope::Proxy, true)
        );
        assert_eq!(
            parse_line("GRANT `app_read`@`%`,`app_write`@`%` TO `u`@`%`"),
            Some(Line::Roles {
                grantable: false,
                count: 2
            })
        );
        assert_eq!(
            parse_line("GRANT `app_read`@`%` TO `u`@`%` WITH ADMIN OPTION"),
            Some(Line::Roles {
                grantable: true,
                count: 1
            })
        );
        assert_eq!(
            parse_line("REVOKE INSERT ON `mysql`.* FROM `u`@`%`"),
            Some(Line::Ignored)
        );
    }

    #[test]
    fn mariadb_lines_are_parsed() {
        assert_eq!(
            privs("GRANT SELECT ON `support`.* TO `app_read`"),
            (vec!["SELECT".into()], db("support"), false)
        );
        assert_eq!(
            privs("GRANT ALL PRIVILEGES ON `x`.* TO `r` WITH GRANT OPTION"),
            (vec!["ALL PRIVILEGES".into()], db("x"), true)
        );
        assert_eq!(
            privs("GRANT SELECT ON `support`.* TO 'u'@'%' IDENTIFIED BY PASSWORD '*AB;CD'"),
            (vec!["SELECT".into()], db("support"), false)
        );
        assert_eq!(
            privs("GRANT EXECUTE ON PACKAGE BODY `hr`.`pk` TO `r`"),
            (vec!["EXECUTE".into()], db("hr"), false)
        );
        assert_eq!(
            privs("GRANT SELECT ON `t` TO `r`"),
            (vec!["SELECT".into()], db(""), false)
        );
        assert_eq!(
            parse_line("GRANT `nested` TO `app_read`"),
            Some(Line::Roles {
                grantable: false,
                count: 1
            })
        );
        assert_eq!(
            parse_line("SET DEFAULT ROLE `app_read` FOR `u`@`%`"),
            Some(Line::Ignored)
        );
    }

    #[test]
    fn names_never_act_as_keywords() {
        // `ON` / `TO` / `GRANT OPTION` inside quotes are names.
        assert_eq!(
            privs("GRANT SELECT ON `ON`.`TO` TO `GRANT OPTION`@`%`"),
            (vec!["SELECT".into()], db("ON"), false)
        );
        assert_eq!(
            privs("GRANT SELECT ON `hr`.* TO `u`@`%` WITH MAX_USER_CONNECTIONS 4"),
            (vec!["SELECT".into()], db("hr"), false)
        );
    }

    #[test]
    fn anything_not_understood_is_refused() {
        for line in [
            "",
            "GRANT",
            "GRANT SELECT ON `hr`.*",
            "GRANT SELECT ON `hr`.* TO",
            "GRANT ON `hr`.* TO `u`",
            "GRANT SELECT ON `hr`.* TO `u`; DROP TABLE x",
            "GRANT SELECT ON `hr TO `u`",
            "GRANT SELECT (`a` ON `hr`.`t` TO `u`",
            "GRANT SELECT (`a`)) ON `hr`.`t` TO `u`",
            "GRANT SELECT (`a`) (`b`) ON `hr`.`t` TO `u`",
            "GRANT SELECT, ON `hr`.* TO `u`",
            "GRANT SELECT ON `a`.`b`.`c` TO `u`",
            "GRANT SELECT ON *.`t` TO `u`",
            "GRANT SELECT ON TO `u`",
            "GRANT TO `u`",
            "GRANT SELECT TO `u`",
            "SHOW GRANTS",
            "Grants for u@%",
        ] {
            assert_eq!(parse_line(line), None, "{line}");
        }
        let long = format!("GRANT SELECT ON `{}`.* TO `u`", "x".repeat(MAX_LINE_BYTES));
        assert_eq!(parse_line(&long), None);
    }
}
