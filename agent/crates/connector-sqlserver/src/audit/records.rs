//! SQL Server Audit records (ADR-0051 decision 6, "What is kept"):
//! parsed from the poll's rows ([`Record::from_row`]), statement texts
//! reassembled from their `sequence_number` parts (at most
//! [`MAX_STATEMENT_BYTES`], else cut), records of one statement grouped
//! into one event ([`group`]: one record per object the permission check
//! covered, measured on 2022), then mapped to an access event
//! ([`convert`]).
//!
//! - Objects come from the records (the permission checks), never from
//!   the text. Internal helper objects every catalog view reads
//!   ([`HELPER_OBJECTS`]) are left out.
//! - The statement text goes through `classifiers::query::tsql` only for
//!   reads and writes; DDL, DCL and failed logins never have their text
//!   analysed (a failed login's text holds the name tried; DCL can hold a
//!   password). The text never leaves the agent and is zeroized on drop.
//! - Always reported (`MaskedEvent::always_report`): reads of the
//!   statement-text, credential-bearing and value-bearing objects (from
//!   the records or named in the text), dynamic SQL, calls of user
//!   functions, four-part names, remote data access, server-side copies,
//!   password-taking functions, cut or unreadable texts (which name `*`),
//!   and the audit's own changes (`AUDIT_CHANGE_GROUP`).

use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use databastion_classifiers::masking::{
    ClientAddr, EventAction, EventObject, EventPrincipal, EventSource, MaskedEvent, Signal,
};
use databastion_classifiers::names::NormalizedName;
use databastion_classifiers::query::tsql::{self, TsqlAnalysis, TsqlKind};
use zeroize::Zeroizing;

use crate::discover::normalize;
use crate::token::Value;

/// Longest statement text reassembled; beyond, the text is cut (decision
/// 6: 64 KiB).
pub(crate) const MAX_STATEMENT_BYTES: usize = 64 * 1024;
/// One `statement` part holds at most this many characters.
const PART_CHARS: usize = 4000;
/// Rows above this many are a large result (`shape.full_table_read`
/// threshold, as on the other engines).
pub(crate) const LARGE_LIMIT: u64 = 10_000;
/// Error number of a connection closed before its login packet (a TCP
/// probe; measured: `0x45a6`, no login name).
const ERR_NETWORK_BEFORE_LOGIN: i64 = 17_830;

/// Internal system objects a read of any catalog view is also checked on
/// (measured on 2022: `sys.tables` records `master.sys.syspalvalues`,
/// `master.sys.syspalnames` and `master.sys.objects$` as well).
pub(crate) const HELPER_OBJECTS: &[&str] = &["syspalvalues", "syspalnames", "objects$"];

/// One audit record (the poll's columns, `sql::AUDIT_COLUMNS`).
#[derive(Clone, Default)]
pub(crate) struct Record {
    pub(crate) time_us: i64,
    pub(crate) action: String,
    pub(crate) succeeded: bool,
    pub(crate) class: String,
    pub(crate) session_id: i64,
    pub(crate) principal: String,
    pub(crate) session_principal: String,
    pub(crate) database: String,
    pub(crate) schema: String,
    pub(crate) object: String,
    pub(crate) statement: Zeroizing<String>,
    pub(crate) client_ip: String,
    pub(crate) application: String,
    pub(crate) sequence: i64,
    pub(crate) transaction: i64,
    pub(crate) file: String,
    pub(crate) offset: i64,
    pub(crate) group: String,
    pub(crate) error: Option<i64>,
    /// The statement text may be incomplete.
    pub(crate) cut: bool,
}

impl std::fmt::Debug for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Record")
            .field("action", &self.action)
            .field("class", &self.class)
            .field("session_id", &self.session_id)
            .field("offset", &self.offset)
            .finish_non_exhaustive()
    }
}

/// Why a row is not a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Malformed;

fn take_text(row: &mut [Value], i: usize) -> String {
    match row.get_mut(i) {
        Some(Value::Text(t)) => std::mem::take(t).trim_end().to_owned(),
        _ => String::new(),
    }
}

fn int(row: &[Value], i: usize) -> Option<i64> {
    row.get(i).and_then(Value::as_int)
}

impl Record {
    /// A record from one poll row (19 columns). The time, the action, the
    /// file and the offset are required; the rest may be `NULL`.
    pub(crate) fn from_row(mut row: Vec<Value>) -> Result<Self, Malformed> {
        if row.len() != crate::sql::AUDIT_POLL_COLUMNS {
            return Err(Malformed);
        }
        let time_us = int(&row, 0).ok_or(Malformed)?;
        let offset = int(&row, 16).ok_or(Malformed)?;
        let action = take_text(&mut row, 1);
        let file = take_text(&mut row, 15);
        if action.is_empty() || action.len() > 4 || file.is_empty() {
            return Err(Malformed);
        }
        let statement = match row.get_mut(10) {
            Some(Value::Text(t)) => Zeroizing::new(std::mem::take(t)),
            _ => Zeroizing::new(String::new()),
        };
        Ok(Self {
            time_us,
            succeeded: int(&row, 2) == Some(1),
            class: take_text(&mut row, 3),
            session_id: int(&row, 4).unwrap_or(-1),
            principal: take_text(&mut row, 5),
            session_principal: take_text(&mut row, 6),
            database: take_text(&mut row, 7),
            schema: take_text(&mut row, 8),
            object: take_text(&mut row, 9),
            client_ip: take_text(&mut row, 11),
            application: take_text(&mut row, 12),
            sequence: int(&row, 13).unwrap_or(1),
            transaction: int(&row, 14).unwrap_or(0),
            group: take_text(&mut row, 17),
            error: int(&row, 18),
            action,
            statement,
            file,
            offset,
            cut: false,
        })
    }

    /// The acting login: the session's login (`session_server_principal_name`,
    /// the impersonator under `EXECUTE AS`), else the record's principal.
    pub(crate) fn login(&self) -> &str {
        if self.session_principal.is_empty() {
            &self.principal
        } else {
            &self.session_principal
        }
    }

    pub(crate) fn ip(&self) -> Option<IpAddr> {
        self.client_ip.trim().parse().ok()
    }
}

/// Folds `sequence_number` parts into the record of their first part
/// (same `sequence_group_id`, in file order). A part without its first
/// part, a text above [`MAX_STATEMENT_BYTES`] and a first part of 4 000
/// characters whose next part is not in the batch are cut.
pub(crate) fn reassemble(records: Vec<Record>) -> Vec<Record> {
    let mut out: Vec<Record> = Vec::with_capacity(records.len());
    for r in records {
        if r.sequence > 1 {
            let head = out.iter_mut().rev().take(64).find(|h| {
                !r.group.is_empty() && h.group == r.group && h.session_id == r.session_id
            });
            match head {
                Some(h) => {
                    if h.statement.len() + r.statement.len() > MAX_STATEMENT_BYTES {
                        h.cut = true;
                    } else {
                        // A new buffer of the full size: the old one is
                        // zeroized when dropped (a reallocation by
                        // `push_str` would leave it unzeroized).
                        let mut joined =
                            String::with_capacity(h.statement.len() + r.statement.len());
                        joined.push_str(&h.statement);
                        joined.push_str(&r.statement);
                        h.statement = Zeroizing::new(joined);
                    }
                    h.sequence = r.sequence;
                }
                None => {
                    let mut r = r;
                    r.cut = true;
                    out.push(r);
                }
            }
            continue;
        }
        out.push(r);
    }
    for r in &mut out {
        // A full part whose continuation is not in this batch.
        if r.sequence == 1 && r.statement.chars().count() == PART_CHARS {
            r.cut = true;
        }
    }
    out
}

/// One statement: its first record and the objects of every record.
#[derive(Debug)]
pub(crate) struct Statement {
    pub(crate) head: Record,
    /// (database, schema, object, class) of each record.
    pub(crate) objects: Vec<(String, String, String, String)>,
}

fn same_statement(a: &Record, b: &Record) -> bool {
    a.session_id == b.session_id
        && a.transaction == b.transaction
        && a.time_us == b.time_us
        && a.action == b.action
        && a.succeeded == b.succeeded
        && a.principal == b.principal
        && a.session_principal == b.session_principal
        && a.cut == b.cut
        && *a.statement == *b.statement
}

/// Groups the records of one statement (same session, transaction, time,
/// action, result, principals and text; measured: one record per object
/// of a join, all at one `event_time`) into one [`Statement`], looking
/// back at most 64 statements. Empty texts are never grouped.
pub(crate) fn group(records: Vec<Record>) -> Vec<Statement> {
    let mut out: Vec<Statement> = Vec::new();
    for r in records {
        let obj = (
            r.database.clone(),
            r.schema.clone(),
            r.object.clone(),
            r.class.clone(),
        );
        if !r.statement.is_empty()
            && let Some(s) = out
                .iter_mut()
                .rev()
                .take(64)
                .find(|s| same_statement(&s.head, &r))
        {
            if !s.objects.contains(&obj) && s.objects.len() < 64 {
                s.objects.push(obj);
            }
            continue;
        }
        out.push(Statement {
            head: r,
            objects: vec![obj],
        });
    }
    out
}

/// What a record's action is (a closed mapping of `sys.dm_audit_actions`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mapped {
    Event(EventAction),
    /// `AUDIT_SESSION_CHANGED` or `AUDIT_SHUTDOWN_ON_FAILURE`: the audit
    /// started or stopped (refinement item 1, (a')).
    Restart,
    /// Not mapped (transactions, logouts, batch events…).
    Ignored,
}

/// Securable classes of principals and credentials: their `CREATE` /
/// `ALTER` / `DROP` is DCL.
const PRINCIPAL_CLASSES: &[&str] = &[
    "SL", "LX", "WL", "WG", "US", "SU", "WU", "GU", "RL", "SG", "AR", "CL", "CU", "AL", "AU", "XL",
    "XU", "PL", "PU", "CD", "DC",
];

/// The audit's own classes: server audit, server and database audit
/// specifications (`AUDIT_CHANGE_GROUP`).
pub(crate) const AUDIT_CLASSES: &[&str] = &["A", "SA", "DA"];

/// Maps an action and a class.
pub(crate) fn map(action: &str, class: &str) -> Mapped {
    use EventAction::{AuthFailure, Connect, Dcl, Ddl, Read, Write};
    match action {
        "SL" | "RC" | "EX" | "DBCC" | "BA" | "BAL" => Mapped::Event(Read),
        "IN" | "UP" | "DL" | "SN" => Mapped::Event(Write),
        "LGIF" | "DBAF" => Mapped::Event(AuthFailure),
        "LGIS" | "DBAS" => Mapped::Event(Connect),
        "AUSC" | "AUSF" => Mapped::Restart,
        "G" | "GWG" | "D" | "DWC" | "R" | "RWC" | "RWG" | "APRL" | "DPRL" | "PWC" | "PWCS"
        | "PWEX" | "PWMC" | "PWPL" | "PWR" | "PWRS" | "PWU" | "CCLG" | "CMLG" | "NMLG" | "LGDA"
        | "LGEA" | "LGDB" | "LGLG" | "LGNM" | "IMP" | "TO" | "USAF" | "USLG" | "USTC" | "CSPP" => {
            Mapped::Event(Dcl)
        }
        "CR" | "AL" | "DR" | "TRO" if PRINCIPAL_CLASSES.contains(&class) => Mapped::Event(Dcl),
        "CR" | "AL" | "DR" | "TRO" | "RS" | "ALTR" | "ALSS" | "ALST" | "ALRS" | "ALCN" | "ADBO"
        | "DABO" | "XA" | "XU" => Mapped::Event(Ddl),
        _ => Mapped::Ignored,
    }
}

/// Whether the statement changes the audit itself (an `AUDIT_CHANGE_GROUP`
/// record): always reported, and the proofs are probed again at once
/// (re-review N3).
pub(crate) fn is_audit_change(s: &Statement) -> bool {
    matches!(s.head.action.as_str(), "CR" | "AL" | "DR")
        && AUDIT_CLASSES.contains(&s.head.class.as_str())
}

/// Whether a record's object is one of the always-reported lists: an
/// object of `sys` (or `msdb`'s `dbo`, `SSISDB`'s `catalog` and
/// `internal`) of those names.
fn listed_object(schema: &str, object: &str) -> bool {
    let schema = schema.to_lowercase();
    let object = object.to_lowercase();
    matches!(schema.as_str(), "sys" | "dbo" | "catalog" | "internal")
        && tsql::STATEMENT_TEXT_OBJECTS
            .iter()
            .chain(tsql::CREDENTIAL_OBJECTS)
            .chain(tsql::VALUE_OBJECTS)
            .any(|n| *n == object)
}

/// Export tools by application name (`signature.bcp`; measured: `bcp`
/// sends `bcp`).
fn export_tool(app: &str) -> bool {
    let a = app.trim().to_ascii_lowercase();
    a == "bcp" || a.starts_with("sqlpackage") || a.contains("import and export wizard")
}

/// The event of a statement: `None` for an ignored action, a restart
/// marker, or a TCP probe that never sent a login (no name, error
/// 17830). Returns the event and the text analysis (for the own rule).
pub(crate) fn convert(s: &Statement) -> Option<(MaskedEvent, Option<TsqlAnalysis>)> {
    let h = &s.head;
    let Mapped::Event(mut action) = map(&h.action, &h.class) else {
        return None;
    };
    let ts = SystemTime::UNIX_EPOCH + Duration::from_micros(u64::try_from(h.time_us).unwrap_or(0));
    let client = ClientAddr::parse(&h.client_ip).filter(|c| matches!(c, ClientAddr::Ip(_)));
    if action == EventAction::AuthFailure {
        if h.principal.is_empty() && h.error == Some(ERR_NETWORK_BEFORE_LOGIN) {
            return None;
        }
        let principal = EventPrincipal::failed_account(&h.principal)
            .with_client(client)
            .with_application(&h.application);
        return Some((
            MaskedEvent::new(EventSource::SqlserverAudit, action, principal, ts),
            None,
        ));
    }
    let principal = EventPrincipal::account(h.login())
        .with_client(client)
        .with_application(&h.application);
    let analysis = (matches!(action, EventAction::Read | EventAction::Write)
        && !h.statement.trim().is_empty())
    .then(|| tsql::analyze_tsql(&h.statement, h.cut));
    // A password-taking procedure called: DCL, kind only.
    if analysis.as_ref().is_some_and(|a| a.credential) {
        action = EventAction::Dcl;
    }
    let mut ev = MaskedEvent::new(EventSource::SqlserverAudit, action, principal, ts);
    let mut always = false;
    let mut star = false;
    let wildcard = NormalizedName::wildcard;
    // Objects of the records.
    for (db, schema, object, class) in &s.objects {
        if schema.eq_ignore_ascii_case("sys") && HELPER_OBJECTS.contains(&object.as_str()) {
            continue;
        }
        let dbn = if db.is_empty() {
            wildcard()
        } else {
            normalize(db)
        };
        let o = if class == "DB" || object.is_empty() || matches!(h.action.as_str(), "BA" | "BAL") {
            EventObject::new(dbn, None, wildcard())
        } else {
            let sch = (!schema.is_empty()).then(|| normalize(schema));
            EventObject::new(dbn, sch, normalize(object))
        };
        if listed_object(schema, object) {
            always = true;
        }
        ev = ev.with_object(o);
    }
    if matches!(h.action.as_str(), "BA" | "BAL") {
        ev = ev.with_signal(Signal::BackupDatabase);
        always = true;
    }
    if is_audit_change(s) {
        always = true;
    }
    if action == EventAction::Read && export_tool(&h.application) {
        ev = ev.with_signal(Signal::Bcp);
    }
    if let Some(a) = &analysis {
        if a.credential || a.credential_function {
            // Kind and the records' objects only (decision 6, M6).
            always |= a.credential_function;
        } else if !a.usable() {
            // A cut, unlexable or ambiguous text: what it names cannot be
            // known (the ADR-0045 #181 rule).
            star = true;
            always = true;
        } else {
            if a.full_table_read(LARGE_LIMIT + 1) && action == EventAction::Read {
                ev = ev.with_signal(Signal::FullTableRead);
            }
            if a.remote_access {
                ev = ev.with_signal(Signal::RemoteDataAccess);
                star = true;
                always = true;
            }
            if a.backup {
                ev = ev.with_signal(Signal::BackupDatabase);
                always = true;
            }
            if a.dynamic_sql || a.user_function || a.four_part {
                star = true;
                always = true;
            }
            for n in &a.listed {
                let db = if h.database.is_empty() {
                    wildcard()
                } else {
                    normalize(&h.database)
                };
                ev = ev.with_object(EventObject::new(db, Some(normalize("sys")), normalize(n)));
                always = true;
            }
        }
        if a.kind == TsqlKind::Execute && a.dynamic_sql {
            star = true;
        }
    }
    if star || ev.objects().is_empty() {
        let db = if h.database.is_empty() {
            wildcard()
        } else {
            normalize(&h.database)
        };
        ev = ev.with_object(EventObject::new(db, None, wildcard()));
    }
    if always {
        ev = ev.with_always_report();
    }
    Some((ev, analysis))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn rec(action: &str, class: &str, schema: &str, object: &str, stmt: &str) -> Record {
        Record {
            time_us: 1_800_000_000_000_000,
            action: action.to_owned(),
            succeeded: true,
            class: class.to_owned(),
            session_id: 55,
            principal: "app".to_owned(),
            session_principal: "app".to_owned(),
            database: "retail".to_owned(),
            schema: schema.to_owned(),
            object: object.to_owned(),
            statement: Zeroizing::new(stmt.to_owned()),
            client_ip: "10.1.2.3".to_owned(),
            application: "SQLCMD".to_owned(),
            sequence: 1,
            transaction: 7,
            file: "/a/f_0_1.sqlaudit".to_owned(),
            offset: 4096,
            group: "0x01".to_owned(),
            error: None,
            cut: false,
        }
    }

    fn one(records: Vec<Record>) -> (MaskedEvent, Option<TsqlAnalysis>) {
        let g = group(reassemble(records));
        assert_eq!(g.len(), 1);
        convert(&g[0]).unwrap()
    }

    fn names(ev: &MaskedEvent) -> Vec<String> {
        ev.objects()
            .iter()
            .map(|o| {
                format!(
                    "{}.{}.{}",
                    o.database().as_str(),
                    o.schema().map_or("-", |s| s.as_str()),
                    o.object().as_str()
                )
            })
            .collect()
    }

    #[test]
    fn a_join_is_one_read_of_both_tables() {
        let q = "SELECT TOP (1) c.id FROM retail.crm.customers c JOIN retail.crm.customer_notes n ON n.customer_id = c.id";
        let (ev, _) = one(vec![
            rec("SL", "U", "crm", "customer_notes", q),
            rec("SL", "U", "crm", "customers", q),
        ]);
        assert_eq!(ev.action(), EventAction::Read);
        assert_eq!(
            names(&ev),
            ["retail.crm.customer_notes", "retail.crm.customers"]
        );
        assert!(ev.signals().is_empty() && !ev.always_report());
        assert_eq!(ev.source(), EventSource::SqlserverAudit);
        assert_eq!(ev.rows(), None);
    }

    #[test]
    fn whole_table_read_and_bcp() {
        let mut r = rec(
            "SL",
            "U",
            "crm",
            "customers",
            "select * from retail.crm.customers",
        );
        r.application = "bcp".to_owned();
        let (ev, _) = one(vec![r]);
        assert!(ev.signals().contains(&Signal::FullTableRead));
        assert!(ev.signals().contains(&Signal::Bcp));
    }

    #[test]
    fn catalog_helpers_are_left_out() {
        let q = "SELECT COUNT(*) FROM sys.tables";
        let (ev, _) = one(vec![
            rec("SL", "V", "sys", "tables", q),
            rec("SL", "U", "sys", "syspalvalues", q),
            rec("SL", "V", "sys", "objects$", q),
        ]);
        assert_eq!(names(&ev), ["retail.sys.tables"]);
    }

    #[test]
    fn listed_objects_are_always_reported() {
        let (ev, _) = one(vec![rec(
            "SL",
            "V",
            "sys",
            "sql_logins",
            "SELECT name FROM sys.sql_logins",
        )]);
        assert!(ev.always_report());
        let (ev, _) = one(vec![rec(
            "SL",
            "U",
            "crm",
            "customers",
            "SELECT t.text FROM sys.dm_exec_query_stats s CROSS APPLY sys.dm_exec_sql_text(s.sql_handle) t",
        )]);
        assert!(ev.always_report());
        assert!(
            names(&ev)
                .iter()
                .any(|n| n.ends_with("sys.dm_exec_sql_text"))
        );
        // A user table of a listed name in another schema is not.
        let (ev, _) = one(vec![rec(
            "SL",
            "U",
            "crm",
            "servers",
            "SELECT a FROM crm.servers WHERE b = 1",
        )]);
        assert!(!ev.always_report());
    }

    #[test]
    fn dynamic_sql_user_functions_and_remote_access() {
        let (ev, _) = one(vec![rec(
            "SL",
            "U",
            "crm",
            "customers",
            "SELECT dbo.f(a) FROM crm.customers WHERE a = 1",
        )]);
        assert!(ev.always_report());
        assert!(names(&ev).contains(&"retail.-.*".to_owned()));
        let (ev, _) = one(vec![rec(
            "EX",
            "X",
            "sys",
            "xp_cmdshell",
            "EXEC xp_cmdshell 'dir'",
        )]);
        assert!(ev.signals().contains(&Signal::RemoteDataAccess) && ev.always_report());
        let mut r = rec(
            "SL",
            "U",
            "crm",
            "customers",
            "SELECT * FROM OPENROWSET('x','y','SELECT 1')",
        );
        r.succeeded = false;
        let (ev, _) = one(vec![r]);
        assert!(
            ev.signals().contains(&Signal::RemoteDataAccess),
            "even when refused"
        );
    }

    #[test]
    fn backups_and_audit_changes() {
        let (ev, _) = one(vec![rec(
            "BA",
            "DB",
            "",
            "retail",
            "BACKUP DATABASE retail TO DISK = N'/tmp/x'",
        )]);
        assert!(ev.signals().contains(&Signal::BackupDatabase) && ev.always_report());
        assert_eq!(names(&ev), ["retail.-.*"]);
        let s = group(vec![rec(
            "AL",
            "A",
            "",
            "databastion_audit",
            "ALTER SERVER AUDIT x WITH (STATE = OFF)",
        )]);
        assert!(is_audit_change(&s[0]));
        let (ev, a) = convert(&s[0]).unwrap();
        assert_eq!(ev.action(), EventAction::Ddl);
        assert!(
            ev.always_report() && a.is_none(),
            "DDL text is never analysed"
        );
    }

    #[test]
    fn failed_logins_and_probes() {
        let mut r = rec(
            "LGIF",
            "LX",
            "",
            "",
            "Login failed for user 'jane'. [CLIENT: 10.1.2.3]",
        );
        r.principal = "jane".to_owned();
        r.session_id = 0;
        r.error = Some(18_456);
        let (ev, a) = one(vec![r.clone()]);
        assert_eq!(ev.action(), EventAction::AuthFailure);
        assert!(!ev.principal().send_name() && a.is_none());
        r.principal.clear();
        r.error = Some(17_830);
        assert!(convert(&group(vec![r])[0]).is_none());
    }

    #[test]
    fn credential_dcl_and_procedures() {
        let (ev, a) = one(vec![rec(
            "CR",
            "SL",
            "",
            "jane",
            "CREATE LOGIN jane WITH PASSWORD = N'******'",
        )]);
        assert_eq!(ev.action(), EventAction::Dcl);
        assert!(a.is_none());
        let (ev, a) = one(vec![rec(
            "EX",
            "X",
            "sys",
            "sp_addlogin",
            "EXEC sp_addlogin jane, Pa55word",
        )]);
        assert_eq!(ev.action(), EventAction::Dcl);
        assert!(a.unwrap().credential);
    }

    #[test]
    fn long_statements_are_reassembled_or_cut() {
        let part1 = "x".repeat(4000);
        let mut a = rec("SL", "U", "crm", "customers", &part1);
        a.group = "0xAA".to_owned();
        let mut b = rec("SL", "U", "crm", "customers", " WHERE 1 = 1");
        b.sequence = 2;
        b.group = "0xAA".to_owned();
        let out = reassemble(vec![a.clone(), b.clone()]);
        assert_eq!(out.len(), 1);
        assert!(!out[0].cut && out[0].statement.ends_with("WHERE 1 = 1"));
        assert!(reassemble(vec![a])[0].cut, "its next part is missing");
        assert!(reassemble(vec![b])[0].cut, "a part without its head");
        let (ev, _) = one(vec![rec("SL", "U", "crm", "customers", "SELECT 'abc")]);
        assert!(ev.always_report() && names(&ev).contains(&"retail.-.*".to_owned()));
    }

    #[test]
    fn rows_need_their_required_columns() {
        assert!(Record::from_row(vec![Value::Null; 3]).is_err());
        let mut row = vec![Value::Null; crate::sql::AUDIT_POLL_COLUMNS];
        assert!(Record::from_row(row.clone()).is_err());
        row[0] = Value::Int(1);
        row[1] = Value::Text("SL  ".to_owned());
        row[15] = Value::Text("/a/b.sqlaudit".to_owned());
        row[16] = Value::Int(4096);
        let r = Record::from_row(row).unwrap();
        assert_eq!(r.action, "SL");
        assert!(r.statement.is_empty());
    }
}
