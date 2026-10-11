//! Integration tests of ADR-0049 decision 8 (user code next to catalogs
//! only) against a PostgreSQL server, on every available source (the
//! pgaudit log files, then `pg_stat_statements`):
//!
//! - a role creates `"$user".length(integer)`, a `public` operator `+` on
//!   `integer`, a domain whose `CHECK` calls a user function, an implicit
//!   cast `integer → mytype` with `public.length(mytype)`, an overload with
//!   a defaulted argument, and `public.abs()` on a string-category type;
//!   a superuser creates an explicit, then an implicit, user-function cast
//!   `integer → text`. Each call, operator or cast next to `pg_class` is a
//!   read of `*`, always reported, before the next probe (stale probe after
//!   the DDL) and after it; built-ins and qualified names stay quiet;
//! - a database with `citext` and `hstore` and a few thousand relations,
//!   where `psql`'s describe queries, `postgres_exporter`'s catalog queries
//!   and the agent's own polls stay quiet and the probe is not cut, while a
//!   `"$user".length(integer)` overload there is still `*`;
//! - the server facts the probe rests on (pinning, one assertion each);
//! - the drift test of the built-in lists, both ways.
//!
//! Same prerequisites as `it.rs`. The fixtures live in their own
//! databases (dropped and recreated), owned by test roles dropped at the
//! end; nothing is added to `dev/`.

#![allow(clippy::print_stderr)]

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use databastion_classifiers::masking::{EventAction, MaskedEvent};
use databastion_core::config::TargetConfig;
use databastion_core::{AuditLevel, Connector};

use super::it::{
    EXPORTER_ACTIVITY, Logs, SERIAL, TempDir, Url, admin, admin_url, agent_url, audit_logs,
    collect_until, describe, raw_client, start_audit_with, target,
};
use crate::PostgresConnector;
use crate::audit::builtins;
use crate::conn::{Session, Timeouts};
use crate::discover::normalize;

/// The scenario database, the extensions database, the facts database.
const CODE_DB: &str = "databastion_it_code";
const EXT_DB: &str = "databastion_it_code_ext";
const FACTS_DB: &str = "databastion_it_code_facts";
/// A role that creates objects in `public` and in its own schema.
const CODE_ROLE: &str = "databastion_it_code";
/// A role whose statements must stay quiet.
const QUIET_ROLE: &str = "databastion_it_code_quiet";
const CODE_PASSWORD: &str = "dev-only-it-code-FAKE";
/// Marker in literals of the audited statements: never in an event or a
/// log (I2).
const CODE_MARK: &str = "Cd8Qz-it-code";
/// Relations of the extensions database.
const MANY_RELATIONS: u32 = 3000;

/// A target on `dbs`, reading `log` when given.
fn code_target(
    u: &Url,
    id: &str,
    log: Option<(&std::path::Path, &str)>,
    dbs: &[&str],
) -> (TempDir, TargetConfig) {
    let (dir, t) = target(u, &u.user, &u.password, &u.dbname, false);
    drop(t);
    let secret = dir.0.join("secret");
    let audit = log.map_or(String::new(), |(p, f)| {
        format!(", audit_log: {{path: \"{}\", format: {f}}}", p.display())
    });
    let list: Vec<String> = dbs.iter().map(|d| format!("\"{d}\"")).collect();
    let yaml = format!(
        "console: {{url: \"https://c.example\"}}\nstate_dir: /s\ntargets:\n  - id: {id}\n    \
         engine: postgres\n    host: \"{}\"\n    port: {}\n    account: \"{}\"\n    \
         secret: {{file: \"{}\"}}\n    postgres: {{databases: [{}], tls: disable{audit}}}\n",
        u.host,
        u.port,
        u.user,
        secret.display(),
        list.join(", ")
    );
    let config = databastion_core::AgentConfig::parse(&yaml).unwrap();
    (dir, config.targets[0].clone())
}

/// Whether pgaudit is loaded on the server.
async fn pgaudit_loaded(a: &tokio_postgres::Client) -> bool {
    let n: i64 = a
        .query_one(
            "SELECT count(*) FROM pg_catalog.pg_settings WHERE name = 'pgaudit.log'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    n > 0
}

async fn create_roles(a: &tokio_postgres::Client) {
    // Left over by an interrupted run.
    for db in [CODE_DB, EXT_DB, FACTS_DB] {
        a.batch_execute(&format!("DROP DATABASE IF EXISTS {db} WITH (FORCE)"))
            .await
            .unwrap();
    }
    for role in [CODE_ROLE, QUIET_ROLE] {
        a.batch_execute(&format!(
            "DROP ROLE IF EXISTS {role}; CREATE ROLE {role} LOGIN PASSWORD '{CODE_PASSWORD}'"
        ))
        .await
        .unwrap();
    }
}

async fn drop_roles(a: &tokio_postgres::Client) {
    for role in [CODE_ROLE, QUIET_ROLE] {
        a.batch_execute(&format!("DROP ROLE IF EXISTS {role}"))
            .await
            .unwrap();
    }
}

/// A fresh database `db` where [`CODE_ROLE`] can create in `public` and in
/// its own schema, with pgaudit logging reads, writes and DDL there.
async fn fresh_db(a: &tokio_postgres::Client, adm: &Url, db: &str) -> tokio_postgres::Client {
    a.batch_execute(&format!("DROP DATABASE IF EXISTS {db} WITH (FORCE)"))
        .await
        .unwrap();
    a.batch_execute(&format!("CREATE DATABASE {db}"))
        .await
        .unwrap();
    a.batch_execute(&format!(
        "GRANT CONNECT, CREATE ON DATABASE {db} TO {CODE_ROLE}, {QUIET_ROLE}"
    ))
    .await
    .unwrap();
    if pgaudit_loaded(a).await {
        a.batch_execute(&format!(
            "ALTER DATABASE {db} SET pgaudit.log = 'read, write, ddl'"
        ))
        .await
        .unwrap();
    }
    let c = admin(adm, db).await;
    c.batch_execute(&format!(
        "CREATE SCHEMA {CODE_ROLE} AUTHORIZATION {CODE_ROLE}; \
         GRANT CREATE ON SCHEMA public TO {CODE_ROLE}"
    ))
    .await
    .unwrap();
    c
}

/// A read of `*` by `user` in `db`, always reported.
fn star_of(e: &MaskedEvent, user: &str, db: &str) -> bool {
    e.principal().account_name() == user
        && e.action() == EventAction::Read
        && e.always_report()
        && e.objects()
            .iter()
            .any(|o| o.object().as_str() == "*" && o.database().as_str() == normalize(db).as_str())
}

/// Waits for one more read of `*` by `user` in `db` than before.
async fn expect_star(
    rx: &mut tokio::sync::mpsc::Receiver<MaskedEvent>,
    events: &mut Vec<MaskedEvent>,
    user: &str,
    db: &str,
    what: &str,
) {
    let count = |ev: &[MaskedEvent]| ev.iter().filter(|e| star_of(e, user, db)).count();
    let before = count(events);
    collect_until(rx, events, Duration::from_secs(20), |ev| count(ev) > before).await;
    assert!(
        count(events) > before,
        "{what}: no read of * by {user}: {:#?}",
        events.iter().map(describe).collect::<Vec<_>>()
    );
}

async fn run(c: &tokio_postgres::Client, q: &str) {
    c.simple_query(q)
        .await
        .unwrap_or_else(|e| panic!("{q}: {e}"));
}

/// `check()` (the collision probe) once the stream has read the DDL just
/// run: a probe that starts before the stream sees a DDL stays stale (the
/// mark is the time the stream saw it, fail closed).
async fn probe_after_ddl(connector: &PostgresConnector, t: &TargetConfig) {
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert!(connector.check(t).await.reachable);
}

/// Lets a `pg_stat_statements` poll pass: the order of statements within
/// one poll is not known, so a DDL polled with earlier statements makes the
/// whole poll stale (fail closed).
async fn settle() {
    tokio::time::sleep(Duration::from_millis(2500)).await;
}

/// The sources of the test server: the pgaudit log files, then
/// `pg_stat_statements`.
fn sources() -> Vec<(String, Option<(PathBuf, &'static str)>)> {
    let mut out: Vec<(String, Option<(PathBuf, &'static str)>)> = audit_logs()
        .into_iter()
        .map(|(p, f)| (format!("pgaudit {f}"), Some((p, f))))
        .collect();
    out.push(("pg_stat_statements".to_owned(), None));
    out
}

/// ADR-0049 decision 8 against the server, scenario by scenario (see the
/// module documentation).
#[tokio::test]
async fn user_code_next_to_catalogs_is_a_read_of_star() {
    let (Some(u), Some(adm)) = (agent_url(), admin_url()) else {
        return;
    };
    let _serial = SERIAL.lock().await;
    let logs = Logs::default();
    let _guard = logs.capture();
    let a = admin(&adm, &u.dbname).await;
    create_roles(&a).await;
    for (i, (label, log)) in sources().into_iter().enumerate() {
        let c_admin = fresh_db(&a, &adm, CODE_DB).await;
        let (_dir, t) = code_target(
            &u,
            &format!("pg-code-{i}"),
            log.as_ref().map(|(p, f)| (p.as_path(), *f)),
            &[&u.dbname, CODE_DB],
        );
        let connector = Arc::new(PostgresConnector::new());
        let health = connector.check(&t).await;
        assert!(health.reachable, "{label}: {health:?}");
        if log.is_none() && health.audit_level != AuditLevel::Limited {
            eprintln!("skipped: {label}: pg_stat_statements is not usable by the agent role");
            continue;
        }
        let state = TempDir::new();
        let (task, mut rx) = start_audit_with(Arc::clone(&connector), &t, &state.0);
        tokio::time::sleep(Duration::from_millis(2500)).await;
        let code = raw_client(&adm, CODE_ROLE, CODE_PASSWORD, CODE_DB).await;
        let quiet = raw_client(&adm, QUIET_ROLE, CODE_PASSWORD, CODE_DB).await;
        let mut events = Vec::new();
        // Built-ins and qualified names next to catalogs: quiet.
        for q in [
            &format!(
                "SELECT length(relname), lower(relname), '{CODE_MARK}' FROM pg_class \
                 WHERE relkind = 'r' AND relname LIKE 'pg%' LIMIT 1"
            ),
            "SELECT pg_catalog.length('x') FROM pg_catalog.pg_class LIMIT 1",
            "SELECT relname::text, CAST(relpages AS bigint) FROM pg_class ORDER BY 1 LIMIT 1",
            "SELECT 1 OPERATOR(pg_catalog.+) 1 FROM pg_class LIMIT 1",
        ] {
            run(&quiet, q).await;
        }
        settle().await;
        // (1) A function created and called before the next probe: the
        // probe is stale after the DDL (log order on pgaudit, the poll on
        // pg_stat_statements).
        run(
            &code,
            &format!(
                "CREATE FUNCTION {CODE_ROLE}.length(integer) RETURNS integer \
                 LANGUAGE sql AS 'SELECT 7'"
            ),
        )
        .await;
        run(
            &code,
            &format!("SELECT length(42), '{CODE_MARK}' FROM pg_class LIMIT 1"),
        )
        .await;
        expect_star(
            &mut rx,
            &mut events,
            CODE_ROLE,
            CODE_DB,
            &format!("{label}: stale probe after CREATE FUNCTION"),
        )
        .await;
        // (2) The probe names `length` for this database: `"$user".length(
        // integer)` wins on type match (CVE-2018-1058).
        probe_after_ddl(&connector, &t).await;
        run(&code, "SELECT length(42) FROM pg_class LIMIT 1").await;
        expect_star(
            &mut rx,
            &mut events,
            CODE_ROLE,
            CODE_DB,
            &format!("{label}: \"$user\".length(integer)"),
        )
        .await;
        run(
            &quiet,
            "SELECT pg_catalog.length('x') FROM pg_catalog.pg_class LIMIT 1",
        )
        .await;
        run(&code, &format!("DROP FUNCTION {CODE_ROLE}.length(integer)")).await;
        // (3) A `public` operator `+` on `integer`, and a domain whose
        // CHECK calls a user function.
        run(
            &code,
            "CREATE FUNCTION public.myplus(integer, integer) RETURNS integer \
               LANGUAGE sql AS 'SELECT 9'; \
             CREATE OPERATOR public.+ (leftarg = integer, rightarg = integer, \
               function = public.myplus); \
             CREATE FUNCTION public.chk(integer) RETURNS boolean LANGUAGE sql AS 'SELECT true'; \
             CREATE DOMAIN public.dpos AS integer CHECK (public.chk(VALUE))",
        )
        .await;
        probe_after_ddl(&connector, &t).await;
        run(&code, "SELECT 1 + 1 FROM pg_class LIMIT 1").await;
        expect_star(
            &mut rx,
            &mut events,
            CODE_ROLE,
            CODE_DB,
            &format!("{label}: public operator +"),
        )
        .await;
        run(&code, "SELECT 1::public.dpos FROM pg_class LIMIT 1").await;
        expect_star(
            &mut rx,
            &mut events,
            CODE_ROLE,
            CODE_DB,
            &format!("{label}: cast to a user domain"),
        )
        .await;
        run(
            &code,
            "DROP OPERATOR public.+ (integer, integer); \
             DROP FUNCTION public.myplus(integer, integer); \
             DROP DOMAIN public.dpos; DROP FUNCTION public.chk(integer)",
        )
        .await;
        // (4) The type owner's implicit cast `integer → mytype`, with
        // `public.length(mytype)` (no superuser needed).
        run(
            &code,
            "CREATE TYPE public.mytype AS ENUM ('a'); \
             CREATE FUNCTION public.int_to_mytype(integer) RETURNS public.mytype \
               LANGUAGE sql AS $$SELECT 'a'::public.mytype$$; \
             CREATE CAST (integer AS public.mytype) \
               WITH FUNCTION public.int_to_mytype(integer) AS IMPLICIT; \
             CREATE FUNCTION public.length(public.mytype) RETURNS integer \
               LANGUAGE sql AS 'SELECT 8'",
        )
        .await;
        probe_after_ddl(&connector, &t).await;
        run(&code, "SELECT length(42) FROM pg_class LIMIT 1").await;
        expect_star(
            &mut rx,
            &mut events,
            CODE_ROLE,
            CODE_DB,
            &format!("{label}: implicit cast integer -> mytype with public.length(mytype)"),
        )
        .await;
        run(
            &code,
            "DROP FUNCTION public.length(public.mytype); \
             DROP CAST (integer AS public.mytype); \
             DROP FUNCTION public.int_to_mytype(integer); DROP TYPE public.mytype",
        )
        .await;
        // (5) A defaulted argument: `strpos('x')` reaches
        // `public.strpos(text, myenum DEFAULT 'a')` at one argument.
        run(
            &code,
            "CREATE TYPE public.myenum AS ENUM ('a'); \
             CREATE FUNCTION public.strpos(text, public.myenum DEFAULT 'a') RETURNS integer \
               LANGUAGE sql AS 'SELECT 11'",
        )
        .await;
        probe_after_ddl(&connector, &t).await;
        run(&code, "SELECT strpos('x') FROM pg_class LIMIT 1").await;
        expect_star(
            &mut rx,
            &mut events,
            CODE_ROLE,
            CODE_DB,
            &format!("{label}: defaulted argument"),
        )
        .await;
        run(
            &quiet,
            "SELECT pg_catalog.strpos('abc', 'b') FROM pg_catalog.pg_class LIMIT 1",
        )
        .await;
        run(
            &code,
            "DROP FUNCTION public.strpos(text, public.myenum); DROP TYPE public.myenum",
        )
        .await;
        // (6) `abs('5')` with `public.abs(mystr)`, a string-category type
        // (a base type: superuser).
        run(
            &c_admin,
            "CREATE TYPE public.mystr; \
             CREATE FUNCTION public.mystr_in(cstring) RETURNS public.mystr \
               LANGUAGE internal IMMUTABLE STRICT AS 'textin'; \
             CREATE FUNCTION public.mystr_out(public.mystr) RETURNS cstring \
               LANGUAGE internal IMMUTABLE STRICT AS 'textout'; \
             CREATE TYPE public.mystr (INPUT = public.mystr_in, OUTPUT = public.mystr_out, \
               LIKE = text, CATEGORY = 'S'); \
             CREATE FUNCTION public.abs(public.mystr) RETURNS integer \
               LANGUAGE sql AS 'SELECT 12'",
        )
        .await;
        probe_after_ddl(&connector, &t).await;
        run(&code, "SELECT abs('5') FROM pg_class LIMIT 1").await;
        expect_star(
            &mut rx,
            &mut events,
            CODE_ROLE,
            CODE_DB,
            &format!("{label}: abs('5') with public.abs(mystr)"),
        )
        .await;
        run(
            &quiet,
            "SELECT lower('X'), pg_catalog.abs(-5) FROM pg_class WHERE 'x' = 'y' LIMIT 1",
        )
        .await;
        settle().await;
        run(&c_admin, "DROP TYPE public.mystr CASCADE").await;
        // Everything so far: the quiet role and the agent gave nothing.
        collect_until(&mut rx, &mut events, Duration::from_secs(4), |_| false).await;
        let before_casts = events.len();
        // (7) A superuser's explicit cast `integer → text` with a user
        // function: `::text` is not built in in this database, whatever
        // the source type (ADR-0049 R2), so the agent's own casts to
        // `pg_catalog.text` there are reported too (from here on).
        run(
            &c_admin,
            "CREATE FUNCTION public.f(integer) RETURNS text LANGUAGE sql AS $$SELECT 'user'$$; \
             CREATE CAST (integer AS text) WITH FUNCTION public.f(integer)",
        )
        .await;
        probe_after_ddl(&connector, &t).await;
        run(&code, "SELECT 42::text FROM pg_class LIMIT 1").await;
        expect_star(
            &mut rx,
            &mut events,
            CODE_ROLE,
            CODE_DB,
            &format!("{label}: explicit user cast integer -> text"),
        )
        .await;
        run(&quiet, "SELECT relname FROM pg_class LIMIT 1").await;
        collect_until(&mut rx, &mut events, Duration::from_secs(4), |_| false).await;
        // (8) The same cast, implicit: it runs with no cast and no
        // unqualified name in the text, so every catalog-only statement of
        // the database is `*` (the agent's own statements there too).
        run(
            &c_admin,
            "DROP CAST (integer AS text); \
             CREATE CAST (integer AS text) WITH FUNCTION public.f(integer) AS IMPLICIT",
        )
        .await;
        probe_after_ddl(&connector, &t).await;
        run(
            &code,
            "SELECT pg_catalog.length(42) FROM pg_catalog.pg_class LIMIT 1",
        )
        .await;
        expect_star(
            &mut rx,
            &mut events,
            CODE_ROLE,
            CODE_DB,
            &format!("{label}: pg_catalog.length(42) under an implicit user cast"),
        )
        .await;
        run(
            &code,
            "SELECT relname FROM pg_class UNION SELECT relname FROM pg_catalog.pg_class",
        )
        .await;
        expect_star(
            &mut rx,
            &mut events,
            CODE_ROLE,
            CODE_DB,
            &format!("{label}: UNION under an implicit user cast"),
        )
        .await;
        run(
            &c_admin,
            "DROP CAST (integer AS text); DROP FUNCTION public.f(integer)",
        )
        .await;
        task.abort();
        let all: Vec<String> = events.iter().map(describe).collect();
        eprintln!("{label} events ({}):\n{}", all.len(), all.join("\n"));
        assert!(
            !events
                .iter()
                .any(|e| e.principal().account_name() == QUIET_ROLE),
            "{label}: built-ins and qualified names: {all:#?}"
        );
        assert!(
            !events[..before_casts]
                .iter()
                .any(|e| e.principal().account_name() == u.user),
            "{label}: the agent's own statements: {all:#?}"
        );
        for e in &events {
            assert!(!format!("{e:?}").contains(CODE_MARK), "{label}");
            assert!(!describe(e).contains(CODE_MARK), "{label}");
        }
        drop(code);
        drop(quiet);
        drop(c_admin);
        a.batch_execute(&format!("DROP DATABASE IF EXISTS {CODE_DB} WITH (FORCE)"))
            .await
            .unwrap();
    }
    drop_roles(&a).await;
    let text = logs.text();
    assert!(
        !text.contains(CODE_MARK),
        "a statement text reached the logs"
    );
    assert!(!text.contains("myplus"), "a probe name reached the logs");
}

/// `postgres_exporter`'s default catalog queries (activity, settings, locks,
/// database and table statistics).
fn exporter_queries() -> Vec<&'static str> {
    vec![
        EXPORTER_ACTIVITY,
        "SELECT name, setting, COALESCE(unit, ''), short_desc, vartype FROM pg_settings \
         WHERE vartype IN ('bool', 'integer', 'real') AND name != 'sync_commit_cancel_wait'",
        "SELECT pg_database.datname,tmp.mode,COALESCE(count,0) as count FROM ( VALUES \
         ('accesssharelock'), ('rowsharelock'), ('rowexclusivelock'), ('shareupdateexclusivelock'), \
         ('sharelock'), ('sharerowexclusivelock'), ('exclusivelock'), ('accessexclusivelock'), \
         ('sireadlock') ) AS tmp(mode) CROSS JOIN pg_database LEFT JOIN (SELECT database, \
         lower(mode) AS mode,count(*) AS count FROM pg_locks WHERE database IS NOT NULL \
         GROUP BY database, lower(mode) ) AS tmp2 ON tmp.mode=tmp2.mode and \
         pg_database.oid = tmp2.database ORDER BY 1",
        "SELECT datid, datname, numbackends, xact_commit, xact_rollback, blks_read, blks_hit, \
         tup_returned, tup_fetched, tup_inserted, tup_updated, tup_deleted, conflicts, \
         temp_files, temp_bytes, deadlocks, blk_read_time, blk_write_time, stats_reset \
         FROM pg_stat_database",
        "SELECT current_database() datname, schemaname, relname, seq_scan, seq_tup_read, \
         idx_scan, idx_tup_fetch, n_tup_ins, n_tup_upd, n_tup_del, n_tup_hot_upd, n_live_tup, \
         n_dead_tup, n_mod_since_analyze, COALESCE(last_vacuum, '1970-01-01Z') as last_vacuum, \
         COALESCE(last_autovacuum, '1970-01-01Z') as last_autovacuum, vacuum_count, \
         autovacuum_count, analyze_count, autoanalyze_count FROM pg_stat_user_tables",
        "SELECT pg_database.datname, pg_database.datconnlimit FROM pg_database",
    ]
}

/// `psql`'s describe commands (`\d` and friends) as `role`, through the
/// host's `psql` (its version picks the server-specific queries).
/// `false` when `psql` is not there.
fn psql_describe(adm: &Url, role: &str, db: &str) -> bool {
    let out = std::process::Command::new("psql")
        .args([
            "-X",
            "-q",
            "-h",
            &adm.host,
            "-p",
            &adm.port.to_string(),
            "-U",
            role,
            "-d",
            db,
            "-c",
            "\\d",
            "-c",
            "\\dt many.*",
            "-c",
            "\\d many.t1",
            "-c",
            "\\df",
            "-c",
            "\\dT",
            "-c",
            "\\dx",
            "-c",
            "\\dn",
            "-c",
            "\\du",
            "-c",
            "\\l",
        ])
        .env("PGPASSWORD", CODE_PASSWORD)
        .env("PGAPPNAME", "psql")
        .output();
    match out {
        Ok(o) if o.status.success() => true,
        Ok(o) => {
            eprintln!(
                "skipped: psql describe commands failed ({})",
                String::from_utf8_lossy(&o.stderr)
                    .lines()
                    .next()
                    .unwrap_or("")
            );
            false
        }
        Err(_) => {
            eprintln!("skipped: no psql on the host");
            false
        }
    }
}

/// A database with `citext` and `hstore` installed in `public` and a few
/// thousand relations: the probe is not cut (and finds only the overloads
/// a built-in value reaches), `psql`'s describe queries,
/// `postgres_exporter`'s catalog queries and the agent's own polls stay
/// quiet, and `"$user".length(integer)` is still `*`. Prints the probe's
/// time there (load impact).
#[tokio::test]
async fn extensions_and_many_relations_stay_quiet() {
    let (Some(u), Some(adm)) = (agent_url(), admin_url()) else {
        return;
    };
    let _serial = SERIAL.lock().await;
    let a = admin(&adm, &u.dbname).await;
    let available: i64 = a
        .query_one(
            "SELECT count(*) FROM pg_catalog.pg_available_extensions \
             WHERE name IN ('citext', 'hstore')",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    if available < 2 {
        eprintln!("skipped: citext or hstore is not available on the server");
        return;
    }
    create_roles(&a).await;
    let e_admin = fresh_db(&a, &adm, EXT_DB).await;
    e_admin
        .batch_execute(&format!(
            "CREATE EXTENSION citext; CREATE EXTENSION hstore; CREATE SCHEMA many; \
             GRANT USAGE ON SCHEMA many TO {QUIET_ROLE}"
        ))
        .await
        .unwrap();
    // In transactions of 200 relations (the lock table).
    for from in (1..=MANY_RELATIONS).step_by(200) {
        e_admin
            .batch_execute(&format!(
                "DO $$ BEGIN FOR i IN {from}..{} LOOP \
                   EXECUTE pg_catalog.format('CREATE TABLE many.t%s (a integer, \
                     b public.citext, c public.hstore)', i); \
                 END LOOP; END $$",
                (from + 199).min(MANY_RELATIONS)
            ))
            .await
            .unwrap();
    }
    // The probe in that database: not cut, only what a built-in value
    // reaches (hstore's `->` on `text[]`: `'a=>1' -> ARRAY['a']`).
    let (_d, t0) = code_target(&u, "pg-code-ext-probe", None, &[EXT_DB]);
    let timeouts = Timeouts::new(Duration::from_secs(3));
    let session = Session::connect(&t0, EXT_DB, timeouts).await.unwrap();
    let mut times = Vec::new();
    let mut names = None;
    for _ in 0..10 {
        let started = Instant::now();
        names = crate::check::user_code_probe(&session, timeouts)
            .await
            .unwrap();
        times.push(started.elapsed());
    }
    times.sort();
    let names = names.expect("the probe is not cut");
    eprintln!(
        "probe with citext, hstore and {MANY_RELATIONS} relations: median {:?}, max {:?}; \
         {names:?}",
        times[times.len() / 2],
        times[times.len() - 1]
    );
    assert!(names.functions.is_empty(), "{names:?}");
    assert!(names.types.is_empty(), "{names:?}");
    assert!(
        names.operators.iter().all(|o| o == "->"),
        "{:?}",
        names.operators
    );
    assert!(!names.implicit_cast);
    assert!(times[times.len() / 2] < Duration::from_secs(2));
    drop(session);
    for (i, (label, log)) in sources().into_iter().enumerate() {
        let (_dir, t) = code_target(
            &u,
            &format!("pg-code-ext-{i}"),
            log.as_ref().map(|(p, f)| (p.as_path(), *f)),
            &[&u.dbname, EXT_DB],
        );
        let connector = Arc::new(PostgresConnector::new());
        let health = connector.check(&t).await;
        if log.is_none() && health.audit_level != AuditLevel::Limited {
            eprintln!("skipped: {label}: pg_stat_statements is not usable by the agent role");
            continue;
        }
        let state = TempDir::new();
        let (task, mut rx) = start_audit_with(Arc::clone(&connector), &t, &state.0);
        tokio::time::sleep(Duration::from_millis(2500)).await;
        let quiet = raw_client(&adm, QUIET_ROLE, CODE_PASSWORD, EXT_DB).await;
        for q in exporter_queries() {
            run(&quiet, q).await;
        }
        for q in [
            "SELECT lower('X'), upper(relname) FROM pg_class WHERE 'x' = 'y' LIMIT 1",
            "SELECT relname FROM pg_class WHERE relname ~ '^t1' AND relname LIKE 't%' LIMIT 1",
        ] {
            run(&quiet, q).await;
        }
        let described = psql_describe(&adm, QUIET_ROLE, EXT_DB);
        let mut events = Vec::new();
        for _ in 0..2 {
            assert!(connector.check(&t).await.reachable, "{label}");
        }
        collect_until(&mut rx, &mut events, Duration::from_secs(5), |_| false).await;
        settle().await;
        // A `"$user".length(integer)` overload there is still `*`.
        let code = raw_client(&adm, CODE_ROLE, CODE_PASSWORD, EXT_DB).await;
        run(
            &code,
            &format!(
                "CREATE FUNCTION {CODE_ROLE}.length(integer) RETURNS integer \
                 LANGUAGE sql AS 'SELECT 7'"
            ),
        )
        .await;
        probe_after_ddl(&connector, &t).await;
        run(&code, "SELECT length(42) FROM pg_class LIMIT 1").await;
        expect_star(
            &mut rx,
            &mut events,
            CODE_ROLE,
            EXT_DB,
            &format!("{label}: \"$user\".length(integer) next to citext and hstore"),
        )
        .await;
        run(&code, &format!("DROP FUNCTION {CODE_ROLE}.length(integer)")).await;
        task.abort();
        let all: Vec<String> = events.iter().map(describe).collect();
        eprintln!(
            "{label} events ({}, psql describe: {described}):\n{}",
            all.len(),
            all.join("\n")
        );
        assert!(
            !events
                .iter()
                .any(|e| e.principal().account_name() == QUIET_ROLE),
            "{label}: exporter, psql and built-ins: {all:#?}"
        );
        assert!(
            !events
                .iter()
                .any(|e| e.principal().account_name() == u.user),
            "{label}: the agent's own statements: {all:#?}"
        );
    }
    drop(e_admin);
    a.batch_execute(&format!("DROP DATABASE IF EXISTS {EXT_DB} WITH (FORCE)"))
        .await
        .unwrap();
    drop_roles(&a).await;
}

/// The SQLSTATE of a statement's error, or `None` when it succeeds.
async fn sqlstate(c: &tokio_postgres::Client, q: &str) -> Option<String> {
    c.simple_query(q)
        .await
        .err()
        .and_then(|e| e.code().map(|s| s.code().to_owned()))
}

async fn one_text(c: &tokio_postgres::Client, q: &str) -> String {
    let rows = c
        .simple_query(q)
        .await
        .unwrap_or_else(|e| panic!("{q}: {e}"));
    rows.iter()
        .find_map(|m| match m {
            tokio_postgres::SimpleQueryMessage::Row(r) => r.get(0).map(str::to_owned),
            _ => None,
        })
        .unwrap_or_default()
}

/// ADR-0049 decision 8, pinning: the function and operator resolution
/// facts the collision probe rests on, one assertion each, with what the
/// probe reports for each.
#[tokio::test]
async fn user_code_server_facts() {
    let (Some(u), Some(adm)) = (agent_url(), admin_url()) else {
        return;
    };
    let _serial = SERIAL.lock().await;
    let a = admin(&adm, &u.dbname).await;
    let version: String = a
        .query_one("SELECT pg_catalog.version()", &[])
        .await
        .unwrap()
        .get(0);
    create_roles(&a).await;
    let f_admin = fresh_db(&a, &adm, FACTS_DB).await;
    let code = raw_client(&adm, CODE_ROLE, CODE_PASSWORD, FACTS_DB).await;
    let (_d, t) = code_target(&u, "pg-code-facts", None, &[FACTS_DB]);
    let timeouts = Timeouts::new(Duration::from_secs(3));
    let probe = || async {
        let s = Session::connect(&t, FACTS_DB, timeouts).await.unwrap();
        crate::check::user_code_probe(&s, timeouts)
            .await
            .unwrap()
            .expect("not cut")
    };
    // A fresh database: nothing.
    assert_eq!(
        probe().await,
        crate::audit::user_code::ProbeNames::default(),
        "{version}"
    );
    // (1) `"$user".length(integer)` wins over `pg_catalog.length` for an
    // integer, with the default search path (a non-superuser).
    run(
        &code,
        &format!(
            "CREATE FUNCTION {CODE_ROLE}.length(integer) RETURNS integer \
             LANGUAGE sql AS 'SELECT 7'"
        ),
    )
    .await;
    assert_eq!(one_text(&code, "SELECT length(42)").await, "7", "{version}");
    let n = probe().await;
    assert!(n.functions.contains("length"), "{version}: {n:?}");
    assert!(n.param_functions.contains("length"), "{version}: {n:?}");
    run(&code, &format!("DROP FUNCTION {CODE_ROLE}.length(integer)")).await;
    // (2) An implicit cast `integer → mytype` created by the type's owner
    // makes `length(42)` reach `public.length(mytype)`.
    run(
        &code,
        "CREATE TYPE public.mytype AS ENUM ('a'); \
         CREATE FUNCTION public.int_to_mytype(integer) RETURNS public.mytype \
           LANGUAGE sql AS $$SELECT 'a'::public.mytype$$; \
         CREATE CAST (integer AS public.mytype) \
           WITH FUNCTION public.int_to_mytype(integer) AS IMPLICIT; \
         CREATE FUNCTION public.length(public.mytype) RETURNS integer \
           LANGUAGE sql AS 'SELECT 8'",
    )
    .await;
    assert_eq!(one_text(&code, "SELECT length(42)").await, "8", "{version}");
    assert!(probe().await.functions.contains("length"), "{version}");
    // Without the cast, an integer reaches no `length` at all.
    run(&code, "DROP CAST (integer AS public.mytype)").await;
    assert_eq!(
        sqlstate(&code, "SELECT length(42)").await.as_deref(),
        Some("42883"),
        "{version}"
    );
    // (3) With an enum (category `E`), `abs('5')` is ambiguous: an untyped
    // literal does not resolve to a non-string user type when built-in
    // overloads take another category (the probe still reports it).
    run(
        &code,
        "CREATE FUNCTION public.abs(public.mytype) RETURNS integer LANGUAGE sql AS 'SELECT 10'",
    )
    .await;
    assert_eq!(
        sqlstate(&code, "SELECT abs('5')").await.as_deref(),
        Some("42725"),
        "{version}: abs('5') with an enum overload"
    );
    assert!(probe().await.functions.contains("abs"), "{version}");
    // (4) A defaulted argument: `strpos('x')` reaches
    // `public.strpos(text, mytype DEFAULT 'a')` at one argument.
    run(
        &code,
        "CREATE FUNCTION public.strpos(text, public.mytype DEFAULT 'a') RETURNS integer \
         LANGUAGE sql AS 'SELECT 11'",
    )
    .await;
    assert_eq!(
        one_text(&code, "SELECT strpos('x')").await,
        "11",
        "{version}"
    );
    assert_eq!(
        one_text(&code, "SELECT strpos('abc', 'b')").await,
        "2",
        "{version}"
    );
    assert!(probe().await.functions.contains("strpos"), "{version}");
    // Several arguments: an exact match on one (`integer`) favours the user
    // overload, whose other argument only a literal reaches, over the
    // built-in `strpos(text, text)`.
    run(
        &code,
        "DROP FUNCTION public.strpos(text, public.mytype); \
         CREATE FUNCTION public.strpos(integer, public.mytype) RETURNS integer \
         LANGUAGE sql AS 'SELECT 13'",
    )
    .await;
    assert_eq!(
        one_text(&code, "SELECT strpos(42, 'a')").await,
        "13",
        "{version}"
    );
    assert!(probe().await.functions.contains("strpos"), "{version}");
    run(
        &code,
        "DROP FUNCTION public.strpos(integer, public.mytype); \
         DROP FUNCTION public.abs(public.mytype); DROP FUNCTION public.length(public.mytype); \
         DROP FUNCTION public.int_to_mytype(integer); DROP TYPE public.mytype",
    )
    .await;
    assert_eq!(
        probe().await,
        crate::audit::user_code::ProbeNames::default(),
        "{version}"
    );
    // (5) A string-category user type (superuser: a base type):
    // `abs('5')` resolves to `public.abs(mystr)`; `lower('X')` stays the
    // built-in (`text` is the preferred string type).
    run(
        &f_admin,
        "CREATE TYPE public.mystr; \
         CREATE FUNCTION public.mystr_in(cstring) RETURNS public.mystr \
           LANGUAGE internal IMMUTABLE STRICT AS 'textin'; \
         CREATE FUNCTION public.mystr_out(public.mystr) RETURNS cstring \
           LANGUAGE internal IMMUTABLE STRICT AS 'textout'; \
         CREATE TYPE public.mystr (INPUT = public.mystr_in, OUTPUT = public.mystr_out, \
           LIKE = text, CATEGORY = 'S'); \
         CREATE FUNCTION public.abs(public.mystr) RETURNS integer LANGUAGE sql AS 'SELECT 12'; \
         CREATE FUNCTION public.lower(public.mystr) RETURNS text \
           LANGUAGE sql AS $$SELECT 'user'$$",
    )
    .await;
    assert_eq!(one_text(&code, "SELECT abs('5')").await, "12", "{version}");
    assert_eq!(one_text(&code, "SELECT lower('X')").await, "x", "{version}");
    let n = probe().await;
    assert!(n.functions.contains("abs"), "{version}: {n:?}");
    assert!(!n.functions.contains("lower"), "{version}: {n:?}");
    run(&f_admin, "DROP TYPE public.mystr CASCADE").await;
    // (6) citext and hstore: `lower`, `=` and `LIKE` on literals stay the
    // built-ins; hstore's `->` on `text[]` is reached by
    // `'…' -> ARRAY[…]` (the only colliding name).
    let ext: i64 = a
        .query_one(
            "SELECT count(*) FROM pg_catalog.pg_available_extensions \
             WHERE name IN ('citext', 'hstore')",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    if ext == 2 {
        run(&f_admin, "CREATE EXTENSION citext; CREATE EXTENSION hstore").await;
        assert_eq!(
            one_text(&code, "SELECT pg_catalog.pg_typeof(lower('X'))::text").await,
            "text",
            "{version}"
        );
        assert_eq!(one_text(&code, "SELECT 'x' = 'X'").await, "f", "{version}");
        assert_eq!(
            one_text(
                &code,
                "SELECT pg_catalog.pg_typeof('a=>1' -> ARRAY['a'])::text"
            )
            .await,
            "text[]",
            "{version}: hstore's -> (hstore, text[])"
        );
        let n = probe().await;
        assert!(n.functions.is_empty(), "{version}: {n:?}");
        assert_eq!(
            n.operators.iter().map(String::as_str).collect::<Vec<_>>(),
            ["->"],
            "{version}: {n:?}"
        );
        // citext's SQL-language wrappers: reached by a typed parameter.
        assert!(n.param_functions.contains("regexp_replace"), "{version}");
        assert!(!n.param_functions.contains("lower"), "{version}");
        run(&f_admin, "DROP EXTENSION hstore; DROP EXTENSION citext").await;
    } else {
        eprintln!("skipped: citext or hstore is not available on the server");
    }
    // (7) A superuser's user-function cast `integer → text`: explicit,
    // `42::text` runs it; implicit, `pg_catalog.length(42)` does too (no
    // cast, no unqualified name). A `UNION` of `text` and `integer` is
    // still refused (different type categories).
    run(
        &f_admin,
        "CREATE FUNCTION public.f(integer) RETURNS text LANGUAGE sql AS $$SELECT 'user'$$; \
         CREATE CAST (integer AS text) WITH FUNCTION public.f(integer)",
    )
    .await;
    assert_eq!(
        one_text(&code, "SELECT 42::text").await,
        "user",
        "{version}"
    );
    assert_eq!(
        one_text(&code, "SELECT pg_catalog.length(42::text)").await,
        "4",
        "{version}"
    );
    let n = probe().await;
    assert!(n.explicit_cast_targets.contains("text"), "{version}: {n:?}");
    assert!(!n.implicit_cast, "{version}: {n:?}");
    run(
        &f_admin,
        "DROP CAST (integer AS text); \
         CREATE CAST (integer AS text) WITH FUNCTION public.f(integer) AS IMPLICIT",
    )
    .await;
    assert_eq!(
        one_text(&code, "SELECT pg_catalog.length(42)").await,
        "4",
        "{version}"
    );
    assert_eq!(
        sqlstate(&code, "SELECT 'a'::text UNION SELECT 1")
            .await
            .as_deref(),
        Some("42804"),
        "{version}"
    );
    assert!(probe().await.implicit_cast, "{version}");
    run(
        &f_admin,
        "DROP CAST (integer AS text); \
         CREATE CAST (integer AS text) WITH FUNCTION public.f(integer) AS ASSIGNMENT",
    )
    .await;
    assert!(probe().await.implicit_cast, "{version}: assignment");
    run(
        &f_admin,
        "DROP CAST (integer AS text); DROP FUNCTION public.f(integer)",
    )
    .await;
    // (8) User types named like built-ins: a domain `public.int4` is
    // reported; a table named `text` (a relation row type) is not.
    run(
        &code,
        "CREATE DOMAIN public.int4 AS pg_catalog.int4; CREATE TABLE public.text (a integer)",
    )
    .await;
    let n = probe().await;
    assert!(n.types.contains("int4"), "{version}: {n:?}");
    assert!(!n.types.contains("text"), "{version}: {n:?}");
    assert!(!n.types.contains("_text"), "{version}: {n:?}");
    drop(code);
    drop(f_admin);
    a.batch_execute(&format!("DROP DATABASE IF EXISTS {FACTS_DB} WITH (FORCE)"))
        .await
        .unwrap();
    drop_roles(&a).await;
}

/// ADR-0049 decision 8, drift: the built-in lists of the server's major
/// version equal its catalogs, both ways (functions, operators and types of
/// `pg_catalog` and `information_schema` that are not extension members,
/// initdb's `plpgsql` aside; keywords).
#[tokio::test]
async fn builtin_lists_match_the_server() {
    let Some(adm) = admin_url() else {
        return;
    };
    let _serial = SERIAL.lock().await;
    let a = admin(&adm, &adm.dbname).await;
    let version: String = a
        .query_one("SELECT pg_catalog.version()", &[])
        .await
        .unwrap()
        .get(0);
    let num: i32 = a
        .query_one("SELECT current_setting('server_version_num')::int", &[])
        .await
        .unwrap()
        .get(0);
    let major = u32::try_from(num).unwrap() / 10_000;
    assert!(
        (builtins::OLDEST_MAJOR..=builtins::NEWEST_MAJOR).contains(&major),
        "{version}: no built-in lists for this major version: generate them with \
         agent/crates/connector-postgres/builtins/generate.sh"
    );
    let not_member = |class: &str, oid: &str| {
        format!(
            "NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d \
               JOIN pg_catalog.pg_extension e ON e.oid = d.refobjid \
              WHERE d.classid = '{class}'::pg_catalog.regclass AND d.objid = {oid} \
                AND d.deptype = 'e' AND e.extname <> 'plpgsql')"
        )
    };
    let queries = [
        (
            "functions",
            format!(
                "SELECT DISTINCT CASE WHEN n.nspname = 'pg_catalog' THEN p.proname::text \
                   ELSE 'information_schema.' || p.proname END \
                 FROM pg_catalog.pg_proc p \
                 JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace \
                 WHERE n.nspname IN ('pg_catalog', 'information_schema') AND {}",
                not_member("pg_catalog.pg_proc", "p.oid")
            ),
        ),
        (
            "operators",
            format!(
                "SELECT DISTINCT o.oprname::text FROM pg_catalog.pg_operator o \
                 WHERE o.oprnamespace = 'pg_catalog'::pg_catalog.regnamespace AND {}",
                not_member("pg_catalog.pg_operator", "o.oid")
            ),
        ),
        (
            "types",
            format!(
                "SELECT DISTINCT CASE WHEN n.nspname = 'pg_catalog' THEN t.typname::text \
                   ELSE 'information_schema.' || t.typname END \
                 FROM pg_catalog.pg_type t \
                 JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace \
                 WHERE n.nspname IN ('pg_catalog', 'information_schema') AND {}",
                not_member("pg_catalog.pg_type", "t.oid")
            ),
        ),
        (
            "keywords",
            "SELECT word || ' ' || catcode::text FROM pg_catalog.pg_get_keywords()".to_owned(),
        ),
    ];
    for (kind, q) in queries {
        let server: BTreeSet<String> = a
            .query(&q, &[])
            .await
            .unwrap()
            .iter()
            .map(|r| r.get(0))
            .collect();
        let listed: BTreeSet<String> = builtins::raw_lines(major, kind)
            .into_iter()
            .map(str::to_owned)
            .collect();
        let missing: Vec<&String> = server.difference(&listed).collect();
        let extra: Vec<&String> = listed.difference(&server).collect();
        eprintln!(
            "{version}: {kind}: {} on the server, {} listed",
            server.len(),
            listed.len()
        );
        assert!(
            missing.is_empty() && extra.is_empty(),
            "{version}: {kind} drift (regenerate the lists with builtins/generate.sh): \
             not listed {missing:?}, listed but not on the server {extra:?}"
        );
    }
}
