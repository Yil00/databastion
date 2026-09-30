//! A scripted LDAP server over an in-memory stream, for the connector's
//! unit tests: every request is decoded ([`proto::parse_request`]) and
//! answered by a closure, which may return anything, malformed bytes
//! included.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use databastion_classifiers::masking::{HmacKey, MaskedFinding};
use databastion_core::config::{Limits, TargetConfig};
use databastion_core::{FailureCode, FindingSink, ScanJob, ScanParams};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use crate::ber;
use crate::conn::{self, Auth, Session, Timeouts};
use crate::error::Stage;
use crate::proto::{self, Entry, Filter, Request, Scope, Search, encode};
use crate::schema::tests::{ATTRIBUTE_TYPES, OBJECT_CLASSES};

type Handler = Box<dyn FnMut(i32, &Request) -> Vec<Vec<u8>> + Send>;

async fn read_frame(s: &mut DuplexStream) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 2];
    s.read_exact(&mut buf).await.ok()?;
    let total = loop {
        match ber::message_len(&buf).ok()? {
            Some(t) => break t,
            None => {
                let mut b = [0u8; 1];
                s.read_exact(&mut b).await.ok()?;
                buf.push(b[0]);
            }
        }
    };
    let have = buf.len();
    buf.resize(total, 0);
    s.read_exact(&mut buf[have..]).await.ok()?;
    Some(buf)
}

/// Starts a server answering with `handler`; returns the client end and
/// the requests seen.
pub(crate) fn serve(mut handler: Handler) -> (DuplexStream, Arc<Mutex<Vec<Request>>>) {
    let (client, mut server) = tokio::io::duplex(1 << 20);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Some(frame) = read_frame(&mut server).await {
            let Some((id, req)) = proto::parse_request(&frame) else {
                break;
            };
            log.lock().unwrap().push(req.clone());
            if req == Request::Unbind {
                break;
            }
            for out in handler(id, &req) {
                if server.write_all(&out).await.is_err() {
                    return;
                }
            }
        }
    });
    (client, seen)
}

/// Answers a simple or SASL bind with success and Who am I? with `dn:`
/// + `identity`; `rest` answers everything else.
pub(crate) fn directory(
    identity: &'static str,
    mut rest: impl FnMut(i32, &Request) -> Vec<Vec<u8>> + Send + 'static,
) -> Handler {
    Box::new(move |id, req| match req {
        Request::BindSimple { .. } | Request::BindSasl { .. } => {
            vec![encode::bind_response(id, 0)]
        }
        Request::Extended { oid } if oid == proto::OID_WHOAMI => {
            vec![encode::extended_response(
                id,
                0,
                Some(format!("dn:{identity}").as_bytes()),
            )]
        }
        other => rest(id, other),
    })
}

const AGENT: &str = "cn=databastion,ou=services,dc=example,dc=org";

fn timeouts() -> Timeouts {
    Timeouts::new(Duration::from_secs(1))
}

async fn session(
    h: Handler,
) -> (
    Result<Session<DuplexStream>, crate::error::LdError>,
    Arc<Mutex<Vec<Request>>>,
) {
    let (client, seen) = serve(h);
    let s = Session::establish(
        client,
        timeouts(),
        Auth::Simple {
            dn: AGENT,
            password: "pw",
        },
    )
    .await;
    (s, seen)
}

fn everything() -> Search<'static> {
    Search {
        base: "dc=example,dc=org",
        scope: Scope::Sub,
        size_limit: 10,
        time_limit: 0,
        types_only: false,
        filter: Filter::Present("objectClass"),
        attributes: &["1.1"],
    }
}

#[tokio::test]
async fn bind_and_identity() {
    let (s, seen) = session(directory(
        "CN=Databastion, ou=services,dc=example,dc=org",
        |_, _| Vec::new(),
    ))
    .await;
    let s = s.unwrap();
    assert_eq!(s.identity, AGENT);
    assert_eq!(
        seen.lock().unwrap()[0],
        Request::BindSimple {
            dn: AGENT.to_owned(),
            password: "pw".to_owned()
        }
    );
    // A refused bind.
    let (s, _) = session(Box::new(|id, _| vec![encode::bind_response(id, 49)])).await;
    let e = s.unwrap_err();
    assert_eq!(e.code, FailureCode::AuthenticationFailed);
    assert_eq!(e.result, Some(49));
    // Anonymous after the bind: refused.
    let (s, _) = session(Box::new(|id, req| match req {
        Request::BindSimple { .. } => vec![encode::bind_response(id, 0)],
        _ => vec![encode::extended_response(id, 0, Some(b""))],
    }))
    .await;
    assert_eq!(s.unwrap_err().code, FailureCode::AuthenticationFailed);
}

#[tokio::test]
async fn an_empty_password_is_never_sent() {
    let (client, seen) = serve(directory(AGENT, |_, _| Vec::new()));
    let e = Session::establish(
        client,
        timeouts(),
        Auth::Simple {
            dn: AGENT,
            password: "",
        },
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, FailureCode::AuthenticationFailed);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn sasl_external_must_give_the_configured_identity() {
    for (identity, ok) in [
        (
            "gidnumber=0+uidnumber=0,cn=peercred,cn=external,cn=auth",
            false,
        ),
        (AGENT, true),
    ] {
        let (client, seen) = serve(directory(identity, |_, _| Vec::new()));
        let r = Session::establish(client, timeouts(), Auth::External { expect: AGENT }).await;
        assert_eq!(r.is_ok(), ok, "{identity}");
        assert_eq!(
            seen.lock().unwrap()[0],
            Request::BindSasl {
                mechanism: "EXTERNAL".to_owned()
            }
        );
    }
}

#[tokio::test]
async fn start_tls_refuses_bytes_after_the_response() {
    // Success alone: the stream is handed back for the handshake.
    let (client, _) = serve(Box::new(|id, _| {
        vec![encode::extended_response(id, 0, None)]
    }));
    assert!(conn::start_tls(client, timeouts()).await.is_ok());
    // Success followed by injected bytes (a forged bind response).
    let (client, _) = serve(Box::new(|id, _| {
        let mut out = encode::extended_response(id, 0, None);
        out.extend_from_slice(&encode::bind_response(2, 0));
        vec![out]
    }));
    let e = conn::start_tls(client, timeouts()).await.unwrap_err();
    assert_eq!(e.stage, Stage::Tls);
    // Refused: no fallback.
    let (client, _) = serve(Box::new(|id, _| {
        vec![encode::extended_response(id, 52, None)]
    }));
    let e = conn::start_tls(client, timeouts()).await.unwrap_err();
    assert_eq!(e.stage, Stage::Tls);
    assert_eq!(e.result, Some(52));
}

#[tokio::test]
async fn searches_count_entries_and_references_and_fail_closed() {
    let (s, _) = session(directory(AGENT, |id, _| {
        vec![
            encode::entry(id, "ou=people,dc=example,dc=org", &[]),
            encode::reference(id),
            encode::entry(id, "ou=groups,dc=example,dc=org", &[]),
            encode::done(id, 4),
        ]
    }))
    .await;
    let mut s = s.unwrap();
    let mut n = 0;
    let o = s
        .search(Stage::Sample, &everything(), &mut |_: Entry| n += 1)
        .await
        .unwrap();
    assert_eq!((o.entries, o.references, n), (2, 1, 2));
    assert!(o.cut() && o.error(Stage::Sample).is_none());
    // Hostile or broken servers: another message id, a notice of
    // disconnection, an oversized message, garbage, silence.
    let cases: Vec<(Handler, FailureCode)> = vec![
        (
            directory(AGENT, |id, _| vec![encode::done(id + 1, 0)]),
            FailureCode::Internal,
        ),
        (
            directory(AGENT, |_, _| vec![encode::notice_of_disconnection()]),
            FailureCode::TargetUnreachable,
        ),
        (
            directory(AGENT, |_, _| vec![vec![0x30, 0x84, 0x7f, 0xff, 0xff, 0xff]]),
            FailureCode::Internal,
        ),
        (
            directory(AGENT, |_, _| vec![vec![0x04, 0x01, 0x00]]),
            FailureCode::Internal,
        ),
        (directory(AGENT, |_, _| Vec::new()), FailureCode::Timeout),
    ];
    // More entries than the size limit (10): the bound is enforced here.
    let flood: Handler = directory(AGENT, |id, _| {
        let mut out: Vec<Vec<u8>> = (0..11)
            .map(|i| encode::entry(id, &format!("cn={i},dc=example,dc=org"), &[]))
            .collect();
        out.push(encode::done(id, 0));
        out
    });
    let cases: Vec<(Handler, FailureCode)> = cases
        .into_iter()
        .chain(std::iter::once((flood, FailureCode::ResourceLimit)))
        .collect();
    for (h, code) in cases {
        let (s, _) = session(h).await;
        let mut s = s.unwrap();
        let e = s
            .search(Stage::Sample, &everything(), &mut |_: Entry| {})
            .await
            .unwrap_err();
        assert_eq!(e.code, code);
        assert!(s.is_broken());
    }
}

/// The dev tree, served by the scripted directory.
fn tree(id: i32, req: &Request) -> Vec<Vec<u8>> {
    let Request::Search {
        base,
        scope,
        filter,
        attributes,
        ..
    } = req
    else {
        return vec![encode::done(id, 53)];
    };
    let mut out = Vec::new();
    match (base.as_str(), scope) {
        ("", 0) => out.push(encode::entry(
            id,
            "",
            &[
                ("namingContexts", &[b"dc=example,dc=org", b"cn=accesslog"]),
                ("subschemaSubentry", &[b"cn=Subschema"]),
            ],
        )),
        ("cn=Subschema", 0) => {
            let at: Vec<&[u8]> = ATTRIBUTE_TYPES.iter().map(|s| s.as_bytes()).collect();
            let oc: Vec<&[u8]> = OBJECT_CLASSES.iter().map(|s| s.as_bytes()).collect();
            out.push(encode::entry(
                id,
                "cn=Subschema",
                &[("attributeTypes", &at), ("objectClasses", &oc)],
            ));
        }
        ("dc=example,dc=org", 2) if filter.starts_with("(|(objectClass=organizationalUnit)") => {
            for dn in [
                "dc=example,dc=org",
                "ou=people,dc=example,dc=org",
                "ou=Jane Doe,ou=teams,dc=example,dc=org",
                "ou=John Smith,ou=teams,dc=example,dc=org",
            ] {
                out.push(encode::entry(id, dn, &[]));
            }
            out.push(encode::reference(id));
        }
        ("ou=people,dc=example,dc=org", 1) => {
            assert!(
                !attributes
                    .iter()
                    .any(|a| a.eq_ignore_ascii_case("userPassword") || a == "*"),
                "credential or wildcard requested: {attributes:?}"
            );
            for i in 0..30 {
                let mail = format!("person{i}@example.org");
                out.push(encode::entry(
                    id,
                    &format!("uid=p{i},ou=people,dc=example,dc=org"),
                    &[
                        ("objectClass", &[b"top", b"person", b"inetOrgPerson"]),
                        ("mail", &[mail.as_bytes()]),
                        // A hostile server sends what was not asked for.
                        ("userPassword", &[b"{SSHA}c2VjcmV0c2VjcmV0c2VjcmV0"]),
                    ],
                ));
            }
        }
        (b, 1) if b.contains("ou=teams") => {
            for i in 0..10 {
                let mail = format!("team{i}@example.com");
                out.push(encode::entry(
                    id,
                    &format!("uid=t{i},{b}"),
                    &[
                        ("structuralObjectClass", &[b"inetOrgPerson"]),
                        ("mail", &[mail.as_bytes()]),
                    ],
                ));
            }
        }
        ("cn=accesslog", _) => panic!("the log database was scanned"),
        _ => {}
    }
    out.push(encode::done(id, 0));
    out
}

fn target() -> TargetConfig {
    databastion_core::AgentConfig::parse(
        "{console: {url: \"https://c.example\"}, state_dir: /s, targets: [{id: t, engine: \
         openldap, host: 127.0.0.1, account: a, secret: {env: PW}, openldap: {tls: disable}}]}",
    )
    .unwrap()
    .targets[0]
        .clone()
}

#[tokio::test]
async fn discovery_over_the_scripted_directory() {
    let t = target();
    let job = ScanJob::new(
        ScanParams::contract_defaults(),
        &t,
        &Limits::default(),
        Arc::new(HmacKey::new(&[7u8; 32]).unwrap()),
    );
    let (sink, mut rx) = FindingSink::channel(1024);
    let logs = crate::i2::Logs::default();
    let _guard = logs.capture();
    let r = crate::discover::scan(&job, &sink, &t, || async {
        let (client, _) = serve(directory(AGENT, tree));
        Session::establish(
            client,
            timeouts(),
            Auth::Simple {
                dn: AGENT,
                password: "pw",
            },
        )
        .await
    })
    .await;
    r.unwrap();
    drop(sink);
    let mut findings: Vec<MaskedFinding> = Vec::new();
    while let Some(f) = rx.recv().await {
        findings.push(f);
    }
    let locations: Vec<(String, String, String, String)> = findings
        .iter()
        .map(|f| {
            let l = f.location().unwrap();
            (
                l.database.as_str().to_owned(),
                l.schema.as_ref().unwrap().as_str().to_owned(),
                l.object.as_str().to_owned(),
                l.field.as_str().to_owned(),
            )
        })
        .collect();
    // Both person-named team containers are pooled into one location.
    assert_eq!(
        locations,
        vec![
            (
                "dc=example,dc=org".to_owned(),
                "ou=*,ou=teams,dc=example,dc=org".to_owned(),
                "inetOrgPerson".to_owned(),
                "mail".to_owned()
            ),
            (
                "dc=example,dc=org".to_owned(),
                "ou=people,dc=example,dc=org".to_owned(),
                "inetOrgPerson".to_owned(),
                "mail".to_owned()
            ),
        ]
    );
    assert_eq!(findings[0].sampled(), 20);
    // No finding on the password the server sent unasked.
    assert!(
        findings
            .iter()
            .all(|f| f.classifier().as_str() == "pii.email")
    );
    // Interim I2 check (end-of-phase-6 review L2): none of the served
    // values (nor of the dev ground truth) and no entry DN in the
    // serialized findings nor in the logs.
    let mut values = crate::i2::ground_truth_values(&crate::i2::ground_truth());
    values.extend((0..30).map(|i| format!("person{i}@example.org")));
    values.extend((0..10).map(|i| format!("team{i}@example.com")));
    values.push("c2VjcmV0c2VjcmV0c2VjcmV0".to_owned());
    crate::i2::assert_clean(
        "serialized findings",
        &crate::i2::findings_text(&findings),
        &values,
        &[],
    );
    crate::i2::assert_clean("scan logs", &logs.text(), &values, &[AGENT]);
}

/// `check()`'s audit proofs against a scripted `cn=accesslog`.
mod proofs {
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;
    use crate::check::{CheckState, prove};

    const OUTER: &str = "dc=example,dc=org";
    const NESTED: &str = "ou=nested,dc=example,dc=org";

    fn contexts() -> Vec<(String, String)> {
        [OUTER, NESTED]
            .iter()
            .map(|c| ((*c).to_owned(), (*c).to_owned()))
            .collect()
    }

    /// A directory whose log holds successful searches below the nested
    /// context only, and records the absent-entry probes while `failures`
    /// is on.
    fn log_server(failures: Arc<AtomicBool>, probes: Arc<Mutex<Vec<String>>>) -> Handler {
        let logged: Arc<Mutex<HashSet<String>>> = Arc::default();
        directory(AGENT, move |id, req| {
            let Request::Search { base, filter, .. } = req else {
                return vec![encode::done(id, 53)];
            };
            if base == "cn=accesslog" {
                // The proof of a probe: its exact DN.
                if let Some(rest) = filter.split("(reqDN=").nth(1) {
                    let dn = rest.split(')').next().unwrap_or_default();
                    if logged.lock().unwrap().contains(dn) {
                        return vec![
                            encode::entry(id, "reqStart=1,cn=accesslog", &[]),
                            encode::done(id, 0),
                        ];
                    }
                    return vec![encode::done(id, 0)];
                }
                // A proof of logged reads: the only records are below the
                // nested context, so a search that leaves it out finds
                // nothing.
                let excludes_nested =
                    filter.contains(&format!("(!(reqDN:dnSubtreeMatch:={NESTED}))"));
                if filter.contains("(reqResult=0)") && !excludes_nested {
                    return vec![
                        encode::entry(id, "reqStart=2,cn=accesslog", &[]),
                        encode::done(id, 0),
                    ];
                }
                return vec![encode::done(id, 0)];
            }
            if base.starts_with(crate::check::ABSENT_RDN) {
                probes.lock().unwrap().push(base.clone());
                if failures.load(Ordering::SeqCst) {
                    logged.lock().unwrap().insert(base.clone());
                }
                return vec![encode::done(id, 32)];
            }
            vec![encode::entry(id, base, &[]), encode::done(id, 0)]
        })
    }

    /// #79 round-3 review L2: a context does not borrow the read proof of
    /// a naming context nested in it.
    #[tokio::test]
    async fn a_context_never_borrows_a_nested_contexts_proof() {
        let (s, seen) = session(log_server(Arc::default(), Arc::default())).await;
        let mut s = s.unwrap();
        let state = CheckState::default();
        let t = target();
        prove(&state, &t, &mut s, &contexts(), "cn=accesslog")
            .await
            .unwrap();
        assert!(state.proven(&t.id, NESTED));
        assert!(!state.proven(&t.id, OUTER));
        // The outer context's proof searches leave the nested one out; the
        // nested one's leave nothing out.
        let filters: Vec<String> = seen
            .lock()
            .unwrap()
            .iter()
            .filter_map(|r| match r {
                Request::Search { base, filter, .. } if base == "cn=accesslog" => {
                    Some(filter.clone())
                }
                _ => None,
            })
            .filter(|f| f.contains("(reqResult=0)"))
            .collect();
        assert!(
            filters
                .iter()
                .any(|f| f.contains(&format!("(reqDN:dnSubtreeMatch:={OUTER})"))
                    && f.contains(&format!("(!(reqDN:dnSubtreeMatch:={NESTED}))")))
        );
        assert!(
            filters
                .iter()
                .filter(|f| f.contains(&format!("(reqDN:dnSubtreeMatch:={NESTED})"))
                    && !f.contains("(!("))
                .count()
                >= 1
        );
    }

    /// #79 round-3 review L1: the absent-entry probe runs at every report,
    /// with a DN of its own, and only its latest answer counts.
    #[tokio::test]
    async fn the_failed_operation_probe_keeps_only_the_latest_answer() {
        let failures = Arc::new(AtomicBool::new(true));
        let probes: Arc<Mutex<Vec<String>>> = Arc::default();
        let (s, _) = session(log_server(Arc::clone(&failures), Arc::clone(&probes))).await;
        let mut s = s.unwrap();
        let state = CheckState::default();
        let t = target();
        prove(&state, &t, &mut s, &contexts(), "cn=accesslog")
            .await
            .unwrap();
        assert_eq!(state.failures_logged(&t.id, OUTER), Some(true));
        assert_eq!(state.failures_logged(&t.id, NESTED), Some(true));
        // `olcAccessLogSuccess: TRUE` from now on: the next report sees it,
        // although the earlier probes' records are still in the log.
        failures.store(false, Ordering::SeqCst);
        prove(&state, &t, &mut s, &contexts(), "cn=accesslog")
            .await
            .unwrap();
        assert_eq!(state.failures_logged(&t.id, OUTER), Some(false));
        assert_eq!(state.failures_logged(&t.id, NESTED), Some(false));
        // Every probe has its own DN, below its context.
        let probes = probes.lock().unwrap();
        assert_eq!(probes.len(), 4);
        assert_eq!(probes.iter().collect::<HashSet<_>>().len(), 4);
        assert!(probes.iter().all(|p| p.ends_with(OUTER)));
    }
}

/// A scripted `cn=accesslog` serving searches of the tree: entry `n` has
/// CSN `csn(n)` and `reqDN` `dns[n - 1]`.
fn accesslog(dns: Vec<&'static str>) -> Handler {
    directory(AGENT, move |id, req| {
        let Request::Search { base, .. } = req else {
            return vec![encode::done(id, 53)];
        };
        assert_eq!(base, "cn=accesslog");
        let mut out: Vec<Vec<u8>> = dns
            .iter()
            .enumerate()
            .map(|(i, dn)| {
                let c = log_csn(u32::try_from(i + 1).unwrap());
                encode::entry(
                    id,
                    &format!("reqStart={c},cn=accesslog"),
                    &[
                        ("reqStart", &[b"20260929202642.000001Z"]),
                        ("reqType", &[b"search"]),
                        ("reqAuthzID", &[b"cn=admin,dc=example,dc=org"]),
                        ("reqDN", &[dn.as_bytes()]),
                        ("reqResult", &[b"0"]),
                        ("reqScope", &[b"sub"]),
                        ("reqFilter", &[b"(objectClass=*)"]),
                        ("reqAttr", &[b"mail"]),
                        ("reqEntries", &[b"3"]),
                        ("entryCSN", &[c.as_bytes()]),
                    ],
                )
            })
            .collect();
        out.push(encode::done(id, 0));
        out
    })
}

fn log_csn(n: u32) -> String {
    format!("20260929202642.{n:06}Z#000000#000#000000")
}

/// One accesslog poll from the saved position of `store`, with the core's
/// request applied to it (`isolate`, `skip`): the events, or `None` when
/// the poll panicked.
async fn poll_log(
    dns: Vec<&'static str>,
    store: &databastion_core::audit::CursorStore,
    isolate: bool,
    skip: u32,
    state: &crate::check::CheckState,
) -> Option<Vec<databastion_classifiers::masking::MaskedEvent>> {
    use databastion_core::EventSink;
    use databastion_core::audit::own::{OwnAccount, SharedOwnUsage};

    use crate::audit::events::EventBuilder;
    use crate::audit::{Position, poll};

    let (s, _) = session(accesslog(dns)).await;
    let mut s = s.unwrap();
    let mut request = store.clone().with_skip(skip);
    if isolate {
        request = request.with_isolation();
    }
    let mut position = Position::load(Some(&request));
    let t = target();
    let (sink, mut rx) = EventSink::channel(64);
    let mut builder = EventBuilder::new(
        OwnAccount::new(AGENT, None, None, 1000, SharedOwnUsage::default()),
        AGENT.to_owned(),
        1000,
        Vec::new(),
    );
    let store = store.clone();
    let polled = {
        use futures_util::FutureExt as _;
        std::panic::AssertUnwindSafe(poll(
            &t,
            &sink,
            state,
            &mut s,
            &mut builder,
            &mut position,
            Some(&store),
            "cn=accesslog",
        ))
        .catch_unwind()
        .await
    };
    drop(sink);
    let mut events = Vec::new();
    while let Some(e) = rx.recv().await {
        events.push(e);
    }
    match polled {
        Ok(r) => {
            r.unwrap();
            Some(events)
        }
        Err(_) => None,
    }
}

fn skip_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "databastion-ldap-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Phase-7 review H1: an entry that makes the parser panic is dropped
/// alone and counted; the entries around it give events.
#[tokio::test]
async fn an_entry_that_crashes_the_parser_is_dropped_alone() {
    use databastion_core::audit::CursorStore;

    use crate::audit::{CURSOR, TEST_PARSE_POISON};
    let dir = skip_dir("parse");
    let store = CursorStore::new(&dir, "t", CURSOR).unwrap();
    store
        .save(format!("v2\ncursor {}\n", log_csn(0)).as_bytes())
        .unwrap();
    let poison: &'static str =
        Box::leak(format!("{TEST_PARSE_POISON},dc=example,dc=org").into_boxed_str());
    let state = crate::check::CheckState::default();
    let events = poll_log(
        vec!["dc=example,dc=org", poison, "dc=example,dc=org"],
        &store,
        false,
        0,
        &state,
    )
    .await
    .expect("a parser panic does not fail the poll");
    assert_eq!(events.len(), 2);
    assert_eq!(state.dropped(&target().id), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Poison records (phase-7 security review M1): a panic outside the
/// parser (here in the event conversion) reaches the core, which restarts
/// the stream in isolation mode (entries handed over and saved one by
/// one), then asks it to skip one entry at the exact position: only the
/// entry at fault is lost, never the entries before it in its page.
#[tokio::test]
async fn isolation_mode_then_a_skip_drop_the_entry_at_fault_only() {
    use databastion_core::audit::CursorStore;

    use crate::audit::{CURSOR, TEST_CONVERT_POISON};
    let dir = skip_dir("isolate");
    let store = CursorStore::new(&dir, "t", CURSOR).unwrap();
    store
        .save(format!("v2\ncursor {}\n", log_csn(0)).as_bytes())
        .unwrap();
    let poison: &'static str =
        Box::leak(format!("{TEST_CONVERT_POISON},dc=example,dc=org").into_boxed_str());
    let dns = || {
        vec![
            "dc=example,dc=org",
            "dc=example,dc=org",
            poison,
            "dc=example,dc=org",
            "dc=example,dc=org",
        ]
    };
    let state = crate::check::CheckState::default();
    // A normal poll panics before saving anything.
    assert!(poll_log(dns(), &store, false, 0, &state).await.is_none());
    let saved = || String::from_utf8(store.load().unwrap().unwrap()).unwrap();
    assert!(saved().contains(&format!("cursor {}", log_csn(0))));
    // Isolation mode: the two entries before it are handed over and saved.
    assert!(poll_log(dns(), &store, true, 0, &state).await.is_none());
    assert!(
        saved().contains(&format!("cursor {}", log_csn(2))),
        "{}",
        saved()
    );
    // One skip at that exact position: the entry at fault only.
    let events = poll_log(dns(), &store, true, 1, &state)
        .await
        .expect("the entry at fault is skipped");
    assert_eq!(events.len(), 2);
    assert_eq!(state.dropped(&target().id), 1);
    assert!(
        saved().contains(&format!("cursor {}", log_csn(5))),
        "{}",
        saved()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// PR #83 round-3 review L-1: a `handing` entry left in the saved position
/// (a failed hand-over) is read like any other by a session without
/// isolation nor skip: reported once, then marked read, and the `handing`
/// line is gone.
#[tokio::test]
async fn a_stale_handing_entry_is_read_once_and_cleared() {
    use databastion_core::audit::CursorStore;

    use crate::audit::CURSOR;
    let dir = skip_dir("handing");
    let store = CursorStore::new(&dir, "t", CURSOR).unwrap();
    store
        .save(
            format!(
                "v2\ncursor {}\nhanding {}\nseen {}\n",
                log_csn(1),
                log_csn(2),
                log_csn(1)
            )
            .as_bytes(),
        )
        .unwrap();
    let dns = || vec!["dc=example,dc=org", "dc=example,dc=org"];
    let state = crate::check::CheckState::default();
    let events = poll_log(dns(), &store, false, 0, &state).await.unwrap();
    assert_eq!(events.len(), 1, "entry 2 reported once");
    let saved = String::from_utf8(store.load().unwrap().unwrap()).unwrap();
    assert!(!saved.contains("handing"), "{saved}");
    assert!(saved.contains(&format!("seen {}", log_csn(2))), "{saved}");
    // Not reported again.
    let events = poll_log(dns(), &store, false, 0, &state).await.unwrap();
    assert!(events.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}
