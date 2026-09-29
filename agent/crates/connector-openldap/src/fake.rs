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
}
