//! Discovery of a `cas` target (ADR-0041 decision 4).
//!
//! - **Service registry**: each listed `.json` (or, for `yaml_dir`, `.yml` /
//!   `.yaml`) file is one unit of work
//!   (paced, ADR-0035), read through [`crate::fsread`] and parsed by
//!   [`crate::parse::definition`] under panic isolation. String values are
//!   pooled per (service type, field path) across services and classified
//!   through `ScanJob::classify`, so only masked samples and fingerprints
//!   leave (I2). Locations: `database` = `service_registry`, `schema` = the
//!   service type, `object` = the service's normalized name when every
//!   value of the pool comes from services of that one name, else `*`,
//!   `field` = the normalized path. `sampled` counts values,
//!   `estimated_rows` the services. At most [`MAX_POOLED_BYTES`] of values
//!   and the compiled-pattern budget of [`crate::registry`] per scan.
//!   Credential fields are never sampled;
//!   `clientSecret` only gives the count of services holding one in clear
//!   ([`RegistryFacts::clear_secrets`]).
//! - **Audit log**: the `who` of `AUTHENTICATION_SUCCESS` records in the
//!   last [`AUDIT_TAIL_BYTES`] of the log (at most `sample_rows`), as
//!   `audit_trail` / `audit_log` / `who`. `what`, headers, user agents and
//!   addresses are never sampled; failed authentications' names never are
//!   (a typed name can be a password).
//! - Coverage: a file sampled counts in `sampled`; unreadable or refused in
//!   `skipped_not_readable`; not a definition or unparsable in
//!   `skipped_unsupported`; too large, beyond the file cap or beyond a
//!   parser bound in `skipped_limit`; a parser panic in `skipped_error`.
//!   A refused source counts as one object not readable.
//!
//! Called from `Connector::discover` ([`crate::connector`]), where
//! [`CasError`] maps to `ConnectorError`. [`index_registry`] builds the
//! service index alone (no classification) for an audit stream that starts
//! before any scan.

use std::collections::HashMap;
use std::sync::Arc;

use databastion_classifiers::masking::{FindingLocation, MaskedFinding, RawSample};
use databastion_classifiers::names::{NormalizedName, normalize_path};
use databastion_core::sink::SinkClosed;
use databastion_core::{FindingSink, Paced, ScanCoverage, ScanJob};
use zeroize::Zeroizing;

use crate::audit::events::is_unidentified;
use crate::config::CasSettings;
use crate::fsread::{self, FileSkip, Policy, Refusal};
use crate::parse::definition::{DefinitionError, SecretForm, ServiceType, parse_registry_file};
use crate::parse::record::Action;
use crate::registry::{ServiceIndex, field_name, object_name};
use crate::state::{CasState, RegistryFacts};

/// Bytes of the audit log's end read for the `who` location.
pub const AUDIT_TAIL_BYTES: u64 = 1024 * 1024;
/// Most (service type, field) pools kept per scan.
pub const MAX_POOLS: usize = 4096;
/// Most bytes of values pooled per scan (review of #138 L6): values beyond
/// it are not kept, and their file counts as skipped for a limit.
pub const MAX_POOLED_BYTES: usize = 32 * 1024 * 1024;

/// Why a scan stopped (never a value, a path or a file name).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CasError {
    /// The scan was cancelled during a Discovery pause.
    #[error("scan cancelled")]
    Cancelled,
    /// The core stopped consuming findings.
    #[error(transparent)]
    SinkClosed(#[from] SinkClosed),
    /// A blocking task failed (not a panic: those are resumed).
    #[error("internal error")]
    Internal,
}

impl From<databastion_core::pacing::Cancelled> for CasError {
    fn from(_: databastion_core::pacing::Cancelled) -> Self {
        Self::Cancelled
    }
}

fn joined<T>(r: Result<T, tokio::task::JoinError>) -> Result<T, CasError> {
    r.map_err(|e| {
        let _ = databastion_core::resume_panic(e);
        CasError::Internal
    })
}

/// Values of one (service type, field) pool.
struct Pool {
    field: NormalizedName,
    values: Vec<Zeroizing<String>>,
    services: u64,
    last_service: Option<usize>,
    /// The services' common name (`None` once they differ).
    object: Option<NormalizedName>,
}

/// One registry file's outcome.
enum FileOutcome {
    Skipped(FileSkip),
    Panicked,
    Refused(DefinitionError),
    Parsed(crate::parse::definition::Definition),
}

/// Runs a Discovery scan of a `cas` target.
///
/// # Errors
/// [`CasError`] when the scan is cancelled or the sink is closed.
pub async fn discover(
    settings: &CasSettings,
    job: &ScanJob,
    sink: &FindingSink,
    state: &Arc<CasState>,
) -> Result<(), CasError> {
    discover_with(settings, job, sink, state, Policy::agent()).await
}

pub(crate) async fn discover_with(
    settings: &CasSettings,
    job: &ScanJob,
    sink: &FindingSink,
    state: &Arc<CasState>,
    policy: Policy,
) -> Result<(), CasError> {
    if settings.registry_dir.is_some() {
        scan_registry(settings, job, sink, state, policy).await?;
    }
    if settings.audit_log.is_some() {
        scan_audit_log(settings, job, sink, state, policy).await?;
    }
    Ok(())
}

fn cover(sink: &FindingSink, f: impl FnOnce(&mut ScanCoverage)) {
    let mut c = ScanCoverage::default();
    f(&mut c);
    sink.add_coverage(c);
}

async fn scan_registry(
    settings: &CasSettings,
    job: &ScanJob,
    sink: &FindingSink,
    state: &Arc<CasState>,
    policy: Policy,
) -> Result<(), CasError> {
    let Some(dir) = settings.registry_dir.clone() else {
        return Ok(());
    };
    let format = settings.registry_format;
    let listed = job
        .paced(tokio::task::spawn_blocking(move || {
            if dir.still_resolves() {
                fsread::list_registry(dir.path(), format, policy)
            } else {
                Err(Refusal::ResolvedChanged)
            }
        }))
        .await?;
    let listing = match listed {
        Paced::OutOfTime => {
            job.skip_out_of_time(sink, 1);
            return Ok(());
        }
        Paced::Done(r) => match joined(r)? {
            Ok(l) => Arc::new(l),
            Err(refusal) => {
                tracing::warn!(
                    reason = ?refusal,
                    "CAS service registry refused or not readable; nothing of it is read"
                );
                cover(sink, |c| c.not_readable = 1);
                state.note_registry(RegistryFacts::default(), None);
                return Ok(());
            }
        },
    };
    let mut facts = RegistryFacts {
        skipped: listing.over_cap,
        ..RegistryFacts::default()
    };
    cover(sink, |c| c.limit = listing.over_cap);
    let mut names = listing.files.clone();
    job.rotate(&mut names);
    let mut index = ServiceIndex::default();
    let mut pools: HashMap<(ServiceType, String), Pool> = HashMap::new();
    let max_values = usize::try_from(job.sample_rows()).unwrap_or(usize::MAX);
    let mut pooled_bytes = 0usize;
    for (i, name) in names.iter().enumerate() {
        let l = Arc::clone(&listing);
        let name = name.clone();
        let paced = job
            .paced(tokio::task::spawn_blocking(move || {
                // Reading and parsing one file are isolated together: a
                // panic costs that file only (review of #138 I6).
                databastion_core::isolate(|| match l.read(&name, policy) {
                    Err(skip) => FileOutcome::Skipped(skip),
                    Ok(bytes) => match parse_registry_file(format, &bytes) {
                        Err(e) => FileOutcome::Refused(e),
                        Ok(d) => FileOutcome::Parsed(d),
                    },
                })
                .unwrap_or(FileOutcome::Panicked)
            }))
            .await?;
        let outcome = match paced {
            Paced::OutOfTime => {
                let left = names.len().saturating_sub(i);
                job.skip_out_of_time(sink, left);
                facts.skipped = facts
                    .skipped
                    .saturating_add(u64::try_from(left).unwrap_or(u64::MAX));
                break;
            }
            Paced::Done(r) => joined(r)?,
        };
        let def = match outcome {
            FileOutcome::Parsed(d) => d,
            other => {
                facts.skipped = facts.skipped.saturating_add(1);
                if matches!(other, FileOutcome::Skipped(FileSkip::Writable)) {
                    facts.writable = facts.writable.saturating_add(1);
                }
                cover(sink, |c| match other {
                    FileOutcome::Skipped(FileSkip::TooLarge)
                    | FileOutcome::Refused(DefinitionError::Bounds) => c.limit = 1,
                    FileOutcome::Skipped(_) => c.not_readable = 1,
                    FileOutcome::Refused(_) => c.unsupported = 1,
                    FileOutcome::Panicked | FileOutcome::Parsed(_) => c.error = 1,
                });
                continue;
            }
        };
        if def.client_secret == SecretForm::Clear {
            facts.clear_secrets = facts.clear_secrets.saturating_add(1);
        }
        // A service beyond the compiled-pattern budget is indexed without
        // its pattern (it never matches) and counted as a limit.
        let mut limited = !index.add(&def);
        let object = object_name(&def);
        let service_type = def.service_type;
        for s in def.values {
            let field = field_name(&s.path);
            let key = (service_type, field.as_str().to_owned());
            if !pools.contains_key(&key) && pools.len() >= MAX_POOLS {
                continue;
            }
            let pool = pools.entry(key).or_insert_with(|| Pool {
                field,
                values: Vec::new(),
                services: 0,
                last_service: None,
                object: Some(object.clone()),
            });
            if pool.last_service != Some(i) {
                pool.last_service = Some(i);
                pool.services = pool.services.saturating_add(1);
                if pool.object.as_ref() != Some(&object) {
                    pool.object = None;
                }
            }
            if pool.values.len() < max_values {
                let len = s.value.len();
                if pooled_bytes.saturating_add(len) > MAX_POOLED_BYTES {
                    limited = true;
                } else {
                    pooled_bytes += len;
                    pool.values.push(s.value);
                }
            }
        }
        // A file whose values did not all fit the scan's budgets counts as
        // skipped for a limit, otherwise as sampled.
        cover(sink, |c| {
            if limited {
                c.limit = 1;
            } else {
                c.sampled = 1;
            }
        });
    }
    // A skipped file may hold a duplicate of a client id (ADR-0044,
    // review of #182 L1): no client is then named.
    if facts.skipped > 0 {
        index.disable_clients();
    }
    index.finish();
    state.note_registry(facts, Some(Arc::new(index)));
    if facts.clear_secrets > 0 {
        tracing::warn!(
            services = facts.clear_secrets,
            "CAS services hold their client secret in clear (encrypt them; the values are never read further)"
        );
    }
    // Classification: agent CPU only, off the async threads.
    let job2 = job.clone();
    let database = normalize_path("service_registry");
    let findings = joined(
        tokio::task::spawn_blocking(move || {
            let mut keys: Vec<(ServiceType, String)> = pools.keys().cloned().collect();
            keys.sort();
            let mut out: Vec<MaskedFinding> = Vec::new();
            for k in keys {
                let Some(pool) = pools.remove(&k) else {
                    continue;
                };
                let samples: Vec<RawSample<'_>> =
                    pool.values.iter().map(|v| RawSample::new(v)).collect();
                let location = FindingLocation {
                    database: database.clone(),
                    schema: Some(normalize_path(k.0.as_str())),
                    object: pool.object.clone().unwrap_or_else(NormalizedName::wildcard),
                    field: pool.field.clone(),
                };
                for f in job2.classify(pool.field.as_str(), &samples) {
                    out.push(
                        f.into_finding(location.clone())
                            .with_estimated_rows(pool.services),
                    );
                }
            }
            out
        })
        .await,
    )?;
    for f in findings {
        sink.submit(f).await?;
    }
    Ok(())
}

/// Reads and parses the registry for the service index only (no value is
/// classified nor kept): the audit stream's service match when no
/// Discovery scan ran since the agent started. `None` when the target
/// declares no registry or it is refused. Blocking I/O: call from a
/// blocking thread.
pub(crate) fn index_registry(
    settings: &CasSettings,
    policy: Policy,
) -> Option<(ServiceIndex, RegistryFacts)> {
    let dir = settings.registry_dir.as_ref()?;
    if !dir.still_resolves() {
        return None;
    }
    let format = settings.registry_format;
    let listing = fsread::list_registry(dir.path(), format, policy).ok()?;
    let mut facts = RegistryFacts {
        skipped: listing.over_cap,
        ..RegistryFacts::default()
    };
    let mut index = ServiceIndex::default();
    for name in &listing.files {
        // Err(true): refused because the agent could write it.
        let parsed = databastion_core::isolate(|| match listing.read(name, policy) {
            Err(skip) => Err(skip == FileSkip::Writable),
            Ok(bytes) => parse_registry_file(format, &bytes).map_err(|_| false),
        })
        .unwrap_or(Err(false));
        match parsed {
            Ok(def) => {
                if def.client_secret == SecretForm::Clear {
                    facts.clear_secrets = facts.clear_secrets.saturating_add(1);
                }
                let _ = index.add(&def);
            }
            Err(writable) => {
                facts.skipped = facts.skipped.saturating_add(1);
                if writable {
                    facts.writable = facts.writable.saturating_add(1);
                }
            }
        }
    }
    if facts.skipped > 0 {
        index.disable_clients();
    }
    index.finish();
    Some((index, facts))
}

async fn scan_audit_log(
    settings: &CasSettings,
    job: &ScanJob,
    sink: &FindingSink,
    state: &Arc<CasState>,
    policy: Policy,
) -> Result<(), CasError> {
    let Some(log) = settings.audit_log.clone() else {
        return Ok(());
    };
    let job2 = job.clone();
    let state2 = Arc::clone(state);
    let paced = job
        .paced(tokio::task::spawn_blocking(move || {
            if !log.path.still_resolves() {
                return Err(Refusal::ResolvedChanged);
            }
            let tail = fsread::read_log_tail(log.path.path(), AUDIT_TAIL_BYTES, policy)?;
            let now = std::time::SystemTime::now();
            let batch = crate::audit::stream::parse_lines(
                tail.bytes.split(|b| *b == b'\n'),
                log.offset,
                now,
            );
            drop(tail);
            state2.note_evidence(&batch.evidence);
            let max = usize::try_from(job2.sample_rows()).unwrap_or(usize::MAX);
            let whos: Vec<Zeroizing<String>> = batch
                .records
                .into_iter()
                .filter(|r| r.action == Action::AuthSuccess)
                .filter_map(|r| r.who)
                .filter(|w| !is_unidentified(w))
                .take(max)
                .collect();
            let samples: Vec<RawSample<'_>> = whos.iter().map(|w| RawSample::new(w)).collect();
            Ok(job2.classify("who", &samples))
        }))
        .await?;
    let found = match paced {
        Paced::OutOfTime => {
            job.skip_out_of_time(sink, 1);
            return Ok(());
        }
        Paced::Done(r) => joined(r)?,
    };
    let findings = match found {
        Ok(f) => f,
        Err(refusal) => {
            tracing::warn!(reason = ?refusal, "CAS audit log refused or not readable");
            cover(sink, |c| c.not_readable = 1);
            return Ok(());
        }
    };
    cover(sink, |c| c.sampled = 1);
    let location = FindingLocation {
        database: normalize_path("audit_trail"),
        schema: None,
        object: normalize_path("audit_log"),
        field: normalize_path("who"),
    };
    for f in findings {
        sink.submit(f.into_finding(location.clone())).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsread::tests::TempDir;
    use databastion_classifiers::masking::ClassifierId;

    const FAKE_SERVICE: &str = r#"{
      "@class": "org.apereo.cas.services.OidcRegisteredService",
      "name": "HR-Portal", "id": 3, "serviceId": "^https://hr\\.example\\.org/.*",
      "clientId": "hr-portal", "clientSecret": "fake-clear-secret-0000",
      "contacts": ["java.util.ArrayList", [
        {"name": "Jane Doe", "email": "jane.doe@example.org"},
        {"name": "John Roe", "email": "john.roe@example.org"}]]
    }"#;

    const OTHER_SERVICE: &str = r#"{
      "@class": "org.apereo.cas.services.OidcRegisteredService",
      "name": "Wiki", "id": 4, "serviceId": "^https://wiki\\.example\\.org/.*",
      "clientSecret": "${WIKI_SECRET}",
      "contacts": [{"name": "Max Moe", "email": "max.moe@example.org"}]
    }"#;

    fn settings(dir: &TempDir, audit: bool) -> CasSettings {
        let reg = dir.path().join("services");
        let log = if audit {
            format!(
                ", audit_log: {{path: {}/cas_audit.log}}",
                dir.path().display()
            )
        } else {
            String::new()
        };
        CasSettings::from_yaml(
            &format!("{{service_registry: {{json_dir: {}}}{log}}}", reg.display()),
            &[],
        )
        .unwrap()
    }

    /// Findings of a scan (the coverage counters are read by the core
    /// only).
    async fn scan(s: &CasSettings) -> (Vec<MaskedFinding>, Arc<CasState>) {
        let (sink, mut rx) = FindingSink::channel(1024);
        let state = Arc::new(CasState::default());
        let job = ScanJob::default();
        discover_with(s, &job, &sink, &state, Policy::TESTS)
            .await
            .unwrap();
        drop(sink);
        let mut out = Vec::new();
        while let Some(f) = rx.recv().await {
            out.push(f);
        }
        (out, state)
    }

    #[tokio::test]
    async fn the_registry_yields_masked_findings_only() {
        let dir = TempDir::new("disc");
        let reg = dir.path().join("services");
        std::fs::create_dir(&reg).unwrap();
        std::fs::write(reg.join("HR-Portal-3.json"), FAKE_SERVICE).unwrap();
        std::fs::write(reg.join("Wiki-4.json"), OTHER_SERVICE).unwrap();
        std::fs::write(reg.join("Broken-5.json"), "{ not json").unwrap();
        std::fs::write(
            reg.join("Export-6.json"),
            r#"{"email": "hidden.value@example.org"}"#,
        )
        .unwrap();
        let (findings, state) = scan(&settings(&dir, false)).await;
        let emails: Vec<&MaskedFinding> = findings
            .iter()
            .filter(|f| f.classifier() == ClassifierId::PII_EMAIL)
            .collect();
        assert_eq!(emails.len(), 1, "{findings:?}");
        let e = emails[0];
        let loc = e.location().unwrap();
        assert_eq!(loc.database.as_str(), "service_registry");
        assert_eq!(loc.schema.as_ref().unwrap().as_str(), "oidc");
        assert_eq!(loc.object.as_str(), "*", "two services pooled");
        assert_eq!(loc.field.as_str(), "contacts[].email");
        assert_eq!(e.sampled(), 3);
        assert_eq!(e.estimated_rows(), Some(2));
        let all = format!("{findings:?}");
        for leak in [
            "jane.doe@example.org",
            "john.roe",
            "max.moe",
            "hidden.value",
            "fake-clear-secret",
            "WIKI_SECRET",
            "HR-Portal-3",
        ] {
            assert!(!all.contains(leak), "{leak} in {all}");
        }
        let snap = state.snapshot();
        assert_eq!(
            snap.registry,
            Some(RegistryFacts {
                skipped: 2,
                clear_secrets: 1,
                writable: 0,
            })
        );
        assert_eq!(state.services().unwrap().len(), 2);
        // Skipped files: no client id names a token response (ADR-0044,
        // review of #182 L1), in the scan's index and in the stream's.
        assert!(!state.services().unwrap().clients_enabled());
        let (idx, _) = index_registry(&settings(&dir, false), Policy::TESTS).unwrap();
        assert!(!idx.clients_enabled());
        std::fs::remove_file(reg.join("Broken-5.json")).unwrap();
        std::fs::remove_file(reg.join("Export-6.json")).unwrap();
        let (_, state) = scan(&settings(&dir, false)).await;
        assert!(state.services().unwrap().clients_enabled());
        let (idx, _) = index_registry(&settings(&dir, false), Policy::TESTS).unwrap();
        assert!(idx.clients_enabled());
    }

    #[tokio::test]
    async fn a_registry_with_configuration_files_is_not_read() {
        let dir = TempDir::new("disc-config");
        let reg = dir.path().join("services");
        std::fs::create_dir(&reg).unwrap();
        std::fs::write(reg.join("HR-Portal-3.json"), FAKE_SERVICE).unwrap();
        std::fs::write(reg.join("application.yml"), "cas.secret: hunter2-SECRET").unwrap();
        let (findings, state) = scan(&settings(&dir, false)).await;
        assert!(findings.is_empty());
        assert_eq!(state.snapshot().registry, Some(RegistryFacts::default()));
        assert!(state.services().is_none());
    }

    #[tokio::test]
    async fn the_audit_log_gives_successful_principals_only() {
        let dir = TempDir::new("disc-audit");
        std::fs::create_dir(dir.path().join("services")).unwrap();
        let mut log = String::new();
        for i in 0..20 {
            log.push_str(&format!(
                "{{\"action\": \"AUTHENTICATION_SUCCESS\", \"who\": \"user{i}@example.org\", \"when\": 1791115200000, \"what\": \"TGT-{i}-FAKE\"}}\n"
            ));
            log.push_str(&format!(
                "{{\"action\": \"AUTHENTICATION_FAILED\", \"who\": \"typed-password-{i}@example.org\", \"when\": 1791115200000}}\n"
            ));
        }
        std::fs::write(dir.path().join("cas_audit.log"), log).unwrap();
        let (findings, _) = scan(&settings(&dir, true)).await;
        assert_eq!(findings.len(), 1, "{findings:?}");
        let f = &findings[0];
        assert_eq!(f.classifier(), ClassifierId::PII_EMAIL);
        assert_eq!(f.sampled(), 20, "failed authentications never sampled");
        let loc = f.location().unwrap();
        assert_eq!(
            (
                loc.database.as_str(),
                loc.object.as_str(),
                loc.field.as_str()
            ),
            ("audit_trail", "audit_log", "who")
        );
        let all = format!("{findings:?}");
        assert!(!all.contains("user1") && !all.contains("TGT-") && !all.contains("typed"));
    }

    const FIXTURES: [(&str, &str, &str); 3] = [
        (
            "HR-Portal-10000003",
            include_str!("../fixtures/registry/HR-Portal-10000003.json"),
            include_str!("../fixtures/registry/HR-Portal-10000003.yml"),
        ),
        (
            "Wiki-10000004",
            include_str!("../fixtures/registry/Wiki-10000004.json"),
            include_str!("../fixtures/registry/Wiki-10000004.yaml"),
        ),
        (
            "SP-10000005",
            include_str!("../fixtures/registry/SP-10000005.json"),
            include_str!("../fixtures/registry/SP-10000005.yml"),
        ),
    ];

    fn yaml_settings(dir: &TempDir) -> CasSettings {
        CasSettings::from_yaml(
            &format!(
                "{{service_registry: {{yaml_dir: {}}}}}",
                dir.path().join("services").display()
            ),
            &[],
        )
        .unwrap()
    }

    /// Findings in a comparable form, sorted: masked samples sorted too
    /// (their order is keyed per scan job) and fingerprints counted (each
    /// scan job has its own key).
    fn comparable(findings: &[MaskedFinding]) -> Vec<String> {
        let mut v: Vec<String> = findings
            .iter()
            .map(|f| {
                let mut samples: Vec<String> = f
                    .masked_samples()
                    .iter()
                    .map(|m| format!("{m:?}"))
                    .collect();
                samples.sort();
                format!(
                    "{:?} {samples:?} {} {:?} {} {} {} {:?}",
                    f.classifier(),
                    f.fingerprints().len(),
                    f.location(),
                    f.sampled(),
                    f.matched(),
                    f.confidence(),
                    f.estimated_rows()
                )
            })
            .collect();
        v.sort();
        v
    }

    #[tokio::test]
    async fn a_yaml_registry_gives_the_findings_of_its_json_equivalent() {
        let json_dir = TempDir::new("disc-json-eq");
        let yaml_dir = TempDir::new("disc-yaml-eq");
        let jreg = json_dir.path().join("services");
        let yreg = yaml_dir.path().join("services");
        std::fs::create_dir(&jreg).unwrap();
        std::fs::create_dir(&yreg).unwrap();
        for (stem, json, yaml) in FIXTURES {
            std::fs::write(jreg.join(format!("{stem}.json")), json).unwrap();
            std::fs::write(yreg.join(format!("{stem}.yml")), yaml).unwrap();
        }
        // A JSON file in a YAML registry is not listed.
        std::fs::write(yreg.join("Stray-9.json"), FAKE_SERVICE).unwrap();
        let (jf, jstate) = scan(&settings(&json_dir, false)).await;
        let (yf, ystate) = scan(&yaml_settings(&yaml_dir)).await;
        assert!(!jf.is_empty());
        assert_eq!(comparable(&jf), comparable(&yf));
        assert_eq!(jstate.snapshot().registry, ystate.snapshot().registry);
        assert_eq!(
            ystate.snapshot().registry,
            Some(RegistryFacts {
                skipped: 0,
                clear_secrets: 1,
                writable: 0,
            })
        );
        assert_eq!(ystate.services().unwrap().len(), 3);
        let all = format!("{yf:?}");
        for leak in [
            "jane.doe@example.org",
            "john.roe",
            "fake-clear-secret",
            "FAKE-",
            "hunter2",
            "HR-Portal-10000003",
        ] {
            assert!(!all.contains(leak), "{leak} in {all}");
        }
    }

    #[tokio::test]
    async fn hostile_yaml_files_are_skipped_and_counted() {
        let dir = TempDir::new("disc-yaml-hostile");
        let outside = TempDir::new("disc-yaml-outside");
        let reg = dir.path().join("services");
        std::fs::create_dir(&reg).unwrap();
        let (_, _, good) = FIXTURES[0];
        std::fs::write(reg.join("Good-1.yml"), good).unwrap();
        let head = "--- !<org.apereo.cas.services.CasRegisteredService>\nserviceId: x\n";
        let mut laughs = format!("{head}a0: &a0 [\"lol\", \"lol\"]\n");
        for i in 1..10 {
            let p = i - 1;
            laughs.push_str(&format!("a{i}: &a{i} [*a{p}, *a{p}, *a{p}]\n"));
        }
        std::fs::write(reg.join("Laughs-2.yml"), laughs).unwrap();
        let mut deep = head.to_owned();
        for i in 0..100 {
            deep.push_str(&format!("{}k:\n", " ".repeat(i)));
        }
        std::fs::write(reg.join("Deep-3.yml"), deep).unwrap();
        std::fs::write(
            reg.join("Tag-4.yml"),
            format!("{head}description: !!python/object/apply:os.system [id]\n"),
        )
        .unwrap();
        std::fs::write(
            reg.join("Merge-5.yml"),
            format!("{head}other:\n  <<: {{email: hidden.value@example.org}}\n"),
        )
        .unwrap();
        let target = outside.path().join("Target.yml");
        std::fs::write(&target, good).unwrap();
        std::os::unix::fs::symlink(&target, reg.join("Sym-6.yml")).unwrap();
        let linked = outside.path().join("Linked.yml");
        std::fs::write(&linked, good).unwrap();
        std::fs::hard_link(&linked, reg.join("Hard-7.yml")).unwrap();
        let mut big = head.to_owned();
        big.push_str(&"# padding\n".repeat(110_000));
        std::fs::write(reg.join("Big-8.yml"), big).unwrap();
        let (findings, state) = scan(&yaml_settings(&dir)).await;
        assert_eq!(
            state.snapshot().registry,
            Some(RegistryFacts {
                skipped: 7,
                clear_secrets: 1,
                writable: 0,
            })
        );
        assert_eq!(state.services().unwrap().len(), 1);
        let all = format!("{findings:?}");
        assert!(
            !all.contains("hidden.value") && !all.contains("lol"),
            "{all}"
        );
    }
}
