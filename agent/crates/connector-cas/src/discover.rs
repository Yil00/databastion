//! Discovery of a `cas` target (ADR-0041 decision 4).
//!
//! - **Service registry**: each listed `.json` file is one unit of work
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
//! TODO(P8-C): called from `Connector::discover` once the `cas` engine is
//! wired into the core; [`CasError`] then maps to `ConnectorError`.

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
use crate::parse::definition::{DefinitionError, SecretForm, ServiceType, parse_definition};
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
    discover_with(settings, job, sink, state, Policy::STRICT).await
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
    let listed = job
        .paced(tokio::task::spawn_blocking(move || {
            if dir.still_resolves() {
                fsread::list_registry(dir.path(), policy)
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
                    Ok(bytes) => match parse_definition(&bytes) {
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
}
