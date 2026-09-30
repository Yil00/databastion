//! Discovery (ADR-0029 decisions 5 and 6): per naming context, the
//! containers, then a bounded one-level search in each; entries grouped by
//! (normalized container, structural object class); values classified
//! through `ScanJob::classify` and `classifiers::masking` only (I2).
//!
//! Locations: `database` = the naming context, `schema` = the container,
//! `object` = the structural object class, `field` = the attribute; all
//! normalized (`names::normalize_ldap_dn`, `normalize_path`,
//! `normalize_ldap_attribute`). Entry DNs never leave the agent and are
//! never logged.

use std::collections::HashMap;
use std::future::Future;

use databastion_classifiers::masking::{FindingLocation, RawSample};
use databastion_classifiers::names::{
    NormalizedName, normalize_ldap_attribute, normalize_ldap_dn, normalize_path,
};
use databastion_core::config::TargetConfig;
use databastion_core::{ConnectorError, FailureCode, FindingSink, ScanCoverage, ScanJob};
use tokio::io::{AsyncRead, AsyncWrite};
use zeroize::Zeroizing;

use crate::catalog;
use crate::check::CheckState;
use crate::conn::{Session, Timeouts};
use crate::dn;
use crate::error::{LdError, Stage};
use crate::proto::{Entry, Filter, Scope, Search};
use crate::schema::Schema;

/// Longest value classified, in bytes (cut on a character boundary).
pub(crate) const MAX_VALUE_BYTES: usize = 4096;
/// Most object classes kept per container group.
const MAX_CLASSES_PER_CONTAINER: usize = 64;
/// Most attributes kept per group.
const MAX_FIELDS_PER_GROUP: usize = 1024;

fn fail(target: &TargetConfig, e: LdError) -> ConnectorError {
    tracing::warn!(
        target_id = %target.id,
        stage = e.stage.as_str(),
        result = e.result,
        code = %e.code,
        "scan failed"
    );
    e.into_connector_error()
}

/// A value as the classifiers read it: UTF-8 text (cut to
/// [`MAX_VALUE_BYTES`]), or `YYYY-MM-DD` for a Generalized Time. `None`
/// when it cannot be read.
pub(crate) fn text_value(raw: &[u8], time: bool) -> Option<Zeroizing<String>> {
    let s = std::str::from_utf8(raw).ok()?;
    if s.is_empty() {
        return None;
    }
    if time {
        let b = s.as_bytes();
        if !b.get(..8).is_some_and(|p| p.iter().all(u8::is_ascii_digit)) {
            return None;
        }
        let (y, m, d) = (s.get(0..4)?, s.get(4..6)?, s.get(6..8)?);
        let month: u8 = m.parse().ok()?;
        let day: u8 = d.parse().ok()?;
        if !(1..=12).contains(&month) || !(1..=31).contains(&day) || y == "0000" {
            return None;
        }
        return Some(Zeroizing::new(format!("{y}-{m}-{d}")));
    }
    let mut end = s.len().min(MAX_VALUE_BYTES);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s.get(..end).map(|v| Zeroizing::new(v.to_owned()))
}

/// The sampled values of one (container, object class) group.
#[derive(Default)]
struct Group {
    entries: u64,
    fields: HashMap<NormalizedName, Vec<Zeroizing<String>>>,
}

impl Group {
    fn add(&mut self, schema: &Schema, e: &Entry, n: usize) {
        self.entries += 1;
        for a in &e.attributes {
            if !schema.eligible(&a.name) {
                continue;
            }
            let Some(canonical) = schema.canonical_attribute(&a.name) else {
                continue;
            };
            let field = normalize_ldap_attribute(&canonical);
            if !self.fields.contains_key(&field) && self.fields.len() >= MAX_FIELDS_PER_GROUP {
                continue;
            }
            let time = schema.is_time(&a.name);
            let values = self.fields.entry(field).or_default();
            for v in &a.values {
                if values.len() >= n {
                    break;
                }
                if let Some(t) = text_value(v, time) {
                    values.push(t);
                }
            }
        }
    }
}

/// Groups of containers with the same normalized name, by object class.
type Groups = HashMap<NormalizedName, Group>;

/// Per-scan totals, for the final log line.
#[derive(Debug, Default)]
struct Totals {
    contexts: u64,
    containers: u64,
    groups: u64,
    entries: u64,
    skipped: u64,
}

/// `Connector::discover` for OpenLDAP.
pub(crate) async fn discover(
    job: &ScanJob,
    sink: &FindingSink,
    _state: &CheckState,
) -> Result<(), ConnectorError> {
    let target = job.target().ok_or_else(|| {
        LdError::new(FailureCode::Internal, Stage::Connect).into_connector_error()
    })?;
    let timeouts = Timeouts::new(job.statement_timeout());
    scan(job, sink, target, || Session::connect(target, timeouts)).await
}

/// A usable session in `slot`, reconnecting when it is missing, broken or
/// stale.
async fn ensure<'s, S, F, Fut>(
    slot: &'s mut Option<Session<S>>,
    target: &TargetConfig,
    connect: &mut F,
) -> Result<&'s mut Session<S>, ConnectorError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Session<S>, LdError>>,
{
    if slot.as_ref().is_none_or(|s| s.is_broken() || s.is_stale()) {
        if let Some(old) = slot.take() {
            old.close().await;
        }
        *slot = Some(connect().await.map_err(|e| fail(target, e))?);
    }
    slot.as_mut()
        .ok_or_else(|| LdError::new(FailureCode::Internal, Stage::Connect).into_connector_error())
}

/// The scan, over sessions from `connect` (the scripted server in tests).
pub(crate) async fn scan<S, F, Fut>(
    job: &ScanJob,
    sink: &FindingSink,
    target: &TargetConfig,
    mut connect: F,
) -> Result<(), ConnectorError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Session<S>, LdError>>,
{
    let n = usize::try_from(job.sample_rows())
        .unwrap_or(usize::MAX)
        .max(1);
    let accesslog = dn::canon(&target.openldap_settings().accesslog_base).unwrap_or_default();
    let mut slot: Option<Session<S>> = None;
    // Paced (ADR-0035 proposed): the root DSE and schema reads, each
    // container listing and each container's sampling.
    let (dse, schema) = {
        let s = ensure(&mut slot, target, &mut connect).await?;
        job.paced(async {
            let dse = catalog::root_dse(s, Stage::Introspection)
                .await
                .map_err(|e| fail(target, e))?;
            // Without a schema the connector cannot tell credential
            // attributes apart: the scan fails rather than requesting
            // everything.
            let schema = catalog::schema(s, dse.subschema.as_deref())
                .await
                .map_err(|e| fail(target, e))?;
            Ok::<_, ConnectorError>((dse, schema))
        })
        .await??
    };
    if dse.naming_contexts_cut {
        tracing::warn!(
            target_id = %target.id,
            limit = catalog::MAX_NAMING_CONTEXTS,
            "naming context list cut at its limit: the other contexts are not covered"
        );
        sink.add_coverage(ScanCoverage {
            limit: 1,
            ..ScanCoverage::default()
        });
    }
    let (requested, left_out) = schema.requested();
    if left_out > 0 || schema.skipped > 0 {
        tracing::warn!(
            target_id = %target.id,
            attributes_left_out = left_out,
            descriptions_not_parsed = schema.skipped,
            "schema only partly usable: some attributes are not requested"
        );
    }
    let mut attributes: Vec<&str> = requested.iter().map(String::as_str).collect();
    attributes.extend(["objectClass", "structuralObjectClass"]);
    let mut totals = Totals::default();
    for suffix in &dse.naming_contexts {
        let canon = dn::canon(suffix).unwrap_or_default();
        if canon.is_empty() || canon == accesslog {
            continue;
        }
        let database = normalize_ldap_dn(suffix);
        if !job.includes_database(database.as_str()) {
            continue;
        }
        totals.contexts += 1;
        let listed = {
            let s = ensure(&mut slot, target, &mut connect).await?;
            job.paced(catalog::containers(s, suffix)).await?
        };
        let (containers, cut, references) = match listed {
            Ok(l) => l,
            Err(e) if !e.fatal => {
                sink.add_coverage(
                    if e.code == FailureCode::PermissionDenied
                        || e.code == FailureCode::UnknownTarget
                    {
                        ScanCoverage {
                            not_readable: 1,
                            ..ScanCoverage::default()
                        }
                    } else {
                        ScanCoverage {
                            error: 1,
                            ..ScanCoverage::default()
                        }
                    },
                );
                tracing::warn!(
                    target_id = %target.id,
                    database = database.as_str(),
                    result = e.result,
                    "containers not listed: naming context skipped"
                );
                continue;
            }
            Err(e) => return Err(fail(target, e)),
        };
        if cut {
            tracing::warn!(
                target_id = %target.id,
                database = database.as_str(),
                limit = catalog::MAX_CONTAINERS,
                "container listing cut: the other containers are not covered"
            );
        }
        sink.add_coverage(ScanCoverage {
            limit: u64::from(cut),
            remote: references,
            ..ScanCoverage::default()
        });
        // Containers with the same normalized name are read one after the
        // other and pooled before classification.
        let mut ordered: Vec<(NormalizedName, Zeroizing<String>)> = containers
            .into_iter()
            .map(|c| (normalize_ldap_dn(&c), c))
            .filter(|(name, _)| job.includes_schema(name.as_str()))
            .collect();
        ordered.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
        let mut current: Option<(NormalizedName, Groups)> = None;
        for (container, raw) in ordered {
            if current.as_ref().is_some_and(|(name, _)| *name != container) {
                if let Some((name, groups)) = current.take() {
                    flush(job, sink, &database, &name, groups, &mut totals).await?;
                }
            }
            let groups = &mut current
                .get_or_insert_with(|| (container.clone(), Groups::new()))
                .1;
            totals.containers += 1;
            let read = {
                let s = ensure(&mut slot, target, &mut connect).await?;
                job.paced(sample_container(
                    s,
                    &schema,
                    &raw,
                    &attributes,
                    n,
                    job,
                    groups,
                ))
                .await?
            };
            match read {
                Ok((entries, references)) => {
                    totals.entries += entries;
                    if references > 0 {
                        sink.add_coverage(ScanCoverage {
                            remote: references,
                            ..ScanCoverage::default()
                        });
                    }
                }
                Err(e) => {
                    totals.skipped += 1;
                    let not_readable = matches!(
                        e.code,
                        FailureCode::PermissionDenied | FailureCode::UnknownTarget
                    );
                    sink.add_coverage(if not_readable {
                        ScanCoverage {
                            not_readable: 1,
                            ..ScanCoverage::default()
                        }
                    } else {
                        ScanCoverage {
                            error: 1,
                            ..ScanCoverage::default()
                        }
                    });
                    tracing::warn!(
                        target_id = %target.id,
                        database = database.as_str(),
                        container = container.as_str(),
                        stage = e.stage.as_str(),
                        result = e.result,
                        code = %e.code,
                        "container not covered"
                    );
                }
            }
        }
        if let Some((name, groups)) = current.take() {
            flush(job, sink, &database, &name, groups, &mut totals).await?;
        }
    }
    if let Some(s) = slot {
        s.close().await;
    }
    tracing::info!(
        target_id = %target.id,
        naming_contexts = totals.contexts,
        containers = totals.containers,
        groups = totals.groups,
        entries = totals.entries,
        skipped = totals.skipped,
        "target scanned"
    );
    Ok(())
}

/// One one-level search of `container`, its entries added to `groups`.
/// Returns the entries and continuation references read.
async fn sample_container<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut Session<S>,
    schema: &Schema,
    container: &str,
    attributes: &[&str],
    n: usize,
    job: &ScanJob,
    groups: &mut Groups,
) -> Result<(u64, u64), LdError> {
    let search = Search {
        base: container,
        scope: Scope::One,
        size_limit: u32::try_from(n).unwrap_or(u32::MAX),
        time_limit: 0,
        types_only: false,
        filter: Filter::Present("objectClass"),
        attributes,
    };
    let mut on_entry = |e: Entry| {
        let class = schema.structural_class(
            e.first_str("structuralObjectClass"),
            e.values("objectClass")
                .filter_map(|v| std::str::from_utf8(v).ok()),
        );
        let object = class
            .as_deref()
            .map_or_else(NormalizedName::wildcard, normalize_path);
        if !job.includes_object(object.as_str()) {
            return;
        }
        if !groups.contains_key(&object) && groups.len() >= MAX_CLASSES_PER_CONTAINER {
            return;
        }
        groups.entry(object).or_default().add(schema, &e, n);
    };
    let outcome = s.search(Stage::Sample, &search, &mut on_entry).await?;
    if let Some(e) = outcome.error(Stage::Sample) {
        return Err(e);
    }
    Ok((outcome.entries, outcome.references))
}

/// Classifies and submits the groups of one normalized container. Nothing
/// is open on the server here.
async fn flush(
    job: &ScanJob,
    sink: &FindingSink,
    database: &NormalizedName,
    container: &NormalizedName,
    groups: Groups,
    totals: &mut Totals,
) -> Result<(), ConnectorError> {
    let mut groups: Vec<(NormalizedName, Group)> = groups.into_iter().collect();
    groups.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
    for (object, group) in groups {
        if group.entries == 0 {
            continue;
        }
        totals.groups += 1;
        sink.add_coverage(ScanCoverage {
            sampled: 1,
            ..ScanCoverage::default()
        });
        let mut fields: Vec<_> = group.fields.into_iter().collect();
        fields.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
        for (field, values) in fields {
            let samples: Vec<RawSample<'_>> =
                values.iter().map(|v| RawSample::new(v.as_str())).collect();
            for finding in job.classify(field.as_str(), &samples) {
                sink.submit(finding.into_finding(FindingLocation {
                    database: database.clone(),
                    schema: Some(container.clone()),
                    object: object.clone(),
                    field: field.clone(),
                }))
                .await?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_are_text_or_dates() {
        assert_eq!(
            text_value(b"jane@example.org", false).unwrap().as_str(),
            "jane@example.org"
        );
        assert_eq!(
            text_value(b"19800131000000Z", true).unwrap().as_str(),
            "1980-01-31"
        );
        assert!(text_value(b"19801331000000Z", true).is_none());
        assert!(text_value(b"garbage", true).is_none());
        assert!(text_value(&[0xff, 0xfe], false).is_none());
        assert!(text_value(b"", false).is_none());
        let long = "é".repeat(3000);
        let cut = text_value(long.as_bytes(), false).unwrap();
        assert!(cut.len() <= MAX_VALUE_BYTES && cut.len() >= MAX_VALUE_BYTES - 1);
    }
}
