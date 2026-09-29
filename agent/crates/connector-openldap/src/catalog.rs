//! Directory metadata: the root DSE, the schema and the containers of a
//! naming context (ADR-0029 decision 5). Every search is bounded (size and
//! time limits, attribute lists built in code).

use databastion_core::FailureCode;
use tokio::io::{AsyncRead, AsyncWrite};
use zeroize::Zeroizing;

use crate::conn::Session;
use crate::dn;
use crate::error::{LdError, Stage};
use crate::proto::{Entry, Filter, Scope, Search};
use crate::schema::Schema;

/// Most naming contexts read from the root DSE.
pub(crate) const MAX_NAMING_CONTEXTS: usize = 64;
/// Most containers listed per naming context.
pub(crate) const MAX_CONTAINERS: u32 = 1024;
/// Classes of the entries Discovery samples below (their RDN types are
/// the contract's container RDNs: `ou`, `o`, `dc`, `c`, `l`).
pub(crate) const CONTAINER_CLASSES: [&str; 6] = [
    "organizationalUnit",
    "organization",
    "dcObject",
    "domain",
    "country",
    "locality",
];

/// What the root DSE tells.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RootDse {
    /// Naming contexts as the server spells them (at most
    /// [`MAX_NAMING_CONTEXTS`]).
    pub(crate) naming_contexts: Vec<String>,
    /// Naming contexts beyond the bound.
    pub(crate) naming_contexts_cut: bool,
    pub(crate) subschema: Option<String>,
    pub(crate) config_context: Option<String>,
}

fn dn_value(v: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(v).ok()?;
    (!s.is_empty() && s.len() <= dn::MAX_DN_BYTES && dn::rdns(s).is_some()).then(|| s.to_owned())
}

/// The root DSE (base search on the empty DN).
pub(crate) async fn root_dse<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut Session<S>,
    stage: Stage,
) -> Result<RootDse, LdError> {
    let mut dse = RootDse::default();
    let search = Search {
        base: "",
        scope: Scope::Base,
        size_limit: 1,
        time_limit: 0,
        types_only: false,
        filter: Filter::Present("objectClass"),
        attributes: &["namingContexts", "subschemaSubentry", "configContext"],
    };
    let mut on_entry = |e: Entry| {
        for v in e.values("namingContexts") {
            if dse.naming_contexts.len() >= MAX_NAMING_CONTEXTS {
                dse.naming_contexts_cut = true;
            } else if let Some(d) = dn_value(v) {
                dse.naming_contexts.push(d);
            }
        }
        dse.subschema = e.values("subschemaSubentry").next().and_then(dn_value);
        dse.config_context = e.values("configContext").next().and_then(dn_value);
    };
    let outcome = s.search(stage, &search, &mut on_entry).await?;
    if let Some(e) = outcome.error(stage) {
        return Err(e);
    }
    if outcome.entries == 0 {
        return Err(LdError {
            fatal: false,
            ..LdError::new(FailureCode::PermissionDenied, stage)
        });
    }
    Ok(dse)
}

/// The schema of the subschema subentry `dn` (default `cn=Subschema`).
pub(crate) async fn schema<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut Session<S>,
    subschema: Option<&str>,
) -> Result<Schema, LdError> {
    let base = subschema.unwrap_or("cn=Subschema");
    let search = Search {
        base,
        scope: Scope::Base,
        size_limit: 1,
        time_limit: 0,
        types_only: false,
        filter: Filter::Eq("objectClass", "subschema".to_owned()),
        attributes: &["attributeTypes", "objectClasses"],
    };
    let mut parsed: Option<Schema> = None;
    let mut on_entry = |e: Entry| {
        parsed = Some(Schema::parse(
            e.values("attributeTypes"),
            e.values("objectClasses"),
        ));
    };
    let outcome = s
        .search(Stage::Introspection, &search, &mut on_entry)
        .await?;
    if let Some(e) = outcome.error(Stage::Introspection) {
        return Err(e);
    }
    parsed.filter(|p| p.attribute_types() > 0).ok_or(LdError {
        fatal: false,
        ..LdError::new(FailureCode::PermissionDenied, Stage::Introspection)
    })
}

/// The filter that lists containers.
pub(crate) fn container_filter() -> Filter {
    Filter::Or(
        CONTAINER_CLASSES
            .iter()
            .map(|c| Filter::Eq("objectClass", (*c).to_owned()))
            .collect(),
    )
}

/// The containers of the naming context `suffix` (the context itself
/// first), DNs only (attributes `1.1`). The flag tells whether the listing
/// was cut; the count is the continuation references seen.
pub(crate) async fn containers<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut Session<S>,
    suffix: &str,
) -> Result<(Vec<Zeroizing<String>>, bool, u64), LdError> {
    let search = Search {
        base: suffix,
        scope: Scope::Sub,
        size_limit: MAX_CONTAINERS,
        time_limit: 0,
        types_only: false,
        filter: container_filter(),
        attributes: &["1.1"],
    };
    let suffix_canon = dn::canon(suffix).unwrap_or_default();
    let mut out = vec![Zeroizing::new(suffix.to_owned())];
    let mut on_entry = |e: Entry| {
        if dn::canon(&e.dn).is_some_and(|c| c != suffix_canon && dn::is_within(&c, &suffix_canon)) {
            out.push(e.dn);
        }
    };
    let outcome = s
        .search(Stage::Introspection, &search, &mut on_entry)
        .await?;
    if let Some(e) = outcome.error(Stage::Introspection) {
        return Err(e);
    }
    Ok((out, outcome.cut(), outcome.references))
}
