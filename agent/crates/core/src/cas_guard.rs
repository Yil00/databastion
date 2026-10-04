//! CAS store guard (ADR-0041 decisions 5 and 6, security review M9), on by
//! default in the PostgreSQL, MySQL / MariaDB, MongoDB and OpenLDAP
//! connectors.
//!
//! Apereo CAS keeps three stores in engines DataBastion already reads: the
//! **ticket registry** (live SSO bearer credentials), the **service
//! registry** (definitions with client secrets) and the **audit trail**
//! (ticket ids, cookies, names typed at failed logins). This module is the
//! connector-independent part of the guard:
//!
//! - **recognition** ([`recognize`]): by name (built-in names, matched
//!   case-insensitively and schema-agnostically after removing everything
//!   but letters and digits, so `CasTickets` = `cas_tickets`), by the
//!   per-target `cas_stores` lists of `agent.yaml` ([`CasStores`]), and by
//!   column shape (a renamed table);
//! - **what is read** ([`column_rule`], [`ColumnRule`]): nothing of a
//!   ticket registry but its `type` aggregate; never the ticket-id,
//!   header and extra-info columns of an audit trail; the audit trail's
//!   principal and the service registry body classified without masked
//!   samples (and without `secret.*` fingerprints for the body);
//! - the **ticket registry metadata** ([`TicketCounts`]): counts per kind
//!   and whether the tickets are encrypted, from `type` only;
//! - the per-scan tally ([`ScanGuard`]) behind the target notes
//!   `coverage.cas_guard_tripped` and `security.ticket_registry_unencrypted`
//!   (added by the core to the target's `check()` notes).
//!
//! The third recognition rule, the ticket-id **value tripwire**, runs in
//! the shared sampling path (`ScanJob::classify`, with
//! `databastion_classifiers::cas::is_ticket_id`): a column or field holding
//! one ticket-id-shaped value is dropped whole, before classification.
//!
//! Nothing here logs or returns a sampled value; object and column names
//! are only compared.

use std::sync::atomic::{AtomicU64, Ordering};

use serde::Deserialize;

/// Most names in each `cas_stores` list.
pub const MAX_CAS_STORE_NAMES: usize = 64;
/// Longest name in a `cas_stores` list.
const MAX_CAS_STORE_NAME: usize = 128;

/// Kind of CAS store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum StoreKind {
    /// Ticket registry: metadata only (the `type` aggregate).
    TicketRegistry,
    /// Service registry: the definition body without masked samples nor
    /// `secret.*` fingerprints.
    ServiceRegistry,
    /// Audit trail: ticket ids, headers and extra info never read; the
    /// principal without masked samples.
    AuditTrail,
}

impl StoreKind {
    /// Stable name for logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TicketRegistry => "ticket_registry",
            Self::ServiceRegistry => "service_registry",
            Self::AuditTrail => "audit_trail",
        }
    }
}

/// What a connector does with one column (or document field, or LDAP
/// attribute) of an object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnRule {
    /// Sampled and classified as usual.
    Sampled,
    /// Never selected, never read.
    NeverRead,
    /// Classified; findings keep counts and fingerprints, no masked sample.
    NoMaskedSamples,
    /// Classified; findings keep counts and the fingerprints of non-secret
    /// classifiers only, no masked sample.
    NoSamplesNoSecretFingerprints,
}

/// Per-target CAS stores under custom names (`targets[].<engine>.cas_stores`
/// in `agent.yaml`, ADR-0041 decision 5): table, collection or LDAP object
/// class names, compared like the built-in names (case-insensitively,
/// letters and digits only, whatever the schema or database).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CasStores {
    /// Ticket registry tables or collections (metadata only).
    #[serde(default)]
    pub ticket_registry: Vec<String>,
    /// Service registry tables, collections or LDAP object classes.
    #[serde(default)]
    pub service_registry: Vec<String>,
    /// Audit trail tables or collections.
    #[serde(default)]
    pub audit_trail: Vec<String>,
}

impl CasStores {
    /// Checks the lists: at most [`MAX_CAS_STORE_NAMES`] names each, each
    /// 1 to 128 characters without control characters. Returns the
    /// offending key on error.
    ///
    /// # Errors
    /// The name of the list that is refused, and why.
    pub fn validate(&self) -> Result<(), (&'static str, &'static str)> {
        for (key, list) in [
            ("ticket_registry", &self.ticket_registry),
            ("service_registry", &self.service_registry),
            ("audit_trail", &self.audit_trail),
        ] {
            if list.len() > MAX_CAS_STORE_NAMES {
                return Err((key, "at most 64 names"));
            }
            if list.iter().any(|n| {
                n.is_empty()
                    || n.chars().count() > MAX_CAS_STORE_NAME
                    || n.chars().any(char::is_control)
                    || name_key(n).is_empty()
            }) {
                return Err((
                    key,
                    "names must be 1 to 128 characters with a letter or digit and no control \
                     character",
                ));
            }
        }
        Ok(())
    }

    fn kind_of(&self, key: &str) -> Option<StoreKind> {
        let listed = |l: &[String]| l.iter().any(|n| name_key(n) == key);
        if listed(&self.ticket_registry) {
            Some(StoreKind::TicketRegistry)
        } else if listed(&self.audit_trail) {
            Some(StoreKind::AuditTrail)
        } else if listed(&self.service_registry) {
            Some(StoreKind::ServiceRegistry)
        } else {
            None
        }
    }
}

/// The comparison key of a table, collection, object class or column
/// name: its letters and digits, lower-cased; the part after the last `.`
/// only (schema-agnostic: `cas.CasTickets` and `CAS_TICKETS` are the same
/// table).
#[must_use]
pub fn name_key(name: &str) -> String {
    let last = name.rsplit('.').next().unwrap_or(name);
    last.chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

/// Built-in ticket registry names: the JPA table (`CasTickets` /
/// `cas_tickets`, verified) and the MongoDB ticket collections (CAS 8.0
/// defaults, to verify).
const TICKET_REGISTRY_NAMES: &[&str] = &[
    "castickets",
    "ticketgrantingticketscollection",
    "serviceticketscollection",
    "proxyticketscollection",
    "proxygrantingticketscollection",
    "transientsessionticketscollection",
    "oauthcodescollection",
    "oauthaccesstokenscollection",
    "oauthrefreshtokenscollection",
    "oauthdevicetokenscollection",
    "oauthdeviceusercodescollection",
    "casticketscollection",
];

/// Built-in service registry names: the JPA table (`RegisteredServices`,
/// verified), the MongoDB collection and the LDAP object class (CAS
/// defaults, to verify).
const SERVICE_REGISTRY_NAMES: &[&str] = &[
    "registeredservices",
    "casserviceregistry",
    "casregisteredservice",
];

/// Built-in audit trail names: the JDBC table (`COM_AUDIT_TRAIL`,
/// verified) and the MongoDB collection (CAS default, to verify).
const AUDIT_TRAIL_NAMES: &[&str] = &["comaudittrail", "mongodbcasauditrepository"];

fn builtin_kind(key: &str) -> Option<StoreKind> {
    if TICKET_REGISTRY_NAMES.contains(&key) {
        Some(StoreKind::TicketRegistry)
    } else if AUDIT_TRAIL_NAMES.contains(&key) {
        Some(StoreKind::AuditTrail)
    } else if SERVICE_REGISTRY_NAMES.contains(&key) {
        Some(StoreKind::ServiceRegistry)
    } else {
        None
    }
}

/// Every name key the guard recognizes for `stores` (built-in names and
/// the target's lists), for a catalog query that pre-selects candidate
/// objects (compared there with the same key: letters and digits,
/// lower-cased).
#[must_use]
pub fn known_name_keys(stores: Option<&CasStores>) -> Vec<String> {
    let mut keys: Vec<String> = TICKET_REGISTRY_NAMES
        .iter()
        .chain(SERVICE_REGISTRY_NAMES)
        .chain(AUDIT_TRAIL_NAMES)
        .map(|k| (*k).to_owned())
        .collect();
    if let Some(s) = stores {
        for n in s
            .ticket_registry
            .iter()
            .chain(&s.service_registry)
            .chain(&s.audit_trail)
        {
            keys.push(name_key(n));
        }
    }
    keys.sort();
    keys.dedup();
    keys
}

/// The store kind of an object by name only: the target's `cas_stores`
/// first, then the built-in names. `names`: the object's name and, for a
/// partitioned table, its partitions' names.
#[must_use]
pub fn recognize_name<'a>(
    stores: Option<&CasStores>,
    names: impl IntoIterator<Item = &'a str>,
) -> Option<StoreKind> {
    names.into_iter().find_map(|n| {
        let key = name_key(n);
        stores
            .and_then(|s| s.kind_of(&key))
            .or_else(|| builtin_kind(&key))
    })
}

/// The store kind of an object by its column (or top-level field) shape,
/// whatever its name: `id`, `type`, `body` (MongoDB: or `json`),
/// `principal_id` (or `principalId`, MongoDB `principal`) and either
/// `parent_id` or an expiration column is a ticket registry; `AUD_RESOURCE`
/// with `AUD_ACTION` is an audit trail.
#[must_use]
pub fn recognize_shape<'a>(columns: impl IntoIterator<Item = &'a str>) -> Option<StoreKind> {
    let keys: Vec<String> = columns.into_iter().map(name_key).collect();
    let has = |k: &str| keys.iter().any(|c| c == k);
    if has("audresource") && has("audaction") {
        return Some(StoreKind::AuditTrail);
    }
    let ticket = has("id")
        && has("type")
        && (has("body") || has("json"))
        && (has("principalid") || has("principal"))
        && (has("parentid") || keys.iter().any(|c| c.contains("expir")));
    ticket.then_some(StoreKind::TicketRegistry)
}

/// [`recognize_name`], then [`recognize_shape`].
#[must_use]
pub fn recognize<'a>(
    stores: Option<&CasStores>,
    names: impl IntoIterator<Item = &'a str>,
    columns: impl IntoIterator<Item = &'a str>,
) -> Option<StoreKind> {
    recognize_name(stores, names).or_else(|| recognize_shape(columns))
}

/// Service definition classes of the closed map of ADR-0041 decision 4
/// (simple class names).
const SERVICE_CLASSES: &[&str] = &[
    "CasRegisteredService",
    "RegexRegisteredService",
    "OidcRegisteredService",
    "OAuthRegisteredService",
    "SamlRegisteredService",
    "WSFederationRegisteredService",
];

/// Longest text parsed as a service definition.
const MAX_DEFINITION_BYTES: usize = 256 * 1024;

/// Whether a text (an LDAP `description` value, a document field) is a
/// CAS service definition: a JSON object whose `@class` is in the closed
/// map of ADR-0041 decision 4 (security review M5). Nothing of the text is
/// kept: only `@class` is deserialized, every other key is skipped.
#[must_use]
pub fn is_service_definition(text: &str) -> bool {
    #[derive(Deserialize)]
    struct Head {
        #[serde(rename = "@class")]
        class: String,
    }
    let t = text.trim_start();
    if !t.starts_with('{') || t.len() > MAX_DEFINITION_BYTES || !t.contains("\"@class\"") {
        return false;
    }
    serde_json::from_str::<Head>(t).is_ok_and(|h| {
        let simple = h.class.rsplit('.').next().unwrap_or("");
        SERVICE_CLASSES.contains(&simple)
    })
}

/// Audit trail columns never read (ADR-0041 decisions 5 and 6): the
/// resource (ticket ids), the request headers (cookies), the extra info;
/// and their MongoDB / Inspektr field names.
const AUDIT_NEVER_READ: &[&str] = &[
    "audresource",
    "audheaders",
    "audextrainfo",
    "resourceoperatedupon",
    "resource",
    "headers",
    "extrainfo",
];

/// Audit trail principal columns: classified without masked samples
/// (security review M3: the name typed at a failed login may be a
/// password).
const AUDIT_PRINCIPAL: &[&str] = &["auduser", "principal", "who"];

/// The rule for one column (or field path: every `.`-separated segment is
/// compared, so `clientInfo.headers.*` of an audit document is never read)
/// of an object of `kind`.
#[must_use]
pub fn column_rule(kind: Option<StoreKind>, column: &str) -> ColumnRule {
    let segments = || column.split(['.', '[', ']']).map(name_key);
    match kind {
        None => ColumnRule::Sampled,
        Some(StoreKind::TicketRegistry) => ColumnRule::NeverRead,
        Some(StoreKind::AuditTrail) => {
            if segments().any(|s| AUDIT_NEVER_READ.contains(&s.as_str())) {
                ColumnRule::NeverRead
            } else if segments().any(|s| AUDIT_PRINCIPAL.contains(&s.as_str())) {
                ColumnRule::NoMaskedSamples
            } else {
                ColumnRule::Sampled
            }
        }
        Some(StoreKind::ServiceRegistry) => {
            if segments().any(|s| s == "body") {
                ColumnRule::NoSamplesNoSecretFingerprints
            } else {
                ColumnRule::Sampled
            }
        }
    }
}

/// The rule for a field of a **document** store (a MongoDB collection, an
/// LDAP entry), where the whole document is the stored object: a service
/// registry document is the definition itself, so every field gets the
/// body rule.
#[must_use]
pub fn document_rule(kind: Option<StoreKind>, path: &str) -> ColumnRule {
    match kind {
        Some(StoreKind::ServiceRegistry) => ColumnRule::NoSamplesNoSecretFingerprints,
        other => column_rule(other, path),
    }
}

/// Columns of a ticket registry that the agent's account may read: the
/// metadata of decision 6 (`type`, the creation, use and expiration times,
/// the use count). Every other column of a ticket registry is a credential
/// column (fail closed: an unknown column counts).
const TICKET_METADATA_COLUMNS: &[&str] = &[
    "type",
    "creationtime",
    "expirationtime",
    "expireat",
    "lastusedtime",
    "previouslastusedtime",
    "lasttimeused",
    "previoustimeused",
    "countofuses",
    "numberoftimesused",
];

/// Whether a column of an object of `kind` holds credentials the agent's
/// account should not be able to read (`privilege.ticket_credentials_readable`).
#[must_use]
pub fn is_credential_column(kind: StoreKind, column: &str) -> bool {
    match kind {
        StoreKind::TicketRegistry => !TICKET_METADATA_COLUMNS.contains(&name_key(column).as_str()),
        StoreKind::AuditTrail => {
            column_rule(Some(StoreKind::AuditTrail), column) == ColumnRule::NeverRead
        }
        StoreKind::ServiceRegistry => false,
    }
}

/// The column a ticket registry's metadata aggregate groups on, if the
/// object has it (`type`, any case).
#[must_use]
pub fn ticket_type_column<'a>(columns: impl IntoIterator<Item = &'a str>) -> Option<&'a str> {
    columns.into_iter().find(|c| name_key(c) == "type")
}

/// Kind of a CAS ticket, from its registry `type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TicketKind {
    /// Ticket-granting ticket (the SSO session).
    Tgt,
    /// Service ticket.
    St,
    /// Proxy ticket.
    Pt,
    /// Proxy-granting ticket.
    Pgt,
    /// OAuth / OIDC authorization code.
    OauthCode,
    /// OAuth / OIDC access token.
    OauthAccessToken,
    /// OAuth / OIDC refresh token.
    OauthRefreshToken,
    /// Anything else (transient session tickets, device codes, unknown).
    Other,
}

impl TicketKind {
    /// Every kind, in a stable order.
    pub const ALL: [Self; 8] = [
        Self::Tgt,
        Self::St,
        Self::Pt,
        Self::Pgt,
        Self::OauthCode,
        Self::OauthAccessToken,
        Self::OauthRefreshToken,
        Self::Other,
    ];

    /// Stable name for logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tgt => "tgt",
            Self::St => "st",
            Self::Pt => "pt",
            Self::Pgt => "pgt",
            Self::OauthCode => "oauth_code",
            Self::OauthAccessToken => "oauth_access_token",
            Self::OauthRefreshToken => "oauth_refresh_token",
            Self::Other => "other",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Tgt => 0,
            Self::St => 1,
            Self::Pt => 2,
            Self::Pgt => 3,
            Self::OauthCode => 4,
            Self::OauthAccessToken => 5,
            Self::OauthRefreshToken => 6,
            Self::Other => 7,
        }
    }
}

/// How a ticket registry row's `type` reads: an encoded (encrypted)
/// ticket, or a ticket of a kind stored in clear.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketType {
    /// The encoded ticket class (`crypto.enabled: true`, ADR-0041
    /// decision 5, verified: the stored type is the encoded ticket's class
    /// name). The ticket's own kind is not visible.
    Encoded,
    /// A ticket stored in clear.
    Clear(TicketKind),
}

/// Reads a ticket registry `type` value (a Java class name, or a ticket
/// prefix). Only compared, never kept nor logged.
#[must_use]
pub fn ticket_type(value: &str) -> TicketType {
    let simple = value.trim().rsplit(['.', '$']).next().unwrap_or("");
    let lower = simple.to_ascii_lowercase();
    if lower.contains("encodedticket") {
        return TicketType::Encoded;
    }
    let kind = match lower.as_str() {
        "tgt" => TicketKind::Tgt,
        "st" => TicketKind::St,
        "pt" => TicketKind::Pt,
        "pgt" => TicketKind::Pgt,
        "oc" => TicketKind::OauthCode,
        "at" => TicketKind::OauthAccessToken,
        "rt" => TicketKind::OauthRefreshToken,
        l if l.contains("proxygrantingticket") => TicketKind::Pgt,
        l if l.contains("ticketgrantingticket") => TicketKind::Tgt,
        l if l.contains("proxyticket") => TicketKind::Pt,
        l if l.contains("serviceticket") => TicketKind::St,
        l if l.contains("accesstoken") => TicketKind::OauthAccessToken,
        l if l.contains("refreshtoken") => TicketKind::OauthRefreshToken,
        l if l.contains("oauth") && l.contains("code") => TicketKind::OauthCode,
        _ => TicketKind::Other,
    };
    TicketType::Clear(kind)
}

/// Counts from a ticket registry's metadata aggregate (`type`, `count(*)`
/// grouped by `type`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TicketCounts {
    /// Clear tickets per [`TicketKind`] (index order of
    /// [`TicketKind::ALL`]).
    clear: [u64; 8],
    /// Encoded (encrypted) tickets.
    encrypted: u64,
}

impl TicketCounts {
    /// Adds the `count` rows of one `type` value.
    pub fn add(&mut self, type_value: &str, count: u64) {
        match ticket_type(type_value) {
            TicketType::Encoded => self.encrypted = self.encrypted.saturating_add(count),
            TicketType::Clear(k) => {
                if let Some(c) = self.clear.get_mut(k.index()) {
                    *c = c.saturating_add(count);
                }
            }
        }
    }

    /// Adds another registry's counts.
    pub fn merge(&mut self, other: &Self) {
        for (a, b) in self.clear.iter_mut().zip(other.clear) {
            *a = a.saturating_add(b);
        }
        self.encrypted = self.encrypted.saturating_add(other.encrypted);
    }

    /// Tickets stored in clear (`security.ticket_registry_unencrypted`).
    #[must_use]
    pub fn unencrypted(&self) -> u64 {
        self.clear.iter().fold(0u64, |a, b| a.saturating_add(*b))
    }

    /// Encoded tickets.
    #[must_use]
    pub fn encrypted(&self) -> u64 {
        self.encrypted
    }

    /// Clear tickets of one kind.
    #[must_use]
    pub fn clear_of(&self, kind: TicketKind) -> u64 {
        self.clear.get(kind.index()).copied().unwrap_or(0)
    }
}

/// What the guard saw during one Discovery scan of a target: shared by the
/// clones of its `ScanJob`, read by the core for the target's notes.
#[derive(Debug, Default)]
pub struct ScanGuard {
    tripped: AtomicU64,
    unencrypted: AtomicU64,
    encrypted: AtomicU64,
    registries: AtomicU64,
}

impl ScanGuard {
    /// One more column or field dropped by the ticket-id tripwire.
    pub(crate) fn trip(&self) {
        self.tripped.fetch_add(1, Ordering::Relaxed);
    }

    /// A ticket registry's metadata.
    pub(crate) fn add_registry(&self, counts: &TicketCounts) {
        self.registries.fetch_add(1, Ordering::Relaxed);
        self.unencrypted
            .fetch_add(counts.unencrypted(), Ordering::Relaxed);
        self.encrypted
            .fetch_add(counts.encrypted(), Ordering::Relaxed);
    }

    /// Columns or fields dropped by the tripwire so far.
    #[must_use]
    pub fn tripped(&self) -> u64 {
        self.tripped.load(Ordering::Relaxed)
    }

    /// Tickets stored in clear, over the registries read so far.
    #[must_use]
    pub fn unencrypted(&self) -> u64 {
        self.unencrypted.load(Ordering::Relaxed)
    }

    /// Ticket registries whose metadata was read.
    #[must_use]
    pub fn registries(&self) -> u64 {
        self.registries.load(Ordering::Relaxed)
    }

    /// The target notes of this scan's guard (counts only).
    #[must_use]
    pub fn notes(&self) -> Vec<crate::TargetNote> {
        use crate::{NoteCode, TargetNote};
        let mut out = Vec::new();
        if self.tripped() > 0 {
            out.push(TargetNote::new(NoteCode::CoverageCasGuardTripped).with_count(self.tripped()));
        }
        if self.unencrypted() > 0 {
            out.push(
                TargetNote::new(NoteCode::SecurityTicketRegistryUnencrypted)
                    .with_count(self.unencrypted()),
            );
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stores(t: &[&str], s: &[&str], a: &[&str]) -> CasStores {
        let v = |l: &[&str]| l.iter().map(|x| (*x).to_owned()).collect();
        CasStores {
            ticket_registry: v(t),
            service_registry: v(s),
            audit_trail: v(a),
        }
    }

    #[test]
    fn builtin_names_match_whatever_the_case_schema_and_separators() {
        for n in [
            "CasTickets",
            "cas_tickets",
            "CAS_TICKETS",
            "public.CasTickets",
            "cas.cas_tickets",
            "ticketGrantingTicketsCollection",
        ] {
            assert_eq!(
                recognize_name(None, [n]),
                Some(StoreKind::TicketRegistry),
                "{n}"
            );
        }
        for n in [
            "RegisteredServices",
            "registered_services",
            "cas-service-registry",
        ] {
            assert_eq!(
                recognize_name(None, [n]),
                Some(StoreKind::ServiceRegistry),
                "{n}"
            );
        }
        for n in ["COM_AUDIT_TRAIL", "com_audit_trail", "ComAuditTrail"] {
            assert_eq!(
                recognize_name(None, [n]),
                Some(StoreKind::AuditTrail),
                "{n}"
            );
        }
        for n in [
            "customers",
            "tickets",
            "cas_tickets_archive",
            "audit_trail",
            "",
        ] {
            assert_eq!(recognize_name(None, [n]), None, "{n}");
        }
        // A partition of a recognized root, or a root named like one.
        assert_eq!(
            recognize_name(None, ["sessions", "CasTickets"]),
            Some(StoreKind::TicketRegistry)
        );
    }

    #[test]
    fn cas_stores_add_custom_names() {
        let s = stores(&["sso_tix"], &["Apps"], &["LoginTrail"]);
        assert_eq!(s.validate(), Ok(()));
        assert_eq!(
            recognize_name(Some(&s), ["SSO_TIX"]),
            Some(StoreKind::TicketRegistry)
        );
        assert_eq!(
            recognize_name(Some(&s), ["apps"]),
            Some(StoreKind::ServiceRegistry)
        );
        assert_eq!(
            recognize_name(Some(&s), ["login_trail"]),
            Some(StoreKind::AuditTrail)
        );
        // The built-in names still apply.
        assert_eq!(
            recognize_name(Some(&s), ["CasTickets"]),
            Some(StoreKind::TicketRegistry)
        );
        // A name listed twice: the ticket registry (most restrictive) wins.
        let both = stores(&["x"], &["x"], &[]);
        assert_eq!(
            recognize_name(Some(&both), ["x"]),
            Some(StoreKind::TicketRegistry)
        );
    }

    #[test]
    fn cas_stores_are_bounded() {
        assert!(stores(&[""], &[], &[]).validate().is_err());
        assert!(stores(&[], &["__"], &[]).validate().is_err());
        assert!(stores(&[], &[], &["a\nb"]).validate().is_err());
        let long = "x".repeat(129);
        assert!(stores(&[long.as_str()], &[], &[]).validate().is_err());
        let many: Vec<String> = (0..65).map(|i| format!("t{i}")).collect();
        let s = CasStores {
            ticket_registry: many,
            ..CasStores::default()
        };
        assert_eq!(s.validate().unwrap_err().0, "ticket_registry");
    }

    #[test]
    fn renamed_tables_are_recognized_by_shape() {
        let jpa = [
            "ID",
            "PARENT_ID",
            "BODY",
            "TYPE",
            "PRINCIPAL_ID",
            "ATTRIBUTES",
            "CREATION_TIME",
            "EXPIRATION_TIME",
        ];
        assert_eq!(recognize_shape(jpa), Some(StoreKind::TicketRegistry));
        assert_eq!(
            recognize(None, ["sessions_v2"], jpa),
            Some(StoreKind::TicketRegistry)
        );
        // camelCase, an expiration column instead of the parent id.
        assert_eq!(
            recognize_shape(["id", "type", "body", "principalId", "expireAt"]),
            Some(StoreKind::TicketRegistry)
        );
        // MongoDB document shape.
        assert_eq!(
            recognize_shape(["_id", "type", "json", "principal", "expireAt"]),
            Some(StoreKind::TicketRegistry)
        );
        // Missing one required column: not a ticket registry.
        assert_eq!(
            recognize_shape(["id", "type", "body", "principal_id"]),
            None
        );
        assert_eq!(
            recognize_shape(["id", "type", "body", "created_at", "expires"]),
            None
        );
        assert_eq!(
            recognize_shape(["AUD_USER", "AUD_RESOURCE", "AUD_ACTION", "AUD_DATE"]),
            Some(StoreKind::AuditTrail)
        );
        assert_eq!(recognize_shape(["AUD_RESOURCE"]), None);
    }

    #[test]
    fn rules_per_store() {
        use ColumnRule::*;
        let t = Some(StoreKind::TicketRegistry);
        for c in ["id", "type", "body", "anything"] {
            assert_eq!(column_rule(t, c), NeverRead, "{c}");
        }
        let a = Some(StoreKind::AuditTrail);
        assert_eq!(column_rule(a, "AUD_RESOURCE"), NeverRead);
        assert_eq!(column_rule(a, "aud_headers"), NeverRead);
        assert_eq!(column_rule(a, "AUD_EXTRA_INFO"), NeverRead);
        assert_eq!(column_rule(a, "client_info.headers.*"), NeverRead);
        assert_eq!(column_rule(a, "resourceOperatedUpon"), NeverRead);
        assert_eq!(column_rule(a, "AUD_USER"), NoMaskedSamples);
        assert_eq!(column_rule(a, "principal"), NoMaskedSamples);
        assert_eq!(column_rule(a, "AUD_CLIENT_IP"), Sampled);
        let s = Some(StoreKind::ServiceRegistry);
        assert_eq!(column_rule(s, "body"), NoSamplesNoSecretFingerprints);
        assert_eq!(column_rule(s, "BODY"), NoSamplesNoSecretFingerprints);
        assert_eq!(column_rule(s, "serviceId"), Sampled);
        assert_eq!(
            document_rule(s, "contacts[].email"),
            NoSamplesNoSecretFingerprints
        );
        assert_eq!(document_rule(a, "AUD_RESOURCE"), NeverRead);
        assert_eq!(column_rule(None, "AUD_RESOURCE"), Sampled);
    }

    #[test]
    fn service_definitions_are_recognized_by_class() {
        assert!(is_service_definition(
            r#"{"@class":"org.apereo.cas.services.CasRegisteredService","serviceId":"^https://a.example.org/.*","id":1}"#
        ));
        assert!(is_service_definition(
            r#"  {"id":2,"@class":"org.apereo.cas.services.OidcRegisteredService","clientSecret":"x"}"#
        ));
        for t in [
            "",
            "plain description",
            r#"{"@class":"java.util.HashMap"}"#,
            r#"{"class":"org.apereo.cas.services.CasRegisteredService"}"#,
            r#"{"@class":"org.apereo.cas.services.CasRegisteredService""#,
            r#"["@class"]"#,
        ] {
            assert!(!is_service_definition(t), "{t}");
        }
    }

    #[test]
    fn credential_columns() {
        let t = StoreKind::TicketRegistry;
        for c in [
            "ID",
            "parent_id",
            "BODY",
            "principal_id",
            "ATTRIBUTES",
            "unknown",
        ] {
            assert!(is_credential_column(t, c), "{c}");
        }
        for c in ["TYPE", "creation_time", "EXPIRATION_TIME", "last_used_time"] {
            assert!(!is_credential_column(t, c), "{c}");
        }
        let a = StoreKind::AuditTrail;
        assert!(is_credential_column(a, "AUD_RESOURCE"));
        assert!(is_credential_column(a, "AUD_HEADERS"));
        assert!(!is_credential_column(a, "AUD_USER"));
        assert!(!is_credential_column(StoreKind::ServiceRegistry, "body"));
        assert_eq!(ticket_type_column(["ID", "TYPE"]), Some("TYPE"));
        assert_eq!(ticket_type_column(["ID"]), None);
    }

    #[test]
    fn ticket_types_map_to_kinds_and_encryption() {
        use TicketKind::*;
        for (v, k) in [
            ("org.apereo.cas.ticket.TicketGrantingTicketImpl", Tgt),
            ("org.apereo.cas.ticket.ServiceTicketImpl", St),
            ("org.apereo.cas.ticket.proxy.ProxyTicketImpl", Pt),
            ("org.apereo.cas.ticket.proxy.ProxyGrantingTicketImpl", Pgt),
            ("org.apereo.cas.ticket.code.OAuth20DefaultCode", OauthCode),
            (
                "org.apereo.cas.ticket.accesstoken.OAuth20DefaultAccessToken",
                OauthAccessToken,
            ),
            ("OAuth20DefaultRefreshToken", OauthRefreshToken),
            ("TGT", Tgt),
            ("ST", St),
            ("org.apereo.cas.ticket.TransientSessionTicketImpl", Other),
            ("", Other),
        ] {
            assert_eq!(ticket_type(v), TicketType::Clear(k), "{v}");
        }
        assert_eq!(
            ticket_type("org.apereo.cas.ticket.registry.EncodedTicket"),
            TicketType::Encoded
        );
        assert_eq!(
            ticket_type("org.apereo.cas.ticket.registry.DefaultEncodedTicket"),
            TicketType::Encoded
        );
        let mut c = TicketCounts::default();
        c.add("org.apereo.cas.ticket.TicketGrantingTicketImpl", 3);
        c.add("org.apereo.cas.ticket.ServiceTicketImpl", 2);
        c.add("org.apereo.cas.ticket.registry.EncodedTicket", 5);
        assert_eq!(c.unencrypted(), 5);
        assert_eq!(c.encrypted(), 5);
        assert_eq!(c.clear_of(Tgt), 3);
        let mut total = TicketCounts::default();
        total.merge(&c);
        total.merge(&c);
        assert_eq!(total.unencrypted(), 10);
    }

    #[test]
    fn scan_guard_notes_are_counts_only() {
        let g = ScanGuard::default();
        assert!(g.notes().is_empty());
        g.trip();
        g.trip();
        let mut c = TicketCounts::default();
        c.add("ServiceTicketImpl", 4);
        g.add_registry(&c);
        let notes = g.notes();
        assert_eq!(notes.len(), 2);
        assert_eq!(notes[0].code(), crate::NoteCode::CoverageCasGuardTripped);
        assert_eq!(notes[0].count(), Some(2));
        assert_eq!(
            notes[1].code(),
            crate::NoteCode::SecurityTicketRegistryUnencrypted
        );
        assert_eq!(notes[1].count(), Some(4));
        assert!(notes.iter().all(|n| n.labels().is_empty()));
        assert_eq!(g.registries(), 1);
    }
}
