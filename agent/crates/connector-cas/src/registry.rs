//! Names and service matching from parsed service definitions (ADR-0041
//! decisions 4 and 7).
//!
//! - [`field_name`]: a definition path as a Discovery `field`: keys in
//!   snake case, array levels `[]`, keys of data-keyed maps `*`, through
//!   `normalize_field_path` (ADR-0009), e.g. `contacts[].email`,
//!   `attribute_release_policy.allowed_attributes.*[]`.
//! - [`object_name`]: the service `name` normalized; `*` when it may carry
//!   a value, then `service_<id>` from the numeric `id` (normalized too, so
//!   an id of more than six digits stays `*`).
//! - [`ServiceIndex`]: `serviceId` patterns compiled with the `regex`
//!   crate under a size limit, in evaluation order. A pattern that does
//!   not compile (Java-only syntax: look-arounds, possessive quantifiers)
//!   cannot be evaluated: a lookup that reaches it stops with no service
//!   (`*`), since CAS might have matched it (review of #138). A lookup
//!   gives only the entry's type and normalized name: the host it was
//!   given never leaves the agent.
//! - **Client ids** (ADR-0044): each OAuth / OIDC entry's `clientId` is
//!   reduced, when the entry is added, to a keyed tag ([`ClientTag`], a
//!   tag key of the index's own, fresh and random, never persisted nor
//!   sent); the raw client id is not kept. A tag maps to the one entry
//!   holding that client id (exact, case-sensitive bytes); a client id
//!   shared by two entries maps to none. A lookup gives the same type and
//!   normalized name as a `serviceId` match.

use std::collections::HashMap;
use std::collections::hash_map::Entry as MapEntry;

use databastion_classifiers::masking::LocalTagKey;
use databastion_classifiers::names::{
    NormalizedName, PathPart, normalize_field_path, normalize_path,
};
use regex::{Regex, RegexBuilder};

use crate::parse::MAX_CLIENT_ID_BYTES;
use crate::parse::definition::{Definition, Seg, ServiceType};
use crate::parse::url::ServiceHost;

/// Purpose of the index's tag key for client ids.
pub const CLIENT_TAG_PURPOSE: &str = "cas-oauth-client-ids";

/// A keyed tag of an OAuth / OIDC client id (made with the key of the
/// [`ServiceIndex`] that gave it; meaningless for any other index). Never
/// printed, persisted nor sent.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClientTag([u8; 16]);

impl std::fmt::Debug for ClientTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClientTag(<redacted>)")
    }
}

/// An entry of a [`ServiceIndex`] (valid for that index only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryRef(usize);

/// Compiled size limit of one `serviceId` pattern, and of its lazy DFA
/// cache, in bytes.
const PATTERN_SIZE_LIMIT: usize = 64 * 1024;
/// Total budget of compiled patterns per index (review of #138 L6), charged
/// at the worst case of each pattern (both limits): at most 512 patterns
/// are compiled; services beyond are indexed without one (never matched).
pub const PATTERN_BUDGET: usize = 64 * 1024 * 1024;
/// Most services indexed.
pub const MAX_SERVICES: usize = 4096;

/// `camelCase` to `snake_case` (ASCII upper-case letters only).
fn snake(key: &str) -> String {
    let mut out = String::with_capacity(key.len() + 4);
    for (i, c) in key.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 && !out.ends_with('_') {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// The Discovery `field` of a definition path.
#[must_use]
pub fn field_name(path: &[Seg]) -> NormalizedName {
    let keys: Vec<Option<String>> = path
        .iter()
        .map(|s| match s {
            Seg::Key(k) => Some(snake(k)),
            Seg::Wildcard => Some("*".to_owned()),
            Seg::Index => None,
        })
        .collect();
    let parts: Vec<PathPart<'_>> = keys
        .iter()
        .map(|k| k.as_deref().map_or(PathPart::Index, PathPart::Key))
        .collect();
    normalize_field_path(&parts)
}

/// The Discovery `object` of a definition.
#[must_use]
pub fn object_name(def: &Definition) -> NormalizedName {
    let wildcard = NormalizedName::wildcard();
    if let Some(name) = def.name.as_deref() {
        let n = normalize_path(name);
        if n != wildcard {
            return n;
        }
    }
    // A bare number would read as an array index: `service_<id>`.
    def.id
        .map_or(wildcard, |id| normalize_path(&format!("service_{id}")))
}

/// The `serviceId` pattern of an indexed service.
enum Pattern {
    Compiled(Regex),
    /// Does not compile (Java-only syntax): whether it matches is unknown,
    /// so a lookup that reaches it stops with no service.
    Invalid,
    /// Beyond [`PATTERN_BUDGET`]: whether it matches is unknown, so a
    /// lookup that reaches it stops with no service (review of #138: a
    /// lower-priority catch-all must not take its requests).
    Unknown,
}

/// One indexed service.
struct Entry {
    order: i64,
    service_type: ServiceType,
    object: NormalizedName,
    pattern: Pattern,
    /// Tag of the `clientId` (OAuth / OIDC entries only).
    client: Option<ClientTag>,
}

/// The services of a registry, for the audit service match.
pub struct ServiceIndex {
    entries: Vec<Entry>,
    /// Pattern budget charged so far.
    charged: usize,
    /// Tag key of the client ids (`None` when the system random source
    /// failed: no client is then indexed).
    client_key: Option<LocalTagKey>,
    /// Client id tag to its entry (`None`: shared by several entries),
    /// built by [`Self::finish`].
    clients: HashMap<ClientTag, Option<usize>>,
}

impl Default for ServiceIndex {
    /// An empty index with a fresh random client tag key.
    fn default() -> Self {
        Self::with_client_key(databastion_core::audit::ephemeral_tag_key(
            CLIENT_TAG_PURPOSE,
        ))
    }
}

impl std::fmt::Debug for ServiceIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceIndex")
            .field("services", &self.entries.len())
            .field("clients", &self.clients.len())
            .finish()
    }
}

impl ServiceIndex {
    /// An empty index whose client ids are tagged with `key` (tests and
    /// fuzzing: a fixed key; `None`: no client is indexed).
    #[must_use]
    pub fn with_client_key(key: Option<LocalTagKey>) -> Self {
        Self {
            entries: Vec::new(),
            charged: 0,
            client_key: key,
            clients: HashMap::new(),
        }
    }

    /// The tag of a client id: `None` when it is empty or longer than
    /// [`MAX_CLIENT_ID_BYTES`], or the index has no key. Exact bytes.
    #[must_use]
    pub fn client_tag(&self, id: &str) -> Option<ClientTag> {
        if id.is_empty() || id.len() > MAX_CLIENT_ID_BYTES {
            return None;
        }
        let t = self
            .client_key
            .as_ref()?
            .tag(&[b"cas/oauth-client-id\0", id.as_bytes()]);
        let mut out = [0u8; 16];
        for (o, b) in out.iter_mut().zip(t.iter()) {
            *o = *b;
        }
        Some(ClientTag(out))
    }

    /// The one entry whose `clientId` has this tag (`None` when no entry,
    /// or several, hold it).
    #[must_use]
    pub fn client(&self, tag: ClientTag) -> Option<EntryRef> {
        self.clients.get(&tag).copied().flatten().map(EntryRef)
    }

    /// An entry's type and normalized name, as [`Self::lookup`] gives them.
    #[must_use]
    pub fn entry(&self, r: EntryRef) -> Option<(ServiceType, &NormalizedName)> {
        self.entries.get(r.0).map(|e| (e.service_type, &e.object))
    }

    /// Indexes `defs` (at most [`MAX_SERVICES`]), in evaluation order.
    #[must_use]
    pub fn new<'a>(defs: impl IntoIterator<Item = &'a Definition>) -> Self {
        let mut idx = Self::default();
        for d in defs {
            let _ = idx.add(d);
        }
        idx.finish();
        idx
    }

    /// Adds one service; call [`Self::finish`] once every service is
    /// added. `false` when it is beyond [`MAX_SERVICES`] or its pattern is
    /// beyond [`PATTERN_BUDGET`] (not indexed, or indexed without a
    /// pattern).
    pub fn add(&mut self, d: &Definition) -> bool {
        if self.entries.len() >= MAX_SERVICES {
            return false;
        }
        let cost = 2 * PATTERN_SIZE_LIMIT;
        let within = self.charged.saturating_add(cost) <= PATTERN_BUDGET;
        let pattern = if within {
            self.charged += cost;
            RegexBuilder::new(&d.service_id)
                .size_limit(PATTERN_SIZE_LIMIT)
                .dfa_size_limit(PATTERN_SIZE_LIMIT)
                .build()
                .map_or(Pattern::Invalid, Pattern::Compiled)
        } else {
            Pattern::Unknown
        };
        let client = match d.service_type {
            ServiceType::Oauth | ServiceType::Oidc => {
                d.client_id.as_deref().and_then(|id| self.client_tag(id))
            }
            _ => None,
        };
        self.entries.push(Entry {
            order: d.evaluation_order.unwrap_or(i64::MAX),
            service_type: d.service_type,
            object: object_name(d),
            pattern,
            client,
        });
        within
    }

    /// Sorts the services in evaluation order (stable: file order for
    /// equal orders) and maps the client id tags to their entries.
    pub fn finish(&mut self) {
        self.entries.sort_by_key(|e| e.order);
        self.clients.clear();
        for (i, e) in self.entries.iter().enumerate() {
            if let Some(t) = e.client {
                match self.clients.entry(t) {
                    MapEntry::Vacant(v) => {
                        v.insert(Some(i));
                    }
                    MapEntry::Occupied(mut o) => {
                        o.insert(None);
                    }
                }
            }
        }
    }

    /// Services indexed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no service is indexed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The first service (in evaluation order) whose pattern matches
    /// `scheme://host/`: its type and normalized name. `None` when none
    /// matches, or when a service whose pattern could not be compiled
    /// (Java-only syntax, or beyond the budget) comes first (it might
    /// match).
    #[must_use]
    pub fn lookup(&self, host: &ServiceHost) -> Option<(ServiceType, &NormalizedName)> {
        let url = host.as_url();
        for e in &self.entries {
            match &e.pattern {
                Pattern::Compiled(p) if p.is_match(&url) => {
                    return Some((e.service_type, &e.object));
                }
                Pattern::Compiled(_) => {}
                Pattern::Invalid | Pattern::Unknown => return None,
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::definition::parse_definition;
    use crate::parse::url::service_of;

    fn def(json: &str) -> Definition {
        parse_definition(json.as_bytes()).unwrap()
    }

    #[test]
    fn fields_are_snake_case_with_wildcards() {
        let k = |s: &str| Seg::Key(s.to_owned());
        assert_eq!(
            field_name(&[k("contacts"), Seg::Index, k("email")]).as_str(),
            "contacts[].email"
        );
        assert_eq!(
            field_name(&[
                k("attributeReleasePolicy"),
                k("allowedAttributes"),
                Seg::Wildcard,
                Seg::Index
            ])
            .as_str(),
            "attribute_release_policy.allowed_attributes.*[]"
        );
        assert_eq!(
            field_name(&[k("properties"), Seg::Wildcard, k("values"), Seg::Index]).as_str(),
            "properties.*.values[]"
        );
        assert_eq!(field_name(&[k("serviceId")]).as_str(), "service_id");
        assert_eq!(field_name(&[k("jane.doe@example.org")]).as_str(), "*");
        assert_eq!(snake("URLValue"), "u_r_l_value");
    }

    #[test]
    fn objects_fall_back_to_the_id() {
        let base = r#""@class": "org.apereo.cas.services.CasRegisteredService", "serviceId": "x""#;
        assert_eq!(
            object_name(&def(&format!(
                "{{{base}, \"name\": \"HR-Portal\", \"id\": 3}}"
            )))
            .as_str(),
            "HR-Portal"
        );
        assert_eq!(
            object_name(&def(&format!(
                "{{{base}, \"name\": \"jane.doe@example.org\", \"id\": 3}}"
            )))
            .as_str(),
            "service_3"
        );
        assert_eq!(
            object_name(&def(&format!("{{{base}, \"id\": 10000003}}"))).as_str(),
            "*"
        );
        assert_eq!(object_name(&def(&format!("{{{base}}}"))).as_str(), "*");
    }

    /// Client ids (ADR-0044): OAuth / OIDC entries only, exact bytes, a
    /// shared one selects nothing, the raw value is not kept.
    #[test]
    fn client_ids_select_one_oauth_entry() {
        let mk = |class: &str, name: &str, client: &str, order: i64| {
            def(&format!(
                r#"{{"@class": "{class}", "name": "{name}", "serviceId": "^https://x/$",
                    "clientId": {client}, "evaluationOrder": {order}}}"#
            ))
        };
        let oidc = "org.apereo.cas.services.OidcRegisteredService";
        let oauth = "org.apereo.cas.support.oauth.services.OAuthRegisteredService";
        let long = format!("\"{}\"", "c".repeat(MAX_CLIENT_ID_BYTES + 1));
        let defs = [
            mk(oidc, "Late", r#""mixed-Case""#, 90),
            mk(oauth, "Early", r#""batch-job""#, 10),
            mk(oidc, "Dup-A", r#""shared""#, 20),
            mk(oauth, "Dup-B", r#""shared""#, 30),
            mk(
                "org.apereo.cas.services.CasRegisteredService",
                "Cas",
                r#""cas-client""#,
                40,
            ),
            mk(oidc, "Long", &long, 50),
            mk(oidc, "Number", "3", 60),
        ];
        let idx = ServiceIndex::new(&defs);
        let name = |id: &str| {
            let t = idx.client_tag(id)?;
            let r = idx.client(t)?;
            idx.entry(r)
                .map(|(t, o)| format!("{}.{}", t.as_str(), o.as_str()))
        };
        // Evaluation order does not change which entry a client id selects.
        assert_eq!(name("batch-job").as_deref(), Some("oauth.Early"));
        assert_eq!(name("mixed-Case").as_deref(), Some("oidc.Late"));
        for none in ["mixed-case", "batch-job ", "shared", "cas-client", "3", ""] {
            assert_eq!(name(none), None, "{none:?}");
        }
        assert_eq!(name(&"c".repeat(MAX_CLIENT_ID_BYTES + 1)), None);
        // Tags are keyed per index: another index's tag selects nothing.
        let other = ServiceIndex::new(&defs);
        let t = other.client_tag("batch-job").unwrap();
        assert!(idx.client(t).is_none());
        // No key: no client.
        let mut keyless = ServiceIndex::with_client_key(None);
        let _ = keyless.add(&defs[1]);
        keyless.finish();
        assert!(keyless.client_tag("batch-job").is_none());
        let dbg = format!("{idx:?} {t:?}");
        for leak in ["batch", "shared", "mixed"] {
            assert!(!dbg.contains(leak), "{leak}");
        }
    }

    #[test]
    fn services_match_in_evaluation_order() {
        let mk = |name: &str, pattern: &str, order: i64| {
            def(&format!(
                r#"{{"@class": "org.apereo.cas.services.CasRegisteredService", "name": "{name}",
                    "serviceId": "{pattern}", "evaluationOrder": {order}}}"#
            ))
        };
        let defs = [
            mk("Catch-All", "^https://.*", 100),
            mk("HR", "^https://hr\\\\.example\\\\.org/.*", 1),
            mk("Java-Only", "^https://(?=x).*", 200),
        ];
        let idx = ServiceIndex::new(&defs);
        assert_eq!(idx.len(), 3);
        // A pattern that does not compile, first in evaluation order,
        // stops the lookup: CAS may have matched it.
        let first = mk("Java-First", "^https://(?=x).*", 0);
        let invalid_first = ServiceIndex::new([&first, &defs[0], &defs[1]]);
        assert!(
            invalid_first
                .lookup(&service_of("https://hr.example.org/x").unwrap())
                .is_none()
        );
        let mut big = ServiceIndex::default();
        let budget = PATTERN_BUDGET / (2 * PATTERN_SIZE_LIMIT);
        for i in 0..budget {
            assert!(big.add(&defs[2]), "{i}");
        }
        // Beyond the budget, a high-priority service (order 1) has no
        // pattern: the catch-all (order 100) does not take its requests.
        assert!(!big.add(&defs[1]));
        assert!(!big.add(&defs[0]));
        big.finish();
        assert!(
            big.lookup(&service_of("https://hr.example.org/x").unwrap())
                .is_none()
        );
        let host = |u: &str| service_of(u).unwrap();
        let (t, o) = idx.lookup(&host("https://hr.example.org/x")).unwrap();
        assert_eq!((t, o.as_str()), (ServiceType::Cas, "HR"));
        assert_eq!(
            idx.lookup(&host("https://wiki.example.org/"))
                .unwrap()
                .1
                .as_str(),
            "Catch-All"
        );
        assert!(idx.lookup(&host("http://wiki.example.org/")).is_none());
    }
}
