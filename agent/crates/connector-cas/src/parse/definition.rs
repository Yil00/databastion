//! CAS service definitions (JSON or YAML), read through a closed, bounded
//! serde visitor (ADR-0041 decision 4). Never through a generic
//! `serde_json::Value`: nodes are counted while deserializing (depth at
//! most [`MAX_DEPTH`], at most [`MAX_NODES`] nodes and [`MAX_ARRAY_ITEMS`]
//! array items per file), strings are cut to [`MAX_STRING_BYTES`] on a
//! character boundary.
//!
//! - A document is a service definition only when its top-level object has
//!   an `@class` of the closed map ([`ServiceType::from_class`]) and a
//!   string `serviceId`; otherwise [`DefinitionError::NotDefinition`] and
//!   none of its values is kept for classification.
//! - **Credential fields are never sampled**: `clientSecret`, and every key
//!   whose raw name contains (case-insensitively) one of
//!   [`CREDENTIAL_WORDS`], before any `*` collapsing. Their value and
//!   everything below it is skipped with `IgnoredAny` (never copied). For
//!   the top-level `clientSecret`, only its [`SecretForm`] is recorded,
//!   from the borrowed text, without allocating it.
//! - URLs are kept only after removing their userinfo, query string and
//!   fragment ([`super::url::strip_credentials`]).
//! - Keys of data-keyed maps (`properties`, attribute maps) collapse to
//!   `*`; Jackson type-name strings (`java.util.ArrayList`) are skipped and
//!   their typed arrays read as plain arrays.
//! - A duplicate top-level `@class`, `serviceId`, `name`, `id`,
//!   `evaluationOrder` or `clientSecret` refuses the document.
//!
//! Comments are not accepted (whether CAS 8.0 still accepts them in JSON
//! definitions is to verify, ADR-0041 decision 4): a file with comments
//! does not parse and is skipped.
//!
//! **YAML** ([`parse_yaml_definition`]): the bytes are first pre-scanned
//! ([`super::yaml::prescan`]: anchors, aliases, merge keys, tags other
//! than CAS class hints, directives and second documents refused before
//! any parsing), then the copy with its class hints blanked goes through
//! the same visitor with `serde_yaml_ng`. The class is the root node's tag
//! (`--- !<org.apereo.cas.…>`, what CAS 8.0.2 requires); a top-level
//! `@class` key next to it refuses the document. YAML resolves unquoted
//! digits to integers (`phone: 33612345678`, a card number): below the
//! top level they are classified as their decimal text, which drops a
//! leading `+`, a `0x` / `0o` prefix or `_` separators' meaning; a number
//! with a leading zero stays a string. Floats are not classified. JSON
//! numbers are never classified (unchanged).

use std::fmt;

use serde::de::{self, DeserializeSeed, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use zeroize::Zeroizing;

use super::url::strip_credentials;
use super::yaml::{self, Refusal};
use super::{bounded_owned, is_java_type};

pub use databastion_core::config::cas::RegistryFormat;

/// Deepest nesting (the top-level object is depth 1).
pub const MAX_DEPTH: usize = 32;
/// Most JSON nodes (values) per file.
pub const MAX_NODES: usize = 65_536;
/// Most array items per file.
pub const MAX_ARRAY_ITEMS: usize = 4096;
/// Longest string kept, in bytes (cut on a character boundary).
pub const MAX_STRING_BYTES: usize = 4096;
/// Longest key kept in a path, in bytes (longer: `*`).
const MAX_KEY_BYTES: usize = 256;

/// Substrings that make a key a credential (security review M2, review of
/// #138 M2): compared case-insensitively on the raw key. `header` skips
/// every HTTP header map or list (`headers`, `httpHeaders`: `Authorization`,
/// `Cookie` values) whatever its shape. Over-exclusion (`keyAlias`,
/// `tokenExpiration`, `authenticationPolicy`, `bypass…`) is accepted.
pub const CREDENTIAL_WORDS: [&str; 19] = [
    "secret",
    "password",
    "passwd",
    "pass",
    "pwd",
    "key",
    "token",
    "credential",
    "jwk",
    "private",
    "keystore",
    "authorization",
    "auth",
    "cookie",
    "bearer",
    "salt",
    "cipher",
    "signing",
    "header",
];

/// Keys whose children are data (names chosen by the operator), collapsed
/// to `*` in paths (as MongoDB field paths, ADR-0026 decision 8).
const DATA_KEYED_MAPS: [&str; 6] = [
    "properties",
    "requiredAttributes",
    "rejectedAttributes",
    "allowedAttributes",
    "attributes",
    "metadata",
];

/// Top-level keys kept by the parser: each at most once.
const KEPT_TOP_KEYS: [&str; 6] = [
    "@class",
    "serviceId",
    "name",
    "id",
    "evaluationOrder",
    "clientSecret",
];

/// Structural string keys, never sampled (enums, class names).
const STRUCTURAL_KEYS: [&str; 4] = ["@class", "logoutType", "responseType", "timeUnit"];

/// Whether a raw key names a credential field.
#[must_use]
pub fn is_credential_key(key: &str) -> bool {
    CREDENTIAL_WORDS.iter().any(|w| {
        key.as_bytes()
            .windows(w.len())
            .any(|win| win.eq_ignore_ascii_case(w.as_bytes()))
    })
}

/// Service type, from the closed map of `@class` (the Discovery schema).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ServiceType {
    /// `CasRegisteredService` (and the older `RegexRegisteredService`).
    Cas,
    /// `OAuthRegisteredService`.
    Oauth,
    /// `OidcRegisteredService`.
    Oidc,
    /// `SamlRegisteredService`.
    Saml,
    /// `WSFederationRegisteredService`.
    WsFederation,
    /// Another `org.apereo.cas.…RegisteredService`.
    Other,
}

impl ServiceType {
    /// The type of a fully qualified `@class`; `None` when it is not a CAS
    /// registered service class (the document is then not a definition).
    #[must_use]
    pub fn from_class(class: &str) -> Option<Self> {
        Some(match class {
            "org.apereo.cas.services.CasRegisteredService"
            | "org.apereo.cas.services.RegexRegisteredService" => Self::Cas,
            "org.apereo.cas.support.oauth.services.OAuthRegisteredService" => Self::Oauth,
            "org.apereo.cas.services.OidcRegisteredService" => Self::Oidc,
            "org.apereo.cas.support.saml.services.SamlRegisteredService" => Self::Saml,
            "org.apereo.cas.ws.idp.services.WSFederationRegisteredService" => Self::WsFederation,
            other => {
                let simple = other.strip_prefix("org.apereo.cas.")?.rsplit('.').next()?;
                let ok = simple.ends_with("RegisteredService")
                    && other
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_');
                return ok.then_some(Self::Other);
            }
        })
    }

    /// The Discovery schema name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cas => "cas",
            Self::Oauth => "oauth",
            Self::Oidc => "oidc",
            Self::Saml => "saml",
            Self::WsFederation => "ws_federation",
            Self::Other => "other",
        }
    }
}

/// What the top-level `clientSecret` holds. Nothing of the value itself is
/// kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SecretForm {
    /// Absent, null or empty.
    #[default]
    Absent,
    /// A reference resolved at run time (`${…}`, `#{…}`).
    Reference,
    /// The output of a cipher executor (a five-segment compact JWE, or a
    /// `{cipher}` value; the exact CAS 8.0 shape is to verify).
    Encrypted,
    /// Anything else: a secret in clear.
    Clear,
}

impl SecretForm {
    /// The form of a secret text (borrowed; never copied).
    #[must_use]
    pub fn of(s: &str) -> Self {
        let t = s.trim();
        if t.is_empty() {
            return Self::Absent;
        }
        if (t.starts_with("${") || t.starts_with("#{")) && t.ends_with('}') {
            return Self::Reference;
        }
        if t.starts_with("{cipher}") {
            return Self::Encrypted;
        }
        // A compact JWE (five segments) only: a three-segment JWS is
        // signed, not encrypted (even `alg: none`), so it counts as clear.
        let compact = t.starts_with("eyJ")
            && t.split('.').count() == 5
            && t.split('.').all(|p| {
                p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            });
        if compact {
            Self::Encrypted
        } else {
            Self::Clear
        }
    }
}

/// One segment of a field path.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Seg {
    /// An object key (bounded).
    Key(String),
    /// A key of a data-keyed map, or a key too long to keep.
    Wildcard,
    /// An array level.
    Index,
}

impl fmt::Debug for Seg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Key(k) => write!(f, "{k}"),
            Self::Wildcard => f.write_str("*"),
            Self::Index => f.write_str("[]"),
        }
    }
}

/// A string value of a definition, to be classified, with its path.
pub struct Sampled {
    /// Path from the top-level object.
    pub path: Vec<Seg>,
    /// The value (URLs already stripped of their credentials).
    pub value: Zeroizing<String>,
}

impl fmt::Debug for Sampled {
    // The value is never printed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sampled")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

/// A parsed service definition.
pub struct Definition {
    /// From `@class`.
    pub service_type: ServiceType,
    /// `name` (bounded), when a string.
    pub name: Option<Zeroizing<String>>,
    /// Numeric `id`.
    pub id: Option<i64>,
    /// `evaluationOrder`.
    pub evaluation_order: Option<i64>,
    /// The raw `serviceId` pattern (bounded), for the audit service match
    /// only; its stripped form is in `values`.
    pub service_id: Zeroizing<String>,
    /// Form of the top-level `clientSecret`.
    pub client_secret: SecretForm,
    /// String values to classify (credential and structural fields
    /// excluded).
    pub values: Vec<Sampled>,
}

impl fmt::Debug for Definition {
    // Values, names and patterns are never printed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Definition")
            .field("service_type", &self.service_type)
            .field("client_secret", &self.client_secret)
            .field("values", &self.values.len())
            .finish_non_exhaustive()
    }
}

/// Why a document is not used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefinitionError {
    /// Valid JSON, but no `@class` of the closed map or no `serviceId` (or
    /// not an object).
    NotDefinition,
    /// Not valid JSON, a duplicate top-level key, or trailing data.
    Malformed,
    /// Beyond a structural bound (depth, nodes, array items; for YAML
    /// also lines and flow nesting).
    Bounds,
    /// YAML outside the accepted subset (an anchor, an alias, a merge key,
    /// a tag other than a class hint, a directive, a second document…),
    /// refused by the pre-scan before any parsing.
    Refused,
}

impl From<Refusal> for DefinitionError {
    fn from(r: Refusal) -> Self {
        match r {
            Refusal::NotCas => Self::NotDefinition,
            Refusal::Bounds => Self::Bounds,
            Refusal::Encoding
            | Refusal::Anchor
            | Refusal::Alias
            | Refusal::Tag
            | Refusal::MergeKey
            | Refusal::Directive
            | Refusal::Documents
            | Refusal::ComplexKey
            | Refusal::Syntax => Self::Refused,
        }
    }
}

/// Parses one service definition file of a registry in `format`.
///
/// # Errors
/// [`DefinitionError`]; nothing of a refused document is returned.
pub fn parse_registry_file(
    format: RegistryFormat,
    bytes: &[u8],
) -> Result<Definition, DefinitionError> {
    match format {
        RegistryFormat::Json => parse_definition(bytes),
        RegistryFormat::Yaml => parse_yaml_definition(bytes),
    }
}

/// Parses one YAML service definition file: pre-scanned, then read by the
/// same visitor as JSON (see the module documentation).
///
/// # Errors
/// [`DefinitionError`]; nothing of a refused document is returned.
pub fn parse_yaml_definition(bytes: &[u8]) -> Result<Definition, DefinitionError> {
    let pre = yaml::prescan(bytes)?;
    let de = serde_yaml_ng::Deserializer::from_slice(&pre.text);
    // The by-value deserializer refuses a stream of several documents.
    parse_with(de, Some(pre.class))
}

/// Parses one service definition file.
///
/// # Errors
/// [`DefinitionError`]; nothing of a refused document is returned.
pub fn parse_definition(bytes: &[u8]) -> Result<Definition, DefinitionError> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let top = parse_with(&mut de, None)?;
    if de.end().is_err() {
        return Err(DefinitionError::Malformed);
    }
    Ok(top)
}

/// The visitor over any deserializer; `root_class` is the class given
/// outside the mapping (the YAML root tag), in which case an `@class` key
/// refuses the document.
fn parse_with<'de, D: Deserializer<'de>>(
    de: D,
    root_class: Option<String>,
) -> Result<Definition, DefinitionError> {
    let preset = root_class.is_some();
    // YAML resolves unquoted digits to integers: on that path they are
    // classified as their decimal text (JSON numbers stay unsampled).
    let mut ctx = Ctx {
        numbers_as_text: preset,
        ..Ctx::default()
    };
    let top = de.deserialize_any(TopVisitor {
        ctx: &mut ctx,
        preset_class: preset,
    });
    let top = match top {
        Ok(t) => t,
        Err(_) => {
            return Err(ctx.error.unwrap_or(DefinitionError::Malformed));
        }
    };
    let Top::Object(top) = top else {
        return Err(DefinitionError::NotDefinition);
    };
    let class = if preset { root_class } else { top.class };
    let service_type = class
        .as_deref()
        .and_then(ServiceType::from_class)
        .ok_or(DefinitionError::NotDefinition)?;
    let service_id = top.service_id.ok_or(DefinitionError::NotDefinition)?;
    Ok(Definition {
        service_type,
        name: top.name,
        id: top.id,
        evaluation_order: top.evaluation_order,
        service_id,
        client_secret: top.client_secret,
        values: ctx.values,
    })
}

#[derive(Default)]
struct Ctx {
    /// Integers are sampled as their decimal text (YAML only).
    numbers_as_text: bool,
    path: Vec<Seg>,
    depth: usize,
    nodes: usize,
    array_items: usize,
    values: Vec<Sampled>,
    /// The first bound or duplicate hit (serde errors carry text only).
    error: Option<DefinitionError>,
}

impl Ctx {
    fn fail<E: de::Error>(&mut self, e: DefinitionError) -> E {
        self.error.get_or_insert(e);
        E::custom("refused")
    }

    fn node<E: de::Error>(&mut self) -> Result<(), E> {
        self.nodes += 1;
        if self.nodes > MAX_NODES {
            return Err(self.fail(DefinitionError::Bounds));
        }
        Ok(())
    }

    fn enter<E: de::Error>(&mut self) -> Result<(), E> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(self.fail(DefinitionError::Bounds));
        }
        Ok(())
    }

    fn item<E: de::Error>(&mut self) -> Result<(), E> {
        self.array_items += 1;
        if self.array_items > MAX_ARRAY_ITEMS {
            return Err(self.fail(DefinitionError::Bounds));
        }
        Ok(())
    }

    /// An integer node: sampled as text on the YAML path.
    fn number(&mut self, text: impl FnOnce() -> String) {
        if self.numbers_as_text {
            let t = Zeroizing::new(text());
            self.sample(&t);
        }
    }

    fn sample(&mut self, s: &str) {
        if is_java_type(s) {
            return;
        }
        let stripped = strip_credentials(s);
        let value = bounded_owned(&stripped, MAX_STRING_BYTES);
        drop(stripped);
        if value.trim().is_empty() {
            return;
        }
        self.values.push(Sampled {
            path: self.path.clone(),
            value,
        });
    }
}

/// The top-level fields kept.
#[derive(Default)]
struct TopFields {
    class: Option<String>,
    service_id: Option<Zeroizing<String>>,
    name: Option<Zeroizing<String>>,
    id: Option<i64>,
    evaluation_order: Option<i64>,
    client_secret: SecretForm,
}

enum Top {
    Object(TopFields),
    Other,
}

/// A key and whether it names a credential, read from the borrowed text.
struct Key {
    text: Option<String>,
    credential: bool,
}

struct KeySeed;

impl<'de> DeserializeSeed<'de> for KeySeed {
    type Value = Key;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Key, D::Error> {
        d.deserialize_str(KeySeed)
    }
}

impl Visitor<'_> for KeySeed {
    type Value = Key;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a key")
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Key, E> {
        Ok(Key {
            text: (v.len() <= MAX_KEY_BYTES).then(|| v.to_owned()),
            credential: is_credential_key(v),
        })
    }
}

struct TopVisitor<'a> {
    ctx: &'a mut Ctx,
    /// The class came from outside the mapping: `@class` refuses.
    preset_class: bool,
}

impl<'de> Visitor<'de> for TopVisitor<'_> {
    type Value = Top;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a service definition")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Top, A::Error> {
        let ctx = self.ctx;
        let preset_class = self.preset_class;
        ctx.node()?;
        ctx.enter()?;
        let mut top = TopFields::default();
        // Top-level keys kept are seen once at most: a second `@class` or
        // `serviceId` could otherwise override the first.
        let mut seen = [false; KEPT_TOP_KEYS.len()];
        while let Some(key) = map.next_key_seed(KeySeed)? {
            let Some(name) = key.text.as_deref() else {
                // An over-long key: its value is skipped.
                map.next_value::<IgnoredAny>()?;
                continue;
            };
            if let Some(i) = KEPT_TOP_KEYS.iter().position(|k| *k == name) {
                if seen.get(i).copied().unwrap_or(true) {
                    return Err(ctx.fail(DefinitionError::Malformed));
                }
                if let Some(s) = seen.get_mut(i) {
                    *s = true;
                }
            }
            match name {
                "@class" if preset_class => return Err(ctx.fail(DefinitionError::Malformed)),
                "@class" => {
                    top.class = map.next_value::<MaybeStr>()?.0.map(|b| b.to_string());
                }
                "clientSecret" => {
                    top.client_secret = map.next_value::<FormOf>()?.0;
                }
                "id" => top.id = map.next_value::<Number>()?.0,
                "evaluationOrder" => top.evaluation_order = map.next_value::<Number>()?.0,
                "serviceId" | "name" => {
                    let Some(raw) = map.next_value::<MaybeStr>()?.0 else {
                        continue;
                    };
                    ctx.path.push(Seg::Key(name.to_owned()));
                    ctx.node()?;
                    ctx.sample(&raw);
                    ctx.path.pop();
                    if name == "serviceId" {
                        top.service_id = Some(raw);
                    } else {
                        top.name = Some(raw);
                    }
                }
                _ if key.credential || STRUCTURAL_KEYS.contains(&name) => {
                    map.next_value::<IgnoredAny>()?;
                }
                _ => {
                    ctx.path.push(Seg::Key(name.to_owned()));
                    map.next_value_seed(Node {
                        ctx: &mut *ctx,
                        collapse: DATA_KEYED_MAPS.contains(&name),
                    })?;
                    ctx.path.pop();
                }
            }
        }
        ctx.depth -= 1;
        Ok(Top::Object(top))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Top, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(Top::Other)
    }

    fn visit_str<E: de::Error>(self, _: &str) -> Result<Top, E> {
        Ok(Top::Other)
    }
    fn visit_bool<E: de::Error>(self, _: bool) -> Result<Top, E> {
        Ok(Top::Other)
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<Top, E> {
        Ok(Top::Other)
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> Result<Top, E> {
        Ok(Top::Other)
    }
    fn visit_i128<E: de::Error>(self, _: i128) -> Result<Top, E> {
        Ok(Top::Other)
    }
    fn visit_u128<E: de::Error>(self, _: u128) -> Result<Top, E> {
        Ok(Top::Other)
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Top, E> {
        Ok(Top::Other)
    }
    fn visit_unit<E: de::Error>(self) -> Result<Top, E> {
        Ok(Top::Other)
    }
}

/// A string cut to [`MAX_STRING_BYTES`]; `None` for any other JSON type
/// (skipped without being kept).
struct MaybeStr(Option<Zeroizing<String>>);

impl<'de> de::Deserialize<'de> for MaybeStr {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = MaybeStr;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a string")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<MaybeStr, E> {
                Ok(MaybeStr(Some(bounded_owned(v, MAX_STRING_BYTES))))
            }
            fn visit_bool<E: de::Error>(self, _: bool) -> Result<MaybeStr, E> {
                Ok(MaybeStr(None))
            }
            fn visit_i64<E: de::Error>(self, _: i64) -> Result<MaybeStr, E> {
                Ok(MaybeStr(None))
            }
            fn visit_u64<E: de::Error>(self, _: u64) -> Result<MaybeStr, E> {
                Ok(MaybeStr(None))
            }
            fn visit_i128<E: de::Error>(self, _: i128) -> Result<MaybeStr, E> {
                Ok(MaybeStr(None))
            }
            fn visit_u128<E: de::Error>(self, _: u128) -> Result<MaybeStr, E> {
                Ok(MaybeStr(None))
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> Result<MaybeStr, E> {
                Ok(MaybeStr(None))
            }
            fn visit_unit<E: de::Error>(self) -> Result<MaybeStr, E> {
                Ok(MaybeStr(None))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<MaybeStr, A::Error> {
                while seq.next_element::<IgnoredAny>()?.is_some() {}
                Ok(MaybeStr(None))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<MaybeStr, A::Error> {
                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                Ok(MaybeStr(None))
            }
        }
        d.deserialize_any(V)
    }
}

/// A number (`None` for any other JSON type).
struct Number(Option<i64>);

impl<'de> de::Deserialize<'de> for Number {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Number;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a number")
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Number, E> {
                Ok(Number(Some(v)))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Number, E> {
                Ok(Number(i64::try_from(v).ok()))
            }
            fn visit_i128<E: de::Error>(self, v: i128) -> Result<Number, E> {
                Ok(Number(i64::try_from(v).ok()))
            }
            fn visit_u128<E: de::Error>(self, v: u128) -> Result<Number, E> {
                Ok(Number(i64::try_from(v).ok()))
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> Result<Number, E> {
                Ok(Number(None))
            }
            fn visit_str<E: de::Error>(self, _: &str) -> Result<Number, E> {
                Ok(Number(None))
            }
            fn visit_bool<E: de::Error>(self, _: bool) -> Result<Number, E> {
                Ok(Number(None))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Number, E> {
                Ok(Number(None))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Number, A::Error> {
                while seq.next_element::<IgnoredAny>()?.is_some() {}
                Ok(Number(None))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Number, A::Error> {
                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                Ok(Number(None))
            }
        }
        d.deserialize_any(V)
    }
}

/// The [`SecretForm`] of a value, from its borrowed text.
struct FormOf(SecretForm);

impl<'de> de::Deserialize<'de> for FormOf {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = FormOf;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a client secret")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<FormOf, E> {
                Ok(FormOf(SecretForm::of(v)))
            }
            fn visit_unit<E: de::Error>(self) -> Result<FormOf, E> {
                Ok(FormOf(SecretForm::Absent))
            }
            // Any other shape is not a reference nor a cipher output:
            // counted as clear, never read further.
            fn visit_bool<E: de::Error>(self, _: bool) -> Result<FormOf, E> {
                Ok(FormOf(SecretForm::Clear))
            }
            fn visit_i64<E: de::Error>(self, _: i64) -> Result<FormOf, E> {
                Ok(FormOf(SecretForm::Clear))
            }
            fn visit_u64<E: de::Error>(self, _: u64) -> Result<FormOf, E> {
                Ok(FormOf(SecretForm::Clear))
            }
            fn visit_i128<E: de::Error>(self, _: i128) -> Result<FormOf, E> {
                Ok(FormOf(SecretForm::Clear))
            }
            fn visit_u128<E: de::Error>(self, _: u128) -> Result<FormOf, E> {
                Ok(FormOf(SecretForm::Clear))
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> Result<FormOf, E> {
                Ok(FormOf(SecretForm::Clear))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<FormOf, A::Error> {
                while seq.next_element::<IgnoredAny>()?.is_some() {}
                Ok(FormOf(SecretForm::Clear))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<FormOf, A::Error> {
                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                Ok(FormOf(SecretForm::Clear))
            }
        }
        d.deserialize_any(V)
    }
}

/// What a nested node was (to read Jackson typed arrays).
#[derive(PartialEq, Eq)]
enum NodeKind {
    JavaType,
    Other,
}

/// A nested value, walked with the shared context.
struct Node<'a> {
    ctx: &'a mut Ctx,
    /// Keys of this map (when it is one) collapse to `*`.
    collapse: bool,
}

impl<'de> DeserializeSeed<'de> for Node<'_> {
    type Value = NodeKind;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<NodeKind, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Node<'_> {
    type Value = NodeKind;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<NodeKind, E> {
        self.ctx.node()?;
        if is_java_type(v) {
            return Ok(NodeKind::JavaType);
        }
        self.ctx.sample(v);
        Ok(NodeKind::Other)
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<NodeKind, E> {
        self.ctx.node()?;
        Ok(NodeKind::Other)
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<NodeKind, E> {
        self.ctx.node()?;
        self.ctx.number(|| v.to_string());
        Ok(NodeKind::Other)
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<NodeKind, E> {
        self.ctx.node()?;
        self.ctx.number(|| v.to_string());
        Ok(NodeKind::Other)
    }
    // Integers beyond 64 bits (YAML: 20 digits or more; never from JSON
    // without `arbitrary_precision`).
    fn visit_i128<E: de::Error>(self, v: i128) -> Result<NodeKind, E> {
        self.ctx.node()?;
        self.ctx.number(|| v.to_string());
        Ok(NodeKind::Other)
    }
    fn visit_u128<E: de::Error>(self, v: u128) -> Result<NodeKind, E> {
        self.ctx.node()?;
        self.ctx.number(|| v.to_string());
        Ok(NodeKind::Other)
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<NodeKind, E> {
        self.ctx.node()?;
        Ok(NodeKind::Other)
    }
    fn visit_unit<E: de::Error>(self) -> Result<NodeKind, E> {
        self.ctx.node()?;
        Ok(NodeKind::Other)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<NodeKind, A::Error> {
        let ctx = self.ctx;
        ctx.node()?;
        ctx.enter()?;
        ctx.path.push(Seg::Index);
        let mut first_was_type = false;
        let mut i = 0usize;
        loop {
            // Jackson typed arrays (`["java.util.ArrayList", [ … ]]`): the
            // second element is read at this array's level.
            let typed = i == 1 && first_was_type;
            if typed {
                ctx.path.pop();
            }
            let kind = seq.next_element_seed(Node {
                ctx: &mut *ctx,
                collapse: self.collapse,
            })?;
            if typed {
                ctx.path.push(Seg::Index);
            }
            let Some(kind) = kind else {
                break;
            };
            // Counted once read: the element itself is bounded by the
            // node count and the depth.
            ctx.item()?;
            if i == 0 {
                first_was_type = kind == NodeKind::JavaType;
            }
            i += 1;
        }
        ctx.path.pop();
        ctx.depth -= 1;
        Ok(NodeKind::Other)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<NodeKind, A::Error> {
        let ctx = self.ctx;
        ctx.node()?;
        ctx.enter()?;
        while let Some(key) = map.next_key_seed(KeySeed)? {
            let structural = key
                .text
                .as_deref()
                .is_some_and(|k| STRUCTURAL_KEYS.contains(&k));
            if key.credential || structural {
                map.next_value::<IgnoredAny>()?;
                continue;
            }
            let (seg, collapse) = match key.text {
                Some(_) if self.collapse => (Seg::Wildcard, false),
                Some(k) => {
                    let c = DATA_KEYED_MAPS.contains(&k.as_str());
                    (Seg::Key(k), c)
                }
                None => (Seg::Wildcard, false),
            };
            ctx.path.push(seg);
            map.next_value_seed(Node {
                ctx: &mut *ctx,
                collapse,
            })?;
            ctx.path.pop();
        }
        ctx.depth -= 1;
        Ok(NodeKind::Other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OIDC: &str = r#"{
      "@class": "org.apereo.cas.services.OidcRegisteredService",
      "id": 10000003,
      "name": "HR-Portal",
      "serviceId": "^https://user:hunter2-SECRET@hr.example.org/.*?token=abc#frag",
      "evaluationOrder": 3,
      "clientId": "hr-portal",
      "clientSecret": "fake-clear-secret-0000",
      "description": "Owner jane.doe@example.org",
      "jwks": "{\"keys\": [{\"d\": \"FAKE-PRIVATE\"}]}",
      "contacts": ["java.util.ArrayList", [
        {"@class": "org.apereo.cas.services.DefaultRegisteredServiceContact",
         "name": "Jane Doe", "email": "jane.doe@example.org", "phone": "+33 6 12 34 56 78"}
      ]],
      "properties": {"@class": "java.util.HashMap",
        "costCenter": {"@class": "org.apereo.cas.services.DefaultRegisteredServiceProperty",
                       "values": ["java.util.HashSet", ["CC-42"]]},
        "apiPassword": {"values": ["fake-property-secret"]}},
      "attributeReleasePolicy": {
        "@class": "org.apereo.cas.services.ReturnStaticAttributeReleasePolicy",
        "allowedAttributes": {"@class": "java.util.LinkedHashMap",
          "employeeNumber": ["java.util.ArrayList", ["E-1234"]]}},
      "accessStrategy": {"requiredAttributes": {"memberOf": ["hr-staff"]}},
      "logoutType": "BACK_CHANNEL",
      "signingKeyAlias": "fake-alias",
      "accessTokenExpiration": "PT1H",
      "enabled": true
    }"#;

    fn paths(d: &Definition) -> Vec<(String, String)> {
        let mut v: Vec<_> = d
            .values
            .iter()
            .map(|s| (format!("{:?}", s.path), s.value.to_string()))
            .collect();
        v.sort();
        v
    }

    #[test]
    fn an_oidc_definition_is_reduced() {
        let d = parse_definition(OIDC.as_bytes()).unwrap();
        assert_eq!(d.service_type, ServiceType::Oidc);
        assert_eq!(d.id, Some(10_000_003));
        assert_eq!(d.evaluation_order, Some(3));
        assert_eq!(d.client_secret, SecretForm::Clear);
        assert_eq!(d.name.as_deref().map(String::as_str), Some("HR-Portal"));
        let p = paths(&d);
        let expected = [
            ("[accessStrategy, requiredAttributes, *, []]", "hr-staff"),
            (
                "[attributeReleasePolicy, allowedAttributes, *, []]",
                "E-1234",
            ),
            ("[clientId]", "hr-portal"),
            ("[contacts, [], email]", "jane.doe@example.org"),
            ("[contacts, [], name]", "Jane Doe"),
            ("[contacts, [], phone]", "+33 6 12 34 56 78"),
            ("[description]", "Owner jane.doe@example.org"),
            ("[name]", "HR-Portal"),
            ("[properties, *, values, []]", "CC-42"),
            ("[serviceId]", "^https://hr.example.org/.*"),
        ];
        let expected: Vec<(String, String)> = expected
            .iter()
            .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
            .collect();
        assert_eq!(p, expected);
        // Nothing of a credential reaches the values.
        for (_, v) in &p {
            for bad in [
                "fake-clear-secret",
                "FAKE-PRIVATE",
                "hunter2",
                "fake-property",
                "fake-alias",
                "token=",
                "frag",
                "BACK_CHANNEL",
                "PT1H",
                "java.util",
            ] {
                assert!(!v.contains(bad), "{bad} in {v}");
            }
        }
    }

    #[test]
    fn credential_keys_match_case_insensitively() {
        for k in [
            "clientSecret",
            "PASSWORD",
            "userPasswd",
            "signingKey",
            "keyAlias",
            "accessToken",
            "credentials",
            "jwks",
            "privateKey",
            "KeyStoreLocation",
            "monkey",
            "Authorization",
            "basicAuthUsername",
            "Cookie",
            "bearerValue",
            "clientPwd",
            "passphrase",
            "hashSalt",
            "cipherExecutor",
            "signingAlgorithm",
            "httpHeaders",
            "headers",
        ] {
            assert!(is_credential_key(k), "{k}");
        }
        for k in [
            "name",
            "email",
            "serviceId",
            "description",
            "contacts",
            "kéy",
        ] {
            assert!(!is_credential_key(k), "{k}");
        }
    }

    /// HTTP-based policies carry credentials in headers, basic
    /// authentication fields and URLs (review of #138 M2).
    #[test]
    fn http_policies_keep_no_credential() {
        let doc = r#"{
          "@class": "org.apereo.cas.services.CasRegisteredService",
          "serviceId": "^https://app.example.org/.*", "name": "App",
          "attributeReleasePolicy": {
            "@class": "org.apereo.cas.services.ReturnRestfulAttributeReleasePolicy",
            "endpoint": "https://svc:fake-pa/ss@attrs.example.org/release?apikey=FAKE-QUERY",
            "headers": {"@class": "java.util.LinkedHashMap",
                        "Authorization": "Basic RkFLRS1IRUFERVI=", "X-Trace": "FAKE-TRACE"}
          },
          "accessStrategy": {
            "@class": "org.apereo.cas.services.RemoteEndpointServiceAccessStrategy",
            "endpointUrl": "//fake-user:fake-pwd@authz.example.org/check",
            "acceptableResponseCodes": "200,202",
            "httpHeaders": [{"name": "Cookie", "value": "FAKE-COOKIE"}],
            "basicAuthUsername": "FAKE-USER", "basicAuthPassword": "FAKE-BASIC"
          },
          "proxyPolicy": {
            "@class": "org.apereo.cas.services.RestfulRegisteredServiceProxyPolicy",
            "endpoint": "https://proxy.example.org/p#FAKE-FRAGMENT",
            "headers": {"Cookie": "TGC=FAKE-TGC"}
          },
          "ticketGrantingTicketExpirationPolicy": {
            "@class": "org.apereo.cas.services.DefaultRegisteredServiceTicketGrantingTicketExpirationPolicy",
            "requestHeaders": {"Authorization": "Bearer FAKE-BEARER"}
          }
        }"#;
        let d = parse_definition(doc.as_bytes()).unwrap();
        let p = paths(&d);
        for (_, v) in &p {
            for bad in [
                "FAKE-",
                "fake-pa",
                "ss@",
                "fake-user",
                "fake-pwd",
                "RkFLRS",
                "apikey",
            ] {
                assert!(!v.contains(bad), "{bad} in {v}");
            }
        }
        let kept: Vec<&str> = p.iter().map(|(_, v)| v.as_str()).collect();
        assert!(
            kept.contains(&"https://attrs.example.org/release"),
            "{kept:?}"
        );
        assert!(kept.contains(&"//authz.example.org/check"), "{kept:?}");
        assert!(kept.contains(&"https://proxy.example.org/p"), "{kept:?}");
    }

    #[test]
    fn secret_forms() {
        assert_eq!(SecretForm::of(""), SecretForm::Absent);
        assert_eq!(SecretForm::of("${CLIENT_SECRET}"), SecretForm::Reference);
        assert_eq!(
            SecretForm::of("#{systemProperties['x']}"),
            SecretForm::Reference
        );
        assert_eq!(SecretForm::of("{cipher}AbCd"), SecretForm::Encrypted);
        assert_eq!(
            SecretForm::of("eyJhbGciOiJSU0EtT0FFUCJ9.a2V5.aXY.Y2lwaGVy.dGFn"),
            SecretForm::Encrypted
        );
        // A JWS (here `alg: none`) is readable: clear.
        assert_eq!(
            SecretForm::of("eyJhbGciOiJub25lIn0.ZmFrZQ."),
            SecretForm::Clear
        );
        assert_eq!(
            SecretForm::of("eyJhbGciOiJIUzUxMiJ9.ZmFrZQ.c2ln"),
            SecretForm::Clear
        );
        assert_eq!(SecretForm::of("eyJ.a.b.c"), SecretForm::Clear);
        assert_eq!(SecretForm::of("fake-secret"), SecretForm::Clear);
        let form = |json: &str| {
            parse_definition(
                format!(
                    "{{\"@class\": \"org.apereo.cas.support.oauth.services.OAuthRegisteredService\", \
                     \"serviceId\": \"x\", \"clientSecret\": {json}}}"
                )
                .as_bytes(),
            )
            .unwrap()
            .client_secret
        };
        assert_eq!(form("null"), SecretForm::Absent);
        assert_eq!(form("\"${S}\""), SecretForm::Reference);
        assert_eq!(form("{\"a\": 1}"), SecretForm::Clear);
        assert_eq!(form("42"), SecretForm::Clear);
    }

    #[test]
    fn other_documents_are_not_definitions_and_keep_nothing() {
        for doc in [
            r#"{"serviceId": "x", "contacts": [{"email": "jane.doe@example.org"}]}"#,
            r#"{"@class": "com.example.Evil", "serviceId": "x"}"#,
            r#"{"@class": "org.apereo.cas.services.CasRegisteredService"}"#,
            r#"{"@class": "org.apereo.cas.services.CasRegisteredService", "serviceId": 3}"#,
            r#"{"@class": "org.apereo.cas.config.CasConfiguration", "serviceId": "x"}"#,
            r#"["org.apereo.cas.services.CasRegisteredService"]"#,
            r#""text""#,
        ] {
            assert_eq!(
                parse_definition(doc.as_bytes()).unwrap_err(),
                DefinitionError::NotDefinition,
                "{doc}"
            );
        }
        assert_eq!(
            ServiceType::from_class("org.apereo.cas.foo.CustomRegisteredService"),
            Some(ServiceType::Other)
        );
    }

    #[test]
    fn malformed_and_duplicate_documents_are_refused() {
        let base = r#""@class": "org.apereo.cas.services.CasRegisteredService", "serviceId": "x""#;
        for doc in [
            format!("{{{base}, \"serviceId\": \"y\"}}"),
            format!("{{{base}, \"@class\": \"org.apereo.cas.services.CasRegisteredService\"}}"),
            format!("{{{base}, \"name\": \"a\", \"name\": \"b\"}}"),
            format!("{{{base}, \"id\": 1, \"id\": 2}}"),
            format!("{{{base}, \"clientSecret\": \"a\", \"clientSecret\": null}}"),
            format!("{{{base}}} trailing"),
            format!("// comment\n{{{base}}}"),
            format!("{{{base}, /* c */ \"name\": \"a\"}}"),
            "{".to_owned(),
            String::new(),
        ] {
            assert_eq!(
                parse_definition(doc.as_bytes()).unwrap_err(),
                DefinitionError::Malformed,
                "{doc}"
            );
        }
    }

    #[test]
    fn bounds_are_enforced() {
        let base = r#""@class": "org.apereo.cas.services.CasRegisteredService", "serviceId": "x""#;
        let deep = format!(
            "{{{base}, \"a\": {}{}}}",
            "[".repeat(MAX_DEPTH),
            "]".repeat(MAX_DEPTH)
        );
        assert_eq!(
            parse_definition(deep.as_bytes()).unwrap_err(),
            DefinitionError::Bounds
        );
        let ok_depth = format!(
            "{{{base}, \"a\": {}{}}}",
            "[".repeat(MAX_DEPTH - 1),
            "]".repeat(MAX_DEPTH - 1)
        );
        assert!(parse_definition(ok_depth.as_bytes()).is_ok());
        let items = vec!["1"; MAX_ARRAY_ITEMS + 1].join(",");
        let wide = format!("{{{base}, \"a\": [{items}]}}");
        assert_eq!(
            parse_definition(wide.as_bytes()).unwrap_err(),
            DefinitionError::Bounds
        );
        let items = vec!["1"; MAX_ARRAY_ITEMS].join(",");
        assert!(parse_definition(format!("{{{base}, \"a\": [{items}]}}").as_bytes()).is_ok());
        let keys: Vec<String> = (0..=MAX_NODES).map(|i| format!("\"k{i}\": 1")).collect();
        let many = format!("{{{base}, \"m\": {{{}}}}}", keys.join(","));
        assert_eq!(
            parse_definition(many.as_bytes()).unwrap_err(),
            DefinitionError::Bounds
        );
        // Strings are cut on a character boundary.
        let long = "é".repeat(MAX_STRING_BYTES);
        let d = parse_definition(format!("{{{base}, \"description\": \"{long}\"}}").as_bytes())
            .unwrap();
        let v = &d
            .values
            .iter()
            .find(|s| s.path == [Seg::Key("description".into())])
            .unwrap()
            .value;
        assert!(v.len() <= MAX_STRING_BYTES && v.chars().all(|c| c == 'é'));
    }

    /// The fixture pairs of `fixtures/registry/`: a JSON definition and the
    /// same definition in CAS 8.0.2's YAML form.
    const PAIRS: [(&str, &str); 3] = [
        (
            include_str!("../../fixtures/registry/HR-Portal-10000003.json"),
            include_str!("../../fixtures/registry/HR-Portal-10000003.yml"),
        ),
        (
            include_str!("../../fixtures/registry/Wiki-10000004.json"),
            include_str!("../../fixtures/registry/Wiki-10000004.yaml"),
        ),
        (
            include_str!("../../fixtures/registry/SP-10000005.json"),
            include_str!("../../fixtures/registry/SP-10000005.yml"),
        ),
    ];

    #[test]
    fn yaml_definitions_reduce_like_their_json_equivalents() {
        for (json, yaml) in PAIRS {
            let j = parse_definition(json.as_bytes()).unwrap();
            let y = parse_registry_file(RegistryFormat::Yaml, yaml.as_bytes()).unwrap();
            assert_eq!(j.service_type, y.service_type);
            assert_eq!(j.id, y.id);
            assert_eq!(j.evaluation_order, y.evaluation_order);
            assert_eq!(j.name, y.name);
            assert_eq!(j.service_id, y.service_id);
            assert_eq!(j.client_secret, y.client_secret);
            assert!(!j.values.is_empty());
            assert_eq!(paths(&j), paths(&y), "{yaml}");
        }
        let y = parse_yaml_definition(PAIRS[0].1.as_bytes()).unwrap();
        assert_eq!(y.service_type, ServiceType::Oidc);
        assert_eq!(y.client_secret, SecretForm::Clear);
        let kept = format!("{:?} {y:?}", paths(&y));
        for bad in [
            "fake-clear-secret",
            "FAKE-PRIVATE",
            "hunter2",
            "fake-property",
            "fake-alias",
            "token=",
            "BACK_CHANNEL",
            "java.util",
            "org.apereo",
        ] {
            assert!(!kept.contains(bad), "{bad} in {kept}");
        }
        let saml = parse_yaml_definition(PAIRS[2].1.as_bytes()).unwrap();
        let kept = format!("{:?}", paths(&saml));
        assert!(!kept.contains("FAKE-"), "{kept}");
        assert!(kept.contains("R&D *team*"), "{kept}");
    }

    const YAML_HEAD: &str = "--- !<org.apereo.cas.services.OidcRegisteredService>\n\
                             serviceId: \"^https://app.example.org/.*\"\nname: App\n";

    fn yaml(body: &str) -> Result<Definition, DefinitionError> {
        parse_yaml_definition(format!("{YAML_HEAD}{body}").as_bytes())
    }

    #[test]
    fn hostile_yaml_is_refused_before_parsing() {
        // Billion laughs: every alias level would multiply the nodes.
        let mut laughs = String::from("a0: &a0 [\"lol\", \"lol\", \"lol\", \"lol\", \"lol\"]\n");
        for i in 1..10 {
            let p = i - 1;
            laughs.push_str(&format!(
                "a{i}: &a{i} [*a{p}, *a{p}, *a{p}, *a{p}, *a{p}, *a{p}]\n"
            ));
        }
        assert_eq!(yaml(&laughs).unwrap_err(), DefinitionError::Refused);
        // Deep nesting bombs, block and flow.
        let mut deep = String::new();
        for i in 0..200 {
            deep.push_str(&" ".repeat(i));
            deep.push_str("k:\n");
        }
        assert_eq!(yaml(&deep).unwrap_err(), DefinitionError::Bounds);
        let flow = format!("a: {}{}\n", "[".repeat(10_000), "]".repeat(10_000));
        assert_eq!(yaml(&flow).unwrap_err(), DefinitionError::Bounds);
        let seqs = format!("a:\n{}x\n", "- ".repeat(10_000));
        assert_eq!(yaml(&seqs).unwrap_err(), DefinitionError::Bounds);
        for body in [
            "description: !!python/object/apply:os.system [\"id\"]\n",
            "description: !!str x\n",
            "description: !local x\n",
            "description: !<tag:yaml.org,2002:str> x\n",
            "base: &b {email: jane.doe@example.org}\nother:\n  <<: *b\n",
            "other:\n  <<: {email: jane.doe@example.org}\n",
            "description: x\n---\nname: B\n",
            "description: x\n...\n",
        ] {
            assert_eq!(yaml(body).unwrap_err(), DefinitionError::Refused, "{body}");
        }
        // Not what CAS loads: no class hint at the start.
        for doc in [
            "serviceId: x\n",
            "{\"@class\": \"org.apereo.cas.services.CasRegisteredService\", \"serviceId\": \"x\"}",
            "--- !<com.example.Evil>\nserviceId: x\n",
            "",
        ] {
            assert_eq!(
                parse_yaml_definition(doc.as_bytes()).unwrap_err(),
                DefinitionError::NotDefinition,
                "{doc}"
            );
        }
        // An `@class` key next to the class hint, a duplicate kept key.
        assert_eq!(
            yaml("\"@class\": org.apereo.cas.services.CasRegisteredService\n").unwrap_err(),
            DefinitionError::Malformed
        );
        assert_eq!(yaml("name: B\n").unwrap_err(), DefinitionError::Malformed);
        // Syntax errors found by the parser.
        assert_eq!(yaml("a: b: c\n").unwrap_err(), DefinitionError::Refused);
        assert_eq!(
            yaml("a: \"x\" y\n").unwrap_err(),
            DefinitionError::Malformed
        );
        // The visitor's own bounds still apply.
        let items = vec!["1"; MAX_ARRAY_ITEMS + 1].join(", ");
        assert_eq!(
            yaml(&format!("a: [{items}]\n")).unwrap_err(),
            DefinitionError::Bounds
        );
        assert!(yaml("a: [1, 2]\nclientSecret: ${S}\n").is_ok());
    }

    #[test]
    fn unquoted_yaml_numbers_are_classified_as_text() {
        let json = r#"{"@class": "org.apereo.cas.services.CasRegisteredService",
          "serviceId": "^https://app.example.org/.*", "name": "App",
          "contacts": [{"name": "Jane Doe", "phone": "0612345678", "mobile": "33612345678"}],
          "properties": {"card": {"values": ["4111111111111111"]},
                         "iban": {"values": ["12345678901234567890123"]}}}"#;
        let yaml = "--- !<org.apereo.cas.services.CasRegisteredService>\n\
                    serviceId: \"^https://app.example.org/.*\"\nname: App\n\
                    contacts:\n- name: Jane Doe\n  phone: 0612345678\n  mobile: 33612345678\n\
                    properties:\n  card:\n    values: [4111111111111111]\n\
                    \x20 iban:\n    values:\n    - 12345678901234567890123\n";
        let j = parse_definition(json.as_bytes()).unwrap();
        let y = parse_yaml_definition(yaml.as_bytes()).unwrap();
        assert_eq!(paths(&j), paths(&y));
        assert!(paths(&y).iter().any(|(_, v)| v == "4111111111111111"));
        // JSON numbers are still not sampled; top-level `id` never is.
        let j = parse_definition(
            br#"{"@class": "org.apereo.cas.services.CasRegisteredService", "serviceId": "x",
                 "id": 4111111111111111, "phone": 33612345678}"#,
        )
        .unwrap();
        assert_eq!(paths(&j), [("[serviceId]".to_owned(), "x".to_owned())]);
        let y = parse_yaml_definition(
            b"--- !<org.apereo.cas.services.CasRegisteredService>\nserviceId: x\n\
              id: 4111111111111111\nevaluationOrder: 3\nratio: 1.5\n",
        )
        .unwrap();
        assert_eq!(y.id, Some(4_111_111_111_111_111));
        assert_eq!(paths(&y), [("[serviceId]".to_owned(), "x".to_owned())]);
    }
}
