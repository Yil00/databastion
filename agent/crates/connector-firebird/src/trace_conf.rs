//! The Firebird configuration files that decide the Audit level (ADR-0060
//! decision 6, proofs 2 to 6 and 11, M3; refinements R2 rules 2 and 4,
//! R4, R8 item 6, R9, R21 and R27 item 2).
//!
//! Three parsers, each with a closed grammar and fail closed: anything the
//! agent does not know (an `include`, an unknown key, a duplicate, a value
//! of the wrong type, a macro outside the closed list) makes the file
//! **not evaluated** rather than guessed, so the level stays Limited.
//!
//! - [`parse_firebird_conf`]: `firebird.conf`, `Key = value` lines with the
//!   key names of the 4.0 and 5.0 images ([`FIREBIRD_CONF_KEYS`]); only
//!   `AuditTraceConfigFile`, `ServerMode` and `TracePlugin` are kept.
//! - [`parse_databases_conf`]: `databases.conf`, `alias = path` lines and
//!   per-database `{ … }` blocks with the per-database keys of the images
//!   ([`DATABASES_CONF_KEYS`]); the alias names, paths (macros resolved
//!   against the declared root) and `SecurityDatabase` values are kept,
//!   on the agent host only.
//! - [`parse_trace_conf`]: the trace configuration, `database [= pattern]`
//!   and `services` sections with the keys of the images' `fbtrace.conf`
//!   ([`DATABASE_KEYS`], [`SERVICES_KEYS`]).
//!
//! [`evaluate`] then applies the proofs to the declared databases. Paths
//! and alias names never leave the agent host: notes carry closed labels
//! only, and the local detail names the declared database labels.
//!
//! Firebird compares configuration keys and macros without case (the
//! images' `firebird.conf`: "Like the rest of config internals, macros are
//! case-insensitive"); so do these parsers, for keys and macros only.

use databastion_core::{NoteCode, NoteLabel, TargetNote};

/// Largest configuration file read, in bytes.
pub(crate) const MAX_CONF_BYTES: usize = 1 << 20;
/// Most sections of a trace configuration, aliases of a `databases.conf`.
const MAX_ENTRIES: usize = 4096;
/// Longest line of a configuration file.
const MAX_LINE: usize = 8192;
/// The proof 5 floor of `max_sql_length`.
pub(crate) const MIN_SQL_LENGTH: u64 = 4096;
/// The largest `max_sql_length` the Partial level accepts: a statement
/// text line must fit the core tailer's line bound (1 MiB,
/// `databastion_core::audit::tail::MAX_RECORD_BYTES`), with a margin of
/// 64 KiB. A longer line would be skipped by the tailer (its record is
/// then made ambiguous by the stream, never parsed without it), so a text
/// could never be read whole.
pub(crate) const MAX_SQL_LENGTH_CARRIED: u64 =
    databastion_core::audit::tail::MAX_RECORD_BYTES as u64 - 64 * 1024;
/// The server's default `max_sql_length` (images' `fbtrace.conf`).
const DEFAULT_SQL_LENGTH: u64 = 300;

/// The keys of the 4.0.7 and 5.0.4 images' `firebird.conf` (the union).
pub(crate) const FIREBIRD_CONF_KEYS: &[&str] = &[
    "AllowEncryptedSecurityDatabase",
    "AllowUpdateOverwrite",
    "AuditTraceConfigFile",
    "AuthClient",
    "AuthServer",
    "BugcheckAbort",
    "ClearGTTAtRetaining",
    "ClientBatchBuffer",
    "ConnectionIdleTimeout",
    "ConnectionTimeout",
    "CpuAffinityMask",
    "DataTypeCompatibility",
    "DatabaseAccess",
    "DatabaseGrowthIncrement",
    "DeadlockTimeout",
    "DefaultDbCachePages",
    "DefaultProfilerPlugin",
    "DefaultTimeZone",
    "DummyPacketInterval",
    "EventMemSize",
    "ExtConnPoolLifeTime",
    "ExtConnPoolSize",
    "ExternalFileAccess",
    "FileSystemCacheSize",
    "FileSystemCacheThreshold",
    "GCPolicy",
    "GuardianOption",
    "IPv6V6Only",
    "InlineSortThreshold",
    "IpcName",
    "KeyHolderPlugin",
    "LockAcquireSpins",
    "LockHashSlots",
    "LockMemSize",
    "MaxIdentifierByteLength",
    "MaxIdentifierCharLength",
    "MaxParallelWorkers",
    "MaxStatementCacheSize",
    "MaxUnflushedWriteTime",
    "MaxUnflushedWrites",
    "MaxUserTraceLogSize",
    "OnDisconnectTriggerTimeout",
    "OptimizeForFirstRows",
    "OuterJoinConversion",
    "OutputRedirectionFile",
    "ParallelWorkers",
    "ProcessPriorityLevel",
    "Providers",
    "ReadConsistency",
    "Redirection",
    "RelaxedAliasChecking",
    "RemoteAccess",
    "RemoteAuxPort",
    "RemoteBindAddress",
    "RemoteFileOpenAbility",
    "RemotePipeName",
    "RemoteServiceName",
    "RemoteServicePort",
    "SecurityDatabase",
    "ServerMode",
    "SnapshotsMemSize",
    "StatementTimeout",
    "SubQueryConversion",
    "TcpLoopbackFastPath",
    "TcpNoNagle",
    "TcpRemoteBufferSize",
    "TempBlockSize",
    "TempCacheLimit",
    "TempDirectories",
    "TempTableDirectory",
    "TipCacheBlockSize",
    "TracePlugin",
    "UdfAccess",
    "UseFileSystemCache",
    "UseLegacyKernelObjectsNames",
    "UserManager",
    "WireCompression",
    "WireCrypt",
    "WireCryptPlugin",
];

/// The per-database keys of the images' `firebird.conf` ("Per-database
/// configurable", the union of 4.0.7 and 5.0.4), with the per-connection
/// wire keys the server reads from `databases.conf` (lot 1: measured).
/// None changes what the trace logs (measurement 12c).
pub(crate) const DATABASES_CONF_KEYS: &[&str] = &[
    "AllowEncryptedSecurityDatabase",
    "AllowUpdateOverwrite",
    "AuthClient",
    "AuthServer",
    "ClearGTTAtRetaining",
    "ConnectionIdleTimeout",
    "DataTypeCompatibility",
    "DatabaseAccess",
    "DatabaseGrowthIncrement",
    "DeadlockTimeout",
    "DefaultDbCachePages",
    "DefaultProfilerPlugin",
    "EventMemSize",
    "ExternalFileAccess",
    "FileSystemCacheThreshold",
    "GCPolicy",
    "InlineSortThreshold",
    "LockAcquireSpins",
    "LockHashSlots",
    "LockMemSize",
    "MaxIdentifierByteLength",
    "MaxIdentifierCharLength",
    "MaxStatementCacheSize",
    "MaxUnflushedWriteTime",
    "MaxUnflushedWrites",
    "OnDisconnectTriggerTimeout",
    "OptimizeForFirstRows",
    "OuterJoinConversion",
    "Providers",
    "RemoteAccess",
    "RemoteAuxPort",
    "SecurityDatabase",
    "SnapshotsMemSize",
    "StatementTimeout",
    "SubQueryConversion",
    "TempCacheLimit",
    "TempTableDirectory",
    "TipCacheBlockSize",
    "UseFileSystemCache",
    "UserManager",
    "WireCompression",
    "WireCrypt",
    "WireCryptPlugin",
];

/// The macros resolved against the declared root (R2 rule 2, review L-4).
/// Assumption (review of part 1, L2): the layout of the official images
/// and of the tarball install, `/opt/firebird`, where `$(root)`,
/// `$(install)`, `$(this)` (the directory of `firebird.conf` and
/// `databases.conf`), `$(dir_conf)` and `$(dir_secDb)` are all the root
/// directory. A distribution layout (`/etc/firebird`, `/var/lib/firebird`)
/// resolves them elsewhere: a path through them then names another file
/// than the server's, which fails closed (the binding or the alias does
/// not match, Limited). The engine-matrix drift test checks the images.
const ROOT_MACROS: &[&str] = &["root", "install", "this", "dir_conf", "dir_secdb"];

/// Why a configuration file is not evaluated (kinds only, never content).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfError {
    TooLarge,
    Encoding,
    Syntax,
    UnknownKey,
    Include,
    Duplicate,
    Value,
}

/// `ServerMode` (decision 6, proof 10; R1 rule 10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum ServerMode {
    /// `Super` / `ThreadedDedicated` (the default).
    #[default]
    Super,
    /// `SuperClassic` / `ThreadedShared`.
    SuperClassic,
    /// `Classic` / `MultiProcess`: Limited (R1 rule 10).
    Classic,
}

/// What the agent keeps of `firebird.conf`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct FirebirdConf {
    /// `AuditTraceConfigFile`, as written (resolved by [`resolve`]).
    pub(crate) audit_trace_config_file: Option<String>,
    pub(crate) server_mode: ServerMode,
    /// `TracePlugin` is absent or `fbtrace`: the system audit trace is
    /// written by the plugin whose format the parser knows.
    pub(crate) trace_plugin_default: bool,
}

/// One logical line: its text without comment and surrounding blanks.
fn lines(text: &[u8]) -> Result<Vec<&str>, ConfError> {
    if text.len() > MAX_CONF_BYTES {
        return Err(ConfError::TooLarge);
    }
    let text = std::str::from_utf8(text).map_err(|_| ConfError::Encoding)?;
    let mut out = Vec::new();
    for raw in text.split('\n') {
        if raw.len() > MAX_LINE {
            return Err(ConfError::Syntax);
        }
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        if raw.chars().any(|c| c.is_control() && c != '\t') {
            return Err(ConfError::Syntax);
        }
        let line = strip_comment(raw).trim_matches([' ', '\t']);
        if !line.is_empty() {
            out.push(line);
        }
    }
    Ok(out)
}

/// The line before an unquoted `#`.
fn strip_comment(line: &str) -> &str {
    let mut quote = None;
    for (i, c) in line.char_indices() {
        match (quote, c) {
            (None, '#') => return &line[..i],
            (None, '\'' | '"') => quote = Some(c),
            (Some(q), c) if c == q => quote = None,
            _ => {}
        }
    }
    line
}

/// `key = value` (or `key value`, the images' comments show both): the
/// key and the raw value.
fn entry(line: &str) -> Option<(&str, &str)> {
    let end = line.find(['=', ' ', '\t']).unwrap_or(line.len());
    let (key, rest) = line.split_at(end);
    if key.is_empty() || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return None;
    }
    let rest = rest.trim_start_matches([' ', '\t']);
    let value = rest
        .strip_prefix('=')
        .unwrap_or(rest)
        .trim_matches([' ', '\t']);
    Some((key, value))
}

/// A value with its quotes removed (one pair of `'` or `"`).
fn unquote(v: &str) -> Result<&str, ConfError> {
    for q in ['\'', '"'] {
        if let Some(inner) = v.strip_prefix(q) {
            return inner
                .strip_suffix(q)
                .filter(|i| !i.contains(q))
                .ok_or(ConfError::Value);
        }
    }
    if v.contains(['\'', '"']) {
        return Err(ConfError::Value);
    }
    Ok(v)
}

fn known<'k>(keys: &[&'k str], key: &str) -> Option<&'k str> {
    keys.iter().copied().find(|k| k.eq_ignore_ascii_case(key))
}

/// Parses `firebird.conf`.
pub(crate) fn parse_firebird_conf(text: &[u8]) -> Result<FirebirdConf, ConfError> {
    let mut conf = FirebirdConf {
        trace_plugin_default: true,
        ..FirebirdConf::default()
    };
    let mut seen = std::collections::HashSet::new();
    for line in lines(text)? {
        if is_include(line) {
            return Err(ConfError::Include);
        }
        let (key, value) = entry(line).ok_or(ConfError::Syntax)?;
        let key = known(FIREBIRD_CONF_KEYS, key).ok_or(ConfError::UnknownKey)?;
        // Which of two settings of one key the server keeps is not
        // measured: a duplicate of a key the proofs read is not evaluated.
        if !seen.insert(key) && matches!(key, "AuditTraceConfigFile" | "ServerMode" | "TracePlugin")
        {
            return Err(ConfError::Duplicate);
        }
        let value = unquote(value)?;
        match key {
            "AuditTraceConfigFile" => {
                conf.audit_trace_config_file = (!value.is_empty()).then(|| value.to_owned());
            }
            "ServerMode" => {
                conf.server_mode = match value.to_ascii_lowercase().as_str() {
                    "super" | "threadeddedicated" => ServerMode::Super,
                    "superclassic" | "threadedshared" => ServerMode::SuperClassic,
                    "classic" | "multiprocess" => ServerMode::Classic,
                    _ => return Err(ConfError::Value),
                };
            }
            "TracePlugin" => conf.trace_plugin_default = value.eq_ignore_ascii_case("fbtrace"),
            _ => {}
        }
    }
    Ok(conf)
}

fn is_include(line: &str) -> bool {
    line.get(..7)
        .is_some_and(|w| w.eq_ignore_ascii_case("include"))
        && line[7..].starts_with([' ', '\t'])
}

/// A configuration path with the closed macros resolved against `root`:
/// `None` when it uses another macro (an unknown path, R2 rule 2).
pub(crate) fn resolve(path: &str, root: &str) -> Option<String> {
    let mut out = String::with_capacity(path.len());
    let mut rest = path;
    while let Some(i) = rest.find("$(") {
        out.push_str(&rest[..i]);
        let after = &rest[i + 2..];
        let end = after.find(')')?;
        let name = after[..end].to_ascii_lowercase();
        if !ROOT_MACROS.contains(&name.as_str()) {
            return None;
        }
        out.push_str(root.trim_end_matches('/'));
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    if out.is_empty() {
        return None;
    }
    if !out.starts_with('/') {
        // Relative names are resolved against the root (decision 6, M3).
        out = format!("{}/{out}", root.trim_end_matches('/'));
    }
    canonical(&out)
}

/// A path without `.`, `..` or empty components (`None` for `..` above
/// the root, or a backslash: never matched).
fn canonical(path: &str) -> Option<String> {
    if path.contains('\\') {
        return None;
    }
    let mut parts: Vec<&str> = Vec::new();
    for p in path.split('/') {
        match p {
            "" | "." => {}
            // Refused (review of part 1, L2): a `..` component may cross
            // a symlinked directory the server resolves otherwise.
            ".." => return None,
            p => parts.push(p),
        }
    }
    Some(format!("/{}", parts.join("/")))
}

/// One `databases.conf` entry.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Alias {
    pub(crate) name: String,
    /// The resolved path, `None` when it uses a macro outside the closed
    /// list (its printed name is ambiguous, R2 rule 2).
    pub(crate) path: Option<String>,
    /// `SecurityDatabase` of its block, as written (R9 rule 3).
    pub(crate) security_database: Option<String>,
}

impl std::fmt::Debug for Alias {
    // Names and paths stay on the agent host, out of debug strings too
    // (review of part 1, N1).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Alias")
            .field("path_known", &self.path.is_some())
            .field("security_database", &self.security_database.is_some())
            .finish_non_exhaustive()
    }
}

/// The evaluated alias map (R2 rule 2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct AliasMap {
    pub(crate) aliases: Vec<Alias>,
}

impl AliasMap {
    /// The entry of an alias (exact, byte for byte).
    pub(crate) fn get(&self, name: &str) -> Option<&Alias> {
        self.aliases.iter().find(|a| a.name == name)
    }

    /// Every alias that maps to `path`.
    pub(crate) fn aliases_of<'a>(&'a self, path: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.aliases
            .iter()
            .filter(move |a| a.path.as_deref() == Some(path))
            .map(|a| a.name.as_str())
    }
}

/// Parses `databases.conf` (R2 rule 2): `alias = path` entries, each
/// optionally followed by a `{ … }` block of per-database keys.
pub(crate) fn parse_databases_conf(text: &[u8], root: &str) -> Result<AliasMap, ConfError> {
    let mut map = AliasMap::default();
    let mut block: Option<usize> = None;
    let mut keys = std::collections::HashSet::new();
    for line in lines(text)? {
        if is_include(line) {
            return Err(ConfError::Include);
        }
        if line == "{" {
            if block.is_some() || map.aliases.is_empty() {
                return Err(ConfError::Syntax);
            }
            block = Some(map.aliases.len() - 1);
            keys.clear();
            continue;
        }
        if line == "}" {
            block.take().ok_or(ConfError::Syntax)?;
            continue;
        }
        if let Some(i) = block {
            let (key, value) = entry(line).ok_or(ConfError::Syntax)?;
            let key = known(DATABASES_CONF_KEYS, key).ok_or(ConfError::UnknownKey)?;
            if !keys.insert(key) {
                return Err(ConfError::Duplicate);
            }
            if key == "SecurityDatabase" {
                map.aliases[i].security_database = Some(unquote(value)?.to_owned());
            }
            continue;
        }
        let (name, path) = line.split_once('=').ok_or(ConfError::Syntax)?;
        let name = name.trim_matches([' ', '\t']);
        let mut path = path.trim_matches([' ', '\t']);
        let opens = path.ends_with('{');
        if opens {
            path = path[..path.len() - 1].trim_end_matches([' ', '\t']);
        }
        let path = unquote(path)?;
        if name.is_empty()
            || name.contains([' ', '\t', '{', '}', '='])
            || path.is_empty()
            || map.aliases.len() >= MAX_ENTRIES
        {
            return Err(ConfError::Syntax);
        }
        if map.get(name).is_some() {
            return Err(ConfError::Duplicate);
        }
        map.aliases.push(Alias {
            name: name.to_owned(),
            path: resolve(path, root),
            security_database: None,
        });
        if opens {
            block = Some(map.aliases.len() - 1);
            keys.clear();
        }
    }
    if block.is_some() {
        return Err(ConfError::Syntax);
    }
    Ok(map)
}

/// The keys of a database section (the images' `fbtrace.conf`).
pub(crate) const DATABASE_KEYS: &[&str] = &[
    "enabled",
    "include_filter",
    "exclude_filter",
    "log_filename",
    "max_log_size",
    "log_connections",
    "connection_id",
    "log_transactions",
    "log_statement_prepare",
    "log_statement_free",
    "log_statement_start",
    "log_statement_finish",
    "log_procedure_compile",
    "log_procedure_start",
    "log_procedure_finish",
    "log_function_compile",
    "log_function_start",
    "log_function_finish",
    "log_trigger_compile",
    "log_trigger_start",
    "log_trigger_finish",
    "log_context",
    "log_errors",
    "log_warnings",
    "include_gds_codes",
    "exclude_gds_codes",
    "log_initfini",
    "log_sweep",
    "print_plan",
    "explain_plan",
    "print_perf",
    "log_blr_requests",
    "print_blr",
    "log_dyn_requests",
    "print_dyn",
    "time_threshold",
    "max_sql_length",
    "max_blr_length",
    "max_dyn_length",
    "max_arg_length",
    "max_arg_count",
];

/// The keys of a services section.
pub(crate) const SERVICES_KEYS: &[&str] = &[
    "enabled",
    "include_filter",
    "exclude_filter",
    "log_filename",
    "max_log_size",
    "log_services",
    "log_service_query",
    "log_errors",
    "log_warnings",
    "include_gds_codes",
    "exclude_gds_codes",
    "log_initfini",
];

/// The type of a key's value.
fn value_kind(key: &str) -> ValueKind {
    match key {
        "include_filter" | "exclude_filter" | "log_filename" | "include_gds_codes"
        | "exclude_gds_codes" => ValueKind::Text,
        "max_log_size" | "connection_id" | "time_threshold" | "max_sql_length"
        | "max_blr_length" | "max_dyn_length" | "max_arg_length" | "max_arg_count" => {
            ValueKind::Number
        }
        _ => ValueKind::Bool,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValueKind {
    Bool,
    Number,
    Text,
}

/// A setting's value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Value {
    Bool(bool),
    Number(u64),
    Text(String),
}

fn parse_value(key: &str, raw: &str) -> Result<Value, ConfError> {
    // Booleans and numbers unquoted only (review of part 1, L3).
    if value_kind(key) != ValueKind::Text && raw.contains(['\'', '"']) {
        return Err(ConfError::Value);
    }
    let v = unquote(raw)?;
    Ok(match value_kind(key) {
        ValueKind::Bool => Value::Bool(match v.to_ascii_lowercase().as_str() {
            "true" | "yes" | "on" | "1" => true,
            "false" | "no" | "off" | "0" => false,
            _ => return Err(ConfError::Value),
        }),
        ValueKind::Number => {
            if v.is_empty() || v.len() > 19 || !v.bytes().all(|b| b.is_ascii_digit()) {
                return Err(ConfError::Value);
            }
            Value::Number(v.parse().map_err(|_| ConfError::Value)?)
        }
        ValueKind::Text => Value::Text(v.to_owned()),
    })
}

/// The settings of one section, in the order written (no key twice).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Settings(pub(crate) Vec<(&'static str, Value)>);

impl Settings {
    fn get(&self, key: &str) -> Option<&Value> {
        self.0.iter().find(|(k, _)| *k == key).map(|(_, v)| v)
    }

    /// The default's settings overridden by these (R2 rule 4).
    fn over(&self, default: &Self) -> Self {
        let mut out = default.clone();
        for (k, v) in &self.0 {
            match out.0.iter_mut().find(|(ok, _)| ok == k) {
                Some(slot) => slot.1 = v.clone(),
                None => out.0.push((k, v.clone())),
            }
        }
        out
    }

    fn flag(&self, key: &str) -> bool {
        matches!(self.get(key), Some(Value::Bool(true)))
    }

    fn number(&self, key: &str) -> Option<u64> {
        match self.get(key) {
            Some(Value::Number(n)) => Some(*n),
            _ => None,
        }
    }

    fn text(&self, key: &str) -> Option<&str> {
        match self.get(key) {
            Some(Value::Text(t)) => Some(t),
            _ => None,
        }
    }

    /// A text setting that is set to something (a filter that applies).
    fn nonempty(&self, key: &str) -> bool {
        self.text(key).is_some_and(|t| !t.trim().is_empty())
    }
}

/// A trace configuration section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Section {
    pub(crate) kind: SectionKind,
    pub(crate) settings: Settings,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SectionKind {
    /// `database` (the default section) or `database = <pattern>`.
    Database(Option<String>),
    /// `services` or `services = <pattern>`.
    Services(Option<String>),
}

/// A parsed trace configuration.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct TraceConf {
    pub(crate) sections: Vec<Section>,
}

/// Parses the trace configuration.
pub(crate) fn parse_trace_conf(text: &[u8]) -> Result<TraceConf, ConfError> {
    let mut conf = TraceConf::default();
    let mut pending: Option<SectionKind> = None;
    let mut open: Option<Section> = None;
    let (mut default_db, mut default_svc) = (false, false);
    for line in lines(text)? {
        if is_include(line) {
            return Err(ConfError::Include);
        }
        if let Some(sec) = open.as_mut() {
            if line == "}" {
                conf.sections.extend(open.take());
                continue;
            }
            let (key, raw) = entry(line).ok_or(ConfError::Syntax)?;
            let keys = match sec.kind {
                SectionKind::Database(_) => DATABASE_KEYS,
                SectionKind::Services(_) => SERVICES_KEYS,
            };
            // Exact case (review of part 1, L3): the images write them
            // lower-case; another spelling is not evaluated.
            let key = keys
                .iter()
                .copied()
                .find(|k| *k == key)
                .ok_or(ConfError::UnknownKey)?;
            if sec.settings.get(key).is_some() {
                return Err(ConfError::Duplicate);
            }
            let value = parse_value(key, raw)?;
            sec.settings.0.push((key, value));
            continue;
        }
        let (head, opens) = match line.strip_suffix('{') {
            Some(h) if !h.ends_with('{') => (h.trim_end_matches([' ', '\t']), true),
            _ => (line, false),
        };
        if head.is_empty() && opens {
            let kind = pending.take().ok_or(ConfError::Syntax)?;
            open = Some(Section {
                kind,
                settings: Settings::default(),
            });
            continue;
        }
        if pending.is_some() || conf.sections.len() >= MAX_ENTRIES {
            return Err(ConfError::Syntax);
        }
        let kind = section_head(head)?;
        match &kind {
            SectionKind::Database(None) if std::mem::replace(&mut default_db, true) => {
                return Err(ConfError::Duplicate);
            }
            SectionKind::Services(None) if std::mem::replace(&mut default_svc, true) => {
                return Err(ConfError::Duplicate);
            }
            _ => {}
        }
        if opens {
            open = Some(Section {
                kind,
                settings: Settings::default(),
            });
        } else {
            pending = Some(kind);
        }
    }
    if pending.is_some() || open.is_some() {
        return Err(ConfError::Syntax);
    }
    Ok(conf)
}

fn section_head(head: &str) -> Result<SectionKind, ConfError> {
    let (word, pattern) = match head.split_once('=') {
        Some((w, p)) => (
            w.trim_matches([' ', '\t']),
            Some(p.trim_matches([' ', '\t'])),
        ),
        None => (head, None),
    };
    let pattern = match pattern {
        Some(p) => {
            let p = unquote(p)?;
            // `{{` and `}}` stand for one brace (the images' comment).
            if p.is_empty() || p.replace("{{", "").replace("}}", "").contains(['{', '}']) {
                return Err(ConfError::Syntax);
            }
            Some(p.replace("{{", "{").replace("}}", "}"))
        }
        None => None,
    };
    if word.eq_ignore_ascii_case("database") {
        Ok(SectionKind::Database(pattern))
    } else if word.eq_ignore_ascii_case("services") {
        Ok(SectionKind::Services(pattern))
    } else {
        Err(ConfError::Syntax)
    }
}

/// `SIMILAR TO` metacharacters, `_` and `%` included (proof 3, open
/// question 12), and the escape.
fn has_metachar(p: &str) -> bool {
    p.contains([
        '_', '%', '[', ']', '(', ')', '|', '^', '-', '+', '*', '?', '{', '}', '\\',
    ])
}

/// A declared database, as [`evaluate`] sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DeclaredDb<'a> {
    /// The operator's label (local detail only).
    pub(crate) label: &'a str,
    /// `MON$DATABASE_NAME` from the agent's own attachment (R2 rule 1 (a)),
    /// when `check()` read it.
    pub(crate) resolved: Option<&'a str>,
    /// The declared `attach` when it is an alias (R2 rule 1 (b)).
    pub(crate) alias: Option<&'a str>,
}

/// Inputs of [`evaluate`].
#[derive(Debug, Clone)]
pub(crate) struct Inputs<'a> {
    pub(crate) trace: &'a TraceConf,
    /// The evaluated `databases.conf`, `None` when not declared or not
    /// evaluated.
    pub(crate) aliases: Option<&'a AliasMap>,
    pub(crate) databases: &'a [DeclaredDb<'a>],
    /// The declared log (canonical absolute path).
    pub(crate) log: &'a str,
    /// The declared Firebird root.
    pub(crate) root: &'a str,
    /// The longest constant text of `sql::STATEMENTS` (R8 item 6).
    pub(crate) longest_own_text: usize,
}

/// The verdict of the configuration proofs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Verdict {
    /// Notes to report.
    pub(crate) notes: Vec<TargetNote>,
    /// Proofs 3 to 6 and 11 hold for every declared database.
    pub(crate) partial: bool,
    /// The smallest effective `max_sql_length` over the declared
    /// databases (the parser's cut rule).
    pub(crate) max_sql_length: u64,
    /// `log_connections` is on everywhere it applies (R10 item 1: the
    /// note is reported either way).
    pub(crate) log_connections: bool,
    /// Local detail lines (declared labels and closed reasons only).
    pub(crate) detail: Vec<String>,
}

/// The proof 4 settings, in the order of the label rank (R36 item 2).
const REQUIRED_FLAGS: &[&str] = &[
    "log_blr_requests",
    "print_perf",
    "log_statement_finish",
    "log_connections",
    "log_transactions",
    "log_initfini",
    "log_procedure_finish",
    "log_function_finish",
    "log_trigger_finish",
    "log_errors",
    "log_sweep",
];

/// A section's `log_filename`: `Some(path)` resolved against the root,
/// `None` when it uses `\N` substitutions (not evaluated) or is absent.
fn log_of(settings: &Settings, root: &str) -> Result<Option<String>, ()> {
    let Some(name) = settings.text("log_filename") else {
        return Ok(None);
    };
    if name.contains('\\') {
        return Err(());
    }
    Ok(resolve(name, root))
}

/// Applies proofs 3 to 6 and 11 (with R2 rule 4, R8 item 6, R21 and R27
/// item 2) to the declared databases.
pub(crate) fn evaluate(i: &Inputs<'_>) -> Verdict {
    let mut not_evaluated: Vec<&'static str> = Vec::new();
    let mut missing: Vec<&'static str> = Vec::new();
    let mut detail = Vec::new();
    let mut max_sql = u64::MAX;
    let mut log_connections = true;
    let add = |v: &mut Vec<&'static str>, l: &'static str| {
        if !v.contains(&l) {
            v.push(l);
        }
    };
    let default_db = i
        .trace
        .sections
        .iter()
        .find(|s| s.kind == SectionKind::Database(None))
        .map(|s| s.settings.clone())
        .unwrap_or_default();
    let named: Vec<(&str, &Settings)> = i
        .trace
        .sections
        .iter()
        .filter_map(|s| match &s.kind {
            SectionKind::Database(Some(p)) => Some((p.as_str(), &s.settings)),
            _ => None,
        })
        .collect();
    // The names every declared database can be printed under.
    let mut declared_names: Vec<String> = Vec::new();
    for db in i.databases {
        let mut names: Vec<String> = Vec::new();
        match db.resolved {
            Some(p) => names.push(p.to_owned()),
            None => {
                add(&mut not_evaluated, "databases_conf");
                detail.push(format!(
                    "{}: the resolved path was not read on the agent's own attachment",
                    db.label
                ));
            }
        }
        if let Some(a) = db.alias {
            names.push(a.to_owned());
        }
        match (i.aliases, db.resolved) {
            (Some(map), Some(p)) => names.extend(map.aliases_of(p).map(str::to_owned)),
            (None, _) => add(&mut not_evaluated, "databases_conf"),
            _ => {}
        }
        names.sort();
        names.dedup();
        let mut effective: Option<Settings> = None;
        for name in &names {
            let mut capped = false;
            let mut chosen = None;
            for (pattern, settings) in &named {
                let plain_match = *pattern == name.as_str() && !has_metachar(pattern);
                if (has_metachar(pattern) || !pattern.starts_with('/')) && !plain_match {
                    // A pattern the agent cannot evaluate (`SIMILAR TO`,
                    // or a plain file name): before the first match, the
                    // server might apply it instead (R2 rule 4).
                    capped = true;
                    continue;
                }
                if plain_match {
                    chosen = Some(*settings);
                    break;
                }
            }
            if capped {
                add(&mut not_evaluated, "similar_to_pattern");
            }
            let eff = chosen.map_or_else(|| default_db.clone(), |s| s.over(&default_db));
            match &effective {
                None => effective = Some(eff),
                Some(e) if *e != eff => {
                    add(&mut not_evaluated, "databases_conf");
                    detail.push(format!(
                        "{}: its names (path and aliases) have different trace settings",
                        db.label
                    ));
                }
                Some(_) => {}
            }
        }
        declared_names.extend(names);
        let eff = effective.unwrap_or_else(|| default_db.clone());
        // Proof 4.
        if eff.number("connection_id").unwrap_or(0) != 0 {
            add(&mut missing, "connection_id");
        }
        if !eff.flag("enabled") {
            add(&mut missing, "enabled");
        }
        match log_of(&eff, i.root) {
            Ok(Some(p)) if p == i.log => {}
            Err(()) => add(&mut not_evaluated, "similar_to_pattern"),
            _ => add(&mut missing, "log_filename"),
        }
        if eff.nonempty("include_filter") {
            add(&mut missing, "include_filter");
        }
        if eff.nonempty("exclude_filter") {
            add(&mut missing, "exclude_filter");
        }
        for flag in REQUIRED_FLAGS {
            if !eff.flag(flag) {
                add(&mut missing, flag);
            }
        }
        // GDS-code filters hide error records the rules read (R22): the
        // error records are then not all written.
        if eff.nonempty("include_gds_codes") || eff.nonempty("exclude_gds_codes") {
            add(&mut missing, "log_errors");
        }
        if eff.number("time_threshold").unwrap_or(100) != 0 {
            add(&mut missing, "time_threshold");
        }
        log_connections &= eff.flag("log_connections");
        let sql_length = eff.number("max_sql_length").unwrap_or(DEFAULT_SQL_LENGTH);
        if sql_length > MAX_SQL_LENGTH_CARRIED {
            // Sent as `other` until the label set has `max_sql_length`
            // (a contract revision).
            add(&mut missing, "max_sql_length");
            detail.push(format!(
                "{}: max_sql_length {sql_length} above {MAX_SQL_LENGTH_CARRIED} bytes, the \
                 longest statement text line the agent reads",
                db.label
            ));
        }
        max_sql = max_sql.min(sql_length);
    }
    if i.databases.is_empty() {
        max_sql = DEFAULT_SQL_LENGTH;
    }
    // Proof 11: the declared log holds only declared databases. A
    // `log_filename` with substitutions may be the declared log.
    let writes_here = |s: &Settings| {
        s.flag("enabled")
            && match log_of(s, i.root) {
                Ok(Some(p)) => p == i.log,
                Ok(None) => false,
                Err(()) => true,
            }
    };
    if writes_here(&default_db) {
        add(&mut not_evaluated, "foreign_databases_logged");
    }
    for (pattern, settings) in &named {
        if writes_here(&settings.over(&default_db))
            && (has_metachar(pattern) || !declared_names.iter().any(|n| n == pattern))
        {
            add(&mut not_evaluated, "foreign_databases_logged");
        }
    }
    // Proof 6 and R27 item 2: the services section.
    let services: Vec<&Section> = i
        .trace
        .sections
        .iter()
        .filter(|s| matches!(s.kind, SectionKind::Services(_)))
        .collect();
    let svc_ok = match services.as_slice() {
        [s] if s.kind == SectionKind::Services(None) => {
            s.settings.flag("enabled")
                && s.settings.flag("log_services")
                && matches!(log_of(&s.settings, i.root), Ok(Some(ref p)) if p == i.log)
                && !s.settings.nonempty("include_filter")
                && !s.settings.nonempty("exclude_filter")
        }
        _ => false,
    };
    let mut notes = Vec::new();
    if !svc_ok {
        add(&mut missing, "log_services");
        notes.push(TargetNote::new(NoteCode::AuditServicesNotAudited));
    }
    // Proof 5 and R8 item 6.
    let longest = u64::try_from(i.longest_own_text).unwrap_or(u64::MAX);
    let text_cap = max_sql < longest;
    if max_sql < MIN_SQL_LENGTH.max(longest) {
        notes.push(TargetNote::new(NoteCode::AuditStatementTextLimitLow));
    }
    if !missing.is_empty() {
        notes.push(
            TargetNote::new(NoteCode::AuditTraceSettingsMissing)
                .with_labels(missing.iter().map(|l| NoteLabel::firebird(l))),
        );
    }
    if !not_evaluated.is_empty() {
        notes.push(
            TargetNote::new(NoteCode::AuditTraceConfigNotEvaluated)
                .with_labels(not_evaluated.iter().map(|l| NoteLabel::firebird(l))),
        );
    }
    Verdict {
        partial: missing.is_empty() && not_evaluated.is_empty() && !text_cap,
        notes,
        max_sql_length: max_sql,
        log_connections,
        detail,
    }
}

/// The `audit.trace_config_not_evaluated` note for a configuration file
/// that could not be read or bound to the running server (proofs 1 and 2,
/// M3): one of the closed labels `firebird_conf_unreadable`,
/// `trace_config_unreadable`, `trace_config_file_mismatch`,
/// `config_changed_since_start`, `server_process_not_visible`,
/// `databases_conf`.
pub(crate) fn not_evaluated(label: &'static str) -> TargetNote {
    TargetNote::new(NoteCode::AuditTraceConfigNotEvaluated)
        .with_labels([NoteLabel::firebird(label)])
}

/// Proof 2's first half (M3): `AuditTraceConfigFile` of `firebird.conf`,
/// resolved against the root, names the declared trace configuration.
pub(crate) fn binds_trace_config(conf: &FirebirdConf, root: &str, declared: &str) -> bool {
    conf.trace_plugin_default
        && conf
            .audit_trace_config_file
            .as_deref()
            .and_then(|p| resolve(p, root))
            .is_some_and(|p| p == declared)
}

/// R9 rule 3: the evaluated map gives the declared database a
/// `SecurityDatabase` naming itself (its alias or its resolved path).
/// `None` when the map is not evaluated (the caller then excludes the
/// database where Audit is configured).
pub(crate) fn own_security_database(
    map: Option<&AliasMap>,
    db: &DeclaredDb<'_>,
    root: &str,
) -> Option<bool> {
    let map = map?;
    for a in map.aliases.iter().filter(|a| {
        db.alias == Some(a.name.as_str()) || (a.path.is_some() && a.path.as_deref() == db.resolved)
    }) {
        // An entry whose path is unknown: fail closed.
        let Some(path) = a.path.as_deref() else {
            return Some(true);
        };
        let Some(sec) = &a.security_database else {
            continue;
        };
        // An absolute path (or a macro), else an alias of the map; one
        // that resolves to nothing known is taken as this database.
        let target = if sec.starts_with('/') || sec.contains("$(") {
            resolve(sec, root)
        } else if sec == &a.name {
            Some(path.to_owned())
        } else {
            map.get(sec).and_then(|t| t.path.clone())
        };
        match target {
            Some(t) if t != path && Some(t.as_str()) != db.resolved => {}
            _ => return Some(true),
        }
    }
    Some(false)
}
