//! Statements and result decoding (ADR-0060 decisions 1, 2 and 4).
//!
//! - A **closed statement set** ([`STATEMENTS`]): constant texts only, no
//!   string built from job parameters; the session refuses any other text
//!   ([`checked`]). Every result column is cast on the server to one of the
//!   closed types (`INTEGER`, `BIGINT`, `SMALLINT`, `BOOLEAN`, `VARCHAR …
//!   CHARACTER SET UTF8` or `OCTETS`).
//! - The **describe** answer of `op_prepare_statement` (an info buffer) is
//!   parsed with bounds; a column of another type, a blob, an array, a
//!   declared length above 32 765 bytes, an input parameter, or more
//!   columns than the statement selects makes the statement fail and the
//!   attachment be replaced (fail closed).
//! - The output message is described in BLR with exactly these types, and
//!   rows (protocol 13+: a null bitmap, then the non-null values) are
//!   decoded with every length checked against its column before it is
//!   read.

use zeroize::Zeroizing;

use crate::xdr::{Reader, XdrError};

/// One of the connector's constant statements, by purpose.
pub(crate) struct Statement {
    pub(crate) name: &'static str,
    pub(crate) text: &'static str,
}

/// The engine version (decision 2).
pub(crate) const VERSION: &str = "SELECT CAST(RDB$GET_CONTEXT('SYSTEM', 'ENGINE_VERSION') AS VARCHAR(32) CHARACTER SET UTF8) FROM RDB$DATABASE";

/// The wire encryption and the transaction the server reports for this
/// attachment (decisions 3 and 4; context names measured on 5.0.4).
pub(crate) const SESSION: &str = "SELECT CAST(RDB$GET_CONTEXT('SYSTEM', 'WIRE_ENCRYPTED') AS VARCHAR(8) CHARACTER SET UTF8), CAST(RDB$GET_CONTEXT('SYSTEM', 'WIRE_CRYPT_PLUGIN') AS VARCHAR(63) CHARACTER SET UTF8), CAST(RDB$GET_CONTEXT('SYSTEM', 'READ_ONLY') AS VARCHAR(8) CHARACTER SET UTF8), CAST(RDB$GET_CONTEXT('SYSTEM', 'ISOLATION_LEVEL') AS VARCHAR(31) CHARACTER SET UTF8) FROM RDB$DATABASE";

/// The agent's own attachment as the server sees it (decision 3, the
/// forwarder rule; refinement R1, the run identity).
pub(crate) const OWN_ATTACHMENT: &str = "SELECT CURRENT_CONNECTION, CAST(MON$REMOTE_PROTOCOL AS VARCHAR(16) CHARACTER SET UTF8), CAST(MON$REMOTE_ADDRESS AS VARCHAR(255) CHARACTER SET UTF8), CAST(MON$SERVER_PID AS INTEGER) FROM MON$ATTACHMENTS WHERE MON$ATTACHMENT_ID = CURRENT_CONNECTION";

/// The server-side safety net of the connector obligations (decision 3):
/// an idle attachment is ended by the server after 2 minutes.
pub(crate) const IDLE_TIMEOUT: &str = "SET SESSION IDLE TIMEOUT 2 MINUTE";

/// The effective identity (decision 4): never `CURRENT_ROLE` to decide
/// (a `DEFAULT` role is in use while `CURRENT_ROLE` is `NONE`, refinement
/// R4), the owner of the database, the security-database flag of the
/// account's own row.
pub(crate) const IDENTITY: &str = "SELECT CAST(CURRENT_USER AS VARCHAR(63) CHARACTER SET UTF8), CAST(CURRENT_ROLE AS VARCHAR(63) CHARACTER SET UTF8), RDB$ROLE_IN_USE('RDB$ADMIN'), (SELECT CAST(TRIM(TRAILING FROM MON$OWNER) AS VARCHAR(63) CHARACTER SET UTF8) FROM MON$DATABASE), (SELECT COALESCE(MAX(CASE WHEN SEC$ADMIN THEN 1 ELSE 0 END), -1) FROM SEC$USERS WHERE SEC$USER_NAME = CURRENT_USER) FROM RDB$DATABASE";

/// The effective system privileges of the session (decision 4), in the
/// order of the bit table ([`crate::privileges::SYSTEM_PRIVILEGES`]) up to
/// `REPLICATE_INTO_DATABASE`, the Firebird 4.0 list. The argument is an
/// unquoted keyword (refinement R4).
pub(crate) const SYSTEM_PRIVILEGES_4: &str = "SELECT RDB$SYSTEM_PRIVILEGE(USER_MANAGEMENT), RDB$SYSTEM_PRIVILEGE(READ_RAW_PAGES), RDB$SYSTEM_PRIVILEGE(CREATE_USER_TYPES), RDB$SYSTEM_PRIVILEGE(USE_NBACKUP_UTILITY), RDB$SYSTEM_PRIVILEGE(CHANGE_SHUTDOWN_MODE), RDB$SYSTEM_PRIVILEGE(TRACE_ANY_ATTACHMENT), RDB$SYSTEM_PRIVILEGE(MONITOR_ANY_ATTACHMENT), RDB$SYSTEM_PRIVILEGE(ACCESS_SHUTDOWN_DATABASE), RDB$SYSTEM_PRIVILEGE(CREATE_DATABASE), RDB$SYSTEM_PRIVILEGE(DROP_DATABASE), RDB$SYSTEM_PRIVILEGE(USE_GBAK_UTILITY), RDB$SYSTEM_PRIVILEGE(USE_GSTAT_UTILITY), RDB$SYSTEM_PRIVILEGE(USE_GFIX_UTILITY), RDB$SYSTEM_PRIVILEGE(IGNORE_DB_TRIGGERS), RDB$SYSTEM_PRIVILEGE(CHANGE_HEADER_SETTINGS), RDB$SYSTEM_PRIVILEGE(SELECT_ANY_OBJECT_IN_DATABASE), RDB$SYSTEM_PRIVILEGE(ACCESS_ANY_OBJECT_IN_DATABASE), RDB$SYSTEM_PRIVILEGE(MODIFY_ANY_OBJECT_IN_DATABASE), RDB$SYSTEM_PRIVILEGE(CHANGE_MAPPING_RULES), RDB$SYSTEM_PRIVILEGE(USE_GRANTED_BY_CLAUSE), RDB$SYSTEM_PRIVILEGE(GRANT_REVOKE_ON_ANY_OBJECT), RDB$SYSTEM_PRIVILEGE(GRANT_REVOKE_ANY_DDL_RIGHT), RDB$SYSTEM_PRIVILEGE(CREATE_PRIVILEGED_ROLES), RDB$SYSTEM_PRIVILEGE(GET_DBCRYPT_INFO), RDB$SYSTEM_PRIVILEGE(MODIFY_EXT_CONN_POOL), RDB$SYSTEM_PRIVILEGE(REPLICATE_INTO_DATABASE) FROM RDB$DATABASE";

/// `PROFILE_ANY_ATTACHMENT` (Firebird 5.0).
pub(crate) const SYSTEM_PRIVILEGES_5: &str =
    "SELECT RDB$SYSTEM_PRIVILEGE(PROFILE_ANY_ATTACHMENT) FROM RDB$DATABASE";

/// Role memberships (`RDB$PRIVILEGE = 'M'`), for the role graph of
/// decision 4: every role the account could use, not only those in use.
pub(crate) const ROLE_MEMBERSHIPS: &str = "SELECT CAST(TRIM(TRAILING FROM RDB$USER) AS VARCHAR(63) CHARACTER SET UTF8), CAST(RDB$USER_TYPE AS INTEGER), CAST(TRIM(TRAILING FROM RDB$RELATION_NAME) AS VARCHAR(63) CHARACTER SET UTF8), CAST(COALESCE(RDB$GRANT_OPTION, 0) AS INTEGER) FROM RDB$USER_PRIVILEGES WHERE RDB$PRIVILEGE = 'M' AND RDB$USER_TYPE IN (8, 13)";

/// Every role's system-privilege bit mask (decision 4), as 8 raw bytes.
/// The authentication mappings of the database (review L2): how each
/// mapping is used (`P` a plugin, `S` any plugin server-wide, `M` another
/// mapping, `*` any), its plugin, its source type, whether its source is
/// the account or any user (computed by the server: the source name is
/// never read), and its target type and name.
pub(crate) const AUTH_MAPPINGS: &str = "SELECT CAST(TRIM(TRAILING FROM RDB$MAP_USING) AS VARCHAR(4) CHARACTER SET UTF8), CAST(TRIM(TRAILING FROM RDB$MAP_PLUGIN) AS VARCHAR(63) CHARACTER SET UTF8), CAST(TRIM(TRAILING FROM RDB$MAP_FROM_TYPE) AS VARCHAR(63) CHARACTER SET UTF8), CASE WHEN RDB$MAP_FROM IN (CURRENT_USER, '*') THEN TRUE ELSE FALSE END, CAST(RDB$MAP_TO_TYPE AS INTEGER), CAST(TRIM(TRAILING FROM RDB$MAP_TO) AS VARCHAR(63) CHARACTER SET UTF8) FROM RDB$AUTH_MAPPING";

/// The same for the global mappings of the security database.
pub(crate) const GLOBAL_AUTH_MAPPINGS: &str = "SELECT CAST(TRIM(TRAILING FROM SEC$MAP_USING) AS VARCHAR(4) CHARACTER SET UTF8), CAST(TRIM(TRAILING FROM SEC$MAP_PLUGIN) AS VARCHAR(63) CHARACTER SET UTF8), CAST(TRIM(TRAILING FROM SEC$MAP_FROM_TYPE) AS VARCHAR(63) CHARACTER SET UTF8), CASE WHEN SEC$MAP_FROM IN (CURRENT_USER, '*') THEN TRUE ELSE FALSE END, CAST(SEC$MAP_TO_TYPE AS INTEGER), CAST(TRIM(TRAILING FROM SEC$MAP_TO) AS VARCHAR(63) CHARACTER SET UTF8) FROM SEC$GLOBAL_AUTH_MAPPING";

pub(crate) const ROLE_PRIVILEGES: &str = "SELECT CAST(TRIM(TRAILING FROM RDB$ROLE_NAME) AS VARCHAR(63) CHARACTER SET UTF8), CAST(RDB$SYSTEM_PRIVILEGES AS VARCHAR(8) CHARACTER SET OCTETS) FROM RDB$ROLES";

/// Object grants to the account, `PUBLIC` and roles (decision 4) other
/// than a plain `SELECT` (the only right the account needs, so the read
/// does not grow with the tables granted), with whether the object is a
/// system object (its catalog's `RDB$SYSTEM_FLAG`, never its name): the
/// grantee, its type, the privilege letter, the grant option, the object,
/// its type, whether the grant is on a column, the system flag.
pub(crate) const OBJECT_GRANTS: &str = "SELECT CAST(TRIM(TRAILING FROM P.RDB$USER) AS VARCHAR(63) CHARACTER SET UTF8), CAST(P.RDB$USER_TYPE AS INTEGER), CAST(TRIM(TRAILING FROM P.RDB$PRIVILEGE) AS VARCHAR(6) CHARACTER SET UTF8), CAST(COALESCE(P.RDB$GRANT_OPTION, 0) AS INTEGER), CAST(TRIM(TRAILING FROM P.RDB$RELATION_NAME) AS VARCHAR(63) CHARACTER SET UTF8), CAST(P.RDB$OBJECT_TYPE AS INTEGER), CASE WHEN P.RDB$FIELD_NAME IS NULL THEN FALSE ELSE TRUE END, CAST(CASE P.RDB$OBJECT_TYPE WHEN 0 THEN (SELECT MAX(COALESCE(R.RDB$SYSTEM_FLAG, 0)) FROM RDB$RELATIONS R WHERE R.RDB$RELATION_NAME = P.RDB$RELATION_NAME) WHEN 1 THEN (SELECT MAX(COALESCE(R.RDB$SYSTEM_FLAG, 0)) FROM RDB$RELATIONS R WHERE R.RDB$RELATION_NAME = P.RDB$RELATION_NAME) WHEN 5 THEN (SELECT MAX(COALESCE(X.RDB$SYSTEM_FLAG, 0)) FROM RDB$PROCEDURES X WHERE X.RDB$PROCEDURE_NAME = P.RDB$RELATION_NAME AND X.RDB$PACKAGE_NAME IS NULL) WHEN 7 THEN (SELECT MAX(COALESCE(X.RDB$SYSTEM_FLAG, 0)) FROM RDB$EXCEPTIONS X WHERE X.RDB$EXCEPTION_NAME = P.RDB$RELATION_NAME) WHEN 9 THEN (SELECT MAX(COALESCE(X.RDB$SYSTEM_FLAG, 0)) FROM RDB$FIELDS X WHERE X.RDB$FIELD_NAME = P.RDB$RELATION_NAME) WHEN 11 THEN (SELECT MAX(COALESCE(X.RDB$SYSTEM_FLAG, 0)) FROM RDB$CHARACTER_SETS X WHERE X.RDB$CHARACTER_SET_NAME = P.RDB$RELATION_NAME) WHEN 14 THEN (SELECT MAX(COALESCE(X.RDB$SYSTEM_FLAG, 0)) FROM RDB$GENERATORS X WHERE X.RDB$GENERATOR_NAME = P.RDB$RELATION_NAME) WHEN 15 THEN (SELECT MAX(COALESCE(X.RDB$SYSTEM_FLAG, 0)) FROM RDB$FUNCTIONS X WHERE X.RDB$FUNCTION_NAME = P.RDB$RELATION_NAME AND X.RDB$PACKAGE_NAME IS NULL) WHEN 17 THEN (SELECT MAX(COALESCE(X.RDB$SYSTEM_FLAG, 0)) FROM RDB$COLLATIONS X WHERE X.RDB$COLLATION_NAME = P.RDB$RELATION_NAME) WHEN 18 THEN (SELECT MAX(COALESCE(X.RDB$SYSTEM_FLAG, 0)) FROM RDB$PACKAGES X WHERE X.RDB$PACKAGE_NAME = P.RDB$RELATION_NAME) ELSE 0 END AS INTEGER) FROM RDB$USER_PRIVILEGES P WHERE P.RDB$PRIVILEGE <> 'M' AND (P.RDB$PRIVILEGE <> 'S' OR COALESCE(P.RDB$GRANT_OPTION, 0) > 0) AND ((P.RDB$USER_TYPE = 8 AND P.RDB$USER IN (CURRENT_USER, 'PUBLIC')) OR P.RDB$USER_TYPE = 13)";

/// Objects the account owns (decision 4): relations, procedures,
/// functions, packages, generators, exceptions, domains and roles, user
/// objects only (system flag 0).
pub(crate) const OWNED_OBJECTS: &str = "SELECT (SELECT COUNT(*) FROM RDB$RELATIONS WHERE RDB$OWNER_NAME = CURRENT_USER AND COALESCE(RDB$SYSTEM_FLAG, 0) = 0) + (SELECT COUNT(*) FROM RDB$PROCEDURES WHERE RDB$OWNER_NAME = CURRENT_USER AND COALESCE(RDB$SYSTEM_FLAG, 0) = 0) + (SELECT COUNT(*) FROM RDB$FUNCTIONS WHERE RDB$OWNER_NAME = CURRENT_USER AND COALESCE(RDB$SYSTEM_FLAG, 0) = 0) + (SELECT COUNT(*) FROM RDB$PACKAGES WHERE RDB$OWNER_NAME = CURRENT_USER AND COALESCE(RDB$SYSTEM_FLAG, 0) = 0) + (SELECT COUNT(*) FROM RDB$GENERATORS WHERE RDB$OWNER_NAME = CURRENT_USER AND COALESCE(RDB$SYSTEM_FLAG, 0) = 0) + (SELECT COUNT(*) FROM RDB$EXCEPTIONS WHERE RDB$OWNER_NAME = CURRENT_USER AND COALESCE(RDB$SYSTEM_FLAG, 0) = 0) + (SELECT COUNT(*) FROM RDB$FIELDS WHERE RDB$OWNER_NAME = CURRENT_USER AND COALESCE(RDB$SYSTEM_FLAG, 0) = 0) + (SELECT COUNT(*) FROM RDB$ROLES WHERE RDB$OWNER_NAME = CURRENT_USER AND COALESCE(RDB$SYSTEM_FLAG, 0) = 0) FROM RDB$DATABASE";

/// Active database triggers (decision 4): `ON CONNECT` (8192) and `ON
/// TRANSACTION START` (8194) run user code at every attachment and
/// transaction of the agent.
pub(crate) const DATABASE_TRIGGERS: &str = "SELECT (SELECT COUNT(*) FROM RDB$TRIGGERS WHERE RDB$TRIGGER_TYPE = 8192 AND COALESCE(RDB$TRIGGER_INACTIVE, 0) = 0), (SELECT COUNT(*) FROM RDB$TRIGGERS WHERE RDB$TRIGGER_TYPE = 8194 AND COALESCE(RDB$TRIGGER_INACTIVE, 0) = 0) FROM RDB$DATABASE";

/// Which relations of the credential list exist in this database
/// (decision 4, security review M5): a database can be its own security
/// database.
pub(crate) const CREDENTIAL_RELATIONS: &str = "SELECT CAST(TRIM(TRAILING FROM RDB$RELATION_NAME) AS VARCHAR(63) CHARACTER SET UTF8) FROM RDB$RELATIONS WHERE RDB$RELATION_NAME IN ('PLG$SRP', 'PLG$SRP_VIEW', 'PLG$USERS', 'PLG$VIEW_USERS', 'SEC$USERS', 'SEC$USER_ATTRIBUTES', 'SEC$GLOBAL_AUTH_MAPPING', 'RDB$CONFIG')";

/// The one-bit readability probes of decision 4 (no row content
/// returned), one constant text per relation of the closed credential
/// list. `SEC$USERS` and `SEC$USER_ATTRIBUTES` are probed beyond the
/// account's own row, which every user sees.
pub(crate) const PROBES: &[(&str, &str)] = &[
    (
        "PLG$SRP",
        "SELECT CASE WHEN EXISTS (SELECT 1 FROM PLG$SRP) THEN 1 ELSE 0 END FROM RDB$DATABASE",
    ),
    (
        "PLG$SRP_VIEW",
        "SELECT CASE WHEN EXISTS (SELECT 1 FROM PLG$SRP_VIEW) THEN 1 ELSE 0 END FROM RDB$DATABASE",
    ),
    (
        "PLG$USERS",
        "SELECT CASE WHEN EXISTS (SELECT 1 FROM PLG$USERS) THEN 1 ELSE 0 END FROM RDB$DATABASE",
    ),
    (
        "PLG$VIEW_USERS",
        "SELECT CASE WHEN EXISTS (SELECT 1 FROM PLG$VIEW_USERS) THEN 1 ELSE 0 END FROM RDB$DATABASE",
    ),
    (
        "SEC$USERS",
        "SELECT CASE WHEN EXISTS (SELECT 1 FROM SEC$USERS WHERE SEC$USER_NAME <> CURRENT_USER) THEN 1 ELSE 0 END FROM RDB$DATABASE",
    ),
    (
        "SEC$USER_ATTRIBUTES",
        "SELECT CASE WHEN EXISTS (SELECT 1 FROM SEC$USER_ATTRIBUTES WHERE SEC$USER_NAME <> CURRENT_USER) THEN 1 ELSE 0 END FROM RDB$DATABASE",
    ),
    (
        "SEC$GLOBAL_AUTH_MAPPING",
        "SELECT CASE WHEN EXISTS (SELECT 1 FROM SEC$GLOBAL_AUTH_MAPPING) THEN 1 ELSE 0 END FROM RDB$DATABASE",
    ),
    (
        "RDB$CONFIG",
        "SELECT CASE WHEN EXISTS (SELECT 1 FROM RDB$CONFIG) THEN 1 ELSE 0 END FROM RDB$DATABASE",
    ),
];

/// Every statement the connector may send.
pub(crate) const STATEMENTS: &[Statement] = &[
    Statement {
        name: "version",
        text: VERSION,
    },
    Statement {
        name: "session",
        text: SESSION,
    },
    Statement {
        name: "own_attachment",
        text: OWN_ATTACHMENT,
    },
    Statement {
        name: "idle_timeout",
        text: IDLE_TIMEOUT,
    },
    Statement {
        name: "identity",
        text: IDENTITY,
    },
    Statement {
        name: "system_privileges_4",
        text: SYSTEM_PRIVILEGES_4,
    },
    Statement {
        name: "system_privileges_5",
        text: SYSTEM_PRIVILEGES_5,
    },
    Statement {
        name: "role_memberships",
        text: ROLE_MEMBERSHIPS,
    },
    Statement {
        name: "role_privileges",
        text: ROLE_PRIVILEGES,
    },
    Statement {
        name: "auth_mappings",
        text: AUTH_MAPPINGS,
    },
    Statement {
        name: "global_auth_mappings",
        text: GLOBAL_AUTH_MAPPINGS,
    },
    Statement {
        name: "object_grants",
        text: OBJECT_GRANTS,
    },
    Statement {
        name: "owned_objects",
        text: OWNED_OBJECTS,
    },
    Statement {
        name: "database_triggers",
        text: DATABASE_TRIGGERS,
    },
    Statement {
        name: "credential_relations",
        text: CREDENTIAL_RELATIONS,
    },
];

/// Words no statement of the connector contains outside quotes (I4: it
/// only reads; no PSQL, no outbound connection, no services).
pub(crate) const DENIED: &[&str] = &[
    "insert",
    "update",
    "delete",
    "merge",
    "upsert",
    "create",
    "alter",
    "drop",
    "recreate",
    "grant",
    "revoke",
    "execute",
    "external",
    "commit",
    "rollback",
    "savepoint",
    "for update",
    "with lock",
    "rdb$set_context",
    "gen_id",
    "next value",
    "into",
    "returning",
    "declare",
    "begin",
];

/// The statement text with its quoted identifiers and literals emptied,
/// lower-cased: what [`DENIED`] is checked on.
#[must_use]
pub(crate) fn unquoted(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut quote: Option<char> = None;
    for c in text.chars() {
        match quote {
            Some(q) if c == q => {
                quote = None;
                out.push(c);
            }
            Some(_) => {}
            None => {
                if c == '\'' || c == '"' {
                    quote = Some(c);
                }
                out.extend(c.to_lowercase());
            }
        }
    }
    out
}

/// Whether the skeleton of `text` ([`unquoted`]) holds a word of
/// [`DENIED`] as a whole word (identifier characters `[a-z0-9_$]` delimit
/// words, so a system privilege named `CREATE_USER_TYPES` is not
/// `create`).
#[must_use]
pub(crate) fn has_denied_word(text: &str) -> bool {
    let skeleton = unquoted(text);
    let words: Vec<&str> = skeleton
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '$'))
        .filter(|w| !w.is_empty())
        .collect();
    DENIED.iter().any(|denied| {
        let parts: Vec<&str> = denied.split(' ').collect();
        words.windows(parts.len()).any(|w| w == parts.as_slice())
    })
}

/// Whether `text` is one of the connector's statements (the run-time
/// check of the closed set).
#[must_use]
pub(crate) fn checked(text: &str) -> bool {
    STATEMENTS.iter().any(|s| s.text == text) || PROBES.iter().any(|(_, t)| *t == text)
}

/// Quotes an identifier from the catalog (Discovery, lot 2): `"`, with `"`
/// doubled. The only quoting function of the connector.
#[must_use]
#[cfg_attr(not(test), allow(dead_code, reason = "used by Discovery (lot 2)"))]
pub(crate) fn quote_identifier(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 2);
    out.push('"');
    for c in name.chars() {
        if c == '"' {
            out.push('"');
        }
        out.push(c);
    }
    out.push('"');
    out
}

/// `isc_info_sql_*` items.
pub(crate) mod info {
    pub(crate) const END: u8 = 1;
    pub(crate) const TRUNCATED: u8 = 2;
    pub(crate) const SELECT: u8 = 4;
    pub(crate) const BIND: u8 = 5;
    pub(crate) const DESCRIBE_VARS: u8 = 7;
    pub(crate) const DESCRIBE_END: u8 = 8;
    pub(crate) const SQLDA_SEQ: u8 = 9;
    pub(crate) const TYPE: u8 = 11;
    pub(crate) const SUB_TYPE: u8 = 12;
    pub(crate) const SCALE: u8 = 13;
    pub(crate) const LENGTH: u8 = 14;
    pub(crate) const STMT_TYPE: u8 = 21;
}

/// The describe items sent with every prepare: the statement type, the
/// output columns (type, sub-type, scale, length) and the count of input
/// parameters.
pub(crate) const DESCRIBE_ITEMS: &[u8] = &[
    info::STMT_TYPE,
    info::SELECT,
    info::DESCRIBE_VARS,
    info::SQLDA_SEQ,
    info::TYPE,
    info::SUB_TYPE,
    info::SCALE,
    info::LENGTH,
    info::DESCRIBE_END,
    info::BIND,
    info::DESCRIBE_VARS,
    info::END,
];

/// The answer size asked for the describe items.
pub(crate) const DESCRIBE_BUFFER: u32 = 65_535;

/// Most output columns of one statement.
pub(crate) const MAX_COLUMNS: usize = 255;
/// Longest declared column (the protocol's bound for a `VARCHAR`).
pub(crate) const MAX_COLUMN_BYTES: u32 = 32_765;

/// `SQL_*` types (nullable bit cleared).
pub(crate) mod sqltype {
    pub(crate) const VARYING: i32 = 448;
    pub(crate) const LONG: i32 = 496;
    pub(crate) const SHORT: i32 = 500;
    pub(crate) const INT64: i32 = 580;
    pub(crate) const BOOLEAN: i32 = 32_764;
}

/// Character sets of a `VARYING` column.
pub(crate) mod charset {
    pub(crate) const OCTETS: i32 = 1;
    pub(crate) const UTF8: i32 = 4;
}

/// `isc_info_sql_stmt_select`.
pub(crate) const STMT_SELECT: i64 = 1;

/// A described output column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Column {
    pub(crate) sqltype: i32,
    pub(crate) sub_type: i32,
    pub(crate) scale: i32,
    pub(crate) length: u32,
}

/// A parsed describe answer.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Describe {
    pub(crate) stmt_type: i64,
    pub(crate) columns: Vec<Column>,
    pub(crate) parameters: u32,
}

/// What a statement's caller expects of each column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Col {
    /// `SMALLINT`, `INTEGER` or `BIGINT`, scale 0.
    Int,
    /// `BOOLEAN`.
    Bool,
    /// `VARCHAR(n) CHARACTER SET UTF8`, at most `n` bytes declared.
    Text(u32),
    /// `VARCHAR(n) CHARACTER SET OCTETS`, at most `n` bytes declared.
    Octets(u32),
}

fn le_int(bytes: &[u8]) -> Option<i64> {
    match bytes.len() {
        1 => Some(i64::from(i8::from_le_bytes([bytes[0]]))),
        2 => Some(i64::from(i16::from_le_bytes([bytes[0], bytes[1]]))),
        4 => Some(i64::from(i32::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
        ]))),
        _ => None,
    }
}

/// Parses the describe answer (an info buffer of `isc_info_sql_*` items,
/// each with a 2-byte little-endian length and a little-endian value).
/// Truncated, an unknown item, values outside their ranges, a column count
/// that does not match: refused.
pub(crate) fn parse_describe(buf: &[u8]) -> Result<Describe, XdrError> {
    #[derive(PartialEq)]
    enum Section {
        None,
        Select,
        Bind,
    }
    let mut out = Describe {
        stmt_type: -1,
        ..Describe::default()
    };
    let mut section = Section::None;
    let mut declared: Option<usize> = None;
    let mut current: Option<usize> = None;
    let mut i = 0;
    let mut ended = false;
    while i < buf.len() {
        let item = buf[i];
        i += 1;
        match item {
            info::END => {
                ended = true;
                break;
            }
            info::SELECT => {
                section = Section::Select;
                continue;
            }
            info::BIND => {
                section = Section::Bind;
                continue;
            }
            info::DESCRIBE_END => {
                current = None;
                continue;
            }
            info::TRUNCATED => return Err(XdrError::Bound),
            _ => {}
        }
        let len_bytes = buf.get(i..i + 2).ok_or(XdrError::Bound)?;
        let len = usize::from(u16::from_le_bytes([len_bytes[0], len_bytes[1]]));
        let value = buf.get(i + 2..i + 2 + len).ok_or(XdrError::Bound)?;
        i += 2 + len;
        let v = le_int(value).ok_or(XdrError::Bound)?;
        match (item, &section) {
            (info::STMT_TYPE, _) => out.stmt_type = v,
            (info::DESCRIBE_VARS, Section::Select) => {
                let n = usize::try_from(v).map_err(|_| XdrError::Bound)?;
                if n > MAX_COLUMNS || declared.is_some() {
                    return Err(XdrError::Bound);
                }
                declared = Some(n);
                out.columns = vec![Column::default(); n];
            }
            (info::DESCRIBE_VARS, Section::Bind) => {
                out.parameters = u32::try_from(v).map_err(|_| XdrError::Bound)?;
            }
            (info::SQLDA_SEQ, Section::Select) => {
                let n = usize::try_from(v).map_err(|_| XdrError::Bound)?;
                if n == 0 || n > out.columns.len() {
                    return Err(XdrError::Bound);
                }
                current = Some(n - 1);
            }
            (info::TYPE | info::SUB_TYPE | info::SCALE | info::LENGTH, Section::Select) => {
                let col = current
                    .and_then(|c| out.columns.get_mut(c))
                    .ok_or(XdrError::Bound)?;
                let v32 = i32::try_from(v).map_err(|_| XdrError::Bound)?;
                match item {
                    info::TYPE => col.sqltype = v32 & !1,
                    info::SUB_TYPE => col.sub_type = v32,
                    info::SCALE => col.scale = v32,
                    _ => col.length = u32::try_from(v32).map_err(|_| XdrError::Bound)?,
                }
            }
            _ => return Err(XdrError::Bound),
        }
    }
    if !ended || declared.is_none() {
        return Err(XdrError::Bound);
    }
    Ok(out)
}

/// Whether the described columns are exactly `shape` (decision 1: the
/// closed type set, declared lengths within bounds, no blob or array).
pub(crate) fn matches_shape(columns: &[Column], shape: &[Col]) -> bool {
    columns.len() == shape.len()
        && columns.iter().zip(shape).all(|(c, s)| match s {
            Col::Int => {
                matches!(c.sqltype, sqltype::SHORT | sqltype::LONG | sqltype::INT64) && c.scale == 0
            }
            Col::Bool => c.sqltype == sqltype::BOOLEAN && c.length == 1,
            Col::Text(max) => {
                c.sqltype == sqltype::VARYING
                    && c.sub_type & 0xFF == charset::UTF8
                    && c.length <= *max
                    && c.length <= MAX_COLUMN_BYTES
            }
            Col::Octets(max) => {
                c.sqltype == sqltype::VARYING
                    && c.sub_type & 0xFF == charset::OCTETS
                    && c.length <= *max
                    && c.length <= MAX_COLUMN_BYTES
            }
        })
}

/// BLR codes of the output message.
mod blr {
    pub(super) const VERSION5: u8 = 5;
    pub(super) const BEGIN: u8 = 2;
    pub(super) const MESSAGE: u8 = 4;
    pub(super) const SHORT: u8 = 7;
    pub(super) const LONG: u8 = 8;
    pub(super) const INT64: u8 = 16;
    pub(super) const BOOL: u8 = 23;
    pub(super) const VARYING2: u8 = 38;
    pub(super) const END: u8 = 255;
    pub(super) const EOC: u8 = 76;
}

/// The output message in BLR for checked columns: each column with its
/// type, then a `SHORT` null indicator.
pub(crate) fn output_blr(columns: &[Column]) -> Vec<u8> {
    let mut out = vec![blr::VERSION5, blr::BEGIN, blr::MESSAGE, 0];
    let params = u16::try_from(columns.len() * 2).unwrap_or(u16::MAX);
    out.extend_from_slice(&params.to_le_bytes());
    for c in columns {
        match c.sqltype {
            sqltype::VARYING => {
                out.push(blr::VARYING2);
                out.push(u8::try_from(c.sub_type & 0xFF).unwrap_or(0));
                out.push(0);
                out.extend_from_slice(&u16::try_from(c.length).unwrap_or(0).to_le_bytes());
            }
            sqltype::SHORT => out.extend_from_slice(&[blr::SHORT, 0]),
            sqltype::LONG => out.extend_from_slice(&[blr::LONG, 0]),
            sqltype::INT64 => out.extend_from_slice(&[blr::INT64, 0]),
            _ => out.push(blr::BOOL),
        }
        out.extend_from_slice(&[blr::SHORT, 0]);
    }
    out.extend_from_slice(&[blr::END, blr::EOC]);
    out
}

/// A decoded value. Text and bytes are zeroized when dropped (from
/// Discovery on they carry sampled values).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Value {
    Null,
    Int(i64),
    Bool(bool),
    Text(Zeroizing<String>),
    Bytes(Zeroizing<Vec<u8>>),
}

impl Value {
    pub(crate) fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(v) => Some(*v),
            _ => None,
        }
    }

    pub(crate) fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(v) => Some(*v),
            _ => None,
        }
    }

    pub(crate) fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(v) => Some(v.as_str()),
            _ => None,
        }
    }

    pub(crate) fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(v) => Some(v.as_slice()),
            _ => None,
        }
    }
}

/// One row (protocol 13+): a null bitmap of `(columns + 7) / 8` bytes
/// padded to 4, then the non-null values, each length checked against its
/// column's declared length before it is read. Invalid UTF-8 in a `UTF8`
/// column or a boolean other than 0 / 1 is refused.
pub(crate) fn parse_row(r: &mut Reader<'_>, columns: &[Column]) -> Result<Vec<Value>, XdrError> {
    let bitmap_len = columns.len().div_ceil(8);
    let bitmap = r.raw(bitmap_len)?;
    r.pad(bitmap_len)?;
    let mut row = Vec::with_capacity(columns.len());
    for (i, c) in columns.iter().enumerate() {
        if bitmap[i / 8] & (1 << (i % 8)) != 0 {
            row.push(Value::Null);
            continue;
        }
        row.push(match c.sqltype {
            sqltype::VARYING => {
                let bytes = r.opaque(usize::try_from(c.length).map_err(|_| XdrError::Bound)?)?;
                if c.sub_type & 0xFF == charset::UTF8 {
                    let text = std::str::from_utf8(bytes).map_err(|_| XdrError::Bound)?;
                    Value::Text(Zeroizing::new(text.to_owned()))
                } else {
                    Value::Bytes(Zeroizing::new(bytes.to_vec()))
                }
            }
            sqltype::SHORT | sqltype::LONG => Value::Int(i64::from(r.i32()?)),
            sqltype::INT64 => Value::Int(r.i64()?),
            sqltype::BOOLEAN => {
                let b = r.raw(1)?[0];
                r.pad(1)?;
                match b {
                    0 => Value::Bool(false),
                    1 => Value::Bool(true),
                    _ => return Err(XdrError::Bound),
                }
            }
            _ => return Err(XdrError::Bound),
        });
    }
    Ok(row)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// The describe answer of the 5.0.4 server for `SELECT CAST(… AS
    /// VARCHAR(32) CHARACTER SET UTF8), CURRENT_CONNECTION,
    /// RDB$ROLE_IN_USE('RDB$ADMIN') FROM RDB$DATABASE` (captured).
    const CAPTURED: &str = "150400010000000407040003000000090400010000000b0400c10100000c0400040000000d0400000000000e04008000000008090400020000000b0400440200000c0400000000000d0400000000000e04000800000008090400030000000b0400fc7f00000c0400000000000d0400000000000e04000100000008050704000000000001";

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn the_captured_describe_answer_parses() {
        let d = parse_describe(&unhex(CAPTURED)).unwrap();
        assert_eq!(d.stmt_type, STMT_SELECT);
        assert_eq!(d.parameters, 0);
        assert_eq!(
            d.columns,
            [
                Column {
                    sqltype: sqltype::VARYING,
                    sub_type: 4,
                    scale: 0,
                    length: 128
                },
                Column {
                    sqltype: sqltype::INT64,
                    sub_type: 0,
                    scale: 0,
                    length: 8
                },
                Column {
                    sqltype: sqltype::BOOLEAN,
                    sub_type: 0,
                    scale: 0,
                    length: 1
                },
            ]
        );
        assert!(matches_shape(
            &d.columns,
            &[Col::Text(128), Col::Int, Col::Bool]
        ));
        assert!(!matches_shape(
            &d.columns,
            &[Col::Text(64), Col::Int, Col::Bool]
        ));
        assert!(!matches_shape(
            &d.columns,
            &[Col::Octets(128), Col::Int, Col::Bool]
        ));
        assert!(!matches_shape(&d.columns, &[Col::Text(128), Col::Int]));
        // The BLR of the captured probe (which the server accepted).
        assert_eq!(
            output_blr(&d.columns),
            [
                5, 2, 4, 0, 6, 0, 38, 4, 0, 128, 0, 7, 0, 16, 0, 7, 0, 23, 7, 0, 255, 76
            ]
        );
    }

    #[test]
    fn hostile_describe_answers_are_refused() {
        let good = unhex(CAPTURED);
        // Truncated anywhere, or marked truncated.
        for cut in 0..good.len() - 1 {
            assert!(parse_describe(&good[..cut]).is_err(), "{cut}");
        }
        let mut t = good[..good.len() - 1].to_vec();
        t.push(info::TRUNCATED);
        assert!(parse_describe(&t).is_err());
        // An unknown item, a column index past the count, a huge count.
        assert!(parse_describe(&[0x40, 1, 0, 0, info::END]).is_err());
        assert!(
            parse_describe(&[
                info::SELECT,
                info::DESCRIBE_VARS,
                4,
                0,
                1,
                0,
                0,
                0,
                info::SQLDA_SEQ,
                4,
                0,
                2,
                0,
                0,
                0,
                info::END
            ])
            .is_err()
        );
        assert!(
            parse_describe(&[
                info::SELECT,
                info::DESCRIBE_VARS,
                4,
                0,
                0,
                1,
                0,
                0,
                info::END
            ])
            .is_err()
        );
    }

    #[test]
    fn rows_are_decoded_with_bounds() {
        let cols = [
            Column {
                sqltype: sqltype::VARYING,
                sub_type: 4,
                scale: 0,
                length: 8,
            },
            Column {
                sqltype: sqltype::INT64,
                ..Column::default()
            },
            Column {
                sqltype: sqltype::BOOLEAN,
                length: 1,
                ..Column::default()
            },
            Column {
                sqltype: sqltype::LONG,
                ..Column::default()
            },
        ];
        // Captured shape: bitmap (column 3 null), "5.0.4", 16, false.
        let mut bytes = vec![0b1000, 0, 0, 0];
        bytes.extend_from_slice(&[0, 0, 0, 5]);
        bytes.extend_from_slice(b"5.0.4\0\0\0");
        bytes.extend_from_slice(&16i64.to_be_bytes());
        bytes.extend_from_slice(&[0, 0, 0, 0]);
        let row = parse_row(&mut Reader::new(&bytes), &cols).unwrap();
        assert_eq!(row[0].as_text(), Some("5.0.4"));
        assert_eq!(row[1].as_int(), Some(16));
        assert_eq!(row[2].as_bool(), Some(false));
        assert_eq!(row[3], Value::Null);
        // A value longer than its column, invalid UTF-8, a boolean of 2.
        let mut long = vec![0, 0, 0, 0, 0, 0, 0, 9];
        long.extend_from_slice(&[b'a'; 12]);
        assert!(parse_row(&mut Reader::new(&long), &cols[..1]).is_err());
        let bad = [0, 0, 0, 0, 0, 0, 0, 1, 0xFF, 0, 0, 0];
        assert!(parse_row(&mut Reader::new(&bad), &cols[..1]).is_err());
        let two = [0, 0, 0, 0, 2, 0, 0, 0];
        assert!(parse_row(&mut Reader::new(&two), &cols[2..3]).is_err());
    }

    #[test]
    fn the_statement_set_is_closed_and_read_only() {
        for s in STATEMENTS {
            assert!(checked(s.text), "{}", s.name);
            assert!(!has_denied_word(s.text), "{}: {}", s.name, s.text);
        }
        for (_, text) in PROBES {
            assert!(checked(text));
            assert!(unquoted(text).starts_with("select case when exists (select 1 from "));
            assert!(!has_denied_word(text), "{text}");
        }
        // The deny check sees whole words, quotes excluded.
        assert!(has_denied_word("SELECT 1 FROM T FOR UPDATE"));
        assert!(has_denied_word("delete from t"));
        assert!(!has_denied_word("SELECT 'delete' FROM \"UPDATE\""));
        assert!(!has_denied_word(
            "SELECT RDB$SYSTEM_PRIVILEGE(CREATE_USER_TYPES) FROM X"
        ));
        assert!(!checked("SELECT * FROM CUSTOMERS"));
        assert!(!checked(&format!("{VERSION} ")));
    }

    #[test]
    fn identifiers_are_quoted_with_doubled_quotes() {
        assert_eq!(quote_identifier("CUSTOMERS"), "\"CUSTOMERS\"");
        assert_eq!(quote_identifier("a\"b"), "\"a\"\"b\"");
        assert_eq!(quote_identifier(""), "\"\"");
    }
}
