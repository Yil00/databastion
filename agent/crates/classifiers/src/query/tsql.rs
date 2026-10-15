//! T-SQL statement analysis for the SQL Server Audit source (ADR-0051
//! decision 6, "Statement text"; the T-SQL counterpart of the MySQL mode
//! of ADR-0023 decision 4).
//!
//! The `statement` of a SQL Server Audit record is the text of the
//! statement a permission check belongs to. The agent never sends it (the
//! contract has no field for it): [`analyze_tsql`] reduces it to a
//! statement kind and a closed set of flags, and names only objects of
//! closed lists ([`TsqlAnalysis::listed`]). The objects of an event come
//! from the audit record itself, never from the text.
//!
//! - **Password-bearing statements** (the #82 rule, decision 6, M6) are
//!   recognized from their first tokens only ([`TsqlAnalysis::credential`]):
//!   the lexer stops there, so the rest of the text, where the password
//!   is, is never read. `CREATE` / `ALTER LOGIN`, `USER`, `APPLICATION
//!   ROLE`, `[DATABASE SCOPED] CREDENTIAL`, `EXTERNAL DATA SOURCE`,
//!   `MASTER KEY`, `SYMMETRIC KEY`, `ASYMMETRIC KEY`, `CERTIFICATE`;
//!   `BACKUP` / `RESTORE` of keys and certificates; `OPEN MASTER KEY` /
//!   `OPEN SYMMETRIC KEY`; and `EXEC` of the procedures that take a
//!   password ([`CREDENTIAL_PROCEDURES`]), wherever the call stands in the
//!   text (the lexer stops at the procedure name).
//! - **Lexing**: comments removed (block comments nest), every literal
//!   (`'…'`, `N'…'`, numbers, `0x…`, `$12.50`) reduced to a token without
//!   content, `[…]` (`]]` escaped) read as an identifier, `"…"` kept
//!   opaque: the session's `QUOTED_IDENTIFIER` is unknown, so it is a
//!   string in one reading and an identifier in the other; when it stands
//!   where a name is read, the readings differ and only the kind is kept
//!   ([`TsqlAnalysis::ambiguous`], fail closed). Text that does not lex
//!   (an unterminated literal, identifier or comment), text above
//!   [`super::MAX_QUERY_BYTES`] and cut text keep the kind only.
//! - **Arguments of `EXEC`** are values, never names: every token after
//!   the procedure name up to the end of the statement is skipped
//!   (`EXEC sp_addlogin jane, Pa55word` passes a password unquoted).
//! - **Flags** (each a closed rule, see the fields): dynamic SQL in text,
//!   calls of user functions (a schema-qualified call outside the `sys`
//!   built-ins), remote data access (`signature.remote_data_access`),
//!   server-side copies (`signature.backup_database`), four-part names,
//!   and the shape of the main `SELECT` (`shape.full_table_read`).

use zeroize::Zeroizing;

use super::{Limit, MAX_QUERY_BYTES, Shape};

/// Most tokens lexed per statement.
const MAX_TSQL_TOKENS: usize = 200_000;
/// Longest identifier kept (`sysname`): a longer word is truncated, which
/// can only make a closed-list match fail.
const MAX_WORD_CHARS: usize = 128;
/// Deepest parenthesis nesting followed.
const MAX_DEPTH: usize = 256;
/// Tokens read for the password-bearing prefix rule.
const PREFIX_TOKENS: usize = 8;

/// Statement kind of a T-SQL text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TsqlKind {
    /// `SELECT` (or `WITH … SELECT`).
    Select,
    /// `INSERT`, `UPDATE`, `DELETE`, `MERGE` (or after `WITH`).
    Write,
    /// `EXEC` / `EXECUTE` of a procedure, or a procedure name alone.
    Execute,
    /// `BACKUP` / `RESTORE`.
    Backup,
    /// `DBCC`.
    Dbcc,
    /// `BULK INSERT`.
    Bulk,
    /// `CREATE`, `ALTER`, `DROP`, `TRUNCATE`.
    Ddl,
    /// `GRANT`, `DENY`, `REVOKE`, `ADD` / `DROP` role members.
    Dcl,
    /// Anything else, or no text.
    Other,
}

/// What [`analyze_tsql`] found. Holds no text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsqlAnalysis {
    /// Statement kind (from the first significant tokens).
    pub kind: TsqlKind,
    /// A password-bearing statement: nothing else was read (the #82 rule).
    pub credential: bool,
    /// The whole text lexed (not cut, not too long, every literal,
    /// identifier and comment terminated, not ambiguous).
    pub lexed: bool,
    /// A `"…"` token stands where a name is read: the `QUOTED_IDENTIFIER`
    /// readings differ, so no flag below is derived (kind only).
    pub ambiguous: bool,
    /// A call of a function that takes a password or passphrase
    /// (`PWDCOMPARE`, `ENCRYPTBYPASSPHRASE`…): the statement keeps its kind
    /// and the record's objects, no text-derived signal.
    pub credential_function: bool,
    /// Dynamic SQL in text (`EXEC (…)`, `EXEC sp_executesql …`, `EXEC
    /// @proc`): the inner text is a literal, so the event names `*`.
    pub dynamic_sql: bool,
    /// A schema-qualified call (`s.f(`, `db.s.f(`) outside the `sys`
    /// built-ins of [`SYS_FUNCTIONS`]: user code that runs out of sight.
    pub user_function: bool,
    /// `signature.remote_data_access` (decision 6, M8).
    pub remote_access: bool,
    /// `signature.backup_database`: `BACKUP DATABASE` / `LOG`, `DBCC
    /// CLONEDATABASE`, `sp_detach_db`.
    pub backup: bool,
    /// A four-part name (`server.db.schema.object`): a linked server.
    pub four_part: bool,
    /// Shape of the main `SELECT` (top level only), when there is one.
    pub shape: Option<Shape>,
    /// Objects of the closed always-reported lists named in the text (the
    /// statement-text, credential-bearing and value-bearing objects of
    /// decision 6): canonical names from those lists, never text.
    pub listed: Vec<&'static str>,
}

impl TsqlAnalysis {
    fn kind_only(kind: TsqlKind) -> Self {
        Self {
            kind,
            credential: false,
            lexed: false,
            ambiguous: false,
            credential_function: false,
            dynamic_sql: false,
            user_function: false,
            remote_access: false,
            backup: false,
            four_part: false,
            shape: None,
            listed: Vec::new(),
        }
    }

    /// Whether the text-derived flags may be used (lexed, unambiguous,
    /// not a password-bearing statement or call).
    #[must_use]
    pub fn usable(&self) -> bool {
        self.lexed && !self.ambiguous && !self.credential && !self.credential_function
    }

    /// Whether the main query reads whole relations (`shape.full_table_read`):
    /// no top-level filter, aggregation or derived table, and no `TOP` /
    /// `FETCH` or one of at least `large` rows.
    #[must_use]
    pub fn full_table_read(&self, large: u64) -> bool {
        self.usable()
            && self.kind == TsqlKind::Select
            && self.shape.is_some_and(|s| s.whole_relation(large))
    }
}

/// Procedures that take a password, a secret or a provider string as an
/// argument (decision 6, M6): a call keeps its kind only.
pub const CREDENTIAL_PROCEDURES: &[&str] = &[
    "sp_addlogin",
    "sp_password",
    "sp_setapprole",
    "sp_addapprole",
    "sp_approlepassword",
    "sp_addlinkedsrvlogin",
    "sp_addlinkedserver",
    "sysmail_add_account_sp",
    "sysmail_update_account_sp",
    "sp_control_dbmasterkey_password",
    "sp_addremotelogin",
    "sp_addserver",
];

/// Functions taking a password or passphrase (decision 6, M6).
pub const CREDENTIAL_FUNCTIONS: &[&str] = &[
    "pwdcompare",
    "pwdencrypt",
    "encryptbypassphrase",
    "decryptbypassphrase",
    "decryptbycert",
    "decryptbyasymkey",
    "signbycert",
    "signbyasymkey",
    "decryptbykeyautoasymkey",
    "decryptbykeyautocert",
];

/// Statement-text objects (decision 6, M2; ADR-0045 part (a) counterpart),
/// with `fn_sqlagent_jobsteps` (the job step texts of `sysjobsteps`
/// through a `sys` function, measured on 2022) and `fn_get_audit_file_v2`
/// (SQL Server 2025).
pub const STATEMENT_TEXT_OBJECTS: &[&str] = &[
    "dm_exec_sql_text",
    "dm_exec_input_buffer",
    "dm_exec_query_stats",
    "dm_exec_cached_plans",
    "dm_exec_query_plan",
    "dm_exec_text_query_plan",
    "dm_exec_query_statistics_xml",
    "dm_exec_query_plan_stats",
    "fn_get_sql",
    "query_store_query_text",
    "query_store_plan",
    "fn_get_audit_file",
    "fn_get_audit_file_v2",
    "fn_xe_file_target_read_file",
    "dm_xe_session_targets",
    "fn_trace_gettable",
    "inputbuffer",
    "sp_readerrorlog",
    "xp_readerrorlog",
    "sysjobsteps",
    "sysmail_mailitems",
    "fn_sqlagent_jobsteps",
];

/// Credential-bearing objects (decision 6, M2; ADR-0050 counterpart), with
/// `fn_getproviderstring` (a linked server's provider string, measured on
/// 2022).
pub const CREDENTIAL_OBJECTS: &[&str] = &[
    "sql_logins",
    "syslogins",
    "loginproperty",
    "credentials",
    "database_scoped_credentials",
    "linked_logins",
    "servers",
    "external_data_sources",
    "master_key_passwords",
    "symmetric_keys",
    "key_encryptions",
    "column_master_keys",
    "column_encryption_key_values",
    "certprivatekey",
    "pwdcompare",
    "syslnklgns",
    "sysoledbusers",
    "sysxlgns",
    "sysmail_server",
    "sysmail_account",
    "sysproxies",
    "sysssispackages",
    "environment_variables",
    "fn_getproviderstring",
];

/// Value-bearing statistics and storage (decision 6, M2; ADR-0048
/// counterpart): histograms, raw pages and log records.
pub const VALUE_OBJECTS: &[&str] = &[
    "show_statistics",
    "dm_db_stats_histogram",
    "clonedatabase",
    "fn_dblog",
    "fn_dblog_xtp",
    "fn_dump_dblog",
    "fn_dump_dblog_xtp",
    "fn_full_dblog",
    "fn_dbslog",
    "page",
    "dm_db_page_info",
];

/// The `sys` functions of SQL Server 2019, 2022 and 2025 (P9-A obligation
/// L4): a schema-qualified `sys.f(` is a built-in only when `f` is listed.
/// Measured from `sys.all_objects` (types `FN`, `IF`, `TF`, `FS`, `FT`,
/// `AF`) on 2022 (16.0.4305.5), 2025 (17.0.5015.4: four more, marked) and
/// 2019 (15.0.4500.2: one more, marked);
/// the integration drift test compares it with each matrix image.
pub const SYS_FUNCTIONS: &[&str] = &[
    "dm_cryptographic_provider_algorithms",
    "dm_cryptographic_provider_keys",
    "dm_cryptographic_provider_sessions",
    "dm_db_column_store_redirected_lobs", // 2025
    "dm_db_database_page_allocations",
    "dm_db_exec_cursors", // 2025
    "dm_db_incremental_stats_properties",
    "dm_db_index_operational_stats",
    "dm_db_index_physical_stats",
    "dm_db_log_info",
    "dm_db_log_stats",
    "dm_db_missing_index_columns",
    "dm_db_objects_disabled_on_compatibility_level_change",
    "dm_db_page_info",
    "dm_db_stats_histogram",
    "dm_db_stats_properties",
    "dm_db_stats_properties_internal",
    "dm_db_xtp_hash_index_approx_stats",
    "dm_enumerate_blobdirectory", // 2019
    "dm_exec_cached_plan_dependent_objects",
    "dm_exec_cursors",
    "dm_exec_describe_first_result_set",
    "dm_exec_describe_first_result_set_for_object",
    "dm_exec_input_buffer",
    "dm_exec_plan_attributes",
    "dm_exec_query_plan",
    "dm_exec_query_plan_stats",
    "dm_exec_query_statistics_xml",
    "dm_exec_sql_text",
    "dm_exec_text_query_plan",
    "dm_exec_xml_handles",
    "dm_fts_index_keywords",
    "dm_fts_index_keywords_by_document",
    "dm_fts_index_keywords_by_property",
    "dm_fts_index_keywords_position_by_document",
    "dm_fts_parser",
    "dm_io_virtual_file_stats",
    "dm_logconsumer_cachebufferrefs",
    "dm_logconsumer_privatecachebuffers",
    "dm_logpool_consumers",
    "dm_logpool_sharedcachebuffers",
    "dm_logpoolmgr_freepools",
    "dm_logpoolmgr_respoolsize",
    "dm_logpoolmgr_stats",
    "dm_os_enumerate_filesystem",
    "dm_os_file_exists",
    "dm_os_volume_stats",
    "dm_sql_referenced_entities",
    "dm_sql_referencing_entities",
    "dm_xcs_enumerate_blobdirectory",
    "fn_builtin_permissions",
    "fn_ccolventries_80",
    "fn_cdc_check_parameters",
    "fn_cdc_decrement_lsn",
    "fn_cdc_get_column_ordinal",
    "fn_cdc_get_max_lsn",
    "fn_cdc_get_min_lsn",
    "fn_cdc_has_column_changed",
    "fn_cdc_hexstrtobin",
    "fn_cdc_increment_lsn",
    "fn_cdc_is_bit_set",
    "fn_cdc_is_ddl_handling_enabled",
    "fn_cdc_map_lsn_to_time",
    "fn_cdc_map_time_to_lsn",
    "fn_check_object_signatures",
    "fn_column_store_row_groups",
    "fn_db_backup_file_snapshots",
    "fn_dblog",
    "fn_dblog_xtp",
    "fn_dbslog",
    "fn_dump_dblog",
    "fn_dump_dblog_xtp",
    "fn_enumcurrentprincipals",
    "fn_external_policy_actions_assigned_to_principal",
    "fn_filelog",
    "fn_fiscoltracked",
    "fn_full_dblog",
    "fn_get_audit_file",
    "fn_get_audit_file_v2", // 2025
    "fn_get_sql",
    "fn_getcurrentprincipal",
    "fn_getproviderstring",
    "fn_getrowsetidfromrowdump",
    "fn_getserverportfromproviderstring",
    "fn_hadr_backup_is_preferred_replica",
    "fn_has_change_feed_permissions", // 2025
    "fn_hadr_distributed_ag_database_replica",
    "fn_hadr_distributed_ag_replica",
    "fn_hadr_is_primary_replica",
    "fn_hadr_is_same_replica",
    "fn_helpcollations",
    "fn_helpdatatypemap",
    "fn_isbitsetinbitmask",
    "fn_isrolemember",
    "fn_ledger_retrieve_digests_from_url",
    "fn_listextendedproperty",
    "fn_mapschematype",
    "fn_msdayasnumber",
    "fn_msgeneration_downloadonly",
    "fn_msget_dynamic_filter_login",
    "fn_msorbitmaps",
    "fn_msrepl_getsrvidfromdistdb",
    "fn_msrepl_map_resolver_clsid",
    "fn_mstestbit",
    "fn_msvector_downloadonly",
    "fn_msxe_read_event_stream",
    "fn_my_permissions",
    "fn_numberof1inbinaryafterloc",
    "fn_numberof1invarbinary",
    "fn_pagerescracker",
    "fn_physloccracker",
    "fn_physlocformatter",
    "fn_repl_hash_binary",
    "fn_repladjustcolumnmap",
    "fn_repldecryptver4",
    "fn_replformatdatetime",
    "fn_replgetcolidfrombitmap",
    "fn_replgetparsedddlcmd",
    "fn_replp2pversiontotranid",
    "fn_replreplacesinglequote",
    "fn_replreplacesinglequoteplusprotectstring",
    "fn_repluniquename",
    "fn_replvarbintoint",
    "fn_rowdumpcracker",
    "fn_servershareddrives",
    "fn_sqlagent_job_history",
    "fn_sqlagent_jobs",
    "fn_sqlagent_jobsteps",
    "fn_sqlagent_jobsteps_logs",
    "fn_sqlagent_subsystems",
    "fn_sqlvarbasetostr",
    "fn_stmt_sql_handle_from_sql_stmt",
    "fn_trace_geteventinfo",
    "fn_trace_getfilterinfo",
    "fn_trace_getinfo",
    "fn_trace_gettable",
    "fn_translate_permissions",
    "fn_validate_plan_guide",
    "fn_varbintohexstr",
    "fn_varbintohexsubstring",
    "fn_virtualfilestats",
    "fn_virtualservernodes",
    "fn_xcs_get_file_rowcount",
    "fn_xe_file_target_read_file",
    "fn_yukonsecuritymodelrequired",
    "geographycollectionaggregate",
    "geographyconvexhullaggregate",
    "geographyenvelopeaggregate",
    "geographyunionaggregate",
    "geometrycollectionaggregate",
    "geometryconvexhullaggregate",
    "geometryenvelopeaggregate",
    "geometryunionaggregate",
    "ormask",
];

/// Methods of the `xml` type called on a column or variable (`c.value(`):
/// not user functions.
const XML_METHODS: &[&str] = &["value", "query", "exist", "nodes", "modify", "write"];

/// Procedures and keywords that move data to or through another place
/// (`signature.remote_data_access`, decision 6, M8).
const REMOTE_WORDS: &[&str] = &[
    "openrowset",
    "opendatasource",
    "openquery",
    "xp_cmdshell",
    "xp_dirtree",
    "xp_fileexist",
    "xp_subdirs",
    "sp_invoke_external_rest_endpoint",
    "sp_oacreate",
    "sp_oamethod",
    "sp_execute_external_script",
];

/// Aggregate functions that make a `SELECT` list aggregate-only.
const AGGREGATES: &[&str] = &[
    "count",
    "count_big",
    "sum",
    "avg",
    "min",
    "max",
    "string_agg",
    "stdev",
    "stdevp",
    "var",
    "varp",
    "checksum_agg",
    "approx_count_distinct",
    "grouping",
];

/// A lexical token. Literal content is never kept; identifiers are
/// lowercased and zeroized on drop.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    /// Unquoted identifier or keyword (also `#temp`), lowercased.
    Word(Zeroizing<String>),
    /// `[…]`, unescaped and lowercased.
    Bracket(Zeroizing<String>),
    /// `"…"`: a string or an identifier (unknown `QUOTED_IDENTIFIER`).
    DQuoted,
    /// `'…'`, `N'…'`, `0x…`, a money or decimal literal.
    Literal,
    /// A plain decimal integer (row counts of `TOP` / `FETCH`).
    Int(u64),
    /// `@name`, lowercased (variable and parameter names are not values).
    Var(Zeroizing<String>),
    /// Punctuation or operator.
    Punct(char),
}

impl Tok {
    fn word(&self) -> Option<&str> {
        match self {
            Self::Word(w) => Some(w.as_str()),
            _ => None,
        }
    }

    /// An identifier, quoted or not.
    fn ident(&self) -> Option<&str> {
        match self {
            Self::Word(w) | Self::Bracket(w) => Some(w.as_str()),
            _ => None,
        }
    }

    fn is(&self, w: &str) -> bool {
        self.word() == Some(w)
    }

    fn punct(&self, c: char) -> bool {
        *self == Self::Punct(c)
    }

    fn name_like(&self) -> bool {
        matches!(self, Self::Word(_) | Self::Bracket(_) | Self::DQuoted)
    }
}

/// Why lexing stopped early.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LexEnd {
    /// End of the text.
    Done,
    /// An unterminated literal, identifier or comment, or a bound.
    Failed,
}

fn is_ident_start(c: char) -> bool {
    c.is_alphabetic() || c == '_' || c == '#'
}

fn is_ident_cont(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '_' | '#' | '@' | '$')
}

fn bounded_lower(s: &str) -> Zeroizing<String> {
    Zeroizing::new(
        s.chars()
            .take(MAX_WORD_CHARS)
            .flat_map(char::to_lowercase)
            .collect(),
    )
}

/// A lazy T-SQL lexer over `text`.
struct Lexer<'a> {
    chars: std::iter::Peekable<std::str::CharIndices<'a>>,
    text: &'a str,
    count: usize,
}

impl<'a> Lexer<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            chars: text.char_indices().peekable(),
            text,
            count: 0,
        }
    }

    fn peek_char(&mut self) -> Option<char> {
        self.chars.peek().map(|(_, c)| *c)
    }

    /// Skips a quoted run closed by `close` (doubled to escape). `false`
    /// when unterminated.
    fn skip_quoted(&mut self, close: char) -> bool {
        while let Some((_, c)) = self.chars.next() {
            if c == close {
                if self.peek_char() == Some(close) {
                    self.chars.next();
                    continue;
                }
                return true;
            }
        }
        false
    }

    /// Reads a bracketed identifier (after `[`).
    fn bracket(&mut self) -> Option<Zeroizing<String>> {
        let mut out = Zeroizing::new(String::new());
        while let Some((_, c)) = self.chars.next() {
            if c == ']' {
                if self.peek_char() == Some(']') {
                    self.chars.next();
                } else {
                    let lower = bounded_lower(&out);
                    return Some(lower);
                }
            }
            if out.chars().count() < MAX_WORD_CHARS {
                out.push(c);
            }
        }
        None
    }

    /// The next token, `Err` at the end or on a lexing failure.
    fn next_tok(&mut self) -> Result<Tok, LexEnd> {
        self.count += 1;
        if self.count > MAX_TSQL_TOKENS {
            return Err(LexEnd::Failed);
        }
        loop {
            let Some((i, c)) = self.chars.next() else {
                return Err(LexEnd::Done);
            };
            if c.is_whitespace() {
                continue;
            }
            // Comments.
            if c == '-' && self.peek_char() == Some('-') {
                for (_, d) in self.chars.by_ref() {
                    if d == '\n' || d == '\r' {
                        break;
                    }
                }
                continue;
            }
            if c == '/' && self.peek_char() == Some('*') {
                self.chars.next();
                // Block comments nest in T-SQL.
                let mut depth = 1usize;
                let mut prev = '\0';
                loop {
                    let Some((_, d)) = self.chars.next() else {
                        return Err(LexEnd::Failed);
                    };
                    if prev == '/' && d == '*' {
                        depth += 1;
                        prev = '\0';
                        continue;
                    }
                    if prev == '*' && d == '/' {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                        prev = '\0';
                        continue;
                    }
                    prev = d;
                }
                continue;
            }
            // Literals.
            if c == '\'' {
                return if self.skip_quoted('\'') {
                    Ok(Tok::Literal)
                } else {
                    Err(LexEnd::Failed)
                };
            }
            if (c == 'N' || c == 'n') && self.peek_char() == Some('\'') {
                self.chars.next();
                return if self.skip_quoted('\'') {
                    Ok(Tok::Literal)
                } else {
                    Err(LexEnd::Failed)
                };
            }
            if c == '"' {
                return if self.skip_quoted('"') {
                    Ok(Tok::DQuoted)
                } else {
                    Err(LexEnd::Failed)
                };
            }
            if c == '[' {
                return self.bracket().map(Tok::Bracket).ok_or(LexEnd::Failed);
            }
            if c.is_ascii_digit()
                || (c == '.' && self.peek_char().is_some_and(|d| d.is_ascii_digit()))
            {
                return Ok(self.number(i, c));
            }
            if c == '$'
                && self
                    .peek_char()
                    .is_some_and(|d| d.is_ascii_digit() || d == '.')
            {
                // Money literal.
                self.number(i, '0');
                return Ok(Tok::Literal);
            }
            if c == '@' {
                let mut name = String::new();
                if self.peek_char() == Some('@') {
                    self.chars.next();
                    name.push('@');
                }
                while let Some(d) = self.peek_char() {
                    if is_ident_cont(d) {
                        name.push(d);
                        self.chars.next();
                    } else {
                        break;
                    }
                }
                return Ok(Tok::Var(bounded_lower(&name)));
            }
            if is_ident_start(c) || c == '$' {
                let mut end = i + c.len_utf8();
                while let Some((j, d)) = self.chars.peek().copied() {
                    if is_ident_cont(d) {
                        end = j + d.len_utf8();
                        self.chars.next();
                    } else {
                        break;
                    }
                }
                let word = self.text.get(i..end).unwrap_or_default();
                return Ok(Tok::Word(bounded_lower(word)));
            }
            return Ok(Tok::Punct(c));
        }
    }

    /// A number starting with `first` at byte `start`: an integer, or any
    /// other numeric literal (decimal, exponent, `0x…` binary).
    fn number(&mut self, start: usize, first: char) -> Tok {
        if first == '0' && matches!(self.peek_char(), Some('x' | 'X')) {
            self.chars.next();
            while self.peek_char().is_some_and(|d| d.is_ascii_hexdigit()) {
                self.chars.next();
            }
            return Tok::Literal;
        }
        let mut end = start + first.len_utf8();
        let mut plain = first.is_ascii_digit();
        let mut prev = first;
        while let Some((j, d)) = self.chars.peek().copied() {
            let exp_sign = matches!(d, '+' | '-') && matches!(prev, 'e' | 'E');
            if d.is_ascii_digit() || d == '.' || matches!(d, 'e' | 'E') || exp_sign {
                if !d.is_ascii_digit() {
                    plain = false;
                }
                prev = d;
                end = j + d.len_utf8();
                self.chars.next();
            } else {
                break;
            }
        }
        if plain {
            self.text
                .get(start..end)
                .and_then(|s| s.parse::<u64>().ok())
                .map_or(Tok::Literal, Tok::Int)
        } else {
            Tok::Literal
        }
    }
}

/// The first significant keyword's kind.
fn kind_of(first: Option<&str>, second: Option<&str>) -> TsqlKind {
    match first {
        Some("select") => TsqlKind::Select,
        Some("insert" | "update" | "delete" | "merge") => TsqlKind::Write,
        Some("exec" | "execute") => TsqlKind::Execute,
        Some("backup" | "restore") => TsqlKind::Backup,
        Some("dbcc") => TsqlKind::Dbcc,
        Some("bulk") if second == Some("insert") => TsqlKind::Bulk,
        Some("create" | "alter" | "drop" | "truncate") => TsqlKind::Ddl,
        Some("grant" | "deny" | "revoke") => TsqlKind::Dcl,
        _ => TsqlKind::Other,
    }
}

/// Whether the first words name a password-bearing statement.
fn credential_prefix(words: &[&str]) -> bool {
    let w = |i: usize| words.get(i).copied();
    match (w(0), w(1)) {
        (Some("create" | "alter"), Some("login" | "user" | "credential" | "certificate")) => true,
        (Some("create" | "alter"), Some("application")) => w(2) == Some("role"),
        (Some("create" | "alter"), Some("database")) => {
            w(2) == Some("scoped") && w(3) == Some("credential")
        }
        (Some("create" | "alter"), Some("external")) => {
            w(2) == Some("data") && w(3) == Some("source")
        }
        (
            Some("create" | "alter" | "backup" | "restore" | "open" | "regenerate"),
            Some("master" | "symmetric" | "asymmetric" | "service"),
        ) => true,
        (Some("backup" | "restore"), Some("certificate")) => true,
        _ => false,
    }
}

/// Whether `name` (lowercased, possibly schema-qualified elsewhere) is a
/// password-taking procedure.
fn credential_procedure(name: &str) -> bool {
    CREDENTIAL_PROCEDURES.contains(&name)
}

/// Analyzes the statement text of a SQL Server Audit record. `truncated`:
/// the text may have been cut (reassembly bound, an unfinished sequence):
/// kind only.
#[must_use]
pub fn analyze_tsql(text: &str, truncated: bool) -> TsqlAnalysis {
    if text.len() > MAX_QUERY_BYTES {
        return TsqlAnalysis::kind_only(TsqlKind::Other);
    }
    let mut lexer = Lexer::new(text);
    let mut toks: Vec<Tok> = Vec::new();
    let mut end = LexEnd::Done;
    // The prefix: token by token, the password-bearing rules checked after
    // each one, so the lexer stops at the class (`CREATE LOGIN`) or at the
    // name of a password-taking procedure, before any argument is read.
    while toks.len() < PREFIX_TOKENS {
        match lexer.next_tok() {
            Ok(t) => {
                let procedure = t.ident().is_some_and(credential_procedure);
                toks.push(t);
                if procedure {
                    return at_credential_procedure(&toks);
                }
                let words: Vec<&str> = toks.iter().filter_map(Tok::word).collect();
                if credential_prefix(&words) {
                    let mut a = TsqlAnalysis::kind_only(TsqlKind::Dcl);
                    a.credential = true;
                    return a;
                }
            }
            Err(e) => {
                end = e;
                break;
            }
        }
    }
    let mut lexed = end == LexEnd::Done;
    if lexed && toks.len() == PREFIX_TOKENS {
        // The rest, stopping at the name of a password-taking procedure
        // anywhere in the text (its arguments are never read).
        loop {
            match lexer.next_tok() {
                Ok(t) => {
                    let stop = t.ident().is_some_and(credential_procedure);
                    toks.push(t);
                    if stop {
                        return at_credential_procedure(&toks);
                    }
                }
                Err(LexEnd::Done) => break,
                Err(LexEnd::Failed) => {
                    lexed = false;
                    break;
                }
            }
        }
    }
    let kind = main_kind(&toks).unwrap_or_else(|| {
        let mut words = toks.iter().filter_map(Tok::word);
        kind_of(words.next(), words.next())
    });
    if !lexed || truncated {
        let mut a = TsqlAnalysis::kind_only(kind);
        // A cut or unlexable text still says what it is when its first
        // words do (the kind), never more.
        a.lexed = false;
        return a;
    }
    analyze_tokens(&toks, kind)
}

/// The lexer stopped at the name of a password-taking procedure (the last
/// token of `toks`). Called at the head of the statement (`[EXEC[UTE]
/// [@rc =]] [db.][schema.]proc`): the password-bearing class, kind only.
/// Anywhere else (a column alias, a table or a later call named so): the
/// rest is not read (its arguments may be a password), and the text keeps
/// its kind only as **not lexed**, so the event names `*` and is always
/// reported (security review of P9-A lot 2, M1).
fn at_credential_procedure(toks: &[Tok]) -> TsqlAnalysis {
    let mut i = 0;
    if toks
        .first()
        .is_some_and(|t| t.is("exec") || t.is("execute"))
    {
        i = 1;
        if matches!(toks.get(1), Some(Tok::Var(_))) && toks.get(2).is_some_and(|t| t.punct('=')) {
            i = 3;
        }
    }
    let name = toks.get(i..).unwrap_or_default();
    // Only the parts of a dotted name (`master..sp_x` included).
    // and no two names in a row (`SELECT sp_addlogin` is not a call).
    let head = !name.is_empty()
        && name.iter().all(|t| t.ident().is_some() || t.punct('.'))
        && name
            .windows(2)
            .all(|w| !(w[0].ident().is_some() && w[1].ident().is_some()));
    if head {
        let mut a = TsqlAnalysis::kind_only(TsqlKind::Execute);
        a.credential = true;
        return a;
    }
    let mut words = toks.iter().filter_map(Tok::word);
    let kind = main_kind(toks).unwrap_or_else(|| kind_of(words.next(), words.next()));
    TsqlAnalysis::kind_only(kind)
}

/// The kind of the main statement, after a `WITH` CTE list.
fn main_kind(toks: &[Tok]) -> Option<TsqlKind> {
    let mut i = 0;
    while toks.get(i).is_some_and(|t| t.punct(';') || t.punct('(')) {
        i += 1;
    }
    if !toks.get(i).is_some_and(|t| t.is("with")) {
        return None;
    }
    // Skip to the first top-level SELECT / INSERT / UPDATE / DELETE /
    // MERGE after the CTE definitions.
    let mut depth = 0usize;
    for t in toks.iter().skip(i + 1) {
        if t.punct('(') {
            depth += 1;
        } else if t.punct(')') {
            depth = depth.saturating_sub(1);
        } else if depth == 0
            && let Some(w) = t.word()
            && matches!(w, "select" | "insert" | "update" | "delete" | "merge")
        {
            return Some(kind_of(Some(w), None));
        }
    }
    None
}

/// A dotted name starting at `i`: its parts (identifiers) and the index
/// after it. `DQuoted` parts are `None`. Empty parts (`db..t`) count.
fn dotted(toks: &[Tok], i: usize) -> (Vec<Option<&str>>, bool, usize) {
    let mut parts = Vec::new();
    let mut j = i;
    let mut dq = false;
    loop {
        match toks.get(j) {
            Some(t) if t.name_like() => {
                if matches!(t, Tok::DQuoted) {
                    dq = true;
                }
                parts.push(t.ident());
                j += 1;
            }
            _ => break,
        }
        // `db..t`: an empty part.
        while toks.get(j).is_some_and(|t| t.punct('.'))
            && toks.get(j + 1).is_some_and(|t| t.punct('.'))
        {
            parts.push(None);
            j += 1;
        }
        if toks.get(j).is_some_and(|t| t.punct('.')) && toks.get(j + 1).is_some_and(Tok::name_like)
        {
            j += 1;
            continue;
        }
        break;
    }
    (parts, dq, j)
}

/// `DBCC` commands of the lists: names only after `DBCC`.
const DBCC_ONLY: &[&str] = &["inputbuffer", "show_statistics", "clonedatabase", "page"];

/// Schemas that hold the listed objects (`sys`, `msdb`'s `dbo`, `SSISDB`'s
/// `catalog` and `internal`), or none (`master..syslogins`, an
/// unqualified `fn_dblog(`): a user table `crm.servers` is not
/// `sys.servers`.
fn listed_qualifier(q: Option<&str>) -> bool {
    matches!(q, None | Some("sys" | "dbo" | "catalog" | "internal"))
}

fn listed_name(qualifier: Option<&str>, name: &str) -> Option<&'static str> {
    if DBCC_ONLY.contains(&name) || !listed_qualifier(qualifier) {
        return None;
    }
    STATEMENT_TEXT_OBJECTS
        .iter()
        .chain(CREDENTIAL_OBJECTS)
        .chain(VALUE_OBJECTS)
        .find(|n| **n == name)
        .copied()
}

fn dbcc_listed(cmd: &str) -> Option<&'static str> {
    DBCC_ONLY
        .contains(&cmd)
        .then(|| {
            STATEMENT_TEXT_OBJECTS
                .iter()
                .chain(VALUE_OBJECTS)
                .find(|n| **n == cmd)
                .copied()
        })
        .flatten()
}

/// The part before the last of a dotted name (`None`: none, or empty).
fn qualifier<'a>(parts: &[Option<&'a str>]) -> Option<&'a str> {
    parts
        .len()
        .checked_sub(2)
        .and_then(|i| parts.get(i).copied().flatten())
}

/// Words that end the arguments of an `EXEC` (a new statement).
fn statement_start(w: &str) -> bool {
    matches!(
        w,
        "select"
            | "insert"
            | "update"
            | "delete"
            | "merge"
            | "exec"
            | "execute"
            | "with"
            | "declare"
            | "set"
            | "if"
            | "while"
            | "begin"
            | "end"
            | "return"
            | "create"
            | "alter"
            | "drop"
            | "truncate"
            | "grant"
            | "deny"
            | "revoke"
            | "backup"
            | "restore"
            | "dbcc"
            | "bulk"
            | "use"
            | "print"
            | "raiserror"
            | "throw"
            | "open"
            | "fetch"
            | "close"
            | "deallocate"
    )
}

#[allow(clippy::too_many_lines)]
fn analyze_tokens(toks: &[Tok], kind: TsqlKind) -> TsqlAnalysis {
    let mut a = TsqlAnalysis::kind_only(kind);
    a.lexed = true;
    let mut i = 0usize;
    let mut depth = 0usize;
    let mut prev_kw: Option<&str> = None;
    // `DBCC` at statement start: its command word follows.
    while i < toks.len() {
        let t = &toks[i];
        if t.punct('(') {
            depth += 1;
            if depth > MAX_DEPTH {
                return TsqlAnalysis::kind_only(kind);
            }
            i += 1;
            continue;
        }
        if t.punct(')') {
            depth = depth.saturating_sub(1);
            i += 1;
            continue;
        }
        // EXEC / EXECUTE: dynamic SQL, the procedure, then its arguments
        // skipped (values, never names).
        if t.is("exec") || t.is("execute") {
            let mut j = i + 1;
            if matches!(toks.get(j), Some(Tok::Var(_)))
                && toks.get(j + 1).is_some_and(|t| t.punct('='))
            {
                j += 2;
            }
            match toks.get(j) {
                Some(Tok::Punct('(')) => {
                    // EXEC ('…' + …) [AT server]: dynamic SQL.
                    a.dynamic_sql = true;
                    let mut d = 0usize;
                    while let Some(u) = toks.get(j) {
                        if u.punct('(') {
                            d += 1;
                        } else if u.punct(')') {
                            d = d.saturating_sub(1);
                            if d == 0 {
                                j += 1;
                                break;
                            }
                        }
                        j += 1;
                    }
                    if toks.get(j).is_some_and(|u| u.is("at")) {
                        a.remote_access = true;
                        a.four_part = true;
                    }
                }
                Some(Tok::Var(_)) => {
                    // EXEC @proc_name: the procedure is in a variable.
                    a.dynamic_sql = true;
                    j += 1;
                }
                Some(u) if u.name_like() => {
                    let (parts, dq, after) = dotted(toks, j);
                    if dq {
                        a.ambiguous = true;
                    }
                    let proc = parts.last().copied().flatten().unwrap_or("");
                    if parts.len() >= 4 {
                        a.four_part = true;
                        a.remote_access = true;
                    }
                    if proc == "sp_executesql" {
                        a.dynamic_sql = true;
                    }
                    if REMOTE_WORDS.contains(&proc) {
                        a.remote_access = true;
                    }
                    if matches!(proc, "sp_detach_db") {
                        a.backup = true;
                    }
                    if proc == "sp_send_dbmail" {
                        // Query results mailed: @query (or @attach_query…).
                        let mut k = after;
                        while let Some(u) = toks.get(k) {
                            if u.punct(';') || u.word().is_some_and(statement_start) {
                                break;
                            }
                            if let Tok::Var(v) = u
                                && v.starts_with("query")
                            {
                                a.remote_access = true;
                            }
                            k += 1;
                        }
                    }
                    if let Some(n) = listed_name(qualifier(&parts), proc) {
                        a.listed.push(n);
                    }
                    j = after;
                }
                _ => {}
            }
            // The arguments: skipped up to the end of the statement; an
            // `AT server` at their end is a remote execution.
            while let Some(u) = toks.get(j) {
                if u.punct(';') || u.word().is_some_and(statement_start) {
                    break;
                }
                if u.is("at") && toks.get(j + 1).is_some_and(Tok::name_like) {
                    a.remote_access = true;
                    a.four_part = true;
                }
                j += 1;
            }
            i = j;
            prev_kw = None;
            continue;
        }
        // DBCC <command>.
        if t.is("dbcc") {
            if let Some(cmd) = toks.get(i + 1).and_then(Tok::ident) {
                if let Some(n) = dbcc_listed(cmd) {
                    a.listed.push(n);
                }
                if cmd == "clonedatabase" {
                    a.backup = true;
                }
            }
            i += 2;
            continue;
        }
        if t.is("backup")
            && toks
                .get(i + 1)
                .is_some_and(|u| u.is("database") || u.is("log"))
        {
            a.backup = true;
        }
        if t.is("bulk") && toks.get(i + 1).is_some_and(|u| u.is("insert")) {
            a.remote_access = true;
        }
        // CREATE EXTERNAL TABLE … AS SELECT (CETAS).
        if t.is("create")
            && toks.get(i + 1).is_some_and(|u| u.is("external"))
            && toks.get(i + 2).is_some_and(|u| u.is("table"))
        {
            let rest = &toks[i..];
            if rest.windows(2).any(|w| w[0].is("as") && w[1].is("select")) {
                a.remote_access = true;
            }
        }
        if let Some(w) = t.word()
            && REMOTE_WORDS.contains(&w)
        {
            a.remote_access = true;
        }
        if t.name_like() {
            let (parts, dq, after) = dotted(toks, i);
            let call = toks.get(after).is_some_and(|u| u.punct('('));
            let in_name_position = call
                || parts.len() > 1
                || matches!(
                    prev_kw,
                    Some("from" | "join" | "into" | "update" | "table" | "apply")
                );
            if dq && in_name_position {
                a.ambiguous = true;
            }
            let last = parts.last().copied().flatten();
            if let Some(n) = last.and_then(|l| listed_name(qualifier(&parts), l)) {
                // A listed name named by its object (a dotted name, a call
                // or after FROM / JOIN), not a column of that name.
                if in_name_position {
                    a.listed.push(n);
                }
            }
            if let Some(n) = last
                && CREDENTIAL_FUNCTIONS.contains(&n)
                && call
            {
                a.credential_function = true;
            }
            if parts.len() >= 4 {
                a.four_part = true;
                if matches!(prev_kw, Some("into" | "update" | "merge")) {
                    a.remote_access = true;
                }
            }
            if call && parts.len() >= 2 {
                let schema = parts.get(parts.len() - 2).copied().flatten();
                let builtin =
                    schema == Some("sys") && last.is_some_and(|n| SYS_FUNCTIONS.contains(&n));
                let method = parts.len() == 2 && last.is_some_and(|n| XML_METHODS.contains(&n));
                if !builtin && !method {
                    a.user_function = true;
                }
            }
            prev_kw = if parts.len() == 1 { t.word() } else { None };
            i = after.max(i + 1);
            continue;
        }
        prev_kw = None;
        i += 1;
    }
    a.listed.sort_unstable();
    a.listed.dedup();
    if a.ambiguous {
        let mut k = TsqlAnalysis::kind_only(kind);
        k.lexed = true;
        k.ambiguous = true;
        return k;
    }
    if kind == TsqlKind::Select {
        a.shape = Some(select_shape(toks));
    }
    a
}

/// The shape of the main `SELECT` (top level): filter, aggregation, a
/// derived table or function in `FROM`, `TOP` / `OFFSET … FETCH`.
fn select_shape(toks: &[Tok]) -> Shape {
    let mut shape = Shape {
        star: false,
        filtered: false,
        aggregated: false,
        derived: false,
        limit: Limit::None,
    };
    // The main SELECT: the first top-level `select` (after a CTE list).
    let mut depth = 0usize;
    let mut start = None;
    for (i, t) in toks.iter().enumerate() {
        if t.punct('(') {
            depth += 1;
        } else if t.punct(')') {
            depth = depth.saturating_sub(1);
        } else if depth == 0 && t.is("with") {
            // A CTE can filter or aggregate what the main query reads:
            // never a whole-table read by shape.
            shape.derived = true;
        } else if depth == 0 && t.is("select") {
            start = Some(i);
            break;
        }
    }
    let Some(start) = start else { return shape };
    let mut i = start + 1;
    // DISTINCT / ALL, then TOP (n) [PERCENT].
    if toks.get(i).is_some_and(|t| t.is("distinct") || t.is("all")) {
        i += 1;
    }
    if toks.get(i).is_some_and(|t| t.is("top")) {
        let (n, after) = match (toks.get(i + 1), toks.get(i + 2), toks.get(i + 3)) {
            (Some(Tok::Punct('(')), Some(Tok::Int(n)), Some(Tok::Punct(')'))) => (Some(*n), i + 4),
            (Some(Tok::Int(n)), _, _) => (Some(*n), i + 2),
            (Some(Tok::Punct('(')), _, _) => (None, close_paren(toks, i + 1) + 1),
            _ => (None, i + 2),
        };
        let percent = toks.get(after).is_some_and(|t| t.is("percent"));
        shape.limit = match (n, percent) {
            // TOP 100 PERCENT is every row; another percentage is unknown.
            (Some(100), true) => Limit::None,
            (Some(n), false) => Limit::Rows(n),
            _ => Limit::Unknown,
        };
        i = after + usize::from(percent);
    }
    let mut depth = 0usize;
    let mut in_list = true;
    let mut has_from = false;
    let mut list_aggregate = false;
    let mut list_plain = false;
    // The previous top-level token starts a FROM item (`FROM`, `JOIN`,
    // `APPLY`, or `,` in the FROM clause).
    let mut item_start = false;
    while let Some(t) = toks.get(i) {
        if t.punct('(') {
            if depth == 0 && !in_list && item_start {
                shape.derived = true;
            }
            depth += 1;
            item_start = false;
            i += 1;
            continue;
        }
        if t.punct(')') {
            if depth == 0 {
                // The end of an enclosing parenthesis.
                break;
            }
            depth -= 1;
            item_start = false;
            i += 1;
            continue;
        }
        if depth > 0 {
            i += 1;
            continue;
        }
        match t.word() {
            Some("from") if in_list => {
                in_list = false;
                has_from = true;
            }
            Some("where") => shape.filtered = true,
            Some("group" | "having") => shape.aggregated = true,
            Some("union" | "except" | "intersect") => {
                // Another query joins the result: not a whole-table read
                // by this rule.
                shape.derived = true;
                break;
            }
            Some("fetch")
                if matches!(toks.get(i + 1).and_then(Tok::word), Some("next" | "first")) =>
            {
                shape.limit = match toks.get(i + 2) {
                    Some(Tok::Int(n)) => Limit::Rows(*n),
                    _ => Limit::Unknown,
                };
            }
            _ => {}
        }
        if in_list {
            if t.punct('*') {
                shape.star = true;
                list_plain = true;
            } else if let Some(w) = t.word() {
                if AGGREGATES.contains(&w) && toks.get(i + 1).is_some_and(|u| u.punct('(')) {
                    list_aggregate = true;
                } else if !matches!(w, "as") {
                    list_plain = true;
                }
            } else if matches!(t, Tok::Bracket(_) | Tok::DQuoted) {
                list_plain = true;
            }
        } else if t.name_like() && item_start {
            // A FROM item: a function call there (a table-valued
            // function) is derived.
            let (_, _, after) = dotted(toks, i);
            if toks.get(after).is_some_and(|u| u.punct('(')) {
                shape.derived = true;
            }
            item_start = false;
            i = after.max(i + 1);
            continue;
        }
        item_start = !in_list && (t.is("from") || t.is("join") || t.is("apply") || t.punct(','));
        i += 1;
    }
    if list_aggregate && !list_plain {
        shape.aggregated = true;
    }
    if !has_from {
        // No relation read at the top level (constants, subqueries in the
        // select list): never a whole-table read.
        shape.derived = true;
    }
    shape
}

/// The index of the `)` closing the `(` at `open` (or the end).
fn close_paren(toks: &[Tok], open: usize) -> usize {
    let mut d = 0usize;
    let mut k = open;
    while let Some(t) = toks.get(k) {
        if t.punct('(') {
            d += 1;
        } else if t.punct(')') {
            d = d.saturating_sub(1);
            if d == 0 {
                return k;
            }
        }
        k += 1;
    }
    k
}

#[cfg(test)]
mod tests {
    use super::*;

    fn an(t: &str) -> TsqlAnalysis {
        analyze_tsql(t, false)
    }

    #[test]
    fn password_bearing_statements_keep_their_class_only() {
        for t in [
            "CREATE LOGIN jane WITH PASSWORD = 'S3cret-marker'",
            "ALTER LOGIN jane WITH PASSWORD = N'S3cret-marker' OLD_PASSWORD = 'x'",
            "create user u with password = 'S3cret-marker'",
            "CREATE APPLICATION ROLE r WITH PASSWORD = 'S3cret-marker'",
            "ALTER APPLICATION ROLE r WITH PASSWORD = 'S3cret-marker'",
            "CREATE CREDENTIAL c WITH IDENTITY = 'u', SECRET = 'S3cret-marker'",
            "CREATE DATABASE SCOPED CREDENTIAL c WITH IDENTITY = 'u', SECRET = 'S3cret-marker'",
            "CREATE EXTERNAL DATA SOURCE s WITH (LOCATION = 'x', CREDENTIAL = c)",
            "CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'S3cret-marker'",
            "OPEN MASTER KEY DECRYPTION BY PASSWORD = 'S3cret-marker'",
            "BACKUP SERVICE MASTER KEY TO FILE = 'f' ENCRYPTION BY PASSWORD = 'S3cret-marker'",
            "CREATE SYMMETRIC KEY k WITH KEY_SOURCE = 'S3cret-marker', IDENTITY_VALUE = 'x' ENCRYPTION BY PASSWORD = 'p'",
            "OPEN SYMMETRIC KEY k DECRYPTION BY PASSWORD = 'S3cret-marker'",
            "CREATE ASYMMETRIC KEY k WITH ALGORITHM = RSA_2048 ENCRYPTION BY PASSWORD = 'S3cret-marker'",
            "BACKUP CERTIFICATE c TO FILE = 'f' WITH PRIVATE KEY (ENCRYPTION BY PASSWORD = 'S3cret-marker')",
            "EXEC sp_addlogin jane, Pa55word",
            "EXECUTE master.dbo.sp_addlinkedsrvlogin 'srv', 'false', NULL, 'u', 'S3cret-marker'",
            "exec @rc = sp_password NULL, 'S3cret-marker', 'jane'",
            "sp_setapprole 'r', 'S3cret-marker'",
            "EXEC sp_addlinkedserver @server = 's', @provstr = 'Password=S3cret-marker'",
            "EXEC master..sp_addlinkedsrvlogin 's', 'false'",
        ] {
            let a = an(t);
            assert!(a.credential, "{t}");
            assert!(!a.usable(), "{t}");
            assert!(a.listed.is_empty() && a.shape.is_none(), "{t}");
        }
        assert!(!an("SELECT login FROM crm.logins").credential);
        // A password-taking procedure's name elsewhere (review M1): not the
        // class, the rest unread, so not lexed (the event names `*`).
        for t in [
            "SELECT * FROM crm.customers AS sp_password",
            "SELECT 1; EXEC msdb.dbo.sysmail_add_account_sp @account_name = 'a', @password = Pa55word",
            "SELECT sp_addlogin FROM t",
        ] {
            let a = an(t);
            assert!(!a.credential && !a.lexed && !a.usable(), "{t}");
            assert_eq!(a.kind, TsqlKind::Select, "{t}");
        }
        // A function taking a password: kind and objects, no text signal.
        let a = an("SELECT name FROM sys.sql_logins WHERE PWDCOMPARE('pw', password_hash) = 1");
        assert!(a.credential_function && !a.usable());
        assert_eq!(a.kind, TsqlKind::Select);
    }

    #[test]
    fn literals_and_comments_never_become_names() {
        let a = an(
            "SELECT 'x.dm_exec_sql_text(' FROM t /* sys.fn_dblog( */ -- dbo.f(\nWHERE a = N'dbo.g('",
        );
        assert!(a.usable());
        assert!(!a.user_function && a.listed.is_empty());
        // Nested block comments.
        let a = an("SELECT a FROM t /* outer /* inner */ still comment dbo.f( */ WHERE b = 1");
        assert!(a.usable() && !a.user_function);
        assert!(a.shape.unwrap().filtered);
        // Unterminated: kind only.
        for t in [
            "SELECT 'abc FROM t",
            "SELECT a /* x",
            "SELECT [a FROM t",
            "SELECT \"a FROM t",
        ] {
            let a = an(t);
            assert!(!a.lexed && a.kind == TsqlKind::Select, "{t}");
        }
        assert!(!analyze_tsql("SELECT * FROM t", true).lexed);
        // `--` comments end at `\r` too (review L7).
        let a = an("SELECT a FROM t -- x\rWHERE b = 1");
        assert!(a.shape.unwrap().filtered);
    }

    #[test]
    fn double_quotes_in_name_positions_are_ambiguous() {
        let a = an("SELECT * FROM \"crm\".\"customers\"");
        assert!(a.ambiguous && !a.usable());
        assert!(a.shape.is_none());
        // A value position: both readings give an operand.
        let a = an("SELECT * FROM crm.customers WHERE note = \"x\"");
        assert!(a.usable() && a.shape.unwrap().filtered);
    }

    #[test]
    fn shapes() {
        let full = |t: &str| an(t).full_table_read(10_001);
        assert!(full("SELECT * FROM crm.customers"));
        assert!(full("select [id],[email] from retail.crm.customers"));
        assert!(full("SELECT TOP (100000) * FROM t"));
        assert!(full("SELECT TOP 100 PERCENT * FROM t"));
        assert!(!full("SELECT TOP (100) * FROM t"));
        assert!(!full("SELECT TOP 10 * FROM t"));
        assert!(!full("SELECT TOP (@p0) * FROM t"));
        assert!(!full("SELECT * FROM t WHERE id = @P1"));
        assert!(!full("SELECT COUNT(*) FROM t"));
        assert!(!full("SELECT a, COUNT(*) FROM t GROUP BY a"));
        assert!(!full(
            "SELECT * FROM t ORDER BY id OFFSET 0 ROWS FETCH NEXT 50 ROWS ONLY"
        ));
        assert!(full(
            "SELECT * FROM t ORDER BY id OFFSET 0 ROWS FETCH NEXT 50000 ROWS ONLY"
        ));
        assert!(!full("SELECT * FROM (SELECT a FROM t) x"));
        assert!(!full(
            "WITH c AS (SELECT a FROM t WHERE b = 1) SELECT * FROM c"
        ));
        assert!(!full("UPDATE t SET a = 1"));
        assert!(full(
            "SELECT c.id, n.note FROM crm.customers c JOIN crm.customer_notes n ON n.customer_id = c.id"
        ));
        assert!(!full("SELECT * FROM dbo.tvf(1)"));
        assert!(!full(
            "SELECT CONVERT(int, (SELECT COUNT(*) FROM sys.views))"
        ));
        assert!(!full(
            "SELECT CASE WHEN EXISTS (SELECT 1 FROM sys.sql_logins) THEN 1 ELSE 0 END"
        ));
    }

    #[test]
    fn exec_arguments_are_values() {
        // An unquoted argument that looks like a call or a name.
        let a = an("EXEC dbo.report x.y, dbo.f");
        assert_eq!(a.kind, TsqlKind::Execute);
        assert!(!a.user_function && a.listed.is_empty());
        let a = an("EXEC dbo.report sql_logins; SELECT * FROM t");
        assert!(a.listed.is_empty());
    }

    #[test]
    fn flags() {
        assert!(an("EXEC ('SELECT * FROM t')").dynamic_sql);
        assert!(an("EXEC sp_executesql N'SELECT 1'").dynamic_sql);
        assert!(an("EXECUTE @p").dynamic_sql);
        let a = an("EXEC ('SELECT 1') AT linked1");
        assert!(a.dynamic_sql && a.remote_access);
        assert!(an("SELECT * FROM OPENROWSET('SQLNCLI', 'x', 'SELECT 1')").remote_access);
        assert!(an("SELECT * FROM OPENQUERY(l, 'SELECT 1')").remote_access);
        assert!(an("BULK INSERT t FROM 'f'").remote_access);
        assert!(an("EXEC xp_cmdshell 'dir'").remote_access);
        assert!(an("EXEC master..xp_dirtree '\\\\host\\share'").remote_access);
        assert!(
            an("EXEC msdb.dbo.sp_send_dbmail @recipients = 'a', @query = 'SELECT 1'").remote_access
        );
        assert!(!an("EXEC msdb.dbo.sp_send_dbmail @recipients = 'a', @body = 'x'").remote_access);
        assert!(
            an("CREATE EXTERNAL TABLE e WITH (LOCATION = 'x') AS SELECT * FROM t").remote_access
        );
        let a = an("INSERT INTO srv.db.dbo.t SELECT * FROM crm.customers");
        assert!(a.four_part && a.remote_access);
        let a = an("SELECT * FROM srv.db.dbo.t");
        assert!(a.four_part && !a.remote_access);
        assert!(an("BACKUP DATABASE retail TO DISK = 'x'").backup);
        assert!(an("BACKUP LOG retail TO DISK = 'x'").backup);
        assert!(an("DBCC CLONEDATABASE (retail, retail_clone)").backup);
        assert!(an("EXEC sp_detach_db 'retail'").backup);
        let a = an("SELECT dbo.f(a) FROM t");
        assert!(a.user_function);
        assert!(an("SELECT * FROM retail.dbo.tvf(1)").user_function);
        assert!(!an("SELECT * FROM sys.fn_my_permissions(NULL, 'SERVER')").user_function);
        assert!(an("SELECT sys.not_a_builtin(1)").user_function);
        assert!(!an("SELECT x.value('(/a)[1]', 'int') FROM t").user_function);
        assert!(!an("SELECT UPPER(a), COUNT(*) FROM t").user_function);
    }

    #[test]
    fn listed_objects() {
        let a = an(
            "SELECT t.text FROM sys.dm_exec_query_stats s CROSS APPLY sys.dm_exec_sql_text(s.sql_handle) t",
        );
        assert_eq!(a.listed, vec!["dm_exec_query_stats", "dm_exec_sql_text"]);
        assert_eq!(an("DBCC INPUTBUFFER(52)").listed, vec!["inputbuffer"]);
        assert_eq!(
            an("DBCC SHOW_STATISTICS('t', i)").listed,
            vec!["show_statistics"]
        );
        assert_eq!(an("DBCC PAGE(5, 1, 100, 3)").listed, vec!["page"]);
        assert_eq!(
            an("SELECT * FROM fn_dblog(NULL, NULL)").listed,
            vec!["fn_dblog"]
        );
        assert_eq!(
            an("SELECT name FROM sys.sql_logins").listed,
            vec!["sql_logins"]
        );
        assert_eq!(
            an("SELECT name FROM master..syslogins").listed,
            vec!["syslogins"]
        );
        assert_eq!(an("EXEC sp_readerrorlog").listed, vec!["sp_readerrorlog"]);
        // A column of a listed name is not the object.
        assert!(an("SELECT servers FROM crm.t").listed.is_empty());
        assert_eq!(
            an("SELECT LOGINPROPERTY('sa', 'PasswordHash')").listed,
            vec!["loginproperty"]
        );
    }

    #[test]
    fn exec_arguments_end_at_a_statement() {
        // A keyword ends the arguments; a call after it is analysed (fail
        // closed: a user function).
        assert!(an("EXEC crm.report if .a(").user_function);
        assert!(!an("EXEC crm.report x.a(").user_function);
    }

    #[test]
    fn kinds() {
        assert_eq!(
            an("WITH c AS (SELECT 1 a) DELETE FROM t").kind,
            TsqlKind::Write
        );
        assert_eq!(
            an("WITH c AS (SELECT 1 a) SELECT * FROM c").kind,
            TsqlKind::Select
        );
        assert_eq!(an("  select 1").kind, TsqlKind::Select);
        assert_eq!(an("").kind, TsqlKind::Other);
        assert_eq!(an("GRANT SELECT ON t TO u").kind, TsqlKind::Dcl);
        assert_eq!(an("DROP TABLE t").kind, TsqlKind::Ddl);
    }
}

#[cfg(test)]
mod proptests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        /// Never panics, whatever the text.
        #[test]
        fn never_panics(text in "\\PC{0,300}", cut in any::<bool>()) {
            let _ = analyze_tsql(&text, cut);
        }

        /// The content of a literal or a comment never changes what is
        /// found: the analysis of `SELECT a FROM t WHERE b = <literal>`
        /// is the same whatever the literal holds.
        #[test]
        fn literal_content_is_never_read(inner in "\\PC{0,80}") {
            let lit = format!("N'{}'", inner.replace('\'', "''"));
            let reference = analyze_tsql("SELECT a FROM crm.t WHERE b = N'x'", false);
            let a = analyze_tsql(&format!("SELECT a FROM crm.t WHERE b = {lit}"), false);
            prop_assert_eq!(&a, &reference);
            let comment: String = inner.chars().filter(|c| !matches!(c, '*' | '/')).collect();
            let a = analyze_tsql(&format!("SELECT a FROM crm.t /* {comment} */ WHERE b = 1"), false);
            prop_assert_eq!(&a, &reference);
        }

        /// A password-bearing statement keeps its class only, whatever
        /// follows its first words.
        #[test]
        fn credential_prefix_wins(tail in "\\PC{0,200}", which in 0usize..6) {
            let head = ["CREATE LOGIN x WITH PASSWORD = ", "ALTER LOGIN x WITH PASSWORD = ",
                "EXEC sp_addlogin x, ", "CREATE CREDENTIAL c WITH IDENTITY = 'i', SECRET = ",
                "OPEN MASTER KEY DECRYPTION BY PASSWORD = ", "exec master.dbo.sp_password "][which];
            let a = analyze_tsql(&format!("{head}{tail}"), false);
            prop_assert!(a.credential);
            prop_assert!(a.listed.is_empty() && a.shape.is_none() && !a.usable());
        }

        /// Arguments of `EXEC` are never names. The generator has no letter
        /// from `f` on, so no statement keyword (`if`, `select`…), which
        /// ends the arguments: what follows one is analysed as a new
        /// statement, fail closed (`exec_arguments_end_at_a_statement`).
        #[test]
        fn exec_arguments_never_named(args in "[a-e_.,() ]{0,80}") {
            let a = analyze_tsql(&format!("EXEC crm.report {args}"), false);
            prop_assert!(!a.user_function);
            prop_assert!(a.listed.is_empty());
        }
    }
}
