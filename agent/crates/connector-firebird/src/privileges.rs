//! The account's privileges against the refusal and over-privilege lists
//! (ADR-0060 decision 4 and refinement R3), evaluated from what `check()`
//! read. Pure: the property tests and the fake-server tests drive it.
//!
//! - **Refused** (`privilege.refused`; Discovery and Audit do not run):
//!   `SYSDBA` by effective name, the database owner, `RDB$ADMIN` in use or
//!   reachable through the role graph (from the account or `PUBLIC`), the
//!   security-database administrator flag, a readable verifier relation,
//!   and the system privileges of the refusal list, any bit the per-version
//!   table does not know included.
//! - **Warned**: `privilege.global_privileges` for the other system
//!   privileges, a readable credential relation and a readable server
//!   configuration (`server_config_readable`, R3); `privilege.extended_variant`
//!   for `SELECT_ANY_OBJECT_IN_DATABASE` with `extended_grants: true`;
//!   `privilege.beyond_select` for object and DDL rights other than
//!   `SELECT`, `privilege.grant_option`, `privilege.owner_of_objects`.
//!   Grants held through `PUBLIC` count as the account's. Grants on system
//!   objects (their catalog's system flag, never their name) are not the
//!   account's own rights.
//! - **Roles other than the reader role** (P10-C review N4): no note of
//!   their own; what they hold is evaluated through the graph (system
//!   privileges and object grants) and reported under the codes above,
//!   and their number is in the local detail. `privilege.other_roles`
//!   stays PostgreSQL's.
//! - **Fail closed**: a read that fails or is cut gives
//!   `privilege.not_evaluated` and blocks Discovery and Audit, except the
//!   role graph (`role_graph`), whose residual (roles not in use not
//!   evaluated) the ADR accepts: the session's effective system privileges
//!   are always read.

use std::collections::{BTreeSet, VecDeque};

use databastion_core::{CountMerge, NoteCode, NoteLabel, Notes, TargetNote};

/// The system privileges by bit position (`RDB$ROLES.RDB$SYSTEM_PRIVILEGES`
/// is 8 bytes, bit `n` at byte `n / 8`, bit `n % 8`; bit 0 is unused),
/// Firebird 4.0 and 5.0, measured (`SELECT_ANY_OBJECT_IN_DATABASE` is bit
/// 16: `0000010000000000`). Checked by a drift test on each matrix image.
/// The names are the `TargetNoteLabel` values of revision `2026_10_d`.
pub(crate) const SYSTEM_PRIVILEGES: [&str; 27] = [
    "user_management",
    "read_raw_pages",
    "create_user_types",
    "use_nbackup_utility",
    "change_shutdown_mode",
    "trace_any_attachment",
    "monitor_any_attachment",
    "access_shutdown_database",
    "create_database",
    "drop_database",
    "use_gbak_utility",
    "use_gstat_utility",
    "use_gfix_utility",
    "ignore_db_triggers",
    "change_header_settings",
    "select_any_object_in_database",
    "access_any_object_in_database",
    "modify_any_object_in_database",
    "change_mapping_rules",
    "use_granted_by_clause",
    "grant_revoke_on_any_object",
    "grant_revoke_any_ddl_right",
    "create_privileged_roles",
    "get_dbcrypt_info",
    "modify_ext_conn_pool",
    "replicate_into_database",
    "profile_any_attachment",
];

/// The privileges known on a major version (bit positions 1 to this).
pub(crate) const fn known_bits(major: u32) -> usize {
    if major >= 5 { 27 } else { 26 }
}

/// System privileges that are over-privilege, not refused (decision 4).
const WARNED: &[&str] = &[
    "select_any_object_in_database",
    "use_gstat_utility",
    "get_dbcrypt_info",
    "create_user_types",
];

/// The extended variant's privilege (decision 4, R3).
const EXTENDED: &str = "select_any_object_in_database";

/// Relations whose readability is a refusal (verifiers and legacy
/// hashes, security review M5).
const VERIFIER_RELATIONS: &[&str] = &["PLG$SRP", "PLG$SRP_VIEW", "PLG$USERS", "PLG$VIEW_USERS"];

/// Most roles followed through the graph (decision 4).
pub(crate) const MAX_ROLES: usize = 64;

/// `RDB$USER_TYPE` values.
pub(crate) const USER: i64 = 8;
pub(crate) const ROLE: i64 = 13;

/// A role membership row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Membership {
    pub(crate) grantee: String,
    pub(crate) grantee_type: i64,
    pub(crate) role: String,
}

/// An object grant row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Grant {
    pub(crate) grantee: String,
    pub(crate) grantee_type: i64,
    pub(crate) privilege: String,
    pub(crate) grant_option: i64,
    pub(crate) system: bool,
}

/// What `check()` read in one database. `None`: the read failed or was
/// cut.
#[derive(Debug, Clone, Default)]
pub(crate) struct Facts {
    pub(crate) major: u32,
    pub(crate) current_user: Option<String>,
    pub(crate) admin_role_in_use: Option<bool>,
    pub(crate) owner: Option<String>,
    /// The `SEC$ADMIN` flag of the account's own row (`None` when unread
    /// or when the row is not visible).
    pub(crate) security_admin: Option<bool>,
    /// `RDB$SYSTEM_PRIVILEGE(...)` in [`SYSTEM_PRIVILEGES`] order.
    pub(crate) effective: Option<Vec<bool>>,
    pub(crate) memberships: Option<Vec<Membership>>,
    pub(crate) role_masks: Option<Vec<(String, Vec<u8>)>>,
    pub(crate) grants: Option<Vec<Grant>>,
    pub(crate) owned: Option<i64>,
    /// Active `ON CONNECT` and `ON TRANSACTION START` triggers.
    pub(crate) triggers: Option<(i64, i64)>,
    /// The credential relations probed, readable or not; `None` when the
    /// probes could not all be run.
    pub(crate) readable: Option<Vec<(String, bool)>>,
    /// `extended_grants: true`.
    pub(crate) extended_grants: bool,
}

/// The evaluation of the account in one or more databases.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Evaluation {
    pub(crate) refused: BTreeSet<String>,
    pub(crate) global: BTreeSet<String>,
    pub(crate) extended: BTreeSet<String>,
    pub(crate) beyond: BTreeSet<String>,
    pub(crate) beyond_count: u64,
    pub(crate) grant_option: bool,
    pub(crate) owned: u64,
    pub(crate) not_evaluated: BTreeSet<String>,
    /// Reads of the refusal list that failed: Discovery and Audit do not
    /// run.
    pub(crate) incomplete: BTreeSet<&'static str>,
    pub(crate) login_triggers: u64,
    pub(crate) transaction_triggers: u64,
    /// Roles reachable other than `RDB$ADMIN` (local detail).
    pub(crate) roles: BTreeSet<String>,
    /// `extended_grants: true` without the privilege (local detail).
    pub(crate) extended_unused: bool,
}

/// Whether bit `n` of a mask is set.
fn bit(mask: &[u8], n: usize) -> bool {
    mask.get(n / 8).is_some_and(|b| b & (1 << (n % 8)) != 0)
}

/// Every role reachable from the account and `PUBLIC` (decision 4), or
/// `None` past [`MAX_ROLES`].
fn reachable_roles(user: &str, memberships: &[Membership]) -> Option<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    let mut queue: VecDeque<(String, i64)> =
        [(user.to_owned(), USER), ("PUBLIC".to_owned(), USER)].into();
    while let Some((who, kind)) = queue.pop_front() {
        for m in memberships
            .iter()
            .filter(|m| m.grantee == who && m.grantee_type == kind)
        {
            if out.insert(m.role.clone()) {
                if out.len() > MAX_ROLES {
                    return None;
                }
                queue.push_back((m.role.clone(), ROLE));
            }
        }
    }
    Some(out)
}

/// The label of a privilege letter of `RDB$USER_PRIVILEGES` beyond
/// `SELECT` (contract values of protocol 0.1.0, and `usage` of revision
/// `2026_10_d`); `None` for `SELECT`.
fn letter_label(letter: &str) -> Option<&'static str> {
    Some(match letter {
        "S" => return None,
        "I" => "insert",
        "U" => "update",
        "D" => "delete",
        "R" => "references",
        "X" => "execute",
        "G" => "usage",
        "C" => "create",
        "L" => "alter",
        "O" => "drop",
        _ => "other",
    })
}

impl Evaluation {
    /// Adds the evaluation of one database.
    pub(crate) fn add(&mut self, f: &Facts) {
        let user = f.current_user.clone();
        match &user {
            Some(u) if u == "SYSDBA" => {
                self.refused.insert("sysdba".to_owned());
            }
            Some(_) => {}
            None => {
                self.incomplete.insert("identity");
            }
        }
        match f.admin_role_in_use {
            Some(true) => {
                self.refused.insert("rdb_admin".to_owned());
            }
            Some(false) => {}
            None => {
                self.incomplete.insert("identity");
            }
        }
        match (&f.owner, &user) {
            (Some(o), Some(u)) if o == u => {
                self.refused.insert("database_owner".to_owned());
            }
            (Some(_), Some(_)) => {}
            _ => {
                self.incomplete.insert("owner");
            }
        }
        match f.security_admin {
            Some(true) => {
                self.refused.insert("security_database_admin".to_owned());
            }
            Some(false) => {}
            None => {
                self.not_evaluated
                    .insert("security_database_admin".to_owned());
                self.incomplete.insert("security_database_admin");
            }
        }
        // The session's effective system privileges (mappings, default
        // roles and the roles in use included).
        let mut held: BTreeSet<usize> = BTreeSet::new();
        match &f.effective {
            Some(values) if values.len() == known_bits(f.major) => {
                held.extend(
                    values
                        .iter()
                        .enumerate()
                        .filter(|(_, v)| **v)
                        .map(|(i, _)| i + 1),
                );
            }
            _ => {
                self.incomplete.insert("system_privileges");
            }
        }
        // Every role the account could use (decision 4, M6).
        let roles = match (&user, &f.memberships, &f.role_masks) {
            (Some(u), Some(m), Some(masks)) => match reachable_roles(u, m) {
                Some(roles) => {
                    for r in &roles {
                        match masks.iter().find(|(n, _)| n == r) {
                            Some((_, mask)) => {
                                for n in 1..64 {
                                    if bit(mask, n) {
                                        held.insert(n);
                                    }
                                }
                            }
                            // A role named in a grant but absent from
                            // RDB$ROLES: the graph is not evaluated.
                            None => {
                                self.not_evaluated.insert("role_graph".to_owned());
                            }
                        }
                    }
                    roles
                }
                None => {
                    self.not_evaluated.insert("role_graph".to_owned());
                    BTreeSet::new()
                }
            },
            _ => {
                self.not_evaluated.insert("role_graph".to_owned());
                BTreeSet::new()
            }
        };
        if roles.contains("RDB$ADMIN") {
            self.refused.insert("rdb_admin".to_owned());
        }
        self.roles
            .extend(roles.iter().filter(|r| *r != "RDB$ADMIN").cloned());
        for n in held {
            let name = SYSTEM_PRIVILEGES
                .get(n - 1)
                .filter(|_| n <= known_bits(f.major));
            match name {
                Some(&EXTENDED) if f.extended_grants => {
                    self.extended.insert(EXTENDED.to_owned());
                }
                Some(name) if WARNED.contains(name) => {
                    self.global.insert((*name).to_owned());
                }
                Some(name) => {
                    self.refused.insert((*name).to_owned());
                }
                // A bit the per-version table does not know: refused.
                None => {
                    self.refused.insert("other".to_owned());
                }
            }
        }
        if f.extended_grants && !self.extended.contains(EXTENDED) {
            self.extended_unused = true;
        }
        // Object grants to the account, PUBLIC or a reachable role.
        match (&f.grants, &user) {
            (Some(grants), Some(u)) => {
                for g in grants.iter().filter(|g| {
                    !g.system
                        && ((g.grantee_type == USER && (g.grantee == *u || g.grantee == "PUBLIC"))
                            || (g.grantee_type == ROLE && roles.contains(&g.grantee)))
                }) {
                    if g.grant_option > 0 {
                        self.grant_option = true;
                    }
                    if let Some(label) = letter_label(&g.privilege) {
                        self.beyond.insert(label.to_owned());
                        self.beyond_count = self.beyond_count.saturating_add(1);
                    }
                }
            }
            _ => {
                self.not_evaluated.insert("other".to_owned());
                self.incomplete.insert("object_grants");
            }
        }
        match f.owned {
            Some(n) => self.owned = self.owned.saturating_add(u64::try_from(n).unwrap_or(0)),
            None => {
                self.incomplete.insert("owned_objects");
            }
        }
        if let Some((login, tx)) = f.triggers {
            self.login_triggers = self.login_triggers.max(u64::try_from(login).unwrap_or(0));
            self.transaction_triggers = self
                .transaction_triggers
                .max(u64::try_from(tx).unwrap_or(0));
        }
        // Credential relations (decision 4, M5) and the server
        // configuration (R3), one bit each.
        match &f.readable {
            Some(list) => {
                for (relation, _) in list.iter().filter(|(_, r)| *r) {
                    if VERIFIER_RELATIONS.contains(&relation.as_str()) {
                        self.refused.insert("verifier_relation_readable".to_owned());
                    } else if relation == "RDB$CONFIG" {
                        self.global.insert("server_config_readable".to_owned());
                    } else {
                        self.global
                            .insert("credential_relation_readable".to_owned());
                    }
                }
            }
            None => {
                self.incomplete.insert("credential_relations");
            }
        }
    }

    /// A right of the refusal list is held.
    pub(crate) fn is_refused(&self) -> bool {
        !self.refused.is_empty()
    }

    /// Discovery and Audit must not run: refused, or the refusal list
    /// could not be evaluated completely.
    pub(crate) fn blocks(&self) -> bool {
        self.is_refused() || !self.incomplete.is_empty()
    }

    /// The notes of the evaluation.
    pub(crate) fn notes(&self, notes: &mut Notes) {
        let labels = |set: &BTreeSet<String>| {
            set.iter()
                .map(|l| NoteLabel::firebird(l))
                .collect::<Vec<_>>()
        };
        if self.is_refused() {
            notes.add(
                TargetNote::new(NoteCode::PrivilegeRefused).with_labels(labels(&self.refused)),
            );
        }
        if !self.global.is_empty() {
            notes.add(
                TargetNote::new(NoteCode::PrivilegeGlobalPrivileges)
                    .with_count(self.global.len() as u64)
                    .with_labels(labels(&self.global)),
            );
        }
        if !self.extended.is_empty() {
            notes.add(
                TargetNote::new(NoteCode::PrivilegeExtendedVariant)
                    .with_labels(labels(&self.extended)),
            );
        }
        if self.beyond_count > 0 {
            notes.add(
                TargetNote::new(NoteCode::PrivilegeBeyondSelect)
                    .with_count(self.beyond_count)
                    .with_labels(labels(&self.beyond)),
            );
        }
        if self.grant_option {
            notes.add(TargetNote::new(NoteCode::PrivilegeGrantOption));
        }
        if self.owned > 0 {
            notes.add(TargetNote::new(NoteCode::PrivilegeOwnerOfObjects).with_count(self.owned));
        }
        if !self.not_evaluated.is_empty() || !self.incomplete.is_empty() {
            let mut l = labels(&self.not_evaluated);
            if l.is_empty() {
                l.push(NoteLabel::OTHER);
            }
            notes.merge(
                TargetNote::new(NoteCode::PrivilegeNotEvaluated).with_labels(l),
                CountMerge::Sum,
            );
        }
        if self.login_triggers > 0 {
            notes.add(
                TargetNote::new(NoteCode::SecurityLoginEventTrigger)
                    .with_count(self.login_triggers),
            );
        }
    }

    /// A local summary (no value: privilege, role and relation names of
    /// the catalog only).
    pub(crate) fn summary(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        let list = |s: &BTreeSet<String>| s.iter().cloned().collect::<Vec<_>>().join(", ");
        if self.is_refused() {
            parts.push(format!(
                "refused: {} (Discovery and Audit do not run)",
                list(&self.refused)
            ));
        }
        if !self.incomplete.is_empty() {
            let why: Vec<&str> = self.incomplete.iter().copied().collect();
            parts.push(format!(
                "the refusal list could not be evaluated completely ({}): Discovery and Audit \
                 do not run",
                why.join(", ")
            ));
        }
        if !self.roles.is_empty() {
            parts.push(format!("{} role(s) reachable", self.roles.len()));
        }
        if self.transaction_triggers > 0 {
            parts.push(format!(
                "{} active ON TRANSACTION START trigger(s)",
                self.transaction_triggers
            ));
        }
        if self.extended_unused {
            parts.push(
                "extended_grants is set but SELECT_ANY_OBJECT_IN_DATABASE is not held".to_owned(),
            );
        }
        parts.join("; ")
    }
}

/// The over-privilege labels counted per letter (for tests).
#[cfg(test)]
pub(crate) fn letters() -> std::collections::BTreeMap<&'static str, Option<&'static str>> {
    ["S", "I", "U", "D", "R", "X", "G", "C", "L", "O", "Z"]
        .into_iter()
        .map(|l| (l, letter_label(l)))
        .collect()
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// What the minimal account of the measurements reads on 5.0.4.
    pub(crate) fn minimal() -> Facts {
        Facts {
            major: 5,
            current_user: Some("DATABASTION_AGENT".into()),
            admin_role_in_use: Some(false),
            owner: Some("SYSDBA".into()),
            security_admin: Some(false),
            effective: Some(vec![false; 27]),
            memberships: Some(vec![Membership {
                grantee: "DATABASTION_AGENT".into(),
                grantee_type: USER,
                role: "DATABASTION_READER".into(),
            }]),
            role_masks: Some(vec![
                ("RDB$ADMIN".into(), vec![0xFF; 8]),
                ("DATABASTION_READER".into(), vec![0; 8]),
            ]),
            grants: Some(vec![
                Grant {
                    grantee: "DATABASTION_READER".into(),
                    grantee_type: ROLE,
                    privilege: "S".into(),
                    grant_option: 0,
                    system: false,
                },
                // PUBLIC's default grants on system objects.
                Grant {
                    grantee: "PUBLIC".into(),
                    grantee_type: USER,
                    privilege: "G".into(),
                    grant_option: 0,
                    system: true,
                },
                Grant {
                    grantee: "PUBLIC".into(),
                    grantee_type: USER,
                    privilege: "X".into(),
                    grant_option: 0,
                    system: true,
                },
                // Another user's write grant.
                Grant {
                    grantee: "SOMEONE".into(),
                    grantee_type: USER,
                    privilege: "U".into(),
                    grant_option: 1,
                    system: false,
                },
            ]),
            owned: Some(0),
            triggers: Some((0, 0)),
            readable: Some(vec![
                ("SEC$USERS".into(), false),
                ("RDB$CONFIG".into(), false),
            ]),
            extended_grants: false,
        }
    }

    fn codes(e: &Evaluation) -> Vec<&'static str> {
        let mut notes = Notes::default();
        e.notes(&mut notes);
        notes.into_vec().iter().map(|n| n.code().as_str()).collect()
    }

    #[test]
    fn the_minimal_account_has_no_note() {
        let mut e = Evaluation::default();
        e.add(&minimal());
        assert!(!e.blocks(), "{e:?}");
        assert!(codes(&e).is_empty(), "{:?}", codes(&e));
        assert_eq!(e.roles.len(), 1);
    }

    #[test]
    fn identities_of_the_refusal_list() {
        for (change, label) in [
            (
                Box::new(|f: &mut Facts| f.current_user = Some("SYSDBA".into()))
                    as Box<dyn Fn(&mut Facts)>,
                "sysdba",
            ),
            (Box::new(|f| f.admin_role_in_use = Some(true)), "rdb_admin"),
            (
                Box::new(|f| f.owner = Some("DATABASTION_AGENT".into())),
                "database_owner",
            ),
            (
                Box::new(|f| f.security_admin = Some(true)),
                "security_database_admin",
            ),
            (
                Box::new(|f| {
                    f.memberships.as_mut().unwrap().push(Membership {
                        grantee: "PUBLIC".into(),
                        grantee_type: USER,
                        role: "RDB$ADMIN".into(),
                    });
                }),
                "rdb_admin",
            ),
            (
                Box::new(|f| {
                    f.readable.as_mut().unwrap().push(("PLG$SRP".into(), true));
                }),
                "verifier_relation_readable",
            ),
        ] {
            let mut f = minimal();
            change(&mut f);
            let mut e = Evaluation::default();
            e.add(&f);
            assert!(e.is_refused() && e.blocks(), "{label}");
            assert!(e.refused.contains(label), "{label}: {e:?}");
            assert_eq!(codes(&e)[0], "privilege.refused");
        }
    }

    #[test]
    fn system_privileges_through_the_session_and_the_graph() {
        // Effective: TRACE_ANY_ATTACHMENT (bit 6) in use.
        let mut f = minimal();
        f.effective.as_mut().unwrap()[5] = true;
        let mut e = Evaluation::default();
        e.add(&f);
        assert!(e.refused.contains("trace_any_attachment"));
        // A nested role (not in use) with MONITOR_ANY_ATTACHMENT (bit 7).
        let mut f = minimal();
        f.memberships.as_mut().unwrap().push(Membership {
            grantee: "DATABASTION_READER".into(),
            grantee_type: ROLE,
            role: "NESTED".into(),
        });
        f.role_masks
            .as_mut()
            .unwrap()
            .push(("NESTED".into(), vec![0b1000_0000, 0, 0, 0, 0, 0, 0, 0]));
        let mut e = Evaluation::default();
        e.add(&f);
        assert!(e.refused.contains("monitor_any_attachment"), "{e:?}");
        // SELECT_ANY_OBJECT_IN_DATABASE (bit 16): over-privilege, or the
        // extended variant with the flag.
        let mask = vec![0, 0, 1, 0, 0, 0, 0, 0];
        let mut f = minimal();
        f.role_masks.as_mut().unwrap()[1].1 = mask.clone();
        let mut e = Evaluation::default();
        e.add(&f);
        assert!(!e.blocks() && e.global.contains("select_any_object_in_database"));
        f.extended_grants = true;
        let mut e = Evaluation::default();
        e.add(&f);
        assert!(!e.blocks() && e.extended.contains("select_any_object_in_database"));
        assert!(e.global.is_empty());
        // PROFILE_ANY_ATTACHMENT (bit 27) is unknown on 4.0: refused as
        // `other`; on 5.0 by name.
        let mut f = minimal();
        f.role_masks.as_mut().unwrap()[1].1 = vec![0, 0, 0, 0b0000_1000, 0, 0, 0, 0];
        let mut e = Evaluation::default();
        e.add(&f);
        assert!(e.refused.contains("profile_any_attachment"));
        f.major = 4;
        f.effective = Some(vec![false; 26]);
        let mut e = Evaluation::default();
        e.add(&f);
        assert!(e.refused.contains("other"), "{e:?}");
        // A bit past the table on any version.
        let mut f = minimal();
        f.role_masks.as_mut().unwrap()[1].1 = vec![0, 0, 0, 0, 0, 0, 0, 0x80];
        let mut e = Evaluation::default();
        e.add(&f);
        assert!(e.refused.contains("other"));
    }

    #[test]
    fn object_grants_beyond_select() {
        let mut f = minimal();
        f.grants.as_mut().unwrap().extend([
            Grant {
                grantee: "PUBLIC".into(),
                grantee_type: USER,
                privilege: "D".into(),
                grant_option: 0,
                system: false,
            },
            Grant {
                grantee: "DATABASTION_AGENT".into(),
                grantee_type: USER,
                privilege: "S".into(),
                grant_option: 1,
                system: false,
            },
            Grant {
                grantee: "DATABASTION_READER".into(),
                grantee_type: ROLE,
                privilege: "C".into(),
                grant_option: 0,
                system: false,
            },
        ]);
        f.owned = Some(3);
        f.triggers = Some((1, 2));
        f.readable
            .as_mut()
            .unwrap()
            .extend([("RDB$CONFIG".into(), true), ("SEC$USERS".into(), true)]);
        let mut e = Evaluation::default();
        e.add(&f);
        assert!(!e.blocks());
        assert_eq!(e.beyond, ["create", "delete"].map(String::from).into());
        assert_eq!(e.beyond_count, 2);
        assert!(e.grant_option);
        assert_eq!(e.owned, 3);
        assert_eq!(
            e.global,
            ["credential_relation_readable", "server_config_readable"]
                .map(String::from)
                .into()
        );
        assert_eq!(
            codes(&e),
            [
                "privilege.global_privileges",
                "privilege.beyond_select",
                "privilege.grant_option",
                "privilege.owner_of_objects",
                "security.login_event_trigger"
            ]
        );
        assert!(e.summary().contains("2 active ON TRANSACTION START"));
    }

    #[test]
    fn failed_reads_fail_closed() {
        for change in [
            Box::new(|f: &mut Facts| f.current_user = None) as Box<dyn Fn(&mut Facts)>,
            Box::new(|f| f.admin_role_in_use = None),
            Box::new(|f| f.owner = None),
            Box::new(|f| f.security_admin = None),
            Box::new(|f| f.effective = None),
            Box::new(|f| f.effective = Some(vec![false; 3])),
            Box::new(|f| f.grants = None),
            Box::new(|f| f.owned = None),
            Box::new(|f| f.readable = None),
        ] {
            let mut f = minimal();
            change(&mut f);
            let mut e = Evaluation::default();
            e.add(&f);
            assert!(e.blocks(), "{e:?}");
            assert!(codes(&e).contains(&"privilege.not_evaluated"));
        }
        // The role graph alone: not evaluated, the residual, not blocking.
        let mut f = minimal();
        f.memberships = None;
        let mut e = Evaluation::default();
        e.add(&f);
        assert!(!e.blocks());
        assert!(e.not_evaluated.contains("role_graph"));
        // More than 64 roles.
        let mut f = minimal();
        let m = f.memberships.as_mut().unwrap();
        for i in 0..70 {
            m.push(Membership {
                grantee: "PUBLIC".into(),
                grantee_type: USER,
                role: format!("R{i}"),
            });
        }
        let mut e = Evaluation::default();
        e.add(&f);
        assert!(e.not_evaluated.contains("role_graph"));
        // A role missing from RDB$ROLES.
        let mut f = minimal();
        f.role_masks = Some(vec![]);
        let mut e = Evaluation::default();
        e.add(&f);
        assert!(e.not_evaluated.contains("role_graph"));
    }

    #[test]
    fn the_letter_table_is_closed() {
        let l = letters();
        assert_eq!(l["S"], None);
        assert_eq!(l["G"], Some("usage"));
        assert_eq!(l["Z"], Some("other"));
        // Every label is a contract value the Firebird builder accepts.
        for label in l.values().flatten() {
            assert!(
                *label == "other" || !NoteLabel::firebird(label).is_other(),
                "{label}"
            );
        }
        for name in SYSTEM_PRIVILEGES {
            assert!(!NoteLabel::firebird(name).is_other(), "{name}");
        }
    }
}
