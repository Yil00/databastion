//! Over-privilege of the agent's account (ADR-0026 decision 5).
//!
//! `connectionStatus` with `showPrivileges: true` returns the account's
//! resolved privileges: those of every role, inherited ones included, so
//! no role is left unevaluated. Discovery needs `find` and
//! `listCollections` on the monitored databases; everything else is
//! reported, as counts:
//! - write or administration actions: any action outside the known
//!   read-only list (an unknown action counts here: fail closed);
//! - read actions beyond `find` / `listCollections` (`changeStream` streams
//!   every future write of a database, values included);
//! - cluster-wide actions (`inprog` shows other sessions' operations with
//!   their literals, `getCmdLineOpts` the server settings…);
//! - privileges on every database (`anyResource`, or an empty database
//!   name as `readAnyDatabase` has);
//! - access to system collections (`system.*`) or to the `admin`, `local`
//!   and `config` databases (credentials, the oplog, profiled queries,
//!   stored JavaScript).
//!
//! A resource the connector cannot parse counts as a privilege on every
//! database. Role names are never read nor logged; action names are logged
//! only when they are on the lists below.

use std::collections::BTreeSet;

use databastion_core::{NoteCode, TargetNote};

use crate::bson::{Doc, Malformed, Value};
use crate::catalog::is_system_database;

/// The Discovery grant.
pub(crate) const DISCOVERY_ACTIONS: [&str; 2] = ["find", "listCollections"];

/// Actions without side effects (reads of data, metadata or server state).
const READ_ACTIONS: &[&str] = &[
    "find",
    "listCollections",
    "listDatabases",
    "listIndexes",
    "listSearchIndexes",
    "collStats",
    "dbStats",
    "dbHash",
    "changeStream",
    "indexStats",
    "planCacheRead",
    "viewRole",
    "viewUser",
    "serverStatus",
    "inprog",
    "top",
    "getCmdLineOpts",
    "getParameter",
    "getLog",
    "hostInfo",
    "connPoolStats",
    "netstat",
    "replSetGetStatus",
    "replSetGetConfig",
    "listShards",
    "getShardMap",
    "getShardVersion",
    "checkMetadataConsistency",
    "getDefaultRWConcern",
    "getClusterParameter",
    "listClusterCatalog",
    "listSessions",
    "listCachedAndActiveUsers",
    "operationMetrics",
    "queryStatsRead",
    "queryStatsReadTransformed",
    "shardedDataDistribution",
    "useUUID",
    "bypassDefaultMaxTimeMS",
];

/// Most privileges and actions read from one reply.
const MAX_PRIVILEGES: usize = 4096;
const MAX_ACTIONS: usize = 256;

/// The account's privileges beyond the Discovery grant.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PrivilegeReport {
    pub(crate) write_actions: BTreeSet<String>,
    pub(crate) read_beyond: BTreeSet<String>,
    pub(crate) cluster_actions: BTreeSet<String>,
    pub(crate) any_database: bool,
    pub(crate) system_collections: bool,
}

enum Resource<'a> {
    Cluster,
    Any,
    Namespace { db: &'a str, collection: &'a str },
}

fn resource<'a>(doc: Doc<'a>) -> Result<Option<Resource<'a>>, Malformed> {
    if doc.flag("cluster")? == Some(true) {
        return Ok(Some(Resource::Cluster));
    }
    if doc.flag("anyResource")? == Some(true) {
        return Ok(Some(Resource::Any));
    }
    let db = doc.str("db")?;
    let collection = doc.str("collection")?;
    let buckets = doc.str("system_buckets")?;
    Ok(match (db, collection, buckets) {
        (Some(db), Some(collection), _) => Some(Resource::Namespace { db, collection }),
        // Time-series buckets: the collection's own data.
        (Some(db), None, Some(_)) => Some(Resource::Namespace { db, collection: "" }),
        _ => None,
    })
}

/// An action name as logged: its name when known, `other` otherwise.
pub(crate) fn loggable(action: &str) -> &str {
    if READ_ACTIONS.contains(&action) || WRITE_NAMES.contains(&action) {
        action
    } else {
        "other"
    }
}

/// Write / administration actions whose names are logged as they are.
const WRITE_NAMES: &[&str] = &[
    "insert",
    "update",
    "remove",
    "createCollection",
    "createIndex",
    "dropCollection",
    "dropIndex",
    "dropDatabase",
    "renameCollectionSameDB",
    "collMod",
    "convertToCapped",
    "compact",
    "enableProfiler",
    "killCursors",
    "killAnyCursor",
    "killop",
    "createUser",
    "dropUser",
    "changePassword",
    "changeOwnPassword",
    "grantRole",
    "revokeRole",
    "createRole",
    "dropRole",
    "setAuthenticationRestriction",
    "applyOps",
    "shutdown",
    "setParameter",
    "fsync",
    "reIndex",
    "validate",
];

impl PrivilegeReport {
    /// Evaluates the `authInfo.authenticatedUserPrivileges` of a
    /// `connectionStatus` reply.
    pub(crate) fn from_connection_status(reply: Doc<'_>) -> Result<Self, Malformed> {
        let mut r = Self::default();
        let Some(auth) = reply.doc("authInfo")? else {
            return Err(Malformed);
        };
        let Some(privileges) = auth.array("authenticatedUserPrivileges")? else {
            return Err(Malformed);
        };
        for (i, element) in privileges.iter().enumerate() {
            if i >= MAX_PRIVILEGES {
                // Unread privileges: assume the worst.
                r.any_database = true;
                break;
            }
            let (_, value) = element?;
            let Value::Doc(p) = value else {
                return Err(Malformed);
            };
            let res = match p.doc("resource")? {
                Some(d) => resource(d)?,
                None => None,
            };
            let mut actions: Vec<&str> = Vec::new();
            if let Some(list) = p.array("actions")? {
                for (j, a) in list.iter().enumerate() {
                    if j >= MAX_ACTIONS {
                        r.any_database = true;
                        break;
                    }
                    if let (_, Value::Str(s)) = a? {
                        actions.push(std::str::from_utf8(s).map_err(|_| Malformed)?);
                    }
                }
            }
            r.add(res, &actions);
        }
        Ok(r)
    }

    fn add(&mut self, resource: Option<Resource<'_>>, actions: &[&str]) {
        for action in actions {
            let read = READ_ACTIONS.contains(action);
            if !read {
                self.write_actions.insert((*action).to_owned());
            }
            let beyond = read && !DISCOVERY_ACTIONS.contains(action);
            match &resource {
                Some(Resource::Cluster) => {
                    self.cluster_actions.insert((*action).to_owned());
                }
                Some(Resource::Any) | None => {
                    self.any_database = true;
                    self.system_collections = true;
                    if beyond {
                        self.read_beyond.insert((*action).to_owned());
                    }
                }
                Some(Resource::Namespace { db, collection }) => {
                    if db.is_empty() {
                        self.any_database = true;
                    }
                    if is_system_database(db) || collection.starts_with("system.") {
                        self.system_collections = true;
                    }
                    if beyond {
                        self.read_beyond.insert((*action).to_owned());
                    }
                }
            }
        }
    }

    /// Whether the account holds the Discovery grant only.
    pub(crate) fn is_minimal(&self) -> bool {
        self == &Self::default()
    }

    /// The report as closed notes (counts only).
    pub(crate) fn notes(&self) -> Vec<TargetNote> {
        let mut out = Vec::new();
        let count = |s: &BTreeSet<String>| s.len() as u64;
        if !self.write_actions.is_empty() {
            out.push(
                TargetNote::new(NoteCode::PrivilegeWriteActions)
                    .with_count(count(&self.write_actions)),
            );
        }
        if !self.read_beyond.is_empty() {
            out.push(
                TargetNote::new(NoteCode::PrivilegeReadBeyondDiscovery)
                    .with_count(count(&self.read_beyond)),
            );
        }
        if !self.cluster_actions.is_empty() {
            out.push(
                TargetNote::new(NoteCode::PrivilegeClusterActions)
                    .with_count(count(&self.cluster_actions)),
            );
        }
        if self.any_database {
            out.push(TargetNote::new(NoteCode::PrivilegeAnyDatabase));
        }
        if self.system_collections {
            out.push(TargetNote::new(NoteCode::PrivilegeSystemCollections));
        }
        out
    }

    /// The report for the agent's log (known action names only).
    pub(crate) fn summary(&self) -> Vec<String> {
        let names = |s: &BTreeSet<String>| {
            let mut v: Vec<&str> = s.iter().map(|a| loggable(a)).collect();
            v.dedup();
            v.join(", ")
        };
        let mut out = Vec::new();
        if !self.write_actions.is_empty() {
            out.push(format!(
                "write or administration actions: {}",
                names(&self.write_actions)
            ));
        }
        if !self.read_beyond.is_empty() {
            out.push(format!(
                "read actions beyond find and listCollections: {}",
                names(&self.read_beyond)
            ));
        }
        if !self.cluster_actions.is_empty() {
            out.push(format!(
                "cluster-wide actions: {}",
                names(&self.cluster_actions)
            ));
        }
        if self.any_database {
            out.push("a privilege on every database".to_owned());
        }
        if self.system_collections {
            out.push(
                "access to system collections or to the admin, local or config databases"
                    .to_owned(),
            );
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bson::DocBuf;

    fn privilege(resource: DocBuf, actions: &[&str]) -> DocBuf {
        DocBuf::new()
            .doc("resource", resource)
            .array_str("actions", actions)
    }

    fn ns(db: &str, collection: &str) -> DocBuf {
        DocBuf::new().str("db", db).str("collection", collection)
    }

    fn report(privileges: Vec<DocBuf>) -> PrivilegeReport {
        let bytes = DocBuf::new()
            .doc(
                "authInfo",
                DocBuf::new().array("authenticatedUserPrivileges", privileges),
            )
            .i32("ok", 1)
            .finish();
        PrivilegeReport::from_connection_status(Doc::new(&bytes).unwrap()).unwrap()
    }

    fn codes(r: &PrivilegeReport) -> Vec<(&'static str, Option<u64>)> {
        r.notes()
            .iter()
            .map(|n| (n.code().as_str(), n.count()))
            .collect()
    }

    #[test]
    fn the_discovery_role_is_minimal() {
        let r = report(vec![
            privilege(ns("app", ""), &["find", "listCollections"]),
            privilege(ns("crm", ""), &["find", "listCollections"]),
        ]);
        assert!(r.is_minimal(), "{r:?}");
        assert!(r.notes().is_empty());
    }

    #[test]
    fn read_and_cluster_monitor_are_reported() {
        // `read` on app + `clusterMonitor` (the previous recommendation).
        let r = report(vec![
            privilege(
                ns("app", ""),
                &[
                    "changeStream",
                    "collStats",
                    "dbHash",
                    "dbStats",
                    "find",
                    "killCursors",
                    "listCollections",
                    "listIndexes",
                    "listSearchIndexes",
                ],
            ),
            privilege(ns("app", "system.js"), &["find", "listCollections"]),
            privilege(
                DocBuf::new().bool("cluster", true),
                &["inprog", "serverStatus", "getCmdLineOpts", "listDatabases"],
            ),
            privilege(ns("", "system.profile"), &["find"]),
        ]);
        assert_eq!(
            codes(&r),
            [
                ("privilege.write_actions", Some(1)),
                ("privilege.read_beyond_discovery", Some(6)),
                ("privilege.cluster_actions", Some(4)),
                ("privilege.any_database", None),
                ("privilege.system_collections", None),
            ]
        );
        assert!(r.summary().iter().any(|s| s.contains("changeStream")));
    }

    #[test]
    fn write_roles_any_resource_and_unknown_resources() {
        let r = report(vec![privilege(
            ns("app", ""),
            &["find", "insert", "update", "remove", "someFutureAction"],
        )]);
        assert_eq!(codes(&r), [("privilege.write_actions", Some(4))]);
        // Unknown action names are logged as `other`, never as sent.
        assert!(r.summary()[0].contains("other"));
        assert!(!r.summary()[0].contains("someFutureAction"));
        let r = report(vec![privilege(
            DocBuf::new().bool("anyResource", true),
            &["find"],
        )]);
        assert!(r.any_database && r.system_collections);
        // readAnyDatabase: an empty database name.
        let r = report(vec![privilege(ns("", ""), &["find", "listCollections"])]);
        assert_eq!(codes(&r), [("privilege.any_database", None)]);
        // A resource that cannot be parsed: assume every database.
        let r = report(vec![privilege(DocBuf::new().i32("weird", 1), &["find"])]);
        assert!(r.any_database);
        // Admin database access.
        let r = report(vec![privilege(ns("admin", ""), &["find"])]);
        assert_eq!(codes(&r), [("privilege.system_collections", None)]);
    }

    #[test]
    fn a_reply_without_privileges_is_malformed() {
        let bytes = DocBuf::new().i32("ok", 1).finish();
        assert!(PrivilegeReport::from_connection_status(Doc::new(&bytes).unwrap()).is_err());
    }
}
