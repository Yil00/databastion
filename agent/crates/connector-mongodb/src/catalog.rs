//! Databases and collections in scope (ADR-0026 decision 7).
//!
//! - `listDatabases` with `nameOnly` and `authorizedDatabases`: the
//!   databases the account holds privileges on, without the
//!   `listDatabases` action. `admin`, `local` and `config` are never read.
//! - `listCollections` with `nameOnly` and `authorizedCollections`: names
//!   and types, never the view definitions (which can hold literals).
//!   `system.*` and the queryable-encryption state collections
//!   (`enxcol_.*`) are out of scope.
//!
//! Both lists are bounded; a listing cut at its bound is reported once as
//! `skipped_limit` and its cursor killed (never `getMore`).

use tokio::io::{AsyncRead, AsyncWrite};

use databastion_core::FailureCode;

use crate::bson::{Doc, DocBuf, Value};
use crate::conn::{Kind, Session};
use crate::error::{MgError, Stage};

/// Most databases read from one listing.
pub(crate) const MAX_DATABASES: usize = 1024;
/// Most collections read per database.
pub(crate) const MAX_COLLECTIONS: usize = 4096;
/// Databases never read.
pub(crate) const SYSTEM_DATABASES: [&str; 3] = ["admin", "local", "config"];

/// Kind of a listed collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CollKind {
    Collection,
    Timeseries,
    /// Never read: it runs its pipeline.
    View,
    /// Any other type: not read (fail closed).
    Other,
}

/// A collection of the listing (raw name; never logged as is).
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Collection {
    pub(crate) name: String,
    pub(crate) kind: CollKind,
}

impl std::fmt::Debug for Collection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Collection")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

/// Whether a database is out of scope whatever the job.
pub(crate) fn is_system_database(name: &str) -> bool {
    SYSTEM_DATABASES.contains(&name)
}

/// Whether a collection is out of scope whatever the job.
pub(crate) fn is_system_collection(name: &str) -> bool {
    name.starts_with("system.") || name.starts_with("enxcol_.")
}

fn malformed(stage: Stage) -> impl Fn(crate::bson::Malformed) -> MgError {
    move |_| MgError::new(FailureCode::Internal, stage)
}

/// Databases the account holds privileges on, system databases excluded,
/// and whether the listing was cut at [`MAX_DATABASES`].
pub(crate) async fn list_databases<S: AsyncRead + AsyncWrite + Unpin>(
    session: &mut Session<S>,
) -> Result<(Vec<String>, bool), MgError> {
    let command = DocBuf::new()
        .i32("listDatabases", 1)
        .bool("nameOnly", true)
        .bool("authorizedDatabases", true);
    let reply = session
        .command(Stage::Introspection, "admin", command, Kind::Read)
        .await?;
    let doc = reply.doc();
    let bad = malformed(Stage::Introspection);
    let list = doc
        .array("databases")
        .map_err(&bad)?
        .ok_or(bad(crate::bson::Malformed))?;
    let mut out = Vec::new();
    let mut truncated = false;
    for element in list.iter() {
        let (_, value) = element.map_err(&bad)?;
        let Value::Doc(entry) = value else {
            return Err(bad(crate::bson::Malformed));
        };
        let Some(name) = entry.str("name").map_err(&bad)? else {
            continue;
        };
        if name.is_empty() || is_system_database(name) {
            continue;
        }
        if out.len() >= MAX_DATABASES {
            truncated = true;
            break;
        }
        out.push(name.to_owned());
    }
    Ok((out, truncated))
}

/// Parses one `listCollections` entry.
fn collection(entry: Doc<'_>) -> Result<Option<Collection>, crate::bson::Malformed> {
    let Some(name) = entry.str("name")? else {
        return Ok(None);
    };
    if name.is_empty() || is_system_collection(name) {
        return Ok(None);
    }
    let kind = match entry.str("type")? {
        Some("collection") => CollKind::Collection,
        Some("timeseries") => CollKind::Timeseries,
        Some("view") => CollKind::View,
        _ => CollKind::Other,
    };
    Ok(Some(Collection {
        name: name.to_owned(),
        kind,
    }))
}

/// Collections of `db` the account can see, and whether the listing was
/// cut at [`MAX_COLLECTIONS`].
pub(crate) async fn list_collections<S: AsyncRead + AsyncWrite + Unpin>(
    session: &mut Session<S>,
    db: &str,
) -> Result<(Vec<Collection>, bool), MgError> {
    let batch = i32::try_from(MAX_COLLECTIONS).unwrap_or(i32::MAX);
    let command = DocBuf::new()
        .i32("listCollections", 1)
        .bool("nameOnly", true)
        .bool("authorizedCollections", true)
        .doc("cursor", DocBuf::new().i32("batchSize", batch));
    let reply = session
        .command(Stage::Introspection, db, command, Kind::Read)
        .await?;
    let bad = malformed(Stage::Introspection);
    let (collections, cursor_id) = {
        let doc = reply.doc();
        let cursor = doc
            .doc("cursor")
            .map_err(&bad)?
            .ok_or(bad(crate::bson::Malformed))?;
        let batch = cursor
            .array("firstBatch")
            .map_err(&bad)?
            .ok_or(bad(crate::bson::Malformed))?;
        let mut out = Vec::new();
        for element in batch.iter() {
            let (_, value) = element.map_err(&bad)?;
            let Value::Doc(entry) = value else {
                return Err(bad(crate::bson::Malformed));
            };
            if out.len() >= MAX_COLLECTIONS {
                break;
            }
            if let Some(c) = collection(entry).map_err(&bad)? {
                out.push(c);
            }
        }
        (out, cursor.int("id").map_err(&bad)?.unwrap_or(0))
    };
    drop(reply);
    let truncated = cursor_id != 0;
    if truncated {
        session
            .kill_cursor(db, "$cmd.listCollections", cursor_id)
            .await;
    }
    Ok((collections, truncated))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, kind: &str) -> Vec<u8> {
        DocBuf::new().str("name", name).str("type", kind).finish()
    }

    #[test]
    fn collection_kinds_and_scope() {
        let parse = |bytes: Vec<u8>| collection(Doc::new(&bytes).unwrap()).unwrap();
        assert_eq!(
            parse(entry("users", "collection")).unwrap().kind,
            CollKind::Collection
        );
        assert_eq!(
            parse(entry("metrics", "timeseries")).unwrap().kind,
            CollKind::Timeseries
        );
        assert_eq!(parse(entry("v", "view")).unwrap().kind, CollKind::View);
        assert_eq!(parse(entry("x", "future")).unwrap().kind, CollKind::Other);
        for name in [
            "system.profile",
            "system.js",
            "system.views",
            "system.buckets.metrics",
            "enxcol_.users.esc",
            "",
        ] {
            assert!(parse(entry(name, "collection")).is_none(), "{name}");
        }
        // `fs.files` is an ordinary collection name.
        assert!(parse(entry("fs.files", "collection")).is_some());
        assert!(is_system_database("admin") && is_system_database("local"));
        assert!(is_system_database("config") && !is_system_database("app"));
    }

    #[test]
    fn debug_hides_the_name() {
        let c = Collection {
            name: "jane.doe@example.com".to_owned(),
            kind: CollKind::Collection,
        };
        assert!(!format!("{c:?}").contains("jane"));
    }
}
