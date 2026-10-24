//! Entry points of the fuzz targets (`agent/fuzz`, feature `fuzzing`, never
//! the agent binary; ADR-0059 decision 5, security review L6).
//!
//! - [`header`]: the Rust header pre-check alone.
//! - [`ipc`]: both IPC decoders and the frame assembler.
//! - [`file`]: a main file and optional `-wal`, `-shm` and `-journal` files,
//!   written to a private directory and run through the reader's real
//!   pipeline (the path and file checks, the header pre-check, the
//!   connection setup, the catalog, `table_xinfo` and sampling statements)
//!   with the production limits and a small statement deadline. The
//!   self-check of decision 1 runs first and fails the run when the build
//!   did not get the production `LIBSQLITE3_FLAGS`.
//!
//! Every entry point must never panic nor hang, whatever the input.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::OnceLock;

use crate::files::Policy;
use crate::ipc::{
    FrameBuffer, MAX_RESPONSE, OpenRequest, Request, Response, RowidAlias, SampleRange,
    SampleRequest,
};
use crate::reader::Session;

/// The header pre-check on arbitrary bytes.
pub fn header(data: &[u8]) {
    let len = u64::try_from(data.len()).unwrap_or(0);
    let _ = crate::header::check(data, len.saturating_mul(4096));
    let _ = crate::header::check(data, len);
}

/// Both IPC decoders and the frame assembler.
pub fn ipc(data: &[u8]) {
    let _ = Request::decode(data);
    let _ = Response::decode(data);
    let mut fb = FrameBuffer::new(MAX_RESPONSE);
    for chunk in data.chunks(7) {
        if fb.push(chunk).is_err() {
            break;
        }
        if let Ok(Some(body)) = fb.take() {
            let _ = Response::decode(&body);
        }
    }
}

/// The private directory of this fuzz process (mode 0700).
fn dir() -> &'static PathBuf {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        use std::os::unix::fs::PermissionsExt;
        // The self-check first: a build without the production flags fails
        // the run here.
        crate::db::self_check().expect("SQLite self-check (production LIBSQLITE3_FLAGS)");
        let d = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("databastion-fuzz-sqlite-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        d
    })
}

/// Splits the input into length-prefixed parts (a 3-byte length each):
/// the main file, then the `-wal`, `-shm` and `-journal` files (absent when
/// the input ends first).
fn split(mut data: &[u8]) -> Vec<&[u8]> {
    let mut parts = Vec::new();
    while parts.len() < 4 {
        let Some((len, rest)) = data.split_first_chunk::<3>() else {
            break;
        };
        let n = usize::from(len[0]) << 16 | usize::from(len[1]) << 8 | usize::from(len[2]);
        let (part, rest) = rest.split_at(n.min(rest.len()));
        parts.push(part);
        data = rest;
    }
    parts
}

/// A hostile file set through the reader's pipeline.
pub fn file(data: &[u8]) {
    let d = dir();
    let main = d.join("f.db");
    let sides = ["-wal", "-shm", "-journal"];
    for s in sides {
        let _ = std::fs::remove_file(crate::files::side_path(&main, s));
    }
    let parts = split(data);
    let Some(first) = parts.first() else {
        return;
    };
    std::fs::write(&main, first).unwrap();
    for (s, part) in sides.iter().zip(parts.iter().skip(1)) {
        std::fs::write(crate::files::side_path(&main, s), part).unwrap();
    }
    let req = OpenRequest {
        path: zeroize::Zeroizing::new(crate::files::path_bytes(&main)),
        max_statement_ms: 50,
        rollback_read: true,
    };
    // The fuzzer's own files: the writability and read-only mount rules
    // cannot hold here; every other check and every SQLite setting is the
    // production one.
    let policy = Policy {
        refuse_agent_writable: false,
        require_read_only_fs: false,
        exact_descriptor_set: false,
    };
    let Ok((mut s, _)) = Session::open(&req, policy) else {
        return;
    };
    let Response::Catalog(rows, _) = s.handle(&Request::Catalog) else {
        return;
    };
    for row in rows.iter().filter(|r| !r.view && r.rootpage > 0).take(8) {
        let Response::Columns(cols) = s.handle(&Request::Columns(row.name.clone())) else {
            continue;
        };
        let columns: Vec<_> = cols
            .iter()
            .filter(|c| c.hidden != 2 && crate::sql::quote(&c.name).is_some())
            .take(crate::ipc::MAX_COLUMNS)
            .map(|c| c.name.clone())
            .collect();
        if columns.is_empty() {
            continue;
        }
        let range = match s.handle(&Request::Bounds(row.name.clone(), RowidAlias::Rowid)) {
            Response::Bounds(Some((lo, _))) => SampleRange::From(lo),
            Response::Bounds(None) => continue,
            _ => SampleRange::Plain { reverse: false },
        };
        let alias = match range {
            SampleRange::Plain { .. } => None,
            _ => Some(RowidAlias::Rowid),
        };
        let _ = s.handle(&Request::Sample(SampleRequest {
            table: row.name.clone(),
            alias,
            columns,
            range,
            limit: 100,
        }));
    }
    let _ = s.handle(&Request::Pragmas);
    let _ = s.handle(&Request::Close);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_points_take_any_input() {
        for input in [&b""[..], b"\x00\x00\x05hello", &[0xff; 300]] {
            header(input);
            ipc(input);
            file(input);
        }
        // A real file through the pipeline.
        let d = crate::it::Dir::new("fuzz-seed");
        let p = d.path("seed.db");
        crate::testing::seed(&p, false);
        let bytes = std::fs::read(&p).unwrap();
        let mut input = vec![
            u8::try_from(bytes.len() >> 16).unwrap(),
            u8::try_from((bytes.len() >> 8) & 0xff).unwrap(),
            u8::try_from(bytes.len() & 0xff).unwrap(),
        ];
        input.extend_from_slice(&bytes);
        file(&input);
    }
}
