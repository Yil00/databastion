//! The reader process (ADR-0059 decision 4): `databastion-agent
//! sqlite-reader`, started by the agent with a fresh `execve` of its own
//! binary, a cleared environment and no argument but the mode. It holds no
//! secret: the path and the limits arrive over the IPC channel (its
//! standard input). It never logs: it reports closed codes over IPC, and
//! the agent logs them under the target id.
//!
//! Order (decision 4): [`sandbox::early`]; the open request; Landlock and
//! seccomp ([`sandbox::restrict`]); the self-check ([`db::self_check`]);
//! decision 2's open procedure and decision 5's setup ([`Session::open`]);
//! then one request at a time until `close`, an IPC violation or the end of
//! the channel. Values are copied into zeroizing buffers, sent and wiped.

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

use crate::db::{self, Db};
use crate::files::{self, Checked, MAX_WAL_BYTES, Policy, SideFiles};
use crate::ipc::{
    Code, Failure, FrameBuffer, MAX_REQUEST, OpenInfo, OpenRequest, Request, Response,
};
use crate::sandbox;

/// One open file: the held check descriptor and SQLite's connection. The
/// connection is closed before the check descriptor (field order: `db`
/// first), so SQLite's POSIX locks are never dropped by a close of ours.
pub struct Session {
    db: Option<Db>,
    checked: Checked,
    path: PathBuf,
    policy: Policy,
    side: SideFiles,
    wal: bool,
    first_statement_done: bool,
    /// The side files the Landlock grant covers (`None` in-process): one
    /// that appears later cannot be read, the file changed (review L4).
    granted: Option<Vec<(PathBuf, files::Identity)>>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("wal", &self.wal)
            .finish_non_exhaustive()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // SQLite's connection first, then (field drop) the check descriptor.
        self.db.take();
    }
}

impl Session {
    /// Decision 2's open procedure (steps 1 to 6), decision 3's journal
    /// rules, then decision 5's connection setup.
    ///
    /// # Errors
    /// The failure of the first step that refused the file.
    pub fn open(
        req: &OpenRequest,
        policy: Policy,
        granted: Option<Vec<(PathBuf, files::Identity)>>,
    ) -> Result<(Self, OpenInfo), Failure> {
        let path = PathBuf::from(OsString::from_vec(req.path.to_vec()));
        let (lo, hi) = databastion_core::config::sqlite::MAX_STATEMENT_MS_RANGE;
        if !(lo..=hi).contains(&req.max_statement_ms) {
            return Err(Failure::new(Code::Protocol));
        }
        let checked = files::open_checked(&path, policy)?;
        let side = checked.side;
        // A `-wal` next to a rollback-mode header: SQLite opens it in WAL
        // mode (decision 3's table, last row).
        let wal = checked.header.wal || side.wal.is_some();
        if wal {
            match (side.wal, side.shm) {
                (Some(w), Some(_)) if w.size <= MAX_WAL_BYTES => {}
                _ => return Err(Failure::new(Code::WalNotReadable)),
            }
        } else if !req.rollback_read {
            return Err(Failure::new(Code::RollbackNotRead));
        }
        let id = checked.id;
        let db = db::open(&path, req.max_statement_ms, || files::bind_main(id, policy))?;
        let info = OpenInfo {
            dev: id.dev,
            ino: id.ino,
            wal,
            world_readable: checked.world_readable,
            writer_version: checked.header.writer_version,
            shm_ino: side.shm.map_or(0, |s| s.id.ino),
        };
        Ok((
            Self {
                db: Some(db),
                checked,
                path,
                policy,
                side,
                wal,
                first_statement_done: false,
                granted,
            },
            info,
        ))
    }

    /// The checks before each unit of work after the first statement:
    /// every descriptor bound (step 8), the light recheck of the path and
    /// the held descriptor, the `-wal` size.
    fn before_unit(&mut self) -> Result<(), Failure> {
        let side = files::recheck(&self.path, &self.checked, self.policy)?;
        if let Some(granted) = &self.granted {
            // By path and by `(st_dev, st_ino)`: a side file re-created with
            // a new inode is not the one granted either.
            let present = [
                (side.wal, "-wal"),
                (side.shm, "-shm"),
                (side.journal, "-journal"),
            ];
            for (here, suffix) in present {
                let Some(f) = here else { continue };
                let path = files::side_path(&self.path, suffix);
                if !granted.iter().any(|(p, id)| *p == path && *id == f.id) {
                    return Err(Failure::new(Code::SideFileAppeared));
                }
            }
        }
        if self.wal && side.wal.is_some_and(|w| w.size > MAX_WAL_BYTES) {
            return Err(Failure::new(Code::WalTooLarge));
        }
        if self.first_statement_done {
            self.side = files::bind_all(&self.path, &self.checked, self.policy)?;
        }
        Ok(())
    }

    fn after_first_statement(&mut self) -> Result<(), Failure> {
        if !self.first_statement_done {
            self.first_statement_done = true;
            self.side = files::bind_all(&self.path, &self.checked, self.policy)?;
        }
        Ok(())
    }

    fn db(&self) -> Result<&Db, Failure> {
        self.db.as_ref().ok_or_else(|| Failure::new(Code::Protocol))
    }

    /// Runs one request after `open`.
    #[must_use]
    pub fn handle(&mut self, req: &Request) -> Response {
        match self.run(req) {
            Ok(r) => r,
            Err(f) => Response::Failed(f),
        }
    }

    fn run(&mut self, req: &Request) -> Result<Response, Failure> {
        if matches!(req, Request::Close) {
            self.db.take();
            return Ok(Response::Closed);
        }
        self.before_unit()?;
        let out = match req {
            Request::Open(_) | Request::Close => return Err(Failure::new(Code::Protocol)),
            Request::LightCheck => Response::LightOk,
            Request::Catalog => {
                // The first statement reads the schema: a schema that does
                // not load is not a SQLite file the reader accepts.
                let (rows, cut) = self.db()?.catalog().map_err(|f| {
                    if self.first_statement_done {
                        f
                    } else {
                        schema_failure(f)
                    }
                })?;
                Response::Catalog(rows, cut)
            }
            Request::Stats => Response::Stats(self.db()?.stats()?),
            Request::Columns(t) => Response::Columns(self.db()?.columns(t)?),
            Request::Bounds(t, a) => Response::Bounds(self.db()?.bounds(t, *a)?),
            Request::Sample(s) => Response::Sample(self.db()?.sample(s)?),
            Request::Pragmas => Response::Pragmas(self.db()?.pragmas()?),
        };
        if matches!(req, Request::Catalog) {
            self.after_first_statement()?;
        }
        Ok(out)
    }
}

/// A failure while the schema is read (the first statement): corruption,
/// a value or statement over `LENGTH` / `SQL_LENGTH`, `SQLITE_NOTADB` or a
/// schema the library cannot parse is `coverage.unrecognized_file_format`
/// (decision 7).
fn schema_failure(f: Failure) -> Failure {
    match f.code {
        Code::Corrupt | Code::TooBig | Code::Internal | Code::NoSuchTable | Code::NoRowid => {
            Failure {
                code: Code::UnrecognizedFormat,
                ..f
            }
        }
        _ => f,
    }
}

/// Reads one frame from the reader's standard input (the IPC socket).
fn read_request() -> Result<Request, ()> {
    let stdin = rustix::stdio::stdin();
    let mut fb = FrameBuffer::new(MAX_REQUEST);
    let mut chunk = zeroize::Zeroizing::new(vec![0u8; 8192]);
    loop {
        let want = fb.want().map_err(|_| ())?;
        if want == 0 {
            break;
        }
        let n = want.min(chunk.len());
        let buf = chunk.get_mut(..n).ok_or(())?;
        match rustix::io::read(stdin, &mut *buf) {
            Ok(0) => return Err(()),
            Ok(got) => fb.push(buf.get(..got).ok_or(())?).map_err(|_| ())?,
            Err(rustix::io::Errno::INTR) => {}
            Err(_) => return Err(()),
        }
    }
    let body = fb.take().map_err(|_| ())?.ok_or(())?;
    Request::decode(&body).map_err(|_| ())
}

/// Writes one response frame to the IPC socket.
fn write_response(resp: &Response) -> Result<(), ()> {
    let frame = match resp.encode() {
        Ok(f) => f,
        // A response over its bound is never sent whole.
        Err(_) => Response::Failed(Failure::new(Code::TooBig))
            .encode()
            .map_err(|_| ())?,
    };
    let stdin = rustix::stdio::stdin();
    let mut sent = 0;
    while sent < frame.len() {
        match rustix::io::write(stdin, frame.get(sent..).ok_or(())?) {
            Ok(0) => return Err(()),
            Ok(n) => sent += n,
            Err(rustix::io::Errno::INTR) => {}
            Err(_) => return Err(()),
        }
    }
    Ok(())
}

/// The reader process's main function (exit status 0 after `close`, 1
/// otherwise). Called first by the agent binary in reader mode, before any
/// configuration, state or identity file is read.
#[must_use]
pub fn main() -> i32 {
    let early = sandbox::early();
    let Ok(Request::Open(open)) = read_request() else {
        return 1;
    };
    let path = PathBuf::from(OsString::from_vec(open.path.to_vec()));
    // Review M1: the path rules (canonical, no symlink in any component,
    // the ancestors) before the Landlock grant is built from it; the grant
    // itself follows no symlink and is checked again after
    // `restrict_self`.
    let ready = early
        .and_then(|()| files::check_ancestors(&path, Policy::STRICT))
        .and_then(|()| sandbox::restrict(&path))
        .and_then(|sides| db::self_check().map(|()| sides));
    let granted = match ready {
        Ok(sides) => sides,
        Err(f) => {
            let _ = write_response(&Response::Failed(f));
            return 1;
        }
    };
    let (mut session, info) = match Session::open(&open, Policy::STRICT, Some(granted)) {
        Ok(s) => s,
        Err(f) => {
            let _ = write_response(&Response::Failed(f));
            return 1;
        }
    };
    drop(open);
    if write_response(&Response::Opened(info)).is_err() {
        return 1;
    }
    loop {
        let Ok(req) = read_request() else {
            return 1;
        };
        let resp = session.handle(&req);
        let closed = matches!(resp, Response::Closed);
        if write_response(&resp).is_err() {
            return 1;
        }
        drop(resp);
        if closed {
            return 0;
        }
    }
}
