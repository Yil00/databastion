//! The agent's side of a reader process (ADR-0059 decision 4): spawned with
//! a fresh `execve` of the agent's own binary (`/proc/self/exe
//! sqlite-reader`, `tokio::process::Command`, killed on drop), the
//! environment cleared, standard input one end of a `UnixStream::pair()`,
//! standard output and error `/dev/null`. Every request carries a deadline;
//! past it (or on any IPC violation) the reader is killed with `SIGKILL`
//! and reaped. The IPC runs on a blocking thread with socket timeouts (the
//! connector enables no tokio `net` feature).

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::OnceLock;
use std::time::Duration;

use crate::ipc::{Channel, ChannelError, Request, Response};

/// The reader mode's argument.
pub const READER_MODE: &str = "sqlite-reader";
/// Time added to a statement deadline for the IPC and the reader's own
/// checks (decision 3: `max_statement_ms` plus 2 s).
pub const DEADLINE_SLACK: Duration = Duration::from_secs(2);

/// Why a reader is gone (it costs one unit of work, decision 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Death {
    /// Killed at its deadline.
    Deadline,
    /// It died (a signal such as `SIGBUS` or `SIGSEGV`, an `RLIMIT` signal,
    /// or an exit) or closed the channel.
    Died,
    /// An IPC violation: a frame over its bound, an unknown message, a
    /// malformed field.
    Protocol,
    /// It could not be started.
    Spawn,
}

impl Death {
    /// Stable name, for the agent's log.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Deadline => "deadline",
            Self::Died => "died",
            Self::Protocol => "protocol",
            Self::Spawn => "spawn",
        }
    }
}

/// Test support: the reader executable of other crates' tests (the agent
/// binary built by Cargo), instead of `/proc/self/exe` (a test harness).
static EXECUTABLE: OnceLock<PathBuf> = OnceLock::new();

/// Test support only (feature `test-support`, never the agent binary):
/// the reader executable, the agent binary of the tests.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn set_reader_executable_for_tests(path: PathBuf) {
    let _ = EXECUTABLE.set(path);
}

/// Test support: the credentials the reader of other crates' tests runs
/// with (a test running as root plays the agent's account).
#[cfg(any(test, feature = "test-support"))]
static CREDENTIALS: OnceLock<(u32, u32)> = OnceLock::new();

/// Test support only (feature `test-support`, never the agent binary):
/// the reader runs as `uid` / `gid` (the test runs as root).
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn set_reader_credentials_for_tests(uid: u32, gid: u32) {
    let _ = CREDENTIALS.set((uid, gid));
}

/// Whether the tests set reader credentials (the agent's process is then
/// root, playing another account; its own light check cannot judge what
/// the agent's account could write, the reader does).
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn test_credentials() -> bool {
    CREDENTIALS.get().is_some()
}

fn executable() -> PathBuf {
    EXECUTABLE
        .get()
        .cloned()
        .unwrap_or_else(|| PathBuf::from("/proc/self/exe"))
}

/// A running reader.
pub struct ReaderProcess {
    child: tokio::process::Child,
    sock: Option<Channel>,
}

impl std::fmt::Debug for ReaderProcess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReaderProcess").finish_non_exhaustive()
    }
}

impl ReaderProcess {
    /// Starts a reader. No secret is passed: the environment is cleared
    /// and the only argument is the mode.
    ///
    /// # Errors
    /// [`Death::Spawn`].
    pub fn spawn() -> Result<Self, Death> {
        let (agent, reader) = Channel::pair().map_err(|_| Death::Spawn)?;
        let mut command = tokio::process::Command::new(executable());
        command
            .arg(READER_MODE)
            .env_clear()
            .stdin(Stdio::from(reader))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        #[cfg(any(test, feature = "test-support"))]
        if let Some((uid, gid)) = CREDENTIALS.get() {
            command.uid(*uid).gid(*gid);
        }
        let child = command.spawn().map_err(|_| Death::Spawn)?;
        Ok(Self {
            child,
            sock: Some(agent),
        })
    }

    /// Sends `req` and waits for its response, at most `deadline`. On any
    /// failure the reader is killed and reaped: the process is gone.
    ///
    /// # Errors
    /// The [`Death`].
    pub async fn call(&mut self, req: &Request, deadline: Duration) -> Result<Response, Death> {
        let Some(sock) = self.sock.take() else {
            return Err(Death::Died);
        };
        let frame = req.encode().map_err(|_| Death::Protocol)?;
        let joined = tokio::task::spawn_blocking(move || sock.exchange(&frame, deadline)).await;
        match joined {
            Ok((sock, Ok(resp))) => {
                self.sock = Some(sock);
                Ok(resp)
            }
            Ok((_, Err(e))) => {
                self.kill().await;
                Err(match e {
                    ChannelError::Deadline => Death::Deadline,
                    ChannelError::Closed => Death::Died,
                    ChannelError::Protocol => Death::Protocol,
                })
            }
            Err(_) => {
                self.kill().await;
                Err(Death::Died)
            }
        }
    }

    /// Test support: the reader's process id.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    #[must_use]
    pub fn pid_for_tests(&self) -> Option<u32> {
        self.child.id()
    }

    /// `SIGKILL` and reap (bounded).
    pub async fn kill(&mut self) {
        self.sock = None;
        let _ = self.child.start_kill();
        let _ = tokio::time::timeout(Duration::from_secs(5), self.child.wait()).await;
    }

    /// Asks the reader to close and exit; kills it if it does not.
    pub async fn close(mut self) {
        let _ = self.call(&Request::Close, Duration::from_secs(2)).await;
        match tokio::time::timeout(Duration::from_secs(2), self.child.wait()).await {
            Ok(_) => {}
            Err(_) => self.kill().await,
        }
    }
}
