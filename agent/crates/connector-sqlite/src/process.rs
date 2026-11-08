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

/// The state letter of process `pid` (`/proc/<pid>/stat`, after the
/// command name).
fn process_state(pid: i32) -> Option<char> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat.rsplit_once(") ")?.1.chars().next()
}

/// The unit of the times in `/proc/<pid>/stat` (`USER_HZ`): 100 on every
/// architecture the agent is built for (x86_64, aarch64).
const USER_HZ: u64 = 100;

/// The CPU time (`utime` + `stime`, fields 14 and 15) of a
/// `/proc/<pid>/stat` line, read after the command name (which may hold
/// spaces and parentheses).
fn cpu_time_of(stat: &str) -> Option<Duration> {
    let mut fields = stat.rsplit_once(") ")?.1.split_ascii_whitespace();
    // Field 3 (the state) is the first after the command name.
    let utime: u64 = fields.nth(11)?.parse().ok()?;
    let stime: u64 = fields.next()?.parse().ok()?;
    let ticks = utime.checked_add(stime)?;
    Some(Duration::from_millis(ticks.saturating_mul(1000) / USER_HZ))
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
    /// Stopped with `SIGSTOP` between units (review N1).
    stopped: bool,
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
            stopped: false,
        })
    }

    /// Sends `req` and waits for its response, at most `deadline`. On any
    /// failure the reader is killed and reaped: the process is gone.
    ///
    /// # Errors
    /// The [`Death`].
    pub async fn call(&mut self, req: &Request, deadline: Duration) -> Result<Response, Death> {
        self.resume();
        let Some(sock) = self.sock.take() else {
            return Err(Death::Died);
        };
        let frame = req.encode().map_err(|_| Death::Protocol)?;
        let joined = tokio::task::spawn_blocking(move || sock.exchange(&frame, deadline)).await;
        match joined {
            Ok((sock, Ok(resp))) => {
                self.sock = Some(sock);
                // Review L8: only SQLite's own result codes pass.
                Ok(match resp {
                    Response::Failed(f) => Response::Failed(f.with_known_engine_code()),
                    other => other,
                })
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

    /// The reader's process id (`None` once reaped).
    #[must_use]
    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    /// The CPU time the reader used so far (review L6), from
    /// `/proc/<pid>/stat`; `None` when it cannot be read.
    #[must_use]
    pub fn cpu_time(&self) -> Option<Duration> {
        let pid = self.pid()?;
        cpu_time_of(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
    }

    /// Test support: the reader's process id.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    #[must_use]
    pub fn pid_for_tests(&self) -> Option<u32> {
        self.pid()
    }

    /// Stops the reader with `SIGSTOP` (review N1): between units it cannot
    /// run, so the locks the agent reads while it is stopped are the locks
    /// it holds until the next request. Waits (at most 200 ms) until the
    /// kernel reports it stopped; `false` if it is not.
    pub async fn pause(&mut self) -> bool {
        let Some(pid) = self.pid().and_then(|p| i32::try_from(p).ok()) else {
            return false;
        };
        let Some(pid) = rustix::process::Pid::from_raw(pid) else {
            return false;
        };
        if rustix::process::kill_process(pid, rustix::process::Signal::STOP).is_err() {
            return false;
        }
        self.stopped = true;
        for _ in 0..200 {
            if process_state(pid.as_raw_nonzero().get()) == Some('T') {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        false
    }

    /// Continues a stopped reader (`SIGCONT`), just before its next
    /// request.
    pub fn resume(&mut self) {
        if !std::mem::take(&mut self.stopped) {
            return;
        }
        if let Some(pid) = self
            .pid()
            .and_then(|p| i32::try_from(p).ok())
            .and_then(rustix::process::Pid::from_raw)
        {
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::CONT);
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_time_is_utime_plus_stime() {
        // A command name with spaces and a parenthesis.
        let stat = "4242 (a (b) c) S 1 4242 4242 0 -1 4194560 300 0 0 0 \
                    1234 466 0 0 20 0 1 0 100 1000000 200 18446744073709551615";
        assert_eq!(cpu_time_of(stat), Some(Duration::from_millis(17_000)));
        assert_eq!(cpu_time_of("1 (x) S 1 2"), None);
        assert_eq!(cpu_time_of("garbage"), None);
        assert_eq!(
            cpu_time_of("1 (x) R 0 0 0 0 0 0 0 0 0 0 x 1 0"),
            None,
            "not a number"
        );
    }

    #[test]
    fn this_process_has_a_cpu_time() {
        let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
        assert!(cpu_time_of(&stat).is_some());
    }
}
