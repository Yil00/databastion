//! One session with one node (ADR-0052 decisions 1 and 5): the handshake
//! (`AUTH <user> <password>`, then `HELLO 3 SETNAME databastion-agent`
//! without credentials, H2), then commands of the closed set, each with a
//! client-side deadline (a deadline closes the connection: Redis has no
//! server-side cancel) and at most [`MAX_PIPELINE`] in flight.

use std::time::Duration;

use databastion_core::FailureCode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroize;

use crate::cmd::{Cmd, Request};
use crate::error::{RdError, Stage};
use crate::net::{Endpoint, Transport};
use crate::resp::{Decoder, ErrorWord, Limits, Value};

/// Most commands in flight (decision 1).
pub(crate) const MAX_PIPELINE: usize = 64;
/// Bytes read from the socket at a time.
const READ_CHUNK: usize = 16 * 1024;

/// What `HELLO` reported.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Hello {
    /// The connection id (the agent's own connections, decision 8).
    pub(crate) id: Option<i64>,
    /// `mode`: `standalone`, `cluster` or `sentinel`.
    pub(crate) sentinel: bool,
}

/// An authenticated RESP3 session.
pub(crate) struct Session {
    io: Transport,
    pending: Vec<u8>,
    pub(crate) hello: Hello,
    /// Unusable after a fatal error.
    broken: bool,
    /// The agent's own connection, registered for Audit's own-entry rule
    /// (decision 8, H3); marked closed on drop.
    own: Option<crate::audit::own::Registration>,
    /// The server run the connection was registered on.
    own_run: Option<u64>,
    /// When the connection was opened (before its first command): the
    /// start of its lifetime for the own-entry rule.
    started: std::time::SystemTime,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.pending.zeroize();
    }
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("id", &self.hello.id)
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Connects, authenticates and selects RESP3. `password` stays in
    /// zeroized memory and travels only inside `AUTH`.
    pub(crate) async fn open(
        endpoint: &Endpoint,
        tls: Option<std::sync::Arc<rustls::ClientConfig>>,
        user: &str,
        password: &str,
        timeout: Duration,
    ) -> Result<Self, RdError> {
        let started = std::time::SystemTime::now();
        let io = endpoint.open(tls).await?;
        let mut s = Self {
            io,
            pending: Vec::new(),
            hello: Hello::default(),
            broken: false,
            own: None,
            own_run: None,
            started,
        };
        let auth = s
            .call(&Cmd::Auth { user, password }, timeout, Stage::Auth)
            .await?;
        match auth {
            Value::Str(ref b) if b.as_slice() == b"OK" => {}
            Value::Error(w) => {
                return Err(RdError {
                    // `ERR` here: a server without ACL users (before 6.0).
                    code: if w == ErrorWord::Err {
                        FailureCode::Unsupported
                    } else {
                        crate::error::failure_of(w)
                    },
                    word: Some(w),
                    stage: Stage::Auth,
                    fatal: true,
                });
            }
            _ => return Err(RdError::new(FailureCode::Unsupported, Stage::Auth)),
        }
        let hello = s.call(&Cmd::Hello, timeout, Stage::SessionSetup).await?;
        s.hello = parse_hello(&hello)?;
        Ok(s)
    }

    /// Registers this connection as one of the agent's own for `target_id`
    /// (its connection id from `HELLO`, its local address, the server run
    /// and the time it was opened).
    pub(crate) fn register_own(&mut self, target_id: &str, run: Option<u64>) {
        if let Some(id) = self.hello.id {
            self.own_run = run;
            self.own = Some(crate::audit::own::register(
                target_id,
                id,
                self.io.local_addr(),
                run,
                self.started,
            ));
        }
    }

    /// Records the address the server reports for this registered
    /// connection (`CLIENT LIST ID <own id>`), so its slow-log entries are
    /// recognized as the agent's even once it is closed and no `CLIENT
    /// LIST` of the Audit stream saw it open. Sent only when the account is
    /// known to hold `+client|list` on the target's node and the address
    /// is not recorded yet; a refusal clears that knowledge (no second
    /// try). A transport failure is returned (the session is unusable).
    pub(crate) async fn learn_own_address(
        &mut self,
        target_id: &str,
        timeout: Duration,
    ) -> Result<(), RdError> {
        use crate::audit::own;
        let run = self.own_run;
        let Some(id) = self.hello.id else {
            return Ok(());
        };
        if self.own.is_none()
            || !own::learns_addresses(target_id)
            || own::is_seen(target_id, id, run)
        {
            return Ok(());
        }
        let reply = self
            .call(&Cmd::ClientListId(id), timeout, Stage::SessionSetup)
            .await?;
        match reply.error() {
            Some(ErrorWord::Noperm) => own::set_client_list(target_id, false),
            Some(_) => {}
            None => {
                if let Some(addr) = crate::audit::entries::own_address(&reply, id) {
                    own::seen(target_id, id, run, addr);
                }
            }
        }
        Ok(())
    }

    /// Sends one command and reads its reply. Error replies are returned
    /// as [`Value::Error`]; a transport, decoding or deadline failure is an
    /// error and leaves the session unusable.
    pub(crate) async fn call(
        &mut self,
        cmd: &Cmd<'_>,
        timeout: Duration,
        stage: Stage,
    ) -> Result<Value, RdError> {
        let mut out = self
            .pipeline(std::slice::from_ref(cmd), timeout, stage)
            .await?;
        out.pop()
            .ok_or_else(|| RdError::new(FailureCode::Internal, stage))
    }

    /// Sends up to [`MAX_PIPELINE`] commands, then reads their replies in
    /// order, each under its own limits, all under one deadline.
    pub(crate) async fn pipeline(
        &mut self,
        cmds: &[Cmd<'_>],
        timeout: Duration,
        stage: Stage,
    ) -> Result<Vec<Value>, RdError> {
        if self.broken {
            return Err(RdError::new(FailureCode::TargetUnreachable, stage));
        }
        if cmds.len() > MAX_PIPELINE {
            return Err(RdError::new(FailureCode::Internal, stage));
        }
        let r = tokio::time::timeout(timeout, self.exchange(cmds, stage)).await;
        let r = match r {
            Ok(r) => r,
            Err(_) => Err(RdError::new(FailureCode::Timeout, stage)),
        };
        if r.is_err() {
            self.broken = true;
        }
        r
    }

    async fn exchange(&mut self, cmds: &[Cmd<'_>], stage: Stage) -> Result<Vec<Value>, RdError> {
        let req = Request::of(cmds);
        self.io
            .write_all(&req.0)
            .await
            .map_err(|e| RdError::io(&e, stage))?;
        self.io.flush().await.map_err(|e| RdError::io(&e, stage))?;
        drop(req);
        let mut out = Vec::with_capacity(cmds.len().min(MAX_PIPELINE));
        for c in cmds {
            out.push(self.read_reply(c.limits(), stage).await?);
        }
        Ok(out)
    }

    async fn read_reply(&mut self, limits: Limits, stage: Stage) -> Result<Value, RdError> {
        let mut decoder = Decoder::new(limits);
        // Bytes left over from the previous reply first.
        if !self.pending.is_empty() {
            let mut pending = std::mem::take(&mut self.pending);
            let r = decoder.feed(&pending);
            let r = match r {
                Ok((used, v)) => {
                    let rest = pending.get(used..).unwrap_or_default().to_vec();
                    pending.zeroize();
                    self.pending = rest;
                    v
                }
                Err(e) => {
                    pending.zeroize();
                    return Err(RdError::decode(e, stage));
                }
            };
            if let Some(v) = r {
                return Ok(v);
            }
        }
        let mut chunk = vec![0u8; READ_CHUNK];
        let result = loop {
            let n = match self.io.read(&mut chunk).await {
                Ok(0) => {
                    break Err(RdError::new(FailureCode::TargetUnreachable, stage));
                }
                Ok(n) => n,
                Err(e) => break Err(RdError::io(&e, stage)),
            };
            let data = chunk.get(..n).unwrap_or_default();
            match decoder.feed(data) {
                Ok((used, Some(v))) => {
                    self.pending
                        .extend_from_slice(data.get(used..).unwrap_or_default());
                    break Ok(v);
                }
                Ok((_, None)) => {}
                Err(e) => break Err(RdError::decode(e, stage)),
            }
        };
        chunk.zeroize();
        result
    }

    /// Closes the connection (best effort).
    pub(crate) async fn close(mut self) {
        let _ = tokio::time::timeout(Duration::from_millis(500), self.io.shutdown()).await;
    }
}

/// Reads the `HELLO` reply map: `proto` must be 3, `mode` and `id` are
/// kept; nothing else (`server` and `version` are read from `INFO`).
pub(crate) fn parse_hello(reply: &Value) -> Result<Hello, RdError> {
    let unsupported = || RdError::new(FailureCode::Unsupported, Stage::SessionSetup);
    let pairs = match reply {
        Value::Map(pairs) => pairs,
        // A refused `HELLO 3` (no RESP3): unsupported (decision 1).
        _ => return Err(unsupported()),
    };
    let mut hello = Hello::default();
    let mut proto = None;
    for (k, v) in pairs {
        match k.as_bytes() {
            Some(b"proto") => proto = Some(v),
            Some(b"id") => {
                if let Value::Int(id) = v {
                    hello.id = Some(*id);
                }
            }
            Some(b"mode") => hello.sentinel = v.as_bytes() == Some(b"sentinel"),
            _ => {}
        }
    }
    if proto != Some(&Value::Int(3)) {
        return Err(unsupported());
    }
    Ok(hello)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resp::decode_all;

    fn hello(bytes: &[u8]) -> Result<Hello, RdError> {
        let l = Cmd::Hello.limits();
        parse_hello(&decode_all(bytes, l).unwrap().unwrap())
    }

    #[test]
    fn hello_reply() {
        let ok = b"%7\r\n$6\r\nserver\r\n$6\r\nvalkey\r\n$7\r\nversion\r\n$5\r\n9.0.6\r\n$5\r\nproto\r\n:3\r\n$2\r\nid\r\n:42\r\n$4\r\nmode\r\n$10\r\nstandalone\r\n$4\r\nrole\r\n$6\r\nmaster\r\n$7\r\nmodules\r\n*0\r\n";
        assert_eq!(
            hello(ok).unwrap(),
            Hello {
                id: Some(42),
                sentinel: false
            }
        );
        let sentinel = b"%2\r\n$5\r\nproto\r\n:3\r\n$4\r\nmode\r\n$8\r\nsentinel\r\n";
        assert!(hello(sentinel).unwrap().sentinel);
        let resp2 = b"%1\r\n$5\r\nproto\r\n:2\r\n";
        assert_eq!(hello(resp2).unwrap_err().code, FailureCode::Unsupported);
        assert_eq!(
            hello(b"-NOPROTO unsupported protocol version\r\n")
                .unwrap_err()
                .code,
            FailureCode::Unsupported
        );
        // The modules array is capped.
        let mut many = b"%1\r\n$7\r\nmodules\r\n*65\r\n".to_vec();
        many.extend_from_slice(&b":1\r\n".repeat(65));
        assert!(decode_all(&many, Cmd::Hello.limits()).is_err());
    }
}
