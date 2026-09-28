//! Connections opened by the connector itself (security review M2).
//!
//! The connector opens the TCP or Unix-socket connection to the declared
//! target (I5: no other host) and hands it to tokio-postgres
//! (`connect_raw`), so that:
//! - without TLS, an [`AuthGuard`] reads the server's authentication
//!   requests before the driver does and refuses a cleartext or MD5
//!   password request (tokio-postgres has no `require_auth`): an active
//!   attacker on the path cannot obtain the password in clear or an MD5
//!   hash of it (I3). Only SCRAM (or password-less peer / trust
//!   authentication on a local socket) is accepted;
//! - cancel requests use a fresh connection to the same endpoint
//!   (`cancel_query_raw`).
//!
//! No listening socket is ever created (I1).

use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::tls::{RustlsConnect, RustlsConnector};

/// TCP connect timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Where a target listens, and its TLS settings.
#[derive(Clone)]
pub(crate) struct Endpoint {
    addr: Addr,
    pub(crate) tls: RustlsConnector,
}

#[derive(Clone)]
enum Addr {
    Tcp { host: String, port: u16 },
    Unix { path: PathBuf },
}

impl Endpoint {
    pub(crate) fn tcp(host: &str, port: u16, tls: RustlsConnector) -> Self {
        Self {
            addr: Addr::Tcp {
                host: host.to_owned(),
                port,
            },
            tls,
        }
    }

    /// `socket` is the socket file (`/run/postgresql/.s.PGSQL.5432`) or its
    /// directory (port 5432). No TLS on a Unix socket.
    pub(crate) fn unix(socket: &Path) -> Self {
        let is_file = socket
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with(".s.PGSQL."));
        let path = if is_file {
            socket.to_owned()
        } else {
            socket.join(".s.PGSQL.5432")
        };
        Self {
            addr: Addr::Unix { path },
            tls: RustlsConnector::disabled(),
        }
    }

    /// TLS handshake for this endpoint (server name = configured host).
    pub(crate) fn tls_connect(&self) -> RustlsConnect {
        match &self.addr {
            Addr::Tcp { host, .. } => self.tls.connector_for(host),
            Addr::Unix { .. } => self.tls.connector_for(""),
        }
    }

    /// Opens a connection to the endpoint.
    pub(crate) async fn open(&self) -> io::Result<Transport> {
        match &self.addr {
            Addr::Tcp { host, port } => {
                let stream = tokio::time::timeout(
                    CONNECT_TIMEOUT,
                    tokio::net::TcpStream::connect((host.as_str(), *port)),
                )
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timed out"))??;
                stream.set_nodelay(true)?;
                Ok(Transport::Tcp(stream))
            }
            Addr::Unix { path } => Ok(Transport::Unix(
                tokio::net::UnixStream::connect(path).await?,
            )),
        }
    }
}

/// A client connection (TCP or Unix socket).
pub(crate) enum Transport {
    Tcp(tokio::net::TcpStream),
    Unix(tokio::net::UnixStream),
}

impl AsyncRead for Transport {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            Self::Unix(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Transport {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            Self::Unix(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_flush(cx),
            Self::Unix(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            Self::Unix(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Server authentication request codes (protocol `AuthenticationRequest`).
const AUTH_OK: u32 = 0;
const AUTH_CLEARTEXT: u32 = 3;
const AUTH_MD5: u32 = 5;
const AUTH_SASL_CONTINUE: u32 = 11;
/// Lowest SCRAM iteration count accepted without TLS (PostgreSQL's
/// default; an attacker on the path could otherwise ask for 1 to make the
/// relayed proof cheap to attack offline).
const MIN_SCRAM_ITERATIONS: u64 = 4096;
/// Largest `SASLContinue` body parsed.
const MAX_SASL_BODY: usize = 2048;

/// Error kind of a refused authentication method.
pub(crate) const REFUSED_AUTH: io::ErrorKind = io::ErrorKind::PermissionDenied;

/// Parses server messages up to the end of authentication.
#[derive(Default)]
struct AuthParse {
    header: Vec<u8>,
    skip: usize,
    /// Body of a `SASLContinue` being collected, and its remaining length.
    sasl: Option<(Vec<u8>, usize)>,
}

/// `i=` of a SCRAM server-first-message (`r=…,s=…,i=4096`).
fn scram_iterations(body: &[u8]) -> Option<u64> {
    std::str::from_utf8(body)
        .ok()?
        .split(',')
        .find_map(|f| f.strip_prefix("i="))?
        .parse()
        .ok()
}

impl AuthParse {
    /// `Err` on a cleartext / MD5 request; `Ok(true)` once authentication
    /// ended (success or error message).
    fn feed(&mut self, mut bytes: &[u8]) -> Result<bool, ()> {
        while !bytes.is_empty() {
            if let Some((body, left)) = &mut self.sasl {
                let n = (*left).min(bytes.len());
                body.extend_from_slice(&bytes[..n]);
                *left -= n;
                bytes = &bytes[n..];
                if *left == 0 {
                    if scram_iterations(body).is_none_or(|i| i < MIN_SCRAM_ITERATIONS) {
                        return Err(());
                    }
                    self.sasl = None;
                }
                continue;
            }
            if self.skip > 0 {
                let n = self.skip.min(bytes.len());
                self.skip -= n;
                bytes = &bytes[n..];
                continue;
            }
            self.header.push(bytes[0]);
            bytes = &bytes[1..];
            if self.header.len() < 5 {
                continue;
            }
            let len = usize::try_from(u32::from_be_bytes([
                self.header[1],
                self.header[2],
                self.header[3],
                self.header[4],
            ]))
            .map_err(|_| ())?;
            match self.header[0] {
                b'R' => {
                    if len < 8 {
                        return Err(());
                    }
                    if self.header.len() < 9 {
                        continue;
                    }
                    let code = u32::from_be_bytes([
                        self.header[5],
                        self.header[6],
                        self.header[7],
                        self.header[8],
                    ]);
                    match code {
                        AUTH_CLEARTEXT | AUTH_MD5 => return Err(()),
                        AUTH_OK => return Ok(true),
                        AUTH_SASL_CONTINUE => {
                            if len - 8 > MAX_SASL_BODY {
                                return Err(());
                            }
                            self.sasl = Some((Vec::with_capacity(len - 8), len - 8));
                            self.header.clear();
                            if len == 8 {
                                return Err(());
                            }
                            continue;
                        }
                        _ => {}
                    }
                    self.skip = len - 8;
                }
                // Error response: authentication ended, the driver reports it.
                b'E' => return Ok(true),
                _ => {
                    if len < 4 {
                        return Err(());
                    }
                    self.skip = len - 4;
                }
            }
            self.header.clear();
        }
        Ok(false)
    }
}

/// Refuses cleartext / MD5 password requests on a connection without TLS.
pub(crate) struct AuthGuard<S> {
    inner: S,
    parse: Option<AuthParse>,
}

impl<S> AuthGuard<S> {
    /// `active`: the connection has no TLS.
    pub(crate) fn new(inner: S, active: bool) -> Self {
        Self {
            inner,
            parse: active.then(AuthParse::default),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for AuthGuard<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        ready!(Pin::new(&mut this.inner).poll_read(cx, buf))?;
        if let Some(p) = &mut this.parse {
            match p.feed(&buf.filled()[before..]) {
                Err(()) => {
                    // The request never reaches the driver: no answer is
                    // sent.
                    buf.set_filled(before);
                    return Poll::Ready(Err(io::Error::new(
                        REFUSED_AUTH,
                        "cleartext or MD5 password, or weak SCRAM parameters, requested on a \
                         connection without TLS",
                    )));
                }
                Ok(true) => this.parse = None,
                Ok(false) => {}
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for AuthGuard<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth(code: u32, extra: &[u8]) -> Vec<u8> {
        let mut m = vec![b'R'];
        m.extend_from_slice(&u32::try_from(8 + extra.len()).unwrap().to_be_bytes());
        m.extend_from_slice(&code.to_be_bytes());
        m.extend_from_slice(extra);
        m
    }

    #[test]
    fn unix_socket_paths() {
        let path = |e: Endpoint| match e.addr {
            Addr::Unix { path } => path,
            Addr::Tcp { .. } => PathBuf::new(),
        };
        assert_eq!(
            path(Endpoint::unix(Path::new("/run/postgresql/.s.PGSQL.5433"))),
            Path::new("/run/postgresql/.s.PGSQL.5433")
        );
        assert_eq!(
            path(Endpoint::unix(Path::new("/run/postgresql"))),
            Path::new("/run/postgresql/.s.PGSQL.5432")
        );
    }

    #[test]
    fn cleartext_and_md5_are_refused() {
        assert!(AuthParse::default().feed(&auth(3, &[])).is_err());
        assert!(AuthParse::default().feed(&auth(5, b"salt")).is_err());
    }

    #[test]
    fn scram_passes_byte_by_byte() {
        let mut stream = auth(10, b"SCRAM-SHA-256\0\0");
        stream.extend(auth(11, b"r=nonce,s=c2FsdA==,i=4096"));
        stream.extend(auth(12, b"v=sig"));
        stream.extend(auth(0, &[]));
        let mut p = AuthParse::default();
        let mut done = false;
        for b in &stream {
            done = p.feed(std::slice::from_ref(b)).unwrap();
        }
        assert!(done);
        // A cleartext request after SASL is still refused.
        let mut p = AuthParse::default();
        let mut stream = auth(10, b"SCRAM-SHA-256\0\0");
        stream.extend(auth(3, &[]));
        assert!(p.feed(&stream).is_err());
    }

    #[test]
    fn weak_scram_iterations_are_refused() {
        for body in [
            &b"r=nonce,s=c2FsdA==,i=1"[..],
            b"r=nonce,s=c2FsdA==,i=4095",
            b"r=nonce,s=c2FsdA==",
            b"r=nonce,s=c2FsdA==,i=x",
        ] {
            let mut stream = auth(10, b"SCRAM-SHA-256\0\0");
            stream.extend(auth(11, body));
            assert!(AuthParse::default().feed(&stream).is_err(), "{body:?}");
        }
        let mut p = AuthParse::default();
        let ok = auth(11, b"r=nonce,s=c2FsdA==,i=600000");
        for b in &ok {
            assert_eq!(p.feed(std::slice::from_ref(b)), Ok(false));
        }
        assert!(AuthParse::default().feed(&auth(11, &[b'x'; 4096])).is_err());
    }

    #[test]
    fn negotiate_version_and_errors() {
        let mut stream = vec![b'v', 0, 0, 0, 8, 0, 0, 0, 0];
        stream.extend(auth(0, &[]));
        assert_eq!(AuthParse::default().feed(&stream), Ok(true));
        assert_eq!(AuthParse::default().feed(&[b'E', 0, 0, 0, 5, 0]), Ok(true));
        assert!(AuthParse::default().feed(&[b'R', 0, 0, 0, 4]).is_err());
    }
}
