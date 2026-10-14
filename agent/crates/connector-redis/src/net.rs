//! Connections to the declared node only (I5, ADR-0052 decisions 3 and
//! 5): TCP with TLS from the first byte (`verify_full`), or, with
//! `disable`, a Unix socket (peer credentials checked before `AUTH`,
//! security review L1 and re-review N2) or a loopback IP literal. No
//! listening socket is ever created (I1).

use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use databastion_core::FailureCode;
use rustls::ClientConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use zeroize::Zeroizing;

use crate::error::{RdError, Stage};

/// TCP connect and TLS handshake timeout (decision 1).
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Largest client key file read.
const MAX_KEY_FILE: u64 = 64 * 1024;

/// Where a node listens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Endpoint {
    Tcp {
        host: String,
        port: u16,
    },
    Unix {
        path: PathBuf,
        server_uid: Option<u32>,
    },
}

/// A client connection.
pub(crate) enum Transport {
    Tcp(tokio::net::TcpStream),
    Unix(tokio::net::UnixStream),
    Tls(Box<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>),
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "connect timed out")
}

impl Endpoint {
    /// Opens a connection: TLS from the first byte when `tls` is given; on
    /// a Unix socket, the peer's uid is checked first.
    pub(crate) async fn open(&self, tls: Option<Arc<ClientConfig>>) -> Result<Transport, RdError> {
        match self {
            Self::Tcp { host, port } => {
                let stream = tokio::time::timeout(
                    CONNECT_TIMEOUT,
                    tokio::net::TcpStream::connect((host.as_str(), *port)),
                )
                .await
                .map_err(|_| RdError::io(&timed_out(), Stage::Connect))?
                .map_err(|e| RdError::io(&e, Stage::Connect))?;
                stream
                    .set_nodelay(true)
                    .map_err(|e| RdError::io(&e, Stage::Connect))?;
                let Some(config) = tls else {
                    return Ok(Transport::Tcp(stream));
                };
                let name = ServerName::try_from(host.clone())
                    .map_err(|_| RdError::new(FailureCode::Internal, Stage::Tls))?;
                let tls = tokio::time::timeout(
                    CONNECT_TIMEOUT,
                    tokio_rustls::TlsConnector::from(config).connect(name, stream),
                )
                .await
                .map_err(|_| RdError::new(FailureCode::Timeout, Stage::Tls))?
                .map_err(|_| RdError::new(FailureCode::TargetUnreachable, Stage::Tls))?;
                Ok(Transport::Tls(Box::new(tls)))
            }
            Self::Unix { path, server_uid } => {
                if tls.is_some() {
                    return Err(RdError::new(FailureCode::Internal, Stage::Tls));
                }
                let expected = expected_uid(path, *server_uid)?;
                let stream =
                    tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::UnixStream::connect(path))
                        .await
                        .map_err(|_| RdError::io(&timed_out(), Stage::Connect))?
                        .map_err(|e| RdError::io(&e, Stage::Connect))?;
                let peer = stream
                    .peer_cred()
                    .map_err(|e| RdError::io(&e, Stage::Connect))?;
                if peer.uid() != expected {
                    tracing::warn!(
                        "Redis / Valkey socket: the peer is not the expected server user; \
                         the password is not sent"
                    );
                    return Err(RdError::new(
                        FailureCode::AuthenticationFailed,
                        Stage::Connect,
                    ));
                }
                Ok(Transport::Unix(stream))
            }
        }
    }
}

/// The uid the server on `path` must run as (re-review N2): `server_uid`
/// when declared; otherwise the socket file's owner, trusted only when no
/// other user can write to the socket's directory and the owner is not
/// the agent's own uid. Otherwise the declaration is required: refused as
/// `unsupported` (a configuration error).
fn expected_uid(path: &Path, server_uid: Option<u32>) -> Result<u32, RdError> {
    if let Some(uid) = server_uid {
        return Ok(uid);
    }
    let refuse = |why: &'static str| {
        tracing::warn!(
            reason = why,
            "Redis / Valkey socket: declare redis.server_uid (ADR-0052 decision 3)"
        );
        RdError::new(FailureCode::Unsupported, Stage::Connect)
    };
    let meta = std::fs::symlink_metadata(path).map_err(|e| RdError::io(&e, Stage::Connect))?;
    let dir = path
        .parent()
        .ok_or_else(|| refuse("the socket has no parent directory"))?;
    let dir_meta = std::fs::metadata(dir).map_err(|e| RdError::io(&e, Stage::Connect))?;
    if dir_meta.mode() & 0o022 != 0 {
        return Err(refuse("other users can write to the socket's directory"));
    }
    if meta.uid() == rustix::process::geteuid().as_raw() {
        return Err(refuse("the socket is owned by the agent's own user"));
    }
    Ok(meta.uid())
}

/// The rustls configuration of `verify_full` (decision 3): TLS 1.2 or 1.3,
/// the pinned CA (then the only root) or the system store, and the
/// optional client certificate.
pub(crate) fn tls_config(
    ca_file: Option<&Path>,
    client: Option<(&Path, &Path)>,
) -> Result<Arc<ClientConfig>, RdError> {
    let fail = || RdError::new(FailureCode::Internal, Stage::Tls);
    let mut roots = rustls::RootCertStore::empty();
    match ca_file {
        Some(path) => {
            let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(path)
                .map_err(|_| fail())?
                .collect::<Result<_, _>>()
                .map_err(|_| fail())?;
            let (added, _) = roots.add_parsable_certificates(certs);
            if added == 0 {
                return Err(fail());
            }
        }
        None => {
            let native = rustls_native_certs::load_native_certs();
            let (added, _) = roots.add_parsable_certificates(native.certs);
            if added == 0 {
                return Err(fail());
            }
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| fail())?
        .with_root_certificates(roots);
    let config = match client {
        None => builder.with_no_client_auth(),
        Some((cert, key)) => {
            let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert)
                .map_err(|_| fail())?
                .collect::<Result<_, _>>()
                .map_err(|_| fail())?;
            let pem = read_client_key(key).map_err(|_| fail())?;
            let key = PrivateKeyDer::from_pem_slice(&pem).map_err(|_| fail())?;
            builder
                .with_client_auth_cert(certs, key)
                .map_err(|_| fail())?
        }
    };
    Ok(Arc::new(config))
}

/// Reads the client key (security review L8, ADR-0043): opened with
/// `O_NOFOLLOW`, then the **opened** file is checked with `fstat`: a
/// regular file owned by the agent's user, mode `0600`, or `0640` with the
/// agent's group. Read into zeroized memory.
pub(crate) fn read_client_key(path: &Path) -> io::Result<Zeroizing<Vec<u8>>> {
    use rustix::fs::{Mode, OFlags};
    use std::io::Read;
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NOCTTY | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    let file = std::fs::File::from(fd);
    let meta = file.metadata()?;
    let denied = |m: &'static str| io::Error::new(io::ErrorKind::PermissionDenied, m);
    if !meta.file_type().is_file() {
        return Err(denied("client key is not a regular file"));
    }
    if meta.uid() != rustix::process::geteuid().as_raw() {
        return Err(denied("client key is not owned by the agent user"));
    }
    let mode = meta.mode() & 0o777;
    let group_ok = mode == 0o640 && meta.gid() == rustix::process::getegid().as_raw();
    if mode != 0o600 && !group_ok {
        return Err(denied(
            "client key must be 0600, or 0640 with the agent's group",
        ));
    }
    let mut out = Zeroizing::new(Vec::new());
    file.take(MAX_KEY_FILE).read_to_end(&mut out)?;
    Ok(out)
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
            Self::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
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
            Self::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_flush(cx),
            Self::Unix(s) => Pin::new(s).poll_flush(cx),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            Self::Unix(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmp() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "databastion-redis-net-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn client_key_checks_the_opened_file() {
        let dir = tmp();
        let key = dir.join("client.key");
        std::fs::write(&key, b"-----BEGIN PRIVATE KEY-----\n").unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_client_key(&key).is_ok());
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_client_key(&key).is_err());
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.join("link.key");
        std::os::unix::fs::symlink(&key, &link).unwrap();
        assert!(
            read_client_key(&link).is_err(),
            "a symlink is never followed"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn socket_owner_is_trusted_only_in_a_private_directory() {
        let dir = tmp();
        let sock = dir.join("redis.sock");
        std::fs::write(&sock, b"").unwrap();
        // Owned by the test's own user: never trusted by default.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(expected_uid(&sock, None).is_err());
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(expected_uid(&sock, None).is_err());
        assert_eq!(expected_uid(&sock, Some(999)).unwrap(), 999);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
