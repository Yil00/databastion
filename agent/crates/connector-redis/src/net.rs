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

impl Transport {
    /// The local TCP address of the connection (`None` on a Unix socket):
    /// the agent's own `addr:port` as a server without NAT reports it
    /// (ADR-0052 decision 8, own entries).
    pub(crate) fn local_addr(&self) -> Option<std::net::SocketAddr> {
        match self {
            Self::Tcp(s) => s.local_addr().ok(),
            Self::Tls(s) => s.get_ref().0.local_addr().ok(),
            Self::Unix(_) => None,
        }
    }
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
                let (expected, path) = expected_uid(path, *server_uid)?;
                let stream =
                    tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::UnixStream::connect(&path))
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

/// What the trust rule looks at in one file or directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Owned {
    uid: u32,
    mode: u32,
}

/// The trust rule of a socket whose server user is not declared
/// (re-review N2, security review M3), on facts gathered without following
/// a final symlink: the path must be a socket; its owner must not be the
/// agent's own user; its directory must be owned by root or the socket's
/// owner and writable by no one else; every further ancestor must be owned
/// by root or the socket's owner and, when others may write to it, be
/// sticky (so no other user can rename what it holds). Returns the
/// expected uid, or why the owner cannot be trusted.
fn judge(
    socket: Option<Owned>,
    parent: Owned,
    ancestors: &[Owned],
    agent: u32,
) -> Result<u32, &'static str> {
    let socket = socket.ok_or("the path is not a socket (a symlink is never followed)")?;
    if socket.uid == agent {
        return Err("the socket is owned by the agent's own user");
    }
    let trusted_owner = |d: &Owned| d.uid == 0 || d.uid == socket.uid;
    if !trusted_owner(&parent) {
        return Err("the socket's directory is owned by another user");
    }
    if parent.mode & 0o022 != 0 {
        return Err("other users can write to the socket's directory");
    }
    for a in ancestors {
        if !trusted_owner(a) {
            return Err("an ancestor directory is owned by another user");
        }
        if a.mode & 0o022 != 0 && a.mode & 0o1000 == 0 {
            return Err("other users can write to an ancestor directory");
        }
    }
    Ok(socket.uid)
}

/// The uid the server on `path` must run as, and the path to connect to:
/// `server_uid` and `path` when declared; otherwise the socket file's
/// owner under [`judge`]'s rule, and the path with its directory resolved
/// (the directories checked are the ones connected through). Otherwise the
/// declaration is required: refused as `unsupported` (a configuration
/// error).
fn expected_uid(path: &Path, server_uid: Option<u32>) -> Result<(u32, PathBuf), RdError> {
    if let Some(uid) = server_uid {
        return Ok((uid, path.to_path_buf()));
    }
    let refuse = |why: &'static str| {
        tracing::warn!(
            reason = why,
            "Redis / Valkey socket: declare redis.server_uid (ADR-0052 decision 3)"
        );
        RdError::new(FailureCode::Unsupported, Stage::Connect)
    };
    let io_err = |e: io::Error| RdError::io(&e, Stage::Connect);
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(refuse("the socket has no parent directory"));
    };
    let dir = std::fs::canonicalize(if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    })
    .map_err(io_err)?;
    let resolved = dir.join(name);
    let owned = |m: &std::fs::Metadata| Owned {
        uid: m.uid(),
        mode: m.mode(),
    };
    let meta = std::fs::symlink_metadata(&resolved).map_err(io_err)?;
    let socket = {
        use std::os::unix::fs::FileTypeExt;
        meta.file_type().is_socket().then(|| owned(&meta))
    };
    let parent = owned(&std::fs::symlink_metadata(&dir).map_err(io_err)?);
    let mut ancestors = Vec::new();
    for a in dir.ancestors().skip(1) {
        ancestors.push(owned(&std::fs::symlink_metadata(a).map_err(io_err)?));
    }
    let uid = judge(
        socket,
        parent,
        &ancestors,
        rustix::process::geteuid().as_raw(),
    )
    .map_err(refuse)?;
    Ok((uid, resolved))
}

/// The rustls configuration of `verify_full` (decision 3): TLS 1.2 or 1.3,
/// the pinned CA (then the only root) or the system store, and the
/// optional client certificate.
///
/// Zeroization residuals (security review L2): the client key's PEM is read
/// into zeroized memory, but `PrivateKeyDer` and the signing key rustls
/// builds from it keep their own copies for the configuration's lifetime,
/// and rustls copies every record it sends (the `AUTH` password included)
/// into its own send buffers, which are not zeroized when freed. The
/// connector's own request buffers are sized once and zeroized
/// ([`crate::cmd::Request`]).
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
        // The socket file is made by a separate process: agent code never
        // binds a socket (I1, crates/agent/tests/architecture.rs).
        let made = std::process::Command::new("python3")
            .args([
                "-c",
                "import socket, sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])",
            ])
            .arg(&sock)
            .status()
            .expect("python3 is needed to make a test socket");
        assert!(made.success());
        // Owned by the test's own user: never trusted by default.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(expected_uid(&sock, None).is_err());
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(expected_uid(&sock, None).is_err());
        assert_eq!(expected_uid(&sock, Some(999)).unwrap().0, 999);
        // A regular file or a symlink is never a trusted socket.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let file = dir.join("file.sock");
        std::fs::write(&file, b"").unwrap();
        assert!(expected_uid(&file, None).is_err());
        let link = dir.join("link.sock");
        std::os::unix::fs::symlink(&sock, &link).unwrap();
        assert!(expected_uid(&link, None).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Security review M3: the directory's owner and every ancestor count.
    #[test]
    fn socket_trust_rule() {
        let agent = 1000;
        let redis = 999;
        let attacker = 1001;
        let sock = Some(Owned {
            uid: redis,
            mode: 0o140_777,
        });
        let root_dir = |mode| Owned { uid: 0, mode };
        let tmp = root_dir(0o41_777);
        // /run/redis (redis, 0755) under /run (root, 0755): trusted.
        assert_eq!(
            judge(
                sock,
                Owned {
                    uid: redis,
                    mode: 0o40_755
                },
                &[root_dir(0o40_755)],
                agent
            ),
            Ok(redis)
        );
        // /tmp/redis made by an attacker (0755): refused.
        assert!(
            judge(
                sock,
                Owned {
                    uid: attacker,
                    mode: 0o40_755
                },
                &[tmp],
                agent
            )
            .is_err()
        );
        // /tmp/redis made by redis under sticky /tmp: trusted.
        assert_eq!(
            judge(
                sock,
                Owned {
                    uid: redis,
                    mode: 0o40_750
                },
                &[tmp],
                agent
            ),
            Ok(redis)
        );
        // An ancestor owned by another user, or writable without the
        // sticky bit: refused.
        let parent = Owned {
            uid: redis,
            mode: 0o40_755,
        };
        assert!(
            judge(
                sock,
                parent,
                &[Owned {
                    uid: attacker,
                    mode: 0o40_755
                }],
                agent
            )
            .is_err()
        );
        assert!(judge(sock, parent, &[root_dir(0o40_777)], agent).is_err());
        // A group-writable directory, the agent's own socket, not a socket.
        assert!(
            judge(
                sock,
                Owned {
                    uid: redis,
                    mode: 0o40_775
                },
                &[],
                agent
            )
            .is_err()
        );
        assert!(judge(sock, parent, &[], redis).is_err());
        assert!(judge(None, parent, &[], agent).is_err());
    }

    /// Security review M1: a peer whose uid is not the declared server's
    /// never gets a byte, the password least of all. The listener runs in
    /// a separate process (agent code never binds a socket, I1) as the
    /// test's own user, so its uid is the agent's: declaring another uid
    /// must refuse with `authentication_failed`, and the accepted
    /// connection must read end of file at once (0 bytes), through the
    /// whole `Session::open` path that would send `AUTH`.
    #[test]
    fn a_peer_with_another_uid_never_gets_the_password() {
        use std::io::{BufRead, BufReader};
        let dir = tmp();
        let sock = dir.join("redis.sock");
        // Binds, says `ready`, accepts one connection (10 s at most),
        // reads it to end of file and prints the byte count.
        let mut listener = std::process::Command::new("python3")
            .args([
                "-c",
                "import socket, sys\n\
                 s = socket.create_server(sys.argv[1], family=socket.AF_UNIX)\n\
                 s.settimeout(10)\n\
                 print('ready', flush=True)\n\
                 c, _ = s.accept(); c.settimeout(10); n = 0\n\
                 while True:\n    b = c.recv(4096)\n    if not b: break\n    n += len(b)\n\
                 print(n, flush=True)\n",
            ])
            .arg(&sock)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("python3 is needed to make a test socket");
        let mut out = BufReader::new(listener.stdout.take().unwrap());
        let mut line = String::new();
        out.read_line(&mut line).unwrap();
        assert_eq!(line.trim(), "ready");

        let own = rustix::process::geteuid().as_raw();
        let endpoint = Endpoint::Unix {
            path: sock.clone(),
            server_uid: Some(own.wrapping_add(1)),
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt
            .block_on(crate::conn::Session::open(
                &endpoint,
                None,
                "databastion",
                "never-sent-password",
                Duration::from_secs(5),
            ))
            .unwrap_err();
        assert_eq!(err.code, FailureCode::AuthenticationFailed);
        assert_eq!(err.stage, Stage::Connect);

        line.clear();
        out.read_line(&mut line).unwrap();
        assert!(listener.wait().unwrap().success());
        assert_eq!(line.trim(), "0", "bytes the peer received");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
