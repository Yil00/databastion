//! Connections opened by the connector: TCP or Unix socket to the declared
//! target only (I5), with TLS from the first byte when configured (MongoDB
//! has no in-protocol upgrade). No listening socket is ever created (I1).

use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// TCP connect and TLS handshake timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Where a target listens.
#[derive(Clone, Debug)]
pub(crate) enum Endpoint {
    Tcp { host: String, port: u16 },
    Unix { path: PathBuf },
}

impl Endpoint {
    /// Opens a connection to the endpoint, with TLS when `tls` is given
    /// (`verify_full`: the server name is the configured host).
    pub(crate) async fn open(&self, tls: Option<Arc<ClientConfig>>) -> io::Result<Transport> {
        match self {
            Self::Tcp { host, port } => {
                let stream = tokio::time::timeout(
                    CONNECT_TIMEOUT,
                    tokio::net::TcpStream::connect((host.as_str(), *port)),
                )
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timed out"))??;
                stream.set_nodelay(true)?;
                let Some(config) = tls else {
                    return Ok(Transport::Tcp(stream));
                };
                let name = ServerName::try_from(host.clone()).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "invalid TLS server name")
                })?;
                let tls = tokio::time::timeout(
                    CONNECT_TIMEOUT,
                    tokio_rustls::TlsConnector::from(config).connect(name, stream),
                )
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out")
                })??;
                Ok(Transport::Tls(Box::new(tls)))
            }
            Self::Unix { path } => {
                if tls.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "TLS on a Unix socket",
                    ));
                }
                let stream =
                    tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::UnixStream::connect(path))
                        .await
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::TimedOut, "connect timed out")
                        })??;
                Ok(Transport::Unix(stream))
            }
        }
    }
}

/// A client connection.
pub(crate) enum Transport {
    Tcp(tokio::net::TcpStream),
    Unix(tokio::net::UnixStream),
    Tls(Box<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>),
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
