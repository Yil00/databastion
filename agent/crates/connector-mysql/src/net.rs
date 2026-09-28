//! Connections opened by the connector: TCP or Unix socket to the declared
//! target only (I5), upgraded to TLS in the MySQL protocol's `SSLRequest`
//! step. No listening socket is ever created (I1).

use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::auth::Channel;

/// TCP connect timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Where a target listens.
#[derive(Clone, Debug)]
pub(crate) enum Endpoint {
    Tcp { host: String, port: u16 },
    Unix { path: PathBuf },
}

impl Endpoint {
    /// The channel of a connection without TLS to this endpoint.
    pub(crate) fn plain_channel(&self) -> Channel {
        match self {
            Self::Unix { .. } => Channel::Unix,
            Self::Tcp { host, .. } => {
                if host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
                {
                    Channel::LoopbackPlain
                } else {
                    Channel::NetworkPlain
                }
            }
        }
    }

    /// Opens a connection to the endpoint.
    pub(crate) async fn open(&self) -> io::Result<Transport> {
        match self {
            Self::Tcp { host, port } => {
                let stream = tokio::time::timeout(
                    CONNECT_TIMEOUT,
                    tokio::net::TcpStream::connect((host.as_str(), *port)),
                )
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timed out"))??;
                stream.set_nodelay(true)?;
                Ok(Transport::Tcp(stream))
            }
            Self::Unix { path } => Ok(Transport::Unix(
                tokio::net::UnixStream::connect(path).await?,
            )),
        }
    }
}

/// A client connection.
pub(crate) enum Transport {
    Tcp(tokio::net::TcpStream),
    Unix(tokio::net::UnixStream),
    Tls(Box<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>),
    /// Placeholder while the TCP stream is being upgraded.
    Closed,
}

impl Transport {
    /// Upgrades a TCP connection to TLS (`verify_full`, server name =
    /// configured host). A Unix socket or an already upgraded stream is an
    /// error.
    pub(crate) async fn upgrade(self, config: Arc<ClientConfig>, host: &str) -> io::Result<Self> {
        let Self::Tcp(tcp) = self else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TLS on a non-TCP stream",
            ));
        };
        let name = ServerName::try_from(host.to_owned())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid TLS server name"))?;
        let tls = tokio_rustls::TlsConnector::from(config)
            .connect(name, tcp)
            .await?;
        Ok(Self::Tls(Box::new(tls)))
    }
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "transport closed")
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
            Self::Closed => Poll::Ready(Err(closed())),
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
            Self::Closed => Poll::Ready(Err(closed())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_flush(cx),
            Self::Unix(s) => Pin::new(s).poll_flush(cx),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
            Self::Closed => Poll::Ready(Err(closed())),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            Self::Unix(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
            Self::Closed => Poll::Ready(Ok(())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_channels() {
        let tcp = |h: &str| Endpoint::Tcp {
            host: h.to_owned(),
            port: 3306,
        };
        assert_eq!(tcp("127.0.0.1").plain_channel(), Channel::LoopbackPlain);
        assert_eq!(tcp("::1").plain_channel(), Channel::LoopbackPlain);
        // A name is never treated as loopback.
        assert_eq!(tcp("localhost").plain_channel(), Channel::NetworkPlain);
        assert_eq!(tcp("10.0.0.5").plain_channel(), Channel::NetworkPlain);
        let unix = Endpoint::Unix {
            path: PathBuf::from("/run/mysqld/mysqld.sock"),
        };
        assert_eq!(unix.plain_channel(), Channel::Unix);
    }
}
