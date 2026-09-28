//! rustls adapter for tokio-postgres (rustls only, no OpenSSL, no `unsafe`).
//!
//! `verify_full`: TLS 1.2 or 1.3, the server certificate verified against
//! the target's pinned CA file (`postgres.ca_file`, the only trusted root
//! then) or the system store, and its name checked against the configured
//! host. There is no "encrypt without verifying" mode. `disable`: plain
//! connection (the handshake is never attempted).
//!
//! No `tls-server-end-point` channel binding is offered: SCRAM runs without
//! `-PLUS`; server authentication comes from the certificate check.

use std::future::Future;
use std::io;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use rustls::ClientConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_postgres::tls::{ChannelBinding, MakeTlsConnect, TlsConnect, TlsStream};

/// Why the TLS configuration could not be built. No path or content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum TlsSetupError {
    #[error("cannot read the CA file, or it holds no certificate")]
    CaFile,
    #[error("no trusted root certificate in the system store")]
    NoRoots,
    #[error("cannot build the TLS configuration")]
    Config,
}

/// TLS connector handed to tokio-postgres (connections and cancel
/// requests).
#[derive(Clone)]
pub(crate) struct RustlsConnector {
    config: Option<Arc<ClientConfig>>,
}

impl RustlsConnector {
    /// No TLS (`tls: disable`).
    pub(crate) fn disabled() -> Self {
        Self { config: None }
    }

    /// `verify_full` with a pinned CA file or the system roots.
    pub(crate) fn verify_full(ca_file: Option<&Path>) -> Result<Self, TlsSetupError> {
        let mut roots = rustls::RootCertStore::empty();
        match ca_file {
            Some(path) => {
                let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(path)
                    .map_err(|_| TlsSetupError::CaFile)?
                    .collect::<Result<_, _>>()
                    .map_err(|_| TlsSetupError::CaFile)?;
                let (added, _) = roots.add_parsable_certificates(certs);
                if added == 0 {
                    return Err(TlsSetupError::CaFile);
                }
            }
            None => {
                let native = rustls_native_certs::load_native_certs();
                let (added, _) = roots.add_parsable_certificates(native.certs);
                if added == 0 {
                    return Err(TlsSetupError::NoRoots);
                }
            }
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| TlsSetupError::Config)?
            .with_root_certificates(roots)
            .with_no_client_auth();
        // PostgreSQL 17 checks the ALPN protocol when a client sends one.
        config.alpn_protocols = vec![b"postgresql".to_vec()];
        Ok(Self {
            config: Some(Arc::new(config)),
        })
    }
}

impl RustlsConnector {
    /// The handshake for `domain` (connections opened by the connector
    /// itself: `connect_raw`, `cancel_query_raw`).
    pub(crate) fn connector_for(&self, domain: &str) -> RustlsConnect {
        RustlsConnect {
            config: self.config.clone(),
            server_name: ServerName::try_from(domain.to_owned()).ok(),
        }
    }
}

impl<S> MakeTlsConnect<S> for RustlsConnector
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = RustlsStream<S>;
    type TlsConnect = RustlsConnect;
    type Error = io::Error;

    fn make_tls_connect(&mut self, domain: &str) -> io::Result<RustlsConnect> {
        // Resolved lazily: with `tls: disable` (or a Unix socket) the
        // handshake is never attempted and no server name is needed.
        Ok(self.connector_for(domain))
    }
}

/// One TLS handshake.
pub(crate) struct RustlsConnect {
    config: Option<Arc<ClientConfig>>,
    server_name: Option<ServerName<'static>>,
}

impl<S> TlsConnect<S> for RustlsConnect
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = RustlsStream<S>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<RustlsStream<S>>> + Send>>;

    fn connect(self, stream: S) -> Self::Future {
        Box::pin(async move {
            let config = self
                .config
                .ok_or_else(|| io::Error::other("TLS is disabled for this target"))?;
            let name = self
                .server_name
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no TLS server name"))?;
            let tls = tokio_rustls::TlsConnector::from(config)
                .connect(name, stream)
                .await?;
            Ok(RustlsStream(tls))
        })
    }
}

/// A TLS stream to the server.
pub(crate) struct RustlsStream<S>(tokio_rustls::client::TlsStream<S>);

impl<S> AsyncRead for RustlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for RustlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl<S> TlsStream for RustlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn channel_binding(&self) -> ChannelBinding {
        ChannelBinding::none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ca_file_errors_carry_no_path() {
        let missing = Path::new("/nonexistent/databastion-ca-SECRET.pem");
        let e = RustlsConnector::verify_full(Some(missing)).err().unwrap();
        assert_eq!(e, TlsSetupError::CaFile);
        assert!(!e.to_string().contains("SECRET"));
    }

    #[tokio::test]
    async fn disabled_connector_never_handshakes() {
        let mut c = RustlsConnector::disabled();
        let connect =
            <RustlsConnector as MakeTlsConnect<tokio::io::DuplexStream>>::make_tls_connect(
                &mut c,
                "db.example",
            )
            .unwrap();
        let (a, _b) = tokio::io::duplex(64);
        assert!(connect.connect(a).await.is_err());
    }
}
