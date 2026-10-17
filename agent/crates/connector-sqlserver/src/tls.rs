//! TLS (ADR-0051 decision 2, refinement item 3): rustls with the `ring`
//! provider, the pinned CA as the only root (or the system store), the
//! declared host checked. `strict` (TDS 8.0) runs TLS from the first byte
//! with ALPN `tds/8.0`; `mandatory` runs the handshake inside `PRELOGIN`
//! packets ([`PreloginWrap`]), then the whole session is encrypted.
//!
//! SQL Server's fallback self-signed certificate (`CN =
//! SSL_Self_Signed_Fallback`, no SAN, new at each start) never verifies:
//! the verifier only marks that it saw it, for the local detail.

use std::io;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::tds;

/// The subject marker of SQL Server's fallback certificate.
const FALLBACK_CN: &[u8] = b"SSL_Self_Signed_Fallback";
/// ALPN of TDS 8.0.
pub(crate) const ALPN_TDS8: &[u8] = b"tds/8.0";

/// Whether a DER certificate carries the fallback certificate's subject.
pub(crate) fn is_fallback_certificate(der: &[u8]) -> bool {
    der.windows(FALLBACK_CN.len()).any(|w| w == FALLBACK_CN)
}

/// The WebPKI verifier, unchanged, plus a flag set when the refused
/// certificate is SQL Server's fallback one.
#[derive(Debug)]
struct Verifier {
    inner: Arc<WebPkiServerVerifier>,
    fallback_seen: Arc<AtomicBool>,
}

impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let r = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        );
        if r.is_err() && is_fallback_certificate(end_entity.as_ref()) {
            self.fallback_seen.store(true, Ordering::Relaxed);
        }
        r
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// The TLS configurations of a target: `mandatory` (no ALPN) and `strict`
/// (ALPN `tds/8.0`), sharing the fallback flag.
#[derive(Clone)]
pub(crate) struct TlsConfigs {
    pub(crate) mandatory: Arc<ClientConfig>,
    pub(crate) strict: Arc<ClientConfig>,
    pub(crate) fallback_seen: Arc<AtomicBool>,
}

/// Builds the configurations: TLS 1.2 or 1.3, the pinned CA file (then the
/// only trusted root) or the system store. `None`: no usable root.
pub(crate) fn configs(ca_file: Option<&Path>) -> Option<TlsConfigs> {
    let mut roots = rustls::RootCertStore::empty();
    let certs: Vec<CertificateDer<'static>> = match ca_file {
        Some(path) => CertificateDer::pem_file_iter(path)
            .ok()?
            .collect::<Result<_, _>>()
            .ok()?,
        None => rustls_native_certs::load_native_certs().certs,
    };
    let (added, _) = roots.add_parsable_certificates(certs);
    if added == 0 {
        return None;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
        .build()
        .ok()?;
    let fallback_seen = Arc::new(AtomicBool::new(false));
    let verifier = Arc::new(Verifier {
        inner,
        fallback_seen: Arc::clone(&fallback_seen),
    });
    let mandatory = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .ok()?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let mut strict = mandatory.clone();
    strict.alpn_protocols = vec![ALPN_TDS8.to_vec()];
    Some(TlsConfigs {
        mandatory: Arc::new(mandatory),
        strict: Arc::new(strict),
        fallback_seen,
    })
}

/// Most handshake bytes buffered before a flush.
const MAX_HANDSHAKE_WRITE: usize = 64 * 1024;

/// The TDS 7.x TLS handshake adapter: while `handshake` is on, TLS records
/// written are framed as `PRELOGIN` packets on flush, and the server's
/// `PRELOGIN` packets are unwrapped on read (header checked first). Once
/// the handshake completes, [`PreloginWrap::pass_through`] makes it a plain
/// pipe: the TLS records then travel bare.
pub(crate) struct PreloginWrap<S> {
    inner: S,
    handshake: bool,
    wbuf: Vec<u8>,
    out: Vec<u8>,
    out_pos: usize,
    header: [u8; tds::HEADER],
    header_len: usize,
    left: usize,
}

impl<S> PreloginWrap<S> {
    pub(crate) fn new(inner: S) -> Self {
        Self {
            inner,
            handshake: true,
            wbuf: Vec::new(),
            out: Vec::new(),
            out_pos: 0,
            header: [0; tds::HEADER],
            header_len: 0,
            left: 0,
        }
    }

    /// Ends the `PRELOGIN` framing (after the handshake).
    pub(crate) fn pass_through(&mut self) {
        self.handshake = false;
    }
}

/// Validates a handshake packet header; the payload length.
pub(crate) fn handshake_header(h: &[u8; tds::HEADER]) -> io::Result<usize> {
    let len = usize::from(u16::from_be_bytes([h[2], h[3]]));
    if !matches!(h[0], tds::ptype::PRELOGIN | tds::ptype::TABULAR_RESULT)
        || len <= tds::HEADER
        || len > tds::MAX_PACKET
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected packet during the TLS handshake",
        ));
    }
    Ok(len - tds::HEADER)
}

impl<S: AsyncRead + AsyncWrite + Unpin> PreloginWrap<S> {
    fn poll_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.out.is_empty() && !self.wbuf.is_empty() {
            self.out = tds::frame(tds::ptype::PRELOGIN, &self.wbuf, tds::DEFAULT_PACKET);
            self.wbuf.clear();
            self.out_pos = 0;
        }
        while self.out_pos < self.out.len() {
            let rest = self.out.get(self.out_pos..).unwrap_or_default();
            let n = std::task::ready!(Pin::new(&mut self.inner).poll_write(cx, rest))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.out_pos += n;
        }
        self.out.clear();
        self.out_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for PreloginWrap<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.handshake {
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }
        std::task::ready!(this.poll_out(cx))?;
        while this.left == 0 {
            if this.header_len < tds::HEADER {
                let mut hb = ReadBuf::new(&mut this.header[this.header_len..]);
                std::task::ready!(Pin::new(&mut this.inner).poll_read(cx, &mut hb))?;
                let n = hb.filled().len();
                if n == 0 {
                    return Poll::Ready(Ok(()));
                }
                this.header_len += n;
                continue;
            }
            this.left = handshake_header(&this.header)?;
            this.header_len = 0;
        }
        let mut scratch = [0u8; 4096];
        let want = this.left.min(buf.remaining()).min(scratch.len());
        let mut rb = ReadBuf::new(&mut scratch[..want]);
        std::task::ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
        let n = rb.filled().len();
        buf.put_slice(rb.filled());
        this.left -= n;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for PreloginWrap<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if !this.handshake {
            return Pin::new(&mut this.inner).poll_write(cx, data);
        }
        if this.wbuf.len() + data.len() > MAX_HANDSHAKE_WRITE {
            std::task::ready!(this.poll_out(cx))?;
        }
        let n = data.len().min(MAX_HANDSHAKE_WRITE);
        this.wbuf
            .extend_from_slice(data.get(..n).unwrap_or_default());
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.handshake {
            std::task::ready!(this.poll_out(cx))?;
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn fallback_marker() {
        let mut der = vec![0x30, 0x82];
        der.extend_from_slice(b"..CN=SSL_Self_Signed_Fallback..");
        assert!(is_fallback_certificate(&der));
        assert!(!is_fallback_certificate(b"CN=sqlserver"));
    }

    #[tokio::test]
    async fn handshake_bytes_are_framed_and_unframed() {
        let (a, mut b) = tokio::io::duplex(1 << 16);
        let mut w = PreloginWrap::new(a);
        w.write_all(b"client-hello").await.unwrap();
        w.flush().await.unwrap();
        let mut got = [0u8; 20];
        b.read_exact(&mut got).await.unwrap();
        assert_eq!(&got[..2], &[tds::ptype::PRELOGIN, tds::STATUS_EOM]);
        assert_eq!(&got[8..], b"client-hello");
        // Server reply in two packets.
        b.write_all(&tds::frame(tds::ptype::PRELOGIN, b"server-hello", 512))
            .await
            .unwrap();
        let mut back = [0u8; 12];
        w.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"server-hello");
        w.pass_through();
        w.write_all(b"raw").await.unwrap();
        w.flush().await.unwrap();
        let mut raw = [0u8; 3];
        b.read_exact(&mut raw).await.unwrap();
        assert_eq!(&raw, b"raw");
    }

    #[test]
    fn handshake_headers_are_checked() {
        assert!(handshake_header(&[0x12, 1, 0, 20, 0, 0, 1, 0]).is_ok());
        assert!(handshake_header(&[0x12, 1, 0, 8, 0, 0, 1, 0]).is_err());
        assert!(handshake_header(&[0x17, 3, 3, 0, 20, 0, 0, 0]).is_err());
    }
}
