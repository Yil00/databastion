//! rustls client configuration (rustls only, `ring` provider, no
//! OpenSSL).
//!
//! `verify_full`: TLS 1.2 or 1.3, the server certificate verified against
//! the target's pinned CA file (`mysql.ca_file`, the only trusted root
//! then) or the system store, and its name (DNS name or IP address SAN)
//! checked against the configured host. There is no "encrypt without
//! verifying" mode: MySQL / MariaDB self-signed auto-generated
//! certificates need their CA pinned and a certificate naming the host.

use std::path::Path;
use std::sync::Arc;

use rustls::ClientConfig;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;

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

/// `verify_full` configuration with a pinned CA file or the system roots.
pub(crate) fn verify_full(ca_file: Option<&Path>) -> Result<Arc<ClientConfig>, TlsSetupError> {
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
            // The system store is loaded once per process (every session,
            // including `KILL QUERY` sessions, builds a configuration); a
            // failure is not cached.
            static SYSTEM: std::sync::OnceLock<Arc<ClientConfig>> = std::sync::OnceLock::new();
            if let Some(config) = SYSTEM.get() {
                return Ok(Arc::clone(config));
            }
            let native = rustls_native_certs::load_native_certs();
            let (added, _) = roots.add_parsable_certificates(native.certs);
            if added == 0 {
                return Err(TlsSetupError::NoRoots);
            }
            let config = build(roots)?;
            let _ = SYSTEM.set(Arc::clone(&config));
            return Ok(config);
        }
    }
    build(roots)
}

fn build(roots: rustls::RootCertStore) -> Result<Arc<ClientConfig>, TlsSetupError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| TlsSetupError::Config)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ca_file_errors_carry_no_path() {
        let missing = Path::new("/nonexistent/databastion-ca-SECRET.pem");
        let e = verify_full(Some(missing)).err().unwrap();
        assert_eq!(e, TlsSetupError::CaFile);
        assert!(!e.to_string().contains("SECRET"));
    }
}
