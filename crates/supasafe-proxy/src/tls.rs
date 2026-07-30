//! TLS for both sides of the proxy.
//!
//! * **Server side**: SupaSafe can present a certificate to connecting agents,
//!   so the hop from the agent to the proxy is encrypted like any other
//!   PostgreSQL connection.
//! * **Client side**: SupaSafe verifies the database's certificate against the
//!   public roots, a certificate authority you supply, or a pinned fingerprint.
//!
//! Pinning is checked once the handshake completes and before a single byte of
//! the startup packet is sent, so a server presenting an unexpected
//! certificate never sees a username, let alone a password.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{client::TlsStream as ClientTlsStream, TlsAcceptor, TlsConnector};

/// Install the cryptography provider exactly once per process.
fn install_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // Failing here means another provider was already installed, which is
        // fine.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Anything that can go wrong setting up or checking TLS.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("could not read {path}: {source}")]
    Read { path: PathBuf, source: io::Error },
    #[error("{path} contains no certificates")]
    NoCertificates { path: PathBuf },
    #[error("{path} contains no private key")]
    NoPrivateKey { path: PathBuf },
    #[error("TLS configuration is invalid: {0}")]
    Config(String),
    #[error("the TLS handshake failed: {0}")]
    Handshake(String),
    #[error(
        "the database presented a certificate with fingerprint {actual}, but SupaSafe is pinned \
         to {expected}. The connection was dropped before anything was sent."
    )]
    PinMismatch { expected: String, actual: String },
    #[error("the database presented no certificate")]
    NoPeerCertificate,
    #[error("{0:?} is not a valid host name for certificate verification")]
    BadHostName(String),
}

/// The certificate SupaSafe presents to agents.
#[derive(Clone)]
pub struct TlsServerConfig {
    acceptor: TlsAcceptor,
}

impl std::fmt::Debug for TlsServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TlsServerConfig")
    }
}

impl TlsServerConfig {
    /// Load a certificate chain and its private key from PEM files.
    pub fn from_pem(cert_path: &Path, key_path: &Path) -> Result<TlsServerConfig, TlsError> {
        install_provider();

        let certs = load_certs(cert_path)?;
        if certs.is_empty() {
            return Err(TlsError::NoCertificates {
                path: cert_path.to_path_buf(),
            });
        }
        let key = load_key(key_path)?;

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| TlsError::Config(e.to_string()))?;

        Ok(TlsServerConfig {
            acceptor: TlsAcceptor::from(Arc::new(config)),
        })
    }

    pub fn acceptor(&self) -> TlsAcceptor {
        self.acceptor.clone()
    }
}

/// How SupaSafe verifies the database it is forwarding to.
#[derive(Clone)]
pub struct TlsClientConfig {
    connector: TlsConnector,
    /// A SHA-256 fingerprint of the expected leaf certificate, lower-case hex.
    pin: Option<String>,
}

impl std::fmt::Debug for TlsClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsClientConfig")
            .field("pinned", &self.pin.is_some())
            .finish()
    }
}

impl TlsClientConfig {
    /// Verify against the public certificate authorities.
    pub fn with_webpki_roots() -> Result<TlsClientConfig, TlsError> {
        install_provider();
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self::from_roots(roots)
    }

    /// Verify against a certificate authority you supply, and nothing else.
    pub fn with_custom_ca(ca_path: &Path) -> Result<TlsClientConfig, TlsError> {
        install_provider();
        let mut roots = RootCertStore::empty();
        for cert in load_certs(ca_path)? {
            roots
                .add(cert)
                .map_err(|e| TlsError::Config(format!("{}: {e}", ca_path.display())))?;
        }
        if roots.is_empty() {
            return Err(TlsError::NoCertificates {
                path: ca_path.to_path_buf(),
            });
        }
        Self::from_roots(roots)
    }

    fn from_roots(roots: RootCertStore) -> Result<TlsClientConfig, TlsError> {
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(TlsClientConfig {
            connector: TlsConnector::from(Arc::new(config)),
            pin: None,
        })
    }

    /// Refuse any certificate whose SHA-256 fingerprint is not this one.
    ///
    /// Takes the usual `AA:BB:CC:...` or bare hex form, case-insensitively.
    pub fn pinned_to(mut self, fingerprint: &str) -> TlsClientConfig {
        self.pin = Some(normalize_fingerprint(fingerprint));
        self
    }

    pub fn is_pinned(&self) -> bool {
        self.pin.is_some()
    }

    /// Complete a TLS handshake with the database and check the pin.
    pub async fn connect<S>(&self, host: &str, stream: S) -> Result<ClientTlsStream<S>, TlsError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|_| TlsError::BadHostName(host.to_string()))?;

        let tls = self
            .connector
            .connect(server_name, stream)
            .await
            .map_err(|e| TlsError::Handshake(e.to_string()))?;

        if let Some(expected) = &self.pin {
            let (_, connection) = tls.get_ref();
            let leaf = connection
                .peer_certificates()
                .and_then(|certs| certs.first())
                .ok_or(TlsError::NoPeerCertificate)?;
            let actual = fingerprint_of(leaf);
            if &actual != expected {
                // Dropping `tls` here closes the connection. Nothing has been
                // written to it yet, so the mismatched server has learned
                // nothing beyond the fact that somebody connected.
                return Err(TlsError::PinMismatch {
                    expected: expected.clone(),
                    actual,
                });
            }
        }

        Ok(tls)
    }
}

/// The SHA-256 fingerprint of a certificate, as lower-case hex.
pub fn fingerprint_of(cert: &CertificateDer<'_>) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(cert.as_ref());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Accept `AA:BB:...`, `aabb...` and whitespace-separated forms alike.
fn normalize_fingerprint(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_ascii_lowercase()
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let data = std::fs::read(path).map_err(|source| TlsError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let mut reader = std::io::BufReader::new(&data[..]);
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| TlsError::Read {
            path: path.to_path_buf(),
            source,
        })
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>, TlsError> {
    let data = std::fs::read(path).map_err(|source| TlsError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let mut reader = std::io::BufReader::new(&data[..]);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|source| TlsError::Read {
            path: path.to_path_buf(),
            source,
        })?
        .ok_or_else(|| TlsError::NoPrivateKey {
            path: path.to_path_buf(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_normalise_to_the_same_thing() {
        let colons = "AA:BB:CC:dd:ee:ff";
        let bare = "aabbccddeeff";
        let spaced = "AA BB CC DD EE FF";
        assert_eq!(normalize_fingerprint(colons), bare);
        assert_eq!(normalize_fingerprint(spaced), bare);
        assert_eq!(normalize_fingerprint(bare), bare);
    }

    #[test]
    fn a_fingerprint_is_a_sha256_of_the_der() {
        let cert = CertificateDer::from(vec![1, 2, 3, 4]);
        let fp = fingerprint_of(&cert);
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn public_roots_load() {
        let config = TlsClientConfig::with_webpki_roots().expect("roots load");
        assert!(!config.is_pinned());
        assert!(config.pinned_to("aa:bb").is_pinned());
    }

    #[test]
    fn missing_files_produce_a_clear_error() {
        let err = TlsServerConfig::from_pem(
            Path::new("/nonexistent/cert.pem"),
            Path::new("/nonexistent/key.pem"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("could not read"));
    }
}
