use std::fmt;

use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use ureq::tls::{Certificate, ClientCert, PrivateKey};
use zeroize::Zeroizing;

use crate::TransportError;

/// A freshly generated ECDSA P-256 host key and a CSR signed by it.
///
/// The CSR carries no identifying subject: the platform assigns the agent ID
/// when it issues the certificate.
pub struct HostKey {
    key_pem: Zeroizing<String>,
    csr_pem: String,
}

impl HostKey {
    /// Generates a new host key from the operating system's CSPRNG.
    pub fn generate() -> Result<Self, TransportError> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|_| TransportError::KeyGeneration)?;
        let csr = CertificateParams::default()
            .serialize_request(&key)
            .and_then(|csr| csr.pem())
            .map_err(|_| TransportError::KeyGeneration)?;
        Ok(Self {
            key_pem: Zeroizing::new(key.serialize_pem()),
            csr_pem: csr,
        })
    }

    /// The PEM PKCS#10 request to send in an enrollment or renewal.
    #[must_use]
    pub fn csr_pem(&self) -> &str {
        &self.csr_pem
    }

    /// Exposes the PKCS#8 PEM private key for the explicit purpose of storing
    /// it in the agent-owned state directory.
    #[must_use]
    pub fn expose_key_pem(&self) -> &str {
        &self.key_pem
    }
}

impl fmt::Debug for HostKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HostKey([REDACTED])")
    }
}

/// A platform-issued certificate chain and its private key, used for mTLS.
#[derive(Clone)]
pub struct ClientIdentity {
    cert: ClientCert,
}

impl ClientIdentity {
    /// Builds an identity from a PEM chain (leaf first) and a PEM private key.
    pub fn from_pem(chain_pem: &[String], key_pem: &str) -> Result<Self, TransportError> {
        let chain = chain_pem
            .iter()
            .map(|pem| Certificate::from_pem(pem.as_bytes()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| TransportError::InvalidIdentity)?;
        if chain.is_empty() {
            return Err(TransportError::InvalidIdentity);
        }
        let key = PrivateKey::from_pem(key_pem.as_bytes())
            .map_err(|_| TransportError::InvalidIdentity)?;
        Ok(Self {
            cert: ClientCert::new_with_certs(&chain, key),
        })
    }

    pub(crate) fn client_cert(&self) -> ClientCert {
        self.cert.clone()
    }
}

impl fmt::Debug for ClientIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ClientIdentity([REDACTED])")
    }
}
