//! Self-signed TLS identity, persisted under `~/.config/uqs/localsend/`.
//!
//! LocalSend identifies a device by the SHA-256 of its certificate (DER), upper-case hex.
//! That hash is the `fingerprint` in every discovery message, so it must stay stable
//! across restarts: generate once, then reload.

use std::path::{Path, PathBuf};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum CertError {
    #[error("I/O error at {path}: {source}")]
    Io { path: PathBuf, source: std::io::Error },
    #[error("certificate generation failed: {0}")]
    Generate(#[from] rcgen::Error),
    #[error("stored certificate is unreadable: {0}")]
    Parse(String),
}

/// Certificate + private key, both DER, plus the LocalSend fingerprint of the certificate.
#[derive(Debug)]
pub struct Identity {
    pub cert_der: CertificateDer<'static>,
    pub key_der: PrivateKeyDer<'static>,
    pub fingerprint: String,
}

impl Clone for Identity {
    fn clone(&self) -> Self {
        Self {
            cert_der: self.cert_der.clone(),
            key_der: self.key_der.clone_key(),
            fingerprint: self.fingerprint.clone(),
        }
    }
}

/// `SHA-256(cert DER)` as upper-case hex — what LocalSend shows as a device's fingerprint.
pub fn fingerprint_of(cert_der: &[u8]) -> String {
    hex::encode_upper(Sha256::digest(cert_der))
}

/// Default location: `$XDG_CONFIG_HOME/uqs/localsend` (or `~/.config/uqs/localsend`).
pub fn default_dir() -> PathBuf {
    let base = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|_| std::env::var("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|_| PathBuf::from("."));
    base.join("uqs").join("localsend")
}

impl Identity {
    /// Load `cert.pem` + `key.pem` from `dir`, or generate and store a fresh pair.
    pub fn load_or_create(dir: &Path) -> Result<Self, CertError> {
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        if cert_path.is_file() && key_path.is_file() {
            match Self::load(&cert_path, &key_path) {
                Ok(id) => return Ok(id),
                Err(e) => tracing::warn!("ignoring stored LocalSend identity ({e}); generating a new one"),
            }
        }
        let id = Self::generate()?;
        std::fs::create_dir_all(dir).map_err(|source| CertError::Io { path: dir.to_path_buf(), source })?;
        let (cert_pem, key_pem) = id.pems();
        write_private(&cert_path, cert_pem.as_bytes())?;
        write_private(&key_path, key_pem.as_bytes())?;
        Ok(id)
    }

    /// Fresh ECDSA P-256 self-signed certificate. Not persisted.
    pub fn generate() -> Result<Self, CertError> {
        let mut params = rcgen::CertificateParams::new(vec!["localsend".to_string()])?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(rcgen::DnType::CommonName, "LocalSend User");
        params.distinguished_name.push(rcgen::DnType::OrganizationName, "LocalSend");
        let key_pair = rcgen::KeyPair::generate()?;
        let cert = params.self_signed(&key_pair)?;
        let cert_der = cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(key_pair.serialize_der().into());
        let fingerprint = fingerprint_of(&cert_der);
        Ok(Self { cert_der, key_der, fingerprint })
    }

    fn load(cert_path: &Path, key_path: &Path) -> Result<Self, CertError> {
        let cert_pem = std::fs::read(cert_path).map_err(|source| CertError::Io { path: cert_path.to_path_buf(), source })?;
        let key_pem = std::fs::read(key_path).map_err(|source| CertError::Io { path: key_path.to_path_buf(), source })?;
        let cert_der = rustls_pemfile::certs(&mut cert_pem.as_slice())
            .next()
            .ok_or_else(|| CertError::Parse("no certificate in cert.pem".into()))?
            .map_err(|e| CertError::Parse(e.to_string()))?;
        let key_der = rustls_pemfile::private_key(&mut key_pem.as_slice())
            .map_err(|e| CertError::Parse(e.to_string()))?
            .ok_or_else(|| CertError::Parse("no private key in key.pem".into()))?;
        let fingerprint = fingerprint_of(&cert_der);
        Ok(Self { cert_der, key_der, fingerprint })
    }

    fn pems(&self) -> (String, String) {
        let cert = pem_block("CERTIFICATE", self.cert_der.as_ref());
        let key = pem_block("PRIVATE KEY", self.key_der.secret_der());
        (cert, key)
    }

    /// rustls server config presenting this certificate (TLS 1.2 + 1.3, no client auth).
    pub fn server_config(&self) -> Result<rustls::ServerConfig, rustls::Error> {
        crate::install_crypto_provider();
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![self.cert_der.clone()], self.key_der.clone_key())
    }
}

fn pem_block(label: &str, der: &[u8]) -> String {
    use std::fmt::Write;
    let b64 = base64_encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        let _ = writeln!(out, "{}", std::str::from_utf8(chunk).unwrap_or(""));
    }
    let _ = writeln!(out, "-----END {label}-----");
    out
}

fn base64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

fn write_private(path: &Path, data: &[u8]) -> Result<(), CertError> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|source| CertError::Io { path: path.to_path_buf(), source })?;
    f.write_all(data).map_err(|source| CertError::Io { path: path.to_path_buf(), source })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_uppercase_sha256_hex() {
        // SHA-256("abc")
        assert_eq!(
            fingerprint_of(b"abc"),
            "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
        );
        assert_eq!(fingerprint_of(b"abc").len(), 64);
    }

    #[test]
    fn generated_identity_fingerprint_matches_der() {
        let id = Identity::generate().unwrap();
        assert_eq!(id.fingerprint, fingerprint_of(id.cert_der.as_ref()));
    }

    #[test]
    fn identity_persists_and_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let a = Identity::load_or_create(dir.path()).unwrap();
        assert!(dir.path().join("cert.pem").is_file());
        assert!(dir.path().join("key.pem").is_file());
        let b = Identity::load_or_create(dir.path()).unwrap();
        assert_eq!(a.fingerprint, b.fingerprint);
        assert_eq!(a.cert_der, b.cert_der);
        // and it can back a TLS server
        b.server_config().unwrap();
    }

    #[test]
    fn pem_encoding_round_trips() {
        let id = Identity::generate().unwrap();
        let (cert_pem, _) = id.pems();
        let der = rustls_pemfile::certs(&mut cert_pem.as_bytes()).next().unwrap().unwrap();
        assert_eq!(der, id.cert_der);
    }
}
