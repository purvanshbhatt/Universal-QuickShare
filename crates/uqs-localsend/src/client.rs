//! Sending side: `prepare-upload` + `upload` to a LocalSend peer, plus the two small
//! calls discovery needs (`/register`, `/info`).
//!
//! TLS: LocalSend apps use self-signed certificates, so there is no chain to validate.
//! Instead the presented certificate's SHA-256 must equal the fingerprint the peer
//! advertised (HTTPS apps advertise exactly that hash). A peer whose fingerprint is not a
//! hash (HTTP-mode apps, or an explicit `--target` with no discovery) is accepted as is.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::StreamExt;
use reqwest::header::CONTENT_LENGTH;
use reqwest::{Body, Client, StatusCode};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio_util::io::ReaderStream;

use uqs_core::transfer::OutgoingItem;

use crate::cert::fingerprint_of;
use crate::discovery::Peer;
use crate::protocol::{
    base_url, DeviceInfo, FileMeta, PrepareUploadRequest, PrepareUploadResponse, Protocol, PATH_CANCEL, PATH_INFO,
    PATH_PREPARE_UPLOAD, PATH_REGISTER, PATH_UPLOAD,
};
use crate::{install_crypto_provider, is_cert_fingerprint, random_id};

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("TLS setup failed: {0}")]
    Tls(#[from] rustls::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("nothing to send")]
    NoItems,
    #[error("the receiver requires a PIN")]
    PinRequired,
    #[error("declined by the receiver")]
    Declined,
    #[error("the receiver is busy with another transfer")]
    Busy,
    #[error("the receiver is rate-limiting requests")]
    TooManyRequests,
    #[error("peer answered {0}: {1}")]
    Status(u16, String),
}

impl ClientError {
    fn from_status(status: StatusCode, body: String) -> Self {
        match status {
            StatusCode::UNAUTHORIZED => Self::PinRequired,
            StatusCode::FORBIDDEN => Self::Declined,
            StatusCode::CONFLICT => Self::Busy,
            StatusCode::TOO_MANY_REQUESTS => Self::TooManyRequests,
            s => Self::Status(s.as_u16(), body.chars().take(200).collect()),
        }
    }
}

// --- TLS ---------------------------------------------------------------------------------

#[derive(Debug)]
struct FingerprintVerifier {
    /// Upper-case hex SHA-256 the peer advertised; `None` = accept any certificate.
    expected: Option<String>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if let Some(expected) = &self.expected {
            let got = fingerprint_of(end_entity.as_ref());
            if !got.eq_ignore_ascii_case(expected) {
                return Err(rustls::Error::General(format!(
                    "peer certificate fingerprint {got} does not match the advertised {expected}"
                )));
            }
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// HTTP client for one peer. `fingerprint` pins the certificate when it is a hash.
pub fn http_client(protocol: Protocol, fingerprint: &str) -> Result<Client, ClientError> {
    install_crypto_provider();
    let mut b = Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .user_agent(concat!("uqs-localsend/", env!("CARGO_PKG_VERSION")));
    if protocol == Protocol::Https {
        let provider = rustls::crypto::CryptoProvider::get_default()
            .cloned()
            .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()));
        let expected = is_cert_fingerprint(fingerprint).then(|| fingerprint.to_string());
        let tls = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(FingerprintVerifier { expected, provider }))
            .with_no_client_auth();
        b = b.use_preconfigured_tls(tls);
    }
    Ok(b.build()?)
}

// --- discovery calls ---------------------------------------------------------------------

/// `POST /register`: tell `peer` who we are; returns what it says about itself.
pub async fn register(peer: &Peer, local: &DeviceInfo) -> Result<DeviceInfo, ClientError> {
    let client = http_client(peer.protocol, &peer.fingerprint)?;
    let url = format!("{}{PATH_REGISTER}", base_url(peer.protocol, peer.ip, peer.port));
    let resp = client.post(url).json(local).timeout(Duration::from_secs(5)).send().await?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(ClientError::from_status(status, body));
    }
    // Some apps answer `/register` with an empty body; fall back to what we already know.
    Ok(serde_json::from_str(&body).unwrap_or_else(|_| peer_info(peer)))
}

/// `GET /info?fingerprint=…`: liveness probe and alias refresh.
pub async fn info(peer: &Peer, local: &DeviceInfo) -> Result<DeviceInfo, ClientError> {
    probe(peer.ip, peer.port, peer.protocol, &peer.fingerprint, local).await
}

/// `GET /info` on an address with no prior discovery (CLI `--target`). No certificate
/// pinning is possible without an advertised fingerprint; the reply's fingerprint is kept
/// so later calls to the returned peer are pinned.
pub async fn probe_addr(ip: std::net::IpAddr, port: u16, protocol: Protocol, local: &DeviceInfo) -> Result<Peer, ClientError> {
    let info = probe(ip, port, protocol, "", local).await?;
    let mut peer = Peer::from_info(&info, ip);
    if info.port.is_none() {
        peer.port = port;
    }
    if info.protocol.is_none() {
        peer.protocol = protocol;
    }
    Ok(peer)
}

async fn probe(ip: std::net::IpAddr, port: u16, protocol: Protocol, fingerprint: &str, local: &DeviceInfo) -> Result<DeviceInfo, ClientError> {
    let client = http_client(protocol, fingerprint)?;
    let url = format!("{}{PATH_INFO}", base_url(protocol, ip, port));
    let resp = client
        .get(url)
        .query(&[("fingerprint", local.fingerprint.as_str())])
        .timeout(Duration::from_secs(5))
        .send()
        .await?;
    let status = resp.status();
    if !status.is_success() {
        return Err(ClientError::from_status(status, resp.text().await.unwrap_or_default()));
    }
    Ok(resp.json().await?)
}

fn peer_info(peer: &Peer) -> DeviceInfo {
    DeviceInfo {
        alias: peer.alias.clone(),
        version: crate::protocol::PROTOCOL_VERSION.to_string(),
        device_model: peer.device_model.clone(),
        device_type: peer.device_type,
        fingerprint: peer.fingerprint.clone(),
        port: Some(peer.port),
        protocol: Some(peer.protocol),
        download: peer.download,
    }
}

// --- sending -----------------------------------------------------------------------------

enum Payload {
    File(PathBuf),
    Text(Vec<u8>),
}

/// Send files and texts to `peer`. `on_progress(done, total)` counts bytes across all items.
///
/// Texts travel the LocalSend way: a `text/plain` entry whose `preview` holds the whole
/// message, so the receiving app shows it as a message (copy / open link) rather than a file.
pub async fn send_items<P>(
    peer: &Peer,
    local: &DeviceInfo,
    items: &[OutgoingItem],
    pin: Option<&str>,
    on_progress: P,
) -> Result<(), ClientError>
where
    P: FnMut(u64, u64) + Send + 'static,
{
    let (files, payloads) = describe(items).await?;
    if files.is_empty() {
        return Err(ClientError::NoItems);
    }
    let total: u64 = files.values().map(|f| f.size).sum();

    let client = http_client(peer.protocol, &peer.fingerprint)?;
    let base = base_url(peer.protocol, peer.ip, peer.port);

    let mut prepare = client.post(format!("{base}{PATH_PREPARE_UPLOAD}"));
    if let Some(pin) = pin {
        prepare = prepare.query(&[("pin", pin)]);
    }
    // No timeout: the person at the other end may take a while to tap Accept.
    let resp = prepare.json(&PrepareUploadRequest { info: local.clone(), files }).send().await?;
    let status = resp.status();
    if status == StatusCode::NO_CONTENT {
        return Ok(()); // receiver already has everything
    }
    if !status.is_success() {
        return Err(ClientError::from_status(status, resp.text().await.unwrap_or_default()));
    }
    let accepted: PrepareUploadResponse = resp.json().await?;

    // (bytes finished before the current item, callback)
    let progress = Arc::new(Mutex::new((0u64, on_progress)));
    report(&progress, 0, total);

    let mut sent_before = 0u64;
    for (id, size, payload) in payloads {
        let Some(token) = accepted.files.get(&id) else {
            continue; // the receiver chose to skip this one
        };
        let body = match payload {
            Payload::Text(bytes) => Body::from(bytes),
            Payload::File(path) => {
                let file = tokio::fs::File::open(&path).await?;
                let progress = progress.clone();
                let stream = ReaderStream::with_capacity(file, 64 * 1024).map(move |chunk| {
                    if let Ok(b) = &chunk {
                        let mut g = progress.lock().unwrap_or_else(|e| e.into_inner());
                        g.0 += b.len() as u64;
                        let done = g.0;
                        (g.1)(done, total);
                    }
                    chunk
                });
                Body::wrap_stream(stream)
            }
        };
        let result = client
            .post(format!("{base}{PATH_UPLOAD}"))
            .query(&[("sessionId", accepted.session_id.as_str()), ("fileId", id.as_str()), ("token", token.as_str())])
            .header(CONTENT_LENGTH, size)
            .body(body)
            .send()
            .await;
        let resp = match result {
            Ok(r) => r,
            Err(e) => {
                cancel(&client, &base, &accepted.session_id).await;
                return Err(e.into());
            }
        };
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            cancel(&client, &base, &accepted.session_id).await;
            return Err(ClientError::from_status(status, body));
        }
        sent_before += size;
        {
            let mut g = progress.lock().unwrap_or_else(|e| e.into_inner());
            g.0 = sent_before;
        }
        report(&progress, sent_before, total);
    }
    Ok(())
}

fn report<P: FnMut(u64, u64)>(progress: &Mutex<(u64, P)>, done: u64, total: u64) {
    let mut g = progress.lock().unwrap_or_else(|e| e.into_inner());
    (g.1)(done, total);
}

async fn cancel(client: &Client, base: &str, session_id: &str) {
    let _ = client
        .post(format!("{base}{PATH_CANCEL}"))
        .query(&[("sessionId", session_id)])
        .timeout(Duration::from_secs(3))
        .send()
        .await;
}

async fn describe(items: &[OutgoingItem]) -> Result<(HashMap<String, FileMeta>, Vec<(String, u64, Payload)>), ClientError> {
    let mut files = HashMap::new();
    let mut payloads = Vec::new();
    for item in items {
        let id = random_id();
        match item {
            OutgoingItem::File(path) => {
                let md = tokio::fs::metadata(path).await?;
                let meta = FileMeta {
                    id: id.clone(),
                    file_name: path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into()),
                    size: md.len(),
                    file_type: mime_of(path),
                    sha256: None,
                    preview: None,
                    metadata: None,
                };
                payloads.push((id.clone(), md.len(), Payload::File(path.clone())));
                files.insert(id, meta);
            }
            OutgoingItem::Text { title, body, .. } => {
                let bytes = body.clone().into_bytes();
                let meta = FileMeta {
                    id: id.clone(),
                    file_name: text_file_name(title),
                    size: bytes.len() as u64,
                    file_type: "text/plain".to_string(),
                    sha256: None,
                    preview: Some(body.clone()),
                    metadata: None,
                };
                payloads.push((id.clone(), bytes.len() as u64, Payload::Text(bytes)));
                files.insert(id, meta);
            }
        }
    }
    Ok((files, payloads))
}

pub(crate) fn mime_of(path: &Path) -> String {
    mime_guess::from_path(path).first_or_octet_stream().essence_str().to_string()
}

/// `My note.txt` from a text's title: filesystem-safe, at most 40 chars.
pub(crate) fn text_file_name(title: &str) -> String {
    let stem: String = title
        .chars()
        .filter(|c| c.is_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.'))
        .take(40)
        .collect::<String>()
        .trim()
        .trim_end_matches('.')
        .to_string();
    if stem.is_empty() {
        "message.txt".to_string()
    } else {
        format!("{stem}.txt")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_names_are_safe() {
        assert_eq!(text_file_name("https://example.com/a?b=c"), "httpsexample.comabc.txt");
        assert_eq!(text_file_name("///"), "message.txt");
        assert_eq!(text_file_name("Hello world"), "Hello world.txt");
        assert!(text_file_name(&"x".repeat(100)).len() <= 44);
    }

    #[test]
    fn mime_guess_falls_back_to_octet_stream() {
        assert_eq!(mime_of(Path::new("a.jpg")), "image/jpeg");
        assert_eq!(mime_of(Path::new("a.unknownext")), "application/octet-stream");
    }

    #[tokio::test]
    async fn describe_marks_texts_as_messages() {
        let items = vec![OutgoingItem::text("https://example.com")];
        let (files, payloads) = describe(&items).await.unwrap();
        assert_eq!(files.len(), 1);
        let f = files.values().next().unwrap();
        assert_eq!(f.file_type, "text/plain");
        assert_eq!(f.preview.as_deref(), Some("https://example.com"));
        assert!(f.is_text_message());
        assert_eq!(payloads[0].1, "https://example.com".len() as u64);
    }
}
