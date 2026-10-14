//! Quick Share QR-code handshake (`https://quickshare.google/qrcode#key=...`).
//!
//! Allows pairing & skipping user prompt or discovering hidden receivers without BLE.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use hkdf::Hkdf;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::SecretKey;
use qrcode::QrCode;
use sha2::Sha256;
use thiserror::Error;

use crate::mdns::url64_encode;

#[derive(Debug, Error)]
pub enum QrError {
    #[error("QR record buffer too short")]
    BufferTooShort,
    #[error("AES-128-GCM decryption failed")]
    DecryptFailed,
}

pub struct QuickShareQrCode {
    pub url: String,
    pub key_payload: Vec<u8>,
    secret_key: SecretKey,
}

impl QuickShareQrCode {
    /// Generate a new ephemeral P-256 keypair and Quick Share QR code URL.
    pub fn generate() -> Self {
        let secret_key = SecretKey::random(&mut rand::thread_rng());
        let pub_key = secret_key.public_key();
        let pt = pub_key.to_encoded_point(false);
        let x_bytes = pt.x().expect("uncompressed point has X");

        // 2-byte version 0 (0x00, 0x00) + 1-byte version 2 (0x02) + 32-byte X coordinate
        let mut key_payload = Vec::with_capacity(35);
        key_payload.extend_from_slice(&[0x00, 0x00, 0x02]);
        key_payload.extend_from_slice(x_bytes);

        let url = format!(
            "https://quickshare.google/qrcode#key={}",
            url64_encode(&key_payload)
        );

        Self {
            url,
            key_payload,
            secret_key,
        }
    }

    /// Sign the 32-byte UKEY2 `auth_string` with ECDSA-P256-SHA256 in 64-byte IEEE P1363 (`r || s`)
    /// format for `PairedKeyEncryptionFrame.qr_code_handshake_data`.
    pub fn sign_auth_string(&self, auth_string: &[u8]) -> [u8; 64] {
        let signing_key = SigningKey::from(&self.secret_key);
        let sig: Signature = signing_key.sign(auth_string);
        let bytes = sig.to_bytes();
        let mut out = [0u8; 64];
        out.copy_from_slice(&bytes);
        out
    }

    /// Decrypt TLV record type `1` (QR code encrypted device name) from a hidden receiver.
    pub fn decrypt_qrcode_record(&self, buffer: &[u8]) -> Result<Vec<u8>, QrError> {
        if buffer.len() < 28 {
            return Err(QrError::BufferTooShort);
        }
        let hk = Hkdf::<Sha256>::new(None, &self.key_payload);
        let mut advertising_token = [0u8; 16];
        let mut name_encryption_token = [0u8; 16];
        hk.expand(b"advertisingContext", &mut advertising_token)
            .expect("16 bytes HKDF expand");
        hk.expand(b"encryptionKey", &mut name_encryption_token)
            .expect("16 bytes HKDF expand");

        let iv = Nonce::from_slice(&buffer[..12]);
        let ciphertext_and_tag = &buffer[12..];

        let cipher = Aes128Gcm::new_from_slice(&name_encryption_token)
            .expect("16-byte AES-128 key");
        cipher
            .decrypt(
                iv,
                Payload {
                    msg: ciphertext_and_tag,
                    aad: &advertising_token,
                },
            )
            .map_err(|_| QrError::DecryptFailed)
    }

    /// Render the QR code as Unicode block art for terminal display.
    pub fn render_unicode(&self) -> String {
        let code = QrCode::new(self.url.as_bytes()).expect("QR code generation succeeds");
        code.render::<qrcode::render::unicode::Dense1x2>()
            .dark_color(qrcode::render::unicode::Dense1x2::Light)
            .light_color(qrcode::render::unicode::Dense1x2::Dark)
            .build()
    }
}
