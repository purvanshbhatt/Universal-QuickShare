//! D2D `SecureMessage` encryption and decryption layer (AES-256-CBC + HMAC-SHA256).

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use prost::Message;
use rand::RngCore;
use sha2::Sha256;
use thiserror::Error;

use uqs_proto::securegcm::{DeviceToDeviceMessage, GcmMetadata, Type as GcmType};
use uqs_proto::securemessage::{EncScheme, Header, HeaderAndBody, SecureMessage, SigScheme};

use crate::ukey2::D2DKeys;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Error)]
pub enum D2DError {
    #[error("HMAC-SHA256 verification failed")]
    HmacMismatch,
    #[error("AES-256-CBC padding or IV error")]
    CipherError,
    #[error("protobuf decode error: {0}")]
    ProtoDecode(#[from] prost::DecodeError),
}

#[derive(Clone, Debug)]
pub struct SecureChannel {
    encrypt_key: [u8; 32],
    decrypt_key: [u8; 32],
    send_hmac_key: [u8; 32],
    recv_hmac_key: [u8; 32],
    pub auth_string: [u8; 32],
    pub pin: String,
    send_seq: i32,
}

impl SecureChannel {
    pub fn new(keys: D2DKeys) -> Self {
        Self {
            encrypt_key: keys.encrypt_key,
            decrypt_key: keys.decrypt_key,
            send_hmac_key: keys.send_hmac_key,
            recv_hmac_key: keys.recv_hmac_key,
            auth_string: keys.auth_string,
            pin: keys.pin,
            send_seq: 0,
        }
    }

    /// Wrap `frame_bytes` in a `DeviceToDeviceMessage`, encrypt with AES-256-CBC (PKCS#7),
    /// and sign `HeaderAndBody` with HMAC-SHA256 to produce a serialized `SecureMessage`.
    pub fn encrypt(&mut self, frame_bytes: &[u8]) -> Vec<u8> {
        self.send_seq = self.send_seq.wrapping_add(1);
        let d2d = DeviceToDeviceMessage {
            message: Some(frame_bytes.to_vec()),
            sequence_number: Some(self.send_seq),
        };
        let plaintext = d2d.encode_to_vec();

        let mut iv = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut iv);

        let ciphertext =
            Aes256CbcEnc::new(&self.encrypt_key.into(), &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(&plaintext);

        let public_metadata = GcmMetadata {
            r#type: GcmType::DeviceToDeviceMessage as i32,
            version: Some(1),
        }
        .encode_to_vec();

        let header = Header {
            signature_scheme: SigScheme::HmacSha256 as i32,
            encryption_scheme: EncScheme::Aes256Cbc as i32,
            verification_key_id: None,
            decryption_key_id: None,
            iv: Some(iv.to_vec()),
            public_metadata: Some(public_metadata),
            associated_data_length: None,
        };

        let header_and_body_bytes = HeaderAndBody {
            header,
            body: ciphertext,
        }
        .encode_to_vec();

        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.send_hmac_key)
            .expect("HMAC accepts any key size");
        mac.update(&header_and_body_bytes);
        let signature = mac.finalize().into_bytes().to_vec();

        SecureMessage {
            header_and_body: header_and_body_bytes,
            signature,
        }
        .encode_to_vec()
    }

    /// Verify and decrypt a serialized `SecureMessage`, returning the inner `DeviceToDeviceMessage.message`.
    pub fn decrypt(&self, secure_message_bytes: &[u8]) -> Result<Vec<u8>, D2DError> {
        let secure_msg = SecureMessage::decode(secure_message_bytes)?;

        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.recv_hmac_key)
            .expect("HMAC accepts any key size");
        mac.update(&secure_msg.header_and_body);
        mac.verify_slice(&secure_msg.signature)
            .map_err(|_| D2DError::HmacMismatch)?;

        let hab = HeaderAndBody::decode(secure_msg.header_and_body.as_slice())?;
        let iv_slice = hab.header.iv.as_deref().ok_or(D2DError::CipherError)?;
        let iv: [u8; 16] = iv_slice.try_into().map_err(|_| D2DError::CipherError)?;

        let plaintext = Aes256CbcDec::new(&self.decrypt_key.into(), &iv.into())
            .decrypt_padded_vec_mut::<Pkcs7>(&hab.body)
            .map_err(|_| D2DError::CipherError)?;

        let d2d = DeviceToDeviceMessage::decode(plaintext.as_slice())?;
        Ok(d2d.message.unwrap_or_default())
    }
}
