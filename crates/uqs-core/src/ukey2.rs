//! UKEY2 (P256_SHA512) key exchange and D2D HKDF key + PIN derivation.
//!
//! Verified against `NearbyShareExe` (D2D salt `82aa55a0...` at offset `0x26c9a28`)
//! and Google's `third_party/ukey2` C++ reference implementation.

use hkdf::Hkdf;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{EncodedPoint, PublicKey, SecretKey};
use prost::Message;
use rand::RngCore;
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};

use uqs_proto::securegcm::{
    ukey2_client_init::CipherCommitment, ukey2_message, Ukey2ClientFinished, Ukey2ClientInit,
    Ukey2HandshakeCipher, Ukey2Message, Ukey2ServerInit,
};
use uqs_proto::securemessage::{EcP256PublicKey, GenericPublicKey, PublicKeyType};

use crate::framing::{recv_frame, send_frame, FrameError};

/// SHA-256("D2D") — verified in `NearbyShareExe` at file offset 40669992 (`0x26c9a28`).
pub const D2D_SALT: [u8; 32] = [
    0x82, 0xaa, 0x55, 0xa0, 0xd3, 0x97, 0xf8, 0x83, 0x46, 0xca, 0x1c, 0xee, 0x8d, 0x39, 0x09, 0xb9,
    0x5f, 0x13, 0xfa, 0x7d, 0xeb, 0x1d, 0x4a, 0xb3, 0x83, 0x76, 0xb8, 0x25, 0x6d, 0xa8, 0x55, 0x10,
];

/// SHA-256("SecureMessage")
pub const SECUREMESSAGE_SALT: [u8; 32] = [
    0xbf, 0x9d, 0x2a, 0x53, 0xc6, 0x36, 0x16, 0xd7, 0x5d, 0xb0, 0xa7, 0x16, 0x5b, 0x91, 0xc1, 0xef,
    0x73, 0xe5, 0x37, 0xf2, 0x42, 0x74, 0x05, 0xfa, 0x23, 0x61, 0x0a, 0x4b, 0xe6, 0x57, 0x64, 0x2e,
];

pub const AUTH_SALT: &[u8] = b"UKEY2 v1 auth";
pub const NEXT_SALT: &[u8] = b"UKEY2 v1 next";
pub const NEXT_PROTOCOL: &str = "AES_256_CBC-HMAC_SHA256";

#[derive(Debug, Error)]
pub enum Ukey2Error {
    #[error("framing error: {0}")]
    Framing(#[from] FrameError),
    #[error("protobuf decode error: {0}")]
    ProtoDecode(#[from] prost::DecodeError),
    #[error("unexpected UKEY2 message type: {0:?}")]
    UnexpectedMessageType(Option<i32>),
    #[error("invalid UKEY2 parameter: {0}")]
    InvalidParameter(&'static str),
    #[error("SHA-512 cipher commitment mismatch")]
    CommitmentMismatch,
    #[error("invalid EC P-256 public key")]
    InvalidPublicKey,
}

#[derive(Clone, Debug)]
pub struct D2DKeys {
    pub decrypt_key: [u8; 32],
    pub recv_hmac_key: [u8; 32],
    pub encrypt_key: [u8; 32],
    pub send_hmac_key: [u8; 32],
    pub auth_string: [u8; 32],
    pub pin: String,
}

/// Encode a 32-byte big-endian unsigned P-256 coordinate per Google `securemessage`
/// `ExportEcP256Key`: strip leading zero bytes, then unconditionally prepend `0x00`.
pub fn encode_point_signed(coord: &[u8; 32]) -> Vec<u8> {
    let first_non_zero = coord.iter().position(|&b| b != 0).unwrap_or(coord.len());
    let minimal = &coord[first_non_zero..];
    let mut out = Vec::with_capacity(1 + minimal.len());
    out.push(0x00);
    out.extend_from_slice(minimal);
    out
}

/// Decode a `securemessage` signed big-endian coordinate back into a 32-byte unsigned array.
pub fn decode_point_unsigned(encoded: &[u8]) -> Result<[u8; 32], Ukey2Error> {
    let first_non_zero = encoded.iter().position(|&b| b != 0).unwrap_or(encoded.len());
    let stripped = &encoded[first_non_zero..];
    if stripped.len() > 32 {
        return Err(Ukey2Error::InvalidPublicKey);
    }
    let mut out = [0u8; 32];
    out[32 - stripped.len()..].copy_from_slice(stripped);
    Ok(out)
}

pub fn encode_p256_public_key(pub_key: &PublicKey) -> Vec<u8> {
    let pt = pub_key.to_encoded_point(false);
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(pt.x().expect("uncompressed point has X"));
    y.copy_from_slice(pt.y().expect("uncompressed point has Y"));

    let generic = GenericPublicKey {
        r#type: PublicKeyType::EcP256 as i32,
        ec_p256_public_key: Some(EcP256PublicKey {
            x: encode_point_signed(&x),
            y: encode_point_signed(&y),
        }),
        rsa2048_public_key: None,
        dh2048_public_key: None,
    };
    generic.encode_to_vec()
}

pub fn parse_p256_public_key(generic_bytes: &[u8]) -> Result<PublicKey, Ukey2Error> {
    let generic = GenericPublicKey::decode(generic_bytes)?;
    if generic.r#type != PublicKeyType::EcP256 as i32 {
        return Err(Ukey2Error::InvalidPublicKey);
    }
    let ec_key = generic
        .ec_p256_public_key
        .ok_or(Ukey2Error::InvalidPublicKey)?;
    let x = decode_point_unsigned(&ec_key.x)?;
    let y = decode_point_unsigned(&ec_key.y)?;
    let pt = EncodedPoint::from_affine_coordinates(&x.into(), &y.into(), false);
    Option::from(PublicKey::from_encoded_point(&pt)).ok_or(Ukey2Error::InvalidPublicKey)
}

pub fn hkdf_extract_expand(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("32 bytes is valid length for HKDF-SHA256");
    okm
}

/// Compute the 4-digit Quick Share confirmation PIN from the 32-byte UKEY2 auth string.
/// Uses signed bytes and C-style truncating remainder modulo 9973 (matching C++ `%`).
pub fn to_four_digit_pin(auth_string: &[u8]) -> String {
    const K_HASH_MODULO: i32 = 9973;
    const K_HASH_BASE_MULTIPLIER: i32 = 31;

    let mut hash: i32 = 0;
    let mut multiplier: i32 = 1;
    for &b in auth_string {
        let signed_b = (b as i8) as i32;
        hash = (hash + signed_b * multiplier) % K_HASH_MODULO;
        multiplier = (multiplier * K_HASH_BASE_MULTIPLIER) % K_HASH_MODULO;
    }
    format!("{:04}", hash.abs())
}

pub fn derive_d2d_keys(
    shared_secret_sha256: &[u8; 32],
    client_init_bytes: &[u8],
    server_init_bytes: &[u8],
    is_server: bool,
) -> D2DKeys {
    let mut ukey_info = Vec::with_capacity(client_init_bytes.len() + server_init_bytes.len());
    ukey_info.extend_from_slice(client_init_bytes);
    ukey_info.extend_from_slice(server_init_bytes);

    let auth_string = hkdf_extract_expand(AUTH_SALT, shared_secret_sha256, &ukey_info);
    let next_secret = hkdf_extract_expand(NEXT_SALT, shared_secret_sha256, &ukey_info);

    let d2d_client = hkdf_extract_expand(&D2D_SALT, &next_secret, b"client");
    let d2d_server = hkdf_extract_expand(&D2D_SALT, &next_secret, b"server");

    let (own_key, peer_key) = if is_server {
        (d2d_server, d2d_client)
    } else {
        (d2d_client, d2d_server)
    };

    let encrypt_key = hkdf_extract_expand(&SECUREMESSAGE_SALT, &own_key, b"ENC:2");
    let send_hmac_key = hkdf_extract_expand(&SECUREMESSAGE_SALT, &own_key, b"SIG:1");
    let decrypt_key = hkdf_extract_expand(&SECUREMESSAGE_SALT, &peer_key, b"ENC:2");
    let recv_hmac_key = hkdf_extract_expand(&SECUREMESSAGE_SALT, &peer_key, b"SIG:1");
    let pin = to_four_digit_pin(&auth_string);

    D2DKeys {
        decrypt_key,
        recv_hmac_key,
        encrypt_key,
        send_hmac_key,
        auth_string,
        pin,
    }
}

pub fn ecdh_shared_secret_sha256(secret: &SecretKey, peer_pub: &PublicKey) -> [u8; 32] {
    let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer_pub.as_affine());
    let mut hasher = Sha256::new();
    hasher.update(shared.raw_secret_bytes());
    hasher.finalize().into()
}

/// Drive the UKEY2 handshake as the server (receiver).
pub async fn run_server_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
) -> Result<D2DKeys, Ukey2Error> {
    let client_init_bytes = recv_frame(stream).await?;
    let msg = Ukey2Message::decode(client_init_bytes.as_slice())?;
    if msg.message_type != Some(ukey2_message::Type::ClientInit as i32) {
        return Err(Ukey2Error::UnexpectedMessageType(msg.message_type));
    }
    let client_init_data = msg
        .message_data
        .ok_or(Ukey2Error::InvalidParameter("missing ClientInit data"))?;
    let client_init = Ukey2ClientInit::decode(client_init_data.as_slice())?;

    if client_init.version != Some(1) {
        return Err(Ukey2Error::InvalidParameter("unsupported ClientInit version"));
    }
    if client_init.random.as_ref().map(|r| r.len()) != Some(32) {
        return Err(Ukey2Error::InvalidParameter("ClientInit random != 32 bytes"));
    }
    if client_init.next_protocol.as_deref() != Some(NEXT_PROTOCOL) {
        return Err(Ukey2Error::InvalidParameter("unsupported next_protocol"));
    }

    let commitment = client_init
        .cipher_commitments
        .iter()
        .find(|c| c.handshake_cipher == Some(Ukey2HandshakeCipher::P256Sha512 as i32))
        .and_then(|c| c.commitment.clone())
        .ok_or(Ukey2Error::InvalidParameter("missing P256_SHA512 commitment"))?;

    let secret = SecretKey::random(&mut rand::thread_rng());
    let pub_key = secret.public_key();

    let mut random = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut random);

    let server_init = Ukey2ServerInit {
        version: Some(1),
        random: Some(random),
        handshake_cipher: Some(Ukey2HandshakeCipher::P256Sha512 as i32),
        public_key: Some(encode_p256_public_key(&pub_key)),
    };
    let server_init_msg = Ukey2Message {
        message_type: Some(ukey2_message::Type::ServerInit as i32),
        message_data: Some(server_init.encode_to_vec()),
    };
    let server_init_bytes = server_init_msg.encode_to_vec();
    send_frame(stream, &server_init_bytes).await?;

    let client_finished_bytes = recv_frame(stream).await?;
    let actual_hash = Sha512::digest(&client_finished_bytes);
    if actual_hash.as_slice() != commitment.as_slice() {
        return Err(Ukey2Error::CommitmentMismatch);
    }

    let fin_msg = Ukey2Message::decode(client_finished_bytes.as_slice())?;
    if fin_msg.message_type != Some(ukey2_message::Type::ClientFinish as i32) {
        return Err(Ukey2Error::UnexpectedMessageType(fin_msg.message_type));
    }
    let fin_data = fin_msg
        .message_data
        .ok_or(Ukey2Error::InvalidParameter("missing ClientFinished data"))?;
    let client_finished = Ukey2ClientFinished::decode(fin_data.as_slice())?;
    let peer_pub_bytes = client_finished
        .public_key
        .ok_or(Ukey2Error::InvalidPublicKey)?;
    let peer_pub = parse_p256_public_key(&peer_pub_bytes)?;

    let shared_sha256 = ecdh_shared_secret_sha256(&secret, &peer_pub);
    Ok(derive_d2d_keys(
        &shared_sha256,
        &client_init_bytes,
        &server_init_bytes,
        true,
    ))
}

/// Drive the UKEY2 handshake as the client (sender).
pub async fn run_client_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
) -> Result<D2DKeys, Ukey2Error> {
    let secret = SecretKey::random(&mut rand::thread_rng());
    let pub_key = secret.public_key();

    let client_finished = Ukey2ClientFinished {
        public_key: Some(encode_p256_public_key(&pub_key)),
    };
    let client_finished_msg = Ukey2Message {
        message_type: Some(ukey2_message::Type::ClientFinish as i32),
        message_data: Some(client_finished.encode_to_vec()),
    };
    let client_finished_bytes = client_finished_msg.encode_to_vec();

    let commitment_hash = Sha512::digest(&client_finished_bytes).to_vec();
    let mut random = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut random);

    let client_init = Ukey2ClientInit {
        version: Some(1),
        random: Some(random),
        cipher_commitments: vec![CipherCommitment {
            handshake_cipher: Some(Ukey2HandshakeCipher::P256Sha512 as i32),
            commitment: Some(commitment_hash),
        }],
        next_protocol: Some(NEXT_PROTOCOL.to_string()),
    };
    let client_init_msg = Ukey2Message {
        message_type: Some(ukey2_message::Type::ClientInit as i32),
        message_data: Some(client_init.encode_to_vec()),
    };
    let client_init_bytes = client_init_msg.encode_to_vec();
    send_frame(stream, &client_init_bytes).await?;

    let server_init_bytes = recv_frame(stream).await?;
    let srv_msg = Ukey2Message::decode(server_init_bytes.as_slice())?;
    if srv_msg.message_type != Some(ukey2_message::Type::ServerInit as i32) {
        return Err(Ukey2Error::UnexpectedMessageType(srv_msg.message_type));
    }
    let srv_data = srv_msg
        .message_data
        .ok_or(Ukey2Error::InvalidParameter("missing ServerInit data"))?;
    let server_init = Ukey2ServerInit::decode(srv_data.as_slice())?;
    if server_init.version != Some(1) {
        return Err(Ukey2Error::InvalidParameter("unsupported ServerInit version"));
    }
    if server_init.handshake_cipher != Some(Ukey2HandshakeCipher::P256Sha512 as i32) {
        return Err(Ukey2Error::InvalidParameter("unsupported ServerInit cipher"));
    }
    let peer_pub_bytes = server_init
        .public_key
        .ok_or(Ukey2Error::InvalidPublicKey)?;
    let peer_pub = parse_p256_public_key(&peer_pub_bytes)?;

    send_frame(stream, &client_finished_bytes).await?;

    let shared_sha256 = ecdh_shared_secret_sha256(&secret, &peer_pub);
    Ok(derive_d2d_keys(
        &shared_sha256,
        &client_init_bytes,
        &server_init_bytes,
        false,
    ))
}
