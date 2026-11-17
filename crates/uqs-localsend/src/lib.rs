//! LocalSend protocol v2 for Universal Quick Share.
//!
//! LocalSend is the open, cross-platform share protocol (iOS, Android, Windows, macOS,
//! Linux apps) — the practical way for an iPhone to reach a Linux PC whose Wi-Fi card has
//! no AWDL/AirDrop support. Three pieces:
//!
//! - [`discovery`]: multicast UDP on `224.0.0.167:53317` (announce, respond, keep a
//!   [`discovery::PeerBook`] of nearby LocalSend devices), on every LAN interface.
//! - [`server`]: HTTPS on `:53317` with a persisted self-signed certificate
//!   (`/info`, `/register`, `/prepare-upload`, `/upload`, `/cancel`). Incoming sessions are
//!   mapped onto `uqs_core::transfer::{TransferOffer, ReceivedItem}` and confirmed through
//!   the same accept/decline callback shape the Quick Share receiver uses ([`server::Hooks`]).
//! - [`client`]: `prepare-upload` + `upload` of `uqs_core::transfer::OutgoingItem`s to a
//!   discovered peer, its self-signed certificate accepted after a fingerprint check.

pub mod cert;
pub mod client;
pub mod discovery;
pub mod protocol;
pub mod server;

pub use cert::{fingerprint_of, Identity};
pub use client::{send_items, ClientError};
pub use discovery::{Discovery, DiscoveryConfig, DiscoveryEvent, Peer, PeerBook};
pub use protocol::{DeviceInfo, DeviceType, Protocol, DEFAULT_PORT, MULTICAST_GROUP};
pub use server::{Hooks, ReceiveEvent, Server, ServerConfig};

use std::sync::Once;

/// rustls needs one process-wide crypto provider; pick `ring` (pure Rust build, no cmake).
/// Safe to call any number of times.
pub fn install_crypto_provider() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// 16 random bytes as lower-case hex: session ids, file ids, upload tokens.
pub fn random_id() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

/// True when `fp` looks like a certificate hash (what HTTPS-mode LocalSend apps advertise).
/// HTTP-mode apps advertise a random string instead; then there is no certificate to pin.
pub fn is_cert_fingerprint(fp: &str) -> bool {
    fp.len() == 64 && fp.bytes().all(|b| b.is_ascii_hexdigit())
}
