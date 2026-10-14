//! Quick Share mDNS (`_FC9F5ED42C8A._tcp.local.`) advertisement, discovery,
//! `WifiLanServiceInfo` instance-name encoding, and `sharing.Advertisement` TXT `'n'` encoding.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::time::Duration;

use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// `sharing/nearby_connections_manager_impl.cc`: `kServiceId = "NearbySharing"`.
pub const SERVICE_ID: &[u8] = b"NearbySharing";

/// First 6 bytes of `SHA-256("NearbySharing")` uppercase hex -> `_FC9F5ED42C8A._tcp.local.`.
pub const SERVICE_TYPE: &str = "_FC9F5ED42C8A._tcp.local.";

/// First 3 bytes of `SHA-256("NearbySharing")`.
pub const INSTANCE_SERVICE_ID_HASH: [u8; 3] = [0xFC, 0x9F, 0x5E];

pub const TXT_KEY_ENDPOINT_INFO: &str = "n";
pub const TXT_KEY_IPV4: &str = "IPv4";

pub const WIFI_LAN_SERVICE_INFO_VERSION: u8 = 1;
pub const PCP_P2P_POINT_TO_POINT: u8 = 3;

const ENDPOINT_ID_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
pub const ADVERTISEMENT_SALT_SIZE: usize = 2;
pub const ADVERTISEMENT_METADATA_KEY_SIZE: usize = 14;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ShareTargetType {
    Unknown = 0,
    Phone = 1,
    Tablet = 2,
    Laptop = 3,
    Car = 4,
    Foldable = 5,
    Xr = 6,
}

impl TryFrom<u8> for ShareTargetType {
    type Error = MdnsError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Unknown),
            1 => Ok(Self::Phone),
            2 => Ok(Self::Tablet),
            3 => Ok(Self::Laptop),
            4 => Ok(Self::Car),
            5 => Ok(Self::Foldable),
            6 => Ok(Self::Xr),
            other => Err(MdnsError::UnknownDeviceType(other)),
        }
    }
}

#[derive(Debug, Error)]
pub enum MdnsError {
    #[error("base64 decode error: {0}")]
    Base64(String),
    #[error("service instance name too short: {0} bytes")]
    InstanceNameTooShort(usize),
    #[error("unsupported WifiLanServiceInfo version: {0}")]
    UnsupportedVersion(u8),
    #[error("empty endpoint info")]
    EmptyEndpointInfo,
    #[error("unknown ShareTargetType: {0}")]
    UnknownDeviceType(u8),
    #[error("device name exceeds 255 bytes")]
    DeviceNameTooLong,
    #[error("missing 'n' TXT record")]
    MissingTxtEndpointInfo,
    #[error("no usable non-loopback IPv4 address found")]
    NoIpv4Address,
    #[error("mDNS daemon error: {0}")]
    Daemon(String),
}

pub fn url64_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn url64_decode(input: &str) -> Result<Vec<u8>, MdnsError> {
    let trimmed = input.trim_end_matches('=');
    URL_SAFE_NO_PAD
        .decode(trimmed)
        .or_else(|_| URL_SAFE.decode(input))
        .map_err(|e| MdnsError::Base64(e.to_string()))
}

pub fn default_hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "universal-quickshare".to_string())
}

/// Deterministic 4-character alphanumeric endpoint ID derived from `hostname`.
pub fn stable_endpoint_id(hostname: &str) -> [u8; 4] {
    let digest = Sha256::digest(hostname.as_bytes());
    let mut out = [0u8; 4];
    for i in 0..4 {
        out[i] = ENDPOINT_ID_ALPHABET[(digest[i] as usize) % ENDPOINT_ID_ALPHABET.len()];
    }
    out
}

/// Build the 10-byte `WifiLanServiceInfo` instance payload and encode as unpadded URL-safe base64.
/// Including the two trailing zero bytes (empty UWB address + WebRTC state) is required by
/// Windows Quick Share's stricter `WifiLanServiceInfo` parser.
pub fn build_service_instance_name(endpoint_id: &[u8; 4]) -> String {
    let version_and_pcp = ((WIFI_LAN_SERVICE_INFO_VERSION & 0b111) << 5) | (PCP_P2P_POINT_TO_POINT & 0b11111);
    let mut payload = [0u8; 10];
    payload[0] = version_and_pcp;
    payload[1..5].copy_from_slice(endpoint_id);
    payload[5..8].copy_from_slice(&INSTANCE_SERVICE_ID_HASH);
    payload[8] = 0x00;
    payload[9] = 0x00;
    url64_encode(&payload)
}

/// Parse an mDNS service instance name into `(endpoint_id, service_id_hash)`.
pub fn parse_service_instance_name(instance_name: &str) -> Result<([u8; 4], [u8; 3]), MdnsError> {
    let clean = instance_name.trim_start_matches('_');
    let raw = url64_decode(clean)?;
    if raw.len() < 8 {
        return Err(MdnsError::InstanceNameTooShort(raw.len()));
    }
    let version = (raw[0] >> 5) & 0b111;
    if version != WIFI_LAN_SERVICE_INFO_VERSION {
        return Err(MdnsError::UnsupportedVersion(version));
    }
    let mut endpoint_id = [0u8; 4];
    endpoint_id.copy_from_slice(&raw[1..5]);
    let mut service_id_hash = [0u8; 3];
    service_id_hash.copy_from_slice(&raw[5..8]);
    Ok((endpoint_id, service_id_hash))
}

/// Build the binary `sharing::Advertisement` endpoint info carried in TXT `'n'`.
pub fn build_endpoint_info(
    device_name: Option<&str>,
    device_type: ShareTargetType,
) -> Result<Vec<u8>, MdnsError> {
    let has_name = device_name.is_some();
    let byte0 = ((!has_name as u8) << 4) | (((device_type as u8) & 0b111) << 1);
    let mut out = Vec::with_capacity(18 + device_name.map(|n| n.len()).unwrap_or(0));
    out.push(byte0);

    let mut salt_and_key = [0u8; ADVERTISEMENT_SALT_SIZE + ADVERTISEMENT_METADATA_KEY_SIZE];
    rand::thread_rng().fill_bytes(&mut salt_and_key);
    out.extend_from_slice(&salt_and_key);

    if let Some(name) = device_name {
        let name_bytes = name.as_bytes();
        if name_bytes.len() > 255 {
            return Err(MdnsError::DeviceNameTooLong);
        }
        out.push(name_bytes.len() as u8);
        out.extend_from_slice(name_bytes);
    }
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedAdvertisement {
    pub visible: bool,
    pub device_name: Option<String>,
    pub device_type: ShareTargetType,
    pub tlv_records: HashMap<u8, Vec<u8>>,
}

/// Parse binary `sharing::Advertisement` endpoint info from TXT `'n'`.
pub fn parse_endpoint_info(endpoint_info: &[u8]) -> Result<ParsedAdvertisement, MdnsError> {
    if endpoint_info.is_empty() {
        return Err(MdnsError::EmptyEndpointInfo);
    }
    let byte0 = endpoint_info[0];
    let has_no_device_name = ((byte0 >> 4) & 1) != 0;
    let visible = !has_no_device_name;
    let raw_type = (byte0 >> 1) & 0b111;
    let device_type = ShareTargetType::try_from(raw_type)?;

    let header_size = 1 + ADVERTISEMENT_SALT_SIZE + ADVERTISEMENT_METADATA_KEY_SIZE;
    let mut cursor = header_size.min(endpoint_info.len());
    let mut device_name = None;

    if visible && endpoint_info.len() > header_size {
        let name_len = endpoint_info[header_size] as usize;
        cursor = header_size + 1;
        let end = (cursor + name_len).min(endpoint_info.len());
        device_name = Some(String::from_utf8_lossy(&endpoint_info[cursor..end]).into_owned());
        cursor = end;
    }

    let mut tlv_records = HashMap::new();
    while cursor + 2 <= endpoint_info.len() {
        let tlv_type = endpoint_info[cursor];
        let tlv_len = endpoint_info[cursor + 1] as usize;
        cursor += 2;
        if cursor + tlv_len <= endpoint_info.len() {
            tlv_records.insert(tlv_type, endpoint_info[cursor..cursor + tlv_len].to_vec());
            cursor += tlv_len;
        } else {
            break;
        }
    }

    Ok(ParsedAdvertisement {
        visible,
        device_name,
        device_type,
        tlv_records,
    })
}

/// Probe outbound route to find the host's primary non-loopback LAN IPv4 address.
pub fn pick_ipv4_address() -> Result<Ipv4Addr, MdnsError> {
    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
        if sock.connect("8.8.8.8:80").is_ok() {
            if let Ok(local_addr) = sock.local_addr() {
                if let IpAddr::V4(ipv4) = local_addr.ip() {
                    if !ipv4.is_loopback() && !ipv4.is_unspecified() {
                        return Ok(ipv4);
                    }
                }
            }
        }
    }
    Err(MdnsError::NoIpv4Address)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredDevice {
    pub endpoint_id: String,
    pub device_name: String,
    pub device_type: ShareTargetType,
    pub address: Ipv4Addr,
    pub port: u16,
    pub tlv_records: HashMap<u8, Vec<u8>>,
}

pub struct MdnsAdvertiser {
    daemon: ServiceDaemon,
    fullname: String,
    pub endpoint_id: [u8; 4],
    pub address: Ipv4Addr,
    pub port: u16,
}

impl MdnsAdvertiser {
    pub fn start(
        device_name: &str,
        device_type: ShareTargetType,
        address: Ipv4Addr,
        port: u16,
    ) -> Result<Self, MdnsError> {
        let hostname = default_hostname();
        let endpoint_id = stable_endpoint_id(&hostname);
        let instance_name = build_service_instance_name(&endpoint_id);
        let endpoint_info = build_endpoint_info(Some(device_name), device_type)?;
        let txt_n = url64_encode(&endpoint_info);
        let ipv4_str = address.to_string();

        let properties = [
            (TXT_KEY_ENDPOINT_INFO, txt_n.as_str()),
            (TXT_KEY_IPV4, ipv4_str.as_str()),
        ];

        let host_fqdn = format!("{hostname}.local.");
        let service_info = ServiceInfo::new(
            SERVICE_TYPE,
            &instance_name,
            &host_fqdn,
            IpAddr::V4(address),
            port,
            &properties[..],
        )
        .map_err(|e| MdnsError::Daemon(e.to_string()))?;

        let fullname = service_info.get_fullname().to_string();
        let daemon = ServiceDaemon::new().map_err(|e| MdnsError::Daemon(e.to_string()))?;
        daemon
            .register(service_info)
            .map_err(|e| MdnsError::Daemon(e.to_string()))?;

        Ok(Self {
            daemon,
            fullname,
            endpoint_id,
            address,
            port,
        })
    }

    pub fn stop(self) {
        let _ = self.daemon.unregister(&self.fullname);
        let _ = self.daemon.shutdown();
    }
}

/// Browse `_FC9F5ED42C8A._tcp.local.` for `duration` and return discovered Quick Share receivers.
pub async fn discover_devices(duration: Duration) -> Result<Vec<DiscoveredDevice>, MdnsError> {
    let daemon = ServiceDaemon::new().map_err(|e| MdnsError::Daemon(e.to_string()))?;
    let receiver = daemon
        .browse(SERVICE_TYPE)
        .map_err(|e| MdnsError::Daemon(e.to_string()))?;

    let mut found: HashMap<[u8; 4], DiscoveredDevice> = HashMap::new();
    let deadline = tokio::time::Instant::now() + duration;

    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, receiver.recv_async()).await {
            Ok(Ok(ServiceEvent::ServiceResolved(info))) => {
                let fullname = info.get_fullname();
                let instance_name = fullname
                    .strip_suffix(&format!(".{SERVICE_TYPE}"))
                    .unwrap_or(fullname);

                let Ok((endpoint_id, _)) = parse_service_instance_name(instance_name) else {
                    continue;
                };

                let Some(txt_n) = info.get_property_val_str(TXT_KEY_ENDPOINT_INFO) else {
                    continue;
                };
                let Ok(endpoint_bytes) = url64_decode(txt_n) else {
                    continue;
                };
                let Ok(adv) = parse_endpoint_info(&endpoint_bytes) else {
                    continue;
                };

                let ipv4 = info
                    .get_addresses_v4()
                    .into_iter()
                    .copied()
                    .find(|ip| !ip.is_loopback())
                    .or_else(|| {
                        info.get_property_val_str(TXT_KEY_IPV4)
                            .and_then(|s| s.parse::<Ipv4Addr>().ok())
                    });

                let Some(address) = ipv4 else {
                    continue;
                };

                found.insert(
                    endpoint_id,
                    DiscoveredDevice {
                        endpoint_id: String::from_utf8_lossy(&endpoint_id).into_owned(),
                        device_name: adv
                            .device_name
                            .unwrap_or_else(|| "(hidden Quick Share device)".to_string()),
                        device_type: adv.device_type,
                        address,
                        port: info.get_port(),
                        tlv_records: adv.tlv_records,
                    },
                );
            }
            Ok(Ok(_)) => continue,
            _ => break,
        }
    }

    let _ = daemon.shutdown();
    Ok(found.into_values().collect())
}
