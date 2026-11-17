//! Quick Share mDNS (`_FC9F5ED42C8A._tcp.local.`) advertisement, discovery,
//! `WifiLanServiceInfo` instance-name encoding, and `sharing.Advertisement` TXT `'n'` encoding.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::time::Duration;

use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use mdns_sd::{IfKind, ServiceDaemon, ServiceEvent, ServiceInfo};
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

/// A physical-ish network interface with an IPv4 address (Wi-Fi, Ethernet, USB tether).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanInterface {
    pub name: String,
    pub addr: Ipv4Addr,
    pub netmask: Ipv4Addr,
}

impl LanInterface {
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let m = u32::from(self.netmask);
        (u32::from(self.addr) & m) == (u32::from(ip) & m)
    }
}

/// Interface names that never carry a phone: container bridges, VPN tunnels, VM NICs.
/// Advertising their addresses makes Android pick an unreachable A record and silently
/// drop the receiver from the share sheet.
pub fn is_virtual_interface(name: &str) -> bool {
    const PREFIXES: [&str; 14] = [
        "lo", "docker", "br-", "veth", "virbr", "tun", "tap", "wg", "vmnet", "vbox", "zt", "tailscale",
        "nordlynx", "nordtun",
    ];
    PREFIXES.iter().any(|p| name.starts_with(p))
}

/// Every interface with a usable IPv4 (non-loopback, not virtual), default-route one first.
pub fn lan_interfaces() -> Vec<LanInterface> {
    let mut out: Vec<LanInterface> = if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(|i| !is_virtual_interface(&i.name))
        .filter_map(|i| match i.addr {
            if_addrs::IfAddr::V4(v4) if !v4.ip.is_loopback() && !v4.ip.is_link_local() => Some(LanInterface {
                name: i.name,
                addr: v4.ip,
                netmask: v4.netmask,
            }),
            _ => None,
        })
        .collect();
    if let Some(primary) = route_ipv4_address() {
        out.sort_by_key(|i| i.addr != primary);
    }
    out
}

/// Names of all interfaces that should be excluded from mDNS traffic.
fn virtual_interface_names() -> Vec<String> {
    let mut names: Vec<String> = if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .map(|i| i.name)
        .filter(|n| is_virtual_interface(n))
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Keep mDNS off container bridges / VPN tunnels so announcements and queries only
/// travel on links a phone can be on.
fn restrict_daemon_to_lan(daemon: &ServiceDaemon) {
    for name in virtual_interface_names() {
        let _ = daemon.disable_interface(IfKind::Name(name));
    }
}

/// Source address of the default route (the interface that reaches the internet), if any.
fn route_ipv4_address() -> Option<Ipv4Addr> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    match sock.local_addr().ok()?.ip() {
        IpAddr::V4(ip) if !ip.is_loopback() && !ip.is_unspecified() => Some(ip),
        _ => None,
    }
}

/// The host's primary LAN IPv4: the default-route interface, else the first real one.
pub fn pick_ipv4_address() -> Result<Ipv4Addr, MdnsError> {
    if let Some(ip) = route_ipv4_address() {
        return Ok(ip);
    }
    lan_interfaces().first().map(|i| i.addr).ok_or(MdnsError::NoIpv4Address)
}

/// Among a peer's addresses, prefer one on a subnet we are actually attached to.
pub fn prefer_reachable(addrs: impl IntoIterator<Item = Ipv4Addr>) -> Option<Ipv4Addr> {
    let ours = lan_interfaces();
    let mut fallback = None;
    for ip in addrs {
        if ip.is_loopback() {
            continue;
        }
        if ours.iter().any(|i| i.contains(ip)) {
            return Some(ip);
        }
        fallback.get_or_insert(ip);
    }
    fallback
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredDevice {
    pub endpoint_id: String,
    pub device_name: String,
    pub device_type: ShareTargetType,
    /// Best address to connect to (on a subnet we share, if any).
    pub address: Ipv4Addr,
    /// Every IPv4 the peer announced.
    pub all_addresses: Vec<Ipv4Addr>,
    pub port: u16,
    pub tlv_records: HashMap<u8, Vec<u8>>,
}

pub struct MdnsAdvertiser {
    daemon: ServiceDaemon,
    fullname: String,
    pub endpoint_id: [u8; 4],
    /// Primary (default-route) address, also published in the `IPv4` TXT key.
    pub address: Ipv4Addr,
    /// Every address announced (one A record per real interface).
    pub addresses: Vec<Ipv4Addr>,
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
        // A multi-homed PC (Ethernet + Wi-Fi + USB tether) must answer on each link with
        // that link's own address: Android connects to the A record it resolved, and a
        // phone on Wi-Fi cannot reach the wired subnet.
        let lan: Vec<Ipv4Addr> = lan_interfaces().into_iter().map(|i| i.addr).collect();
        let announced: Vec<IpAddr> = if lan.is_empty() {
            vec![IpAddr::V4(address)]
        } else {
            lan.iter().copied().map(IpAddr::V4).collect()
        };
        let service_info = ServiceInfo::new(
            SERVICE_TYPE,
            &instance_name,
            &host_fqdn,
            &announced[..],
            port,
            &properties[..],
        )
        .map_err(|e| MdnsError::Daemon(e.to_string()))?;

        let fullname = service_info.get_fullname().to_string();
        let daemon = ServiceDaemon::new().map_err(|e| MdnsError::Daemon(e.to_string()))?;
        restrict_daemon_to_lan(&daemon);
        daemon
            .register(service_info)
            .map_err(|e| MdnsError::Daemon(e.to_string()))?;

        Ok(Self {
            daemon,
            fullname,
            endpoint_id,
            address,
            addresses: if lan.is_empty() { vec![address] } else { lan },
            port,
        })
    }

    /// Unregister and shut the mDNS daemon down (also happens automatically on drop).
    pub fn stop(self) {
        drop(self);
    }
}

impl Drop for MdnsAdvertiser {
    fn drop(&mut self) {
        let _ = self.daemon.unregister(&self.fullname);
        let _ = self.daemon.shutdown();
    }
}

/// Live discovery event from [`watch_devices`].
#[derive(Debug, Clone)]
pub enum DiscoveryEvent {
    /// A receiver appeared or its advertisement changed.
    Found(DiscoveredDevice),
    /// A receiver's advertisement expired or was withdrawn (`endpoint_id`).
    Lost(String),
}

/// Browse continuously and stream `Found`/`Lost` events until the returned receiver is
/// dropped. Our own advertisement is filtered out like in [`discover_devices`].
pub fn watch_devices() -> Result<tokio::sync::mpsc::Receiver<DiscoveryEvent>, MdnsError> {
    let daemon = ServiceDaemon::new().map_err(|e| MdnsError::Daemon(e.to_string()))?;
    restrict_daemon_to_lan(&daemon);
    let browser = daemon
        .browse(SERVICE_TYPE)
        .map_err(|e| MdnsError::Daemon(e.to_string()))?;
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    let own_id = stable_endpoint_id(&default_hostname());

    tokio::spawn(async move {
        loop {
            let ev = match browser.recv_async().await {
                Ok(ev) => ev,
                Err(_) => break,
            };
            let out = match ev {
                ServiceEvent::ServiceResolved(info) => {
                    resolve_device(&info, Some(&own_id)).map(DiscoveryEvent::Found)
                }
                ServiceEvent::ServiceRemoved(_, fullname) => {
                    let instance_name = fullname
                        .strip_suffix(&format!(".{SERVICE_TYPE}"))
                        .unwrap_or(&fullname);
                    parse_service_instance_name(instance_name)
                        .ok()
                        .map(|(ep, _)| DiscoveryEvent::Lost(String::from_utf8_lossy(&ep).into_owned()))
                }
                _ => None,
            };
            if let Some(out) = out {
                if tx.send(out).await.is_err() {
                    break; // GUI went away
                }
            }
        }
        let _ = daemon.shutdown();
    });
    Ok(rx)
}

/// Turn a resolved mDNS record into a [`DiscoveredDevice`], skipping `skip_id` (our own
/// endpoint) when given. Of the peer's A records, the one on a subnet we share wins.
fn resolve_device(info: &mdns_sd::ServiceInfo, skip_id: Option<&[u8; 4]>) -> Option<DiscoveredDevice> {
    let fullname = info.get_fullname();
    let instance_name = fullname
        .strip_suffix(&format!(".{SERVICE_TYPE}"))
        .unwrap_or(fullname);
    let (endpoint_id, _) = parse_service_instance_name(instance_name).ok()?;
    if skip_id == Some(&endpoint_id) {
        return None;
    }
    let txt_n = info.get_property_val_str(TXT_KEY_ENDPOINT_INFO)?;
    let adv = parse_endpoint_info(&url64_decode(txt_n).ok()?).ok()?;
    let mut all: Vec<Ipv4Addr> = info.get_addresses_v4().into_iter().copied().collect();
    all.sort();
    let address = prefer_reachable(all.iter().copied()).or_else(|| {
        info.get_property_val_str(TXT_KEY_IPV4)
            .and_then(|s| s.parse::<Ipv4Addr>().ok())
    })?;
    Some(DiscoveredDevice {
        endpoint_id: String::from_utf8_lossy(&endpoint_id).into_owned(),
        device_name: adv
            .device_name
            .unwrap_or_else(|| "(hidden Quick Share device)".to_string()),
        device_type: adv.device_type,
        address,
        all_addresses: all,
        port: info.get_port(),
        tlv_records: adv.tlv_records,
    })
}

/// Browse `_FC9F5ED42C8A._tcp.local.` for `duration` and return discovered Quick Share receivers.
/// Skips our own advertisement (same hostname-derived endpoint ID) so the sender
/// never offers to send to itself.
pub async fn discover_devices(duration: Duration) -> Result<Vec<DiscoveredDevice>, MdnsError> {
    discover_devices_with(duration, false).await
}

/// [`discover_devices`] with the option to include this host's own advertisement
/// (`include_self`), useful to check what phones will actually see.
pub async fn discover_devices_with(
    duration: Duration,
    include_self: bool,
) -> Result<Vec<DiscoveredDevice>, MdnsError> {
    let daemon = ServiceDaemon::new().map_err(|e| MdnsError::Daemon(e.to_string()))?;
    restrict_daemon_to_lan(&daemon);
    let receiver = daemon
        .browse(SERVICE_TYPE)
        .map_err(|e| MdnsError::Daemon(e.to_string()))?;

    let own_id = if include_self { None } else { Some(stable_endpoint_id(&default_hostname())) };
    let mut found: HashMap<String, DiscoveredDevice> = HashMap::new();
    let deadline = tokio::time::Instant::now() + duration;

    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, receiver.recv_async()).await {
            Ok(Ok(ServiceEvent::ServiceResolved(info))) => {
                if let Some(d) = resolve_device(&info, own_id.as_ref()) {
                    found.insert(d.endpoint_id.clone(), d);
                }
            }
            Ok(Ok(_)) => continue,
            _ => break,
        }
    }

    let _ = daemon.shutdown();
    Ok(found.into_values().collect())
}
