//! Universal Quick Share — Apple AirDrop (`_airdrop._tcp.local.`) & AWDL module.
//!
//! Includes:
//! 1. Linux WiFi & AWDL (`awdl0` / monitor-mode / driver) hardware capability detection.
//! 2. Apple AirDrop BLE advertisement payload (`0x004C` company ID, type `0x05`).
//! 3. `_airdrop._tcp.local.` mDNS advertisement and discovery (`flags=1019`).
//! 4. AirDrop `/Discover`, `/Ask` XML plist framing and `070707` ODC CPIO archive pack/unpack
//!    for `/Upload`.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const AIRDROP_MDNS_SERVICE_TYPE: &str = "_airdrop._tcp.local.";
pub const AIRDROP_DEFAULT_FLAGS: u32 = 1019; // 0x3fb: MixedTypes | FileURL | Pipelining | Grouping | Discover | Unicast
pub const APPLE_COMPANY_ID: u16 = 0x004C;
pub const AIRDROP_BLE_TYPE: u8 = 0x05;

#[derive(Debug, Error)]
pub enum AirdropError {
    #[error("AWDL interface (`awdl0`) is not active: {0}")]
    AwdlNotActive(String),
    #[error("mDNS error: {0}")]
    Mdns(String),
    #[error("invalid CPIO archive: {0}")]
    Cpio(String),
    #[error("invalid AirDrop plist payload: {0}")]
    Plist(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WirelessInterfaceStatus {
    pub name: String,
    pub driver: String,
    pub supports_monitor_mode: bool,
    pub awdl_chipset_tier: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AirdropHardwareReport {
    pub awdl0_present: bool,
    pub wireless_interfaces: Vec<WirelessInterfaceStatus>,
    pub ready_for_native_awdl: bool,
    pub status_summary: String,
}

/// Inspect `/sys/class/net` and `iw list` to determine WiFi chipset, monitor-mode support,
/// and whether an `awdl0` interface is active for AirDrop.
pub fn inspect_airdrop_hardware() -> AirdropHardwareReport {
    let mut awdl0_present = false;
    let mut wireless_interfaces = Vec::new();
    let monitor_supported = check_iw_monitor_support();

    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == "awdl0" {
                awdl0_present = true;
            }
            let wireless_dir = entry.path().join("wireless");
            let phy80211_dir = entry.path().join("phy80211");
            if wireless_dir.exists() || phy80211_dir.exists() {
                let driver_link = entry.path().join("device/driver");
                let driver = std::fs::read_link(&driver_link)
                    .ok()
                    .and_then(|p| p.file_name().map(|f| f.to_string_lossy().into_owned()))
                    .unwrap_or_else(|| "unknown".to_string());

                let tier = classify_awdl_driver(&driver);
                wireless_interfaces.push(WirelessInterfaceStatus {
                    name,
                    driver,
                    supports_monitor_mode: monitor_supported,
                    awdl_chipset_tier: tier,
                });
            }
        }
    }

    let ready_for_native_awdl = awdl0_present;
    let status_summary = if awdl0_present {
        "awdl0 interface is active; AirDrop over AWDL + LAN mDNS is fully available.".to_string()
    } else if let Some(first) = wireless_interfaces.first() {
        format!(
            "Found wireless interface '{}' (driver: {}, monitor_mode: {}, AWDL tier: {}). \
             `awdl0` is not currently up — AirDrop LAN mDNS fallback is enabled; bring up `awdl0` \
             with `owl -i {}` for direct Apple-to-Linux AWDL radio frames.",
            first.name,
            first.driver,
            first.supports_monitor_mode,
            first.awdl_chipset_tier,
            first.name
        )
    } else {
        "No 802.11 wireless interface detected; AirDrop restricted to LAN mDNS.".to_string()
    };

    AirdropHardwareReport {
        awdl0_present,
        wireless_interfaces,
        ready_for_native_awdl,
        status_summary,
    }
}

fn check_iw_monitor_support() -> bool {
    for bin in ["/usr/sbin/iw", "/sbin/iw", "iw"] {
        if let Ok(output) = Command::new(bin).arg("list").output() {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                return stdout.contains("* monitor");
            }
        }
    }
    false
}

fn classify_awdl_driver(driver: &str) -> String {
    match driver {
        "ath9k" | "ath9k_htc" | "rt2800usb" | "carl9170" => {
            "Tier-1 (verified active monitor + frame injection for owl AWDL)".to_string()
        }
        d if d.starts_with("rtw88") || d.starts_with("rtw89") || d.starts_with("mt76") => {
            "Tier-2 (mac80211 monitor mode supported; frame injection varies by firmware)".to_string()
        }
        "iwlwifi" | "brcmfmac" => {
            "Tier-3 (monitor mode supported; active AWDL injection restricted by firmware)".to_string()
        }
        _ => "Unknown driver capability".to_string(),
    }
}

/// Build the 20-byte Apple (`0x004C`) Type `0x05` AirDrop BLE manufacturer data payload.
///
/// Format:
/// - byte 0: `0x05` (AirDrop sub-type)
/// - byte 1: `0x12` (18 bytes following)
/// - bytes 2..10: 8 zero padding bytes
/// - byte 10: `0x01` (AirDrop protocol version 1)
/// - bytes 11..13: first 2 bytes of SHA-256(apple_id)
/// - bytes 13..15: first 2 bytes of SHA-256(phone)
/// - bytes 15..17: first 2 bytes of SHA-256(email)
/// - bytes 17..19: first 2 bytes of SHA-256(email)
/// - byte 19: `0x00`
pub fn build_airdrop_ble_payload(apple_id: &str, phone: &str, email: &str) -> [u8; 20] {
    let mut out = [0u8; 20];
    out[0] = AIRDROP_BLE_TYPE;
    out[1] = 0x12;
    out[10] = 0x01;

    let h_id = Sha256::digest(apple_id.as_bytes());
    let h_phone = Sha256::digest(phone.as_bytes());
    let h_email = Sha256::digest(email.as_bytes());

    out[11..13].copy_from_slice(&h_id[..2]);
    out[13..15].copy_from_slice(&h_phone[..2]);
    out[15..17].copy_from_slice(&h_email[..2]);
    out[17..19].copy_from_slice(&h_email[..2]);
    out[19] = 0x00;
    out
}

/// Build XML plist response for AirDrop `POST /Discover`.
pub fn build_discover_response_plist(computer_name: &str, model_name: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>ReceiverComputerName</key>
    <string>{}</string>
    <key>ReceiverModelName</key>
    <string>{}</string>
</dict>
</plist>
"#,
        xml_escape(computer_name),
        xml_escape(model_name)
    )
}

/// Build XML plist request for AirDrop `POST /Ask`.
pub fn build_ask_request_plist(
    sender_computer_name: &str,
    sender_model_name: &str,
    file_names: &[String],
) -> String {
    let mut files_xml = String::new();
    for f in file_names {
        let escaped = xml_escape(f);
        files_xml.push_str(&format!(
            r#"        <dict>
            <key>FileName</key>
            <string>{escaped}</string>
            <key>FileType</key>
            <string>public.data</string>
            <key>FileBomPath</key>
            <string>./{escaped}</string>
            <key>FileIsDirectory</key>
            <false/>
            <key>ConvertMediaFormats</key>
            <false/>
        </dict>
"#
        ));
    }

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>BundleID</key>
    <string>com.apple.finder</string>
    <key>SenderComputerName</key>
    <string>{}</string>
    <key>SenderModelName</key>
    <string>{}</string>
    <key>Files</key>
    <array>
{}    </array>
</dict>
</plist>
"#,
        xml_escape(sender_computer_name),
        xml_escape(sender_model_name),
        files_xml
    )
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Pack a list of `(relative_name, file_bytes)` entries into an AirDrop-compatible
/// POSIX.1 `070707` (ODC) ASCII CPIO archive.
pub fn pack_cpio_odc(entries: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (idx, (raw_name, content)) in entries.iter().enumerate() {
        let clean_name = format!("./{}", sanitize_cpio_filename(raw_name));
        let name_with_nul = format!("{clean_name}\0");
        let ino = (idx + 1) & 0o777777;
        let mode = 0o100644;
        let fsize = content.len();
        let header = format!(
            "070707{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{:011o}{:06o}{:011o}",
            1,                       // c_dev
            ino,                     // c_ino
            mode,                    // c_mode
            0,                       // c_uid
            0,                       // c_gid
            1,                       // c_nlink
            0,                       // c_rdev
            0,                       // c_mtime
            name_with_nul.len(),     // c_namesize
            fsize                    // c_filesize
        );
        debug_assert_eq!(header.len(), 76);
        out.extend_from_slice(header.as_bytes());
        out.extend_from_slice(name_with_nul.as_bytes());
        out.extend_from_slice(content);
    }

    // Trailer entry `TRAILER!!!`
    let trailer_name = "TRAILER!!!\0";
    let trailer_hdr = format!(
        "070707{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{:011o}{:06o}{:011o}",
        0,
        0,
        0,
        0,
        0,
        1,
        0,
        0,
        trailer_name.len(),
        0
    );
    out.extend_from_slice(trailer_hdr.as_bytes());
    out.extend_from_slice(trailer_name.as_bytes());
    out
}

/// Unpack a POSIX.1 `070707` (ODC) CPIO archive from an AirDrop `/Upload` stream,
/// sanitizing every entry path to prevent path traversal.
pub fn unpack_cpio_odc(archive: &[u8]) -> Result<Vec<(String, Vec<u8>)>, AirdropError> {
    let mut cursor = 0usize;
    let mut files = Vec::new();

    while cursor + 76 <= archive.len() {
        let hdr = std::str::from_utf8(&archive[cursor..cursor + 76])
            .map_err(|_| AirdropError::Cpio("non-ASCII ODC header".into()))?;
        if !hdr.starts_with("070707") {
            return Err(AirdropError::Cpio(
                "missing 070707 ODC magic in CPIO header".into(),
            ));
        }
        let mode = u32::from_str_radix(&hdr[18..24], 8)
            .map_err(|_| AirdropError::Cpio("invalid octal c_mode".into()))?;
        let namesize = usize::from_str_radix(&hdr[59..65], 8)
            .map_err(|_| AirdropError::Cpio("invalid octal c_namesize".into()))?;
        let filesize = usize::from_str_radix(&hdr[65..76], 8)
            .map_err(|_| AirdropError::Cpio("invalid octal c_filesize".into()))?;

        cursor += 76;
        if cursor + namesize > archive.len() {
            return Err(AirdropError::Cpio("truncated CPIO filename".into()));
        }
        let raw_name = &archive[cursor..cursor + namesize];
        let name_str = String::from_utf8_lossy(raw_name)
            .trim_end_matches('\0')
            .to_string();
        cursor += namesize;

        if cursor + filesize > archive.len() {
            return Err(AirdropError::Cpio("truncated CPIO file body".into()));
        }
        let body = archive[cursor..cursor + filesize].to_vec();
        cursor += filesize;

        if name_str == "TRAILER!!!" {
            break;
        }

        // Only extract regular files (S_IFREG = 0o100000)
        if (mode & 0o170000) == 0o100000 {
            let safe = sanitize_cpio_filename(&name_str);
            files.push((safe, body));
        }
    }

    Ok(files)
}

pub fn sanitize_cpio_filename(raw: &str) -> String {
    let before_nul = raw.split('\0').next().unwrap_or("");
    let normalized = before_nul.replace('\\', "/");
    let base = normalized.rsplit('/').next().unwrap_or("");
    let trimmed = base.trim_start_matches('.');
    if trimmed.is_empty() {
        "airdrop_file".to_string()
    } else {
        trimmed.to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredAirdropPeer {
    pub instance_name: String,
    pub hostname: String,
    pub addresses: Vec<IpAddr>,
    pub port: u16,
    pub flags: u32,
}

/// Browse `_airdrop._tcp.local.` for `duration`.
pub async fn discover_airdrop_peers(
    duration: Duration,
) -> Result<Vec<DiscoveredAirdropPeer>, AirdropError> {
    let daemon = ServiceDaemon::new().map_err(|e| AirdropError::Mdns(e.to_string()))?;
    let receiver = daemon
        .browse(AIRDROP_MDNS_SERVICE_TYPE)
        .map_err(|e| AirdropError::Mdns(e.to_string()))?;

    let mut peers: HashMap<String, DiscoveredAirdropPeer> = HashMap::new();
    let deadline = tokio::time::Instant::now() + duration;

    while tokio::time::Instant::now() < deadline {
        let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(rem, receiver.recv_async()).await {
            Ok(Ok(ServiceEvent::ServiceResolved(info))) => {
                let flags = info
                    .get_property_val_str("flags")
                    .and_then(|s| s.parse::<u32>().ok())
                    .unwrap_or(0);
                let addresses: Vec<IpAddr> = info.get_addresses().iter().copied().collect();
                peers.insert(
                    info.get_fullname().to_string(),
                    DiscoveredAirdropPeer {
                        instance_name: info.get_fullname().to_string(),
                        hostname: info.get_hostname().to_string(),
                        addresses,
                        port: info.get_port(),
                        flags,
                    },
                );
            }
            Ok(Ok(_)) => continue,
            _ => break,
        }
    }

    let _ = daemon.shutdown();
    Ok(peers.into_values().collect())
}

/// Advertise an AirDrop receiver on `_airdrop._tcp.local.`.
pub fn advertise_airdrop_mdns(
    instance_id: &str,
    hostname: &str,
    address: Ipv4Addr,
    port: u16,
) -> Result<(ServiceDaemon, String), AirdropError> {
    let flags_str = AIRDROP_DEFAULT_FLAGS.to_string();
    let props = [("flags", flags_str.as_str())];
    let host_fqdn = format!("{hostname}.local.");
    let info = ServiceInfo::new(
        AIRDROP_MDNS_SERVICE_TYPE,
        instance_id,
        &host_fqdn,
        IpAddr::V4(address),
        port,
        &props[..],
    )
    .map_err(|e| AirdropError::Mdns(e.to_string()))?;

    let fullname = info.get_fullname().to_string();
    let daemon = ServiceDaemon::new().map_err(|e| AirdropError::Mdns(e.to_string()))?;
    daemon
        .register(info)
        .map_err(|e| AirdropError::Mdns(e.to_string()))?;
    Ok((daemon, fullname))
}

/// Save unpacked CPIO files into `output_dir`.
pub async fn save_uploaded_cpio_archive(
    archive: &[u8],
    output_dir: &Path,
) -> Result<Vec<PathBuf>, AirdropError> {
    let entries = unpack_cpio_odc(archive)?;
    tokio::fs::create_dir_all(output_dir).await?;
    let mut saved = Vec::with_capacity(entries.len());
    for (name, bytes) in entries {
        let dest = output_dir.join(&name);
        tokio::fs::write(&dest, &bytes).await?;
        saved.push(dest);
    }
    Ok(saved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_airdrop_ble_payload_structure() {
        let ble = build_airdrop_ble_payload("user@icloud.com", "+15551234567", "user@icloud.com");
        assert_eq!(ble[0], 0x05);
        assert_eq!(ble[1], 0x12);
        assert_eq!(&ble[2..10], &[0u8; 8]);
        assert_eq!(ble[10], 0x01);
        assert_eq!(ble[19], 0x00);
    }

    #[test]
    fn roundtrip_cpio_odc_archive_with_path_sanitization() {
        let input = vec![
            ("hello.txt".to_string(), b"Hello AirDrop!".to_vec()),
            ("../../evil.sh".to_string(), b"echo nope".to_vec()),
        ];
        let packed = pack_cpio_odc(&input);
        let unpacked = unpack_cpio_odc(&packed).unwrap();
        assert_eq!(unpacked.len(), 2);
        assert_eq!(unpacked[0].0, "hello.txt");
        assert_eq!(unpacked[0].1, b"Hello AirDrop!");
        assert_eq!(unpacked[1].0, "evil.sh");
        assert_eq!(unpacked[1].1, b"echo nope");
    }

    #[test]
    fn inspect_hardware_runs_cleanly() {
        let report = inspect_airdrop_hardware();
        assert!(!report.status_summary.is_empty());
    }
}
