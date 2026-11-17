//! Wire types of the LocalSend protocol, version 2.
//!
//! Field names follow the published spec (<https://github.com/localsend/protocol>) exactly:
//! camelCase JSON, `fileType` as a MIME type, optional fields omitted when `None`.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use serde::{Deserialize, Serialize};

/// Multicast group every LocalSend app joins.
pub const MULTICAST_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 167);
/// UDP (discovery) and TCP (HTTPS) port shared by all LocalSend apps.
pub const DEFAULT_PORT: u16 = 53317;
/// Protocol version string we speak.
pub const PROTOCOL_VERSION: &str = "2.1";

pub const PATH_INFO: &str = "/api/localsend/v2/info";
pub const PATH_REGISTER: &str = "/api/localsend/v2/register";
pub const PATH_PREPARE_UPLOAD: &str = "/api/localsend/v2/prepare-upload";
pub const PATH_UPLOAD: &str = "/api/localsend/v2/upload";
pub const PATH_CANCEL: &str = "/api/localsend/v2/cancel";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DeviceType {
    Mobile,
    #[default]
    Desktop,
    Web,
    Headless,
    Server,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Http,
    #[default]
    Https,
}

impl Protocol {
    pub fn scheme(self) -> &'static str {
        match self {
            Protocol::Http => "http",
            Protocol::Https => "https",
        }
    }
}

/// What a device says about itself: the body of `/register` and `/info` responses, the
/// `info` block of `prepare-upload`, and (with [`Announcement`]) the multicast message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceInfo {
    pub alias: String,
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_model: Option<String>,
    #[serde(default)]
    pub device_type: DeviceType,
    pub fingerprint: String,
    /// Port the HTTP(S) server listens on. Absent in `/info` replies of some apps.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Protocol>,
    /// Whether the device offers the (optional) browser download API.
    #[serde(default)]
    pub download: bool,
}

fn default_version() -> String {
    PROTOCOL_VERSION.to_string()
}

impl DeviceInfo {
    pub fn new(alias: impl Into<String>, fingerprint: impl Into<String>, port: u16, protocol: Protocol) -> Self {
        Self {
            alias: alias.into(),
            version: PROTOCOL_VERSION.to_string(),
            device_model: Some("Linux".to_string()),
            device_type: DeviceType::Desktop,
            fingerprint: fingerprint.into(),
            port: Some(port),
            protocol: Some(protocol),
            download: false,
        }
    }

    pub fn port_or_default(&self) -> u16 {
        self.port.unwrap_or(DEFAULT_PORT)
    }

    pub fn protocol_or_default(&self) -> Protocol {
        self.protocol.unwrap_or_default()
    }
}

/// The multicast UDP message. `announce: true` asks everyone to reply (over UDP with
/// `announce: false`, and/or by POSTing their own info to the sender's `/register`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Announcement {
    #[serde(flatten)]
    pub info: DeviceInfo,
    #[serde(default)]
    pub announce: bool,
}

/// One entry of the `files` map in `prepare-upload`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileMeta {
    pub id: String,
    pub file_name: String,
    pub size: u64,
    /// MIME type (`image/jpeg`, `text/plain`, …).
    pub file_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// LocalSend puts the full text here when sharing a message rather than a file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<FileMetadata>,
}

impl FileMeta {
    /// LocalSend's "message" convention: a `text/plain` entry whose body is already in `preview`.
    pub fn is_text_message(&self) -> bool {
        self.preview.is_some() && self.file_type.starts_with("text/plain")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct FileMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accessed: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareUploadRequest {
    pub info: DeviceInfo,
    pub files: HashMap<String, FileMeta>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareUploadResponse {
    pub session_id: String,
    /// file id → upload token.
    pub files: HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadQuery {
    pub session_id: String,
    pub file_id: String,
    pub token: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionQuery {
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PinQuery {
    pub pin: Option<String>,
}

/// Base URL of a peer's API, e.g. `https://192.168.12.7:53317`.
pub fn base_url(protocol: Protocol, ip: IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(v4) => format!("{}://{v4}:{port}", protocol.scheme()),
        IpAddr::V6(v6) => format!("{}://[{v6}]:{port}", protocol.scheme()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn announcement_matches_spec_json() {
        let raw = r#"{
            "alias": "Nice Orange",
            "version": "2.0",
            "deviceModel": "Samsung",
            "deviceType": "mobile",
            "fingerprint": "random string",
            "port": 53317,
            "protocol": "https",
            "download": true,
            "announce": true
        }"#;
        let a: Announcement = serde_json::from_str(raw).unwrap();
        assert_eq!(a.info.alias, "Nice Orange");
        assert_eq!(a.info.device_type, DeviceType::Mobile);
        assert_eq!(a.info.protocol, Some(Protocol::Https));
        assert_eq!(a.info.port, Some(53317));
        assert!(a.announce);

        let v: serde_json::Value = serde_json::to_value(&a).unwrap();
        assert_eq!(v["deviceModel"], "Samsung");
        assert_eq!(v["deviceType"], "mobile");
        assert_eq!(v["announce"], true);
        let back: Announcement = serde_json::from_value(v).unwrap();
        assert_eq!(back, a);
    }

    #[test]
    fn info_reply_without_port_is_accepted() {
        let raw = r#"{"alias":"iPhone","version":"2.1","deviceModel":"iPhone 15","deviceType":"mobile","fingerprint":"ABC","download":false}"#;
        let i: DeviceInfo = serde_json::from_str(raw).unwrap();
        assert_eq!(i.port, None);
        assert_eq!(i.port_or_default(), DEFAULT_PORT);
        assert_eq!(i.protocol_or_default(), Protocol::Https);
    }

    #[test]
    fn prepare_upload_round_trip() {
        let raw = r#"{
            "info": {"alias":"Nice Orange","version":"2.0","deviceModel":"Samsung","deviceType":"mobile",
                     "fingerprint":"random string","port":53317,"protocol":"https","download":true},
            "files": {
                "some file id": {"id":"some file id","fileName":"my image.png","size":324242,"fileType":"image/jpeg",
                                 "sha256":"abc","preview":null,
                                 "metadata":{"modified":"2021-01-01T12:00:00Z","accessed":"2021-01-01T12:00:00Z"}},
                "msg": {"id":"msg","fileName":"hello.txt","size":5,"fileType":"text/plain","preview":"hello"}
            }
        }"#;
        let req: PrepareUploadRequest = serde_json::from_str(raw).unwrap();
        assert_eq!(req.files.len(), 2);
        assert_eq!(req.files["some file id"].file_name, "my image.png");
        assert!(!req.files["some file id"].is_text_message());
        assert!(req.files["msg"].is_text_message());

        let json = serde_json::to_string(&req).unwrap();
        let back: PrepareUploadRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, req);
        // Optional fields that are None are omitted, as the spec marks them optional.
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v["files"]["msg"].get("sha256").is_none());
        assert_eq!(v["files"]["msg"]["fileName"], "hello.txt");

        let resp = PrepareUploadResponse {
            session_id: "mySessionId".into(),
            files: HashMap::from([("some file id".to_string(), "someFileToken".to_string())]),
        };
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["sessionId"], "mySessionId");
        assert_eq!(v["files"]["some file id"], "someFileToken");
        let back: PrepareUploadResponse = serde_json::from_value(v).unwrap();
        assert_eq!(back, resp);
    }

    #[test]
    fn base_url_formats_v4_and_v6() {
        assert_eq!(base_url(Protocol::Https, "192.168.12.7".parse().unwrap(), 53317), "https://192.168.12.7:53317");
        assert_eq!(base_url(Protocol::Http, "::1".parse().unwrap(), 1), "http://[::1]:1");
    }
}
