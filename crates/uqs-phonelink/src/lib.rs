//! Universal Quick Share — Microsoft Link to Windows / Phone Link (`uqs-phonelink`).
//!
//! Implements the reverse-engineered Microsoft Link to Windows (`com.microsoft.appmanager`)
//! protocol over `pbvalueset::ValueSet`, `side_channel::v1`, and CDP/NanoAPI framing (TCP port 5040
//! & BLE UUIDs `df444d48-ae6b-494e-a95c-50a4a0055d30` / `eedd2140-424a-4fb5-ad72-1e86dd0b2f0a`):
//! - **Clipboard Sync (`PCPhoneCopy` / `copypaste_metadata`)** with Linux Wayland/X11 clipboard bridge
//! - **SMS/MMS Messaging (`MESSAGES_SMS`, `requestType` 0..3 & `MessageRequestHandler` RPCs)**
//! - **Phone Calls (`DIAL_ON_PHONE` & `CALL_LOGS`)**

use std::collections::HashMap;
use std::io::Write;
use std::net::SocketAddr;
use std::process::{Command, Stdio};

use prost::Message;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use uqs_proto::pbvalueset::{DataValueType, DataVariant, ValueSet};
use uqs_proto::side_channel::v1::{
    side_channel_client_request, SideChannelClientRequest, SideChannelTraceContext,
    SideChannelWakeRequest,
};

/// Default Microsoft Connected Devices Platform (CDP / Project Rome) TCP port.
pub const CDP_DEFAULT_TCP_PORT: u16 = 5040;

/// BLE Service Data UUID scanned by `com.microsoft.mmx.agents.ypp.ambientexperience.providers.bluetooth.discovery.e`.
pub const LTW_BLE_DISCOVERY_UUID: &str = "df444d48-ae6b-494e-a95c-50a4a0055d30";

/// BLE GATT Signaling Service & Characteristic UUIDs (`Pa.a` / `BleSignalingSocketClient`).
pub const LTW_GATT_SIGNALING_SERVICE_UUID: &str = "eedd2140-424a-4fb5-ad72-1e86dd0b2f0a";
pub const LTW_GATT_SIGNALING_WRITE_UUID: &str = "eedd2140-0000-4fb5-ad72-1e86dd0b2f0a";
pub const LTW_GATT_SIGNALING_NOTIFY_UUID: &str = "eedd2140-0000-0000-ad72-1e86dd0b2f0a";

/// Bluetooth RFCOMM/BLE SideChannel UUID (`com.microsoft.mmx.agents.ypp.sidechannel.bluetooth.h`).
pub const LTW_BLUETOOTH_SIDECHANNEL_UUID: &str = "111FAB8F-00A2-4935-B6B4-ACA388CDD473";

/// Microsoft Bluetooth SIG Company Identifier (`BluetoothWrapperImpl.MICROSOFT_COMPANY_ID = 6`).
pub const MICROSOFT_COMPANY_ID: u16 = 0x0006;

#[derive(Debug, Error)]
pub enum PhoneLinkError {
    #[error("protobuf decode error: {0}")]
    ProtoDecode(#[from] prost::DecodeError),
    #[error("missing required ValueSet key: {0}")]
    MissingKey(&'static str),
    #[error("unexpected ValueSet contentType: {0}")]
    UnexpectedContentType(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Linux clipboard tool error: {0}")]
    ClipboardTool(String),
}

// ---------------------------------------------------------------------------
// ValueSet Builder & Reader Helpers (`value_set/valueset.proto`)
// ---------------------------------------------------------------------------

pub fn variant_string(val: impl Into<String>) -> DataVariant {
    DataVariant {
        value_type: DataValueType::String as i32,
        string_value: val.into(),
        ..Default::default()
    }
}

pub fn variant_string_array(vals: Vec<String>) -> DataVariant {
    DataVariant {
        value_type: DataValueType::StringArray as i32,
        string_array: vals,
        ..Default::default()
    }
}

pub fn variant_int32(val: i32) -> DataVariant {
    DataVariant {
        value_type: DataValueType::Int32 as i32,
        int32_value: val,
        ..Default::default()
    }
}

pub fn variant_int64(val: i64) -> DataVariant {
    DataVariant {
        value_type: DataValueType::Int64 as i32,
        int64_value: val,
        ..Default::default()
    }
}

pub fn variant_bool(val: bool) -> DataVariant {
    DataVariant {
        value_type: DataValueType::Bool as i32,
        bool_value: val,
        ..Default::default()
    }
}

pub fn variant_bytes(bytes: Vec<u8>) -> DataVariant {
    DataVariant {
        value_type: DataValueType::UInt8Array as i32,
        uint8_array: bytes,
        ..Default::default()
    }
}

pub fn get_vs_string<'a>(vs: &'a ValueSet, key: &str) -> Option<&'a str> {
    vs.entries.get(key).and_then(|v| {
        if v.value_type == DataValueType::String as i32 {
            Some(v.string_value.as_str())
        } else {
            None
        }
    })
}

pub fn get_vs_string_array<'a>(vs: &'a ValueSet, key: &str) -> Option<&'a [String]> {
    vs.entries.get(key).and_then(|v| {
        if v.value_type == DataValueType::StringArray as i32 {
            Some(v.string_array.as_slice())
        } else {
            None
        }
    })
}

pub fn get_vs_int32(vs: &ValueSet, key: &str) -> Option<i32> {
    vs.entries.get(key).and_then(|v| {
        if v.value_type == DataValueType::Int32 as i32 {
            Some(v.int32_value)
        } else {
            None
        }
    })
}

pub fn get_vs_int64(vs: &ValueSet, key: &str) -> Option<i64> {
    vs.entries.get(key).and_then(|v| {
        if v.value_type == DataValueType::Int64 as i32 {
            Some(v.int64_value)
        } else {
            None
        }
    })
}

pub fn get_vs_bytes<'a>(vs: &'a ValueSet, key: &str) -> Option<&'a [u8]> {
    vs.entries.get(key).and_then(|v| {
        if v.value_type == DataValueType::UInt8Array as i32 {
            Some(v.uint8_array.as_slice())
        } else {
            None
        }
    })
}

// ---------------------------------------------------------------------------
// 1. Cross-Device Copy & Paste (`PCPhoneCopy` & `copypaste_metadata`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClipboardContent {
    Text {
        plain: String,
        html: Option<String>,
    },
    Image {
        mime_type: String,
        bytes: Vec<u8>,
    },
}

/// Build a serialized `pbvalueset::ValueSet` for PC -> Phone clipboard copy
/// (`com.microsoft.mmx.agents.M` case 4: `ContentTransferClipboardRequestHandler`).
pub fn build_pc_to_phone_clipboard_valueset(
    content: &ClipboardContent,
    correlation_vector: &str,
) -> Vec<u8> {
    let mut entries = HashMap::new();
    entries.insert("contentType".to_string(), variant_string("PCPhoneCopy"));
    entries.insert(
        "correlationVector".to_string(),
        variant_string(correlation_vector),
    );

    match content {
        ClipboardContent::Text { plain, html } => {
            if let Some(h) = html {
                entries.insert(
                    "mimetypes".to_string(),
                    variant_string_array(vec!["text/html".to_string(), "text/plain".to_string()]),
                );
                entries.insert(
                    "data".to_string(),
                    variant_string_array(vec![h.clone(), plain.clone()]),
                );
            } else {
                entries.insert(
                    "mimetypes".to_string(),
                    variant_string_array(vec!["text/plain".to_string()]),
                );
                entries.insert(
                    "data".to_string(),
                    variant_string_array(vec![plain.clone()]),
                );
            }
        }
        ClipboardContent::Image { mime_type, bytes } => {
            entries.insert(
                "mimetypes".to_string(),
                variant_string_array(vec![mime_type.clone()]),
            );
            entries.insert("image_bytes".to_string(), variant_bytes(bytes.clone()));
        }
    }

    ValueSet { entries }.encode_to_vec()
}

/// Parse an incoming `ValueSet` carrying `"PCPhoneCopy"` or `"copypaste_metadata"`
/// (`com.microsoft.mmx.agents.C0256h0` / `M.java` case 4).
pub fn parse_clipboard_valueset(raw_bytes: &[u8]) -> Result<ClipboardContent, PhoneLinkError> {
    let vs = ValueSet::decode(raw_bytes)?;
    if let Some(ct) = get_vs_string(&vs, "contentType") {
        if ct != "PCPhoneCopy" && ct != "copypaste_metadata" && ct != "COPY_METADATA" {
            return Err(PhoneLinkError::UnexpectedContentType(ct.to_string()));
        }
    }

    let mimetypes = get_vs_string_array(&vs, "mimetypes")
        .ok_or(PhoneLinkError::MissingKey("mimetypes"))?;

    if let Some(img_bytes) = get_vs_bytes(&vs, "image_bytes") {
        if !img_bytes.is_empty() {
            let mime = mimetypes
                .first()
                .cloned()
                .unwrap_or_else(|| "image/png".to_string());
            return Ok(ClipboardContent::Image {
                mime_type: mime,
                bytes: img_bytes.to_vec(),
            });
        }
    }

    let data = get_vs_string_array(&vs, "data").ok_or(PhoneLinkError::MissingKey("data"))?;
    let mut plain = String::new();
    let mut html = None;

    for (mime, val) in mimetypes.iter().zip(data.iter()) {
        if mime == "text/html" {
            html = Some(val.clone());
        } else if mime.starts_with("text/") && plain.is_empty() {
            plain = val.clone();
        }
    }
    if plain.is_empty() {
        if let Some(first) = data.first() {
            plain = first.clone();
        }
    }

    Ok(ClipboardContent::Text { plain, html })
}

// ---------------------------------------------------------------------------
// 2. SMS / MMS Messaging (`MESSAGES_SMS` & `MessageRequestHandler`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum SmsRequestType {
    SyncMetadataAndContent = 0,
    FetchContentOnly = 1,
    SendMessage = 2,
    MarkAsRead = 3,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutgoingSmsRequest {
    pub recipients: Vec<String>,
    pub body: String,
    pub thread_id: Option<i64>,
    pub subscription_id: Option<i32>,
    pub temp_id: String,
    pub correlation_vector: String,
}

/// Build a `pbvalueset::ValueSet` to send an SMS message via Link to Windows
/// (`com.microsoft.mmx.agents.M` case 9 -> `com.microsoft.cll.android.w:562–718`).
pub fn build_send_sms_valueset(req: &OutgoingSmsRequest) -> Vec<u8> {
    let mut entries = HashMap::new();
    entries.insert("contentType".to_string(), variant_string("MESSAGES_SMS"));
    entries.insert(
        "correlationVector".to_string(),
        variant_string(&req.correlation_vector),
    );
    entries.insert(
        "requestType".to_string(),
        variant_int32(SmsRequestType::SendMessage as i32),
    );
    entries.insert("sendMessage".to_string(), variant_bool(true));
    entries.insert(
        "threadId".to_string(),
        variant_int64(req.thread_id.unwrap_or(-1)),
    );
    entries.insert(
        "subscriptionId".to_string(),
        variant_int32(req.subscription_id.unwrap_or(-1)),
    );
    entries.insert(
        "recipients".to_string(),
        variant_string_array(req.recipients.clone()),
    );
    entries.insert(
        "toAddresses".to_string(),
        variant_string(req.recipients.join(",")),
    );
    entries.insert("tempId".to_string(), variant_string(&req.temp_id));
    entries.insert("body".to_string(), variant_string(&req.body));
    entries.insert("partCount".to_string(), variant_int32(0));

    ValueSet { entries }.encode_to_vec()
}

/// Build a `pbvalueset::ValueSet` requesting SMS conversation/message synchronization (`requestType = 0`).
pub fn build_sync_sms_valueset(correlation_vector: &str) -> Vec<u8> {
    let mut entries = HashMap::new();
    entries.insert("contentType".to_string(), variant_string("MESSAGES_SMS"));
    entries.insert(
        "correlationVector".to_string(),
        variant_string(correlation_vector),
    );
    entries.insert(
        "requestType".to_string(),
        variant_int32(SmsRequestType::SyncMetadataAndContent as i32),
    );
    ValueSet { entries }.encode_to_vec()
}

/// Build a `pbvalueset::ValueSet` to mark an SMS conversation thread as read (`requestType = 3`).
pub fn build_mark_conversation_read_valueset(thread_id: i64, correlation_vector: &str) -> Vec<u8> {
    let mut entries = HashMap::new();
    entries.insert("contentType".to_string(), variant_string("MESSAGES_SMS"));
    entries.insert(
        "correlationVector".to_string(),
        variant_string(correlation_vector),
    );
    entries.insert(
        "requestType".to_string(),
        variant_int32(SmsRequestType::MarkAsRead as i32),
    );
    entries.insert("threadId".to_string(), variant_int64(thread_id));
    ValueSet { entries }.encode_to_vec()
}

/// Parse an SMS send request from a `pbvalueset::ValueSet`.
pub fn parse_send_sms_valueset(raw_bytes: &[u8]) -> Result<OutgoingSmsRequest, PhoneLinkError> {
    let vs = ValueSet::decode(raw_bytes)?;
    let ct = get_vs_string(&vs, "contentType").unwrap_or("");
    if ct != "MESSAGES_SMS" && ct != "messaging" {
        return Err(PhoneLinkError::UnexpectedContentType(ct.to_string()));
    }
    let recipients = get_vs_string_array(&vs, "recipients")
        .map(|s| s.to_vec())
        .or_else(|| {
            get_vs_string(&vs, "toAddresses")
                .map(|s| s.split(',').map(|p| p.trim().to_string()).collect())
        })
        .ok_or(PhoneLinkError::MissingKey("recipients"))?;

    let body = get_vs_string(&vs, "body")
        .ok_or(PhoneLinkError::MissingKey("body"))?
        .to_string();
    let thread_id = get_vs_int64(&vs, "threadId").filter(|&id| id != -1);
    let subscription_id = get_vs_int32(&vs, "subscriptionId").filter(|&id| id != -1);
    let temp_id = get_vs_string(&vs, "tempId")
        .unwrap_or("temp-0")
        .to_string();
    let correlation_vector = get_vs_string(&vs, "correlationVector")
        .unwrap_or("uqs.0")
        .to_string();

    Ok(OutgoingSmsRequest {
        recipients,
        body,
        thread_id,
        subscription_id,
        temp_id,
        correlation_vector,
    })
}

// ---------------------------------------------------------------------------
// 3. Phone Calls (`DIAL_ON_PHONE` & `CALL_LOGS`, `M.java` cases 1 & 6)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DialCallRequest {
    pub phone_number: String,
    pub correlation_vector: String,
}

/// Build a `pbvalueset::ValueSet` for `DialCommandRequestHandler` (`M.java:647–656`).
pub fn build_dial_call_valueset(phone_number: &str, correlation_vector: &str) -> Vec<u8> {
    let mut entries = HashMap::new();
    entries.insert("contentType".to_string(), variant_string("DIAL_ON_PHONE"));
    entries.insert("phoneNumber".to_string(), variant_string(phone_number));
    entries.insert(
        "correlationVector".to_string(),
        variant_string(correlation_vector),
    );
    ValueSet { entries }.encode_to_vec()
}

/// Parse a `DIAL_ON_PHONE` `ValueSet`.
pub fn parse_dial_call_valueset(raw_bytes: &[u8]) -> Result<DialCallRequest, PhoneLinkError> {
    let vs = ValueSet::decode(raw_bytes)?;
    let ct = get_vs_string(&vs, "contentType").unwrap_or("");
    if ct != "DIAL_ON_PHONE" {
        return Err(PhoneLinkError::UnexpectedContentType(ct.to_string()));
    }
    let phone_number = get_vs_string(&vs, "phoneNumber")
        .ok_or(PhoneLinkError::MissingKey("phoneNumber"))?
        .to_string();
    let correlation_vector = get_vs_string(&vs, "correlationVector")
        .unwrap_or("uqs.0")
        .to_string();
    Ok(DialCallRequest {
        phone_number,
        correlation_vector,
    })
}

/// Build a `SideChannelClientRequest` Wake request (`side_channel/v1/main.proto`).
pub fn build_sidechannel_wake_request(trace_id: &str) -> Vec<u8> {
    SideChannelClientRequest {
        context: Some(SideChannelTraceContext {
            trace_id: trace_id.to_string(),
            ..Default::default()
        }),
        request: Some(side_channel_client_request::Request::WakeRequest(
            SideChannelWakeRequest {},
        )),
        authorization: None,
    }
    .encode_to_vec()
}

// ---------------------------------------------------------------------------
// 4. Linux System Clipboard Integration (`wl-paste`/`wl-copy`, `xclip`, `xsel`)
// ---------------------------------------------------------------------------

/// Read current text from the local Linux clipboard (Wayland `wl-paste` or X11 `xclip`/`xsel`).
pub fn read_linux_clipboard_text() -> Result<String, PhoneLinkError> {
    let candidates: &[(&str, &[&str])] = &[
        ("wl-paste", &["--no-newline"]),
        ("xclip", &["-selection", "clipboard", "-o"]),
        ("xsel", &["--clipboard", "--output"]),
    ];
    for (bin, args) in candidates {
        if let Ok(output) = Command::new(bin).args(*args).output() {
            if output.status.success() {
                return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
            }
        }
    }
    Err(PhoneLinkError::ClipboardTool(
        "Neither wl-paste, xclip, nor xsel succeeded".into(),
    ))
}

/// Write text to the local Linux clipboard (Wayland `wl-copy` or X11 `xclip`/`xsel`).
pub fn write_linux_clipboard_text(text: &str) -> Result<(), PhoneLinkError> {
    let candidates: &[(&str, &[&str])] = &[
        ("wl-copy", &[]),
        ("xclip", &["-selection", "clipboard", "-i"]),
        ("xsel", &["--clipboard", "--input"]),
    ];
    for (bin, args) in candidates {
        if let Ok(mut child) = Command::new(bin)
            .args(*args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(text.as_bytes());
            }
            if let Ok(status) = child.wait() {
                if status.success() {
                    return Ok(());
                }
            }
        }
    }
    Err(PhoneLinkError::ClipboardTool(
        "Neither wl-copy, xclip, nor xsel succeeded".into(),
    ))
}

// ---------------------------------------------------------------------------
// 5. CDP / PhoneLink TCP Port 5040 Wire Framing & Session Node
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PhoneLinkEvent {
    ClipboardReceived(ClipboardContent),
    SmsReceived(OutgoingSmsRequest),
    CallDialRequested(DialCallRequest),
}

/// Send a 4-byte BE length-prefixed `ValueSet` packet to a peer on TCP (default port 5040).
pub async fn send_phonelink_valueset(
    addr: SocketAddr,
    valueset_bytes: &[u8],
) -> Result<(), PhoneLinkError> {
    let mut stream = TcpStream::connect(addr).await?;
    let len = (valueset_bytes.len() as u32).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(valueset_bytes).await?;
    stream.flush().await?;
    Ok(())
}

/// Decode any incoming `pbvalueset::ValueSet` packet into a strongly typed `PhoneLinkEvent`.
pub fn decode_phonelink_valueset(raw_bytes: &[u8]) -> Result<PhoneLinkEvent, PhoneLinkError> {
    let vs = ValueSet::decode(raw_bytes)?;
    let ct = get_vs_string(&vs, "contentType").unwrap_or("");
    match ct {
        "PCPhoneCopy" | "copypaste_metadata" | "COPY_METADATA" => {
            Ok(PhoneLinkEvent::ClipboardReceived(parse_clipboard_valueset(
                raw_bytes,
            )?))
        }
        "MESSAGES_SMS" | "messaging" => {
            Ok(PhoneLinkEvent::SmsReceived(parse_send_sms_valueset(
                raw_bytes,
            )?))
        }
        "DIAL_ON_PHONE" => Ok(PhoneLinkEvent::CallDialRequested(parse_dial_call_valueset(
            raw_bytes,
        )?)),
        other => Err(PhoneLinkError::UnexpectedContentType(other.to_string())),
    }
}

/// Accept one incoming Phone Link connection and decode its `PhoneLinkEvent`.
pub async fn accept_one_phonelink_event(
    listener: &TcpListener,
) -> Result<(SocketAddr, PhoneLinkEvent), PhoneLinkError> {
    let (mut stream, peer) = listener.accept().await?;
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    let ev = decode_phonelink_valueset(&buf)?;
    Ok((peer, ev))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_pc_to_phone_clipboard_text_and_html() {
        let content = ClipboardContent::Text {
            plain: "Copied on Kali Linux".to_string(),
            html: Some("<b>Copied on Kali Linux</b>".to_string()),
        };
        let bytes = build_pc_to_phone_clipboard_valueset(&content, "uqs.cv.1");
        let ev = decode_phonelink_valueset(&bytes).unwrap();
        match ev {
            PhoneLinkEvent::ClipboardReceived(decoded) => assert_eq!(decoded, content),
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn roundtrip_pc_to_phone_clipboard_image() {
        let content = ClipboardContent::Image {
            mime_type: "image/png".to_string(),
            bytes: vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a],
        };
        let bytes = build_pc_to_phone_clipboard_valueset(&content, "uqs.cv.2");
        let parsed = parse_clipboard_valueset(&bytes).unwrap();
        assert_eq!(parsed, content);
    }

    #[test]
    fn roundtrip_send_sms_valueset() {
        let req = OutgoingSmsRequest {
            recipients: vec!["+15550192834".to_string()],
            body: "Hello from Universal Quick Share on Linux!".to_string(),
            thread_id: Some(42),
            subscription_id: Some(1),
            temp_id: "uuid-1234".to_string(),
            correlation_vector: "uqs.sms.1".to_string(),
        };
        let bytes = build_send_sms_valueset(&req);
        let ev = decode_phonelink_valueset(&bytes).unwrap();
        match ev {
            PhoneLinkEvent::SmsReceived(decoded) => assert_eq!(decoded, req),
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn roundtrip_dial_call_valueset() {
        let bytes = build_dial_call_valueset("+15559876543", "uqs.call.1");
        let ev = decode_phonelink_valueset(&bytes).unwrap();
        match ev {
            PhoneLinkEvent::CallDialRequested(call) => {
                assert_eq!(call.phone_number, "+15559876543");
                assert_eq!(call.correlation_vector, "uqs.call.1");
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[tokio::test]
    async fn tcp_phonelink_event_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            accept_one_phonelink_event(&listener).await.unwrap().1
        });

        let payload = build_dial_call_valueset("+18005551212", "uqs.call.9");
        send_phonelink_valueset(addr, &payload).await.unwrap();

        let ev = server.await.unwrap();
        match ev {
            PhoneLinkEvent::CallDialRequested(c) => assert_eq!(c.phone_number, "+18005551212"),
            other => panic!("unexpected: {other:?}"),
        }
    }
}
