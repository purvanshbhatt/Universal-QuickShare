//! Quick Share file, text, and WiFi-credential receive & send session state machines.

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use prost::Message;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::fs::{self, File};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::net::TcpStream;

use uqs_proto::location::nearby::connections::{
    connection_request_frame, connection_response_frame, offline_frame, os_info,
    payload_transfer_frame::{
        control_message, payload_chunk, payload_header, ControlMessage, PacketType, PayloadChunk,
        PayloadHeader,
    },
    v1_frame as off_v1, ConnectionRequestFrame, ConnectionResponseFrame as OffConnResp,
    KeepAliveFrame, OfflineFrame, OsInfo, PayloadTransferFrame, V1Frame as OffV1Frame,
};
use uqs_proto::nearby::sharing::service::proto::{
    connection_response_frame as share_resp, file_metadata, frame as share_frame,
    paired_key_result_frame, v1_frame as share_v1, ConnectionResponseFrame as ShareConnResp,
    text_metadata, FileMetadata, Frame as ShareFrame, IntroductionFrame,
    PairedKeyEncryptionFrame, PairedKeyResultFrame, TextMetadata, V1Frame as ShareV1Frame,
    WifiCredentials,
};

use crate::d2d::{D2DError, SecureChannel};
use crate::framing::{recv_frame, send_frame, FrameError};
use crate::mdns::{build_endpoint_info, parse_endpoint_info, ShareTargetType};
use crate::ukey2::{run_client_handshake, run_server_handshake, Ukey2Error};

pub const CHUNK_SIZE: usize = 64 * 1024;

#[derive(Debug, Error)]
pub enum TransferError {
    #[error("framing error: {0}")]
    Framing(#[from] FrameError),
    #[error("UKEY2 error: {0}")]
    Ukey2(#[from] Ukey2Error),
    #[error("D2D encryption error: {0}")]
    D2d(#[from] D2DError),
    #[error("protobuf decode error: {0}")]
    ProtoDecode(#[from] prost::DecodeError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol violation: {0}")]
    Protocol(&'static str),
    #[error("transfer declined or canceled by peer")]
    DeclinedOrCanceled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReceivedItem {
    File {
        name: String,
        path: PathBuf,
        size: u64,
    },
    Text {
        title: String,
        body: String,
    },
    WifiCredentials {
        ssid: String,
        password: String,
        security_type: i32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferOffer {
    pub peer_name: String,
    pub pin: String,
    pub files: Vec<OfferedFile>,
    pub texts: Vec<OfferedText>,
    pub wifi_ssids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfferedFile {
    pub payload_id: i64,
    pub name: String,
    pub size: u64,
    pub mime_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfferedText {
    pub payload_id: i64,
    pub title: String,
    pub size: u64,
}

/// `TextMetadata.Type` — tells the receiver how to present a text attachment
/// (Android opens URLs in the browser, dials phone numbers, maps addresses).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutgoingTextKind {
    Text,
    Url,
    Address,
    PhoneNumber,
}

impl OutgoingTextKind {
    /// Guess the kind from the content: `http(s)://` → URL, digits/`+` only → phone number.
    pub fn guess(body: &str) -> Self {
        let t = body.trim();
        let lower = t.to_ascii_lowercase();
        if (lower.starts_with("http://") || lower.starts_with("https://"))
            && !t.contains(char::is_whitespace)
        {
            return Self::Url;
        }
        let digits = t.chars().filter(|c| c.is_ascii_digit()).count();
        if digits >= 7
            && t.chars()
                .all(|c| c.is_ascii_digit() || matches!(c, '+' | ' ' | '-' | '(' | ')'))
        {
            return Self::PhoneNumber;
        }
        Self::Text
    }

    fn proto_type(self) -> i32 {
        match self {
            Self::Text => text_metadata::Type::Text as i32,
            Self::Url => text_metadata::Type::Url as i32,
            Self::Address => text_metadata::Type::Address as i32,
            Self::PhoneNumber => text_metadata::Type::PhoneNumber as i32,
        }
    }
}

/// Something the local side wants to share: a file on disk or a text/URL snippet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutgoingItem {
    File(PathBuf),
    Text {
        kind: OutgoingTextKind,
        /// Shown in the receiver's notification (`TextMetadata.text_title`).
        title: String,
        body: String,
    },
}

impl OutgoingItem {
    /// Build a text item, guessing the kind and deriving a short title from the body.
    pub fn text(body: impl Into<String>) -> Self {
        let body = body.into();
        let kind = OutgoingTextKind::guess(&body);
        let first_line = body.lines().next().unwrap_or("").trim();
        let mut title: String = first_line.chars().take(60).collect();
        if title.len() < first_line.len() {
            title.push('…');
        }
        if title.is_empty() {
            title = "Text".to_string();
        }
        Self::Text { kind, title, body }
    }

    /// Interpret clipboard text the way a share sheet would: `file://` URIs (what Thunar,
    /// Nautilus and Dolphin put on the clipboard on Copy) become file items when they all
    /// exist on disk; anything else becomes one text item. Empty clipboard → empty vec.
    pub fn from_clipboard_text(clip: &str) -> Vec<Self> {
        if clip.trim().is_empty() {
            return Vec::new();
        }
        let lines: Vec<&str> = clip
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && *l != "copy" && *l != "cut")
            .collect();
        let uris: Vec<PathBuf> = lines
            .iter()
            .filter_map(|l| l.strip_prefix("file://").map(percent_decode_path))
            .collect();
        if !uris.is_empty() && uris.len() == lines.len() && uris.iter().all(|p| p.is_file()) {
            uris.into_iter().map(Self::File).collect()
        } else {
            vec![Self::text(clip.to_string())]
        }
    }
}

/// Minimal `%XX` decoding for `file://` URIs (`%20` → space, etc.).
fn percent_decode_path(s: &str) -> PathBuf {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    PathBuf::from(String::from_utf8_lossy(&out).into_owned())
}

/// Sanitize an untrusted filename offered by a remote peer (prevents `../` and `..\` traversal).
pub fn sanitize_offered_name(raw: &str) -> String {
    let before_nul = raw.split('\0').next().unwrap_or("");
    let normalized = before_nul.replace('\\', "/");
    let base = normalized.rsplit('/').next().unwrap_or("");
    let trimmed = base.trim_start_matches('.');
    if trimmed.is_empty() {
        "unnamed_file".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Pick a non-colliding file destination inside `output_dir`.
pub fn unique_destination(output_dir: &Path, safe_name: &str) -> PathBuf {
    let base_candidate = output_dir.join(safe_name);
    if !base_candidate.exists() {
        return base_candidate;
    }
    let path_obj = Path::new(safe_name);
    let stem = path_obj
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(safe_name);
    let ext = path_obj
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| format!(".{e}"))
        .unwrap_or_default();

    let mut counter = 1u32;
    loop {
        let candidate = output_dir.join(format!("{stem} ({counter}){ext}"));
        if !candidate.exists() {
            return candidate;
        }
        counter += 1;
    }
}

fn next_positive_payload_id() -> i64 {
    let mut buf = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut buf);
    let val = (u64::from_be_bytes(buf) >> 1) as i64;
    if val == 0 { 1 } else { val }
}

pub fn build_transport_connection_response_accept() -> Vec<u8> {
    OfflineFrame {
        version: Some(offline_frame::Version::V1 as i32),
        v1: Some(OffV1Frame {
            r#type: Some(off_v1::FrameType::ConnectionResponse as i32),
            connection_response: Some(OffConnResp {
                response: Some(connection_response_frame::ResponseStatus::Accept as i32),
                os_info: Some(OsInfo {
                    r#type: Some(os_info::OsType::Linux as i32),
                }),
                multiplex_socket_bitmask: Some(0),
                safe_to_disconnect_version: Some(0),
                ..Default::default()
            }),
            ..Default::default()
        }),
    }
    .encode_to_vec()
}

pub fn build_keep_alive_frame() -> Vec<u8> {
    build_keep_alive_frame_with_ack(false)
}

/// Nearby Connections answers every received `KEEP_ALIVE` with `ack=true`; a peer that
/// stays silent for ~30 s is disconnected, so both sides must keep answering while idle.
pub fn build_keep_alive_frame_with_ack(ack: bool) -> Vec<u8> {
    OfflineFrame {
        version: Some(offline_frame::Version::V1 as i32),
        v1: Some(OffV1Frame {
            r#type: Some(off_v1::FrameType::KeepAlive as i32),
            keep_alive: Some(KeepAliveFrame {
                ack: Some(ack),
                seq_num: None,
            }),
            ..Default::default()
        }),
    }
    .encode_to_vec()
}

pub fn wrap_offline_bytes_payload(sharing_frame_bytes: &[u8]) -> [Vec<u8>; 2] {
    wrap_offline_bytes_payload_with_id(next_positive_payload_id(), sharing_frame_bytes)
}

/// Wrap raw bytes into a 2-frame BYTES payload (data chunk + LAST_CHUNK terminator) with a
/// caller-chosen `payload_id`, so a `TextMetadata.payload_id` announced in the Introduction
/// can be matched to the text body that follows.
pub fn wrap_offline_bytes_payload_with_id(payload_id: i64, sharing_frame_bytes: &[u8]) -> [Vec<u8>; 2] {
    let total_size = sharing_frame_bytes.len() as i64;

    let data_frame = OfflineFrame {
        version: Some(offline_frame::Version::V1 as i32),
        v1: Some(OffV1Frame {
            r#type: Some(off_v1::FrameType::PayloadTransfer as i32),
            payload_transfer: Some(PayloadTransferFrame {
                packet_type: Some(PacketType::Data as i32),
                payload_header: Some(PayloadHeader {
                    id: Some(payload_id),
                    r#type: Some(payload_header::PayloadType::Bytes as i32),
                    total_size: Some(total_size),
                    is_sensitive: Some(false),
                    file_name: None,
                    parent_folder: None,
                    last_modified_timestamp_millis: None,
                }),
                payload_chunk: Some(PayloadChunk {
                    flags: Some(0),
                    offset: Some(0),
                    body: Some(sharing_frame_bytes.to_vec()),
                    index: None,
                }),
                control_message: None,
            }),
            ..Default::default()
        }),
    }
    .encode_to_vec();

    let terminator = OfflineFrame {
        version: Some(offline_frame::Version::V1 as i32),
        v1: Some(OffV1Frame {
            r#type: Some(off_v1::FrameType::PayloadTransfer as i32),
            payload_transfer: Some(PayloadTransferFrame {
                packet_type: Some(PacketType::Data as i32),
                payload_header: Some(PayloadHeader {
                    id: Some(payload_id),
                    r#type: Some(payload_header::PayloadType::Bytes as i32),
                    total_size: Some(total_size),
                    is_sensitive: Some(false),
                    file_name: None,
                    parent_folder: None,
                    last_modified_timestamp_millis: None,
                }),
                payload_chunk: Some(PayloadChunk {
                    flags: Some(payload_chunk::Flags::LastChunk as i32),
                    offset: Some(total_size),
                    body: Some(Vec::new()),
                    index: None,
                }),
                control_message: None,
            }),
            ..Default::default()
        }),
    }
    .encode_to_vec();

    [data_frame, terminator]
}

pub fn build_paired_key_encryption_frames(qr_signature: Option<&[u8]>) -> [Vec<u8>; 2] {
    let mut secret_id_hash = vec![0u8; 6];
    let mut signed_data = vec![0u8; 72];
    rand::thread_rng().fill_bytes(&mut secret_id_hash);
    rand::thread_rng().fill_bytes(&mut signed_data);

    let frame = ShareFrame {
        version: Some(share_frame::Version::V1 as i32),
        v1: Some(ShareV1Frame {
            r#type: Some(share_v1::FrameType::PairedKeyEncryption as i32),
            paired_key_encryption: Some(PairedKeyEncryptionFrame {
                signed_data: Some(signed_data),
                secret_id_hash: Some(secret_id_hash),
                optional_signed_data: None,
                qr_code_handshake_data: qr_signature.map(|s| s.to_vec()),
            }),
            ..Default::default()
        }),
    }
    .encode_to_vec();

    wrap_offline_bytes_payload(&frame)
}

pub fn build_paired_key_result_unable_frames() -> [Vec<u8>; 2] {
    let frame = ShareFrame {
        version: Some(share_frame::Version::V1 as i32),
        v1: Some(ShareV1Frame {
            r#type: Some(share_v1::FrameType::PairedKeyResult as i32),
            paired_key_result: Some(PairedKeyResultFrame {
                status: Some(paired_key_result_frame::Status::Unable as i32),
                os_type: None,
            }),
            ..Default::default()
        }),
    }
    .encode_to_vec();

    wrap_offline_bytes_payload(&frame)
}

pub fn build_sharing_response_frames(accept: bool) -> [Vec<u8>; 2] {
    let status = if accept {
        share_resp::Status::Accept as i32
    } else {
        share_resp::Status::Reject as i32
    };
    let frame = ShareFrame {
        version: Some(share_frame::Version::V1 as i32),
        v1: Some(ShareV1Frame {
            r#type: Some(share_v1::FrameType::Response as i32),
            connection_response: Some(ShareConnResp {
                status: Some(status),
                attachment_details: HashMap::new(),
                ..Default::default()
            }),
            ..Default::default()
        }),
    }
    .encode_to_vec();

    wrap_offline_bytes_payload(&frame)
}

pub fn build_payload_received_ack(payload_id: i64, offset: i64) -> Vec<u8> {
    OfflineFrame {
        version: Some(offline_frame::Version::V1 as i32),
        v1: Some(OffV1Frame {
            r#type: Some(off_v1::FrameType::PayloadTransfer as i32),
            payload_transfer: Some(PayloadTransferFrame {
                packet_type: Some(PacketType::Control as i32),
                payload_header: Some(PayloadHeader {
                    id: Some(payload_id),
                    ..Default::default()
                }),
                payload_chunk: None,
                control_message: Some(ControlMessage {
                    event: Some(control_message::EventType::PayloadReceivedAck as i32),
                    offset: Some(offset),
                }),
            }),
            ..Default::default()
        }),
    }
    .encode_to_vec()
}

struct ActiveFileReceive {
    name: String,
    dest_path: PathBuf,
    part_path: PathBuf,
    size: u64,
    bytes_written: u64,
    file: File,
    finalized: bool,
}

/// Handle a single incoming Quick Share TCP connection on the receiver side.
///
/// `confirm_offer` is awaited while the connection keeps answering the peer's `KEEP_ALIVE`
/// frames, so a slow human Accept/Reject (seconds to minutes) no longer makes Android drop
/// the connection. Blocking UI must be wrapped in `tokio::task::spawn_blocking` by the caller.
pub async fn handle_incoming_connection<F, Fut>(
    stream: &mut TcpStream,
    output_dir: &Path,
    confirm_offer: F,
) -> Result<Vec<ReceivedItem>, TransferError>
where
    F: FnMut(TransferOffer) -> Fut,
    Fut: Future<Output = bool>,
{
    handle_incoming_connection_with_progress(stream, output_dir, confirm_offer, |_, _| {}).await
}

/// Like [`handle_incoming_connection`], additionally reporting `(bytes_done, bytes_total)`
/// after every received chunk once the offer is accepted.
pub async fn handle_incoming_connection_with_progress<F, Fut>(
    stream: &mut TcpStream,
    output_dir: &Path,
    mut confirm_offer: F,
    mut on_progress: impl FnMut(u64, u64),
) -> Result<Vec<ReceivedItem>, TransferError>
where
    F: FnMut(TransferOffer) -> Fut,
    Fut: Future<Output = bool>,
{
    let first_bytes = recv_frame(stream).await?;
    let conn_req_frame = OfflineFrame::decode(first_bytes.as_slice())?;
    let v1 = conn_req_frame
        .v1
        .ok_or(TransferError::Protocol("missing OfflineFrame.v1"))?;
    if v1.r#type != Some(off_v1::FrameType::ConnectionRequest as i32) {
        return Err(TransferError::Protocol("expected CONNECTION_REQUEST first"));
    }

    let peer_name = v1
        .connection_request
        .as_ref()
        .and_then(|cr| cr.endpoint_info.as_deref())
        .and_then(|ei| parse_endpoint_info(ei).ok())
        .and_then(|adv| adv.device_name)
        .or_else(|| {
            v1.connection_request
                .as_ref()
                .and_then(|cr| cr.endpoint_name.clone())
        })
        .unwrap_or_else(|| "Android Device".to_string());

    let keys = run_server_handshake(stream).await?;
    send_frame(stream, &build_transport_connection_response_accept()).await?;

    let peer_resp_bytes = recv_frame(stream).await?;
    let peer_resp = OfflineFrame::decode(peer_resp_bytes.as_slice())?;
    if peer_resp.v1.and_then(|v| v.r#type) != Some(off_v1::FrameType::ConnectionResponse as i32) {
        return Err(TransferError::Protocol(
            "expected peer plaintext CONNECTION_RESPONSE",
        ));
    }

    let mut channel = SecureChannel::new(keys);

    for raw in build_paired_key_encryption_frames(None) {
        let enc = channel.encrypt(&raw);
        send_frame(stream, &enc).await?;
    }

    fs::create_dir_all(output_dir).await?;

    let mut bytes_reassembly: HashMap<i64, Vec<u8>> = HashMap::new();
    let mut active_files: HashMap<i64, ActiveFileReceive> = HashMap::new();
    let mut pending_texts: HashMap<i64, OfferedText> = HashMap::new();
    let mut pending_wifi: HashMap<i64, (String, i32)> = HashMap::new();
    let mut completed_items: Vec<ReceivedItem> = Vec::new();
    let mut offer_accepted = false;
    let mut bytes_total: u64 = 0;
    let mut bytes_done: u64 = 0;

    loop {
        let enc_bytes = match recv_frame(stream).await {
            Ok(b) => b,
            Err(FrameError::ConnectionClosedImmediately | FrameError::UnexpectedEof) => break,
            Err(e) => return Err(TransferError::Framing(e)),
        };

        let offline_bytes = channel.decrypt(&enc_bytes)?;
        let off_frame = OfflineFrame::decode(offline_bytes.as_slice())?;
        let Some(v1) = off_frame.v1 else { continue };

        match v1.r#type {
            x if x == Some(off_v1::FrameType::KeepAlive as i32) => {
                let ka = channel.encrypt(&build_keep_alive_frame_with_ack(true));
                send_frame(stream, &ka).await?;
                continue;
            }
            x if x == Some(off_v1::FrameType::Disconnection as i32) => break,
            x if x == Some(off_v1::FrameType::PayloadTransfer as i32) => {}
            _ => continue,
        }

        let Some(pt) = v1.payload_transfer else {
            continue;
        };
        let Some(header) = pt.payload_header else {
            continue;
        };
        let payload_id = header.id.unwrap_or(0);

        if pt.packet_type == Some(PacketType::Control as i32) {
            if let Some(ctrl) = pt.control_message {
                if ctrl.event == Some(control_message::EventType::PayloadCanceled as i32)
                    || ctrl.event == Some(control_message::EventType::PayloadError as i32)
                {
                    for (_, mut af) in active_files.drain() {
                        let _ = af.file.shutdown().await;
                        let _ = fs::remove_file(&af.part_path).await;
                    }
                    return Err(TransferError::DeclinedOrCanceled);
                }
            }
            continue;
        }

        let Some(chunk) = pt.payload_chunk else {
            continue;
        };
        let is_last = (chunk.flags.unwrap_or(0) & (payload_chunk::Flags::LastChunk as i32)) != 0;
        let body = chunk.body.unwrap_or_default();

        if header.r#type == Some(payload_header::PayloadType::Bytes as i32) {
            let buf = bytes_reassembly.entry(payload_id).or_default();
            if !body.is_empty() {
                buf.extend_from_slice(&body);
                if pending_texts.contains_key(&payload_id) {
                    bytes_done += body.len() as u64;
                    on_progress(bytes_done.min(bytes_total), bytes_total);
                }
            }
            if is_last {
                let full_bytes = bytes_reassembly.remove(&payload_id).unwrap_or_default();
                if let Some(text_meta) = pending_texts.remove(&payload_id) {
                    let body_str = String::from_utf8_lossy(&full_bytes).into_owned();
                    let ack = channel.encrypt(&build_payload_received_ack(
                        payload_id,
                        full_bytes.len() as i64,
                    ));
                    send_frame(stream, &ack).await?;
                    completed_items.push(ReceivedItem::Text {
                        title: text_meta.title,
                        body: body_str,
                    });
                } else if let Some((ssid, sec_type)) = pending_wifi.remove(&payload_id) {
                    let creds = WifiCredentials::decode(full_bytes.as_slice())?;
                    let ack = channel.encrypt(&build_payload_received_ack(
                        payload_id,
                        full_bytes.len() as i64,
                    ));
                    send_frame(stream, &ack).await?;
                    completed_items.push(ReceivedItem::WifiCredentials {
                        ssid,
                        password: creds.password.unwrap_or_default(),
                        security_type: sec_type,
                    });
                } else {
                    let share_msg = ShareFrame::decode(full_bytes.as_slice())?;
                    if let Some(sv1) = share_msg.v1 {
                        match sv1.r#type {
                            t if t == Some(share_v1::FrameType::PairedKeyEncryption as i32) => {
                                for raw in build_paired_key_result_unable_frames() {
                                    let enc = channel.encrypt(&raw);
                                    send_frame(stream, &enc).await?;
                                }
                            }
                            t if t == Some(share_v1::FrameType::PairedKeyResult as i32) => {}
                            t if t == Some(share_v1::FrameType::Introduction as i32) => {
                                if let Some(intro) = sv1.introduction {
                                    let offered_files: Vec<OfferedFile> = intro
                                        .file_metadata
                                        .iter()
                                        .map(|m| OfferedFile {
                                            payload_id: m.payload_id.unwrap_or(0),
                                            name: sanitize_offered_name(
                                                m.name.as_deref().unwrap_or("file"),
                                            ),
                                            size: m.size.unwrap_or(0) as u64,
                                            mime_type: m
                                                .mime_type
                                                .clone()
                                                .unwrap_or_else(|| "application/octet-stream".into()),
                                        })
                                        .collect();

                                    let offered_texts: Vec<OfferedText> = intro
                                        .text_metadata
                                        .iter()
                                        .map(|t| OfferedText {
                                            payload_id: t.payload_id.unwrap_or(0),
                                            title: t.text_title.clone().unwrap_or_default(),
                                            size: t.size.unwrap_or(0) as u64,
                                        })
                                        .collect();

                                    let wifi_ssids: Vec<String> = intro
                                        .wifi_credentials_metadata
                                        .iter()
                                        .filter_map(|w| w.ssid.clone())
                                        .collect();

                                    let offer = TransferOffer {
                                        peer_name: peer_name.clone(),
                                        pin: channel.pin.clone(),
                                        files: offered_files.clone(),
                                        texts: offered_texts.clone(),
                                        wifi_ssids,
                                    };

                                    let accept =
                                        await_offer_decision(stream, &mut channel, confirm_offer(offer))
                                            .await?;
                                    offer_accepted = accept;

                                    if accept {
                                        bytes_total = offered_files.iter().map(|f| f.size).sum::<u64>()
                                            + offered_texts.iter().map(|t| t.size).sum::<u64>();
                                        on_progress(0, bytes_total);
                                        for f in offered_files {
                                            let dest_path = unique_destination(output_dir, &f.name);
                                            let part_path = dest_path
                                                .with_file_name(format!("{}.part", f.name));
                                            let file = File::create(&part_path).await?;
                                            active_files.insert(
                                                f.payload_id,
                                                ActiveFileReceive {
                                                    name: f.name,
                                                    dest_path,
                                                    part_path,
                                                    size: f.size,
                                                    bytes_written: 0,
                                                    file,
                                                    finalized: false,
                                                },
                                            );
                                        }
                                        for t in offered_texts {
                                            pending_texts.insert(t.payload_id, t);
                                        }
                                        for w in &intro.wifi_credentials_metadata {
                                            if let (Some(pid), Some(ssid)) =
                                                (w.payload_id, w.ssid.clone())
                                            {
                                                pending_wifi.insert(
                                                    pid,
                                                    (ssid, w.security_type.unwrap_or(0)),
                                                );
                                            }
                                        }
                                    }

                                    for raw in build_sharing_response_frames(accept) {
                                        let enc = channel.encrypt(&raw);
                                        send_frame(stream, &enc).await?;
                                    }

                                    if !accept {
                                        return Err(TransferError::DeclinedOrCanceled);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        } else if header.r#type == Some(payload_header::PayloadType::File as i32) {
            if let Some(af) = active_files.get_mut(&payload_id) {
                if !af.finalized && !body.is_empty() {
                    let offset = chunk.offset.unwrap_or(0) as u64;
                    af.file.seek(std::io::SeekFrom::Start(offset)).await?;
                    af.file.write_all(&body).await?;
                    af.bytes_written += body.len() as u64;
                    bytes_done += body.len() as u64;
                    on_progress(bytes_done.min(bytes_total), bytes_total);
                }
                if (is_last || af.bytes_written >= af.size) && !af.finalized {
                    af.file.flush().await?;
                    af.finalized = true;
                    fs::rename(&af.part_path, &af.dest_path).await?;
                    let ack = channel.encrypt(&build_payload_received_ack(
                        payload_id,
                        af.bytes_written as i64,
                    ));
                    let _ = send_frame(stream, &ack).await;
                    completed_items.push(ReceivedItem::File {
                        name: af.name.clone(),
                        path: af.dest_path.clone(),
                        size: af.size,
                    });
                }
            }
        }

        if offer_accepted
            && active_files.values().all(|f| f.finalized)
            && pending_texts.is_empty()
            && pending_wifi.is_empty()
        {
            break;
        }
    }

    Ok(completed_items)
}

/// Await the user's Accept/Reject decision while servicing the peer's `KEEP_ALIVE`s.
///
/// Returns `Ok(false)` if the peer disconnects or cancels before the user answers.
/// `TcpStream::peek()` is cancel-safe (MSG_PEEK consumes nothing) and, unlike `readable()`,
/// only resolves when a byte really is queued, so the frame is then read whole outside the
/// `select!` and no bytes are lost when the decision future wins the race.
async fn await_offer_decision<Fut: Future<Output = bool>>(
    stream: &mut TcpStream,
    channel: &mut SecureChannel,
    decision: Fut,
) -> Result<bool, TransferError> {
    let mut decision = Box::pin(decision);
    let mut peek_buf = [0u8; 1];
    loop {
        tokio::select! {
            answer = &mut decision => return Ok(answer),
            peeked = stream.peek(&mut peek_buf) => {
                if peeked? == 0 {
                    return Ok(false); // peer went away while the user was deciding
                }
                let enc = match recv_frame(stream).await {
                    Ok(b) => b,
                    Err(FrameError::ConnectionClosedImmediately | FrameError::UnexpectedEof) => {
                        return Ok(false);
                    }
                    Err(e) => return Err(TransferError::Framing(e)),
                };
                if !pump_idle_frame(stream, channel, &enc).await? {
                    return Ok(false);
                }
            }
        }
    }
}

/// Handle a frame received while waiting for something else. Answers `KEEP_ALIVE`,
/// returns `Ok(false)` on `DISCONNECTION` / payload cancel, ignores anything else.
async fn pump_idle_frame(
    stream: &mut TcpStream,
    channel: &mut SecureChannel,
    enc: &[u8],
) -> Result<bool, TransferError> {
    let raw = channel.decrypt(enc)?;
    let off = OfflineFrame::decode(raw.as_slice())?;
    let Some(v1) = off.v1 else { return Ok(true) };
    match v1.r#type {
        t if t == Some(off_v1::FrameType::KeepAlive as i32) => {
            let ka = channel.encrypt(&build_keep_alive_frame_with_ack(true));
            send_frame(stream, &ka).await?;
        }
        t if t == Some(off_v1::FrameType::Disconnection as i32) => return Ok(false),
        t if t == Some(off_v1::FrameType::PayloadTransfer as i32) => {
            if let Some(ctrl) = v1.payload_transfer.and_then(|pt| pt.control_message) {
                if ctrl.event == Some(control_message::EventType::PayloadCanceled as i32)
                    || ctrl.event == Some(control_message::EventType::PayloadError as i32)
                {
                    return Ok(false);
                }
            }
        }
        _ => {}
    }
    Ok(true)
}

fn guess_file_type_and_mime(path: &Path) -> (i32, String) {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "jpg" | "jpeg" => (file_metadata::Type::Image as i32, "image/jpeg".into()),
        "png" => (file_metadata::Type::Image as i32, "image/png".into()),
        "gif" => (file_metadata::Type::Image as i32, "image/gif".into()),
        "webp" => (file_metadata::Type::Image as i32, "image/webp".into()),
        "mp4" => (file_metadata::Type::Video as i32, "video/mp4".into()),
        "mkv" => (file_metadata::Type::Video as i32, "video/x-matroska".into()),
        "mp3" => (file_metadata::Type::Audio as i32, "audio/mpeg".into()),
        "wav" => (file_metadata::Type::Audio as i32, "audio/wav".into()),
        "apk" => (
            file_metadata::Type::AndroidApp as i32,
            "application/vnd.android.package-archive".into(),
        ),
        "pdf" => (file_metadata::Type::Document as i32, "application/pdf".into()),
        "txt" | "md" => (file_metadata::Type::Document as i32, "text/plain".into()),
        _ => (
            file_metadata::Type::Unknown as i32,
            "application/octet-stream".into(),
        ),
    }
}

async fn recv_sharing_frame(
    stream: &mut TcpStream,
    channel: &mut SecureChannel,
) -> Result<ShareFrame, TransferError> {
    let mut reassembly = Vec::new();
    loop {
        let enc = recv_frame(stream).await?;
        let raw = channel.decrypt(&enc)?;
        let off = OfflineFrame::decode(raw.as_slice())?;
        let Some(v1) = off.v1 else { continue };
        if v1.r#type == Some(off_v1::FrameType::KeepAlive as i32) {
            // The receiver's human may take a while to tap Accept; keep the link alive.
            let ka = channel.encrypt(&build_keep_alive_frame_with_ack(true));
            send_frame(stream, &ka).await?;
            continue;
        }
        if v1.r#type == Some(off_v1::FrameType::Disconnection as i32) {
            return Err(TransferError::DeclinedOrCanceled);
        }
        if v1.r#type != Some(off_v1::FrameType::PayloadTransfer as i32) {
            continue;
        }
        let Some(pt) = v1.payload_transfer else {
            continue;
        };
        if pt.packet_type != Some(PacketType::Data as i32) {
            continue;
        }
        let Some(chunk) = pt.payload_chunk else {
            continue;
        };
        if let Some(body) = chunk.body {
            reassembly.extend_from_slice(&body);
        }
        if (chunk.flags.unwrap_or(0) & (payload_chunk::Flags::LastChunk as i32)) != 0 {
            return Ok(ShareFrame::decode(reassembly.as_slice())?);
        }
    }
}

/// Connect to a Quick Share receiver at `target_addr` and send `files`.
/// Thin wrapper over [`send_items_to_peer`] kept for existing callers.
pub async fn send_files_to_peer<F>(
    target_addr: SocketAddr,
    sender_name: &str,
    endpoint_id: &[u8; 4],
    files: &[PathBuf],
    qr_signature_fn: Option<F>,
    on_pin: impl FnOnce(&str),
) -> Result<(), TransferError>
where
    F: FnOnce(&[u8]) -> [u8; 64],
{
    let items: Vec<OutgoingItem> = files.iter().cloned().map(OutgoingItem::File).collect();
    send_items_to_peer(target_addr, sender_name, endpoint_id, &items, qr_signature_fn, on_pin).await
}

/// Connect to a Quick Share receiver at `target_addr` and send `items` (files and/or
/// text/URL snippets) in one session, exactly as the Android share sheet does.
pub async fn send_items_to_peer<F>(
    target_addr: SocketAddr,
    sender_name: &str,
    endpoint_id: &[u8; 4],
    items: &[OutgoingItem],
    qr_signature_fn: Option<F>,
    on_pin: impl FnOnce(&str),
) -> Result<(), TransferError>
where
    F: FnOnce(&[u8]) -> [u8; 64],
{
    send_items_to_peer_with_progress(
        target_addr,
        sender_name,
        endpoint_id,
        items,
        qr_signature_fn,
        on_pin,
        |_, _| {},
    )
    .await
}

/// Like [`send_items_to_peer`], additionally reporting `(bytes_done, bytes_total)` after
/// every chunk. `on_progress(0, total)` fires once the receiver accepts.
pub async fn send_items_to_peer_with_progress<F>(
    target_addr: SocketAddr,
    sender_name: &str,
    endpoint_id: &[u8; 4],
    items: &[OutgoingItem],
    qr_signature_fn: Option<F>,
    on_pin: impl FnOnce(&str),
    mut on_progress: impl FnMut(u64, u64),
) -> Result<(), TransferError>
where
    F: FnOnce(&[u8]) -> [u8; 64],
{
    if items.is_empty() {
        return Err(TransferError::Protocol("nothing to send"));
    }
    let mut stream = TcpStream::connect(target_addr).await?;
    let endpoint_info =
        build_endpoint_info(Some(sender_name), ShareTargetType::Laptop).unwrap_or_default();
    let endpoint_name_latin1: String = endpoint_info.iter().map(|&b| b as char).collect();

    let conn_req = OfflineFrame {
        version: Some(offline_frame::Version::V1 as i32),
        v1: Some(OffV1Frame {
            r#type: Some(off_v1::FrameType::ConnectionRequest as i32),
            connection_request: Some(ConnectionRequestFrame {
                endpoint_id: Some(String::from_utf8_lossy(endpoint_id).into_owned()),
                endpoint_name: Some(endpoint_name_latin1),
                endpoint_info: Some(endpoint_info),
                mediums: vec![connection_request_frame::Medium::WifiLan as i32],
                ..Default::default()
            }),
            ..Default::default()
        }),
    }
    .encode_to_vec();
    send_frame(&mut stream, &conn_req).await?;

    let keys = run_client_handshake(&mut stream).await?;
    on_pin(&keys.pin);

    send_frame(&mut stream, &build_transport_connection_response_accept()).await?;
    let peer_resp_bytes = recv_frame(&mut stream).await?;
    let peer_resp = OfflineFrame::decode(peer_resp_bytes.as_slice())?;
    if peer_resp.v1.and_then(|v| v.r#type) != Some(off_v1::FrameType::ConnectionResponse as i32) {
        return Err(TransferError::Protocol("expected peer CONNECTION_RESPONSE"));
    }

    let mut channel = SecureChannel::new(keys);
    let qr_sig = qr_signature_fn.map(|f| f(&channel.auth_string));

    for raw in build_paired_key_encryption_frames(qr_sig.as_ref().map(|s| s.as_slice())) {
        let enc = channel.encrypt(&raw);
        send_frame(&mut stream, &enc).await?;
    }
    let _peer_pke = recv_sharing_frame(&mut stream, &mut channel).await?;

    for raw in build_paired_key_result_unable_frames() {
        let enc = channel.encrypt(&raw);
        send_frame(&mut stream, &enc).await?;
    }
    let _peer_pkr = recv_sharing_frame(&mut stream, &mut channel).await?;

    let mut file_metas = Vec::new();
    let mut text_metas = Vec::new();
    // (path, payload_id) for files; (body, payload_id) for texts — sent in this order.
    let mut file_payloads: Vec<(&PathBuf, i64)> = Vec::new();
    let mut text_payloads: Vec<(&str, i64)> = Vec::new();
    for (idx, item) in items.iter().enumerate() {
        let pid = next_positive_payload_id();
        match item {
            OutgoingItem::File(path) => {
                let meta = fs::metadata(path).await?;
                let (ftype, mime) = guess_file_type_and_mime(path);
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("file")
                    .to_string();
                file_metas.push(FileMetadata {
                    name: Some(name),
                    r#type: Some(ftype),
                    payload_id: Some(pid),
                    size: Some(meta.len() as i64),
                    mime_type: Some(mime),
                    id: Some(idx as i64),
                    ..Default::default()
                });
                file_payloads.push((path, pid));
            }
            OutgoingItem::Text { kind, title, body } => {
                text_metas.push(TextMetadata {
                    text_title: Some(title.clone()),
                    r#type: Some(kind.proto_type()),
                    payload_id: Some(pid),
                    size: Some(body.len() as i64),
                    id: Some(idx as i64),
                    is_sensitive_text: Some(false),
                });
                text_payloads.push((body.as_str(), pid));
            }
        }
    }

    let intro = ShareFrame {
        version: Some(share_frame::Version::V1 as i32),
        v1: Some(ShareV1Frame {
            r#type: Some(share_v1::FrameType::Introduction as i32),
            introduction: Some(IntroductionFrame {
                file_metadata: file_metas,
                text_metadata: text_metas,
                start_transfer: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        }),
    }
    .encode_to_vec();

    for raw in wrap_offline_bytes_payload(&intro) {
        let enc = channel.encrypt(&raw);
        send_frame(&mut stream, &enc).await?;
    }

    let resp = recv_sharing_frame(&mut stream, &mut channel).await?;
    let status = resp
        .v1
        .and_then(|v| v.connection_response)
        .and_then(|cr| cr.status);
    if status != Some(share_resp::Status::Accept as i32) {
        return Err(TransferError::DeclinedOrCanceled);
    }

    let mut bytes_total: u64 = text_payloads.iter().map(|(b, _)| b.len() as u64).sum::<u64>();
    for (path, _) in &file_payloads {
        bytes_total += fs::metadata(path).await?.len();
    }
    let mut bytes_done: u64 = 0;
    on_progress(0, bytes_total);

    // Text bodies are plain BYTES payloads whose id matches the announced TextMetadata.
    let mut last_payload_id = None;
    for (body, payload_id) in &text_payloads {
        for raw in wrap_offline_bytes_payload_with_id(*payload_id, body.as_bytes()) {
            let enc = channel.encrypt(&raw);
            send_frame(&mut stream, &enc).await?;
        }
        bytes_done += body.len() as u64;
        on_progress(bytes_done, bytes_total);
        last_payload_id = Some(*payload_id);
    }

    for (path, payload_id) in file_payloads {
        last_payload_id = Some(payload_id);
        let total_size = fs::metadata(path).await?.len() as i64;
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file")
            .to_string();
        let mut f = File::open(path).await?;
        let mut offset = 0i64;
        let mut buf = vec![0u8; CHUNK_SIZE];

        loop {
            let n = f.read(&mut buf).await?;
            let is_last = n == 0;
            let chunk_frame = OfflineFrame {
                version: Some(offline_frame::Version::V1 as i32),
                v1: Some(OffV1Frame {
                    r#type: Some(off_v1::FrameType::PayloadTransfer as i32),
                    payload_transfer: Some(PayloadTransferFrame {
                        packet_type: Some(PacketType::Data as i32),
                        payload_header: Some(PayloadHeader {
                            id: Some(payload_id),
                            r#type: Some(payload_header::PayloadType::File as i32),
                            total_size: Some(total_size),
                            is_sensitive: Some(false),
                            file_name: Some(file_name.clone()),
                            parent_folder: None,
                            last_modified_timestamp_millis: None,
                        }),
                        payload_chunk: Some(PayloadChunk {
                            flags: Some(if is_last {
                                payload_chunk::Flags::LastChunk as i32
                            } else {
                                0
                            }),
                            offset: Some(offset),
                            body: Some(buf[..n].to_vec()),
                            index: None,
                        }),
                        control_message: None,
                    }),
                    ..Default::default()
                }),
            }
            .encode_to_vec();

            let enc = channel.encrypt(&chunk_frame);
            send_frame(&mut stream, &enc).await?;
            offset += n as i64;
            bytes_done += n as u64;
            on_progress(bytes_done.min(bytes_total), bytes_total);
            if is_last {
                break;
            }
        }
    }

    if let Some(last_pid) = last_payload_id {
        wait_for_received_ack(&mut stream, &mut channel, last_pid).await;
    }

    Ok(())
}

async fn wait_for_received_ack(
    stream: &mut TcpStream,
    channel: &mut SecureChannel,
    expected_payload_id: i64,
) {
    while let Ok(enc) = recv_frame(stream).await {
        let Ok(raw) = channel.decrypt(&enc) else {
            break;
        };
        let Ok(off) = OfflineFrame::decode(raw.as_slice()) else {
            break;
        };
        let Some(v1) = off.v1 else { continue };
        if v1.r#type == Some(off_v1::FrameType::KeepAlive as i32) {
            let ka = channel.encrypt(&build_keep_alive_frame_with_ack(true));
            if send_frame(stream, &ka).await.is_err() {
                break;
            }
            continue;
        }
        if v1.r#type == Some(off_v1::FrameType::Disconnection as i32) {
            break;
        }
        if v1.r#type != Some(off_v1::FrameType::PayloadTransfer as i32) {
            continue;
        }
        let Some(pt) = v1.payload_transfer else {
            continue;
        };
        if pt.packet_type != Some(PacketType::Control as i32) {
            continue;
        }
        if pt.payload_header.and_then(|h| h.id) != Some(expected_payload_id) {
            continue;
        }
        if pt.control_message.and_then(|c| c.event)
            == Some(control_message::EventType::PayloadReceivedAck as i32)
        {
            break;
        }
    }
}
