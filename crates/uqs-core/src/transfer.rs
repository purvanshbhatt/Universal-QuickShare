//! Quick Share file, text, and WiFi-credential receive & send session state machines.

use std::collections::HashMap;
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
    FileMetadata, Frame as ShareFrame, IntroductionFrame, PairedKeyEncryptionFrame,
    PairedKeyResultFrame, V1Frame as ShareV1Frame, WifiCredentials,
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
    OfflineFrame {
        version: Some(offline_frame::Version::V1 as i32),
        v1: Some(OffV1Frame {
            r#type: Some(off_v1::FrameType::KeepAlive as i32),
            keep_alive: Some(KeepAliveFrame {
                ack: Some(false),
                seq_num: None,
            }),
            ..Default::default()
        }),
    }
    .encode_to_vec()
}

pub fn wrap_offline_bytes_payload(sharing_frame_bytes: &[u8]) -> [Vec<u8>; 2] {
    let payload_id = next_positive_payload_id();
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
pub async fn handle_incoming_connection<F>(
    stream: &mut TcpStream,
    output_dir: &Path,
    mut confirm_offer: F,
) -> Result<Vec<ReceivedItem>, TransferError>
where
    F: FnMut(&TransferOffer) -> bool,
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
                let ka = channel.encrypt(&build_keep_alive_frame());
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

                                    let accept = confirm_offer(&offer);
                                    offer_accepted = accept;

                                    if accept {
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
    channel: &SecureChannel,
) -> Result<ShareFrame, TransferError> {
    let mut reassembly = Vec::new();
    loop {
        let enc = recv_frame(stream).await?;
        let raw = channel.decrypt(&enc)?;
        let off = OfflineFrame::decode(raw.as_slice())?;
        let Some(v1) = off.v1 else { continue };
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
    let _peer_pke = recv_sharing_frame(&mut stream, &channel).await?;

    for raw in build_paired_key_result_unable_frames() {
        let enc = channel.encrypt(&raw);
        send_frame(&mut stream, &enc).await?;
    }
    let _peer_pkr = recv_sharing_frame(&mut stream, &channel).await?;

    let mut metas = Vec::with_capacity(files.len());
    let mut payload_ids = Vec::with_capacity(files.len());
    for (idx, path) in files.iter().enumerate() {
        let meta = fs::metadata(path).await?;
        let pid = next_positive_payload_id();
        payload_ids.push(pid);
        let (ftype, mime) = guess_file_type_and_mime(path);
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file")
            .to_string();
        metas.push(FileMetadata {
            name: Some(name),
            r#type: Some(ftype),
            payload_id: Some(pid),
            size: Some(meta.len() as i64),
            mime_type: Some(mime),
            id: Some(idx as i64),
            ..Default::default()
        });
    }

    let intro = ShareFrame {
        version: Some(share_frame::Version::V1 as i32),
        v1: Some(ShareV1Frame {
            r#type: Some(share_v1::FrameType::Introduction as i32),
            introduction: Some(IntroductionFrame {
                file_metadata: metas,
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

    let resp = recv_sharing_frame(&mut stream, &channel).await?;
    let status = resp
        .v1
        .and_then(|v| v.connection_response)
        .and_then(|cr| cr.status);
    if status != Some(share_resp::Status::Accept as i32) {
        return Err(TransferError::DeclinedOrCanceled);
    }

    for (path, &payload_id) in files.iter().zip(payload_ids.iter()) {
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
            if is_last {
                break;
            }
        }
    }

    if let Some(&last_pid) = payload_ids.last() {
        wait_for_received_ack(&mut stream, &channel, last_pid).await;
    }

    Ok(())
}

async fn wait_for_received_ack(
    stream: &mut TcpStream,
    channel: &SecureChannel,
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
