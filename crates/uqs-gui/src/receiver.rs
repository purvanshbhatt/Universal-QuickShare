//! Always-on Quick Share receiver running inside the GUI process.
//!
//! One instance per `ReceiverConfig`; iced restarts the stream when the config's hash
//! changes (name / folder / visibility edited in Settings).

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iced::futures::channel::mpsc::Sender;
use iced::futures::{SinkExt, Stream};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinSet;

use uqs_core::framing::FrameError;
use uqs_core::mdns::{pick_ipv4_address, MdnsAdvertiser, ShareTargetType};
use uqs_core::transfer::{
    handle_incoming_connection_with_progress, ReceivedItem, TransferError, TransferOffer,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReceiverConfig {
    pub device_name: String,
    pub download_dir: PathBuf,
    pub visible: bool,
}

/// The Accept/Decline answer channel for one offer. Cloneable so it can travel inside
/// iced messages; answering twice is harmless (the second sender is already gone).
pub type Reply = Arc<Mutex<Option<oneshot::Sender<bool>>>>;

pub fn answer(reply: &Reply, accept: bool) {
    if let Some(tx) = reply.lock().ok().and_then(|mut g| g.take()) {
        let _ = tx.send(accept);
    }
}

#[derive(Debug, Clone)]
pub enum ReceiverEvent {
    /// Human-readable listener state for the header pill.
    Status { visible: bool, detail: String },
    Offer { id: u64, offer: TransferOffer, reply: Reply },
    Progress { id: u64, done: u64, total: u64 },
    Done { id: u64, items: Vec<ReceivedItem> },
    Failed { id: u64, peer: String, error: String },
}

pub fn run(cfg: ReceiverConfig) -> impl Stream<Item = ReceiverEvent> {
    iced::stream::channel(32, async move |mut out: Sender<ReceiverEvent>| {
        if !cfg.visible {
            let _ = out
                .send(ReceiverEvent::Status { visible: false, detail: "Hidden from nearby devices".into() })
                .await;
            std::future::pending::<()>().await;
        }
        let mut next_id: u64 = 1;
        loop {
            let ipv4 = match pick_ipv4_address() {
                Ok(ip) => ip,
                Err(e) => {
                    let _ = out
                        .send(ReceiverEvent::Status { visible: false, detail: format!("Waiting for network ({e})") })
                        .await;
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
            };
            let listener = match TcpListener::bind(("0.0.0.0", 0)).await {
                Ok(l) => l,
                Err(e) => {
                    let _ = out
                        .send(ReceiverEvent::Status { visible: false, detail: format!("Cannot listen: {e}") })
                        .await;
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
            };
            let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
            let advertiser = match MdnsAdvertiser::start(&cfg.device_name, ShareTargetType::Laptop, ipv4, port) {
                Ok(a) => a,
                Err(e) => {
                    let _ = out
                        .send(ReceiverEvent::Status { visible: false, detail: format!("mDNS failed: {e}") })
                        .await;
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
            };
            let addrs = advertiser.addresses.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", ");
            tracing::info!("receiver up: {:?} port {} via {}", cfg.device_name, port, addrs);
            let _ = out
                .send(ReceiverEvent::Status {
                    visible: true,
                    detail: format!("Visible as “{}” · {addrs} · port {port}", cfg.device_name),
                })
                .await;

            // JoinSet aborts every in-flight connection when this stream is dropped.
            let mut connections: JoinSet<()> = JoinSet::new();
            loop {
                let (mut stream, peer) = match listener.accept().await {
                    Ok(x) => x,
                    Err(e) => {
                        tracing::warn!("accept failed: {e}; rebinding");
                        break;
                    }
                };
                let id = next_id;
                next_id += 1;
                let dir = cfg.download_dir.clone();
                let tx = out.clone();
                connections.spawn(async move {
                    let offer_tx = tx.clone();
                    let mut progress_tx = tx.clone();
                    let confirm = move |offer: TransferOffer| {
                        let mut offer_tx = offer_tx.clone();
                        async move {
                            let (rtx, rrx) = oneshot::channel();
                            let reply: Reply = Arc::new(Mutex::new(Some(rtx)));
                            if offer_tx.send(ReceiverEvent::Offer { id, offer, reply }).await.is_err() {
                                return false;
                            }
                            rrx.await.unwrap_or(false)
                        }
                    };
                    let on_progress = |done: u64, total: u64| {
                        let _ = progress_tx.try_send(ReceiverEvent::Progress { id, done, total });
                    };
                    let res = handle_incoming_connection_with_progress(&mut stream, &dir, confirm, on_progress).await;
                    let mut tx = tx;
                    match res {
                        Ok(items) => {
                            let _ = tx.send(ReceiverEvent::Done { id, items }).await;
                        }
                        Err(TransferError::Framing(FrameError::ConnectionClosedImmediately)) => {
                            tracing::debug!("probe from {peer}");
                        }
                        Err(e) => {
                            let _ = tx
                                .send(ReceiverEvent::Failed { id, peer: peer.to_string(), error: e.to_string() })
                                .await;
                        }
                    }
                });
                // Reap finished tasks so the set does not grow without bound.
                while connections.try_join_next().is_some() {}
            }
            drop(advertiser);
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    })
}
