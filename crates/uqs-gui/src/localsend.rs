//! Always-on LocalSend receiver and peer discovery inside the GUI process.
//!
//! Mirrors `receiver.rs` for the LocalSend protocol: one instance per `LocalSendConfig`,
//! restarted by iced when the config changes. Incoming sessions surface as the same
//! `ReceiverEvent`s the Quick Share receiver emits, so the Activity panel needs no new
//! code path; peers surface as `Found`/`Lost` for the "Nearby devices" list.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iced::futures::channel::mpsc::Sender;
use iced::futures::{SinkExt, Stream};
use tokio::sync::{broadcast, mpsc};

use uqs_localsend::{
    cert, DeviceInfo, Discovery, DiscoveryConfig, DiscoveryEvent, Hooks, Identity, Peer, PeerBook, ReceiveEvent,
    Server, ServerConfig,
};

use crate::receiver::ReceiverEvent;

/// LocalSend session ids start here so they never collide with Quick Share ids
/// (`receiver.rs` counts up from 1).
pub const SESSION_ID_BASE: u64 = 1 << 40;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LocalSendConfig {
    pub device_name: String,
    pub download_dir: PathBuf,
    /// Settings → "Visible to nearby devices".
    pub visible: bool,
    /// Settings → "Also accept LocalSend (iPhone) shares".
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub enum LocalSendEvent {
    /// Server state. `info` is what we advertise; the send path reuses it as the sender's
    /// identity. `None` while the server is not up (port busy, no identity, disabled).
    Ready { info: Option<DeviceInfo>, detail: String },
    Receiver(ReceiverEvent),
    Found(Peer),
    Lost(String),
}

pub fn run(cfg: LocalSendConfig) -> impl Stream<Item = LocalSendEvent> {
    iced::stream::channel(64, async move |mut out: Sender<LocalSendEvent>| {
        if !cfg.enabled {
            let _ = out.send(LocalSendEvent::Ready { info: None, detail: "LocalSend off".into() }).await;
            std::future::pending::<()>().await;
        }
        loop {
            let identity = match Identity::load_or_create(&cert::default_dir()) {
                Ok(i) => i,
                Err(e) => {
                    let _ = out.send(LocalSendEvent::Ready { info: None, detail: format!("LocalSend: {e}") }).await;
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    continue;
                }
            };
            let (tx, mut rx) = mpsc::channel::<ReceiveEvent>(64);
            let book = PeerBook::new();
            let mut scfg = ServerConfig::new(&cfg.device_name, identity, cfg.download_dir.clone(), Hooks::channel(tx));
            scfg.accept_shares = cfg.visible;
            scfg.book = book.clone();
            scfg.session_id_base = SESSION_ID_BASE;
            let server = match Server::start(scfg).await {
                Ok(s) => s,
                Err(e) => {
                    let _ = out.send(LocalSendEvent::Ready { info: None, detail: format!("LocalSend: {e}") }).await;
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    continue;
                }
            };
            let mut dcfg = DiscoveryConfig::new(server.info.clone());
            dcfg.visible = cfg.visible;
            let mut peers = book.subscribe();
            let detail = match Discovery::start(dcfg, book.clone()) {
                Ok(_d) => {
                    // Keep the discovery alive for as long as the server runs.
                    let d = _d;
                    let detail = if cfg.visible {
                        format!("LocalSend · port {}", server.local_addr.port())
                    } else {
                        "LocalSend hidden".to_string()
                    };
                    let _ = out.send(LocalSendEvent::Ready { info: Some(server.info.clone()), detail: detail.clone() }).await;
                    for p in book.peers() {
                        let _ = out.send(LocalSendEvent::Found(p)).await;
                    }
                    pump(&mut out, &mut rx, &mut peers, &book).await;
                    drop(d);
                    detail
                }
                Err(e) => {
                    let detail = format!("LocalSend: discovery failed ({e})");
                    let _ = out.send(LocalSendEvent::Ready { info: Some(server.info.clone()), detail: detail.clone() }).await;
                    pump(&mut out, &mut rx, &mut peers, &book).await;
                    detail
                }
            };
            tracing::warn!("LocalSend stream restarting ({detail})");
            drop(server);
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    })
}

/// Forward receiver and peer events until a channel closes.
async fn pump(
    out: &mut Sender<LocalSendEvent>,
    rx: &mut mpsc::Receiver<ReceiveEvent>,
    peers: &mut broadcast::Receiver<DiscoveryEvent>,
    book: &PeerBook,
) {
    loop {
        let ev = tokio::select! {
            ev = rx.recv() => match ev {
                Some(ev) => LocalSendEvent::Receiver(map(ev)),
                None => return,
            },
            ev = peers.recv() => match ev {
                Ok(DiscoveryEvent::Found(p)) => LocalSendEvent::Found(p),
                Ok(DiscoveryEvent::Lost(fp)) => LocalSendEvent::Lost(fp),
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    for p in book.peers() {
                        if out.send(LocalSendEvent::Found(p)).await.is_err() {
                            return;
                        }
                    }
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => return,
            },
        };
        if out.send(ev).await.is_err() {
            return;
        }
    }
}

fn map(ev: ReceiveEvent) -> ReceiverEvent {
    match ev {
        ReceiveEvent::Offer { id, offer, reply } => {
            ReceiverEvent::Offer { id, offer, reply: Arc::new(Mutex::new(Some(reply))) }
        }
        ReceiveEvent::Progress { id, done, total } => ReceiverEvent::Progress { id, done, total },
        ReceiveEvent::Done { id, items } => ReceiverEvent::Done { id, items },
        ReceiveEvent::Failed { id, peer, error } => ReceiverEvent::Failed { id, peer, error },
    }
}
