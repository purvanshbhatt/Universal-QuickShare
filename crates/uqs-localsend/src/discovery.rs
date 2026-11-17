//! Multicast UDP discovery (`224.0.0.167:53317`) and the book of known peers.
//!
//! Every LAN interface from `uqs_core::mdns::lan_interfaces()` is joined and announced on;
//! this PC is multi-homed (wired, Wi-Fi, tether, container bridges) and the phones sit on
//! the Wi-Fi subnet, never on the default route.
//!
//! Peers appear through three paths, all ending in [`PeerBook::upsert`]:
//! 1. their multicast announcement (we answer it over HTTP `/register`, UDP as fallback);
//! 2. their HTTP `POST /register` to us, answering *our* announcement (see `server.rs`);
//! 3. an explicit `/info` probe (CLI `--target`).
//!
//! LocalSend apps do not re-announce periodically, so a peer is only dropped after its
//! `/info` endpoint stops answering.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use socket2::{Domain, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::broadcast;
use tokio::task::JoinSet;

use uqs_core::mdns::{lan_interfaces, LanInterface};

use crate::client;
use crate::protocol::{Announcement, DeviceInfo, DeviceType, Protocol, DEFAULT_PORT, MULTICAST_GROUP};

/// A LocalSend device seen on the network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peer {
    /// Certificate hash (HTTPS apps) or a random string (HTTP apps). Stable per install.
    pub fingerprint: String,
    pub alias: String,
    pub device_model: Option<String>,
    pub device_type: DeviceType,
    pub ip: IpAddr,
    pub port: u16,
    pub protocol: Protocol,
    pub download: bool,
    #[serde(skip, default = "Instant::now")]
    pub last_seen: Instant,
}

impl Peer {
    pub fn from_info(info: &DeviceInfo, ip: IpAddr) -> Self {
        Self {
            fingerprint: info.fingerprint.clone(),
            alias: info.alias.clone(),
            device_model: info.device_model.clone(),
            device_type: info.device_type,
            ip,
            port: info.port_or_default(),
            protocol: info.protocol_or_default(),
            download: info.download,
            last_seen: Instant::now(),
        }
    }

    pub fn addr(&self) -> SocketAddr {
        SocketAddr::new(self.ip, self.port)
    }

    /// Identity fields only — ignores `last_seen`.
    fn same_as(&self, other: &Peer) -> bool {
        self.fingerprint == other.fingerprint
            && self.alias == other.alias
            && self.ip == other.ip
            && self.port == other.port
            && self.protocol == other.protocol
            && self.device_type == other.device_type
    }
}

#[derive(Debug, Clone)]
pub enum DiscoveryEvent {
    Found(Peer),
    /// Fingerprint of the peer that stopped answering.
    Lost(String),
}

/// Shared, thread-safe registry of peers; fan-out of changes over a broadcast channel.
#[derive(Clone)]
pub struct PeerBook {
    peers: Arc<Mutex<HashMap<String, Peer>>>,
    events: broadcast::Sender<DiscoveryEvent>,
}

impl Default for PeerBook {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerBook {
    pub fn new() -> Self {
        let (events, _) = broadcast::channel(64);
        Self { peers: Arc::new(Mutex::new(HashMap::new())), events }
    }

    /// Add or refresh a peer. Emits `Found` when it is new or its address/alias changed.
    pub fn upsert(&self, peer: Peer) {
        let mut g = self.peers.lock().unwrap_or_else(|e| e.into_inner());
        let changed = match g.get(&peer.fingerprint) {
            Some(old) => !old.same_as(&peer),
            None => true,
        };
        g.insert(peer.fingerprint.clone(), peer.clone());
        drop(g);
        if changed {
            tracing::info!("LocalSend peer: {} ({:?}) at {}://{}:{}", peer.alias, peer.device_type, peer.protocol.scheme(), peer.ip, peer.port);
            let _ = self.events.send(DiscoveryEvent::Found(peer));
        }
    }

    pub fn remove(&self, fingerprint: &str) {
        let removed = self.peers.lock().unwrap_or_else(|e| e.into_inner()).remove(fingerprint);
        if let Some(p) = removed {
            tracing::info!("LocalSend peer gone: {}", p.alias);
            let _ = self.events.send(DiscoveryEvent::Lost(fingerprint.to_string()));
        }
    }

    pub fn get(&self, fingerprint: &str) -> Option<Peer> {
        self.peers.lock().unwrap_or_else(|e| e.into_inner()).get(fingerprint).cloned()
    }

    /// All peers, alias order.
    pub fn peers(&self) -> Vec<Peer> {
        let mut v: Vec<Peer> = self.peers.lock().unwrap_or_else(|e| e.into_inner()).values().cloned().collect();
        v.sort_by(|a, b| a.alias.to_lowercase().cmp(&b.alias.to_lowercase()));
        v
    }

    pub fn subscribe(&self) -> broadcast::Receiver<DiscoveryEvent> {
        self.events.subscribe()
    }
}

#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Our own advertisement (alias, fingerprint, HTTPS port).
    pub local: DeviceInfo,
    /// Announce ourselves and answer others' announcements. `false` = listen only.
    pub visible: bool,
    /// Re-announce interval (`None` = once at start only).
    pub announce_every: Option<Duration>,
    /// How often known peers are probed with `/info`.
    pub probe_every: Duration,
    /// UDP port to listen/announce on (always 53317 outside tests).
    pub port: u16,
}

impl DiscoveryConfig {
    pub fn new(local: DeviceInfo) -> Self {
        Self {
            local,
            visible: true,
            announce_every: Some(Duration::from_secs(10)),
            probe_every: Duration::from_secs(20),
            port: DEFAULT_PORT,
        }
    }
}

/// Running discovery: multicast listener, announcer, liveness prober. Dropping it stops all three.
pub struct Discovery {
    book: PeerBook,
    local: Arc<DeviceInfo>,
    port: u16,
    _tasks: JoinSet<()>,
}

impl Discovery {
    pub fn start(cfg: DiscoveryConfig, book: PeerBook) -> std::io::Result<Self> {
        let socket = bind_multicast_listener(cfg.port)?;
        let local = Arc::new(cfg.local.clone());
        let mut tasks = JoinSet::new();

        tasks.spawn(listen_loop(socket, local.clone(), book.clone(), cfg.visible, cfg.port));
        if cfg.visible {
            let (l, every, port) = (local.clone(), cfg.announce_every, cfg.port);
            tasks.spawn(async move {
                loop {
                    announce(&l, true, port);
                    match every {
                        Some(d) => tokio::time::sleep(d).await,
                        None => return,
                    }
                }
            });
        }
        tasks.spawn(probe_loop(local.clone(), book.clone(), cfg.probe_every));

        Ok(Self { book, local, port: cfg.port, _tasks: tasks })
    }

    pub fn book(&self) -> &PeerBook {
        &self.book
    }

    pub fn peers(&self) -> Vec<Peer> {
        self.book.peers()
    }

    /// Send one announcement burst now (e.g. when the user opens the device list).
    pub fn announce_now(&self) {
        announce(&self.local, true, self.port);
    }
}

/// Listen for `duration`, announcing at start, and return every peer heard. CLI helper.
/// Peers that only answer over HTTP `/register` need a running [`crate::server::Server`]
/// that shares `book`; pass the server's book for complete results.
pub async fn discover(cfg: DiscoveryConfig, book: PeerBook, duration: Duration) -> std::io::Result<Vec<Peer>> {
    let d = Discovery::start(cfg, book)?;
    tokio::time::sleep(duration).await;
    Ok(d.peers())
}

// --- sockets ---------------------------------------------------------------------------

/// `0.0.0.0:port`, SO_REUSEADDR + SO_REUSEPORT (a LocalSend desktop app may share the host),
/// joined to the group on every LAN interface.
fn bind_multicast_listener(port: u16) -> std::io::Result<UdpSocket> {
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(socket2::Protocol::UDP))?;
    s.set_reuse_address(true)?;
    #[cfg(unix)]
    s.set_reuse_port(true)?;
    s.set_nonblocking(true)?;
    s.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)).into())?;
    join_all_interfaces(&s);
    UdpSocket::from_std(s.into())
}

fn join_all_interfaces(s: &Socket) {
    let ifaces = lan_interfaces();
    if ifaces.is_empty() {
        if let Err(e) = s.join_multicast_v4(&MULTICAST_GROUP, &Ipv4Addr::UNSPECIFIED) {
            tracing::warn!("multicast join (any) failed: {e}");
        }
    }
    for i in &ifaces {
        match s.join_multicast_v4(&MULTICAST_GROUP, &i.addr) {
            Ok(()) => tracing::debug!("joined {MULTICAST_GROUP} on {} ({})", i.name, i.addr),
            // EADDRINUSE = already a member on that interface (re-join after a network change).
            Err(e) if e.raw_os_error() == Some(98) => {}
            Err(e) => tracing::debug!("multicast join on {} failed: {e}", i.name),
        }
    }
}

/// Send `payload` to the group once per LAN interface (the kernel otherwise picks the
/// default-route interface only, which is not where the phones are).
fn multicast_send(payload: &[u8], port: u16) {
    let group = SocketAddr::V4(SocketAddrV4::new(MULTICAST_GROUP, port));
    let ifaces = lan_interfaces();
    let mut sent = 0;
    for i in &ifaces {
        if send_via(i, payload, group).is_ok() {
            sent += 1;
        }
    }
    if sent == 0 {
        // No interface list (or all failed): let the kernel route it.
        if let Ok(s) = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) {
            let _ = s.send_to(payload, group);
        }
    }
}

fn send_via(iface: &LanInterface, payload: &[u8], to: SocketAddr) -> std::io::Result<()> {
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(socket2::Protocol::UDP))?;
    s.set_reuse_address(true)?;
    s.set_multicast_if_v4(&iface.addr)?;
    s.set_multicast_ttl_v4(1)?;
    s.bind(&SocketAddr::from((iface.addr, 0)).into())?;
    s.send_to(payload, &to.into())?;
    Ok(())
}

fn announcement_bytes(local: &DeviceInfo, announce: bool) -> Vec<u8> {
    let msg = Announcement { info: local.clone(), announce };
    serde_json::to_vec(&msg).unwrap_or_default()
}

fn announce(local: &DeviceInfo, announce: bool, port: u16) {
    multicast_send(&announcement_bytes(local, announce), port);
}

// --- tasks -----------------------------------------------------------------------------

async fn listen_loop(socket: UdpSocket, local: Arc<DeviceInfo>, book: PeerBook, visible: bool, port: u16) {
    let mut buf = vec![0u8; 64 * 1024];
    let mut last_rejoin = Instant::now();
    let std_sock = socket.into_std().ok();
    let Some(std_sock) = std_sock else { return };
    let raw = Socket::from(std_sock.try_clone().expect("udp socket clone"));
    let socket = match UdpSocket::from_std(std_sock) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("multicast listener unusable: {e}");
            return;
        }
    };
    loop {
        // Interfaces come and go (Wi-Fi reconnect, tether plugged in): re-join every 30 s.
        if last_rejoin.elapsed() > Duration::from_secs(30) {
            join_all_interfaces(&raw);
            last_rejoin = Instant::now();
        }
        let (n, from) = match tokio::time::timeout(Duration::from_secs(30), socket.recv_from(&mut buf)).await {
            Ok(Ok(x)) => x,
            Ok(Err(e)) => {
                tracing::warn!("multicast recv failed: {e}");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
            Err(_) => continue,
        };
        let msg: Announcement = match serde_json::from_slice(&buf[..n]) {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!("ignoring multicast from {from}: {e}");
                continue;
            }
        };
        if msg.info.fingerprint == local.fingerprint {
            continue; // our own packet looped back
        }
        let peer = Peer::from_info(&msg.info, from.ip());
        book.upsert(peer.clone());
        if msg.announce && visible {
            let (local, port) = (local.clone(), port);
            tokio::spawn(async move {
                // Preferred answer: register over HTTP; it also tells us the peer is reachable.
                let reg = tokio::time::timeout(Duration::from_secs(4), client::register(&peer, &local)).await;
                match reg {
                    Ok(Ok(_)) => return,
                    Ok(Err(e)) => tracing::debug!("register with {} failed ({e}); answering over UDP", peer.alias),
                    Err(_) => tracing::debug!("register with {} timed out; answering over UDP", peer.alias),
                }
                let bytes = announcement_bytes(&local, false);
                if let Ok(s) = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) {
                    let _ = s.send_to(&bytes, SocketAddr::new(peer.ip, port));
                }
                multicast_send(&bytes, port);
            });
        }
    }
}

/// Probe each known peer's `/info`; drop it after two consecutive failures.
async fn probe_loop(local: Arc<DeviceInfo>, book: PeerBook, every: Duration) {
    let mut failures: HashMap<String, u8> = HashMap::new();
    loop {
        tokio::time::sleep(every).await;
        for peer in book.peers() {
            let ok = tokio::time::timeout(Duration::from_secs(4), client::info(&peer, &local)).await;
            match ok {
                Ok(Ok(info)) => {
                    failures.remove(&peer.fingerprint);
                    // Alias or port may have changed in the app's settings.
                    let mut fresh = Peer::from_info(&info, peer.ip);
                    if info.port.is_none() {
                        fresh.port = peer.port;
                    }
                    if info.protocol.is_none() {
                        fresh.protocol = peer.protocol;
                    }
                    if fresh.fingerprint != peer.fingerprint {
                        book.remove(&peer.fingerprint);
                    }
                    book.upsert(fresh);
                }
                _ => {
                    let n = failures.entry(peer.fingerprint.clone()).or_insert(0);
                    *n += 1;
                    if *n >= 2 {
                        failures.remove(&peer.fingerprint);
                        book.remove(&peer.fingerprint);
                    }
                }
            }
        }
        failures.retain(|fp, _| book.get(fp).is_some());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(fp: &str, alias: &str) -> Peer {
        let info = DeviceInfo::new(alias, fp, 53317, Protocol::Https);
        Peer::from_info(&info, "192.168.12.7".parse().unwrap())
    }

    #[test]
    fn book_emits_found_once_per_change_and_lost_on_remove() {
        let book = PeerBook::new();
        let mut rx = book.subscribe();
        book.upsert(peer("A", "iPhone"));
        book.upsert(peer("A", "iPhone")); // unchanged → no event
        book.upsert(peer("A", "Renamed"));
        book.remove("A");
        book.remove("A"); // already gone → no event
        assert!(matches!(rx.try_recv().unwrap(), DiscoveryEvent::Found(p) if p.alias == "iPhone"));
        assert!(matches!(rx.try_recv().unwrap(), DiscoveryEvent::Found(p) if p.alias == "Renamed"));
        assert!(matches!(rx.try_recv().unwrap(), DiscoveryEvent::Lost(fp) if fp == "A"));
        assert!(rx.try_recv().is_err());
        assert!(book.peers().is_empty());
    }

    #[test]
    fn announcement_bytes_are_flat_json() {
        let info = DeviceInfo::new("PC", "F", 53317, Protocol::Https);
        let v: serde_json::Value = serde_json::from_slice(&announcement_bytes(&info, true)).unwrap();
        assert_eq!(v["alias"], "PC");
        assert_eq!(v["announce"], true);
        assert_eq!(v["port"], 53317);
        assert_eq!(v["protocol"], "https");
        assert_eq!(v["deviceType"], "desktop");
        assert!(v.get("info").is_none());
    }
}
