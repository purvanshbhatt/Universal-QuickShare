//! End-to-end: this crate's client sends to this crate's server over TLS on loopback.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::mpsc;

use uqs_core::transfer::{OutgoingItem, ReceivedItem};
use uqs_localsend::{
    client, ClientError, DeviceInfo, Hooks, Identity, Peer, PeerBook, Protocol, ReceiveEvent, Server, ServerConfig,
};

struct Harness {
    server: Server,
    download_dir: tempfile::TempDir,
    events: mpsc::Receiver<ReceiveEvent>,
}

async fn start(accept: bool, pin: Option<&str>) -> Harness {
    let download_dir = tempfile::tempdir().unwrap();
    let (tx, mut rx) = mpsc::channel(64);
    // Forward events to the test, answering offers like a user would.
    let (fwd_tx, fwd_rx) = mpsc::channel(64);
    tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            match ev {
                ReceiveEvent::Offer { id, offer, reply } => {
                    let _ = reply.send(accept);
                    let (dummy, _) = tokio::sync::oneshot::channel();
                    let _ = fwd_tx.send(ReceiveEvent::Offer { id, offer, reply: dummy }).await;
                }
                other => {
                    let _ = fwd_tx.send(other).await;
                }
            }
        }
    });
    let mut cfg = ServerConfig::new("Test PC", Identity::generate().unwrap(), download_dir.path().to_path_buf(), Hooks::channel(tx));
    cfg.bind = SocketAddr::from(([127, 0, 0, 1], 0));
    cfg.pin = pin.map(str::to_string);
    cfg.session_id_base = 1000;
    let server = Server::start(cfg).await.unwrap();
    Harness { server, download_dir, events: fwd_rx }
}

fn peer_of(server: &Server) -> Peer {
    Peer::from_info(&server.info, server.local_addr.ip())
}

fn sender() -> DeviceInfo {
    DeviceInfo::new("Test Phone", Identity::generate().unwrap().fingerprint, 1, Protocol::Https)
}

async fn next_event(h: &mut Harness) -> ReceiveEvent {
    tokio::time::timeout(Duration::from_secs(10), h.events.recv()).await.expect("event in time").expect("channel open")
}

#[tokio::test]
async fn file_and_text_round_trip() {
    let mut h = start(true, None).await;
    let peer = peer_of(&h.server);
    assert_eq!(peer.fingerprint, h.server.info.fingerprint);

    let src_dir = tempfile::tempdir().unwrap();
    let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let file_path = src_dir.path().join("photo.jpg");
    std::fs::write(&file_path, &payload).unwrap();

    let items = vec![OutgoingItem::File(file_path.clone()), OutgoingItem::text("https://example.com/page")];
    let seen = Arc::new(Mutex::new(Vec::<(u64, u64)>::new()));
    let seen2 = seen.clone();
    client::send_items(&peer, &sender(), &items, None, move |d, t| seen2.lock().unwrap().push((d, t)))
        .await
        .unwrap();

    // Offer first, carrying both items split by kind.
    let ReceiveEvent::Offer { id, offer, .. } = next_event(&mut h).await else { panic!("expected offer") };
    assert_eq!(id, 1000);
    assert_eq!(offer.peer_name, "Test Phone");
    assert_eq!(offer.files.len(), 1);
    assert_eq!(offer.files[0].size, payload.len() as u64);
    assert_eq!(offer.files[0].mime_type, "image/jpeg");
    assert_eq!(offer.texts.len(), 1);
    assert_eq!(offer.texts[0].title, "https://example.com/page");

    // Then progress and done.
    let mut done_items = None;
    for _ in 0..200 {
        match next_event(&mut h).await {
            ReceiveEvent::Progress { id: pid, done, total } => {
                assert_eq!(pid, 1000);
                assert!(done <= total);
            }
            ReceiveEvent::Done { id: did, items } => {
                assert_eq!(did, 1000);
                done_items = Some(items);
                break;
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    let items = done_items.expect("done event");
    assert_eq!(items.len(), 2);
    let file = items.iter().find_map(|i| match i {
        ReceivedItem::File { name, path, size } => Some((name.clone(), path.clone(), *size)),
        _ => None,
    });
    let (name, path, size) = file.expect("file item");
    assert_eq!(name, file_path.file_name().unwrap().to_string_lossy());
    assert_eq!(size, payload.len() as u64);
    assert_eq!(path.parent(), Some(h.download_dir.path()));
    assert_eq!(std::fs::read(&path).unwrap(), payload);
    let text = items.iter().find_map(|i| match i {
        ReceivedItem::Text { title, body } => Some((title.clone(), body.clone())),
        _ => None,
    });
    assert_eq!(text, Some(("https://example.com/page".to_string(), "https://example.com/page".to_string())));

    // Sender-side progress reached the total.
    let seen = seen.lock().unwrap();
    let total = payload.len() as u64 + "https://example.com/page".len() as u64;
    assert_eq!(seen.last().copied(), Some((total, total)));
    assert!(seen.iter().all(|(d, t)| d <= t && *t == total));
}

#[tokio::test]
async fn declined_offer_yields_403_and_nothing_on_disk() {
    let mut h = start(false, None).await;
    let peer = peer_of(&h.server);
    let items = vec![OutgoingItem::text("secret")];
    let err = client::send_items(&peer, &sender(), &items, None, |_, _| {}).await.unwrap_err();
    assert!(matches!(err, ClientError::Declined), "{err}");
    assert!(matches!(next_event(&mut h).await, ReceiveEvent::Offer { .. }));
    assert_eq!(std::fs::read_dir(h.download_dir.path()).unwrap().count(), 0);

    // The slot is free again: a second attempt is asked about, not told 409.
    let err = client::send_items(&peer, &sender(), &items, None, |_, _| {}).await.unwrap_err();
    assert!(matches!(err, ClientError::Declined), "{err}");
}

#[tokio::test]
async fn pin_is_enforced() {
    let mut h = start(true, Some("4321")).await;
    let peer = peer_of(&h.server);
    let items = vec![OutgoingItem::text("hi")];
    let err = client::send_items(&peer, &sender(), &items, None, |_, _| {}).await.unwrap_err();
    assert!(matches!(err, ClientError::PinRequired), "{err}");
    let err = client::send_items(&peer, &sender(), &items, Some("0000"), |_, _| {}).await.unwrap_err();
    assert!(matches!(err, ClientError::PinRequired), "{err}");
    client::send_items(&peer, &sender(), &items, Some("4321"), |_, _| {}).await.unwrap();
    assert!(matches!(next_event(&mut h).await, ReceiveEvent::Offer { .. }));
}

#[tokio::test]
async fn wrong_fingerprint_is_rejected_by_tls() {
    let h = start(true, None).await;
    let mut peer = peer_of(&h.server);
    peer.fingerprint = "0".repeat(64); // looks like a hash, but not this server's
    let err = client::send_items(&peer, &sender(), &[OutgoingItem::text("x")], None, |_, _| {}).await.unwrap_err();
    assert!(matches!(err, ClientError::Http(_)), "{err}");
    // A non-hash fingerprint (HTTP-mode app, manual --target) disables pinning.
    peer.fingerprint = "random string".into();
    let err = client::info(&peer, &sender()).await;
    assert!(err.is_ok(), "{err:?}");
}

#[tokio::test]
async fn register_and_info_feed_the_peer_book() {
    let h = start(true, None).await;
    let peer = peer_of(&h.server);
    let me = sender();
    let theirs = client::register(&peer, &me).await.unwrap();
    assert_eq!(theirs.alias, "Test PC");
    assert_eq!(theirs.fingerprint, h.server.info.fingerprint);
    assert_eq!(theirs.port, Some(h.server.local_addr.port()));
    let book: &PeerBook = &h.server.book;
    let known = book.peers();
    assert_eq!(known.len(), 1);
    assert_eq!(known[0].alias, "Test Phone");
    assert_eq!(known[0].ip, h.server.local_addr.ip());
    assert_eq!(known[0].port, 1);

    let info = client::info(&peer, &me).await.unwrap();
    assert_eq!(info, theirs);
    let probed = client::probe_addr(h.server.local_addr.ip(), h.server.local_addr.port(), Protocol::Https, &me).await.unwrap();
    assert_eq!(probed.fingerprint, h.server.info.fingerprint);
}

#[tokio::test]
async fn traversal_names_stay_in_download_dir() {
    let mut h = start(true, None).await;
    let peer = peer_of(&h.server);
    let dir = tempfile::tempdir().unwrap();
    let evil = dir.path().join("..evil.txt");
    std::fs::write(&evil, b"x").unwrap();
    client::send_items(&peer, &sender(), &[OutgoingItem::File(evil)], None, |_, _| {}).await.unwrap();
    let _offer = next_event(&mut h).await;
    loop {
        if let ReceiveEvent::Done { items, .. } = next_event(&mut h).await {
            let ReceivedItem::File { path, .. } = &items[0] else { panic!() };
            assert_eq!(path.parent(), Some(h.download_dir.path()));
            assert_eq!(path.file_name().unwrap(), "evil.txt");
            break;
        }
    }
    assert!(Path::new(h.download_dir.path()).join("evil.txt").is_file());
}
