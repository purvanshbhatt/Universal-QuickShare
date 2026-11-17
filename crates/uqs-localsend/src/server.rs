//! Receiving side: the HTTPS server every LocalSend app talks to.
//!
//! One transfer session at a time (as LocalSend does). A session is born in
//! `prepare-upload`, where the sender's file list becomes a `TransferOffer` and the
//! [`Hooks::confirm`] callback — the same accept/decline question the Quick Share receiver
//! asks — decides between `200 {sessionId, files}` and `403`. Each `upload` then streams
//! one file into the download folder (or, for LocalSend "messages", into a
//! `ReceivedItem::Text`); when the last one lands, [`Hooks::done`] fires.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, DefaultBodyLimit, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures::StreamExt;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot, Notify};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;

use uqs_core::transfer::{sanitize_offered_name, unique_destination, OfferedFile, OfferedText, ReceivedItem, TransferOffer};

use crate::cert::Identity;
use crate::discovery::{Peer, PeerBook};
use crate::protocol::{
    DeviceInfo, FileMeta, PinQuery, PrepareUploadRequest, PrepareUploadResponse, Protocol, SessionQuery, UploadQuery,
    PATH_CANCEL, PATH_INFO, PATH_PREPARE_UPLOAD, PATH_REGISTER, PATH_UPLOAD,
};
use crate::random_id;

/// A session that has shown no upload activity for this long is considered abandoned.
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(90);
/// Cap for a LocalSend text message body.
const MAX_TEXT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("cannot bind {addr}: {source}")]
    Bind { addr: SocketAddr, source: std::io::Error },
    #[error("TLS configuration failed: {0}")]
    Tls(#[from] rustls::Error),
}

/// What a receiving session reports, for consumers that prefer a channel over callbacks
/// (see [`Hooks::channel`]).
#[derive(Debug)]
pub enum ReceiveEvent {
    Offer { id: u64, offer: TransferOffer, reply: oneshot::Sender<bool> },
    Progress { id: u64, done: u64, total: u64 },
    Done { id: u64, items: Vec<ReceivedItem> },
    Failed { id: u64, peer: String, error: String },
}

type ConfirmFuture = Pin<Box<dyn Future<Output = bool> + Send>>;

struct HooksInner {
    confirm: Box<dyn Fn(u64, TransferOffer) -> ConfirmFuture + Send + Sync>,
    progress: Box<dyn Fn(u64, u64, u64) + Send + Sync>,
    done: Box<dyn Fn(u64, Vec<ReceivedItem>) + Send + Sync>,
    failed: Box<dyn Fn(u64, String, String) + Send + Sync>,
}

/// How the server talks to its host. `confirm` has the Quick Share receiver's shape —
/// `TransferOffer -> Future<bool>` — plus the session id, since this server lives across
/// many transfers.
#[derive(Clone)]
pub struct Hooks(Arc<HooksInner>);

impl Hooks {
    pub fn new<C, Fut, P, D, F>(confirm: C, progress: P, done: D, failed: F) -> Self
    where
        C: Fn(u64, TransferOffer) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = bool> + Send + 'static,
        P: Fn(u64, u64, u64) + Send + Sync + 'static,
        D: Fn(u64, Vec<ReceivedItem>) + Send + Sync + 'static,
        F: Fn(u64, String, String) + Send + Sync + 'static,
    {
        Self(Arc::new(HooksInner {
            confirm: Box::new(move |id, offer| Box::pin(confirm(id, offer))),
            progress: Box::new(progress),
            done: Box::new(done),
            failed: Box::new(failed),
        }))
    }

    /// Adapter: every hook becomes a [`ReceiveEvent`] on `tx`; `Offer` carries the reply
    /// sender, exactly like the GUI's Accept/Decline card expects. An offer whose receiver
    /// is gone is declined.
    pub fn channel(tx: mpsc::Sender<ReceiveEvent>) -> Self {
        let (t1, t2, t3, t4) = (tx.clone(), tx.clone(), tx.clone(), tx);
        Self::new(
            move |id, offer| {
                let tx = t1.clone();
                async move {
                    let (reply, answer) = oneshot::channel();
                    if tx.send(ReceiveEvent::Offer { id, offer, reply }).await.is_err() {
                        return false;
                    }
                    answer.await.unwrap_or(false)
                }
            },
            move |id, done, total| {
                let _ = t2.try_send(ReceiveEvent::Progress { id, done, total });
            },
            move |id, items| {
                let tx = t3.clone();
                tokio::spawn(async move {
                    let _ = tx.send(ReceiveEvent::Done { id, items }).await;
                });
            },
            move |id, peer, error| {
                let tx = t4.clone();
                tokio::spawn(async move {
                    let _ = tx.send(ReceiveEvent::Failed { id, peer, error }).await;
                });
            },
        )
    }

    fn confirm(&self, id: u64, offer: TransferOffer) -> ConfirmFuture {
        (self.0.confirm)(id, offer)
    }
    fn progress(&self, id: u64, done: u64, total: u64) {
        (self.0.progress)(id, done, total)
    }
    fn done(&self, id: u64, items: Vec<ReceivedItem>) {
        (self.0.done)(id, items)
    }
    fn failed(&self, id: u64, peer: String, error: String) {
        (self.0.failed)(id, peer, error)
    }
}

pub struct ServerConfig {
    /// Name shown in the sender's device list.
    pub alias: String,
    pub identity: Identity,
    pub download_dir: PathBuf,
    /// `0.0.0.0:53317` in production; `127.0.0.1:0` in tests.
    pub bind: SocketAddr,
    /// Require this PIN on `prepare-upload` (`?pin=`). `None` = no PIN.
    pub pin: Option<String>,
    /// `false` = answer nothing: not discoverable, refuses shares (Settings → not visible).
    pub accept_shares: bool,
    /// Peers that `POST /register` land here (shared with discovery).
    pub book: PeerBook,
    pub hooks: Hooks,
    /// First numeric session id; lets a host keep LocalSend ids apart from other receivers'.
    pub session_id_base: u64,
}

impl ServerConfig {
    pub fn new(alias: impl Into<String>, identity: Identity, download_dir: PathBuf, hooks: Hooks) -> Self {
        Self {
            alias: alias.into(),
            identity,
            download_dir,
            bind: SocketAddr::from(([0, 0, 0, 0], crate::protocol::DEFAULT_PORT)),
            pin: None,
            accept_shares: true,
            book: PeerBook::new(),
            hooks,
            session_id_base: 1,
        }
    }
}

/// A running server. Dropping it closes the listener and aborts in-flight sessions.
pub struct Server {
    pub local_addr: SocketAddr,
    /// What we advertise: alias, fingerprint, bound port, `https`.
    pub info: DeviceInfo,
    pub book: PeerBook,
    task: JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Server {
    pub async fn start(cfg: ServerConfig) -> Result<Server, ServerError> {
        crate::install_crypto_provider();
        let listener = TcpListener::bind(cfg.bind).await.map_err(|source| ServerError::Bind { addr: cfg.bind, source })?;
        let local_addr = listener.local_addr().map_err(|source| ServerError::Bind { addr: cfg.bind, source })?;
        let tls = Arc::new(cfg.identity.server_config()?);
        let info = DeviceInfo::new(cfg.alias.clone(), cfg.identity.fingerprint.clone(), local_addr.port(), Protocol::Https);
        let book = cfg.book.clone();

        let state = Arc::new(AppState {
            info: info.clone(),
            download_dir: cfg.download_dir,
            pin: cfg.pin,
            accept_shares: cfg.accept_shares,
            book: cfg.book,
            hooks: cfg.hooks,
            slot: Mutex::new(Slot::Free),
            next_id: AtomicU64::new(cfg.session_id_base),
        });
        let app = Router::new()
            .route(PATH_INFO, get(info_handler))
            .route(PATH_REGISTER, post(register_handler))
            .route(PATH_PREPARE_UPLOAD, post(prepare_upload_handler))
            .route(PATH_UPLOAD, post(upload_handler))
            .route(PATH_CANCEL, post(cancel_handler))
            .layer(DefaultBodyLimit::max(MAX_TEXT_BYTES))
            .with_state(state);

        let acceptor = TlsAcceptor::from(tls);
        let task = tokio::spawn(async move {
            loop {
                let (tcp, peer) = match listener.accept().await {
                    Ok(x) => x,
                    Err(e) => {
                        tracing::warn!("LocalSend accept failed: {e}");
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        continue;
                    }
                };
                let acceptor = acceptor.clone();
                let app = app.clone();
                tokio::spawn(async move {
                    let tls = match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await {
                        Ok(Ok(t)) => t,
                        Ok(Err(e)) => {
                            tracing::debug!("TLS handshake with {peer} failed: {e}");
                            return;
                        }
                        Err(_) => return,
                    };
                    let service = hyper::service::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
                        req.extensions_mut().insert(ConnectInfo(peer));
                        let app = app.clone();
                        async move { app.oneshot(req).await }
                    });
                    if let Err(e) = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(tls), service)
                        .await
                    {
                        tracing::debug!("connection from {peer} ended: {e}");
                    }
                });
            }
        });
        tracing::info!("LocalSend receiver listening on https://{local_addr} as {:?} ({})", info.alias, info.fingerprint);
        Ok(Server { local_addr, info, book, task })
    }
}

// --- state -------------------------------------------------------------------------------

struct AppState {
    info: DeviceInfo,
    download_dir: PathBuf,
    pin: Option<String>,
    accept_shares: bool,
    book: PeerBook,
    hooks: Hooks,
    slot: Mutex<Slot>,
    next_id: AtomicU64,
}

enum Slot {
    Free,
    /// `prepare-upload` is waiting for the user's answer; `cancel` wakes it up.
    Confirming { id: u64, peer_ip: IpAddr, cancel: Arc<Notify> },
    Active(Session),
}

struct Session {
    id: u64,
    session_id: String,
    peer_ip: IpAddr,
    peer_name: String,
    files: HashMap<String, PendingFile>,
    total: u64,
    done: u64,
    items: Vec<ReceivedItem>,
    last_activity: Instant,
}

struct PendingFile {
    token: String,
    meta: FileMeta,
    state: FileState,
}

enum FileState {
    Waiting,
    Receiving { path: Option<PathBuf> },
    Done,
}

impl Session {
    fn all_done(&self) -> bool {
        self.files.values().all(|f| matches!(f.state, FileState::Done))
    }

    /// Paths of half-written files, for cleanup after a cancel or failure.
    fn partial_paths(&self) -> Vec<PathBuf> {
        self.files
            .values()
            .filter_map(|f| match &f.state {
                FileState::Receiving { path: Some(p) } => Some(p.clone()),
                _ => None,
            })
            .collect()
    }
}

/// Build the offer the host confirms. Files and texts are numbered in file-name order so
/// the same request always yields the same offer.
fn offer_from(req: &PrepareUploadRequest) -> TransferOffer {
    let mut entries: Vec<&FileMeta> = req.files.values().collect();
    entries.sort_by(|a, b| a.file_name.cmp(&b.file_name).then(a.id.cmp(&b.id)));
    let mut files = Vec::new();
    let mut texts = Vec::new();
    for (i, m) in entries.iter().enumerate() {
        let payload_id = i as i64 + 1;
        if m.is_text_message() {
            texts.push(OfferedText { payload_id, title: title_of(m.preview.as_deref().unwrap_or("")), size: m.size });
        } else {
            files.push(OfferedFile {
                payload_id,
                name: sanitize_offered_name(&m.file_name),
                size: m.size,
                mime_type: m.file_type.clone(),
            });
        }
    }
    TransferOffer { peer_name: req.info.alias.clone(), pin: String::new(), files, texts, wifi_ssids: Vec::new() }
}

/// First line, at most 60 chars — the same rule `OutgoingItem::text` uses for titles.
fn title_of(body: &str) -> String {
    let first = body.lines().next().unwrap_or("").trim();
    let mut t: String = first.chars().take(60).collect();
    if t.len() < first.len() {
        t.push('…');
    }
    if t.is_empty() {
        "Text".to_string()
    } else {
        t
    }
}

fn plain(status: StatusCode, msg: &'static str) -> Response {
    (status, msg).into_response()
}

// --- handlers ----------------------------------------------------------------------------

async fn info_handler(State(st): State<Arc<AppState>>) -> Response {
    if !st.accept_shares {
        return StatusCode::NOT_FOUND.into_response();
    }
    Json(st.info.clone()).into_response()
}

/// Parse a JSON body regardless of its `Content-Type` (not every app sets one).
fn parse_json<T: serde::de::DeserializeOwned>(body: &Bytes) -> Result<T, Response> {
    serde_json::from_slice(body).map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid body: {e}")).into_response())
}

async fn register_handler(
    State(st): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    body: Bytes,
) -> Response {
    if !st.accept_shares {
        return StatusCode::NOT_FOUND.into_response();
    }
    let info: DeviceInfo = match parse_json(&body) {
        Ok(i) => i,
        Err(r) => return r,
    };
    if info.fingerprint != st.info.fingerprint {
        st.book.upsert(Peer::from_info(&info, addr.ip()));
    }
    Json(st.info.clone()).into_response()
}

async fn prepare_upload_handler(
    State(st): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Query(q): Query<PinQuery>,
    body: Bytes,
) -> Response {
    if !st.accept_shares {
        return plain(StatusCode::FORBIDDEN, "Not accepting shares");
    }
    let req: PrepareUploadRequest = match parse_json(&body) {
        Ok(r) => r,
        Err(r) => return r,
    };
    if let Some(expected) = &st.pin {
        if q.pin.as_deref() != Some(expected.as_str()) {
            return plain(StatusCode::UNAUTHORIZED, "PIN required");
        }
    }
    if req.files.is_empty() {
        return StatusCode::NO_CONTENT.into_response();
    }
    // Knowing the sender's address is useful later even if it never uploads.
    if req.info.fingerprint != st.info.fingerprint {
        st.book.upsert(Peer::from_info(&req.info, addr.ip()));
    }

    let id = st.next_id.fetch_add(1, Ordering::Relaxed);
    let cancel = Arc::new(Notify::new());
    {
        let mut slot = st.slot.lock().unwrap_or_else(|e| e.into_inner());
        if let Slot::Active(s) = &*slot {
            if s.last_activity.elapsed() > SESSION_IDLE_TIMEOUT {
                let dead = std::mem::replace(&mut *slot, Slot::Free);
                if let Slot::Active(s) = dead {
                    abandon(&st, s, "timed out");
                }
            }
        }
        match &*slot {
            Slot::Free => *slot = Slot::Confirming { id, peer_ip: addr.ip(), cancel: cancel.clone() },
            _ => return plain(StatusCode::CONFLICT, "Blocked by another session"),
        }
    }

    let offer = offer_from(&req);
    let peer_name = offer.peer_name.clone();
    let accepted = tokio::select! {
        a = st.hooks.confirm(id, offer) => a,
        _ = cancel.notified() => {
            st.hooks.failed(id, peer_name, "canceled by sender".into());
            free_if_confirming(&st, id);
            return plain(StatusCode::FORBIDDEN, "Canceled");
        }
    };
    if !accepted {
        free_if_confirming(&st, id);
        return plain(StatusCode::FORBIDDEN, "Rejected");
    }

    let session_id = random_id();
    let mut tokens = HashMap::new();
    let mut files = HashMap::new();
    let mut total = 0u64;
    for (fid, meta) in req.files {
        let token = random_id();
        tokens.insert(fid.clone(), token.clone());
        total += meta.size;
        files.insert(fid, PendingFile { token, meta, state: FileState::Waiting });
    }
    let session = Session {
        id,
        session_id: session_id.clone(),
        peer_ip: addr.ip(),
        peer_name,
        files,
        total,
        done: 0,
        items: Vec::new(),
        last_activity: Instant::now(),
    };
    {
        let mut slot = st.slot.lock().unwrap_or_else(|e| e.into_inner());
        match &*slot {
            Slot::Confirming { id: cid, .. } if *cid == id => *slot = Slot::Active(session),
            _ => return plain(StatusCode::CONFLICT, "Blocked by another session"),
        }
    }
    st.hooks.progress(id, 0, total);
    Json(PrepareUploadResponse { session_id, files: tokens }).into_response()
}

fn free_if_confirming(st: &AppState, id: u64) {
    let mut slot = st.slot.lock().unwrap_or_else(|e| e.into_inner());
    if matches!(&*slot, Slot::Confirming { id: cid, .. } if *cid == id) {
        *slot = Slot::Free;
    }
}

/// Drop a session's half-written files and tell the host it failed.
fn abandon(st: &AppState, s: Session, why: &str) {
    for p in s.partial_paths() {
        let _ = std::fs::remove_file(p);
    }
    st.hooks.failed(s.id, s.peer_name, why.to_string());
}

async fn upload_handler(
    State(st): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Query(q): Query<UploadQuery>,
    body: Body,
) -> Response {
    // Claim the file under the lock, then stream without it.
    let (id, meta, is_text, path) = {
        let mut slot = st.slot.lock().unwrap_or_else(|e| e.into_inner());
        let Slot::Active(s) = &mut *slot else {
            return plain(StatusCode::FORBIDDEN, "Invalid session");
        };
        if s.session_id != q.session_id {
            return plain(StatusCode::FORBIDDEN, "Invalid session");
        }
        if s.peer_ip != addr.ip() {
            return plain(StatusCode::FORBIDDEN, "Invalid IP address");
        }
        let Some(f) = s.files.get_mut(&q.file_id) else {
            return plain(StatusCode::FORBIDDEN, "Invalid file id");
        };
        if f.token != q.token {
            return plain(StatusCode::FORBIDDEN, "Invalid token");
        }
        if !matches!(f.state, FileState::Waiting) {
            return plain(StatusCode::BAD_REQUEST, "File already uploaded");
        }
        let is_text = f.meta.is_text_message();
        let path = if is_text {
            None
        } else {
            if let Err(e) = std::fs::create_dir_all(&st.download_dir) {
                return (StatusCode::INTERNAL_SERVER_ERROR, format!("cannot create download folder: {e}")).into_response();
            }
            Some(unique_destination(&st.download_dir, &sanitize_offered_name(&f.meta.file_name)))
        };
        f.state = FileState::Receiving { path: path.clone() };
        s.last_activity = Instant::now();
        (s.id, f.meta.clone(), is_text, path)
    };

    let result = if is_text {
        receive_text(&st, id, &meta, body).await.map(|body| ReceivedItem::Text { title: title_of(&body), body })
    } else {
        let path = path.expect("file path chosen");
        receive_file(&st, id, &path, body).await.map(|size| ReceivedItem::File {
            name: path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
            path,
            size,
        })
    };

    let mut slot = st.slot.lock().unwrap_or_else(|e| e.into_inner());
    let Slot::Active(s) = &mut *slot else {
        return plain(StatusCode::FORBIDDEN, "Session ended"); // canceled meanwhile
    };
    if s.id != id {
        return plain(StatusCode::FORBIDDEN, "Session ended");
    }
    match result {
        Ok(item) => {
            if let Some(f) = s.files.get_mut(&q.file_id) {
                f.state = FileState::Done;
            }
            s.items.push(item);
            s.last_activity = Instant::now();
            if s.all_done() {
                let finished = std::mem::replace(&mut *slot, Slot::Free);
                drop(slot);
                if let Slot::Active(s) = finished {
                    st.hooks.progress(s.id, s.total, s.total);
                    st.hooks.done(s.id, s.items);
                }
            }
            StatusCode::OK.into_response()
        }
        Err(e) => {
            let dead = std::mem::replace(&mut *slot, Slot::Free);
            drop(slot);
            if let Slot::Active(s) = dead {
                abandon(&st, s, &e);
            }
            (StatusCode::INTERNAL_SERVER_ERROR, e).into_response()
        }
    }
}

async fn receive_file(st: &AppState, id: u64, path: &PathBuf, body: Body) -> Result<u64, String> {
    let mut file = tokio::fs::File::create(path).await.map_err(|e| format!("cannot create {}: {e}", path.display()))?;
    let mut stream = body.into_data_stream();
    let mut written = 0u64;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("upload interrupted: {e}"))?;
        file.write_all(&chunk).await.map_err(|e| format!("write failed: {e}"))?;
        written += chunk.len() as u64;
        bump_progress(st, id, chunk.len() as u64);
    }
    file.flush().await.map_err(|e| format!("write failed: {e}"))?;
    Ok(written)
}

async fn receive_text(st: &AppState, id: u64, meta: &FileMeta, body: Body) -> Result<String, String> {
    let mut stream = body.into_data_stream();
    let mut buf: Vec<u8> = Vec::with_capacity(meta.size.min(MAX_TEXT_BYTES as u64) as usize);
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("upload interrupted: {e}"))?;
        if buf.len() + chunk.len() > MAX_TEXT_BYTES {
            return Err("text message too large".into());
        }
        buf.extend_from_slice(&chunk);
        bump_progress(st, id, chunk.len() as u64);
    }
    if buf.is_empty() {
        // The preview already holds the message; some senders send no body for it.
        return Ok(meta.preview.clone().unwrap_or_default());
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn bump_progress(st: &AppState, id: u64, n: u64) {
    let (done, total) = {
        let mut slot = st.slot.lock().unwrap_or_else(|e| e.into_inner());
        match &mut *slot {
            Slot::Active(s) if s.id == id => {
                s.done += n;
                s.last_activity = Instant::now();
                (s.done, s.total)
            }
            _ => return,
        }
    };
    st.hooks.progress(id, done, total);
}

async fn cancel_handler(
    State(st): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Query(q): Query<SessionQuery>,
) -> Response {
    let mut slot = st.slot.lock().unwrap_or_else(|e| e.into_inner());
    match &*slot {
        Slot::Confirming { peer_ip, cancel, .. } if *peer_ip == addr.ip() => {
            cancel.notify_one(); // prepare-upload frees the slot and reports the failure
            StatusCode::OK.into_response()
        }
        Slot::Active(s) if s.peer_ip == addr.ip() && q.session_id.as_deref().is_none_or(|sid| sid == s.session_id) => {
            let dead = std::mem::replace(&mut *slot, Slot::Free);
            drop(slot);
            if let Slot::Active(s) = dead {
                abandon(&st, s, "canceled by sender");
            }
            StatusCode::OK.into_response()
        }
        _ => StatusCode::OK.into_response(), // nothing of theirs to cancel
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offer_splits_messages_from_files() {
        let raw = r#"{
            "info": {"alias":"iPhone","version":"2.1","deviceType":"mobile","fingerprint":"X"},
            "files": {
                "b": {"id":"b","fileName":"../../etc/passwd","size":10,"fileType":"text/plain"},
                "a": {"id":"a","fileName":"IMG_0001.HEIC","size":1234,"fileType":"image/heic"},
                "m": {"id":"m","fileName":"message.txt","size":19,"fileType":"text/plain","preview":"https://example.com"}
            }
        }"#;
        let req: PrepareUploadRequest = serde_json::from_str(raw).unwrap();
        let offer = offer_from(&req);
        assert_eq!(offer.peer_name, "iPhone");
        assert_eq!(offer.pin, "");
        assert_eq!(offer.files.len(), 2);
        assert_eq!(offer.files[0].name, "passwd"); // traversal stripped, sorted by name
        assert_eq!(offer.files[1].name, "IMG_0001.HEIC");
        assert_eq!(offer.texts.len(), 1);
        assert_eq!(offer.texts[0].title, "https://example.com");
    }

    #[test]
    fn titles_are_first_line_truncated() {
        assert_eq!(title_of("hello\nworld"), "hello");
        assert_eq!(title_of(""), "Text");
        let long = "x".repeat(70);
        assert_eq!(title_of(&long).chars().count(), 61);
    }
}
