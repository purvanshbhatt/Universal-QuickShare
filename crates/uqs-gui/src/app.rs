//! iced daemon: state, update, view.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use iced::futures::channel::mpsc::Sender;
use iced::futures::{SinkExt, Stream};
use iced::widget::{
    button, column, container, pick_list, progress_bar, row, scrollable, space, svg, text, text_input,
    toggler,
};
use iced::{event, window, Element, Event, Fill, Font, Length, Size, Subscription, Task, Theme};

use uqs_core::ble::BleTriggerHandle;
use uqs_core::mdns::{stable_endpoint_id, DiscoveredDevice, DiscoveryEvent, ShareTargetType};
use uqs_core::transfer::{
    send_items_to_peer_with_progress, OutgoingItem, OutgoingTextKind, ReceivedItem, TransferOffer,
};
use uqs_localsend::{DeviceInfo as LsDeviceInfo, DeviceType as LsDeviceType, Peer as LsPeer};
use uqs_phonelink::{read_linux_clipboard_text, write_linux_clipboard_text};

use crate::config::Config;
use crate::icons;
use crate::ipc;
use crate::localsend::{self, LocalSendConfig, LocalSendEvent};
use crate::receiver::{self, ReceiverConfig, ReceiverEvent, Reply};
use crate::theme::{self as tk, SPACE_LG, SPACE_MD, SPACE_SM, SPACE_XL, SPACE_XS};
use crate::tray::{self, TrayCommand};

#[derive(Debug, Clone)]
pub struct Launch {
    pub show_window: bool,
    pub initial: Option<ipc::Command>,
}

pub fn run(launch: Launch) -> iced::Result {
    iced::daemon(move || State::boot(launch.clone()), State::update, State::view)
        .title(State::title)
        .subscription(State::subscription)
        .theme(State::theme)
        .run()
}

// --- state ----------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen {
    Main,
    Settings,
}

#[derive(Debug, Clone)]
enum SendState {
    Idle,
    Connecting { device: String },
    Waiting { device: String, pin: String },
    Sending { device: String, pin: String, done: u64, total: u64 },
    Done { device: String, summary: String },
    Failed { device: String, error: String },
}

#[derive(Debug, Clone)]
struct PendingOffer {
    id: u64,
    offer: TransferOffer,
    reply: Reply,
}

#[derive(Debug, Clone)]
struct Receiving {
    peer: String,
    done: u64,
    total: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HistoryKind {
    Received,
    Sent,
    Failed,
}

#[derive(Debug, Clone)]
struct HistoryEntry {
    at: String,
    kind: HistoryKind,
    title: String,
    detail: String,
    path: Option<PathBuf>,
    text: Option<String>,
}

/// One row of "Nearby devices": a Quick Share endpoint or a LocalSend peer.
#[derive(Debug, Clone)]
enum Nearby {
    QuickShare(DiscoveredDevice),
    LocalSend(LsPeer),
}

impl Nearby {
    /// Stable key across both protocols (prefixed so the two id spaces cannot collide).
    fn id(&self) -> String {
        match self {
            Nearby::QuickShare(d) => format!("qs:{}", d.endpoint_id),
            Nearby::LocalSend(p) => format!("ls:{}", p.fingerprint),
        }
    }

    fn name(&self) -> &str {
        match self {
            Nearby::QuickShare(d) => &d.device_name,
            Nearby::LocalSend(p) => &p.alias,
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Nearby::QuickShare(d) => match d.device_type {
                ShareTargetType::Phone | ShareTargetType::Foldable => "Phone",
                ShareTargetType::Tablet => "Tablet",
                ShareTargetType::Laptop => "Computer",
                ShareTargetType::Car => "Car",
                ShareTargetType::Xr => "Headset",
                ShareTargetType::Unknown => "Device",
            },
            Nearby::LocalSend(p) => match p.device_type {
                LsDeviceType::Mobile => "Phone",
                LsDeviceType::Desktop => "Computer",
                LsDeviceType::Web => "Browser",
                LsDeviceType::Headless | LsDeviceType::Server => "Server",
            },
        }
    }

    /// Second line of the row: kind, protocol (LocalSend only), address.
    fn caption(&self) -> String {
        match self {
            Nearby::QuickShare(d) => format!("{} · {}", self.kind(), d.address),
            Nearby::LocalSend(p) => format!("{} · LocalSend · {}", self.kind(), p.ip),
        }
    }

    fn icon(&self) -> svg::Handle {
        match self {
            Nearby::QuickShare(d) => device_icon(d.device_type),
            Nearby::LocalSend(p) => match p.device_type {
                LsDeviceType::Mobile => icons::phone(),
                LsDeviceType::Desktop => icons::laptop(),
                _ => icons::device(),
            },
        }
    }
}

/// `BleTriggerHandle` has no `Debug`; messages need one.
pub struct Ble(#[allow(dead_code)] BleTriggerHandle);

impl std::fmt::Debug for Ble {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BleTriggerHandle")
    }
}

const APPEARANCES: [&str; 3] = ["System", "Light", "Dark"];

pub struct State {
    window: Option<window::Id>,
    tray_ok: Option<bool>,
    config: Config,
    system_dark: bool,
    theme_light: Theme,
    theme_dark: Theme,
    _ble: Option<Arc<Ble>>,

    devices: Vec<Nearby>,
    selected: Option<String>,
    /// Our LocalSend identity while its server is up (used as the sender's `info`).
    localsend_info: Option<LsDeviceInfo>,
    localsend_detail: String,

    outgoing: Vec<OutgoingItem>,
    draft: String,
    hovering_drop: bool,
    send: SendState,

    receiver_visible: bool,
    receiver_detail: String,
    pending: VecDeque<PendingOffer>,
    receiving: HashMap<u64, Receiving>,
    history: Vec<HistoryEntry>,

    screen: Screen,
    settings_draft: Config,
    notice: Option<String>,
}

#[derive(Debug, Clone)]
pub enum SendEvent {
    Pin(String),
    Progress(u64, u64),
    Done,
    Failed(String),
}

#[derive(Debug, Clone)]
pub enum Message {
    Noop,
    WindowOpened(window::Id),
    WindowClosed(window::Id),
    CloseRequested(window::Id),
    SystemTheme(iced::theme::Mode),
    BleStarted(Option<Arc<Ble>>),

    Discovery(DiscoveryEvent),
    Receiver(ReceiverEvent),
    LocalSend(LocalSendEvent),
    Ipc(ipc::Command),
    Tray(TrayCommand),

    SelectDevice(String),
    DraftChanged(String),
    AddDraft,
    RemoveItem(usize),
    ClearItems,
    PickFiles,
    FilesPicked(Option<Vec<PathBuf>>),
    FileDropped(PathBuf),
    DropHover(bool),
    PasteClipboard,
    ClipboardRead(Option<String>),

    Send,
    SendEvent(SendEvent),
    DismissSend,

    Accept(u64),
    Decline(u64),
    OpenPath(PathBuf),
    CopyText(String),
    ClearHistory,
    DismissNotice,

    OpenSettings,
    CloseSettings,
    SetName(String),
    SetDownloadDir(String),
    BrowseDownloadDir,
    DownloadDirPicked(Option<PathBuf>),
    SetVisible(bool),
    SetAutoAccept(bool),
    SetLocalSend(bool),
    SetAppearance(&'static str),
    SaveSettings,
}

impl State {
    fn boot(launch: Launch) -> (Self, Task<Message>) {
        let config = Config::load();
        let state = Self {
            window: None,
            tray_ok: None,
            settings_draft: config.clone(),
            config,
            system_dark: false,
            theme_light: tk::light(),
            theme_dark: tk::dark(),
            _ble: None,
            devices: Vec::new(),
            selected: None,
            localsend_info: None,
            localsend_detail: "LocalSend starting…".into(),
            outgoing: Vec::new(),
            draft: String::new(),
            hovering_drop: false,
            send: SendState::Idle,
            receiver_visible: false,
            receiver_detail: "Starting…".into(),
            pending: VecDeque::new(),
            receiving: HashMap::new(),
            history: Vec::new(),
            screen: Screen::Main,
            notice: None,
        };
        let mut tasks = vec![
            Task::perform(BleTriggerHandle::start(), |r| Message::BleStarted(r.ok().map(|h| Arc::new(Ble(h))))),
            iced::system::theme().map(Message::SystemTheme),
        ];
        let mut state = state;
        if launch.show_window {
            tasks.push(state.open_window());
        }
        if let Some(cmd) = launch.initial {
            tasks.push(Task::done(Message::Ipc(cmd)));
        }
        (state, Task::batch(tasks))
    }

    fn title(&self, _id: window::Id) -> String {
        match self.screen {
            Screen::Main => "Quick Share".into(),
            Screen::Settings => "Quick Share — Settings".into(),
        }
    }

    fn theme(&self, _id: window::Id) -> Theme {
        if self.config.dark.unwrap_or(self.system_dark) {
            self.theme_dark.clone()
        } else {
            self.theme_light.clone()
        }
    }

    fn subscription(&self) -> Subscription<Message> {
        Subscription::batch([
            Subscription::run(discovery_stream).map(Message::Discovery),
            Subscription::run_with(receiver_config(&self.config), receiver_stream).map(Message::Receiver),
            Subscription::run_with(localsend_config(&self.config), localsend_stream).map(Message::LocalSend),
            Subscription::run(ipc::listen).map(Message::Ipc),
            Subscription::run(tray::run).map(Message::Tray),
            iced::system::theme_changes().map(Message::SystemTheme),
            event::listen_with(handle_event),
        ])
    }

    // --- window helpers ---------------------------------------------------------------

    fn open_window(&mut self) -> Task<Message> {
        if let Some(id) = self.window {
            return window::gain_focus(id);
        }
        let (id, task) = window::open(window::Settings {
            size: Size::new(860.0, 620.0),
            min_size: Some(Size::new(640.0, 480.0)),
            position: window::Position::Centered,
            exit_on_close_request: false,
            platform_specific: window::settings::PlatformSpecific {
                application_id: "uqs-gui".into(),
                ..Default::default()
            },
            ..Default::default()
        });
        self.window = Some(id);
        task.map(Message::WindowOpened)
    }

    fn attention(&mut self) -> Task<Message> {
        match self.window {
            Some(id) => Task::batch([
                window::gain_focus(id),
                window::request_user_attention(id, Some(window::UserAttention::Informational)),
            ]),
            None => self.open_window(),
        }
    }

    fn read_clipboard(&self) -> Task<Message> {
        Task::perform(
            async { tokio::task::spawn_blocking(read_linux_clipboard_text).await.ok().and_then(|r| r.ok()) },
            Message::ClipboardRead,
        )
    }

    fn add_files(&mut self, files: impl IntoIterator<Item = PathBuf>) {
        for f in files {
            if f.is_file() {
                if !self.outgoing.iter().any(|i| matches!(i, OutgoingItem::File(p) if *p == f)) {
                    self.outgoing.push(OutgoingItem::File(f));
                }
            } else if f.is_dir() {
                self.notice = Some(format!("Folders are not supported yet: {}", f.display()));
            }
        }
    }

    fn push_history(&mut self, kind: HistoryKind, title: String, detail: String, path: Option<PathBuf>, text: Option<String>) {
        self.history.insert(
            0,
            HistoryEntry { at: chrono::Local::now().format("%H:%M").to_string(), kind, title, detail, path, text },
        );
        self.history.truncate(50);
    }

    // --- update -----------------------------------------------------------------------

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Noop => Task::none(),
            Message::WindowOpened(id) => {
                self.window = Some(id);
                window::gain_focus(id)
            }
            Message::WindowClosed(id) => {
                if self.window == Some(id) {
                    self.window = None;
                }
                Task::none()
            }
            Message::CloseRequested(id) => {
                if self.tray_ok == Some(false) {
                    return iced::exit();
                }
                self.window = None;
                self.screen = Screen::Main;
                window::close(id)
            }
            Message::SystemTheme(mode) => {
                self.system_dark = mode == iced::theme::Mode::Dark;
                Task::none()
            }
            Message::BleStarted(h) => {
                if h.is_none() {
                    tracing::warn!("BLE FastInit trigger unavailable; phones may need Quick Share opened manually");
                }
                self._ble = h;
                Task::none()
            }

            Message::Discovery(DiscoveryEvent::Found(d)) => {
                self.upsert_device(Nearby::QuickShare(d));
                Task::none()
            }
            Message::Discovery(DiscoveryEvent::Lost(id)) => {
                self.remove_device(&format!("qs:{id}"));
                Task::none()
            }

            Message::Receiver(ev) => self.on_receiver(ev),
            Message::LocalSend(LocalSendEvent::Ready { info, detail }) => {
                if info.is_none() {
                    // Server gone: its peers are unreachable through us until it is back.
                    self.devices.retain(|d| !matches!(d, Nearby::LocalSend(_)));
                    if self.selected.as_deref().is_some_and(|s| s.starts_with("ls:")) {
                        self.selected = None;
                    }
                }
                self.localsend_info = info;
                self.localsend_detail = detail;
                Task::none()
            }
            Message::LocalSend(LocalSendEvent::Receiver(ev)) => self.on_receiver(ev),
            Message::LocalSend(LocalSendEvent::Found(p)) => {
                self.upsert_device(Nearby::LocalSend(p));
                Task::none()
            }
            Message::LocalSend(LocalSendEvent::Lost(fp)) => {
                self.remove_device(&format!("ls:{fp}"));
                Task::none()
            }

            Message::Ipc(ipc::Command::Ping) => Task::none(),
            Message::Ipc(ipc::Command::Show) | Message::Tray(TrayCommand::Show) => self.open_window(),
            Message::Ipc(ipc::Command::Quit) | Message::Tray(TrayCommand::Quit) => iced::exit(),
            Message::Ipc(ipc::Command::Send { files, text, clipboard }) => {
                self.screen = Screen::Main;
                self.add_files(files);
                if let Some(t) = text {
                    if !t.trim().is_empty() {
                        self.outgoing.push(OutgoingItem::text(t));
                    }
                }
                let clip = if clipboard { self.read_clipboard() } else { Task::none() };
                Task::batch([clip, self.open_window()])
            }
            Message::Tray(TrayCommand::SendClipboard) => {
                self.screen = Screen::Main;
                Task::batch([self.read_clipboard(), self.open_window()])
            }
            Message::Tray(TrayCommand::Ready(ok)) => {
                self.tray_ok = Some(ok);
                Task::none()
            }

            Message::SelectDevice(id) => {
                self.selected = Some(id);
                Task::none()
            }
            Message::DraftChanged(s) => {
                self.draft = s;
                Task::none()
            }
            Message::AddDraft => {
                if !self.draft.trim().is_empty() {
                    self.outgoing.push(OutgoingItem::text(std::mem::take(&mut self.draft)));
                }
                Task::none()
            }
            Message::RemoveItem(i) => {
                if i < self.outgoing.len() {
                    self.outgoing.remove(i);
                }
                Task::none()
            }
            Message::ClearItems => {
                self.outgoing.clear();
                self.send = SendState::Idle;
                Task::none()
            }
            Message::PickFiles => Task::perform(
                async {
                    rfd::AsyncFileDialog::new()
                        .set_title("Files to share")
                        .pick_files()
                        .await
                        .map(|hs| hs.into_iter().map(|h| h.path().to_path_buf()).collect())
                },
                Message::FilesPicked,
            ),
            Message::FilesPicked(files) => {
                if let Some(files) = files {
                    self.add_files(files);
                }
                Task::none()
            }
            Message::FileDropped(p) => {
                self.hovering_drop = false;
                self.screen = Screen::Main;
                self.add_files([p]);
                Task::none()
            }
            Message::DropHover(h) => {
                self.hovering_drop = h;
                Task::none()
            }
            Message::PasteClipboard => self.read_clipboard(),
            Message::ClipboardRead(clip) => {
                match clip {
                    Some(c) => {
                        let items = OutgoingItem::from_clipboard_text(&c);
                        if items.is_empty() {
                            self.notice = Some("Clipboard is empty.".into());
                        } else {
                            for it in items {
                                match it {
                                    OutgoingItem::File(p) => self.add_files([p]),
                                    other => self.outgoing.push(other),
                                }
                            }
                        }
                    }
                    None => self.notice = Some("Could not read the clipboard (xclip/xsel/wl-paste missing?).".into()),
                }
                Task::none()
            }

            Message::Send => {
                let Some(dev) = self.selected_device().cloned() else { return Task::none() };
                if self.outgoing.is_empty() {
                    return Task::none();
                }
                self.send = SendState::Connecting { device: dev.name().to_string() };
                let items = self.outgoing.clone();
                let name = self.config.device_name.clone();
                match dev {
                    Nearby::QuickShare(dev) => {
                        let addr = SocketAddr::from((dev.address, dev.port));
                        let endpoint = stable_endpoint_id(&uqs_core::mdns::default_hostname());
                        Task::stream(send_stream(addr, name, endpoint, items)).map(Message::SendEvent)
                    }
                    Nearby::LocalSend(peer) => {
                        let local = self.localsend_info.clone().unwrap_or_else(|| {
                            LsDeviceInfo::new(name, String::new(), uqs_localsend::DEFAULT_PORT, uqs_localsend::Protocol::Https)
                        });
                        Task::stream(localsend_send_stream(peer, local, items)).map(Message::SendEvent)
                    }
                }
            }
            Message::SendEvent(ev) => {
                let device = match &self.send {
                    SendState::Connecting { device }
                    | SendState::Waiting { device, .. }
                    | SendState::Sending { device, .. }
                    | SendState::Done { device, .. }
                    | SendState::Failed { device, .. } => device.clone(),
                    SendState::Idle => String::from("device"),
                };
                match ev {
                    SendEvent::Pin(pin) => self.send = SendState::Waiting { device, pin },
                    SendEvent::Progress(done, total) => {
                        let pin = match &self.send {
                            SendState::Waiting { pin, .. } | SendState::Sending { pin, .. } => pin.clone(),
                            _ => String::new(),
                        };
                        self.send = SendState::Sending { device, pin, done, total };
                    }
                    SendEvent::Done => {
                        let summary = describe_items(&self.outgoing);
                        self.push_history(HistoryKind::Sent, format!("Sent to {device}"), summary.clone(), None, None);
                        self.outgoing.clear();
                        self.send = SendState::Done { device, summary };
                    }
                    SendEvent::Failed(error) => {
                        self.push_history(HistoryKind::Failed, format!("Send to {device} failed"), error.clone(), None, None);
                        self.send = SendState::Failed { device, error };
                    }
                }
                Task::none()
            }
            Message::DismissSend => {
                self.send = SendState::Idle;
                Task::none()
            }

            Message::Accept(id) | Message::Decline(id) => {
                let accept = matches!(message, Message::Accept(_));
                if let Some(pos) = self.pending.iter().position(|p| p.id == id) {
                    let p = self.pending.remove(pos).expect("position exists");
                    receiver::answer(&p.reply, accept);
                    if accept {
                        let total = p.offer.files.iter().map(|f| f.size).sum::<u64>()
                            + p.offer.texts.iter().map(|t| t.size).sum::<u64>();
                        self.receiving.insert(id, Receiving { peer: p.offer.peer_name.clone(), done: 0, total });
                    }
                }
                Task::none()
            }
            Message::OpenPath(p) => Task::perform(
                async move {
                    let _ = tokio::task::spawn_blocking(move || open::that_detached(&p)).await;
                },
                |_| Message::Noop,
            ),
            Message::CopyText(t) => {
                self.notice = Some("Copied to clipboard.".into());
                Task::perform(
                    async move {
                        let _ = tokio::task::spawn_blocking(move || write_linux_clipboard_text(&t)).await;
                    },
                    |_| Message::Noop,
                )
            }
            Message::ClearHistory => {
                self.history.clear();
                Task::none()
            }
            Message::DismissNotice => {
                self.notice = None;
                Task::none()
            }

            Message::OpenSettings => {
                self.settings_draft = self.config.clone();
                self.screen = Screen::Settings;
                Task::none()
            }
            Message::CloseSettings => {
                self.screen = Screen::Main;
                Task::none()
            }
            Message::SetName(s) => {
                self.settings_draft.device_name = s;
                Task::none()
            }
            Message::SetDownloadDir(s) => {
                self.settings_draft.download_dir = PathBuf::from(s);
                Task::none()
            }
            Message::BrowseDownloadDir => Task::perform(
                async {
                    rfd::AsyncFileDialog::new()
                        .set_title("Folder for received files")
                        .pick_folder()
                        .await
                        .map(|h| h.path().to_path_buf())
                },
                Message::DownloadDirPicked,
            ),
            Message::DownloadDirPicked(p) => {
                if let Some(p) = p {
                    self.settings_draft.download_dir = p;
                }
                Task::none()
            }
            Message::SetVisible(v) => {
                self.settings_draft.visible = v;
                Task::none()
            }
            Message::SetAutoAccept(v) => {
                self.settings_draft.auto_accept = v;
                Task::none()
            }
            Message::SetLocalSend(v) => {
                self.settings_draft.localsend = v;
                Task::none()
            }
            Message::SetAppearance(a) => {
                self.settings_draft.dark = match a {
                    "Light" => Some(false),
                    "Dark" => Some(true),
                    _ => None,
                };
                Task::none()
            }
            Message::SaveSettings => {
                let mut draft = self.settings_draft.clone();
                if draft.device_name.trim().is_empty() {
                    draft.device_name = uqs_core::mdns::default_hostname();
                }
                if let Err(e) = draft.save() {
                    self.notice = Some(format!("Could not save settings: {e}"));
                }
                self.config = draft;
                self.screen = Screen::Main;
                Task::none()
            }
        }
    }

    fn on_receiver(&mut self, ev: ReceiverEvent) -> Task<Message> {
        match ev {
            ReceiverEvent::Status { visible, detail } => {
                self.receiver_visible = visible;
                self.receiver_detail = detail;
                Task::none()
            }
            ReceiverEvent::Offer { id, offer, reply } => {
                if self.config.auto_accept {
                    receiver::answer(&reply, true);
                    let total = offer.files.iter().map(|f| f.size).sum::<u64>()
                        + offer.texts.iter().map(|t| t.size).sum::<u64>();
                    self.receiving.insert(id, Receiving { peer: offer.peer_name.clone(), done: 0, total });
                    return notify("Receiving", &format!("{} · {}", offer.peer_name, describe_offer(&offer)));
                }
                self.pending.push_back(PendingOffer { id, offer: offer.clone(), reply });
                self.screen = Screen::Main;
                Task::batch([
                    self.attention(),
                    notify(
                        &format!("{} wants to share", offer.peer_name),
                        &if offer.pin.is_empty() {
                            describe_offer(&offer)
                        } else {
                            format!("{} · PIN {}", describe_offer(&offer), offer.pin)
                        },
                    ),
                ])
            }
            ReceiverEvent::Progress { id, done, total } => {
                if let Some(r) = self.receiving.get_mut(&id) {
                    r.done = done;
                    r.total = total;
                }
                Task::none()
            }
            ReceiverEvent::Done { id, items } => {
                let peer = self.receiving.remove(&id).map(|r| r.peer).unwrap_or_else(|| "a device".into());
                self.pending.retain(|p| p.id != id);
                let mut tasks = Vec::new();
                for item in items {
                    match item {
                        ReceivedItem::File { name, path, size } => {
                            self.push_history(
                                HistoryKind::Received,
                                name.clone(),
                                format!("from {peer} · {}", human_size(size)),
                                Some(path.clone()),
                                None,
                            );
                            tasks.push(notify("File received", &format!("{name} → {}", path.display())));
                        }
                        ReceivedItem::Text { title, body } => {
                            self.push_history(
                                HistoryKind::Received,
                                title.clone(),
                                format!("from {peer} · copied to clipboard"),
                                None,
                                Some(body.clone()),
                            );
                            let b = body.clone();
                            tasks.push(Task::perform(
                                async move {
                                    let _ = tokio::task::spawn_blocking(move || write_linux_clipboard_text(&b)).await;
                                },
                                |_| Message::Noop,
                            ));
                            tasks.push(notify(&format!("Copied to clipboard: {title}"), &body));
                        }
                        ReceivedItem::WifiCredentials { ssid, password, .. } => {
                            self.push_history(
                                HistoryKind::Received,
                                format!("Wi-Fi: {ssid}"),
                                format!("from {peer} · password copied"),
                                None,
                                Some(password.clone()),
                            );
                            tasks.push(notify("Wi-Fi credentials received", &format!("SSID {ssid}")));
                        }
                    }
                }
                Task::batch(tasks)
            }
            ReceiverEvent::Failed { id, peer, error } => {
                let who = self.receiving.remove(&id).map(|r| r.peer).unwrap_or(peer);
                let was_pending = self.pending.iter().any(|p| p.id == id);
                self.pending.retain(|p| p.id != id);
                if !was_pending {
                    self.push_history(HistoryKind::Failed, format!("Transfer from {who} failed"), error, None, None);
                }
                Task::none()
            }
        }
    }

    fn selected_device(&self) -> Option<&Nearby> {
        let id = self.selected.as_deref()?;
        self.devices.iter().find(|d| d.id() == id)
    }

    fn upsert_device(&mut self, d: Nearby) {
        let id = d.id();
        if let Some(existing) = self.devices.iter_mut().find(|x| x.id() == id) {
            *existing = d;
        } else {
            self.devices.push(d);
        }
        self.devices.sort_by(|a, b| a.name().to_lowercase().cmp(&b.name().to_lowercase()));
        if self.selected.is_none() && self.devices.len() == 1 {
            self.selected = Some(id);
        }
    }

    fn remove_device(&mut self, id: &str) {
        self.devices.retain(|d| d.id() != id);
        if self.selected.as_deref() == Some(id) {
            self.selected = None;
        }
    }

    // --- view -------------------------------------------------------------------------

    fn view(&self, _id: window::Id) -> Element<'_, Message> {
        let body: Element<'_, Message> = match self.screen {
            Screen::Main => self.main_screen(),
            Screen::Settings => self.settings_screen(),
        };
        let mut page = column![self.header(), body].spacing(SPACE_LG).height(Fill);
        if let Some(n) = &self.notice {
            page = page.push(
                container(
                    row![
                        text(n).size(tk::TEXT_CAPTION),
                        space::horizontal(),
                        button(icon(icons::close(), 14, false)).style(tk::quiet).padding(SPACE_XS).on_press(Message::DismissNotice),
                    ]
                    .align_y(iced::Center)
                    .spacing(SPACE_SM),
                )
                .style(tk::card)
                .padding([SPACE_XS, SPACE_MD]),
            );
        }
        container(page).padding(SPACE_XL).width(Fill).height(Fill).into()
    }

    fn header(&self) -> Element<'_, Message> {
        let pill = container(text(&self.receiver_detail).size(tk::TEXT_CAPTION))
            .style({
                let on = self.receiver_visible;
                move |t| tk::pill(t, on)
            })
            .padding([SPACE_XS, SPACE_MD]);
        let ls_pill: Element<'_, Message> = if self.config.localsend {
            container(text(&self.localsend_detail).size(tk::TEXT_CAPTION))
                .style({
                    let on = self.localsend_info.is_some() && self.config.visible;
                    move |t| tk::pill(t, on)
                })
                .padding([SPACE_XS, SPACE_MD])
                .into()
        } else {
            space::horizontal().width(0).into()
        };
        let subtitle = if self.config.localsend {
            "Android · iPhone · Windows · Linux, over your Wi-Fi"
        } else {
            "Android · Windows · Linux, over your Wi-Fi"
        };
        let settings_btn = match self.screen {
            Screen::Main => button(icon(icons::gear(), 18, false)).style(tk::quiet).padding(SPACE_SM).on_press(Message::OpenSettings),
            Screen::Settings => button(icon(icons::back(), 18, false)).style(tk::quiet).padding(SPACE_SM).on_press(Message::CloseSettings),
        };
        row![
            icon(icons::mark(), 30, true),
            column![
                text("Quick Share").size(tk::TEXT_DISPLAY),
                text(subtitle).size(tk::TEXT_CAPTION).style(muted),
            ]
            .spacing(2),
            space::horizontal(),
            ls_pill,
            pill,
            settings_btn,
        ]
        .spacing(SPACE_MD)
        .align_y(iced::Center)
        .into()
    }

    fn main_screen(&self) -> Element<'_, Message> {
        row![self.compose_panel(), self.activity_panel()]
            .spacing(SPACE_LG)
            .height(Fill)
            .into()
    }

    fn compose_panel(&self) -> Element<'_, Message> {
        let hovering = self.hovering_drop;
        let drop = container(
            column![
                text(if hovering { "Release to add" } else { "Drop files here" }).size(tk::TEXT_BODY),
                row![
                    button(text("Add files…").size(tk::TEXT_BODY)).style(tk::ghost).padding([SPACE_SM, SPACE_MD]).on_press(Message::PickFiles),
                    button(text("Paste clipboard").size(tk::TEXT_BODY)).style(tk::ghost).padding([SPACE_SM, SPACE_MD]).on_press(Message::PasteClipboard),
                ]
                .spacing(SPACE_SM),
            ]
            .spacing(SPACE_MD)
            .align_x(iced::Center),
        )
        .style(move |t| tk::drop_zone(t, hovering))
        .padding(SPACE_LG)
        .width(Fill)
        .align_x(iced::Center);

        let mut items = column![].spacing(SPACE_XS);
        for (i, item) in self.outgoing.iter().enumerate() {
            let (ic, label, meta) = match item {
                OutgoingItem::File(p) => (
                    icons::file(),
                    p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
                    std::fs::metadata(p).map(|m| human_size(m.len())).unwrap_or_default(),
                ),
                OutgoingItem::Text { kind, title, body } => (
                    match kind {
                        OutgoingTextKind::Url => icons::link(),
                        OutgoingTextKind::PhoneNumber => icons::phone(),
                        _ => icons::text(),
                    },
                    title.clone(),
                    match kind {
                        OutgoingTextKind::Url => "link".to_string(),
                        OutgoingTextKind::PhoneNumber => "phone number".to_string(),
                        _ => format!("{} chars", body.chars().count()),
                    },
                ),
            };
            items = items.push(
                row![
                    icon(ic, 16, false),
                    text(label).size(tk::TEXT_BODY).width(Fill),
                    text(meta).size(tk::TEXT_CAPTION).style(muted),
                    button(icon(icons::close(), 14, false)).style(tk::quiet).padding(SPACE_XS).on_press(Message::RemoveItem(i)),
                ]
                .spacing(SPACE_SM)
                .align_y(iced::Center),
            );
        }

        let draft_row = row![
            text_input("Type text, or paste a link…", &self.draft)
                .style(tk::input)
                .padding([SPACE_SM, SPACE_MD])
                .size(tk::TEXT_BODY)
                .on_input(Message::DraftChanged)
                .on_submit(Message::AddDraft),
            button(text("Add").size(tk::TEXT_BODY))
                .style(tk::ghost)
                .padding([SPACE_SM, SPACE_MD])
                .on_press_maybe((!self.draft.trim().is_empty()).then_some(Message::AddDraft)),
        ]
        .spacing(SPACE_SM);

        // devices
        let mut device_list = column![].spacing(SPACE_XS);
        if self.devices.is_empty() {
            let hint = if self.config.localsend {
                "No devices yet. Android: open Quick Share (or its share sheet) so the phone becomes visible. iPhone: open the LocalSend app."
            } else {
                "No devices yet. On the phone, open Quick Share (or its share sheet) so it becomes visible."
            };
            device_list = device_list.push(text(hint).size(tk::TEXT_CAPTION).style(muted));
        }
        for d in &self.devices {
            let id = d.id();
            let selected = self.selected.as_deref() == Some(id.as_str());
            let row_content = row![
                icon(d.icon(), 20, selected),
                column![
                    text(d.name()).size(tk::TEXT_BODY),
                    text(d.caption()).size(tk::TEXT_CAPTION).style(muted),
                ]
                .spacing(1)
                .width(Fill),
                if selected { icon(icons::check(), 16, true) } else { space::horizontal().width(16).into() },
            ]
            .spacing(SPACE_MD)
            .align_y(iced::Center);
            let btn = button(row_content)
                .style(tk::row_button)
                .padding([SPACE_SM, SPACE_MD])
                .width(Fill)
                .on_press(Message::SelectDevice(id));
            let wrapped: Element<'_, Message> = if selected {
                container(btn).style(tk::selected_row).width(Fill).into()
            } else {
                btn.into()
            };
            device_list = device_list.push(wrapped);
        }

        let can_send = !self.outgoing.is_empty()
            && self.selected_device().is_some()
            && !matches!(self.send, SendState::Connecting { .. } | SendState::Waiting { .. } | SendState::Sending { .. });
        let send_label = match self.selected_device() {
            Some(d) if !self.outgoing.is_empty() => format!("Send {} to {}", describe_items(&self.outgoing), d.name()),
            Some(_) => "Add something to send".to_string(),
            None => "Pick a device".to_string(),
        };

        let status: Element<'_, Message> = match &self.send {
            SendState::Idle => space::vertical().height(0).into(),
            SendState::Connecting { device } => text(format!("Connecting to {device}…")).size(tk::TEXT_CAPTION).style(muted).into(),
            SendState::Waiting { device, pin } => column![
                text(format!("Waiting for {device} to accept")).size(tk::TEXT_CAPTION).style(muted),
                pin_row(pin),
            ]
            .spacing(SPACE_XS)
            .into(),
            SendState::Sending { device, done, total, .. } => column![
                row![
                    text(format!("Sending to {device}")).size(tk::TEXT_CAPTION).style(muted).width(Fill),
                    text(format!("{} / {}", human_size(*done), human_size(*total))).size(tk::TEXT_CAPTION).style(muted),
                ],
                progress_bar(0.0..=1.0, ratio(*done, *total)).girth(6).style(tk::progress),
            ]
            .spacing(SPACE_XS)
            .into(),
            SendState::Done { device, summary } => row![
                icon(icons::check(), 16, true),
                text(format!("Sent {summary} to {device}")).size(tk::TEXT_BODY).width(Fill),
                button(text("OK").size(tk::TEXT_CAPTION)).style(tk::quiet).padding([SPACE_XS, SPACE_SM]).on_press(Message::DismissSend),
            ]
            .spacing(SPACE_SM)
            .align_y(iced::Center)
            .into(),
            SendState::Failed { device, error } => row![
                text(format!("Could not send to {device}: {error}")).size(tk::TEXT_CAPTION).style(danger_text).width(Fill),
                button(text("Dismiss").size(tk::TEXT_CAPTION)).style(tk::quiet).padding([SPACE_XS, SPACE_SM]).on_press(Message::DismissSend),
            ]
            .spacing(SPACE_SM)
            .align_y(iced::Center)
            .into(),
        };

        let send_btn = button(text(send_label).size(tk::TEXT_BODY))
            .style(tk::primary)
            .padding([SPACE_MD, SPACE_LG])
            .width(Fill)
            .on_press_maybe(can_send.then_some(Message::Send));

        let mut top = column![section("Share"), drop].spacing(SPACE_MD);
        if !self.outgoing.is_empty() {
            top = top.push(
                row![
                    text(format!("{}", describe_items(&self.outgoing))).size(tk::TEXT_CAPTION).style(muted).width(Fill),
                    button(text("Clear").size(tk::TEXT_CAPTION)).style(tk::quiet).padding([SPACE_XS, SPACE_SM]).on_press(Message::ClearItems),
                ]
                .align_y(iced::Center),
            );
            top = top.push(items);
        }
        top = top.push(draft_row);

        let devices_header = row![
            section("Nearby devices"),
            space::horizontal(),
            text(format!("{}", self.devices.len())).size(tk::TEXT_CAPTION).style(muted),
        ]
        .align_y(iced::Center);

        container(
            column![
                top,
                devices_header,
                scrollable(device_list).height(Fill),
                status,
                send_btn,
            ]
            .spacing(SPACE_MD)
            .height(Fill),
        )
        .style(tk::card)
        .padding(SPACE_LG)
        .width(Length::FillPortion(5))
        .height(Fill)
        .into()
    }

    fn activity_panel(&self) -> Element<'_, Message> {
        let mut col = column![].spacing(SPACE_MD).height(Fill);
        col = col.push(
            row![
                section("Activity"),
                space::horizontal(),
                button(text("Clear").size(tk::TEXT_CAPTION))
                    .style(tk::quiet)
                    .padding([SPACE_XS, SPACE_SM])
                    .on_press_maybe((!self.history.is_empty()).then_some(Message::ClearHistory)),
            ]
            .align_y(iced::Center),
        );

        if let Some(p) = self.pending.front() {
            let o = &p.offer;
            let mut lines = column![].spacing(2);
            for f in o.files.iter().take(4) {
                lines = lines.push(
                    row![
                        icon(icons::file(), 14, false),
                        text(&f.name).size(tk::TEXT_CAPTION).width(Fill),
                        text(human_size(f.size)).size(tk::TEXT_CAPTION).style(muted),
                    ]
                    .spacing(SPACE_SM)
                    .align_y(iced::Center),
                );
            }
            if o.files.len() > 4 {
                lines = lines.push(text(format!("…and {} more", o.files.len() - 4)).size(tk::TEXT_CAPTION).style(muted));
            }
            for t in &o.texts {
                lines = lines.push(
                    row![icon(icons::text(), 14, false), text(&t.title).size(tk::TEXT_CAPTION).width(Fill)]
                        .spacing(SPACE_SM)
                        .align_y(iced::Center),
                );
            }
            for s in &o.wifi_ssids {
                lines = lines.push(
                    row![icon(icons::wifi(), 14, false), text(format!("Wi-Fi “{s}”")).size(tk::TEXT_CAPTION).width(Fill)]
                        .spacing(SPACE_SM)
                        .align_y(iced::Center),
                );
            }
            let card = container(
                column![
                    text(format!("{} wants to share", o.peer_name)).size(tk::TEXT_TITLE),
                    text(describe_offer(o)).size(tk::TEXT_CAPTION).style(muted),
                    lines,
                    if o.pin.is_empty() {
                        // LocalSend has no confirmation code; the sender's name is the check.
                        Element::from(space::vertical().height(0))
                    } else {
                        row![
                            pin_row(&o.pin),
                            text("Same code on the phone?").size(tk::TEXT_CAPTION).style(muted),
                        ]
                        .spacing(SPACE_MD)
                        .align_y(iced::Center)
                        .into()
                    },
                    row![
                        space::horizontal(),
                        button(text("Decline").size(tk::TEXT_BODY)).style(tk::danger).padding([SPACE_SM, SPACE_MD]).on_press(Message::Decline(p.id)),
                        button(text("Accept").size(tk::TEXT_BODY)).style(tk::primary).padding([SPACE_SM, SPACE_LG]).on_press(Message::Accept(p.id)),
                    ]
                    .spacing(SPACE_SM)
                    .align_y(iced::Center),
                ]
                .spacing(SPACE_MD),
            )
            .style(tk::attention_card)
            .padding(SPACE_LG)
            .width(Fill);
            col = col.push(card);
            if self.pending.len() > 1 {
                col = col.push(text(format!("{} more waiting", self.pending.len() - 1)).size(tk::TEXT_CAPTION).style(muted));
            }
        }

        let mut receiving: Vec<&Receiving> = self.receiving.values().collect();
        receiving.sort_by(|a, b| a.peer.cmp(&b.peer));
        for r in receiving {
            col = col.push(
                column![
                    row![
                        text(format!("Receiving from {}", r.peer)).size(tk::TEXT_CAPTION).style(muted).width(Fill),
                        text(format!("{} / {}", human_size(r.done), human_size(r.total))).size(tk::TEXT_CAPTION).style(muted),
                    ],
                    progress_bar(0.0..=1.0, ratio(r.done, r.total)).girth(6).style(tk::progress),
                ]
                .spacing(SPACE_XS),
            );
        }

        let mut list = column![].spacing(SPACE_XS);
        if self.history.is_empty() && self.pending.is_empty() && self.receiving.is_empty() {
            list = list.push(
                column![
                    icon(icons::inbox(), 28, false),
                    text("Nothing yet.").size(tk::TEXT_BODY),
                    text("Shares from your phone show up here. Files go to the download folder; text and links land on your clipboard.")
                        .size(tk::TEXT_CAPTION)
                        .style(muted),
                ]
                .spacing(SPACE_SM)
                .padding([SPACE_LG, 0.0]),
            );
        }
        for (i, h) in self.history.iter().enumerate() {
            let ic = match h.kind {
                HistoryKind::Received => icons::inbox(),
                HistoryKind::Sent => icons::send(),
                HistoryKind::Failed => icons::close(),
            };
            let action: Element<'_, Message> = if let Some(p) = &h.path {
                button(text("Open").size(tk::TEXT_CAPTION))
                    .style(tk::quiet)
                    .padding([SPACE_XS, SPACE_SM])
                    .on_press(Message::OpenPath(p.clone()))
                    .into()
            } else if let Some(t) = &h.text {
                button(text("Copy").size(tk::TEXT_CAPTION))
                    .style(tk::quiet)
                    .padding([SPACE_XS, SPACE_SM])
                    .on_press(Message::CopyText(t.clone()))
                    .into()
            } else {
                space::horizontal().width(0).into()
            };
            let _ = i;
            list = list.push(
                row![
                    icon(ic, 16, h.kind == HistoryKind::Received),
                    column![
                        text(&h.title).size(tk::TEXT_BODY),
                        text(&h.detail).size(tk::TEXT_CAPTION).style(if h.kind == HistoryKind::Failed { danger_text } else { muted }),
                    ]
                    .spacing(1)
                    .width(Fill),
                    text(&h.at).size(tk::TEXT_CAPTION).style(muted),
                    action,
                ]
                .spacing(SPACE_SM)
                .align_y(iced::Center),
            );
        }
        col = col.push(scrollable(list).height(Fill));

        container(col)
            .style(tk::card)
            .padding(SPACE_LG)
            .width(Length::FillPortion(4))
            .height(Fill)
            .into()
    }

    fn settings_screen(&self) -> Element<'_, Message> {
        let d = &self.settings_draft;
        let appearance = match d.dark {
            None => "System",
            Some(false) => "Light",
            Some(true) => "Dark",
        };
        let form = column![
            section("Settings"),
            field(
                "Device name",
                "What phones see in their Quick Share list.",
                text_input("Device name", &d.device_name)
                    .style(tk::input)
                    .padding([SPACE_SM, SPACE_MD])
                    .size(tk::TEXT_BODY)
                    .on_input(Message::SetName)
                    .into(),
            ),
            field(
                "Download folder",
                "Received files are saved here.",
                row![
                    text_input("~/Downloads", &d.download_dir.to_string_lossy())
                        .style(tk::input)
                        .padding([SPACE_SM, SPACE_MD])
                        .size(tk::TEXT_BODY)
                        .on_input(Message::SetDownloadDir),
                    button(row![icon(icons::folder(), 16, false), text("Browse…").size(tk::TEXT_BODY)].spacing(SPACE_SM).align_y(iced::Center))
                        .style(tk::ghost)
                        .padding([SPACE_SM, SPACE_MD])
                        .on_press(Message::BrowseDownloadDir),
                ]
                .spacing(SPACE_SM)
                .into(),
            ),
            toggler(d.visible).label("Visible to nearby devices").size(20).on_toggle(Message::SetVisible),
            text("Off = this PC can still send, but phones cannot find it.").size(tk::TEXT_CAPTION).style(muted),
            toggler(d.auto_accept).label("Accept incoming shares automatically").size(20).on_toggle(Message::SetAutoAccept),
            text("Anyone on your Wi-Fi who can see this PC could then drop files on it. Keep off on shared networks.")
                .size(tk::TEXT_CAPTION)
                .style(muted),
            toggler(d.localsend).label("Also accept LocalSend (iPhone) shares").size(20).on_toggle(Message::SetLocalSend),
            text("Speaks the LocalSend protocol on port 53317. iPhones, and any device with the LocalSend app, can then send here and receive from here.")
                .size(tk::TEXT_CAPTION)
                .style(muted),
            field(
                "Appearance",
                "",
                pick_list(APPEARANCES, Some(appearance), Message::SetAppearance).padding([SPACE_SM, SPACE_MD]).into(),
            ),
        ]
        .spacing(SPACE_MD)
        .max_width(560);
        let footer = row![
            space::horizontal(),
            button(text("Cancel").size(tk::TEXT_BODY)).style(tk::ghost).padding([SPACE_SM, SPACE_LG]).on_press(Message::CloseSettings),
            button(text("Save").size(tk::TEXT_BODY)).style(tk::primary).padding([SPACE_SM, SPACE_XL]).on_press(Message::SaveSettings),
        ]
        .spacing(SPACE_SM)
        .width(Length::Fixed(560.0));

        container(column![scrollable(form).height(Fill), footer].spacing(SPACE_LG))
            .style(tk::card)
            .padding(SPACE_LG)
            .width(Fill)
            .height(Fill)
            .into()
    }
}

// --- view helpers ---------------------------------------------------------------------

fn section(title: &str) -> Element<'_, Message> {
    text(title).size(tk::TEXT_TITLE).into()
}

fn field<'a>(label: &'a str, hint: &'a str, control: Element<'a, Message>) -> Element<'a, Message> {
    let mut c = column![text(label).size(tk::TEXT_BODY)].spacing(SPACE_XS);
    if !hint.is_empty() {
        c = c.push(text(hint).size(tk::TEXT_CAPTION).style(muted));
    }
    c.push(control).into()
}

fn icon<'a>(handle: svg::Handle, size: u16, accent: bool) -> Element<'a, Message> {
    svg(handle)
        .width(size as f32)
        .height(size as f32)
        .style(move |t, _| tk::icon(t, accent))
        .into()
}

fn pin_row(pin: &str) -> Element<'_, Message> {
    if pin.is_empty() {
        return space::horizontal().width(0).into();
    }
    text(pin).size(tk::TEXT_PIN).font(Font::MONOSPACE).into()
}

fn muted(theme: &Theme) -> text::Style {
    text::Style { color: Some(tk::muted(theme)) }
}

fn danger_text(theme: &Theme) -> text::Style {
    text::Style { color: Some(theme.extended_palette().danger.base.color) }
}

fn device_icon(t: ShareTargetType) -> svg::Handle {
    match t {
        ShareTargetType::Phone | ShareTargetType::Foldable => icons::phone(),
        ShareTargetType::Tablet => icons::tablet(),
        ShareTargetType::Laptop => icons::laptop(),
        _ => icons::device(),
    }
}

fn ratio(done: u64, total: u64) -> f32 {
    if total == 0 {
        0.0
    } else {
        (done as f64 / total as f64).clamp(0.0, 1.0) as f32
    }
}

pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

fn describe_items(items: &[OutgoingItem]) -> String {
    let files = items.iter().filter(|i| matches!(i, OutgoingItem::File(_))).count();
    let texts = items.len() - files;
    let plural = |n: usize, one: &str, many: &str| if n == 1 { format!("1 {one}") } else { format!("{n} {many}") };
    match (files, texts) {
        (f, 0) => plural(f, "file", "files"),
        (0, t) => plural(t, "text item", "text items"),
        (f, t) => format!("{} + {}", plural(f, "file", "files"), plural(t, "text item", "text items")),
    }
}

fn describe_offer(o: &TransferOffer) -> String {
    let mut parts = Vec::new();
    if !o.files.is_empty() {
        let total: u64 = o.files.iter().map(|f| f.size).sum();
        parts.push(format!("{} file{} · {}", o.files.len(), if o.files.len() == 1 { "" } else { "s" }, human_size(total)));
    }
    if !o.texts.is_empty() {
        parts.push(format!("{} text item{}", o.texts.len(), if o.texts.len() == 1 { "" } else { "s" }));
    }
    if !o.wifi_ssids.is_empty() {
        parts.push("Wi-Fi credentials".into());
    }
    if parts.is_empty() {
        "nothing?".into()
    } else {
        parts.join(" · ")
    }
}

// --- streams & subscriptions -----------------------------------------------------------

fn handle_event(ev: Event, _status: event::Status, id: window::Id) -> Option<Message> {
    match ev {
        Event::Window(window::Event::FileDropped(p)) => Some(Message::FileDropped(p)),
        Event::Window(window::Event::FileHovered(_)) => Some(Message::DropHover(true)),
        Event::Window(window::Event::FilesHoveredLeft) => Some(Message::DropHover(false)),
        Event::Window(window::Event::CloseRequested) => Some(Message::CloseRequested(id)),
        Event::Window(window::Event::Closed) => Some(Message::WindowClosed(id)),
        _ => None,
    }
}

fn receiver_config(c: &Config) -> ReceiverConfig {
    ReceiverConfig { device_name: c.device_name.clone(), download_dir: c.download_dir.clone(), visible: c.visible }
}

fn receiver_stream(cfg: &ReceiverConfig) -> impl Stream<Item = ReceiverEvent> {
    receiver::run(cfg.clone())
}

fn localsend_config(c: &Config) -> LocalSendConfig {
    LocalSendConfig {
        device_name: c.device_name.clone(),
        download_dir: c.download_dir.clone(),
        visible: c.visible,
        enabled: c.localsend,
    }
}

fn localsend_stream(cfg: &LocalSendConfig) -> impl Stream<Item = LocalSendEvent> {
    localsend::run(cfg.clone())
}

/// LocalSend has no confirmation code: the empty `Pin` just switches the status line to
/// "Waiting for … to accept" while the other side looks at its dialog.
fn localsend_send_stream(peer: LsPeer, local: LsDeviceInfo, items: Vec<OutgoingItem>) -> impl Stream<Item = SendEvent> {
    iced::stream::channel(256, async move |mut out: Sender<SendEvent>| {
        let _ = out.send(SendEvent::Pin(String::new())).await;
        let mut prog_tx = out.clone();
        let res = uqs_localsend::send_items(&peer, &local, &items, None, move |done, total| {
            let _ = prog_tx.try_send(SendEvent::Progress(done, total));
        })
        .await;
        let _ = out
            .send(match res {
                Ok(()) => SendEvent::Done,
                Err(e) => SendEvent::Failed(e.to_string()),
            })
            .await;
    })
}

fn discovery_stream() -> impl Stream<Item = DiscoveryEvent> {
    iced::stream::channel(32, async move |mut out: Sender<DiscoveryEvent>| loop {
        match uqs_core::mdns::watch_devices() {
            Ok(mut rx) => {
                while let Some(ev) = rx.recv().await {
                    if out.send(ev).await.is_err() {
                        return;
                    }
                }
            }
            Err(e) => tracing::warn!("mDNS browse failed: {e}; retrying"),
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    })
}

fn send_stream(addr: SocketAddr, sender_name: String, endpoint_id: [u8; 4], items: Vec<OutgoingItem>) -> impl Stream<Item = SendEvent> {
    iced::stream::channel(256, async move |mut out: Sender<SendEvent>| {
        let mut pin_tx = out.clone();
        let mut prog_tx = out.clone();
        let res = send_items_to_peer_with_progress(
            addr,
            &sender_name,
            &endpoint_id,
            &items,
            None::<fn(&[u8]) -> [u8; 64]>,
            move |pin| {
                let _ = pin_tx.try_send(SendEvent::Pin(pin.to_string()));
            },
            move |done, total| {
                let _ = prog_tx.try_send(SendEvent::Progress(done, total));
            },
        )
        .await;
        let _ = out
            .send(match res {
                Ok(()) => SendEvent::Done,
                Err(e) => SendEvent::Failed(e.to_string()),
            })
            .await;
    })
}

fn notify(summary: &str, body: &str) -> Task<Message> {
    let summary = summary.to_string();
    let body = body.to_string();
    Task::perform(
        async move {
            let _ = tokio::task::spawn_blocking(move || {
                notify_rust::Notification::new()
                    .appname("Universal Quick Share")
                    .summary(&summary)
                    .body(&body)
                    .icon("document-send")
                    .show()
            })
            .await;
        },
        |_| Message::Noop,
    )
}
