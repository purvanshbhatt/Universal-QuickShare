use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{ bail, Context, Result };
use clap::{ Parser, Subcommand };
use notify_rust::Notification;
use tokio::net::{TcpListener, TcpStream};

use uqs_airdrop::{ discover_airdrop_peers, inspect_airdrop_hardware };
use uqs_core::ble::BleTriggerHandle;
use uqs_core::framing::FrameError;
use uqs_core::mdns::{
    default_hostname, discover_devices, discover_devices_with, pick_ipv4_address, stable_endpoint_id,
    MdnsAdvertiser, ShareTargetType,
};
use uqs_core::qrcode_flow::QuickShareQrCode;
use uqs_core::transfer::{
    handle_incoming_connection, send_items_to_peer, OutgoingItem, ReceivedItem, TransferError,
    TransferOffer,
};
use uqs_phonelink::{
    accept_one_phonelink_event, build_dial_call_valueset, build_pc_to_phone_clipboard_valueset,
    build_send_sms_valueset, read_linux_clipboard_text, send_phonelink_valueset,
    write_linux_clipboard_text, ClipboardContent, OutgoingSmsRequest, PhoneLinkEvent,
    CDP_DEFAULT_TCP_PORT,
};

#[derive(Parser)]
#[command(
    name = "uqs",
    version,
    about = "Universal Quick Share — Android Quick Share, Apple AirDrop & Microsoft Link to Windows for Linux"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Receive files, text, and WiFi credentials via Android/Windows Quick Share
    Receive {
        /// Visible device name advertised over mDNS
        #[arg(short, long)]
        name: Option<String>,
        /// Output directory for received files
        #[arg(short, long, default_value = "./downloads")]
        output: PathBuf,
        /// Automatically accept all incoming transfers without prompting
        #[arg(short, long)]
        auto_accept: bool,
        /// Display a Quick Share QR code in the terminal
        #[arg(short, long)]
        qrcode: bool,
    },
    /// Send files to an Android, Windows, or Linux Quick Share receiver
    Send {
        /// Direct target address (`ip:port`), skipping mDNS discovery if provided
        #[arg(short, long)]
        target: Option<SocketAddr>,
        /// Sender device name
        #[arg(short, long)]
        name: Option<String>,
        /// Display a Quick Share QR code for pairing
        #[arg(short, long)]
        qrcode: bool,
        /// Discovery timeout in seconds when `--target` is omitted
        #[arg(long, default_value_t = 5)]
        timeout: u64,
        /// Text, URL, or phone number to share (shown on the receiver like an Android text share)
        #[arg(long)]
        text: Option<String>,
        /// Share whatever is on the local clipboard (text, a link, or files copied in the file manager)
        #[arg(long)]
        clipboard: bool,
        /// Files to send
        files: Vec<PathBuf>,
    },
    /// Discover nearby Quick Share (`_FC9F5ED42C8A._tcp`) and AirDrop (`_airdrop._tcp`) devices
    Discover {
        /// Scan duration in seconds
        #[arg(short, long, default_value_t = 4)]
        timeout: u64,
        /// Also list this PC's own advertisement (what phones see), with every address
        #[arg(long)]
        all: bool,
    },
    /// Always-on background receiver (for the systemd service): Accept/Reject popup per transfer
    Daemon {
        /// Visible device name advertised over mDNS
        #[arg(short, long)]
        name: Option<String>,
        /// Output directory for received files
        #[arg(short, long, default_value = "~/Downloads")]
        output: PathBuf,
        /// Accept incoming transfers without a popup prompt
        #[arg(short, long)]
        auto_accept: bool,
    },
    /// GUI send: discover receivers, pick one from a popup, send files
    /// (wired to the file manager's "Send via Quick Share" action)
    SendGui {
        /// Sender device name
        #[arg(short, long)]
        name: Option<String>,
        /// Discovery timeout in seconds
        #[arg(long, default_value_t = 8)]
        timeout: u64,
        /// Text, URL, or phone number to share
        #[arg(long)]
        text: Option<String>,
        /// Share whatever is on the local clipboard (text, a link, or files copied in the file manager)
        #[arg(long)]
        clipboard: bool,
        /// Files to send (passed by the file manager)
        files: Vec<PathBuf>,
    },
    /// Inspect local WiFi chipset, monitor mode, and AWDL (`awdl0`) readiness for Apple AirDrop
    AirdropStatus,
    /// Microsoft Link to Windows / Phone Link operations (Clipboard, SMS, Calls)
    Phonelink {
        #[command(subcommand)]
        action: PhoneLinkAction,
    },
}

#[derive(Subcommand)]
enum PhoneLinkAction {
    /// Listen for incoming Link to Windows `ValueSet` events (Clipboard, SMS, Calls)
    Listen {
        /// TCP port to bind (default CDP port 5040)
        #[arg(short, long, default_value_t = CDP_DEFAULT_TCP_PORT)]
        port: u16,
        /// Automatically apply incoming `PCPhoneCopy`/`copypaste_metadata` to the Linux clipboard
        #[arg(long, default_value_t = true)]
        sync_clipboard: bool,
    },
    /// Copy text (from `--text` or the local Linux clipboard) to a paired Phone Link peer (`PCPhoneCopy`)
    Copy {
        /// Target peer address (`ip:port`, default port 5040)
        #[arg(short, long)]
        target: SocketAddr,
        /// Explicit text to copy; if omitted, reads from Linux clipboard (`wl-paste`/`xclip`/`xsel`)
        #[arg(long)]
        text: Option<String>,
    },
    /// Send an SMS message through a paired Phone Link device (`MESSAGES_SMS`, `requestType=2`)
    Sms {
        /// Target peer address (`ip:port`)
        #[arg(short, long)]
        target: SocketAddr,
        /// Recipient phone number (e.g. `+15551234567`)
        #[arg(long)]
        to: String,
        /// SMS text body
        #[arg(long)]
        body: String,
    },
    /// Dial a phone call on a paired Phone Link device (`DIAL_ON_PHONE`)
    Call {
        /// Target peer address (`ip:port`)
        #[arg(short, long)]
        target: SocketAddr,
        /// Phone number to dial
        #[arg(long)]
        number: String,
    },
}

fn notify_desktop(summary: &str, body: &str) {
    let _ = Notification::new()
        .appname("Universal Quick Share")
        .summary(summary)
        .body(body)
        .show();
}

/// Expand `~/` in paths (daemon runs via systemd without a shell).
fn shellexpand_output(p: &std::path::Path) -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        if let Some(rest) = p.to_string_lossy().strip_prefix("~/") {
            return PathBuf::from(home).join(rest);
        }
    }
    p.to_path_buf()
}

/// Turn CLI inputs into the list of things to share.
///
/// Clipboard contents that are `file://` URIs (what Thunar/Nautilus put there on Copy) are
/// sent as files; anything else is sent as text with the kind (URL/phone/plain) auto-detected.
fn collect_outgoing(files: &[PathBuf], text: Option<String>, clipboard: bool) -> Result<Vec<OutgoingItem>> {
    let mut items = Vec::new();
    for f in files {
        if !f.is_file() {
            bail!("File not found: {}", f.display());
        }
        items.push(OutgoingItem::File(f.clone()));
    }
    if let Some(t) = text {
        if t.trim().is_empty() {
            bail!("--text is empty");
        }
        items.push(OutgoingItem::text(t));
    }
    if clipboard {
        let clip = read_linux_clipboard_text().context("could not read the clipboard")?;
        let mut from_clip = OutgoingItem::from_clipboard_text(&clip);
        if from_clip.is_empty() {
            bail!("clipboard is empty");
        }
        items.append(&mut from_clip);
    }
    if items.is_empty() {
        bail!("nothing to send: pass files, --text <TEXT>, or --clipboard");
    }
    Ok(items)
}

fn describe_items(items: &[OutgoingItem]) -> String {
    let files = items.iter().filter(|i| matches!(i, OutgoingItem::File(_))).count();
    let texts = items.len() - files;
    match (files, texts) {
        (f, 0) => format!("{f} file(s)"),
        (0, t) => format!("{t} text item(s)"),
        (f, t) => format!("{f} file(s) + {t} text item(s)"),
    }
}

/// Serve one accepted connection on its own task so other senders (and Android's TCP
/// reachability probes) are never queued behind a human staring at the Accept popup.
fn spawn_connection(mut stream: TcpStream, peer: SocketAddr, output: PathBuf, auto_accept: bool, verbose: bool) {
    tokio::spawn(async move {
        let res = handle_incoming_connection(&mut stream, &output, move |offer| async move {
            // `prompt_offer` blocks on the notification daemon; keep it off the async threads
            // so keep-alives to the phone continue while the user decides.
            tokio::task::spawn_blocking(move || prompt_offer(&offer, auto_accept))
                .await
                .unwrap_or(false)
        })
        .await;
        match res {
            Ok(items) => {
                if verbose {
                    for item in &items {
                        if let ReceivedItem::File { name, path, size } = item {
                            eprintln!("Saved {name} ({size} bytes) → {}", path.display());
                        }
                    }
                }
                report_received(items);
            }
            Err(TransferError::Framing(FrameError::ConnectionClosedImmediately)) => {
                tracing::debug!("Peer {peer} closed immediately (reachability probe)");
            }
            Err(e) => {
                if verbose {
                    eprintln!("Transfer from {peer} ended: {e}");
                } else {
                    tracing::warn!("transfer from {peer} failed: {e}");
                }
            }
        }
    });
}

fn report_received(items: Vec<ReceivedItem>) {
    for item in items {
        match item {
            ReceivedItem::File { name, path, size } => {
                notify_desktop("File received", &format!("{name} ({size} bytes)\n→ {}", path.display()));
            }
            ReceivedItem::Text { title, body } => {
                // Mirror Android: a received text/link lands on the clipboard, ready to paste.
                match write_linux_clipboard_text(&body) {
                    Ok(()) => notify_desktop(&format!("Copied to clipboard: {title}"), &body),
                    Err(e) => {
                        tracing::warn!("clipboard write failed: {e}");
                        notify_desktop(&format!("Text received: {title}"), &body);
                    }
                }
            }
            ReceivedItem::WifiCredentials { ssid, password, .. } => {
                notify_desktop("WiFi credentials received", &format!("SSID: {ssid}\nPassword: {password}"));
            }
        }
    }
}

/// Popup with Accept/Reject buttons, mirroring the Windows app's toast
/// (`toast=accept` / `toast=reject` action strings found in NearbyShareExe).
/// shortcut: no auto-timeout — xfce4-notifyd has no wait_for_action timeout; dismissing = reject.
fn prompt_offer(offer: &TransferOffer, auto_accept: bool) -> bool {
    let mut body = format!(
        "{} file(s){} from {}\nPIN: {}",
        offer.files.len(),
        if offer.texts.is_empty() {
            String::new()
        } else {
            format!(" + {} text(s)", offer.texts.len())
        },
        offer.peer_name,
        offer.pin
    );
    for f in offer.files.iter().take(3) {
        body.push_str(&format!("\n• {} ({})", f.name, f.mime_type));
    }
    if offer.files.len() > 3 {
        body.push_str(&format!("\n• …and {} more", offer.files.len() - 3));
    }

    if auto_accept {
        notify_desktop(&format!("Receiving from {}", offer.peer_name), &body);
        return true;
    }

    let handle = Notification::new()
        .appname("Universal Quick Share")
        .summary(&format!("Quick Share from {} — PIN {}", offer.peer_name, offer.pin))
        .body(&body)
        .icon("document-save")
        .timeout(0) // stay until user answers (xfce4-notifyd respects expire never)
        .action("accept", "Accept")
        .action("reject", "Reject")
        .show();
    match handle {
        Ok(h) => {
            // Blocks this connection's task only; one transfer at a time is fine.
            // shortcut: no auto-timeout; dismissing the popup counts as reject.
            let answer = std::cell::Cell::new(false);
            h.wait_for_action(|a| answer.set(a == "accept"));
            answer.get()
        }
        Err(_) => false,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Receive {
            name,
            output,
            auto_accept,
            qrcode,
        } => {
            let device_name = name.unwrap_or_else(default_hostname);
            let ipv4 = pick_ipv4_address().context("failed to determine local LAN IPv4 address")?;
            let listener = TcpListener::bind(("0.0.0.0", 0)).await?;
            let port = listener.local_addr()?.port();

            let _ble = match BleTriggerHandle::start().await {
                Ok(h) => Some(h),
                Err(e) => {
                    tracing::warn!("BLE FastInit trigger not started ({e}); relying on mDNS/QR");
                    None
                }
            };

            let advertiser = MdnsAdvertiser::start(
                &device_name,
                ShareTargetType::Laptop,
                ipv4,
                port,
            )?;

            eprintln!(
                "Universal Quick Share listening as {:?} on port {} via {} (endpoint_id={})",
                device_name,
                port,
                advertiser.addresses.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", "),
                String::from_utf8_lossy(&advertiser.endpoint_id)
            );
            let _ = ipv4;
            if qrcode {
                let qr = QuickShareQrCode::generate();
                eprintln!("\nScan QR code on Android:\n{}\nURL: {}\n", qr.render_unicode(), qr.url);
            }

            loop {
                tokio::select! {
                    accept_res = listener.accept() => {
                        let (stream, peer) = accept_res?;
                        spawn_connection(stream, peer, output.clone(), auto_accept, true);
                    }
                    _ = tokio::signal::ctrl_c() => {
                        eprintln!("\nShutting down receiver...");
                        break;
                    }
                }
            }
            advertiser.stop();
        }

        Commands::Send {
            target,
            name,
            qrcode,
            timeout,
            text,
            clipboard,
            files,
        } => {
            let items = collect_outgoing(&files, text, clipboard)?;
            eprintln!("Sharing {}", describe_items(&items));
            let sender_name = name.unwrap_or_else(default_hostname);
            let endpoint_id = stable_endpoint_id(&sender_name);
            let qr = if qrcode {
                let q = QuickShareQrCode::generate();
                eprintln!("Scan QR code on receiver:\n{}\nURL: {}\n", q.render_unicode(), q.url);
                Some(q)
            } else {
                None
            };

            let _ble = BleTriggerHandle::start().await.ok();

            let target_addr = if let Some(addr) = target {
                addr
            } else {
                eprintln!("Discovering nearby Quick Share receivers ({timeout}s)...");
                let devices = discover_devices(Duration::from_secs(timeout)).await?;
                if devices.is_empty() {
                    bail!("No Quick Share devices found on LAN.");
                }
                for (i, d) in devices.iter().enumerate() {
                    eprintln!(
                        "  [{}] {} ({:?}) at {}:{}",
                        i + 1,
                        d.device_name,
                        d.device_type,
                        d.address,
                        d.port
                    );
                }
                if devices.len() == 1 {
                    SocketAddr::from((devices[0].address, devices[0].port))
                } else {
                    eprint!("Select device [1-{}]: ", devices.len());
                    let _ = io::stderr().flush();
                    let mut line = String::new();
                    io::stdin().read_line(&mut line)?;
                    let idx: usize = line.trim().parse().context("invalid selection")?;
                    if idx == 0 || idx > devices.len() {
                        bail!("Selection out of range");
                    }
                    SocketAddr::from((devices[idx - 1].address, devices[idx - 1].port))
                }
            };

            eprintln!("Connecting to {target_addr}...");
            send_items_to_peer(
                target_addr,
                &sender_name,
                &endpoint_id,
                &items,
                qr.as_ref().map(|q| move |auth: &[u8]| q.sign_auth_string(auth)),
                |pin| eprintln!("Confirmation PIN: {pin}"),
            )
            .await?;
            eprintln!("Transfer completed.");
        }

        Commands::Discover { timeout, all } => {
            let _ble = BleTriggerHandle::start().await.ok();
            let dur = Duration::from_secs(timeout);
            let lan = uqs_core::mdns::lan_interfaces();
            println!(
                "Local interfaces used for Quick Share: {}",
                lan.iter().map(|i| format!("{} {}", i.name, i.addr)).collect::<Vec<_>>().join(", ")
            );
            let (qs_res, ad_res) = tokio::join!(
                discover_devices_with(dur, all),
                discover_airdrop_peers(dur)
            );
            let qs = qs_res?;
            let ad = ad_res?;
            println!("Quick Share devices ({}):", qs.len());
            for d in &qs {
                println!(
                    "  - {} [{}] ({:?}) -> {}:{}  (announced: {})",
                    d.device_name,
                    d.endpoint_id,
                    d.device_type,
                    d.address,
                    d.port,
                    d.all_addresses.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", ")
                );
            }
            println!("AirDrop devices ({}):", ad.len());
            for p in &ad {
                println!(
                    "  - {} ({}) flags={} -> {:?}:{}",
                    p.instance_name, p.hostname, p.flags, p.addresses, p.port
                );
            }
        }

        Commands::Daemon { name, output, auto_accept } => {
            let device_name = name.unwrap_or_else(default_hostname);
            let output = shellexpand_output(&output);
            std::fs::create_dir_all(&output)?;
            // shortcut: AirDrop always-on receive needs AWDL radio support this
            // rtw88 card lacks; Quick Share receive is always-on instead. Upgrade:
            // awdl0 via owl when a Tier-1 card (ath9k) is present.
            loop {
                let ipv4 = match pick_ipv4_address() {
                    Ok(ip) => ip,
                    Err(e) => {
                        tracing::warn!("no LAN address yet ({e}); retrying in 5s");
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        continue;
                    }
                };
                let listener = match TcpListener::bind(("0.0.0.0", 0)).await {
                    Ok(l) => l,
                    Err(e) => {
                        tracing::error!("bind failed: {e}");
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        continue;
                    }
                };
                let port = listener.local_addr()?.port();
                let ble = BleTriggerHandle::start().await.ok();
                let advertiser = MdnsAdvertiser::start(&device_name, ShareTargetType::Laptop, ipv4, port);
                match advertiser {
                    Ok(adv) => {
                        tracing::info!("daemon up: {:?} on {}:{} (endpoint {})", device_name, ipv4, port,
                            String::from_utf8_lossy(&adv.endpoint_id));
                        loop {
                            match listener.accept().await {
                                Ok((stream, peer)) => {
                                    spawn_connection(stream, peer, output.clone(), auto_accept, false);
                                }
                                Err(e) => {
                                    tracing::error!("accept failed: {e}");
                                    break; // rebind everything
                                }
                            }
                        }
                        adv.stop();
                    }
                    Err(e) => tracing::warn!("mDNS advertise failed: {e}"),
                }
                drop(ble);
                // advertiser died or EINTR-class crash: full restart, new port+announcement
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }

        Commands::SendGui { name, timeout, text, clipboard, files } => {
            let items = match collect_outgoing(&files, text, clipboard) {
                Ok(items) => items,
                Err(e) => {
                    notify_desktop("Quick Share", &e.to_string());
                    return Err(e);
                }
            };
            let sender_name = name.unwrap_or_else(default_hostname);
            let endpoint_id = stable_endpoint_id(&sender_name);
            let _ble = BleTriggerHandle::start().await.ok();

            notify_desktop("Quick Share", "Looking for nearby devices…");
            let devices = discover_devices(Duration::from_secs(timeout)).await?;
            if devices.is_empty() {
                notify_desktop("Quick Share", "No nearby receivers found.\nMake sure the receiving device has Quick Share open / is visible.");
                bail!("no devices");
            }

            let addr = if devices.len() == 1 {
                SocketAddr::from((devices[0].address, devices[0].port))
            } else {
                // shortcut: max 3 device buttons (notification action limit);
                // beyond that pick the strongest signal. Upgrade: real picker window.
                let mut list = String::new();
                for d in devices.iter().take(3) {
                    list.push_str(&format!("• {}\n", d.device_name));
                }
                let mut base = Notification::new();
                base.appname("Universal Quick Share")
                    .summary("Send to which device?")
                    .body(&list)
                    .timeout(0)
                    .action("dev0", &devices[0].device_name)
                    .action("cancel", "Cancel");
                if devices.len() > 1 { base.action("dev1", &devices[1].device_name); }
                if devices.len() > 2 { base.action("dev2", &devices[2].device_name); }
                let idx = match base.show() {
                    Ok(h) => {
                        let picked = std::cell::Cell::new(Option::<usize>::None);
                        h.wait_for_action(|a| {
                            picked.set(match a {
                                "dev0" => Some(0),
                                "dev1" => Some(1),
                                "dev2" => Some(2),
                                _ => None,
                            });
                        });
                        picked.get()
                    }
                    Err(_) => None,
                };
                match idx {
                    Some(i) => SocketAddr::from((devices[i].address, devices[i].port)),
                    None => bail!("canceled"),
                }
            };

            send_items_to_peer(
                addr,
                &sender_name,
                &endpoint_id,
                &items,
                None::<fn(&[u8]) -> [u8; 64]>,
                |pin| notify_desktop("Quick Share", &format!("Confirm PIN {pin} on the receiving device")),
            ).await?;
            notify_desktop("Quick Share", &format!("Sent {}.", describe_items(&items)));
        }

        Commands::AirdropStatus => {
            let report = inspect_airdrop_hardware();
            println!("{}", serde_json::to_string_pretty(&report)?);
        }

        Commands::Phonelink { action } => match action {
            PhoneLinkAction::Listen {
                port,
                sync_clipboard,
            } => {
                let listener = TcpListener::bind(("0.0.0.0", port)).await?;
                eprintln!("Phone Link (Link to Windows / CDP) listening on 0.0.0.0:{port}...");
                loop {
                    tokio::select! {
                        res = accept_one_phonelink_event(&listener) => {
                            match res {
                                Ok((peer, ev)) => match ev {
                                    PhoneLinkEvent::ClipboardReceived(clip) => {
                                        match clip {
                                            ClipboardContent::Text { plain, .. } => {
                                                eprintln!("[PhoneLink {peer}] Clipboard text: {plain:?}");
                                                if sync_clipboard {
                                                    if let Err(e) = write_linux_clipboard_text(&plain) {
                                                        tracing::warn!("Could not update system clipboard: {e}");
                                                    }
                                                }
                                                notify_desktop("Phone Clipboard Synced", &plain);
                                            }
                                            ClipboardContent::Image { mime_type, bytes } => {
                                                eprintln!("[PhoneLink {peer}] Clipboard image ({mime_type}, {} bytes)", bytes.len());
                                                notify_desktop("Phone Clipboard Image", &format!("{mime_type} ({} bytes)", bytes.len()));
                                            }
                                        }
                                    }
                                    PhoneLinkEvent::SmsReceived(sms) => {
                                        eprintln!("[PhoneLink {peer}] SMS -> {:?}: {}", sms.recipients, sms.body);
                                        notify_desktop(
                                            &format!("SMS ({})", sms.recipients.join(", ")),
                                            &sms.body,
                                        );
                                    }
                                    PhoneLinkEvent::CallDialRequested(call) => {
                                        eprintln!("[PhoneLink {peer}] Dial request: {}", call.phone_number);
                                        notify_desktop("Phone Call", &format!("Dialing {}", call.phone_number));
                                    }
                                },
                                Err(e) => eprintln!("PhoneLink packet error: {e}"),
                            }
                        }
                        _ = tokio::signal::ctrl_c() => break,
                    }
                }
            }
            PhoneLinkAction::Copy { target, text } => {
                let plain = match text {
                    Some(t) => t,
                    None => read_linux_clipboard_text()?,
                };
                let vs = build_pc_to_phone_clipboard_valueset(
                    &ClipboardContent::Text { plain, html: None },
                    "uqs.clip.1",
                );
                send_phonelink_valueset(target, &vs).await?;
                eprintln!("Sent PCPhoneCopy clipboard payload to {target}.");
            }
            PhoneLinkAction::Sms { target, to, body } => {
                let vs = build_send_sms_valueset(&OutgoingSmsRequest {
                    recipients: vec![to],
                    body,
                    thread_id: None,
                    subscription_id: None,
                    temp_id: "uqs-sms-1".to_string(),
                    correlation_vector: "uqs.sms.1".to_string(),
                });
                send_phonelink_valueset(target, &vs).await?;
                eprintln!("Sent MESSAGES_SMS send request to {target}.");
            }
            PhoneLinkAction::Call { target, number } => {
                let vs = build_dial_call_valueset(&number, "uqs.call.1");
                send_phonelink_valueset(target, &vs).await?;
                eprintln!("Sent DIAL_ON_PHONE request ({number}) to {target}.");
            }
        },
    }

    Ok(())
}
