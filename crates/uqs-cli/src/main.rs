use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{ bail, Context, Result };
use clap::{ Parser, Subcommand };
use notify_rust::Notification;
use tokio::net::TcpListener;

use uqs_airdrop::{ discover_airdrop_peers, inspect_airdrop_hardware };
use uqs_core::ble::BleTriggerHandle;
use uqs_core::framing::FrameError;
use uqs_core::mdns::{
    default_hostname, discover_devices, pick_ipv4_address, stable_endpoint_id, MdnsAdvertiser,
    ShareTargetType,
};
use uqs_core::qrcode_flow::QuickShareQrCode;
use uqs_core::transfer::{
    handle_incoming_connection, send_files_to_peer, ReceivedItem, TransferError, TransferOffer,
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
        /// Files to send
        #[arg(required = true)]
        files: Vec<PathBuf>,
    },
    /// Discover nearby Quick Share (`_FC9F5ED42C8A._tcp`) and AirDrop (`_airdrop._tcp`) devices
    Discover {
        /// Scan duration in seconds
        #[arg(short, long, default_value_t = 4)]
        timeout: u64,
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

fn prompt_offer(offer: &TransferOffer, auto_accept: bool) -> bool {
    eprintln!(
        "\nIncoming Quick Share transfer from {:?} [PIN: {}]",
        offer.peer_name, offer.pin
    );
    for f in &offer.files {
        eprintln!("  File: {} ({} bytes, {})", f.name, f.size, f.mime_type);
    }
    for t in &offer.texts {
        eprintln!("  Text: {} ({} bytes)", t.title, t.size);
    }
    for ssid in &offer.wifi_ssids {
        eprintln!("  WiFi Credentials: SSID {:?}", ssid);
    }
    notify_desktop(
        &format!("Quick Share from {} (PIN {})", offer.peer_name, offer.pin),
        &format!("{} file(s), {} text(s)", offer.files.len(), offer.texts.len()),
    );
    if auto_accept {
        eprintln!("Auto-accepting transfer.");
        return true;
    }
    eprint!("Accept transfer? [y/N]: ");
    let _ = io::stderr().flush();
    let mut line = String::new();
    if io::stdin().read_line(&mut line).is_ok() {
        matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
    } else {
        false
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
                "Universal Quick Share listening as {:?} on {}:{} (endpoint_id={})",
                device_name,
                ipv4,
                port,
                String::from_utf8_lossy(&advertiser.endpoint_id)
            );
            if qrcode {
                let qr = QuickShareQrCode::generate();
                eprintln!("\nScan QR code on Android:\n{}\nURL: {}\n", qr.render_unicode(), qr.url);
            }

            loop {
                tokio::select! {
                    accept_res = listener.accept() => {
                        let (mut stream, peer) = accept_res?;
                        match handle_incoming_connection(&mut stream, &output, |offer| {
                            prompt_offer(offer, auto_accept)
                        }).await {
                            Ok(items) => {
                                for item in items {
                                    match item {
                                        ReceivedItem::File { name, path, size } => {
                                            eprintln!("Saved file {:?} ({size} bytes) -> {}", name, path.display());
                                            notify_desktop("Quick Share File Received", &format!("{name} saved to {}", path.display()));
                                        }
                                        ReceivedItem::Text { title, body } => {
                                            eprintln!("Received text {:?}:", title);
                                            println!("{body}");
                                            notify_desktop("Quick Share Text Received", &body);
                                        }
                                        ReceivedItem::WifiCredentials { ssid, password, .. } => {
                                            eprintln!("Received WiFi SSID {:?}, Password: {:?}", ssid, password);
                                        }
                                    }
                                }
                            }
                            Err(TransferError::Framing(FrameError::ConnectionClosedImmediately)) => {
                                tracing::debug!("Peer {peer} closed immediately (reachability probe)");
                            }
                            Err(e) => {
                                eprintln!("Transfer from {peer} ended: {e}");
                            }
                        }
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
            files,
        } => {
            for f in &files {
                if !f.is_file() {
                    bail!("File not found: {}", f.display());
                }
            }
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
            send_files_to_peer(
                target_addr,
                &sender_name,
                &endpoint_id,
                &files,
                qr.as_ref().map(|q| move |auth: &[u8]| q.sign_auth_string(auth)),
                |pin| eprintln!("Confirmation PIN: {pin}"),
            )
            .await?;
            eprintln!("Transfer completed.");
        }

        Commands::Discover { timeout } => {
            let _ble = BleTriggerHandle::start().await.ok();
            let dur = Duration::from_secs(timeout);
            let (qs_res, ad_res) = tokio::join!(
                discover_devices(dur),
                discover_airdrop_peers(dur)
            );
            let qs = qs_res?;
            let ad = ad_res?;
            println!("Quick Share devices ({}):", qs.len());
            for d in &qs {
                println!(
                    "  - {} [{}] ({:?}) -> {}:{}",
                    d.device_name, d.endpoint_id, d.device_type, d.address, d.port
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
