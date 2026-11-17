//! Universal Quick Share — desktop app (tray + window) for Linux.
//!
//! One instance owns the receiver, the tray icon and the IPC socket. Any later
//! invocation (`uqs-gui photo.jpg`, `uqs-gui --clipboard`, the Thunar action) hands
//! its request to the running instance and exits.

mod app;
mod config;
mod icons;
mod ipc;
mod receiver;
mod theme;
mod tray;

use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "uqs-gui", version, about = "Universal Quick Share — send and receive like Android, on Linux")]
struct Cli {
    /// Start in the tray without opening the window (used by autostart)
    #[arg(long)]
    hidden: bool,
    /// Text, URL or phone number to share
    #[arg(long)]
    text: Option<String>,
    /// Share whatever is on the clipboard (text, a link, or files copied in the file manager)
    #[arg(long)]
    clipboard: bool,
    /// Ask the running instance to quit
    #[arg(long)]
    quit: bool,
    /// Files to share (opens the device picker)
    files: Vec<PathBuf>,
}

fn main() -> iced::Result {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,wgpu=warn,naga=warn,iced_wgpu=warn")),
        )
        .init();

    let cli = Cli::parse();
    let files: Vec<PathBuf> = cli
        .files
        .iter()
        .map(|f| std::fs::canonicalize(f).unwrap_or_else(|_| f.clone()))
        .collect();

    let command = if cli.quit {
        Some(ipc::Command::Quit)
    } else if !files.is_empty() || cli.text.is_some() || cli.clipboard {
        Some(ipc::Command::Send { files, text: cli.text.clone(), clipboard: cli.clipboard })
    } else if !cli.hidden {
        Some(ipc::Command::Show)
    } else {
        None
    };

    // One instance only: hand the request (or a bare presence check) to a running one.
    if ipc::try_send(command.as_ref().unwrap_or(&ipc::Command::Ping)).is_ok() {
        return Ok(());
    }
    if cli.quit {
        return Ok(()); // nothing was running
    }

    app::run(app::Launch { show_window: !cli.hidden, initial: command })
}
