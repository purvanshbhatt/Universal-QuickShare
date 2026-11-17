//! Single-instance IPC over a Unix socket.
//!
//! The first `uqs-gui` process owns the socket and the tray; later invocations
//! (Thunar's "Send via Quick Share", a keyboard shortcut, `uqs-gui --clipboard`)
//! forward their request here and exit.

use std::io::Write;
use std::path::PathBuf;

use iced::futures::{SinkExt, Stream};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UnixListener;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Command {
    /// Presence check from `--hidden` starts; the running instance does nothing.
    Ping,
    /// Open (or focus) the main window.
    Show,
    /// Pre-load things to share and open the window on the device picker.
    Send {
        files: Vec<PathBuf>,
        text: Option<String>,
        clipboard: bool,
    },
    Quit,
}

pub fn socket_path() -> PathBuf {
    if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
        return PathBuf::from(dir).join("uqs-gui.sock");
    }
    let uid = std::fs::metadata("/proc/self").map(|m| {
        use std::os::unix::fs::MetadataExt;
        m.uid()
    });
    PathBuf::from(format!("/tmp/uqs-gui-{}.sock", uid.unwrap_or(0)))
}

/// Forward `cmd` to a running instance. `Err` means nobody is listening.
pub fn try_send(cmd: &Command) -> std::io::Result<()> {
    let mut stream = std::os::unix::net::UnixStream::connect(socket_path())?;
    let mut line = serde_json::to_string(cmd).map_err(std::io::Error::other)?;
    line.push('\n');
    stream.write_all(line.as_bytes())?;
    stream.flush()?;
    Ok(())
}

/// Bind the socket (replacing a stale one) and stream incoming commands forever.
pub fn listen() -> impl Stream<Item = Command> {
    iced::stream::channel(16, async move |mut out: iced::futures::channel::mpsc::Sender<Command>| {
        let path = socket_path();
        let _ = std::fs::remove_file(&path);
        let listener = match UnixListener::bind(&path) {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("IPC socket bind failed at {}: {e}", path.display());
                std::future::pending::<()>().await;
                unreachable!()
            }
        };
        loop {
            let Ok((stream, _)) = listener.accept().await else { continue };
            let mut line = String::new();
            let mut reader = BufReader::new(stream);
            if reader.read_line(&mut line).await.is_ok() {
                match serde_json::from_str::<Command>(line.trim()) {
                    Ok(cmd) => {
                        let _ = out.send(cmd).await;
                    }
                    Err(e) => tracing::warn!("bad IPC command {line:?}: {e}"),
                }
            }
        }
    })
}
