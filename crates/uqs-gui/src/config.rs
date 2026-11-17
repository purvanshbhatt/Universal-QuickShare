//! Persistent user settings (`~/.config/uqs/config.json`).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Config {
    /// Name other devices see in their Quick Share sheet.
    pub device_name: String,
    /// Where received files land.
    pub download_dir: PathBuf,
    /// Accept incoming transfers without asking.
    pub auto_accept: bool,
    /// Advertise on the LAN / BLE so others can find this PC.
    pub visible: bool,
    /// `None` follows the desktop's light/dark mode.
    pub dark: Option<bool>,
}

impl Default for Config {
    fn default() -> Self {
        let home = std::env::var("HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("."));
        Self {
            device_name: uqs_core::mdns::default_hostname(),
            download_dir: home.join("Downloads"),
            auto_accept: false,
            visible: true,
            dark: None,
        }
    }
}

impl Config {
    fn path() -> PathBuf {
        let base = std::env::var("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|_| std::env::var("HOME").map(|h| PathBuf::from(h).join(".config")))
            .unwrap_or_else(|_| PathBuf::from("."));
        base.join("uqs").join("config.json")
    }

    pub fn load() -> Self {
        std::fs::read_to_string(Self::path())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let path = Self::path();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }
}
