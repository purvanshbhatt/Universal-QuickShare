//! BlueZ D-Bus LE Advertisement (`0000fe2c-0000-1000-8000-00805f9b34fb`) for Quick Share FastInit.
//!
//! Broadcasting this 24-byte service data on UUID `0xFE2C` wakes up nearby Android phones
//! so they begin advertising their `_FC9F5ED42C8A._tcp.local.` mDNS receiver service.

use std::collections::HashMap;

use rand::RngCore;
use thiserror::Error;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, Value};
use zbus::{interface, Connection};

pub const FAST_INIT_UUID: &str = "0000fe2c-0000-1000-8000-00805f9b34fb";
pub const FAST_INIT_PREFIX: [u8; 14] = [
    0xfc, 0x12, 0x8e, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
pub const ADV_OBJECT_PATH: &str = "/org/universalquickshare/FastInitAdvertisement";

#[derive(Debug, Error)]
pub enum BleError {
    #[error("D-Bus error: {0}")]
    Dbus(#[from] zbus::Error),
    #[error("no BlueZ adapter (`org.bluez.Adapter1`) found on system bus")]
    NoAdapterFound,
}

/// Build the 24-byte FastInit BLE service data payload:
/// 14-byte prefix (`fc128e20...`) + 9 random salt/secret_id_hash bytes + `0x00` flags byte.
pub fn build_fast_init_payload() -> Vec<u8> {
    let mut payload = Vec::with_capacity(24);
    payload.extend_from_slice(&FAST_INIT_PREFIX);
    let mut rnd = [0u8; 9];
    rand::thread_rng().fill_bytes(&mut rnd);
    payload.extend_from_slice(&rnd);
    payload.push(0x00);
    payload
}

struct FastInitAdvertisement {
    payload: Vec<u8>,
}

#[interface(name = "org.bluez.LEAdvertisement1")]
impl FastInitAdvertisement {
    #[zbus(property, name = "Type")]
    fn adv_type(&self) -> &str {
        "broadcast"
    }

    #[zbus(property, name = "ServiceData")]
    fn service_data(&self) -> HashMap<String, Value<'_>> {
        let mut map = HashMap::new();
        map.insert(
            FAST_INIT_UUID.to_string(),
            Value::from(self.payload.clone()),
        );
        map
    }

    fn release(&self) {
        tracing::debug!("BlueZ released FastInit BLE advertisement");
    }
}

pub struct BleTriggerHandle {
    conn: Connection,
    adapter_path: OwnedObjectPath,
}

impl BleTriggerHandle {
    /// Register the Quick Share FastInit BLE advertisement with BlueZ on the system bus.
    pub async fn start() -> Result<Self, BleError> {
        let conn = Connection::system().await?;
        let adapter_path = find_adapter_path(&conn).await?;

        let adv = FastInitAdvertisement {
            payload: build_fast_init_payload(),
        };
        conn.object_server().at(ADV_OBJECT_PATH, adv).await?;

        let adv_path = ObjectPath::try_from(ADV_OBJECT_PATH).expect("valid object path");
        let empty_opts: HashMap<&str, Value<'_>> = HashMap::new();

        conn.call_method(
            Some("org.bluez"),
            &adapter_path,
            Some("org.bluez.LEAdvertisingManager1"),
            "RegisterAdvertisement",
            &(adv_path, empty_opts),
        )
        .await?;

        tracing::info!("Registered Quick Share FastInit BLE advertisement on {adapter_path}");
        Ok(Self { conn, adapter_path })
    }

    pub async fn stop(self) {
        if let Ok(adv_path) = ObjectPath::try_from(ADV_OBJECT_PATH) {
            let _ = self
                .conn
                .call_method(
                    Some("org.bluez"),
                    &self.adapter_path,
                    Some("org.bluez.LEAdvertisingManager1"),
                    "UnregisterAdvertisement",
                    &(adv_path,),
                )
                .await;
        }
    }
}

async fn find_adapter_path(conn: &Connection) -> Result<OwnedObjectPath, BleError> {
    type ManagedObjects =
        HashMap<OwnedObjectPath, HashMap<String, HashMap<String, zbus::zvariant::OwnedValue>>>;

    let reply = conn
        .call_method(
            Some("org.bluez"),
            "/",
            Some("org.freedesktop.DBus.ObjectManager"),
            "GetManagedObjects",
            &(),
        )
        .await?;

    let objects: ManagedObjects = reply.body().deserialize()?;
    for (path, ifaces) in objects {
        if ifaces.contains_key("org.bluez.Adapter1") {
            return Ok(path);
        }
    }
    Err(BleError::NoAdapterFound)
}
