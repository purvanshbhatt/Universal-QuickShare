# Quick Share (Google Nearby Share) — Reverse-Engineered Protocol Specification

> Status: **verified against the authentic shipped Google binary**
> `NearbyShareExe` (Quick Share by Google for Windows, v1.0.2697.0, x64, SHA-256
> `f210df187fffbbf72b9602eca9d56745ed8da66cef64b973297b584bd11e7584` of the
> `better_together.msi` payload downloaded 2026-10-13 from
> `dl.google.com/release2/Nearby/...` via Google's Omaha update service).
>
> Sources of evidence, in order of authority:
> 1. **REA analysis of the shipped binary** (evidence IDs cited below)
> 2. **Open-source code the binary is built from**: `google/nearby` (Apache-2.0)
>    and Chromium's `nearby_share` classes (confirmed present via RTTI/strings in the binary)
> 3. Community RE (grishka/NearDrop PROTOCOL.md, teaishealthy/pyquickshare MIT)
>    — cross-checked, not trusted blindly

---

## 1. Architecture

```
+---------------------------------------------------------------+
|                    Quick Share app (closed)                    |
|  Flutter UI <-> gRPC (google.quick_share_sdk.v1) <-> business  |
|  layers: visibility, certificates, transfer, paired-key logic  |
+---------------------------------------------------------------+
|         Nearby Sharing layer (Chromium nearby_share, OSS)     |
|   TransferMetadata / PairedKeyEncryptionFrame / offline prefs  |
+---------------------------------------------------------------+
|   Nearby Connections transport (github.com/google/nearby, OSS) |
|  Offline frames -> UKEY2 -> Secure msg (D2D) -> Payload layer   |
|  Mediums: WiFi LAN (mDNS+TCP), BLE v2, WiFi Direct, AWDL, BT   |
+---------------------------------------------------------------+
```

Confirmed in binary (strings):
- `location/nearby/apps/better_together/windows/nearby_share/{main,flutter_window,background_surfaces,tray_icon,...}.cc`
- `google.quick_share_sdk.v1.{Send,Accept,Reject,RegisterObserver,SetVisibility,...}` — gRPC bridge (Flutter↔native)
- RTTI: `NearbyShareCertificateManagerImpl@sharing@nearby`, `WifiLanServiceInfo` deserialization, `BwuManager` (bandwidth upgrade)

## 2. Roles & discovery

- **Receiver = server**: listens on arbitrary TCP port, advertises mDNS service
- **Sender = client**: discovers via mDNS, connects

### 2.1 mDNS service (WiFi LAN medium)

| Field | Value (verified) |
|---|---|
| Service type | `_FC9F5ED42C8A._tcp.local.` |
| Instance name | **base64** of the binary `WifiLanServiceInfo` blob below |
| TXT record `n` | **base64** of the endpoint-info TLV blob (max 131 raw bytes) |

Instance-name blob (`re/nearby/connections/implementation/wifi_lan_service_info.cc:171-212`, OpenJDK-style serialization; per-byte layout):

```
byte 0        : (version << 5) | pcp        -- version=1; pcp: 1=P2P_CLUSTER, 2=P2P_STAR, 3=P2P_POINT_TO_POINT
bytes 1..4    : endpoint_id (4 ASCII chars)
bytes 5..7    : service_id_hash (3 bytes)
byte 8        : uwb_address length (0 if absent)
[optional]    : uwb address bytes, then 1 byte webrtc-connectable flag
```

The binary rejects other values: `Cannot deserialize WifiLanServiceInfo: unsupported V1 PCP` (strings evidence).

### 2.2 BLE trigger (Android-side handshake)

Android only looks for (and advertises its own mDNS for) Quick Share after seeing a
BLE advertisement on **service UUID 0xFCA2** whose service-data prefix matches the
Quick Share format. Without it, the phone's share sheet will not show receivers
(community-verified; NearDrop could not send BLE on macOS for this reason).
On Linux, BlueZ LE advertising **can** carry service data (pyquickshare does this
via `org.bluez.LEAdvertisement1`), so both directions work.

`BleAdvertisement { version=%d, pcp=%d, fast_advertisement=%v, service_id_hash=%s, endpoint_id=%s, endpoint_info_=%s}` — format string found in binary.

### 2.3 QR-code flow (optional)

`https://quickshare.google/qrcode#key=XXX` where XXX = URL-safe base64 of
`[2-byte version 0][1-byte version 2|3][ECDSA P-256 public key X coordinate]`.
Receiver scans → immediately advertises mDNS with a QR TLV in endpoint info;
sender includes an ECDSA signature of the UKEY2 auth key in `PairedKeyEncryptionFrame.qr_code_handshake_data` (IEEE P1363 r||s, 64 bytes) to skip the accept prompt.

## 3. Connection (TCP)

Every message = **4-byte big-endian length prefix + serialized protobuf**.

Handshake sequence (verified in binary strings `read UKEY2 Message 1`, `OnReadPairedKeyEncryptionFrame`, ...):

```
client --> server: ConnectionRequest   (offline frame)
client --> server: UKEY2 ClientInit
server --> client: UKEY2 ServerInit
client --> server: UKEY2 ClientFinish
server --> client: ConnectionResponse  (plaintext accept)
client --> server: ConnectionResponse  (plaintext accept)
--- from here everything is encrypted (D2D layer) ---
server --> client: PairedKeyEncryptionFrame (or pairing result)
client --> server: PairedKeyEncryptionFrame
client --> server: Introduction (TransferMetadata, in BYTES payload)
server --> client: Response (accept/reject)
client --> server: FILE payloads (chunked)
client --> server: Disconnection
```

## 4. UKEY2 key exchange (verified: binary constant + pyquickshare + NearDrop agree)

- Cipher: **P256_SHA512** (ECDH P-256, SHA-512 commitment)
- ClientInit: version=1, 32 random bytes, `next_protocol="AES_256_CBC-HMAC_SHA256"`,
  commitment = SHA512(serialized ClientFinish message)
- Keys (all HKDF-SHA256):
  - `dhs = SHA256(ECDH(priv, peer_pub))`
  - `next_secret = HKDF(dhs, salt="UKEY2 v1 next", info=m1||m2)`
  - `auth_string  = HKDF(dhs, salt="UKEY2 v1 auth", info=m1||m2)`
  - `d2d_client_key = HKDF(next_secret, salt=D2D_SALT, info="client")`
  - `d2d_server_key = HKDF(next_secret, salt=D2D_SALT, info="server")`
  - where `D2D_SALT = SHA256("D2D") = 82aa55a0d397f88346ca1cee8d3909b95f13fa7deb1d4ab38376b8256da85510`
    **verified as raw bytes in NearbyShareExe at file offset 40669992 (0x26c9a28)**,
    adjacent to the string `SigncryptD2DPayload: payload is empty.`
  - per-direction session keys:
    `key = HKDF(d2d_{client|server}_key, salt=SHA256("SecureMessage"), info="ENC:2")` (AES-256 key)
    `hmac_key = HKDF(d2d_{client|server}_key, salt=SHA256("SecureMessage"), info="SIG:1")` (HMAC key)

- **PIN** (auth string → 4 digits): the Nearby Connections algorithm
  (`kHashModulo = 9973`, multiplier 31 over signed bytes, digit split 2+2 — see
  pyquickshare `to_pin` / OSS `authentication_utils.cc`).

## 5. D2D encryption layer

Every post-handshake offline frame body = `HeaderAndBody` protobuf:
`header.encryption_scheme = AES256_CBC`, `signature = HMAC_SHA256`,
`iv` = 16 random bytes (per message), public metadata `{version:1, type:DEVICE_TO_DEVICE_MESSAGE}`.
Signature covers header+body. Payloads > ~65KB are chunked by the **payload layer**
(`PayloadTransferFrame`: id, type BYTES|FILE, total_size, offset, LAST_CHUNK flag).
Android quirks: two frames per negotiation message (second 0-length with LAST_CHUNK);
**KEEP_ALIVE offline frame every 10 s** or Android drops the connection.

## 6. Sharing (Quick Share) layer

Protobufs (present in binary; `nearby.sharing.service.proto` etc.):
- `PairedKeyEncryptionFrame` / `PairedKeyResultFrame` — optional pairing/token handshake
- `TransferMetadata` with `token` (transfer id) — introduction message:
  text description, file list w/ sizes+mimes, pin type (default/QR/account), sender name
- `google.quick_share_sdk.TransferMetadata.token` string confirmed in binary

Receiving flow after intro: prompt user (or auto-accept rules) → `Response(ACCEPT)` →
FILE payloads arrive → write to downloads dir → done.

## 7. Sending flow (Linux → Android)

1. BLE-advertise 0xFCA2 service data (BlueZ) so Android shows the "share nearby" UI,
   OR target devices already visible via QR/mDNS
2. mDNS-browse `_FC9F5ED42C8A._tcp` to find receiver; parse instance blob (§2.1)
3. TCP connect + handshake (§3-§5), introduction, wait for accept, stream FILE payloads
4. Optional bandwidth upgrade to WiFi Direct (not required on LAN)

## 8. Endpoint info (TXT `n`) — device-profile TLV

Type-length-value records; community-documented types observed:
type 0x00 device name / type 0x01 QR blob / type 0x03 device profile
(name, device type = DESKTOP/LAPTOP/PHONE, account image URL, four account-key
hash blobs). **TODO: verify byte layout in Ghidra** (see re/evidence/ for planned probes).

## Evidence index

| Finding | Evidence |
|---|---|
| Installer is Omaha client, not managed (no CLI dir) | REA `ev_3fcb9d99199e82010cac3f74d9b0f9b59b5ce7e715a7b2dc8c468fb4dd55afd3`; Omaha update-check returned MSI URL + SHA-256 (matches downloaded file) |
| App payload inventory (PE, x64, 13 sections, 47.7 MB) | REA `ev_a3174cf01e442ab83e6d8980dab4b7e36015aa5ae2a8b3ce59ec7b50e1155033` (installer) — extracted MSI via 7z |
| D2D HKDF salt constant (raw bytes) | `NearbyShareExe` file offset 40669992, adjacent `SigncryptD2DPayload` string |
| UKEY2/PIN/BLE/PCP/mDNS internals present | strings: `UKEY2 v1`, `read UKEY2 Message 1`, `BleAdvertisement { version=%d, pcp=%d, ...}`, `Cannot deserialize WifiLanServiceInfo: unsupported V1 PCP`, `wifi_lan_mdns.cc` |
| mDNS instance/TXT encoding | OSS `google/nearby` `wifi_lan_service_info.cc` + binary strings agreement |
| Sharing protos | strings: `nearby.sharing.service.proto`, `PairedKeyEncryptionFrame`, `TransferMetadata.token` |
| Community cross-check | grishka/NearDrop PROTOCOL.md; teaishealthy/pyquickshare (MIT) |

## Reference trees

- `re/targets/msi-extract/NearbyShareExe` — main analysis target
- `re/nearby/` — google/nearby (Apache-2.0) transport reference
- `re/refs/pyquickshare/` — MIT Python implementation (send+receive) — candidate to adapt
- `re/refs/quickshare-cli-py/` — second MIT Python reference
