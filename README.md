# Universal QuickShare

A universal file-sharing and device-linking daemon for Linux, reverse-engineered from the
shipped binaries and compatible with:

- **Android / Windows Quick Share** (`uqs-core`): receive and send files/text over
  `_FC9F5ED42C8A._tcp` mDNS + TCP with the UKEY2 (P256-SHA512) handshake and
  AES-256-CBC + HMAC-SHA256 device-to-device encryption. BlueZ `FE2C` FastInit BLE
  advertisement wakes up Android senders.
- **Apple AirDrop** (`uqs-airdrop`): `_airdrop._tcp` discovery, Apple `0x004C` BLE trigger
  payloads, OpenDrop-compatible `/Discover`, `/Ask`, `/Upload` (CPIO `070707` archives),
  and AWDL hardware detection (`awdl0` / monitor-mode check).
- **Microsoft Link to Windows** (`uqs-phonelink`): reverse-engineered clipboard sync
  (`PCPhoneCopy` / `copypaste_metadata`), SMS send/sync (`MESSAGES_SMS`), and call dialing
  (`DIAL_ON_PHONE`) over CDP `pbvalueset.ValueSet` on TCP port 5040.

## Usage

```bash
uqs receive --qrcode            # receive files from your phone
uqs send photo.jpg              # send to a nearby Quick Share device
uqs discover                    # list Quick Share + AirDrop devices on the LAN
uqs airdrop-status              # check AWDL / monitor-mode support of your WiFi card
uqs phonelink listen            # receive clipboard / SMS / call events (port 5040)
uqs phonelink copy --target <ip>:5040 --text "hello"
uqs phonelink sms  --target <ip>:5040 --to "+15551234567" --body "Hi"
uqs phonelink call --target <ip>:5040 --number "+15551234567"
```

## Build

```bash
cargo build --workspace
cargo test  --workspace
```

No system dependencies are needed to build (protobuf code generation uses pure-Rust
`protox` + `prost`). At runtime, Quick Share needs BlueZ (`bluetoothd`) for BLE
advertising; clipboard sync uses `wl-copy`/`wl-paste` (Wayland) or `xclip`/`xsel` (X11).

## Reverse-engineering evidence

Protocol specifications verified against shipped vendor binaries are documented in
`docs/protocol-quickshare.md` and `docs/protocol-phonelink.md`, with binary evidence
captured in `re/evidence/`.
