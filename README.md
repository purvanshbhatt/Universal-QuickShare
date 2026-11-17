# Universal QuickShare

A universal file-sharing and device-linking daemon for Linux, reverse-engineered from the
shipped binaries and compatible with:

- **Android / Windows Quick Share** (`uqs-core`): receive and send files/text over
  `_FC9F5ED42C8A._tcp` mDNS + TCP with the UKEY2 (P256-SHA512) handshake and
  AES-256-CBC + HMAC-SHA256 device-to-device encryption. BlueZ `FE2C` FastInit BLE
  advertisement wakes up Android senders.
- **LocalSend, for iPhones** (`uqs-localsend`): LocalSend protocol v2 — multicast UDP
  discovery on `224.0.0.167:53317` and HTTPS on port 53317 with a persisted self-signed
  certificate (`~/.config/uqs/localsend/`, fingerprint = SHA-256 of the certificate).
  `/info`, `/register`, `/prepare-upload`, `/upload`, `/cancel` as receiver; `prepare-upload`
  + `upload` as sender, the peer's certificate pinned to its advertised fingerprint.
- **Apple AirDrop** (`uqs-airdrop`): `_airdrop._tcp` discovery, Apple `0x004C` BLE trigger
  payloads, OpenDrop-compatible `/Discover`, `/Ask`, `/Upload` (CPIO `070707` archives),
  and AWDL hardware detection (`awdl0` / monitor-mode check).
- **Microsoft Link to Windows** (`uqs-phonelink`): reverse-engineered clipboard sync
  (`PCPhoneCopy` / `copypaste_metadata`), SMS send/sync (`MESSAGES_SMS`), and call dialing
  (`DIAL_ON_PHONE`) over CDP `pbvalueset.ValueSet` on TCP port 5040.

## Desktop app (`uqs-gui`)

A tray app with a single window, built with iced (pure Rust, no GTK/Qt needed):

- **Receive** is always on: an incoming share opens the window with the sender's name,
  the item list and the 4-digit confirmation code; Accept/Decline. Files land in the
  download folder, text and links go straight to your clipboard.
- **Send** anything: drop files on the window, "Add files…", "Paste clipboard" (text, a
  link, or files copied in Thunar), or type/paste text. Pick a nearby device, hit Send.
- Second invocations hand off to the running instance: `uqs-gui photo.jpg`,
  `uqs-gui --clipboard`, `uqs-gui --text "https://…"`. Thunar's "Send via Quick Share"
  uses this.
- Settings: device name, download folder, visibility, auto-accept, "Also accept LocalSend
  (iPhone) shares", light/dark.

## iPhone (and anything else) via LocalSend

Native AirDrop needs AWDL, which most Linux Wi-Fi drivers (rtw88 included) do not offer.
The app therefore also speaks [LocalSend](https://localsend.org), an open protocol with
free apps for iOS, Android, Windows, macOS and Linux.

1. Install **LocalSend** from the App Store on the iPhone (Play Store / Microsoft Store /
   Homebrew for other devices).
2. Put both devices on the same Wi-Fi. The PC announces on every real interface (Ethernet,
   Wi-Fi, USB tether), so it does not matter which one the phone shares with it.
3. Open LocalSend on the phone. Its **Send** tab lists this PC under the device name from
   Settings; pick it, choose photos, files or paste a link, and tap Send.
4. On the PC the window opens with the sender's name and the item list (no PIN — LocalSend
   has none); Accept. Photos and files land in the download folder, a link or text goes
   straight to the clipboard, same as a Quick Share transfer.
5. The other way: in the PC's **Nearby devices** list the iPhone shows up with a
   *LocalSend* caption while the LocalSend app is open on it. Add files or text and Send;
   accept on the phone.

`Settings → Also accept LocalSend (iPhone) shares` turns this on and off (default on).
Turning *Visible to nearby devices* off hides the PC from LocalSend too.

If a LocalSend app is already running on this PC, it owns port 53317 and `uqs-gui` reports
`LocalSend: cannot bind` in the header; close one of them.

`scripts/install.sh` installs the launcher, an autostart entry (tray at login) and the
Thunar action, and retires the old headless `uqs.service`.

## CLI usage

```bash
uqs receive --qrcode            # receive files from your phone
uqs send photo.jpg              # send to a nearby Quick Share device
uqs send --text "https://…"     # send a link / text (also: --clipboard)
uqs discover                    # list Quick Share + AirDrop devices on the LAN
uqs localsend discover          # list LocalSend devices (iPhone app open?)
uqs localsend send photo.jpg    # send to the one LocalSend device found (--to <name> if several)
uqs localsend send --text "https://…" --target 192.168.12.7   # direct, no discovery
uqs localsend receive -o ~/Downloads   # headless LocalSend receiver on 53317
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

`cargo test -p uqs-localsend` includes an end-to-end loopback transfer (client → TLS server)
plus wire-format, fingerprint and PIN tests.

No system dependencies are needed to build (protobuf code generation uses pure-Rust
`protox` + `prost`). At runtime, Quick Share needs BlueZ (`bluetoothd`) for BLE
advertising; clipboard sync uses `wl-copy`/`wl-paste` (Wayland) or `xclip`/`xsel` (X11).

## Reverse-engineering evidence

Protocol specifications verified against shipped vendor binaries are documented in
`docs/protocol-quickshare.md` and `docs/protocol-phonelink.md`, with binary evidence
captured in `re/evidence/`.
