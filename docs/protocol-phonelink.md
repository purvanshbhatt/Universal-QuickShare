# Microsoft Link to Windows / Phone Link — Reverse-Engineered Protocol Specification

> Status: **verified against shipped Microsoft binaries using REA + JADX**
>
> Analyzed artifacts:
> 1. **`link_to_windows.apk`** (`com.microsoft.appmanager` v1.24082.214.0, 144 MB,
>    SHA-256 `5c66101ca1dd603039b937a23ac18aca68d96c06d30a4043e269b94eb3f1d0e5`)
>    — bound in REA as archive target; contains 35+ plaintext `.proto` schemas,
>    `classes.dex`..`classes11.dex`, and `lib/arm64-v8a/liblibnanoapi.so`.
> 2. **`lib/arm64-v8a/liblibnanoapi.so`** (11 MB ELF arm64,
>    SHA-256 `2b58a5880eb7aa95ab0512dc4de21ff39b441507d940c4f88f012b05424190ad`)
>    — Microsoft's native NanoAPI / Basix channel engine (`MessageChannel`, `BlobChannel`,
>    `AudioSourceChannel`, `VideoSourceChannel`, `BasixClientBridgeOverTcp`).
> 3. **`Microsoft.ConnectedDevices.Xamarin.Droid.dll`** (SHA-256
>    `004163e4d5b49a155e25d19f6d56c88094e69dbc05e2db08528f7f2fcc685619`,
>    REA evidence `ev_f94228bc5923d058f346b5f570aaaeddbe15a73ae11f424a94f371e3a21ff193`)
>    and its embedded native **`libcdp_sdk.so`** (6.5 MB ELF arm, SHA-256
>    `6c887fe7f3e474233c8633a8fccb5377a1f9658d5d6556c61cd936f43a4419d7`)
>    — Microsoft Connected Devices Platform (CDP / Project Rome) engine.

---

## 1. Layered Architecture

```
+-------------------------------------------------------------------+
|  Application Agents (com.microsoft.mmx.agents.M & handlers.*)      |
|  - Clipboard: PCPhoneCopy / copypaste_metadata (M.java case 4)     |
|  - SMS/MMS:   MESSAGES_SMS / MessageRequestHandler (M.java case 9) |
|  - Calls:     DIAL_ON_PHONE / CALL_LOGS (M.java case 1 & 6)        |
+-------------------------------------------------------------------+
|  Payload Serialization                                             |
|  - pbvalueset.ValueSet (value_set/valueset.proto)                  |
|  - platform_sdk.v1.ProtoCreatePlatformChannelRequest / Manifest    |
|  - side_channel.v1.SideChannelClientRequest (wake / capability)    |
+-------------------------------------------------------------------+
|  Discovery, Signaling & Transport                                  |
|  - BLE Discovery Service Data UUID:                                |
|      df444d48-ae6b-494e-a95c-50a4a0055d30                          |
|  - BLE GATT Signaling Socket (Pa.a / BleSignalingSocket*):         |
|      Service:  eedd2140-424a-4fb5-ad72-1e86dd0b2f0a                |
|      Write:    eedd2140-0000-4fb5-ad72-1e86dd0b2f0a                |
|      Notify:   eedd2140-0000-0000-ad72-1e86dd0b2f0a                |
|  - Bluetooth SideChannel UUID:                                     |
|      111FAB8F-00A2-4935-B6B4-ACA388CDD473                          |
|  - CDP / NanoAPI TCP Transport: TCP port 5040 + NamedStreams       |
+-------------------------------------------------------------------+
```

---

## 2. `pbvalueset.ValueSet` Wire Schema (`value_set/valueset.proto`)

All Rome / `AppService` agent messages are serialized as `pbvalueset.ValueSet`:
- `map<string, DataVariant> entries = 1;`
- Key `DataValueType` discriminants in `DataVariant`:
  - `DataValueType_Int32 = 4` (`int32_value = 5`)
  - `DataValueType_Int64 = 6` (`int64_value = 7`)
  - `DataValueType_Bool = 11` (`bool_value = 12`)
  - `DataValueType_String = 12` (`string_value = 13`)
  - `DataValueType_Object = 17` (`object_value = 18`, nested `ValueSet`)
  - `DataValueType_UInt8Array = 18` (`uint8_array = 21`, `bytes`)
  - `DataValueType_Int32Array = 21` (`int32_array = 24`)
  - `DataValueType_StringArray = 29` (`string_array = 32`)

---

## 3. Cross-Device Copy & Paste (`ContentTransferClipboard*`)

### 3.1 PC / Linux → Phone (`com.microsoft.mmx.agents.M`, `case 4`, lines 379–525)

Dispatched when `map.get("contentType").equals("PCPhoneCopy")`:

| `ValueSet` Key | `DataValueType` | Value |
|---|---|---|
| `"contentType"` | `String` (12) | `"PCPhoneCopy"` |
| `"correlationVector"` | `String` (12) | Correlation vector string (e.g. `"uqs.1"`) |
| `"mimetypes"` | `StringArray` (29) | `["text/plain"]`, `["text/html", "text/plain"]`, or `["image/png"]` |
| `"data"` | `StringArray` (29) | Parallel array of text/HTML strings matching `mimetypes` |
| `"image_bytes"` | `UInt8Array` (18) | Raw image bytes when `mimetypes` is `["image/png"]` / `["image/jpeg"]` |

### 3.2 Phone → PC / Linux (`com.microsoft.mmx.agents.C0256h0`, lines 860–889)

Emitted by `ClipboardManagerOnPrimaryClipChangedListenerC0260i0` when the phone's primary clip changes:
- `MediaType.COPY_METADATA` (`"copypaste_metadata"`)
- Same `"mimetypes"` (`StringArray`), `"data"` (`StringArray`), `"image_bytes"` (`UInt8Array`), and `"correlationVector"` (`String`) fields; sets `"copypaste_message_oversize": true` if text exceeds 65,536 characters.

---

## 4. SMS & MMS Messaging (`MessagingRequestHandler` & `MessageRequestHandler`)

### 4.1 `ValueSet` Protocol (`com.microsoft.mmx.agents.M` `case 8`/`9`, `com.microsoft.cll.android.w:562–718`)

| `ValueSet` Key | `DataValueType` | Description |
|---|---|---|
| `"contentType"` | `String` (12) | `"MESSAGES_SMS"` (or `"messaging"`) |
| `"correlationVector"` | `String` (12) | Correlation vector |
| `"requestType"` | `Int32` (4) | `0` = Sync metadata+content, `1` = Fetch `requestedItems`, `2` = Send SMS/MMS, `3` = Mark conversation read |
| `"threadId"` | `Int64` (6) | Thread ID (`-1` if sending to explicit recipients) |
| `"recipients"` | `StringArray` (29) | Array of destination phone numbers (e.g. `["+15551234567"]`) |
| `"toAddresses"` | `String` (12) | Alternative comma-separated destination numbers |
| `"subscriptionId"` | `Int32` (4) | SIM subscription ID (`-1` for default SIM) |
| `"tempId"` | `String` (12) | Client-generated UUID for tracking send status |
| `"body"` | `String` (12) | SMS text message body |
| `"subject"` | `String` (12) | Optional MMS subject |
| `"partCount"` | `Int32` (4) | Number of MMS attachment parts (`0` for plain SMS) |

### 4.2 `DeviceProxyClient` Command Table (`handlers/l.java:88–96`)

`MessageRequestHandler` registers 7 RPC commands:
- `"GetConversationList"`
- `"GetMessageList"`
- `"SendMessage"`
- `"UpdateConversation"` (marks conversation read)
- `"GetMessageList.AI"`
- `"SendMessage.AI"`
- `"GetMessage"`

---

## 5. Phone Calls (`DialCommandRequestHandler` & `CallingRequestHandler`)

### 5.1 Dial Call on Phone (`com.microsoft.mmx.agents.M`, `case 6`, lines 647–656)

| `ValueSet` Key | `DataValueType` | Value |
|---|---|---|
| `"contentType"` | `String` (12) | `"DIAL_ON_PHONE"` |
| `"phoneNumber"` | `String` (12) | Phone number to dial (launches `Intent.ACTION_DIAL` with `tel:<phoneNumber>`) |
| `"correlationVector"` | `String` (12) | Correlation vector |

### 5.2 Call Logs Sync (`com.microsoft.mmx.agents.M`, `case 1`, lines 286–314)

- `"contentType"`: `"CALL_LOGS"`
- `"correlationVector"`: `<cv>`
