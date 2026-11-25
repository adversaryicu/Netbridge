<p align="center">
  <img src="assets/netbridge-icon.png" alt="NetBridge icon" width="112" height="112">
</p>

<h1 align="center">NetBridge</h1>

<p align="center">A portable Wi-Fi Network Tap and transparent traffic inspector for the M5Stack Cardputer Zero.</p>

NetBridge turns a Cardputer Zero into a pocket-sized **inline Wi-Fi Network Tap** for inspecting and understanding the traffic of the devices and software you use. Launch it from APPLaunch to bring up an isolated Wi-Fi tap bridged to Ethernet; press **ESC** to shut down all NetBridge services and restore your previous Wi-Fi. It stays off at boot and leaves the stock desktop, launcher, and audio untouched.

<p align="center">
  <img src="assets/screen-preview.png" alt="NetBridge Cardputer Zero 320x170 screen" width="420">
</p>

<p align="center">
  <img src="assets/inspector-preview.jpg" alt="NetBridge Traffic & Application Inspector" width="860">
</p>

## Highlights

- **Full, unredacted visibility**: Captures URLs, query parameters, headers, cookies, tokens, bodies, WebSocket frames, and TLS metadata in full.
- **Plain-text export confirmation**: Authenticated `JSONL`, `HAR`, `CSV`, raw payload, and hex exports warn and require confirmation before downloading unredacted logs.
- **Capture Ingest Filters & Noise Control**: Toggle 8 traffic categories (`HTML / Text`, `JSON / API`, `Scripts & CSS`, `Images & Media`, `Fonts & Binary`, `WebSockets`, `Raw TCP`, `TLS / Errors`), filter by `Ingest host…`, or enable **Skip OS/Browser Noise** inside `mitmdump` *before* payloads are read or stored.
- **Deep Search & Offline Tab Cache**: Search on-demand across all headers, URLs, and payloads (`/api/flows-search`), with browser-only `sessionStorage` caching so logs stay viewable if the connection drops and clear when the tab closes.
- **Opt-in & Fail-open**: Uses a persistent device-local RSA-2048 CA (`/trust`), per-client approval expiring on disconnect (`/admin`), and automatic `nftables` fail-open pass-through if `netbridge-proxy.service` stops.
- **Tuned for 352 MiB RAM**: Bounded `80`-flow / `6 MiB` ring, bounded `zlib`/`zstd` decompression, `64 KiB` HTTP previews, and a one-shot framebuffer screen (`[R/5]` toggles password visibility).

## Quick Install (via SSH)

Review the source and network policy before installing on a device you own or are authorized to administer. Over Ethernet SSH on the Cardputer Zero:

```sh
git clone https://github.com/adversaryicu/Netbridge.git
cd Netbridge
chmod +x install.sh
sudo ./install.sh --apt
```

`install.sh` checks prerequisites (`--apt` installs missing Debian packages), runs the test suite, configures the `netbridge-ap` NetworkManager profile (generating a `Noun-Noun-4Digit` Wi-Fi passphrase), provisions `/usr/local/lib/netbridge/mitm-venv` (`mitmdump`), compiles the native watchdog, and adds **NetBridge** to APPLaunch.

1. Open **NetBridge** from APPLaunch (press **`R`** or **`5`** to reveal the Wi-Fi password).
2. Connect your test device, open `http://192.168.50.1/`, install the CA, and verify trust over HTTPS.
3. Pair the administrator account at `https://192.168.50.1/admin`, approve the client, and enable inspection.
4. Inspect live traffic at `https://192.168.50.1/inspector`. Press **ESC** on the Cardputer to stop.

### Update, Status & Uninstall

```sh
sudo ./install.sh update             # Pull latest, test, update code/units (preserves config & CA)
sudo ./install.sh status             # Show install state, services, and CA fingerprint
sudo ./install.sh uninstall          # Remove services/app (retains CA & config)
sudo ./install.sh uninstall --purge  # Remove everything including CA, admin, and service users
```

## Security & Distribution

- **Authorized use only**: Device-local secrets (CA private key, Wi-Fi passphrase, admin credentials) never leave the device; NetBridge does not bypass certificate pinning or silently install CAs.
- **Why GitHub over SSH**: Inline `nftables` redirection (`CAP_NET_ADMIN`) and `NetworkManager` AP control require elevated network privileges, which conflicts with the Cardputer Store's non-root app rule. Store packaging will be revisited with `CardputerZero/packages` maintainers once validation is complete.

## Docs & License

- [Architecture & Ownership](docs/architecture.md) · [Revisions & Test Checklist](docs/REVISIONS-2026-11-24.md) · [Roadmap](docs/NEXT-STEPS.md)
- Licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE) (noncommercial use only).
