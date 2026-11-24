<p align="center">
  <img src="assets/netbridge-icon.png" alt="NetBridge icon" width="128" height="128">
</p>

<h1 align="center">NetBridge</h1>

<p align="center">A portable Wi-Fi Network Tap and transparent traffic inspector for the M5Stack Cardputer Zero.</p>

NetBridge turns an M5Stack Cardputer Zero into a pocket-sized **inline Wi-Fi Network Tap** for inspecting and understanding the network traffic of the devices and software you use. When opened from the Cardputer launcher, it brings up an isolated Wi-Fi access point bridged to Ethernet, displays the connection details on the 320×170 screen, and restores your previous Wi-Fi connection when closed with **ESC**. It stays off at boot and leaves the existing Cardputer desktop, launcher, audio, and network services untouched.

The goal of NetBridge is **full, unredacted visibility** into client traffic. Once a client device trusts the local CA and is enabled for inspection, NetBridge captures and presents URLs, query parameters, headers, request/response bodies, WebSocket frames, and TLS/connection metadata in full—nothing is hidden or redacted from the operator—through the built-in **Traffic & Application Inspector** (`/inspector`).

## Inspection philosophy

- **Full visibility, no redaction**: NetBridge is built to help you see everything your devices and applications actually send over the wire. Logged traffic is intended to be inspected in full without hiding headers, query parameters, cookies, tokens, or payloads.
- **Plain-text export warning**: Because captured logs are unredacted, exporting them (`JSONL`, `HAR`, or `CSV`) produces plain-text files that can expose sensitive data such as session tokens, cookies, or credentials. Exports require authentication, present a warning, and require confirmation before downloading.

## Features

- **Portable Wi-Fi tap**: NetworkManager shared-mode WPA2 access point (`wlan0`) with DHCP, DNS, and Ethernet NAT (`eth0`) acting as an inline tap for connected test devices.
- **Opt-in transparent `mitmdump` inspection** (`netbridge-proxy.service` on `:8080`): redirects outbound public TCP traffic on `wlan0` (excluding the local portal, DNS, and protected subnets) only for explicitly approved and opted-in clients, with automatic fail-open firewall removal if the proxy stops or fails health checks.
- **Full-page Traffic & Application Inspector** (`/inspector`): dark-themed live UI with a heartbeat strip (`STATUS`, `RING`, `LAST EVENT`, `LAST POLL`), per-event timestamps, client and substring filters, full request/response headers, formatted body preview, raw payload download, side-by-side hex dump (`--set stream_large_bodies=524288`, `64 KiB` HTTP payload preview, `32 KiB` TCP/WebSocket buffer), TLS/connection metadata, and authenticated `JSONL`, `HAR`, and `CSV` exports.
- **Unified CA onboarding & Browser Trust Verification** (`/` and `/trust`): public CA download, platform install instructions, SHA-256 fingerprint, and HTTPS reachability check.
- **Persistent device-local PKI**: RSA-2048 CA with explicit rotation, a separate portal certificate, and a dedicated proxy CA directory (`/etc/netbridge/proxy-ca`).
- **Network & host isolation**: dedicated `inet netbridge` nftables table blocking AP access to host management and upstream private networks; IPv6 disabled on the AP to prevent unhandled bypass paths; UDP/443 QUIC rejection for inspected clients so traffic falls back to TCP/TLS.
- **Authenticated administration** (`/admin`): first-administrator pairing code, salted scrypt passwords, CSRF protection, secure cookies, rate limiting, and per-client approval state that expires on disconnect.
- **On-demand Cardputer lifecycle**: native launcher entry with a transparent cyber-style icon, session-owned startup and cleanup (including recovery after a hung or force-closed app), and zero boot-time background overhead.
- **Memory-bounded capture**: bounded HTTP framing, sessions, request sizes, workers, audit logs, and single-file flow storage (`80`-flow / `6 MiB` cap) tuned for the Cardputer Zero's 352 MiB RAM.

## Requirements

- M5Stack Cardputer Zero running Debian ARM64 with NetworkManager, systemd,
  nftables, Python 3, `python3-h11`, `python3-cryptography`, Pillow, a C compiler,
  and the vendor APPLaunch launcher.
- `mitmproxy` (`mitmdump`) dependencies provisioned into an isolated virtual
  environment (`/usr/local/lib/netbridge/mitm-venv`) during portal setup.
- Built-in Wi-Fi capable of AP mode and built-in Ethernet connected to an
  authorized upstream network.
- Root access for one-time installation. The running app uses a fixed, narrowly
  scoped privileged broker and does not ask for a system password each time.

The implementation is device-specific. It validates the Wi-Fi country/interface
configuration and refuses to overwrite unknown NetworkManager resources.

## Install on a Cardputer

Read the source and review the network policy before applying it to a device you
own or are authorized to administer. From this repository on the Cardputer:

```sh
python3 -m unittest discover -s tests -v
sudo python3 scripts/netbridge-network.py install
sudo python3 scripts/netbridge-portal.py install
sudo python3 scripts/install-app.py --user "$USER"
```

`netbridge-portal.py install` provisions the isolated `mitmdump` virtual
environment at `/usr/local/lib/netbridge/mitm-venv` and publishes the proxy CA
identity under `/etc/netbridge/proxy-ca`.

Then open **NetBridge** from APPLaunch. It displays the SSID, password, and portal
URL. Connect a device you own or are authorized to inspect, open the displayed
HTTP address, install the public CA using the platform instructions, verify trust
over HTTPS on the same page, and pair the first administrator. Choose the
administrator password directly in the browser; it is never stored in this
repository.

Once a client is approved in `/admin`, toggle inspection on for that client and
view its traffic live at `/inspector`.

The app records the currently active Wi-Fi profile at launch. Press **ESC** to
stop the NetBridge-owned services and restore that profile. A transient systemd
session also cleans up after a crash or stale heartbeat. NetBridge services are
not enabled at boot.

## Security model

NetBridge is intended for inspecting devices and software on networks you own or
are explicitly authorized to test:

- **Device secrets stay on-device**: The CA private key, Wi-Fi passphrase, and
  administrator credentials remain local to the device and are never served or
  exported.
- **Captured traffic is unredacted**: Logged client requests, headers, query
  parameters, cookies, tokens, and payloads are shown in full to the
  authenticated operator in `/inspector`. Plain-text exports (`JSONL`, `HAR`,
  `CSV`) carry the same unredacted data and warn the user to confirm before
  downloading.
- **Explicit opt-in & fail-open routing**: Inspection is disabled by default,
  scoped strictly to approved and opted-in clients, and falls back to direct
  pass-through immediately if `netbridge-proxy.service` stops or fails health
  checks.
- **Hardened portal**: Administrative actions and traffic inspection/exports
  require HTTPS, authentication, `Origin` and CSRF checks. Client approval is
  separate from CA trust and expires when the client disconnects.
- **No stealth interception**: NetBridge does not bypass certificate pinning or
  silently install a CA on client devices.

## Project layout

```text
config/       validated public network defaults
portal/       controller, portal server, PKI, mitmdump addon and browser assets
scripts/      network, installation, app lifecycle and framebuffer code
systemd/      NetBridge-owned unit templates (portal, controller, proxy, CA timer)
tests/        unit, protocol, network and lifecycle checks
assets/       selected transparent launcher icon
docs/         public architecture and planned work
```

The original design specification, device handoff, private validation reports,
credentials, CA material and runtime state are intentionally excluded from the
public repository. See [architecture](docs/architecture.md) and
[next steps](docs/NEXT-STEPS.md) for the public technical roadmap.

## Current limitations and roadmap

On the 352 MiB RAM Cardputer Zero, measured idle controller-plus-portal memory
is about 34–35 MiB PSS; with `mitmdump` active under a 150-flow burst, combined
PSS reaches about 85–86 MiB with 0 MiB swap. Full simultaneous process-tree
profiling (including AP/launcher/lease processes) remains on the roadmap.

Current gaps and upcoming work:
- **Full unredacted logging**: remove the remaining query-parameter redaction in
  `portal/proxy_addon.py` so all logged URLs and parameters appear in full.
- **Continuous live WebSocket frame tracking**: stream frames in real time while
  sockets remain open (`websocket_start` / `websocket_message`), in addition to
  `websocket_end` capture.
- **Full simultaneous process-tree memory baseline** and lifecycle edge-case
  validation.
- **ARM64 `.deb` packaging** for distribution via the Cardputer Store.

See [NEXT-STEPS.md](docs/NEXT-STEPS.md) for acceptance gates and known gaps.

## License

NetBridge is available under the [PolyForm Noncommercial License 1.0.0](LICENSE).
You may use, study, modify, and share it for noncommercial purposes. Commercial
use is not granted by this license. The complete terms are in `LICENSE`.
