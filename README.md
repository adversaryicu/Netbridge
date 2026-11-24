<p align="center">
  <img src="assets/netbridge-icon.png" alt="NetBridge icon" width="128" height="128">
</p>

<h1 align="center">NetBridge</h1>

<p align="center">A local, authorized-test Wi-Fi gateway, certificate onboarding portal, and transparent traffic inspector for the M5Stack Cardputer Zero.</p>

NetBridge turns a Cardputer Zero into a small Ethernet-backed Wi-Fi gateway. The
Cardputer app starts the hotspot and local browser portal when opened, shows the
connection details on the 320×170 display, and restores the previous Wi-Fi
connection when closed. The app remains off at boot and leaves the existing
Cardputer desktop, launcher, audio and network services alone.

The current release provides connectivity, unified certificate onboarding and
browser trust verification, authenticated administration, and an opt-in
transparent `mitmdump` inspection subsystem (`netbridge-proxy.service`) with a
dedicated full-page **Traffic & Application Inspector** (`/inspector`).

## Features

- NetworkManager shared-mode WPA2 access point with DHCP, DNS and Ethernet NAT.
- Private-network and host-management protections in a dedicated nftables table.
- IPv6 disabled on the AP to avoid an unhandled bypass path, plus UDP/443 QUIC
  rejection for inspected clients so traffic falls back cleanly to TCP/TLS.
- Unified onboarding and **Browser Trust Verification** (`/` and `/trust`) with
  public CA download, platform install instructions, SHA-256 fingerprint, and
  HTTPS reachability check.
- Persistent device-local RSA-2048 CA with explicit rotation, a separate portal
  certificate, and a dedicated proxy CA directory (`/etc/netbridge/proxy-ca`).
- First-administrator pairing code, salted scrypt passwords, CSRF protection,
  secure cookies and rate limiting.
- Client approval state that expires when a client disconnects.
- Opt-in transparent `mitmdump` inspection (`netbridge-proxy.service` on `:8080`)
  redirecting outbound public TCP traffic (`wlan0`, excluding the local portal,
  DNS, and protected subnets) only for explicitly approved and opted-in clients,
  with automatic fail-open firewall removal if the proxy is disabled or
  unhealthy.
- Dedicated full-page **Traffic & Application Inspector** (`/inspector`) in an
  `adversary.icu`-inspired dark theme, featuring a live heartbeat strip
  (`STATUS`, `RING`, `LAST EVENT`, `LAST POLL`), per-event timestamps, client
  and substring filters, request/response headers, formatted body preview, raw
  payload download, side-by-side hex dump (`--set stream_large_bodies=524288`,
  `64 KiB` captured HTTP payload preview, `32 KiB` TCP/WebSocket buffer),
  TLS/connection metadata, and authenticated `JSONL`, `HAR`, and `CSV` exports.
- Native Cardputer launcher entry with a transparent cyber-style icon.
- Session-owned startup and cleanup, including recovery after a hung or force-closed app.
- Bounded HTTP framing, sessions, request sizes, single-file flow storage
  (80-flow / 6 MiB cap), workers and audit logs.

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

Then open **NetBridge** from APPLaunch. It displays the SSID, password and portal
URL. Connect an authorized phone or laptop, open the displayed HTTP address,
install the public CA using the platform instructions, verify trust over HTTPS on
the same page, and pair the first administrator. Choose the administrator
password directly in the browser; it is never stored in this repository.

Once a client is approved in `/admin`, traffic inspection can be toggled on for
selected clients and viewed live at `/inspector`.

The app records the currently active Wi-Fi profile at launch. Press **ESC** to
stop the NetBridge-owned services and restore that profile. A transient systemd
session also cleans up after a crash or stale heartbeat. NetBridge services are
not enabled at boot.

## Security model

NetBridge is for a clearly authorized test network. The CA private key remains on
the device and is never served or exported. The public portal does not infer trust
from a certificate download or a browser exception. Administrative mutations and
traffic exports require HTTPS, authentication, Origin and CSRF checks. Client
approval is separate from CA trust and is revoked on disconnection.

Inspection is disabled by default, isolated to explicitly opted-in clients, and
falls back to direct pass-through immediately if `netbridge-proxy.service` stops
or fails health checks. NetBridge does not bypass certificate pinning or silently
install a CA on client devices.

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
- **Continuous live WebSocket frame tracking** (streaming frames while sockets
  remain open, in addition to `websocket_end` capture).
- **Full simultaneous process-tree memory baseline** and lifecycle edge-case
  validation.
- **ARM64 `.deb` packaging** for distribution via the Cardputer Store.

See [NEXT-STEPS.md](docs/NEXT-STEPS.md) for acceptance gates and known gaps.

## License

NetBridge is available under the [PolyForm Noncommercial License 1.0.0](LICENSE).
You may use, study, modify, and share it for noncommercial purposes. Commercial
use is not granted by this license. The complete terms are in `LICENSE`.
