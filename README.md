<p align="center">
  <img src="assets/netbridge-icon.png" alt="NetBridge icon" width="128" height="128">
</p>

<h1 align="center">NetBridge</h1>

<p align="center">A local, authorized-test Wi-Fi gateway and certificate onboarding app for the M5Stack Cardputer Zero.</p>

NetBridge turns a Cardputer Zero into a small Ethernet-backed Wi-Fi gateway. The
Cardputer app starts the hotspot and local browser portal when opened, shows the
connection details on the 320×170 display, and restores the previous Wi-Fi
connection when closed. The app remains off at boot and leaves the existing
Cardputer desktop, launcher, audio and network services alone.

The current release provides reliable connectivity, certificate onboarding and
authenticated administration. HTTPS traffic inspection is intentionally **not
implemented** yet; no interception or redirection is installed by this software.

## Features

- NetworkManager shared-mode WPA2 access point with DHCP, DNS and Ethernet NAT.
- Private-network and host-management protections in a dedicated nftables table.
- IPv6 disabled on the AP in the current MVP to avoid an unhandled bypass path.
- Browser onboarding at the gateway address with public CA download and SHA-256 fingerprint.
- Persistent device-local RSA-2048 CA with explicit rotation and a separate portal certificate.
- First-administrator pairing code, salted scrypt passwords, CSRF protection, secure cookies and rate limiting.
- Client approval state that expires when a client disconnects.
- Native Cardputer launcher entry with a transparent cyber-style icon.
- Session-owned startup and cleanup, including recovery after a hung or force-closed app.
- Bounded HTTP framing, sessions, request sizes, workers and audit logs.

## Requirements

- M5Stack Cardputer Zero running Debian ARM64 with NetworkManager, systemd,
  nftables, Python 3, `python3-h11`, `python3-cryptography`, Pillow, a C compiler,
  and the vendor APPLaunch launcher.
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

Then open **NetBridge** from APPLaunch. It displays the SSID, password and portal
URL. Connect an authorized phone or laptop, open the displayed HTTP address,
install the public CA using the platform instructions, verify trust over HTTPS,
and pair the first administrator. Choose the administrator password directly in
the browser; it is never stored in this repository.

The app records the currently active Wi-Fi profile at launch. Press **ESC** to
stop the NetBridge-owned services and restore that profile. A transient systemd
session also cleans up after a crash or stale heartbeat. NetBridge services are
not enabled at boot.

## Security model

NetBridge is for a clearly authorized test network. The CA private key remains on
the device and is never served or exported. The public portal does not infer trust
from a certificate download or a browser exception. Administrative mutations
require HTTPS, authentication, Origin and CSRF checks. Client approval is separate
from CA trust and is revoked on disconnection.

The MVP does not bypass certificate pinning, decrypt QUIC/HTTP3, install a CA
silently, capture traffic, export bodies, or intercept third-party devices. Do
not add inspection without explicit authorization, readiness checks and a safe
pass-through failure path.

## Project layout

```text
config/       validated public network defaults
portal/       controller, portal server, PKI and browser assets
scripts/      network, installation, app lifecycle and framebuffer code
systemd/      NetBridge-owned unit templates
tests/        unit, protocol, network and lifecycle checks
assets/       selected transparent launcher icon
docs/         public architecture and planned work
```

The original design specification, device handoff, private validation reports,
credentials, CA material and runtime state are intentionally excluded from the
public repository. See [architecture](docs/architecture.md) and
[next steps](docs/NEXT-STEPS.md) for the public technical roadmap.

## Current limitations and roadmap

The measured controller-plus-portal steady state is about 34–35 MiB PSS. The
complete app process tree is estimated around 44 MiB after replacing the Python
heartbeat supervisor with a tiny native watchdog; the requested 30 MiB target is
not yet met. A full simultaneous process-tree measurement is the next profiling
task.

The next major phase is a separately measured mitmdump integration, followed by
bounded metadata, filtering, redacted export and resilience testing. mitmdump is
the only planned inspection engine. It must remain off by default and remove
redirects immediately if unhealthy.

See [NEXT-STEPS.md](docs/NEXT-STEPS.md) for acceptance gates and known gaps.

## License

No license has been selected for this repository yet. Until one is added, all
rights remain with the project owner.
