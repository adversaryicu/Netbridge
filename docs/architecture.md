# Current architecture and ownership

As implemented 2026-11-21. This describes the gateway/onboarding application,
not the future inspection/capture architecture.

```text
Cardputer APPLaunch (existing user service, unchanged)
  -> netbridge-app.py (normal user; framebuffer and keyboard)
      -> one-shot netbridge-screen.py renderer
      -> sudo [only fixed no-argument broker]
          -> systemd-run --pipe: transient netbridge-session.service
              -> netbridge-session.py startup
                  -> capture current Wi-Fi UUID
                  -> start AP / controller / portal / renewal timer
                  -> verify HTTPS with device CA
                  -> exec netbridge-lease (native heartbeat watchdog)
              -> ExecStopPost: netbridge-session.py cleanup
                  -> stop owned services / AP, remove owned filter
                  -> restore previous Wi-Fi, retain identity/settings

Wi-Fi client -> wlan0 / 192.168.50.1
  HTTP/HTTPS -> unprivileged portal -> Unix socket -> root controller
  Internet  -> NetBridge nft filter -> NetworkManager NAT -> eth0 -> router

Root controller -> short-lived certificate/password workers
No traffic interception, capture store or export subsystem exists yet.
```

## Installed resources

| Path/resource | Ownership and purpose |
| --- | --- |
| `/usr/local/lib/netbridge/netbridge-network.py` | Root-owned network/profile/firewall operations |
| `/usr/local/lib/netbridge/netbridge-portal.py` | Portal installation, pairing and CA renewal CLI |
| `/usr/local/lib/netbridge/netbridge-app.py` | Unprivileged native app entry |
| `/usr/local/lib/netbridge/netbridge-screen.py` | One-shot screen renderer |
| `/usr/local/lib/netbridge/netbridge-session.py` | Fixed root startup/cleanup broker |
| `/usr/local/lib/netbridge/netbridge-lease` | Native stdin heartbeat watchdog |
| `/usr/local/lib/netbridge/portal/` | Controller, server, CA/storage/auth workers, static web assets |
| `/etc/netbridge/phase1.toml` | Root-only validated network configuration |
| `/etc/netbridge/ap-passphrase` | Root-only hotspot password; never include in handoff/export |
| `/etc/netbridge/portal.json` | Public gateway configuration |
| `/etc/netbridge/portal-tls/` | Separate portal certificate/key, accessible to portal group |
| `/etc/NetworkManager/system-connections/netbridge-ap.nmconnection` | Only NetBridge's connection profile; mode 0600, autoconnect false |
| `/var/lib/netbridge/phase1.json` | Interface/UUID ownership state and last previous Wi-Fi |
| `/var/lib/netbridge/ca/current` | Current generation link; CA private key remains root-only |
| `/var/lib/netbridge/portal-public/` | Public CA certificate and metadata only |
| `/var/lib/netbridge/admin.json` | Salted administrator password record, root-only |
| `/var/lib/netbridge/pairing.json` | Hashed expiring first-pair token, when applicable |
| `/var/lib/netbridge/audit.log` | Bounded action log, two rotated backups |
| `/run/netbridge/control.sock` | Restricted controller IPC; root/portal peer validation |
| `/run/netbridge-session-state.json` | Root-only snapshot for current session cleanup |
| `/etc/sudoers.d/netbridge-app` | One named launcher account, fixed broker, no arguments |
| `/usr/share/APPLaunch/applications/netbridge.desktop` | Native launcher entry |
| `/usr/share/APPLaunch/share/images/netbridge-icon.png` | Transparent 100px icon |
| nftables `inet netbridge` | NetBridge's filtering only |
| nftables `ip nm-shared-wlan0` | NetworkManager-owned shared-mode NAT; do not edit |

## Service lifecycle

Persistent unit definitions live in `/etc/systemd/system/`:

- `netbridge-ap.service`: oneshot active while AP is up; firewall before activation.
- `netbridge-controller.service`: root, restricted write paths, bounded helper API.
- `netbridge-portal.service`: `netbridge-portal` user, low-port binding capability,
  restricted filesystem/address families, CA private directory inaccessible.
- `netbridge-certificate-renew.timer` and `.service`: leaf validity checks while
  the app is open; shutdown also stops a running renewal operation.

All are disabled for boot. `netbridge-session.service` is transient, single-instance,
and created only on app launch. ExecStopPost cleanup survives a killed supervisor.
The service-start status alone was insufficient for readiness, so startup now
verifies an HTTPS response before presenting credentials.

The native watchdog is not the future proxy-health watchdog. Proxy readiness,
atomic redirect installation/removal, and failure-to-bypass behavior still need
implementation and dedicated tests.

## Source map

- `scripts/`: network/portal installers, application, screen, session, native
  watchdog source, app integration installer and icon export helper.
- `portal/controller.py`: account/session/client state and privileged operations.
- `portal/server.py`: bounded asyncio+h11 HTTP/HTTPS front end.
- `portal/pki.py`, `certificate_worker.py`: CA/leaf handling and isolated worker.
- `portal/auth_worker.py`, `storage.py`: password worker and atomic storage.
- `portal/static/`: browser onboarding/admin interface.
- `systemd/`: service/timer templates; installation does not enable boot startup.
- `tests/`: unit tests, firewall/lifecycle integration, memory measurement, preview.
- `assets/`: generated source icon and launcher PNG; prompt/provenance in README.

## Installation and update cautions

See the main README for ordered commands. Network install precedes portal install,
then app integration. The app installer needs a compiler for the tiny watchdog;
future packaging should compile it at build time. The current network installer
rewrites configuration from its source defaults on reinstall, so preserve any
device-specific settings deliberately before using it for an update.

For an icon-only update, copy the PNG and desktop entry as root, mode 0644;
do not run the full installer, which intentionally stops the old app/services.
The launcher watches its application directory. No desktop/launcher service
restart was used for this icon deployment.
