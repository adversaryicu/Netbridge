# Current architecture and ownership

As implemented 2026-11-24. NetBridge operates as an on-demand portable Wi-Fi **Network Tap** and transparent traffic inspector on the M5Stack Cardputer Zero.

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
                  -> stop proxy, portal, controller, renewal, AP; remove owned filter
                  -> restore previous Wi-Fi, retain identity/settings

Wi-Fi client -> wlan0 / 192.168.50.1
  HTTP/HTTPS (local portal) -> unprivileged portal -> Unix socket -> root controller
  Non-inspected / fail-open -> NetBridge nft filter -> NetworkManager NAT -> eth0 -> WAN
  Inspected client (@inspected_v4, public TCP != 53):
    -> nft prerouting redirect to :8080 -> netbridge-proxy (mitmdump transparent)
    -> proxy_addon.py -> stage file (/run/netbridge/proxy-stage) + Unix socket IPC
    -> root controller (/run/netbridge/flows, 80-flow / 6 MiB ring)
    -> eth0 -> WAN (direct outbound from netbridge-proxy)

Root controller -> short-lived certificate/password workers
```

## Installed resources

| Path/resource | Ownership and purpose |
| --- | --- |
| `/usr/local/lib/netbridge/netbridge-network.py` | Root-owned network/profile/firewall operations |
| `/usr/local/lib/netbridge/netbridge-portal.py` | Portal installation, `mitmdump` venv setup, pairing, and CA renewal CLI |
| `/usr/local/lib/netbridge/netbridge-app.py` | Unprivileged native app entry |
| `/usr/local/lib/netbridge/netbridge-screen.py` | One-shot screen renderer |
| `/usr/local/lib/netbridge/netbridge-session.py` | Fixed root startup/cleanup broker |
| `/usr/local/lib/netbridge/netbridge-lease` | Native stdin heartbeat watchdog |
| `/usr/local/lib/netbridge/mitm-venv/` | Isolated `mitmdump` Python virtual environment |
| `/usr/local/lib/netbridge/portal/` | Controller, portal server, `proxy_addon.py`, CA/storage/auth workers, static web assets |
| `/etc/netbridge/phase1.toml` | Root-only validated network configuration |
| `/etc/netbridge/ap-passphrase` | Root-only hotspot password; never include in handoff/export |
| `/etc/netbridge/portal.json` | Public tap configuration |
| `/etc/netbridge/portal-tls/` | Separate portal certificate/key, accessible to `netbridge-portal` group |
| `/etc/netbridge/proxy-ca/` | Combined CA material for `netbridge-proxy` (`mitmdump`), separate from portal leaf |
| `/etc/NetworkManager/system-connections/netbridge-ap.nmconnection` | Only NetBridge's connection profile; mode 0600, autoconnect false |
| `/var/lib/netbridge/phase1.json` | Interface/UUID ownership state and last previous Wi-Fi |
| `/var/lib/netbridge/ca/current` | Current generation link; CA private key remains root-only |
| `/var/lib/netbridge/portal-public/` | Public CA certificate and metadata only |
| `/var/lib/netbridge/admin.json` | Salted administrator password record, root-only |
| `/var/lib/netbridge/pairing.json` | Hashed expiring first-pair token, when applicable |
| `/var/lib/netbridge/audit.log` | Bounded action log, two rotated backups |
| `/run/netbridge/control.sock` | Restricted controller IPC; root, `netbridge-portal`, and `netbridge-proxy` (`flow-event` only) |
| `/run/netbridge/proxy-stage/` | Bounded staging directory (`MAX_STAGE_FILES=48`) for proxy-to-controller flow handoff |
| `/run/netbridge/flows/` | Bounded flow ring (`MAX_FLOWS=80`, `MAX_FLOW_STORAGE_BYTES=6 MiB`), mode 0640 root:`netbridge-portal` |
| `/run/netbridge-session-state.json` | Root-only snapshot for current session cleanup |
| `/etc/sudoers.d/netbridge-app` | One named launcher account, fixed broker, no arguments |
| `/usr/share/APPLaunch/applications/netbridge.desktop` | Native launcher entry |
| `/usr/share/APPLaunch/share/images/netbridge-icon.png` | Transparent 100px icon |
| nftables `inet netbridge` | NetBridge filtering, WAN port-8080 drop, QUIC block, and `@inspected_v4` `:8080` redirect |
| nftables `ip nm-shared-wlan0` | NetworkManager-owned shared-mode NAT; do not edit |

## Service lifecycle & privilege boundaries

Persistent unit definitions live in `/etc/systemd/system/`:

- `netbridge-ap.service`: oneshot active while AP is up; firewall applied before activation.
- `netbridge-controller.service`: root, restricted write paths, owns state, client approvals, firewall `@inspected_v4` sync, and `/run/netbridge/flows/`.
- `netbridge-portal.service`: `netbridge-portal` user, low-port binding capability, restricted filesystem/address families, CA private directory inaccessible. Serves `/`, `/trust`, `/admin`, `/inspector`, and `/api/*`.
- `netbridge-proxy.service`: `netbridge-proxy` user, runs `mitmdump` in transparent mode on `:8080` with `proxy_addon.py`. Hardened with `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `PrivateDevices=yes`, `InaccessiblePaths=/var/lib/netbridge/ca`, and `ReadWritePaths=/run/netbridge`. Starts only when inspection is enabled.
- `netbridge-certificate-renew.timer` and `.service`: leaf validity checks while the app is open; shutdown also stops a running renewal operation.

All units are disabled for boot. `netbridge-session.service` is transient, single-instance, and created only on app launch. `ExecStopPost` cleanup survives a killed supervisor.

## Inspection, IPC, and fail-open behavior

1. **Authorization**: A client must install the NetBridge CA, confirm the HTTPS trust probe (`/trust`), and be approved by an authenticated operator in `/admin`. Approval and trust reset automatically on client disconnect (`iw event` + 2s polling).
2. **Firewall & isolation**: When inspection is enabled and `netbridge-proxy.service` is healthy, `controller.py` populates `inet netbridge` set `inspected_v4`. Outbound public TCP traffic (`dport != 53`) from `@inspected_v4` is redirected to `:8080`, and `udp dport 443` (QUIC) is rejected for `@inspected_v4` so clients fall back to TCP/TLS. Direct port `8080` access is dropped from WAN (`eth0`) and rejected from non-DNAT LAN clients.
3. **Capture & bounded memory**: `proxy_addon.py` captures unredacted URLs, headers, and bounded payloads (`64 KiB` HTTP preview, `32 KiB` TCP/WebSocket buffer, bounded `zlib`/`zstd` decompression, `payload_status` indicator) and hands off staged flow records over `/run/netbridge/control.sock` (where `netbridge-proxy` UID is restricted to `flow-event` only). `controller.py` enforces an `80`-flow / `6 MiB` ring cap.
4. **Browser Inspector & Exports**: `/inspector` polls `/api/status`, fetches per-flow details/raw payloads via `/api/flow` and `/api/flow-raw`, and exports unredacted `JSONL`, `HAR`, and `CSV` via `/api/flows-export`. All exports and raw/hex downloads require an explicit plain-text sensitivity confirmation modal in the UI.
5. **Fail-open**: `controller.py` monitors `netbridge-proxy.service` (`systemctl is-active` + `:8080` listening check) every 2 seconds. If the proxy stops or fails health checks, `inspected_v4` is flushed immediately and clients revert to direct NAT pass-through.

## Source map

- `scripts/`: network/portal installers, application, screen, session, native watchdog source, app integration installer, and icon export helper.
- `portal/controller.py`: account/session/client state, firewall sync, flow ring, and privileged operations.
- `portal/server.py`: bounded asyncio+h11 HTTP/HTTPS front end and `JSONL`/`HAR`/`CSV`/raw/hex export endpoints.
- `portal/proxy_addon.py`: `mitmdump` transparent capture addon with bounded decompression and staging IPC.
- `portal/pki.py`, `certificate_worker.py`: CA/leaf handling and isolated worker.
- `portal/auth_worker.py`, `storage.py`: password worker and atomic storage.
- `portal/static/`: browser onboarding, admin, and `/inspector` interface (including export confirmation modal).
- `systemd/`: service/timer templates; installation does not enable boot startup.
- `tests/`: unit tests (`test_network.py`, `test_portal.py`, `test_proxy_addon.py`), firewall/lifecycle integration, memory measurement, preview.
- `assets/`: generated source icon and launcher PNG; prompt/provenance in README.
