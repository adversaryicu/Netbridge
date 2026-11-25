# NetBridge — Project Review Revisions (2026-11-24)

This document tracks the revisions made in response to the November 24, 2026 Project Review (`NetBridge_Project_Review_2026-11-24.md`), separating what has been implemented and unit-tested remotely from what requires live testing on the M5Stack Cardputer Zero.

## 1. Review Findings & Disposition

| Finding / Recommendation | Priority | Disposition | Notes |
|---|---|---|---|
| **Finding 01** — Long-lived connections (WebSocket / TCP) memory retention | High | **Deferred to on-device testing** | Requires live multi-hour soak test on Cardputer Zero alongside continuous live WebSocket tracking (`websocket_start` / `websocket_message`). |
| **Finding 02** — Compressed payload memory spikes in `_read_message_bytes()` | High | **Implemented remotely** | Replaced unbounded `message.content` access with bounded `zlib` / `zstandard` streaming decompression capped at `MAX_HTTP_BODY + 1` bytes (`portal/proxy_addon.py`). Verified locally with synthetic 4 MiB gzip/deflate bombs. |
| **Finding 03** — Capture drop counters & stats | Medium | **Intentionally skipped** | Omitted per operator decision to avoid unnecessary RAM usage on the 352 MiB Cardputer Zero. |
| **Finding 04** — Documentation vs. source disagreement on query redaction | Medium | **Implemented remotely** | Removed dead `SENSITIVE_KEYS`, `SENSITIVE_SUBSTRINGS`, `is_sensitive_key`, and `redact_path` from `portal/proxy_addon.py`. Verified with synthetic unredacted query/header tests (`tests/test_proxy_addon.py`, `tests/test_portal.py`). |
| **Finding 05** — `validate_inbound_headers=false` in `mitmdump` | High | **Implemented remotely (regression test on-device)** | Removed `--set validate_inbound_headers=false` from `systemd/netbridge-proxy.service` so `mitmdump` validates inbound HTTP headers by default. |
| **Finding 06** — Direct port `8080` isolation & `MemoryMax` caveat | High | **Implemented remotely (probe on-device)** | Added `iifname "{wan}" tcp dport 8080 counter drop` to `chain input` in `scripts/netbridge-network.py` (LAN `input` already rejects non-DNAT port `8080` traffic). `MemoryMax` remains advisory because the Cardputer kernel lacks memory cgroups. |
| **Section 5** — Payload completeness indicator | Medium | **Implemented remotely** | Added `payload_status` (`complete`, `partial`, `streamed`, `empty`) to flow metadata (`portal/proxy_addon.py`, `portal/controller.py`) and the `/inspector` **Details** tab (`portal/static/app.js`). |
| **Section 7** — On-device RAM/stats dashboard | High | **Intentionally skipped** | Omitted per operator decision to avoid unnecessary RAM usage on the 352 MiB Cardputer Zero. |
| **Section 8** — Architecture documentation synchronization | Medium | **Implemented remotely** | Rewrote `docs/architecture.md` to document the 2026-11-24 Network Tap, `mitmdump` service, proxy CA, staging/IPC, `inspected_v4` firewall, `/inspector`, and fail-open behavior. |
| **User addition** — Capture ingest filters (memory management) | High | **Implemented remotely** | Added `/api/capture-filters` (`controller.py`, `server.py`), `/inspector` `INGEST` checkboxes (`http`, `json`, `images`, `websocket`, `tcp`, `errors`), and pre-read filtering in `proxy_addon.py` so unselected categories are skipped before body reading/decompression/staging. |

## 2. Deployment Steps on the Cardputer Zero

Once back on the Cardputer (or connected via Ethernet SSH), pull the updated repository and reinstall the updated network firewall template and systemd unit:

```sh
cd /home/digan/netbridge
git pull origin master

# Reinstall unit templates and firewall rules
sudo python3 scripts/netbridge-network.py install
sudo python3 scripts/netbridge-portal.py install
sudo systemctl daemon-reload

# Run the full unit test suite (including test_portal.py on Linux)
python3 -m unittest discover -s tests -v
```

> [!NOTE]
> `netbridge-network.py install` rewrites `/etc/netbridge/phase1.toml` from `config/phase1.toml`. If you customized `phase1.toml` on-device, back it up before running `install` or re-apply your local settings afterward.

## 3. On-Device Live Test Checklist

Run these checks with NetBridge launched from APPLaunch and a test device connected to `NetBridge-Lab`:

1. **Port `8080` Isolation (Finding 06)**
   - From an upstream Ethernet host on the LAN: confirm `curl -m 3 http://<cardputer-eth-ip>:8080/` times out / is dropped.
   - From an unapproved or non-inspected Wi-Fi client: confirm `curl -m 3 http://192.168.50.1:8080/` is rejected.
   - From an approved, opted-in client: confirm normal HTTP/HTTPS browsing works transparently.

2. **Header Validation Regression Check (Finding 05)**
   - With inspection enabled, test representative web browsers, mobile apps, and CLI clients (`curl`) to confirm restoring `mitmdump` inbound header validation does not break legitimate traffic.
   - If a specific target device sends non-standard headers that require disabling validation, document the exact client/reason before re-adding `--set validate_inbound_headers=false`.

3. **Bounded Decompression Lab Test (Finding 02)**
   - Serve a synthetic highly compressible `gzip` or `deflate` response (e.g., 4 MiB of zeros compressed to ~4 KiB) from a local test server over the tap.
   - Confirm the client receives the response without interruption, `/inspector` shows `Payload Status: partial` with a `64 KiB` preview, and `netbridge-proxy.service` RSS/PSS does not spike.

4. **Unredacted Capture & Export Confirmation (Finding 04)**
   - Send a synthetic request containing query parameters (`?token=test_token&api_key=test_key`) and `Authorization` / `Cookie` headers.
   - Confirm `/inspector` displays all query parameters and headers unredacted.
   - Click `JSONL`, `HAR`, `CSV`, `Download Raw`, and `Export Hex` in `/inspector` and confirm the plain-text export warning modal appears before download.

5. **Proxy Crash / Hang / OOM Fail-Open Recovery**
   - While an inspected client is browsing, run `sudo systemctl kill -s SIGKILL netbridge-proxy.service` (or `systemctl stop netbridge-proxy.service`).
   - Confirm `controller.py` detects the unhealthy proxy within ~2 seconds, flushes `inspected_v4`, and restores direct NAT pass-through without requiring client proxy changes.

6. **Long-Lived Connection & Memory Baseline (Finding 01)**
   - Keep a WebSocket or long-lived TCP stream open while monitoring `ps` / `/proc/<pid>/smaps_rollup` for `mitmdump`, `netbridge-controller`, `netbridge-portal`, and `dnsmasq` to measure true simultaneous process-tree PSS.

7. **Capture Ingest Filters (Memory & Ring-Slot Conservation)**
   - In `/inspector`, uncheck `Images & Media` and `HTTP / Web` (leaving e.g. `JSON / API` and `WebSockets` checked).
   - Browse an image-heavy page on the test device and confirm image requests are not ingested into the 80-flow ring, while JSON API calls and WebSockets continue to appear.
