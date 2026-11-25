# Next session plan

Baseline: 2026-11-24. NetBridge is a portable Wi-Fi **Network Tap** for the M5Stack Cardputer Zero, built to give operators full, unredacted visibility into the traffic of the devices and software they use.

Next priorities:
1. **On-device validation of 2026-11-24 revisions** (see [REVISIONS-2026-11-24.md](REVISIONS-2026-11-24.md): bounded decompression lab test, WAN port `8080` isolation probe, header-validation regression check, fail-open crash test, and unredacted synthetic verification).
2. **Continuous live WebSocket frame tracking** (`websocket_start` and `websocket_message` hooks in `portal/proxy_addon.py` so long-lived open WebSockets appear immediately and stream frames live in `/inspector` instead of waiting for `websocket_end`).

These are future tasks, not claims of completed functionality or authorization to deploy unreviewed interception.

## 1. Establish the complete memory baseline

Open the final app with native watchdog. Measure all NetBridge process trees
and NetworkManager's AP dnsmasq, including sudo/systemd-run, shell, UI, controller,
portal, `iw event` and temporary password/certificate workers. Record RSS, PSS,
SwapPss, peak usage, CPU, disk writes and available device RAM for idle, signed-in
dashboard and a bounded 1/3-client workload. Existing measure_memory.py covers
only controller/portal; extend coverage rather than relabeling its output.

Acceptance: reproducible simultaneous totals, scopes and timestamps; no swapped
memory disguised as savings. Approximately 44 MiB is currently an estimate.
Do not disable unrelated services, clear caches, reduce authentication strength
or weaken privilege separation to reach 30 MiB.

Then profile retained controller/portal allocations. Consider a compiled native
UI or control/web component only if measured benefits justify the additional
security and maintenance work. Preserve mitmdump as the only inspection engine.

## 2. Close current lifecycle and installation gaps

- Confirm the new transparent icon looks right on the physical black launcher.
- Reboot with NetBridge closed: verify it remains off and ordinary Cardputer
  functions remain available; launch it and recheck portal/Internet.
- Verify two-client Wi-Fi isolation, WAN removal/reconnect, real-client approval
  expiry, startup failure and changed/disconnected previous-Wi-Fi scenarios.
- Test full settings workflow on authorized clients. Use disposable identities
  for CA rotation unless the user deliberately wants the live CA changed.
- Refresh screen credentials after portal changes; handle long SSIDs/passwords
  legibly and consider a reveal action to meet the original secret-display intent.
- Improve actionable on-screen startup/cleanup errors and pending pairing-code
  expiry behavior; UI currently directs failures to the session log.
- Review renewal/exit races and recovery if power loss interrupts startup/cleanup.
- Add complete uninstall/update handling with explicit identity-retention choices.
  Avoid overwriting changed configuration with source defaults during updates.
- Package the program into a distributable ARM64 `.deb` file for publication
  to the **Cardputer Store**, including dependencies, precompiled native
  watchdog (`netbridge-lease`), APPLaunch desktop/icon integration, and
  maintainer scripts for clean install/upgrade/uninstall without overwriting
  existing device config or identity; test on a fresh Cardputer image without
  removing existing services.

Acceptance: existing desktop/launcher/network profiles retained; app off at boot;
known failures recover predictably; repeatable fresh install and update.

## 3. Harden transparent mitmdump tap integration

Transparent `mitmdump` integration (`netbridge-proxy.service` on `:8080`),
selected-client IPv4 TCP redirection, UDP/443 QUIC rejection for inspected
clients, and `/inspector` are implemented. Remaining hardening and verification:

- Validate proxy crash, hang, and OOM scenarios on-device to confirm redirects are
  removed immediately and direct pass-through connectivity is restored without
  requiring client reconfiguration.
- Document measured `mitmdump` memory/CPU behavior under sustained multi-client
  traffic (noting that this kernel lacks memory cgroup enforcement, so unit
  `MemoryMax` values are not hard protection).
- Keep documentation explicit that pinning, app-specific CA policies, VPN
  tunnels, ECH, and QUIC (when not falling back to TCP/TLS) remain inherent
  visibility limits.

Acceptance: explicitly authorized browser/device requests are observed
accurately; inspection starts off; pass-through works without proxy; proxy
crash/hang/OOM removes redirects and restores connectivity cleanly.

## 4. Full-visibility inspection, filtering and live monitoring

- **Unredacted capture** (implemented): dead query-parameter redaction helpers
  (`SENSITIVE_KEYS` / `redact_path`) have been removed from
  `portal/proxy_addon.py`; all logged traffic—including full URLs, query
  parameters, headers, cookies, tokens, and payloads—is captured and displayed
  in `/inspector` with nothing hidden or redacted from the operator.
- **Continuous live WebSocket frame tracking**: hook `websocket_start` and
  `websocket_message` in `portal/proxy_addon.py` (in addition to
  `websocket_end`) so long-lived open WebSocket connections (e.g. desktop app
  chat streams) appear immediately in `/inspector` and continuously stream/append
  incoming and outgoing frames and payloads in real time while the socket stays
  open, within bounded per-flow (`80`-flow / `6 MiB`) and buffer limits.
- Track pass-through, blocked, failed, and decrypted states distinctly.
- Formalize client/domain/status filter precedence and pre/post-decryption
  semantics.
- Add compact on-device display status (WAN, clients, inspection, errors,
  resource usage).

Acceptance: full unredacted traffic is visible to the authenticated operator;
load cannot grow queues/history indefinitely; unsupported TLS and trust failures
remain visible as failures; UI works cleanly when inspection is off.

## 5. Export and evidence handling

- Keep `JSONL`, `HAR`, and `CSV` exports **unredacted** so exported logs match
  the full traffic visible in `/inspector`.
- **Plain-text export warning and confirmation** (implemented in `/inspector`):
  downloading `JSONL`, `HAR`, `CSV`, raw payloads, or hex dumps presents a
  confirmation modal warning that plain-text exports can expose sensitive
  information (such as tokens, cookies, or credentials).
- Add export manifests with artifact hashes, UTC timestamps/timezone, applied
  filters, explicit quotas, retention limits, low-disk cutoff, and purge
  controls.
- Optional packet/PCAP exports come later (noting PCAP is link/packet data, not
  automatically decrypted HTTPS).
- Never export NetBridge's own CA private keys, Wi-Fi passphrase, administrator
  credentials, or unrelated host data.

Acceptance: size/time bounds and low-disk paths are tested; manifests describe
actual capture scope; exports require authentication, deliberate operator
confirmation of the plain-text sensitivity warning, and never leak device-local
secrets.

## 6. Resilience and release readiness

Sustained 1/3-client throughput and TLS load, peak RAM, thermal/power behavior,
CA expiry/rotation, SD write rate, disk-full, power interruption, proxy crashes,
portal recovery and rate-limit abuse. Verify documented mobile/browser layouts.
Record measured supported-client limits before claiming production readiness.

The original DOCX definition of done also requires full lifecycle validation,
live WebSocket tracking, export quotas/warnings, and failure recovery before
release readiness is claimed.
