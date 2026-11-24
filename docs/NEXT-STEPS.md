# Next session plan

Baseline: 2026-11-21. Stop after documentation/icon work for today. These are
future tasks, not claims of completed functionality or authorization to deploy
unreviewed interception.

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

## 3. Determine mitmdump feasibility, then integrate conservatively

Recheck current ARM64 package/version availability and supported transparent
options on the actual device. Initial APT lists had no candidate and mitmdump
was absent. Do not assume a package source, pin guessed versions, or invent flags.
Profile a minimal instance before choosing limits; this kernel lacks memory
cgroup enforcement, so the spec's provisional MemoryMax values are not protection.

Implement isolated process lifecycle and health detection first. Only then add
atomic, selected-client IPv4 TCP/80 and TCP/443 redirection with original
destination preservation, explicit opt-in and trusted/approved test clients.
Exclude the local portal, DNS, upstream management and proxy-originated traffic.
Remove redirects immediately on proxy failure; leaving a restart policy alone
is insufficient. Native app lease supervision does not already provide this.

Acceptance: an explicitly authorized browser request is observed accurately;
inspection starts off; passthrough works without proxy; proxy crash/hang/OOM
removes redirects and restores connectivity without requiring client settings.
Do not claim QUIC, pinned apps, VPN tunnels or all mobile app HTTPS is decrypted.

## 4. Metadata, filtering and compact monitoring

Add a bounded 100-event metadata ring and bounded transport from the mitmdump
addon. Redact sensitive headers/query fields by default; no bodies by default.
Track pass-through, blocked, failed and decrypted states distinctly. Implement
client/domain/status filters with documented precedence and pre/post-decryption
semantics. Add compact display status (WAN, clients, inspection, errors, resource
usage) and browser live flows. Avoid unbounded per-flow objects or duplicate bodies.

Acceptance: load cannot grow queues/history indefinitely; unsupported TLS and
trust failures remain visible as failures; UI works when inspection is off.

## 5. Export and evidence handling

Implement authenticated, disabled-by-default redacted JSONL/CSV exports, manifest
and artifact hashes, UTC timestamps/timezone, applied filters, explicit quotas,
retention and low-disk cutoff. Optional flow/packet exports come later. PCAP is
packet data, not automatically decrypted HTTPS. Never export CA keys, Wi-Fi or
administrator credentials, or unrelated host data. Add purge controls.

Acceptance: size/time bounds and low-disk paths are tested; manifests describe
actual capture scope; exports require authentication and deliberate operator action.

## 6. Resilience and release readiness

Sustained 1/3-client throughput and TLS load, peak RAM, thermal/power behavior,
CA expiry/rotation, SD write rate, disk-full, power interruption, proxy crashes,
portal recovery and rate-limit abuse. Verify documented mobile/browser layouts.
Record measured supported-client limits before claiming production readiness.

The original DOCX definition of done also requires working inspection, filters,
exports and failure recovery; the current gateway/onboarding milestone alone
does not satisfy it.
