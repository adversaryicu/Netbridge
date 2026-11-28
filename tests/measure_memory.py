#!/usr/bin/env python3
"""Measure NetBridge service memory, CPU, restarts, and system RAM without discarding caches."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import ssl
import subprocess
import time
import urllib.error
import urllib.request

SERVICES = (
    'netbridge-controller',
    'netbridge-portal',
    'netbridge-proxy',
    'netbridge-ap',
    'netbridge-lease',
)


def _systemd_props(service):
    props = {
        'ActiveState': 'unknown',
        'MainPID': '0',
        'NRestarts': '0',
        'Result': 'unknown',
        'ControlGroup': '',
        'CPUUsageNSec': '',
    }
    try:
        out = subprocess.check_output(
            [
                'systemctl', 'show', service,
                '-p', 'ActiveState',
                '-p', 'MainPID',
                '-p', 'NRestarts',
                '-p', 'Result',
                '-p', 'ControlGroup',
                '-p', 'CPUUsageNSec',
            ],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        for line in out.splitlines():
            if '=' in line:
                k, v = line.split('=', 1)
                props[k.strip()] = v.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return props


def _cgroup_pids(control_group, main_pid):
    pids = set()
    if control_group:
        procs_file = Path('/sys/fs/cgroup') / control_group.lstrip('/') / 'cgroup.procs'
        if procs_file.is_file():
            try:
                for line in procs_file.read_text().splitlines():
                    line = line.strip()
                    if line.isdigit() and int(line) > 0:
                        pids.add(int(line))
            except OSError:
                pass
    if main_pid > 0:
        pids.add(main_pid)
    return sorted(pids)


def _read_proc_mem(pid):
    rss = pss = swap_pss = vm_hwm = 0
    smaps = Path(f'/proc/{pid}/smaps_rollup')
    if smaps.is_file():
        try:
            for line in smaps.read_text().splitlines():
                parts = line.split()
                if len(parts) < 2:
                    continue
                label = parts[0].rstrip(':')
                if label == 'Rss':
                    rss += int(parts[1])
                elif label == 'Pss':
                    pss += int(parts[1])
                elif label == 'SwapPss':
                    swap_pss += int(parts[1])
        except (OSError, ValueError):
            pass
    status = Path(f'/proc/{pid}/status')
    if status.is_file():
        try:
            for line in status.read_text().splitlines():
                if line.startswith('VmHWM:'):
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        vm_hwm += int(parts[1])
                    break
        except (OSError, ValueError):
            pass
    return rss, pss, swap_pss, vm_hwm


def _read_cgroup_memory(control_group):
    if not control_group:
        return None
    mem_cur = Path('/sys/fs/cgroup') / control_group.lstrip('/') / 'memory.current'
    if mem_cur.is_file():
        try:
            return int(mem_cur.read_text().strip())
        except (OSError, ValueError):
            return None
    return None


def read_system_meminfo():
    info = {}
    meminfo = Path('/proc/meminfo')
    if not meminfo.is_file():
        return info
    raw = {}
    for line in meminfo.read_text().splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            raw[parts[0].rstrip(':')] = int(parts[1])
    total = raw.get('MemTotal', 0)
    avail = raw.get('MemAvailable', 0)
    swap_total = raw.get('SwapTotal', 0)
    swap_free = raw.get('SwapFree', 0)
    info['MemTotal_MiB'] = round(total / 1024, 2)
    info['MemAvailable_MiB'] = round(avail / 1024, 2)
    info['SwapTotal_MiB'] = round(swap_total / 1024, 2)
    info['SwapFree_MiB'] = round(swap_free / 1024, 2)
    info['SwapUsed_MiB'] = round(max(0, swap_total - swap_free) / 1024, 2)
    return info


def snapshot(services=SERVICES):
    services_data = {}
    total_rss = total_pss = total_swap = total_hwm = 0
    for name in services:
        props = _systemd_props(name)
        main_pid = int(props['MainPID']) if props['MainPID'].isdigit() else 0
        pids = _cgroup_pids(props['ControlGroup'], main_pid)
        rss = pss = swap_pss = vm_hwm = 0
        for pid in pids:
            r, p, s, h = _read_proc_mem(pid)
            rss += r
            pss += p
            swap_pss += s
            vm_hwm += h
        total_rss += rss
        total_pss += pss
        total_swap += swap_pss
        total_hwm += vm_hwm
        cpu_ns = int(props['CPUUsageNSec']) if props['CPUUsageNSec'].isdigit() else None
        services_data[name] = {
            'active_state': props['ActiveState'],
            'main_pid': main_pid,
            'pids': pids,
            'n_restarts': int(props['NRestarts']) if props['NRestarts'].isdigit() else 0,
            'result': props['Result'],
            'Rss_KiB': rss,
            'Pss_KiB': pss,
            'SwapPss_KiB': swap_pss,
            'VmHWM_KiB': vm_hwm,
            'cgroup_memory_bytes': _read_cgroup_memory(props['ControlGroup']),
            'cpu_seconds': round(cpu_ns / 1e9, 3) if cpu_ns is not None else None,
        }
    return {
        'sampled_at_utc': datetime.now(timezone.utc).isoformat(),
        'services': services_data,
        'system': read_system_meminfo(),
        'combined_Rss_MiB': round(total_rss / 1024, 2),
        'combined_Pss_MiB': round(total_pss / 1024, 2),
        'combined_Pss_plus_SwapPss_MiB': round((total_pss + total_swap) / 1024, 2),
        'combined_VmHWM_MiB': round(total_hwm / 1024, 2),
    }


def _identity_digests():
    digests = {}
    ca_path = Path('/var/lib/netbridge/portal-public/ca.json')
    admin_path = Path('/var/lib/netbridge/admin.json')
    if ca_path.is_file():
        try:
            digests['ca'] = json.loads(ca_path.read_text()).get('fingerprint', '')
        except (OSError, ValueError):
            pass
    if admin_path.is_file():
        try:
            digests['admin_digest'] = hashlib.sha256(admin_path.read_bytes()).hexdigest()
        except OSError:
            pass
    return digests


def _run_https_probe():
    portal_cfg = Path('/etc/netbridge/portal.json')
    ca_crt = Path('/var/lib/netbridge/portal-public/netbridge-ca.crt')
    if not portal_cfg.is_file() or not ca_crt.is_file():
        return {'skipped': True, 'reason': 'portal config or CA cert not present'}
    gateway = json.loads(portal_cfg.read_text())['gateway']
    context = ssl.create_default_context(cafile=str(ca_crt))

    def visit(index):
        path = ('/', '/api/public', '/admin')[index % 3]
        with urllib.request.urlopen('https://' + gateway + path, context=context, timeout=10) as response:
            response.read()
            return response.status

    with ThreadPoolExecutor(max_workers=3) as executor:
        statuses = list(executor.map(visit, range(36)))

    request = urllib.request.Request(
        'https://' + gateway + '/api/login',
        data=json.dumps({'password': 'not-the-real-password-memory-probe'}).encode(),
        headers={'Content-Type': 'application/json', 'Origin': 'https://' + gateway},
        method='POST',
    )
    try:
        urllib.request.urlopen(request, context=context, timeout=15)
        login_status = 200
    except urllib.error.HTTPError as error:
        login_status = error.code
    return {
        'skipped': False,
        'successful_https_requests': statuses.count(200),
        'incorrect_password_status': login_status,
    }


def compare_with_baseline(current, baseline):
    comparison = {}
    base_services = baseline.get('services', {})
    cur_services = current.get('services', {})
    if base_services:
        svc_delta = {}
        for name, cur in cur_services.items():
            prev = base_services.get(name, {})
            if 'Pss_KiB' in prev:
                svc_delta[name] = {
                    'Pss_KiB_delta': cur.get('Pss_KiB', 0) - prev.get('Pss_KiB', 0),
                    'Rss_KiB_delta': cur.get('Rss_KiB', 0) - prev.get('Rss_KiB', 0),
                }
        comparison['services_delta'] = svc_delta
    if 'combined_Pss_MiB' in baseline:
        comparison['combined_Pss_MiB_delta'] = round(
            current['combined_Pss_MiB'] - baseline['combined_Pss_MiB'], 2
        )
    cur_id = _identity_digests()
    if baseline.get('ca') and 'ca' in cur_id:
        comparison['ca_unchanged'] = (baseline['ca'] == cur_id['ca'])
    if baseline.get('admin_digest') and 'admin_digest' in cur_id:
        comparison['admin_unchanged'] = (baseline['admin_digest'] == cur_id['admin_digest'])
    return comparison


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', help='Optional baseline JSON file to compare against')
    parser.add_argument('--save-baseline', help='Save current snapshot and identity digests as a baseline JSON file')
    parser.add_argument('--output', help='Write JSON report to this file path')
    parser.add_argument('--duration', type=float, default=0.0, help='Continuous sampling duration in seconds')
    parser.add_argument('--interval', type=float, default=1.0, help='Sampling interval in seconds when duration > 0')
    parser.add_argument('--skip-https-probe', action='store_true', help='Skip HTTPS/scrypt probe against local portal')
    args = parser.parse_args()

    before = snapshot()
    probe = {'skipped': True, 'reason': 'requested'} if args.skip_https_probe else _run_https_probe()
    samples = [before]
    if args.duration > 0:
        deadline = time.monotonic() + args.duration
        interval = max(0.2, args.interval)
        while time.monotonic() < deadline:
            time.sleep(min(interval, max(0.0, deadline - time.monotonic())))
            samples.append(snapshot())
    else:
        after = snapshot()
        samples.append(after)

    peak_pss_mib = max(s['combined_Pss_MiB'] for s in samples)
    peak_rss_mib = max(s['combined_Rss_MiB'] for s in samples)
    peak_total_mib = max(s['combined_Pss_plus_SwapPss_MiB'] for s in samples)
    latest = samples[-1]

    result = {
        'measured_at_utc': datetime.now(timezone.utc).isoformat(),
        'before': before,
        'latest': latest,
        'sample_count': len(samples),
        'peak': {
            'combined_Rss_MiB': peak_rss_mib,
            'combined_Pss_MiB': peak_pss_mib,
            'combined_Pss_plus_SwapPss_MiB': peak_total_mib,
        },
        'https_probe': probe,
    }
    if args.baseline:
        bpath = Path(args.baseline)
        if bpath.is_file():
            baseline = json.loads(bpath.read_text())
            result['baseline_comparison'] = compare_with_baseline(latest, baseline)
        else:
            result['baseline_comparison'] = {'error': f'Baseline file not found: {args.baseline}'}

    if args.save_baseline:
        bdata = dict(latest)
        bdata.update(_identity_digests())
        out_b = Path(args.save_baseline)
        out_b.parent.mkdir(parents=True, exist_ok=True)
        out_b.write_text(json.dumps(bdata, indent=2) + '\n')

    rendered = json.dumps(result, indent=2)
    if args.output:
        out_p = Path(args.output)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(rendered + '\n')
    print(rendered)


if __name__ == '__main__':
    main()
