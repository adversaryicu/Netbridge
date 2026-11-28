#!/usr/bin/env python3
"""Privileged local controller. Only the dedicated portal UID can use its socket."""
import asyncio
from collections import OrderedDict, deque
import hashlib
import hmac
import importlib.util
import ipaddress
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import socket
import struct
import time
import tomllib

from storage import write
from auth_worker import password_hash, password_matches

BASE = Path('/var/lib/netbridge')
ADMIN = BASE / 'admin.json'
PAIR = BASE / 'pairing.json'
PUBLIC = BASE / 'portal-public'
CA = BASE / 'ca'
TLS = Path('/etc/netbridge/portal-tls')
SOCKET = '/run/netbridge/control.sock'
FLOWS_DIR = Path('/run/netbridge/flows')
STAGE_DIR = Path('/run/netbridge/proxy-stage')
CAPTURE_FILTERS_FILE = Path('/run/netbridge/capture-filters.json')
CAPTURE_CATEGORIES = ('html', 'json', 'assets', 'images', 'binary', 'websocket', 'tcp', 'errors')
MAX_FLOWS = 100
MAX_FLOW_STORAGE_BYTES = 6 * 1024 * 1024
PROXY_FAIL_THRESHOLD = 3
SYS_NET = Path('/sys/class/net')


class Failure(Exception):
    def __init__(self, message, status=400):
        self.message, self.status = message, status


class Controller:
    proxy_uid = None
    inspection_enabled = False
    proxy_healthy = False
    proxy_process_healthy = False
    proxy_functional_healthy = False
    proxy_health_detail = 'off'
    _proxy_fail_streak = 0
    _last_flow_at = 0.0
    _synced_inspected = ()
    flow_seq = 0
    flow_bytes = 0
    retained_total = 0
    evicted_ring = 0
    evicted_quota = 0
    controller_errors = 0
    capture_filters = list(CAPTURE_CATEGORIES)
    capture_host_filter = ''
    capture_skip_noise = False

    def __init__(self):
        self.config = tomllib.loads(Path('/etc/netbridge/phase1.toml').read_text())
        self.network = json.loads((BASE / 'phase1.json').read_text())
        self.gateway = str(ipaddress.ip_interface(self.config['lan']['cidr']).ip)
        self.portal_uid = pwd.getpwnam('netbridge-portal').pw_uid
        self.portal_gid = pwd.getpwnam('netbridge-portal').pw_gid
        try:
            self.proxy_uid = pwd.getpwnam('netbridge-proxy').pw_uid
        except KeyError:
            self.proxy_uid = None
        self.clients = {}
        self.sessions = OrderedDict()
        self.attempts = OrderedDict()
        self.flows = deque()
        self.flow_seq = 0
        self.flow_bytes = 0
        self.retained_total = 0
        self.evicted_ring = 0
        self.evicted_quota = 0
        self.controller_errors = 0
        self._proxy_stats = {}
        self._stats_baseline = {}
        self.capture_filters = list(CAPTURE_CATEGORIES)
        self.capture_host_filter = ''
        self.capture_skip_noise = False
        self.flow_sizes = {}
        self.inspection_enabled = False
        self.proxy_healthy = False
        self.proxy_process_healthy = False
        self.proxy_functional_healthy = False
        self.proxy_health_detail = 'off'
        self._proxy_fail_streak = 0
        self._last_flow_at = 0.0
        self._synced_inspected = ()
        self.operation = asyncio.Lock()
        self.firewall_lock = asyncio.Lock()
        self.hash_gate = asyncio.Semaphore(1)
        self.pending = False
        self.health = 'starting'
        self.audit = logging.getLogger('netbridge.audit')
        self.audit.setLevel(logging.INFO)
        handler = RotatingFileHandler(BASE / 'audit.log', maxBytes=262144, backupCount=2)
        handler.setFormatter(logging.Formatter('%(asctime)sZ %(message)s'))
        handler.formatter.converter = time.gmtime
        self.audit.addHandler(handler)

    def audit_event(self, action):
        # Action names only. No passwords, cookies, tokens, request bodies or URLs.
        self.audit.info(action)

    async def password_work(self, action, password, record=None):
        if not isinstance(password,str) or len(password)>128:
            raise Failure('Invalid administrator password')
        if action=='hash' and len(password)<12:
            raise Failure('Administrator password must contain 12-128 characters')
        process=await asyncio.create_subprocess_exec('/usr/bin/python3',
            str(Path(__file__).with_name('auth_worker.py')), stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        payload=json.dumps({'action':action,'password':password,'record':record}).encode()
        try:
            output,_=await asyncio.wait_for(process.communicate(payload),15)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            raise Failure('Password verification timed out',503)
        if process.returncode:
            raise Failure('Password verification unavailable',503)
        result=json.loads(output)
        return result['record'] if action=='hash' else result['valid']

    async def command(self, *args):
        env = {**os.environ, 'LC_ALL': 'C'}
        process = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE,
                                                        stderr=asyncio.subprocess.PIPE, env=env)
        try:
            out, err = await asyncio.wait_for(process.communicate(), timeout=45)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            raise Failure('Device command timed out', 503)
        if process.returncode:
            raise Failure('Device operation failed; check diagnostics over Ethernet SSH', 503)
        return out.decode()

    def rate_limit(self, ip):
        now = time.monotonic()
        times = [t for t in self.attempts.get(ip, []) if now - t < 60]
        self.attempts[ip] = times
        self.attempts.move_to_end(ip)
        while len(self.attempts) > 64:
            self.attempts.popitem(last=False)
        if len(times) >= 5:
            raise Failure('Too many attempts. Wait one minute.', 429)
        times.append(now)

    def new_session(self):
        now = time.monotonic()
        token = secrets.token_urlsafe(32)
        record = {'csrf': secrets.token_urlsafe(24), 'expires': now + 1800, 'created': now}
        self.sessions[token] = record
        while len(self.sessions) > 16:
            self.sessions.popitem(last=False)
        return {'session': token, 'csrf': record['csrf']}

    def authorize(self, request, mutate=False):
        token = request.get('session', '')
        record = self.sessions.get(token)
        now = time.monotonic()
        if not record or record['expires'] < now or record['created'] + 28800 < now:
            self.sessions.pop(token, None)
            raise Failure('Sign in to administer NetBridge', 401)
        if mutate and not hmac.compare_digest(str(request.get('csrf', '')), record['csrf']):
            raise Failure('Invalid request token; refresh the page', 403)
        record['expires'] = now + 1800
        return record

    def current_client(self, ip):
        if self.health != 'ok':
            raise Failure('Client monitoring is unavailable; try again shortly', 503)
        for record in self.clients.values():
            if record.get('ip') == ip:
                return record
        raise Failure('Connect this browser to the NetBridge Wi-Fi network first', 403)

    def reconcile(self, stations, addresses):
        # A missing station or reset association age invalidates trust and approval.
        now = time.monotonic()
        active = {}
        for mac, age in stations.items():
            birth = now - age
            old = self.clients.get(mac)
            if not old or abs(old['association_start'] - birth) > 3:
                old = {'mac': mac, 'downloaded': False, 'trust_confirmed': False,
                       'approved': False, 'association_start': birth}
            old['ip'], old['name'] = addresses.get(mac, ('', 'Test device'))
            active[mac] = old
        self.clients = active

    def inspection_state(self):
        if not self.inspection_enabled:
            return 'off'
        return 'on' if self.proxy_healthy else 'degraded'

    def desired_inspected_ips(self):
        if not (self.inspection_enabled and self.proxy_healthy and self.health == 'ok'):
            return ()
        ips = []
        for client in self.clients.values():
            if client.get('approved') and client.get('trust_confirmed') and client.get('ip'):
                try:
                    ips.append(str(ipaddress.IPv4Address(client['ip'])))
                except ValueError:
                    pass
        return tuple(sorted(set(ips)))

    @staticmethod
    def is_proxy_port_listening(port=8080):
        suffix = f':{port:04X}'
        for table in ('/proc/net/tcp', '/proc/net/tcp6'):
            path = Path(table)
            if not path.exists():
                continue
            for line in path.read_text().splitlines()[1:]:
                cols = line.split()
                if len(cols) >= 4 and cols[1].endswith(suffix) and cols[3] == '0A':
                    return True
        return False

    async def check_proxy_process_health(self):
        if not self.is_proxy_port_listening(8080):
            return False
        process = await asyncio.create_subprocess_exec(
            'systemctl', 'is-active', 'netbridge-proxy.service',
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        try:
            out, _ = await asyncio.wait_for(process.communicate(), timeout=5)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            return False
        return process.returncode == 0 and out.decode().strip() == 'active'

    async def check_proxy_functional_health(self, host='127.0.0.1', port=8080, timeout=4.0):
        writer = None
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
            writer.write(
                f'GET /__netbridge_healthz HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n'.encode('ascii')
            )
            await asyncio.wait_for(writer.drain(), timeout=timeout)
            chunks = []
            total_len = 0
            while total_len < 4096:
                chunk = await asyncio.wait_for(reader.read(1024), timeout=timeout)
                if not chunk:
                    break
                chunks.append(chunk)
                total_len += len(chunk)
            resp = b''.join(chunks)
            head, _, body = resp.partition(b'\r\n\r\n')
            first_line = head.split(b'\r\n', 1)[0]
            return b' 200 ' in first_line and b'netbridge-proxy-ok' in body
        except (OSError, asyncio.TimeoutError):
            return False
        finally:
            if writer is not None:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=1)
                except (OSError, asyncio.TimeoutError):
                    pass

    async def check_proxy_health(self):
        proc_ok = await self.check_proxy_process_health()
        self.proxy_process_healthy = proc_ok
        if not proc_ok:
            self.proxy_functional_healthy = False
            self.proxy_health_detail = 'process_down'
            return False
        func_ok = await self.check_proxy_functional_health()
        self.proxy_functional_healthy = func_ok
        self.proxy_health_detail = 'ok' if func_ok else 'functional_probe_failed'
        return func_ok

    async def apply_inspected_ips(self, ips):
        script = 'flush set inet netbridge inspected_v4\n'
        if ips:
            elements = ', '.join(str(ipaddress.IPv4Address(ip)) for ip in ips)
            script += f'add element inet netbridge inspected_v4 {{ {elements} }}\n'
        process = await asyncio.create_subprocess_exec(
            'nft', '-f', '-', stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            _, err = await asyncio.wait_for(process.communicate(script.encode()), timeout=10)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            raise Failure('Firewall update timed out', 503)
        if process.returncode:
            raise Failure('Firewall update failed; check diagnostics over Ethernet SSH', 503)

    async def sync_inspection_firewall(self, force=False):
        lock = getattr(self, 'firewall_lock', None)
        if lock is None:
            lock = self.firewall_lock = asyncio.Lock()
        async with lock:
            ips = self.desired_inspected_ips()
            if not force and ips == self._synced_inspected:
                return
            await self.apply_inspected_ips(ips)
            self._synced_inspected = ips

    def setup_flow_dirs(self):
        for directory in (FLOWS_DIR, STAGE_DIR):
            directory.mkdir(parents=True, exist_ok=True)
            for item in directory.iterdir():
                if item.is_dir():
                    shutil.rmtree(item, ignore_errors=True)
                else:
                    item.unlink(missing_ok=True)
        os.chmod(FLOWS_DIR, 0o750)
        os.chown(FLOWS_DIR, 0, self.portal_gid)
        os.chmod(STAGE_DIR, 0o750)
        if self.proxy_uid is not None:
            os.chown(STAGE_DIR, self.proxy_uid, 0)
        self.write_capture_filters()

    def write_capture_filters(self):
        if not CAPTURE_FILTERS_FILE.parent.is_dir():
            return
        filters = list(getattr(self, 'capture_filters', CAPTURE_CATEGORIES))
        host_filter = str(getattr(self, 'capture_host_filter', '') or '')
        skip_noise = bool(getattr(self, 'capture_skip_noise', False))
        payload = {'categories': filters, 'host_filter': host_filter, 'skip_noise': skip_noise}
        write(CAPTURE_FILTERS_FILE, json.dumps(payload) + '\n', 0o644)

    def _delete_flow_files(self, flow_id):
        sizes = getattr(self, 'flow_sizes', None)
        if sizes is not None:
            self.flow_bytes = max(0, getattr(self, 'flow_bytes', 0) - sizes.pop(flow_id, 0))
        for suffix in ('.json', '.req', '.resp'):
            (FLOWS_DIR / f'{flow_id}{suffix}').unlink(missing_ok=True)

    def _read_proxy_stats(self):
        stats_file = STAGE_DIR / 'proxy-stats.json'
        if stats_file.is_file():
            try:
                data = json.loads(stats_file.read_text())
                if isinstance(data, dict):
                    self._proxy_stats = data
                    return data
            except (OSError, ValueError):
                pass
        return getattr(self, '_proxy_stats', {}) or {}

    def get_capture_stats(self):
        proxy = self._read_proxy_stats()
        base = getattr(self, '_stats_baseline', {}) or {}
        def diff(src, key, bkey=None):
            val = int(src.get(key, 0) or 0)
            b = int(base.get(bkey or key, 0) or 0)
            return max(0, val - b) if val >= b else max(0, val)

        observed = diff(proxy, 'observed')
        filtered = diff(proxy, 'filtered')
        dropped_queue = diff(proxy, 'queue_drops')
        dropped_stage = diff(proxy, 'stage_drops')
        ipc_failures = diff(proxy, 'ipc_failures')
        worker_errors = diff(proxy, 'worker_errors')
        retained = max(0, getattr(self, 'retained_total', 0) - int(base.get('retained_total', 0) or 0))
        evicted_ring = max(0, getattr(self, 'evicted_ring', 0) - int(base.get('evicted_ring', 0) or 0))
        evicted_quota = max(0, getattr(self, 'evicted_quota', 0) - int(base.get('evicted_quota', 0) or 0))
        controller_errors = max(0, getattr(self, 'controller_errors', 0) - int(base.get('controller_errors', 0) or 0))
        total_loss = dropped_queue + dropped_stage + ipc_failures + worker_errors + controller_errors
        return {
            'observed': observed,
            'retained': retained,
            'active_ring': len(self.flows) if hasattr(self, 'flows') else 0,
            'filtered': filtered,
            'evicted': evicted_ring + evicted_quota,
            'evicted_ring': evicted_ring,
            'evicted_quota': evicted_quota,
            'dropped_queue': dropped_queue,
            'dropped_stage': dropped_stage,
            'worker_errors': worker_errors,
            'ipc_failures': ipc_failures,
            'controller_errors': controller_errors,
            'total_loss': total_loss,
            'last_error': str(proxy.get('last_error', '') or '')[:80],
        }

    def clear_flow_files(self):
        proxy = self._read_proxy_stats()
        self._stats_baseline = {
            'observed': int(proxy.get('observed', 0) or 0),
            'filtered': int(proxy.get('filtered', 0) or 0),
            'queue_drops': int(proxy.get('queue_drops', 0) or 0),
            'stage_drops': int(proxy.get('stage_drops', 0) or 0),
            'ipc_failures': int(proxy.get('ipc_failures', 0) or 0),
            'worker_errors': int(proxy.get('worker_errors', 0) or 0),
            'retained_total': getattr(self, 'retained_total', 0),
            'evicted_ring': getattr(self, 'evicted_ring', 0),
            'evicted_quota': getattr(self, 'evicted_quota', 0),
            'controller_errors': getattr(self, 'controller_errors', 0),
        }
        if hasattr(self, 'flows'):
            self.flows.clear()
        if hasattr(self, 'flow_sizes'):
            self.flow_sizes.clear()
        self.flow_bytes = 0
        for directory in (FLOWS_DIR, STAGE_DIR):
            if directory.exists():
                for item in directory.iterdir():
                    if item.is_file() and item.name != 'proxy-stats.json':
                        item.unlink(missing_ok=True)

    def _enforce_flow_quota(self):
        while getattr(self, 'flow_bytes', 0) > MAX_FLOW_STORAGE_BYTES and len(self.flows) > 1:
            oldest = self.flows.popleft()
            self._delete_flow_files(oldest['id'])
            self.evicted_quota = getattr(self, 'evicted_quota', 0) + 1

    def record_flow(self, raw, stage=None):
        staged_meta = None
        if stage is not None:
            if not isinstance(stage, str) or not re.fullmatch(r'[0-9a-f]{32}', stage):
                raise Failure('Invalid flow stage token')
            staged_meta = STAGE_DIR / f'stage-{stage}.json'
            if not staged_meta.is_file():
                raise Failure('Missing staged flow payload', 404)
            raw = json.loads(staged_meta.read_text())
        if not isinstance(raw, dict):
            raise Failure('Invalid flow payload')
        if not hasattr(self, 'flows'):
            self.flows = deque()
        if not hasattr(self, 'flow_sizes'):
            self.flow_sizes = {}
        try:
            self.flow_seq += 1
            flow_id = self.flow_seq
            state = str(raw.get('state', 'error'))
            if state not in ('decrypted', 'passthrough', 'websocket', 'tcp', 'tls_failed', 'error'):
                state = 'error'
            try:
                status = max(0, min(4999, int(raw.get('status', 0))))
            except (TypeError, ValueError):
                status = 0
            try:
                byte_count = max(0, int(raw.get('bytes', 0)))
            except (TypeError, ValueError):
                byte_count = 0
            try:
                req_bytes = max(0, int(raw.get('req_bytes', 0)))
            except (TypeError, ValueError):
                req_bytes = 0
            try:
                duration_ms = max(0, int(raw.get('duration_ms', 0)))
            except (TypeError, ValueError):
                duration_ms = 0
            try:
                server_port = max(0, min(65535, int(raw.get('server_port', 0))))
            except (TypeError, ValueError):
                server_port = 0
            payload_status = str(raw.get('payload_status', ''))
            if payload_status not in ('complete', 'partial', 'streamed', 'empty'):
                if raw.get('req_truncated') or raw.get('resp_truncated') or raw.get('messages_truncated'):
                    payload_status = 'partial'
                elif req_bytes == 0 and byte_count == 0:
                    payload_status = 'empty'
                else:
                    payload_status = 'complete'
            try:
                omitted_messages = max(0, int(raw.get('omitted_messages', 0) or 0))
            except (TypeError, ValueError):
                omitted_messages = 0
            summary = {
                'id': flow_id,
                'time': str(raw.get('time', ''))[:32],
                'client_ip': str(raw.get('client_ip', ''))[:45],
                'server_ip': str(raw.get('server_ip', ''))[:45],
                'server_port': server_port,
                'method': str(raw.get('method', 'GET'))[:16],
                'scheme': str(raw.get('scheme', 'http'))[:16],
                'host': str(raw.get('host', ''))[:128],
                'path': str(raw.get('path', '/'))[:120],
                'status': status,
                'reason': str(raw.get('reason', ''))[:64],
                'content_type': str(raw.get('content_type', ''))[:48],
                'req_bytes': req_bytes,
                'bytes': byte_count,
                'payload_status': payload_status,
                'duration_ms': duration_ms,
                'state': state,
                'detail': str(raw.get('detail', ''))[:120],
            }
            if omitted_messages:
                summary['omitted_messages'] = omitted_messages
            if FLOWS_DIR.is_dir():
                portal_gid = getattr(self, 'portal_gid', None)
                meta_dest = FLOWS_DIR / f'{flow_id}.json'
                if staged_meta is not None and staged_meta.is_file():
                    os.replace(staged_meta, meta_dest)
                else:
                    meta = dict(raw)
                    meta['id'] = flow_id
                    meta_dest.write_text(json.dumps(meta))
                os.chmod(meta_dest, 0o640)
                if portal_gid is not None:
                    os.chown(meta_dest, 0, portal_gid)
                disk_bytes = meta_dest.stat().st_size
                self.flow_sizes[flow_id] = disk_bytes
                self.flow_bytes = getattr(self, 'flow_bytes', 0) + disk_bytes
            while len(self.flows) >= MAX_FLOWS:
                oldest = self.flows.popleft()
                self._delete_flow_files(oldest['id'])
                self.evicted_ring = getattr(self, 'evicted_ring', 0) + 1
            self.flows.append(summary)
            self.retained_total = getattr(self, 'retained_total', 0) + 1
            self._last_flow_at = time.monotonic()
            self._enforce_flow_quota()
        except Failure:
            self.controller_errors = getattr(self, 'controller_errors', 0) + 1
            raise
        except Exception:
            self.controller_errors = getattr(self, 'controller_errors', 0) + 1
            raise
        finally:
            if staged_meta is not None:
                staged_meta.unlink(missing_ok=True)

    async def monitor(self):
        while True:
            try:
                output = await self.command('iw', 'dev', self.network['lan'], 'station', 'dump')
                stations = {}
                for block in output.split('Station ')[1:]:
                    mac = block.split()[0].lower()
                    match = re.search(r'connected time:\s*(\d+)', block)
                    if match:
                        stations[mac] = int(match[1])
                addresses = {}
                lease_file = Path('/var/lib/NetworkManager') / f"dnsmasq-{self.network['lan']}.leases"
                if lease_file.exists():
                    for line in lease_file.read_text().splitlines()[:256]:
                        fields = line.split()
                        if len(fields) >= 4 and (int(fields[0]) == 0 or int(fields[0]) > time.time()):
                            addresses[fields[1].lower()] = (fields[2], fields[3][:64] if fields[3] != '*' else 'Test device')
                neighbors = json.loads(await self.command('ip', '-j', 'neigh', 'show', 'dev', self.network['lan']))
                for neighbor in neighbors[:256]:
                    if neighbor.get('lladdr') in stations and '.' in neighbor.get('dst', ''):
                        mac = neighbor['lladdr']
                        addresses[mac] = (neighbor['dst'], addresses.get(mac, ('', 'Test device'))[1])
                self.reconcile(stations, addresses)
                self.health = 'ok'
            except Exception:
                self.clients.clear()
                self.health = 'unavailable'
            try:
                await self.sync_inspection_firewall()
            except Exception:
                self.audit_event('firewall_sync_failed')
            await asyncio.sleep(2)

    async def proxy_monitor(self):
        while True:
            try:
                if self.inspection_enabled:
                    proc_ok = await self.check_proxy_process_health()
                    self.proxy_process_healthy = proc_ok
                    if not proc_ok:
                        self.proxy_functional_healthy = False
                        self.proxy_health_detail = 'process_down'
                        self._proxy_fail_streak = PROXY_FAIL_THRESHOLD
                        healthy = False
                    else:
                        if time.monotonic() - getattr(self, '_last_flow_at', 0.0) < 5.0:
                            func_ok = True
                        else:
                            func_ok = await self.check_proxy_functional_health()
                        self.proxy_functional_healthy = func_ok
                        if func_ok:
                            self._proxy_fail_streak = 0
                            self.proxy_health_detail = 'ok'
                            healthy = True
                        else:
                            self._proxy_fail_streak = getattr(self, '_proxy_fail_streak', 0) + 1
                            self.proxy_health_detail = 'functional_probe_failed'
                            healthy = self.proxy_healthy if self._proxy_fail_streak < PROXY_FAIL_THRESHOLD else False
                    if healthy != self.proxy_healthy:
                        self.proxy_healthy = healthy
                        if healthy:
                            self.audit_event('proxy_healthy')
                        elif proc_ok:
                            self.audit_event('proxy_functional_unhealthy_fail_open')
                        else:
                            self.audit_event('proxy_unhealthy_fail_open')
                        await self.sync_inspection_firewall(force=True)
                else:
                    self.proxy_process_healthy = False
                    self.proxy_functional_healthy = False
                    self.proxy_health_detail = 'off'
                    self._proxy_fail_streak = 0
                    if self.proxy_healthy or self._synced_inspected:
                        self.proxy_healthy = False
                        await self.sync_inspection_firewall(force=True)
            except Exception:
                self.proxy_healthy = False
                self.proxy_functional_healthy = False
                self.proxy_health_detail = 'monitor_error'
                self.audit_event('proxy_monitor_failed')
            await asyncio.sleep(2)

    async def station_events(self):
        # Polling supplies identity/address data; station deletion events revoke
        # approval even when a quick disconnect/reconnect falls between polls.
        while True:
            process = await asyncio.create_subprocess_exec('iw', 'event', '-t',
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
            try:
                while line := await process.stdout.readline():
                    text = line.decode(errors='replace')
                    if self.network['lan'] not in text:
                        continue
                    match = re.search(r'del station\s+([0-9a-f:]{17})', text, re.I)
                    if match:
                        if self.clients.pop(match[1].lower(), None) is not None:
                            try:
                                await self.sync_inspection_firewall()
                            except Exception:
                                pass
                    elif 'disconnected' in text.lower():
                        self.clients.clear()
                        try:
                            await self.sync_inspection_firewall()
                        except Exception:
                            pass
            finally:
                if process.returncode is None:
                    process.terminate()
                await process.wait()
                self.clients.clear()
                try:
                    await self.sync_inspection_firewall()
                except Exception:
                    pass
            await asyncio.sleep(5)

    async def delayed(self, task):
        self.pending = True
        await asyncio.sleep(2)
        try:
            await task()
        except Exception:
            self.audit_event('operation_failed')
        finally:
            self.pending = False

    async def dispatch(self, request):
        action = request.get('action')
        data = request.get('data') or {}
        if not isinstance(data, dict):
            raise Failure('Invalid request')
        if action in ('flow-event', 'capture-stats'):
            peer_uid = request.get('_peer_uid')
            if peer_uid is None or (peer_uid != 0 and peer_uid != self.proxy_uid):
                raise Failure('Forbidden', 403)
            if action == 'capture-stats':
                stats = request.get('stats') if isinstance(request.get('stats'), dict) else data
                self._proxy_stats = dict(stats)
                return {'ok': True}
            self.record_flow(request.get('event') if 'event' in request else data, stage=request.get('stage'))
            return {'ok': True}
        ip = str(ipaddress.ip_address(request.get('ip', '0.0.0.0')))
        if action == 'public':
            return {'ca': json.loads((PUBLIC / 'ca.json').read_text()), 'paired': ADMIN.exists(),
                    'gateway': self.gateway, 'inspection': self.inspection_state()}
        if action == 'downloaded':
            try:
                self.current_client(ip)['downloaded'] = True
            except Failure:
                pass
            return {'ok': True}
        if not request.get('secure'):
            raise Failure('HTTPS is required for this operation', 403)
        if action == 'trust-probe':
            client = self.current_client(ip)
            client['challenge'] = secrets.token_urlsafe(24)
            client['challenge_expires'] = time.monotonic() + 300
            return {'challenge': client['challenge'], 'confirmed': client['trust_confirmed']}
        if action == 'trust-confirm':
            client = self.current_client(ip)
            if (data.get('no_warning') is not True or client.get('challenge_expires', 0) < time.monotonic()
                    or not client.get('challenge') or not hmac.compare_digest(str(data.get('challenge', '')), client['challenge'])):
                raise Failure('Run the HTTPS test again and confirm no certificate warning was bypassed')
            client['trust_confirmed'] = True
            client.pop('challenge', None)
            self.audit_event('browser_trust_confirmed')
            return {'ok': True}
        if action in ('login', 'pair'):
            self.rate_limit(ip)
            async with self.hash_gate:
                if action == 'pair':
                    if ADMIN.exists():
                        raise Failure('An administrator is already configured', 409)
                    if not PAIR.exists():
                        raise Failure('Generate a pairing code on the device first', 403)
                    pair = json.loads(PAIR.read_text())
                    candidate = hashlib.sha256(str(data.get('code', '')).encode()).hexdigest()
                    if pair['expires'] < time.time() or not hmac.compare_digest(candidate, pair['hash']):
                        raise Failure('Pairing code is invalid or expired', 403)
                    record = await self.password_work('hash', data.get('password'))
                    write(ADMIN, json.dumps(record))
                    PAIR.unlink()
                    self.audit_event('administrator_paired')
                else:
                    if not ADMIN.exists():
                        raise Failure('Pair an administrator first', 401)
                    valid = await self.password_work('verify', data.get('password'), json.loads(ADMIN.read_text()))
                    if not valid:
                        self.audit_event('login_failed')
                        raise Failure('Incorrect administrator password', 401)
                    self.audit_event('login_success')
            return self.new_session()
        record = self.authorize(request, mutate=action not in ('status', 'flow-index'))
        if action == 'flow-index':
            return {
                'ok': True,
                'ids': [f['id'] for f in self.flows] if hasattr(self, 'flows') else [],
                'capture_stats': self.get_capture_stats(),
            }
        if action == 'status':
            clients = [{k: v for k, v in c.items() if k in ('mac', 'ip', 'name', 'downloaded', 'trust_confirmed', 'approved')}
                       for c in self.clients.values()]
            wan = SYS_NET / self.network['wan'] / 'carrier'
            flows = list(reversed(self.flows)) if hasattr(self, 'flows') else []
            return {'csrf': record['csrf'], 'clients': clients, 'monitor': self.health,
                    'wan_connected': wan.read_text().strip() == '1', 'inspection': self.inspection_state(),
                    'proxy_health': {
                        'process': getattr(self, 'proxy_process_healthy', False),
                        'functional': getattr(self, 'proxy_functional_healthy', False),
                        'detail': getattr(self, 'proxy_health_detail', 'off'),
                        'fail_streak': getattr(self, '_proxy_fail_streak', 0),
                    },
                    'inspected_clients': len(self.desired_inspected_ips()), 'flows': flows,
                    'capture_stats': self.get_capture_stats(),
                    'capture_filters': list(getattr(self, 'capture_filters', CAPTURE_CATEGORIES)),
                    'capture_host_filter': str(getattr(self, 'capture_host_filter', '') or ''),
                    'capture_skip_noise': bool(getattr(self, 'capture_skip_noise', False)),
                    'ssid': self.config['ap']['ssid'], 'ca': json.loads((PUBLIC / 'ca.json').read_text()),
                    'pending': self.pending}
        if action == 'logout':
            self.sessions.pop(request['session'], None)
            return {'ok': True}
        if action in ('approve', 'revoke'):
            client = self.clients.get(str(data.get('mac', '')).lower())
            if self.health != 'ok' or not client:
                raise Failure('Client disconnected; refresh the client list', 409)
            if action == 'approve' and not client['trust_confirmed']:
                raise Failure('This client must complete and confirm the HTTPS trust test first', 409)
            client['approved'] = action == 'approve'
            await self.sync_inspection_firewall()
            self.audit_event('client_' + action)
            return {'ok': True, 'inspection': self.inspection_state()}
        if action == 'flows-clear':
            self.clear_flow_files()
            self.audit_event('flows_cleared')
            return {'ok': True}
        if action == 'capture-filters':
            raw_cats = data.get('categories')
            if not isinstance(raw_cats, list) or not all(isinstance(c, str) for c in raw_cats):
                raise Failure('Invalid capture filter list')
            unknown = [c for c in raw_cats if c not in CAPTURE_CATEGORIES]
            if unknown:
                raise Failure('Invalid capture filter category')
            host_filter = data.get('host_filter', getattr(self, 'capture_host_filter', ''))
            if not isinstance(host_filter, str):
                raise Failure('Invalid host filter')
            skip_noise = data.get('skip_noise', getattr(self, 'capture_skip_noise', False))
            if type(skip_noise) is not bool:
                raise Failure('Invalid noise filter flag')
            selected = set(raw_cats)
            self.capture_filters = [c for c in CAPTURE_CATEGORIES if c in selected]
            self.capture_host_filter = host_filter.strip()[:128]
            self.capture_skip_noise = skip_noise
            self.write_capture_filters()
            self.audit_event('capture_filters_updated')
            return {'ok': True, 'capture_filters': list(self.capture_filters),
                    'capture_host_filter': self.capture_host_filter,
                    'capture_skip_noise': self.capture_skip_noise}
        if action == 'inspection':
            enabled = data.get('enabled')
            if type(enabled) is not bool:
                raise Failure('Invalid inspection request')
            lock = getattr(self, 'operation', None)
            if lock is None:
                lock = self.operation = asyncio.Lock()
            async with lock:
                if enabled:
                    await self.command('systemctl', 'start', 'netbridge-proxy.service')
                    deadline = time.monotonic() + 15
                    healthy = False
                    while time.monotonic() < deadline:
                        if await self.check_proxy_health():
                            healthy = True
                            break
                        await asyncio.sleep(0.25)
                    if not healthy:
                        await asyncio.create_subprocess_exec('systemctl', 'stop', 'netbridge-proxy.service')
                        self.inspection_enabled = False
                        self.proxy_healthy = False
                        await self.sync_inspection_firewall(force=True)
                        self.audit_event('inspection_start_failed')
                        raise Failure('Inspection proxy failed to become ready; direct routing remains active', 503)
                    self.inspection_enabled = True
                    self.proxy_healthy = True
                    await self.sync_inspection_firewall(force=True)
                    self.audit_event('inspection_enabled')
                else:
                    self.inspection_enabled = False
                    self.proxy_healthy = False
                    await self.sync_inspection_firewall(force=True)
                    await self.command('systemctl', 'stop', 'netbridge-proxy.service')
                    self.audit_event('inspection_disabled')
            return {'ok': True, 'inspection': self.inspection_state()}
        if action == 'admin-password':
            async with self.hash_gate:
                new = await self.password_work('hash', data.get('password'))
                write(ADMIN, json.dumps(new))
            self.sessions.clear()
            self.audit_event('administrator_password_changed')
            return {'ok': True, 'sign_out': True}
        if self.pending:
            raise Failure('Another device operation is still running', 409)
        if action == 'rotate-ca':
            if data.get('confirmation') != 'ROTATE':
                raise Failure('Type ROTATE to confirm CA replacement')
            async def rotate():
                async with self.operation:
                    self.inspection_enabled = False
                    self.proxy_healthy = False
                    await self.sync_inspection_firewall(force=True)
                    proc = await asyncio.create_subprocess_exec('systemctl', 'stop', 'netbridge-proxy.service')
                    await proc.wait()
                    await self.command('/usr/bin/python3', str(Path(__file__).with_name('certificate_worker.py')), 'rotate')
                    self.clients.clear()
                    self.sessions.clear()
                    self.clear_flow_files()
                    self.audit_event('ca_rotated')
                    await self.command('systemctl', 'restart', 'netbridge-portal')
            self.pending = True
            asyncio.create_task(self.delayed(rotate))
            return {'ok': True, 'message': 'CA rotation scheduled. Return to HTTP onboarding and install the new CA.'}
        if action == 'ap-settings':
            ssid, password = data.get('ssid', ''), data.get('password', '')
            if not re.fullmatch(r'[A-Za-z0-9 _.-]{1,32}', ssid):
                raise Failure('SSID must be 1-32 simple ASCII characters')
            if not re.fullmatch(r'[A-Za-z0-9!@#$%&*+.,_=-]{8,63}', password):
                raise Failure('Wi-Fi password must be 8-63 letters, numbers or common punctuation, without spaces')
            async def change_ap():
                async with self.operation:
                    spec = importlib.util.spec_from_file_location('nbnetwork', '/usr/local/lib/netbridge/netbridge-network.py')
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    config = module.load_config()
                    old_config, old_secret, old_profile = module.CONFIG.read_text(), module.SECRET.read_text(), module.PROFILE.read_text()
                    config['ap']['ssid'] = ssid
                    try:
                        updated = re.sub(r'^ssid = .*$', 'ssid = ' + json.dumps(ssid), old_config, flags=re.M)
                        module.atomic_write(module.CONFIG, updated)
                        module.atomic_write(module.SECRET, password + '\n')
                        module.atomic_write(module.PROFILE, module.profile(config, module.load_state(), password))
                        await self.command('nmcli', 'connection', 'load', str(module.PROFILE))
                        await self.command('systemctl', 'restart', 'netbridge-ap')
                        self.config = config
                        self.clients.clear()
                        await self.sync_inspection_firewall(force=True)
                        self.audit_event('ap_settings_changed')
                    except Exception:
                        module.atomic_write(module.CONFIG, old_config)
                        module.atomic_write(module.SECRET, old_secret)
                        module.atomic_write(module.PROFILE, old_profile)
                        await self.command('nmcli', 'connection', 'load', str(module.PROFILE))
                        await self.command('systemctl', 'restart', 'netbridge-ap')
                        raise
            self.pending = True
            asyncio.create_task(self.delayed(change_ap))
            return {'ok': True, 'message': 'Wi-Fi settings saved for application. Reconnect using the new name and password.'}
        raise Failure('Unknown action', 404)

    async def handle(self, reader, writer):
        try:
            credentials = writer.get_extra_info('socket').getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            _, uid, _ = struct.unpack('3i', credentials)
            allowed = {0, self.portal_uid}
            if self.proxy_uid is not None:
                allowed.add(self.proxy_uid)
            if uid not in allowed:
                raise Failure('Forbidden', 403)
            raw = await asyncio.wait_for(reader.readline(), timeout=5)
            request = json.loads(raw)
            if not isinstance(request, dict):
                raise Failure('Invalid request')
            if uid == self.proxy_uid and request.get('action') not in ('flow-event', 'capture-stats'):
                raise Failure('Forbidden', 403)
            request['_peer_uid'] = uid
            result = await self.dispatch(request)
            response = {'status': 200, 'data': result}
        except Failure as error:
            response = {'status': error.status, 'data': {'error': error.message}}
        except (ValueError, TypeError, KeyError):
            response = {'status': 400, 'data': {'error': 'Invalid request'}}
        except Exception:
            self.audit_event('controller_request_failed')
            response = {'status': 503, 'data': {'error': 'Device operation unavailable; check Ethernet SSH diagnostics'}}
        try:
            writer.write(json.dumps(response).encode() + b'\n')
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()


async def main():
    controller = Controller()
    controller.setup_flow_dirs()
    await controller.command('/usr/bin/python3', str(Path(__file__).with_name('certificate_worker.py')), 'prepare')
    Path(SOCKET).unlink(missing_ok=True)
    server = await asyncio.start_unix_server(controller.handle, path=SOCKET, limit=8192)
    os.chown(SOCKET, 0, controller.portal_gid)
    os.chmod(SOCKET, 0o666 if controller.proxy_uid is not None else 0o660)
    asyncio.create_task(controller.monitor())
    asyncio.create_task(controller.proxy_monitor())
    asyncio.create_task(controller.station_events())
    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    asyncio.run(main())
