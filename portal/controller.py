#!/usr/bin/env python3
"""Privileged local controller. Only the dedicated portal UID can use its socket."""
import asyncio
from collections import OrderedDict
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


class Failure(Exception):
    def __init__(self, message, status=400):
        self.message, self.status = message, status


class Controller:
    def __init__(self):
        self.config = tomllib.loads(Path('/etc/netbridge/phase1.toml').read_text())
        self.network = json.loads((BASE / 'phase1.json').read_text())
        self.gateway = str(ipaddress.ip_interface(self.config['lan']['cidr']).ip)
        self.portal_uid = pwd.getpwnam('netbridge-portal').pw_uid
        self.portal_gid = pwd.getpwnam('netbridge-portal').pw_gid
        self.clients = {}
        self.sessions = OrderedDict()
        self.attempts = OrderedDict()
        self.operation = asyncio.Lock()
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
        process = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE,
                                                        stderr=asyncio.subprocess.PIPE)
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
                        self.clients.pop(match[1].lower(), None)
                    elif 'disconnected' in text.lower():
                        self.clients.clear()
            finally:
                if process.returncode is None:
                    process.terminate()
                await process.wait()
                self.clients.clear()
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
        ip = str(ipaddress.ip_address(request.get('ip', '0.0.0.0')))
        if action == 'public':
            return {'ca': json.loads((PUBLIC / 'ca.json').read_text()), 'paired': ADMIN.exists(),
                    'gateway': self.gateway, 'inspection': 'off'}
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
        record = self.authorize(request, mutate=action != 'status')
        if action == 'status':
            clients = [{k: v for k, v in c.items() if k in ('mac', 'ip', 'name', 'downloaded', 'trust_confirmed', 'approved')}
                       for c in self.clients.values()]
            wan = Path('/sys/class/net') / self.network['wan'] / 'carrier'
            return {'csrf': record['csrf'], 'clients': clients, 'monitor': self.health,
                    'wan_connected': wan.read_text().strip() == '1', 'inspection': 'off',
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
            self.audit_event('client_' + action)
            return {'ok': True, 'inspection': 'off'}
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
                    await self.command('/usr/bin/python3', str(Path(__file__).with_name('certificate_worker.py')), 'rotate')
                    self.clients.clear()
                    self.sessions.clear()
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
            if uid not in (0, self.portal_uid):
                raise Failure('Forbidden', 403)
            raw = await asyncio.wait_for(reader.readline(), timeout=5)
            request = json.loads(raw)
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
    await controller.command('/usr/bin/python3', str(Path(__file__).with_name('certificate_worker.py')), 'prepare')
    Path(SOCKET).unlink(missing_ok=True)
    server = await asyncio.start_unix_server(controller.handle, path=SOCKET, limit=8192)
    os.chown(SOCKET, 0, controller.portal_gid)
    os.chmod(SOCKET, 0o660)
    asyncio.create_task(controller.monitor())
    asyncio.create_task(controller.station_events())
    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    asyncio.run(main())
