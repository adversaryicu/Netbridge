#!/usr/bin/env python3
"""Bounded h11 HTTP/1.1 facade; the separate controller owns authorization."""
import asyncio
import gc
from collections import OrderedDict
from http.cookies import SimpleCookie, CookieError
import json
import logging
from pathlib import Path
import signal
import ssl
import time

import h11

ROOT = Path(__file__).resolve().parent
PUBLIC = Path('/var/lib/netbridge/portal-public')
TLS = Path('/etc/netbridge/portal-tls')
SOCKET = '/run/netbridge/control.sock'
COOKIE = '__Host-netbridge'
MAX_BODY = 4096
MAX_HEADERS = 8192
SECURITY_HEADERS = {
    'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY',
    'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
}


class Response:
    def __init__(self, status=200, body=b'', content_type='application/json', headers=None):
        self.status = status
        self.body = body.encode() if isinstance(body, str) else body
        self.headers = {**SECURITY_HEADERS, 'Content-Type':content_type, **(headers or {})}


def json_response(data, status=200):
    return Response(status, json.dumps(data), 'application/json; charset=utf-8')


class Request:
    def __init__(self, event, body, remote, secure):
        self.method = event.method.decode('ascii')
        self.path = event.target.decode('ascii').split('?', 1)[0]
        self.headers = {k.decode('ascii'):v.decode('latin1') for k,v in event.headers}
        self.body, self.remote, self.secure = body, remote, secure


class Reject(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message


async def rpc(payload):
    reader, writer = await asyncio.wait_for(asyncio.open_unix_connection(SOCKET, limit=32768), 3)
    try:
        writer.write(json.dumps(payload).encode() + b'\n')
        await writer.drain()
        return json.loads(await asyncio.wait_for(reader.readline(), 15))
    finally:
        writer.close()
        await writer.wait_closed()


class Portal:
    def __init__(self, gateway):
        self.gateway, self.rates, self.active = gateway, OrderedDict(), 0
        self.cleanup_timer = None

    def collect_idle(self):
        self.cleanup_timer = None
        if self.active == 0:
            # Completed asyncio/TLS connections can form reference cycles. Do
            # not retain their native buffers until an unrelated GC threshold.
            gc.collect()

    async def route(self, request):
        host = request.headers.get('host')
        expected = self.gateway + (':443' if request.secure else ':80')
        if host not in (self.gateway, expected):
            raise Reject(421, 'Use the numeric gateway address')
        origin = f"{'https' if request.secure else 'http'}://{host}"
        if request.method not in ('GET', 'HEAD') and request.headers.get('origin') != origin:
            raise Reject(403, 'Cross-origin request rejected')
        now = time.monotonic()
        start, count = self.rates.get(request.remote, (now, 0))
        if now - start >= 60:
            start, count = now, 0
        self.rates[request.remote] = (start, count + 1)
        self.rates.move_to_end(request.remote)
        while len(self.rates) > 128:
            self.rates.popitem(last=False)
        if count >= 300:
            raise Reject(429, 'Too many requests; wait one minute')
        static = {'/': ('index.html', 'text/html'), '/admin': ('index.html', 'text/html'),
                  '/trust': ('index.html', 'text/html'), '/app.js': ('app.js', 'application/javascript'),
                  '/style.css': ('style.css', 'text/css')}
        if request.path in static and request.method in ('GET', 'HEAD'):
            if request.path in ('/admin', '/trust') and not request.secure:
                return Response(302, headers={'Location':f'https://{self.gateway}{request.path}'})
            name, kind = static[request.path]
            return Response(body=(ROOT / 'static' / name).read_bytes(), content_type=kind)
        if request.path == '/ca.crt' and request.method in ('GET', 'HEAD'):
            pem = (PUBLIC / 'netbridge-ca.crt').read_bytes()
            if b'PRIVATE KEY' in pem:
                raise RuntimeError('Refusing to serve private key material')
            if request.method == 'GET':
                try:
                    await rpc({'action':'downloaded', 'ip':request.remote})
                except Exception:
                    pass
            return Response(body=pem, content_type='application/x-x509-ca-cert',
                            headers={'Content-Disposition':'attachment; filename="NetBridge-CA.crt"'})
        reads = {'public', 'status', 'trust-probe'}
        writes = {'pair', 'login', 'logout', 'trust-confirm', 'approve', 'revoke',
                  'admin-password', 'rotate-ca', 'ap-settings'}
        action = request.path[5:] if request.path.startswith('/api/') else ''
        if not ((request.method == 'GET' and action in reads) or (request.method == 'POST' and action in writes)):
            raise Reject(404, 'Not found')
        if action != 'public' and not request.secure:
            raise Reject(403, 'Open administration over HTTPS')
        data = {}
        if request.method == 'POST':
            if request.headers.get('content-type', '').split(';')[0].strip().lower() != 'application/json':
                raise Reject(415, 'JSON is required')
            data = json.loads(request.body)
            if not isinstance(data, dict):
                raise Reject(400, 'Invalid request')
        cookies = SimpleCookie()
        try:
            cookies.load(request.headers.get('cookie', ''))
        except CookieError:
            raise Reject(400, 'Invalid cookie')
        session = cookies[COOKIE].value if COOKIE in cookies else ''
        result = await rpc({'action':action, 'ip':request.remote, 'secure':request.secure,
                            'session':session, 'csrf':request.headers.get('x-netbridge-csrf', ''), 'data':data})
        body = result['data']
        token = body.pop('session', None)
        response = json_response(body, result['status'])
        if token:
            response.headers['Set-Cookie'] = f'{COOKIE}={token}; Path=/; Secure; HttpOnly; SameSite=Strict'
        if action in ('logout', 'admin-password') and result['status'] == 200:
            response.headers['Set-Cookie'] = f'{COOKIE}=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict'
        return response

    async def receive(self, connection, reader):
        event, body = None, bytearray()
        while True:
            part = connection.next_event()
            if part is h11.NEED_DATA:
                connection.receive_data(await reader.read(2048))
            elif isinstance(part, h11.Request):
                event = part
                headers = dict(part.headers)
                size = len(part.target) + sum(len(k) + len(v) + 4 for k,v in part.headers)
                if len(part.headers) > 32 or size > MAX_HEADERS:
                    raise Reject(431, 'Request headers are too large')
                if b'content-length' in headers and b'transfer-encoding' in headers:
                    raise Reject(400, 'Ambiguous request framing')
                if int(headers.get(b'content-length', b'0')) > MAX_BODY:
                    raise Reject(413, 'Request body is too large')
                if b'expect' in headers:
                    raise Reject(417, 'Expect is not supported')
            elif isinstance(part, h11.Data):
                if len(body) + len(part.data) > MAX_BODY:
                    raise Reject(413, 'Request body is too large')
                body.extend(part.data)
            elif isinstance(part, h11.EndOfMessage):
                if part.headers:
                    raise Reject(400, 'Trailers are not supported')
                return event, bytes(body)
            elif isinstance(part, h11.ConnectionClosed):
                raise ConnectionError('Client disconnected')

    async def handle(self, reader, writer):
        if self.active >= 16:
            writer.close()
            await writer.wait_closed()
            return
        self.active += 1
        if self.cleanup_timer:
            self.cleanup_timer.cancel()
            self.cleanup_timer = None
        connection, event = h11.Connection(h11.SERVER, max_incomplete_event_size=MAX_HEADERS), None
        try:
            try:
                event, body = await asyncio.wait_for(self.receive(connection, reader), 5)
                remote = writer.get_extra_info('peername')[0]
                request = Request(event, body, remote, writer.get_extra_info('ssl_object') is not None)
                response = await asyncio.wait_for(self.route(request), 20)
            except Reject as error:
                response = json_response({'error':error.message}, error.status)
            except (h11.RemoteProtocolError, UnicodeError, ValueError):
                response = json_response({'error':'Invalid HTTP request'}, 400)
            except asyncio.TimeoutError:
                response = json_response({'error':'Request timed out'}, 408)
            except (ConnectionError, OSError):
                return
            except Exception:
                response = json_response({'error':'Device controller unavailable; routing is independent'}, 503)
            # Close these short responses to bound idle TLS state. Browsers
            # reconnect normally; this portal has no streaming APIs.
            headers = {**response.headers, 'Content-Length':str(len(response.body)), 'Connection':'close'}
            writer.write(connection.send(h11.Response(status_code=response.status,
                headers=[(k.encode('ascii'),v.encode('latin1')) for k,v in headers.items()])))
            if event is None or event.method != b'HEAD':
                writer.write(connection.send(h11.Data(data=response.body)))
            writer.write(connection.send(h11.EndOfMessage()))
            await asyncio.wait_for(writer.drain(), 5)
        except (h11.LocalProtocolError, ConnectionError, OSError, asyncio.TimeoutError):
            pass
        finally:
            self.active -= 1
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 2)
            except (OSError, asyncio.TimeoutError):
                pass
            if self.active == 0 and self.cleanup_timer is None:
                self.cleanup_timer = asyncio.get_running_loop().call_later(2, self.collect_idle)


async def main():
    config = json.loads(Path('/etc/netbridge/portal.json').read_text())
    portal = Portal(config['gateway'])
    servers = [await asyncio.start_server(portal.handle, config['gateway'], 80, limit=8192, backlog=16)]
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(TLS / 'portal-cert.pem', TLS / 'portal-key.pem')
        servers.append(await asyncio.start_server(portal.handle, config['gateway'], 443, ssl=context,
                       limit=8192, backlog=16, ssl_handshake_timeout=5, ssl_shutdown_timeout=2))
    except (OSError, ssl.SSLError):
        logging.error('HTTPS unavailable; HTTP onboarding remains available. Check CA diagnostics.')
    stopped = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        asyncio.get_running_loop().add_signal_handler(sig, stopped.set)
    await stopped.wait()
    for listener in servers:
        listener.close()
        await listener.wait_closed()


if __name__ == '__main__':
    asyncio.run(main())
