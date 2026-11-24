#!/usr/bin/env python3
"""Full-message metadata and memory-bounded payload capture addon for mitmdump."""
import base64
from datetime import datetime, timezone
import gc
import json
from pathlib import Path
import queue
import socket
import threading
import time
from urllib.parse import parse_qsl, quote_plus, urlsplit
import uuid

SOCKET = '/run/netbridge/control.sock'
STAGE_DIR = Path('/run/netbridge/proxy-stage')
MAX_HTTP_BODY = 65536
MAX_TCP_BODY = 32768
MAX_DECOMPRESS_RAW = 262144
MAX_HEADERS = 96
MAX_HEADER_VAL = 2048
MAX_URL = 2048
MAX_QUEUE = 32
MAX_STAGE_FILES = 48

SENSITIVE_KEYS = frozenset({
    'password', 'passwd', 'pass', 'pwd', 'token', 'access_token',
    'refresh_token', 'id_token', 'auth', 'authorization', 'key',
    'api_key', 'apikey', 'secret', 'client_secret', 'session',
    'sessionid', 'sid', 'code', 'jwt', 'credential', 'credentials',
    'cookie', 'sig', 'signature', 'private_key', 'bearer',
})
SENSITIVE_SUBSTRINGS = ('token', 'secret', 'password', 'passwd', 'apikey', 'api_key', 'auth')


def is_sensitive_key(name):
    lower = (name or '').strip().lower()
    if lower in SENSITIVE_KEYS:
        return True
    return any(part in lower for part in SENSITIVE_SUBSTRINGS)


def redact_path(raw_path):
    if not raw_path:
        return '/'
    parts = urlsplit(str(raw_path))
    path = parts.path or '/'
    if parts.query:
        pairs = []
        for key, value in parse_qsl(parts.query, keep_blank_values=True):
            encoded_key = quote_plus(key)
            if is_sensitive_key(key):
                pairs.append(f'{encoded_key}=[REDACTED]')
            else:
                pairs.append(f'{encoded_key}={quote_plus(value)}')
        full = f"{path}?{'&'.join(pairs)}"
    else:
        full = path
    if len(full) > 160:
        return full[:157] + '...'
    return full


def utc_iso(ts=None):
    dt = datetime.fromtimestamp(ts, timezone.utc) if ts is not None else datetime.now(timezone.utc)
    return dt.strftime('%Y-%m-%dT%H:%M:%S.') + f'{dt.microsecond // 1000:03d}Z'


def _decode_str(value, limit=MAX_HEADER_VAL):
    if isinstance(value, bytes):
        text = value.decode('utf-8', errors='replace')
    else:
        text = str(value)
    return text[:limit]


def extract_headers(headers):
    if not headers:
        return []
    items = headers.items(multi=True) if hasattr(headers, 'items') and 'multi' in getattr(headers.items, '__code__', type('', (), {'co_varnames': ()})).co_varnames else (headers.items() if hasattr(headers, 'items') else headers)
    result = []
    for k, v in items:
        if len(result) >= MAX_HEADERS:
            break
        result.append([_decode_str(k, 256), _decode_str(v, MAX_HEADER_VAL)])
    return result


def _header_value(headers, target):
    if not headers:
        return ''
    if hasattr(headers, 'get'):
        return str(headers.get(target, '') or '')
    target_lower = target.lower()
    for k, v in extract_headers(headers):
        if k.lower() == target_lower:
            return v
    return ''


def extract_conn(conn):
    if not conn:
        return {}
    peer = getattr(conn, 'peername', None)
    addr = getattr(conn, 'address', None) or peer
    ip = str(addr[0]) if addr and len(addr) >= 1 else ''
    port = int(addr[1]) if addr and len(addr) >= 2 and addr[1] is not None else 0
    alpn = getattr(conn, 'alpn', None)
    if isinstance(alpn, bytes):
        alpn = alpn.decode('ascii', errors='replace')
    info = {
        'ip': ip[:45],
        'port': port,
        'sni': str(getattr(conn, 'sni', None) or '')[:128],
        'tls': bool(getattr(conn, 'tls', False)),
        'tls_version': str(getattr(conn, 'tls_version', None) or '')[:32],
        'cipher': str(getattr(conn, 'cipher', None) or '')[:96],
        'alpn': str(alpn or '')[:32],
        'error': str(getattr(conn, 'error', None) or '')[:160],
    }
    certs = getattr(conn, 'certificate_list', None) or ()
    if certs:
        cert = certs[0]
        try:
            subj = ', '.join(f'{k}={v}' for k, v in cert.subject)
            iss = ', '.join(f'{k}={v}' for k, v in cert.issuer)
            fp_raw = cert.fingerprint()
            fp = ':'.join(f'{b:02X}' for b in fp_raw) if isinstance(fp_raw, (bytes, bytearray)) else str(fp_raw)
            info['cert'] = {
                'subject': subj[:256],
                'issuer': iss[:256],
                'fingerprint': fp[:96],
                'not_before': cert.notbefore.isoformat() if getattr(cert, 'notbefore', None) else '',
                'not_after': cert.notafter.isoformat() if getattr(cert, 'notafter', None) else '',
            }
        except Exception:
            pass
    return info


def _read_message_bytes(message, limit=MAX_HTTP_BODY):
    if not message:
        return b'', 0, False
    raw_compressed = getattr(message, 'raw_content', None)
    if raw_compressed is None:
        # Large streamed response where mitmdump did not buffer the body in RAM.
        cl = _header_value(getattr(message, 'headers', None), 'content-length')
        try:
            total = max(0, int(cl)) if cl else 0
        except ValueError:
            total = 0
        return b'', total, total > 0
    raw_len = len(raw_compressed)
    if raw_len > MAX_DECOMPRESS_RAW:
        return bytes(raw_compressed[:limit]), raw_len, True
    raw = None
    try:
        raw = getattr(message, 'content', None)
    except Exception:
        raw = None
    if raw is None:
        raw = raw_compressed
    if isinstance(raw, str):
        raw = raw.encode('utf-8', errors='replace')
    total = len(raw)
    if total > limit:
        return bytes(raw[:limit]), total, True
    return bytes(raw), total, False


def send_event(payload, sock_path=SOCKET):
    line = json.dumps(payload).encode() + b'\n'
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(1.5)
        client.connect(sock_path)
        client.sendall(line)
        client.recv(1024)


class NetBridgeAddon:
    def __init__(self, sock_path=SOCKET, stage_dir=STAGE_DIR, background=True):
        self.sock_path = sock_path
        self.stage_dir = Path(stage_dir)
        self._queue = queue.Queue(maxsize=MAX_QUEUE)
        self._background = background
        self._count = 0
        if background:
            thread = threading.Thread(target=self._worker, name='nb-flow-ipc', daemon=True)
            thread.start()

    def _stage_and_send(self, record):
        meta, req_bytes, resp_bytes = record
        if req_bytes:
            meta['req_b64'] = base64.b64encode(req_bytes).decode('ascii')
        if resp_bytes:
            meta['resp_b64'] = base64.b64encode(resp_bytes).decode('ascii')
        token = uuid.uuid4().hex
        meta_path = self.stage_dir / f'stage-{token}.json'
        if self.stage_dir.exists() and sum(1 for _ in self.stage_dir.iterdir()) >= MAX_STAGE_FILES:
            return
        self.stage_dir.mkdir(parents=True, exist_ok=True)
        try:
            meta_path.write_text(json.dumps(meta))
            meta_path.chmod(0o640)
            send_event({'action': 'flow-event', 'stage': token}, self.sock_path)
        except OSError:
            meta_path.unlink(missing_ok=True)

    def _worker(self):
        processed = 0
        while True:
            item = self._queue.get()
            try:
                self._stage_and_send(item)
            except Exception:
                pass
            finally:
                self._queue.task_done()
            processed += 1
            if processed % 25 == 0:
                gc.collect()

    def emit_record(self, meta, req_bytes=b'', resp_bytes=b''):
        if not self._background:
            self.emit(meta)
            return
        while True:
            try:
                self._queue.put_nowait((meta, req_bytes, resp_bytes))
                return
            except queue.Full:
                try:
                    self._queue.get_nowait()
                    self._queue.task_done()
                except queue.Empty:
                    pass

    def emit(self, meta):
        try:
            send_event({'action': 'flow-event', 'event': meta}, self.sock_path)
        except OSError:
            pass

    @staticmethod
    def _client_ip(conn):
        if conn and getattr(conn, 'peername', None):
            return str(conn.peername[0])
        return ''

    def response(self, flow):
        req = getattr(flow, 'request', None)
        resp = getattr(flow, 'response', None)
        if not req or not resp:
            return
        client_conn = getattr(flow, 'client_conn', None)
        server_conn = getattr(flow, 'server_conn', None)
        scheme = (getattr(req, 'scheme', None) or 'http').lower()
        is_tls = bool(getattr(client_conn, 'tls', False)) or scheme == 'https'
        start = getattr(req, 'timestamp_start', None) or time.time()
        end = getattr(resp, 'timestamp_end', None) or time.time()
        req_bytes, req_total, req_trunc = _read_message_bytes(req, MAX_HTTP_BODY)
        resp_bytes, resp_total, resp_trunc = _read_message_bytes(resp, MAX_HTTP_BODY)
        ctype = _header_value(getattr(resp, 'headers', None), 'content-type').split(';')[0].strip()[:64]
        req_ctype = _header_value(getattr(req, 'headers', None), 'content-type').split(';')[0].strip()[:64]
        server_info = extract_conn(server_conn)
        client_info = extract_conn(client_conn)
        raw_path = str(getattr(req, 'path', '/') or '/')[:MAX_URL]
        meta = {
            'time': utc_iso(start),
            'client_ip': self._client_ip(client_conn)[:45],
            'server_ip': server_info.get('ip', ''),
            'server_port': server_info.get('port', 443 if is_tls else 80),
            'method': str(getattr(req, 'method', 'GET') or 'GET')[:16],
            'scheme': scheme[:16],
            'host': str(getattr(req, 'pretty_host', None) or getattr(req, 'host', '') or '')[:128],
            'path': raw_path,
            'http_version': str(getattr(req, 'http_version', 'HTTP/1.1') or 'HTTP/1.1')[:16],
            'resp_http_version': str(getattr(resp, 'http_version', 'HTTP/1.1') or 'HTTP/1.1')[:16],
            'status': int(getattr(resp, 'status_code', 0) or 0),
            'reason': str(getattr(resp, 'reason', '') or '')[:64],
            'content_type': ctype,
            'req_content_type': req_ctype,
            'req_bytes': req_total,
            'bytes': resp_total,
            'req_truncated': req_trunc,
            'resp_truncated': resp_trunc,
            'duration_ms': max(0, int((end - start) * 1000)),
            'state': 'decrypted' if is_tls else 'passthrough',
            'detail': '',
            'request_headers': extract_headers(getattr(req, 'headers', None)),
            'response_headers': extract_headers(getattr(resp, 'headers', None)),
            'client_conn': client_info,
            'server_conn': server_info,
            'timings': {
                'start': utc_iso(start),
                'tls_setup': utc_iso(getattr(client_conn, 'timestamp_tls_setup', None)) if getattr(client_conn, 'timestamp_tls_setup', None) else '',
                'end': utc_iso(end),
            },
        }
        self.emit_record(meta, req_bytes, resp_bytes)
        self._count += 1
        if self._count % 25 == 0:
            gc.collect()

    def websocket_end(self, flow):
        ws = getattr(flow, 'websocket', None)
        req = getattr(flow, 'request', None)
        if not ws or not req:
            return
        client_conn = getattr(flow, 'client_conn', None)
        server_conn = getattr(flow, 'server_conn', None)
        is_tls = bool(getattr(client_conn, 'tls', False)) or (getattr(req, 'scheme', '') == 'https')
        client_buf = bytearray()
        server_buf = bytearray()
        transcript = []
        req_total = 0
        resp_total = 0
        for msg in (getattr(ws, 'messages', None) or [])[:128]:
            content = getattr(msg, 'content', b'') or b''
            if isinstance(content, str):
                content = content.encode('utf-8', errors='replace')
            from_client = bool(getattr(msg, 'from_client', False))
            if from_client:
                req_total += len(content)
                if len(client_buf) < MAX_TCP_BODY:
                    client_buf.extend(content[:MAX_TCP_BODY - len(client_buf)])
            else:
                resp_total += len(content)
                if len(server_buf) < MAX_TCP_BODY:
                    server_buf.extend(content[:MAX_TCP_BODY - len(server_buf)])
            transcript.append({
                'dir': '->' if from_client else '<-',
                'type': 'text' if getattr(msg, 'is_text', False) else 'binary',
                'len': len(content),
                'time': utc_iso(getattr(msg, 'timestamp', None)),
            })
        start = getattr(req, 'timestamp_start', None) or time.time()
        end = getattr(ws, 'timestamp_end', None) or time.time()
        server_info = extract_conn(server_conn)
        meta = {
            'time': utc_iso(start),
            'client_ip': self._client_ip(client_conn)[:45],
            'server_ip': server_info.get('ip', ''),
            'server_port': server_info.get('port', 443 if is_tls else 80),
            'method': 'WS',
            'scheme': 'wss' if is_tls else 'ws',
            'host': str(getattr(req, 'pretty_host', None) or getattr(req, 'host', '') or '')[:128],
            'path': str(getattr(req, 'path', '/') or '/')[:MAX_URL],
            'http_version': 'WebSocket',
            'resp_http_version': 'WebSocket',
            'status': int(getattr(ws, 'close_code', None) or 101),
            'reason': str(getattr(ws, 'close_reason', '') or 'Closed')[:64],
            'content_type': 'application/websocket',
            'req_content_type': 'application/websocket',
            'req_bytes': req_total,
            'bytes': resp_total,
            'req_truncated': req_total > MAX_TCP_BODY,
            'resp_truncated': resp_total > MAX_TCP_BODY,
            'duration_ms': max(0, int((end - start) * 1000)),
            'state': 'websocket',
            'detail': f'{len(transcript)} frames',
            'request_headers': extract_headers(getattr(req, 'headers', None)),
            'response_headers': [],
            'client_conn': extract_conn(client_conn),
            'server_conn': server_info,
            'frames': transcript,
        }
        self.emit_record(meta, bytes(client_buf), bytes(server_buf))

    def _emit_tcp(self, flow, is_error=False):
        client_conn = getattr(flow, 'client_conn', None)
        server_conn = getattr(flow, 'server_conn', None)
        server_info = extract_conn(server_conn)
        client_info = extract_conn(client_conn)
        is_tls = bool(client_info.get('tls') or server_info.get('tls'))
        client_buf = bytearray()
        server_buf = bytearray()
        chunks = []
        req_total = 0
        resp_total = 0
        for msg in (getattr(flow, 'messages', None) or [])[:128]:
            content = getattr(msg, 'content', b'') or b''
            from_client = bool(getattr(msg, 'from_client', False))
            if from_client:
                req_total += len(content)
                if len(client_buf) < MAX_TCP_BODY:
                    client_buf.extend(content[:MAX_TCP_BODY - len(client_buf)])
            else:
                resp_total += len(content)
                if len(server_buf) < MAX_TCP_BODY:
                    server_buf.extend(content[:MAX_TCP_BODY - len(server_buf)])
            chunks.append({
                'dir': '->' if from_client else '<-',
                'len': len(content),
                'time': utc_iso(getattr(msg, 'timestamp', None)),
            })
        start = getattr(flow, 'timestamp_start', None) or getattr(client_conn, 'timestamp_start', None) or time.time()
        end = getattr(client_conn, 'timestamp_end', None) or time.time()
        err = getattr(flow, 'error', None)
        sni = client_info.get('sni') or server_info.get('sni')
        port = server_info.get('port', 0)
        host = sni or server_info.get('ip') or 'unknown'
        detail = str(getattr(err, 'msg', '') or '')[:120] if err else f'{len(chunks)} TCP chunks'
        meta = {
            'time': utc_iso(start),
            'client_ip': self._client_ip(client_conn)[:45],
            'server_ip': server_info.get('ip', ''),
            'server_port': port,
            'method': 'TLS-TCP' if is_tls else 'TCP',
            'scheme': 'tls-tcp' if is_tls else 'tcp',
            'host': host[:128],
            'path': f':{port}' if port else '/',
            'http_version': 'TCP',
            'resp_http_version': 'TCP',
            'status': 0,
            'reason': 'Error' if is_error else 'Stream',
            'content_type': 'application/octet-stream',
            'req_content_type': 'application/octet-stream',
            'req_bytes': req_total,
            'bytes': resp_total,
            'req_truncated': req_total > MAX_TCP_BODY,
            'resp_truncated': resp_total > MAX_TCP_BODY,
            'duration_ms': max(0, int((end - start) * 1000)),
            'state': 'error' if is_error else 'tcp',
            'detail': detail,
            'request_headers': [],
            'response_headers': [],
            'client_conn': client_info,
            'server_conn': server_info,
            'frames': chunks,
        }
        self.emit_record(meta, bytes(client_buf), bytes(server_buf))

    def tcp_end(self, flow):
        self._emit_tcp(flow, is_error=False)

    def tcp_error(self, flow):
        self._emit_tcp(flow, is_error=True)

    def error(self, flow):
        err = getattr(flow, 'error', None)
        req = getattr(flow, 'request', None)
        client_conn = getattr(flow, 'client_conn', None)
        server_conn = getattr(flow, 'server_conn', None)
        server_info = extract_conn(server_conn)
        client_info = extract_conn(client_conn)
        host = ''
        if req:
            host = getattr(req, 'pretty_host', None) or getattr(req, 'host', '') or ''
        if not host:
            host = client_info.get('sni') or server_info.get('ip') or 'unknown'
        req_bytes, req_total, req_trunc = _read_message_bytes(req, MAX_HTTP_BODY) if req else (b'', 0, False)
        meta = {
            'time': utc_iso(),
            'client_ip': self._client_ip(client_conn)[:45],
            'server_ip': server_info.get('ip', ''),
            'server_port': server_info.get('port', 0),
            'method': str(getattr(req, 'method', 'TCP') or 'TCP')[:16] if req else 'TCP',
            'scheme': str(getattr(req, 'scheme', 'https') or 'https')[:16] if req else 'tcp',
            'host': str(host)[:128],
            'path': str(getattr(req, 'path', '/') or '/')[:MAX_URL] if req else '/',
            'http_version': str(getattr(req, 'http_version', '') or '')[:16] if req else '',
            'resp_http_version': '',
            'status': 0,
            'reason': 'Error',
            'content_type': '',
            'req_content_type': '',
            'req_bytes': req_total,
            'bytes': 0,
            'req_truncated': req_trunc,
            'resp_truncated': False,
            'duration_ms': 0,
            'state': 'error',
            'detail': str(getattr(err, 'msg', None) or 'Connection error')[:120],
            'request_headers': extract_headers(getattr(req, 'headers', None)) if req else [],
            'response_headers': [],
            'client_conn': client_info,
            'server_conn': server_info,
        }
        self.emit_record(meta, req_bytes, b'')

    def _tls_failed(self, data, default_detail):
        context = getattr(data, 'context', None)
        conn = getattr(data, 'conn', None)
        client_conn = getattr(context, 'client', None) if context else None
        server_conn = getattr(context, 'server', None) if context else None
        server_info = extract_conn(server_conn)
        client_info = extract_conn(client_conn)
        host = (
            (getattr(conn, 'sni', None) if conn else None)
            or client_info.get('sni')
            or server_info.get('ip')
            or 'unknown'
        )
        detail = (getattr(conn, 'error', None) if conn else None) or default_detail
        meta = {
            'time': utc_iso(),
            'client_ip': self._client_ip(client_conn)[:45],
            'server_ip': server_info.get('ip', ''),
            'server_port': server_info.get('port', 443),
            'method': 'TLS',
            'scheme': 'https',
            'host': str(host)[:128],
            'path': '/',
            'http_version': 'TLS',
            'resp_http_version': '',
            'status': 0,
            'reason': 'TLS Failed',
            'content_type': '',
            'req_content_type': '',
            'req_bytes': 0,
            'bytes': 0,
            'req_truncated': False,
            'resp_truncated': False,
            'duration_ms': 0,
            'state': 'tls_failed',
            'detail': str(detail)[:120],
            'request_headers': [],
            'response_headers': [],
            'client_conn': client_info,
            'server_conn': server_info,
        }
        self.emit_record(meta, b'', b'')

    def tls_failed_client(self, data):
        self._tls_failed(data, 'Client rejected TLS certificate or aborted handshake')

    def tls_failed_server(self, data):
        self._tls_failed(data, 'Upstream TLS handshake failed')


addons = [NetBridgeAddon()]
