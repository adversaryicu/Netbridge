#!/usr/bin/env python3
"""Bounded h11 HTTP/1.1 facade; the separate controller owns authorization."""
import asyncio
import base64
from collections import OrderedDict
import csv
from datetime import datetime, timezone
import gc
from http.cookies import SimpleCookie, CookieError
import io
import json
import logging
from pathlib import Path
import signal
import ssl
import time
from urllib.parse import parse_qs, urlsplit

import h11

ROOT = Path(__file__).resolve().parent
PUBLIC = Path('/var/lib/netbridge/portal-public')
TLS = Path('/etc/netbridge/portal-tls')
FLOWS_DIR = Path('/run/netbridge/flows')
SOCKET = '/run/netbridge/control.sock'
COOKIE = '__Host-netbridge'
MAX_BODY = 4096
MAX_HEADERS = 8192
MAX_PREVIEW_BYTES = 32768
SAFE_IMAGE_TYPES = frozenset({
    'image/png', 'image/jpeg', 'image/gif', 'image/webp',
    'image/x-icon', 'image/vnd.microsoft.icon', 'image/bmp',
})
EXT_MAP = {
    'application/json': '.json', 'text/html': '.html', 'application/javascript': '.js',
    'text/javascript': '.js', 'text/css': '.css', 'text/plain': '.txt', 'text/xml': '.xml',
    'application/xml': '.xml', 'image/png': '.png', 'image/jpeg': '.jpg', 'image/gif': '.gif',
    'image/webp': '.webp', 'image/svg+xml': '.svg', 'image/x-icon': '.ico',
    'application/pdf': '.pdf', 'application/zip': '.zip',
}
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


class StreamingResponse:
    def __init__(self, status=200, chunks=(), content_type='application/octet-stream', headers=None):
        self.status = status
        self.chunks = chunks
        self.headers = {**SECURITY_HEADERS, 'Content-Type': content_type, **(headers or {})}


def json_response(data, status=200):
    return Response(status, json.dumps(data), 'application/json; charset=utf-8')


def format_hex_dump(data, limit=None):
    view = data[:limit] if limit is not None else data
    lines = []
    for offset in range(0, len(view), 16):
        chunk = view[offset:offset + 16]
        left = ' '.join(f'{b:02x}' for b in chunk[:8])
        right = ' '.join(f'{b:02x}' for b in chunk[8:])
        hex_col = f'{left:<23}  {right:<23}'
        ascii_col = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f'{offset:08x}  {hex_col}  |{ascii_col}|')
    return '\n'.join(lines)


def is_text_payload(data, content_type=''):
    if not data:
        return True
    ctype = (content_type or '').lower()
    if ctype.startswith('text/') or any(tok in ctype for tok in ('json', 'javascript', 'xml', 'form-urlencoded', 'yaml', 'csv', 'svg')):
        return b'\x00' not in data[:4096]
    if b'\x00' in data[:4096]:
        return False
    sample = data[:8192]
    try:
        text = sample.decode('utf-8')
    except UnicodeDecodeError:
        return False
    printable = sum(1 for ch in text if ch in '\r\n\t' or ord(ch) >= 32)
    return (printable / max(1, len(text))) >= 0.90


def build_payload_view(raw, content_type='', truncated=False, total_bytes=None, size_meta=None):
    ctype = (content_type or '').lower()
    captured = len(raw)
    size = total_bytes if total_bytes is not None else captured
    is_text = is_text_payload(raw, ctype)
    view = {
        'size': size,
        'captured': captured,
        'truncated': bool(truncated),
        'content_type': ctype,
        'is_text': is_text,
        'is_image': ctype in SAFE_IMAGE_TYPES or ctype == 'image/svg+xml',
        'is_inline_image': ctype in SAFE_IMAGE_TYPES,
        'text': raw[:MAX_PREVIEW_BYTES].decode('utf-8', errors='replace') if (raw and is_text) else '',
        'text_truncated': len(raw) > MAX_PREVIEW_BYTES and is_text,
        'hex': format_hex_dump(raw, limit=MAX_PREVIEW_BYTES) if raw else '',
        'hex_truncated': len(raw) > MAX_PREVIEW_BYTES,
    }
    if size_meta:
        view.update(size_meta)
    return view


def _read_flow_record(flow_id, flows_dir=None):
    flows_dir = flows_dir or FLOWS_DIR
    meta_path = flows_dir / f'{flow_id}.json'
    if not meta_path.is_file():
        raise Reject(404, 'Flow details unavailable or evicted')
    meta = json.loads(meta_path.read_text())
    meta.setdefault('id', flow_id)
    if 'req_b64' in meta:
        req_raw = base64.b64decode(meta.pop('req_b64') or '')
    else:
        req_path = flows_dir / f'{flow_id}.req'
        req_raw = req_path.read_bytes() if req_path.is_file() else b''
    if 'resp_b64' in meta:
        resp_raw = base64.b64decode(meta.pop('resp_b64') or '')
    else:
        resp_path = flows_dir / f'{flow_id}.resp'
        resp_raw = resp_path.read_bytes() if resp_path.is_file() else b''
    return meta, req_raw, resp_raw


def _payload_size_meta(meta, prefix):
    keys = ('wire_bytes', 'compressed_bytes', 'retained_bytes', 'decoded_bytes',
            'decoded_bytes_min', 'decoded_size_known', 'content_encoding', 'decompression_status')
    out = {}
    for k in keys:
        full_key = f'{prefix}_{k}'
        if full_key in meta:
            out[k] = meta[full_key]
    return out


def build_flow_detail(flow_id, flows_dir=None):
    meta, req_raw, resp_raw = _read_flow_record(flow_id, flows_dir)
    return {
        'flow': meta,
        'request': build_payload_view(
            req_raw, meta.get('req_content_type', ''), meta.get('req_truncated', False),
            meta.get('req_bytes'), size_meta=_payload_size_meta(meta, 'req'),
        ),
        'response': build_payload_view(
            resp_raw, meta.get('content_type', ''), meta.get('resp_truncated', False),
            meta.get('bytes'), size_meta=_payload_size_meta(meta, 'resp'),
        ),
    }


def build_flows_since(after_id, ids, limit=10, max_bytes=1048576, flows_dir=None, device_id='', capture_session_id=''):
    flows_dir = flows_dir or FLOWS_DIR
    limit = max(1, min(20, int(limit)))
    sorted_ids = sorted(ids)
    min_available_id = sorted_ids[0] if sorted_ids else 0
    max_available_id = sorted_ids[-1] if sorted_ids else 0
    pending_ids = [fid for fid in sorted_ids if fid > after_id]
    items = []
    approx_bytes = 0
    last_id = after_id
    for fid in pending_ids:
        if len(items) >= limit:
            break
        try:
            detail = build_flow_detail(fid, flows_dir)
        except Reject:
            last_id = fid
            continue
        est = (
            len(detail['request'].get('text', ''))
            + len(detail['request'].get('hex', ''))
            + len(detail['response'].get('text', ''))
            + len(detail['response'].get('hex', ''))
            + 2048
        )
        if items and approx_bytes + est > max_bytes:
            break
        items.append(detail)
        approx_bytes += est
        last_id = fid
    has_more = any(fid > last_id for fid in pending_ids)
    return {
        'device_id': device_id,
        'capture_session_id': capture_session_id,
        'min_available_id': min_available_id,
        'max_available_id': max_available_id,
        'items': items,
        'next_after_id': last_id,
        'has_more': has_more,
    }


def sanitize_csv_cell(value):
    if not isinstance(value, str) or not value:
        return value
    if value[0] in ('=', '+', '-', '@', '\t', '\r') or value.lstrip(' \t\r\n').startswith(('=', '+', '-', '@')):
        return "'" + value
    return value


def _har_url(m):
    scheme = (m.get('scheme') or 'http').lower()
    host = m.get('host', '') or ''
    path = m.get('path', '/') or '/'
    if not host:
        return path
    port = m.get('server_port')
    default_port = 443 if scheme == 'https' else 80
    if port and port != default_port and ':' not in host.rsplit(']', 1)[-1]:
        return f'{scheme}://{host}:{port}{path}'
    return f'{scheme}://{host}{path}'


def _har_req_cookies(headers):
    cookies = []
    for k, v in headers or []:
        if str(k).lower() == 'cookie':
            for part in str(v).split(';'):
                if '=' in part:
                    ck, cv = part.strip().split('=', 1)
                    if ck:
                        cookies.append({'name': ck.strip(), 'value': cv.strip()})
    return cookies


def _har_resp_cookies(headers):
    cookies = []
    for k, v in headers or []:
        if str(k).lower() == 'set-cookie':
            first = str(v).split(';', 1)[0]
            if '=' in first:
                ck, cv = first.strip().split('=', 1)
                if ck:
                    cookies.append({'name': ck.strip(), 'value': cv.strip()})
    return cookies


def _har_redirect_url(m):
    status = int(m.get('status', 0) or 0)
    if not (300 <= status < 400):
        return ''
    for k, v in m.get('response_headers') or []:
        if str(k).lower() == 'location':
            return str(v)
    return ''


def _normalize_http_version(ver):
    s = str(ver or '').strip()
    if s.upper().startswith('HTTP/'):
        return s
    return 'HTTP/1.1'


def _export_meta_for_format(fmt, safe_csv=False):
    if fmt in ('csv', 'csv-safe'):
        return 'text/csv; charset=utf-8', 'csv'
    if fmt == 'jsonl':
        return 'application/x-ndjson; charset=utf-8', 'jsonl'
    if fmt == 'har':
        return 'application/json; charset=utf-8', 'har'
    raise Reject(400, 'Unsupported export format')


def iter_export(fmt, ids, flows_dir=None, safe_csv=False, capture_stats=None):
    flows_dir = flows_dir or FLOWS_DIR
    if fmt == 'csv-safe':
        fmt = 'csv'
        safe_csv = True
    _export_meta_for_format(fmt, safe_csv=safe_csv)
    if fmt == 'csv':
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(['id', 'time', 'client_ip', 'server_ip', 'server_port', 'method', 'scheme',
                         'host', 'path', 'status', 'content_type', 'req_bytes', 'resp_bytes',
                         'duration_ms', 'state', 'detail', 'payload_status'])
        yield buf.getvalue().encode('utf-8')
        for flow_id in ids:
            meta_path = flows_dir / f'{flow_id}.json'
            if not meta_path.is_file():
                continue
            m = json.loads(meta_path.read_text())
            row = [
                m.get('id', flow_id), m.get('time', ''), m.get('client_ip', ''), m.get('server_ip', ''),
                m.get('server_port', 0), m.get('method', ''), m.get('scheme', ''), m.get('host', ''),
                m.get('path', ''), m.get('status', 0), m.get('content_type', ''), m.get('req_bytes', 0),
                m.get('bytes', 0), m.get('duration_ms', 0), m.get('state', ''), m.get('detail', ''),
                m.get('payload_status', ''),
            ]
            if safe_csv:
                row = [sanitize_csv_cell(v) for v in row]
            rbuf = io.StringIO()
            csv.writer(rbuf).writerow(row)
            yield rbuf.getvalue().encode('utf-8')
        return
    if fmt == 'jsonl':
        if capture_stats is not None:
            meta_line = json.dumps({
                '_netbridge_meta': True,
                'exported_at': datetime.now(timezone.utc).isoformat(),
                'capture_stats': capture_stats,
            }) + '\n'
            yield meta_line.encode('utf-8')
        for flow_id in ids:
            try:
                m, req_raw, resp_raw = _read_flow_record(flow_id, flows_dir)
            except Reject:
                continue
            if req_raw:
                m['request_base64'] = base64.b64encode(req_raw).decode('ascii')
                if is_text_payload(req_raw, m.get('req_content_type', '')):
                    m['request_text'] = req_raw.decode('utf-8', errors='replace')
            if resp_raw:
                m['response_base64'] = base64.b64encode(resp_raw).decode('ascii')
                if is_text_payload(resp_raw, m.get('content_type', '')):
                    m['response_text'] = resp_raw.decode('utf-8', errors='replace')
            yield (json.dumps(m) + '\n').encode('utf-8')
        return
    if fmt == 'har':
        yield b'{\n  "log": {\n    "version": "1.2",\n    "creator": {"name": "NetBridge", "version": "1.0"},\n    "entries": [\n'
        included = 0
        skipped_non_http = 0
        for flow_id in ids:
            try:
                m, req_raw, resp_raw = _read_flow_record(flow_id, flows_dir)
            except Reject:
                continue
            scheme = (m.get('scheme') or 'http').lower()
            if m.get('state') not in ('decrypted', 'passthrough') or scheme not in ('http', 'https'):
                skipped_non_http += 1
                continue
            path = m.get('path', '/') or '/'
            url = _har_url(m)
            req_headers = [{'name': k, 'value': v} for k, v in m.get('request_headers', [])]
            resp_headers = [{'name': k, 'value': v} for k, v in m.get('response_headers', [])]
            query_str = urlsplit(path).query
            qparams = [{'name': k, 'value': v} for k, vals in parse_qs(query_str, keep_blank_values=True).items() for v in vals]
            req_obj = {
                'method': m.get('method', 'GET'),
                'url': url,
                'httpVersion': _normalize_http_version(m.get('http_version')),
                'headers': req_headers,
                'queryString': qparams,
                'cookies': _har_req_cookies(m.get('request_headers', [])),
                'headersSize': -1,
                'bodySize': m.get('req_bytes', len(req_raw)),
            }
            if req_raw:
                if is_text_payload(req_raw, m.get('req_content_type', '')):
                    req_obj['postData'] = {'mimeType': m.get('req_content_type', 'application/octet-stream'), 'text': req_raw.decode('utf-8', errors='replace')}
                else:
                    req_obj['postData'] = {'mimeType': m.get('req_content_type', 'application/octet-stream'), 'text': base64.b64encode(req_raw).decode('ascii'), 'encoding': 'base64'}
            resp_content = {'size': m.get('bytes', len(resp_raw)), 'mimeType': m.get('content_type', 'application/octet-stream')}
            if resp_raw:
                if is_text_payload(resp_raw, m.get('content_type', '')):
                    resp_content['text'] = resp_raw.decode('utf-8', errors='replace')
                else:
                    resp_content['text'] = base64.b64encode(resp_raw).decode('ascii')
                    resp_content['encoding'] = 'base64'
            entry = {
                'startedDateTime': m.get('time', ''),
                'time': m.get('duration_ms', 0),
                'request': req_obj,
                'response': {
                    'status': m.get('status', 0),
                    'statusText': m.get('reason', ''),
                    'httpVersion': _normalize_http_version(m.get('resp_http_version')),
                    'headers': resp_headers,
                    'cookies': _har_resp_cookies(m.get('response_headers', [])),
                    'content': resp_content,
                    'redirectURL': _har_redirect_url(m),
                    'headersSize': -1,
                    'bodySize': m.get('bytes', len(resp_raw)),
                },
                'cache': {},
                'timings': {
                    'blocked': -1, 'dns': -1, 'connect': -1, 'ssl': -1,
                    'send': -1, 'wait': m.get('duration_ms', 0), 'receive': -1,
                },
                'serverIPAddress': m.get('server_ip', ''),
                '_netbridge': {
                    'flow_id': m.get('id', flow_id),
                    'state': m.get('state', ''),
                    'payload_status': m.get('payload_status', ''),
                    'req_truncated': bool(m.get('req_truncated', False)),
                    'resp_truncated': bool(m.get('resp_truncated', False)),
                    'req_retained_bytes': m.get('req_retained_bytes', len(req_raw)),
                    'resp_retained_bytes': m.get('resp_retained_bytes', len(resp_raw)),
                    'resp_decoded_size_known': m.get('resp_decoded_size_known', True),
                    'resp_wire_bytes': m.get('resp_wire_bytes', m.get('bytes', len(resp_raw))),
                    'resp_content_encoding': m.get('resp_content_encoding', ''),
                },
            }
            prefix = '      ' if included == 0 else ',\n      '
            yield (prefix + json.dumps(entry)).encode('utf-8')
            included += 1
        nb_meta = {
            'exported_at': datetime.now(timezone.utc).isoformat(),
            'included_entries': included,
            'skipped_non_http': skipped_non_http,
            'capture_stats': capture_stats or {},
            'timing_note': 'Granular phase timings (send/receive/dns/connect/ssl) are unavailable from mitmdump; -1 indicates unknown.',
        }
        yield f'\n    ],\n    "_netbridge": {json.dumps(nb_meta)}\n  }}\n}}\n'.encode('utf-8')
        return


def build_export(fmt, ids, flows_dir=None, safe_csv=False, capture_stats=None):
    ctype, ext = _export_meta_for_format(fmt, safe_csv=safe_csv)
    payload = b''.join(iter_export(fmt, ids, flows_dir=flows_dir, safe_csv=safe_csv, capture_stats=capture_stats))
    return payload, ctype, ext


def search_flows(query, ids, flows_dir=None):
    q = (query or '').strip()
    if not (1 <= len(q) <= 128):
        raise Reject(400, 'Search query must be 1-128 characters')
    needle = q.lower()
    flows_dir = flows_dir or FLOWS_DIR
    matches = []
    for flow_id in reversed(list(ids)):
        try:
            m, req_raw, resp_raw = _read_flow_record(flow_id, flows_dir)
        except Reject:
            continue
        where = []
        url_blob = ' '.join(str(m.get(k, '') or '') for k in ('method', 'scheme', 'host', 'path', 'detail', 'server_ip')).lower()
        if needle in url_blob:
            where.append('url')
        if any(needle in str(k).lower() or needle in str(v).lower() for k, v in (m.get('request_headers') or [])):
            where.append('req_header')
        if any(needle in str(k).lower() or needle in str(v).lower() for k, v in (m.get('response_headers') or [])):
            where.append('resp_header')
        if req_raw and is_text_payload(req_raw, m.get('req_content_type', '')):
            if needle in req_raw.decode('utf-8', errors='replace').lower():
                where.append('req_body')
        if resp_raw and is_text_payload(resp_raw, m.get('content_type', '')):
            if needle in resp_raw.decode('utf-8', errors='replace').lower():
                where.append('resp_body')
        if where:
            matches.append({'id': flow_id, 'where': where})
    return {'query': q, 'matches': matches}


class Request:
    def __init__(self, event, body, remote, secure):
        self.method = event.method.decode('ascii')
        target = event.target.decode('ascii')
        self.path, _, self.query_string = target.partition('?')
        self.query = parse_qs(self.query_string, keep_blank_values=True)
        self.headers = {k.decode('ascii'):v.decode('latin1') for k,v in event.headers}
        self.body, self.remote, self.secure = body, remote, secure


class Reject(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message


async def rpc(payload):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_unix_connection(SOCKET, limit=131072), 3)
    except OSError as error:
        raise RuntimeError('Controller socket unavailable') from error
    try:
        writer.write(json.dumps(payload).encode() + b'\n')
        await writer.drain()
        return json.loads(await asyncio.wait_for(reader.readline(), 22))
    except OSError as error:
        raise RuntimeError('Controller IPC failed') from error
    finally:
        writer.close()
        await writer.wait_closed()


def _require_export_confirmation(request):
    confirmed = (
        request.query.get('confirm', [''])[0] == 'unredacted'
        or request.headers.get('x-netbridge-confirm-export', '').strip().lower() == 'unredacted'
    )
    if not confirmed:
        raise Reject(400, 'Plain-text export requires explicit confirmation (confirm=unredacted)')


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
                  '/trust': ('index.html', 'text/html'), '/inspector': ('index.html', 'text/html'),
                  '/app.js': ('app.js', 'application/javascript'), '/style.css': ('style.css', 'text/css')}
        if request.path in static and request.method in ('GET', 'HEAD'):
            if request.path in ('/admin', '/trust', '/inspector') and not request.secure:
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
        reads = {'public', 'status', 'trust-probe', 'flow', 'flow-raw', 'flows-export', 'flows-search', 'flows-since'}
        writes = {'pair', 'login', 'logout', 'trust-confirm', 'approve', 'revoke',
                  'admin-password', 'rotate-ca', 'ap-settings', 'inspection', 'flows-clear',
                  'capture-filters'}
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
        if action in ('flow', 'flow-raw', 'flows-export', 'flows-search', 'flows-since'):
            auth = await rpc({'action': 'flow-index', 'ip': request.remote, 'secure': request.secure,
                              'session': session, 'csrf': '', 'data': {}})
            if auth['status'] != 200:
                return json_response(auth['data'], auth['status'])
            valid_ids = set(auth['data'].get('ids', []))
            if action == 'flows-since':
                try:
                    after_id = max(0, int(request.query.get('after_id', ['0'])[0]))
                    limit = max(1, min(20, int(request.query.get('limit', ['10'])[0])))
                except ValueError:
                    raise Reject(400, 'Invalid cursor or limit')
                return json_response(build_flows_since(
                    after_id,
                    auth['data'].get('ids', []),
                    limit=limit,
                    device_id=auth['data'].get('device_id', ''),
                    capture_session_id=auth['data'].get('capture_session_id', ''),
                ))
            if action == 'flows-search':
                q = request.query.get('q', [''])[0]
                return json_response(search_flows(q, auth['data'].get('ids', [])))
            if action == 'flows-export':
                _require_export_confirmation(request)
                fmt = request.query.get('format', ['jsonl'])[0].lower()
                safe_csv = request.query.get('safe', ['0'])[0] == '1' or fmt == 'csv-safe'
                ctype, ext = _export_meta_for_format(fmt, safe_csv=safe_csv)
                fname = 'netbridge-capture-safe.csv' if (ext == 'csv' and safe_csv) else f'netbridge-capture.{ext}'
                headers = {'Content-Disposition': f'attachment; filename="{fname}"'}
                if ext == 'csv':
                    headers['X-NetBridge-CSV-Mode'] = 'safe' if safe_csv else 'raw'
                capture_stats = auth['data'].get('capture_stats')
                if isinstance(capture_stats, dict):
                    headers['X-NetBridge-Capture-Stats'] = json.dumps(capture_stats, separators=(',', ':'))
                return StreamingResponse(
                    chunks=iter_export(fmt, auth['data'].get('ids', []), safe_csv=safe_csv, capture_stats=capture_stats),
                    content_type=ctype,
                    headers=headers,
                )
            try:
                flow_id = int(request.query.get('id', [''])[0])
            except ValueError:
                raise Reject(400, 'Invalid flow ID')
            if flow_id < 1 or flow_id not in valid_ids:
                raise Reject(404, 'Flow not found')
            if action == 'flow':
                return json_response(build_flow_detail(flow_id))
            part = request.query.get('part', ['response'])[0]
            if part not in ('request', 'response'):
                raise Reject(400, 'Invalid payload part')
            fmt = request.query.get('format', ['raw'])[0]
            if fmt not in ('raw', 'hex'):
                raise Reject(400, 'Invalid format')
            download = request.query.get('download', ['0'])[0] == '1'
            meta, req_raw, resp_raw = _read_flow_record(flow_id)
            raw_bytes = req_raw if part == 'request' else resp_raw
            ctype = (meta.get('req_content_type', '') if part == 'request' else meta.get('content_type', '')).lower()
            is_inline_image_preview = (not download and fmt == 'raw' and ctype in SAFE_IMAGE_TYPES)
            if not is_inline_image_preview:
                _require_export_confirmation(request)
            if fmt == 'hex':
                return Response(body=format_hex_dump(raw_bytes).encode('utf-8'),
                                content_type='text/plain; charset=utf-8',
                                headers={'Content-Disposition': f'attachment; filename="flow-{flow_id}-{part}.hex"'})
            if is_inline_image_preview:
                return Response(body=raw_bytes, content_type=ctype)
            ext = EXT_MAP.get(ctype, '.bin')
            return Response(body=raw_bytes, content_type='application/octet-stream',
                            headers={'Content-Disposition': f'attachment; filename="flow-{flow_id}-{part}{ext}"'})
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
                response = await asyncio.wait_for(self.route(request), 25)
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
            if isinstance(response, StreamingResponse):
                headers = {**response.headers, 'Transfer-Encoding': 'chunked', 'Connection': 'close'}
                writer.write(connection.send(h11.Response(status_code=response.status,
                    headers=[(k.encode('ascii'), v.encode('latin1')) for k, v in headers.items()])))
                if event is None or event.method != b'HEAD':
                    for chunk in response.chunks:
                        if not chunk:
                            continue
                        if isinstance(chunk, str):
                            chunk = chunk.encode('utf-8')
                        writer.write(connection.send(h11.Data(data=chunk)))
                        await asyncio.wait_for(writer.drain(), 15)
                writer.write(connection.send(h11.EndOfMessage()))
                await asyncio.wait_for(writer.drain(), 15)
            else:
                # Close these short responses to bound idle TLS state. Browsers
                # reconnect normally; this portal has no streaming APIs.
                headers = {**response.headers, 'Content-Length':str(len(response.body)), 'Connection':'close'}
                writer.write(connection.send(h11.Response(status_code=response.status,
                    headers=[(k.encode('ascii'),v.encode('latin1')) for k,v in headers.items()])))
                if event is None or event.method != b'HEAD':
                    writer.write(connection.send(h11.Data(data=response.body)))
                writer.write(connection.send(h11.EndOfMessage()))
                await asyncio.wait_for(writer.drain(), 15)
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
