#!/usr/bin/env python3
"""Full-message metadata and memory-bounded payload capture addon for mitmdump."""
import base64
from datetime import datetime, timezone
import gc
import io
import json
from pathlib import Path
import queue
import socket
import threading
import time
import uuid
import zlib

try:
    import zstandard
except ImportError:
    zstandard = None

SOCKET = '/run/netbridge/control.sock'
STAGE_DIR = Path('/run/netbridge/proxy-stage')
CAPTURE_FILTERS_FILE = Path('/run/netbridge/capture-filters.json')
ALL_CAPTURE_CATEGORIES = frozenset({'html', 'json', 'assets', 'images', 'binary', 'websocket', 'tcp', 'errors'})
NOISE_HOST_SUFFIXES = (
    # Windows & Office 365 background telemetry / connectivity / CRL
    'telemetry.microsoft.com',
    'vortex.data.microsoft.com',
    'events.data.microsoft.com',
    'browser.events.data.microsoft.com',
    'aria.microsoft.com',
    'msftconnecttest.com',
    'msftncsi.com',
    'windowsupdate.com',
    'update.microsoft.com',
    'settings-win.data.microsoft.com',
    'watson.telemetry.microsoft.com',
    'ocsp.digicert.com',
    'crl.microsoft.com',
    # Chrome / Edge background sync, safebrowsing & updates
    'clients2.google.com',
    'clients4.google.com',
    'update.googleapis.com',
    'safebrowsing.googleapis.com',
    'optimizationguide-pa.googleapis.com',
    'edge.microsoft.com',
    'nav-edge.smartscreen.microsoft.com',
    # Firefox background telemetry, captive portal & remote settings
    'detectportal.firefox.com',
    'incoming.telemetry.mozilla.org',
    'firefox.settings.services.mozilla.com',
    'push.services.mozilla.com',
    'shavar.services.mozilla.com',
    'contile.services.mozilla.com',
    # Apple captive portal & metrics
    'captive.apple.com',
    'metrics.icloud.com',
    'xp.apple.com',
)
MAX_HTTP_BODY = 65536
MAX_TCP_BODY = 32768
MAX_STREAM_MESSAGES = 128
MAX_DECOMPRESS_RAW = 262144
MAX_ZSTD_WINDOW_SIZE = 2 * 1024 * 1024
MAX_HEADERS = 96
MAX_HEADER_VAL = 2048
MAX_URL = 2048
MAX_QUEUE = 32
MAX_STAGE_FILES = 48


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


def _bounded_decompress_gzip(raw_compressed, limit):
    decomp = zlib.decompressobj(16 + zlib.MAX_WBITS)
    out = decomp.decompress(raw_compressed, limit + 1)
    if len(out) <= limit and not decomp.unconsumed_tail:
        tail = decomp.flush(limit + 1 - len(out))
        out += tail
    if len(out) > limit or decomp.unconsumed_tail:
        return out[:limit], None, len(out), True
    return out, len(out), None, False


def _bounded_decompress_deflate(raw_compressed, limit):
    for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
        try:
            decomp = zlib.decompressobj(wbits)
            out = decomp.decompress(raw_compressed, limit + 1)
            if len(out) <= limit and not decomp.unconsumed_tail:
                tail = decomp.flush(limit + 1 - len(out))
                out += tail
            if len(out) > limit or decomp.unconsumed_tail:
                return out[:limit], None, len(out), True
            return out, len(out), None, False
        except zlib.error:
            continue
    raise zlib.error('Invalid deflate stream')


def _bounded_decompress_zstd(raw_compressed, limit):
    if zstandard is None:
        return None
    try:
        dctx = zstandard.ZstdDecompressor(max_window_size=MAX_ZSTD_WINDOW_SIZE)
    except TypeError:
        dctx = zstandard.ZstdDecompressor()
    with dctx.stream_reader(io.BytesIO(raw_compressed)) as reader:
        out = reader.read(limit + 1)
    if len(out) > limit:
        return out[:limit], None, len(out), True
    return out, len(out), None, False


def _read_message_payload(message, limit=MAX_HTTP_BODY):
    if not message:
        return {
            'data': b'',
            'retained_bytes': 0,
            'wire_bytes': 0,
            'compressed_bytes': 0,
            'content_encoding': '',
            'decoded_bytes': 0,
            'decoded_bytes_min': None,
            'decoded_size_known': True,
            'truncated': False,
            'streamed': False,
            'decompression_status': 'none',
        }
    encoding = _header_value(getattr(message, 'headers', None), 'content-encoding').lower().strip()[:32]
    is_compressed = bool(encoding and encoding != 'identity')
    raw_compressed = getattr(message, 'raw_content', None)
    if raw_compressed is None:
        # Large streamed response where mitmdump did not buffer the body in RAM.
        cl = _header_value(getattr(message, 'headers', None), 'content-length')
        try:
            total = max(0, int(cl)) if cl else 0
        except ValueError:
            total = 0
        return {
            'data': b'',
            'retained_bytes': 0,
            'wire_bytes': total,
            'compressed_bytes': total if is_compressed else 0,
            'content_encoding': encoding,
            'decoded_bytes': None if is_compressed else total,
            'decoded_bytes_min': None,
            'decoded_size_known': not is_compressed,
            'truncated': total > 0,
            'streamed': total > 0,
            'decompression_status': 'streamed',
        }
    if isinstance(raw_compressed, str):
        raw_compressed = raw_compressed.encode('utf-8', errors='replace')
    raw_len = len(raw_compressed)
    if not is_compressed:
        data = bytes(raw_compressed[:limit])
        return {
            'data': data,
            'retained_bytes': len(data),
            'wire_bytes': raw_len,
            'compressed_bytes': 0,
            'content_encoding': encoding,
            'decoded_bytes': raw_len,
            'decoded_bytes_min': None,
            'decoded_size_known': True,
            'truncated': raw_len > limit,
            'streamed': False,
            'decompression_status': 'none',
        }
    if raw_len > MAX_DECOMPRESS_RAW:
        data = bytes(raw_compressed[:limit])
        return {
            'data': data,
            'retained_bytes': len(data),
            'wire_bytes': raw_len,
            'compressed_bytes': raw_len,
            'content_encoding': encoding,
            'decoded_bytes': None,
            'decoded_bytes_min': None,
            'decoded_size_known': False,
            'truncated': True,
            'streamed': False,
            'decompression_status': 'skipped_oversized',
        }
    try:
        result = None
        if encoding in ('gzip', 'x-gzip'):
            result = _bounded_decompress_gzip(raw_compressed, limit)
        elif encoding == 'deflate':
            result = _bounded_decompress_deflate(raw_compressed, limit)
        elif encoding == 'zstd' and zstandard is not None:
            result = _bounded_decompress_zstd(raw_compressed, limit)
        if result is not None:
            data, exact_decoded, min_decoded, trunc = result
            return {
                'data': data,
                'retained_bytes': len(data),
                'wire_bytes': raw_len,
                'compressed_bytes': raw_len,
                'content_encoding': encoding,
                'decoded_bytes': exact_decoded,
                'decoded_bytes_min': min_decoded,
                'decoded_size_known': exact_decoded is not None,
                'truncated': trunc,
                'streamed': False,
                'decompression_status': 'complete' if exact_decoded is not None else 'partial',
            }
    except Exception:
        data = bytes(raw_compressed[:limit])
        return {
            'data': data,
            'retained_bytes': len(data),
            'wire_bytes': raw_len,
            'compressed_bytes': raw_len,
            'content_encoding': encoding,
            'decoded_bytes': None,
            'decoded_bytes_min': None,
            'decoded_size_known': False,
            'truncated': True,
            'streamed': False,
            'decompression_status': 'failed',
        }
    # Unknown or stacked encoding (e.g. br): keep bounded raw bytes without full expansion.
    data = bytes(raw_compressed[:limit])
    return {
        'data': data,
        'retained_bytes': len(data),
        'wire_bytes': raw_len,
        'compressed_bytes': raw_len,
        'content_encoding': encoding,
        'decoded_bytes': None,
        'decoded_bytes_min': None,
        'decoded_size_known': False,
        'truncated': True,
        'streamed': False,
        'decompression_status': 'unsupported',
    }


def _read_message_bytes(message, limit=MAX_HTTP_BODY):
    info = _read_message_payload(message, limit)
    if info['decoded_size_known'] and info['decoded_bytes'] is not None:
        total = info['decoded_bytes']
    elif info['decoded_bytes_min'] is not None:
        total = info['decoded_bytes_min']
    else:
        total = info['wire_bytes'] or info['retained_bytes']
    return info['data'], total, info['truncated']


def _http_payload_status(req, req_total, req_trunc, resp, resp_total, resp_trunc):
    req_streamed = req is not None and getattr(req, 'raw_content', None) is None and req_total > 0
    resp_streamed = resp is not None and getattr(resp, 'raw_content', None) is None and resp_total > 0
    if req_streamed or resp_streamed:
        return 'streamed'
    if req_trunc or resp_trunc:
        return 'partial'
    if req_total == 0 and resp_total == 0:
        return 'empty'
    return 'complete'


def send_event(payload, sock_path=SOCKET):
    line = json.dumps(payload).encode() + b'\n'
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(1.5)
        client.connect(sock_path)
        client.sendall(line)
        client.recv(1024)


def is_noise_host(host):
    h = (host or '').strip().lower().rstrip('.')
    if not h:
        return False
    return any(h == suffix or h.endswith('.' + suffix) for suffix in NOISE_HOST_SUFFIXES)


def should_ingest(categories, kind, content_type='', status=0, is_error=False,
                  host='', server_ip='', host_filter='', skip_noise=False):
    if skip_noise and is_noise_host(host):
        return False
    hf = (host_filter or '').strip().lower()
    if hf:
        if hf not in (host or '').lower() and hf not in (server_ip or '').lower():
            return False
    if kind == 'http':
        if status >= 400 and 'errors' in categories:
            return True
        c = (content_type or '').lower()
        if c.startswith(('image/', 'video/', 'audio/')):
            return 'images' in categories
        if 'json' in c:
            return 'json' in categories
        if 'javascript' in c or 'ecmascript' in c or 'text/css' in c:
            return 'assets' in categories
        if c.startswith('font/') or any(t in c for t in ('woff', 'octet-stream', 'wasm', 'pdf', 'zip', 'gzip', 'protobuf')):
            return 'binary' in categories
        return 'html' in categories
    if kind == 'websocket':
        return 'websocket' in categories
    if kind == 'tcp':
        return ('tcp' in categories) or (is_error and 'errors' in categories)
    if kind in ('error', 'tls_failed'):
        return 'errors' in categories
    return True


class NetBridgeAddon:
    def __init__(self, sock_path=SOCKET, stage_dir=STAGE_DIR, background=True, filters_file=CAPTURE_FILTERS_FILE):
        self.sock_path = sock_path
        self.stage_dir = Path(stage_dir)
        self.filters_file = Path(filters_file) if filters_file is not None else None
        self._filters_cache = (ALL_CAPTURE_CATEGORIES, '', False)
        self._filters_mtime_ns = None
        self._filters_checked_at = 0.0
        self._queue = queue.Queue(maxsize=MAX_QUEUE)
        self._background = background
        self._count = 0
        self._stats_lock = threading.Lock()
        self._stats = {
            'observed': 0,
            'filtered': 0,
            'queued': 0,
            'queue_drops': 0,
            'stage_drops': 0,
            'ipc_failures': 0,
            'worker_errors': 0,
            'last_error': '',
        }
        self._stats_persisted_at = 0.0
        if background:
            thread = threading.Thread(target=self._worker, name='nb-flow-ipc', daemon=True)
            thread.start()

    def _inc_stat(self, key, delta=1, last_error=None):
        with self._stats_lock:
            self._stats[key] = self._stats.get(key, 0) + delta
            if last_error is not None:
                self._stats['last_error'] = str(last_error)[:80]

    def stats_snapshot(self):
        with self._stats_lock:
            return dict(self._stats)

    def _persist_stats(self, force=False):
        if not self.stage_dir.exists():
            return
        now = time.monotonic()
        if not force and (now - self._stats_persisted_at) < 1.0:
            return
        self._stats_persisted_at = now
        stats_path = self.stage_dir / 'proxy-stats.json'
        tmp_path = self.stage_dir / 'proxy-stats.json.new'
        try:
            tmp_path.write_text(json.dumps(self.stats_snapshot()))
            tmp_path.chmod(0o640)
            tmp_path.replace(stats_path)
        except OSError:
            pass

    def _active_filters(self):
        if self.filters_file is None:
            return self._filters_cache
        now = time.monotonic()
        if now - self._filters_checked_at < 1.0:
            return self._filters_cache
        self._filters_checked_at = now
        try:
            st = self.filters_file.stat()
            if st.st_mtime_ns != self._filters_mtime_ns:
                data = json.loads(self.filters_file.read_text())
                if isinstance(data, dict):
                    raw = data.get('categories', [])
                    parsed = frozenset(c for c in raw if c in ALL_CAPTURE_CATEGORIES)
                    host_filter = str(data.get('host_filter', '') or '').strip()[:128]
                    skip_noise = bool(data.get('skip_noise', False))
                    self._filters_cache = (parsed, host_filter, skip_noise)
                else:
                    self._filters_cache = (ALL_CAPTURE_CATEGORIES, '', False)
                self._filters_mtime_ns = st.st_mtime_ns
        except (OSError, ValueError, TypeError):
            self._filters_cache = (ALL_CAPTURE_CATEGORIES, '', False)
            self._filters_mtime_ns = None
        return self._filters_cache

    def _should_ingest(self, kind, content_type='', status=0, is_error=False, host='', server_ip=''):
        cats, host_filter, skip_noise = self._active_filters()
        return should_ingest(
            cats, kind, content_type=content_type, status=status, is_error=is_error,
            host=host, server_ip=server_ip, host_filter=host_filter, skip_noise=skip_noise,
        )

    def _stage_and_send(self, record):
        meta, req_bytes, resp_bytes = record
        if req_bytes:
            meta['req_b64'] = base64.b64encode(req_bytes).decode('ascii')
        if resp_bytes:
            meta['resp_b64'] = base64.b64encode(resp_bytes).decode('ascii')
        token = uuid.uuid4().hex
        meta_path = self.stage_dir / f'stage-{token}.json'
        if self.stage_dir.exists() and sum(
            1 for p in self.stage_dir.iterdir()
            if p.name.startswith('stage-') and p.name.endswith('.json')
        ) >= MAX_STAGE_FILES:
            self._inc_stat('stage_drops')
            self._persist_stats(force=True)
            return
        self.stage_dir.mkdir(parents=True, exist_ok=True)
        try:
            meta_path.write_text(json.dumps(meta))
            meta_path.chmod(0o640)
            send_event({'action': 'flow-event', 'stage': token}, self.sock_path)
            self._persist_stats()
        except OSError as exc:
            meta_path.unlink(missing_ok=True)
            self._inc_stat('ipc_failures', last_error=f'{type(exc).__name__}: {exc}')
            self._persist_stats(force=True)

    def _worker(self):
        processed = 0
        while True:
            item = self._queue.get()
            try:
                self._stage_and_send(item)
            except Exception as exc:
                self._inc_stat('worker_errors', last_error=f'{type(exc).__name__}: {exc}')
                self._persist_stats(force=True)
            finally:
                self._queue.task_done()
            processed += 1
            if processed % 25 == 0:
                gc.collect()

    def emit_record(self, meta, req_bytes=b'', resp_bytes=b''):
        self._inc_stat('queued')
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
                    self._inc_stat('queue_drops')
                except queue.Empty:
                    pass

    def emit(self, meta):
        try:
            send_event({'action': 'flow-event', 'event': meta}, self.sock_path)
        except OSError as exc:
            self._inc_stat('ipc_failures', last_error=f'{type(exc).__name__}: {exc}')

    @staticmethod
    def _client_ip(conn):
        if conn and getattr(conn, 'peername', None):
            return str(conn.peername[0])
        return ''

    def request(self, flow):
        req = getattr(flow, 'request', None)
        client_conn = getattr(flow, 'client_conn', None)
        if not req or self._client_ip(client_conn) not in ('127.0.0.1', '::1'):
            return
        if getattr(req, 'path', '') != '/__netbridge_healthz':
            return
        flow._nb_healthz = True
        try:
            from mitmproxy import http
            flow.response = http.Response.make(200, b'netbridge-proxy-ok', {'Content-Type': 'text/plain'})
        except ImportError:
            pass

    def response(self, flow):
        if getattr(flow, '_nb_healthz', False):
            return
        req = getattr(flow, 'request', None)
        resp = getattr(flow, 'response', None)
        if not req or not resp:
            return
        self._inc_stat('observed')
        ctype = _header_value(getattr(resp, 'headers', None), 'content-type').split(';')[0].strip()[:64]
        status_code = int(getattr(resp, 'status_code', 0) or 0)
        host = str(getattr(req, 'pretty_host', None) or getattr(req, 'host', '') or '')[:128]
        if not self._should_ingest('http', content_type=ctype, status=status_code, host=host):
            self._inc_stat('filtered')
            self._persist_stats()
            return
        client_conn = getattr(flow, 'client_conn', None)
        server_conn = getattr(flow, 'server_conn', None)
        scheme = (getattr(req, 'scheme', None) or 'http').lower()
        is_tls = bool(getattr(client_conn, 'tls', False)) or scheme == 'https'
        start = getattr(req, 'timestamp_start', None) or time.time()
        end = getattr(resp, 'timestamp_end', None) or time.time()
        req_info = _read_message_payload(req, MAX_HTTP_BODY)
        resp_info = _read_message_payload(resp, MAX_HTTP_BODY)
        req_bytes = req_info['data']
        resp_bytes = resp_info['data']
        req_trunc = req_info['truncated']
        resp_trunc = resp_info['truncated']
        req_total = (
            req_info['decoded_bytes'] if req_info['decoded_size_known'] and req_info['decoded_bytes'] is not None
            else (req_info['decoded_bytes_min'] if req_info['decoded_bytes_min'] is not None else (req_info['wire_bytes'] or req_info['retained_bytes']))
        )
        resp_total = (
            resp_info['decoded_bytes'] if resp_info['decoded_size_known'] and resp_info['decoded_bytes'] is not None
            else (resp_info['decoded_bytes_min'] if resp_info['decoded_bytes_min'] is not None else (resp_info['wire_bytes'] or resp_info['retained_bytes']))
        )
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
            'req_wire_bytes': req_info['wire_bytes'],
            'req_compressed_bytes': req_info['compressed_bytes'],
            'req_retained_bytes': req_info['retained_bytes'],
            'req_decoded_bytes': req_info['decoded_bytes'],
            'req_decoded_bytes_min': req_info['decoded_bytes_min'],
            'req_decoded_size_known': req_info['decoded_size_known'],
            'req_content_encoding': req_info['content_encoding'],
            'req_decompression_status': req_info['decompression_status'],
            'resp_wire_bytes': resp_info['wire_bytes'],
            'resp_compressed_bytes': resp_info['compressed_bytes'],
            'resp_retained_bytes': resp_info['retained_bytes'],
            'resp_decoded_bytes': resp_info['decoded_bytes'],
            'resp_decoded_bytes_min': resp_info['decoded_bytes_min'],
            'resp_decoded_size_known': resp_info['decoded_size_known'],
            'resp_content_encoding': resp_info['content_encoding'],
            'resp_decompression_status': resp_info['decompression_status'],
            'req_truncated': req_trunc,
            'resp_truncated': resp_trunc,
            'payload_status': _http_payload_status(req, req_total, req_trunc, resp, resp_total, resp_trunc),
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
        self._inc_stat('observed')
        host = str(getattr(req, 'pretty_host', None) or getattr(req, 'host', '') or '')[:128]
        if not self._should_ingest('websocket', host=host):
            self._inc_stat('filtered')
            self._persist_stats()
            return
        client_conn = getattr(flow, 'client_conn', None)
        server_conn = getattr(flow, 'server_conn', None)
        is_tls = bool(getattr(client_conn, 'tls', False)) or (getattr(req, 'scheme', '') == 'https')
        client_buf = bytearray()
        server_buf = bytearray()
        transcript = []
        req_total = 0
        resp_total = 0
        total_messages = 0
        for msg in (getattr(ws, 'messages', None) or []):
            total_messages += 1
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
            if len(transcript) < MAX_STREAM_MESSAGES:
                transcript.append({
                    'dir': '->' if from_client else '<-',
                    'type': 'text' if getattr(msg, 'is_text', False) else 'binary',
                    'len': len(content),
                    'time': utc_iso(getattr(msg, 'timestamp', None)),
                })
        retained_messages = len(transcript)
        omitted_messages = max(0, total_messages - retained_messages)
        messages_truncated = omitted_messages > 0
        req_retained = len(client_buf)
        resp_retained = len(server_buf)
        req_truncated = req_total > req_retained
        resp_truncated = resp_total > resp_retained
        if req_truncated or resp_truncated or messages_truncated:
            payload_status = 'partial'
        elif req_total == 0 and resp_total == 0:
            payload_status = 'empty'
        else:
            payload_status = 'complete'
        detail = (
            f'{retained_messages}/{total_messages} frames ({omitted_messages} omitted)'
            if omitted_messages > 0 else f'{total_messages} frames'
        )
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
            'req_retained_bytes': req_retained,
            'resp_retained_bytes': resp_retained,
            'req_truncated': req_truncated,
            'resp_truncated': resp_truncated,
            'total_messages': total_messages,
            'retained_messages': retained_messages,
            'omitted_messages': omitted_messages,
            'messages_truncated': messages_truncated,
            'payload_status': payload_status,
            'duration_ms': max(0, int((end - start) * 1000)),
            'state': 'websocket',
            'detail': detail,
            'request_headers': extract_headers(getattr(req, 'headers', None)),
            'response_headers': [],
            'client_conn': extract_conn(client_conn),
            'server_conn': server_info,
            'frames': transcript,
        }
        self.emit_record(meta, bytes(client_buf), bytes(server_buf))

    def _emit_tcp(self, flow, is_error=False):
        self._inc_stat('observed')
        client_conn = getattr(flow, 'client_conn', None)
        server_conn = getattr(flow, 'server_conn', None)
        server_info = extract_conn(server_conn)
        client_info = extract_conn(client_conn)
        sni = client_info.get('sni') or server_info.get('sni')
        host = sni or server_info.get('ip') or 'unknown'
        if not self._should_ingest('tcp', is_error=is_error, host=host, server_ip=server_info.get('ip', '')):
            self._inc_stat('filtered')
            self._persist_stats()
            return
        is_tls = bool(client_info.get('tls') or server_info.get('tls'))
        client_buf = bytearray()
        server_buf = bytearray()
        chunks = []
        req_total = 0
        resp_total = 0
        total_messages = 0
        for msg in (getattr(flow, 'messages', None) or []):
            total_messages += 1
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
            if len(chunks) < MAX_STREAM_MESSAGES:
                chunks.append({
                    'dir': '->' if from_client else '<-',
                    'len': len(content),
                    'time': utc_iso(getattr(msg, 'timestamp', None)),
                })
        retained_messages = len(chunks)
        omitted_messages = max(0, total_messages - retained_messages)
        messages_truncated = omitted_messages > 0
        req_retained = len(client_buf)
        resp_retained = len(server_buf)
        req_truncated = req_total > req_retained
        resp_truncated = resp_total > resp_retained
        if req_truncated or resp_truncated or messages_truncated:
            payload_status = 'partial'
        elif req_total == 0 and resp_total == 0:
            payload_status = 'empty'
        else:
            payload_status = 'complete'
        start = getattr(flow, 'timestamp_start', None) or getattr(client_conn, 'timestamp_start', None) or time.time()
        end = getattr(client_conn, 'timestamp_end', None) or time.time()
        err = getattr(flow, 'error', None)
        sni = client_info.get('sni') or server_info.get('sni')
        port = server_info.get('port', 0)
        host = sni or server_info.get('ip') or 'unknown'
        if err:
            detail = str(getattr(err, 'msg', '') or '')[:120]
        elif omitted_messages > 0:
            detail = f'{retained_messages}/{total_messages} TCP chunks ({omitted_messages} omitted)'
        else:
            detail = f'{total_messages} TCP chunks'
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
            'req_retained_bytes': req_retained,
            'resp_retained_bytes': resp_retained,
            'req_truncated': req_truncated,
            'resp_truncated': resp_truncated,
            'total_messages': total_messages,
            'retained_messages': retained_messages,
            'omitted_messages': omitted_messages,
            'messages_truncated': messages_truncated,
            'payload_status': payload_status,
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
        self._inc_stat('observed')
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
        if not self._should_ingest('error', host=str(host), server_ip=server_info.get('ip', '')):
            self._inc_stat('filtered')
            self._persist_stats()
            return
        req_info = _read_message_payload(req, MAX_HTTP_BODY) if req else _read_message_payload(None, MAX_HTTP_BODY)
        req_bytes = req_info['data']
        req_trunc = req_info['truncated']
        req_total = (
            req_info['decoded_bytes'] if req_info['decoded_size_known'] and req_info['decoded_bytes'] is not None
            else (req_info['decoded_bytes_min'] if req_info['decoded_bytes_min'] is not None else (req_info['wire_bytes'] or req_info['retained_bytes']))
        )
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
            'req_wire_bytes': req_info['wire_bytes'],
            'req_compressed_bytes': req_info['compressed_bytes'],
            'req_retained_bytes': req_info['retained_bytes'],
            'req_decoded_bytes': req_info['decoded_bytes'],
            'req_decoded_bytes_min': req_info['decoded_bytes_min'],
            'req_decoded_size_known': req_info['decoded_size_known'],
            'req_content_encoding': req_info['content_encoding'],
            'req_decompression_status': req_info['decompression_status'],
            'req_truncated': req_trunc,
            'resp_truncated': False,
            'payload_status': 'partial' if req_trunc else ('empty' if req_total == 0 else 'complete'),
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
        self._inc_stat('observed')
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
        if not self._should_ingest('tls_failed', host=str(host), server_ip=server_info.get('ip', '')):
            self._inc_stat('filtered')
            self._persist_stats()
            return
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
            'payload_status': 'empty',
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
