import asyncio
from collections import OrderedDict
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import hashlib
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'portal'))
import pki
import controller
import proxy_addon
import server
from types import SimpleNamespace
from unittest.mock import AsyncMock
from cryptography import x509
from cryptography.hazmat.primitives import serialization


class PKITests(unittest.TestCase):
    def test_ca_persistence_and_explicit_rotation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'ca'
            first = pki.provision(root, '192.168.50.1')
            self.assertEqual(first, pki.provision(root, '192.168.50.1'))
            key, cert = pki.validate_ca(root / 'current')
            public = (root / 'current/mitmproxy-ca-cert.pem').read_bytes()
            self.assertNotIn(b'PRIVATE KEY', public)
            self.assertEqual(0o600, (root / 'current/mitmproxy-ca.pem').stat().st_mode & 0o777)
            leaf = x509.load_pem_x509_certificate((root / 'current/portal-cert.pem').read_bytes())
            leaf.verify_directly_issued_by(cert)
            self.assertNotEqual(first['fingerprint'], pki.provision(root, '192.168.50.1', rotate=True)['fingerprint'])

    def test_corrupt_ca_is_not_silently_replaced(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'ca'
            pki.provision(root, '192.168.50.1')
            (root / 'current/mitmproxy-ca.pem').write_text('corrupt')
            with self.assertRaises(ValueError):
                pki.provision(root, '192.168.50.1')


class ControllerTests(unittest.TestCase):
    def instance(self):
        item = controller.Controller.__new__(controller.Controller)
        item.clients, item.sessions, item.attempts = {}, OrderedDict(), OrderedDict()
        return item

    def test_disconnect_and_reassociation_revoke_approval(self):
        item = self.instance()
        item.reconcile({'aa:bb:cc:dd:ee:ff': 20}, {})
        item.clients['aa:bb:cc:dd:ee:ff']['approved'] = True
        item.reconcile({'aa:bb:cc:dd:ee:ff': 1}, {})
        self.assertFalse(item.clients['aa:bb:cc:dd:ee:ff']['approved'])
        item.reconcile({}, {})
        self.assertFalse(item.clients)

    def test_csrf_and_session_expiry(self):
        item = self.instance()
        auth = item.new_session()
        with self.assertRaises(controller.Failure):
            item.authorize({'session': auth['session'], 'csrf': 'incorrect'}, mutate=True)
        item.authorize(auth, mutate=True)
        item.sessions[auth['session']]['expires'] = 0
        with self.assertRaises(controller.Failure):
            item.authorize(auth)

    def test_login_rate_limit(self):
        item = self.instance()
        for _ in range(5):
            item.rate_limit('192.168.50.100')
        with self.assertRaises(controller.Failure):
            item.rate_limit('192.168.50.100')

    def test_password_hash(self):
        record = controller.password_hash('correct test password')
        self.assertTrue(controller.password_matches('correct test password', record))
        self.assertFalse(controller.password_matches('incorrect test password', record))

    def test_flow_event_authorization_and_ring_buffer(self):
        from collections import deque
        import base64
        item = self.instance()
        item.proxy_uid = 998
        item.flows = deque()
        item.flow_seq = 0
        item.flow_bytes = 0
        item.flow_sizes = {}
        with self.assertRaises(controller.Failure):
            asyncio.run(item.dispatch({'action': 'flow-event', '_peer_uid': 999, 'event': {'host': 'example.com'}}))
        with self.assertRaises(controller.Failure):
            asyncio.run(item.dispatch({'action': 'flow-event', 'event': {'host': 'example.com'}}))
        with tempfile.TemporaryDirectory() as td:
            flows_dir, stage_dir = Path(td) / 'flows', Path(td) / 'stage'
            flows_dir.mkdir()
            stage_dir.mkdir()
            with patch.object(controller, 'FLOWS_DIR', flows_dir), patch.object(controller, 'STAGE_DIR', stage_dir):
                for i in range(90):
                    token = f'{i:032x}'
                    (stage_dir / f'stage-{token}.json').write_text(json.dumps({
                        'host': f'site{i}.example', 'path': '/test', 'status': 200, 'state': 'decrypted',
                        'request_headers': [['Host', f'site{i}.example']], 'response_headers': [],
                        'resp_b64': base64.b64encode(b'PNGDATA' + bytes([i % 256])).decode('ascii'),
                    }))
                    asyncio.run(item.dispatch({'action': 'flow-event', '_peer_uid': 998, 'stage': token}))
                self.assertEqual(controller.MAX_FLOWS, len(item.flows))
                self.assertEqual(11, item.flows[0]['id'])
                self.assertEqual(90, item.flows[-1]['id'])
                self.assertFalse((flows_dir / '1.json').exists())
                self.assertTrue((flows_dir / '90.json').exists())
                self.assertEqual([], list(stage_dir.iterdir()))

    def test_inspection_sync_and_fail_open(self):
        item = self.instance()
        item.health = 'ok'
        item.inspection_enabled = True
        item.proxy_healthy = True
        item.reconcile(
            {'aa:bb:cc:dd:ee:01': 20, 'aa:bb:cc:dd:ee:02': 20},
            {'aa:bb:cc:dd:ee:01': ('192.168.50.100', 'phone'), 'aa:bb:cc:dd:ee:02': ('192.168.50.101', 'laptop')},
        )
        item.clients['aa:bb:cc:dd:ee:01']['trust_confirmed'] = True
        item.clients['aa:bb:cc:dd:ee:01']['approved'] = True
        item.clients['aa:bb:cc:dd:ee:02']['approved'] = True  # trust_confirmed is False
        applied = []
        async def fake_apply(ips):
            applied.append(ips)
        item.apply_inspected_ips = fake_apply
        asyncio.run(item.sync_inspection_firewall())
        self.assertEqual([('192.168.50.100',)], applied)
        # Disconnecting client removes it on next sync
        item.reconcile({'aa:bb:cc:dd:ee:02': 20}, {'aa:bb:cc:dd:ee:02': ('192.168.50.101', 'laptop')})
        asyncio.run(item.sync_inspection_firewall())
        self.assertEqual([('192.168.50.100',), ()], applied)
        # Re-approve first client, then simulate proxy health failure -> fail-open flush
        item.reconcile({'aa:bb:cc:dd:ee:01': 10}, {'aa:bb:cc:dd:ee:01': ('192.168.50.100', 'phone')})
        item.clients['aa:bb:cc:dd:ee:01']['trust_confirmed'] = True
        item.clients['aa:bb:cc:dd:ee:01']['approved'] = True
        asyncio.run(item.sync_inspection_firewall())
        item.proxy_healthy = False
        asyncio.run(item.sync_inspection_firewall())
        self.assertEqual(('192.168.50.100',), applied[2])
        self.assertEqual((), applied[3])


class ProxyAddonTests(unittest.TestCase):
    def test_unredacted_path_and_headers_preserved(self):
        addon = proxy_addon.NetBridgeAddon(background=False)
        records = []
        addon.emit_record = lambda meta, req_b=b'', resp_b=b'': records.append((meta, req_b, resp_b))
        flow = SimpleNamespace(
            client_conn=SimpleNamespace(peername=('192.168.50.105', 51234), tls=True, sni='example.com'),
            server_conn=SimpleNamespace(address=('93.184.216.34', 443), tls=True),
            request=SimpleNamespace(
                method='GET', scheme='https', pretty_host='example.com', host='example.com',
                path='/auth/callback?token=synthetic_tok&next=/home&api_key=synthetic_key&tab=1',
                http_version='HTTP/2.0',
                headers=[('host', 'example.com'), ('authorization', 'Bearer synthetic_bearer')],
                raw_content=b'', timestamp_start=100.0,
            ),
            response=SimpleNamespace(
                status_code=200, reason='OK', http_version='HTTP/2.0',
                headers={'content-type': 'text/plain'},
                raw_content=b'ok', timestamp_end=100.01,
            ),
        )
        addon.response(flow)
        self.assertEqual(1, len(records))
        meta = records[0][0]
        self.assertIn('token=synthetic_tok', meta['path'])
        self.assertIn('api_key=synthetic_key', meta['path'])
        self.assertIn(['authorization', 'Bearer synthetic_bearer'], meta['request_headers'])

    def test_addon_emits_http_tcp_websocket_and_tls_failed_events(self):
        addon = proxy_addon.NetBridgeAddon(background=False)
        records = []
        addon.emit_record = lambda meta, req_b=b'', resp_b=b'': records.append((meta, req_b, resp_b))
        flow = SimpleNamespace(
            client_conn=SimpleNamespace(peername=('192.168.50.105', 51234), tls=True, sni='example.com',
                                       tls_version='TLSv1.3', cipher='TLS_AES_128_GCM_SHA256', alpn=b'h2'),
            server_conn=SimpleNamespace(address=('93.184.216.34', 443), tls=True, tls_version='TLSv1.3'),
            request=SimpleNamespace(method='POST', scheme='https', pretty_host='example.com', host='example.com',
                                    path='/items?password=hunter2&page=2', http_version='HTTP/2.0',
                                    headers=[('host', 'example.com'), ('content-type', 'application/json')],
                                    raw_content=b'{"beacon":1}', timestamp_start=100.0),
            response=SimpleNamespace(status_code=200, reason='OK', http_version='HTTP/2.0',
                                     headers={'content-type': 'application/json; charset=utf-8'},
                                     raw_content=b'{"ok":true}', timestamp_end=100.05),
        )
        addon.response(flow)
        self.assertEqual(b'{"beacon":1}', flow.request.raw_content)
        self.assertEqual(b'{"ok":true}', flow.response.raw_content)
        self.assertEqual(1, len(records))
        meta, req_b, resp_b = records[0]
        self.assertEqual('decrypted', meta['state'])
        self.assertEqual('192.168.50.105', meta['client_ip'])
        self.assertEqual('/items?password=hunter2&page=2', meta['path'])
        self.assertEqual(b'{"beacon":1}', req_b)
        self.assertEqual(b'{"ok":true}', resp_b)
        self.assertEqual([['host', 'example.com'], ['content-type', 'application/json']], meta['request_headers'])

        tcp_flow = SimpleNamespace(
            client_conn=SimpleNamespace(peername=('192.168.50.105', 51236), tls=False, sni='', timestamp_start=101.0, timestamp_end=101.2),
            server_conn=SimpleNamespace(address=('198.51.100.42', 4444), tls=False, sni=''),
            messages=[
                SimpleNamespace(from_client=True, content=b'\xde\xad\xbe\xefHELLO', timestamp=101.05),
                SimpleNamespace(from_client=False, content=b'CMD_ACK\x00', timestamp=101.10),
            ],
            error=None,
            timestamp_start=101.0,
        )
        addon.tcp_end(tcp_flow)
        self.assertEqual(2, len(records))
        tcp_meta, tcp_req, tcp_resp = records[1]
        self.assertEqual('tcp', tcp_meta['state'])
        self.assertEqual(4444, tcp_meta['server_port'])
        self.assertEqual(b'\xde\xad\xbe\xefHELLO', tcp_req)
        self.assertEqual(b'CMD_ACK\x00', tcp_resp)

        ws_flow = SimpleNamespace(
            client_conn=SimpleNamespace(peername=('192.168.50.105', 51237), tls=True, sni='ws.example'),
            server_conn=SimpleNamespace(address=('93.184.216.34', 443)),
            request=SimpleNamespace(method='GET', scheme='https', pretty_host='ws.example', host='ws.example',
                                    path='/socket', headers=[('upgrade', 'websocket')], timestamp_start=102.0),
            websocket=SimpleNamespace(
                messages=[SimpleNamespace(from_client=True, is_text=True, content=b'ping', timestamp=102.1),
                          SimpleNamespace(from_client=False, is_text=False, content=b'\x01\x02', timestamp=102.2)],
                close_code=1000, close_reason='Normal', timestamp_end=102.5,
            ),
        )
        addon.websocket_end(ws_flow)
        self.assertEqual(3, len(records))
        self.assertEqual('websocket', records[2][0]['state'])
        self.assertEqual(b'ping', records[2][1])
        self.assertEqual(b'\x01\x02', records[2][2])

        tls_data = SimpleNamespace(
            conn=SimpleNamespace(sni='pinned.example', error='Client disconnected during TLS handshake'),
            context=SimpleNamespace(
                client=SimpleNamespace(peername=('192.168.50.105', 51235), sni='pinned.example'),
                server=SimpleNamespace(address=('93.184.216.34', 443)),
            ),
        )
        addon.tls_failed_client(tls_data)
        self.assertEqual(4, len(records))
        self.assertEqual('tls_failed', records[3][0]['state'])
        self.assertEqual('pinned.example', records[3][0]['host'])

    def test_large_body_skips_decompression_and_burst_drops_oldest(self):
        class LargeMessage:
            raw_content = b'X' * (proxy_addon.MAX_DECOMPRESS_RAW + 500)
            headers = {'content-length': str(proxy_addon.MAX_DECOMPRESS_RAW + 500)}

            @property
            def content(self):
                raise AssertionError('Large raw_content should not be decompressed')

        captured, total, trunc = proxy_addon._read_message_bytes(LargeMessage(), proxy_addon.MAX_HTTP_BODY)
        self.assertEqual(proxy_addon.MAX_HTTP_BODY, len(captured))
        self.assertEqual(proxy_addon.MAX_DECOMPRESS_RAW + 500, total)
        self.assertTrue(trunc)
        # Queue drops oldest under burst so latest events always remain
        addon = proxy_addon.NetBridgeAddon(background=False)
        addon._background = True  # test non-started worker queue behavior directly
        for i in range(proxy_addon.MAX_QUEUE + 5):
            addon.emit_record({'seq': i})
        self.assertEqual(proxy_addon.MAX_QUEUE, addon._queue.qsize())
        queued = [addon._queue.get_nowait()[0]['seq'] for _ in range(proxy_addon.MAX_QUEUE)]
        self.assertEqual(5, queued[0])
        self.assertEqual(proxy_addon.MAX_QUEUE + 4, queued[-1])


class HTTPTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.portal = server.Portal('192.168.50.1')
        self.listener = await asyncio.start_server(self.portal.handle, '127.0.0.1', 0)
        self.port = self.listener.sockets[0].getsockname()[1]
        self.client = self

    async def asyncTearDown(self):
        self.listener.close()
        await self.listener.wait_closed()

    async def raw(self, data):
        reader, writer = await asyncio.open_connection('127.0.0.1', self.port)
        writer.write(data)
        await writer.drain()
        response = await asyncio.wait_for(reader.read(), 7)
        writer.close()
        await writer.wait_closed()
        header, body = response.split(b'\r\n\r\n', 1)
        lines = header.decode().split('\r\n')
        return SimpleNamespace(status=int(lines[0].split()[1]),
            headers=dict(line.split(': ', 1) for line in lines[1:]), body=body)

    async def get(self, path, headers):
        return await self.raw(('GET '+path+' HTTP/1.1\r\n' + ''.join(k+': '+v+'\r\n' for k,v in headers.items())+'\r\n').encode())

    async def post(self, path, json, headers):
        import json as serializer
        body=serializer.dumps(json).encode()
        prefix=('POST '+path+' HTTP/1.1\r\n'+''.join(k+': '+v+'\r\n' for k,v in headers.items())+
                'Content-Type: application/json\r\nContent-Length: '+str(len(body))+'\r\n\r\n').encode()
        return await self.raw(prefix+body)

    async def test_wrong_host_rejected(self):
        response = await self.client.get('/', headers={'Host':'attacker.example'})
        self.assertEqual(421, response.status)

    async def test_cross_origin_mutation_rejected(self):
        response = await self.client.post('/api/login', json={'password':'test'}, headers={'Host':'192.168.50.1','Origin':'https://attacker.example'})
        self.assertEqual(403, response.status)

    async def test_http_admin_api_rejected(self):
        response = await self.client.get('/api/status', headers={'Host':'192.168.50.1'})
        self.assertEqual(403, response.status)

    async def test_inspector_page_redirect_and_https_html(self):
        import h11
        response = await self.client.get('/inspector', headers={'Host':'192.168.50.1'})
        self.assertEqual(302, response.status)
        self.assertEqual('https://192.168.50.1/inspector', response.headers['Location'])
        ev = h11.Request(method=b'GET', target=b'/inspector', headers=[(b'host', b'192.168.50.1')])
        secure_resp = await self.portal.route(server.Request(ev, b'', '192.168.50.100', True))
        self.assertEqual(200, secure_resp.status)
        self.assertIn(b'NETBRIDGE // ADVERSARY ICU', secure_resp.body)
        self.assertIn(b'Traffic &amp; Application Inspector', secure_resp.body)

    async def test_private_key_path_not_served(self):
        response = await self.client.get('/mitmproxy-ca.pem', headers={'Host':'192.168.50.1'})
        self.assertEqual(404, response.status)

    async def test_public_page_security_headers(self):
        response = await self.client.get('/', headers={'Host':'192.168.50.1'})
        self.assertEqual(200, response.status)
        self.assertEqual('no-store', response.headers['Cache-Control'])
        self.assertIn("frame-ancestors 'none'", response.headers['Content-Security-Policy'])

    async def test_large_content_length_rejected_before_body(self):
        response=await self.raw(b'POST /api/login HTTP/1.1\r\nHost: 192.168.50.1\r\nContent-Length: 5000\r\n\r\n')
        self.assertEqual(413,response.status)

    async def test_ambiguous_framing_rejected(self):
        response=await self.raw(b'POST /api/login HTTP/1.1\r\nHost: 192.168.50.1\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n')
        self.assertEqual(400,response.status)

    async def test_malformed_chunk_rejected(self):
        response=await self.raw(b'POST /api/login HTTP/1.1\r\nHost: 192.168.50.1\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}XX0\r\n\r\n')
        self.assertEqual(400,response.status)

    async def test_chunked_body_limit(self):
        response=await self.raw(b'POST /api/login HTTP/1.1\r\nHost: 192.168.50.1\r\nTransfer-Encoding: chunked\r\n\r\n1388\r\n'+b'x'*5000+b'\r\n0\r\n\r\n')
        self.assertEqual(413,response.status)

    async def test_duplicate_host_rejected(self):
        response=await self.raw(b'GET / HTTP/1.1\r\nHost: 192.168.50.1\r\nHost: attacker.example\r\n\r\n')
        self.assertEqual(400,response.status)

    async def test_head_has_no_body(self):
        response=await self.raw(b'HEAD / HTTP/1.1\r\nHost: 192.168.50.1\r\n\r\n')
        self.assertEqual(200,response.status)
        self.assertEqual(b'',response.body)
        self.assertGreater(int(response.headers['Content-Length']),0)

    async def test_secure_cookie_and_forwarded_csrf(self):
        import h11
        event=h11.Request(method=b'POST',target=b'/api/login',headers=[(b'host',b'192.168.50.1'),
            (b'origin',b'https://192.168.50.1'),(b'content-type',b'application/json')])
        request=server.Request(event,b'{"password":"test administrator password"}','192.168.50.100',True)
        with patch.object(server,'rpc',new=AsyncMock(return_value={'status':200,'data':{'session':'testtoken','csrf':'testcsrf'}})):
            response=await self.portal.route(request)
        self.assertIn('Secure; HttpOnly; SameSite=Strict',response.headers['Set-Cookie'])
        self.assertNotIn('testtoken',response.body.decode())
        event=h11.Request(method=b'POST',target=b'/api/logout',headers=[(b'host',b'192.168.50.1'),
            (b'origin',b'https://192.168.50.1'),(b'content-type',b'application/json'),
            (b'cookie',b'__Host-netbridge=testtoken'),(b'x-netbridge-csrf',b'testcsrf')])
        request=server.Request(event,b'{}','192.168.50.100',True)
        with patch.object(server,'rpc',new=AsyncMock(return_value={'status':200,'data':{'ok':True}})) as call:
            response=await self.portal.route(request)
        self.assertEqual('testtoken',call.call_args.args[0]['session'])
        self.assertEqual('testcsrf',call.call_args.args[0]['csrf'])
        self.assertIn('Max-Age=0',response.headers['Set-Cookie'])

    async def test_flow_detail_raw_hex_and_exports(self):
        import h11, base64
        with tempfile.TemporaryDirectory() as td:
            flows_dir = Path(td)
            (flows_dir / '1.json').write_text(json.dumps({
                'id': 1, 'time': '2026-11-23T19:00:00Z', 'client_ip': '192.168.50.100',
                'server_ip': '93.184.216.34', 'server_port': 443, 'method': 'POST',
                'scheme': 'https', 'host': 'c2.example', 'path': '/beacon?id=42',
                'http_version': 'HTTP/1.1', 'resp_http_version': 'HTTP/1.1',
                'status': 200, 'reason': 'OK', 'content_type': 'image/png',
                'req_content_type': 'application/octet-stream', 'req_bytes': 4, 'bytes': 8,
                'duration_ms': 15, 'state': 'decrypted', 'detail': '',
                'request_headers': [['Host', 'c2.example']],
                'response_headers': [['Content-Type', 'image/png']],
                'req_b64': base64.b64encode(b'\xde\xad\xbe\xef').decode('ascii'),
                'resp_b64': base64.b64encode(b'\x89PNG\r\n\x1a\n').decode('ascii'),
            }))
            with patch.object(server, 'FLOWS_DIR', flows_dir), \
                 patch.object(server, 'rpc', new=AsyncMock(return_value={'status': 200, 'data': {'ok': True, 'ids': [1]}})):
                # Detail JSON
                ev = h11.Request(method=b'GET', target=b'/api/flow?id=1',
                                 headers=[(b'host', b'192.168.50.1'), (b'cookie', b'__Host-netbridge=tok')])
                resp = await self.portal.route(server.Request(ev, b'', '192.168.50.100', True))
                self.assertEqual(200, resp.status)
                detail = json.loads(resp.body)
                self.assertIn('de ad be ef', detail['request']['hex'])
                self.assertTrue(detail['response']['is_inline_image'])
                # Inline PNG image (allowed without confirmation)
                ev_img = h11.Request(method=b'GET', target=b'/api/flow-raw?id=1&part=response&format=raw',
                                     headers=[(b'host', b'192.168.50.1'), (b'cookie', b'__Host-netbridge=tok')])
                resp_img = await self.portal.route(server.Request(ev_img, b'', '192.168.50.100', True))
                self.assertEqual(b'\x89PNG\r\n\x1a\n', resp_img.body)
                self.assertEqual('image/png', resp_img.headers['Content-Type'])
                # Non-image raw payload without download=1 still requires confirmation
                ev_raw_no_confirm = h11.Request(method=b'GET', target=b'/api/flow-raw?id=1&part=request&format=raw',
                                                headers=[(b'host', b'192.168.50.1'), (b'cookie', b'__Host-netbridge=tok')])
                with self.assertRaises(server.Reject) as ctx_raw:
                    await self.portal.route(server.Request(ev_raw_no_confirm, b'', '192.168.50.100', True))
                self.assertEqual(400, ctx_raw.exception.status)
                # Hex export (requires explicit confirmation)
                ev_hex = h11.Request(method=b'GET', target=b'/api/flow-raw?id=1&part=request&format=hex&download=1&confirm=unredacted',
                                     headers=[(b'host', b'192.168.50.1'), (b'cookie', b'__Host-netbridge=tok')])
                resp_hex = await self.portal.route(server.Request(ev_hex, b'', '192.168.50.100', True))
                self.assertIn(b'00000000  de ad be ef', resp_hex.body)
                # Bulk exports: JSONL, HAR, CSV (require confirm=unredacted and stream chunks)
                for fmt, expect in (('jsonl', b'c2.example'), ('har', b'"version": "1.2"'), ('csv', b'c2.example')):
                    ev_exp = h11.Request(method=b'GET', target=f'/api/flows-export?format={fmt}&confirm=unredacted'.encode(),
                                         headers=[(b'host', b'192.168.50.1'), (b'cookie', b'__Host-netbridge=tok')])
                    resp_exp = await self.portal.route(server.Request(ev_exp, b'', '192.168.50.100', True))
                    self.assertEqual(200, resp_exp.status)
                    body = b''.join(resp_exp.chunks) if isinstance(resp_exp, server.StreamingResponse) else resp_exp.body
                    self.assertIn(expect, body)

    async def test_nb006_export_confirmation_and_nb007_safe_csv_and_nb005_har(self):
        import h11, base64
        with tempfile.TemporaryDirectory() as td:
            flows_dir = Path(td)
            (flows_dir / '1.json').write_text(json.dumps({
                'id': 1, 'time': '2026-11-28T10:00:00Z', 'client_ip': '192.168.50.100',
                'server_ip': '93.184.216.34', 'server_port': 8443, 'method': 'GET',
                'scheme': 'https', 'host': 'app.example', 'path': '/=1+1?a=1',
                'http_version': 'HTTP/1.1', 'resp_http_version': 'HTTP/1.1',
                'status': 302, 'reason': 'Found', 'content_type': 'text/html',
                'req_content_type': '', 'req_bytes': 0, 'bytes': 2,
                'duration_ms': 12, 'state': 'decrypted', 'detail': '=cmd()',
                'payload_status': 'complete',
                'request_headers': [['Host', 'app.example:8443'], ['Cookie', 'sid=abc; theme=dark']],
                'response_headers': [['Location', 'https://app.example:8443/next'], ['Set-Cookie', 'tok=xyz; HttpOnly']],
                'resp_b64': base64.b64encode(b'hi').decode('ascii'),
            }))
            (flows_dir / '2.json').write_text(json.dumps({
                'id': 2, 'time': '2026-11-28T10:00:01Z', 'client_ip': '192.168.50.100',
                'server_ip': '198.51.100.5', 'server_port': 4444, 'method': 'TCP',
                'scheme': 'tcp', 'host': '198.51.100.5', 'path': ':4444',
                'status': 0, 'state': 'tcp', 'detail': '1 TCP chunks',
            }))
            with patch.object(server, 'FLOWS_DIR', flows_dir), \
                 patch.object(server, 'rpc', new=AsyncMock(return_value={'status': 200, 'data': {'ok': True, 'ids': [1, 2], 'capture_stats': {'observed': 2, 'total_loss': 0}}})):
                # NB-006: Unconfirmed export rejected
                ev_no = h11.Request(method=b'GET', target=b'/api/flows-export?format=csv',
                                    headers=[(b'host', b'192.168.50.1'), (b'cookie', b'__Host-netbridge=tok')])
                with self.assertRaises(server.Reject) as ctx:
                    await self.portal.route(server.Request(ev_no, b'', '192.168.50.100', True))
                self.assertEqual(400, ctx.exception.status)

                # NB-007: Safe CSV neutralizes formula cells; raw CSV preserves them
                ev_safe = h11.Request(method=b'GET', target=b'/api/flows-export?format=csv&safe=1&confirm=unredacted',
                                      headers=[(b'host', b'192.168.50.1'), (b'cookie', b'__Host-netbridge=tok')])
                resp_safe = await self.portal.route(server.Request(ev_safe, b'', '192.168.50.100', True))
                self.assertEqual('safe', resp_safe.headers['X-NetBridge-CSV-Mode'])
                safe_text = b''.join(resp_safe.chunks).decode('utf-8')
                self.assertIn("'=cmd()", safe_text)

                ev_raw = h11.Request(method=b'GET', target=b'/api/flows-export?format=csv&confirm=unredacted',
                                     headers=[(b'host', b'192.168.50.1'), (b'cookie', b'__Host-netbridge=tok')])
                resp_raw = await self.portal.route(server.Request(ev_raw, b'', '192.168.50.100', True))
                self.assertEqual('raw', resp_raw.headers['X-NetBridge-CSV-Mode'])
                raw_text = b''.join(resp_raw.chunks).decode('utf-8')
                self.assertIn(',=cmd(),', raw_text)

                # NB-005: HAR fidelity
                ev_har = h11.Request(method=b'GET', target=b'/api/flows-export?format=har&confirm=unredacted',
                                     headers=[(b'host', b'192.168.50.1'), (b'cookie', b'__Host-netbridge=tok')])
                resp_har = await self.portal.route(server.Request(ev_har, b'', '192.168.50.100', True))
                har = json.loads(b''.join(resp_har.chunks).decode('utf-8'))
                self.assertEqual(1, len(har['log']['entries']))
                self.assertEqual(1, har['log']['_netbridge']['skipped_non_http'])
                entry = har['log']['entries'][0]
                self.assertEqual('https://app.example:8443/=1+1?a=1', entry['request']['url'])
                self.assertEqual('https://app.example:8443/next', entry['response']['redirectURL'])
                self.assertEqual(2, len(entry['request']['cookies']))
                self.assertEqual(1, len(entry['response']['cookies']))
                self.assertEqual(-1, entry['timings']['send'])
                self.assertEqual(-1, entry['timings']['receive'])
                self.assertEqual(12, entry['timings']['wait'])

    async def test_nb003_full_ring_streaming_export_memory(self):
        import tracemalloc, base64
        with tempfile.TemporaryDirectory() as td:
            flows_dir = Path(td)
            b64_payload = base64.b64encode(b'A' * 65536).decode('ascii')
            ids = list(range(1, 81))
            for i in ids:
                (flows_dir / f'{i}.json').write_text(json.dumps({
                    'id': i, 'time': '2026-11-28T10:00:00Z', 'client_ip': '192.168.50.100',
                    'server_ip': '93.184.216.34', 'server_port': 443, 'method': 'GET',
                    'scheme': 'https', 'host': 'bench.example', 'path': f'/item/{i}',
                    'status': 200, 'state': 'decrypted', 'content_type': 'text/plain',
                    'req_bytes': 0, 'bytes': 65536, 'resp_b64': b64_payload,
                }))
            tracemalloc.start()
            try:
                count = 0
                for chunk in server.iter_export('jsonl', ids, flows_dir=flows_dir):
                    self.assertIsInstance(chunk, bytes)
                    count += 1
                _, peak = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()
            self.assertEqual(80, count)
            self.assertLess(peak, 4 * 1024 * 1024)


class AdministrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_pair_login_approve_logout_and_no_implicit_trust(self):
        with tempfile.TemporaryDirectory() as temporary:
            admin, pair = Path(temporary) / 'admin.json', Path(temporary) / 'pair.json'
            (Path(temporary) / 'ca.json').write_text(json.dumps({'name': 'Test CA', 'fingerprint': '00', 'expires': '2046-01-01T00:00:00+00:00'}))
            (Path(temporary) / 'eth0').mkdir()
            (Path(temporary) / 'eth0' / 'carrier').write_text('1\n')
            code = 'one-time-test-code'
            pair.write_text(json.dumps({'hash': hashlib.sha256(code.encode()).hexdigest(), 'expires': time.time()+60}))
            item = controller.Controller.__new__(controller.Controller)
            item.clients, item.sessions, item.attempts = {}, OrderedDict(), OrderedDict()
            item.hash_gate = asyncio.Semaphore(1)
            item.audit_event = lambda action: None
            item.health = 'ok'
            item.network = {'wan': 'eth0', 'lan': 'wlan0'}
            item.config = {'ap': {'ssid': 'TestNet'}}
            item.pending = False
            item.reconcile({'aa:bb:cc:dd:ee:ff': 20}, {'aa:bb:cc:dd:ee:ff': ('192.168.50.100','test')})
            async def dispatch(action, data=None, **kwargs):
                return await item.dispatch({'action':action, 'data':data or {}, 'ip':'192.168.50.100','secure':True, **kwargs})
            with patch.object(controller, 'ADMIN', admin), patch.object(controller, 'PAIR', pair), \
                 patch.object(controller, 'PUBLIC', Path(temporary)), patch.object(controller, 'SYS_NET', Path(temporary)):
                auth = await dispatch('pair', {'code':code,'password':'test administrator password'})
                self.assertTrue(admin.exists())
                self.assertFalse(pair.exists())
                with self.assertRaises(controller.Failure):
                    await dispatch('pair', {'code':code,'password':'different administrator password'})
                with self.assertRaises(controller.Failure):
                    await dispatch('approve', {'mac':'aa:bb:cc:dd:ee:ff'}, **auth)
                probe = await dispatch('trust-probe')
                self.assertFalse(item.clients['aa:bb:cc:dd:ee:ff']['trust_confirmed'])
                await dispatch('trust-confirm', {'challenge':probe['challenge'], 'no_warning':True})
                await dispatch('approve', {'mac':'aa:bb:cc:dd:ee:ff'}, **auth)
                self.assertTrue(item.clients['aa:bb:cc:dd:ee:ff']['approved'])
                await dispatch('logout', **auth)
                with self.assertRaises(controller.Failure):
                    await dispatch('revoke', {'mac':'aa:bb:cc:dd:ee:ff'}, **auth)
                second = await dispatch('login', {'password':'test administrator password'})
                self.assertNotEqual(auth['session'], second['session'])
                applied = []
                item.apply_inspected_ips = lambda ips: asyncio.sleep(0, result=applied.append(ips))
                item.command = AsyncMock(return_value='')
                item.check_proxy_health = AsyncMock(return_value=True)
                res = await dispatch('inspection', {'enabled': True}, **second)
                self.assertEqual('on', res['inspection'])
                self.assertEqual('on', item.inspection_state())
                self.assertEqual([('192.168.50.100',)], applied)
                item.record_flow({'client_ip': '192.168.50.100', 'host': 'example.com', 'state': 'decrypted', 'status': 200})
                status = await dispatch('status', **second)
                self.assertEqual(1, len(status['flows']))
                await dispatch('flows-clear', {}, **second)
                self.assertEqual(0, len(item.flows))
                res = await dispatch('inspection', {'enabled': False}, **second)
                self.assertEqual('off', res['inspection'])
                self.assertEqual((), applied[-1])

    def test_nb004_functional_proxy_health_check(self):
        item = controller.Controller.__new__(controller.Controller)
        item.check_proxy_process_health = AsyncMock(return_value=True)
        item.check_proxy_functional_health = AsyncMock(return_value=False)
        self.assertFalse(asyncio.run(item.check_proxy_health()))
        self.assertTrue(item.proxy_process_healthy)
        self.assertFalse(item.proxy_functional_healthy)
        self.assertEqual('functional_probe_failed', item.proxy_health_detail)

    def test_nb002_capture_stats_baseline_handles_proxy_restart(self):
        item = controller.Controller.__new__(controller.Controller)
        item._proxy_stats = {'observed': 50, 'filtered': 10, 'queue_drops': 2}
        item._stats_baseline = {'observed': 50, 'filtered': 10, 'queue_drops': 2}
        item.retained_total = 0
        item.evicted_ring = 0
        item.evicted_quota = 0
        item.controller_errors = 0
        with patch.object(controller, 'STAGE_DIR', Path('/nonexistent-netbridge-stage')):
            # Simulate proxy restart where proxy counters reset below baseline
            item._proxy_stats = {'observed': 3, 'filtered': 1, 'queue_drops': 0}
            stats = item.get_capture_stats()
        self.assertEqual(3, stats['observed'])
        self.assertEqual(1, stats['filtered'])
        self.assertEqual(0, stats['dropped_queue'])


if __name__ == '__main__':
    unittest.main()
