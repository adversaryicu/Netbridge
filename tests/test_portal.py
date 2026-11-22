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


class AdministrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_pair_login_approve_logout_and_no_implicit_trust(self):
        with tempfile.TemporaryDirectory() as temporary:
            admin, pair = Path(temporary) / 'admin.json', Path(temporary) / 'pair.json'
            code = 'one-time-test-code'
            pair.write_text(json.dumps({'hash': hashlib.sha256(code.encode()).hexdigest(), 'expires': time.time()+60}))
            item = controller.Controller.__new__(controller.Controller)
            item.clients, item.sessions, item.attempts = {}, OrderedDict(), OrderedDict()
            item.hash_gate = asyncio.Semaphore(1)
            item.audit_event = lambda action: None
            item.health = 'ok'
            item.reconcile({'aa:bb:cc:dd:ee:ff': 20}, {'aa:bb:cc:dd:ee:ff': ('192.168.50.100','test')})
            async def dispatch(action, data=None, **kwargs):
                return await item.dispatch({'action':action, 'data':data or {}, 'ip':'192.168.50.100','secure':True, **kwargs})
            with patch.object(controller, 'ADMIN', admin), patch.object(controller, 'PAIR', pair):
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


if __name__ == '__main__':
    unittest.main()
