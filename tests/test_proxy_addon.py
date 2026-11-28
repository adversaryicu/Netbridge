"""Pure-Python tests for proxy_addon bounded decompression, unredacted capture, and payload status."""
import gzip
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'portal'))

import proxy_addon


class BoundedDecompressionTests(unittest.TestCase):
    def test_gzip_bomb_is_bounded_without_full_expansion(self):
        # 4 MiB of zeros compresses to ~4 KiB gzip, well under MAX_DECOMPRESS_RAW.
        bomb = gzip.compress(b'\x00' * (4 * 1024 * 1024))
        self.assertLess(len(bomb), proxy_addon.MAX_DECOMPRESS_RAW)
        msg = SimpleNamespace(
            headers={'content-encoding': 'gzip'},
            raw_content=bomb,
        )
        captured, total, truncated = proxy_addon._read_message_bytes(msg, proxy_addon.MAX_HTTP_BODY)
        self.assertEqual(proxy_addon.MAX_HTTP_BODY, len(captured))
        self.assertTrue(truncated)
        self.assertGreaterEqual(total, proxy_addon.MAX_HTTP_BODY)

    def test_small_gzip_response_decompresses_cleanly(self):
        body = b'{"hello":"world"}' * 10
        msg = SimpleNamespace(
            headers={'content-encoding': 'gzip'},
            raw_content=gzip.compress(body),
        )
        captured, total, truncated = proxy_addon._read_message_bytes(msg, proxy_addon.MAX_HTTP_BODY)
        self.assertEqual(body, captured)
        self.assertEqual(len(body), total)
        self.assertFalse(truncated)

    def test_deflate_bomb_and_raw_deflate(self):
        small = zlib.compress(b'netbridge-deflate')
        captured, total, truncated = proxy_addon._read_message_bytes(
            SimpleNamespace(headers={'content-encoding': 'deflate'}, raw_content=small),
            proxy_addon.MAX_HTTP_BODY,
        )
        self.assertEqual(b'netbridge-deflate', captured)
        self.assertFalse(truncated)

        # Raw deflate (no zlib wrapper)
        comp = zlib.compressobj(wbits=-zlib.MAX_WBITS)
        raw_deflate = comp.compress(b'raw-deflate-ok') + comp.flush()
        captured, total, truncated = proxy_addon._read_message_bytes(
            SimpleNamespace(headers={'content-encoding': 'deflate'}, raw_content=raw_deflate),
            proxy_addon.MAX_HTTP_BODY,
        )
        self.assertEqual(b'raw-deflate-ok', captured)
        self.assertFalse(truncated)

        # Large deflate bomb
        bomb = zlib.compress(b'A' * (2 * 1024 * 1024))
        captured, total, truncated = proxy_addon._read_message_bytes(
            SimpleNamespace(headers={'content-encoding': 'deflate'}, raw_content=bomb),
            proxy_addon.MAX_HTTP_BODY,
        )
        self.assertEqual(proxy_addon.MAX_HTTP_BODY, len(captured))
        self.assertTrue(truncated)

    def test_malformed_and_unknown_encodings_fall_back_safely(self):
        malformed = SimpleNamespace(headers={'content-encoding': 'gzip'}, raw_content=b'not-gzip-bytes')
        captured, total, truncated = proxy_addon._read_message_bytes(malformed, 1024)
        self.assertEqual(b'not-gzip-bytes', captured)
        self.assertEqual(len(b'not-gzip-bytes'), total)
        self.assertTrue(truncated)

        brotli = SimpleNamespace(headers={'content-encoding': 'br'}, raw_content=b'br-bytes')
        captured, total, truncated = proxy_addon._read_message_bytes(brotli, 1024)
        self.assertEqual(b'br-bytes', captured)
        self.assertTrue(truncated)

    def test_uncompressed_and_streamed_messages(self):
        plain = SimpleNamespace(headers={}, raw_content=b'X' * (proxy_addon.MAX_DECOMPRESS_RAW + 500))
        captured, total, truncated = proxy_addon._read_message_bytes(plain, proxy_addon.MAX_HTTP_BODY)
        self.assertEqual(proxy_addon.MAX_HTTP_BODY, len(captured))
        self.assertEqual(proxy_addon.MAX_DECOMPRESS_RAW + 500, total)
        self.assertTrue(truncated)

        streamed = SimpleNamespace(headers={'content-length': '2097152'}, raw_content=None)
        captured, total, truncated = proxy_addon._read_message_bytes(streamed, proxy_addon.MAX_HTTP_BODY)
        self.assertEqual(b'', captured)
        self.assertEqual(2097152, total)
        self.assertTrue(truncated)


class UnredactedAndPayloadStatusTests(unittest.TestCase):
    def test_unredacted_query_and_headers_and_payload_status(self):
        addon = proxy_addon.NetBridgeAddon(background=False)
        records = []
        addon.emit_record = lambda meta, req_b=b'', resp_b=b'': records.append((meta, req_b, resp_b))
        flow = SimpleNamespace(
            client_conn=SimpleNamespace(peername=('192.168.50.105', 55000), tls=True, sni='api.example'),
            server_conn=SimpleNamespace(address=('93.184.216.34', 443), tls=True),
            request=SimpleNamespace(
                method='POST', scheme='https', pretty_host='api.example', host='api.example',
                path='/v1/session?token=synth_123&api_key=synth_456',
                http_version='HTTP/1.1',
                headers=[('authorization', 'Bearer synth_jwt'), ('cookie', 'sid=synth_cookie')],
                raw_content=b'{"user":"test"}', timestamp_start=100.0,
            ),
            response=SimpleNamespace(
                status_code=200, reason='OK', http_version='HTTP/1.1',
                headers={'content-type': 'application/json'},
                raw_content=b'{"ok":true}', timestamp_end=100.02,
            ),
        )
        addon.response(flow)
        self.assertEqual(1, len(records))
        meta = records[0][0]
        self.assertEqual('/v1/session?token=synth_123&api_key=synth_456', meta['path'])
        self.assertIn(['authorization', 'Bearer synth_jwt'], meta['request_headers'])
        self.assertIn(['cookie', 'sid=synth_cookie'], meta['request_headers'])
        self.assertEqual('complete', meta['payload_status'])

    def test_payload_status_variants(self):
        self.assertEqual('empty', proxy_addon._http_payload_status(
            SimpleNamespace(raw_content=b''), 0, False, SimpleNamespace(raw_content=b''), 0, False))
        self.assertEqual('partial', proxy_addon._http_payload_status(
            SimpleNamespace(raw_content=b'a'), 1, False, SimpleNamespace(raw_content=b'b'), 70000, True))
        self.assertEqual('streamed', proxy_addon._http_payload_status(
            SimpleNamespace(raw_content=b''), 0, False, SimpleNamespace(raw_content=None), 1048576, True))


class CaptureIngestFilterTests(unittest.TestCase):
    def test_should_ingest_classification(self):
        self.assertTrue(proxy_addon.should_ingest({'html'}, 'http', content_type='text/html', status=200))
        self.assertFalse(proxy_addon.should_ingest({'html'}, 'http', content_type='application/json', status=200))
        self.assertTrue(proxy_addon.should_ingest({'json'}, 'http', content_type='application/json', status=200))
        self.assertTrue(proxy_addon.should_ingest({'assets'}, 'http', content_type='application/javascript', status=200))
        self.assertTrue(proxy_addon.should_ingest({'assets'}, 'http', content_type='text/css', status=200))
        self.assertFalse(proxy_addon.should_ingest({'html', 'json'}, 'http', content_type='text/css', status=200))
        self.assertTrue(proxy_addon.should_ingest({'images'}, 'http', content_type='image/png', status=200))
        self.assertTrue(proxy_addon.should_ingest({'images'}, 'http', content_type='video/mp4', status=200))
        self.assertTrue(proxy_addon.should_ingest({'binary'}, 'http', content_type='font/woff2', status=200))
        self.assertTrue(proxy_addon.should_ingest({'binary'}, 'http', content_type='application/octet-stream', status=200))
        self.assertTrue(proxy_addon.should_ingest({'errors'}, 'http', content_type='application/json', status=502))
        self.assertTrue(proxy_addon.should_ingest({'websocket'}, 'websocket'))
        self.assertFalse(proxy_addon.should_ingest({'html'}, 'websocket'))
        self.assertTrue(proxy_addon.should_ingest({'tcp'}, 'tcp'))
        self.assertTrue(proxy_addon.should_ingest({'errors'}, 'tcp', is_error=True))
        self.assertTrue(proxy_addon.should_ingest({'errors'}, 'tls_failed'))

    def test_noise_and_host_filters(self):
        self.assertTrue(proxy_addon.is_noise_host('events.data.microsoft.com'))
        self.assertTrue(proxy_addon.is_noise_host('sub.detectportal.firefox.com'))
        self.assertFalse(proxy_addon.is_noise_host('substrate.office.com'))
        self.assertFalse(proxy_addon.should_ingest(
            {'json'}, 'http', content_type='application/json', host='events.data.microsoft.com', skip_noise=True))
        self.assertTrue(proxy_addon.should_ingest(
            {'websocket'}, 'websocket', host='substrate.office.com', skip_noise=True))
        self.assertTrue(proxy_addon.should_ingest(
            {'websocket'}, 'websocket', host='substrate.office.com', host_filter='office.com'))
        self.assertFalse(proxy_addon.should_ingest(
            {'websocket'}, 'websocket', host='example.com', host_filter='office.com'))

    def test_addon_skips_unselected_categories_and_reloads_file(self):
        with tempfile.TemporaryDirectory() as td:
            flt_path = Path(td) / 'capture-filters.json'
            flt_path.write_text(json.dumps({
                'categories': ['websocket', 'json'],
                'host_filter': 'example',
                'skip_noise': True,
            }))
            addon = proxy_addon.NetBridgeAddon(background=False, filters_file=flt_path)
            records = []
            addon.emit_record = lambda meta, req_b=b'', resp_b=b'': records.append((meta, req_b, resp_b))

            img_flow = SimpleNamespace(
                client_conn=SimpleNamespace(peername=('192.168.50.105', 50000), tls=True),
                server_conn=SimpleNamespace(address=('93.184.216.34', 443), tls=True),
                request=SimpleNamespace(method='GET', scheme='https', pretty_host='cdn.example', host='cdn.example',
                                        path='/logo.png', headers=[], raw_content=b'', timestamp_start=1.0),
                response=SimpleNamespace(status_code=200, reason='OK',
                                         headers={'content-type': 'image/png'},
                                         raw_content=b'PNGDATA', timestamp_end=1.1),
            )
            with patch.object(proxy_addon, '_read_message_bytes', side_effect=AssertionError('should not read skipped image')):
                addon.response(img_flow)
            self.assertEqual(0, len(records))

            # Non-matching host skipped before read
            other_json = SimpleNamespace(
                client_conn=SimpleNamespace(peername=('192.168.50.105', 50001), tls=True),
                server_conn=SimpleNamespace(address=('93.184.216.34', 443), tls=True),
                request=SimpleNamespace(method='POST', scheme='https', pretty_host='other.org', host='other.org',
                                        path='/v1/ping', headers=[], raw_content=b'{}', timestamp_start=2.0),
                response=SimpleNamespace(status_code=200, reason='OK',
                                         headers={'content-type': 'application/json'},
                                         raw_content=b'{"ok":true}', timestamp_end=2.1),
            )
            addon.response(other_json)
            self.assertEqual(0, len(records))

            json_flow = SimpleNamespace(
                client_conn=SimpleNamespace(peername=('192.168.50.105', 50001), tls=True),
                server_conn=SimpleNamespace(address=('93.184.216.34', 443), tls=True),
                request=SimpleNamespace(method='POST', scheme='https', pretty_host='api.example', host='api.example',
                                        path='/v1/ping', headers=[], raw_content=b'{}', timestamp_start=2.0),
                response=SimpleNamespace(status_code=200, reason='OK',
                                         headers={'content-type': 'application/json; charset=utf-8'},
                                         raw_content=b'{"ok":true}', timestamp_end=2.1),
            )
            addon.response(json_flow)
            self.assertEqual(1, len(records))

            # Skip TCP and errors when not selected
            addon.tcp_end(SimpleNamespace(client_conn=None, server_conn=None, messages=[]))
            addon.tls_failed_client(SimpleNamespace())
            self.assertEqual(1, len(records))

            # Reload when file updates
            flt_path.write_text(json.dumps({'categories': ['tcp'], 'host_filter': '', 'skip_noise': False}))
            addon._filters_checked_at = 0.0
            addon._filters_mtime_ns = None
            addon.tcp_end(SimpleNamespace(
                client_conn=SimpleNamespace(peername=('192.168.50.105', 50002), tls=False, timestamp_start=3.0, timestamp_end=3.1),
                server_conn=SimpleNamespace(address=('198.51.100.1', 9000), tls=False),
                messages=[SimpleNamespace(from_client=True, content=b'hi', timestamp=3.05)],
                error=None, timestamp_start=3.0,
            ))
            self.assertEqual(2, len(records))


try:
    import server as portal_server
except ImportError:
    portal_server = None


@unittest.skipIf(portal_server is None, 'h11/server module not available on this host')
class DeepSearchTests(unittest.TestCase):
    def test_search_flows_matches_url_headers_and_bodies(self):
        with tempfile.TemporaryDirectory() as td:
            fdir = Path(td)
            (fdir / '1.json').write_text(json.dumps({
                'id': 1, 'method': 'POST', 'scheme': 'https', 'host': 'substrate.office.com',
                'path': '/m365Copilot/Chathub?session=abc', 'req_content_type': 'application/json',
                'content_type': 'application/json',
                'request_headers': [['authorization', 'Bearer my_jwt_token']],
                'response_headers': [['x-trace-id', 'trace-999']],
                'req_b64': 'eyJwcm9tcHQiOiJoZWxsbyBjb3BpbG90In0=',
                'resp_b64': 'eyJyZXBseSI6IndvcmxkIn0=',
            }))
            res_hdr = portal_server.search_flows('my_jwt_token', [1], flows_dir=fdir)
            self.assertEqual([{'id': 1, 'where': ['req_header']}], res_hdr['matches'])
            res_body = portal_server.search_flows('hello copilot', [1], flows_dir=fdir)
            self.assertEqual([{'id': 1, 'where': ['req_body']}], res_body['matches'])
            res_none = portal_server.search_flows('not_present_anywhere', [1], flows_dir=fdir)
            self.assertEqual([], res_none['matches'])


class FindingsPhase1And2AddonTests(unittest.TestCase):
    def test_nb001_websocket_and_tcp_over_128_messages_report_partial(self):
        addon = proxy_addon.NetBridgeAddon(background=False)
        records = []
        addon.emit_record = lambda meta, req_b=b'', resp_b=b'': records.append((meta, req_b, resp_b))

        ws_msgs = [
            SimpleNamespace(from_client=(i % 2 == 0), is_text=True, content=b'A' * 10, timestamp=100.0 + i)
            for i in range(150)
        ]
        ws_flow = SimpleNamespace(
            client_conn=SimpleNamespace(peername=('192.168.50.105', 51000), tls=True),
            server_conn=SimpleNamespace(address=('93.184.216.34', 443)),
            request=SimpleNamespace(method='GET', scheme='https', pretty_host='ws.example', host='ws.example',
                                    path='/ws', headers=[], timestamp_start=100.0),
            websocket=SimpleNamespace(messages=ws_msgs, close_code=1000, close_reason='Normal', timestamp_end=110.0),
        )
        addon.websocket_end(ws_flow)
        ws_meta = records[0][0]
        self.assertEqual('partial', ws_meta['payload_status'])
        self.assertEqual(150, ws_meta['total_messages'])
        self.assertEqual(128, ws_meta['retained_messages'])
        self.assertEqual(22, ws_meta['omitted_messages'])
        self.assertTrue(ws_meta['messages_truncated'])
        self.assertEqual(750, ws_meta['req_bytes'])
        self.assertEqual(750, ws_meta['bytes'])
        self.assertIn('omitted', ws_meta['detail'])

        tcp_msgs = [
            SimpleNamespace(from_client=(i % 2 == 0), content=b'B' * 8, timestamp=200.0 + i)
            for i in range(140)
        ]
        tcp_flow = SimpleNamespace(
            client_conn=SimpleNamespace(peername=('192.168.50.105', 51001), tls=False, timestamp_start=200.0, timestamp_end=205.0),
            server_conn=SimpleNamespace(address=('198.51.100.1', 9000), tls=False),
            messages=tcp_msgs, error=None, timestamp_start=200.0,
        )
        addon.tcp_end(tcp_flow)
        tcp_meta = records[1][0]
        self.assertEqual('partial', tcp_meta['payload_status'])
        self.assertEqual(140, tcp_meta['total_messages'])
        self.assertEqual(128, tcp_meta['retained_messages'])
        self.assertEqual(12, tcp_meta['omitted_messages'])
        self.assertTrue(tcp_meta['messages_truncated'])
        self.assertEqual(560, tcp_meta['req_bytes'])
        self.assertEqual(560, tcp_meta['bytes'])

    def test_nb010_compressed_payload_unknown_decoded_size_and_zstd_window(self):
        bomb = gzip.compress(b'\x00' * (512 * 1024))
        msg = SimpleNamespace(headers={'content-encoding': 'gzip'}, raw_content=bomb)
        info = proxy_addon._read_message_payload(msg, proxy_addon.MAX_HTTP_BODY)
        self.assertFalse(info['decoded_size_known'])
        self.assertIsNone(info['decoded_bytes'])
        self.assertGreater(info['decoded_bytes_min'], proxy_addon.MAX_HTTP_BODY)
        self.assertEqual(len(bomb), info['wire_bytes'])
        self.assertEqual('partial', info['decompression_status'])

        class FakeReader:
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False
            def read(self, n):
                return b'Z' * n

        seen_kwargs = {}
        class FakeZstd:
            @staticmethod
            def ZstdDecompressor(**kwargs):
                seen_kwargs.update(kwargs)
                return SimpleNamespace(stream_reader=lambda bio: FakeReader())

        with patch.object(proxy_addon, 'zstandard', FakeZstd):
            z_info = proxy_addon._read_message_payload(
                SimpleNamespace(headers={'content-encoding': 'zstd'}, raw_content=b'fakezstd'),
                1024,
            )
        self.assertEqual(proxy_addon.MAX_ZSTD_WINDOW_SIZE, seen_kwargs.get('max_window_size'))
        self.assertFalse(z_info['decoded_size_known'])
        self.assertIsNone(z_info['decoded_bytes'])
        self.assertEqual(1025, z_info['decoded_bytes_min'])

    def test_nb002_loss_counters_and_healthz_bypass(self):
        with tempfile.TemporaryDirectory() as td:
            stage = Path(td)
            addon = proxy_addon.NetBridgeAddon(stage_dir=stage, background=False)
            # Healthz request should not increment observed or emit
            hflow = SimpleNamespace(
                _nb_healthz=True,
                client_conn=SimpleNamespace(peername=('127.0.0.1', 12345)),
                request=SimpleNamespace(path='/__netbridge_healthz'),
                response=SimpleNamespace(status_code=200),
            )
            addon.response(hflow)
            self.assertEqual(0, addon.stats_snapshot()['observed'])

            # Stage drop when MAX_STAGE_FILES reached
            for i in range(proxy_addon.MAX_STAGE_FILES):
                (stage / f'stage-{i:032x}.json').write_text('{}')
            addon._stage_and_send(({'host': 'example.com'}, b'', b''))
            self.assertEqual(1, addon.stats_snapshot()['stage_drops'])
            self.assertTrue((stage / 'proxy-stats.json').is_file())

    def test_nb011_measure_memory_runs_without_baseline(self):
        sys.path.insert(0, str(ROOT / 'tests'))
        import measure_memory
        with patch.object(measure_memory, '_systemd_props', return_value={
            'ActiveState': 'inactive', 'MainPID': '0', 'NRestarts': '0',
            'Result': 'success', 'ControlGroup': '', 'CPUUsageNSec': '0',
        }), patch.object(measure_memory, 'read_system_meminfo', return_value={'MemTotal_MiB': 352.0}):
            snap = measure_memory.snapshot()
        self.assertIn('netbridge-proxy', snap['services'])
        self.assertIn('netbridge-controller', snap['services'])
        self.assertIn('netbridge-portal', snap['services'])
        comp = measure_memory.compare_with_baseline(snap, {'combined_Pss_MiB': 10.0, 'services': {}})
        self.assertIn('combined_Pss_MiB_delta', comp)


if __name__ == '__main__':
    unittest.main()
