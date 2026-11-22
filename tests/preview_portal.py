"""Loopback-only layout preview; fixture APIs never run on the device service."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import json

STATIC = Path(__file__).resolve().parents[1] / 'portal/static'


class Preview(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/api/public':
            body = json.dumps({'paired':False, 'gateway':'192.168.50.1', 'inspection':'off',
                'ca':{'name':'NetBridge CA · Layout preview', 'fingerprint':':'.join(['AB']*32),
                      'expires':'2046-11-21T00:00:00Z'}}).encode()
            kind, status = 'application/json', 200
        elif self.path == '/api/status':
            body, kind, status = b'{"error":"Sign in"}', 'application/json', 401
        elif self.path in ('/', '/admin', '/trust', '/style.css', '/app.js'):
            name = 'index.html' if self.path in ('/', '/admin', '/trust') else self.path[1:]
            body = (STATIC / name).read_bytes()
            kind = 'text/css' if name.endswith('.css') else 'application/javascript' if name.endswith('.js') else 'text/html'
            status = 200
        else:
            body, kind, status = b'Not found', 'text/plain', 404
        self.send_response(status)
        self.send_header('Content-Type', kind)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == '__main__':
    print('Layout preview: http://127.0.0.1:18080', flush=True)
    ThreadingHTTPServer(('127.0.0.1', 18080), Preview).serve_forever()
