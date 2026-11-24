#!/usr/bin/env python3
"""Exercise the real nft rules in disposable namespaces, never the live AP."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tomllib
import uuid

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('network', ROOT / 'scripts/netbridge-network.py')
network = importlib.util.module_from_spec(spec)
spec.loader.exec_module(network)


def main():
    if os.geteuid() != 0:
        raise SystemExit('Run with sudo; only disposable namespaces are modified.')
    prefix = 'nbtest-' + uuid.uuid4().hex[:6]
    client, gateway, upstream = [prefix + suffix for suffix in ('-c', '-g', '-u')]
    created = []
    def cmd(*args, check=True, data=None):
        return subprocess.run(args, input=data, text=True, capture_output=True, check=check, timeout=15)
    def inside(ns, *args, **kwargs):
        return cmd('ip', 'netns', 'exec', ns, *args, **kwargs)
    try:
        for ns in (client, gateway, upstream):
            cmd('ip', 'netns', 'add', ns)
            created.append(ns)
            inside(ns, 'ip', 'link', 'set', 'lo', 'up')
        inside(gateway, 'ip', 'link', 'add', 'wlan0', 'type', 'veth', 'peer', 'name', 'nb-client')
        inside(gateway, 'ip', 'link', 'set', 'nb-client', 'netns', client)
        inside(gateway, 'ip', 'link', 'add', 'eth0', 'type', 'veth', 'peer', 'name', 'nb-upstream')
        inside(gateway, 'ip', 'link', 'set', 'nb-upstream', 'netns', upstream)
        for ns, iface, address in [(gateway, 'wlan0', '192.168.50.1/24'),
                                   (client, 'nb-client', '192.168.50.100/24'),
                                   (gateway, 'eth0', '192.168.1.1/24'),
                                   (upstream, 'nb-upstream', '192.168.1.2/24')]:
            inside(ns, 'ip', 'address', 'add', address, 'dev', iface)
            inside(ns, 'ip', 'link', 'set', iface, 'up')
        inside(upstream, 'ip', 'address', 'add', '198.18.0.1/32', 'dev', 'lo')
        inside(client, 'ip', 'route', 'add', 'default', 'via', '192.168.50.1')
        inside(gateway, 'ip', 'route', 'add', '198.18.0.1/32', 'via', '192.168.1.2')
        inside(upstream, 'ip', 'route', 'add', '192.168.50.0/24', 'via', '192.168.1.1')
        inside(gateway, 'sysctl', '-qw', 'net.ipv4.ip_forward=1')
        config = tomllib.loads((ROOT / 'config/phase1.toml').read_text())
        rules = network.firewall(config, {'lan': 'wlan0', 'wan': 'eth0'})
        # Reapply the exact transaction to test atomic replacement/idempotence too.
        for _ in range(2):
            inside(gateway, 'nft', '-f', '-', data=rules)
        for destination, expected in [('192.168.50.1', True), ('198.18.0.1', True), ('192.168.1.2', False)]:
            result = inside(client, 'ping', '-c', '1', '-W', '1', destination, check=False)
            if (result.returncode == 0) != expected:
                raise AssertionError(f'Unexpected forwarding result for {destination}: {result.stdout}')
            print(f'PASS: {destination}: {"allowed" if expected else "blocked"}', flush=True)
        # A packet to an unapproved host port must hit the explicit reject rule.
        inside(client, 'python3', '-c',
               "import socket; s=socket.socket(); s.settimeout(1); print(s.connect_ex(('192.168.50.1',22)))")
        table = inside(gateway, 'nft', 'list', 'chain', 'inet', 'netbridge', 'input').stdout
        import re
        if not re.search(r'iifname "wlan0" counter packets [1-9][0-9]* bytes [0-9]+ reject', table):
            raise AssertionError('Host-service rejection rule was not exercised')
        print('PASS: AP access to host SSH hits firewall rejection', flush=True)
        print('PASS: repeated firewall replacement', flush=True)
        # Verify transparent inspection redirect only affects @inspected_v4 and fails open on flush.
        up_http = subprocess.Popen(
            ['ip', 'netns', 'exec', upstream, 'python3', '-c',
             "import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('198.18.0.1', 80)); s.listen(4); "
             "[c.sendall(b'UPSTREAM') or c.close() for c, _ in iter(s.accept, None)]"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        up_app = subprocess.Popen(
            ['ip', 'netns', 'exec', upstream, 'python3', '-c',
             "import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('198.18.0.1', 4444)); s.listen(4); "
             "[c.sendall(b'UPSTREAM_4444') or c.close() for c, _ in iter(s.accept, None)]"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        gw_proxy = subprocess.Popen(
            ['ip', 'netns', 'exec', gateway, 'python3', '-c',
             "import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('0.0.0.0', 8080)); s.listen(4); "
             "[c.sendall(b'PROXY') or c.close() for c, _ in iter(s.accept, None)]"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        gw_portal = subprocess.Popen(
            ['ip', 'netns', 'exec', gateway, 'python3', '-c',
             "import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('192.168.50.1', 80)); s.listen(4); "
             "[c.sendall(b'PORTAL') or c.close() for c, _ in iter(s.accept, None)]"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            import time
            time.sleep(0.3)
            def probe(host, port):
                return inside(client, 'python3', '-c',
                              f"import socket; s=socket.socket(); s.settimeout(2); s.connect(('{host}', {port})); print(s.recv(32).decode())").stdout.strip()
            assert probe('198.18.0.1', 80) == 'UPSTREAM', 'Uninspected client should bypass proxy'
            assert probe('198.18.0.1', 4444) == 'UPSTREAM_4444', 'Uninspected client app port should bypass proxy'
            inside(gateway, 'nft', 'add', 'element', 'inet', 'netbridge', 'inspected_v4', '{ 192.168.50.100 }')
            assert probe('198.18.0.1', 80) == 'PROXY', 'Inspected client should redirect HTTP to :8080'
            assert probe('198.18.0.1', 4444) == 'PROXY', 'Inspected client custom app TCP port should redirect to :8080'
            assert probe('192.168.50.1', 80) == 'PORTAL', 'Gateway portal must not be redirected'
            direct_8080 = inside(client, 'python3', '-c',
                                 "import socket; s=socket.socket(); s.settimeout(1); print(s.connect_ex(('192.168.50.1', 8080)))").stdout.strip()
            assert direct_8080 != '0', f'Direct client connection to :8080 should be rejected, got {direct_8080}'
            quic_probe = inside(client, 'python3', '-c',
                                "import socket, time\ns=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\ns.settimeout(1)\n"
                                "s.connect(('198.18.0.1', 443))\ns.send(b'quic')\ntime.sleep(0.1)\n"
                                "try:\n s.recv(16)\n print('NONE')\nexcept Exception as e:\n print(type(e).__name__)").stdout.strip()
            assert quic_probe == 'ConnectionRefusedError', f'QUIC UDP/443 should be rejected for inspected client, got {quic_probe}'
            inside(gateway, 'nft', 'flush', 'set', 'inet', 'netbridge', 'inspected_v4')
            assert probe('198.18.0.1', 80) == 'UPSTREAM', 'Flushing inspected_v4 must fail open to upstream'
            assert probe('198.18.0.1', 4444) == 'UPSTREAM_4444', 'Flushing inspected_v4 must fail open app port to upstream'
            print('PASS: per-client HTTP + app-TCP redirect, portal exclusion, direct-8080 block, QUIC block, and fail-open flush', flush=True)
        finally:
            for proc in (up_http, up_app, gw_proxy, gw_portal):
                proc.terminate()
                proc.wait(timeout=5)
    finally:
        for ns in reversed(created):
            cmd('ip', 'netns', 'delete', ns, check=False)


if __name__ == '__main__':
    main()
