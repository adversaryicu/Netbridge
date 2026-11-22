#!/usr/bin/env python3
"""Install, pair, inspect or disable the local portal without changing routing."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import secrets
import shutil
import subprocess
import sys
import time
import tomllib

SOURCE = Path(__file__).resolve().parents[1]
INSTALL = Path('/usr/local/lib/netbridge/portal')
BASE = Path('/var/lib/netbridge')


def run(*args):
    subprocess.run(args, check=True, timeout=90)


def module():
    sys.path.insert(0, str(INSTALL if INSTALL.exists() else SOURCE / 'portal'))
    import pki
    return pki


def pairing():
    if (BASE / 'admin.json').exists():
        raise SystemExit('Administrator already configured. Pairing cannot replace an existing account.')
    code = secrets.token_urlsafe(9)
    module().write(BASE / 'pairing.json', json.dumps({'hash': hashlib.sha256(code.encode()).hexdigest(), 'expires': time.time() + 900}))
    print('One-time pairing code (expires in 15 minutes): ' + code)


def install():
    import h11
    import cryptography
    config = tomllib.loads(Path('/etc/netbridge/phase1.toml').read_text())
    gateway = str(ipaddress.ip_interface(config['lan']['cidr']).ip)
    try:
        account = pwd.getpwnam('netbridge-portal')
    except KeyError:
        run('useradd', '--system', '--user-group', '--no-create-home', '--home-dir', '/nonexistent', '--shell', '/usr/sbin/nologin', 'netbridge-portal')
        account = pwd.getpwnam('netbridge-portal')
    if account.pw_shell != '/usr/sbin/nologin':
        raise SystemExit('Existing netbridge-portal account is not a dedicated service account')
    INSTALL.mkdir(parents=True, exist_ok=True)
    shutil.copytree(SOURCE / 'portal', INSTALL, dirs_exist_ok=True, ignore=shutil.ignore_patterns('__pycache__'))
    for path in INSTALL.rglob('*'):
        os.chmod(path, 0o755 if path.is_dir() else 0o644)
    pki = module()
    pki.refresh(BASE / 'ca', BASE / 'portal-public', Path('/etc/netbridge/portal-tls'), gateway, account.pw_gid)
    pki.write('/etc/netbridge/portal.json', json.dumps({'gateway': gateway}), 0o644)
    for filename in ('netbridge-controller.service', 'netbridge-portal.service', 'netbridge-certificate-renew.service', 'netbridge-certificate-renew.timer'):
        pki.write(Path('/etc/systemd/system') / filename, (SOURCE / 'systemd' / filename).read_bytes(), 0o644)
    pki.write('/usr/local/lib/netbridge/netbridge-portal.py', Path(__file__).read_bytes(), 0o755)
    run('systemctl', 'daemon-reload')
    print('Portal installed without boot startup. Open NetBridge to start it. CA identity retained.')
    print('Onboarding: http://' + gateway + '/  Administration: https://' + gateway + '/admin')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['install', 'pairing-code', 'fingerprint', 'disable', 'renew'])
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Run with sudo')
    if args.action == 'install':
        install()
    elif args.action == 'pairing-code':
        pairing()
    elif args.action == 'fingerprint':
        print((BASE / 'portal-public/ca.json').read_text())
    elif args.action == 'renew':
        gateway = json.loads(Path('/etc/netbridge/portal.json').read_text())['gateway']
        account = pwd.getpwnam('netbridge-portal')
        if module().refresh(BASE / 'ca', BASE / 'portal-public', Path('/etc/netbridge/portal-tls'), gateway, account.pw_gid):
            run('systemctl', 'restart', 'netbridge-portal')
            print('Renewed portal leaf certificate; CA identity unchanged.')
    else:
        run('systemctl', 'disable', '--now', 'netbridge-certificate-renew.timer')
        run('systemctl', 'disable', '--now', 'netbridge-portal', 'netbridge-controller')
        print('Portal and controller stopped. CA/admin data retained; Internet sharing is unchanged.')


if __name__ == '__main__':
    main()
