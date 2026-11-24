#!/usr/bin/env python3
"""Release all certificate-library memory on completion. Never print key material."""
import argparse
import json
import os
from pathlib import Path
import pwd

import pki


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['prepare', 'rotate'])
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Run as root')
    gateway = json.loads(Path('/etc/netbridge/portal.json').read_text())['gateway']
    account = pwd.getpwnam('netbridge-portal')
    try:
        proxy_gid = pwd.getpwnam('netbridge-proxy').pw_gid
        proxy_dir = Path('/etc/netbridge/proxy-ca')
    except KeyError:
        proxy_gid = None
        proxy_dir = None
    pki.refresh(Path('/var/lib/netbridge/ca'), Path('/var/lib/netbridge/portal-public'),
                Path('/etc/netbridge/portal-tls'), gateway, account.pw_gid, args.action == 'rotate',
                proxy_dir=proxy_dir, proxy_gid=proxy_gid)


if __name__ == '__main__':
    main()
