#!/usr/bin/env python3
"""Measure real services after bounded requests; never discard caches or swap."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import ssl
import subprocess
import time
import urllib.error
import urllib.request


def snapshot():
    result = {}
    for name in ('netbridge-controller', 'netbridge-portal'):
        pid = subprocess.check_output(['systemctl', 'show', name, '-p', 'MainPID', '--value'], text=True).strip()
        data = {}
        for line in Path('/proc/' + pid + '/smaps_rollup').read_text().splitlines():
            label = line.split(':')[0]
            if label in ('Rss', 'Pss', 'SwapPss'):
                data[label + '_KiB'] = int(line.split()[1])
        result[name] = data
    result['combined_Pss_MiB'] = round(sum(v['Pss_KiB'] for v in result.values()) / 1024, 2)
    result['combined_Pss_plus_SwapPss_MiB'] = round(sum(v['Pss_KiB'] + v['SwapPss_KiB'] for v in result.values() if isinstance(v, dict)) / 1024, 2)
    return result


def main():
    gateway = json.loads(Path('/etc/netbridge/portal.json').read_text())['gateway']
    context = ssl.create_default_context(cafile='/var/lib/netbridge/portal-public/netbridge-ca.crt')
    before = snapshot()
    def visit(index):
        path = ('/', '/api/public', '/admin')[index % 3]
        with urllib.request.urlopen('https://' + gateway + path, context=context, timeout=10) as response:
            response.read()
            return response.status
    with ThreadPoolExecutor(max_workers=3) as executor:
        statuses = list(executor.map(visit, range(36)))
    # Exercise unchanged scrypt strength once without requesting real credentials.
    request = urllib.request.Request('https://' + gateway + '/api/login',
        data=json.dumps({'password':'not-the-real-password-memory-probe'}).encode(),
        headers={'Content-Type':'application/json','Origin':'https://' + gateway}, method='POST')
    try:
        urllib.request.urlopen(request, context=context, timeout=15)
        login_status = 200
    except urllib.error.HTTPError as error:
        login_status = error.code
    baseline = json.loads(Path('/var/lib/netbridge/code-backup-pre-memory/baseline.json').read_text())
    unchanged = {
        'ca':baseline['ca'] == json.loads(Path('/var/lib/netbridge/portal-public/ca.json').read_text())['fingerprint'],
        'administrator':baseline['admin_digest'] == hashlib.sha256(Path('/var/lib/netbridge/admin.json').read_bytes()).hexdigest(),
    }
    after_requests = snapshot()
    time.sleep(3)
    result = {'measured_at_utc':datetime.now(timezone.utc).isoformat(), 'before':before,
              'after_https_and_password_check':after_requests, 'settled_after_3_seconds':snapshot(),
              'successful_https_requests':statuses.count(200),
              'incorrect_password_status':login_status, 'identity_unchanged':unchanged}
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
