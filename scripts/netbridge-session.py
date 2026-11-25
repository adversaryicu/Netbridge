#!/usr/bin/python3 -I
"""Fixed-command privileged session broker. No caller-controlled root commands."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import ssl
import urllib.request

ROOT = Path('/usr/local/lib/netbridge')
SNAPSHOT = Path('/run/netbridge-session-state.json')
UNITS = ['netbridge-proxy.service', 'netbridge-certificate-renew.timer', 'netbridge-certificate-renew.service',
         'netbridge-portal.service', 'netbridge-controller.service', 'netbridge-ap.service']


def command(*args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=120).stdout.strip()


def network():
    spec = importlib.util.spec_from_file_location('network', ROOT / 'netbridge-network.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def cleanup():
    # Stop the portal before removing the AP; never modify unrelated units.
    command('systemctl', 'stop', *UNITS)
    if SNAPSHOT.exists():
        saved = json.loads(SNAPSHOT.read_text())
        net = network()
        net.stop()  # Confirm AP is down before removing its filter.
        current = command('nmcli', '-g', 'GENERAL.CON-UUID', 'device', 'show', saved['lan'])
        # Respect a connection the user explicitly selected while the app ran.
        if current in ('', '--', saved['uuid']):
            if saved['previous_wifi']:
                command('nmcli', '--wait', '30', 'connection', 'up', 'uuid', saved['previous_wifi'])
            else:
                command('nmcli', 'device', 'disconnect', saved['lan'], check=False)
        SNAPSHOT.unlink()


def serve():
    net = network()
    state = net.load_state()
    previous = command('nmcli', '-g', 'GENERAL.CON-UUID', 'device', 'show', state['lan'])
    if previous == state['uuid']:
        raise RuntimeError('NetBridge AP is already active outside this app session')
    state['previous_wifi'] = previous if previous != '--' else ''
    net.atomic_write(SNAPSHOT, json.dumps(state))
    # Keep the network script's failed-start recovery in sync with this launch.
    net.atomic_write(net.STATE, json.dumps(state))
    config = net.load_config()
    active_reg = net.active_reg_domain(command('iw', 'reg', 'get', check=False))
    if config['ap']['country'] == 'auto' and active_reg == '00':
        print(json.dumps({'prompt': 'country'}), flush=True)
        raw_reply = sys.stdin.readline()
        if not raw_reply:
            raise RuntimeError('Wi-Fi country setup cancelled')
        reply = json.loads(raw_reply)
        net.save_country(reply.get('country', ''))
        config = net.load_config()
    elif config['ap']['country'] != 'auto' and active_reg != config['ap']['country']:
        command('iw', 'reg', 'set', config['ap']['country'], check=False)
    command('systemctl', 'start', 'netbridge-ap.service')
    command('systemctl', 'start', 'netbridge-controller.service', 'netbridge-portal.service',
            'netbridge-certificate-renew.timer')
    gateway = config['lan']['cidr'].split('/')[0]
    context = ssl.create_default_context(cafile='/var/lib/netbridge/portal-public/netbridge-ca.crt')
    deadline = time.monotonic() + 30
    while True:
        try:
            with urllib.request.urlopen('https://' + gateway + '/api/public', context=context, timeout=2) as response:
                if response.status != 200:
                    raise RuntimeError('Portal health check failed')
            break
        except OSError:
            if time.monotonic() >= deadline:
                raise RuntimeError('Portal failed to become ready')
            time.sleep(0.25)
    pairing = ''
    if not Path('/var/lib/netbridge/admin.json').exists():
        pairing = command('/usr/bin/python3', str(ROOT / 'netbridge-portal.py'), 'pairing-code').split(': ')[-1]
    print(json.dumps({'ssid': config['ap']['ssid'], 'password': net.SECRET.read_text().strip(),
                      'url': 'http://' + gateway, 'pairing': pairing}), flush=True)
    # Release Python/TLS startup allocations. The native lease process just waits
    # for heartbeat/EOF; systemd retains the same ExecStopPost crash cleanup.
    os.execv(str(ROOT / 'netbridge-lease'), ['netbridge-lease'])


def main():
    if os.geteuid() != 0:
        raise SystemExit('Use the installed NetBridge application')
    action = sys.argv[1:]
    if not action:
        # sudoers grants ONLY this no-argument entry. systemd owns crash cleanup.
        os.execv('/usr/bin/systemd-run', ['systemd-run', '--quiet', '--pipe', '--wait', '--collect',
            '--unit=netbridge-session', '--property=UMask=0077',
            '--property=TimeoutStopSec=180',
            '--property=ExecStopPost=/usr/bin/python3 -I /usr/local/lib/netbridge/netbridge-session.py cleanup',
            '/usr/bin/python3', '-I', str(ROOT / 'netbridge-session.py'), 'serve'])
    elif action == ['serve']:
        serve()
    elif action == ['cleanup']:
        cleanup()
    else:
        raise SystemExit('Invalid operation')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('NetBridge session: ' + str(error), file=sys.stderr)
        sys.exit(1)
