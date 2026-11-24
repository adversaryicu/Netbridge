"""On-device integration check. Stops/starts only NetBridge. Run as launcher user."""
import json
import os
import select
import signal
import subprocess
import time
import urllib.request


def command(*args):
    return subprocess.run(args, capture_output=True, text=True).stdout.strip()


def launch():
    process = subprocess.Popen(['sudo', '-n', '/usr/local/lib/netbridge/netbridge-session.py'],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    if not select.select([process.stdout], [], [], 100)[0]:
        raise AssertionError('Session did not become ready')
    line = process.stdout.readline()
    if not line:
        raise AssertionError(process.stderr.read().decode())
    data = json.loads(line)
    assert data['ssid'] and data['password'] and data['url']
    with urllib.request.urlopen(data['url'], timeout=5) as response:
        assert response.status == 200
    print('Hotspot and onboarding ready (credentials withheld)', flush=True)
    pid = command('systemctl', 'show', 'netbridge-session', '-p', 'MainPID', '--value')
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        try:
            with open('/proc/' + pid + '/comm') as stream:
                if stream.read().strip() == 'netbridge-lease':
                    break
        except FileNotFoundError:
            pass
        time.sleep(0.1)
    else:
        raise AssertionError('Python startup helper did not release its memory')
    return process


def restored(previous):
    deadline = time.monotonic() + 100
    while time.monotonic() < deadline:
        active = command('systemctl', 'is-active', 'netbridge-session')
        current = command('nmcli', '-g', 'GENERAL.CON-UUID', 'device', 'show', 'wlan0')
        if active not in ('active', 'activating', 'deactivating') and current == previous:
            break
        time.sleep(1)
    else:
        raise AssertionError('Session cleanup or Wi-Fi restoration failed')
    for unit in ('netbridge-ap', 'netbridge-controller', 'netbridge-portal', 'netbridge-proxy', 'netbridge-certificate-renew.timer'):
        assert command('systemctl', 'is-active', unit) != 'active', unit
        assert command('systemctl', 'is-enabled', unit) != 'enabled', unit
    print('All NetBridge units stopped; previous Wi-Fi restored; boot startup disabled', flush=True)


previous = command('nmcli', '-g', 'GENERAL.CON-UUID', 'device', 'show', 'wlan0')
p = launch()
duplicate = subprocess.run(['sudo', '-n', '/usr/local/lib/netbridge/netbridge-session.py'],
                           input=b'', capture_output=True, timeout=10)
assert duplicate.returncode != 0, 'Duplicate instance accepted'
assert command('systemctl', 'is-active', 'netbridge-ap') == 'active'
print('Duplicate launch rejected without disturbing current session', flush=True)
p.stdin.close()
assert p.wait(timeout=160) == 0, p.stderr.read().decode()
restored(previous)
p = launch()
# Simulate an unresponsive UI: no heartbeat is sent.
assert p.wait(timeout=180) == 0, p.stderr.read().decode()
restored(previous)
print('Hung UI lease expires and cleans up', flush=True)
p = launch()
os.killpg(p.pid, signal.SIGKILL)
p.wait(timeout=10)
p.stdin.close()
restored(previous)
print('Force-closed client cleans up; all lifecycle checks passed', flush=True)
