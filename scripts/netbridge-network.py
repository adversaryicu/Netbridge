#!/usr/bin/env python3
"""Phase 1 only: NetworkManager AP, protected routing, and explicit rollback."""
import argparse
import getpass
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tomllib
import uuid

CONFIG = Path('/etc/netbridge/phase1.toml')
STATE = Path('/var/lib/netbridge/phase1.json')
SECRET = Path('/etc/netbridge/ap-passphrase')
PROFILE = Path('/etc/NetworkManager/system-connections/netbridge-ap.nmconnection')
UNIT = Path('/etc/systemd/system/netbridge-ap.service')
SELF = Path('/usr/local/lib/netbridge/netbridge-network.py')


def run(*args, check=True, data=None):
    result = subprocess.run(args, input=data, text=True, capture_output=True, timeout=90)
    if check and result.returncode:
        # Never include command arguments: a future caller might pass a secret.
        raise RuntimeError(f'{args[0]} failed: {result.stderr.strip()}')
    return result.stdout.strip()


def atomic_write(path, content, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + '.new')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'w') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def validate(config):
    if config['schema_version'] != 1:
        raise ValueError('Unsupported configuration schema')
    ap, lan = config['ap'], config['lan']
    if not re.fullmatch(r'[A-Za-z0-9 _.-]{1,32}', ap['ssid']):
        raise ValueError('SSID must be 1-32 simple ASCII characters')
    if ap['country'] != 'US' or ap['channel'] not in range(1, 12):
        raise ValueError('Phase 1 currently validates US channels 1-11 only')
    if type(ap['client_isolation']) is not bool:
        raise ValueError('client_isolation must be boolean')
    address = ipaddress.IPv4Interface(lan['cidr'])
    if address.network.prefixlen != 24 or address.ip in (address.network.network_address, address.network.broadcast_address):
        raise ValueError('Phase 1 requires a valid gateway in a /24 subnet')
    first, last = map(ipaddress.IPv4Address, (lan['dhcp_start'], lan['dhcp_end']))
    if not (address.network.network_address < first <= last < address.network.broadcast_address):
        raise ValueError('Invalid DHCP range')
    if first <= address.ip <= last:
        raise ValueError('DHCP range contains the gateway')
    if not 120 <= lan['lease_seconds'] <= 3600:
        raise ValueError('DHCP lease must be 120-3600 seconds')
    for interface in config['network'].values():
        if interface and not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', interface):
            raise ValueError('Invalid interface name')
    return config


def load_config():
    return validate(tomllib.loads(CONFIG.read_text()))


def load_state():
    return json.loads(STATE.read_text())


def check_conflicts(config, routes, lan_interface):
    subnet = ipaddress.IPv4Interface(config['lan']['cidr']).network
    for route in routes:
        if route.get('dst') == 'default' or route.get('dev') == lan_interface:
            continue
        dest = route.get('dst')
        if dest and subnet.overlaps(ipaddress.IPv4Network(dest, strict=False)):
            raise ValueError(f'LAN subnet conflicts with route {dest}')


def firewall(config, state):
    lan, wan = state['lan'], state['wan']
    interface = ipaddress.IPv4Interface(config['lan']['cidr'])
    gateway = str(interface.ip)
    subnet = str(interface.network)
    return f'''add table inet netbridge
flush table inet netbridge
table inet netbridge {{
  set protected_v4 {{
    type ipv4_addr; flags interval;
    elements = {{ 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8,
      169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 }}
  }}
  set inspected_v4 {{
    type ipv4_addr;
  }}
  chain prerouting {{
    type nat hook prerouting priority dstnat; policy accept;
    iifname "{lan}" ip saddr @inspected_v4 ip daddr != {gateway} ip daddr != @protected_v4 tcp dport != 53 counter redirect to :8080
  }}
  chain input {{
    type filter hook input priority -10; policy accept;
    iifname "{wan}" tcp dport 8080 counter drop
    iifname "{lan}" meta nfproto ipv6 counter drop
    iifname "{lan}" udp sport 68 udp dport 67 counter accept
    iifname "{lan}" ip saddr != {subnet} counter drop
    iifname "{lan}" udp dport 53 counter accept
    iifname "{lan}" tcp dport {{ 53, 80, 443 }} counter accept
    iifname "{lan}" ip saddr @inspected_v4 ct status dnat tcp dport 8080 counter accept
    iifname "{lan}" icmp type echo-request limit rate 10/second counter accept
    iifname "{lan}" counter reject
  }}
  chain forward {{
    type filter hook forward priority -10; policy accept;
    iifname "{lan}" meta nfproto ipv6 counter drop
    oifname "{lan}" meta nfproto ipv6 counter drop
    iifname "{lan}" ip saddr != {subnet} counter drop
    iifname "{lan}" ip daddr @protected_v4 counter reject
    iifname "{lan}" ip saddr @inspected_v4 udp dport 443 counter reject
    iifname "{lan}" oifname "{wan}" ct state {{ new, established, related }} counter accept
    iifname "{lan}" counter reject
    iifname "{wan}" oifname "{lan}" ct state {{ established, related }} counter accept
    oifname "{lan}" counter reject
  }}
}}
'''


def profile(config, state, password):
    ap, lan = config['ap'], config['lan']
    return f'''[connection]
id=netbridge-ap
uuid={state['uuid']}
type=wifi
interface-name={state['lan']}
autoconnect=false

[wifi]
mode=ap
ssid={ap['ssid']}
band=bg
channel={ap['channel']}
ap-isolation={int(ap['client_isolation'])}
powersave=2

[wifi-security]
key-mgmt=wpa-psk
proto=rsn;
pairwise=ccmp;
group=ccmp;
psk={password}

[ipv4]
method=shared
address1={lan['cidr']}
shared-dhcp-range={lan['dhcp_start']},{lan['dhcp_end']}
shared-dhcp-lease-time={lan['lease_seconds']}
never-default=true

[ipv6]
method=disabled
'''


def install(source):
    for command in ('nmcli', 'nft', 'dnsmasq', 'iw', 'ip', 'systemctl'):
        if not shutil.which(command):
            raise RuntimeError(f'Missing prerequisite: {command}')
    config = validate(tomllib.loads((source / 'config/phase1.toml').read_text()))
    devices = [line.split(':') for line in run('nmcli', '-t', '-f', 'DEVICE,TYPE,STATE', 'device').splitlines()]
    lan_candidates = [d[0] for d in devices if d[1] == 'wifi']
    wan_candidates = [d[0] for d in devices if d[1] == 'ethernet' and d[2] == 'connected']
    lan = config['network']['lan_interface']
    wan = config['network']['wan_interface']
    if not lan and len(lan_candidates) == 1:
        lan = lan_candidates[0]
    if not wan and len(wan_candidates) == 1:
        wan = wan_candidates[0]
    if lan not in lan_candidates or wan not in wan_candidates or lan == wan:
        raise RuntimeError('Select one Wi-Fi LAN and one connected Ethernet WAN explicitly')
    if 'country US:' not in run('iw', 'reg', 'get'):
        raise RuntimeError('Expected existing US regulatory domain; configure the correct country first')
    routes = json.loads(run('ip', '-j', '-4', 'route'))
    check_conflicts(config, routes, lan)
    if not any(r.get('dst') == 'default' and r.get('dev') == wan for r in routes):
        raise RuntimeError('Ethernet must have a default route before installation')
    # Fail before modifying files if this NM version lacks required properties.
    previous = run('nmcli', '-g', 'GENERAL.CON-UUID', 'device', 'show', lan)
    if previous and previous != '--':
        run('nmcli', '-g', 'ipv4.shared-dhcp-range,802-11-wireless.ap-isolation', 'connection', 'show', previous)
    if STATE.exists():
        state = load_state()
        if (state['lan'], state['wan']) != (lan, wan):
            raise RuntimeError('Interface change requires rollback and reinstallation')
    else:
        if PROFILE.exists() or UNIT.exists() or run('nft', 'list', 'table', 'inet', 'netbridge', check=False):
            raise RuntimeError('Existing NetBridge resources have no ownership state; refusing overwrite')
        state = {'schema_version': 1, 'uuid': str(uuid.uuid4()), 'lan': lan, 'wan': wan,
                 'previous_wifi': previous if previous != '--' else ''}
    run('nft', '--check', '-f', '-', data=firewall(config, state))
    atomic_write(STATE, json.dumps(state, indent=2) + '\n')
    atomic_write(CONFIG, (source / 'config/phase1.toml').read_text())
    if not SECRET.exists():
        atomic_write(SECRET, secrets.token_urlsafe(18) + '\n')
    atomic_write(PROFILE, profile(config, state, SECRET.read_text().strip()))
    atomic_write(SELF, Path(__file__).read_text(), 0o755)
    atomic_write(UNIT, (source / 'systemd/netbridge-ap.service').read_text(), 0o644)
    run('nmcli', 'connection', 'load', str(PROFILE))
    run('systemctl', 'daemon-reload')
    print('Installed. Hotspot is not started or enabled automatically by install.')


def start():
    config, state = load_config(), load_state()
    check_conflicts(config, json.loads(run('ip', '-j', '-4', 'route')), state['lan'])
    # Apply the protective filter BEFORE making the AP available.
    run('nft', '-f', '-', data=firewall(config, state))
    try:
        run('nmcli', '--wait', '40', 'connection', 'up', 'uuid', state['uuid'])
    except Exception:
        # The profile may have partially activated; take it down before cleanup.
        run('nmcli', 'connection', 'down', 'uuid', state['uuid'], check=False)
        restore_previous(state)
        raise
    print('AP started; inspection OFF. Firewall protects AP clients and upstream private networks.')


def stop():
    state = load_state()
    active = run('nmcli', '-g', 'GENERAL.CON-UUID', 'device', 'show', state['lan'])
    if active == state['uuid']:
        run('nmcli', '--wait', '20', 'connection', 'down', 'uuid', state['uuid'])
    # Confirm AP is down before removing its protection. Never flush unrelated rules.
    if run('nmcli', '-g', 'GENERAL.CON-UUID', 'device', 'show', state['lan']) == state['uuid']:
        raise RuntimeError('AP still active; retaining firewall')
    run('nft', 'delete', 'table', 'inet', 'netbridge', check=False)


def restore_previous(state):
    if state['previous_wifi']:
        run('nmcli', '--wait', '30', 'connection', 'up', 'uuid', state['previous_wifi'], check=False)


def rollback():
    state = load_state()
    run('systemctl', 'disable', '--now', 'netbridge-ap.service')
    stop()
    restore_previous(state)
    print('Hotspot disabled; previous Wi-Fi activation requested. Ethernet unchanged.')
    print('Installed files retained for inspection or restart. Use uninstall to remove them.')


def uninstall():
    rollback()
    state = load_state()
    run('nmcli', 'connection', 'delete', 'uuid', state['uuid'])
    for path in (PROFILE, UNIT, SELF, SECRET, CONFIG, STATE):
        path.unlink(missing_ok=True)
    run('systemctl', 'daemon-reload')
    print('Removed only the known NetBridge Phase 1 files and profile.')


def status():
    state = load_state()
    for args in [('ip', '-br', 'address'), ('ip', 'route'),
                 ('nmcli', '-t', '-f', 'DEVICE,TYPE,STATE', 'device'),
                 ('systemctl', 'is-active', 'netbridge-ap.service'),
                 ('nft', 'list', 'table', 'inet', 'netbridge'),
                 ('iw', 'dev', state['lan'], 'station', 'dump')]:
        print(run(*args, check=False))
    print('Inspection: OFF (not installed in Phase 1)')


def password():
    new = getpass.getpass('New AP password: ')
    if not (8 <= len(new) <= 63 and re.fullmatch(r'[A-Za-z0-9!@#$%&*+.,_=-]+', new)):
        raise ValueError('Use 8-63 ASCII letters, numbers or common punctuation; no spaces')
    config, state = load_config(), load_state()
    old_secret, old_profile = SECRET.read_text(), PROFILE.read_text()
    was_active = run('systemctl', 'is-active', 'netbridge-ap', check=False) == 'active'
    try:
        atomic_write(SECRET, new + '\n')
        atomic_write(PROFILE, profile(config, state, new))
        run('nmcli', 'connection', 'load', str(PROFILE))
        if was_active:
            run('systemctl', 'restart', 'netbridge-ap')
    except Exception:
        atomic_write(SECRET, old_secret)
        atomic_write(PROFILE, old_profile)
        run('nmcli', 'connection', 'load', str(PROFILE), check=False)
        if was_active:
            run('systemctl', 'restart', 'netbridge-ap', check=False)
        raise
    print('AP password changed. Reconnect clients using the new password.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['install', 'start', 'stop', 'rollback', 'uninstall', 'status', 'credentials', 'password'])
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run with sudo')
    if args.action == 'install':
        install(args.source)
    elif args.action == 'credentials':
        print(f"SSID: {load_config()['ap']['ssid']}\nPassword: {SECRET.read_text().strip()}")
    else:
        globals()[args.action]()


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f'NetBridge: {error}', file=sys.stderr)
        sys.exit(1)
