#!/usr/bin/python3
"""One-time application integration; modifies only NetBridge-owned resources."""
import argparse
import os
from pathlib import Path
import pwd
import re
import subprocess

SOURCE = Path(__file__).resolve().parents[1]
DEST = Path('/usr/local/lib/netbridge')


def run(*args):
    subprocess.run(args, check=True, timeout=180)


def write(path, data, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    os.chown(path, 0, 0)
    path.chmod(mode)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--user', required=True, help='Local Cardputer launcher account')
    args = parser.parse_args()
    if os.geteuid() != 0 or not re.fullmatch('[a-z_][a-z0-9_-]*', args.user):
        parser.error('Run as root with a valid local username')
    pwd.getpwnam(args.user)
    from PIL import ImageFont
    ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf', 14)
    if not Path('/usr/share/APPLaunch/applications').is_dir():
        raise SystemExit('Cardputer APPLaunch is required')
    binary = SOURCE / 'scripts/netbridge-lease'
    run('cc', '-O2', '-Wall', '-Wextra', '-Werror', '-o', str(binary),
        str(SOURCE / 'scripts/netbridge-lease.c'))
    run('systemctl', 'stop', 'netbridge-session.service') if Path('/run/systemd/transient/netbridge-session.service').exists() else None
    write(DEST / 'netbridge-lease', binary.read_bytes(), 0o755)
    # Stop old prototype services before changing to launch-only operation.
    run('systemctl', 'stop', 'netbridge-certificate-renew.service')
    run('systemctl', 'disable', '--now', 'netbridge-certificate-renew.timer',
        'netbridge-portal.service', 'netbridge-controller.service', 'netbridge-ap.service')
    run('/usr/bin/python3', str(DEST / 'netbridge-network.py'), 'rollback')
    for name in ('netbridge-session.py', 'netbridge-app.py', 'netbridge-screen.py'):
        write(DEST / name, (SOURCE / 'scripts' / name).read_bytes(), 0o755)
    # Empty quoted argument list in sudoers permits no arguments, not arbitrary arguments.
    policy = f'{args.user} ALL=(root) NOPASSWD: /usr/local/lib/netbridge/netbridge-session.py ""\n'
    candidate = Path('/etc/sudoers.d/netbridge-app.new')
    write(candidate, policy.encode(), 0o440)
    try:
        run('/usr/sbin/visudo', '-cf', str(candidate))
        candidate.replace('/etc/sudoers.d/netbridge-app')
    finally:
        candidate.unlink(missing_ok=True)
    write(Path('/usr/share/APPLaunch/share/images/netbridge-icon.png'),
          (SOURCE / 'assets/netbridge-icon.png').read_bytes(), 0o644)
    write(Path('/usr/share/APPLaunch/applications/netbridge.desktop'),
          (SOURCE / 'netbridge.desktop').read_bytes(), 0o644)
    print('NetBridge installed in APPLaunch; no NetBridge boot services enabled.')


if __name__ == '__main__':
    main()
