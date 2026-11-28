#!/usr/bin/env python3
"""Unified NetBridge installer, updater, status checker, and uninstaller."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
try:
    import pwd
except ImportError:
    pwd = None
import re
import shutil
import subprocess
import sys

SOURCE = Path(__file__).resolve().parents[1]
DEST = Path('/usr/local/lib/netbridge')
ETC_DIR = Path('/etc/netbridge')
VAR_DIR = Path('/var/lib/netbridge')
RUN_DIR = Path('/run/netbridge')
SESSION_STATE = Path('/run/netbridge-session-state.json')
SYSTEMD_DIR = Path('/etc/systemd/system')
SUDOERS_FILE = Path('/etc/sudoers.d/netbridge-app')
APPLAUNCH_APPS = Path('/usr/share/APPLaunch/applications')
APPLAUNCH_IMAGES = Path('/usr/share/APPLaunch/share/images')

SYSTEMD_UNITS = (
    'netbridge-ap.service',
    'netbridge-controller.service',
    'netbridge-portal.service',
    'netbridge-proxy.service',
    'netbridge-certificate-renew.service',
    'netbridge-certificate-renew.timer',
)
ACTIVE_MANAGED_SERVICES = ('netbridge-controller', 'netbridge-portal', 'netbridge-proxy')
SERVICE_ACCOUNTS = ('netbridge-portal', 'netbridge-proxy')
SCRIPT_BINARIES = (
    'netbridge-network.py',
    'netbridge-portal.py',
    'netbridge-session.py',
    'netbridge-app.py',
    'netbridge-screen.py',
)
APT_PACKAGES = ('python3-h11', 'python3-cryptography', 'python3-pil', 'python3-venv', 'gcc')
REQUIRED_COMMANDS = ('nmcli', 'nft', 'dnsmasq', 'iw', 'ip', 'systemctl')


def run(*args, check=True, timeout=180, capture=False, cwd=None):
    return subprocess.run(
        args,
        check=check,
        timeout=timeout,
        cwd=str(cwd) if cwd else None,
        text=capture,
        capture_output=capture,
    )


def resolve_user(explicit_user=None):
    candidate = explicit_user or os.environ.get('SUDO_USER') or ''
    if not candidate or candidate == 'root' or not re.fullmatch(r'[a-z_][a-z0-9_-]*', candidate):
        raise SystemExit('Specify a non-root Cardputer user with --user <username> (or run via sudo)')
    if pwd is not None:
        pwd.getpwnam(candidate)
    return candidate


def require_root():
    if os.geteuid() != 0:
        raise SystemExit('Run with sudo (e.g. sudo ./install.sh ...)')


def _missing_python_deps():
    missing = []
    for mod, pkg in (('h11', 'python3-h11'), ('cryptography', 'python3-cryptography'), ('PIL', 'python3-pil')):
        if importlib.util.find_spec(mod) is None:
            missing.append(pkg)
    if not shutil.which('cc'):
        missing.append('gcc')
    return missing


def check_prerequisites(install_apt=False):
    missing_cmds = [cmd for cmd in REQUIRED_COMMANDS if not shutil.which(cmd)]
    if missing_cmds:
        raise SystemExit(f'Missing required system commands: {", ".join(missing_cmds)}')
    if not APPLAUNCH_APPS.is_dir():
        raise SystemExit('Cardputer APPLaunch (/usr/share/APPLaunch/applications) is required')
    missing_pkgs = _missing_python_deps()
    if missing_pkgs:
        if install_apt:
            run('apt-get', 'update', timeout=300)
            run('apt-get', 'install', '-y', *APT_PACKAGES, timeout=600)
            still_missing = _missing_python_deps()
            if still_missing:
                raise SystemExit(f'Dependencies still missing after apt-get: {", ".join(still_missing)}')
        else:
            raise SystemExit(
                f'Missing packages ({", ".join(missing_pkgs)}). '
                f'Install them with: sudo apt-get update && sudo apt-get install -y {" ".join(APT_PACKAGES)} '
                f'(or re-run with --apt)'
            )


def run_tests(source=SOURCE):
    run(sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-v', cwd=source, timeout=300)


def _write_bytes(path, data, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + '.new')
    tmp.write_bytes(data)
    os.chown(tmp, 0, 0)
    tmp.chmod(mode)
    tmp.replace(path)


def _compile_watchdog(source=SOURCE, target=None):
    src = source / 'scripts/netbridge-lease.c'
    out = source / 'scripts/netbridge-lease'
    run('cc', '-O2', '-Wall', '-Wextra', '-Werror', '-o', str(out), str(src), timeout=120)
    _write_bytes(target or (DEST / 'netbridge-lease'), out.read_bytes(), 0o755)


def _validate_python_tree(paths):
    for path in paths:
        compile(path.read_text(encoding='utf-8'), str(path), 'exec')


def _reconcile_mitm_venv(source=SOURCE):
    venv_pip = DEST / 'mitm-venv/bin/pip'
    venv_py = DEST / 'mitm-venv/bin/python3'
    portal_script = source / 'scripts/netbridge-portal.py'
    if not venv_py.is_file() or not venv_pip.is_file() or not portal_script.is_file():
        return
    match = re.search(r"MITMPROXY_VERSION\s*=\s*['\"]([^'\"]+)['\"]", portal_script.read_text())
    if not match:
        return
    desired = match.group(1)
    res = run(
        str(venv_py), '-c',
        'import importlib.metadata; print(importlib.metadata.version("mitmproxy"))',
        check=False, capture=True, timeout=15,
    )
    current = (res.stdout or '').strip() if res.returncode == 0 else ''
    if current != desired:
        run(str(venv_pip), 'install', '--only-binary=:all:', f'mitmproxy=={desired}', timeout=600)


def _copy_if_exists(src, dst):
    if src.is_file():
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)


def _restore_file(src, dst, mode):
    if src.is_file():
        _write_bytes(dst, src.read_bytes(), mode)
    else:
        dst.unlink(missing_ok=True)


def _is_active(unit):
    res = run('systemctl', 'is-active', unit, check=False, capture=True, timeout=15)
    return res.returncode == 0 and (res.stdout or '').strip() == 'active'


def do_install(args):
    require_root()
    user = resolve_user(args.user)
    check_prerequisites(install_apt=args.apt)
    if not args.skip_tests:
        run_tests(SOURCE)
    run(sys.executable, str(SOURCE / 'scripts/netbridge-network.py'), 'install', timeout=180)
    run(sys.executable, str(SOURCE / 'scripts/netbridge-portal.py'), 'install', timeout=900)
    run(sys.executable, str(SOURCE / 'scripts/install-app.py'), '--user', user, timeout=180)
    print('\nNetBridge installation complete.')
    print('Open NetBridge from APPLaunch, connect a test device, and open http://192.168.50.1/ .')


def do_update(args):
    require_root()
    if not (DEST / 'netbridge-network.py').exists() or not (ETC_DIR / 'phase1.toml').exists():
        raise SystemExit('NetBridge is not installed yet. Run: sudo ./install.sh install')
    check_prerequisites(install_apt=args.apt)
    if not args.no_pull and (SOURCE / '.git').exists():
        pull_user = args.user or os.environ.get('SUDO_USER')
        if pull_user and pull_user != 'root' and shutil.which('sudo'):
            run('sudo', '-u', pull_user, 'git', '-C', str(SOURCE), 'pull', '--ff-only', timeout=120)
        else:
            run('git', '-C', str(SOURCE), 'pull', '--ff-only', timeout=120)
    if not args.skip_tests:
        run_tests(SOURCE)

    was_active = [svc for svc in ACTIVE_MANAGED_SERVICES if _is_active(svc)]
    stage_dir = DEST.parent / f'.{DEST.name}.stage'
    backup_dir = DEST.parent / f'.{DEST.name}.backup'
    shutil.rmtree(stage_dir, ignore_errors=True)
    shutil.rmtree(backup_dir, ignore_errors=True)
    stage_dir.mkdir(parents=True, exist_ok=True)
    backup_dir.mkdir(parents=True, exist_ok=True)
    activated = False

    try:
        _compile_watchdog(SOURCE, target=stage_dir / 'netbridge-lease')
        staged_portal = stage_dir / 'portal'
        shutil.copytree(SOURCE / 'portal', staged_portal, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        for path in staged_portal.rglob('*'):
            os.chown(path, 0, 0)
            path.chmod(0o755 if path.is_dir() else 0o644)
        _validate_python_tree(list(staged_portal.rglob('*.py')) + [SOURCE / 'scripts' / name for name in SCRIPT_BINARIES])
        if not (staged_portal / 'server.py').is_file() or not (stage_dir / 'netbridge-lease').is_file():
            raise RuntimeError('Staged update is missing required application files')

        # Back up existing installed files before mutating DEST or systemd.
        portal_dest = DEST / 'portal'
        if portal_dest.exists():
            shutil.copytree(portal_dest, backup_dir / 'portal', ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        _copy_if_exists(DEST / 'netbridge-lease', backup_dir / 'netbridge-lease')
        for name in SCRIPT_BINARIES:
            _copy_if_exists(DEST / name, backup_dir / 'scripts' / name)
        for unit in SYSTEMD_UNITS:
            _copy_if_exists(SYSTEMD_DIR / unit, backup_dir / 'systemd' / unit)
        _copy_if_exists(APPLAUNCH_IMAGES / 'netbridge-icon.png', backup_dir / 'netbridge-icon.png')
        _copy_if_exists(DEST / 'adversaryicu-logo.png', backup_dir / 'adversaryicu-logo.png')
        _copy_if_exists(APPLAUNCH_APPS / 'netbridge.desktop', backup_dir / 'netbridge.desktop')

        _reconcile_mitm_venv(SOURCE)

        # Activate staged update atomically/cleanly (removing obsolete portal files).
        activated = True
        if portal_dest.exists():
            shutil.rmtree(portal_dest)
        shutil.move(str(staged_portal), str(portal_dest))
        _write_bytes(DEST / 'netbridge-lease', (stage_dir / 'netbridge-lease').read_bytes(), 0o755)
        for name in SCRIPT_BINARIES:
            _write_bytes(DEST / name, (SOURCE / 'scripts' / name).read_bytes(), 0o755)
        for unit in SYSTEMD_UNITS:
            _write_bytes(SYSTEMD_DIR / unit, (SOURCE / 'systemd' / unit).read_bytes(), 0o644)
        _write_bytes(APPLAUNCH_IMAGES / 'netbridge-icon.png', (SOURCE / 'assets/netbridge-icon.png').read_bytes(), 0o644)
        _write_bytes(DEST / 'adversaryicu-logo.png', (SOURCE / 'assets/adversaryicu-logo.png').read_bytes(), 0o644)
        _write_bytes(APPLAUNCH_APPS / 'netbridge.desktop', (SOURCE / 'netbridge.desktop').read_bytes(), 0o644)

        run('systemctl', 'daemon-reload', timeout=30)
        for svc in was_active:
            run('systemctl', 'restart', svc, timeout=60)
            if not _is_active(svc):
                raise RuntimeError(f'Service failed to become active after update: {svc}')
    except Exception as exc:
        if activated:
            portal_dest = DEST / 'portal'
            if (backup_dir / 'portal').is_dir():
                shutil.rmtree(portal_dest, ignore_errors=True)
                shutil.copytree(backup_dir / 'portal', portal_dest)
                for path in portal_dest.rglob('*'):
                    os.chown(path, 0, 0)
                    path.chmod(0o755 if path.is_dir() else 0o644)
            _restore_file(backup_dir / 'netbridge-lease', DEST / 'netbridge-lease', 0o755)
            for name in SCRIPT_BINARIES:
                _restore_file(backup_dir / 'scripts' / name, DEST / name, 0o755)
            for unit in SYSTEMD_UNITS:
                _restore_file(backup_dir / 'systemd' / unit, SYSTEMD_DIR / unit, 0o644)
            _restore_file(backup_dir / 'netbridge-icon.png', APPLAUNCH_IMAGES / 'netbridge-icon.png', 0o644)
            _restore_file(backup_dir / 'adversaryicu-logo.png', DEST / 'adversaryicu-logo.png', 0o644)
            _restore_file(backup_dir / 'netbridge.desktop', APPLAUNCH_APPS / 'netbridge.desktop', 0o644)
            run('systemctl', 'daemon-reload', check=False, timeout=30)
            for svc in was_active:
                run('systemctl', 'restart', svc, check=False, timeout=60)
        raise SystemExit(f'NetBridge update failed{" and rolled back to previous version" if activated else ""}: {exc}') from exc
    finally:
        shutil.rmtree(stage_dir, ignore_errors=True)
        shutil.rmtree(backup_dir, ignore_errors=True)

    print('NetBridge updated cleanly; existing config, CA identity, and admin credentials preserved.')
    if was_active:
        print(f'Restarted active services: {", ".join(was_active)}')
    else:
        print('No NetBridge services were active; launch NetBridge from APPLaunch when ready.')


def do_uninstall(args):
    require_root()
    if Path('/run/systemd/transient/netbridge-session.service').exists():
        run('systemctl', 'stop', 'netbridge-session.service', check=False, timeout=45)
    for unit in reversed(SYSTEMD_UNITS):
        run('systemctl', 'disable', '--now', unit, check=False, timeout=45)

    net_script = DEST / 'netbridge-network.py'
    state_file = VAR_DIR / 'phase1.json'
    if net_script.exists() and state_file.exists():
        run(sys.executable, str(net_script), 'rollback', check=False, timeout=60)
        try:
            nm_uuid = json.loads(state_file.read_text()).get('uuid')
            if nm_uuid:
                run('nmcli', 'connection', 'delete', 'uuid', nm_uuid, check=False, timeout=30)
        except (OSError, ValueError):
            pass
    run('nft', 'delete', 'table', 'inet', 'netbridge', check=False, timeout=15)

    for unit in SYSTEMD_UNITS:
        (SYSTEMD_DIR / unit).unlink(missing_ok=True)
    for path in (
        SUDOERS_FILE,
        APPLAUNCH_APPS / 'netbridge.desktop',
        APPLAUNCH_IMAGES / 'netbridge-icon.png',
        SESSION_STATE,
    ):
        path.unlink(missing_ok=True)
    shutil.rmtree(DEST, ignore_errors=True)
    shutil.rmtree(RUN_DIR, ignore_errors=True)
    run('systemctl', 'daemon-reload', check=False, timeout=30)

    if args.purge:
        shutil.rmtree(ETC_DIR, ignore_errors=True)
        shutil.rmtree(VAR_DIR, ignore_errors=True)
        for account in SERVICE_ACCOUNTS:
            run('userdel', account, check=False, timeout=15)
        print('NetBridge completely uninstalled and purged (config, CA identity, and admin data removed).')
    else:
        print('NetBridge uninstalled. CA identity, admin account, and config retained in /etc/netbridge and /var/lib/netbridge.')
        print('Re-run with --purge to remove device identity and configuration.')


def do_status(_args):
    installed = (DEST / 'netbridge-network.py').exists() and (ETC_DIR / 'phase1.toml').exists()
    print(f'Installed: {"yes" if installed else "no"}')
    for unit in ('netbridge-session', *SYSTEMD_UNITS):
        res = run('systemctl', 'is-active', unit, check=False, capture=True, timeout=10)
        state = (res.stdout or '').strip() or 'inactive'
        print(f'  {unit}: {state}')
    ca_meta = VAR_DIR / 'portal-public/ca.json'
    if ca_meta.exists():
        try:
            info = json.loads(ca_meta.read_text())
            print(f'CA: {info.get("name", "?")} ({info.get("fingerprint", "?")})')
        except (OSError, ValueError):
            pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)

    p_install = sub.add_parser('install', help='Install NetBridge on this Cardputer Zero')
    p_install.add_argument('--user', help='Local Cardputer launcher account (defaults to $SUDO_USER)')
    p_install.add_argument('--apt', action='store_true', help='Install missing Debian packages via apt-get')
    p_install.add_argument('--skip-tests', action='store_true', help='Skip unit tests before installing')

    p_update = sub.add_parser('update', help='Pull/apply code updates while preserving config and CA')
    p_update.add_argument('--user', help='Local user for git pull (defaults to $SUDO_USER)')
    p_update.add_argument('--apt', action='store_true', help='Install missing Debian packages via apt-get')
    p_update.add_argument('--no-pull', action='store_true', help='Skip git pull --ff-only')
    p_update.add_argument('--skip-tests', action='store_true', help='Skip unit tests before updating')

    p_uninstall = sub.add_parser('uninstall', help='Remove NetBridge services, launcher entry, and code')
    p_uninstall.add_argument('--purge', action='store_true', help='Also delete CA, admin account, config, and service users')

    sub.add_parser('status', help='Show NetBridge installation and service status')

    args = parser.parse_args()
    if args.action == 'install':
        do_install(args)
    elif args.action == 'update':
        do_update(args)
    elif args.action == 'uninstall':
        do_uninstall(args)
    elif args.action == 'status':
        do_status(args)


if __name__ == '__main__':
    main()
