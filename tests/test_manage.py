"""Tests for scripts/netbridge-manage.py (cross-platform with mocked system calls)."""
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('netbridge_manage', ROOT / 'scripts/netbridge-manage.py')
manage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manage)


class ManageTests(unittest.TestCase):
    def test_resolve_user_validation(self):
        with patch.object(manage, 'pwd', SimpleNamespace(getpwnam=lambda u: None)):
            self.assertEqual('digan', manage.resolve_user('digan'))
            with patch.dict(os.environ, {'SUDO_USER': 'digan'}):
                self.assertEqual('digan', manage.resolve_user(None))
            for bad in ('', 'root', 'bad user', '../etc'):
                with self.assertRaises(SystemExit):
                    manage.resolve_user(bad)

    def test_uninstall_retains_identity_by_default_and_purges_with_flag(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            dest = base / 'usr_local_lib'
            etc_dir = base / 'etc_netbridge'
            var_dir = base / 'var_lib_netbridge'
            run_dir = base / 'run_netbridge'
            sysd = base / 'systemd'
            sudoers = base / 'sudoers_netbridge'
            apps = base / 'apps'
            imgs = base / 'imgs'
            sess = base / 'session_state.json'

            for d in (dest, etc_dir, var_dir, run_dir, sysd, apps, imgs):
                d.mkdir(parents=True)
            (dest / 'netbridge-network.py').write_text('# stub')
            (var_dir / 'phase1.json').write_text(json.dumps({'uuid': 'ap-uuid-1'}))
            (etc_dir / 'phase1.toml').write_text('schema_version = 1\n')
            (sysd / 'netbridge-proxy.service').write_text('[Unit]\n')
            sudoers.write_text('digan ALL=...\n')
            (apps / 'netbridge.desktop').write_text('[Desktop Entry]\n')
            (imgs / 'netbridge-icon.png').write_bytes(b'PNG')
            sess.write_text('{}')

            calls = []
            def fake_run(*args, **kwargs):
                calls.append(args)
                return SimpleNamespace(returncode=0, stdout='')

            with patch.object(manage, 'require_root'), \
                 patch.object(manage, 'DEST', dest), \
                 patch.object(manage, 'ETC_DIR', etc_dir), \
                 patch.object(manage, 'VAR_DIR', var_dir), \
                 patch.object(manage, 'RUN_DIR', run_dir), \
                 patch.object(manage, 'SYSTEMD_DIR', sysd), \
                 patch.object(manage, 'SUDOERS_FILE', sudoers), \
                 patch.object(manage, 'APPLAUNCH_APPS', apps), \
                 patch.object(manage, 'APPLAUNCH_IMAGES', imgs), \
                 patch.object(manage, 'SESSION_STATE', sess), \
                 patch.object(manage, 'run', side_effect=fake_run):
                manage.do_uninstall(SimpleNamespace(purge=False))

            self.assertFalse(dest.exists())
            self.assertFalse(sudoers.exists())
            self.assertFalse((apps / 'netbridge.desktop').exists())
            self.assertFalse((sysd / 'netbridge-proxy.service').exists())
            # Retained without --purge
            self.assertTrue((etc_dir / 'phase1.toml').exists())
            self.assertTrue((var_dir / 'phase1.json').exists())
            self.assertIn(('nmcli', 'connection', 'delete', 'uuid', 'ap-uuid-1'), calls)
            self.assertFalse(any(c[0] == 'userdel' for c in calls))

            # Now test --purge
            calls.clear()
            dest.mkdir(parents=True)
            with patch.object(manage, 'require_root'), \
                 patch.object(manage, 'DEST', dest), \
                 patch.object(manage, 'ETC_DIR', etc_dir), \
                 patch.object(manage, 'VAR_DIR', var_dir), \
                 patch.object(manage, 'RUN_DIR', run_dir), \
                 patch.object(manage, 'SYSTEMD_DIR', sysd), \
                 patch.object(manage, 'SUDOERS_FILE', sudoers), \
                 patch.object(manage, 'APPLAUNCH_APPS', apps), \
                 patch.object(manage, 'APPLAUNCH_IMAGES', imgs), \
                 patch.object(manage, 'SESSION_STATE', sess), \
                 patch.object(manage, 'run', side_effect=fake_run):
                manage.do_uninstall(SimpleNamespace(purge=True))

            self.assertFalse(etc_dir.exists())
            self.assertFalse(var_dir.exists())
            self.assertIn(('userdel', 'netbridge-portal'), calls)
            self.assertIn(('userdel', 'netbridge-proxy'), calls)

    def test_update_preserves_config_and_restarts_only_active_services(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            dest = base / 'usr_local_lib'
            etc_dir = base / 'etc_netbridge'
            sysd = base / 'systemd'
            apps = base / 'apps'
            imgs = base / 'imgs'
            for d in (dest, etc_dir, sysd, apps, imgs):
                d.mkdir(parents=True)
            (dest / 'netbridge-network.py').write_text('# old')
            (etc_dir / 'phase1.toml').write_text('custom = true\n')

            calls = []
            def fake_run(*args, **kwargs):
                calls.append(args)
                return SimpleNamespace(returncode=0, stdout='')

            with patch.object(manage, 'require_root'), \
                 patch.object(manage, 'check_prerequisites'), \
                 patch.object(manage, 'DEST', dest), \
                 patch.object(manage, 'ETC_DIR', etc_dir), \
                 patch.object(manage, 'SYSTEMD_DIR', sysd), \
                 patch.object(manage, 'APPLAUNCH_APPS', apps), \
                 patch.object(manage, 'APPLAUNCH_IMAGES', imgs), \
                 patch.object(manage, '_compile_watchdog'), \
                 patch.object(manage, '_is_active', side_effect=lambda s: s == 'netbridge-portal'), \
                 patch.object(manage, 'run', side_effect=fake_run), \
                 patch.object(os, 'chown', lambda *a: None, create=True):
                manage.do_update(SimpleNamespace(user='digan', apt=False, no_pull=True, skip_tests=True))

            self.assertEqual('custom = true\n', (etc_dir / 'phase1.toml').read_text())
            self.assertTrue((dest / 'portal/proxy_addon.py').exists())
            self.assertTrue((sysd / 'netbridge-proxy.service').exists())
            self.assertIn(('systemctl', 'daemon-reload'), calls)
            self.assertIn(('systemctl', 'restart', 'netbridge-portal'), calls)
            self.assertNotIn(('systemctl', 'restart', 'netbridge-controller'), calls)


if __name__ == '__main__':
    unittest.main()
