"""No network mutations: validate addressing, isolation, and error recovery."""
import importlib.util
from pathlib import Path
import subprocess
import tomllib
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('network', ROOT / 'scripts/netbridge-network.py')
network = importlib.util.module_from_spec(spec)
spec.loader.exec_module(network)


class NetworkTests(unittest.TestCase):
    def setUp(self):
        self.config = tomllib.loads((ROOT / 'config/phase1.toml').read_text())
        self.state = {'lan': 'wlan0', 'wan': 'eth0', 'uuid': 'test-uuid', 'previous_wifi': 'old-uuid'}

    def test_valid_defaults(self):
        network.validate(self.config)

    def test_firewall_includes_inspection_redirect_and_quic_block(self):
        rules = network.firewall(self.config, self.state)
        self.assertIn('set inspected_v4', rules)
        self.assertIn('chain prerouting', rules)
        self.assertIn('ip saddr @inspected_v4 ip daddr != 192.168.50.1 ip daddr != @protected_v4 tcp dport != 53 counter redirect to :8080', rules)
        self.assertIn('ip saddr @inspected_v4 ct status dnat tcp dport 8080 counter accept', rules)
        self.assertIn('ip saddr @inspected_v4 udp dport 443 counter reject', rules)

    def test_reject_gateway_in_pool(self):
        self.config['lan']['dhcp_start'] = '192.168.50.1'
        with self.assertRaises(ValueError):
            network.validate(self.config)

    def test_reject_outside_pool(self):
        self.config['lan']['dhcp_end'] = '192.168.51.199'
        with self.assertRaises(ValueError):
            network.validate(self.config)

    def test_detect_wan_overlap(self):
        with self.assertRaises(ValueError):
            network.check_conflicts(self.config, [{'dev': 'eth0', 'dst': '192.168.0.0/16'}], 'wlan0')

    def test_own_route_and_default_are_not_conflicts(self):
        network.check_conflicts(self.config, [{'dev': 'wlan0', 'dst': '192.168.50.0/24'},
                                            {'dev': 'eth0', 'dst': 'default'}], 'wlan0')

    def test_reject_keyfile_injection(self):
        self.config['ap']['ssid'] = 'test\n[ipv4]'
        with self.assertRaises(ValueError):
            network.validate(self.config)

    def test_failed_activation_restores_previous_connection(self):
        calls = []
        def run(*args, **kwargs):
            calls.append(args)
            if args == ('ip', '-j', '-4', 'route'):
                return '[]'
            if args[:4] == ('nmcli', '--wait', '40', 'connection'):
                raise RuntimeError('AP activation failed')
            return ''
        with patch.object(network, 'load_config', return_value=self.config), \
             patch.object(network, 'load_state', return_value=self.state), \
             patch.object(network, 'run', side_effect=run):
            with self.assertRaisesRegex(RuntimeError, 'activation failed'):
                network.start()
        self.assertLess(calls.index(('nft', '-f', '-')), calls.index(('nmcli', '--wait', '40', 'connection', 'up', 'uuid', 'test-uuid')))
        self.assertIn(('nmcli', 'connection', 'down', 'uuid', 'test-uuid'), calls)
        self.assertIn(('nmcli', '--wait', '30', 'connection', 'up', 'uuid', 'old-uuid'), calls)

    def test_failed_stop_keeps_firewall(self):
        with patch.object(network, 'load_state', return_value=self.state), \
             patch.object(network, 'run', return_value='test-uuid') as run:
            with self.assertRaisesRegex(RuntimeError, 'retaining firewall'):
                network.stop()
            self.assertFalse(any(c.args[:2] == ('nft', 'delete') for c in run.call_args_list))


if __name__ == '__main__':
    unittest.main()
