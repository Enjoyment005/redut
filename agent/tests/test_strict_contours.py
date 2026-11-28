"""Strict contour safety across network reconciliation, restart and rollback."""
import contextlib
import os
from pathlib import Path
import shlex
import unittest
from unittest import mock

import _ctx
import apply
import contours
import dns_policy
from test_contours import LifecycleFixture


class Firewall:
    """Small iptables command recorder with real rule-order semantics."""
    def __init__(self):
        self.commands = []
        self.route_rule = True
        self.chains = {(False, 'mangle', 'REDUT_PREROUTING'): [
            '-m set --match-set ru_whitelist dst -j RETURN',
            '-d 10.77.0.0/24 -j RETURN',
            '-j REDUT_C2', '-j MARK --set-xmark 0x64/0xffffffff']}
        self.sets = {contours.SET: ['10.77.0.2'], contours.SET6: ['2001:db8::2']}

    def run(self, args, allow_failure=False, data=None):
        self.commands.append((list(args), data))
        binary = os.path.basename(args[0])
        if args == ['ip', '-4', 'rule', 'show']:
            return 0, '101: from all fwmark 0x65 lookup 20101\n' if self.route_rule else ''
        if args[:4] == ['ip', '-4', 'rule', 'del']:
            self.route_rule = False
            return 0, ''
        if args[:2] == ['ipset', 'save']:
            name = args[2]
            family = 'inet6' if name == contours.SET6 else 'inet'
            return 0, 'create %s hash:ip family %s\n' % (name, family) + ''.join(
                'add %s %s\n' % (name, address) for address in self.sets.get(name, []))
        if binary in ('iptables-restore', 'ip6tables-restore'):
            ipv6 = binary.startswith('ip6')
            table = data.splitlines()[0][1:]
            for line in data.splitlines()[1:]:
                if line.startswith('-F '):
                    self.chains[(ipv6, table, line.split()[1])] = []
                elif line.startswith('-A '):
                    _, chain, rule = line.split(' ', 2)
                    self.chains.setdefault((ipv6, table, chain), []).append(rule)
            return 0, ''
        if binary in ('iptables', 'ip6tables'):
            ipv6 = binary == 'ip6tables'
            table = args[args.index('-t') + 1] if '-t' in args else 'filter'
            for command in ('-S', '-C', '-I', '-D', '-F', '-X'):
                if command not in args:
                    continue
                i = args.index(command)
                chain = args[i + 1]
                key = (ipv6, table, chain)
                if command == '-S' and key not in self.chains:
                    return 1, ''
                rules = self.chains.setdefault(key, [])
                rest = args[i + 2:]
                if command == '-S':
                    return 0, ''.join('-A %s %s\n' % (chain, rule) for rule in rules)
                if command == '-C':
                    return (0 if ' '.join(rest) in rules else 1), ''
                if command == '-I':
                    rules.insert(int(rest[0]) - 1, ' '.join(rest[1:]))
                elif command == '-D':
                    if len(rest) == 1 and rest[0].isdigit():
                        rules.pop(int(rest[0]) - 1)
                    elif ' '.join(rest) in rules:
                        rules.remove(' '.join(rest))
                elif command == '-F':
                    rules.clear()
                elif command == '-X':
                    self.chains.pop(key, None)
                return 0, ''
        return 0, ''

    def rules(self, table, chain):
        return self.chains.get((False, table, chain), [])

    def input_result(self, source, interface, port):
        for rule in self.rules('filter', 'REDUT_C2_DNS_ACL'):
            parts = shlex.split(rule)
            if '--dport' not in parts or parts[parts.index('--dport') + 1] != str(port):
                continue
            if '-p' in parts and parts[parts.index('-p') + 1] != 'tcp':
                continue
            if '-i' in parts and parts[parts.index('-i') + 1] != interface:
                continue
            if '--match-set' in parts and source not in self.sets.get(contours.SET, []):
                continue
            return parts[parts.index('-j') + 1]
        return None


class StrictContourTests(LifecycleFixture):
    def setUp(self):
        super().setUp()
        self.create()
        self.child = contours.config(self.cfg)
        live = apply.load_json(self.child['singbox_config'])
        live['outbounds'] = [{'type': 'vless', 'tag': 'socks-out', 'server': '192.0.2.33'}]
        apply.dump_json_replace(live, self.child['singbox_config'])
        self.firewall = Firewall()

    def runtime(self, strict=True, carrier=True, peers=True):
        stack = contextlib.ExitStack()
        stack.enter_context(mock.patch.object(contours, '_run', side_effect=self.firewall.run))
        stack.enter_context(mock.patch.object(contours, '_ipset_swap', side_effect=lambda name, values, family: self.firewall.sets.__setitem__(name, list(values))))
        stack.enter_context(mock.patch.object(contours, 'peer_addresses', return_value=(
            ['10.77.0.2'] if peers else [], ['2001:db8::2'] if peers else [], {'peer'})))
        stack.enter_context(mock.patch.object(dns_policy, 'strict', return_value=strict, create=True))
        stack.enter_context(mock.patch.object(dns_policy, 'STRICT_PROXY_PORT', 10802, create=True))
        stack.enter_context(mock.patch.object(dns_policy, 'reconcile'))
        stack.enter_context(mock.patch.object(dns_policy, 'boot_guard'))
        stack.enter_context(mock.patch.object(dns_policy, 'whitelist_text', return_value=''))
        original_exists = os.path.exists
        stack.enter_context(mock.patch.object(os.path, 'exists', side_effect=lambda path:
            carrier if path == '/sys/class/net/' + contours.TUN else original_exists(path)))
        return stack

    def test_stale_emergency_never_opens_wan_or_direct_dns(self):
        Path(self.child['emergency_intent']).write_text('direct\n')
        with self.runtime():
            contours.reconcile_network(self.cfg)
        commands = [args for args, _ in self.firewall.commands]
        self.assertFalse(any(args[:4] == ['ip', 'route', 'replace', 'default'] and 'via' in args for args in commands))
        self.assertIn(['ip', 'route', 'replace', 'default', 'dev', contours.TUN, 'metric', '100', 'table', contours.TABLE], commands)
        dns = Path(contours.paths(self.cfg)['dnsmasq']).read_text()
        self.assertIn('server=127.0.0.1#5355\n', dns)
        self.assertNotIn('server=1.1.1.1', dns)
        guard = self.firewall.rules('filter', 'REDUT_C2_GUARD')
        self.assertEqual(guard, ['-i wg0 -m set --match-set redut_c2_peers src ! -o tun-redut-c2 -j REJECT'])
        self.assertEqual(self.firewall.rules('mangle', 'REDUT_PREROUTING')[0], '-j REDUT_C2')
        first_guard = next(i for i, (_, data) in enumerate(self.firewall.commands) if data and ':REDUT_C2_GUARD ' in data)
        first_route = next(i for i, (args, _) in enumerate(self.firewall.commands) if args[:2] == ['ip', 'route'])
        self.assertLess(first_guard, first_route)

    def test_missing_tunnel_stays_unreachable(self):
        Path(self.child['emergency_intent']).write_text('direct\n')
        with self.runtime(carrier=False):
            contours.reconcile_network(self.cfg)
        commands = [args for args, _ in self.firewall.commands]
        self.assertIn(['ip', 'route', 'replace', 'unreachable', 'default', 'metric', '32760', 'table', contours.TABLE], commands)
        self.assertIn(['ip', 'route', 'del', 'default', 'metric', '100', 'table', contours.TABLE], commands)
        self.assertFalse(any(args[:4] == ['ip', 'route', 'replace', 'default'] for args in commands))

    def test_legacy_mode_restores_ru_bypass_after_strict(self):
        with self.runtime():
            contours.reconcile_network(self.cfg)
        with self.runtime(strict=False):
            contours.reconcile_network(self.cfg)
        rules = self.firewall.rules('mangle', 'REDUT_PREROUTING')
        self.assertEqual(rules.count('-j REDUT_C2'), 1)
        self.assertGreater(rules.index('-j REDUT_C2'), rules.index('-m set --match-set ru_whitelist dst -j RETURN'))
        self.assertLess(rules.index('-j REDUT_C2'), rules.index('-j MARK --set-xmark 0x64/0xffffffff'))
        self.assertTrue(any('ru_whitelist dst -j RETURN' in rule for rule in self.firewall.rules('filter', 'REDUT_C2_GUARD')))
        self.assertEqual(self.firewall.input_result('10.77.0.2', 'wg0', 10802), 'REJECT')

    def test_emergency_is_rejected_before_intent_or_network_changes(self):
        with self.runtime(), mock.patch.object(contours, 'reconcile_network') as network:
            self.assertFalse(contours.emergency(self.child, True, log=lambda message: None))
        network.assert_not_called()
        self.assertFalse(Path(self.child['emergency_intent']).exists())
        self.assertFalse(Path(self.child['emergency_flag']).exists())

    def test_strict_proxy_is_accessible_only_to_second_contour_over_wg(self):
        with self.runtime():
            contours.reconcile_network(self.cfg)
        self.assertEqual(self.firewall.input_result('10.77.0.2', 'wg0', 10802), 'ACCEPT')
        self.assertEqual(self.firewall.input_result('10.77.0.3', 'wg0', 10802), 'REJECT')
        self.assertEqual(self.firewall.input_result('10.77.0.2', 'eth0', 10802), 'REJECT')
        self.assertEqual(self.firewall.input_result('192.0.2.1', 'eth0', 10802), 'REJECT')
        self.assertEqual(self.firewall.input_result('127.0.0.1', 'lo', 10802), 'REJECT')

    def test_transition_guard_blocks_every_forward_and_proxy_before_publish(self):
        before = Path(self.child['singbox_config']).read_bytes()
        with self.runtime(strict=False):
            contours.strict_transition_guard(self.child)
        self.assertEqual(Path(self.child['singbox_config']).read_bytes(), before)
        self.assertEqual(self.firewall.rules('filter', 'REDUT_C2_GUARD'), ['-i wg0 -m set --match-set redut_c2_peers src -j REJECT'])
        self.assertEqual(self.firewall.rules('filter', 'FORWARD')[0], '-j REDUT_C2_GUARD')
        self.assertEqual(self.firewall.input_result('10.77.0.2', 'wg0', 10802), 'REJECT')
        with self.runtime():
            contours.reconcile_network(self.cfg)
        self.assertEqual(self.firewall.input_result('10.77.0.2', 'wg0', 10802), 'ACCEPT')
        self.assertIn('! -o tun-redut-c2', self.firewall.rules('filter', 'REDUT_C2_GUARD')[0])

    def test_transition_guard_rejects_primary(self):
        with self.assertRaises(contours.ContourError):
            contours.strict_transition_guard(self.cfg)
        self.assertFalse(self.firewall.commands)

    def test_boot_guard_proof_requires_proxy_acl_and_final_deny(self):
        with self.runtime():
            contours.boot_guard(self.cfg)
            self.assertTrue(contours.boot_guard_proven(self.cfg))
            self.firewall.rules('filter', 'REDUT_C2_DNS_ACL').remove('-p tcp --dport 10802 -j REJECT')
            self.assertFalse(contours.boot_guard_proven(self.cfg))

    def test_empty_contour_still_requires_closed_proxy_listener(self):
        with self.runtime(peers=False):
            contours.boot_guard(self.cfg)
            self.assertTrue(contours.boot_guard_proven(self.cfg))
            self.firewall.rules('filter', 'REDUT_C2_DNS_ACL').clear()
            self.assertFalse(contours.boot_guard_proven(self.cfg))

    def test_delete_removes_dns_and_proxy_acl(self):
        with self.runtime():
            contours.reconcile_network(self.cfg)
            contours.delete(self.cfg)
        self.assertNotIn((False, 'filter', 'REDUT_C2_DNS_ACL'), self.firewall.chains)
        self.assertNotIn('-j REDUT_C2_DNS_ACL', self.firewall.rules('filter', 'INPUT'))


class HookPlacementTests(unittest.TestCase):
    def test_reorders_and_deduplicates_without_unprotected_interval(self):
        for original in (['-j ACCEPT', '-j REDUT_C2', '-j RETURN'],
                         ['-j REDUT_C2', '-j RETURN', '-j REDUT_C2'],
                         ['-j RETURN', '-j REDUT_C2', '-j REDUT_C2']):
            for position in (1, 2, 3):
                with self.subTest(original=original, position=position):
                    kernel = Firewall()
                    kernel.chains[(False, 'mangle', 'PARENT')] = list(original)
                    with mock.patch.object(contours, '_run', side_effect=kernel.run):
                        contours._place_hook('mangle', 'PARENT', 'REDUT_C2', position)
                        result = kernel.rules('mangle', 'PARENT')
                        self.assertEqual(result.count('-j REDUT_C2'), 1)
                        self.assertEqual(result.index('-j REDUT_C2'), min(position - 1, len(result) - 1))
                        mutations = [args for args, _ in kernel.commands if '-I' in args or '-D' in args]
                        if mutations:
                            self.assertIn('-I', mutations[0])
                        before = len(mutations)
                        contours._place_hook('mangle', 'PARENT', 'REDUT_C2', position)
                        self.assertEqual(len([args for args, _ in kernel.commands if '-I' in args or '-D' in args]), before)


if __name__ == '__main__':
    unittest.main()
