"""Regression coverage for semantic DNS rescue and non-destructive unknowns."""
import socket
import copy
import datetime
import os
import json
import struct
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace
from contextlib import ExitStack

from test_dns_rescue import normalized
from test_dns_runtime_failopen import FakeFirewall, config
import dns_probe
import dns_evidence
import dns_rescue
import dns_runtime
import pool as pool_mod


CHALLENGE = 'a' * 32
QNAME = CHALLENGE + '.canary.example'
CANDIDATE = {'id': 'cloudflare-proxy', 'operator': 'cloudflare', 'transport': 'proxy'}


def dns_item(name=QNAME, reason='ok', value='192.0.2.53'):
    rcode = {'ok': 0, 'nxdomain': 3, 'nodata': 0, 'wrong_rrset': 0,
             'servfail': 2, 'refused': 5, 'timeout': None, 'runner_error': None}[reason]
    return {'qname': name, 'status': 'PASS' if reason == 'ok' else
            'UNKNOWN' if reason == 'runner_error' else 'FAIL', 'reason': reason,
            'rcode': rcode, 'latency_ms': 20, 'answers': [
                {'owner': name, 'type': 'A', 'value': value, 'ttl': 30}]
            if reason == 'ok' else []}


def v4_report(udp='nxdomain', tcp='ok', app='nxdomain'):
    profile = {
        'dns': {'udp': dns_item(reason=udp), 'tcp': dns_item(reason=tcp)},
        'application_dns': dns_item(reason=app),
        'controls': [{'id': key, 'failure_domain': domain, 'status': 'PASS',
                      'ip_tls': True, 'hostname': True}
                     for key, domain in dns_evidence.CONTROL_DOMAINS.items()],
        'secure': dict(slot=CANDIDATE['id'], operator=CANDIDATE['operator'],
                       transport=CANDIDATE['transport'], dns=dns_item()),
        'sentinels': {'sentinel.example': {
            'dns': {t: dns_item('sentinel.example') for t in ('udp', 'tcp')},
            'application_dns': dns_item('sentinel.example'),
            'secure': {op: dns_item('sentinel.example') for op in ('cloudflare', 'google')}
        }}
    }
    return {'version': 4, 'challenge': CHALLENGE, 'route_generation': 'scope-test',
            'query': {'qname': QNAME, 'type': 'A', 'expected_ipv4': '192.0.2.53'},
            'profiles': {'wg-ip': profile}}


def parse_report(report):
    return dns_evidence.parse_report(
        SimpleNamespace(returncode=0, stdout=json.dumps(report)), challenge=CHALLENGE,
        generation='scope-test', qname=QNAME, expected_ipv4='192.0.2.53',
        profiles=['wg-ip'], mode='causal-round', candidate=CANDIDATE,
        sentinels=['sentinel.example'])


class TestSemanticQuorum(unittest.TestCase):
    def quorum(self, reports):
        return dns_evidence.causal_quorum([parse_report(r) for r in reports], ['wg-ip'])

    def test_udp_nxdomain_tcp_ok_application_failure(self):
        self.assertEqual(self.quorum([v4_report()] * 3)['reason'], 'INTERFERENCE_SUSPECTED')

    def test_timeouts_with_working_controls(self):
        report = v4_report('timeout', 'timeout', 'timeout')
        self.assertEqual(self.quorum([report] * 3)['reason'], 'PRIMARY_DNS_PATH_FAILED')

    def test_two_of_three_including_last_required(self):
        good, bad = v4_report('ok', 'ok', 'ok'), v4_report()
        self.assertEqual(self.quorum([bad, good, bad])['status'], 'PASS')
        for series in ([bad, bad, good], [good, good, bad], [bad, good, good]):
            self.assertEqual(self.quorum(series)['status'], 'UNKNOWN')

    def test_authoritative_sentinel_nxdomain_is_not_interference(self):
        report = v4_report('ok', 'ok', 'ok')
        item = report['profiles']['wg-ip']['sentinels']['sentinel.example']
        item['dns']['udp'] = dns_item('sentinel.example', 'nxdomain')
        item['application_dns'] = dns_item('sentinel.example', 'nxdomain')
        item['secure'] = {op: dns_item('sentinel.example', 'nxdomain')
                          for op in ('cloudflare', 'google')}
        self.assertEqual(self.quorum([report] * 3)['status'], 'UNKNOWN')
        item['secure'] = {op: dns_item('sentinel.example', value='192.0.2.99')
                          for op in ('cloudflare', 'google')}
        self.assertEqual(self.quorum([report] * 3)['status'], 'PASS')

    def test_malformed_and_unknown_evidence_cannot_authorize(self):
        mutations = [
            lambda r: r.update(version=3),
            lambda r: r.update(challenge='b' * 32),
            lambda r: r.update(route_generation='other'),
            lambda r: r['profiles']['wg-ip']['controls'][1].update(failure_domain='cloudflare'),
            lambda r: r['profiles']['wg-ip']['controls'][1].update(ip_tls=False),
            lambda r: r['profiles']['wg-ip']['secure'].update(dns=dns_item(reason='runner_error')),
            lambda r: r['profiles']['wg-ip']['secure']['dns']['answers'].append(
                {'owner': QNAME, 'type': 'A', 'value': '192.0.2.99', 'ttl': 30}),
            lambda r: r['profiles']['wg-ip']['secure']['dns']['answers'][0].update(ttl=31),
            lambda r: r['profiles']['wg-ip']['dns']['udp'].update(rcode=0),
            lambda r: r['profiles']['wg-ip']['application_dns'].update(latency_ms=2001),
            lambda r: r['profiles']['wg-ip']['dns']['udp'].update(qname='wrong.example'),
        ]
        for change in mutations:
            with self.subTest(change=mutations.index(change)):
                report = v4_report()
                change(report)
                self.assertEqual(self.quorum([report] * 3)['status'], 'UNKNOWN')

    def test_profile_inventory_exact_set_required(self):
        report = v4_report()
        report['profiles']['external-ip'] = copy.deepcopy(report['profiles']['wg-ip'])
        self.assertEqual(parse_report(report)['status'], 'UNKNOWN')

    def test_duplicate_keys_rejected(self):
        raw = json.dumps(v4_report()).replace('"version": 4', '"version": 3, "version": 4')
        with mock.patch.object(json, 'dumps', return_value=raw):
            self.assertEqual(parse_report(v4_report())['status'], 'UNKNOWN')

    def test_deep_json_is_unknown(self):
        with mock.patch.object(json, 'dumps', return_value='[' * 5000 + '0' + ']' * 5000):
            self.assertEqual(parse_report({})['status'], 'UNKNOWN')


class Scenario:
    """Deterministic coordinator integration using real SQLite and fake Linux I/O."""
    def __init__(self):
        self.stack = ExitStack()
        self.root = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.pool = pool_mod.Pool(self.root + '/state.db')
        self.stack.callback(self.pool.close)
        self.cfg = normalized('automatic_last_resort', True, True)
        self.cfg['singbox_config'] = self.root + '/main.json'
        with open(self.cfg['singbox_config'], 'w', encoding='utf-8') as handle:
            json.dump({'outbounds': []}, handle)
        self.pool.set_settings({'automat_state': 'EMERGENCY', 'dns_recovery_exhausted': '1',
                                'dns_incident_id': 'incident-test'})
        self.now, self.attached, self.running = 1000.0, False, False
        self.events = []
        self.round_report = v4_report()
        self.primary = {'status': 'PASS', 'ok': True}
        self.client = {'status': 'PASS', 'ok': True}
        self.inventory = {'identity': 'scope-test', 'digest': 'profile-test', 'profiles': ['wg-ip']}
        self.patch(dns_rescue.os, 'name', 'posix')
        self.patch(dns_rescue.time, 'monotonic', lambda: self.now)
        self.patch(dns_rescue.time, 'sleep', self.advance)
        self.patch(dns_rescue.random, 'uniform', lambda *a: 0.0)
        self.patch(dns_rescue, '_boot_id', lambda: 'boot-test')
        self.patch(dns_rescue, '_now', self.stamp)
        self.patch(dns_rescue, '_age', self.age)
        self.patch(dns_rescue, 'probe_backend', lambda *a, **k: {'ok': True, 'status': 'PASS'})
        boundary = {
            'profile_inventory': lambda *a, **k: copy.deepcopy(self.inventory),
            'route_generation': lambda *a, **k: 'route-test',
            'wireguard_scope_ready': lambda *a, **k: True,
            'wireguard_scope_identity': lambda *a, **k: 'scope-test',
            'wireguard_scope_identity_state': lambda *a, **k: {'status': 'valid', 'identity': 'scope-test'},
            'peer_canary_runner_ready': lambda *a, **k: True,
            'emergency_route_ready': lambda *a, **k: True,
            'emergency_route_state': lambda *a, **k: 'ready',
            'firewall_attached': lambda *a, **k: self.attached,
            'redirect_detached': lambda *a, **k: not self.attached,
            'firewall_detached': lambda *a, **k: not self.attached,
            'firewall_effective': lambda *a, **k: self.attached,
            'listener_guard_effective': lambda *a, **k: True,
            'service_state': lambda *a, **k: 'active' if self.running else 'inactive',
            'service_active': lambda *a, **k: self.running,
            'service_inactive': lambda *a, **k: not self.running,
            'service_start': lambda *a, **k: self.service(True),
            'service_stop': lambda *a, **k: self.service(False),
            'activate_firewall': lambda *a, **k: self.nat(True, k.get('scope', 'all')),
            'deactivate_redirect': lambda *a, **k: self.nat(False, k.get('scope', 'all')),
            '_drain_dns_conntrack': lambda cfg, scope, *a, **k: self.events.append('drain:' + scope),
            'stage_config': lambda *a, **k: None,
            'stage_listener_acl': lambda *a, **k: None,
            'remove_listener_acl': lambda *a, **k: self.events.append('remove-acl'),
            'scrub_candidate_sidecar': lambda *a, **k: None,
            'scrub_primary_test_bypass': lambda *a, **k: None,
            'client_candidate_preflight_proven': lambda *a, **k: self.events.append('preflight') or True,
            'candidate_sidecar_preflight_proven': lambda *a, **k: True,
            'client_roundtrip_proven': lambda *a, **k: True,
            'client_roundtrip_result': lambda *a, **k: self.client,
            'client_primary_detached_result': self.detached,
            'client_primary_recovery_proven': self.recovery,
            'causal_round': lambda *a, **k: parse_report(self.round_report),
        }
        for name, value in boundary.items():
            self.patch(dns_runtime, name, value)

    def patch(self, target, name, value):
        return self.stack.enter_context(mock.patch.object(target, name, value))

    def advance(self, seconds):
        self.now += seconds

    def stamp(self):
        return (datetime.datetime(2026, 9, 8) + datetime.timedelta(seconds=self.now)).isoformat()

    def age(self, stamp):
        if not stamp:
            return None
        return (datetime.datetime.fromisoformat(self.stamp()) -
                datetime.datetime.fromisoformat(stamp)).total_seconds()

    def service(self, active):
        self.events.append('start' if active else 'stop')
        self.running = active

    def nat(self, attached, scope):
        self.events.append(('attach:' if attached else 'detach:') + scope)
        self.attached = attached
        return True

    def detached(self, *args, **kwargs):
        self.events.append('primary-detached')
        if self.attached or not self.running:
            raise AssertionError('primary proof must follow detach and precede listener stop')
        return self.primary

    def recovery(self, *args, **kwargs):
        kwargs['evidence_out'].update(self.primary)
        return self.primary['status'] == 'PASS'

    def tick(self, advance=0):
        self.advance(advance)
        return dns_rescue._automatic_tick_locked(self.cfg, self.pool, 'EMERGENCY', False, lambda *a: None)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.stack.close()


class TestStabilityIntegration(unittest.TestCase):
    def test_automatic_activation_and_safe_return_after_hold_down(self):
        with Scenario() as s:
            result = s.tick()
            self.assertTrue(result['ok'], result)
            self.assertLess(s.events.index('preflight'), s.events.index('attach:all'))
            s.tick(60)
            self.assertEqual(s.pool.dns_state()['return_successes'], 0)
            s.tick(240)
            self.assertEqual(s.pool.dns_state()['return_successes'], 1)
            s.tick(60)
            self.assertTrue(s.attached)
            result = s.tick(60)
            self.assertEqual(result['state']['phase'], 'idle')
            self.assertFalse(s.running)
            self.assertFalse(s.pool.unfinished_dns_operations())
            self.assertLess(s.events.index('primary-detached'), len(s.events) - 1)

    def test_post_detach_failure_restores_same_generation(self):
        with Scenario() as s:
            s.tick()
            generation = s.pool.dns_state()['generation']
            s.primary = {'status': 'FAIL', 'ok': False}
            before = len(s.events)
            result = dns_rescue._deactivate_locked(s.cfg, s.pool)
            self.assertEqual(result['action'], 'primary-unproven-rescue-restored')
            self.assertTrue(s.attached and s.running)
            self.assertNotIn('stop', s.events[before:])
            self.assertEqual(s.pool.dns_state()['generation'], generation)
            self.assertFalse(s.pool.unfinished_dns_operations())

    def test_post_detach_unknown_restore_keeps_listener_and_recovers_later(self):
        with Scenario() as s:
            s.tick()
            s.primary = {'status': 'UNKNOWN', 'ok': False}
            with mock.patch.object(dns_runtime, 'service_state', return_value='unknown'):
                result = dns_rescue._deactivate_locked(s.cfg, s.pool)
            self.assertEqual(result['action'], 'detach-restore-unknown')
            self.assertTrue(s.running)
            self.assertEqual(len(s.pool.unfinished_dns_operations()), 1)
            result = dns_rescue._reconcile_locked(s.cfg, s.pool, 'recovery')
            self.assertEqual(result['phase'], 'active_proxy')
            self.assertTrue(s.running and s.attached)
            self.assertFalse(s.pool.unfinished_dns_operations())

    def test_kill_after_stop_finishes_cleanup_instead_of_retrying_dead_listener(self):
        with Scenario() as s:
            s.tick()
            def kill(*args, **kwargs):
                s.service(False)
                raise KeyboardInterrupt()
            with mock.patch.object(dns_runtime, 'service_stop', side_effect=kill):
                with self.assertRaises(KeyboardInterrupt):
                    dns_rescue._deactivate_locked(s.cfg, s.pool)
            self.assertFalse(s.running or s.attached)
            result = dns_rescue._reconcile_locked(s.cfg, s.pool, 'recovery')
            self.assertNotEqual(result['phase'], 'recovering')
            self.assertFalse(s.pool.unfinished_dns_operations())

    def test_unknown_client_never_failovers_and_alerts_after_fifteen_minutes(self):
        with Scenario() as s:
            s.tick()
            generation = s.pool.dns_state()['generation']
            s.client = {'status': 'UNKNOWN', 'ok': False}
            for _ in range(17):
                result = s.tick(60)
                self.assertEqual(result['state']['active_failures'], 0)
                self.assertTrue(s.attached and s.running)
            self.assertEqual(s.pool.dns_state()['generation'], generation)
            self.assertTrue(dns_rescue._stability(s.pool, s.pool.dns_state())['unknown_alerted'])

    def test_two_client_failures_trigger_only_one_failover(self):
        with Scenario() as s:
            s.tick()
            s.client = {'status': 'FAIL', 'ok': False}
            with mock.patch.object(dns_rescue, '_failover_locked', return_value={'ok': False}) as failover:
                s.tick(60)
                failover.assert_not_called()
                s.tick(60)
                failover.assert_called_once()

    def test_unknown_successors_do_not_exhaust_slots_or_detach(self):
        with Scenario() as s:
            s.tick()
            state = s.pool.dns_state()
            with mock.patch.object(dns_runtime, 'candidate_sidecar_preflight_proven', return_value=False):
                for _ in range(8):
                    result = dns_rescue._failover_locked(s.cfg, s.pool, state, False, lambda *a: None)
                    self.assertEqual(result['action'], 'candidate-path-inspection-unknown')
                    self.assertTrue(s.running and s.attached)
                    s.advance(60)
            self.assertEqual(s.pool.tried_dns_activation_slots('incident-test'), {'cloudflare-proxy'})

    def test_recovered_current_is_kept_when_successor_fails(self):
        with Scenario() as s:
            s.tick()
            def reject(*args, **kwargs):
                kwargs['evidence_out']['status'] = 'FAIL'
                return False
            with mock.patch.object(dns_runtime, 'candidate_sidecar_preflight_proven', side_effect=reject):
                result = dns_rescue._failover_locked(s.cfg, s.pool, s.pool.dns_state(), False, lambda *a: None)
            self.assertEqual(result['action'], 'successor-rejected-current-preserved')
            self.assertTrue(s.running and s.attached)
            self.assertEqual(s.pool.dns_state()['active_failures'], 0)

    def test_failed_drain_and_kill_replay_before_stop(self):
        for interruption in (dns_runtime.DNSRuntimeError, KeyboardInterrupt):
            with self.subTest(interruption=interruption.__name__), Scenario() as s:
                s.tick()
                def broken(*args, **kwargs):
                    kwargs['on_detach_plan'](['all'])
                    s.nat(False, kwargs['scope'])
                    raise interruption('injected drain failure')
                with mock.patch.object(dns_runtime, 'deactivate_redirect', side_effect=broken):
                    if interruption is KeyboardInterrupt:
                        with self.assertRaises(KeyboardInterrupt):
                            dns_rescue._deactivate_locked(s.cfg, s.pool, reason='isolated-ttl')
                    else:
                        self.assertFalse(dns_rescue._deactivate_locked(
                            s.cfg, s.pool, reason='isolated-ttl')['ok'])
                self.assertTrue(s.running)
                self.assertTrue(s.pool.unfinished_dns_operations())
                s.events.clear()
                dns_rescue._reconcile_locked(s.cfg, s.pool, 'recovery')
                self.assertIn('drain:all', s.events)
                self.assertLess(s.events.index('drain:all'), s.events.index('stop'))
                self.assertFalse(s.pool.unfinished_dns_operations())

    def test_expired_readiness_blocks_inactive_listener_successor(self):
        with Scenario() as s:
            s.tick()
            s.cfg['dns_rescue']['readiness_not_after'] = '2000-01-01'
            s.running = False
            result = s.tick(5)
            self.assertFalse(result['ok'])
            self.assertFalse(s.running or s.attached)

    def test_manual_retry_replays_earlier_global_drain_and_closes_sagas(self):
        with Scenario() as s:
            s.tick()
            def broken(*args, **kwargs):
                kwargs['on_detach_plan'](['all'])
                s.nat(False, kwargs['scope'])
                raise dns_runtime.DNSRuntimeError('injected drain failure')
            with mock.patch.object(dns_runtime, 'deactivate_redirect', side_effect=broken):
                self.assertFalse(dns_rescue._deactivate_locked(
                    s.cfg, s.pool, reason='isolated-ttl')['ok'])
            s.events.clear()
            result = dns_rescue._deactivate_locked(s.cfg, s.pool, reason='manual')
            self.assertTrue(result['ok'], result)
            self.assertLess(s.events.index('drain:all'), s.events.index('stop'))
            self.assertFalse(s.pool.unfinished_dns_operations())

    def test_manual_retry_with_failed_primary_restores_active_phase_and_closes_old_saga(self):
        with Scenario() as s:
            s.tick()
            def broken(*args, **kwargs):
                s.nat(False, kwargs['scope'])
                raise dns_runtime.DNSRuntimeError('injected drain failure')
            with mock.patch.object(dns_runtime, 'deactivate_redirect', side_effect=broken):
                dns_rescue._deactivate_locked(s.cfg, s.pool, reason='manual')
            s.primary = {'status': 'UNKNOWN', 'ok': False}
            result = dns_rescue._deactivate_locked(s.cfg, s.pool, reason='manual')
            self.assertEqual(result['state']['phase'], 'active_proxy')
            self.assertFalse(s.pool.unfinished_dns_operations())
            dns_rescue._reconcile_locked(s.cfg, s.pool, 'recovery')
            self.assertTrue(s.attached and s.running)

    def test_continuous_primary_unknown_alert_survives_successful_client_checks(self):
        with Scenario() as s:
            s.tick()
            s.primary = {'status': 'UNKNOWN', 'ok': False}
            for _ in range(20):
                s.tick(60)
            stability = dns_rescue._stability(s.pool, s.pool.dns_state())
            self.assertTrue(stability['unknown_alerted'])
            self.assertTrue(s.running and s.attached)

    def test_readiness_expiry_and_inventory_drift_block_cutover(self):
        for kind in ('readiness', 'inventory'):
            with self.subTest(kind=kind), Scenario() as s:
                def preflight(*args, **kwargs):
                    if kind == 'readiness':
                        s.cfg['dns_rescue']['readiness_not_after'] = '2000-01-01'
                    else:
                        s.inventory['digest'] = 'changed'
                    return True
                s.patch(dns_runtime, 'client_candidate_preflight_proven', preflight)
                result = s.tick()
                self.assertFalse(result['ok'])
                self.assertNotIn('attach:all', s.events)

    def test_twenty_simulated_stability_cycles(self):
        for cycle in range(20):
            with self.subTest(cycle=cycle), Scenario() as s:
                group = cycle // 5
                if group == 1:
                    healthy = v4_report('ok', 'ok', 'ok')
                    if cycle % 2:
                        rounds = [v4_report(), healthy, healthy]
                    else:
                        sentinel = healthy['profiles']['wg-ip']['sentinels']['sentinel.example']
                        sentinel['dns'] = {t: dns_item('sentinel.example', 'nxdomain')
                                           for t in ('udp', 'tcp')}
                        sentinel['application_dns'] = dns_item('sentinel.example', 'nxdomain')
                        sentinel['secure'] = {op: dns_item('sentinel.example', 'nxdomain')
                                              for op in ('cloudflare', 'google')}
                        rounds = [healthy] * 3
                    with mock.patch.object(dns_runtime, 'causal_round',
                                           side_effect=[parse_report(r) for r in rounds]):
                        self.assertFalse(s.tick()['ok'])
                    self.assertFalse(s.attached)
                    self.assertFalse(s.running)
                    self.assertTrue(s.pool.dns_state()['attempt_used'])
                    self.assertFalse(s.tick(60)['ok'])
                    self.assertNotIn('attach:all', s.events)
                    self.assertFalse(s.pool.unfinished_dns_operations())
                    continue
                self.assertTrue(s.tick()['ok'])
                generation = s.pool.dns_state()['generation']
                if group == 2:
                    if cycle % 2:
                        s.client = {'status': 'UNKNOWN', 'ok': False}
                        for _ in range(3):
                            s.tick(60)
                            self.assertEqual(s.pool.dns_state()['generation'], generation)
                    else:
                        s.client = {'status': 'FAIL', 'ok': False}
                        s.tick(60)
                        self.assertEqual(s.pool.dns_state()['generation'], generation)
                        result = s.tick(60)
                        self.assertTrue(result['ok'], result)
                        self.assertNotEqual(s.pool.dns_state()['generation'], generation)
                        self.assertEqual(s.pool.dns_state()['active_slot'], 'google-proxy')
                        s.client = {'status': 'PASS', 'ok': True}
                        next_generation = s.pool.dns_state()['generation']
                        s.tick(60)
                        self.assertEqual(s.pool.dns_state()['generation'], next_generation)
                    self.assertTrue(s.running and s.attached)
                if group == 3:
                    s.primary = {'status': 'FAIL', 'ok': False}
                    s.tick(60)
                    self.assertTrue(s.running and s.attached)
                    self.assertFalse(dns_rescue._deactivate_locked(s.cfg, s.pool)['ok'])
                    self.assertTrue(s.running and s.attached)
                    self.assertEqual(s.pool.dns_state()['generation'], generation)
                    s.primary = {'status': 'PASS', 'ok': True}
                    s.tick(239)
                    self.assertEqual(s.pool.dns_state()['return_successes'], 0)
                    for delay in (61, 60):
                        s.tick(delay)
                        self.assertTrue(s.running and s.attached)
                    self.assertEqual(s.tick(60)['state']['phase'], 'idle')
                else:
                    self.assertTrue(dns_rescue._deactivate_locked(s.cfg, s.pool)['ok'])
                self.assertFalse(s.running or s.attached)
                self.assertFalse(s.pool.unfinished_dns_operations())


class TestConfirmedDefects(unittest.TestCase):
    def test_confirmed_socket_refusal_is_fail_but_permission_is_unknown(self):
        for transport in ('udp', 'tcp'):
            for error, expected in ((ConnectionRefusedError(111), 'FAIL'),
                                    (PermissionError(13), 'UNKNOWN')):
                with self.subTest(transport=transport, expected=expected):
                    sock = mock.MagicMock()
                    sock.__enter__.return_value = sock
                    if transport == 'udp':
                        sock.recv.side_effect = error
                    else:
                        sock.connect.side_effect = error
                    with mock.patch.object(dns_probe.socket, 'socket', return_value=sock):
                        result = dns_probe.probe('127.0.0.1', 1053, transport)
                    self.assertEqual(result['status'], expected)

    def packet(self, addresses, ttl=30):
        txid, query = dns_probe._build_query(123, 'test.canary.example')
        records = b''.join(b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, ttl, 4)
                           + socket.inet_aton(ip) for ip in addresses)
        return (struct.pack('!HHHHHH', txid, 0x8180, 1, len(addresses), 0, 0)
                + query[12:] + records)

    def test_expected_plus_foreign_address_is_not_success(self):
        result = dns_probe.parse_response(self.packet(['192.0.2.53', '192.0.2.99']),
                                          123, 'test.canary.example', '192.0.2.53')
        self.assertFalse(result['ok'])

    def test_owned_canary_ttl_over_thirty_is_not_success(self):
        result = dns_probe.parse_response(self.packet(['192.0.2.53'], ttl=31),
                                          123, 'test.canary.example', '192.0.2.53')
        self.assertFalse(result['ok'])

    def test_unknown_does_not_count_or_detach(self):
        with tempfile.TemporaryDirectory() as tmp:
            pool = pool_mod.Pool(tmp + '/state.db')
            try:
                state = pool.set_dns_state(phase='active_proxy', active_failures=2)
                with mock.patch.object(dns_rescue, '_deactivate_locked') as detach:
                    dns_rescue._hold_active_inspection_unknown(normalized(), pool, state, 'runner')
                self.assertEqual(pool.dns_state()['active_failures'], 2)
                detach.assert_not_called()
            finally:
                pool.close()

    def test_isolated_detach_drains_only_exact_peer(self):
        cfg, fw = config(), FakeFirewall()
        with mock.patch.object(dns_runtime, '_cmd', side_effect=lambda c, *a, **k: fw(c)), \
             mock.patch.object(dns_runtime, '_drain_dns_conntrack') as drain:
            dns_runtime.deactivate_redirect(cfg, 'peer:10.77.0.9')
        self.assertEqual(drain.call_args.args[1], 'peer:10.77.0.9')

    def test_backend_uses_one_qname_for_both_transports(self):
        cfg = normalized('manual_canary', True)
        with mock.patch.object(dns_probe, 'probe', return_value={'ok': True}) as probe:
            dns_rescue.probe_backend(cfg, mock.Mock())
        self.assertEqual(probe.call_args_list[0].kwargs['name'],
                         probe.call_args_list[1].kwargs['name'])
