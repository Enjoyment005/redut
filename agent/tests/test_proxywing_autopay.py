"""Service-scoped auto-renew safety, using SQLite and a simulated provider only."""
import copy
import datetime
import importlib
import importlib.util
import json
import os
import tempfile
import unittest
from unittest import mock

import _ctx
import apply
import pool
from providers import base, proxywing
from providers.base import ProviderError


class ServiceAPI(proxywing.ProxyWing):
    """Real adapter with an in-memory GET/PUT boundary; never contacts an account."""
    min_interval = 0

    def __init__(self):
        super().__init__('YOUR_ACCOUNT_KEY')
        self.orders = [{'id': 'ord_1', 'service_id': 'svc_1', 'proxies': [{'id': 'ip_1'}]}]
        self.services = [{'id': 'svc_1', 'product': '1 Proxy DC UK', 'family': 'Proxy UK',
                          'status': 'active', 'billing_cycle': 'monthly',
                          'next_due_date': '2099-01-01'}]
        self.other_orders = []
        self.enabled = {'svc_1': False}
        self.calls = []
        self.get_hook = None
        self.put_hook = None

    def _api(self, path):
        self.calls.append(('GET', path))
        if self.get_hook:
            self.get_hook(path)
        if path == '/datacenter/proxies':
            return {'orders': copy.deepcopy(self.orders)}
        if path == '/isp/proxies':
            return {'orders': copy.deepcopy(self.other_orders)}
        if path == '/account/services':
            return {'services': copy.deepcopy(self.services)}
        service = path.split('/')[-2]
        return {'service_id': service, 'enabled': self.enabled[service]}

    def put(self, url, body, **kwargs):
        service = url.split('/')[-2]
        self.calls.append(('PUT', service, body['enabled']))
        if self.put_hook:
            self.put_hook(service, body['enabled'])
        self.enabled[service] = body['enabled']
        return {'service_id': service, 'enabled': body['enabled']}


class AutopayCase(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='proxywing-autopay-')
        self.addCleanup(temporary.cleanup)
        self.directory = temporary.name
        self.pool = pool.Pool(os.path.join(temporary.name, 'state.db'))
        self.addCleanup(self.pool.close)
        self.provider = ServiceAPI()
        self.cfg = {'singbox_config': os.path.join(temporary.name, 'singbox.json'),
                    'lock': os.path.join(temporary.name, 'network.lock'),
                    'auto_prolong': {'enabled': True, 'proxywing_months': 1,
                                     'proxywing_provider_auto_renew': True}}
        self.row = {'provider': 'proxywing', 'ext_id': 'datacenter|ord_1|ip_1',
                    'host': '192.0.2.1', 'ip': '192.0.2.1', 'port_socks5': 1080,
                    'port_http': 8080, 'user': 'dummy-user', 'password': 'YOUR_PROXY_PASSWORD',
                    'country': 'de', 'ip_version': 4, 'kind': 'dedicated',
                    'date_end': '2099-12-31'}
        self.uid = self.pool.upsert_proxy(self.row)
        self.pool.conn.execute('UPDATE proxy SET probe_ok=1')
        self.pool.conn.commit()
        self.switch(self.row)
        def direct(req, host_label, timeout, follow_redirects=True):
            self.assertEqual(req.get_method(), 'PUT')
            self.assertFalse(follow_redirects)
            return self.provider.put(req.full_url, json.loads(req.data))
        for target, replacement in [('_urlopen_json', direct),
                                    ('preferred_transport', lambda: 'direct')]:
            patcher = mock.patch.object(base, target, replacement)
            patcher.start()
            self.addCleanup(patcher.stop)

    def switch(self, row, kind='socks'):
        apply.dump_json_replace({'outbounds': [apply.build_outbound(kind, 'socks-out',
            row['host'], row['port_socks5'] if kind == 'socks' else row['port_http'],
            row['user'], row['password'])]}, self.cfg['singbox_config'])

    def module(self):
        self.assertIsNotNone(importlib.util.find_spec('proxywing_autopay'),
                             'service-scoped auto-renew domain module is missing')
        return importlib.import_module('proxywing_autopay')

    def reconcile(self):
        return self.module().reconcile(self.cfg, {'proxywing': self.provider}, self.pool,
                                       log=lambda *args: None)

    def test_enable_requires_exact_opt_in_monthly_healthy_unambiguous_current(self):
        original = copy.deepcopy(self.cfg)
        cases = [('flag', False), ('flag', 'true'), ('flag', 1), ('flag', None),
                 ('global', False), ('months', 3), ('months', True), ('safe', True),
                 ('health', 0), ('health', None), ('wrong-user', 'other'),
                 ('wrong-password', 'other'), ('wrong-port', 999), ('wrong-type', 'direct'),
                 ('ambiguous', True), ('other-provider', True)]
        for kind, value in cases:
            with self.subTest(gate=kind, value=value):
                self.cfg = copy.deepcopy(original)
                self.switch(self.row)
                self.pool.conn.execute('UPDATE proxy SET probe_ok=1')
                self.pool.conn.commit()
                if kind == 'flag':
                    if value is None:
                        self.cfg['auto_prolong'].pop('proxywing_provider_auto_renew')
                    else:
                        self.cfg['auto_prolong']['proxywing_provider_auto_renew'] = value
                elif kind == 'global':
                    self.cfg['auto_prolong']['enabled'] = value
                elif kind == 'months':
                    self.cfg['auto_prolong']['proxywing_months'] = value
                elif kind == 'safe':
                    self.cfg['_config_meta'] = {'safe_mode': value}
                elif kind == 'health':
                    self.pool.conn.execute('UPDATE proxy SET probe_ok=?', (value,))
                    self.pool.conn.commit()
                else:
                    sb = apply.load_json(self.cfg['singbox_config'])
                    field = {'wrong-user': 'username', 'wrong-password': 'password',
                             'wrong-port': 'server_port', 'wrong-type': 'type'}.get(kind)
                    if field:
                        sb['outbounds'][0][field] = value
                    elif kind == 'ambiguous':
                        sb['outbounds'].append(dict(sb['outbounds'][0]))
                    else:
                        sb['outbounds'][0]['server'] = '192.0.2.99'
                    apply.dump_json_replace(sb, self.cfg['singbox_config'])
                result = self.reconcile()
                self.assertFalse([c for c in self.provider.calls if c[0] == 'PUT'], result)
                self.assertFalse(self.provider.enabled['svc_1'])
                self.assertEqual(self.module().status(self.pool)['owned'], [])

    def add_second(self):
        second = dict(self.row, ext_id='datacenter|ord_2|ip_2', port_socks5=2080)
        self.pool.upsert_proxy(second)
        self.pool.conn.execute('UPDATE proxy SET probe_ok=1')
        self.pool.conn.commit()
        self.provider.orders.append({'id': 'ord_2', 'service_id': 'svc_2', 'proxies': [{'id': 'ip_2'}]})
        self.provider.services.append(dict(self.provider.services[0], id='svc_2'))
        self.provider.enabled['svc_2'] = False
        return second

    def test_overdue_warning_uses_actor_and_never_claims_paid_success(self):
        self.provider.services[0]['next_due_date'] = '2020-01-01'
        messages = []
        result = self.module().reconcile(self.cfg, {'proxywing': self.provider}, self.pool,
                                         log=messages.append, actor='cron')
        self.assertTrue(result['ok'])
        self.assertTrue(result.get('payment_pending'))
        self.assertTrue(messages)
        self.assertIn('не оплачивает', messages[-1])
        warnings = [e for e in self.pool.events() if e['result'] == 'payment-pending']
        self.assertEqual(len(warnings), 1)
        self.assertEqual(warnings[0]['actor'], 'cron')
        self.assertFalse([e for e in self.pool.events() if e['result'] == 'paid'])

    def test_real_locks_are_held_in_correct_order_and_locked_entry_does_not_reacquire(self):
        import money
        module = self.module()
        def check_locks(path):
            with self.assertRaises(apply.ApplyError):
                with apply.Flock(self.cfg['lock']):
                    pass
            with self.assertRaises(money.SpendDenied):
                with money._spend_lock(self.pool):
                    pass
        self.provider.get_hook = check_locks
        self.assertTrue(self.reconcile()['ok'])
        with apply.Flock(self.cfg['lock']):
            result = module.release_owned(self.cfg, {'proxywing': self.provider}, self.pool,
                                          log=lambda *args: None, _locked=True)
        self.assertTrue(result['ok'], result)
        self.provider.calls.clear()
        with apply.Flock(self.cfg['lock']):
            result = self.reconcile()
        self.assertFalse(result['ok'])
        self.assertFalse(self.provider.calls)

    def test_multi_proxy_scope_denial_reports_order_and_explains_no_standby_payment(self):
        self.provider.orders[0]['proxies'].append({'id': 'standby_ip'})
        result = self.reconcile()
        self.assertFalse(result['ok'])
        self.assertEqual(result.get('order_id'), 'ord_1')
        self.assertEqual(result.get('reason_code'), 'scope-denied')
        self.assertIn('одним', result.get('reason', ''))
        self.assertFalse([c for c in self.provider.calls if c[0] == 'PUT'])

    def test_unconfirmed_disable_intent_for_same_current_is_not_silently_reowned(self):
        module = self.module()
        self.assertTrue(self.reconcile()['ok'])
        with mock.patch.object(proxywing, 'http_put_json', return_value={'service_id': 'svc_1', 'enabled': False}):
            released = module.release_owned(self.cfg, {'proxywing': self.provider}, self.pool,
                                            log=lambda *args: None)
            self.assertFalse(released['ok'])
            self.assertEqual(module.status(self.pool)['owned'][0]['phase'], 'disabling')
            result = self.reconcile()
        self.assertFalse(result['ok'], result)
        self.assertEqual(module.status(self.pool)['owned'][0]['phase'], 'disabling')

    def test_credential_rotation_during_mapping_does_not_query_old_service_in_new_account(self):
        self.assertTrue(self.reconcile()['ok'])
        def rotate(path):
            if path == '/account/services':
                self.provider.api_key = 'YOUR_ROTATED_ACCOUNT'
        self.provider.get_hook = rotate
        self.provider.calls.clear()
        result = self.reconcile()
        self.assertFalse(result['ok'], result)
        self.assertFalse([c for c in self.provider.calls if c[1].endswith('/auto-renew')])
        self.assertFalse([c for c in self.provider.calls if c[0] == 'PUT'])

    def test_invalid_current_service_scope_still_releases_our_previous_switch(self):
        self.assertTrue(self.reconcile()['ok'])
        self.provider.orders[0]['proxies'].append({'id': 'unneeded_ip'})
        self.provider.calls.clear()
        result = self.reconcile()
        self.assertFalse(result['ok'], result)
        self.assertFalse(self.provider.enabled['svc_1'])
        self.assertEqual([c for c in self.provider.calls if c[0] == 'PUT'], [('PUT', 'svc_1', False)])
        self.assertEqual(self.module().status(self.pool)['owned'], [])

    def test_new_multi_proxy_membership_during_get_blocks_enable(self):
        def broaden_service(path):
            if path.endswith('/auto-renew'):
                self.provider.orders[0]['proxies'].append({'id': 'unneeded_ip'})
        self.provider.get_hook = broaden_service
        result = self.reconcile()
        self.assertFalse(result['ok'], result)
        self.assertFalse([c for c in self.provider.calls if c[0] == 'PUT'])

    def test_failed_submit_journal_cannot_leave_false_ownership_of_foreign_switch(self):
        module = self.module()
        original = self.pool.set_setting
        writes = 0
        def fail_boundary(key, value):
            nonlocal writes
            writes += 1
            if writes == 3:
                raise OSError('journal unavailable before HTTP')
            return original(key, value)
        with mock.patch.object(self.pool, 'set_setting', side_effect=fail_boundary):
            result = self.reconcile()
        self.assertFalse(result['ok'])
        self.assertFalse([c for c in self.provider.calls if c[0] == 'PUT'])
        self.provider.enabled['svc_1'] = True
        result = module.release_owned(self.cfg, {'proxywing': self.provider}, self.pool,
                                      log=lambda *args: None)
        self.assertTrue(result['ok'], result)
        self.assertTrue(self.provider.enabled['svc_1'], 'foreign switch must not be disabled')

    def test_credential_change_during_get_never_mutates_new_account(self):
        for operation in ('enable', 'cleanup'):
            with self.subTest(operation=operation):
                self.provider.api_key = 'YOUR_ACCOUNT_KEY'
                self.provider.get_hook = None
                if operation == 'cleanup':
                    self.assertTrue(self.reconcile()['ok'])
                def rotate(path):
                    if path.endswith('/auto-renew'):
                        self.provider.api_key = 'YOUR_ROTATED_ACCOUNT_KEY'
                self.provider.get_hook = rotate
                self.provider.calls.clear()
                if operation == 'enable':
                    result = self.reconcile()
                else:
                    result = self.module().release_owned(self.cfg, {'proxywing': self.provider}, self.pool,
                                                         log=lambda *args: None)
                self.assertFalse(result['ok'], result)
                self.assertFalse([c for c in self.provider.calls if c[0] == 'PUT'])

    def test_safe_mode_and_unreadable_current_disable_only_our_owned_service(self):
        for gate in ('safe_mode', 'invalid-current', 'global-off', 'mode-off', 'unhealthy'):
            with self.subTest(gate=gate):
                self.cfg['auto_prolong']['enabled'] = True
                self.cfg['auto_prolong']['proxywing_provider_auto_renew'] = True
                self.cfg.pop('_config_meta', None)
                self.pool.conn.execute('UPDATE proxy SET probe_ok=1')
                self.pool.conn.commit()
                self.switch(self.row)
                self.assertTrue(self.reconcile()['ok'])
                self.provider.enabled['foreign'] = True
                if gate == 'safe_mode':
                    self.cfg['_config_meta'] = {'safe_mode': True}
                elif gate == 'invalid-current':
                    os.unlink(self.cfg['singbox_config'])
                elif gate == 'global-off':
                    self.cfg['auto_prolong']['enabled'] = False
                elif gate == 'mode-off':
                    self.cfg['auto_prolong']['proxywing_provider_auto_renew'] = False
                else:
                    self.pool.conn.execute('UPDATE proxy SET probe_ok=0')
                    self.pool.conn.commit()
                self.provider.calls.clear()
                result = self.reconcile()
                self.assertTrue(result['ok'], result)
                self.assertFalse(self.provider.enabled['svc_1'])
                self.assertTrue(self.provider.enabled['foreign'])
                self.assertEqual([c for c in self.provider.calls if c[0] == 'PUT'], [('PUT', 'svc_1', False)])

    def test_status_never_echoes_untrusted_journal_reasons(self):
        module = self.module()
        self.assertTrue(self.reconcile()['ok'])
        state = json.loads(self.pool.get_setting(module.STATE_KEY))
        state['last']['reason'] = 'private-credential-material'
        self.pool.set_setting(module.STATE_KEY, json.dumps(state))
        summary = module.status(self.pool)
        self.assertNotIn('private-credential-material', json.dumps(summary))
        self.provider.calls.clear()
        self.assertFalse(self.reconcile()['ok'])
        self.assertFalse(self.provider.calls)

    def test_order_single_proxy_must_be_the_actual_current_proxy_id(self):
        self.provider.orders[0]['proxies'] = [{'id': 'another_ip'}]
        result = self.reconcile()
        self.assertFalse(result['ok'], result)
        self.assertFalse([c for c in self.provider.calls if c[0] == 'PUT'])

    def test_provider_due_date_advancement_is_observed_never_fabricated_as_payment(self):
        past = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)).date().isoformat()
        future = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=31)).date().isoformat()
        self.provider.services[0]['next_due_date'] = past
        result = self.reconcile()
        self.assertTrue(result['ok'], result)
        self.assertTrue(result.get('payment_pending'))
        self.assertEqual(result.get('next_due_date'), past)
        self.assertIn('не оплачивает', result.get('reason', ''))
        self.provider.services[0]['next_due_date'] = future
        result = self.reconcile()
        self.assertFalse(result.get('payment_pending'))
        self.assertEqual(result.get('next_due_date'), future)
        self.reconcile()
        events = [e for e in self.pool.events() if e['action'] == 'proxywing-auto-renew-observed']
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['result'], 'due-date-advanced')
        self.assertNotIn('paid', events[0]['detail'])
        self.assertNotIn('credential_identity', json.dumps(events))
        self.assertEqual(self.pool.conn.execute('SELECT COUNT(*) FROM money').fetchone()[0], 0)
        self.assertFalse(self.pool.pending_spend_operations())
        self.assertEqual(self.pool.get(self.uid)['date_end'], '2099-12-31')

    def test_interrupted_before_submit_cannot_adopt_or_disable_a_foreign_enable(self):
        module = self.module()
        with mock.patch.object(self.provider, 'set_auto_renew', side_effect=SystemExit('before HTTP')):
            with self.assertRaises(SystemExit):
                self.reconcile()
        self.provider.enabled['svc_1'] = True  # Enabled externally while the process was down.
        result = self.reconcile()
        self.assertEqual(result.get('ownership'), 'external-enabled')
        self.assertEqual(module.status(self.pool)['owned'], [])
        self.provider.calls.clear()
        released = module.release_owned(self.cfg, {'proxywing': self.provider}, self.pool,
                                        log=lambda *args: None)
        self.assertTrue(released['ok'])
        self.assertTrue(self.provider.enabled['svc_1'])
        self.assertFalse(self.provider.calls)

    def test_outstanding_same_account_or_unknown_spend_blocks_enable(self):
        for request, phase in [({'credential_identity': self.module()._credential(self.provider)}, 'planned'),
                               ({}, 'submitted'), ({}, 'committed'), ({}, 'unknown')]:
            with self.subTest(phase=phase):
                self.pool.conn.execute('DELETE FROM spend_operation')
                self.pool.conn.commit()
                op, _ = self.pool.begin_spend_operation('prolong', 'proxywing', request,
                    'autopay-test-' + phase, quote_price=3, currency='USD', balance_before=100)
                self.pool.conn.execute('UPDATE spend_operation SET phase=? WHERE id=?', (phase, op['id']))
                self.pool.conn.commit()
                result = self.reconcile()
                self.assertFalse(result['ok'], result)
                self.assertFalse([c for c in self.provider.calls if c[0] == 'PUT'])
                self.assertFalse(self.provider.enabled['svc_1'])

    def test_channel_change_during_get_is_rechecked_at_put_boundary(self):
        second = self.add_second()
        changed = False
        def change_channel(path):
            nonlocal changed
            if path.endswith('/auto-renew') and not changed:
                changed = True
                self.switch(second)
        self.provider.get_hook = change_channel
        result = self.reconcile()
        self.assertFalse(result['ok'], result)
        self.assertFalse([c for c in self.provider.calls if c[0] == 'PUT'])
        self.assertFalse(any(self.provider.enabled.values()))

    def test_corrupt_or_unknown_state_fails_closed_without_network_or_overwrite(self):
        module = self.module()
        self.assertTrue(self.reconcile()['ok'])
        valid = json.loads(self.pool.get_setting(module.STATE_KEY))
        invalid = [json.dumps(valid)[:-1] + ',"owned":[]}',
                   '{', 'null', '{}', json.dumps(dict(valid, version=2)),
                   json.dumps(dict(valid, version=True)), json.dumps(dict(valid, owned={})),
                   json.dumps(dict(valid, unexpected='secret')),
                   json.dumps(dict(valid, owned=[dict(valid['owned'][0], phase='unknown')])),
                   json.dumps(dict(valid, owned=valid['owned'] * 2)),
                   json.dumps(dict(valid, owned=[dict(valid['owned'][0], service_id='../x')])),
                   json.dumps(dict(valid, last={'credential_identity': 'private-hash'}))]
        for raw in invalid:
            with self.subTest(state=raw[:30]):
                self.pool.set_setting(module.STATE_KEY, raw)
                self.provider.calls.clear()
                result = self.reconcile()
                released = module.release_owned(self.cfg, {'proxywing': self.provider}, self.pool,
                                                log=lambda *args: None)
                self.assertFalse(result['ok'])
                self.assertFalse(released['ok'])
                self.assertFalse(self.provider.calls)
                self.assertEqual(self.pool.get_setting(module.STATE_KEY), raw)
                summary = module.status(self.pool)
                self.assertFalse(summary['ok'])
                self.assertNotIn('private-hash', json.dumps(summary))

    def test_credential_rotation_blocks_without_touching_ids_in_another_account(self):
        self.assertTrue(self.reconcile()['ok'])
        original = self.pool.get_setting(self.module().STATE_KEY)
        self.provider.api_key = 'YOUR_OTHER_ACCOUNT_KEY'
        self.provider.calls.clear()
        result = self.reconcile()
        released = self.module().release_owned(self.cfg, {'proxywing': self.provider}, self.pool,
                                              log=lambda *args: None)
        self.assertFalse(result['ok'])
        self.assertTrue(result.get('pending_cleanup'))
        self.assertFalse(released['ok'])
        self.assertFalse(self.provider.calls)
        before = json.loads(original)['owned']
        self.assertEqual(json.loads(self.pool.get_setting(self.module().STATE_KEY))['owned'], before)
        self.assertNotIn('credential_identity', json.dumps(result))
        self.assertNotIn('credential_identity', json.dumps(self.module().status(self.pool)))

    def test_lost_enable_response_is_resolved_by_get_not_a_second_put(self):
        original = self.provider.put
        def lost(url, body, **kwargs):
            original(url, body, **kwargs)
            raise ProviderError('reply lost', network=True)
        with mock.patch.object(self.provider, 'put', side_effect=lost):
            result = self.reconcile()
        self.assertTrue(result['ok'], result)
        self.assertEqual(result.get('ownership'), 'owned')
        self.assertTrue(self.reconcile()['ok'])
        self.assertEqual([c for c in self.provider.calls if c[0] == 'PUT'], [('PUT', 'svc_1', True)])

    def test_failed_readback_keeps_enable_intent_for_restart_without_resend(self):
        def lost_readback(path):
            if path.endswith('/auto-renew') and self.provider.enabled['svc_1']:
                raise ProviderError('readback lost', network=True)
        self.provider.get_hook = lost_readback
        result = self.reconcile()
        self.assertFalse(result['ok'])
        self.assertEqual(self.module().status(self.pool)['owned'][0]['phase'], 'enabling')
        self.provider.get_hook = None
        result = self.reconcile()
        self.assertTrue(result['ok'], result)
        self.assertEqual(result.get('ownership'), 'owned')
        self.assertEqual([c for c in self.provider.calls if c[0] == 'PUT'], [('PUT', 'svc_1', True)])

    def test_unknown_cleanup_is_durable_nonthrowing_and_blocks_new_enable(self):
        module = self.module()
        self.assertTrue(self.reconcile()['ok'])
        self.switch(self.add_second())
        def fail_cleanup(path):
            if path == '/account/services/svc_1/auto-renew':
                raise ProviderError('unknown response', network=True)
        self.provider.get_hook = fail_cleanup
        self.provider.calls.clear()
        try:
            released = module.release_owned(self.cfg, {'proxywing': self.provider}, self.pool,
                                            log=lambda *args: None)
            result = self.reconcile()
        except Exception as error:
            self.fail('cleanup must return a blocker, not throw: ' + type(error).__name__)
        self.assertFalse(released['ok'])
        self.assertTrue(released.get('pending_cleanup'))
        self.assertFalse(result['ok'])
        self.assertTrue(result.get('pending_cleanup'))
        self.assertEqual([r['service_id'] for r in module.status(self.pool)['owned']], ['svc_1'])
        self.assertFalse([c for c in self.provider.calls if c[0] == 'PUT'])
        self.assertFalse(self.provider.enabled['svc_2'])

    def test_release_owned_disables_only_our_switch_without_enabling_anything(self):
        module = self.module()
        self.assertTrue(callable(getattr(module, 'release_owned', None)), 'release_owned is missing')
        self.assertTrue(self.reconcile()['ok'])
        self.provider.enabled['foreign'] = True
        self.provider.calls.clear()
        result = module.release_owned(self.cfg, {'proxywing': self.provider}, self.pool,
                                      log=lambda *args: None)
        self.assertTrue(result['ok'], result)
        self.assertEqual([c for c in self.provider.calls if c[0] == 'PUT'], [('PUT', 'svc_1', False)])
        self.assertEqual(self.provider.calls[-1], ('GET', '/account/services/svc_1/auto-renew'))
        self.assertTrue(self.provider.enabled['foreign'])
        self.assertEqual(module.status(self.pool)['owned'], [])

    def test_cleanup_of_old_owned_service_is_verified_before_enabling_new(self):
        self.assertTrue(self.reconcile()['ok'])
        self.switch(self.add_second())
        self.provider.calls.clear()
        result = self.reconcile()
        self.assertTrue(result['ok'], result)
        self.assertEqual([c for c in self.provider.calls if c[0] == 'PUT'],
                         [('PUT', 'svc_1', False), ('PUT', 'svc_2', True)])
        cleanup_readback = self.provider.calls.index(('PUT', 'svc_1', False)) + 1
        self.assertEqual(self.provider.calls[cleanup_readback],
                         ('GET', '/account/services/svc_1/auto-renew'))
        self.assertEqual([r['service_id'] for r in self.module().status(self.pool)['owned']], ['svc_2'])

    def test_current_shared_ip_is_identified_by_full_endpoint_not_host(self):
        second = self.add_second()
        self.switch(second)
        result = self.reconcile()
        self.assertEqual(result.get('service_id'), 'svc_2')
        self.assertFalse(self.provider.enabled['svc_1'])
        self.assertEqual([c for c in self.provider.calls if c[0] == 'PUT'],
                         [('PUT', 'svc_2', True)])

    def test_foreign_enabled_is_not_adopted_or_mutated(self):
        self.provider.enabled['svc_1'] = True
        result = self.reconcile()
        self.assertTrue(result['ok'])
        self.assertTrue(result['managed'])
        self.assertEqual(result.get('ownership'), 'external-enabled')
        self.assertFalse([c for c in self.provider.calls if c[0] == 'PUT'])
        self.assertEqual(self.module().status(self.pool)['owned'], [])

    def test_false_to_true_is_durably_owned_and_get_verified_without_payment(self):
        module = self.module()
        def before_put(service, enabled):
            state = json.loads(self.pool.get_setting(module.STATE_KEY))
            self.assertEqual(state['owned'][0]['service_id'], service)
            self.assertEqual(state['owned'][0]['phase'], 'enabling')
        self.provider.put_hook = before_put
        result = self.reconcile()
        self.assertTrue(result['ok'], result)
        self.assertTrue(result['managed'])
        self.assertEqual(result['mode'], 'provider-auto-renew')
        self.assertEqual(result['service_id'], 'svc_1')
        self.assertEqual(result['order_id'], 'ord_1')
        self.assertEqual(self.provider.calls[-1], ('GET', '/account/services/svc_1/auto-renew'))
        summary = module.status(self.pool)
        self.assertEqual(summary['owned'][0]['phase'], 'owned')
        self.assertNotIn('credential_identity', json.dumps(summary))
        self.assertNotIn(self.provider.api_key, json.dumps(summary))
        self.assertEqual(self.pool.conn.execute('SELECT COUNT(*) FROM money').fetchone()[0], 0)
        self.assertEqual(self.pool.pending_spend_operations(), [])


class PutTransportCase(unittest.TestCase):
    def test_put_cannot_opt_out_of_mutation_policy(self):
        with mock.patch.object(base, '_request_json') as request:
            with self.assertRaises(ValueError):
                base.http_put_json('https://example.invalid', {'enabled': True}, mutating=False)
            request.assert_not_called()

    def test_ambiguous_put_never_retries_but_proven_unsent_preserves_put_on_fallback(self):
        url = 'https://example.invalid/account/services/svc_1/auto-renew'
        for preferred in ('direct', 'tun0'):
            with self.subTest(preferred=preferred), \
                 mock.patch.object(base, 'preferred_transport', return_value=preferred), \
                 mock.patch.object(base, '_tun0_alive', return_value=True), \
                 mock.patch.object(base, '_urlopen_json', side_effect=ProviderError('timeout', network=True)) as direct, \
                 mock.patch.object(base, '_curl_json', side_effect=ProviderError('timeout', network=True)) as tunnel:
                with self.assertRaises(ProviderError):
                    base.http_put_json(url, {'enabled': True})
                self.assertEqual(direct.call_count, int(preferred == 'direct'))
                self.assertEqual(tunnel.call_count, int(preferred == 'tun0'))
        with mock.patch.object(base, 'preferred_transport', return_value='direct'), \
             mock.patch.object(base, '_tun0_alive', return_value=True), \
             mock.patch.object(base, 'set_transport') as remember, \
             mock.patch.object(base, '_urlopen_json', side_effect=ProviderError('DNS', network=True, unsent=True)), \
             mock.patch.object(base, '_curl_json', return_value={'enabled': True}) as tunnel:
            self.assertEqual(base.http_put_json(url, {'enabled': True}), {'enabled': True})
            self.assertEqual(tunnel.call_args.kwargs['method'], 'PUT')
            remember.assert_called_once_with('tun0')

    def test_tunnel_put_uses_stdin_explicit_method_and_rejects_redirects(self):
        url = 'https://example.invalid/account/services/svc_1/auto-renew'
        success = mock.Mock(returncode=0, stdout='HTTP/1.1 200 OK\r\n\r\n{"enabled":true}\n__HTTP__200')
        with mock.patch.object(base, 'preferred_transport', return_value='tun0'), \
             mock.patch.object(base, '_tun0_alive', return_value=True), \
             mock.patch.object(base.subprocess, 'run', return_value=success) as runner:
            result = base.http_put_json(url, {'enabled': True})
            self.assertEqual(result, {'enabled': True})
            args, kwargs = runner.call_args
            cmd = args[0]
            self.assertEqual(cmd[cmd.index('-X') + 1], 'PUT')
            self.assertNotIn('-L', cmd)
            self.assertNotIn('--location', cmd)
            self.assertEqual(json.loads(kwargs['input']), {'enabled': True})
            self.assertNotIn('{"enabled": true}', cmd)
            for code in (301, 302, 303, 307, 308):
                runner.return_value = mock.Mock(returncode=0,
                    stdout='HTTP/1.1 %s Redirect\r\nLocation: /other\r\n\r\n{}\n__HTTP__%s' % (code, code))
                with self.subTest(redirect=code), self.assertRaises(ProviderError):
                    base.http_put_json(url, {'enabled': True})


class ProviderIdentityCase(unittest.TestCase):
    def test_service_shared_with_order_in_other_family_is_rejected(self):
        provider = ServiceAPI()
        provider.other_orders = [{'id': 'isp_order', 'service_id': 'svc_1', 'proxies': [{'id': 'isp_ip'}]}]
        with self.assertRaises(ProviderError):
            provider.order_service('datacenter', 'ord_1')

    def test_service_switch_uses_exact_bool_and_response_must_match_request(self):
        provider = ServiceAPI()
        for enabled in (1, 0, 'true', None):
            with self.subTest(enabled=enabled), mock.patch.object(proxywing, 'http_put_json') as put:
                with self.assertRaises(ProviderError):
                    provider.set_auto_renew('svc_1', enabled)
                put.assert_not_called()
        for response in ({'service_id': 'svc_other', 'enabled': True},
                         {'service_id': 'svc_1', 'enabled': 1},
                         {'service_id': 'svc_1', 'enabled': False}, None):
            with self.subTest(response=response), \
                 mock.patch.object(proxywing, 'http_put_json', return_value=response):
                with self.assertRaises(ProviderError):
                    provider.set_auto_renew('svc_1', True)
        for response in ({'service_id': 'svc_1', 'enabled': 'true'},
                         {'service_id': 'other', 'enabled': True}):
            with self.subTest(get=response), mock.patch.object(provider, '_api', return_value=response):
                with self.assertRaises(ProviderError):
                    provider.get_auto_renew('svc_1')

    def test_service_must_be_active_monthly_with_real_billing_date(self):
        cases = [('status', 'suspended'), ('status', None), ('billing_cycle', 'quarterly'),
                 ('billing_cycle', None),
                 ('next_due_date', None), ('next_due_date', 'not-a-date'),
                 ('next_due_date', '2099-02-30'), ('next_due_date', '2099-01-01T12:00:00')]
        for key, value in cases:
            with self.subTest(field=key, value=value):
                provider = ServiceAPI()
                provider.services[0][key] = value
                with self.assertRaises(ProviderError):
                    provider.order_service('datacenter', 'ord_1')

    def test_service_with_multiple_or_unknown_proxies_cannot_be_enabled(self):
        for proxies in (None, [], [{'id': 'ip_1'}, {'id': 'ip_2'}], [None], [{'id': None}]):
            with self.subTest(proxies=proxies):
                provider = ServiceAPI()
                provider.orders[0]['proxies'] = proxies
                with self.assertRaises(ProviderError):
                    provider.order_service('datacenter', 'ord_1')

    def test_order_service_rejects_absent_null_wrong_or_duplicate_mapping(self):
        cases = [
            ([], None),
            ([{'id': 'ord_1'}], None),
            ([{'id': 'ord_1', 'service_id': None}], None),
            ([{'id': 'ord_other', 'service_id': 'svc_1'}], None),
            ([{'id': 'ord_1', 'service_id': 'svc_other'}], None),
            ([{'id': 'ord_1', 'service_id': 1}], None),
            ([{'id': 'ord_1', 'service_id': 'svc_1'}] * 2, None),
            ([{'id': 'ord_1', 'service_id': 'svc_1'},
              {'id': 'ord_2', 'service_id': 'svc_1'}], None),
            (None, []), (None, [{'id': 'svc_other'}]),
            (None, [{'id': 'svc_1'}] * 2),
        ]
        for orders, services in cases:
            with self.subTest(orders=orders, services=services):
                provider = ServiceAPI()
                if orders is not None:
                    provider.orders = orders
                if services is not None:
                    provider.services = services
                with self.assertRaises(ProviderError):
                    provider.order_service('datacenter', 'ord_1')
                self.assertFalse([c for c in provider.calls if c[0] == 'PUT'])


if __name__ == '__main__':
    unittest.main()
