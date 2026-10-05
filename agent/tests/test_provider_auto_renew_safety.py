"""Safety regressions from independent audit; real state, isolated network boundaries."""
import contextlib
import io
import json
from pathlib import Path
import sqlite3
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

PANEL = str(Path(__file__).resolve().parents[1])
sys.path[:0] = [PANEL + '/tests', PANEL]
import apply
import agent
import config_schema
import proxywing_autopay as autopay
from providers import base
from providers.base import ProviderError
import test_proxywing_autopay as domain_fixture
import test_apply_saga as apply_fixture


class IndependentSafetyRegressions(unittest.TestCase):
    def domain_fixture(self):
        case = domain_fixture.AutopayCase()
        case.setUp()
        self.addCleanup(case.doCleanups)
        return case

    def test_known_unsent_enable_must_not_adopt_and_disable_later_foreign_flag(self):
        case = self.domain_fixture()
        with mock.patch.object(base, '_urlopen_json', side_effect=ProviderError(
                'connection refused before send', network=True, unsent=True)), \
                mock.patch.object(base, '_tun0_alive', return_value=False):
            first = case.reconcile()
        self.assertFalse(first['ok'])
        self.assertFalse([c for c in case.provider.calls if c[0] == 'PUT'])
        journal = json.loads(case.pool.get_setting(autopay.STATE_KEY))
        self.assertFalse(journal['owned'][0]['submitted'])
        case.provider.enabled['svc_1'] = True  # Foreign actor after proven non-submission.
        recovered = case.reconcile()
        self.assertEqual(recovered['ownership'], 'external-enabled')
        released = autopay.release_owned(case.cfg, {'proxywing': case.provider}, case.pool,
                                         log=lambda *_: None)
        self.assertTrue(released['ok'])
        self.assertTrue(case.provider.enabled['svc_1'])
        self.assertFalse([c for c in case.provider.calls if c[0] == 'PUT'])

    def test_stale_egress_snapshot_must_not_reenable_after_successful_cli_disable(self):
        case = self.domain_fixture()
        policy = Path(case.directory) / 'policy.json'
        stored = dict(case.cfg, config_schema_version=config_schema.CURRENT_VERSION,
                      db=str(Path(case.directory) / 'state.db'))
        policy.write_text(json.dumps(stored))
        stale = agent.load_config(str(policy))  # Descheduled cron before writer obtains lock.
        self.assertTrue(case.reconcile()['ok'])
        fresh = agent.load_config(str(policy))
        with mock.patch.object(agent, 'open_pool', return_value=case.pool), \
                mock.patch.object(case.pool, 'close'), \
                mock.patch.object(agent, 'load_secrets', return_value=({}, None)), \
                mock.patch.object(agent, 'make_providers', return_value={'proxywing': case.provider}), \
                mock.patch.object(agent.apply_mod, 'run_cmd', return_value=(0, '192.0.2.1')), \
                mock.patch.object(agent.probe_mod, 'geo_country', return_value='de'), \
                contextlib.redirect_stdout(io.StringIO()):
            rc = agent.cmd_provider_auto_renew(fresh, SimpleNamespace(enable=False, disable=True, status=False))
            self.assertEqual(rc, 0)
            self.assertFalse(case.provider.enabled['svc_1'])
            agent.cmd_egress_mark(stale, SimpleNamespace())
        self.assertIs(json.loads(policy.read_text())['auto_prolong']['proxywing_provider_auto_renew'], False)
        self.assertFalse(case.provider.enabled['svc_1'])
        self.assertEqual([c for c in case.provider.calls if c[0] == 'PUT'],
                         [('PUT', 'svc_1', True), ('PUT', 'svc_1', False)])

    def test_policy_changed_during_get_is_rechecked_before_enable(self):
        case = self.domain_fixture()
        policy = Path(case.directory) / 'policy.json'
        policy.write_text(json.dumps(case.cfg))
        case.cfg['_source'] = str(policy)
        def disable(path):
            if path.endswith('/auto-renew'):
                raw = json.loads(policy.read_text())
                raw['auto_prolong']['proxywing_provider_auto_renew'] = False
                policy.write_text(json.dumps(raw))
        case.provider.get_hook = disable
        result = case.reconcile()
        self.assertFalse(result['ok'])
        self.assertFalse(case.provider.enabled['svc_1'])
        self.assertFalse([c for c in case.provider.calls if c[0] == 'PUT'])

    def test_persisted_safe_or_unreadable_policy_never_uses_stale_opt_in(self):
        for problem in ('safe-mode', 'unreadable'):
            with self.subTest(problem=problem):
                case = self.domain_fixture()
                policy = Path(case.directory) / 'policy.json'
                raw = dict(case.cfg, config_schema_version=config_schema.CURRENT_VERSION + 1)
                policy.write_text(json.dumps(raw) if problem == 'safe-mode' else '{')
                case.cfg['_source'] = str(policy)
                case.reconcile()
                self.assertFalse(case.provider.enabled['svc_1'])
                self.assertFalse([c for c in case.provider.calls if c[0] == 'PUT'])
                case.doCleanups()

    def test_refreshed_provider_mode_never_falls_back_to_paid_extend(self):
        import states
        case = self.domain_fixture()
        policy = Path(case.directory) / 'policy.json'
        policy.write_text(json.dumps(case.cfg))
        case.cfg['_source'] = str(policy)
        self.assertTrue(case.reconcile()['ok'])
        stale = dict(case.cfg, auto_prolong=dict(case.cfg['auto_prolong'],
                     proxywing_provider_auto_renew=False))
        with mock.patch.object(states, '_auto_prolong_proxywing',
                               side_effect=AssertionError('paid extend must be fenced')) as paid:
            result = states.auto_prolong(stale, {'proxywing': case.provider}, case.pool,
                                         mock.Mock(), log=lambda *_: None)
        self.assertTrue(result['provider_auto_renew']['managed'])
        paid.assert_not_called()
        self.assertEqual(result['prolonged'], [])

    def test_persisted_opt_in_fences_stale_off_snapshot_before_first_intent(self):
        import states
        case = self.domain_fixture()
        policy = Path(case.directory) / 'policy.json'
        policy.write_text(json.dumps(case.cfg))
        stale = dict(case.cfg, _source=str(policy), auto_prolong=dict(case.cfg['auto_prolong'],
                     proxywing_provider_auto_renew=False))
        self.assertIsNone(case.pool.get_setting(autopay.STATE_KEY))
        with mock.patch.object(states, '_auto_prolong_proxywing',
                               side_effect=AssertionError('paid extend must be fenced')) as paid:
            result = states.auto_prolong(stale, {'proxywing': case.provider}, case.pool,
                                         mock.Mock(), log=lambda *_: None)
        self.assertTrue(result['provider_auto_renew']['managed'])
        self.assertTrue(case.provider.enabled['svc_1'])
        paid.assert_not_called()

    def test_ineligible_proxy_id_mapping_must_cleanup_previous_owned_service(self):
        case = self.domain_fixture()
        self.assertTrue(case.reconcile()['ok'])
        case.provider.calls.clear()
        case.provider.orders[0]['proxies'] = [{'id': 'replacement_ip'}]
        for _ in range(3):
            result = case.reconcile()
            self.assertFalse(result['ok'])
            self.assertEqual(result['reason_code'], 'current-proxy-mismatch')
        self.assertFalse(case.provider.enabled['svc_1'])
        self.assertEqual(autopay.status(case.pool)['owned'], [])
        self.assertEqual([c for c in case.provider.calls if c[0] == 'PUT'], [('PUT', 'svc_1', False)])

    def test_cleanup_error_reporting_cannot_throw_or_erase_owned_intent(self):
        case = self.domain_fixture()
        self.assertTrue(case.reconcile()['ok'])
        original = case.pool.get_setting
        before = original(autopay.STATE_KEY)
        with mock.patch.object(case.pool, 'get_setting', side_effect=sqlite3.OperationalError('read failed')), \
                mock.patch.object(case.pool, 'log_event', side_effect=sqlite3.OperationalError('event failed')):
            result = apply.release_provider_billing_before_switch(case.cfg, case.pool,
                apply.load_json(case.cfg['singbox_config']), apply_fixture.config_for('192.0.2.2'),
                log=mock.Mock(side_effect=RuntimeError('log failed')))
        self.assertFalse(result['ok'])
        self.assertTrue(result['pending_cleanup'])
        self.assertEqual(original(autopay.STATE_KEY), before)
        self.assertTrue(case.provider.enabled['svc_1'])

    def test_billing_setting_failure_must_not_block_explicit_rollback(self):
        case = apply_fixture.TestApplySaga()
        case.setUp()
        self.addCleanup(case.tearDown)
        apply.backup_ring(case.live, case.ring)
        case.write(case.live, apply_fixture.config_for(case.NEW))
        original = case.pool.get_setting
        def transient(key, *args):
            if key == autopay.STATE_KEY:
                raise sqlite3.OperationalError('billing read failure')
            return original(key, *args)
        with case.system_ok() as m, mock.patch.object(case.pool, 'get_setting', side_effect=transient):
            m['singbox_check'].return_value = (0, '')
            m['restart_singbox'].return_value = True
            m['wait_tun0'].return_value = True
            m['verify_egress'].return_value = dict(case.ok_verify, egress_ip=case.OLD)
            m['antiloop_replace'].return_value = 'ok'
            m['patch_boot_script'].return_value = False
            result = apply.rollback_from_ring(case.cfg, pool=case.pool, log=lambda *_: None)
        self.assertTrue(result['ok'])
        self.assertEqual(apply.current_upstream(apply.load_json(case.live)), case.OLD)

    def test_runtime_billing_state_failure_is_deferred_without_throwing(self):
        import states
        case = self.domain_fixture()
        with mock.patch.object(case.pool, 'get_setting', side_effect=sqlite3.OperationalError('read failed')), \
                mock.patch.object(case.pool, 'log_event', side_effect=sqlite3.OperationalError('event failed')):
            result = states.sync_provider_auto_renew(case.cfg, {'proxywing': case.provider}, case.pool,
                log=mock.Mock(side_effect=RuntimeError('log failed')))
        self.assertFalse(result['ok'])
        self.assertTrue(result['pending_cleanup'])
        self.assertFalse([c for c in case.provider.calls if c[0] == 'PUT'])

    def test_billing_setting_read_failure_must_not_block_apply_failover(self):
        case = apply_fixture.TestApplySaga()
        case.setUp()
        self.addCleanup(case.tearDown)
        original = case.pool.get_setting
        def transient(key, *args):
            if key == autopay.STATE_KEY:
                raise sqlite3.OperationalError('transient billing state read failure')
            return original(key, *args)
        with case.system_ok() as m, mock.patch.object(case.pool, 'get_setting', side_effect=transient):
            m['singbox_check'].return_value = (0, '')
            m['restart_singbox'].return_value = True
            m['wait_tun0'].return_value = True
            m['verify_egress'].return_value = case.ok_verify
            m['antiloop_replace'].return_value = 'ok'
            m['patch_boot_script'].return_value = False
            result = apply.apply_candidate(case.cfg, case.row, case.probe, pool=case.pool, log=lambda *_: None)
        self.assertTrue(result['ok'])
        self.assertEqual(apply.current_upstream(apply.load_json(case.live)), case.NEW)


if __name__ == '__main__':
    unittest.main(verbosity=2)
