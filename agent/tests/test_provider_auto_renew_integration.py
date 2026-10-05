"""Runtime integration for opt-in, service-scoped provider auto-renew. No live requests."""
import contextlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import _ctx
import config_schema
import states
import test_proxywing_auto_renew as auto_fixtures


class TestProviderAutoRenewIntegration(unittest.TestCase):
    def setUp(self):
        self.case = auto_fixtures.TestProxyWingAutoRenew()
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.cfg = self.case.cfg
        self.cfg['auto_prolong']['proxywing_provider_auto_renew'] = True
        self.service = SimpleNamespace(
            STATE_KEY='proxywing_autopay:v1',
            reconcile=mock.Mock(return_value={'ok': True, 'managed': True, 'mode': 'enabled',
                                             'service_id': 'svc_1', 'payment_pending': True}),
            release_owned=mock.Mock(return_value={'ok': True, 'mode': 'disabled'}),
            status=mock.Mock(return_value={'mode': 'disabled'}))
        self.modules = mock.patch.dict('sys.modules', {'proxywing_autopay': self.service})
        self.modules.start()
        self.addCleanup(self.modules.stop)

    def test_provider_mode_never_sends_paid_extend(self):
        result = self.case.run_auto()
        self.assertEqual(self.case.provider.calls, [], 'provider-managed invoices must not also call extend')
        self.assertEqual(result['provider_auto_renew']['mode'], 'enabled')
        self.assertEqual(result['prolonged'], [])
        self.service.reconcile.assert_called_once()


    def test_cli_enable_persists_opt_in_and_reconciles_without_extend(self):
        import agent
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'config.json'
            source.write_text(json.dumps({'auto_prolong': {'enabled': True}, 'custom': 'keep'}))
            cfg = dict(self.cfg, _source=str(source), lock=str(Path(directory) / 'agent.lock'))
            args = SimpleNamespace(enable=True, disable=False, status=False)
            with mock.patch.object(agent, 'open_pool', return_value=self.case.pool), \
                    mock.patch.object(agent, 'load_secrets', return_value=({}, None)), \
                    mock.patch.object(agent, 'make_providers', return_value={'proxywing': self.case.provider}), \
                    mock.patch.object(self.case.pool, 'close'):
                self.assertTrue(callable(getattr(agent, 'cmd_provider_auto_renew', None)),
                                'missing supported management CLI')
                rc = agent.cmd_provider_auto_renew(cfg, args)
            stored = json.loads(source.read_text())
            self.assertIs(stored['auto_prolong']['proxywing_provider_auto_renew'], True)
            self.assertEqual(stored['custom'], 'keep')
            self.assertEqual(rc, 0)
            self.assertEqual(self.case.provider.calls, [])
            self.service.reconcile.assert_called_once()


    def test_apply_releases_owned_autopay_before_installing_new_outbound(self):
        self.case.doCleanups()  # remove the automatic-renewal fixture's outbound seam
        import apply as apply_mod
        import test_apply_saga
        case = test_apply_saga.TestApplySaga()
        case.setUp()
        self.addCleanup(case.tearDown)
        case.pool.set_setting('proxywing_autopay:v1', '{"owned": true}')
        hosts = []
        self.service.release_owned.side_effect = lambda *args, **kwargs: (
            hosts.append(apply_mod.current_upstream(apply_mod.load_json(case.live)))
            or {'ok': True, 'mode': 'disabled'})
        with case.system_ok() as m:
            m['singbox_check'].return_value = (0, '')
            m['restart_singbox'].return_value = True
            m['wait_tun0'].return_value = True
            m['verify_egress'].return_value = case.ok_verify
            m['antiloop_replace'].return_value = 'ok'
            m['patch_boot_script'].return_value = False
            apply_mod.apply_candidate(case.cfg, case.row, case.probe, pool=case.pool, log=lambda *_: None)
        self.assertEqual(hosts, [case.OLD], 'disable must precede routing to the replacement')
        self.assertTrue(self.service.release_owned.call_args.kwargs['_locked'])


    def test_egress_cron_reconciles_autopay(self):
        import agent
        with mock.patch.object(agent, 'open_pool', return_value=self.case.pool), \
                mock.patch.object(agent, 'load_secrets', return_value=({}, None)), \
                mock.patch.object(agent, 'make_providers', return_value={}), \
                mock.patch.object(agent.apply_mod, 'run_cmd', return_value=(1, '')), \
                mock.patch.object(self.case.pool, 'close'):
            agent.cmd_egress_mark(self.cfg, SimpleNamespace())
        self.service.reconcile.assert_called_once()


    def test_rollback_releases_autopay_before_installing_backup(self):
        self.case.doCleanups()
        import apply as apply_mod
        import test_apply_saga
        case = test_apply_saga.TestApplySaga()
        case.setUp()
        self.addCleanup(case.tearDown)
        case.pool.set_setting('proxywing_autopay:v1', '{"owned": true}')
        backup = str(Path(case.tmp.name) / 'rollback.json')
        case.write(backup, test_apply_saga.config_for(case.NEW))
        hosts = []
        self.service.release_owned.side_effect = lambda *args, **kwargs: (
            hosts.append(apply_mod.current_upstream(apply_mod.load_json(case.live)))
            or {'ok': True})
        with case.system_ok() as m:
            m['singbox_check'].return_value = (0, '')
            m['restart_singbox'].return_value = True
            m['wait_tun0'].return_value = True
            m['verify_egress'].return_value = case.ok_verify
            m['antiloop_replace'].return_value = 'ok'
            m['patch_boot_script'].return_value = False
            apply_mod.rollback_from_ring(case.cfg, backup_path=backup, pool=case.pool, log=lambda *_: None)
        self.assertEqual(hosts, [case.OLD])


    def test_daily_output_does_not_claim_payment_for_enabled_provider_flag(self):
        import agent
        import io
        output = io.StringIO()
        self.service.reconcile.return_value = {'ok': True, 'managed': True,
            'mode': 'provider-auto-renew', 'ownership': 'owned', 'service_id': 'svc_1',
            'payment_pending': True, 'reason': 'Текущий счёт требует проверки кабинета'}
        with mock.patch.object(agent, 'open_pool', return_value=self.case.pool), \
                mock.patch.object(agent, 'load_secrets', return_value=({}, None)), \
                mock.patch.object(agent, 'make_providers', return_value={'proxywing': self.case.provider}), \
                mock.patch.object(agent, '_make_alerter', return_value=self.case.alerter), \
                mock.patch.object(self.case.pool, 'close'), contextlib.redirect_stdout(output):
            agent.cmd_auto_prolong(self.cfg, SimpleNamespace())
        self.assertIn('Текущий счёт требует проверки кабинета', output.getvalue())
        self.assertNotIn('продлений нет: проверены срок', output.getvalue())
        self.assertEqual(self.case.alerter.sent, [])


class TestRealProviderBillingPath(unittest.TestCase):
    """Actual CLI, SQLite, domain and adapter; only the network boundary is simulated."""
    def test_cli_enable_scheduler_disable_preserves_unrelated_service(self):
        import agent
        import io
        import proxywing_autopay
        import test_proxywing_autopay
        case = test_proxywing_autopay.AutopayCase()
        case.setUp()
        self.addCleanup(case.doCleanups)
        case.provider.enabled['svc_other'] = True
        path = Path(case.directory) / 'policy.json'
        stored = dict(case.cfg, owner_field='keep', db=str(Path(case.directory) / 'state.db'))
        stored['auto_prolong'] = dict(case.cfg['auto_prolong'], proxywing_provider_auto_renew=False)
        path.write_text(json.dumps(stored))
        cfg = dict(case.cfg, _source=str(path))
        with mock.patch.object(agent, 'open_pool', return_value=case.pool), \
                mock.patch.object(case.pool, 'close'), \
                mock.patch.object(agent, 'load_secrets', return_value=({}, None)), \
                mock.patch.object(agent, 'make_providers', return_value={'proxywing': case.provider}), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(agent.cmd_provider_auto_renew(
                cfg, SimpleNamespace(enable=True, disable=False, status=False)), 0)
            self.assertTrue(case.provider.enabled['svc_1'])
            alerter = mock.Mock()
            result = states.auto_prolong(cfg, {'proxywing': case.provider}, case.pool,
                alerter, log=lambda *_: None)
            self.assertEqual(result['provider_auto_renew']['ownership'], 'owned')
            self.assertEqual(result['prolonged'], [])
            alerter.prolonged.assert_not_called()
            self.assertEqual(agent.cmd_provider_auto_renew(
                cfg, SimpleNamespace(enable=False, disable=True, status=False)), 0)
        self.assertFalse(case.provider.enabled['svc_1'])
        self.assertTrue(case.provider.enabled['svc_other'])
        self.assertEqual(proxywing_autopay.status(case.pool)['owned'], [])
        self.assertEqual([call for call in case.provider.calls if call[0] == 'PUT'],
                         [('PUT', 'svc_1', True), ('PUT', 'svc_1', False)])
        self.assertFalse(any('/extend' in str(call) for call in case.provider.calls))
        final = json.loads(path.read_text())
        self.assertIs(final['auto_prolong']['proxywing_provider_auto_renew'], False)
        self.assertEqual(final['owner_field'], 'keep')


if __name__ == '__main__':
    unittest.main()
