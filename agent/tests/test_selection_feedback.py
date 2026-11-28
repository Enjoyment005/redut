"""Regression for slow country selection and a provider/GeoIP disagreement."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import _ctx
from webpanel import views
from test_panel_api import _AppHarness, server


class TestSelectedChannel(_AppHarness):
    def test_selected_catalog_country_is_separate_from_observed_exit(self):
        uid = self.put_proxy('beijing', country='cn', exit_cc='fi', host='192.0.2.20')
        row = self.app.pool.get(uid)
        row.update(protocol='vless', descr='China, Beijing', connection_json='private-connection', password='your_private_password_here')
        with mock.patch.object(self.app.pool, 'list', return_value=[row]), \
             mock.patch.object(self.app, 'read_singbox', return_value={'outbounds':[{'tag':'socks-out','server':row['host']}]}), \
             mock.patch.object(server.apply_mod, 'matches_current', return_value=True), \
             mock.patch.object(self.app.pool, 'get_egress', return_value={'egress':row['host'], 'egress_cc':'fi'}):
            result = server.Handler._status(None)
        self.assertEqual(result['selected_channel'], {'uid':uid, 'provider':'proxy6', 'host':row['host'],
                                                     'label':'China, Beijing', 'country':'cn'})
        self.assertEqual(result['egress_cc'], 'fi')
        self.assertNotIn('private-', json.dumps(result))
        self.assertNotIn('your_private_password_here', json.dumps(result))

    def test_same_host_legacy_connections_resolve_by_credentials_and_port(self):
        first = {'uid':'proxy6:first', 'provider':'proxy6', 'host':'192.0.2.20', 'country':'fi',
                 'port_socks5':1081, 'user':'first-user', 'password':'your_first_password_here'}
        actual = dict(first, uid='proxy6:actual', country='nl', port_socks5=1082,
                      user='actual-user', password='your_actual_password_here')
        sb = {'outbounds':[server.apply_mod.build_outbound('socks', 'socks-out', actual['host'],
                                                          1082, 'actual-user', 'your_actual_password_here')]}
        summary = server.selected_channel([first, actual], sb)
        self.assertEqual((summary['uid'], summary['country']), ('proxy6:actual', 'nl'))
        self.assertNotIn('password', json.dumps(summary))
        self.assertIsNone(server.selected_channel([actual, dict(actual, uid='proxy6:duplicate')], sb))

    def test_unreachable_candidate_returns_readable_failure_without_apply(self):
        uid = self.put_proxy('offline', country='us', host='192.0.2.22')
        handler = mock.Mock()
        handler._client_ip.return_value = '127.0.0.1'
        handler._json.side_effect = lambda status, payload: (status, payload)
        with mock.patch.object(self.app, 'probe_row', return_value={'ok':False, 'disqualified':'no-combo'}), \
             mock.patch.object(server.apply_mod, 'apply_candidate') as apply:
            status, body = server.Handler._do_apply(handler, self.app.pool.get(uid))
        self.assertEqual(status, 409)
        self.assertIn('Не удалось проверить интернет', body['error'])
        self.assertEqual(body['reason'], 'no-combo')
        apply.assert_not_called()

    def test_unmatched_outbound_has_no_invented_catalog_location(self):
        self.put_proxy('old', country='cn', host='192.0.2.20')
        with mock.patch.object(server.apply_mod, 'current_upstream', return_value='192.0.2.21'), \
             mock.patch.object(server.apply_mod, 'matches_current', return_value=False):
            result = server.Handler._status(None)
        self.assertIsNone(result['selected_channel'])


class TestStrategyAttempt(unittest.TestCase):
    def setUp(self):
        from test_strategy_convergence import TestStrategyConvergence
        self.fixture = TestStrategyConvergence()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.fixture.cfg['lock'] = str(Path(self.fixture.tmp.name)/'selection.lock')

    def test_policy_hold_finishes_attempt_without_losing_future_retry(self):
        import states
        f = self.fixture
        f.pool.conn.execute("UPDATE proxy SET latency_ms=200 WHERE uid=?", (f.current,))
        f.pool.conn.execute("UPDATE proxy SET latency_ms=100 WHERE uid=?", (f.fast,))
        f.pool.conn.commit()
        desired = states.request_strategy_selection(f.pool, f.cfg, 'speed')
        with mock.patch.object(states, '_probe', side_effect=f.probe_ok), \
             mock.patch.object(states.apply_mod, 'apply_candidate') as apply:
            result = states.converge_strategy(f.cfg, f.providers, f.pool, log=lambda *_:None)
        self.assertEqual(result['action'], 'held')
        apply.assert_not_called()
        revision = states.selection_revision_state(f.pool, f.cfg)
        self.assertTrue(revision['pending'], 'hold must remain eligible for later reconciliation')
        self.assertEqual(states.selection_attempt_state(f.pool, revision),
                         {'revision':desired, 'state':'done', 'ok':True, 'action':'held'})
        states.request_strategy_selection(f.pool, f.cfg, 'balanced')
        self.assertIsNone(states.selection_attempt_state(f.pool, states.selection_revision_state(f.pool, f.cfg)))

    def test_failed_attempt_is_tied_to_request_without_secrets(self):
        import states
        f = self.fixture
        states.request_strategy_selection(f.pool, f.cfg, 'speed')
        with mock.patch.object(states, '_converge_strategy_locked', return_value={
                'ok':False, 'action':'probe-inconclusive', 'detail':'private-connection'}):
            states.converge_strategy(f.cfg, f.providers, f.pool, log=lambda *_:None)
        state = states.selection_attempt_state(f.pool, states.selection_revision_state(f.pool, f.cfg))
        self.assertFalse(state['ok'])
        self.assertEqual(state['action'], 'probe-inconclusive')
        self.assertNotIn('private-', f.pool.get_setting('selection_attempt'))


@unittest.skipUnless(shutil.which('node'), 'Node.js is required for rendered panel checks')
class TestSelectionUI(unittest.TestCase):
    def test_pending_success_failure_duplicate_and_auto_convergence(self):
        with tempfile.TemporaryDirectory() as tmp:
            page = Path(tmp)/'dashboard.html'
            page.write_text(views.dashboard_page('test', 'synthetic-csrf'))
            result = subprocess.run(['node', str(Path(__file__).with_name('selection_ui_regression.js')), str(page)],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
