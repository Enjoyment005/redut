"""Catalog/credential boundaries for panels sharing one provider account."""
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import _ctx
import pool
from webpanel import server


class ProviderScopeUiTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.cfg = {'contours_path': str(Path(temp.name) / 'contours.json')}
        self.secrets = {'proxywing': {'api_key': 'your_proxywing_api_key_here'},
                        'zenxnet': {'api_key': 'your_zenxnet_subscription_here', 'contours': ['2']}}
        self.rows = [{'uid': 'wing-1', 'provider': 'proxywing', 'gone': 0},
                     {'uid': 'zenx-1', 'provider': 'zenxnet', 'gone': 0}]
        self.app = SimpleNamespace(cfg=self.cfg, secrets=self.secrets,
                                   pool=mock.Mock(), providers={'proxywing': mock.Mock()},
                                   current_host=lambda: None)
        self.app.pool.list.return_value = self.rows
        self.app.pool.get_setting.return_value = '{}'
        self.app.pool.conn.execute.return_value = []
        self.handler = mock.Mock()
        self.handler.headers = {}
        self.handler._json.side_effect = lambda status, data: (status, data)
        self.handler._pool_row.side_effect = lambda row, cur: row
        self.handler._body.return_value = b'{"role":"auto"}'
        for name in ('_do_apply', '_do_prolong', '_do_delete'):
            getattr(self.handler, name).return_value = (200, {'ok': True})
        self.app.probe_row = mock.Mock(return_value=dict(
            ok=True, score=1, exit_ip='192.0.2.20', exit_cc='cn', tg_ok=True, disqualified=None))

    def test_primary_catalog_excludes_secondary_even_if_legacy_rows_remain(self):
        with mock.patch.object(server, 'APP', self.app), \
                mock.patch.object(server, 'pool_view_order', side_effect=lambda rows, *a: rows):
            status, data = server.Handler._api_get(self.handler, '/api/pool', {})
        self.assertEqual(status, 200)
        self.assertEqual([r['provider'] for r in data['proxies']], ['proxywing'])

    def test_primary_key_status_does_not_claim_secondary_subscription(self):
        with mock.patch.object(server, 'APP', self.app):
            data = server.Handler._key_status(self.handler)
        zenx = next(r for r in data['providers'] if r['provider'] == 'zenxnet')
        self.assertFalse(zenx['set'])
        self.assertEqual(zenx['alive'], 0)
        self.assertIsNone(zenx['subscription'])
        self.assertEqual(zenx['masked'], '')

    def test_foreign_catalog_uid_cannot_be_mutated_or_selected(self):
        self.app.pool.get.return_value = self.rows[1]
        for action in ('role', 'probe', 'apply', 'delete', 'prolong'):
            with self.subTest(action=action), mock.patch.object(server, 'APP', self.app):
                status, data = server.Handler._api_post(self.handler, '/api/proxy/zenx-1/' + action)
                self.assertEqual(status, 404)
        self.app.pool.set_role.assert_not_called()
        self.handler._do_apply.assert_not_called()
        self.handler._do_prolong.assert_not_called()
        self.handler._do_delete.assert_not_called()

    def test_refresh_purges_foreign_legacy_catalog_without_provider_call(self):
        p = pool.Pool(':memory:')
        self.addCleanup(p.close)
        p.upsert_proxy(dict(self.rows[1], ext_id='z1', host='192.0.2.20', country='cn'))
        self.assertEqual(len(p.list(include_gone=True)), 1)
        self.app.pool = p
        self.app.providers = {}
        self.app.alerter = mock.Mock()
        with mock.patch.object(server, 'APP', self.app), \
                mock.patch.object(server.states_mod, 'notify_vanished', return_value={'notified': 0}):
            status, data = server.Handler._api_post(self.handler, '/api/pool/refresh')
        self.assertEqual(status, 200)
        self.assertEqual(p.list(include_gone=True), [])

    def test_second_contour_key_does_not_allow_removing_last_primary_key(self):
        self.app.secrets_path = 'unused-test-secrets'
        def update(path, transform):
            return transform(self.secrets)
        with mock.patch.object(server, 'APP', self.app), \
                mock.patch.object(server.auth, 'update_secrets_atomic', side_effect=update):
            status, data = server.Handler._do_key_delete(self.handler, 'proxywing')
        self.assertEqual(status, 400)
        self.assertIn('последний ключ', data['error'])


if __name__ == '__main__':
    unittest.main()
