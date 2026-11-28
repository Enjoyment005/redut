"""Subscription catalogs belong only to contours explicitly using the key."""
import contextlib
import io
import json
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import _ctx
import agent
import contours
import pool
from providers.zenxnet import ZenXNet, parse_node
from test_contours import LifecycleFixture
from test_zenxnet import URL, HWID, uri
from webpanel import contour_ui


class MembershipTests(LifecycleFixture):
    def test_explicit_secondary_membership_isolated_from_primary_auth(self):
        secrets = {'zenxnet': {'api_key': URL, 'hwid': HWID, 'contours': ['2']},
                   'proxy6': {'api_key': 'test'}, 'admin': {'name': 'test'},
                   'smtp': {'host': 'example.invalid'}}
        primary = contours.scoped_secrets(self.cfg, secrets)
        child = dict(self.cfg, contour_id='2')
        second = contours.scoped_secrets(child, secrets)
        self.assertNotIn('zenxnet', primary)
        self.assertIn('proxy6', primary)
        self.assertNotIn('proxy6', second)
        self.assertIn('zenxnet', second)
        self.assertEqual(primary['admin'], second['admin'])
        self.assertEqual(primary['smtp'], second['smtp'])
        self.assertIn('zenxnet', secrets)
        adapters = {'zenxnet': object(), 'proxy6': object()}
        self.assertEqual(set(contours.allowed_providers(self.cfg, adapters, secrets)), {'proxy6'})
        self.assertEqual(set(contours.allowed_providers(child, adapters, secrets)), {'zenxnet'})

    def test_scope_keeps_orphan_primary_provider_rows_manageable(self):
        providers = {'proxywing': object(), 'zenxnet': object()}
        secrets = {'zenxnet': dict(self.secrets['zenxnet'], contours=['2'])}
        self.assertEqual(set(contours.allowed_providers(self.cfg, providers, secrets)), {'proxywing'})

    def test_explicit_primary_and_shared_membership(self):
        child = dict(self.cfg, contour_id='2')
        for members in (['1'], ['1', '2']):
            with self.subTest(members=members):
                secrets = {'zenxnet': dict(self.secrets['zenxnet'], contours=members)}
                self.assertIn('zenxnet', contours.scoped_secrets(self.cfg, secrets))
                self.assertEqual('zenxnet' in contours.scoped_secrets(child, secrets), '2' in members)

    def test_invalid_scope_fails_closed(self):
        for value in (None, [], '2', ['3'], [2], ['2', '2'], [{}]):
            with self.subTest(value=value):
                secrets = {'zenxnet': dict(self.secrets['zenxnet'], contours=value)}
                self.assertEqual(contours.provider_contours(self.cfg, secrets), ())
                self.assertNotIn('zenxnet', contours.scoped_secrets(self.cfg, secrets))
                self.assertNotIn('zenxnet', contours.scoped_secrets(dict(self.cfg, contour_id='2'), secrets))

    def test_legacy_scope_preserves_existing_installation(self):
        self.assertEqual(contours.provider_contours(self.cfg, self.secrets), ('1',))
        self.create()
        self.assertEqual(contours.provider_contours(self.cfg, self.secrets), ('1', '2'))
        self.assertEqual(contours.provider_contours(self.cfg, {'zenxnet': {'hwid': HWID}}), ())

    def test_agent_commands_scope_credentials_but_lifecycle_keeps_shared_copy(self):
        secrets_path = Path(self.temp.name) / 'secrets.json'
        secrets_path.write_text(json.dumps({'zenxnet': dict(self.secrets['zenxnet'], contours=['2']),
                                           'proxy6': {'api_key': 'test'}, 'admin': {'name': 'test'}}))
        with mock.patch.object(agent, 'ETC_SECRETS', str(secrets_path)):
            self.assertNotIn('zenxnet', agent.load_secrets(self.cfg)[0])
            self.assertIn('zenxnet', agent.load_secrets(dict(self.cfg, contour_id='2'))[0])
            self.assertNotIn('proxy6', agent.load_secrets(dict(self.cfg, contour_id='2'))[0])
            self.assertIn('zenxnet', agent.load_secrets()[0])

    def test_cli_stale_secondary_row_cannot_apply_probe_or_appear_in_primary(self):
        path = Path(self.temp.name) / 'secrets.json'
        path.write_text(json.dumps({'zenxnet': dict(self.secrets['zenxnet'], contours=['2'])}))
        database = pool.Pool(self.cfg['db'])
        try:
            uid = database.list()[0]['uid']
            database.set_role(uid, 'auto')
        finally:
            database.close()
        with mock.patch.object(agent, 'ETC_SECRETS', str(path)),                 mock.patch.object(agent, '_probe_one') as probe,                 mock.patch.object(agent, 'read_singbox') as runtime,                 contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(agent.cmd_apply(self.cfg, SimpleNamespace(uid=uid)), 1)
            runtime.assert_not_called()
            self.assertEqual(agent.cmd_probe(self.cfg, SimpleNamespace(uid=uid)), 1)
            self.assertEqual(agent.cmd_probe(self.cfg, SimpleNamespace(uid=None)), 0)
            probe.assert_not_called()
        output = io.StringIO()
        with mock.patch.object(agent, 'ETC_SECRETS', str(path)),                 contextlib.redirect_stdout(output):
            self.assertEqual(agent.cmd_list(self.cfg, SimpleNamespace(all=True)), 0)
        self.assertNotIn(uid, output.getvalue())

    def test_cli_list_keeps_orphan_other_provider_visible(self):
        database = pool.Pool(self.cfg['db'])
        try:
            legacy = dict(parse_node(uri()), provider='proxywing', ext_id='orphan-test')
            database.upsert_proxy(legacy)
        finally:
            database.close()
        output = io.StringIO()
        with mock.patch.object(agent, 'load_secrets', return_value=({}, None)),                 contextlib.redirect_stdout(output):
            self.assertEqual(agent.cmd_list(self.cfg, SimpleNamespace(all=True)), 0)
        self.assertIn('proxywing:orphan-test', output.getvalue())
        self.assertNotIn('zenxnet:', output.getvalue())

    def test_direct_create_rejects_explicit_primary_only_scope_before_resources(self):
        self.secrets['zenxnet']['contours'] = ['1']
        before = Path(self.cfg['db']).read_bytes()
        with mock.patch.object(contours, 'validate_resources') as resources:
            with self.assertRaisesRegex(contours.ContourError, 'подписку ко второму'):
                contours.create(self.cfg, self.secrets)
        resources.assert_not_called()
        self.assertFalse(Path(contours.registry_path(self.cfg)).exists())
        self.assertFalse(Path(contours.paths(self.cfg)['config']).exists())
        self.assertEqual(Path(self.cfg['db']).read_bytes(), before)

    def test_create_uses_subscription_cache_not_primary_catalog(self):
        database = pool.Pool(self.cfg['db'])
        try:
            database.purge_provider('zenxnet')
            before = database.list(include_gone=True)
            self.create()
            self.assertEqual(database.list(include_gone=True), before)
            child = pool.Pool(contours.config(self.cfg)['db'])
            try:
                rows = child.list()
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]['provider'], 'zenxnet')
                self.assertEqual(rows[0]['role'], 'auto')
            finally:
                child.close()
        finally:
            database.close()


class SubscriptionSaveTests(LifecycleFixture):
    def app(self, secrets):
        path = Path(self.temp.name) / 'secrets.json'
        path.write_text(json.dumps(secrets))
        database = pool.Pool(self.cfg['db'])
        self.addCleanup(database.close)
        app = SimpleNamespace(cfg=self.cfg, secrets_path=str(path), db_lock=threading.RLock(),
                              pool=database, current_host=lambda: '192.0.2.17')
        def reload_secrets():
            app.secrets = json.loads(path.read_text())
        app.reload_secrets = reload_secrets
        app.reload_secrets()
        return app

    def test_new_secondary_subscription_never_enters_primary_catalog(self):
        app = self.app({'admin': {'name': 'test'}})
        app.pool.purge_provider('zenxnet')
        contour_ui.save_subscription(app, URL, target='2')
        self.assertEqual(app.pool.list(include_gone=True), [])
        self.assertEqual(app.secrets['zenxnet']['contours'], ['2'])
        device = app.secrets['zenxnet']['hwid']
        self.secrets = app.secrets
        self.create()
        contour_ui.save_subscription(app, URL, target='2')
        self.assertEqual(app.pool.list(include_gone=True), [])
        self.assertEqual(app.secrets['zenxnet']['hwid'], device)
        second = pool.Pool(contours.config(self.cfg)['db'])
        try:
            self.assertEqual(len(second.list()), 1)
        finally:
            second.close()

    def test_subscription_update_only_refreshes_selected_contour(self):
        self.create()
        app = self.app({'zenxnet': dict(self.secrets['zenxnet'], contours=['1', '2'])})
        before = app.pool.list(include_gone=True)
        changed = dict(parse_node(uri()), descr='Updated secondary catalog')
        token = contours.CURRENT.set('2')
        try:
            with mock.patch.object(ZenXNet, 'list', return_value=[changed]):
                contour_ui.save_subscription(contour_ui.Apps(app, None), URL)
        finally:
            contours.CURRENT.reset(token)
        self.assertEqual(app.pool.list(include_gone=True), before)
        self.assertEqual(app.secrets['zenxnet']['contours'], ['1', '2'])
        second = pool.Pool(contours.config(self.cfg)['db'])
        try:
            self.assertEqual(second.list()[0]['descr'], 'Updated secondary catalog')
        finally:
            second.close()

    def test_enabling_primary_is_explicit_and_preserves_secondary(self):
        self.create()
        app = self.app({'zenxnet': dict(self.secrets['zenxnet'], contours=['2'])})
        app.pool.purge_provider('zenxnet')
        contour_ui.save_subscription(app, URL, target='1')
        self.assertEqual(len(app.pool.list()), 1)
        self.assertEqual(app.secrets['zenxnet']['contours'], ['1', '2'])

    def test_check_only_never_enables_a_contour_or_imports_catalog(self):
        app = self.app({'zenxnet': dict(self.secrets['zenxnet'], contours=['2'])})
        app.pool.purge_provider('zenxnet')
        contour_ui.save_subscription(app, URL, check_only=True, target='1')
        self.assertEqual(app.pool.list(include_gone=True), [])
        self.assertEqual(app.secrets['zenxnet']['contours'], ['2'])

    def test_creation_reuses_saved_subscription_and_enables_second_durably(self):
        app = self.app({'zenxnet': dict(self.secrets['zenxnet'], contours=['1'])})
        before = app.pool.list(include_gone=True)
        handler = SimpleNamespace(_json=lambda status, payload: (status, payload))
        def create(cfg, secrets):
            persisted = json.loads(Path(app.secrets_path).read_text())
            self.assertEqual(persisted['zenxnet']['contours'], ['1', '2'])
            self.assertEqual(persisted['zenxnet']['hwid'], HWID)
            self.assertEqual(secrets, persisted)
            return {'ok': True}
        with mock.patch.object(contours, 'create', side_effect=create) as called:
            status, payload = contour_ui.api_post(handler, '/api/contours', {}, app)
        called.assert_called_once()
        self.assertEqual(status, 200)
        self.assertTrue(payload['ok'])
        self.assertEqual(app.pool.list(include_gone=True), before)

    def test_creation_endpoint_explicitly_targets_second_contour(self):
        app = self.app({})
        handler = SimpleNamespace(_json=lambda status, payload: (status, payload))
        with mock.patch.object(contour_ui, 'save_subscription') as save, \
                mock.patch.object(contours, 'create', return_value={'ok': True}):
            contour_ui.api_post(handler, '/api/contours', {'url': URL}, app)
        save.assert_called_once_with(app, URL, target='2')


if __name__ == '__main__':
    unittest.main()
