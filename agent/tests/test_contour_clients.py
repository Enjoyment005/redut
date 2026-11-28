"""Per-tab access lists, profile export and durable client provisioning."""
import contextlib
import copy
import ipaddress
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

import _ctx
import apply
import contours
from test_contours import LifecycleFixture
from webpanel import clients, contour_ui, server


class ScopedClientTests(LifecycleFixture):
    def setUp(self):
        super().setUp()
        self.create()
        self.root = Path(self.temp.name)
        self.wg = self.root / 'wg0.conf'
        self.directory = self.root / 'clients'
        self.marker = self.root / 'wg-operation.json'
        self.wg.write_text('[Interface]\nPrivateKey = test-server\n')
        self.directory.mkdir()
        for name, value in [('WG_CONF', self.wg), ('CLIENTS_DIR', self.directory),
                            ('CLIENT_OP_MARK', self.marker)]:
            patch = mock.patch.object(clients, name, str(value))
            patch.start(); self.addCleanup(patch.stop)
        self.rows = [dict(name='old', pubkey='old-key', conf_name='old', has_conf=True),
                     dict(name='new', pubkey='new-key', conf_name='new', has_conf=True)]

    def inventory(self, selected):
        with mock.patch.object(clients, 'list_clients', return_value=copy.deepcopy(self.rows)), \
             mock.patch.object(clients, 'next_free_ip', return_value='10.77.0.4'):
            return clients.client_inventory(self.cfg, contour=selected)['clients']

    def test_second_starts_empty_and_existing_clients_stay_primary(self):
        self.assertEqual(self.inventory('2'), [])
        self.assertEqual([r['name'] for r in self.inventory('1')], ['old', 'new'])

    def test_explicit_assignment_moves_only_one_client_between_lists(self):
        registry = contours.read(self.cfg)
        registry['assignments']['new-key'] = '2'
        contours.write(self.cfg, registry)
        self.assertEqual([r['name'] for r in self.inventory('1')], ['old'])
        self.assertEqual([r['name'] for r in self.inventory('2')], ['new'])
        self.assertEqual(self.rows[1].get('contour'), None)

    def test_profile_export_and_qr_reject_other_contour_before_reading(self):
        (self.directory / 'old.conf').write_text('synthetic profile')
        app = SimpleNamespace(cfg=self.cfg)
        handler = SimpleNamespace(_json=lambda status, data: (status, data),
                                  _send=lambda status, data, *a, **kw: (status, data))
        with mock.patch.object(server, 'APP', app), \
             mock.patch.object(clients, 'list_clients', return_value=self.rows):
            token = contours.CURRENT.set('2')
            try:
                for suffix in ('config', 'qr'):
                    code, data = server.Handler._api_get.__wrapped__(handler, '/api/clients/old/'+suffix, {})
                    self.assertEqual(code, 404)
                    self.assertNotIn('synthetic profile', str(data))
            finally:
                contours.CURRENT.reset(token)
            self.assertEqual(clients.client_conf_text('old', self.cfg, '1'), 'synthetic profile')

    def test_delete_cannot_revoke_primary_client_from_second(self):
        with mock.patch.object(clients, 'list_clients', return_value=self.rows), \
             mock.patch.object(clients, '_write_client_operation') as journal:
            with self.assertRaises(clients.ClientError):
                clients.delete_client(self.cfg, 'old', pubkey='old-key', contour='2')
            journal.assert_not_called()

    def test_move_checks_source_contour_under_common_lock(self):
        app = SimpleNamespace(cfg=self.cfg)
        token = contours.CURRENT.set('2')
        try:
            with mock.patch.object(clients, 'list_clients', return_value=self.rows), \
                 mock.patch.object(contours, 'assign') as assign:
                with self.assertRaises(contours.ContourError):
                    contour_ui.api_post(None, '/api/contours/assign', {'pubkey':'old-key','contour':'2'}, app)
                assign.assert_not_called()
        finally:
            contours.CURRENT.reset(token)

    def network(self):
        stack = contextlib.ExitStack()
        stack.enter_context(mock.patch.object(contours, '_run', return_value=(0, 'active')))
        stack.enter_context(mock.patch.object(contours, 'verify_dns', return_value=True))
        stack.enter_context(mock.patch.object(contours, 'reconcile_network'))
        stack.enter_context(mock.patch.object(apply, 'verify_for', return_value={'ok':True}))
        stack.enter_context(mock.patch.object(clients, '_live_peer_matches', return_value=True))
        stack.enter_context(mock.patch.object(clients, '_live_peer_absent', return_value=True))
        stack.enter_context(mock.patch.object(clients, '_set_live_peer'))
        stack.enter_context(mock.patch.object(clients, '_run', side_effect=lambda args, **kw: {
            'genkey':'synthetic-private', 'pubkey':'synthetic-public', 'genpsk':'synthetic-psk'
        }.get(args[1], '')))
        stack.enter_context(mock.patch.object(clients, 'server_params', side_effect=lambda cfg: dict(
            text=self.wg.read_text(), net=ipaddress.ip_network('10.77.0.0/24'), wg_ip='10.77.0.1',
            dns='10.77.0.1', server_pub='synthetic-server', host='192.0.2.1', port=51820)))
        return stack

    def test_new_second_client_is_assigned_before_live_peer_and_profile(self):
        with self.network(), mock.patch.object(clients, '_set_live_peer') as live:
            def installed(*args):
                self.assertEqual(contours.read(self.cfg)['assignments'].get('synthetic-public'), '2')
                self.assertFalse((self.directory/'phone.conf').exists())
            live.side_effect = installed
            result = clients.add_client(self.cfg, 'phone', contour='2')
        self.assertEqual(result['contour'], '2')
        self.assertTrue((self.directory/'phone.conf').exists())
        self.assertFalse(self.marker.exists())

    def test_failed_second_assignment_removes_new_profile_and_peer(self):
        original = self.wg.read_bytes()
        with self.network(), mock.patch.object(contours, 'verify_dns', return_value=False):
            with self.assertRaises(clients.ClientError):
                clients.add_client(self.cfg, 'phone', contour='2')
        self.assertEqual(self.wg.read_bytes(), original)
        self.assertFalse((self.directory/'phone.conf').exists())
        self.assertFalse(self.marker.exists())
        self.assertEqual(contours.read(self.cfg)['assignments'], {})

    def test_failed_live_add_rolls_back_secondary_assignment_too(self):
        original = self.wg.read_bytes()
        with self.network(), mock.patch.object(clients, '_set_live_peer', side_effect=clients.ClientError('test failure')):
            with self.assertRaises(clients.ClientError):
                clients.add_client(self.cfg, 'phone', contour='2')
        self.assertEqual(self.wg.read_bytes(), original)
        self.assertEqual(contours.read(self.cfg)['assignments'], {})
        self.assertFalse(self.marker.exists())

    def test_crash_recovery_remembers_second_contour(self):
        desired = self.wg.read_text() + '\n[Peer]\n# phone\nPublicKey = synthetic-public\nAllowedIPs = 10.77.0.2/32\n'
        clients._write_client_operation(dict(kind='add', name='phone', pubkey='synthetic-public',
            address='10.77.0.2', wg_config=desired, client_conf='synthetic profile', contour='2'))
        with self.network():
            result = clients.reconcile_client_operation(self.cfg)
        self.assertTrue(result['ok'])
        self.assertEqual(contours.read(self.cfg)['assignments'], {'synthetic-public':'2'})
        self.assertTrue((self.directory/'phone.conf').exists())
        self.assertFalse(self.marker.exists())

    def test_invalid_journal_contour_cannot_fall_back_to_primary(self):
        clients._write_client_operation(dict(kind='add', name='phone', pubkey='synthetic-public',
            address='10.77.0.2', wg_config='test', client_conf='test', contour='3'))
        with mock.patch.object(clients, '_set_live_peer') as live:
            with self.assertRaises(clients.ClientError):
                clients.reconcile_client_operation(self.cfg)
            live.assert_not_called()

    def test_move_waits_for_durable_client_journal_clear(self):
        self.rows = [dict(name='phone', pubkey='synthetic-public', conf_name='phone', has_conf=True)]
        app = SimpleNamespace(cfg=self.cfg, saga_pool=None)
        handler = SimpleNamespace(_json=lambda status, data:(status,data))
        with self.network(), mock.patch.object(clients, '_clear_client_operation', side_effect=OSError('test disk failure')):
            result = clients.add_client(self.cfg, 'phone', contour='2')
            self.assertTrue(result['recovery_pending'])
            token = contours.CURRENT.set('2')
            try:
                with mock.patch.object(clients, 'list_clients', return_value=self.rows):
                    with self.assertRaises(contours.ContourError):
                        contour_ui.api_post(handler, '/api/contours/assign', {'pubkey':'synthetic-public','contour':'1'}, app)
            finally:
                contours.CURRENT.reset(token)
        self.assertEqual(contours.read(self.cfg)['assignments'], {'synthetic-public':'2'})
        with self.network(), mock.patch.object(clients, 'list_clients', return_value=self.rows):
            token = contours.CURRENT.set('2')
            try:
                status, result = contour_ui.api_post(handler, '/api/contours/assign', {'pubkey':'synthetic-public','contour':'1'}, app)
            finally:
                contours.CURRENT.reset(token)
            self.assertEqual(status, 200)
            clients.reconcile_client_operation(self.cfg)
        self.assertFalse(self.marker.exists())
        self.assertEqual(contours.read(self.cfg)['assignments'], {})

    def test_delete_rechecks_scope_after_pending_operation_recovery(self):
        registry = contours.read(self.cfg); registry['assignments'] = {}; contours.write(self.cfg, registry)
        def recover(*args, **kwargs):
            registry['assignments']['old-key'] = '2'; contours.write(self.cfg, registry)
            return {'ok': True}
        with mock.patch.object(clients, 'list_clients', return_value=self.rows), \
             mock.patch.object(clients, 'reconcile_client_operation', side_effect=recover), \
             mock.patch.object(clients, '_write_client_operation') as journal:
            with self.assertRaises(clients.ClientError):
                clients.delete_client(self.cfg, 'old', pubkey='old-key', contour='1')
            journal.assert_not_called()

    def test_contour_delete_cannot_orphan_pending_second_client(self):
        original = self.wg.read_bytes()
        desired = self.wg.read_text() + '\n[Peer]\n# phone\nPublicKey = synthetic-public\nAllowedIPs = 10.77.0.2/32\n'
        clients._write_client_operation(dict(kind='add', name='phone', pubkey='synthetic-public',
            address='10.77.0.2', wg_config=desired, client_conf='synthetic profile', contour='2'))
        with mock.patch.object(contours, '_run') as commands:
            with self.assertRaises(contours.ContourError):
                contours.delete(self.cfg)
            commands.assert_not_called()
        self.assertEqual(contours.read(self.cfg)['secondary'], 'ready')
        self.assertEqual(self.wg.read_bytes(), original)
        with self.network():
            clients.reconcile_client_operation(self.cfg)
            with self.assertRaises(contours.ContourError):
                contours.delete(self.cfg)
        self.assertFalse(self.marker.exists())
        self.assertEqual(contours.read(self.cfg)['assignments'], {'synthetic-public':'2'})

    def rollback_second_delete(self):
        original = self.wg.read_text() + '\n[Peer]\n# phone\nPublicKey = synthetic-public\nAllowedIPs = 10.77.0.2/32\n'
        registry = contours.read(self.cfg); registry['assignments']['synthetic-public']='2'; contours.write(self.cfg, registry)
        clients._write_client_operation(dict(kind='delete', name='phone', pubkey='synthetic-public',
            wg_config=self.wg.read_text(), rollback_wg_config=original, resolution='rollback',
            rollback_allowed_ips=['10.77.0.2/32'], rollback_client_conf='synthetic profile'))

    def test_delete_rollback_restores_guard_before_live_second_peer(self):
        self.rollback_second_delete()
        order=[]
        def guard(*args, **kwargs):
            self.assertIn('synthetic-public', self.wg.read_text())
            order.append('guard')
        def live(*args, **kwargs):
            self.assertEqual(order, ['guard'])
            order.append('live')
        with mock.patch.object(contours, 'reconcile_network', side_effect=guard), \
             mock.patch.object(clients, '_set_live_peer_allowed_ips', side_effect=live), \
             mock.patch.object(clients, '_live_peer_allowed_ips_match', return_value=True):
            clients.reconcile_client_operation(self.cfg)
        self.assertEqual(order, ['guard','live','guard'])
        self.assertFalse(self.marker.exists())

    def test_delete_rollback_without_guard_keeps_second_peer_offline(self):
        self.rollback_second_delete()
        with mock.patch.object(contours, 'reconcile_network', side_effect=contours.ContourError('test guard failure')), \
             mock.patch.object(clients, '_set_live_peer_allowed_ips') as live:
            with self.assertRaises(clients.ClientError):
                clients.reconcile_client_operation(self.cfg)
            live.assert_not_called()
        self.assertTrue(self.marker.exists())

    def test_pending_revoke_retains_source_guard_until_live_removal_proven(self):
        registry = contours.read(self.cfg); registry['assignments']['synthetic-public']='2'; contours.write(self.cfg, registry)
        clients._write_client_operation(dict(kind='delete', name='phone', pubkey='synthetic-public',
            wg_config=self.wg.read_text(), rollback_allowed_ips=['10.77.0.2/32','fd00::2/128']))
        ips, ipv6, known = contours.peer_addresses(self.cfg)
        self.assertEqual(ips, ['10.77.0.2']); self.assertEqual(ipv6, ['fd00::2'])
        self.assertNotIn('synthetic-public', known)
        with mock.patch.object(contours, '_run', return_value=(0,'-A REDUT_PREROUTING -j MARK --set-mark 100')), \
             mock.patch.object(contours, '_ipset_swap') as swap, \
             mock.patch.object(contours, 'sync_dns'):
            contours.reconcile_network(self.cfg)
            swap.assert_any_call(contours.SET, ['10.77.0.2'], 'inet')
            swap.assert_any_call(contours.SET6, ['fd00::2'], 'inet6')
        with self.network():
            clients.reconcile_client_operation(self.cfg)
        self.assertEqual(contours.peer_addresses(self.cfg), ([], [], set()))

    def test_pending_second_add_never_appears_as_primary(self):
        original=self.wg.read_bytes()
        with self.network(), mock.patch.object(clients, '_assign_new_client', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                clients.add_client(self.cfg, 'phone', contour='2')
        self.assertEqual(contours.read(self.cfg)['assignments'], {})
        self.rows=[dict(name='phone',pubkey='synthetic-public',conf_name=None,has_conf=False)]
        self.assertEqual(self.inventory('1'), [])
        self.assertEqual([r['name'] for r in self.inventory('2')], ['phone'])
        ips, _, known=contours.peer_addresses(self.cfg)
        self.assertEqual(ips, ['10.77.0.2']); self.assertIn('synthetic-public', known)
        operation=clients._load_client_operation(self.cfg)
        operation['resolution']='rollback'; clients._write_client_operation(operation)
        self.assertEqual(self.inventory('1'), []); self.assertEqual(self.inventory('2'), [])
        with self.network():
            clients.reconcile_client_operation(self.cfg)
        self.assertEqual(self.wg.read_bytes(), original)

    def test_pending_guard_cannot_be_reused_by_new_primary_client(self):
        original = self.wg.read_text()
        clients._write_client_operation(dict(kind='add',name='phone',pubkey='synthetic-public',
            address='10.77.0.2',wg_config='test',client_conf='test',contour='2',
            resolution='rollback',rollback_wg_config=original))
        with self.network(), mock.patch.object(clients, '_clear_client_operation', side_effect=OSError('test disk failure')), \
             mock.patch.object(clients, 'next_free_ip') as allocate:
            with self.assertRaises(clients.ClientError):
                clients.add_client(self.cfg, 'next-primary', contour='1')
            allocate.assert_not_called()
        self.assertEqual(clients._load_client_operation(self.cfg)['name'], 'phone')
        self.assertFalse((self.directory/'next-primary.conf').exists())

    def test_inventory_snapshot_cannot_mix_recovery_revisions(self):
        with self.network(), mock.patch.object(clients, '_assign_new_client', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                clients.add_client(self.cfg, 'phone', contour='2')
        original_read=contours.read
        attempted=[]; blocked=[]
        def read_and_recover(cfg):
            snapshot=original_read(cfg)
            if not attempted:
                attempted.append(True)
                try:
                    with apply.Flock(self.cfg['lock']):
                        clients.reconcile_client_operation(self.cfg, _locked=True)
                except apply.LockBusy:
                    blocked.append(True)
            return snapshot
        with self.network(), mock.patch.object(contours, 'read', side_effect=read_and_recover):
            snapshot=clients.client_inventory(self.cfg, contour='1')
        self.assertEqual(snapshot['clients'], [])
        self.assertEqual(blocked, [True])
        with self.network():
            clients.reconcile_client_operation(self.cfg)
            self.assertEqual([r['name'] for r in clients.client_inventory(self.cfg, contour='2')['clients']], ['phone'])
