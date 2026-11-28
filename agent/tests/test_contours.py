import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import _ctx
import apply
import config_schema
import contours
import pool
import states
import vless
from providers.base import ProviderError
from providers.zenxnet import ZenXNet, parse_node
from test_zenxnet import uri, URL, HWID, UUID


class LifecycleFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        source = root / 'config.json'
        raw = {'server': 'test', 'role': 'test', 'subnet': '10.77.0.0/24',
               'wan': 'eth0', 'gw': '192.0.2.1', 'db': str(root/'state.db'),
               'singbox_config': str(root/'sing-box.json'), 'ring': str(root/'cfg'),
               'lock': str(root/'lock'), 'boot_script': str(root/'boot.sh')}
        apply.dump_json_replace(raw, str(source))
        self.cfg = config_schema.normalize(raw, source=str(source))
        self.cfg['_test_unit_dir'] = str(root/'units')
        apply.dump_json_replace(_ctx.fixture('singbox_config_reference.json'), raw['singbox_config'])
        db = pool.Pool(raw['db'])
        db.upsert_proxy(parse_node(uri()))
        db.close()
        self.secrets = {'zenxnet': {'api_key': URL, 'hwid': HWID}}
        listing = mock.patch.object(ZenXNet, 'list', return_value=[parse_node(uri())])
        listing.start()
        self.addCleanup(listing.stop)

    def create(self):
        with mock.patch.object(contours, 'validate_resources'), mock.patch.object(contours, '_run', return_value=(0,'')), mock.patch.object(contours, 'reconcile_network'):
            return contours.create(self.cfg, self.secrets)

class LifecycleTests(LifecycleFixture):
    def test_create_is_idempotent_has_no_peers_and_preserves_primary(self):
        before = Path(self.cfg['singbox_config']).read_bytes()
        self.create()
        self.assertTrue(self.create()['existing'])
        registry = contours.read(self.cfg)
        self.assertEqual(registry['assignments'], {})
        self.assertEqual(registry['secondary'], 'ready')
        child = contours.config(self.cfg)
        self.assertNotEqual(child['db'], self.cfg['db'])
        self.assertNotEqual(child['singbox_config'], self.cfg['singbox_config'])
        self.assertEqual(child['lock'], self.cfg['lock'])
        self.assertEqual(Path(self.cfg['singbox_config']).read_bytes(), before)
        self.assertEqual(len(contours.public(self.cfg)['contours']), 2)
        self.assertFalse(contours.public(self.cfg)['can_create'])

    def test_failed_create_recovers_from_durable_intent(self):
        with mock.patch.object(contours, 'validate_resources'), mock.patch.object(contours, '_run', side_effect=contours.ContourError('interrupted')):
            with self.assertRaises(contours.ContourError):
                contours.create(self.cfg, self.secrets)
        self.assertEqual(contours.read(self.cfg)['secondary'], 'creating')
        self.create()
        self.assertEqual(contours.read(self.cfg)['secondary'], 'ready')

    def test_core_rejection_never_reports_ready(self):
        with mock.patch.object(contours, 'validate_resources'), mock.patch.object(contours, '_run', return_value=(1,'')):
            with self.assertRaises(contours.ContourError): contours.create(self.cfg, self.secrets)
        self.assertEqual(contours.read(self.cfg)['secondary'], 'creating')

    def test_delete_requires_empty_assignments_and_recreate_is_fresh(self):
        self.create()
        registry=contours.read(self.cfg)
        registry['assignments']['peer']='2'; contours.write(self.cfg,registry)
        with self.assertRaises(contours.ContourError): contours.delete(self.cfg)
        registry['assignments']={}; contours.write(self.cfg,registry)
        child=contours.config(self.cfg)
        Path(child['emergency_intent']).write_text('direct')
        with mock.patch.object(contours,'_run',return_value=(0,'')):
            contours.delete(self.cfg)
            self.assertTrue(contours.delete(self.cfg)['ok'])
        self.assertTrue(contours.public(self.cfg)['can_create'])
        self.create()
        self.assertFalse(Path(contours.config(self.cfg)['emergency_intent']).exists())

    def test_assignment_requires_dns_and_rolls_back_failed_network_change(self):
        self.create()
        with mock.patch.object(contours,'peer_addresses',return_value=([],[],{'peer'})), mock.patch.object(apply,'verify_for',return_value={'ok':True}), mock.patch.object(contours,'_run',return_value=(0,'active')), mock.patch.object(contours,'verify_dns',return_value=False):
            with self.assertRaises(contours.ContourError): contours.assign(self.cfg,'peer','2')
        self.assertEqual(contours.read(self.cfg)['assignments'],{})
        with mock.patch.object(contours,'peer_addresses',return_value=([],[],{'peer'})), mock.patch.object(apply,'verify_for',return_value={'ok':True}), mock.patch.object(contours,'_run',return_value=(0,'active')), mock.patch.object(contours,'verify_dns',return_value=True), mock.patch.object(contours,'reconcile_network',side_effect=[contours.ContourError('failure'),None]):
            with self.assertRaises(contours.ContourError): contours.assign(self.cfg,'peer','2')
        self.assertEqual(contours.read(self.cfg)['assignments'],{})

    def test_network_has_own_mark_dns_and_guard_independent_of_mark(self):
        self.create()
        calls=[]
        def run(args, **kwargs):
            calls.append((args,kwargs))
            if args[:4]==['ip','-4','rule','show']: return 0,'101: from all fwmark 0x65 lookup 20101\n'
            if args[-2:]==['-S','REDUT_PREROUTING']:
                return 0,'-A REDUT_PREROUTING -d 10.77.0.0/24 -j RETURN\n-A REDUT_PREROUTING -j MARK --set-xmark 0x64/0xffffffff\n'
            if '-C' in args:return 1,''
            return 0,''
        with mock.patch.object(contours,'_run',side_effect=run), mock.patch.object(contours,'peer_addresses',return_value=(['10.77.0.2'],['2001:db8::2'],{'peer'})):
            contours.reconcile_network(self.cfg)
        commands=[x[0] for x in calls]
        self.assertIn(['ip','route','replace','unreachable','default','metric','32760','table',contours.TABLE],commands)
        data='\n'.join(x[1].get('data') or '' for x in calls)
        self.assertIn('MARK --set-mark 0x65',data)
        self.assertIn('--dport 53 -j REDIRECT --to-ports 5354',data)
        self.assertIn('src ! -o tun-redut-c2 -j REJECT',data)
        self.assertIn('redut_c2_peers6 src -j REJECT',data)
        self.assertNotIn(['conntrack','-F'],commands)
        self.assertIn(['conntrack','-D','-s','10.77.0.2','-p','udp','--dport','53'],commands)
        self.assertNotIn(['systemctl','restart','sing-box'],commands)

    def test_dns_rescue_blocks_conflicting_scope(self):
        self.create()
        registry=contours.read(self.cfg);registry['assignments']={'peer':'2'};contours.write(self.cfg,registry)
        with mock.patch.object(contours,'peer_addresses',return_value=(['10.77.0.2'],[],{'peer'})):
            self.assertTrue(contours.scope_conflicts(self.cfg,'all'))
            self.assertTrue(contours.scope_conflicts(self.cfg,'peer:10.77.0.2'))
            self.assertFalse(contours.scope_conflicts(self.cfg,'peer:10.77.0.3'))

    def test_unconfirmed_emergency_restores_intent(self):
        self.create();child=contours.config(self.cfg)
        with mock.patch.object(contours,'reconcile_network'),mock.patch.object(contours,'health',return_value={'route_ok':False}):
            self.assertFalse(contours.emergency(child,True))
        self.assertFalse(Path(child['emergency_intent']).exists())


class CacheAndIdentityTests(unittest.TestCase):
    def test_durable_cache_reuses_device_and_rate_limit_across_instances(self):
        with tempfile.TemporaryDirectory() as d:
            path=os.path.join(d,'cache.json')
            with mock.patch('providers.zenxnet.public_addresses',return_value=['1.1.1.1']), mock.patch('providers.zenxnet.fetch_subscription',return_value=(uri().encode(),{})) as fetch:
                a=ZenXNet(URL,HWID,path).list(); b=ZenXNet(URL,HWID,path).list()
                self.assertEqual(a,b);self.assertEqual(fetch.call_count,1)
                self.assertEqual(os.stat(path).st_mode & 0o777,0o600)
            os.unlink(path)
            with mock.patch('providers.zenxnet.fetch_subscription',side_effect=ProviderError('limit',kind='rate-limit',retry_after=3600)) as fetch:
                for _ in range(2):
                    with self.assertRaises(ProviderError): ZenXNet(URL,HWID,path).list()
                self.assertEqual(fetch.call_count,1)

    def test_same_host_different_ports_and_uuid_are_distinct_current_nodes(self):
        a=parse_node(uri()); b=parse_node(uri(port=8443)); c=parse_node(uri().replace(UUID,'22222222-2222-4222-8222-222222222222'))
        sb={'outbounds':[vless.outbound(a)]}
        self.assertTrue(apply.matches_current(a,a['host'],sb=sb))
        self.assertFalse(apply.matches_current(b,a['host'],sb=sb))
        self.assertFalse(apply.matches_current(c,a['host'],sb=sb))

    def test_rotation_keeps_other_endpoint_on_same_host(self):
        with tempfile.TemporaryDirectory() as d:
            db=pool.Pool(os.path.join(d,'state.db'))
            try:
                a=parse_node(uri());b=parse_node(uri(port=8443))
                first=db.upsert_proxy(a,role='auto');second=db.upsert_proxy(b,role='auto')
                path=os.path.join(d,'sb.json');apply.dump_json_replace({'outbounds':[vless.outbound(a)]},path)
                candidates=states.selectable_candidates(db,{'singbox_config':path},a['host'],{'zenxnet':object()})
                self.assertNotIn(first,[r['uid'] for r in candidates]);self.assertIn(second,[r['uid'] for r in candidates])
            finally: db.close()


if __name__=='__main__': unittest.main()

class AuditRegressionTests(LifecycleFixture):
    def test_recovery_recreate_reopens_panel_database(self):
        from types import SimpleNamespace
        from webpanel.contour_ui import Apps
        self.create()
        main = SimpleNamespace(cfg=self.cfg, secrets=self.secrets)
        def factory(cfg, primary):
            return SimpleNamespace(cfg=cfg, pool=pool.Pool(cfg['db']))
        apps=Apps(main, factory)
        token=contours.CURRENT.set('2')
        try:
            old=apps.selected();old.pool.set_setting('marker','old')
            with mock.patch.object(contours,'_run',return_value=(0,'')):
                contours.delete(self.cfg)
            self.create()
            new=apps.selected()
            self.assertIsNot(new,old)
            self.assertIsNone(new.pool.get_setting('marker'))
            new.pool.close()
        finally: contours.CURRENT.reset(token)

    def test_secondary_client_crud_respects_primary_dns_ownership(self):
        from webpanel import clients
        self.create()
        primary=pool.Pool(self.cfg['db']);self.addCleanup(primary.close)
        child=contours.config(self.cfg)
        # Use a secondary caller with an idle pool; the shared guard must still
        # check primary ownership before reusing any WireGuard address.
        idle=mock.Mock();idle.dns_state.return_value={'phase':'idle'}
        with mock.patch.object(contours,'main_config',return_value=self.cfg), mock.patch.object(pool,'Pool',return_value=primary), mock.patch.object(primary,'dns_state',return_value={'phase':'active','active_scope':'peer:10.77.0.2'}):
            with self.assertRaises(clients.ClientError):
                clients._dns_membership_guard(child,idle)
        idle.dns_state.assert_not_called()

    def test_manual_pin_survives_catalog_credentials_change_but_detects_external_apply(self):
        db=pool.Pool(self.cfg['db']);self.addCleanup(db.close)
        row=parse_node(uri());uid=db.upsert_proxy(row)
        live={'outbounds':[vless.outbound(row)]}
        apply.dump_json_replace(live,self.cfg['singbox_config'])
        states.set_manual_selection(db,uid,row['host'],cfg=self.cfg)
        revised=parse_node(uri().replace(UUID,'22222222-2222-4222-8222-222222222222'))
        self.assertEqual(uid,db.upsert_proxy(revised))
        self.assertTrue(states.selection_state(db,self.cfg,row['host'])['is_current'])
        apply.dump_json_replace({'outbounds':[vless.outbound(revised)]},self.cfg['singbox_config'])
        self.assertFalse(states.selection_state(db,self.cfg,row['host'])['is_current'])

    def test_update_detects_lost_contour_service_and_membership(self):
        import update
        self.create()
        with mock.patch.object(update,'_is_active',return_value=True), mock.patch.object(contours,'health',return_value={'ok':True}), mock.patch.object(contours,'verify_dns',return_value=True):
            before=update._contour_update_state(self.cfg)
        with mock.patch.object(update,'_is_active',side_effect=lambda u:u!=contours.SERVICE), mock.patch.object(contours,'health',return_value={'ok':False}), mock.patch.object(contours,'verify_dns',return_value=False):
            self.assertFalse(update._verify_contour(self.cfg,before)[0])
        registry=contours.read(self.cfg);registry['assignments']={'peer':'2'};contours.write(self.cfg,registry)
        with mock.patch.object(update,'_is_active',return_value=True), mock.patch.object(contours,'health',return_value={'ok':True}), mock.patch.object(contours,'verify_dns',return_value=True):
            ok,why=update._verify_contour(self.cfg,before)
            self.assertFalse(ok);self.assertIn('assignments',why)

class GuardLockTests(unittest.TestCase):
    def test_busy_systemd_unit_requires_installed_guard_proof(self):
        with mock.patch.object(contours,'boot_guard',side_effect=apply.LockBusy('busy')), mock.patch.object(contours,'boot_guard_proven',return_value=True) as proof:
            contours.guard_service({})
            proof.assert_called_once()
        with mock.patch.object(contours,'boot_guard',side_effect=apply.LockBusy('busy')), mock.patch.object(contours,'boot_guard_proven',return_value=False):
            with self.assertRaises(contours.ContourError): contours.guard_service({})

    def test_missing_guard_never_passes_proof_for_assigned_peer(self):
        registry={'secondary':'ready','assignments':{'peer':'2'},'revision':1,'version':1}
        with mock.patch.object(contours,'read',return_value=registry), mock.patch.object(contours,'peer_addresses',return_value=(['10.77.0.2'],[],{'peer'})), mock.patch.object(contours,'_run',return_value=(1,'')):
            self.assertFalse(contours.boot_guard_proven({}))


class PanelEntrypointTests(unittest.TestCase):
    def test_request_scope_uses_running_entrypoint_not_second_import(self):
        from webpanel import contour_ui,server
        from types import SimpleNamespace
        app=contour_ui.Apps(SimpleNamespace(),None)
        namespace={"APP":app}
        exec("def endpoint(handler,path): return (200, {'selected': '2'})",namespace)
        endpoint=contour_ui.scope_handler(namespace["endpoint"])
        handler=SimpleNamespace(headers={"X-Redut-Contour":"2"},_json=lambda status,data:(status,data))
        with mock.patch.object(app,'selected'),mock.patch.object(server,'APP',None):
            status,result=endpoint(handler,'/api/pool')
        self.assertEqual(status,200);self.assertEqual(result['selected'],'2')


class IncompleteEmptyContourBootTests(LifecycleFixture):
    def interrupt_creation(self):
        child_config = contours.paths(self.cfg)["config"]
        save = apply.dump_json_replace

        def interrupted(value, path):
            if path == child_config:
                raise OSError("simulated power loss before child config")
            return save(value, path)

        with mock.patch.object(contours, "validate_resources"), \
                mock.patch.object(contours, "_run", return_value=(0, "")), \
                mock.patch.object(apply, "dump_json_replace", side_effect=interrupted):
            with self.assertRaises(OSError):
                contours.create(self.cfg, self.secrets)
        self.assertEqual(contours.read(self.cfg)["secondary"], "creating")
        self.assertFalse(Path(contours.paths(self.cfg)["singbox"]).exists())

    def test_boot_and_primary_reconcile_survive_interrupted_empty_creation(self):
        import dns_policy
        self.interrupt_creation()
        primary_before = Path(self.cfg["singbox_config"]).read_bytes()
        with mock.patch("webpanel.clients._wg0_text", return_value=""), \
                mock.patch("webpanel.clients._load_client_operation", return_value=None), \
                mock.patch.object(contours, "_run", return_value=(0, "")) as network:
            contours.boot_guard(self.cfg)
            rules = "\n".join(str(call.kwargs.get("data", "")) for call in network.call_args_list)
            self.assertIn("--dport 10802 -j REJECT", rules)
            self.assertNotIn("--dport 10802 -j ACCEPT", rules)
            with mock.patch.object(dns_policy, "reconcile") as primary_dns:
                contours.reconcile_network(self.cfg)
            primary_dns.assert_called_once_with(self.cfg, _locked=True)
        self.assertEqual(Path(self.cfg["singbox_config"]).read_bytes(), primary_before)
        self.assertEqual(contours.read(self.cfg)["secondary"], "creating")

    def test_boot_survives_deletion_after_child_directory_was_archived(self):
        self.create()
        registry = contours.read(self.cfg)
        registry["secondary"] = "deleting"
        contours.write(self.cfg, registry)
        child_dir = Path(contours.paths(self.cfg)["config"]).parent
        child_dir.rename(child_dir.with_name("2.deleted-test"))
        with mock.patch("webpanel.clients._wg0_text", return_value=""), \
                mock.patch("webpanel.clients._load_client_operation", return_value=None), \
                mock.patch.object(contours, "_run", return_value=(0, "")):
            contours.boot_guard(self.cfg)
            contours.reconcile_network(self.cfg)
        self.assertEqual(contours.read(self.cfg)["secondary"], "deleting")

    def test_missing_child_policy_is_not_ignored_for_assigned_or_pending_peers(self):
        self.interrupt_creation()
        for pending in (False, True):
            with self.subTest(pending=pending):
                registry = contours.read(self.cfg)
                registry["assignments"] = {} if pending else {"protected-peer": "2"}
                contours.write(self.cfg, registry)
                operation = ({"kind": "add", "contour": "2", "pubkey": "protected-peer",
                              "address": "10.77.0.9"} if pending else None)
                peers = "" if pending else "[Peer]\nPublicKey = protected-peer\nAllowedIPs = 10.77.0.9/32\n"
                with mock.patch("webpanel.clients._wg0_text", return_value=peers), \
                        mock.patch("webpanel.clients._load_client_operation", return_value=operation), \
                        mock.patch.object(contours, "_run", return_value=(0, "")):
                    with self.assertRaises(FileNotFoundError):
                        contours.boot_guard(self.cfg)
                    with self.assertRaises(contours.ContourError):
                        contours.reconcile_network(self.cfg)
