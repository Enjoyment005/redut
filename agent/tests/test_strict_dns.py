"""Strict provider policy must not silently acquire a resolver or another exit."""
import copy
from pathlib import Path
from unittest import mock

import _ctx
import apply
import contours
import dns_policy as dns
from test_dns_policy import Fixture


class StrictPolicyTests(Fixture):
    def setUp(self):
        super().setUp()
        self.cfg['contour_id'] = '2'
        ready=mock.patch.object(contours,'ensure_ready');ready.start();self.addCleanup(ready.stop)
        self.sb['inbounds'].append({'type':'direct','tag':'c2-dns','listen':'127.0.0.1',
                                   'listen_port':5355,'override_address':'1.1.1.1','override_port':53})

    def prepared(self):
        return dns.prepare(self.cfg, self.sb, 'provider_strict')

    def test_all_names_use_remote_resolution_without_recursive_fallback(self):
        old = copy.deepcopy(self.sb)
        sb = self.prepared()
        self.assertEqual(self.sb, old)
        self.assertTrue(dns.strict(sb))
        self.assertEqual(dns.mode(sb), 'provider_strict')
        self.assertEqual([s['type'] for s in sb['dns']['servers']], ['fakeip', 'hosts'])
        self.assertEqual(sb['dns']['rules'], [dns.EMPTY_RECORDS,
            {'query_type':'A','action':'route','server':dns.FAKE,'rewrite_ttl':60},dns.REFUSED_RECORDS])
        self.assertEqual(dns.whitelist_text(sb), '')
        self.assertNotIn('default_domain_resolver', sb['route'])
        self.assertEqual(sb['route']['final'], 'socks-out')
        self.assertFalse(any(o['type']=='direct' for o in sb['outbounds']))

    def test_proxy_is_bound_to_wg_gateway_and_does_not_change_transport(self):
        sb = self.prepared()
        self.assertEqual(sb['outbounds'], self.sb['outbounds'])
        self.assertEqual(sb['inbounds'][-1], {'type':'mixed','tag':dns.STRICT_PROXY_TAG,
                         'listen':'10.77.0.1','listen_port':10802})
        self.assertEqual(dns.prepare(self.cfg,sb,'provider_strict'), sb)
        normal = dns.prepare(self.cfg,sb,'provider')
        self.assertFalse(dns.strict(normal))
        self.assertNotIn(dns.STRICT_PROXY_TAG, [i['tag'] for i in normal['inbounds']])
        self.assertIn('proxy-dns',[s['tag'] for s in normal['dns']['servers']])

    def test_unpinned_host_and_custom_routes_are_rejected(self):
        for mutate in (lambda s:s['outbounds'][0].update(server='endpoint.example'),
                       lambda s:s['route']['rules'].append({'outbound':'redut-direct'}),
                       lambda s:s['route']['rules'].insert(0,{'action':'resolve'})):
            with self.subTest(mutate=mutate):
                sb=copy.deepcopy(self.sb); mutate(sb)
                with self.assertRaises(dns.DNSPolicyError): dns.prepare(self.cfg,sb,'provider_strict')

    def test_cli_exposes_strict_mode_before_loading_live_config(self):
        import subprocess, sys
        import agent
        result=subprocess.run([sys.executable, agent.__file__, 'dns-policy', '--help'],
                              capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0)
        self.assertIn('provider_strict',result.stdout)

    def test_policy_changes_keep_existing_manual_connection_fingerprint(self):
        import states
        for ob in self.sb['outbounds']: ob['domain_resolver']='redut-bootstrap'
        self.sb['outbounds'].append({'type':'direct','tag':'redut-direct'})
        self.sb['dns']['servers'].append({'type':'udp','tag':'redut-bootstrap',
                                         'server':'9.9.9.9','detour':'redut-direct'})
        apply.dump_json_replace(self.sb,self.cfg['singbox_config'])
        before=apply.outbound_fingerprint(self.sb['outbounds'])
        self.db.set_setting('selection_mode','manual')
        self.db.set_setting('manual_host',apply.current_upstream(self.sb))
        self.db.set_setting('manual_uid','test:1')
        self.db.set_setting('manual_outbound_fingerprint',before)
        with self.runtime(),mock.patch.object(contours,'strict_transition_guard'):
            self.assertTrue(states.selection_state(self.db,self.cfg,apply.current_upstream(self.sb))['is_current'])
            dns.change(self.cfg,self.db,'provider_strict')
            self.assertTrue(states.selection_state(self.db,self.cfg,apply.current_upstream(self.sb))['is_current'])
            self.assertEqual(apply.outbound_fingerprint(apply.load_json(self.cfg['singbox_config'])['outbounds']),before)
            dns.change(self.cfg,self.db,'provider')
        self.assertEqual(self.db.get_setting('manual_outbound_fingerprint'),before)
        self.assertEqual(apply.outbound_fingerprint(apply.load_json(self.cfg['singbox_config'])['outbounds']),before)

    def test_primary_is_rejected(self):
        self.cfg.pop('contour_id')
        with self.assertRaisesRegex(dns.DNSPolicyError,'только во втором'):
            self.prepared()

    def test_old_ring_backup_cannot_downgrade_active_strict_policy(self):
        Path(self.cfg['ring']).mkdir()
        original=Path(self.cfg['ring'])/'old.json';apply.dump_json_replace(self.sb,str(original))
        before=original.read_bytes()
        apply.dump_json_replace(self.prepared(),self.cfg['singbox_config'])
        restored=apply.load_json(apply.compatible_backup(self.cfg,str(original)))
        self.assertTrue(dns.strict(restored))
        self.assertEqual(restored['outbounds'],self.prepared()['outbounds'])
        self.assertEqual(original.read_bytes(),before)

    def test_rotation_cannot_reintroduce_bootstrap_or_direct(self):
        selected=self.prepared();apply.dump_json_replace(selected,self.cfg['singbox_config'])
        outs=copy.deepcopy(selected['outbounds'])
        for ob in outs:
            ob['server']='203.0.113.7';ob['domain_resolver']='redut-bootstrap'
        with mock.patch.object(apply,'candidate_outbounds',return_value=(*outs,False)):
            stage,new,*_=apply.stage_candidate(self.cfg,{'host':'203.0.113.7','protocol':'vless'}, {})
        Path(stage).unlink()
        self.assertTrue(dns.strict(new))
        self.assertEqual(new['dns'],selected['dns'])
        self.assertFalse(any(o['type']=='direct' for o in new['outbounds']))
        self.assertTrue(all(o['domain_resolver']=='redut-bootstrap' for o in new['outbounds']))
        closed=next(s for s in new['dns']['servers'] if s['tag']=='redut-bootstrap')
        self.assertEqual(closed,{'type':'hosts','tag':'redut-bootstrap','path':['/dev/null']})

    def test_fail_closed_guard_precedes_config_publication(self):
        sequence=[]
        publish=apply.atomic_copy_replace
        def guarded(cfg):
            self.assertFalse(dns.strict(apply.load_json(cfg['singbox_config'])))
            sequence.append('guard')
        def replace(src,dst):
            if dst==self.cfg['singbox_config']:sequence.append('publish')
            publish(src,dst)
        with self.runtime(), mock.patch.object(contours,'strict_transition_guard',side_effect=guarded), \
                mock.patch.object(apply,'atomic_copy_replace',side_effect=replace):
            result=dns.change(self.cfg,self.db,'provider_strict')
        self.assertEqual(sequence[:2],['guard','publish'])
        self.assertTrue(result['strict'])
        self.assertEqual(result['proxy_endpoint'],'10.77.0.1:10802')

    def test_failed_activation_restores_exact_previous_policy(self):
        before=Path(self.cfg['singbox_config']).read_bytes()
        with self.runtime(), mock.patch.object(contours,'strict_transition_guard'), \
                mock.patch.object(dns,'verify',side_effect=[False,True]):
            with self.assertRaises(dns.DNSPolicyError):dns.change(self.cfg,self.db,'provider_strict')
        self.assertEqual(Path(self.cfg['singbox_config']).read_bytes(),before)
        self.assertFalse(self.db.unfinished_operations())

    def test_failed_exit_from_strict_closes_before_recovery_and_retry(self):
        strict=self.prepared();apply.dump_json_replace(strict,self.cfg['singbox_config'])
        events=[];state={'closed':False,'restarts':0}
        def close(cfg):state['closed']=True;events.append('close')
        def restart(cfg):
            state['restarts']+=1
            if state['restarts']==1:
                state['closed']=False;events.append('normal-open')
            else:
                self.assertTrue(state['closed'],'recovery was open before strict restart')
                self.assertTrue(dns.strict(apply.load_json(cfg['singbox_config'])))
                raise OSError('restart interrupted')
        with self.runtime(),mock.patch.object(contours,'strict_transition_guard',side_effect=close), \
                mock.patch.object(dns,'_restart',side_effect=restart),mock.patch.object(dns,'verify',return_value=False):
            with self.assertRaises(OSError):dns.change(self.cfg,self.db,'provider')
            self.assertEqual(events,['close','normal-open','close'])
            op=self.db.unfinished_operations()[0]
            with self.assertRaises(OSError):dns.recover(self.cfg,self.db,op)
            self.assertEqual(events[-1],'close')
        self.assertTrue(self.db.unfinished_operations())

    def test_historical_strict_rollback_recovery_closes_before_publish_and_restart(self):
        target=self.root/'strict-backup.json';apply.dump_json_replace(self.prepared(),str(target))
        before=apply.file_checksum(self.cfg['singbox_config'])
        op=self.db.begin_operation('rollback','user',{'backup':str(target)},'historical',before_checksum=before)
        self.db.transition_operation(op['id'],'staged',after_checksum=apply.file_checksum(str(target)))
        self.db.transition_operation(op['id'],'applied')
        events=[];original=apply.atomic_copy_replace
        def copy(src,dst):events.append('publish');original(src,dst)
        def close(cfg):events.append('close')
        with mock.patch.object(contours,'strict_transition_guard',side_effect=close), \
                mock.patch.object(apply,'atomic_copy_replace',side_effect=copy), \
                mock.patch.object(apply,'antiloop_replace'),mock.patch.object(apply,'patch_boot_script'), \
                mock.patch.object(apply,'restart_for',side_effect=OSError('interrupted')):
            with self.assertRaises(OSError):
                apply.recover_operation(self.cfg,self.db,self.db.get_operation(operation_id=op['id']))
            self.assertEqual(events[:2],['close','publish'])
            self.assertEqual(events[-1],'close')
            self.db.transition_operation(op['id'],'verifying');events.clear()
            with mock.patch.object(apply,'verify_for',return_value={'ok':True}) as verify:
                with self.assertRaises(OSError):
                    apply.recover_operation(self.cfg,self.db,self.db.get_operation(operation_id=op['id']))
                self.assertEqual(events,['close'])
                verify.assert_not_called()

    def test_recovery_restart_false_never_reconciles_a_stale_core(self):
        strict=self.prepared();apply.dump_json_replace(strict,self.cfg['singbox_config'])
        saved=apply.backup_ring(self.cfg['singbox_config'],self.cfg['ring'])
        checksum=apply.file_checksum(self.cfg['singbox_config'])
        op=self.db.begin_operation('apply','auto',{},'restart-false',before_checksum=checksum)
        self.db.transition_operation(op['id'],'staged',after_checksum=checksum)
        self.db.transition_operation(op['id'],'applied')
        operation=self.db.get_operation(operation_id=op['id'])
        for entry in ('restore','converge','target'):
            with self.subTest(entry=entry),mock.patch.object(contours,'strict_transition_guard') as guard, \
                    mock.patch.object(apply,'restart_for',return_value=False), \
                    mock.patch.object(apply,'wait_for') as wait,mock.patch.object(apply,'verify_for') as verify, \
                    mock.patch.object(apply,'antiloop_replace'),mock.patch.object(apply,'patch_boot_script'):
                if entry=='restore':
                    result=apply._restore_before(self.cfg,self.db,operation,None,lambda *_:None)
                elif entry=='converge':
                    result=apply._converge_before_side_effects(self.cfg,self.db,operation,None,lambda *_:None)
                else:
                    target=dict(operation,before_checksum='different')
                    result=apply.recover_operation(self.cfg,self.db,target,log=lambda *_:None)
                self.assertFalse(result['ok']);self.assertEqual(result['action'],'deferred')
                guard.assert_called_once();wait.assert_not_called();verify.assert_not_called()
