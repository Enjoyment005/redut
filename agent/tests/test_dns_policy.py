"""DNS ownership, durable rollback, and client isolation across routing domains."""
import copy
import json
from pathlib import Path
import socket
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import _ctx
import apply
import config_schema
import contours
import dns_policy as dns
import pool


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        raw = dict(server='test', role='test', subnet='10.77.0.0/24', wan='eth0', gw='192.0.2.1',
                   db=str(self.root/'state.db'), singbox_config=str(self.root/'sing-box.json'),
                   ring=str(self.root/'cfg'), lock=str(self.root/'lock'))
        self.cfg = config_schema.normalize(raw, source=str(self.root/'config.json'))
        self.cfg['_test_unit_dir'] = str(self.root/'units')
        self.cfg['emergency_intent'] = str(self.root/'emergency')
        self.cfg['emergency_flag'] = str(self.root/'emergency-flag')
        self.sb = _ctx.fixture('singbox_config_reference.json')
        # Current runtime schema, independent of older saved backup fixtures.
        from singbox_config import migrate
        self.sb = migrate(self.sb)
        apply.dump_json_replace(self.sb, self.cfg['singbox_config'])
        self.db = pool.Pool(self.cfg['db'])
        self.addCleanup(self.db.close)
        patch = mock.patch.object(dns, '_whitelist_lines', return_value=['ipset=/vk.com/ru_whitelist\n'])
        patch.start(); self.addCleanup(patch.stop)

    def runtime(self):
        stack = __import__('contextlib').ExitStack()
        stack.enter_context(mock.patch.object(apply, 'singbox_check', return_value=(0, '')))
        stack.enter_context(mock.patch.object(dns, '_restart'))
        stack.enter_context(mock.patch.object(dns, 'ensure_boot_guard'))
        stack.enter_context(mock.patch.object(dns, 'reconcile'))
        stack.enter_context(mock.patch.object(dns, 'verify', return_value=True))
        return stack


class ConfigTests(Fixture):
    def test_names_follow_proxy_without_changing_exits_or_routing(self):
        before = copy.deepcopy(self.sb)
        result = dns.prepare(self.cfg, self.sb, 'provider')
        self.assertEqual(self.sb, before)
        self.assertEqual(result['outbounds'], before['outbounds'])
        self.assertEqual(result['route']['rules'][1:], before['route']['rules'])
        self.assertEqual(result['route']['default_domain_resolver'], 'proxy-dns')
        self.assertEqual(dns.mode(result), 'provider')
        self.assertEqual(next(s for s in result['dns']['servers'] if s['tag']=='proxy-dns')['detour'], 'socks-out')

    def test_scoped_ranges_cache_and_cloudflare_roundtrip(self):
        a = dns.prepare(self.cfg, self.sb, 'provider')
        child = dict(self.cfg, contour_id='2', db=str(self.root/'second/state.db'))
        b = dns.prepare(child, a, 'cloudflare')
        self.assertNotEqual(a['experimental']['cache_file']['path'], b['experimental']['cache_file']['path'])
        self.assertNotEqual(a['dns']['servers'][-1]['inet4_range'], b['dns']['servers'][-1]['inet4_range'])
        self.assertNotIn(dns.PRIMARY_INBOUND, [r.get('inbound') for r in b['route']['rules']])
        off = dns.prepare(self.cfg, a, 'cloudflare')
        self.assertEqual(off['experimental']['cache_file'], a['experimental']['cache_file'])
        self.assertTrue(off['experimental']['cache_file']['store_fakeip'])
        self.assertFalse(off['dns']['rules'])
        self.assertEqual(dns.prepare(self.cfg, off, 'provider'), a)

    def test_ru_and_owned_canary_names_never_become_bypass_fakeips(self):
        self.cfg['dns_rescue']['canary_qname_suffix'] = 'owned.example'
        result = dns.prepare(self.cfg, self.sb, 'provider')
        excluded = result['dns']['rules'][-1]['rules'][1]
        self.assertTrue(excluded['invert'])
        self.assertTrue({'ru','su','xn--p1ai','vk.com','owned.example'} <= set(excluded['domain_suffix']))
        with mock.patch.object(dns, '_whitelist_lines', return_value=[
                'ipset=/vk.com/ru_whitelist\n', 'ipset=/new-site.com/ru_whitelist\n',
                'ipset=/news.ru/ru_whitelist\n']):
            self.assertEqual(dns.whitelist_text(result), 'ipset=/vk.com/ru_whitelist\nipset=/news.ru/ru_whitelist\n')

    def test_unknown_rules_are_rejected_without_modification(self):
        self.sb['dns']['rules'] = [{'domain_suffix':['example.com'], 'server':'custom'}]
        before = copy.deepcopy(self.sb)
        with self.assertRaises(dns.DNSPolicyError): dns.prepare(self.cfg, self.sb, 'provider')
        self.assertEqual(before, self.sb)

    def test_rotation_preserves_policy_cache_and_names(self):
        selected = dns.prepare(self.cfg, self.sb, 'provider')
        apply.dump_json_replace(selected, self.cfg['singbox_config'])
        row = {'host':'203.0.113.7', 'port_http':8080, 'port_socks5':1080}
        out = [{'type':'socks','tag':'socks-out','server':row['host'],'server_port':1080},
               {'type':'http','tag':'http-tg','server':row['host'],'server_port':8080}]
        with mock.patch.object(apply, 'candidate_outbounds', return_value=(*out,False)):
            stage, new, *_ = apply.stage_candidate(self.cfg, row, {})
        Path(stage).unlink()
        self.assertEqual(new['dns'], selected['dns'])
        self.assertEqual(new['experimental'], selected['experimental'])
        self.assertEqual(apply.current_upstream(new), row['host'])


class TransactionTests(Fixture):
    def test_boot_dependency_precedes_publication_even_if_process_is_interrupted(self):
        original_guard=dns.ensure_boot_guard
        def restart(cfg):
            unit=Path(cfg['_test_unit_dir'])/(dns.GUARD_SERVICE+'.service')
            dropin=Path(cfg['_test_unit_dir'])/'wg-quick@wg0.service.d/40-redut-dns.conf'
            self.assertTrue(unit.exists() and dropin.exists())
            self.assertTrue(dns.managed(apply.load_json(cfg['singbox_config'])))
            raise KeyboardInterrupt('power loss after config replacement')
        with self.runtime(), mock.patch.object(dns,'ensure_boot_guard',side_effect=original_guard), \
                mock.patch.object(contours,'_run',return_value=(0,'')), \
                mock.patch.object(dns,'_restart',side_effect=restart):
            with self.assertRaises(KeyboardInterrupt):dns.change(self.cfg,self.db,'provider')
        self.assertEqual(self.db.unfinished_operations()[0]['phase'],'applied')

    def test_commit_preserves_selection_settings(self):
        self.db.set_setting('selection_mode','manual')
        with self.runtime(): result=dns.change(self.cfg,self.db,'provider')
        self.assertTrue(result['ok'])
        self.assertEqual(self.db.get_setting('selection_mode'),'manual')
        self.assertFalse(self.db.unfinished_operations())
        self.assertEqual(dns.mode(apply.load_json(self.cfg['singbox_config'])),'provider')

    def test_dry_run_and_failed_validation_never_touch_live_or_journal(self):
        before=Path(self.cfg['singbox_config']).read_bytes()
        with self.runtime(): self.assertTrue(dns.change(self.cfg,self.db,'provider',True)['dry_run'])
        with self.runtime(), mock.patch.object(apply,'singbox_check',return_value=(1,'sensitive config')):
            with self.assertRaisesRegex(dns.DNSPolicyError,'Ядро отклонило'):
                dns.change(self.cfg,self.db,'provider')
        self.assertEqual(Path(self.cfg['singbox_config']).read_bytes(),before)
        self.assertFalse(self.db.unfinished_operations())
        self.assertFalse(list(self.root.glob('*.dns-*')))

    def test_probe_failure_restores_exact_bytes_and_finishes_rollback(self):
        before=Path(self.cfg['singbox_config']).read_bytes()
        with self.runtime(), mock.patch.object(dns,'verify',side_effect=[False,True]):
            with self.assertRaisesRegex(dns.DNSPolicyError,'не прошли проверку'):
                dns.change(self.cfg,self.db,'provider')
        self.assertEqual(Path(self.cfg['singbox_config']).read_bytes(),before)
        self.assertEqual(self.db.conn.execute('select phase from operation').fetchone()[0],'rolled_back')

    def test_restart_failure_reverts_and_restarts_previous_mode(self):
        before=Path(self.cfg['singbox_config']).read_bytes()
        with self.runtime(), mock.patch.object(dns,'_restart',side_effect=[OSError('failed'),None]) as restart:
            with self.assertRaises(OSError): dns.change(self.cfg,self.db,'provider')
        self.assertEqual(restart.call_count,2)
        self.assertEqual(Path(self.cfg['singbox_config']).read_bytes(),before)
        self.assertFalse(self.db.unfinished_operations())

    def pending(self):
        before=apply.file_checksum(self.cfg['singbox_config'])
        apply.backup_ring(self.cfg['singbox_config'],self.cfg['ring'])
        op=self.db.begin_operation('dns-policy','user',{'mode':'provider'},'test',before_checksum=before)
        apply.dump_json_replace(dns.prepare(self.cfg,self.sb,'provider'),self.cfg['singbox_config'])
        self.db.transition_operation(op['id'],'staged',after_checksum=apply.file_checksum(self.cfg['singbox_config']))
        return self.db.get_operation(operation_id=op['id'])

    def test_interruption_after_replace_recovers_through_normal_startup_dispatch(self):
        before=Path(self.cfg['singbox_config']).read_bytes();self.pending()
        with self.runtime(): result=apply.recover_unfinished_operations(self.cfg,self.db)
        self.assertEqual(result[0]['action'],'rolled_back')
        self.assertEqual(Path(self.cfg['singbox_config']).read_bytes(),before)

    def test_failed_rollback_remains_pending_until_verification_passes(self):
        self.pending()
        with self.runtime(), mock.patch.object(dns,'verify',return_value=False):
            first=apply.recover_unfinished_operations(self.cfg,self.db)
        self.assertEqual(first[0]['action'],'deferred')
        self.assertTrue(self.db.unfinished_operations())
        with self.runtime(): second=apply.recover_unfinished_operations(self.cfg,self.db)
        self.assertEqual(second[0]['action'],'rolled_back')
        self.assertFalse(self.db.unfinished_operations())

    def test_third_configuration_is_never_replaced(self):
        self.pending();other=copy.deepcopy(self.sb);other['log']={'level':'warn'}
        apply.dump_json_replace(other,self.cfg['singbox_config'])
        before=Path(self.cfg['singbox_config']).read_bytes()
        with self.runtime(),mock.patch.object(dns,'_restart') as restart:
            result=apply.recover_unfinished_operations(self.cfg,self.db)
        self.assertEqual(result[0]['action'],'superseded');restart.assert_not_called()
        self.assertEqual(Path(self.cfg['singbox_config']).read_bytes(),before)

    def test_pending_operation_and_emergency_block_new_mutations(self):
        self.pending()
        with self.runtime():
            with self.assertRaisesRegex(dns.DNSPolicyError,'Другая операция'):
                dns.change(self.cfg,self.db,'cloudflare')
        Path(self.cfg['emergency_intent']).touch()
        with self.runtime():
            with self.assertRaisesRegex(dns.DNSPolicyError,'аварийный'):
                dns.change(self.cfg,self.db,'cloudflare')

    def test_rescue_and_lock_block_dns_change(self):
        with self.runtime(), mock.patch.object(self.db,'dns_state',return_value={'active_scope':'all'}):
            with self.assertRaisesRegex(dns.DNSPolicyError,'DNS Rescue'): dns.change(self.cfg,self.db,'provider')
        with apply.Flock(self.cfg['lock']),self.runtime():
            with self.assertRaises(apply.LockBusy): dns.change(self.cfg,self.db,'provider')


class GatewayTests(Fixture):
    def test_unmigrated_primary_is_untouched(self):
        with mock.patch.object(contours,'_run') as command: dns.reconcile(self.cfg)
        command.assert_not_called()
        self.assertEqual(dns.status(self.cfg)['mode'],'legacy')

    def test_primary_only_intercepts_primary_wg_and_keeps_host_dns_separate(self):
        apply.dump_json_replace(dns.prepare(self.cfg,self.sb,'provider'),self.cfg['singbox_config'])
        with mock.patch.object(contours,'read',return_value={'secondary':'ready'}), \
                mock.patch.object(contours,'_run',return_value=(0,'')), \
                mock.patch.object(contours,'_chain') as chain,mock.patch.object(contours,'_hook'):
            dns.reconcile(self.cfg)
        rules={c.args[1]:c.args[2] for c in chain.call_args_list}
        self.assertEqual(rules['REDUT_C1_DNS'][0],'-m set --match-set redut_c2_peers src -j RETURN')
        self.assertIn('-i wg0 -s 10.77.0.0/24 -p udp --dport 53 -j REDIRECT --to-ports 5352',rules['REDUT_C1_DNS'])
        self.assertTrue(any('! --match-set redut_c2_peers src' in r and '-j ACCEPT' in r for r in rules['REDUT_C1_DNS_ACL']))
        self.assertIn('-p udp --dport 5352 -j REJECT',rules['REDUT_C1_DNS_ACL'])
        text=(self.root/'dns-primary.conf').read_text()
        self.assertIn('server=127.0.0.1#5353',text)
        self.assertNotIn('listen-address=127.',text)

    def test_prepared_guard_is_removed_when_config_publication_never_happened(self):
        with mock.patch.object(contours,'_run',return_value=(0,'')):
            dns.ensure_boot_guard(self.cfg)
            self.assertFalse((self.root/'dns-primary.conf').exists())
            dns.reconcile(self.cfg)
        self.assertFalse((self.root/'units/wg-quick@wg0.service.d/40-redut-dns.conf').exists())
        self.assertFalse((self.root/'units'/(dns.GUARD_SERVICE+'.service')).exists())

    def test_restoring_old_config_disables_gateway_and_interception(self):
        (self.root/'dns-primary.conf').write_text('old')
        with mock.patch.object(contours,'_run',return_value=(0,'')) as command, \
                mock.patch.object(contours,'_chain') as chain,mock.patch.object(contours,'_hook'):
            dns.reconcile(self.cfg)
        self.assertTrue(all(not c.args[2] for c in chain.call_args_list))
        command.assert_any_call(['systemctl','disable','--now',dns.PRIMARY_SERVICE],allow_failure=True)
        self.assertFalse((self.root/'dns-primary.conf').exists())

    def test_secondary_gateway_stays_stopped_until_new_rules_are_written(self):
        child=dict(self.cfg,contour_id='2');order=[]
        with mock.patch.object(apply,'run_cmd',side_effect=lambda args,**kw:order.append(args) or (0,'')), \
                mock.patch.object(contours,'main_config',return_value=self.cfg), \
                mock.patch.object(contours,'sync_dns',side_effect=lambda *a,**k:order.append('sync')):
            self.assertTrue(apply.restart_for(child))
        self.assertEqual(order,[['systemctl','stop',contours.DNS_SERVICE],
                                ['systemctl','restart',contours.SERVICE],'sync',
                                ['systemctl','start',contours.DNS_SERVICE]])

    def test_primary_gateway_never_runs_old_rules_against_new_core(self):
        (self.root/'dns-primary.conf').write_text('old ipset rules')
        order=[]
        with mock.patch.object(apply,'run_cmd',side_effect=lambda args,**kw:order.append(args) or (0,'')), \
                mock.patch.object(apply,'restart_singbox',side_effect=lambda:order.append('core') or True), \
                mock.patch.object(dns,'reconcile',side_effect=lambda *a,**k:order.append('new gateway')):
            self.assertTrue(apply.restart_for(self.cfg))
        self.assertEqual(order,[['systemctl','stop',dns.PRIMARY_SERVICE],'core','new gateway'])

    def test_gateway_stop_failure_does_not_start_new_core(self):
        with mock.patch.object(apply,'run_cmd',return_value=(1,'')) as run:
            self.assertFalse(apply.restart_for(dict(self.cfg,contour_id='2')))
        run.assert_called_once_with(['systemctl','stop',contours.DNS_SERVICE],timeout=30)

    def test_emergency_transitions_synchronously_change_primary_dns(self):
        import states
        apply.dump_json_replace(dns.prepare(self.cfg,self.sb,'provider'),self.cfg['singbox_config'])
        with mock.patch.object(apply,'run_cmd',return_value=(0,'')), \
                mock.patch.object(states,'_middleman_default_matches',return_value=True), \
                mock.patch.object(contours,'_run',return_value=(0,'')):
            self.assertTrue(states.emergency_on(self.cfg,log=lambda _:None))
            self.assertIn('server=1.1.1.1',(self.root/'dns-primary.conf').read_text())
            self.assertTrue(states.emergency_off(self.cfg,log=lambda _:None))
            self.assertIn('server=127.0.0.1#5353',(self.root/'dns-primary.conf').read_text())
        self.assertFalse(Path(self.cfg['emergency_intent']).exists())

    def test_failed_emergency_dns_exit_keeps_direct_intent_and_compensates(self):
        import states
        Path(self.cfg['emergency_intent']).write_text('direct')
        with mock.patch.object(apply,'run_cmd',return_value=(0,'')), \
                mock.patch.object(states,'_middleman_default_matches',return_value=True), \
                mock.patch.object(dns,'sync_emergency',side_effect=[OSError('failure'),None]) as sync:
            self.assertFalse(states.emergency_off(self.cfg,log=lambda _:None))
        self.assertEqual([c.args[1] for c in sync.call_args_list],[False,True])
        self.assertTrue(Path(self.cfg['emergency_intent']).exists())

    def test_boot_guard_protects_primary_before_services_and_requires_physical_proof(self):
        apply.dump_json_replace(dns.prepare(self.cfg,self.sb,'provider'),self.cfg['singbox_config'])
        with mock.patch.object(contours,'_chain') as chain, mock.patch.object(contours,'_hook'), \
                mock.patch.object(contours,'_run',return_value=(0,'')) as run:
            dns.boot_guard(self.cfg)
            self.assertTrue(dns.boot_guard_proven(self.cfg))
            self.assertFalse(any(c.args[0][0]=='systemctl' for c in run.call_args_list))
        self.assertTrue(any(c.args[1]=='REDUT_C1_DNS' for c in chain.call_args_list))
        with mock.patch.object(contours,'_run',return_value=(1,'')):
            self.assertFalse(dns.boot_guard_proven(self.cfg))

    def test_deleting_secondary_removes_primary_references_to_its_set(self):
        with mock.patch.object(contours,'read',return_value={'secondary':'deleting'}):
            rules=dns.primary_rules(self.cfg,True)
        self.assertNotIn(contours.SET,str(rules))

    def test_dns_conntrack_flush_is_scoped_to_selected_peer(self):
        from webpanel import clients
        peers=[{'pubkey':'main','allowed_ips_lines':['10.77.0.2/32']},
               {'pubkey':'second','allowed_ips_lines':['10.77.0.3/32']}]
        with mock.patch.object(contours,'read',return_value={'assignments':{'second':'2'}}), \
                mock.patch.object(clients,'_wg0_text',return_value=''), \
                mock.patch.object(clients,'_parse_peers',return_value=peers), \
                mock.patch.object(contours,'_run',return_value=(0,'')) as run:
            dns.flush_client_dns(self.cfg)
        self.assertEqual(run.call_count,2)
        self.assertTrue(all('10.77.0.2' in c.args[0] and '53' in c.args[0] for c in run.call_args_list))

    def test_both_dns_transports_and_real_connection_are_required(self):
        apply.dump_json_replace(dns.prepare(self.cfg,self.sb,'provider'),self.cfg['singbox_config'])
        with mock.patch.object(dns,'resolve',return_value=['198.19.0.5']) as query, \
                mock.patch.object(apply,'run_cmd',return_value=(0,'8.8.8.8')) as http:
            self.assertTrue(dns.verify(self.cfg))
        self.assertEqual([c.args[2] for c in query.call_args_list],['udp','tcp'])
        self.assertIn('api.ipify.org:443:198.19.0.5',http.call_args.args[0])
        with mock.patch.object(dns,'resolve',return_value=['198.19.128.5']),mock.patch.object(apply,'run_cmd') as http:
            self.assertFalse(dns.verify(self.cfg))
            http.assert_not_called()


class ApiTests(Fixture):
    def handler(self,body):
        handler=mock.Mock();handler.headers={};handler._body.return_value=json.dumps(body).encode()
        handler._json.side_effect=lambda status,payload:(status,payload)
        return handler

    def test_api_rejects_unknown_mode_without_runner(self):
        from webpanel import server
        app=SimpleNamespace(cfg=self.cfg,pool=self.db)
        with mock.patch.object(server,'APP',app),mock.patch.object(server,'_run_agent') as runner:
            status,_=server.Handler._api_post(self.handler({'mode':'https://secret.example'}),'/api/dns-policy')
        self.assertEqual(status,400);runner.assert_not_called()

    def test_post_never_reports_success_if_selected_mode_did_not_apply(self):
        from webpanel import server
        app=SimpleNamespace(cfg=self.cfg,pool=self.db)
        with mock.patch.object(server,'APP',app),mock.patch.object(server,'_run_agent',return_value=(0,'{}')):
            status,data=server.Handler._api_post(self.handler({'mode':'provider'}),'/api/dns-policy')
        self.assertEqual(status,409);self.assertFalse(data['ok'])
        self.assertEqual(data['mode'],'legacy')


if __name__=='__main__': unittest.main()
