"""Automatic money flows with real journals and fake provider payments."""
from unittest import mock
import tempfile
import unittest

import _ctx
import states
import auto_purchase
import money
import pool
from providers import proxyline
from providers.proxywing import norm_proxywing
from providers.base import ProviderError
from test_proxyline_orders import FakeProxyLine
from test_proxywing_orders import FakeMonthly
from test_money import FakeProxy6
from test_auto_prolong import Base, _in


class TestExactRenewal(Base):
    def setUp(self):
        super().setUp()
        self.pool.conn.execute('UPDATE proxy SET port_socks5=1080')
        self.pool.conn.commit()
        self.outbound = {'outbounds': [{'tag': 'socks-out', 'type': 'socks',
            'server': '1.1.1.1', 'server_port': 1080}]}
        states.apply_mod.load_json = lambda path: self.outbound

    def test_shared_host_renews_only_exact_port(self):
        self.pool.conn.execute("UPDATE proxy SET host='1.1.1.1',port_socks5=2080 WHERE uid='proxy6:2'")
        self.pool.conn.commit()
        self.run_it()
        self.assertEqual(self.prov.calls, [('1', 30)])

    def test_ambiguous_endpoint_never_spends(self):
        self.pool.conn.execute("UPDATE proxy SET host='1.1.1.1' WHERE uid='proxy6:2'")
        self.pool.conn.commit()
        self.run_it()
        self.assertFalse(self.prov.calls)
        self.assertTrue(self.alerter.sent)

    def test_channel_changes_during_quote(self):
        original = self.prov.getprice
        def quote(*args):
            self.outbound['outbounds'][0]['server_port'] = 2080
            return original(*args)
        with mock.patch.object(self.prov, 'getprice', side_effect=quote):
            self.run_it()
        self.assertFalse(self.prov.calls)

    def test_unbound_old_job_does_not_renew_sick_current(self):
        states._begin_money_job(self.pool, 'money_request:auto-prolong:proxy6:1', {'uid':'proxy6:1','days':30})
        self.pool.conn.execute("UPDATE proxy SET probe_ok=0 WHERE uid='proxy6:1'")
        self.pool.conn.commit()
        self.run_it()
        self.assertFalse(self.prov.calls)

    def test_fresh_provider_expiry_prevents_early_renewal(self):
        with mock.patch.object(self.prov, 'list', return_value=[{'ext_id':'1',
                'date_end':_in(30), 'kind':'dedicated','ip_version':4}]):
            self.run_it()
        self.assertFalse(self.prov.calls)

    def test_purchase_switch_does_not_disable_enabled_renewal(self):
        self.cfg['money']['buy_enabled'] = False
        self.run_it()
        self.assertEqual(self.prov.calls, [('1', 30)])


class TestAutomaticPurchase(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.pool = pool.Pool(directory.name + '/state.db')
        self.addCleanup(self.pool.close)
        self.cfg = {'singbox_config':'unused', 'countries':{'strategy':'speed'},
                    'money':{'buy_enabled':True}}
        self.sb = {'outbounds':[]}
        patcher = mock.patch.object(states.apply_mod, 'load_json', side_effect=lambda _: self.sb)
        patcher.start(); self.addCleanup(patcher.stop)
        self.pl = FakeProxyLine()
        self.pl.rows = []
        patcher = mock.patch.object(proxyline, 'http_post_form', side_effect=self.pl.post)
        patcher.start(); self.addCleanup(patcher.stop)
        self.pw = FakeMonthly()
        fixture = _ctx.fixture('proxywing_proxies.json')['orders'][0]['proxies'][0]
        self.pw.rows = [dict(norm_proxywing(dict(fixture, id='ip_'+str(i)), {'id':'ord_1'}, 'datacenter'),
                             date_end=_in(30)) for i in (1, 2)]
        self.p6 = FakeProxy6()
        self.p6.getcountry = mock.Mock(return_value=['us'])
        self.p6.getcount = mock.Mock(return_value=1)

    def purchase(self, providers, key='money_request:reserve'):
        return auto_purchase.purchase(self.cfg, providers, self.pool, key, log=lambda _: None)

    def test_proxyline_only_buys_and_replays_without_another_charge(self):
        result, job, raw = self.purchase({'proxyline':self.pl})
        self.assertEqual(len(self.pl.calls), 1)
        self.assertEqual(result['period'], 10)
        self.assertEqual(result['proxies'][0]['provider'], 'proxyline')
        self.assertEqual(self.pool.get('proxyline:100')['role'], 'off')
        self.cfg['money']['buy_enabled'] = False
        replay, _, _ = self.purchase({'proxyline':self.pl})
        self.assertEqual(replay['spend_operation_id'], result['spend_operation_id'])
        self.assertEqual(len(self.pl.calls), 1)

    def test_proxywing_only_buys_and_imports_paid_package(self):
        result, _, _ = self.purchase({'proxywing':self.pw})
        self.assertEqual(len(self.pw.calls), 1)
        self.assertEqual(result['period'], '1 мес')
        self.assertEqual(len(result['proxies']), 2)
        self.assertEqual(self.pool.spent_today('USD'), 3)
        self.assertTrue(all(r['role'] == 'off' for r in self.pool.list()))

    def test_proxy6_uses_full_live_catalog(self):
        self.p6.getcountry.return_value = ['nz']
        result, _, _ = self.purchase({'proxy6':self.p6})
        self.assertEqual(result['country'], 'nz')
        self.assertEqual(self.p6.buy_calls, 1)
        self.p6.getcount.assert_called_with('nz', 4)

    def test_country_catalog_is_an_actual_filter(self):
        self.assertEqual(money.buy_candidates(self.cfg, []), [])
        self.assertEqual(money.buy_candidates(self.cfg, ['nz','nz']), ['nz'])

    def test_all_strategies_honor_country_gate_for_each_provider(self):
        for strategy in ('speed','balanced','reputation'):
            for name, provider in [('proxy6',self.p6),('proxyline',self.pl),('proxywing',self.pw)]:
                with self.subTest(strategy=strategy,provider=name):
                    self.cfg['countries']['strategy'] = strategy
                    offer = auto_purchase.offers(self.cfg, {name:provider}, self.pool, lambda _:None)
                    self.assertEqual(offer['provider'], name)
                    self.assertEqual(offer['country'], 'us')
                    self.cfg['countries']['blacklist'] = ['us']
                    with self.assertRaises(money.SpendDenied):
                        auto_purchase.offers(self.cfg, {name:provider}, self.pool, lambda _:None)
                    self.cfg['countries']['blacklist'] = []

    def test_reputation_filters_low_rated_sale_country_for_every_provider(self):
        self.p6.getcountry.return_value = ['ng']
        self.pl.countries = mock.Mock(return_value=[{'code':'ng'}])
        self.pw.catalog = mock.Mock(return_value=[dict(country='ng', family='isp', product_id='ng1',
                                                quantity=1, price_monthly=3)])
        for name, provider in [('proxy6',self.p6),('proxyline',self.pl),('proxywing',self.pw)]:
            for strategy in ('speed','balanced','reputation'):
                with self.subTest(provider=name,strategy=strategy):
                    self.cfg['countries']['strategy'] = strategy
                    if strategy == 'reputation':
                        with self.assertRaises(money.SpendDenied):
                            auto_purchase.offers(self.cfg, {name:provider}, self.pool, lambda _:None)
                    else:
                        self.assertEqual(auto_purchase.offers(self.cfg, {name:provider}, self.pool,
                                                              lambda _:None)['country'], 'ng')

    def test_unavailable_provider_does_not_hide_others_before_any_payment(self):
        self.p6.getcountry.side_effect = ProviderError('catalog offline')
        result, _, _ = self.purchase({'proxy6':self.p6,'proxyline':self.pl})
        self.assertEqual(result['provider'], 'proxyline')
        self.assertEqual(self.p6.buy_calls, 0)

    def test_lost_payment_never_buys_from_another_provider(self):
        self.pl.lost = True
        with self.assertRaises(ProviderError):
            self.purchase({'proxyline':self.pl})
        with self.assertRaises(money.SpendDenied):
            self.purchase({'proxyline':self.pl,'proxywing':self.pw})
        self.assertEqual(len(self.pl.calls), 1)
        self.assertFalse(self.pw.calls)
        self.assertEqual(self.pool.pending_spend_operations()[0]['phase'], 'submitted')

    def test_manual_selection_during_quote_cancels_purchase(self):
        original = self.pl.quote
        calls = 0
        def quote(*args):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.pool.set_setting('selection_mode', 'manual')
            return original(*args)
        with mock.patch.object(self.pl, 'quote', side_effect=quote):
            with self.assertRaises(money.SpendDenied):
                self.purchase({'proxyline':self.pl})
        self.assertFalse(self.pl.calls)
        self.assertIsNone(self.pool.get_setting('money_request:reserve'))

    def test_reserve_probe_promotes_only_verified_automatically_bought_proxy(self):
        with mock.patch.object(states, '_probe', return_value={'ok':True,'exit_cc':'us'}):
            result = states.ensure_reserve(self.cfg, {'proxyline':self.pl}, self.pool,
                                           mock.Mock(), lambda _:None, 'auto')
        self.assertTrue(result['bought'], result)
        self.assertEqual(result['uids'], ['proxyline:100'])
        self.assertEqual(self.pool.get('proxyline:100')['role'], 'auto')

    def test_failed_probe_keeps_automatic_purchase_off(self):
        with mock.patch.object(states, '_probe', return_value={'ok':False,'exit_cc':'us'}):
            result = states.ensure_reserve(self.cfg, {'proxywing':self.pw}, self.pool,
                                           mock.Mock(), lambda _:None, 'auto')
        self.assertTrue(result['bought'], result)
        self.assertFalse(result['ok'])
        self.assertTrue(all(r['role'] == 'off' for r in self.pool.list()))

    def test_paid_package_not_yet_visible_waits_without_repurchase(self):
        self.pw.rows = []
        with self.assertRaises(money.SpendDenied):
            self.purchase({'proxywing':self.pw})
        with self.assertRaises(money.SpendDenied):
            self.purchase({'proxywing':self.pw})
        self.assertEqual(len(self.pw.calls), 1)
        self.assertIsNotNone(self.pool.get_setting('money_request:reserve'))

    def test_planned_purchase_is_retired_if_reserve_appears(self):
        with mock.patch.object(self.pl, 'buy', side_effect=SystemExit('crash before submission')):
            with self.assertRaises(SystemExit):
                self.purchase({'proxyline':self.pl})
        op = self.pool.pending_spend_operations()[0]
        self.assertEqual(op['phase'], 'planned')
        with mock.patch.object(states, 'selectable_candidates', return_value=[{'uid':'spare'}]):
            with self.assertRaises(money.SpendDenied):
                self.purchase({'proxyline':self.pl})
        self.assertEqual(self.pool.get_spend_operation(op['id'])['phase'], 'failed')
        self.assertIsNone(self.pool.get_setting('money_request:reserve'))
        self.assertFalse(self.pl.calls)

    def test_strategy_revision_changed_during_catalog_prevents_payment(self):
        original = self.pl.countries
        def countries():
            self.pool.set_setting('desired_selection_revision', '2')
            return original()
        with mock.patch.object(self.pl, 'countries', side_effect=countries):
            with self.assertRaises(money.SpendDenied):
                self.purchase({'proxyline':self.pl})
        self.assertFalse(self.pl.calls)

    def test_daily_purchase_limit_applies_to_usd_providers(self):
        self.cfg['money']['max_buys_per_day'] = 0
        for name, provider in [('proxyline',self.pl),('proxywing',self.pw)]:
            with self.assertRaises(money.SpendDenied):
                self.purchase({name:provider})
        self.assertFalse(self.pl.calls or self.pw.calls)

    def test_smaller_package_is_preferred_in_same_country(self):
        self.pw.catalog = mock.Mock(return_value=[dict(country='us', family='isp',product_id='large',
            quantity=10,price_monthly=2),dict(country='us', family='isp',product_id='single',quantity=1,price_monthly=3)])
        self.assertEqual(auto_purchase.offers(self.cfg, {'proxywing':self.pw}, self.pool,
                                            lambda _:None)['product_id'], 'single')

    def test_replenish_uses_same_multi_provider_purchase_and_applies_only_after_probe(self):
        with mock.patch.object(states, '_probe', return_value={'ok':True,'exit_cc':'us'}), \
                mock.patch.object(states.apply_mod, 'apply_candidate', return_value={
                    'new_ip':'203.0.113.15','verify':{'egress_ip':'203.0.113.15','exit_cc':'us'}}) as apply, \
                mock.patch.object(states.apply_mod, 'commit_operation'):
            result = states.try_replenish(self.cfg, {'proxyline':self.pl}, self.pool,
                                         mock.Mock(), lambda _:None, 'auto')
        self.assertTrue(result['ok'], result)
        self.assertEqual(len(self.pl.calls), 1)
        self.assertEqual(apply.call_args.args[1]['provider'], 'proxyline')

    def test_legacy_paid_proxy6_job_replays_after_account_binding_upgrade(self):
        self.p6.api_key = 'fake-account-before-upgrade'
        key = 'money_request:reserve'
        job, raw = states._begin_money_job(self.pool, key, {'country':'us','period':7,'version':4})
        with mock.patch.object(money, '_account_identity', return_value={}):
            paid = money.plan_and_buy(self.pool, self.p6, self.cfg, country='us',period=7,
                                     request_id=job['request_id'])
        result, _, _ = self.purchase({'proxy6':self.p6})
        self.assertEqual(result['spend_operation_id'], paid['spend_operation_id'])
        self.assertEqual(self.p6.buy_calls, 1)

    def test_legacy_unsent_proxy6_job_can_be_replanned_after_upgrade(self):
        self.p6.api_key = 'fake-account-before-upgrade'
        key = 'money_request:reserve'
        job, _ = states._begin_money_job(self.pool, key, {'country':'us','period':7,'version':4})
        with mock.patch.object(money, '_account_identity', return_value={}), \
                mock.patch.object(self.p6, 'buy', side_effect=SystemExit('before HTTP')):
            with self.assertRaises(SystemExit):
                money.plan_and_buy(self.pool, self.p6, self.cfg, country='us',period=7,
                                   request_id=job['request_id'])
        with self.assertRaises(money.SpendDenied):
            self.purchase({'proxy6':self.p6})
        self.assertIsNone(self.pool.get_setting(key))
        self.assertTrue(self.purchase({'proxy6':self.p6})[0]['ok'])
        self.assertEqual(self.p6.buy_calls, 1)

    def test_proxy6_changed_account_never_reconciles_uncertain_payment(self):
        self.p6.api_key = 'fake-account-one'
        self.p6.buy_network_fail = True
        with self.assertRaises(money.SpendDenied):
            self.purchase({'proxy6':self.p6})
        self.p6.api_key = 'fake-account-two'
        previous_reads = self.p6.find_calls
        with self.assertRaises(money.SpendDenied):
            money.reconcile_pending_spend(self.pool, {'proxy6':self.p6})
        with self.assertRaises(money.SpendDenied):
            self.purchase({'proxy6':self.p6})
        self.assertEqual(self.p6.find_calls, previous_reads)
        self.assertEqual(self.p6.buy_calls, 1)

    def test_paid_replenish_never_overrides_new_manual_selection(self):
        self.purchase({'proxyline':self.pl}, 'money_request:replenish')
        self.pool.set_setting('selection_mode', 'manual')
        self.pool.set_setting('desired_selection_revision', '3')
        with mock.patch.object(states, '_probe', return_value={'ok':True,'exit_cc':'us'}), \
                mock.patch.object(states.apply_mod, 'apply_candidate') as apply:
            result = states.try_replenish(self.cfg, {'proxyline':self.pl}, self.pool,
                                         mock.Mock(), lambda _:None, 'auto')
        self.assertFalse(result['ok'])
        apply.assert_not_called()
        self.assertEqual(len(self.pl.calls), 1)
        self.assertIsNone(self.pool.get_setting('money_request:replenish'))
        self.assertEqual(self.pool.get('proxyline:100')['role'], 'auto')

    def test_strategy_change_keeps_paid_healthy_reserve_instead_of_buying_again(self):
        self.purchase({'proxyline':self.pl})
        self.cfg['countries']['strategy'] = 'balanced'
        self.pool.set_setting('desired_selection_revision', '2')
        with mock.patch.object(states, '_probe', return_value={'ok':True,'exit_cc':'us'}):
            first = states.ensure_reserve(self.cfg, {'proxyline':self.pl}, self.pool,
                                          mock.Mock(), lambda _:None, 'auto')
            second = states.ensure_reserve(self.cfg, {'proxyline':self.pl}, self.pool,
                                           mock.Mock(), lambda _:None, 'auto')
        self.assertTrue(first['ok'], first)
        self.assertFalse(second['bought'], second)
        self.assertEqual(len(self.pl.calls), 1)
        self.assertEqual(self.pool.get('proxyline:100')['role'], 'auto')

    def test_paid_replenish_honors_new_blacklist(self):
        self.purchase({'proxyline':self.pl}, 'money_request:replenish')
        self.cfg['countries']['blacklist'] = ['us']
        with mock.patch.object(states, '_probe', return_value={'ok':True,'exit_cc':'us'}), \
                mock.patch.object(states.apply_mod, 'apply_candidate') as apply:
            result = states.try_replenish(self.cfg, {'proxyline':self.pl}, self.pool,
                                         mock.Mock(), lambda _:None, 'auto')
        self.assertFalse(result['ok'])
        apply.assert_not_called()
        self.assertEqual(len(self.pl.calls), 1)
        self.assertEqual(self.pool.get('proxyline:100')['role'], 'off')

    def test_proxy6_failed_probe_keeps_new_proxy_off(self):
        with mock.patch.object(states, '_probe', return_value={'ok':False,'exit_cc':'us'}):
            result = states.ensure_reserve(self.cfg, {'proxy6':self.p6}, self.pool,
                                           mock.Mock(), lambda _:None, 'auto')
        self.assertTrue(result['bought'], result)
        self.assertFalse(result['ok'])
        self.assertEqual(self.pool.get('proxy6:50')['role'], 'off')

    def test_proxy6_paid_response_supplies_pool_even_when_list_is_offline(self):
        with mock.patch.object(self.p6, 'list', side_effect=ProviderError('offline')), \
                mock.patch.object(states, '_probe', return_value={'ok':True,'exit_cc':'us'}):
            result = states.ensure_reserve(self.cfg, {'proxy6':self.p6}, self.pool,
                                           mock.Mock(), lambda _:None, 'auto')
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['uids'], ['proxy6:50'])
        self.assertEqual(self.pool.get('proxy6:50')['role'], 'auto')

    def test_unidentified_proxywing_country_does_not_break_valid_offer(self):
        original = self.pw._api
        def api(path):
            if path.endswith('/products'):
                return {'products':[{'product_id':'eu1','location':'EU','quantity':1,'price_monthly':3},
                                    {'product_id':'nz1','location':'NZ','quantity':1,'price_monthly':3}]}
            return original(path)
        with mock.patch.object(self.pw, '_api', side_effect=api):
            offer = auto_purchase.offers(self.cfg, {'proxywing':self.pw}, self.pool, lambda _:None)
        self.assertEqual(offer['country'], 'nz')

    def test_proxy6_import_is_held_while_provider_reply_is_uncertain(self):
        self.p6.buy_network_fail = True
        with self.assertRaises(money.SpendDenied):
            self.purchase({'proxy6':self.p6})
        row = self.p6._mk('us', self.p6.attempted_descr)
        uid = self.pool.upsert_proxy(row)
        self.assertEqual(self.pool.get(uid)['role'], 'off')
