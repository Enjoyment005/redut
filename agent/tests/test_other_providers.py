"""Other provider contracts: malformed replies must never erase a healthy pool."""
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import _ctx
import pool as pool_mod
from providers import Proxy6, ProxyLine, ProviderError
from providers import proxy6 as p6_mod, proxyline as pl_mod
from providers.proxy6 import norm_proxy6


class TestProviderReadContracts(unittest.TestCase):
    def test_proxy6_catalog_and_stock_reject_malformed_values(self):
        p = Proxy6('fake-key')
        for value in ('us', {'us': 1}, None, ['us', 'not-a-country']):
            with self.subTest(countries=value), mock.patch.object(p, '_api', return_value={'list':value}):
                with self.assertRaises(ProviderError):
                    p.getcountry()
        for value in (True, 1.5, None, -1, 'bad'):
            with self.subTest(count=value), mock.patch.object(p, '_api', return_value={'count':value}):
                with self.assertRaises(ProviderError):
                    p.getcount('us')

    def test_proxy6_price_must_match_requested_quantity_and_period(self):
        p = Proxy6('fake-key')
        correct = dict(price=28,balance=500,currency='RUB',period=7,count=1)
        for changes in ({'period':30}, {'count':2}, {'period':True}, {'count':None}):
            with self.subTest(changes=changes), mock.patch.object(p, '_api', return_value=dict(correct,**changes)):
                with self.assertRaises(ProviderError):
                    p.getprice(1,7)

    def test_proxy6_invalid_amount_cannot_pass_financial_preflight(self):
        import money
        from test_money import cfg
        provider = Proxy6('fake-key')
        pool = SimpleNamespace(buys_today=lambda:0,spent_today=lambda currency:0)
        correct = dict(price=28,balance='500.00',currency='RUB',period=7,count=1)
        for field in ('price','balance'):
            for value in (True,[],{},None,'',-1,float('inf')):
                with self.subTest(field=field,value=value), mock.patch.object(
                        provider,'_api',return_value=dict(correct,**{field:value})):
                    with self.assertRaises(ProviderError):
                        money.preflight_buy(pool,provider,cfg(),country='de',period=7,auto=False)
        with mock.patch.object(provider,'_api',return_value=dict(correct,price='28.00')):
            result = money.preflight_buy(pool,provider,cfg(),country='de',period=7,auto=False)
        self.assertEqual(result['price'],28)
        self.assertEqual(result['balance_before'],500)

    def test_proxy6_requires_an_explicit_success_status(self):
        for reply in ({}, [], {'error': 'upstream failed'}, {'status': 'maybe'}):
            with self.subTest(reply=reply), mock.patch.object(p6_mod, 'http_get_json', return_value=reply):
                with self.assertRaises(ProviderError):
                    Proxy6('fake-key')._api('getproxy')

    def test_missing_currency_is_not_assumed_to_be_rubles(self):
        p = Proxy6('fake-key')
        with mock.patch.object(p, '_api', return_value={'price': 5, 'balance': 50, 'count':1, 'period':7}):
            self.assertIsNone(p.balance()['currency'])
            self.assertIsNone(p.getprice(1, 7)['currency'])

    def test_proxy6_check_accepts_only_real_boolean(self):
        p = Proxy6('fake-key')
        for reply in ({'proxy_status': 'false'}, {}, {'proxy_status': 1}):
            with mock.patch.object(p, '_api', return_value=reply):
                with self.assertRaises(ProviderError):
                    p.check('15')
        with mock.patch.object(p, '_api', return_value={'proxy_status': False}):
            self.assertFalse(p.check('15'))

    def test_money_parameters_cannot_be_silently_truncated(self):
        p = Proxy6('fake-key')
        with mock.patch.object(p, '_api') as api:
            for value in (True, 1.9, float('inf')):
                with self.assertRaises(ProviderError):
                    p.buy(value, 7, 'us')
            api.assert_not_called()

    def test_partial_lists_do_not_replace_the_cached_pool(self):
        with tempfile.TemporaryDirectory() as directory:
            pool = pool_mod.Pool(directory + '/state.db')
            try:
                item = next(iter(_ctx.fixture('proxy6_getproxy.json')['list'].values()))
                norm = norm_proxy6(item)
                uid = pool.upsert_proxy(norm)
                provider = Proxy6('fake-key')
                with mock.patch.object(provider, '_api', return_value={}):
                    for _ in range(2):
                        report = pool.refresh({'proxy6': provider})
                        self.assertIn('proxy6', report['errors'])
                self.assertIsNotNone(pool.get(uid))
                self.assertEqual(pool.get(uid)['gone'], 0)
            finally:
                pool.close()

    def test_proxyline_rejects_malformed_and_truncated_pages(self):
        p = ProxyLine('fake-key')
        for page in ({}, {'results': None}, {'results': [], 'next': 'more'},
                     {'results': [], 'next': None, 'count': 1}, {'results': []},
                     {'results': [], 'count': 0}):
            with self.subTest(page=page), mock.patch.object(p, '_api', return_value=page):
                with self.assertRaises(ProviderError):
                    p.list()

    def test_proxyline_repeated_page_stops_instead_of_returning_a_partial_pool(self):
        p = ProxyLine('fake-key')
        rows = _ctx.fixture('proxyline_proxies.json')['results']
        with mock.patch.object(p, '_api', return_value={'results': rows, 'next': 'more', 'count': 20}) as api:
            with self.assertRaises(ProviderError):
                p.list()
        self.assertLessEqual(api.call_count, 2)

    def test_empty_listing_without_metadata_does_not_erase_either_provider(self):
        from providers.proxyline import norm_proxyline
        for provider, norm, reply in (
                (Proxy6('fake-key'), norm_proxy6(next(iter(_ctx.fixture('proxy6_getproxy.json')['list'].values()))), {'list': {}}),
                (ProxyLine('fake-key'), norm_proxyline(_ctx.fixture('proxyline_proxies.json')['results'][0]), {'results': []})):
            with self.subTest(provider=provider.name), tempfile.TemporaryDirectory() as directory:
                pool = pool_mod.Pool(directory + '/state.db')
                try:
                    uid = pool.upsert_proxy(norm)
                    with mock.patch.object(provider, '_api', return_value=reply):
                        for _ in range(2):
                            self.assertIn(provider.name, pool.refresh({provider.name: provider})['errors'])
                    self.assertIsNotNone(pool.get(uid))
                    self.assertEqual(pool.get(uid)['gone'], 0)
                finally:
                    pool.close()

    def test_proxy6_unknown_version_is_rejected_before_normalization(self):
        item = next(iter(_ctx.fixture('proxy6_getproxy.json')['list'].values()))
        for version in (None, '', '7', True):
            with self.subTest(version=version), self.assertRaises(ProviderError):
                norm_proxy6(dict(item, version=version))

    def test_complete_empty_lists_are_still_supported(self):
        for provider, reply in ((Proxy6('fake-key'), {'list': {}, 'list_count': 0}),
                                (ProxyLine('fake-key'), {'results': [], 'next': None, 'count': 0})):
            with mock.patch.object(provider, '_api', return_value=reply):
                self.assertEqual(provider.list(), [])

    def test_proxyline_renew_only_accepts_documented_terms(self):
        p = ProxyLine('fake-key')
        with mock.patch.object(pl_mod, 'http_post_form') as post:
            for days in (1, 7, 365, True, 30.5):
                with self.assertRaises(ProviderError):
                    p.prolong(['15'], days)
            post.assert_not_called()


class TestProxyLineCatalog(unittest.TestCase):
    def test_countries_and_stock_match_observed_readonly_contract(self):
        p = ProxyLine('fake-key')
        with mock.patch.object(p, '_api', side_effect=[
                [{'code': 'us', 'name': 'United States', 'cities': [{'id': 1, 'name': 'New York'}]}],
                {'count': 1000}]):
            self.assertEqual(p.countries()[0]['code'], 'us')
            self.assertEqual(p.stock('us', 'dedicated', 4), 1000)

    def test_quote_is_readonly_and_bound_to_its_request(self):
        p = ProxyLine('fake-key')
        params = {'type': 'dedicated', 'ip_version': 4, 'country': 'us', 'quantity': 1, 'period': 30}
        with mock.patch.object(pl_mod, 'http_post_form', return_value={
                'amount': 1.2, 'data': dict(params, ip_list=[], type='dedicated_ipv4')}) as post:
            quote = p.quote('us', 'dedicated', 4, 1, 30)
        self.assertEqual(quote['amount'], 1.2)
        self.assertTrue(post.call_args.args[0].endswith('/new-order-amount/'))
        self.assertFalse(post.call_args.kwargs['mutating'])
        self.assertEqual(post.call_args.kwargs['headers'], {'API-KEY': 'fake-key'})
        with mock.patch.object(pl_mod, 'http_post_form', return_value={
                'amount': 1.2, 'data': dict(params, period=5)}):
            with self.assertRaises(ProviderError):
                p.quote('us', 'dedicated', 4, 1, 30)

    def test_live_quote_product_type_names_preserve_request_family(self):
        p = ProxyLine('fake-key')
        p.min_interval = 0
        for kind, version, normalized in (('dedicated',4,'dedicated_ipv4'),
                                           ('shared',4,'shared_ipv4'), ('dedicated',6,'ipv6')):
            data = {'type':normalized,'ip_version':version,'country':'us','quantity':1,'period':30}
            with mock.patch.object(pl_mod, 'http_post_form', return_value={'amount':1.2,'data':data}):
                self.assertEqual(p.quote('us',kind,version,1,30)['type'], kind)
        with mock.patch.object(pl_mod, 'http_post_form', return_value={'amount':1.2,'data':{
                'type':'shared_ipv4','ip_version':4,'country':'us','quantity':1,'period':30}}):
            with self.assertRaises(ProviderError):
                p.quote('us','dedicated',4,1,30)

    def test_invalid_country_does_not_reach_provider(self):
        with mock.patch.object(pl_mod, 'http_post_form') as post:
            with self.assertRaises(ProviderError):
                ProxyLine('fake-key').quote('../us', 'dedicated', 4, 1, 30)
            post.assert_not_called()


class TestCatalogPanel(unittest.TestCase):
    def test_proxyline_market_works_without_proxy6_and_never_spends(self):
        from webpanel import server
        provider = ProxyLine('fake-key')
        app = SimpleNamespace(cfg={}, providers={'proxyline': provider}, pool=SimpleNamespace(
            pending_spend_operations=lambda: [], unacknowledged_spend_operations=lambda: []))
        with mock.patch.object(server, 'APP', app), \
                mock.patch.object(provider, 'countries', return_value=[
                    {'code': 'us', 'name': 'USA'}, {'code': 'ru', 'name': 'Russia'}]), \
                mock.patch.object(provider, 'balance', return_value={'balance': 10, 'currency': 'USD'}), \
                mock.patch.object(provider, 'prolong') as spend:
            result = server.Handler._market(SimpleNamespace(), {'provider': ['proxyline']})
        self.assertEqual([c['code'] for c in result['countries']], ['us'])
        self.assertTrue(result['money_supported'])
        spend.assert_not_called()

    def test_blocked_country_is_rejected_before_quote_or_stock(self):
        from webpanel import server
        provider = ProxyLine('fake-key')
        with mock.patch.object(server, 'APP', SimpleNamespace(cfg={}, providers={'proxyline': provider})), \
                mock.patch.object(provider, 'stock') as stock, mock.patch.object(provider, 'quote') as quote:
            result = server.Handler._market(SimpleNamespace(), {'provider': ['proxyline'], 'country': ['ru']})
        self.assertIn('error', result)

        stock.assert_not_called()
        quote.assert_not_called()

    def test_invalid_proxy6_period_becomes_an_explained_error(self):
        from webpanel import server
        with mock.patch.object(server, 'APP', SimpleNamespace(cfg={}, providers={'proxy6': Proxy6('fake-key')})):
            result = server.Handler._market(SimpleNamespace(), {'period': ['bad']})
        self.assertIn('error', result)


class TestRenewalPriceVersion(unittest.TestCase):
    def test_invalid_numeric_parameters_stop_before_any_financial_call(self):
        import money
        from test_money import FakeProxy6, cfg
        with tempfile.TemporaryDirectory() as directory:
            pool = pool_mod.Pool(directory + '/state.db')
            try:
                provider = FakeProxy6()
                row = dict(provider._mk('us', ''), uid='proxy6:50')
                with mock.patch.object(provider, 'prolong') as prolong, mock.patch.object(provider, 'buy') as buy:
                    for value in (True, False, 30.5, '30x', 0):
                        with self.subTest(value=value), self.assertRaises(money.SpendDenied):
                            money.prolong_with_limits(pool, provider, cfg(), row=row, days=value)
                        for field in ('count', 'period', 'version'):
                            with self.subTest(value=value, field=field), self.assertRaises(money.SpendDenied):
                                money.plan_and_buy(pool, provider, cfg(), country='us', **{field: value})
                    prolong.assert_not_called()
                    buy.assert_not_called()
                self.assertEqual(pool.spent_today('RUB'), 0)
            finally:
                pool.close()

    def test_http_prolong_rejects_bool_and_fraction_before_pool_access(self):
        from webpanel import server
        for value in (True, 30.5):
            status, result = server.Handler._do_prolong(
                SimpleNamespace(_json=lambda code, body: (code, body)), None, 'proxy6:1',
                {'days': value, 'request_id': 'invalid-period-http'})
            self.assertEqual(status, 400)

    def test_price_uses_the_actual_proxy_type_instead_of_new_buy_default(self):
        import money
        from test_money import FakeProxy6, cfg
        for version, kind, expected in ((4, 'shared', 3), (6, 'dedicated', 6)):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as directory:
                pool = pool_mod.Pool(directory + '/state.db')
                try:
                    provider = FakeProxy6()
                    remote = dict(provider._mk('us', ''), ip_version=version, kind=kind)
                    row = dict(provider._mk('us', ''), uid='proxy6:50')
                    with mock.patch.object(provider, 'list', return_value=[remote]), \
                            mock.patch.object(provider, 'getprice', wraps=provider.getprice) as price:
                        money.prolong_with_limits(pool, provider, cfg(), row=row, days=30,
                                                  request_id='actual-renewal-version')
                    self.assertEqual(price.call_args.args[2], expected)
                finally:
                    pool.close()
