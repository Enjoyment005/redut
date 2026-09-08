"""Catalog-driven shop: no invented countries, no currency/budget permission setup."""
import unittest
from unittest import mock

import _ctx
from providers.proxywing import ProxyWing
from providers.base import ProviderError
import test_proxywing_orders as fixtures
from webpanel import views
import money
import test_money as p6_fixtures


class TestShopCatalog(unittest.TestCase):
    def test_isp_country_and_size_are_taken_from_exact_product_name(self):
        provider = ProxyWing('test-key')
        with mock.patch.object(provider, '_api', return_value={'products': [
                dict(product_id='p1', name='1 Proxy ISP US', group='ISP US New York Premium', price_monthly=3),
                dict(product_id='p2', name='2 Proxies ISP UK', group='ISP United Kingdom Premium', price_monthly=4.4)]}):
            rows = provider.catalog('isp')
        self.assertEqual([(p['country'],p['quantity']) for p in rows], [('us',1),('gb',2)])

    def test_regional_bundles_and_unknown_names_cannot_be_presented_as_countries(self):
        provider = ProxyWing('test-key')
        with mock.patch.object(provider, '_api', return_value={'products': [
                dict(product_id='p1', location='EU', quantity=20, price_monthly=22),
                dict(product_id='p2', location='WRLD', quantity=20, price_monthly=22)]}):
            self.assertEqual([p['country'] for p in provider.catalog('datacenter')], ['', ''])
        with mock.patch.object(provider, '_api', return_value={'products': [
                dict(product_id='p1', name='ISP special bundle', price_monthly=3)]}):
            self.assertEqual(provider.catalog('isp')[0]['country'], '')

    def test_metadata_conflicts_and_boolean_quantity_are_rejected(self):
        provider = ProxyWing('test-key')
        for changes in ({'location':'RU'}, {'quantity':True}, {'quantity':2}):
            with self.subTest(changes=changes), mock.patch.object(provider, '_api', return_value={'products': [
                    dict(product_id='p1', name='1 Proxy ISP US', price_monthly=3, **changes)]}):
                with self.assertRaises(ProviderError):
                    provider.catalog('isp')

    def test_explicit_ipv6_is_excluded_from_ipv4_catalog(self):
        provider = ProxyWing('test-key')
        with mock.patch.object(provider, '_api', return_value={'products': [
                dict(product_id='p1', location='DE', quantity=1, ip_version=6, price_monthly=1)]}):
            self.assertEqual(provider.catalog('datacenter'), [])

    def test_money_markup_has_one_shop_and_no_budget_or_manual_catalog_buttons(self):
        markup = views._DASH_HTML.split('id="card_money"',1)[1].split('id="card_pool"',1)[0]
        for old in ('pwbudgetbox','pwenabled','stabbox','plbox','pwbox','Что есть в продаже','Загрузить страны','Загрузить каталог'):
            self.assertNotIn(old, markup)
        self.assertIn('Датацентр IPv4',markup)
        self.assertIn('ISP прокси',markup)


class TestShopPurchase(unittest.TestCase):
    setUp = fixtures.TestMonthlyLedger.setUp
    execute = fixtures.TestMonthlyLedger.execute

    def test_unknown_country_cannot_be_supplied_by_the_browser(self):
        with mock.patch.object(self.provider, 'catalog', return_value=[dict(
                product_id='prod_1',country='',price_monthly=3,quantity=1)]):
            with self.assertRaises(money.SpendDenied):
                self.execute(country='us')
        self.assertFalse(self.provider.calls)

    def test_legacy_budgets_do_not_block_explicit_purchase(self):
        self.cfg.update(money={'buy_enabled':False,'max_buys_per_day':0}, proxywing_money={
            'enabled':False,'max_price_per_buy':0,'max_spend_per_day':0,'min_balance_reserve':100})
        result = self.execute()
        self.assertTrue(result['ok'])
        self.assertEqual(self.pool.spent_today('USD'),3)


class TestShopPanel(unittest.TestCase):
    setUp = fixtures.TestPanelMonthly.setUp
    handler = fixtures.TestPanelMonthly.handler

    def test_market_contains_only_buyable_countries_without_budget_settings(self):
        products = [dict(product_id='p1',country='de',quantity=1),
                    dict(product_id='p2',country='ru',quantity=1),
                    dict(product_id='p3',country='',quantity=20)]
        with mock.patch.object(self.provider, 'catalog', return_value=products):
            result = self.server.Handler._market(self.handler({}), {'provider':['proxywing']})
        self.assertNotIn('budget', result)
        self.assertEqual({p['country'] for p in result['products']},{'de'})

    def test_optional_balance_cache_failure_does_not_hide_paid_result(self):
        with mock.patch.object(self.pool, 'set_setting', side_effect=RuntimeError('cache unavailable')):
            status, result = self.server.Handler._api_post(self.handler(self.body), '/api/proxywing/spend')
        self.assertEqual(status,200)
        self.assertTrue(result['ok'])
        self.assertIsNone(result['balance'])
        self.assertEqual(len(self.provider.calls),1)
        self.assertEqual(self.pool.spent_today('USD'),3)

    def test_proxy6_fresh_price_cannot_exceed_clicked_offer(self):
        provider = p6_fixtures.FakeProxy6(price=100)
        provider.getcount = lambda cc, version: 1
        self.app.providers['proxy6'] = provider
        self.app.cfg = p6_fixtures.cfg()
        handler = self.handler({})
        handler._postbuy = lambda *args: []
        body = dict(country='de',period=7,request_id='shop-price-bound-1',max_total=28,currency='RUB')
        status, result = self.server.Handler._do_buy(handler,body)
        self.assertEqual(status,409,result)
        self.assertEqual(provider.buy_calls,0)
        self.assertEqual(self.app.cfg['money']['max_price_per_buy'],150)
        provider.price = 28
        status, result = self.server.Handler._do_buy(handler,body)
        self.assertEqual(status,200,result)
        self.assertEqual(provider.buy_calls,1)
        provider.price = 100
        status, replay = self.server.Handler._do_buy(handler,body)
        self.assertEqual(status,200,replay)
        self.assertEqual(replay['price'],28)
        self.assertEqual(provider.buy_calls,1)

    def test_proxy6_invalid_offer_currency_is_rejected_without_payment(self):
        provider = p6_fixtures.FakeProxy6()
        self.app.providers['proxy6'] = provider
        self.app.cfg = p6_fixtures.cfg()
        status, _ = self.server.Handler._do_buy(self.handler({}),dict(
            country='de',period=7,request_id='shop-price-bound-2',max_total=28,currency='USD'))
        self.assertEqual(status,400)
        self.assertEqual(provider.buy_calls,0)
