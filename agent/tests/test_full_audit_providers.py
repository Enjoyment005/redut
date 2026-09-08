"""Payment non-delivery and complete provider snapshots, using no network."""
import copy
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import _ctx
import money
from pool import Pool
from providers import proxy6
from providers.base import ProviderError
from providers.proxywing import ProxyWing, norm_proxywing


class LocalProxy6(proxy6.Proxy6):
    """Keep the actual mutation adapter, replacing read-only provider requests."""

    def getprice(self, count, period, version):
        return {'price': 28, 'balance': 1000, 'currency': 'RUB'}

    def find_by_descr(self, descr, state='all'):
        return []

    def list(self):
        return [{'ext_id': '123', 'date_end': '2026-12-01',
                 'kind': 'dedicated', 'ip_version': 4}]


class TestProxy6NonDelivery(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.pool = Pool(str(Path(directory.name) / 'state.db'))
        self.addCleanup(self.pool.close)
        self.provider = LocalProxy6('synthetic-account')
        self.provider.min_interval = 0

    def spend(self, kind, request_id):
        if kind == 'buy':
            return money.plan_and_buy(self.pool, self.provider, {}, country='de',
                                      request_id=request_id)
        return money.prolong_with_limits(self.pool, self.provider, {},
            row={'uid': 'proxy6:123', 'provider': 'proxy6', 'ext_id': '123'},
            days=30, request_id=request_id)

    def test_proven_unsent_retires_buy_and_prolong_without_a_charge(self):
        for kind in ('buy', 'prolong'):
            with self.subTest(kind=kind):
                request_id = 'proven-unsent-' + kind
                error = ProviderError('connection refused', network=True, unsent=True)
                with mock.patch.object(proxy6, 'http_get_json', side_effect=error) as call:
                    with self.assertRaises(ProviderError) as caught:
                        self.spend(kind, request_id)
                self.assertTrue(caught.exception.replace_request)
                self.assertEqual(call.call_count, 1)
                op = money.bound_spend_request(self.pool, request_id)
                self.assertEqual(op['phase'], 'failed')
                self.assertFalse(self.pool.pending_spend_operations())
                self.assertEqual(self.pool.conn.execute('SELECT count(*) FROM money').fetchone()[0], 0)
                with self.assertRaises(money.SpendDenied) as repeat:
                    self.spend(kind, request_id)
                self.assertTrue(repeat.exception.replace_request)

    def test_unknown_delivery_keeps_buy_and_prolong_blocked(self):
        for kind in ('buy', 'prolong'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                db = Pool(str(Path(directory) / 'state.db'))
                original, self.pool = self.pool, db
                try:
                    request_id = 'unknown-result-' + kind
                    error = ProviderError('timeout after send', network=True)
                    with mock.patch.object(proxy6, 'http_get_json', side_effect=error) as call:
                        with self.assertRaises(money.SpendDenied):
                            self.spend(kind, request_id)
                        with self.assertRaises(money.SpendDenied):
                            self.spend(kind, request_id + '-new')
                    self.assertEqual(call.call_count, 1)
                    self.assertEqual(money.bound_spend_request(db, request_id)['phase'], 'submitted')
                    self.assertEqual(db.conn.execute('SELECT count(*) FROM money').fetchone()[0], 0)
                finally:
                    self.pool = original
                    db.close()

    def test_new_intent_can_succeed_after_proven_non_delivery(self):
        with mock.patch.object(proxy6, 'http_get_json', side_effect=ProviderError(
                'DNS failed before HTTP', network=True, unsent=True)):
            with self.assertRaises(ProviderError):
                self.spend('buy', 'unsent-then-new-1')

        def accepted(count, period, country, *, on_submit, **kwargs):
            on_submit()
            return {'proxies': [{'provider': 'proxy6', 'ext_id': '321'}],
                    'price': 28, 'balance': 972, 'currency': 'RUB'}

        with mock.patch.object(self.provider, 'buy', side_effect=accepted) as purchase:
            result = self.spend('buy', 'unsent-then-new-2')
        self.assertTrue(result['ok'])
        self.assertEqual(purchase.call_count, 1)
        self.assertEqual(self.pool.conn.execute('SELECT count(*) FROM money').fetchone()[0], 1)


class TestProxyWingCompleteSnapshot(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.pool = Pool(str(Path(directory.name) / 'state.db'))
        self.addCleanup(self.pool.close)
        self.provider = ProxyWing('synthetic-account')
        self.page = _ctx.fixture('proxywing_proxies.json')
        for family in ('datacenter', 'isp'):
            order = self.page['orders'][0]
            self.pool.upsert_proxy(norm_proxywing(order['proxies'][0], order, family))

    def refresh(self, isp_page):
        pages = {'/datacenter/proxies': copy.deepcopy(self.page), '/isp/proxies': isp_page}
        with mock.patch.object(self.provider, '_api', side_effect=lambda path: pages[path]):
            return self.pool.refresh({'proxywing': self.provider})

    def assert_rejected_without_cache_loss(self, page):
        before = self.pool.list(include_gone=True)
        summary = self.refresh(page)
        self.assertIn('proxywing', summary['errors'])
        self.assertEqual(self.pool.list(include_gone=True), before)

    def test_missing_or_malformed_family_never_replaces_complete_cache(self):
        for page in ({}, None, [], {'orders': None}, {'orders': {}}, {'orders': 'partial'}):
            with self.subTest(page=page):
                self.assert_rejected_without_cache_loss(page)

    def test_incomplete_active_order_never_drops_known_proxies(self):
        for change in ({'proxies': None}, {'proxies': {}}, {'id': ''}):
            with self.subTest(change=change):
                page = copy.deepcopy(self.page)
                page['orders'][0].update(change)
                self.assert_rejected_without_cache_loss(page)
        page = copy.deepcopy(self.page)
        del page['orders'][0]['proxies']
        self.assert_rejected_without_cache_loss(page)

    def test_incomplete_proxy_is_an_error_instead_of_a_partial_listing(self):
        for proxy in (None, {}, {'id': 'broken'}, {'ip': '192.0.2.1', 'socks_port': 1080}):
            with self.subTest(proxy=proxy):
                page = copy.deepcopy(self.page)
                page['orders'][0]['proxies'].append(proxy)
                self.assert_rejected_without_cache_loss(page)

    def test_malformed_status_never_drops_known_proxies(self):
        for status in (['active'], {'value': 'active'}, True, False, 1, 0):
            with self.subTest(status=status):
                page = copy.deepcopy(self.page)
                page['orders'][0]['status'] = status
                self.assert_rejected_without_cache_loss(page)

    def test_optional_status_remains_compatible(self):
        for status in (None, ''):
            with self.subTest(status=status):
                page = copy.deepcopy(self.page)
                page['orders'][0]['status'] = status
                self.assertFalse(self.refresh(page)['errors'])
        page = copy.deepcopy(self.page)
        del page['orders'][0]['status']
        self.assertFalse(self.refresh(page)['errors'])

    def test_explicit_empty_family_still_removes_its_stale_entries(self):
        summary = self.refresh({'orders': []})
        self.assertFalse(summary['errors'])
        rows = self.pool.list(include_gone=True)
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]['ext_id'].startswith('datacenter|'))

    def test_inactive_order_does_not_need_active_proxy_details(self):
        summary = self.refresh({'orders': [{'id': 'ord_gone', 'status': 'terminated'}]})
        self.assertFalse(summary['errors'])
        self.assertEqual(len(self.pool.list(include_gone=True)), 1)


if __name__ == '__main__':
    unittest.main()
