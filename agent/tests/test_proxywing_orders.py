"""ProxyWing monthly API contracts; no real provider requests or charges."""
import unittest
import tempfile
import json
from types import SimpleNamespace
from unittest import mock

import _ctx
from providers.proxywing import ProxyWing
from providers import base
from providers.base import ProviderError
import proxywing_orders as orders
import pool as pool_mod
import money


class TestMonthlyAPI(unittest.TestCase):
    def test_catalog_preserves_both_families_and_package_quantity(self):
        p = ProxyWing('test-key')
        pages = {'/datacenter/products': {'products': [
            {'product_id': 'dcprod_3', 'location': 'UK', 'quantity': 5, 'price_monthly': 9}]},
            '/isp/products': {'products': [
                {'product_id': 'prod_368', 'category': 'isp', 'group': 'ISP US Premium',
                 'name': '1 Proxy ISP US', 'price_monthly': 3}]}}
        with mock.patch.object(p, '_api', side_effect=lambda path: pages[path]):
            products = p.catalog()
        self.assertEqual([x['family'] for x in products], ['datacenter', 'isp'])
        self.assertEqual(products[0]['quantity'], 5)
        self.assertEqual(products[0]['country'], 'gb')

    def test_renewal_is_for_order_in_months(self):
        p = ProxyWing('test-key')
        with mock.patch.object(p, '_post', return_value={'status': 'paid'}) as post:
            p.extend_order('isp', 'ord_100010', 3, 'request-test-001')
        self.assertEqual(post.call_args.args[:3], (
            '/isp/orders/ord_100010/extend', {'cycle': 3, 'cycle_type': 'monthly'},
            'request-test-001'))

    def test_purchase_has_explicit_billing_cycle_and_key(self):
        p = ProxyWing('test-key')
        with mock.patch.object(p, '_post', return_value={'status': 'paid'}) as post:
            p.order_product('datacenter', 'dcprod_3', 'monthly', 'request-test-002')
        self.assertEqual(post.call_args.args[:3], ('/datacenter/orders',
            {'product_id': 'dcprod_3', 'billing_cycle': 'monthly'}, 'request-test-002'))

    def test_invalid_ids_terms_and_prices_stop_before_io(self):
        p = ProxyWing('test-key')
        with mock.patch.object(p, '_post') as post:
            for family, order_id, months in [('wrong', 'ord_1', 1), ('isp', '../order', 1),
                                             ('isp', 'ord_1', True), ('isp', 'ord_1', 7)]:
                with self.assertRaises(ProviderError):
                    p.extend_order(family, order_id, months, 'request-test-003')
            post.assert_not_called()
        for price in (True, 'NaN', -1, 0, 'Infinity'):
            with mock.patch.object(p, '_api', return_value={'products': [
                    {'product_id': 'prod_1', 'price_monthly': price}]}):
                with self.assertRaises(ProviderError):
                    p.catalog('isp')

    def test_direct_json_keeps_idempotency_header_and_disallows_redirect(self):
        with mock.patch.object(base, 'preferred_transport', return_value='direct'), \
                mock.patch.object(base, '_urlopen_json', return_value={}) as call:
            base.http_post_json('https://api.invalid/v1/orders', {'product_id': 'prod_1'},
                                headers={'Idempotency-Key': 'key-0001'})
        req = call.call_args.args[0]
        self.assertEqual(json.loads(req.data), {'product_id': 'prod_1'})
        self.assertEqual(req.get_header('Idempotency-key'), 'key-0001')
        self.assertFalse(call.call_args.kwargs['follow_redirects'])

    def test_tunnel_json_uses_stdin_and_does_not_retry_ambiguous_write(self):
        with mock.patch.object(base.subprocess, 'run', return_value=SimpleNamespace(
                returncode=0, stdout='HTTP/1.1 200 OK\r\n\r\n{}\n__HTTP__200')) as run:
            base._curl_json('https://api.invalid', {}, None, 'api', 2, json_body={'cycle': 3})
        self.assertEqual(json.loads(run.call_args.kwargs['input']), {'cycle': 3})
        self.assertNotIn('-L', run.call_args.args[0])
        with mock.patch.object(base, 'preferred_transport', return_value='direct'), \
                mock.patch.object(base, '_tun0_alive', return_value=True), \
                mock.patch.object(base, '_urlopen_json', side_effect=ProviderError('timeout', network=True)), \
                mock.patch.object(base, '_curl_json') as curl:
            with self.assertRaises(ProviderError):
                base.http_post_json('https://api.invalid', {})
            curl.assert_not_called()


class FakeMonthly(ProxyWing):
    """Fake the transport, retaining adapter request construction and callbacks."""
    def __init__(self):
        super().__init__('fake-account-key')
        self.calls = []
        self.monthly_price = 3.0
        self.usd_balance = 100.0
        self.currency = 'USD'
        self.lose_once = False
        self.response = None
        self.rows = []

    def _api(self, path):
        if path.endswith('/products'):
            return {'products': [{'product_id': 'prod_1', 'location': 'US', 'quantity': 2,
                                  'price_monthly': self.monthly_price}]}
        if path.endswith('/renewal-options'):
            return {'order_id': 'ord_1', 'next_due_date': '2026-09-10',
                    'options': [{'months': n, 'total': n * 3} for n in (1, 3, 6, 12)]}
        if path == '/account/balance':
            return {'balance': self.usd_balance, 'currency': self.currency}
        raise AssertionError(path)

    def list(self):
        return self.rows

    def _post(self, path, body, request_id, on_submit=None):
        if on_submit:
            on_submit()
        self.calls.append((path, body, request_id))
        if self.lose_once:
            self.lose_once = False
            raise ProviderError('lost response', network=True)
        return self.response or dict(status='paid', total=body.get('cycle', 1) * 3,
            order_id='ord_1', invoice_id='inv_1', product_id='prod_1',
            billing_cycle='monthly', next_due_date='2026-12-10')


class TestMonthlyLedger(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.pool = pool_mod.Pool(tmp.name + '/state.db')
        self.addCleanup(self.pool.close)
        self.provider = FakeMonthly()
        self.cfg = {'money': {'buy_enabled': True}, 'proxywing_money': {
            'enabled': True, 'max_price_per_buy': 50, 'max_spend_per_day': 100,
            'min_balance_reserve': 1}}
        self.body = {'kind': 'buy', 'family': 'isp', 'product_id': 'prod_1', 'months': 1,
                     'max_total': 3, 'country': 'us', 'request_id': 'monthly-request-0001'}

    def execute(self, **changes):
        return orders.execute(self.pool, self.provider, self.cfg, dict(self.body, **changes))

    def test_paid_purchase_and_replay_write_one_ledger_row(self):
        first = self.execute()
        self.cfg['proxywing_money']['enabled'] = False
        second = self.execute()
        self.assertEqual(first['spend_operation_id'], second['spend_operation_id'])
        self.assertEqual(len(self.provider.calls), 1)
        self.assertEqual(self.pool.spent_today('USD'), 3)

        self.assertEqual(self.pool.buys_today(), 1)

    def test_timeout_keeps_intent_and_same_key_is_reused(self):
        self.provider.lose_once = True
        with self.assertRaises(ProviderError):
            self.execute()
        with self.assertRaises(money.SpendDenied):
            money.reconcile_pending_spend(self.pool, {'proxywing': self.provider})
        self.assertEqual(len(self.provider.calls), 1)
        with self.assertRaises(money.SpendDenied):
            self.execute(request_id='monthly-new-0002')
        self.execute()
        self.assertEqual([x[2] for x in self.provider.calls], [self.body['request_id']] * 2)
        self.assertEqual(self.pool.spent_today('USD'), 3)

    def test_changed_credential_cannot_resubmit_into_another_account(self):
        self.provider.lose_once = True
        with self.assertRaises(ProviderError):
            self.execute()
        self.provider.api_key = 'another-account'
        with self.assertRaises(money.SpendDenied):
            self.execute()
        self.assertEqual(len(self.provider.calls), 1)

    def test_paid_lost_reply_does_not_require_a_second_balance_reserve(self):
        self.provider.usd_balance = 4
        self.provider.lose_once = True
        with self.assertRaises(ProviderError):
            self.execute()
        self.provider.usd_balance = 1
        self.execute()
        self.assertEqual(self.pool.spent_today('USD'), 3)
        self.assertEqual([c[2] for c in self.provider.calls], [self.body['request_id']] * 2)

    def test_unknown_submission_cannot_replay_after_price_increase(self):
        self.provider.lose_once = True
        with self.assertRaises(ProviderError):
            self.execute()
        self.provider.monthly_price = 30
        with self.assertRaises(money.SpendDenied):
            self.execute()
        self.assertEqual(len(self.provider.calls), 1)
        self.assertEqual(self.pool.spent_today('USD'), 0)
        self.assertEqual(money.bound_spend_request(self.pool, self.body['request_id'])['phase'], 'submitted')

    def test_proven_unsent_first_attempt_releases_request(self):
        def unsent(path, body, request_id, on_submit):
            on_submit()
            raise ProviderError('connection refused', network=True, unsent=True)
        with mock.patch.object(self.provider, '_post', side_effect=unsent):
            with self.assertRaises(ProviderError) as caught:
                self.execute()
        self.assertTrue(caught.exception.replace_request)
        self.assertEqual(money.bound_spend_request(self.pool, self.body['request_id'])['phase'], 'failed')
        self.provider.monthly_price = 30
        with self.assertRaises(money.SpendDenied):
            self.execute(request_id='monthly-request-new')
        self.assertEqual(self.pool.spent_today('USD'), 0)

    def test_refresh_after_paid_import_failure_preserves_order_hold(self):
        from providers.proxywing import norm_proxywing
        fixture = _ctx.fixture('proxywing_proxies.json')['orders'][0]['proxies'][0]
        first = norm_proxywing(dict(fixture, id='prx_1'), {'id': 'ord_1'}, 'isp')
        self.execute()
        reopened = pool_mod.Pool(self.pool.db_path)
        try:
            self.provider.rows = [first]
            reopened.refresh({'proxywing': self.provider})
            uid = 'proxywing:isp|ord_1|prx_1'
            self.assertEqual(reopened.get(uid)['role'], 'off')
            reopened.upsert_proxy(first, role='auto')
            self.provider.rows.append(norm_proxywing(dict(fixture, id='prx_2'), {'id': 'ord_1'}, 'isp'))
            reopened.refresh({'proxywing': self.provider})
            self.assertEqual(reopened.get(uid)['role'], 'auto')
            self.assertEqual(reopened.get('proxywing:isp|ord_1|prx_2')['role'], 'off')
        finally:
            reopened.close()

    def test_refresh_during_lost_reply_keeps_new_members_off(self):
        from providers.proxywing import norm_proxywing
        fixture = _ctx.fixture('proxywing_proxies.json')['orders'][0]['proxies'][0]
        self.provider.lose_once = True
        with self.assertRaises(ProviderError):
            self.execute()
        self.provider.rows = [norm_proxywing(dict(fixture, id='prx_1'), {'id': 'ord_1'}, 'isp')]
        self.pool.refresh({'proxywing': self.provider})
        self.assertEqual(self.pool.get('proxywing:isp|ord_1|prx_1')['role'], 'off')
        self.execute()
        self.assertEqual(self.pool.get('proxywing:isp|ord_1|prx_1')['role'], 'off')

    def test_bad_replay_response_does_not_release_original_unknown(self):
        self.provider.lose_once = True
        with self.assertRaises(ProviderError):
            self.execute()
        with mock.patch.object(self.provider, '_post', side_effect=ProviderError('unauthorized', definitive=True)):
            with self.assertRaises(ProviderError):
                self.execute()
        self.assertEqual(money.bound_spend_request(self.pool, self.body['request_id'])['phase'], 'submitted')

    def test_response_survives_crash_before_ledger_commit(self):
        with mock.patch.object(self.pool, 'complete_spend_operation', side_effect=RuntimeError('crash')):
            with self.assertRaises(RuntimeError):
                self.execute()
        result = money.reconcile_pending_spend(self.pool, {'proxywing': self.provider})
        self.assertEqual(len(result), 1)
        self.execute()
        self.assertEqual(len(self.provider.calls), 1)
        self.assertEqual(self.pool.spent_today('USD'), 3)

    def test_pending_invoice_is_not_reported_as_a_success(self):
        self.provider.response = {'status': 'awaiting_payment', 'total': 3, 'invoice_id': 'inv_1', 'order_id': None}
        with self.assertRaises(money.SpendDenied):
            self.execute()
        self.assertEqual(self.pool.spent_today('USD'), 0)
        self.assertEqual(len(self.pool.pending_spend_operations()), 1)

    def test_full_order_renewal_charges_once_and_updates_sibling_ips(self):
        fixture = _ctx.fixture('proxywing_proxies.json')['orders'][0]['proxies'][0]
        from providers.proxywing import norm_proxywing
        for ident in ('prx_1', 'prx_2'):
            self.pool.upsert_proxy(norm_proxywing(dict(fixture, id=ident), {'id': 'ord_1'}, 'isp'))
        result = self.execute(kind='prolong', order_id='ord_1', months=3, max_total=9)
        self.assertEqual(result['months'], 3)
        self.assertEqual(len(result['uids']), 2)
        self.assertEqual({r['date_end'] for r in self.pool.list()}, {'2026-12-10'})
        self.assertEqual(self.pool.spent_today('USD'), 9)
        self.assertEqual(self.pool.conn.execute('SELECT count(*) FROM money').fetchone()[0], 1)

    def test_rejection_gates_run_before_post(self):
        cases = [('budget', lambda: self.cfg.pop('proxywing_money')),
                 ('disabled', lambda: self.cfg['money'].update(buy_enabled=False)),
                 ('price', lambda: setattr(self.provider, 'monthly_price', 4)),
                 ('currency', lambda: setattr(self.provider, 'currency', 'RUB')),
                 ('missing_currency', lambda: setattr(self.provider, 'currency', None)),
                 ('balance', lambda: setattr(self.provider, 'usd_balance', 3)),
                 ('daily', lambda: self.cfg['proxywing_money'].update(max_spend_per_day=2))]
        import copy
        original = copy.deepcopy(self.cfg)
        for name, mutate in cases:
            with self.subTest(name=name):
                self.cfg = copy.deepcopy(original)
                self.provider = FakeMonthly()
                mutate()
                with self.assertRaises(money.SpendDenied):
                    self.execute()
                self.assertFalse(self.provider.calls)

    def test_existing_order_renewal_does_not_enable_or_require_new_purchases(self):
        from providers.proxywing import norm_proxywing
        fixture = _ctx.fixture('proxywing_proxies.json')['orders'][0]['proxies'][0]
        uid = self.pool.upsert_proxy(norm_proxywing(fixture, {'id': 'ord_1'}, 'isp'))
        self.cfg['money']['buy_enabled'] = False
        result = self.execute(kind='prolong', order_id='ord_1', months=3, max_total=9)
        replay = self.execute(kind='prolong', order_id='ord_1', months=3, max_total=9)
        self.assertEqual(result['date_end'], '2026-12-10')
        self.assertEqual(self.pool.get(uid)['date_end'], '2026-12-10')
        self.assertEqual(result['spend_operation_id'], replay['spend_operation_id'])
        self.assertEqual(len(self.provider.calls), 1)
        self.assertEqual(self.provider.calls[0][0], '/isp/orders/ord_1/extend')
        self.assertEqual(self.pool.spent_today('USD'), 9)
        self.assertFalse(self.cfg['money']['buy_enabled'])
        with self.assertRaises(money.SpendDenied):
            self.execute(request_id='blocked-new-purchase')
        self.assertEqual(len(self.provider.calls), 1)

    def test_renewal_keeps_usd_permission_price_daily_and_reserve_limits(self):
        import copy
        original = copy.deepcopy(self.cfg)
        cases = [dict(enabled=False), dict(max_price_per_buy=8),
                 dict(max_spend_per_day=8), dict(min_balance_reserve=92)]
        for change in cases:
            with self.subTest(change=change):
                self.cfg = copy.deepcopy(original)
                self.cfg['proxywing_money'].update(change)
                with self.assertRaises(money.SpendDenied):
                    self.execute(kind='prolong', order_id='ord_1', months=3, max_total=9)
                self.assertFalse(self.provider.calls)
                self.assertEqual(self.pool.spent_today('USD'), 0)

    def test_safe_mode_blocks_new_and_uncertain_renewal_sends(self):
        self.cfg['_config_meta'] = {'safe_mode': True}
        with self.assertRaises(money.SpendDenied):
            self.execute(kind='prolong', order_id='ord_1', months=3, max_total=9)
        self.assertFalse(self.provider.calls)
        self.cfg['_config_meta']['safe_mode'] = False
        self.provider.lose_once = True
        with self.assertRaises(ProviderError):
            self.execute(kind='prolong', order_id='ord_1', months=3, max_total=9)
        self.cfg['_config_meta']['safe_mode'] = True
        with self.assertRaises(money.SpendDenied):
            self.execute(kind='prolong', order_id='ord_1', months=3, max_total=9)
        self.assertEqual(len(self.provider.calls), 1)
        self.assertEqual(self.pool.pending_spend_operations()[0]['phase'], 'submitted')

    def test_paid_renewal_recovery_in_safe_mode_does_not_send_again(self):
        with mock.patch.object(orders, 'finish', side_effect=OSError('interrupted commit')):
            with self.assertRaises(OSError):
                self.execute(kind='prolong', order_id='ord_1', months=3, max_total=9)
        self.cfg['_config_meta'] = {'safe_mode': True}
        result = self.execute(kind='prolong', order_id='ord_1', months=3, max_total=9)
        self.assertTrue(result['recovered'])
        self.assertEqual(len(self.provider.calls), 1)
        self.assertEqual(self.pool.spent_today('USD'), 9)

    def test_changed_intent_and_wrong_receipt_cannot_commit(self):
        self.execute()
        with self.assertRaises(money.SpendDenied):
            self.execute(family='datacenter')
        self.provider.response = dict(status='paid', total=3, order_id='ord_2',
                                      invoice_id='inv_2', product_id='other', billing_cycle='monthly')
        with self.assertRaises(money.SpendDenied):
            self.execute(request_id='monthly-request-0002')
        self.assertEqual(self.pool.spent_today('USD'), 3)



class TestPanelMonthly(unittest.TestCase):
    def setUp(self):
        TestMonthlyLedger.setUp(self)
        from webpanel import server
        self.server = server
        self.app = SimpleNamespace(cfg=self.cfg, pool=self.pool, providers={'proxywing': self.provider})
        self.patch = mock.patch.object(server, 'APP', self.app)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def handler(self, body):
        return SimpleNamespace(_body=lambda **kw: json.dumps(body).encode(),
                               _json=lambda status, result: (status, result), _client_ip=lambda: '127.0.0.1')

    def test_market_without_proxy6_returns_both_families(self):
        result = self.server.Handler._market(self.handler({}), {'provider': ['proxywing']})
        self.assertEqual({p['family'] for p in result['products']}, {'datacenter', 'isp'})
        self.assertEqual(result['balance']['currency'], 'USD')

    def test_one_family_failure_keeps_other_catalog_and_error(self):
        original = self.provider.catalog
        def catalog(family):
            if family == 'isp':
                raise ProviderError('ISP unavailable')
            return original(family)
        with mock.patch.object(self.provider, 'catalog', side_effect=catalog):
            result = self.server.Handler._market(self.handler({}), {'provider': ['proxywing']})
        self.assertEqual(len(result['products']), 1)
        self.assertIn('isp', result['errors'])

    def test_spend_route_imports_only_paid_order_without_activating_it(self):
        from providers.proxywing import norm_proxywing
        fixture = _ctx.fixture('proxywing_proxies.json')['orders'][0]['proxies'][0]
        self.provider.rows = [norm_proxywing(dict(fixture, id='prx_1'), {'id': 'ord_1'}, 'isp'),
                              norm_proxywing(dict(fixture, id='prx_2'), {'id': 'ord_other'}, 'isp')]
        status, result = self.server.Handler._api_post(self.handler(self.body), '/api/proxywing/spend')
        self.assertEqual(status, 200, result)
        self.assertEqual(result['uids'], ['proxywing:isp|ord_1|prx_1'])
        self.assertEqual(self.pool.get(result['uids'][0])['role'], 'off')
        self.assertIsNone(self.pool.get('proxywing:isp|ord_other|prx_2'))

    def test_preflight_rejection_allows_fixing_request(self):
        self.cfg['proxywing_money']['enabled'] = False
        status, result = self.server.Handler._api_post(self.handler(self.body), '/api/proxywing/spend')
        self.assertEqual(status, 409)
        self.assertTrue(result['replace_request'])
        self.assertFalse(self.provider.calls)

    def test_unavailable_nonmonthly_renewal_returns_json_error(self):
        from providers.proxywing import norm_proxywing
        fixture = _ctx.fixture('proxywing_proxies.json')['orders'][0]['proxies'][0]
        uid = self.pool.upsert_proxy(norm_proxywing(fixture, {'id': 'ord_1'}, 'isp'))
        with mock.patch.object(self.provider, 'renewal_options', side_effect=ProviderError('HTTP 500')):
            status, result = self.server.Handler._api_get(self.handler({}), '/api/proxywing/renewal', {'uid': [uid]})
        self.assertEqual(status, 502)
        self.assertIn('месячные', result['error'])

    def test_renewal_preflight_returns_budget_without_loading_purchase_catalog(self):
        from providers.proxywing import norm_proxywing
        fixture = _ctx.fixture('proxywing_proxies.json')['orders'][0]['proxies'][0]
        uid = self.pool.upsert_proxy(norm_proxywing(fixture, {'id': 'ord_1'}, 'isp'))
        self.cfg['money']['buy_enabled'] = False
        self.cfg['proxywing_money']['enabled'] = False
        with mock.patch.object(self.provider, 'catalog') as catalog:
            status, result = self.server.Handler._api_get(
                self.handler({}), '/api/proxywing/renewal', {'uid': [uid]})
        self.assertEqual(status, 200, result)
        self.assertEqual(result['budget'], self.cfg['proxywing_money'])
        self.assertEqual(result['spent_today'], 0)
        self.assertEqual(result['affected_count'], 1)
        catalog.assert_not_called()
        self.assertFalse(self.provider.calls)

    def test_renewal_preflight_denials_return_json(self):
        from providers.proxywing import norm_proxywing
        fixture = _ctx.fixture('proxywing_proxies.json')['orders'][0]['proxies'][0]
        uid = self.pool.upsert_proxy(norm_proxywing(fixture, {'id': 'ord_1'}, 'isp'))
        with mock.patch.object(self.pool, 'spent_today', side_effect=ValueError('corrupt ledger')):
            status, result = self.server.Handler._api_get(
                self.handler({}), '/api/proxywing/renewal', {'uid': [uid]})
        self.assertEqual(status, 409, result)
        self.assertIn('error', result)
        self.cfg['_config_meta'] = {'safe_mode': True}
        status, result = self.server.Handler._api_get(
            self.handler({}), '/api/proxywing/renewal', {'uid': [uid]})
        self.assertEqual(status, 409, result)
        self.assertIn('error', result)
        self.assertFalse(self.provider.calls)

    def test_safe_mode_budget_save_does_not_write_or_enable_spending(self):
        import os
        import config_store
        path = os.path.join(os.path.dirname(self.pool.db_path), 'config.json')
        with open(path, 'w', encoding='utf-8') as file:
            json.dump({'owner_value': 17}, file)
        self.cfg['_source'] = path
        self.cfg['_config_meta'] = {'safe_mode': True}
        self.cfg['proxywing_money']['enabled'] = False
        with self.assertRaises(money.SpendDenied):
            config_store.save_proxywing_budget(self.cfg, dict(self.cfg['proxywing_money'], enabled=True))
        with open(path, encoding='utf-8') as file:
            self.assertEqual(json.load(file), {'owner_value': 17})
        self.assertFalse(self.cfg['proxywing_money']['enabled'])

    def test_budget_update_preserves_adjacent_disk_fields(self):
        import os
        import config_store
        path = os.path.join(os.path.dirname(self.pool.db_path), 'config.json')
        with open(path, 'w', encoding='utf-8') as f:
            json.dump({'money': {'currency': 'RUB', 'buy_enabled': False}, 'owner_value': 17}, f)
        self.cfg['_source'] = path
        config_store.save_proxywing_budget(self.cfg, self.cfg['proxywing_money'])
        with open(path, encoding='utf-8') as f:
            saved = json.load(f)
        self.assertEqual(saved['owner_value'], 17)
        self.assertFalse(saved['money']['buy_enabled'])
        self.assertEqual(saved['money']['currency'], 'RUB')
