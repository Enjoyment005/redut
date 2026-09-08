"""ProxyLine PDF API contracts and payment crash boundaries, without real requests."""
import copy
import datetime
import json
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import _ctx
import money
import pool as pool_mod
import proxyline_orders as orders
from providers import proxyline as pl
from providers.base import ProviderError


def proxy(ident=15, order_id=42, date_end='2026-09-10T12:00:00', **kw):
    return dict(id=ident, order_id=order_id, type='1', country='us', ip_version=4,
                ip='203.0.113.15', port_http=8080, port_socks5=1080,
                username='fake-user', password='fake-secret', date_end=date_end, **kw)


class FakeProxyLine(pl.ProxyLine):
    min_interval = 0

    def __init__(self):
        super().__init__('fake-account')
        self.rows = [proxy()]
        self.calls = []
        self.usd_balance = 100
        self.price = 1.2
        self.lost = False
        self.rejected = False
        self.override = None

    def _api(self, path, params=None):
        if path == '/balance/':
            return {'balance': str(self.usd_balance)}
        if path == '/countries/':
            return [{'code': 'us', 'name': 'USA'}]
        if path == '/ips-count/':
            return {'count': 50}
        if path == '/proxies/':
            rows = [r for r in self.rows if not params.get('ids') or str(r['id']) in params['ids']]
            return {'results': copy.deepcopy(rows), 'count': len(rows), 'next': None}
        raise AssertionError(path)

    def post(self, url, fields, **kwargs):
        if url.endswith('/new-order-amount/'):
            assert kwargs['mutating'] is False
            return {'amount': self.price, 'data': dict(fields, ip_list=[])}
        assert kwargs['mutating'] is True
        self.calls.append((url, copy.deepcopy(fields)))
        if self.rejected:
            raise ProviderError('insufficient balance', definitive=True)
        if url.endswith('/new-order/'):
            rows = [proxy(100 * len(self.calls) + n, order_id=42 + len(self.calls), date_end='2026-10-10T12:00:00')
                    for n in range(fields['quantity'])]
            self.rows.extend(rows)
        else:
            rows = [r for r in self.rows if str(r['id']) in fields['proxies']]
            for row in rows:
                date = datetime.datetime.fromisoformat(row['date_end']) + datetime.timedelta(days=fields['period'])
                row['date_end'] = date.isoformat()
        self.usd_balance -= self.price
        if self.lost:
            raise ProviderError('response lost', network=True)
        return copy.deepcopy(self.override if self.override is not None else rows)


class TestProxyLinePayments(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.pool = pool_mod.Pool(directory.name + '/state.db')
        self.addCleanup(self.pool.close)
        self.provider = FakeProxyLine()
        self.cfg = {'money': {'buy_enabled': False, 'max_price_per_buy': 0}, 'auto_prolong': {'enabled': True}}
        self.body = dict(kind='buy', country='us', type='dedicated', version=4, quantity=1,
                         period=30, max_total=1.2, request_id='proxyline-request-001')
        patch = mock.patch.object(pl, 'http_post_form', side_effect=self.provider.post)
        patch.start()
        self.addCleanup(patch.stop)

    def execute(self, **changes):
        return orders.execute(self.pool, self.provider, self.cfg, dict(self.body, **changes))

    def renewal(self, **changes):
        self.pool.upsert_proxy(pl.norm_proxyline(self.provider.rows[0]))
        return self.execute(kind='prolong', uid='proxyline:15', **changes)

    def test_buy_uses_modern_type_and_imports_only_bought_ids_off(self):
        result = self.execute()
        self.assertTrue(result['ok'])
        self.assertEqual(self.provider.calls[0][1], {'type': 'dedicated_ipv4', 'country': 'us', 'quantity': 1, 'period': 30})
        self.assertEqual(result['uids'], ['proxyline:100'])
        self.assertEqual(self.pool.get('proxyline:100')['role'], 'off')
        self.assertIsNone(self.pool.get('proxyline:15'))
        self.assertIsNone(result['price'])
        self.assertEqual(result['quoted_price'], 1.2)
        self.assertEqual(result['balance_after'], 98.8)

    def test_repeat_click_replays_without_second_post_even_in_safe_mode(self):
        first = self.execute()
        self.cfg['_config_meta'] = {'safe_mode': True}
        second = self.execute()
        self.assertEqual(first['spend_operation_id'], second['spend_operation_id'])
        self.assertEqual(len(self.provider.calls), 1)
        self.assertEqual(self.pool.buys_today(), 1)

    def test_renewal_uses_purchased_id_and_list_expiry_without_budget_or_new_order_quote(self):
        with mock.patch.object(self.provider, 'quote', side_effect=AssertionError('not a renewal quote')):
            result = self.renewal()
        self.assertEqual(self.provider.calls[0][1], {'proxies': ['15'], 'period': 30})
        self.assertTrue(self.provider.calls[0][0].endswith('/renew/'))
        self.assertEqual(self.pool.get('proxyline:15')['date_end'], '2026-10-10T12:00:00')
        self.assertEqual(self.pool.get('proxyline:15')['role'], 'auto')
        self.assertIsNone(result['price'])
        self.assertTrue(self.pool.prolonged_today('proxyline:15'))

    def test_generic_manual_renewal_uses_same_contract(self):
        row = pl.norm_proxyline(self.provider.rows[0])
        row['uid'] = self.pool.upsert_proxy(row)
        result = money.prolong_with_limits(self.pool, self.provider, self.cfg, row=row,
                                          days=30, actor='user', request_id=self.body['request_id'])
        self.assertTrue(result['ok'])
        self.assertEqual(len(self.provider.calls), 1)

    def test_unknown_amount_is_not_zero_or_ledger_corruption(self):
        self.execute()
        row = dict(self.pool.conn.execute('SELECT * FROM money').fetchone())
        self.assertIsNone(row['price'])
        self.assertEqual(row['price_source'], 'unreported')
        self.assertIsNone(self.pool.spent_today('USD'))
        self.assertEqual(self.pool.spent_today('RUB'), 0)
        with self.assertRaises(money.SpendDenied):
            money._safe_spent_today(self.pool, 'USD')
        self.assertIsNone(money._safe_spent_today(self.pool, 'USD', allow_unreported=True))
        self.execute(request_id='proxyline-request-002')
        self.assertEqual(len(self.provider.calls), 2)

    def test_unknown_amount_does_not_disable_proxywing_manual_spending(self):
        import proxywing_orders
        self.execute()
        proxywing_orders._gates(self.pool, self.cfg, 'buy', {'max_total': 3}, 3, 100)

    def test_metrics_report_unreported_charge_separately_from_invalid_rows(self):
        import metrics
        self.execute()
        report = metrics.local_report(self.pool)
        self.assertEqual(report['spend']['unreported'], [{'currency': 'USD', 'count': 1}])
        self.assertEqual(report['spend']['ignored_invalid_amounts'], 0)

    def test_unmarked_null_amount_still_fails_closed(self):
        self.pool.conn.execute("INSERT INTO money(ts,provider,op,price,currency) VALUES(?, 'proxy6','buy',NULL,'RUB')", (pool_mod.now_iso(),))
        self.pool.conn.commit()
        with self.assertRaises(money.SpendDenied):
            self.execute()
        self.assertEqual(self.provider.calls, [])

    def test_lost_response_never_resends_same_or_new_request(self):
        self.provider.lost = True
        with self.assertRaises(ProviderError):
            self.execute()
        for request_id in (self.body['request_id'], 'proxyline-another-request'):
            with self.assertRaises(money.SpendDenied):
                self.execute(request_id=request_id)
        with self.assertRaises(money.SpendDenied):
            money.reconcile_pending_spend(self.pool, {'proxyline': self.provider})
        self.assertEqual(len(self.provider.calls), 1)
        self.assertEqual(self.pool.pending_spend_operations()[0]['phase'], 'submitted')

    def test_lost_renewal_response_does_not_infer_payment_from_later_expiry(self):
        self.provider.lost = True
        with self.assertRaises(ProviderError):
            self.renewal()
        with self.assertRaises(money.SpendDenied):
            self.renewal()
        self.assertEqual(len(self.provider.calls), 1)

    def test_buy_imported_during_lost_reply_stays_off(self):
        self.provider.lost = True
        with self.assertRaises(ProviderError):
            self.execute()
        self.pool.refresh({'proxyline': self.provider})
        self.assertEqual(self.pool.get('proxyline:100')['role'], 'off')

    def test_saved_receipt_recovers_after_commit_failure_without_post(self):
        with mock.patch.object(orders, 'finish', side_effect=OSError('disk failure')):
            with self.assertRaises(OSError):
                self.execute()
        receipt = self.pool.pending_spend_operations()[0]['result']
        self.assertNotIn('password', json.dumps(receipt))
        self.assertNotIn('fake-secret', json.dumps(receipt))
        self.assertNotIn('fake-account', json.dumps(receipt))
        money.reconcile_pending_spend(self.pool, {'proxyline': self.provider})
        self.assertTrue(self.execute()['ok'])
        self.assertEqual(len(self.provider.calls), 1)

    def test_saved_renewal_receipt_recovers_dates(self):
        with mock.patch.object(orders, 'finish', side_effect=OSError('disk failure')):
            with self.assertRaises(OSError):
                self.renewal()
        result = self.execute(kind='prolong', uid='proxyline:15')
        self.assertEqual(result['date_end'], '2026-10-10T12:00:00')
        self.assertEqual(self.pool.get('proxyline:15')['date_end'], result['date_end'])
        self.assertEqual(len(self.provider.calls), 1)

    def test_definitive_rejection_retires_request(self):
        self.provider.rejected = True
        with self.assertRaises(ProviderError) as caught:
            self.execute()
        self.assertTrue(caught.exception.replace_request)
        self.assertEqual(self.pool.pending_spend_operations(), [])
        with self.assertRaises(money.SpendDenied) as caught:
            self.execute()
        self.assertTrue(caught.exception.replace_request)

    def test_changed_account_and_intent_cannot_reuse_receipt(self):
        self.execute()
        for changed in ({'quantity': 2}, {'period': 60}, {'max_total': 2}, {'country': 'de'}):
            with self.subTest(changed=changed), self.assertRaises(money.SpendDenied):
                self.execute(**changed)
        self.provider.api_key = 'different-fake-account'
        with self.assertRaises(money.SpendDenied):
            self.execute()
        self.assertEqual(len(self.provider.calls), 1)

    def test_expired_proxy_can_be_renewed_without_active_list_filter(self):
        self.provider.rows[0]['date_end'] = '2026-01-01T12:00:00'
        self.assertTrue(self.renewal()['ok'])

    def test_preflight_failures_never_send_paid_post(self):
        for changes in ({'country': 'ru'}, {'period': 7}, {'quantity': True}, {'max_total': True},
                        {'max_total': .5}, {'version': 5}, {'type': 'mtproxy'}):
            with self.subTest(changes=changes), self.assertRaises((money.SpendDenied, ProviderError)):
                self.execute(**changes)
        self.provider.usd_balance = 0
        with self.assertRaises(money.SpendDenied):
            self.execute()
        self.assertEqual(self.provider.calls, [])

    def test_safe_mode_prevents_new_payment(self):
        self.cfg['_config_meta'] = {'safe_mode': True}
        with self.assertRaises(money.SpendDenied):
            self.execute()
        self.assertEqual(self.provider.calls, [])

    def test_wrong_or_malformed_paid_lists_stay_pending(self):
        for reply in ({}, [], [proxy(15)], [proxy(100, order_id=43), proxy(100, order_id=43)]):
            with self.subTest(reply=reply), tempfile.TemporaryDirectory() as directory:
                pool = pool_mod.Pool(directory + '/state.db')
                try:
                    self.provider.override = reply
                    with self.assertRaises((money.SpendDenied, ProviderError)):
                        orders.execute(pool, self.provider, self.cfg, self.body)
                    self.assertEqual(pool.pending_spend_operations()[0]['phase'], 'submitted')
                    self.assertEqual(pool.buys_today(), 0)
                finally:
                    pool.close()

    def test_post_payment_balance_failure_does_not_hide_success(self):
        calls = 0
        original = self.provider.balance
        def balance():
            nonlocal calls
            calls += 1
            if calls > 1:
                raise ProviderError('offline')
            return original()
        with mock.patch.object(self.provider, 'balance', side_effect=balance):
            result = self.execute()
        self.assertTrue(result['ok'])
        self.assertIsNone(result['balance_after'])

    def test_existing_roles_survive_receipt_replay(self):
        self.execute()
        self.pool.set_role('proxyline:100', 'auto')
        self.execute()
        self.assertEqual(self.pool.get('proxyline:100')['role'], 'auto')

    def test_migration_and_reopen_preserve_receipt_and_unreported_amount(self):
        first = self.execute()
        path = self.pool.db_path
        self.pool.close()
        self.pool = pool_mod.Pool(path)
        self.addCleanup(self.pool.close)
        pool_mod.migrate(self.pool.conn, path)
        result = self.execute()
        self.assertEqual(result['spend_operation_id'], first['spend_operation_id'])
        self.assertIsNone(self.pool.spent_today('USD'))
        self.assertEqual(len(self.provider.calls), 1)


class TestProxyLineAuto(unittest.TestCase):
    def setUp(self):
        TestProxyLinePayments.setUp(self)
        self.row = pl.norm_proxyline(self.provider.rows[0])
        self.row.update(uid=self.pool.upsert_proxy(self.row), probe_ok=1)
        self.pool.conn.execute("UPDATE proxy SET probe_ok=1")
        self.pool.conn.commit()
        self.cfg['singbox_config'] = 'fake.json'
        self.ap = {'enabled': True, 'days_before': 3, 'period_days': 30}
        self.sb = {'outbounds': [dict(tag='socks-out', type='socks', server=self.row['host'],
                   server_port=1080, username=self.row['user'], password=self.row['password'])]}

    def run_auto(self):
        import states
        with mock.patch.object(states.probe_mod, 'days_left', return_value=1), \
                mock.patch.object(states.apply_mod, 'load_json', return_value=self.sb), \
                mock.patch.object(states.apply_mod, 'current_upstream', return_value=self.row['host']):
            return states._auto_prolong_proxyline(self.cfg, {'proxyline': self.provider}, self.pool,
                mock.Mock(), self.row, self.ap, lambda line: None, 'auto')

    def test_automatic_renewal_runs_once_without_money_budgets(self):
        self.assertTrue(self.run_auto()['ok'])
        self.assertIsNone(self.run_auto())
        self.assertEqual(len(self.provider.calls), 1)

    def test_unhealthy_proxy_is_not_renewed(self):
        self.row['probe_ok'] = 0
        self.assertIsNone(self.run_auto())
        self.assertEqual(self.provider.calls, [])

    def test_live_health_rechecked_immediately_before_post(self):
        self.pool.conn.execute('UPDATE proxy SET probe_ok=0')
        self.pool.conn.commit()
        self.assertIsNone(self.run_auto())
        self.assertEqual(self.provider.calls, [])
        self.assertEqual(self.pool.pending_spend_operations(), [])

    def test_lost_automatic_reply_never_retries_payment(self):
        self.provider.lost = True
        self.assertIsNone(self.run_auto())
        self.assertIsNone(self.run_auto())
        self.assertEqual(len(self.provider.calls), 1)

    def test_provider_not_due_prevents_paying_from_stale_cache(self):
        import states
        self.provider.rows[0]['date_end'] = '2099-01-01T12:00:00'
        with mock.patch.object(states.apply_mod, 'load_json', return_value=self.sb), \
                mock.patch.object(states.apply_mod, 'current_upstream', return_value=self.row['host']), \
                mock.patch.object(states.probe_mod, 'days_left', side_effect=[1, 1000]):
            result = states._auto_prolong_proxyline(self.cfg, {'proxyline': self.provider}, self.pool,
                mock.Mock(), self.row, self.ap, lambda line: None, 'auto')
        self.assertIsNone(result)
        self.assertEqual(self.provider.calls, [])

    def test_same_ip_different_ports_renews_only_exact_current_proxy(self):
        import states
        other = dict(self.provider.rows[0], id=16, port_socks5=2080, port_http=9080)
        self.provider.rows.append(other)
        self.pool.upsert_proxy(pl.norm_proxyline(other), role='off')
        self.pool.conn.execute('UPDATE proxy SET probe_ok=1')
        self.pool.conn.commit()
        with mock.patch.object(states.probe_mod, 'days_left', return_value=1), \
                mock.patch.object(states.apply_mod, 'load_json', return_value=self.sb):
            result = states.auto_prolong(self.cfg, {'proxyline': self.provider}, self.pool,
                                         mock.Mock(), log=lambda line: None)
        self.assertEqual([call[1]['proxies'] for call in self.provider.calls], [['15']])
        self.assertEqual([row['uid'] for row in result['prolonged']], ['proxyline:15'])
        self.assertFalse(self.pool.prolonged_today('proxyline:16'))

    def test_same_endpoint_with_different_ids_is_ambiguous_and_never_paid(self):
        other = dict(self.provider.rows[0], id=16)
        self.provider.rows.append(other)
        self.pool.upsert_proxy(pl.norm_proxyline(other))
        self.assertIsNone(self.run_auto())
        self.assertEqual(self.provider.calls, [])

    def test_port_changed_during_preflight_cancels_payment(self):
        original = self.provider.balance
        def balance():
            self.sb['outbounds'][0]['server_port'] = 2080
            return original()
        with mock.patch.object(self.provider, 'balance', side_effect=balance):
            self.assertIsNone(self.run_auto())
        self.assertEqual(self.provider.calls, [])
        self.assertEqual(self.pool.pending_spend_operations(), [])

    def test_changed_port_retires_only_unsent_automatic_request(self):
        import states
        with mock.patch.object(self.provider, 'prolong', side_effect=SystemExit('crash before send')):
            with self.assertRaises(SystemExit):
                self.run_auto()
        op = self.pool.pending_spend_operations()[0]
        self.assertEqual(op['phase'], 'planned')
        self.sb['outbounds'][0]['server_port'] = 2080
        with mock.patch.object(states.apply_mod, 'load_json', return_value=self.sb):
            states._retire_obsolete_proxyline_renewals(self.cfg, self.pool)
        self.assertEqual(self.pool.get_spend_operation(op['id'])['phase'], 'failed')
        self.assertEqual(self.provider.calls, [])


class TestProxyLinePanel(unittest.TestCase):
    def setUp(self):
        TestProxyLinePayments.setUp(self)
        from webpanel import server
        self.server = server
        self.app = SimpleNamespace(pool=self.pool, cfg=self.cfg, providers={'proxyline': self.provider})
        patch = mock.patch.object(server, 'APP', self.app)
        patch.start()
        self.addCleanup(patch.stop)

    def handler(self, body):
        return SimpleNamespace(_body=lambda **kw: json.dumps(body).encode(),
                               _json=lambda status, data: (status, data), _client_ip=lambda: '127.0.0.1')

    def test_shop_route_buys_without_proxy6(self):
        status, result = self.server.Handler._api_post(self.handler(self.body), '/api/proxyline/spend')
        self.assertEqual(status, 200, result)
        self.assertTrue(result['ok'])

    def test_market_load_is_readonly_and_offers_supported_periods(self):
        result = self.server.Handler._market(self.handler({}), {'provider': ['proxyline']})
        self.assertTrue(result['money_supported'])
        self.assertEqual(result['periods'], list(pl.PERIODS))
        self.assertEqual(self.provider.calls, [])

    def test_renewal_route_supplies_terms_without_spending(self):
        self.pool.upsert_proxy(pl.norm_proxyline(self.provider.rows[0]))
        status, result = self.server.Handler._api_get(self.handler({}), '/api/proxyline/renewal', {'uid': ['proxyline:15']})
        self.assertEqual(status, 200)
        self.assertEqual(result['periods'], list(pl.PERIODS))
        self.assertEqual(self.provider.calls, [])

    def test_lost_reply_returns_nonreplaceable_original_request(self):
        self.provider.lost = True
        status, result = self.server.Handler._api_post(self.handler(self.body), '/api/proxyline/spend')
        self.assertEqual(status, 409)
        self.assertFalse(result['replace_request'])
        market = self.server.Handler._market(self.handler({}), {'provider': ['proxyline']})
        self.assertEqual(market['pending']['request_id'], self.body['request_id'])
        self.assertNotIn('credential_identity', json.dumps(market))

    def test_rejected_quote_returns_replaceable_error(self):
        body = dict(self.body, max_total=.5)
        status, result = self.server.Handler._api_post(self.handler(body), '/api/proxyline/spend')
        self.assertEqual(status, 409)
        self.assertTrue(result['replace_request'])
        self.assertEqual(self.provider.calls, [])

    def test_saved_purchase_receipt_is_exposed_when_catalog_is_offline(self):
        with mock.patch.object(orders, 'finish', side_effect=OSError('commit interrupted')):
            with self.assertRaises(OSError):
                orders.execute(self.pool, self.provider, self.cfg, self.body)
        with mock.patch.object(self.provider, 'countries', side_effect=ProviderError('catalog outage')):
            market = self.server.Handler._market(self.handler({}), {'provider': ['proxyline']})
        self.assertIn('error', market)
        self.assertEqual(market['pending']['request_id'], self.body['request_id'])
        result = orders.execute(self.pool, self.provider, self.cfg, market['pending'])
        self.assertTrue(result['ok'])
        self.assertEqual(len(self.provider.calls), 1)

    def test_generic_renewal_replay_cannot_bypass_changed_account_binding(self):
        body = dict(kind='prolong', uid='proxyline:15', period=30, request_id=self.body['request_id'])
        self.pool.upsert_proxy(pl.norm_proxyline(self.provider.rows[0]))
        self.server.Handler._api_post(self.handler(body), '/api/proxyline/spend')
        self.provider.api_key = 'different-fake-account'
        status, result = self.server.Handler._do_prolong(self.handler({}), self.pool.get(body['uid']), body['uid'],
            {'days':30, 'request_id':body['request_id']})
        self.assertEqual(status, 409)
        self.assertFalse(result['replace_request'])
        self.assertEqual(len(self.provider.calls), 1)


if __name__ == '__main__':
    unittest.main()
