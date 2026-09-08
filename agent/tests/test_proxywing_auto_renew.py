"""Current-order automatic renewal: actual ledger and adapter, simulated payments."""
import datetime
import tempfile
import unittest
from unittest import mock

import _ctx
import pool
import states
import proxywing_orders as orders
from providers.proxywing import norm_proxywing
from test_proxywing_orders import FakeMonthly
from test_auto_prolong import FakeAlerter


class TestProxyWingAutoRenew(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.pool = pool.Pool(temporary.name + '/state.db')
        self.addCleanup(self.pool.close)
        self.provider = FakeMonthly()
        self.alerter = FakeAlerter()
        self.cfg = {'singbox_config': 'unused', 'money': {'buy_enabled': False},
                    'auto_prolong': {'enabled': True, 'days_before': 3, 'proxywing_months': 1}}
        self.before = (datetime.date.today() + datetime.timedelta(days=2)).isoformat()
        self.after = (datetime.date.today() + datetime.timedelta(days=33)).isoformat()
        fixture = _ctx.fixture('proxywing_proxies.json')['orders'][0]['proxies'][0]
        self.uids = []
        for number in (1, 2):
            row = norm_proxywing(dict(fixture, id='ip_' + str(number)), {'id': 'ord_1'}, 'isp')
            row.update(host='192.0.2.' + str(number), date_end=self.before)
            uid = self.pool.upsert_proxy(row)
            self.uids.append(uid)
        self.pool.conn.execute('UPDATE proxy SET probe_ok=1')
        self.pool.conn.commit()
        self.provider.response = dict(status='paid', order_id='ord_1', invoice_id='inv_1',
                                      total=3, next_due_date=self.after)
        self.current = '192.0.2.1'
        self.provider.renewal_options = mock.Mock(side_effect=lambda *args: {
            'order_id': 'ord_1', 'next_due_date': self.before,
            'options': [{'months': 1, 'total': 3}]})
        endpoint = self.pool.get(self.uids[0])
        for target, value in [('load_json', lambda _: {'outbounds':[{'tag':'socks-out','type':'socks',
                'server':self.current,'server_port':endpoint['port_socks5'],
                'username':endpoint['user'],'password':endpoint['password']}]}), ('current_upstream', lambda _: self.current)]:
            patcher = mock.patch.object(states.apply_mod, target, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_auto(self):
        return states.auto_prolong(self.cfg, {'proxywing': self.provider}, self.pool,
                                    self.alerter, log=lambda *args: None)

    def test_shared_ip_different_port_does_not_renew_another_order(self):
        self.pool.conn.execute("UPDATE proxy SET host='192.0.2.1',port_socks5=20000,"
            "uid='proxywing:isp|ord_2|ip_2',ext_id='isp|ord_2|ip_2' WHERE uid=?", (self.uids[1],))
        self.pool.conn.commit()
        self.provider.renewal_options.side_effect = lambda family, order: {
            'order_id':order,'next_due_date':self.before,'options':[{'months':1,'total':3}]}
        self.run_auto()
        self.assertEqual(len(self.provider.calls), 1)
        self.assertEqual(self.provider.calls[0][0], '/isp/orders/ord_1/extend')

    def test_renews_without_purchase_budget_and_updates_entire_order_once(self):
        result = self.run_auto()
        self.assertEqual(len(result['prolonged']), 1, self.alerter.sent)
        self.assertEqual(self.provider.calls[0][1]['cycle'], 1)
        self.assertEqual({r['date_end'] for r in self.pool.list()}, {self.after})
        self.assertEqual(self.pool.spent_today('USD'), 3)
        self.current = '192.0.2.2'
        self.pool.conn.execute('UPDATE proxy SET date_end=?', (self.before,))
        self.pool.conn.commit()
        self.run_auto()
        self.assertEqual(len(self.provider.calls), 1, 'same order, another IP must not pay twice')

    def test_disabled_unhealthy_and_not_due_never_pay(self):
        self.cfg['auto_prolong']['enabled'] = False
        self.run_auto()
        self.cfg['auto_prolong']['enabled'] = True
        self.pool.conn.execute('UPDATE proxy SET probe_ok=0')
        self.pool.conn.commit()
        self.run_auto()
        self.pool.conn.execute('UPDATE proxy SET probe_ok=1,date_end=?', (self.after,))
        self.pool.conn.commit()
        self.run_auto()
        self.assertFalse(self.provider.calls)

    def test_fresh_provider_date_prevents_spend_from_stale_local_date(self):
        self.before = self.after
        self.run_auto()
        self.assertFalse(self.provider.calls)

    def test_unknown_payment_is_not_resent_by_scheduler(self):
        self.provider.lose_once = True
        self.run_auto()
        first_key = self.provider.calls[0][2]
        self.run_auto()
        self.assertEqual(len(self.provider.calls), 1)
        job, _ = states._load_money_job(self.pool, 'money_request:auto-prolong:proxywing:isp|ord_1')
        self.assertEqual(job['request_id'], first_key)
        result = orders.execute(self.pool, self.provider, self.cfg,
                                dict(job['intent'], request_id=first_key))
        self.assertTrue(result['ok'])
        self.run_auto()
        self.assertEqual(len(self.provider.calls), 2)
        self.assertEqual(self.pool.spent_today('USD'), 3)

    def test_paid_response_recovers_after_restart_without_another_payment(self):
        with mock.patch.object(orders, 'finish', side_effect=OSError('interrupted commit')):
            self.run_auto()
        self.run_auto()
        self.assertEqual(len(self.provider.calls), 1)
        self.assertEqual(self.pool.spent_today('USD'), 3)
        self.assertIsNone(self.pool.get_setting('money_request:auto-prolong:proxywing:isp|ord_1'))

    def test_planned_restart_rechecks_health_before_first_payment(self):
        with mock.patch.object(self.provider, 'extend_order', side_effect=SystemExit('before HTTP')):
            with self.assertRaises(SystemExit):
                self.run_auto()
        self.assertEqual(self.pool.pending_spend_operations()[0]['phase'], 'planned')
        self.pool.conn.execute('UPDATE proxy SET probe_ok=0')
        self.pool.conn.commit()
        self.run_auto()
        self.assertFalse(self.provider.calls)
        self.pool.conn.execute('UPDATE proxy SET probe_ok=1')
        self.pool.conn.commit()
        self.run_auto()
        self.assertEqual(len(self.provider.calls), 1)

    def test_balance_and_safe_mode_denials_do_not_leave_an_unbound_job(self):
        self.provider.usd_balance = 2
        self.run_auto()
        self.provider.usd_balance = 100
        self.cfg['_config_meta'] = {'safe_mode': True}
        self.run_auto()
        self.cfg.pop('_config_meta')
        self.assertFalse(self.provider.calls)
        self.assertIsNone(self.pool.get_setting('money_request:auto-prolong:proxywing:isp|ord_1'))
        self.provider.renewal_options.side_effect = lambda *args: {
            'order_id': 'ord_1', 'next_due_date': self.before,
            'options': [{'months': 1, 'total': 4}]}
        self.run_auto()
        self.assertEqual(len(self.provider.calls), 1, 'new tick reads a fresh price after balance recovers')

    def test_price_increase_between_quote_and_submit_stops_only_that_attempt(self):
        quotes = [3, 4, 4, 4]
        self.provider.renewal_options.side_effect = lambda *args: {
            'order_id': 'ord_1', 'next_due_date': self.before,
            'options': [{'months': 1, 'total': quotes.pop(0)}]}
        self.run_auto()
        self.assertFalse(self.provider.calls)
        self.run_auto()
        self.assertEqual(len(self.provider.calls), 1)

    def test_removed_job_cannot_be_bound_by_an_old_worker(self):
        key = 'money_request:auto-prolong:proxywing:isp|ord_1'
        body = dict(kind='prolong', family='isp', order_id='ord_1', months=1, max_total=3)
        job, raw = states._begin_money_job(self.pool, key, body)
        self.pool.compare_and_delete_setting(key, raw)
        with self.assertRaises(states.money_mod.SpendDenied):
            orders.execute(self.pool, self.provider, self.cfg, dict(body, request_id=job['request_id']),
                           actor='auto', job_key=key, job_raw=raw)
        self.assertFalse(self.provider.calls)

    def test_channel_change_during_remote_quote_prevents_payment(self):
        count = 0
        def quote(*args):
            nonlocal count
            count += 1
            if count == 2:
                self.current = '192.0.2.99'
                self.pool.conn.execute('UPDATE proxy SET probe_ok=0')
                self.pool.conn.commit()
            return {'order_id': 'ord_1', 'next_due_date': self.before,
                    'options': [{'months': 1, 'total': 3}]}
        self.provider.renewal_options.side_effect = quote
        self.run_auto()
        self.assertFalse(self.provider.calls)
        self.assertEqual(self.pool.spent_today('USD'), 0)

    def test_rotation_retires_only_unsent_auto_order_and_renews_new_current(self):
        with mock.patch.object(self.provider, 'extend_order', side_effect=SystemExit('before HTTP')):
            with self.assertRaises(SystemExit):
                self.run_auto()
        old = self.pool.pending_spend_operations()[0]
        self.pool.conn.execute("UPDATE proxy SET uid='proxywing:isp|ord_2|ip_2',ext_id='isp|ord_2|ip_2' WHERE uid=?", (self.uids[1],))
        self.pool.conn.commit()
        self.current = '192.0.2.2'
        self.provider.renewal_options.side_effect = lambda family, order_id: {
            'order_id': order_id, 'next_due_date': self.before, 'options': [{'months': 1, 'total': 3}]}
        self.provider.response['order_id'] = 'ord_2'
        self.run_auto()
        self.assertEqual(self.pool.get_spend_operation(old['id'])['phase'], 'failed')
        self.assertEqual(len(self.provider.calls), 1)
        self.assertEqual(self.provider.calls[0][0], '/isp/orders/ord_2/extend')

    def test_rotation_keeps_uncertain_submitted_payment_blocked(self):
        self.provider.lose_once = True
        self.run_auto()
        old = self.pool.pending_spend_operations()[0]
        self.current = '192.0.2.99'
        self.run_auto()
        self.assertEqual(self.pool.get_spend_operation(old['id'])['phase'], 'submitted')
        self.assertEqual(len(self.provider.calls), 1)


if __name__ == '__main__':
    unittest.main()
