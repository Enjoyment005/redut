# -*- coding: utf-8 -*-
import unittest

import _ctx
from providers.proxywing import ProxyWing


class StubProxyWing(ProxyWing):
    def __init__(self, responses):
        super().__init__("pk_live_test_key")
        self.responses = responses
        self.calls = []

    def _api(self, path):
        self.calls.append(path)
        return self.responses[path]


class TestProxyWing(unittest.TestCase):
    def test_list_aggregates_datacenter_and_isp(self):
        one = _ctx.fixture("proxywing_proxies.json")
        p = StubProxyWing({"/datacenter/proxies": one, "/isp/proxies": one})
        got = p.list()
        self.assertEqual(len(got), 2)
        self.assertEqual({x["ext_id"].split("|", 1)[0] for x in got}, {"datacenter", "isp"})
        self.assertEqual(p.calls, ["/datacenter/proxies", "/isp/proxies"])

    def test_non_active_and_broken_rows_are_ignored(self):
        gone = {"orders": [{"id": "ord_gone", "status": "terminated", "proxies": [{}]}]}
        broken = {"orders": [{"id": "ord_bad", "status": "active", "proxies": [{"id": "p"}]}]}
        p = StubProxyWing({"/datacenter/proxies": gone, "/isp/proxies": broken})
        self.assertEqual(p.list(), [])

    def test_balance(self):
        p = StubProxyWing({"/account/balance": {"balance": 5.2, "currency": "USD"}})
        self.assertEqual(p.balance(), {"balance": 5.2, "currency": "USD"})

    def test_money_is_disabled_until_monthly_policy_exists(self):
        p = StubProxyWing({})
        self.assertFalse(p.caps["buy"])
        self.assertFalse(p.caps["prolong"])
        self.assertFalse(p.caps["delete"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
