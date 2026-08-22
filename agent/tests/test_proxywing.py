# -*- coding: utf-8 -*-
import unittest
import _ctx
from providers.proxywing import ProxyWing


class Stub(ProxyWing):
    def __init__(self, responses):
        super().__init__("pk_live_test_key"); self.responses = responses
    def _api(self, path): return self.responses[path]


class TestProxyWing(unittest.TestCase):
    def test_list_aggregates_families(self):
        one = _ctx.fixture("proxywing_proxies.json")
        got = Stub({"/datacenter/proxies": one, "/isp/proxies": one}).list()
        self.assertEqual(len(got), 2)
        self.assertEqual({x["ext_id"].split("|", 1)[0] for x in got}, {"datacenter", "isp"})
    def test_balance(self):
        self.assertEqual(Stub({"/account/balance":{"balance":5.2,"currency":"USD"}}).balance(),
                         {"balance":5.2,"currency":"USD"})
    def test_money_disabled(self):
        self.assertFalse(Stub({}).caps["buy"]); self.assertFalse(Stub({}).caps["prolong"])


if __name__ == "__main__": unittest.main(verbosity=2)
