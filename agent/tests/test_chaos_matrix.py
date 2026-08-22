# -*- coding: utf-8 -*-
"""Explicit cross-product and money/network boundary cases from RELIABILITY-PLAN."""
import os
import tempfile
import unittest
from unittest import mock

import _ctx  # noqa: F401
import country
import pool as pool_mod
import states


def proxy(ext_id="1", host="198.51.100.10"):
    return {"provider": "proxy6", "ext_id": ext_id, "ip": host, "host": host,
            "port_http": 8080, "port_socks5": 1080, "user": "u", "password": "p",
            "country": "fi", "ip_version": 4, "kind": "dedicated",
            "date_end": "", "descr": "purchase-chaos"}


class PoolCase(unittest.TestCase):
    def setUp(self):
        fd, self.db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.pool = pool_mod.Pool(self.db, server="chaos")

    def tearDown(self):
        self.pool.close()
        os.unlink(self.db)


class TestModeStrategyStateCrossProduct(PoolCase):
    def test_auto_manual_all_strategies_and_runtime_states_are_orthogonal(self):
        runtime_states = (states.OK, states.SUSPECT, states.ROTATING,
                          states.EMERGENCY, states.FROZEN_NET)
        for mode in (states.SELECTION_AUTO, states.SELECTION_MANUAL):
            for strategy in country.STRATEGIES:
                cfg = {"countries": {"strategy": strategy}}
                for runtime_state in runtime_states:
                    with self.subTest(mode=mode, strategy=strategy, state=runtime_state):
                        self.pool.set_settings({
                            "selection_mode": mode,
                            "manual_uid": "proxy6:1" if mode == states.SELECTION_MANUAL else None,
                            "manual_host": "198.51.100.10" if mode == states.SELECTION_MANUAL else None,
                            "manual_since": "2026-08-22 12:00:00"
                            if mode == states.SELECTION_MANUAL else None,
                            "automat_state": runtime_state,
                        })
                        selection = states.selection_state(
                            self.pool, cfg, current_host="198.51.100.10")
                        self.assertEqual(selection["mode"], mode)
                        self.assertEqual(selection["strategy"], strategy)
                        self.assertEqual(self.pool.get_setting("automat_state"), runtime_state)
                        self.assertEqual(selection["is_current"],
                                         mode == states.SELECTION_MANUAL)


class TestPostBuyFailureBoundary(PoolCase):
    def test_successful_purchase_with_failed_postprobe_is_never_applied(self):
        bought = proxy()

        class Provider:
            caps = {"buy": True}

            def getcount(self, country_code, version):
                return 1

        purchase = {"ok": True, "recovered": False, "proxies": [bought],
                    "price": 28.0, "currency": "RUB", "balance_after": 900.0,
                    "country": "fi", "period": 7}
        failed = [("proxy6:1", {"ok": False, "disqualified": "no-combo",
                                 "exit_cc": None}, False)]
        def record_purchase(*args, **kwargs):
            self.pool.upsert_proxy(bought, role="auto")
            return purchase
        cfg = {"server": "chaos", "singbox_config": "unused",
               "countries": {"strategy": "speed"},
               "money": {"buy_enabled": True, "buy_period_days": 7,
                         "buy_version": 4}}
        with mock.patch.object(states.apply_mod, "load_json", return_value={}), \
                mock.patch.object(states.apply_mod, "current_upstream", return_value=None), \
                mock.patch.object(states.money_mod, "buy_candidates", return_value=["fi"]), \
                mock.patch.object(states.money_mod, "plan_and_buy", side_effect=record_purchase), \
                mock.patch.object(states, "postbuy_check", return_value=failed), \
                mock.patch.object(states.apply_mod, "apply_candidate") as apply_candidate:
            result = states.try_replenish(
                cfg, {"proxy6": Provider()}, self.pool, mock.Mock(), lambda message: None, "auto")
        self.assertFalse(result["ok"])
        self.assertIn("непригоден", result["reason"])
        apply_candidate.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
