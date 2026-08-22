# -*- coding: utf-8 -*-
"""Сходящееся применение стратегии: последний выбор побеждает, MANUAL сильнее worker."""
import json
import os
import tempfile
import unittest
from unittest import mock

import _ctx  # noqa: F401
import pool as pool_mod
import states


class TestStrategyConvergence(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "state.db")
        self.cfg_path = os.path.join(self.tmp.name, "config.json")
        self.sb_path = os.path.join(self.tmp.name, "singbox.json")
        with open(self.cfg_path, "w", encoding="utf-8") as f:
            json.dump({"countries": {"strategy": "speed"}}, f)
        with open(self.sb_path, "w", encoding="utf-8") as f:
            json.dump({"outbounds": [{"tag": "socks-out", "type": "socks",
                                      "server": "10.0.0.1", "server_port": 1080}]}, f)
        self.cfg = {"_source": self.cfg_path, "singbox_config": self.sb_path,
                    "countries": {"strategy": "reputation"}}
        self.pool = pool_mod.Pool(self.db, server="test")
        self.current = self.add("proxy6", "cur", "10.0.0.1", "de", latency=400)
        self.fast = self.add("proxywing", "fast", "10.0.0.2", "ng", latency=50)
        self.providers = {"proxy6": object(), "proxywing": object()}

    def tearDown(self):
        self.pool.close()
        self.tmp.cleanup()

    def add(self, provider, ext_id, host, cc, latency):
        uid = self.pool.upsert_proxy({
            "provider": provider, "ext_id": ext_id, "ip": host, "host": host,
            "port_http": 8080, "port_socks5": 1080, "user": "u", "password": "p",
            "country": cc, "ip_version": 4, "kind": "dedicated",
            "date_end": None, "descr": ""})
        self.pool.conn.execute(
            "UPDATE proxy SET probe_ok=1,socks_ok=1,http_ok=1,tg_ok=1,exit_cc=?,"
            " exit_cc_alt=?,geo_agree=1,latency_ms=? WHERE uid=?",
            (cc, cc, latency, uid))
        self.pool.conn.commit()
        return uid

    @staticmethod
    def probe_ok(*_args, **_kwargs):
        return {"ok": True, "disqualified": None, "score": 140.0,
                "exit_ip": "10.0.0.2", "exit_cc": "ng", "tg_code": "200"}

    @staticmethod
    def applied(*_args, **_kwargs):
        return {"ok": True, "old_ip": "10.0.0.1", "new_ip": "10.0.0.2",
                "verify": {"ok": True, "egress_ip": "10.0.0.2", "exit_cc": "ng",
                           "tg_code": "200"}}

    def test_worker_reads_latest_disk_strategy_and_is_provider_neutral(self):
        # В памяти осталась reputation, но последний клик на диске — speed.
        # Быстрый ProxyWing обязан победить медленный Proxy6: provider не tie-break.
        with mock.patch.object(states, "_probe", side_effect=self.probe_ok), \
             mock.patch.object(states.apply_mod, "apply_candidate", side_effect=self.applied) as apply:
            r = states._converge_strategy_locked(
                self.cfg, self.providers, self.pool, log=lambda *_: None)
        self.assertEqual((r["action"], r["strategy"], r["uid"]),
                         ("applied", "speed", self.fast))
        self.assertEqual(apply.call_args.args[1]["provider"], "proxywing")
        self.assertEqual(states.selection_state(self.pool, self.cfg)["mode"], "auto")

    def test_reputation_and_current_stickiness_can_keep_current(self):
        with open(self.cfg_path, "w", encoding="utf-8") as f:
            json.dump({"countries": {"strategy": "reputation"}}, f)
        with mock.patch.object(states, "_probe") as probe, \
             mock.patch.object(states.apply_mod, "apply_candidate") as apply:
            r = states._converge_strategy_locked(
                self.cfg, self.providers, self.pool, log=lambda *_: None)
        self.assertEqual(r["action"], "stable")
        self.assertEqual(r["uid"], self.current)
        probe.assert_not_called()
        apply.assert_not_called()

    def test_fresh_probe_rechecks_ranking_before_apply(self):
        def became_slow(*_args, **_kwargs):
            self.pool.conn.execute(
                "UPDATE proxy SET latency_ms=1000,tg_ok=0,http_ok=0 WHERE uid=?", (self.fast,))
            self.pool.conn.commit()
            return self.probe_ok()

        with mock.patch.object(states, "_probe", side_effect=became_slow), \
             mock.patch.object(states.apply_mod, "apply_candidate") as apply:
            r = states._converge_strategy_locked(
                self.cfg, self.providers, self.pool, log=lambda *_: None)
        self.assertEqual(r["action"], "stable-after-probe")
        apply.assert_not_called()

    def test_manual_selected_after_queue_supersedes_worker(self):
        states.set_manual_selection(self.pool, self.current, "10.0.0.1")
        with mock.patch.object(states, "_probe") as probe, \
             mock.patch.object(states.apply_mod, "apply_candidate") as apply:
            r = states._converge_strategy_locked(
                self.cfg, self.providers, self.pool, log=lambda *_: None)
        self.assertEqual(r["action"], "manual-superseded")
        self.assertEqual(states.selection_state(self.pool, self.cfg)["mode"], "manual")
        probe.assert_not_called()
        apply.assert_not_called()

    def test_provider_without_active_key_is_not_a_candidate(self):
        with mock.patch.object(states, "_probe") as probe:
            r = states._converge_strategy_locked(
                self.cfg, {"proxy6": object()}, self.pool, log=lambda *_: None)
        self.assertEqual((r["action"], r["uid"]), ("stable", self.current))
        probe.assert_not_called()


if __name__ == "__main__":
    unittest.main()
