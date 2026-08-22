# -*- coding: utf-8 -*-
"""Сходящееся применение стратегии: последний выбор побеждает, MANUAL сильнее worker."""
import json
import datetime
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
            " exit_cc_alt=?,geo_agree=1,latency_ms=?,last_probe_at=? WHERE uid=?",
            (cc, cc, latency, datetime.datetime.now().isoformat(), uid))
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

    def test_hysteresis_holds_small_improvement_and_logs_numbers(self):
        self.pool.conn.execute("UPDATE proxy SET latency_ms=200 WHERE uid=?", (self.current,))
        self.pool.conn.execute("UPDATE proxy SET latency_ms=100 WHERE uid=?", (self.fast,))
        self.pool.conn.commit()
        with mock.patch.object(states, "_probe", side_effect=self.probe_ok), \
             mock.patch.object(states.apply_mod, "apply_candidate") as apply:
            result = states._converge_strategy_locked(
                self.cfg, self.providers, self.pool, log=lambda *_: None)
        self.assertEqual(result["action"], "held")
        self.assertEqual(result["decision"]["margin"], 10.0)
        self.assertEqual(result["decision"]["threshold"], 15.0)
        event = self.pool.conn.execute(
            "SELECT result,detail FROM event WHERE action='strategy-apply' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        self.assertEqual(event["result"], "held")
        self.assertIn("лучше на 10.0, порог 15.0", event["detail"])
        diagnostic = next(e for e in self.pool.events()
                          if e["action"] == "strategy-apply" and e["result"] == "held")
        self.assertEqual(diagnostic["decision"]["mode"], "auto")
        self.assertEqual((diagnostic["decision"]["margin"],
                          diagnostic["decision"]["threshold"]), (10.0, 15.0))
        self.assertEqual({row["uid"] for row in diagnostic["decision"]["score_breakdown"]},
                         {self.current, self.fast})
        scores = {row["uid"]: row["total"]
                  for row in diagnostic["decision"]["score_breakdown"]}
        self.assertEqual(scores[self.fast] - scores[self.current],
                         diagnostic["decision"]["margin"])
        self.assertNotIn("password", json.dumps(diagnostic["decision"]))
        apply.assert_not_called()

    def test_hold_keeps_revision_pending_then_applies_after_timer(self):
        revision = states.request_strategy_selection(self.pool, self.cfg, "speed")
        self.pool.mark_used(self.current)
        with mock.patch.object(states, "_probe", side_effect=self.probe_ok), \
             mock.patch.object(states.apply_mod, "apply_candidate",
                               side_effect=self.applied) as apply:
            held = states._converge_strategy_locked(
                self.cfg, self.providers, self.pool, log=lambda *_: None)
            pending = states.selection_revision_state(self.pool, self.cfg)
            self.pool.conn.execute(
                "UPDATE proxy SET last_used_at=? WHERE uid=?",
                ((datetime.datetime.now() - datetime.timedelta(hours=1)).isoformat(),
                 self.current))
            self.pool.conn.commit()
            applied = states._converge_strategy_locked(
                self.cfg, self.providers, self.pool, log=lambda *_: None)
        self.assertEqual(held["action"], "held")
        self.assertEqual((pending["desired"], pending["applied"], pending["pending"]),
                         (revision, 0, True))
        self.assertEqual(applied["action"], "applied")
        self.assertEqual(states.selection_revision_state(self.pool, self.cfg)["applied"],
                         revision)
        self.assertEqual(apply.call_count, 1)

    def test_successful_switch_logs_margin_and_threshold(self):
        with mock.patch.object(states, "_probe", side_effect=self.probe_ok), \
             mock.patch.object(states.apply_mod, "apply_candidate",
                               side_effect=self.applied):
            result = states._converge_strategy_locked(
                self.cfg, self.providers, self.pool, log=lambda *_: None)
        self.assertEqual(result["action"], "applied")
        self.assertEqual((result["decision"]["margin"],
                          result["decision"]["threshold"]), (35.0, 15.0))
        event = self.pool.conn.execute(
            "SELECT detail FROM event WHERE action='strategy-apply' AND result='ok' "
            "ORDER BY id DESC LIMIT 1").fetchone()
        self.assertIn("лучше на 35.0, порог 15.0", event["detail"])

    def test_critical_failure_bypass_finishes_apply_and_audit(self):
        self.cfg["health"] = {"switch_margin": 1000, "min_hold_time": 604800,
                              "max_latency_regression": 0}
        self.pool.conn.execute(
            "UPDATE proxy SET probe_ok=0,last_used_at=? WHERE uid=?",
            (datetime.datetime.now().isoformat(), self.current))
        self.pool.conn.commit()
        with mock.patch.object(states, "_probe", side_effect=self.probe_ok), \
             mock.patch.object(states.apply_mod, "apply_candidate",
                               side_effect=self.applied) as apply, \
             mock.patch.object(states.apply_mod, "commit_operation") as commit:
            result = states._converge_strategy_locked(
                self.cfg, self.providers, self.pool, log=lambda *_: None)
        self.assertEqual(result["action"], "applied")
        self.assertEqual(result["decision"]["reason"], "critical-failure")
        self.assertIn("critical-failure bypass, порог 1000.0", result["detail"])
        apply.assert_called_once()
        commit.assert_called_once()

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

    def test_stale_current_is_reprobed_before_stable(self):
        old = (datetime.datetime.now() - datetime.timedelta(days=3)).isoformat()
        self.pool.conn.execute("UPDATE proxy SET last_probe_at=? WHERE uid=?", (old, self.current))
        self.pool.conn.commit()
        def refresh(*_args, **_kwargs):
            self.pool.conn.execute(
                "UPDATE proxy SET last_probe_at=?,probe_ok=1 WHERE uid=?",
                (datetime.datetime.now().isoformat(), self.current))
            self.pool.conn.commit()
            return self.probe_ok()
        with open(self.cfg_path, "w", encoding="utf-8") as f:
            json.dump({"countries": {"strategy": "reputation"}}, f)
        with mock.patch.object(states, "_probe", side_effect=refresh) as probe, \
             mock.patch.object(states.apply_mod, "apply_candidate") as apply:
            result = states._converge_strategy_locked(
                self.cfg, self.providers, self.pool, log=lambda *_: None)
        self.assertEqual(result["action"], "stable")
        probe.assert_called_once()
        apply.assert_not_called()

    def test_stale_current_is_probed_before_better_candidate(self):
        old = (datetime.datetime.now() - datetime.timedelta(days=3)).isoformat()
        self.pool.conn.execute("UPDATE proxy SET last_probe_at=? WHERE uid=?", (old, self.current))
        self.pool.conn.commit()
        calls = []
        def refresh(_pool, _providers, row, *_args, **_kwargs):
            calls.append(row["uid"])
            self.pool.conn.execute(
                "UPDATE proxy SET last_probe_at=?,probe_ok=1 WHERE uid=?",
                (datetime.datetime.now().isoformat(), row["uid"]))
            self.pool.conn.commit()
            return self.probe_ok()
        with mock.patch.object(states, "_probe", side_effect=refresh), \
             mock.patch.object(states.apply_mod, "apply_candidate", side_effect=self.applied):
            result = states._converge_strategy_locked(
                self.cfg, self.providers, self.pool, log=lambda *_: None)
        self.assertEqual(result["action"], "applied")
        self.assertEqual(calls[:2], [self.current, self.fast])

    def test_failed_only_current_never_becomes_stable_after_cooldown(self):
        self.pool.set_role(self.fast, "off")
        old = (datetime.datetime.now() - datetime.timedelta(days=3)).isoformat()
        self.pool.conn.execute("UPDATE proxy SET last_probe_at=? WHERE uid=?", (old, self.current))
        self.pool.conn.commit()
        calls = []
        def fail(_pool, _providers, row, *_args, **_kwargs):
            calls.append(row["uid"])
            self.pool.conn.execute(
                "UPDATE proxy SET last_probe_at=?,probe_ok=0 WHERE uid=?",
                (datetime.datetime.now().isoformat(), row["uid"]))
            self.pool.conn.commit()
            return {"ok": False, "disqualified": None}
        with mock.patch.object(states, "_probe", side_effect=fail):
            first = states._converge_strategy_locked(
                self.cfg, self.providers, self.pool, log=lambda *_: None)
            self.pool.clear_cooldown(self.current)
            second = states._converge_strategy_locked(
                self.cfg, self.providers, self.pool, log=lambda *_: None)
        self.assertEqual((first["action"], second["action"]), ("empty", "empty"))
        self.assertEqual(calls, [self.current, self.current])

    def test_live_current_missing_from_pool_is_probed_and_ranked_first(self):
        self.pool.conn.execute("DELETE FROM proxy WHERE uid=?", (self.current,))
        self.pool.conn.commit()
        calls = []
        def probe_live(_pool, _providers, row, *_args, **_kwargs):
            calls.append(row["uid"])
            if row["host"] == "10.0.0.1":
                return {"ok": True, "disqualified": None, "latency_ms": 20,
                        "tg_ok": True, "socks_ok": True, "http_ok": True,
                        "exit_cc": "de", "geo_agree": True, "score": 140.0}
            return self.probe_ok()
        with mock.patch.object(states, "_probe", side_effect=probe_live), \
             mock.patch.object(states.apply_mod, "apply_candidate") as apply:
            result = states._converge_strategy_locked(
                self.cfg, self.providers, self.pool, log=lambda *_: None)
        self.assertEqual(result["action"], "stable")
        self.assertEqual(calls, ["live:10.0.0.1"])
        apply.assert_not_called()

class TestSwitchDecision(unittest.TestCase):
    def test_margin_boundary_is_numeric(self):
        cfg = {"health": {"switch_margin": 15, "min_hold_time": 0,
                          "max_latency_regression": 500}}
        self.assertFalse(states.switch_decision(100, 114, cfg=cfg)["allow"])
        decision = states.switch_decision(100, 115, cfg=cfg)
        self.assertTrue(decision["allow"])
        self.assertEqual((decision["margin"], decision["threshold"]), (15.0, 15.0))

    def test_min_hold_and_critical_failure_bypass(self):
        cfg = {"health": {"switch_margin": 15, "min_hold_time": 1800,
                          "max_latency_regression": 500}}
        now = datetime.datetime(2026, 8, 22, 12, 0, 0)
        held = states.switch_decision(
            100, 130, last_used_at="2026-08-22 11:50:00", cfg=cfg, now=now)
        self.assertFalse(held["allow"])
        self.assertEqual(held["hold_remaining"], 1200.0)
        bypass = states.switch_decision(
            None, 130, last_used_at="2026-08-22 11:59:59",
            current_healthy=False, cfg=cfg, now=now)
        self.assertTrue(bypass["allow"])
        self.assertEqual(bypass["reason"], "critical-failure")

    def test_latency_regression_and_invalid_config(self):
        cfg = {"health": {"switch_margin": 1, "min_hold_time": 0,
                          "max_latency_regression": 100}}
        decision = states.switch_decision(
            100, 130, current_latency=50, candidate_latency=151, cfg=cfg)
        self.assertFalse(decision["allow"])
        self.assertEqual(decision["reason"], "latency-regression")
        self.assertEqual(
            states.switch_policy_cfg({"health": {
                "switch_margin": True, "min_hold_time": float("nan"),
                "max_latency_regression": -1}}),
            states.DEFAULT_SWITCH_POLICY)


if __name__ == "__main__":
    unittest.main()
